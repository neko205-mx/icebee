// p2p.go — STUN 发现 + UDP 打洞 + 简易 Gossip
//
// 实验性功能，通过 -p2p 启用。
// 不影响现有 Worker/KV 心跳机制，作为额外通信层叠加。
//
// 流程:
//  1. 绑定本地 UDP 端口
//  2. 向 STUN 服务器查询公网地址 (RFC 5389)
//  3. 心跳时把公网地址上报给 Worker，从响应中获取其他节点的地址
//  4. 向每个 peer 发送 UDP 打洞包，直到双向连通
//  5. 连通后定期交换 gossip（已知 peer 列表）
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// ── 配置 ──────────────────────────────────────────────────────────

var (
	p2pEnable  = true
	p2pPort    = 9201
	stunServer = "" // 留空则使用 defaultSTUNServers
)

// defaultSTUNServers 按优先级排列，超时后依次尝试下一个。
var defaultSTUNServers = []string{
	"stun.chat.bilibili.com:3478",
	"stun.miwifi.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// ── 全局实例 ──────────────────────────────────────────────────────

var p2pN *p2pNode

// ── 类型定义 ──────────────────────────────────────────────────────

type peerState int

const (
	peerStateNew       peerState = iota // 已知地址，尚未发包
	peerStatePunching                   // 已发包，等待对方回应
	peerStateConnected                  // 双向连通
)

func (s peerState) String() string {
	switch s {
	case peerStateNew:
		return "new"
	case peerStatePunching:
		return "punching"
	case peerStateConnected:
		return "connected"
	}
	return "unknown"
}

// PeerAddrInfo 用于与 Worker 交换地址信息。
type PeerAddrInfo struct {
	NodeID string `json:"nodeId"`
	Addr   string `json:"addr"` // "ip:port"
}

type peerEntry struct {
	mu         sync.Mutex
	nodeID     string
	publicAddr string
	state      peerState
	lastSeen   time.Time
	punchCount int
}

// p2pMsg 是节点间 UDP 消息的通用结构。
type p2pMsg struct {
	Type   string                 `json:"t"`          // "punch"|"hello"|"gossip"|"cmd"|"result"
	From   string                 `json:"f"`          // 发送方 nodeId
	Addr   string                 `json:"a"`          // 发送方公网地址（自报）
	Peers  []PeerAddrInfo         `json:"p,omitempty"`// gossip 时携带已知 peer 列表
	Task   map[string]interface{} `json:"task,omitempty"`   // cmd: 转发的任务
	Result map[string]interface{} `json:"result,omitempty"` // result: 执行结果
}

// p2pNode 持有 UDP 连接和 peer 表。
type p2pNode struct {
	nodeID     string
	conn       *net.UDPConn
	publicAddr string // STUN 发现的公网地址

	mu    sync.RWMutex
	peers map[string]*peerEntry // nodeID → entry

	// 任务中继
	execFn          func(map[string]interface{}) map[string]interface{} // 本地执行器回调
	shouldExecuteFn func(taskID string) bool                            // 去重检查，防止 Worker 重复下发
	relayMu         sync.Mutex
	relayResults    []map[string]interface{} // 来自 peer 的执行结果，待上报 Worker
}

// ── 构造 ──────────────────────────────────────────────────────────

func newP2PNode(nodeID string, port int, stunSvr string) (*p2pNode, error) {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("resolve local addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("bind UDP port %d: %w", port, err)
	}

	logf("[p2p] UDP 监听: 0.0.0.0:%d\n", port)

	servers := buildSTUNList(stunSvr)
	pub, err := stunDiscoverWithFallback(conn, servers)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("所有 STUN 服务器均失败: %w", err)
	}

	logf("[p2p] 公网地址: %s\n", pub)

	return &p2pNode{
		nodeID:     nodeID,
		conn:       conn,
		publicAddr: pub,
		peers:      make(map[string]*peerEntry),
	}, nil
}

// ── Peer 管理 ────────────────────────────────────────────────────

// UpdatePeers 合并从 Worker 响应中拿到的 peer 地址列表。
func (p *p2pNode) UpdatePeers(incoming []PeerAddrInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pi := range incoming {
		if pi.NodeID == p.nodeID || pi.Addr == "" {
			continue
		}
		if existing, ok := p.peers[pi.NodeID]; ok {
			existing.mu.Lock()
			if existing.publicAddr != pi.Addr {
				logf("[p2p] peer %s 地址更新: %s → %s\n", pi.NodeID, existing.publicAddr, pi.Addr)
				existing.publicAddr = pi.Addr
				existing.state = peerStateNew
				existing.punchCount = 0
			}
			existing.mu.Unlock()
		} else {
			p.peers[pi.NodeID] = &peerEntry{
				nodeID:     pi.NodeID,
				publicAddr: pi.Addr,
				state:      peerStateNew,
			}
			logf("[p2p] 发现新 peer: %s @ %s\n", pi.NodeID, pi.Addr)
		}
	}
}

func (p *p2pNode) sendMsg(addr string, msg p2pMsg) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(msg)
	_, err = p.conn.WriteToUDP(data, udpAddr)
	return err
}

// HasConnectedPeer 返回是否存在至少一个已连通的 peer。
func (p *p2pNode) HasConnectedPeer() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pe := range p.peers {
		pe.mu.Lock()
		connected := pe.state == peerStateConnected
		pe.mu.Unlock()
		if connected {
			return true
		}
	}
	return false
}

// RefreshPublicAddr 重新向 STUN 服务器查询公网地址，地址变化时返回 true。
// 使用独立临时 socket，避免干扰 p2p conn 上的接收循环。
func (p *p2pNode) RefreshPublicAddr(stunSvr string) bool {
	tmp, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		logf("[p2p] STUN 刷新：无法创建临时 socket: %v\n", err)
		return false
	}
	defer tmp.Close()

	servers := buildSTUNList(stunSvr)
	addr, err := stunDiscoverWithFallback(tmp, servers)
	if err != nil {
		logf("[p2p] STUN 刷新失败: %v\n", err)
		return false
	}
	p.mu.Lock()
	changed := p.publicAddr != addr
	p.publicAddr = addr
	p.mu.Unlock()
	if changed {
		logf("[p2p] 公网地址更新: %s\n", addr)
	}
	return changed
}

// ForwardTask 将任务转发给最多 2 个已连通的 peer 执行。
func (p *p2pNode) ForwardTask(task map[string]interface{}) {
	p.mu.RLock()
	var connected []*peerEntry
	for _, pe := range p.peers {
		pe.mu.Lock()
		if pe.state == peerStateConnected {
			connected = append(connected, pe)
		}
		pe.mu.Unlock()
	}
	p.mu.RUnlock()

	if len(connected) == 0 {
		return
	}
	rand.Shuffle(len(connected), func(i, j int) { connected[i], connected[j] = connected[j], connected[i] })
	if len(connected) > 2 {
		connected = connected[:2]
	}

	msg := p2pMsg{Type: "cmd", From: p.nodeID, Addr: p.publicAddr, Task: task}
	for _, pe := range connected {
		pe.mu.Lock()
		addr, nid := pe.publicAddr, pe.nodeID
		pe.mu.Unlock()
		if err := p.sendMsg(addr, msg); err != nil {
			logf("[p2p] → cmd → %-20s 失败: %v\n", nid, err)
		} else {
			logf("[p2p] → cmd → %-20s task=%s\n", nid, task["taskId"])
		}
	}
}

// PopRelayResults 取出并清空 peer 通过 P2P 返回的执行结果队列。
func (p *p2pNode) PopRelayResults() []map[string]interface{} {
	p.relayMu.Lock()
	defer p.relayMu.Unlock()
	if len(p.relayResults) == 0 {
		return nil
	}
	out := p.relayResults
	p.relayResults = nil
	return out
}

// StatusSummary 返回一行状态摘要（供心跳日志使用）。
func (p *p2pNode) StatusSummary() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total, connected := len(p.peers), 0
	for _, pe := range p.peers {
		pe.mu.Lock()
		if pe.state == peerStateConnected {
			connected++
		}
		pe.mu.Unlock()
	}
	return fmt.Sprintf("p2p=%s peers=%d/%d↑", p.publicAddr, connected, total)
}

// ── 接收循环 ──────────────────────────────────────────────────────

func (p *p2pNode) RunRecvLoop() {
	buf := make([]byte, 4096)
	for {
		n, remote, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// STUN 刷新时 SetDeadline 导致的临时超时，忽略继续
				continue
			}
			logf("[p2p] 接收错误: %v\n", err)
			return
		}

		var msg p2pMsg
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			logf("[p2p] 无法解析消息 from %s: %v\n", remote, err)
			continue
		}

		// 更新 peer 连通状态
		p.mu.RLock()
		pe, known := p.peers[msg.From]
		p.mu.RUnlock()

		if known {
			pe.mu.Lock()
			wasConnected := pe.state == peerStateConnected
			pe.state = peerStateConnected
			pe.lastSeen = time.Now()
			pe.mu.Unlock()
			if !wasConnected {
				logf("[p2p] ✓ 打洞成功! peer=%s remote=%s\n", msg.From, remote)
				// 回一个 hello 让对方也知道打通了
				hello := p2pMsg{Type: "hello", From: p.nodeID, Addr: p.publicAddr}
				_ = p.sendMsg(remote.String(), hello)
			}
		} else {
			// 未知节点主动连进来
			p.mu.Lock()
			p.peers[msg.From] = &peerEntry{
				nodeID:     msg.From,
				publicAddr: remote.String(),
				state:      peerStateConnected,
				lastSeen:   time.Now(),
			}
			p.mu.Unlock()
			logf("[p2p] ✓ 未知节点主动连接: %s @ %s\n", msg.From, remote)
		}

		// 处理消息内容
		switch msg.Type {
		case "punch":
			logf("[p2p] ← punch  from=%-20s remote=%s\n", msg.From, remote)
		case "hello":
			logf("[p2p] ← hello  from=%-20s\n", msg.From)
		case "ping":
			logf("[p2p] ← ping   from=%-20s\n", msg.From)
			pong := p2pMsg{Type: "pong", From: p.nodeID, Addr: p.publicAddr}
			_ = p.sendMsg(remote.String(), pong)
		case "pong":
			logf("[p2p] ← pong   from=%-20s\n", msg.From)
		case "gossip":
			logf("[p2p] ← gossip from=%-20s peers=%d\n", msg.From, len(msg.Peers))
			if len(msg.Peers) > 0 {
				p.UpdatePeers(msg.Peers)
			}
		case "cmd":
			taskID, _ := msg.Task["taskId"].(string)
			logf("[p2p] ← cmd    from=%-20s task=%s\n", msg.From, taskID)
			if p.execFn != nil && msg.Task != nil {
				// 验证签名，P2P 中继同样要求合法签名
				if err := VerifyTask(msg.Task); err != nil {
					logf("[p2p] ← cmd    ⚠ 签名验证失败 task=%s: %v，丢弃\n", taskID, err)
				} else if p.shouldExecuteFn == nil || p.shouldExecuteFn(taskID) {
					replyAddr := remote.String()
					go func(task map[string]interface{}, replyTo string) {
						result := p.execFn(task)
						// 加入自身 nodeId，让中继节点能以正确 ID 上报
						result["nodeId"] = p.nodeID
						reply := p2pMsg{Type: "result", From: p.nodeID, Addr: p.publicAddr, Result: result}
						if err := p.sendMsg(replyTo, reply); err != nil {
							logf("[p2p] → result → %s 失败: %v\n", replyTo, err)
						} else {
							logf("[p2p] → result → %-20s task=%s\n", msg.From, taskID)
						}
					}(msg.Task, replyAddr)
				} else {
					logf("[p2p] ← cmd    已执行过 task=%s，跳过\n", taskID)
				}
			}
		case "result":
			taskID, _ := msg.Result["taskId"].(string)
			nodeID, _ := msg.Result["nodeId"].(string)
			logf("[p2p] ← result from=%-20s task=%s node=%s\n", msg.From, taskID, nodeID)
			if msg.Result != nil {
				p.relayMu.Lock()
				p.relayResults = append(p.relayResults, msg.Result)
				p.relayMu.Unlock()
			}
		}
	}
}

// ── 打洞循环 ──────────────────────────────────────────────────────

func (p *p2pNode) RunPunchLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.RLock()
		entries := make([]*peerEntry, 0, len(p.peers))
		for _, pe := range p.peers {
			entries = append(entries, pe)
		}
		p.mu.RUnlock()

		for _, pe := range entries {
			pe.mu.Lock()
			if pe.state == peerStateConnected {
				pe.mu.Unlock()
				continue
			}
			addr := pe.publicAddr
			nid := pe.nodeID
			pe.punchCount++
			count := pe.punchCount
			pe.state = peerStatePunching
			pe.mu.Unlock()

			msg := p2pMsg{Type: "punch", From: p.nodeID, Addr: p.publicAddr}
			if err := p.sendMsg(addr, msg); err != nil {
				logf("[p2p] → punch #%-3d → %-20s (%s) 失败: %v\n", count, nid, addr, err)
			} else {
				logf("[p2p] → punch #%-3d → %-20s (%s)\n", count, nid, addr)
			}
		}
	}
}

// ── P2P 心跳循环 ─────────────────────────────────────────────

// RunHeartbeatLoop 每 5s 向已连通的 peer 发送 ping，超过 15s 未响应则重置为打洞状态。
func (p *p2pNode) RunHeartbeatLoop() {
	const (
		pingInterval = 5 * time.Second
		peerTimeout  = 15 * time.Second
	)
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.RLock()
		entries := make([]*peerEntry, 0, len(p.peers))
		for _, pe := range p.peers {
			entries = append(entries, pe)
		}
		p.mu.RUnlock()

		for _, pe := range entries {
			pe.mu.Lock()
			state := pe.state
			addr := pe.publicAddr
			nid := pe.nodeID
			since := time.Since(pe.lastSeen)
			pe.mu.Unlock()

			if state != peerStateConnected {
				continue
			}

			if since > peerTimeout {
				pe.mu.Lock()
				pe.state = peerStateNew
				pe.punchCount = 0
				pe.mu.Unlock()
				logf("[p2p] ✗ peer=%s 超时 (%.0fs)，重置为打洞状态\n", nid, since.Seconds())
				continue
			}

			msg := p2pMsg{Type: "ping", From: p.nodeID, Addr: p.publicAddr}
			if err := p.sendMsg(addr, msg); err != nil {
				logf("[p2p] → ping → %-20s 失败: %v\n", nid, err)
			} else {
				logf("[p2p] → ping → %-20s (%.0fs ago)\n", nid, since.Seconds())
			}
		}
	}
}

// ── Gossip 循环 ──────────────────────────────────────────────────

func (p *p2pNode) RunGossipLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.RLock()
		var connected []*peerEntry
		allPeers := make([]PeerAddrInfo, 0, len(p.peers))
		for _, pe := range p.peers {
			pe.mu.Lock()
			allPeers = append(allPeers, PeerAddrInfo{NodeID: pe.nodeID, Addr: pe.publicAddr})
			if pe.state == peerStateConnected {
				connected = append(connected, pe)
			}
			pe.mu.Unlock()
		}
		p.mu.RUnlock()

		if len(connected) == 0 {
			continue
		}

		// 随机选最多 3 个已连通 peer 发送 gossip
		rand.Shuffle(len(connected), func(i, j int) {
			connected[i], connected[j] = connected[j], connected[i]
		})
		if len(connected) > 3 {
			connected = connected[:3]
		}

		msg := p2pMsg{
			Type:  "gossip",
			From:  p.nodeID,
			Addr:  p.publicAddr,
			Peers: allPeers,
		}
		for _, pe := range connected {
			pe.mu.Lock()
			addr, nid := pe.publicAddr, pe.nodeID
			pe.mu.Unlock()
			if err := p.sendMsg(addr, msg); err != nil {
				logf("[p2p] → gossip → %-20s 失败: %v\n", nid, err)
			} else {
				logf("[p2p] → gossip → %-20s (传递 %d 个 peer)\n", nid, len(allPeers))
			}
		}
	}
}

// ── STUN 客户端（RFC 5389）────────────────────────────────────────

const stunMagicCookie = uint32(0x2112A442)

// buildSTUNList 组合用户指定的服务器与默认列表。
// 若用户通过 -stun 指定了服务器，将其置于列表首位。
func buildSTUNList(custom string) []string {
	if custom == "" {
		return defaultSTUNServers
	}
	// 去重：如果自定义地址已在默认列表中，不重复添加
	list := []string{custom}
	for _, s := range defaultSTUNServers {
		if s != custom {
			list = append(list, s)
		}
	}
	return list
}

// stunDiscoverWithFallback 依次尝试 servers 中的服务器，超时或出错时切换下一个。
// 必须在 recvLoop 启动前调用。
func stunDiscoverWithFallback(conn *net.UDPConn, servers []string) (string, error) {
	defer conn.SetDeadline(time.Time{}) // 确保最终恢复无超时

	for i, server := range servers {
		logf("[p2p] STUN [%d/%d] 尝试: %s\n", i+1, len(servers), server)
		addr, err := stunDiscover(conn, server)
		if err != nil {
			logf("[p2p] STUN [%d/%d] 失败: %v\n", i+1, len(servers), err)
			continue
		}
		logf("[p2p] STUN [%d/%d] 成功: %s → 公网地址 %s\n", i+1, len(servers), server, addr)
		return addr, nil
	}
	return "", fmt.Errorf("已尝试 %d 个服务器，均无响应", len(servers))
}

// stunDiscover 向单个 STUN 服务器查询公网地址，DNS + 读写总超时 3s。
func stunDiscover(conn *net.UDPConn, server string) (string, error) {
	// DNS 解析带超时，避免挂死；只取 IPv4 地址（socket 为 udp4）
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	host, port, _ := net.SplitHostPort(server)
	allAddrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("DNS 解析失败: %w", err)
	}
	ipv4 := ""
	for _, a := range allAddrs {
		if net.ParseIP(a).To4() != nil {
			ipv4 = a
			break
		}
	}
	if ipv4 == "" {
		return "", fmt.Errorf("DNS 未返回 IPv4 地址 (got %v)", allAddrs)
	}
	srv, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipv4, port))
	if err != nil {
		return "", fmt.Errorf("解析地址: %w", err)
	}

	// 构造 Binding Request（20 字节头，无属性）
	txID := make([]byte, 12)
	rand.Read(txID)
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)        // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0)              // Message Length = 0
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID)

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.WriteToUDP(req, srv); err != nil {
		return "", fmt.Errorf("发送请求: %w", err)
	}

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", fmt.Errorf("等待响应超时")
	}

	return parseSTUNResponse(buf[:n])
}

// parseSTUNResponse 解析 STUN Binding Response，提取公网 IP:Port。
func parseSTUNResponse(data []byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("响应太短: %d 字节", len(data))
	}
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != 0x0101 {
		return "", fmt.Errorf("意外消息类型: 0x%04x (期望 0x0101)", msgType)
	}
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	if 20+msgLen > len(data) {
		return "", fmt.Errorf("消息长度字段超出数据范围")
	}

	// 遍历属性，优先 XOR-MAPPED-ADDRESS(0x0020)，其次 MAPPED-ADDRESS(0x0001)
	pos, end := 20, 20+msgLen
	var fallback string
	for pos+4 <= end {
		aType := binary.BigEndian.Uint16(data[pos : pos+2])
		aLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+aLen > end {
			break
		}
		val := data[pos : pos+aLen]

		switch aType {
		case 0x0020: // XOR-MAPPED-ADDRESS
			if aLen < 8 || val[1] != 0x01 { // IPv4 only
				break
			}
			port := binary.BigEndian.Uint16(val[2:4]) ^ uint16(stunMagicCookie>>16)
			xip := binary.BigEndian.Uint32(val[4:8])
			ip := xip ^ stunMagicCookie
			return fmt.Sprintf("%d.%d.%d.%d:%d",
				ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff, port), nil

		case 0x0001: // MAPPED-ADDRESS（旧服务器回退）
			if aLen < 8 || val[1] != 0x01 {
				break
			}
			port := binary.BigEndian.Uint16(val[2:4])
			ip := binary.BigEndian.Uint32(val[4:8])
			fallback = fmt.Sprintf("%d.%d.%d.%d:%d",
				ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff, port)
		}

		// 属性值 4 字节对齐
		pos += aLen
		if aLen%4 != 0 {
			pos += 4 - aLen%4
		}
	}

	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("响应中未找到地址属性")
}
