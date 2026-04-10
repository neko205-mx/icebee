// iceBee — Admin（后端 + TUI 控制台合一）
//
// 启动后端心跳线程、本地 HTTP API，并提供全屏 TUI 管理界面。
//
// 编译: go build -o admin ./cmd/admin
//
// TUI 按键:
//   PgUp / PgDn   滚动日志
//   Ctrl+G        跳到最新日志
//   Enter         执行命令
//   Ctrl+C        退出
//
// HTTP API (--port, 默认 9100):
//   GET  /api/ping           健康检查
//   GET  /api/info           配置信息
//   GET  /api/body           当前 body
//   POST /api/body           设置 body（需含 command 字段）
//   POST /api/noop           清除指令
//   POST /api/reset          重置 Worker 全量状态
//   GET  /api/results        各节点最新结果
//   GET  /api/history?n=20   结果历史
//   GET  /api/events         拉取新事件（消费型）
//   GET  /api/heartbeat      心跳线程状态
//   GET  /api/task           当前任务信息
//   GET  /api/worker-status  代理 Worker /api/status
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── 配置 ──────────────────────────────────────────────────────────

var (
	workerURL   = "https://your-worker.workers.dev"
	hbInterval  = 5
	programName = "admin-control"
	apiPort     = 9100
)

// ── Ed25519 签名 ──────────────────────────────────────────────────

var (
	adminPrivKey ed25519.PrivateKey
	adminPubKey  ed25519.PublicKey
	adminPubHex  string // 公钥 hex，随心跳上报给 Worker
)

// loadOrGenKey 从 keyPath 加载或生成 Ed25519 密钥对。
func loadOrGenKey(keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == ed25519.PrivateKeySize {
		adminPrivKey = ed25519.PrivateKey(data)
		adminPubKey = adminPrivKey.Public().(ed25519.PublicKey)
		adminPubHex = hex.EncodeToString(adminPubKey)
		return nil
	}
	// 生成新密钥对
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(priv), 0600); err != nil {
		return err
	}
	adminPrivKey = priv
	adminPubKey = pub
	adminPubHex = hex.EncodeToString(pub)
	return nil
}

// signTask 对 body map（含 _dispatchId）进行签名，注入 _sig 字段。
func signTask(body map[string]interface{}) {
	if adminPrivKey == nil {
		return
	}
	// 计算摘要：排除 _sig 字段后序列化
	cp := make(map[string]interface{}, len(body))
	for k, v := range body {
		if k != "_sig" {
			cp[k] = v
		}
	}
	b, _ := json.Marshal(cp)
	sum := sha256.Sum256(b)
	sig := ed25519.Sign(adminPrivKey, sum[:])
	body["_sig"] = hex.EncodeToString(sig)
}

// ── 工具函数 ──────────────────────────────────────────────────────

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

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// ── 状态 ──────────────────────────────────────────────────────────

type NodeResult struct {
	NodeID     string      `json:"nodeId"`
	TaskID     string      `json:"taskId"`
	Status     string      `json:"status"`
	Output     interface{} `json:"output"`
	Error      string      `json:"error"`
	Command    string      `json:"command"`
	ReportedAt int64       `json:"reportedAt"`
}

type AdminState struct {
	mu             sync.RWMutex
	body           map[string]interface{}
	latestResults  map[string]NodeResult
	allResults     []NodeResult
	events         []map[string]interface{}
	lastStatus     string
	currentTaskID  string
	dispatchedTo   []string
	heartbeatOK    bool
	connectedNodes int
}

func newAdminState() *AdminState {
	return &AdminState{
		body:          map[string]interface{}{"command": "noop", "message": "", "config": map[string]interface{}{}},
		latestResults: make(map[string]NodeResult),
		heartbeatOK:   true,
	}
}

func (s *AdminState) setBody(nb map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cmd, _ := nb["command"].(string); cmd != "" && cmd != "noop" && cmd != "default" {
		nb["_dispatchId"] = randomHex(12)
		signTask(nb) // Ed25519 签名
	}
	s.body = nb
}

func (s *AdminState) getBody() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]interface{}, len(s.body))
	for k, v := range s.body {
		cp[k] = v
	}
	return cp
}

func (s *AdminState) ingestResults(list []NodeResult) {
	if len(list) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range list {
		s.latestResults[r.NodeID] = r
		s.allResults = append(s.allResults, r)
	}
}

func (s *AdminState) getLatestResults() map[string]NodeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]NodeResult, len(s.latestResults))
	for k, v := range s.latestResults {
		cp[k] = v
	}
	return cp
}

func (s *AdminState) getHistory(n int) []NodeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.allResults) <= n {
		cp := make([]NodeResult, len(s.allResults))
		copy(cp, s.allResults)
		return cp
	}
	return s.allResults[len(s.allResults)-n:]
}

func (s *AdminState) pushEvent(evt map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
	if len(s.events) > 500 {
		s.events = s.events[len(s.events)-250:]
	}
}

func (s *AdminState) popEvents() []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.events
	s.events = nil
	return out
}

func (s *AdminState) updateHeartbeat(ok bool, nodes int, taskID string, dispatched []string, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeatOK = ok
	s.connectedNodes = nodes
	s.currentTaskID = taskID
	s.dispatchedTo = dispatched
	s.lastStatus = status
}

func (s *AdminState) getHeartbeatInfo() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"last_status":     s.lastStatus,
		"current_task_id": s.currentTaskID,
		"dispatched_to":   s.dispatchedTo,
		"heartbeat_ok":    s.heartbeatOK,
		"connected_nodes": s.connectedNodes,
	}
}

func (s *AdminState) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = map[string]interface{}{"command": "noop", "message": "", "config": map[string]interface{}{}}
	s.latestResults = make(map[string]NodeResult)
	s.allResults = nil
	s.events = nil
	s.currentTaskID = ""
	s.dispatchedTo = nil
	s.connectedNodes = 0
}

// ── 全局变量 ──────────────────────────────────────────────────────

var (
	state = newAdminState()
	prog  *tea.Program
)

// ── TUI 消息 ──────────────────────────────────────────────────────

// logMsg 追加日志行（支持多行，用 \n 分隔）
type logMsg string

// hbStatusMsg 更新 header 状态
type hbStatusMsg struct {
	nodes int
	ok    bool
}

// resultPanelMsg 触发左侧结果面板刷新
type resultPanelMsg struct{}

// ── 心跳线程 ──────────────────────────────────────────────────────

func heartbeatLoop() {
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		payload := map[string]interface{}{
			"system": systemInfo(), "timestamp": nowISO(),
			"program": programName, "body": state.getBody(),
			"pubKey": adminPubHex,
		}
		b, _ := json.Marshal(payload)

		// 对请求体签名，放入 X-Admin-Sig header
		sum := sha256.Sum256(b)
		sig := ed25519.Sign(adminPrivKey, sum[:])
		sigHex := hex.EncodeToString(sig)

		req, _ := http.NewRequest("POST", workerURL+"/heartbeat/admin", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Sig", sigHex)
		resp, err := client.Do(req)
		ts := time.Now().Format("15:04:05")

		if err != nil {
			msg := fmt.Sprintf("[%s] ✗ heartbeat failed: %v", ts, err)
			state.updateHeartbeat(false, 0, "", nil, msg)
			state.pushEvent(map[string]interface{}{"type": "heartbeat", "time": ts, "ok": false, "message": msg})
			prog.Send(hbStatusMsg{ok: false})
			prog.Send(logMsg(sErr.Render(msg)))
		} else {
			var data map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&data)
			resp.Body.Close()

			nodes := int(jsonFloat(data, "connectedNodes"))
			taskID, _ := data["taskId"].(string)
			cmd, _ := data["currentCommand"].(string)
			dispatched := jsonStringSlice(data, "taskDispatchedTo")

			var results []NodeResult
			if raw, ok := data["nodeResults"].([]interface{}); ok {
				for _, item := range raw {
					if m, ok := item.(map[string]interface{}); ok {
						r := NodeResult{
							NodeID:  strVal(m, "nodeId"),
							TaskID:  strVal(m, "taskId"),
							Status:  strVal(m, "status"),
							Command: strVal(m, "command"),
							Error:   strVal(m, "error"),
							Output:  m["output"],
						}
						if ts2, ok := m["reportedAt"].(float64); ok {
							r.ReportedAt = int64(ts2)
						}
						results = append(results, r)
					}
				}
			}
			state.ingestResults(results)

			parts := []string{fmt.Sprintf("[%s] heartbeat ok", ts), fmt.Sprintf("nodes:%d", nodes)}
			if cmd != "" && cmd != "noop" {
				parts = append(parts, "task:"+cmd, fmt.Sprintf("dispatched:%d", len(dispatched)))
			}
			if len(results) > 0 {
				parts = append(parts, fmt.Sprintf("results:%d", len(results)))
			}
			statusMsg := strings.Join(parts, " | ")
			state.updateHeartbeat(true, nodes, taskID, dispatched, statusMsg)
			state.pushEvent(map[string]interface{}{
				"type": "heartbeat", "time": ts, "ok": true, "nodes": nodes,
				"command": cmd, "dispatched": len(dispatched), "result_count": len(results),
			})

			prog.Send(hbStatusMsg{nodes: nodes, ok: true})
			// 心跳日志用暗色，不干扰主视图
			prog.Send(logMsg(sDim.Render(statusMsg)))

			// 结果回报高亮显示 + 刷新左侧结果面板
			for _, r := range results {
				state.pushEvent(map[string]interface{}{"type": "result", "time": ts, "data": r})
				prog.Send(logMsg(fmtResultInline(r)))
			}
			if len(results) > 0 {
				prog.Send(resultPanelMsg{})
			}
		}

		time.Sleep(time.Duration(hbInterval) * time.Second)
	}
}

// ── HTTP API ──────────────────────────────────────────────────────

func startAPIServer(port int) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{"ok": true}, 200)
	})
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{
			"worker_url": workerURL, "heartbeat_interval": hbInterval,
			"program_name": programName, "system": systemInfo(),
		}, 200)
	})
	mux.HandleFunc("/api/body", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			jsonResp(w, state.getBody(), 200)
			return
		}
		if r.Method == http.MethodPost {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				jsonResp(w, map[string]interface{}{"error": "JSON 解析失败: " + err.Error()}, 400)
				return
			}
			if _, ok := body["command"]; !ok {
				jsonResp(w, map[string]interface{}{"error": "body 必须包含 command 字段"}, 400)
				return
			}
			state.setBody(body)
			jsonResp(w, map[string]interface{}{"ok": true, "body": state.getBody()}, 200)
			return
		}
		jsonResp(w, map[string]interface{}{"error": "method not allowed"}, 405)
	})
	mux.HandleFunc("/api/noop", func(w http.ResponseWriter, r *http.Request) {
		state.setBody(map[string]interface{}{"command": "noop", "message": "", "config": map[string]interface{}{}})
		jsonResp(w, map[string]interface{}{"ok": true}, 200)
	})
	mux.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		workerResp, err := doResetWorker()
		if err != nil {
			jsonResp(w, map[string]interface{}{"error": err.Error()}, 502)
			return
		}
		state.reset()
		jsonResp(w, map[string]interface{}{"ok": true, "worker": workerResp}, 200)
	})
	mux.HandleFunc("/api/results", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{"results": state.getLatestResults(), "total": len(state.allResults)}, 200)
	})
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		n := 20
		if ns := r.URL.Query().Get("n"); ns != "" {
			n, _ = strconv.Atoi(ns)
		}
		jsonResp(w, map[string]interface{}{"history": state.getHistory(n)}, 200)
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{"events": state.popEvents()}, 200)
	})
	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, state.getHeartbeatInfo(), 200)
	})
	mux.HandleFunc("/api/task", func(w http.ResponseWriter, r *http.Request) {
		hb := state.getHeartbeatInfo()
		jsonResp(w, map[string]interface{}{
			"task_id":       hb["current_task_id"],
			"dispatched_to": hb["dispatched_to"],
			"body":          state.getBody(),
		}, 200)
	})
	mux.HandleFunc("/api/worker-status", func(w http.ResponseWriter, r *http.Request) {
		d, err := fetchWorkerStatus()
		if err != nil {
			jsonResp(w, map[string]interface{}{"error": err.Error()}, 502)
			return
		}
		jsonResp(w, d, 200)
	})

	go http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), mux)
}

func jsonResp(w http.ResponseWriter, data interface{}, status int) {
	b, _ := json.Marshal(data)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(b)
}

// ── Worker 代理 ───────────────────────────────────────────────────

func fetchWorkerStatus() (map[string]interface{}, error) {
	resp, err := http.Get(workerURL + "/api/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var d map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&d)
	return d, nil
}

func doResetWorker() (map[string]interface{}, error) {
	resp, err := http.Post(workerURL+"/api/reset", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var d map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&d)
	return d, nil
}

// ── TUI 样式 ──────────────────────────────────────────────────────

var (
	sHeader = lipgloss.NewStyle().
		Bold(true).
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230"))
	sHeaderErr = lipgloss.NewStyle().
			Bold(true).
			Background(lipgloss.Color("196")).
			Foreground(lipgloss.Color("230"))

	sDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	sOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	sErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	sWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	sInfo   = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	sBold   = lipgloss.NewStyle().Bold(true)
	sHint   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	sPrompt = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	sSep    = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

// ── TUI 模型 ──────────────────────────────────────────────────────

type tuiModel struct {
	vp       viewport.Model
	resultVP viewport.Model
	input    textinput.Model
	lines    []string // 全部日志行（含 ANSI）
	w, h     int
	ready    bool
	atBot    bool
	leftW    int // 结果面板宽度
	// header 状态
	hbNodes int
	hbOK    bool
}

var sBanner = lipgloss.NewStyle().Foreground(lipgloss.Color("38")).Bold(true)

func newTUIModel() tuiModel {
	ti := textinput.New()
	ti.Placeholder = "输入命令... (help 查看帮助)"
	ti.Focus()
	ti.CharLimit = 1024
	ti.PromptStyle = sPrompt
	ti.Prompt = "admin> "

	banner := []string{
		sBanner.Render(" ,-.  "),
		sBanner.Render(" \\_/  "),
		sBanner.Render("{|||)<") + "  " + sBanner.Bold(true).Render("iceBee") + "  admin",
		sBanner.Render(" / \\  "),
		sBanner.Render(" `-^  "),
		"",
	}

	return tuiModel{
		input: ti,
		lines: banner,
		atBot: true,
		hbOK:  true,
	}
}

func (m tuiModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	// ── 终端尺寸变化 ──
	case tea.WindowSizeMsg:
		m.w = msg.Width
		m.h = msg.Height
		// header(1) + panelLabel(1) + hint(1) + input(1) = 4 固定行
		vpH := m.h - 4
		if vpH < 1 {
			vpH = 1
		}
		// 均分: 左右各 50%，中间 1 列分隔符
		m.leftW = max(1, (m.w-1)/2)
		rightW := max(1, m.w-m.leftW-1)
		if !m.ready {
			m.vp = viewport.New(m.leftW, vpH)
			m.resultVP = viewport.New(rightW, vpH)
			m.ready = true
		} else {
			m.vp.Width = m.leftW
			m.vp.Height = vpH
			m.resultVP.Width = rightW
			m.resultVP.Height = vpH
		}
		m.refreshViewport()
		m.refreshResultPanel()

	// ── 心跳状态更新 ──
	case hbStatusMsg:
		m.hbOK = msg.ok
		m.hbNodes = msg.nodes

	// ── 结果面板刷新 ──
	case resultPanelMsg:
		if m.ready {
			m.refreshResultPanel()
		}

	// ── 追加日志行 ──
	case logMsg:
		newLines := strings.Split(strings.TrimRight(string(msg), "\n"), "\n")
		m.lines = append(m.lines, newLines...)
		if m.ready {
			m.refreshViewport()
			if m.atBot {
				m.vp.GotoBottom()
			}
		}

	// ── 键盘事件 ──
	case tea.KeyMsg:
		switch msg.Type {

		case tea.KeyCtrlC:
			return m, tea.Quit

		// PgUp/PgDn 滚动日志
		case tea.KeyPgUp:
			m.vp.HalfViewUp()
			m.atBot = m.vp.AtBottom()
			return m, nil

		case tea.KeyPgDown:
			m.vp.HalfViewDown()
			m.atBot = m.vp.AtBottom()
			return m, nil

		// Ctrl+G 跳到最新
		case tea.KeyCtrlG:
			m.vp.GotoBottom()
			m.atBot = true
			return m, nil

		// Enter 提交命令
		case tea.KeyEnter:
			raw := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			if raw == "" {
				return m, nil
			}

			// 回显命令
			m.lines = append(m.lines, sPrompt.Render("admin>")+` `+raw)

			parts := strings.SplitN(raw, " ", 2)
			cmd := strings.ToLower(parts[0])
			arg := ""
			if len(parts) > 1 {
				arg = parts[1]
			}

			// 退出
			if cmd == "quit" || cmd == "exit" || cmd == "q" {
				return m, tea.Quit
			}
			// 清屏
			if cmd == "clear" {
				m.lines = nil
				if m.ready {
					m.vp.SetContent("")
				}
				m.atBot = true
				return m, nil
			}

			// 其他命令在 goroutine 中执行，避免阻塞 TUI
			return m, func() tea.Msg {
				return logMsg(runCmd(cmd, arg))
			}
		}
	}

	// 转发给 textinput
	var tiCmd tea.Cmd
	m.input, tiCmd = m.input.Update(msg)
	cmds = append(cmds, tiCmd)

	return m, tea.Batch(cmds...)
}

func (m *tuiModel) refreshViewport() {
	content := strings.Join(m.lines, "\n")
	m.vp.SetContent(content)
}

func (m *tuiModel) refreshResultPanel() {
	hist := state.getHistory(100)
	if len(hist) == 0 {
		m.resultVP.SetContent(" " + sDim.Render("暂无回报结果"))
		return
	}
	var sb strings.Builder
	// 最新结果在最上方
	for i := len(hist) - 1; i >= 0; i-- {
		sb.WriteString(renderResultBlock(hist[i], m.resultVP.Width))
	}
	m.resultVP.SetContent(strings.TrimRight(sb.String(), "\n"))
	m.resultVP.GotoTop()
}

func (m tuiModel) View() string {
	if !m.ready {
		return "正在初始化..."
	}

	// ── Header ──
	hbIcon := "✓"
	hStyle := sHeader
	if !m.hbOK {
		hbIcon = "✗"
		hStyle = sHeaderErr
	}
	headerContent := fmt.Sprintf(
		" iceBee — Admin  %s  nodes:%-3d  %s",
		hbIcon, m.hbNodes, workerURL,
	)
	header := hStyle.Width(m.w).Render(headerContent)

	// ── 面板标签行（左=日志 vp，右=结果 vp）──
	sPanelLabel := lipgloss.NewStyle().
		Background(lipgloss.Color("235")).
		Foreground(lipgloss.Color("244"))
	leftLabel := sPanelLabel.Width(m.vp.Width).Render(" 事件日志")
	rightLabel := sPanelLabel.Width(m.resultVP.Width).Render(" 回报结果")
	panelLabels := leftLabel + sSep.Render("│") + rightLabel

	// ── 双栏内容区 ──
	vpH := m.resultVP.Height
	var sepLines []string
	for i := 0; i < vpH; i++ {
		sepLines = append(sepLines, sSep.Render("│"))
	}
	separator := strings.Join(sepLines, "\n")
	body := lipgloss.JoinHorizontal(lipgloss.Top,
		m.vp.View(),
		separator,
		m.resultVP.View(),
	)

	// ── 提示栏 ──
	hint := ""
	if !m.atBot {
		hint = sHint.Render("  ↑ PgUp/PgDn 滚动日志  Ctrl+G 跳到最新")
	}
	hintLine := hint + strings.Repeat(" ", maxInt(0, m.w-lipgloss.Width(hint)))

	// ── 输入栏 ──
	inputView := m.input.View()

	return strings.Join([]string{header, panelLabels, body, hintLine, inputView}, "\n")
}

// ── 命令处理（在 tea.Cmd goroutine 中执行）────────────────────────

func runCmd(cmd, arg string) string {
	switch cmd {
	case "help":
		return helpText

	case "body":
		b := state.getBody()
		ob, _ := json.MarshalIndent(b, "  ", "  ")
		return fmt.Sprintf("  当前 Body:\n  %s\n", string(ob))

	case "set":
		if arg == "" {
			return `  用法: set {"command":"restart","message":"说明"}`
		}
		var nb map[string]interface{}
		if err := json.Unmarshal([]byte(arg), &nb); err != nil {
			return sErr.Render("  ✗ JSON 解析失败: " + err.Error())
		}
		if _, ok := nb["command"]; !ok {
			return sWarn.Render("  ⚠ body 中必须包含 command 字段")
		}
		state.setBody(nb)
		return sOK.Render(fmt.Sprintf("  ✓ Body 已更新，下次心跳将下发: %v", nb["command"]))

	case "cmd":
		if arg == "" {
			return "  用法: cmd collect_info"
		}
		b := state.getBody()
		b["command"] = arg
		state.setBody(b)
		return sOK.Render(fmt.Sprintf("  ✓ command → %s (下次心跳下发)", arg))

	case "msg":
		if arg == "" {
			return "  用法: msg 说明文字"
		}
		b := state.getBody()
		b["message"] = arg
		state.setBody(b)
		return sOK.Render(fmt.Sprintf("  ✓ message → %s", arg))

	case "send":
		if arg == "" {
			return "  用法: send restart 请立即重启"
		}
		parts := strings.SplitN(arg, " ", 2)
		nb := map[string]interface{}{"command": parts[0], "message": ""}
		if len(parts) > 1 {
			nb["message"] = parts[1]
		}
		state.setBody(nb)
		out := sOK.Render(fmt.Sprintf("  ✓ 已设置指令: %s", parts[0]))
		if len(parts) > 1 {
			out += "\n    附言: " + parts[1]
		}
		out += "\n" + sDim.Render("    将在下次心跳下发给所有子节点")
		return out

	case "shell":
		if arg == "" {
			return "  用法: shell ls -la /tmp"
		}
		state.setBody(map[string]interface{}{"command": "shell", "shell": arg, "message": ""})
		return sOK.Render(fmt.Sprintf("  ✓ 已设置 shell 指令: %s", arg)) +
			"\n" + sDim.Render("    将在下次心跳下发给所有子节点")

	case "noop":
		state.setBody(map[string]interface{}{"command": "noop", "message": "", "config": map[string]interface{}{}})
		return sOK.Render("  ✓ 已清除指令，不再下发任务")

	case "reset":
		resp, err := doResetWorker()
		if err != nil {
			return sErr.Render(fmt.Sprintf("  ✗ 重置失败: %v", err))
		}
		state.reset()
		_ = resp
		return sOK.Render("  ✓ Worker 已重置，所有状态已清除")

	case "results", "r":
		return fmtResults()

	case "history", "rh":
		return fmtHistory()

	case "events", "e":
		return fmtEvents()

	case "status", "s":
		return fmtStatus()

	case "nodes", "n":
		return fmtNodes()

	case "task", "t":
		return fmtTask()

	default:
		return sWarn.Render(fmt.Sprintf("  未知命令: %s，输入 help 查看帮助", cmd))
	}
}

// ── 格式化输出函数 ────────────────────────────────────────────────

const sep40 = "────────────────────────────────────────"

func fmtResultInline(r NodeResult) string {
	icon := sOK.Render("✅")
	if r.Status != "completed" && r.Status != "success" {
		icon = sErr.Render("❌")
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  %s 结果回报 [%s]  %s → %s\n",
		icon, sBold.Render(r.NodeID), r.Command, r.Status))
	if r.Output != nil {
		ob, _ := json.MarshalIndent(r.Output, "     ", "  ")
		lines := strings.Split(string(ob), "\n")
		shown := len(lines)
		if shown > 12 {
			shown = 12
		}
		for _, l := range lines[:shown] {
			sb.WriteString("     " + l + "\n")
		}
		if len(lines) > 12 {
			sb.WriteString(sDim.Render(fmt.Sprintf("     ... (%d more lines)\n", len(lines)-12)))
		}
	}
	if r.Error != "" {
		sb.WriteString(sErr.Render("     错误: "+r.Error) + "\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func fmtStatus() string {
	d, err := fetchWorkerStatus()
	if err != nil {
		return sErr.Render(fmt.Sprintf("  ✗ 获取状态失败: %v", err))
	}
	var sb strings.Builder
	sb.WriteString("\n  " + sSep.Render("┌─ Worker 状态 ──"+sep40[:20]) + "\n")

	if admin, ok := d["admin"].(map[string]interface{}); ok {
		sb.WriteString(fmt.Sprintf("  │ Admin:       %s / %s\n", strVal(admin, "system"), strVal(admin, "program")))
	} else {
		sb.WriteString("  │ Admin:       " + sWarn.Render("离线") + "\n")
	}

	if task, ok := d["currentTask"].(map[string]interface{}); ok {
		sb.WriteString(fmt.Sprintf("  │ 当前任务:    %s\n", sInfo.Render(strVal(task, "command"))))
		sb.WriteString(fmt.Sprintf("  │ Task ID:     %s\n", sDim.Render(strVal(task, "taskId"))))
		dispatched := jsonStringSlice(task, "dispatchedTo")
		rc := int(jsonFloat(task, "resultCount"))
		sb.WriteString(fmt.Sprintf("  │ 已分发:      %d 节点  已回报: %d\n", len(dispatched), rc))
	} else {
		sb.WriteString("  │ 当前任务:    无\n")
	}

	sb.WriteString(fmt.Sprintf("  │ 节点数:      %d\n", int(jsonFloat(d, "nodeCount"))))
	sb.WriteString(fmt.Sprintf("  │ 待拉取结果:  %d\n", int(jsonFloat(d, "pendingResultsCount"))))

	if nodes, ok := d["nodes"].(map[string]interface{}); ok && len(nodes) > 0 {
		sb.WriteString("  │ " + sSep.Render("┌─ 节点列表:") + "\n")
		for nid, info := range nodes {
			if m, ok := info.(map[string]interface{}); ok {
				sb.WriteString(fmt.Sprintf("  │ │  %s: %s / %s\n", sBold.Render(nid), strVal(m, "system"), strVal(m, "program")))
			}
		}
		sb.WriteString("  │ " + sSep.Render("└──────────") + "\n")
	}

	if hist, ok := d["taskHistory"].([]interface{}); ok && len(hist) > 0 {
		sb.WriteString("  │ " + sSep.Render("┌─ 最近任务:") + "\n")
		limit := 5
		if len(hist) < limit {
			limit = len(hist)
		}
		for _, h := range hist[:limit] {
			if m, ok := h.(map[string]interface{}); ok {
				disp := jsonStringSlice(m, "dispatchedTo")
				resp := int(jsonFloat(m, "respondedNodes"))
				sb.WriteString(fmt.Sprintf("  │ │  %s | %s | %d/%d 回报\n",
					strVal(m, "command"), sDim.Render(strVal(m, "taskId")), resp, len(disp)))
			}
		}
		sb.WriteString("  │ " + sSep.Render("└──────────") + "\n")
	}
	sb.WriteString("  " + sSep.Render("└─"+sep40) + "\n")
	return sb.String()
}

func fmtResults() string {
	latest := state.getLatestResults()
	if len(latest) == 0 {
		return "\n  " + sDim.Render("暂无执行结果") + "\n"
	}
	var sb strings.Builder
	sb.WriteString("\n  " + sSep.Render("┌─ 最新执行结果 ──"+sep40[:18]) + "\n")
	for nid, r := range latest {
		icon := sOK.Render("✅")
		if r.Status != "completed" && r.Status != "success" {
			icon = sErr.Render("❌")
		}
		sb.WriteString(fmt.Sprintf("  │ %s [%s] %s → %s\n", icon, sBold.Render(nid), r.Command, r.Status))
		if r.Output != nil {
			ob, _ := json.MarshalIndent(r.Output, "  │     ", "  ")
			sb.WriteString("  │     " + string(ob) + "\n")
		}
		if r.Error != "" {
			sb.WriteString(sErr.Render("  │     错误: "+r.Error) + "\n")
		}
	}
	sb.WriteString("  " + sSep.Render("└─"+sep40) + "\n")
	sb.WriteString(sDim.Render(fmt.Sprintf("  总计收集: %d 个结果\n", len(state.allResults))))
	return sb.String()
}

func fmtHistory() string {
	hist := state.getHistory(20)
	if len(hist) == 0 {
		return "\n  " + sDim.Render("暂无结果历史") + "\n"
	}
	var sb strings.Builder
	sb.WriteString("\n  " + sSep.Render("┌─ 结果历史 (最近 20 条) ──"+sep40[:14]) + "\n")
	for i := len(hist) - 1; i >= 0; i-- {
		r := hist[i]
		icon := sOK.Render("✅")
		if r.Status != "completed" && r.Status != "success" {
			icon = sErr.Render("❌")
		}
		ts := sDim.Render("?")
		if r.ReportedAt > 0 {
			ts = sDim.Render(time.UnixMilli(r.ReportedAt).Format("15:04:05"))
		}
		out := ""
		if r.Output != nil {
			ob, _ := json.Marshal(r.Output)
			s := string(ob)
			if len(s) > 60 {
				s = s[:60] + "…"
			}
			out = s
		}
		sb.WriteString(fmt.Sprintf("  │ [%s] %s %s: %s → %s\n", ts, icon, sBold.Render(r.NodeID), r.Command, r.Status))
		if out != "" {
			sb.WriteString("  │       " + sDim.Render(out) + "\n")
		}
	}
	sb.WriteString("  " + sSep.Render("└─"+sep40) + "\n")
	return sb.String()
}

func fmtEvents() string {
	d, err := fetchWorkerStatus()
	if err != nil {
		return sErr.Render(fmt.Sprintf("  ✗ 获取事件失败: %v", err))
	}
	events, _ := d["recentEvents"].([]interface{})
	if len(events) == 0 {
		return "\n  " + sDim.Render("暂无事件") + "\n"
	}
	labels := map[string]string{
		"admin": "ADMIN", "child": "NODE ", "task_created": " TASK",
		"result": " RES ", "reset": "RESET",
	}
	var sb strings.Builder
	sb.WriteString("\n  " + sSep.Render("┌─ Worker 事件流 (最近 60 条) ──"+sep40[:9]) + "\n")
	for _, item := range events {
		evt, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tsMs := int64(jsonFloat(evt, "_ts"))
		ts := "?"
		if tsMs > 0 {
			ts = time.UnixMilli(tsMs).Format("15:04:05")
		}
		etype, _ := evt["type"].(string)
		label := labels[etype]
		if label == "" {
			label = etype
		}

		var msg string
		switch etype {
		case "task_created":
			msg = sInfo.Render("新任务") + " " + strVal(evt, "command") + " " + strVal(evt, "message")
		case "result":
			msg = sOK.Render(strVal(evt, "nodeId")) + " 回报 " + strVal(evt, "command") + " → " + strVal(evt, "status")
		case "admin":
			msg = strVal(evt, "program") + " on " + strVal(evt, "system")
			if n := int(jsonFloat(evt, "resultsCollected")); n > 0 {
				msg += sInfo.Render(fmt.Sprintf(" · 拉取 %d 结果", n))
			}
		case "child":
			nid := strVal(evt, "nodeId")
			extras := []string{}
			if b, _ := evt["hasResult"].(bool); b {
				extras = append(extras, sOK.Render("回报"))
			}
			if b, _ := evt["taskDispatched"].(bool); b {
				extras = append(extras, sInfo.Render("下发"))
			}
			msg = sBold.Render(nid) + " · " + strVal(evt, "program") + " on " + strVal(evt, "system")
			if len(extras) > 0 {
				msg += " (" + strings.Join(extras, ", ") + ")"
			}
		case "reset":
			msg = sWarn.Render(strVal(evt, "message"))
		default:
			b, _ := json.Marshal(evt)
			msg = sDim.Render(string(b))
		}
		sb.WriteString(fmt.Sprintf("  │ [%s] %s  %s\n", sDim.Render(ts), sDim.Render(label), msg))
	}
	sb.WriteString("  " + sSep.Render("└─"+sep40) + "\n")
	return sb.String()
}

func fmtNodes() string {
	d, err := fetchWorkerStatus()
	if err != nil {
		return sErr.Render(fmt.Sprintf("  ✗ 获取节点失败: %v", err))
	}
	nodes, _ := d["nodes"].(map[string]interface{})
	if len(nodes) == 0 {
		return "\n  " + sDim.Render("暂无在线节点") + "\n"
	}
	var sb strings.Builder
	sb.WriteString("\n  " + sSep.Render("┌─ 在线节点 ──"+sep40[:27]) + "\n")
	nowMs := time.Now().UnixMilli()
	for nid, info := range nodes {
		m, ok := info.(map[string]interface{})
		if !ok {
			continue
		}
		age := float64(nowMs-int64(jsonFloat(m, "receivedAt"))) / 1000
		dot := sOK.Render("●")
		if age >= 60 {
			dot = sErr.Render("●")
		} else if age >= 15 {
			dot = sWarn.Render("●")
		}
		taskID := strVal(m, "currentTaskId")
		if taskID == "" {
			taskID = sDim.Render("无")
		}
		sb.WriteString(fmt.Sprintf("  │ %s %s\n", dot, sBold.Render(nid)))
		sb.WriteString(fmt.Sprintf("  │    系统: %s | 程序: %s\n", strVal(m, "system"), strVal(m, "program")))
		sb.WriteString(fmt.Sprintf("  │    任务: %s | 最后心跳: %s\n", taskID, sDim.Render(fmt.Sprintf("%ds 前", int(age)))))
		// 权限信息
		if perms, ok := m["perms"].(map[string]interface{}); ok {
			username, _ := perms["username"].(string)
			uid := int(jsonFloat(perms, "uid"))
			isRoot, _ := perms["is_root"].(bool)
			groups := ""
			if gs, ok := perms["groups"].([]interface{}); ok && len(gs) > 0 {
				gNames := make([]string, 0, len(gs))
				for _, g := range gs {
					if s, ok := g.(string); ok {
						gNames = append(gNames, s)
					}
				}
				if len(gNames) > 4 {
					gNames = gNames[:4]
				}
				groups = " (" + strings.Join(gNames, ",") + ")"
			}
			permLine := fmt.Sprintf("%s uid=%d%s", username, uid, groups)
			if isRoot {
				sb.WriteString(fmt.Sprintf("  │    权限: %s\n", sErr.Render("⚠ root — "+permLine)))
			} else {
				sb.WriteString(fmt.Sprintf("  │    权限: %s\n", sDim.Render(permLine)))
			}
		}
	}
	sb.WriteString("  " + sSep.Render("└─"+sep40) + "\n")
	return sb.String()
}

func fmtTask() string {
	hb := state.getHeartbeatInfo()
	taskID, _ := hb["current_task_id"].(string)
	if taskID == "" {
		return "\n  " + sDim.Render("当前无活跃任务") + "\n"
	}
	var sb strings.Builder
	sb.WriteString("\n  " + sSep.Render("┌─ 当前任务 ──"+sep40[:27]) + "\n")
	sb.WriteString(fmt.Sprintf("  │ Task ID:    %s\n", sDim.Render(taskID)))
	body := state.getBody()
	sb.WriteString(fmt.Sprintf("  │ Command:    %s\n", sInfo.Render(strVal(body, "command"))))
	var dispatched []string
	if raw, ok := hb["dispatched_to"].([]string); ok {
		dispatched = raw
	}
	sb.WriteString(fmt.Sprintf("  │ 已分发到:   %d 个节点\n", len(dispatched)))
	for _, nid := range dispatched {
		sb.WriteString(fmt.Sprintf("  │   → %s\n", nid))
	}
	ob, _ := json.MarshalIndent(body, "  │   ", "  ")
	sb.WriteString("  │ Body:\n  │   " + string(ob) + "\n")
	sb.WriteString("  " + sSep.Render("└─"+sep40) + "\n")
	return sb.String()
}

// ── 结果面板渲染 ──────────────────────────────────────────────────

// renderResultBlock 将单条 NodeResult 渲染为适合左侧面板阅读的文本。
func renderResultBlock(r NodeResult, w int) string {
	if w < 12 {
		w = 12
	}
	inner := w - 2

	var sb strings.Builder

	// 状态图标 + 节点名 + 命令 + 时间
	icon := sOK.Render("✓")
	if r.Status != "completed" && r.Status != "success" {
		icon = sErr.Render("✗")
	}
	ts := "?"
	if r.ReportedAt > 0 {
		ts = time.UnixMilli(r.ReportedAt).Format("15:04:05")
	}
	nodeStr := sBold.Render(resultTrunc(r.NodeID, inner-len(ts)-2))
	sb.WriteString(fmt.Sprintf(" %s %s  %s\n", icon, nodeStr, sDim.Render(ts)))
	sb.WriteString(fmt.Sprintf(" %s\n", sDim.Render(resultTrunc(r.Command, inner))))

	// 错误信息
	if r.Error != "" {
		sb.WriteString(" " + sErr.Render(resultTrunc("✗ "+r.Error, inner)) + "\n")
	}

	// 输出内容
	if r.Output != nil {
		sb.WriteString(renderOutputBlock(r.Command, r.Output, w))
	}

	// 分隔线
	sb.WriteString(" " + sDim.Render(strings.Repeat("─", min(inner, w-2))) + "\n")
	return sb.String()
}

// renderOutputBlock 根据命令类型选择最适合的输出格式。
func renderOutputBlock(cmd string, output interface{}, w int) string {
	m, isMap := output.(map[string]interface{})
	switch {
	case isMap && cmd == "shell":
		return renderShellOutput(m, w)
	case isMap:
		return renderKVOutput(m, w)
	default:
		if s, ok := output.(string); ok {
			return renderTextLines(s, w, 15)
		}
		b, _ := json.MarshalIndent(output, "  ", "  ")
		return renderTextLines(string(b), w, 15)
	}
}

// renderShellOutput 渲染 shell 命令的执行结果。
func renderShellOutput(m map[string]interface{}, w int) string {
	var sb strings.Builder
	inner := w - 3

	if shellCmd, _ := m["command"].(string); shellCmd != "" {
		sb.WriteString(" " + sDim.Render("$ ") + resultTrunc(shellCmd, inner-2) + "\n")
	}

	rc := int(jsonFloat(m, "returncode"))
	rcStyle := sOK
	if rc != 0 {
		rcStyle = sErr
	}
	sb.WriteString(" " + rcStyle.Render(fmt.Sprintf("exit %d", rc)) + "\n")

	if stdout, _ := m["stdout"].(string); stdout != "" {
		stdout = strings.TrimRight(stdout, "\n\r")
		lines := strings.Split(stdout, "\n")
		shown := min(len(lines), 20)
		for _, line := range lines[:shown] {
			sb.WriteString("  " + resultTrunc(line, inner) + "\n")
		}
		if len(lines) > shown {
			sb.WriteString("  " + sDim.Render(fmt.Sprintf("… (%d more lines)", len(lines)-shown)) + "\n")
		}
	}
	if stderr, _ := m["stderr"].(string); stderr != "" && strings.TrimSpace(stderr) != "" {
		sb.WriteString(" " + sWarn.Render("stderr:") + "\n")
		stderr = strings.TrimRight(stderr, "\n\r")
		for _, line := range strings.Split(stderr, "\n") {
			sb.WriteString("  " + sWarn.Render(resultTrunc(line, inner)) + "\n")
		}
	}
	return sb.String()
}

// renderKVOutput 以对齐的键值对格式渲染 map 输出。
func renderKVOutput(m map[string]interface{}, w int) string {
	var sb strings.Builder
	inner := w - 3
	keyW := 12

	for _, kv := range resultSortedKV(m) {
		k, v := kv[0], kv[1]
		vTrunc := resultTrunc(v, inner-keyW-1)
		sb.WriteString(fmt.Sprintf("  %-*s %s\n", keyW, resultTrunc(k, keyW), sDim.Render(vTrunc)))
	}
	return sb.String()
}

// renderTextLines 渲染纯文本（多行截断）。
func renderTextLines(s string, w, maxLines int) string {
	var sb strings.Builder
	inner := w - 3
	s = strings.TrimRight(s, "\n\r")
	lines := strings.Split(s, "\n")
	shown := min(len(lines), maxLines)
	for _, line := range lines[:shown] {
		sb.WriteString("  " + resultTrunc(line, inner) + "\n")
	}
	if len(lines) > shown {
		sb.WriteString("  " + sDim.Render(fmt.Sprintf("… (%d more lines)", len(lines)-shown)) + "\n")
	}
	return sb.String()
}

// resultSortedKV 返回按优先级 + 字母序排列的键值对。
func resultSortedKV(m map[string]interface{}) [][2]string {
	priority := []string{
		"hostname", "system", "arch", "cpu_count", "go_version", "pid", "cwd",
		"uptime_seconds", "tasks_executed", "pong", "nodeId",
	}
	seen := make(map[string]bool)
	var result [][2]string
	for _, k := range priority {
		if v, ok := m[k]; ok {
			result = append(result, [2]string{k, resultFmtVal(k, v)})
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		result = append(result, [2]string{k, resultFmtVal(k, m[k])})
	}
	return result
}

// resultFmtVal 将值格式化为可读字符串。
func resultFmtVal(key string, v interface{}) string {
	switch val := v.(type) {
	case float64:
		if key == "uptime_seconds" {
			return time.Duration(val * float64(time.Second)).Round(time.Second).String()
		}
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
		return val
	case nil:
		return "(nil)"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// resultTrunc 截断字符串到最大长度，超出时用 … 替换。
func resultTrunc(s string, max int) string {
	if max <= 0 {
		return ""
	}
	// 简单按字节截断（终端宽度估算用）
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return s[:max-1] + "…"
}

// ── 帮助文本 ──────────────────────────────────────────────────────

const helpText = `
  ┌─ iceBee — Admin 控制台 ────────────────────────────────────────────────┐
  │  指令下发:                                                             │
  │    cmd <command>        设置 command 字段并下发                        │
  │    msg <message>        设置 message 字段                              │
  │    set <json>           设置完整 body (JSON 格式)                      │
  │    send <cmd> [msg]     快速发送: send restart 请重启                  │
  │    shell <命令>         快速 shell: shell ls -la /tmp                  │
  │    noop                 清除当前指令 (停止下发)                        │
  │    reset                清除 Worker 所有状态 (恢复初始)               │
  │  结果查看:                                                             │
  │    results / r          查看所有节点最新执行结果                       │
  │    history / rh         查看结果历史                                   │
  │    events / e           查看 Worker 实时事件流                         │
  │    body                 查看当前 body                                  │
  │  状态:                                                                 │
  │    status / s           查看 Worker 完整状态                           │
  │    nodes / n            查看在线节点                                   │
  │    task / t             查看当前任务信息                               │
  │  其他:                                                                 │
  │    help / clear / quit                                                 │
  │  滚动: PgUp/PgDn 翻页  Ctrl+G 跳到最新                               │
  └────────────────────────────────────────────────────────────────────────┘`

// ── JSON 工具 ─────────────────────────────────────────────────────

func strVal(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func jsonFloat(m map[string]interface{}, key string) float64 {
	v, _ := m[key].(float64)
	return v
}

func jsonStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── 入口 ──────────────────────────────────────────────────────────

func main() {
	flag.StringVar(&workerURL, "url", workerURL, "Worker URL")
	flag.StringVar(&programName, "program", programName, "程序名")
	flag.IntVar(&hbInterval, "interval", hbInterval, "心跳间隔(秒)")
	flag.IntVar(&apiPort, "port", apiPort, "本地 API 端口")
	flag.Parse()

	workerURL = strings.TrimRight(workerURL, "/")

	// 加载或生成 Ed25519 签名密钥
	keyPath := filepath.Join(os.Getenv("HOME"), ".icebee", "admin.key")
	if err := loadOrGenKey(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法加载密钥 (%v)，指令将不签名\n", err)
	} else {
		fmt.Printf("Admin 公钥: %s\n", adminPubHex)
	}

	startAPIServer(apiPort)

	prog = tea.NewProgram(
		newTUIModel(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	go heartbeatLoop()

	if _, err := prog.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "TUI error:", err)
		os.Exit(1)
	}
}
