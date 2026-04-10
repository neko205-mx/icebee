/**
 * Cloudflare Worker — iceBee
 *
 * 完整双向指令-结果管道：
 *   Admin 发指令(body) → Worker 暂存 → Node 心跳拉取指令
 *   → Node 执行 → Node 心跳上报结果 → Worker 暂存
 *   → Admin 心跳拉取结果 → Admin 展示
 *
 * Routes:
 *   POST /heartbeat/admin   — Admin 心跳 (下发指令 + 拉取执行结果)
 *   POST /heartbeat          — Node 心跳 (上报结果 + 拉取新指令)
 *   GET  /api/status          — 全量状态 JSON
 *   POST /api/reset           — 清空所有状态
 *   GET  /                    — 实时仪表盘
 *
 * 架构说明:
 *   使用 Cloudflare KV 持久化状态，解决多 isolate 间内存隔离问题。
 *   写优化: 只在状态真正变化时才写 KV（新任务/上报结果/收集结果），
 *   普通心跳只读，大幅减少写次数，适配免费版 1000次/天限额。
 */

const KV_KEY = "hub_state";
const EVENT_LOG_MAX = 300;

// ─── 默认状态 ────────────────────────────────────────────────────────

function defaultState() {
  return {
    adminLastSeen: null,
    adminBody: null,
    childNodes: {},
    currentTask: null,
    nodeResults: {},      // "nodeId:taskId" → result
    pendingResults: [],   // 待 admin 拉取
    taskHistory: [],
    eventLog: [],
  };
}

// ─── KV 读写 ─────────────────────────────────────────────────────────

async function getState(env) {
  try {
    const raw = await env.KV.get(KV_KEY);
    if (!raw) return defaultState();
    return JSON.parse(raw);
  } catch {
    return defaultState();
  }
}

async function putState(env, state) {
  await env.KV.put(KV_KEY, JSON.stringify(state));
}

// ─── 工具 ────────────────────────────────────────────────────────────

function pushEvent(state, evt) {
  evt._ts = Date.now();
  state.eventLog.push(evt);
  if (state.eventLog.length > EVENT_LOG_MAX)
    state.eventLog = state.eventLog.slice(-Math.floor(EVENT_LOG_MAX * 0.8));
}

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

// ─── Router ──────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers: corsHeaders() });

    try {
      if (request.method === "POST" && path === "/heartbeat/admin")
        return await handleAdminHeartbeat(request, env);
      if (request.method === "POST" && path === "/heartbeat")
        return await handleChildHeartbeat(request, env);
      if (request.method === "GET" && path === "/api/status")
        return await handleStatus(env);
      if (request.method === "POST" && path === "/api/reset")
        return await handleReset(env);
      if (request.method === "GET" && (path === "/" || path === "/dashboard"))
        return handleDashboard();
      return json({ error: "Not Found" }, 404);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },
};

// ─── Admin Heartbeat ─────────────────────────────────────────────────

async function verifyAdminSig(pubKeyHex, sigHex, bodyBytes) {
  try {
    const pubKeyBytes = hexToBytes(pubKeyHex);
    const sigBytes = hexToBytes(sigHex);
    const digest = await crypto.subtle.digest("SHA-256", bodyBytes);
    const pubKey = await crypto.subtle.importKey(
      "raw", pubKeyBytes,
      { name: "NODE-ED25519", namedCurve: "Ed25519" },
      false, ["verify"]
    );
    return await crypto.subtle.verify("NODE-ED25519", pubKey, sigBytes, digest);
  } catch {
    return false;
  }
}

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++)
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

async function handleAdminHeartbeat(request, env) {
  const bodyBytes = await request.arrayBuffer();
  const data = JSON.parse(new TextDecoder().decode(bodyBytes));
  const { system, timestamp, program, body, pubKey } = data;

  if (!system || !timestamp || !program)
    return json({ error: "Missing required fields: system, timestamp, program" }, 400);

  const state = await getState(env);
  let changed = false;

  // ── Admin 认证（TOFU：首次连接锁定公钥，后续验签）──
  if (!state.adminPubKey) {
    // 首次连接：接受并锁定公钥
    if (!pubKey || typeof pubKey !== 'string' || pubKey.length !== 64)
      return json({ error: "首次连接必须提供有效公钥（64字符 hex）" }, 400);
    state.adminPubKey = pubKey;
    pushEvent(state, { type: "admin_key_locked", pubKey: pubKey.slice(0, 16) + "…" });
    changed = true;
  } else {
    // 已锁定：验证签名
    const sigHex = request.headers.get("X-Admin-Sig");
    if (!sigHex || !await verifyAdminSig(state.adminPubKey, sigHex, bodyBytes))
      return json({ error: "Unauthorized: invalid or missing admin signature" }, 401);
  }

  // ── 更新 adminLastSeen（仅记录，不触发写）──
  const adminInfo = { system, timestamp, program, receivedAt: Date.now() };

  // ── 新指令检测 ──
  let newTaskId = null;
  if (body && body.command && body.command !== "noop" && body.command !== "default") {
    const stableId = body._dispatchId
      ? "task-" + body._dispatchId
      : "task-" + simpleHash(JSON.stringify(body));

    if (!state.currentTask || state.currentTask.taskId !== stableId) {
      // 归档旧任务
      if (state.currentTask) {
        const results = {};
        for (const [key, r] of Object.entries(state.nodeResults)) {
          if (r.taskId === state.currentTask.taskId) results[r.nodeId] = r;
        }
        state.taskHistory.push({
          ...state.currentTask,
          results,
          completedAt: Date.now(),
          respondedNodes: Object.keys(results).length,
        });
        if (state.taskHistory.length > 50) state.taskHistory.shift();
      }

      state.currentTask = {
        taskId: stableId,
        command: body.command,
        body,
        createdAt: Date.now(),
        dispatchedTo: [],
      };
      state.adminBody = body;
      state.adminLastSeen = adminInfo;
      newTaskId = stableId;

      pushEvent(state, {
        type: "task_created",
        taskId: stableId,
        command: body.command,
        message: body.message || "",
      });
      pushEvent(state, { type: "admin", system, program, timestamp, hasBody: true, resultsCollected: 0 });
      changed = true;
    }
  }

  // ── 收集结果返回给 admin ──
  const collected = [...state.pendingResults];
  if (collected.length > 0) {
    state.pendingResults = [];
    state.adminLastSeen = adminInfo;
    if (!changed) {  // 如果上面没有因为新任务写入，这里因为收集结果也要写
      pushEvent(state, {
        type: "admin", system, program, timestamp,
        hasBody: !!body, resultsCollected: collected.length,
      });
    }
    changed = true;
  }

  // ── 周期性更新 adminLastSeen（每 60s 写一次，保持在线状态新鲜）──
  if (!changed) {
    const now = Date.now();
    const lastUpdate = state.adminLastSeen ? state.adminLastSeen.receivedAt : 0;
    if (now - lastUpdate > 60_000) {
      state.adminLastSeen = adminInfo;
      changed = true;
    }
  }

  // ── 如果有变化才写 KV ──
  if (changed) {
    if (!state.adminLastSeen) state.adminLastSeen = adminInfo;
    await putState(env, state);
  }

  return json({
    status: "ok",
    message: "Admin heartbeat received.",
    taskId: newTaskId || (state.currentTask ? state.currentTask.taskId : null),
    currentCommand: state.currentTask ? state.currentTask.command : null,
    connectedNodes: Object.keys(state.childNodes).length,
    nodeResults: collected,
    taskDispatchedTo: state.currentTask ? state.currentTask.dispatchedTo : [],
  });
}

// ─── Child Node Heartbeat ────────────────────────────────────────────

async function handleChildHeartbeat(request, env) {
  const data = await request.json();
  const { system, timestamp, program, nodeId, taskResult, stunAddr, relayResults, perms } = data;

  if (!system || !timestamp || !program)
    return json({ error: "Missing required fields: system, timestamp, program" }, 400);

  const state = await getState(env);
  let changed = false;

  const id = nodeId || `${system}-${program}-${simpleHash(request.headers.get("cf-connecting-ip") || "anon")}`;

  // ── 接收 P2P 中继结果（由接收到任务的节点代其他 peer 上报）──
  if (Array.isArray(relayResults) && relayResults.length > 0) {
    for (const rr of relayResults) {
      if (!rr.nodeId || !rr.taskId) continue;
      const result = {
        nodeId: rr.nodeId,
        taskId: rr.taskId,
        status: rr.status || "completed",
        output: rr.output,
        error: rr.error || null,
        command: rr.command || null,
        reportedAt: Date.now(),
        relayedBy: id,
      };
      state.nodeResults[rr.nodeId + ":" + rr.taskId] = result;
      state.pendingResults.push(result);
      pushEvent(state, {
        type: "result", nodeId: rr.nodeId,
        taskId: rr.taskId, command: rr.command || "?",
        status: rr.status || "completed", relayedBy: id,
      });
      changed = true;
    }
  }

  // ── 接收执行结果 ──
  let resultAck = null;
  if (taskResult && taskResult.taskId) {
    const result = {
      nodeId: id,
      taskId: taskResult.taskId,
      status: taskResult.status || "completed",
      output: taskResult.output,
      error: taskResult.error || null,
      command: taskResult.command || null,
      reportedAt: Date.now(),
    };
    state.nodeResults[id + ":" + taskResult.taskId] = result;
    state.pendingResults.push(result);
    resultAck = { taskId: taskResult.taskId, received: true };

    // 更新 childNodes（上报结果时顺带更新）
    state.childNodes[id] = {
      ...(state.childNodes[id] || {}),
      system, timestamp, program, nodeId: id,
      receivedAt: Date.now(),
      currentTaskId: state.currentTask ? state.currentTask.taskId : null,
      ...(stunAddr ? { stunAddr } : {}),
        ...(perms ? { perms } : {}),
    };

    pushEvent(state, {
      type: "result", nodeId: id,
      taskId: taskResult.taskId,
      command: taskResult.command || "?",
      status: taskResult.status || "completed",
    });
    changed = true;
  }

  // ── 下发任务 ──
  let taskToDispatch = null;
  if (state.currentTask) {
    const alreadyReported = !!state.nodeResults[id + ":" + state.currentTask.taskId];
    if (!alreadyReported) {
      taskToDispatch = {
        taskId: state.currentTask.taskId,
        command: state.currentTask.body.command,
        body: state.currentTask.body,
        createdAt: state.currentTask.createdAt,
      };
      // 首次分发到该节点时更新 dispatchedTo
      if (!state.currentTask.dispatchedTo.includes(id)) {
        state.currentTask.dispatchedTo.push(id);
        state.childNodes[id] = {
          ...(state.childNodes[id] || {}),
          system, timestamp, program, nodeId: id,
          receivedAt: Date.now(),
          currentTaskId: state.currentTask.taskId,
          ...(stunAddr ? { stunAddr } : {}),
        ...(perms ? { perms } : {}),
        };
        pushEvent(state, {
          type: "child", nodeId: id, system, program, timestamp,
          hasResult: !!taskResult, taskDispatched: true,
        });
        changed = true;
      }
    }
  }

  // ── 周期性更新节点活跃时间（每 60s 写一次，保持在线状态新鲜）──
  if (!changed) {
    const now = Date.now();
    const existing = state.childNodes[id];
    if (!existing || now - (existing.receivedAt || 0) > 60_000) {
      state.childNodes[id] = {
        ...(existing || {}),
        system, timestamp, program, nodeId: id,
        receivedAt: now,
        currentTaskId: state.currentTask ? state.currentTask.taskId : null,
        ...(stunAddr ? { stunAddr } : {}),
        ...(perms ? { perms } : {}),
      };
      changed = true;
    }
  }

  // ── 如果有变化才写 KV ──
  if (changed) {
    await putState(env, state);
  }

  // 返回其他节点的 P2P 地址（供打洞使用）
  const peers = Object.entries(state.childNodes)
    .filter(([pid, n]) => pid !== id && n.stunAddr)
    .map(([pid, n]) => ({ nodeId: pid, addr: n.stunAddr }));

  return json({
    status: "ok",
    message: taskToDispatch ? "Task dispatched." : "Heartbeat acknowledged.",
    nodeId: id,
    task: taskToDispatch,
    resultAck,
    adminLastSeen: state.adminLastSeen ? state.adminLastSeen.timestamp : null,
    peers,
    adminPubKey: state.adminPubKey || null,
  });
}

// ─── Status API ──────────────────────────────────────────────────────

async function handleStatus(env) {
  const state = await getState(env);
  const currentResults = {};
  if (state.currentTask) {
    for (const [, val] of Object.entries(state.nodeResults)) {
      if (val.taskId === state.currentTask.taskId)
        currentResults[val.nodeId] = val;
    }
  }

  return json({
    admin: state.adminLastSeen,
    adminBody: state.adminBody,
    currentTask: state.currentTask ? {
      ...state.currentTask,
      results: currentResults,
      resultCount: Object.keys(currentResults).length,
    } : null,
    pendingResultsCount: state.pendingResults.length,
    nodes: state.childNodes,
    nodeCount: Object.keys(state.childNodes).length,
    taskHistory: state.taskHistory.slice(-20).reverse(),
    recentEvents: state.eventLog.slice(-60).reverse(),
    adminPubKey: state.adminPubKey || null,
  });
}

// ─── Reset API ───────────────────────────────────────────────────────

async function handleReset(env) {
  const state = defaultState();
  pushEvent(state, { type: "reset", message: "All state cleared" });
  await putState(env, state);
  return json({ status: "ok", message: "All state has been reset." });
}

// ─── Dashboard ───────────────────────────────────────────────────────

function handleDashboard() {
  const html = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>iceBee</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'SF Mono',Consolas,monospace;background:#0d1117;color:#c9d1d9;font-size:13px;line-height:1.6}
  header{background:#161b22;border-bottom:1px solid #30363d;padding:12px 20px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:10}
  header h1{font-size:15px;font-weight:600;color:#e6edf3;letter-spacing:.5px}
  .badge{font-size:11px;padding:2px 8px;border-radius:12px;font-weight:600}
  .badge-ok{background:#1a4a1a;color:#3fb950}
  .badge-err{background:#4a1a1a;color:#f85149}
  .badge-dim{background:#21262d;color:#8b949e}
  .dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
  .dot-ok{background:#3fb950}.dot-warn{background:#d29922}.dot-err{background:#f85149}
  #refresh-indicator{margin-left:auto;font-size:11px;color:#484f58}
  main{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 20px;max-width:1400px;margin:0 auto}
  @media(max-width:900px){main{grid-template-columns:1fr}}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
  .card-full{grid-column:1/-1}
  .card-header{padding:10px 14px;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between}
  .card-header h2{font-size:12px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.8px}
  .card-body{padding:14px}
  table{width:100%;border-collapse:collapse}
  th{font-size:11px;color:#484f58;text-transform:uppercase;letter-spacing:.6px;padding:4px 8px;text-align:left;border-bottom:1px solid #21262d}
  td{padding:6px 8px;border-bottom:1px solid #0d1117;vertical-align:top;word-break:break-all}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#1c2128}
  .kv{display:flex;gap:8px;padding:4px 0}.kv+.kv{border-top:1px solid #21262d}
  .kv-k{color:#484f58;min-width:110px;flex-shrink:0}.kv-v{color:#c9d1d9;word-break:break-all}
  #events-log{max-height:280px;overflow-y:auto;font-size:12px}
  .ev{display:flex;gap:10px;padding:4px 0;border-bottom:1px solid #0d1117}
  .ev:last-child{border:none}
  .ev-ts{color:#484f58;white-space:nowrap;flex-shrink:0}
  .ev-label{width:52px;flex-shrink:0;text-align:right}
  .ev-msg{word-break:break-word}
  .label-admin{color:#58a6ff}.label-node{color:#8b949e}.label-task{color:#d29922}.label-result{color:#3fb950}.label-reset{color:#f85149}
  pre{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:300px;overflow-y:auto}
  .empty{color:#484f58;font-style:italic;padding:8px 0}
  .tag{display:inline-block;font-size:11px;padding:1px 6px;border-radius:4px;background:#21262d;color:#8b949e;margin:1px}
</style>
</head>
<body>
<header>
  <h1>⬡ iceBee</h1>
  <span id="admin-badge" class="badge badge-dim">Admin 离线</span>
  <span id="nodes-badge" class="badge badge-dim">0 节点</span>
  <span id="task-badge" class="badge badge-dim">无任务</span>
  <span id="pubkey-badge" style="font-size:11px;color:#484f58;font-family:monospace" title="Admin Ed25519 公钥"></span>
  <span id="refresh-indicator">刷新中…</span>
</header>
<main>
  <div class="card">
    <div class="card-header"><h2>在线节点</h2><span id="node-count" class="badge badge-dim">0</span></div>
    <div class="card-body" id="nodes-body"><p class="empty">暂无节点</p></div>
  </div>
  <div class="card">
    <div class="card-header"><h2>当前任务</h2><span id="task-status-badge" class="badge badge-dim">无</span></div>
    <div class="card-body" id="task-body"><p class="empty">无活跃任务</p></div>
  </div>
  <div class="card card-full">
    <div class="card-header"><h2>节点执行结果</h2><span id="result-count" class="badge badge-dim">0</span></div>
    <div class="card-body" id="results-body"><p class="empty">暂无结果</p></div>
  </div>
  <div class="card">
    <div class="card-header"><h2>P2P 节点</h2><span id="p2p-count" class="badge badge-dim">0</span></div>
    <div class="card-body" id="p2p-body"><p class="empty">暂无 P2P 节点</p></div>
  </div>
  <div class="card">
    <div class="card-header"><h2>任务历史</h2></div>
    <div class="card-body" id="history-body"><p class="empty">暂无历史</p></div>
  </div>
  <div class="card card-full">
    <div class="card-header"><h2>事件流</h2></div>
    <div id="events-log" class="card-body"><p class="empty">暂无事件</p></div>
  </div>
</main>
<script>
const REFRESH_MS = 3000;
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const ago = ms => { const s=Math.floor((Date.now()-ms)/1000); return s<5?'刚刚':s<60?s+'s前':Math.floor(s/60)+'m前'; };
const ts  = ms => ms ? new Date(ms).toLocaleTimeString('zh',{hour12:false}) : '?';
const labelClass = t => ({'admin':'label-admin','child':'label-node','task_created':'label-task','result':'label-result','reset':'label-reset'}[t]||'label-node');
const labelText  = t => ({'admin':'ADMIN','child':'NODE','task_created':'TASK','result':'RESULT','reset':'RESET'}[t]||t.toUpperCase());

function dotFor(ms) {
  const s=(Date.now()-ms)/1000;
  return s<15?'<span class="dot dot-ok"></span>':s<60?'<span class="dot dot-warn"></span>':'<span class="dot dot-err"></span>';
}

function renderNodes(nodes) {
  const entries = Object.entries(nodes||{});
  $('node-count').textContent=entries.length+' 节点';
  $('node-count').className='badge '+(entries.length?'badge-ok':'badge-dim');
  $('nodes-badge').textContent=entries.length+' 节点';
  $('nodes-badge').className='badge '+(entries.length?'badge-ok':'badge-dim');
  if(!entries.length){$('nodes-body').innerHTML='<p class="empty">暂无节点</p>';return;}
  $('nodes-body').innerHTML='<table><thead><tr><th>节点 ID</th><th>系统</th><th>权限</th><th>最后活动</th></tr></thead><tbody>'+
    entries.map(([id,n])=>{
      const p=n.perms||{};
      const permStr=p.is_root
        ?'<span style="color:#f85149;font-weight:600">⚠ root</span>'
        :'<span style="color:#8b949e">'+esc(p.username||'?')+'</span>'
         +' <span style="color:#484f58">uid='+( p.uid!=null?p.uid:'?')
         +((p.groups||[]).length?' ('+esc((p.groups||[]).slice(0,3).join(', '))+'...)':'')+'</span>';
      return '<tr>'
        +'<td>'+dotFor(n.receivedAt||0)+'<b>'+esc(id)+'</b></td>'
        +'<td>'+esc(n.system||'')+'</td>'
        +'<td>'+permStr+'</td>'
        +'<td>'+ago(n.receivedAt)+'</td>'
        +'</tr>';
    }).join('')+'</tbody></table>';
}

function renderTask(task,pendingCount) {
  if(!task){
    $('task-body').innerHTML='<p class="empty">无活跃任务</p>';
    $('task-status-badge').textContent='无';$('task-status-badge').className='badge badge-dim';
    $('task-badge').textContent='无任务';$('task-badge').className='badge badge-dim';return;
  }
  const dispatched=task.dispatchedTo||[],rc=task.resultCount||0;
  $('task-status-badge').textContent=rc+'/'+dispatched.length+' 回报';
  $('task-status-badge').className='badge '+(rc>=dispatched.length&&dispatched.length?'badge-ok':'badge-err');
  $('task-badge').textContent=task.command;$('task-badge').className='badge badge-err';
  const body=task.body||{};
  let html=\`
    <div class="kv"><span class="kv-k">Task ID</span><span class="kv-v" style="color:#484f58">\${esc(task.taskId)}</span></div>
    <div class="kv"><span class="kv-k">命令</span><span class="kv-v" style="color:#d29922;font-weight:600">\${esc(task.command)}</span></div>
    <div class="kv"><span class="kv-k">创建时间</span><span class="kv-v">\${ts(task.createdAt)}</span></div>
    <div class="kv"><span class="kv-k">已分发</span><span class="kv-v">\${dispatched.map(n=>'<span class="tag">'+esc(n)+'</span>').join('')||'—'}</span></div>
    <div class="kv"><span class="kv-k">已回报</span><span class="kv-v">\${rc} / \${dispatched.length}</span></div>
    <div class="kv"><span class="kv-k">待拉取</span><span class="kv-v">\${pendingCount}</span></div>\`;
  if(body.shell) html+=\`<div class="kv"><span class="kv-k">Shell</span><span class="kv-v" style="color:#79c0ff">\${esc(body.shell)}</span></div>\`;
  if(body.message) html+=\`<div class="kv"><span class="kv-k">Message</span><span class="kv-v">\${esc(body.message)}</span></div>\`;
  $('task-body').innerHTML=html;
}

function renderResults(task) {
  const results=(task&&task.results)?Object.entries(task.results):[];
  $('result-count').textContent=results.length+' 条';
  $('result-count').className='badge '+(results.length?'badge-ok':'badge-dim');
  if(!results.length){$('results-body').innerHTML='<p class="empty">暂无结果</p>';return;}
  $('results-body').innerHTML=results.map(([nodeId,r])=>{
    const ok=r.status==='completed'||r.status==='success';
    let out='';
    if(r.output!=null){const s=typeof r.output==='object'?JSON.stringify(r.output,null,2):String(r.output);out=\`<pre>\${esc(s)}</pre>\`;}
    if(r.error) out+=\`<p style="color:#f85149;margin-top:6px">错误: \${esc(r.error)}</p>\`;
    return \`<div style="margin-bottom:14px"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
      <span>\${ok?'✅':'❌'}</span><b style="color:#e6edf3">\${esc(nodeId)}</b>
      <span class="badge \${ok?'badge-ok':'badge-err'}">\${esc(r.status)}</span>
      <span style="color:#484f58;font-size:11px">\${ts(r.reportedAt)}</span></div>\${out}</div>\`;
  }).join('');
}

function renderP2P(nodes) {
  const entries = Object.entries(nodes||{}).filter(([,n])=>n.stunAddr);
  $('p2p-count').textContent = entries.length + ' 节点';
  $('p2p-count').className = 'badge ' + (entries.length ? 'badge-ok' : 'badge-dim');
  if (!entries.length) { $('p2p-body').innerHTML = '<p class="empty">暂无 P2P 节点（需开启 -p2p）</p>'; return; }
  $('p2p-body').innerHTML = '<table><thead><tr><th>节点 ID</th><th>公网地址</th><th>最后活动</th></tr></thead><tbody>' +
    entries.map(([id, n]) => '<tr>' +
      '<td>' + dotFor(n.receivedAt||0) + '<b>' + esc(id) + '</b></td>' +
      '<td style="color:#79c0ff;font-family:monospace">' + esc(n.stunAddr) + '</td>' +
      '<td>' + ago(n.receivedAt) + '</td>' +
    '</tr>').join('') + '</tbody></table>';
}

function renderHistory(history) {
  if(!history||!history.length){$('history-body').innerHTML='<p class="empty">暂无历史</p>';return;}
  $('history-body').innerHTML='<table><thead><tr><th>命令</th><th>分发</th><th>回报</th><th>完成时间</th></tr></thead><tbody>'+
    history.slice(0,20).map(h=>\`<tr><td style="color:#d29922">\${esc(h.command)}</td><td>\${(h.dispatchedTo||[]).length}</td><td>\${h.respondedNodes||0}</td><td>\${ts(h.completedAt)}</td></tr>\`).join('')+'</tbody></table>';
}

function renderEvents(events) {
  if(!events||!events.length){$('events-log').innerHTML='<p class="empty">暂无事件</p>';return;}
  const atBot=$('events-log').scrollHeight-$('events-log').scrollTop<=$('events-log').clientHeight+40;
  const html=events.slice(0,80).map(e=>{
    const t=e.type||'?';
    let msg='';
    if(t==='task_created') msg=\`新任务 <b style="color:#d29922">\${esc(e.command)}</b> \${esc(e.message||'')}\`;
    else if(t==='result')  msg=\`<b>\${esc(e.nodeId)}</b> 回报 \${esc(e.command)} → <span style="color:\${e.status==='completed'?'#3fb950':'#f85149'}">\${esc(e.status)}</span>\`;
    else if(t==='admin')   msg=\`\${esc(e.program)} on \${esc(e.system)}\${e.resultsCollected?' · 拉取 '+e.resultsCollected+' 结果':''}\`;
    else if(t==='child')   msg=\`<b>\${esc(e.nodeId)}</b> · \${esc(e.program)}\${e.taskDispatched?' <span style="color:#d29922">↓下发</span>':''}\${e.hasResult?' <span style="color:#3fb950">↑回报</span>':''}\`;
    else if(t==='reset')   msg=\`<span style="color:#f85149">\${esc(e.message||'reset')}</span>\`;
    else msg=esc(JSON.stringify(e));
    return \`<div class="ev"><span class="ev-ts">\${ts(e._ts)}</span><span class="ev-label \${labelClass(t)}">\${labelText(t)}</span><span class="ev-msg">\${msg}</span></div>\`;
  }).join('');
  $('events-log').innerHTML=html;
  if(atBot) $('events-log').scrollTop=$('events-log').scrollHeight;
}

async function refresh() {
  try {
    const r=await fetch('/api/status');
    const d=await r.json();
    const admin=d.admin;
    $('admin-badge').textContent=admin?(admin.program+' @ '+(admin.system||'').split('-')[0]):'Admin 离线';
    $('admin-badge').className='badge '+(admin?'badge-ok':'badge-err');
    const pk=d.adminPubKey;
    $('pubkey-badge').textContent=pk?('🔑 '+pk.slice(0,8)+'…'+pk.slice(-8)):'🔑 无公钥';
    $('pubkey-badge').title=pk?('Admin Ed25519 公钥: '+pk):'Admin 尚未上报公钥';
    renderNodes(d.nodes);
    renderP2P(d.nodes);
    renderTask(d.currentTask,d.pendingResultsCount||0);
    renderResults(d.currentTask);
    renderHistory(d.taskHistory);
    renderEvents(d.recentEvents);
    $('refresh-indicator').textContent='更新于 '+new Date().toLocaleTimeString('zh',{hour12:false});
  } catch(e) {
    $('refresh-indicator').textContent='请求失败: '+e.message;
  }
}
refresh();setInterval(refresh,REFRESH_MS);
</script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
