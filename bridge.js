// ==============================================================
// HashPass Bridge — 浏览器端桥接脚本 (中继窗口模式)
// 在 pow.147269358.xyz 控制台粘贴执行
// 通过 window.open 中继页面绕过 CSP connect-src 限制
// ==============================================================
(async () => {
  "use strict";

  // ==================== 用户配置 ====================
  const RUST_URL = "http://localhost:19526/";
  const FAKE_RATE_MIN = 10;
  const FAKE_RATE_MAX = 25;
  const STATUS_INTERVAL = 2000;
  const MAX_DIFFICULTY = 0; // 最大难度限制 (0 = 无限制，例如 20 则只挖难度 ≤ 20 的题)
  // ==================================================

  // 清理旧桥接实例
  if (window.__bridge) {
    if (window.__bridge._relayWin) try { window.__bridge._relayWin.close(); } catch {}
    if (window.__bridge._onMessage) window.removeEventListener("message", window.__bridge._onMessage);
  }

  // ---- 获取页面模块引用 ----
  const { state } = await import("/static/js/state.js");
  const { log } = await import("/static/js/logger.js");
  const { updateHashRate, resetHashRate } = await import("/static/js/hashrate.js");
  const {
    setRequiredDifficulty,
    startPuzzleDurationTimer,
    updateSolveTimeStats,
    updateDifficultyDisplay,
  } = await import("/static/js/mining.js");

  // ---- 状态 ----
  let relayWin = null;
  let relayConnected = false;
  let fakeRateTimer = null;
  let bridgeActive = false;
  let rustMining = false; // Rust 是否正在计算
  let currentPuzzle = null;
  let currentIp = null;
  let pendingStopResolve = null;

  // ---- 工具 ----
  function fakeRate() {
    return FAKE_RATE_MIN + Math.random() * (FAKE_RATE_MAX - FAKE_RATE_MIN);
  }

  function isRustConnected() {
    return relayWin && !relayWin.closed && relayConnected;
  }

  function sendToRust(obj) {
    if (isRustConnected()) {
      relayWin.postMessage({ _r: 1, t: "send", d: JSON.stringify(obj) }, "*");
    }
  }

  // 直接发送到服务器 WS（不依赖 state.mining）
  function serverSend(obj) {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify(obj));
    }
  }

  // ---- 终止 WASM Workers ----
  function killWasmWorkers() {
    if (state.miningWorkers.length > 0) {
      for (const w of state.miningWorkers) {
        w.postMessage({ type: "STOP_MINING" });
        w.terminate();
      }
      state.miningWorkers = [];
      state.workerHashrates = {};
      log("[Bridge] 已终止浏览器 WASM Workers");
    }
  }

  // ---- 假算力上报 ----
  function startFakeHashrate() {
    stopFakeHashrate();
    fakeRateTimer = setInterval(() => {
      if (bridgeActive) {
        serverSend({
          type: "hashrate",
          payload: { rate: fakeRate(), timestamp: Date.now() / 1000 },
        });
      }
    }, STATUS_INTERVAL);
  }

  function stopFakeHashrate() {
    if (fakeRateTimer) {
      clearInterval(fakeRateTimer);
      fakeRateTimer = null;
    }
  }

  // ---- 获取 Trace + IP ----
  async function fetchTrace() {
    let traceData;
    try {
      const resp = await fetch("/cdn-cgi/trace");
      if (resp.ok) {
        traceData = await resp.text();
      }
    } catch {}
    if (!traceData) {
      traceData = await fetch("/api/dev/trace").then((r) => r.text());
    }
    state.traceData = traceData;
    const ipLine = traceData.split("\n").find((l) => l.startsWith("ip="));
    currentIp = ipLine ? ipLine.slice(3).trim() : "unknown";
    return traceData;
  }

  // ---- 获取谜题 ----
  async function fetchPuzzle() {
    const resp = await fetch("/api/puzzle", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${state.sessionToken}`,
      },
      body: JSON.stringify({ visitorId: state.visitorId }),
    });
    if (resp.status === 401) {
      log("会话已过期，请刷新页面", "error");
      return null;
    }
    if (resp.status === 403) {
      const err = await resp.json();
      log(`访问被拒绝: ${err.detail}`, "error");
      return null;
    }
    if (!resp.ok) {
      log(`获取谜题失败: ${resp.status}`, "error");
      return null;
    }
    return resp.json();
  }

  // ---- 提交正确解 ----
  async function submitSolution(nonce, hash) {
    log("正在提交解决方案...");
    try {
      const resp = await fetch("/api/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${state.sessionToken}`,
        },
        body: JSON.stringify({
          visitorId: state.visitorId,
          nonce: nonce,
          submittedSeed: currentPuzzle.seed,
          traceData: state.traceData,
          hash: hash,
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        log(`获胜！兑换码: ${data.invite_code}`, "success");
        document.getElementById("result").classList.remove("hidden");
        document.getElementById("inviteCode").value = data.invite_code;
        sendToRust({ type: "invite_code", code: data.invite_code });
      } else if (resp.status === 401) {
        log("会话已过期，请刷新页面", "error");
        bridgeStop();
      } else {
        const err = await resp.json();
        log(`提交失败: ${err.detail}`, "error");
      }
    } catch (e) {
      log(`提交网络错误: ${e.message}`, "error");
    }
  }

  // ---- 提交超时最优哈希 ----
  async function submitBestHash(bestNonce, bestHash, bestLeadingZeros) {
    if (!bestHash || bestLeadingZeros < 1) {
      log("超时: 无有效哈希可提交", "warning");
      return;
    }
    if (!state.traceData) {
      log("超时: 无 TraceData，跳过提交", "warning");
      return;
    }
    log(`超时: 正在提交最优哈希 (${bestLeadingZeros} 前导零, nonce=${bestNonce})...`);
    try {
      const resp = await fetch("/api/submit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${state.sessionToken}`,
        },
        body: JSON.stringify({
          visitorId: state.visitorId,
          nonce: bestNonce,
          submittedSeed: currentPuzzle.seed,
          traceData: state.traceData,
          hash: bestHash,
          leadingZeros: bestLeadingZeros,
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        log(`超时提交成功 (${data.status})`, "info");
      } else if (resp.status === 409) {
        log("超时提交: 窗口已关闭或种子不匹配", "warning");
      } else {
        const err = await resp.json().catch(() => ({}));
        log(`超时提交失败: ${err.detail || resp.status}`, "error");
      }
    } catch (e) {
      log(`超时提交网络错误: ${e.message}`, "error");
    }
  }

  // ---- 向 Rust 发送 stop 并等待 stopped 响应 ----
  function stopRustMining() {
    return new Promise((resolve) => {
      if (!rustMining || !isRustConnected()) {
        rustMining = false;
        resolve({ bestNonce: 0, bestHash: "", bestLeadingZeros: 0 });
        return;
      }
      rustMining = false;
      pendingStopResolve = resolve;
      sendToRust({ type: "stop" });
      setTimeout(() => {
        if (pendingStopResolve) {
          pendingStopResolve({ bestNonce: 0, bestHash: "", bestLeadingZeros: 0 });
          pendingStopResolve = null;
        }
      }, 5000);
    });
  }

  // ---- 发送新的挖矿任务给 Rust ----
  function startRustMining(puzzle) {
    currentPuzzle = puzzle;
    state.currentSeed = puzzle.seed;
    state.bestHash = null;
    state.bestNonce = -1;
    state.bestLeadingZeros = 0;

    // 难度过滤
    if (MAX_DIFFICULTY > 0 && puzzle.difficulty > MAX_DIFFICULTY) {
      rustMining = false;
      log(`[Bridge] 难度 ${puzzle.difficulty} > 限制 ${MAX_DIFFICULTY}，跳过本轮`, "warning");
      updateRustStatus(`难度过高(${puzzle.difficulty})，等待新题`);
      return;
    }

    rustMining = true;
    sendToRust({
      type: "mine",
      seed: puzzle.seed,
      visitorId: state.visitorId,
      ip: currentIp,
      difficulty: puzzle.difficulty,
      memoryCost: puzzle.memory_cost,
      timeCost: puzzle.time_cost,
      parallelism: puzzle.parallelism,
    });

    log(`[Bridge] 已发送谜题: seed=${puzzle.seed.substring(0, 16)}... diff=${puzzle.difficulty}`);
    updateRustStatus(`挖矿中 (难度=${puzzle.difficulty})`);
  }

  // ---- 处理来自 Rust 的消息 ----
  function handleRustMessage(rawData) {
    try {
      const data = JSON.parse(rawData);

      switch (data.type) {
        case "ready":
          log(`[Bridge] Rust 就绪, ${data.threads} 线程`, "success");
          hookServerWebSocket();
          createBridgeUI();
          break;

        case "status":
          if (!rustMining) break;
          updateHashRate(data.hashRate.toFixed(2));
          if (
            data.bestLeadingZeros > state.bestLeadingZeros ||
            (data.bestLeadingZeros === state.bestLeadingZeros &&
              (state.bestNonce === -1 || data.bestNonce < state.bestNonce))
          ) {
            state.bestLeadingZeros = data.bestLeadingZeros;
            state.bestHash = data.bestHash;
            state.bestNonce = data.bestNonce;
          }
          updateDifficultyDisplay();
          break;

        case "solution":
          log(`[Bridge] Rust 找到解! nonce=${data.nonce}`, "success");
          rustMining = false;
          // 保持 bridgeActive = true：等待 PUZZLE_RESET 自动重启下一轮
          // 保持假算力上报、挖矿计时器运行（与原版行为一致）
          updateRustStatus("已找到解！等待新谜题...");
          submitSolution(data.nonce, data.hash);
          break;

        case "stopped":
          if (pendingStopResolve) {
            pendingStopResolve({
              bestNonce: data.bestNonce,
              bestHash: data.bestHash,
              bestLeadingZeros: data.bestLeadingZeros,
            });
            pendingStopResolve = null;
          }
          break;
      }
    } catch (e) {
      console.error("[Bridge] 解析 Rust 消息失败:", e);
    }
  }

  // ---- Rust 按钮 UI ----
  function updateRustButtons(mining) {
    const s = document.getElementById("rustStartBtn");
    const t = document.getElementById("rustStopBtn");
    if (s) { s.disabled = mining; }
    if (t) { t.disabled = !mining; }
  }

  function updateRustStatus(text) {
    const el = document.getElementById("rustStatus");
    if (el) el.textContent = text;
  }

  function createBridgeUI() {
    for (const id of ["bridgeControls", "rustStatusRow"]) {
      const old = document.getElementById(id);
      if (old) old.remove();
    }

    // 复用页面原生 Tailwind 类名，与 controls section 风格统一
    const origStartBtn = document.getElementById("startBtn");
    const controlsSection = origStartBtn ? origStartBtn.closest("section") || origStartBtn.parentNode : null;

    // 容器：和原始 controls 一样的 flex 布局
    const container = document.createElement("section");
    container.id = "bridgeControls";
    container.className = "controls flex flex-col sm:flex-row gap-2 sm:gap-3";

    // Rust 开始按钮 — 复用原始 startBtn 的全部 class
    const startBtn = document.createElement("button");
    startBtn.id = "rustStartBtn";
    startBtn.textContent = "Rust 挖矿";
    if (origStartBtn) {
      startBtn.className = origStartBtn.className;
    }
    startBtn.addEventListener("click", bridgeStart);

    // Rust 停止按钮 — 复用原始 stopBtn 的全部 class
    const origStopBtn = document.getElementById("stopBtn");
    const stopBtn = document.createElement("button");
    stopBtn.id = "rustStopBtn";
    stopBtn.textContent = "Rust 停止";
    stopBtn.disabled = true;
    if (origStopBtn) {
      stopBtn.className = origStopBtn.className;
    }
    stopBtn.addEventListener("click", async () => {
      await stopRustMining();
      bridgeStop();
    });

    container.appendChild(startBtn);
    container.appendChild(stopBtn);

    // 状态行：和页面 status-item 风格一致
    const statusRow = document.createElement("div");
    statusRow.id = "rustStatusRow";
    statusRow.className =
      "status-item status-item-hover flex justify-between items-center p-2.5 sm:p-3 " +
      "bg-[var(--bg-tertiary)] border border-[var(--border-color)] rounded-xl " +
      "transition-all duration-200 min-h-[42px] sm:min-h-[46px]";

    const statusLabel = document.createElement("span");
    statusLabel.className = "label text-xs text-[var(--text-tertiary)] font-semibold uppercase tracking-wider flex-shrink-0 mr-4";
    statusLabel.textContent = "RUST BRIDGE";

    const statusValue = document.createElement("span");
    statusValue.id = "rustStatus";
    statusValue.className = "value text-xs sm:text-sm text-[var(--text-primary)] font-semibold text-right overflow-hidden text-ellipsis";
    statusValue.textContent = "就绪";

    if (MAX_DIFFICULTY > 0) {
      statusValue.textContent = `就绪 [最大难度:${MAX_DIFFICULTY}]`;
    }

    statusRow.appendChild(statusLabel);
    statusRow.appendChild(statusValue);

    // 插入位置：紧跟在原始 controls section 后面
    if (controlsSection && controlsSection.parentNode) {
      controlsSection.parentNode.insertBefore(statusRow, controlsSection.nextSibling);
      controlsSection.parentNode.insertBefore(container, controlsSection.nextSibling);
    } else {
      document.body.prepend(statusRow);
      document.body.prepend(container);
    }

    log("[Bridge] 已插入 Rust 控制面板");
  }

  // ---- 启动桥接挖矿 ----
  async function bridgeStart() {
    if (bridgeActive) return;
    if (!state.sessionToken) {
      log("请先完成人机验证", "error");
      return;
    }

    bridgeActive = true;
    updateRustButtons(true);
    updateRustStatus("启动中...");

    // 终止浏览器 WASM 挖矿（避免双重计算）
    killWasmWorkers();

    // 启动挖矿计时
    state.miningStartTime = Date.now();
    if (state.miningTimer) clearInterval(state.miningTimer);
    state.miningTimer = setInterval(() => {
      const elapsed = Math.floor((state.miningElapsed + Date.now() - state.miningStartTime) / 1000);
      const m = Math.floor(elapsed / 60);
      const s = elapsed % 60;
      const el = document.getElementById("miningTime");
      if (el) el.textContent = `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    }, 1000);

    try {
      log("[Bridge] 正在获取 Cloudflare Trace...");
      await fetchTrace();
      log(`[Bridge] IP: ${currentIp}`);

      const puzzle = await fetchPuzzle();
      if (!puzzle) {
        bridgeStop();
        return;
      }

      setRequiredDifficulty(puzzle.difficulty);
      if (puzzle.puzzle_start_time) startPuzzleDurationTimer(puzzle.puzzle_start_time);
      updateSolveTimeStats(puzzle.last_solve_time ?? null, puzzle.average_solve_time ?? null);

      log(`[Bridge] 难度: ${puzzle.difficulty}, 内存: ${puzzle.memory_cost / 1024}MB`);

      startRustMining(puzzle);
      serverSend({ type: "mining_start" });
      startFakeHashrate();
    } catch (e) {
      log(`[Bridge] 启动错误: ${e.message}`, "error");
      bridgeStop();
    }
  }

  // ---- 停止桥接挖矿 ----
  async function bridgeStop() {
    if (!bridgeActive) return;
    bridgeActive = false;

    if (rustMining) {
      await stopRustMining();
    }

    if (state.miningTimer) {
      state.miningElapsed += Date.now() - state.miningStartTime;
      clearInterval(state.miningTimer);
      state.miningTimer = null;
    }

    stopFakeHashrate();
    resetHashRate();
    serverSend({ type: "mining_stop" });

    updateRustButtons(false);
    updateRustStatus("已停止");
  }

  // ---- Hook 服务器 WebSocket 消息 ----
  function hookServerWebSocket() {
    if (!state.ws) {
      log("[Bridge] 等待服务器 WebSocket 连接...", "warning");
      setTimeout(hookServerWebSocket, 1000);
      return;
    }

    const origOnMessage = state.ws.onmessage;
    state.ws.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === "PUZZLE_RESET" && bridgeActive) {
          log("[Bridge] 检测到新谜题！", "warning");
          log(`[Bridge] 新种子: ${data.seed.substring(0, 16)}...`);

          if (data.solve_time != null) {
            log(`[Bridge] 上轮用时: ${data.solve_time}s`);
          }
          state.bestLeadingZeros = 0;
          setRequiredDifficulty(data.difficulty);
          updateSolveTimeStats(data.solve_time ?? null, data.average_solve_time ?? null);
          if (data.puzzle_start_time) startPuzzleDurationTimer(data.puzzle_start_time);

          // 通知服务器停止（模拟原版 stopMining → notifyMiningStop）
          serverSend({ type: "mining_stop" });
          stopFakeHashrate();
          resetHashRate();

          const stopped = await stopRustMining();

          if (data.is_timeout) {
            log("[Bridge] 谜题超时！提交最优哈希...", "warning");
            await submitBestHash(stopped.bestNonce, stopped.bestHash, stopped.bestLeadingZeros);
          }

          const newPuzzle = await fetchPuzzle();
          if (newPuzzle) {
            setRequiredDifficulty(newPuzzle.difficulty);
            if (newPuzzle.puzzle_start_time) startPuzzleDurationTimer(newPuzzle.puzzle_start_time);
            updateSolveTimeStats(newPuzzle.last_solve_time ?? null, newPuzzle.average_solve_time ?? null);
            startRustMining(newPuzzle);
            // 通知服务器重新开始（模拟原版 startMining → notifyMiningStart）
            serverSend({ type: "mining_start" });
            startFakeHashrate();
            log("[Bridge] 已切换到新谜题");
          }
          return;
        }

        if (data.type === "TIMEOUT_INVITE_CODE") {
          const code = data.invite_code;
          log(`超时奖励兑换码: ${code}`, "success");
          document.getElementById("result").classList.remove("hidden");
          document.getElementById("inviteCode").value = code;
          sendToRust({ type: "invite_code", code: code });
          return;
        }
      } catch {}

      if (origOnMessage) origOnMessage.call(state.ws, event);
    };

    log("[Bridge] 已 Hook 服务器 WebSocket");
  }

  // ---- 中继窗口消息处理 ----
  function onRelayMessage(event) {
    if (!event.data || event.data._r !== 1) return;

    switch (event.data.t) {
      case "open":
        relayConnected = true;
        log("[Bridge] 中继 WebSocket 已连接 Rust 引擎", "success");
        break;

      case "msg":
        handleRustMessage(event.data.d);
        break;

      case "err":
        log("[Bridge] 中继 WebSocket 错误，请确认 Rust 程序已启动", "error");
        relayConnected = false;
        break;

      case "close":
        log("[Bridge] 中继 WebSocket 断开", "warning");
        relayConnected = false;
        if (bridgeActive) {
          bridgeStop();
        }
        break;
    }
  }

  window.addEventListener("message", onRelayMessage);

  // ---- 通过中继窗口连接 Rust ----
  function connectRust() {
    log("[Bridge] 正在通过中继窗口连接 Rust 引擎...");

    relayWin = window.open(RUST_URL, "_hpRelay", "width=300,height=100");

    if (!relayWin || relayWin.closed) {
      log("[Bridge] 无法打开中继窗口！请允许此网站的弹窗后重试", "error");
      log("[Bridge] 提示: 点击地址栏右侧的弹窗拦截图标，选择'始终允许'", "error");
      return;
    }

    log("[Bridge] 中继窗口已打开，等待 WebSocket 连接...");
  }

  // ---- 页面卸载时清理 ----
  window.addEventListener("beforeunload", () => {
    if (relayWin && !relayWin.closed) {
      try { relayWin.close(); } catch {}
    }
  });

  // ---- 启动 ----
  connectRust();

  window.__bridge = {
    start: bridgeStart,
    stop: bridgeStop,
    status: () => ({
      active: bridgeActive,
      rustMining,
      rustConnected: isRustConnected(),
      puzzle: currentPuzzle ? currentPuzzle.seed.substring(0, 16) + "..." : null,
    }),
    _relayWin: relayWin,
    _onMessage: onRelayMessage,
  };

  log("[Bridge] 桥接脚本已加载 (中继窗口模式)", "success");
  if (MAX_DIFFICULTY > 0) {
    log(`[Bridge] 难度限制: 仅挖 ≤ ${MAX_DIFFICULTY} 的题目`);
  }
  log("[Bridge] Rust 就绪后将显示控制面板");
})();
