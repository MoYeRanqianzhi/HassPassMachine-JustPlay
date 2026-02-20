//! HashPass Miner — 高性能 Argon2d 竞速矿机 (Rust)
//!
//! 挖矿阶段零输出、零无关代码，全部 CPU 资源用于 Argon2d 计算。

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

// ============================================================
// 配置 — 修改此处即可切换目标站点
// ============================================================

const BASE_URL: &str = "https://pow.147269358.xyz";
const INVITE_CODE_FILE: &str = "invite_codes.txt";
const SESSION_FILE: &str = "session.json";

// ============================================================
// 数据结构
// ============================================================

#[derive(Debug, Deserialize)]
struct PuzzleResponse {
    seed: String,
    difficulty: u32,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    #[allow(dead_code)]
    worker_count: Option<u32>,
    #[allow(dead_code)]
    puzzle_start_time: Option<f64>,
    #[allow(dead_code)]
    last_solve_time: Option<f64>,
    #[allow(dead_code)]
    average_solve_time: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    invite_code: String,
}

#[derive(Debug, Serialize)]
struct PuzzleRequest {
    #[serde(rename = "visitorId")]
    visitor_id: String,
}

#[derive(Debug, Serialize)]
struct VerifyRequest {
    #[serde(rename = "visitorId")]
    visitor_id: String,
    nonce: u64,
    #[serde(rename = "submittedSeed")]
    submitted_seed: String,
    #[serde(rename = "traceData")]
    trace_data: String,
    hash: String,
}

struct MiningResult {
    nonce: u64,
    hash_hex: String,
}

/// 浏览器会话数据
#[derive(Serialize, Deserialize, Clone)]
struct SessionData {
    session_token: String,
    visitor_id: String,
    cookies: String,
    user_agent: String,
}

// ============================================================
// 会话持久化
// ============================================================

fn save_session(data: &SessionData) {
    if let Ok(json) = serde_json::to_string_pretty(data) {
        let _ = std::fs::write(SESSION_FILE, json);
    }
}

fn load_session() -> Option<SessionData> {
    let content = std::fs::read_to_string(SESSION_FILE).ok()?;
    serde_json::from_str(&content).ok()
}

// ============================================================
// 浏览器自动化 (最小化 CDP 客户端)
// ============================================================

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct CdpClient {
    write: futures_util::stream::SplitSink<WsStream, Message>,
    read: futures_util::stream::SplitStream<WsStream>,
    next_id: u32,
}

impl CdpClient {
    async fn send_command(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        let msg = serde_json::json!({ "id": id, "method": method, "params": params });
        self.write
            .send(Message::Text(msg.to_string().into()))
            .await
            .context("CDP 发送失败")?;

        loop {
            match tokio::time::timeout(Duration::from_secs(30), self.read.next()).await {
                Ok(Some(Ok(msg))) => {
                    let text = match &msg {
                        Message::Text(t) => t.to_string(),
                        _ => continue,
                    };
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                        if data["id"] == id {
                            return Ok(data);
                        }
                    }
                }
                Ok(Some(Err(e))) => bail!("CDP WebSocket 错误: {}", e),
                Ok(None) => bail!("CDP WebSocket 已关闭"),
                Err(_) => bail!("CDP 命令超时"),
            }
        }
    }
}

struct BrowserGuard {
    child: std::process::Child,
    temp_dir: PathBuf,
}

impl Drop for BrowserGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn find_browser() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let pf86 = std::env::var("ProgramFiles(x86)")
            .unwrap_or_else(|_| r"C:\Program Files (x86)".into());

        let candidates = [
            format!(r"{}\Google\Chrome\Application\chrome.exe", pf),
            format!(r"{}\Google\Chrome\Application\chrome.exe", pf86),
            format!(r"{}\Google\Chrome\Application\chrome.exe", local),
            format!(r"{}\Microsoft\Edge\Application\msedge.exe", pf),
            format!(r"{}\Microsoft\Edge\Application\msedge.exe", pf86),
        ];
        for p in &candidates {
            if Path::new(p).exists() {
                return Ok(PathBuf::from(p));
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let candidates = [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ];
        for p in &candidates {
            if Path::new(p).exists() {
                return Ok(PathBuf::from(p));
            }
        }
    }

    bail!("未找到 Chrome 或 Edge 浏览器")
}

async fn get_session_auto(base_url: &str) -> Result<SessionData> {
    println!("[*] 正在启动浏览器以自动获取 session token...");

    let browser_path = find_browser()?;
    println!("[*] 浏览器: {}", browser_path.display());

    let temp_dir = std::env::temp_dir().join(format!("hashpass_cdp_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir)?;

    let child = std::process::Command::new(&browser_path)
        .args([
            "--remote-debugging-port=0",
            &format!("--user-data-dir={}", temp_dir.display()),
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-blink-features=AutomationControlled",
            "--disable-extensions",
            "--disable-component-extensions-with-background-pages",
            "--disable-default-apps",
            "--disable-background-networking",
            "--disable-sync",
            "--metrics-recording-only",
            "about:blank",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("启动浏览器失败")?;

    let guard = BrowserGuard {
        child,
        temp_dir: temp_dir.clone(),
    };

    let port_file = temp_dir.join("DevToolsActivePort");
    let mut port: u16 = 0;
    println!("[*] 等待 CDP 端口...");
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(content) = std::fs::read_to_string(&port_file) {
            if let Some(first_line) = content.lines().next() {
                if let Ok(p) = first_line.trim().parse::<u16>() {
                    port = p;
                    break;
                }
            }
        }
    }
    if port == 0 {
        bail!("CDP 端口未就绪");
    }
    println!("[*] CDP 端口: {}", port);

    let pages: Vec<serde_json::Value> =
        reqwest::get(format!("http://localhost:{}/json", port))
            .await?
            .json()
            .await?;

    let ws_url = pages
        .iter()
        .find(|p| p["type"] == "page")
        .and_then(|p| p["webSocketDebuggerUrl"].as_str())
        .ok_or_else(|| anyhow!("未找到页面目标"))?
        .to_string();

    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await?;
    let (write, read) = ws.split();
    let mut cdp = CdpClient {
        write,
        read,
        next_id: 1,
    };

    let inject_script = r#"
        (function() {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            const OrigWS = window.WebSocket;
            window.WebSocket = function(url, protocols) {
                const ws = protocols ? new OrigWS(url, protocols) : new OrigWS(url);
                ws.addEventListener('message', function(e) {
                    try {
                        const data = JSON.parse(e.data);
                        if (data.type === 'SESSION_TOKEN') {
                            window.__hashpass_session_token = data.token;
                        }
                    } catch(err) {}
                });
                return ws;
            };
            window.WebSocket.prototype = OrigWS.prototype;
            window.WebSocket.CONNECTING = OrigWS.CONNECTING;
            window.WebSocket.OPEN = OrigWS.OPEN;
            window.WebSocket.CLOSING = OrigWS.CLOSING;
            window.WebSocket.CLOSED = OrigWS.CLOSED;
        })();
    "#;

    cdp.send_command(
        "Page.addScriptToEvaluateOnNewDocument",
        serde_json::json!({ "source": inject_script }),
    )
    .await?;

    println!("[*] 正在导航到 {}...", base_url);
    cdp.send_command("Page.navigate", serde_json::json!({ "url": base_url }))
        .await?;

    println!("[*] 等待 Turnstile 验证完成...");
    println!("[*] (如果出现验证框，请在弹出的浏览器窗口中完成)");

    for i in 0..300 {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let resp = cdp
            .send_command(
                "Runtime.evaluate",
                serde_json::json!({ "expression": "window.__hashpass_session_token || ''" }),
            )
            .await?;

        if let Some(token) = resp
            .pointer("/result/result/value")
            .and_then(|v| v.as_str())
        {
            if !token.is_empty() {
                println!("[+] Session token 获取成功!");

                // 提取浏览器 cookies
                let cookies = match cdp
                    .send_command(
                        "Network.getCookies",
                        serde_json::json!({ "urls": [base_url] }),
                    )
                    .await
                {
                    Ok(resp) => resp
                        .pointer("/result/cookies")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|c| {
                                    let name = c["name"].as_str()?;
                                    let value = c["value"].as_str()?;
                                    Some(format!("{}={}", name, value))
                                })
                                .collect::<Vec<_>>()
                                .join("; ")
                        })
                        .unwrap_or_default(),
                    Err(_) => String::new(),
                };

                // 提取 visitorId (thumbmarkjs 指纹)
                let visitor_id = match cdp
                    .send_command(
                        "Runtime.evaluate",
                        serde_json::json!({
                            "expression": "(async()=>{try{const{state}=await import('/static/js/state.js');return state.visitorId||''}catch{return''}})()",
                            "awaitPromise": true,
                            "returnByValue": true,
                        }),
                    )
                    .await
                {
                    Ok(resp) => resp
                        .pointer("/result/result/value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    Err(_) => String::new(),
                };

                // 提取 User-Agent
                let user_agent = match cdp
                    .send_command(
                        "Runtime.evaluate",
                        serde_json::json!({ "expression": "navigator.userAgent" }),
                    )
                    .await
                {
                    Ok(resp) => resp
                        .pointer("/result/result/value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    Err(_) => String::new(),
                };

                if !cookies.is_empty() {
                    println!("[+] Cookies: {} 字符", cookies.len());
                }
                if !visitor_id.is_empty() {
                    println!(
                        "[+] Visitor ID: {}...",
                        &visitor_id[..16.min(visitor_id.len())]
                    );
                }

                drop(guard);
                return Ok(SessionData {
                    session_token: token.to_string(),
                    visitor_id: if visitor_id.is_empty() {
                        uuid::Uuid::new_v4().to_string()
                    } else {
                        visitor_id
                    },
                    cookies,
                    user_agent,
                });
            }
        }

        if i > 0 && i % 15 == 0 {
            println!("[*] 仍在等待 Turnstile... ({}s)", i);
        }
    }

    drop(guard);
    bail!("获取 session token 超时 (5 分钟)")
}

async fn get_session_manual(base_url: &str) -> Result<SessionData> {
    println!();
    println!("[!] 手动模式 — 请按以下步骤操作:");
    println!("  1. 在浏览器中打开: {}", base_url);
    println!("  2. 完成 Turnstile 人机验证 (通常自动完成)");
    println!("  3. 等待页面显示「就绪」");
    println!("  4. 按 F12 打开 Console，运行以下命令 (整行复制):");
    println!();
    println!(
        r#"     JSON.stringify({{t:(await import('/static/js/state.js')).state.sessionToken,v:(await import('/static/js/state.js')).state.visitorId,c:document.cookie}})"#
    );
    println!();
    println!("  5. 复制输出的 JSON 字符串并粘贴到下方");
    println!();

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", base_url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(base_url)
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(base_url)
            .spawn();
    }

    print!("请粘贴: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    // 去除控制台可能带的外层引号
    let input = input
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| input.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(input);

    if input.is_empty() {
        bail!("未提供数据");
    }

    // 尝试解析 JSON 格式 {"t":"...","v":"...","c":"..."}
    if let Ok(data) = serde_json::from_str::<serde_json::Value>(input) {
        let token = data["t"].as_str().unwrap_or("").to_string();
        let visitor_id = data["v"].as_str().unwrap_or("").to_string();
        let cookies = data["c"].as_str().unwrap_or("").to_string();

        if token.is_empty() {
            bail!("JSON 中未找到 session token (t 字段)");
        }

        println!("[+] Session token: {}...", &token[..16.min(token.len())]);
        if !visitor_id.is_empty() {
            println!(
                "[+] Visitor ID: {}...",
                &visitor_id[..16.min(visitor_id.len())]
            );
        }
        if !cookies.is_empty() {
            println!("[+] Cookies: {} 字符", cookies.len());
        }

        return Ok(SessionData {
            session_token: token,
            visitor_id: if visitor_id.is_empty() {
                uuid::Uuid::new_v4().to_string()
            } else {
                visitor_id
            },
            cookies,
            user_agent: String::new(),
        });
    }

    // 回退: 直接当作纯 token 处理
    println!("[*] 未检测到 JSON，将输入视为纯 session token");
    println!("[!] 警告: 缺少 visitorId 和 cookies，API 调用可能失败");

    Ok(SessionData {
        session_token: input.to_string(),
        visitor_id: uuid::Uuid::new_v4().to_string(),
        cookies: String::new(),
        user_agent: String::new(),
    })
}

// ============================================================
// Argon2d 挖矿核心 — 零开销热路径
// ============================================================

/// u64 → ASCII 字节，零分配，返回写入的切片
#[inline(always)]
fn u64_to_ascii(buf: &mut [u8; 20], n: u64) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut pos = 20usize;
    let mut v = n;
    while v > 0 {
        pos -= 1;
        buf[pos] = (v % 10) as u8 + b'0';
        v /= 10;
    }
    let len = 20 - pos;
    buf.copy_within(pos..20, 0);
    len
}

/// 计算哈希值的前导零比特数
#[inline(always)]
fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            return bits;
        }
    }
    bits
}

/// 单个挖矿线程 — 热路径仅含: nonce格式化 → Argon2d → 比特检查
fn mine_worker(
    thread_id: u32,
    thread_count: u32,
    seed: String,
    visitor_id: String,
    ip: String,
    difficulty: u32,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    found: Arc<AtomicBool>,
    tx: std::sync::mpsc::Sender<MiningResult>,
) {
    let salt_str = format!("{}|{}|{}", seed, visitor_id, ip);
    let salt_bytes = salt_str.as_bytes();

    let params = Params::new(memory_cost, time_cost, parallelism, Some(32)).unwrap();
    let block_count = params.block_count();
    let ctx = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    let mut memory = vec![argon2::Block::default(); block_count];
    let mut hash_output = [0u8; 32];
    let mut nonce_buf = [0u8; 20];

    let mut nonce = thread_id as u64;

    loop {
        if found.load(Ordering::Relaxed) {
            return;
        }

        let nonce_len = u64_to_ascii(&mut nonce_buf, nonce);

        ctx.hash_password_into_with_memory(
            &nonce_buf[..nonce_len],
            salt_bytes,
            &mut hash_output,
            &mut memory,
        )
        .unwrap();

        if count_leading_zero_bits(&hash_output) >= difficulty {
            found.store(true, Ordering::SeqCst);
            let _ = tx.send(MiningResult {
                nonce,
                hash_hex: hex::encode(hash_output),
            });
            return;
        }

        nonce += thread_count as u64;
    }
}

// ============================================================
// HTTP API
// ============================================================

async fn get_trace(client: &reqwest::Client, base_url: &str) -> Result<(String, String)> {
    let trace_url = format!("{}/cdn-cgi/trace", base_url);
    let resp = client.get(&trace_url).send().await;

    let trace_data = match resp {
        Ok(r) if r.status().is_success() => r.text().await?,
        _ => {
            let dev_url = format!("{}/api/dev/trace", base_url);
            client.get(&dev_url).send().await?.text().await?
        }
    };

    let ip = trace_data
        .lines()
        .find(|l| l.starts_with("ip="))
        .map(|l| l[3..].trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    Ok((trace_data, ip))
}

async fn get_puzzle(
    client: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    visitor_id: &str,
) -> Result<PuzzleResponse> {
    let url = format!("{}/api/puzzle", base_url);
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session_token))
        .json(&PuzzleRequest {
            visitor_id: visitor_id.to_string(),
        })
        .send()
        .await?;

    match resp.status() {
        s if s == reqwest::StatusCode::UNAUTHORIZED => {
            bail!("Session token 已过期，请用 --new 重新获取");
        }
        s if s == reqwest::StatusCode::FORBIDDEN => {
            let err: serde_json::Value = resp.json().await?;
            bail!("访问被拒绝: {}", err["detail"]);
        }
        s if !s.is_success() => {
            bail!(
                "获取谜题失败: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        _ => {}
    }

    resp.json().await.context("解析谜题响应失败")
}

async fn submit_solution(
    client: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    visitor_id: &str,
    seed: &str,
    trace_data: &str,
    result: &MiningResult,
) -> Result<VerifyResponse> {
    let url = format!("{}/api/verify", base_url);
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session_token))
        .json(&VerifyRequest {
            visitor_id: visitor_id.to_string(),
            nonce: result.nonce,
            submitted_seed: seed.to_string(),
            trace_data: trace_data.to_string(),
            hash: result.hash_hex.clone(),
        })
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        bail!("Session token 已过期");
    }
    if resp.status().is_success() {
        resp.json().await.context("解析验证响应失败")
    } else {
        let err: serde_json::Value = resp.json().await?;
        bail!("提交失败: {}", err["detail"])
    }
}

// ============================================================
// 邀请码持久化
// ============================================================

fn save_invite_code(code: &str) {
    use std::fs::OpenOptions;
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(INVITE_CODE_FILE)
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{} | {}", timestamp, code);
    }
}

// ============================================================
// 直接提交模式
// ============================================================

fn prompt(label: &str) -> Result<String> {
    print!("{}", label);
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

async fn run_submit_mode(
    client: &reqwest::Client,
    base_url: &str,
    session_token: &str,
    visitor_id: &str,
    trace_data: &str,
) -> Result<()> {
    println!();
    println!("[*] ====== 直接提交模式 ======");
    println!("[*] 请输入挖矿结果:");
    println!();

    let nonce_str = prompt("  nonce: ")?;
    let nonce: u64 = nonce_str.parse().context("nonce 必须是数字")?;

    let hash = prompt("  hash (hex): ")?;
    if hash.is_empty() {
        bail!("hash 不能为空");
    }

    let seed = prompt("  seed: ")?;
    if seed.is_empty() {
        bail!("seed 不能为空");
    }

    println!();
    println!("[*] 正在提交...");
    println!("[*]   nonce = {}", nonce);
    println!("[*]   hash  = {}...", &hash[..32.min(hash.len())]);
    println!("[*]   seed  = {}...", &seed[..32.min(seed.len())]);

    let result = MiningResult {
        nonce,
        hash_hex: hash,
    };

    match submit_solution(
        client,
        base_url,
        session_token,
        visitor_id,
        &seed,
        trace_data,
        &result,
    )
    .await
    {
        Ok(verify) => {
            save_invite_code(&verify.invite_code);
            println!();
            println!("[+] 提交成功! 邀请码 = {}", verify.invite_code);
            println!("[+] 已保存到 {}", INVITE_CODE_FILE);
        }
        Err(e) => {
            eprintln!("[!] 提交失败: {}", e);
        }
    }

    Ok(())
}

// ============================================================
// 构建 HTTP 客户端
// ============================================================

fn build_http_client(session: &SessionData, base_url: &str) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();

    if let Ok(val) = base_url.parse() {
        headers.insert("Origin", val);
    }
    if let Ok(val) = format!("{}/", base_url).parse() {
        headers.insert("Referer", val);
    }

    let ua = if session.user_agent.is_empty() {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    } else {
        &session.user_agent
    };
    if let Ok(val) = ua.parse() {
        headers.insert("User-Agent", val);
    }

    if !session.cookies.is_empty() {
        if let Ok(val) = session.cookies.parse() {
            headers.insert("Cookie", val);
        }
    }

    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .default_headers(headers)
        .build()
        .context("构建 HTTP 客户端失败")
}

// ============================================================
// 主函数
// ============================================================

fn print_banner() {
    println!();
    println!("  ╔═══════════════════════════════════════════╗");
    println!("  ║   HashPass Miner — Rust Native Edition    ║");
    println!("  ║   Argon2d PoW 竞速矿机                   ║");
    println!("  ╚═══════════════════════════════════════════╝");
    println!();
}

fn print_usage() {
    println!("用法: hashpass-machine [选项]");
    println!();
    println!("选项:");
    println!("  --url=<URL>         目标 URL (默认: {})", BASE_URL);
    println!("  --token=<TOKEN>     手动指定 session token");
    println!("  --visitor-id=<ID>   手动指定 visitor ID");
    println!("  --cookie=<COOKIE>   手动指定 Cookie 头");
    println!("  --threads=<N>       挖矿线程数 (默认: CPU 核心数)");
    println!("  --new               强制重新获取会话 (忽略本地缓存)");
    println!("  --auto              使用自动浏览器模式获取会话");
    println!("  --submit            直接提交模式 (手动输入答案)");
    println!("  --help              显示帮助");
    println!();
    println!("会话数据自动保存到 {}，下次启动直接复用。", SESSION_FILE);
}

#[tokio::main]
async fn main() -> Result<()> {
    print_banner();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }

    let base_url = args
        .iter()
        .find(|a| a.starts_with("--url="))
        .map(|a| {
            a.trim_start_matches("--url=")
                .trim_end_matches('/')
                .to_string()
        })
        .unwrap_or_else(|| BASE_URL.to_string());

    let manual_token = args
        .iter()
        .find(|a| a.starts_with("--token="))
        .map(|a| a.trim_start_matches("--token=").to_string());

    let manual_visitor_id = args
        .iter()
        .find(|a| a.starts_with("--visitor-id="))
        .map(|a| a.trim_start_matches("--visitor-id=").to_string());

    let manual_cookie = args
        .iter()
        .find(|a| a.starts_with("--cookie="))
        .map(|a| a.trim_start_matches("--cookie=").to_string());

    let force_new = args.iter().any(|a| a == "--new");
    let force_auto = args.iter().any(|a| a == "--auto");
    let submit_mode = args.iter().any(|a| a == "--submit");

    let thread_count: u32 = args
        .iter()
        .find(|a| a.starts_with("--threads="))
        .and_then(|a| a.trim_start_matches("--threads=").parse().ok())
        .unwrap_or(num_cpus::get() as u32);

    println!("[*] 目标: {}", base_url);
    println!("[*] 挖矿线程: {}", thread_count);
    println!();

    // === Step 1: 获取会话数据 (优先本地缓存) ===
    let session = if let Some(token) = manual_token {
        println!("[+] 使用命令行提供的参数");
        SessionData {
            session_token: token,
            visitor_id: manual_visitor_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            cookies: manual_cookie.unwrap_or_default(),
            user_agent: String::new(),
        }
    } else if !force_new {
        if let Some(cached) = load_session() {
            println!(
                "[+] 从 {} 加载会话 (token={}...)",
                SESSION_FILE,
                &cached.session_token[..16.min(cached.session_token.len())]
            );
            cached
        } else if force_auto {
            match get_session_auto(&base_url).await {
                Ok(s) => s,
                Err(e) => {
                    println!("[!] 自动获取失败: {}", e);
                    get_session_manual(&base_url).await?
                }
            }
        } else {
            get_session_manual(&base_url).await?
        }
    } else {
        println!("[*] --new 强制重新获取会话");
        if force_auto {
            match get_session_auto(&base_url).await {
                Ok(s) => s,
                Err(e) => {
                    println!("[!] 自动获取失败: {}", e);
                    get_session_manual(&base_url).await?
                }
            }
        } else {
            get_session_manual(&base_url).await?
        }
    };

    // 保存会话到本地
    save_session(&session);
    println!("[*] 会话已保存到 {}", SESSION_FILE);

    // === Step 2: HTTP 客户端 ===
    let client = build_http_client(&session, &base_url)?;
    if !session.cookies.is_empty() {
        println!("[*] HTTP 客户端已附加 cookies");
    }

    // === Step 3: Cloudflare Trace ===
    println!("[*] 正在获取网络特征...");
    let (trace_data, ip) = get_trace(&client, &base_url).await?;
    println!("[+] IP: {}", ip);

    // === Step 4: Visitor ID ===
    let visitor_id = session.visitor_id.clone();
    println!("[*] Visitor ID: {}", visitor_id);

    // === 直接提交模式 ===
    if submit_mode {
        return run_submit_mode(
            &client,
            &base_url,
            &session.session_token,
            &visitor_id,
            &trace_data,
        )
        .await;
    }

    // === Step 5: 挖矿主循环 ===
    println!("[*] ====== 开始挖矿循环 ======");

    // 首轮先做基准测试
    let mut benchmarked = false;

    loop {
        // ---- 准备阶段 ----
        let puzzle = match get_puzzle(&client, &base_url, &session.session_token, &visitor_id).await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[!] 获取谜题失败: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        println!(
            "[*] 谜题: seed={}... diff={} mem={}MB t={} p={} threads={}",
            &puzzle.seed[..16.min(puzzle.seed.len())],
            puzzle.difficulty,
            puzzle.memory_cost / 1024,
            puzzle.time_cost,
            puzzle.parallelism,
            thread_count,
        );

        // ---- 首轮基准测试 ----
        if !benchmarked {
            benchmarked = true;
            println!("[*] ====== 基准测试 ======");

            let bench_seed = puzzle.seed.clone();
            let bench_vid = visitor_id.clone();
            let bench_ip = ip.clone();
            let bench_mem = puzzle.memory_cost;
            let bench_time = puzzle.time_cost;
            let bench_par = puzzle.parallelism;
            let bench_diff = puzzle.difficulty;
            let bench_threads = thread_count;

            let bench_result = tokio::task::spawn_blocking(move || {
                let salt_str = format!("{}|{}|{}", bench_seed, bench_vid, bench_ip);
                let salt_bytes = salt_str.as_bytes();

                let params =
                    Params::new(bench_mem, bench_time, bench_par, Some(32)).unwrap();
                let block_count = params.block_count();
                let ctx = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

                let mut memory = vec![argon2::Block::default(); block_count];
                let mut hash_output = [0u8; 32];

                // 先跑 1 次预热（让内存分配和缓存就位）
                ctx.hash_password_into_with_memory(
                    b"999999999",
                    salt_bytes,
                    &mut hash_output,
                    &mut memory,
                )
                .unwrap();

                // 正式跑 3 次取平均
                const BENCH_ROUNDS: u32 = 3;
                let t0 = Instant::now();
                for i in 0..BENCH_ROUNDS {
                    let nonce_str = format!("{}", 1_000_000 + i);
                    ctx.hash_password_into_with_memory(
                        nonce_str.as_bytes(),
                        salt_bytes,
                        &mut hash_output,
                        &mut memory,
                    )
                    .unwrap();
                }
                let total = t0.elapsed();
                let per_hash = total / BENCH_ROUNDS;
                let single_hps = 1.0 / per_hash.as_secs_f64();

                (per_hash, single_hps, bench_threads, bench_diff)
            })
            .await
            .unwrap();

            let (per_hash, single_hps, threads, diff) = bench_result;
            let total_hps = single_hps * threads as f64;
            let expected_hashes = 2u64.pow(diff);
            let expected_secs = expected_hashes as f64 / total_hps;

            println!("[*] 单线程: {:.3}s/hash ({:.2} H/s)", per_hash.as_secs_f64(), single_hps);
            println!("[*] {}线程预估: {:.2} H/s", threads, total_hps);
            println!("[*] 浏览器 WASM: 13.76 H/s | 全网: 441.12 H/s");
            println!(
                "[*] 对比: 本机 vs WASM = {:.1}x | 本机占全网 = {:.1}%",
                total_hps / 13.76,
                total_hps / 441.12 * 100.0,
            );
            println!(
                "[*] 难度={}: 期望 2^{} = {} 次哈希, 预计耗时 {:.1}s ({:.1}min)",
                diff, diff, expected_hashes, expected_secs, expected_secs / 60.0,
            );
            println!("[*] ========================");
        }

        let found = Arc::new(AtomicBool::new(false));
        let (result_tx, result_rx) = std::sync::mpsc::channel::<MiningResult>();

        let start_time = Instant::now();

        // ---- 挖矿阶段（零输出） ----
        let mut handles = Vec::with_capacity(thread_count as usize);
        for i in 0..thread_count {
            let found = found.clone();
            let tx = result_tx.clone();
            let seed = puzzle.seed.clone();
            let vid = visitor_id.clone();
            let ip_c = ip.clone();

            handles.push(std::thread::spawn(move || {
                mine_worker(
                    i,
                    thread_count,
                    seed,
                    vid,
                    ip_c,
                    puzzle.difficulty,
                    puzzle.memory_cost,
                    puzzle.time_cost,
                    puzzle.parallelism,
                    found,
                    tx,
                );
            }));
        }
        drop(result_tx);

        // 等待挖矿结果
        let mining_result = tokio::task::spawn_blocking(move || result_rx.recv()).await;

        // 停止所有线程
        found.store(true, Ordering::SeqCst);
        for h in handles {
            let _ = h.join();
        }

        let elapsed = start_time.elapsed();

        // ---- 结果阶段 ----
        match mining_result {
            Ok(Ok(result)) => {
                println!(
                    "[+] 找到解! nonce={} hash={}... 耗时={:.2}s",
                    result.nonce,
                    &result.hash_hex[..16],
                    elapsed.as_secs_f64(),
                );

                // 自动提交
                match submit_solution(
                    &client,
                    &base_url,
                    &session.session_token,
                    &visitor_id,
                    &puzzle.seed,
                    &trace_data,
                    &result,
                )
                .await
                {
                    Ok(verify) => {
                        save_invite_code(&verify.invite_code);
                        println!(
                            "[+] 获胜! 邀请码={} (已保存到 {})",
                            verify.invite_code, INVITE_CODE_FILE,
                        );
                    }
                    Err(e) => {
                        eprintln!("[!] 提交失败: {} — 继续下一轮", e);
                    }
                }
            }
            _ => {
                eprintln!("[!] 挖矿异常，重新获取谜题");
            }
        }
    }
}
