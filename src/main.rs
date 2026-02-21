//! HashPass Bridge — 本地 Argon2d 计算引擎
//!
//! 通过 WebSocket 接收浏览器端的挖矿任务，利用原生多线程加速 Argon2d 计算。
//! 浏览器端 JS 脚本负责所有网络交互（Turnstile、Session、API 提交、服务器 WebSocket）。

use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const INVITE_CODE_FILE: &str = "invite_codes.txt";
const DEFAULT_PORT: u16 = 19526;

const RELAY_HTML: &str = r#"<!DOCTYPE html><html><head><title>HashPass Relay</title></head><body>
<p id="s">Connecting...</p>
<script>
(function(){
var O=window.opener;
if(!O){document.getElementById("s").textContent="Error: no opener window";return}
var ws=new WebSocket("ws://"+location.host+"/");
ws.onopen=function(){O.postMessage({_r:1,t:"open"},"*");document.getElementById("s").textContent="Relay Active"};
ws.onmessage=function(e){O.postMessage({_r:1,t:"msg",d:e.data},"*")};
ws.onerror=function(){O.postMessage({_r:1,t:"err"},"*")};
ws.onclose=function(){O.postMessage({_r:1,t:"close"},"*");document.getElementById("s").textContent="Disconnected"};
window.addEventListener("message",function(e){if(e.data&&e.data._r===1&&e.data.t==="send"&&ws.readyState===1)ws.send(e.data.d)});
})();
</script></body></html>"#;

// ============================================================
// WS 协议 — 浏览器 → Rust
// ============================================================

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMsg {
    #[serde(rename = "mine")]
    Mine {
        seed: String,
        #[serde(rename = "visitorId")]
        visitor_id: String,
        ip: String,
        difficulty: u32,
        #[serde(rename = "memoryCost")]
        memory_cost: u32,
        #[serde(rename = "timeCost")]
        time_cost: u32,
        parallelism: u32,
    },
    #[serde(rename = "stop")]
    Stop,
    #[serde(rename = "invite_code")]
    InviteCode { code: String },
}

// ============================================================
// WS 协议 — Rust → 浏览器
// ============================================================

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerMsg {
    #[serde(rename = "ready")]
    Ready { threads: u32 },
    #[serde(rename = "status")]
    Status {
        #[serde(rename = "hashRate")]
        hash_rate: f64,
        #[serde(rename = "bestNonce")]
        best_nonce: u64,
        #[serde(rename = "bestHash")]
        best_hash: String,
        #[serde(rename = "bestLeadingZeros")]
        best_leading_zeros: u32,
    },
    #[serde(rename = "solution")]
    Solution { nonce: u64, hash: String },
    #[serde(rename = "stopped")]
    Stopped {
        #[serde(rename = "bestNonce")]
        best_nonce: u64,
        #[serde(rename = "bestHash")]
        best_hash: String,
        #[serde(rename = "bestLeadingZeros")]
        best_leading_zeros: u32,
    },
}

// ============================================================
// Argon2d 挖矿核心 — 零开销热路径
// ============================================================

struct MiningResult {
    nonce: u64,
    hash_hex: String,
}

struct BestHashState {
    nonce: u64,
    hash_hex: String,
    leading_zeros: u32,
}

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
    tx: tokio::sync::mpsc::Sender<MiningResult>,
    best: Arc<std::sync::Mutex<BestHashState>>,
    hash_counter: Arc<AtomicU64>,
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

        hash_counter.fetch_add(1, Ordering::Relaxed);

        let zeros = count_leading_zero_bits(&hash_output);

        // 仅在有改善时加锁更新
        {
            let mut best_lock = best.lock().unwrap();
            if zeros > best_lock.leading_zeros
                || (zeros == best_lock.leading_zeros && nonce < best_lock.nonce)
            {
                best_lock.leading_zeros = zeros;
                best_lock.nonce = nonce;
                best_lock.hash_hex = hex::encode(hash_output);
            }
        }

        if zeros >= difficulty {
            found.store(true, Ordering::SeqCst);
            let _ = tx.blocking_send(MiningResult {
                nonce,
                hash_hex: hex::encode(hash_output),
            });
            return;
        }

        nonce += thread_count as u64;
    }
}

// ============================================================
// 挖矿任务管理
// ============================================================

struct MiningJob {
    found: Arc<AtomicBool>,
    best: Arc<std::sync::Mutex<BestHashState>>,
    hash_counter: Arc<AtomicU64>,
    handles: Vec<std::thread::JoinHandle<()>>,
    start_time: Instant,
    last_count: u64,
    last_time: Instant,
}

impl MiningJob {
    fn start(
        seed: &str,
        visitor_id: &str,
        ip: &str,
        difficulty: u32,
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        thread_count: u32,
        solution_tx: tokio::sync::mpsc::Sender<MiningResult>,
    ) -> Self {
        let found = Arc::new(AtomicBool::new(false));
        let best = Arc::new(std::sync::Mutex::new(BestHashState {
            nonce: 0,
            hash_hex: String::new(),
            leading_zeros: 0,
        }));
        let hash_counter = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::with_capacity(thread_count as usize);
        for i in 0..thread_count {
            let found = found.clone();
            let tx = solution_tx.clone();
            let seed = seed.to_string();
            let vid = visitor_id.to_string();
            let ip_c = ip.to_string();
            let best = best.clone();
            let counter = hash_counter.clone();

            handles.push(std::thread::spawn(move || {
                mine_worker(
                    i,
                    thread_count,
                    seed,
                    vid,
                    ip_c,
                    difficulty,
                    memory_cost,
                    time_cost,
                    parallelism,
                    found,
                    tx,
                    best,
                    counter,
                );
            }));
        }

        let now = Instant::now();
        MiningJob {
            found,
            best,
            hash_counter,
            handles,
            start_time: now,
            last_count: 0,
            last_time: now,
        }
    }

    /// 停止挖矿，返回最优哈希状态
    fn stop(&mut self) -> (u64, String, u32) {
        self.found.store(true, Ordering::SeqCst);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
        let best = self.best.lock().unwrap();
        (best.nonce, best.hash_hex.clone(), best.leading_zeros)
    }

    /// 获取当前状态用于推送
    fn get_status(&mut self) -> ServerMsg {
        let now = Instant::now();
        let current_count = self.hash_counter.load(Ordering::Relaxed);
        let elapsed = now.duration_since(self.last_time).as_secs_f64();

        let hash_rate = if elapsed > 0.1 {
            (current_count - self.last_count) as f64 / elapsed
        } else {
            0.0
        };

        self.last_count = current_count;
        self.last_time = now;

        let best = self.best.lock().unwrap();
        ServerMsg::Status {
            hash_rate,
            best_nonce: best.nonce,
            best_hash: best.hash_hex.clone(),
            best_leading_zeros: best.leading_zeros,
        }
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
// HTTP 中继页面服务
// ============================================================

async fn serve_relay_page(mut stream: tokio::net::TcpStream) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let _ = stream.read(&mut buf).await?;

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        RELAY_HTML.len(),
        RELAY_HTML
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

// ============================================================
// TCP 连接路由 — 区分 HTTP / WebSocket
// ============================================================

async fn handle_tcp(stream: tokio::net::TcpStream, addr: std::net::SocketAddr, thread_count: u32) {
    let mut peek_buf = [0u8; 2048];
    let n = match stream.peek(&mut peek_buf).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[!] peek 错误 {}: {}", addr, e);
            return;
        }
    };

    let request = std::str::from_utf8(&peek_buf[..n]).unwrap_or("");
    let is_ws = request.contains("Upgrade:") || request.contains("upgrade:");

    if is_ws {
        println!("[+] WebSocket 连接: {}", addr);
        match handle_ws_connection(stream, thread_count).await {
            Ok(()) => println!("[*] WebSocket 连接结束: {}", addr),
            Err(e) => eprintln!("[!] WebSocket 错误 {}: {}", addr, e),
        }
    } else {
        println!("[*] 提供中继页面: {}", addr);
        if let Err(e) = serve_relay_page(stream).await {
            eprintln!("[!] HTTP 错误 {}: {}", addr, e);
        }
    }
}

// ============================================================
// WebSocket 连接处理
// ============================================================

async fn handle_ws_connection(
    stream: tokio::net::TcpStream,
    thread_count: u32,
) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut write, mut read) = ws.split();

    // 发送 ready
    let ready_json = serde_json::to_string(&ServerMsg::Ready { threads: thread_count })?;
    write.send(Message::Text(ready_json.into())).await?;
    println!("[+] 已发送 ready (threads={})", thread_count);

    // 持久 solution 通道 — 跨多轮挖矿复用
    let (solution_tx, mut solution_rx) = tokio::sync::mpsc::channel::<MiningResult>(4);
    let mut mining_job: Option<MiningJob> = None;
    let mut status_interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            // ---- 浏览器消息 ----
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let text_str = text.to_string();
                        match serde_json::from_str::<ClientMsg>(&text_str) {
                            Ok(ClientMsg::Mine {
                                seed, visitor_id, ip,
                                difficulty, memory_cost, time_cost, parallelism,
                            }) => {
                                // 停止旧任务
                                if let Some(mut job) = mining_job.take() {
                                    let (_, _, zeros) = job.stop();
                                    println!("[*] 停止旧任务 (best={}零)", zeros);
                                }
                                // 排空旧 solution
                                while solution_rx.try_recv().is_ok() {}

                                println!(
                                    "[*] 开始挖矿: seed={}... diff={} mem={}MB t={} p={} threads={}",
                                    &seed[..16.min(seed.len())],
                                    difficulty,
                                    memory_cost / 1024,
                                    time_cost,
                                    parallelism,
                                    thread_count,
                                );

                                mining_job = Some(MiningJob::start(
                                    &seed, &visitor_id, &ip,
                                    difficulty, memory_cost, time_cost, parallelism,
                                    thread_count,
                                    solution_tx.clone(),
                                ));
                                status_interval.reset();
                            }
                            Ok(ClientMsg::Stop) => {
                                let (nonce, hash, zeros) = if let Some(mut job) = mining_job.take() {
                                    let elapsed = job.start_time.elapsed();
                                    let result = job.stop();
                                    println!(
                                        "[*] 停止挖矿: best={}零 nonce={} 耗时={:.1}s",
                                        result.2, result.0, elapsed.as_secs_f64(),
                                    );
                                    result
                                } else {
                                    (0, String::new(), 0)
                                };
                                let msg = ServerMsg::Stopped {
                                    best_nonce: nonce,
                                    best_hash: hash,
                                    best_leading_zeros: zeros,
                                };
                                let json = serde_json::to_string(&msg)?;
                                write.send(Message::Text(json.into())).await?;
                            }
                            Ok(ClientMsg::InviteCode { code }) => {
                                save_invite_code(&code);
                                println!("[+] 收到邀请码: {} (已保存到 {})", code, INVITE_CODE_FILE);
                            }
                            Err(e) => {
                                eprintln!("[!] 消息解析失败: {}", e);
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = write.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        println!("[*] 浏览器断开连接");
                        break;
                    }
                    Some(Err(e)) => {
                        eprintln!("[!] WebSocket 错误: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            // ---- 挖矿线程找到解 ----
            result = solution_rx.recv() => {
                if let Some(result) = result {
                    if let Some(job) = mining_job.as_ref() {
                        let elapsed = job.start_time.elapsed();
                        println!(
                            "[+] 找到解! nonce={} hash={}... 耗时={:.2}s",
                            result.nonce,
                            &result.hash_hex[..16],
                            elapsed.as_secs_f64(),
                        );
                    }
                    // 发送给浏览器
                    let msg = ServerMsg::Solution {
                        nonce: result.nonce,
                        hash: result.hash_hex,
                    };
                    let json = serde_json::to_string(&msg)?;
                    write.send(Message::Text(json.into())).await?;

                    // 清理挖矿任务（线程已自行退出）
                    if let Some(mut job) = mining_job.take() {
                        job.stop();
                    }
                }
            }
            // ---- 定时推送状态 ----
            _ = status_interval.tick() => {
                if let Some(job) = mining_job.as_mut() {
                    let msg = job.get_status();
                    let json = serde_json::to_string(&msg)?;
                    write.send(Message::Text(json.into())).await?;
                }
            }
        }
    }

    // 连接断开，停止挖矿
    if let Some(mut job) = mining_job.take() {
        job.stop();
        println!("[*] 连接断开，挖矿已停止");
    }

    Ok(())
}

// ============================================================
// 主函数
// ============================================================

fn print_banner() {
    println!();
    println!("  ╔═══════════════════════════════════════════╗");
    println!("  ║   HashPass Bridge — Rust 本地计算引擎     ║");
    println!("  ║   等待浏览器 JS 桥接脚本连接              ║");
    println!("  ╚═══════════════════════════════════════════╝");
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    print_banner();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("用法: hashpass-machine [选项]");
        println!();
        println!("选项:");
        println!("  --threads=<N>   挖矿线程数 (默认: CPU 核心数)");
        println!("  --port=<PORT>   WebSocket 端口 (默认: {})", DEFAULT_PORT);
        println!("  --help          显示帮助");
        println!();
        println!("启动后在浏览器控制台粘贴 JS 桥接脚本即可开始挖矿。");
        println!("邀请码自动保存到 {}", INVITE_CODE_FILE);
        return Ok(());
    }

    let thread_count: u32 = args
        .iter()
        .find(|a| a.starts_with("--threads="))
        .and_then(|a| a.trim_start_matches("--threads=").parse().ok())
        .unwrap_or(num_cpus::get() as u32);

    let port: u16 = args
        .iter()
        .find(|a| a.starts_with("--port="))
        .and_then(|a| a.trim_start_matches("--port=").parse().ok())
        .unwrap_or(DEFAULT_PORT);

    println!("[*] 线程数: {}", thread_count);
    println!("[*] 监听端口: http://localhost:{}", port);
    println!("[*] 中继模式: 浏览器通过弹窗中继页面与 Rust 通信");
    println!("[*] 邀请码保存: {}", INVITE_CODE_FILE);
    println!();
    println!("[*] 等待浏览器连接...");

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            handle_tcp(stream, addr, thread_count).await;
        });
    }
}
