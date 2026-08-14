mod balancer;
mod cfproxy;
mod config;
mod crypto;
mod proxy;
mod ws;

use config::*;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use proxy::{WsPool, parse_cidr_pool, run_proxy};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// Глобальный рантайм — никогда не дропается
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

static STATE: OnceCell<Mutex<Option<ProxyState>>> = OnceCell::new();

#[inline]
fn state_cell() -> &'static Mutex<Option<ProxyState>> {
    STATE.get_or_init(|| Mutex::new(None))
}

#[inline]
fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("tgwsproxy-rt")
            .enable_all()
            .build()
            .expect("failed to build global tokio runtime")
    })
}

struct ProxyState {
    pool: Arc<WsPool>,
    handle: tokio::task::JoinHandle<()>,
    summary_handle: Option<tokio::task::JoinHandle<()>>,
    cancel_tasks: CancellationToken,
}

fn main() {
    let mut host = "127.0.0.1".to_string();
    let mut port = DEFAULT_PORT;
    let mut dc_ips = String::new();
    let mut user_domain = String::new();
    let mut verbose = false;
    let mut console = true;
    let mut cf_enabled = false;

    #[cfg(target_os = "android")]
    let mut cache_dir: PathBuf = PathBuf::from("/data/tmp".to_string());

    #[cfg(all(target_os = "linux", not(target_os = "android")))]
    let mut cache_dir: PathBuf =
        PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/TgWsProxyCli");

    #[cfg(target_os = "windows")]
    let mut cache_dir: PathBuf =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join("TgWsProxyCli");

    let args = std::env::args().collect::<Vec<String>>();
    let mut i = 1; // пропускаем имя программы
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" | "-V" => {
                println!("{}", APP_VERSION);
                return;
            }
            "--host" => {
                host = args[i + 1].clone();
            }
            "--port" => {
                port = args[i + 1].clone().parse().unwrap();
            }
            "--secret" => {
                let res = set_secret(args[i + 1].clone());
                if res.is_err() {
                    lerror!("{}", res.unwrap_err());
                    return;
                }
            }
            "--dc" => {
                dc_ips = args[i + 1].clone();
            }
            "--user-domains" => {
                user_domain = args[i + 1].clone();
            }
            "--pool-size" => {
                let size: i32 = args[i + 1].clone().parse().unwrap();
                set_pool_size(size);
            }
            "--cache-dir" => {
                let path = args[i + 1].clone();
                let path_buf = PathBuf::from(path.clone());
                if path_buf.is_file() && path_buf.exists() {
                    return;
                }
                cache_dir = PathBuf::from(path);
            }
            "--verbose" => {
                verbose = true;
                i += 1;
                continue;
            }
            "--enable-cf" => {
                cf_enabled = true;
                i += 1;
                continue;
            }
            "--no-console" => {
                console = false;
            }
            _ => {
                lerror!("Unknown arg {}", args[i]);
                return;
            }
        }
        i += 2;
    }
    drop(args);

    set_cf_proxy_cache_dir(cache_dir);
    set_cf_proxy_config(cf_enabled, user_domain);
    start_proxy(host, port, dc_ips, verbose, console);

    ctrlc::set_handler(|| {
        linfo!("\r\nCTRL+C received");
        stop_proxy();
        std::process::exit(0);
    })
    .unwrap();

    loop {
        let (handle, summary_handle) = {
            let guard = state_cell().lock();

            match guard.as_ref() {
                Some(state) => {
                    let mut sh = true;
                    if let Some(summary_handle) = &state.summary_handle {
                        sh = summary_handle.is_finished()
                    }
                    (state.handle.is_finished(), sh)
                }
                None => break,
            }
        };

        if handle && summary_handle {
            break;
        }

        std::thread::sleep(Duration::from_millis(50));
    }
    stop_proxy();
}

fn start_proxy(host: String, port: u16, dc_ips: String, verbose: bool, console: bool) {
    init_logging(verbose, console);
    cfproxy::clear_cfproxy_429_cooldowns();

    cfproxy::init_cfproxy_domains();

    let dc_opt_map: HashMap<i32, String> = parse_cidr_pool(&dc_ips);

    let rt = runtime();
    let cancel_tasks = CancellationToken::new();
    let pool = Arc::new(WsPool::new(cancel_tasks.clone()));

    // Канал готовности: ждём успешного bind перед возвратом
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();

    let pool_task = pool.clone();
    let host_task = host.clone();
    let map_task = dc_opt_map.clone();
    let cancel_root = cancel_tasks.clone();

    let handle = rt.spawn(async move {
        // Предварительный bind для сигнала готовности
        let addr = format!("{}:{}", host_task, port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                let _ = tx.send(Ok(()));
                if let Err(e) =
                    run_proxy(pool_task, host_task, port, map_task, cancel_root, listener).await
                {
                    lerror!("listen on {}: {}", addr, e);
                }
            }
            Err(e) => {
                let _ = tx.send(Err(format!("listen on {}: {}", addr, e)));
            }
        }
    });

    let mut summary_handle = None;
    if verbose {
        summary_handle = Some({
            let token = cancel_tasks.clone();
            rt.spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(60)) => {
                            ldebug!("\n{}", STATS.summary_full());
                        }
                    }
                }
            })
        });
    }

    // Ждём результат bind
    match rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            handle.abort();
            return;
        }
        Err(_) => {
            handle.abort();
            return;
        }
    }

    {
        let cell = state_cell();
        let mut guard = cell.lock();

        if guard.is_some() {
            return;
        }
        *guard = Some(ProxyState {
            pool,
            handle,
            summary_handle,
            cancel_tasks,
        });
    }
}

fn stop_proxy() {
    let state = {
        let mut guard = state_cell().lock();

        match guard.take() {
            Some(s) => s,
            None => return,
        }
    };

    // graceful shutdown — НЕ дропаем рантайм
    linfo!("StopProxy: cancelling all tasks");
    state.cancel_tasks.cancel();

    let rt = runtime();
    let pool = state.pool.clone();
    let handle = state.handle;
    let summary_handle = state.summary_handle;
    rt.block_on(async move {
        linfo!("StopProxy: waiting for proxy tasks to finish (max 2s)");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        if summary_handle.is_some() {
            summary_handle.unwrap().abort();
        }
        linfo!("StopProxy: closing pool connections");
        pool.close_all().await;
        linfo!("StopProxy: done");
    });

    STATS.reset();
    WS_BLACKLIST.write().clear();
    DC_FAIL_UNTIL.write().clear();
    cfproxy::clear_cfproxy_429_cooldowns();

    linfo!("StopProxy: exit");
}

fn print_help() {
    println!(
        "
Usage:
    tg-ws-proxy-cli [OPTIONS]

Options:
    -h, --help                 Show this help message
    -V, --version              Show version information

    --host <HOST>              Local listen address
    --port <PORT>              Local listen port
    --secret <SECRET>          MTProto secret
    --dc <ID:IP>               Override Telegram DC address
    --user-domains <DOMAIN>    Custom Cloudflare domain(s)
    --pool-size <SIZE>         WebSocket connection pool size
    --cache-dir <PATH>         Cache directory
    --verbose                  Enable verbose logging
    --enable-cf                Route all connections through Cloudflare
    --no-console               Disable console output
"
    );
}

#[inline]
fn set_pool_size(size: i32) {
    let mut n = size;
    if n < 2 {
        n = 2;
    }
    if n > 16 {
        n = 16;
    }
    POOL_SIZE.store(n, Ordering::Relaxed);
}

#[inline]
fn set_cf_proxy_cache_dir(cache_dir: PathBuf) {
    CFPROXY.write().cache_dir = cache_dir;
}

fn set_cf_proxy_config(enabled: bool, user_domain: String) {
    CFPROXY_ENABLED.store(enabled, Ordering::Relaxed);
    let mut cfg = CFPROXY.write();
    cfg.user_domain = user_domain.clone();
    if !user_domain.is_empty() {
        cfg.domains = vec![user_domain.clone()];
        cfg.active = user_domain;
    }
}

fn set_secret(secret: String) -> Result<(), String> {
    if secret.len() != 32 {
        return Err("the secret is too short".to_string());
    }
    if hex::decode(&secret).is_err() {
        return Err("invalid secret".to_string());
    }
    *PROXY_SECRET.write() = secret;
    Ok(())
}
