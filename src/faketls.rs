use crate::config::*;
use crate::{ldebug, lwarn};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Порт proxy/fake_tls.py.
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

pub const CLIENT_RANDOM_OFFSET: usize = 11;
pub const CLIENT_RANDOM_LEN: usize = 32;
pub const SESSION_ID_OFFSET: usize = 44;
pub const SESSION_ID_LEN: usize = 32;

pub const TIMESTAMP_TOLERANCE: i64 = 120;
pub const TLS_APPDATA_MAX: usize = 16384;

const CCS_FRAME: &[u8] = b"\x14\x03\x03\x00\x01\x01";

// _SERVER_HELLO_TEMPLATE из оригинала (122 байта) + смещения.
const SH_RANDOM_OFF: usize = 11;
const SH_SESSID_OFF: usize = 44;
const SH_PUBKEY_OFF: usize = 89;

fn server_hello_template() -> Vec<u8> {
    let mut t = vec![
        0x16, 0x03, 0x03, 0x00, 0x7a, // record header
        0x02, 0x00, 0x00, 0x76, // server_hello
        0x03, 0x03, // version
    ];
    t.extend_from_slice(&[0u8; 32]); // random
    t.push(0x20); // session id len
    t.extend_from_slice(&[0u8; 32]); // session id
    t.extend_from_slice(&[0x13, 0x01, 0x00]); // cipher
    t.extend_from_slice(&[0x00, 0x2e]); // extensions len
    t.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    t.extend_from_slice(&[0u8; 32]); // pubkey
    t.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    t
}

pub struct TlsVerifyOk {
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
    pub timestamp: u32,
}

/// Порт verify_client_hello(data, secret).
pub fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<TlsVerifyOk> {
    let n = data.len();
    // 5 (record hdr) + 6 (hs type+len+version) + 32 (random) = 43
    if n < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    for b in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if expected[..28] != client_random[..28] {
        return None;
    }

    let mut ts_xor = [0u8; 4];
    for i in 0..4 {
        ts_xor[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_xor);

    let now = now_unix();
    if (now - timestamp as i64).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some(TlsVerifyOk {
        client_random,
        session_id,
        timestamp,
    })
}

/// Порт build_server_hello(secret, client_random, session_id).
pub fn build_server_hello(secret: &[u8], client_random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut sh = server_hello_template();
    sh[SH_SESSID_OFF..SH_SESSID_OFF + 32].copy_from_slice(session_id);
    let mut pubkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut pubkey);
    sh[SH_PUBKEY_OFF..SH_PUBKEY_OFF + 32].copy_from_slice(&pubkey);

    let mut rng = rand::thread_rng();
    let encrypted_size = rng.gen_range(1900..=2100);
    let mut encrypted_data = vec![0u8; encrypted_size];
    rng.fill_bytes(&mut encrypted_data);
    let mut app_record = vec![0x17, 0x03, 0x03, (encrypted_size >> 8) as u8, (encrypted_size & 0xFF) as u8];
    app_record.extend_from_slice(&encrypted_data);

    let mut response = sh;
    response.extend_from_slice(CCS_FRAME);
    response.extend_from_slice(&app_record);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();

    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    response
}

/// Порт wrap_tls_record(data): режем на чанки TLS_APPDATA_MAX.
pub fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len() + (data.len() / TLS_APPDATA_MAX + 1) * 5);
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + TLS_APPDATA_MAX).min(data.len());
        let chunk = &data[offset..end];
        out.push(0x17);
        out.push(0x03);
        out.push(0x03);
        out.push((chunk.len() >> 8) as u8);
        out.push((chunk.len() & 0xFF) as u8);
        out.extend_from_slice(chunk);
        offset = end;
    }
    out
}

// ---------------------------------------------------------------------------
// FakeTls transport через DuplexStream-транслятор.
//
// После успешного verify_client_hello сырой TcpStream нельзя отдать в bridge
// напрямую: клиент дальше говорит TLS-записями. Вместо ручной реализации
// AsyncRead мы поднимаем фоновый транслятор:
//   raw TLS records -> tokio::io::DuplexStream (plain) -> bridge
//   bridge plain    -> wrap_tls_record -> raw
// Bridge при этом работает с обычными plain-байтами.
// ---------------------------------------------------------------------------

pub struct FakeTlsPlain {
    pub read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    pub write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
}

/// Выполняет FakeTLS handshake на уже подключённом conn.
/// На вход: conn, у которого уже прочитан 1-й байт (0x16) — он передан в
/// first_byte. Возвращает:
/// - Ok(Some(plain)) — ee-secret клиент, можно читать 64-байтный handshake.
/// - Ok(None) — не наш клиент: соединение уже проксировано на masking-домен
///   (verify failed) либо закрыто; handle_client должен просто вернуться.
pub async fn server_handshake(
    mut conn: TcpStream,
    first_byte: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
) -> Option<FakeTlsPlain> {
    // Дочитываем TLS record header (ещё 4 байта) и тело.
    let mut hdr_rest = [0u8; 4];
    let conn_ref = &mut conn;
    if tokio::time::timeout(Duration::from_secs(10), conn_ref.read_exact(&mut hdr_rest))
        .await
        .is_err()
    {
        ldebug!(" [{}] incomplete TLS record header", label);
        return None;
    }
    let mut tls_header = vec![first_byte];
    tls_header.extend_from_slice(&hdr_rest);
    let record_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

    let mut record_body = vec![0u8; record_len];
    if tokio::time::timeout(Duration::from_secs(10), conn_ref.read_exact(&mut record_body))
        .await
        .is_err()
    {
        ldebug!(" [{}] incomplete TLS record body", label);
        return None;
    }
    let mut client_hello = tls_header;
    client_hello.extend_from_slice(&record_body);

    let verified = verify_client_hello(&client_hello, secret);
    let ok = match verified {
        Some(v) => v,
        None => {
            ldebug!(
                " [{}] Fake TLS verify failed (size={} rec={}) -> masking",
                label,
                client_hello.len(),
                record_len
            );
            // Отдаём сырое соединение (включая уже прочитанный hello) на
            // masking-домен, как proxy_to_masking_domain в оригинале.
            proxy_to_masking_domain(conn, &client_hello, masking, label).await;
            return None;
        }
    };

    ldebug!(" [{}] Fake TLS handshake ok (ts={})", label, ok.timestamp);
    let server_hello = build_server_hello(secret, &ok.client_random, &ok.session_id);
    if conn_ref.write_all(&server_hello).await.is_err() {
        return None;
    }

    // Поднимаем транслятор TLS records <-> plain duplex.
    // duplex даёт два конца A/B: конец B уходит транслятору, конец A
    // разрезаем на read/write половины и возвращаем в handle_client.
    // Транслятор разворачивает CCS/appdata, bridge видит plain-байты.
    let (raw_r, raw_w) = conn.into_split();
    let (end_a, end_b) = tokio::io::duplex(256 * 1024);
    let (a_read, a_write) = tokio::io::split(end_a);
    tokio::spawn(translator_task(raw_r, raw_w, end_b, label.to_string()));

    // Клиент после ServerHello шлёт CCS + appdata с obfs2-handshake внутри;
    // транслятор их развернёт, bridge увидит plain.
    Some(FakeTlsPlain {
        read: a_read,
        write: a_write,
    })
}

async fn translator_task(
    mut raw_r: tokio::net::tcp::OwnedReadHalf,
    mut raw_w: tokio::net::tcp::OwnedWriteHalf,
    tls_end: tokio::io::DuplexStream,
    label: String,
) {
    let (mut tl_r, mut tl_w) = tokio::io::split(tls_end);
    // raw -> plain (снимаем TLS-фрейминг, порт FakeTlsStream._read_tls_payload)
    let up = async {
        loop {
            let mut hdr = [0u8; 5];
            if raw_r.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let rtype = hdr[0];
            let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if rtype == TLS_RECORD_CCS {
                if rec_len > 0 {
                    let mut skip = vec![0u8; rec_len];
                    if raw_r.read_exact(&mut skip).await.is_err() {
                        break;
                    }
                }
                continue;
            }
            if rtype != TLS_RECORD_APPDATA {
                break;
            }
            if rec_len == 0 {
                continue;
            }
            if rec_len > 65536 + 16384 {
                break;
            }
            let mut data = vec![0u8; rec_len];
            if raw_r.read_exact(&mut data).await.is_err() {
                break;
            }
            if tl_w.write_all(&data).await.is_err() {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    };

    // plain -> raw (накладываем TLS-фрейминг, порт FakeTlsStream.write)
    let down = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tl_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let wrapped = wrap_tls_record(&buf[..n]);
            if raw_w.write_all(&wrapped).await.is_err() {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::join!(up, down);
    ldebug!(" [{}] FakeTLS translator closed", label);
}

/// Порт proxy_to_masking_domain: сырой TCP-релей к masking-домену:443.
pub async fn proxy_to_masking_domain(
    mut conn: TcpStream,
    initial_data: &[u8],
    domain: &str,
    label: &str,
) {
    if domain.is_empty() {
        return;
    }
    let mut up = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:443", domain)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            lwarn!(" [{}] masking: cannot connect to {}:443", label, domain);
            return;
        }
    };
    ldebug!(" [{}] masking -> {}:443", label, domain);
    STATS.connections_masked.fetch_add(1, Ordering::Relaxed);

    if !initial_data.is_empty() {
        if up.write_all(initial_data).await.is_err() {
            return;
        }
    }

    let (mut cr, mut cw) = conn.split();
    let (mut ur, mut uw) = up.split();

    let up_task = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if uw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = uw.shutdown().await;
    };
    let down_task = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match ur.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if cw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = cw.shutdown().await;
    };
    let _ = tokio::join!(up_task, down_task);
}
