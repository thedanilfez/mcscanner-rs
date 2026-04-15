use crate::packets;
use crate::protocol::read_compressed_packet;
use crate::protocol::read_string_from_cursor;
use crate::protocol::read_varint_from_cursor;
use crate::protocol::send_packet;
use crate::protocol::{read_string, read_varint};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::debug;

pub async fn scan(
    addr: &str,
    port_arg: u16,
) -> Result<(i64, i64, String, bool), Box<dyn std::error::Error + Send + Sync>> {
    let (host, port_str) = addr.split_once(':').unwrap_or((addr, ""));
    let port: u16 = if port_arg != 25565 && port_arg != 0 {
        port_arg
    } else {
        port_str.parse().unwrap_or(25565)
    };

    let con = format!("{}:{}", host, port);
    let mut stream =
        tokio::time::timeout(Duration::from_millis(2500), TcpStream::connect(&con)).await??;
    let handshake = packets::handshake(host, port, 765, 1);

    send_packet(&mut stream, &handshake).await?;
    send_packet(&mut stream, &[0x00]).await?;

    let _len = read_varint(&mut stream).await?;
    let _id = read_varint(&mut stream).await?;
    let json_str = read_string(&mut stream).await?;

    let v: Value = serde_json::from_str(&json_str)?;

    let players = v["players"]["online"].as_i64().unwrap_or(0);
    let max = v["players"]["max"].as_i64().unwrap_or(0);

    // protocol version for WL check
    let proto = v["version"]["protocol"].as_i64().unwrap_or(765) as i32;

    let motd = v["description"]["text"]
        .as_str()
        .or_else(|| v["description"].as_str())
        .unwrap_or("No description")
        .to_string();
    drop(stream);

    let wh = match is_whitelisted(host, port, proto).await {
        Ok(val) => val,
        Err(e) => {
            debug!("WL check failed for {}: {}", host, e);
            true
        }
    };

    Ok((players, max, motd, wh))
}

async fn is_whitelisted(
    host: &str,
    port: u16,
    proto: i32,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = tokio::time::timeout(
        Duration::from_millis(2500),
        TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await??;

    let handshake = packets::handshake(host, port, proto, 2);
    send_packet(&mut stream, &handshake).await?;

    // login packet
    let login = packets::login("Infernope", proto);
    send_packet(&mut stream, &login).await?;

    let mut current_threshold: i32 = -1;

    loop {
        let result = read_compressed_packet(&mut stream, current_threshold).await;

        let (id, body) = match result {
            Ok(res) => res,
            Err(e) => {
                if e.kind() == tokio::io::ErrorKind::UnexpectedEof {
                    debug!(
                        "[{}] Connection closed by server (EOF). Assuming Whitelist.",
                        host
                    );
                    return Ok(true);
                }
                return Err(e.into());
            }
        };

        match id {
            0x03 => {
                let mut cursor = std::io::Cursor::new(body);
                current_threshold = read_varint_from_cursor(&mut cursor)?;
                debug!(
                    "[{}] Compression threshold set to: {}",
                    host, current_threshold
                );
            }
            0x00 => {
                let mut cursor = std::io::Cursor::new(body);

                let reason_json = match read_string_from_cursor(&mut cursor) {
                    Ok(reason) => reason,
                    Err(_) => "unknown".to_string(),
                };

                let v: Value = serde_json::from_str(&reason_json).unwrap_or_default();

                let r = if let Some(text) = v["text"].as_str() {
                    text.to_string()
                } else if let Some(translate) = v["translate"].as_str() {
                    match translate {
                        "multiplayer.disconnect.not_whitelisted" => "Not whitelisted".to_string(),
                        "multiplayer.disconnect.banned" => "Banned".to_string(),
                        _ => translate.to_string(),
                    }
                } else {
                    reason_json
                };

                debug!("[{}] Disconnected with reason: {}", host, r);

                return Ok(true);
            }
            0x01 => return Ok(true),
            0x02 => return Ok(false),
            _ => {
                debug!("[{}] Received packet {:#04x}, still waiting...", host, id);
            }
        }
    }
}
