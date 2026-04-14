use crate::packets;
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

    let wh = is_whitelisted(host, port, proto).await.unwrap_or(false);

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

    // received
    let len = read_varint(&mut stream).await?;
    let id = read_varint(&mut stream).await?;

    debug!("[{}] len: {} id: {:#04x}", host, len, id);

    match id {
        // 0x00 - Disconnected
        0x00 => return Ok(true),
        // 0x01 - encryption request (online mode)
        0x01 => return Ok(true),
        // 0x03 - Success
        0x03 => return Ok(false),
        _ => return Ok(true),
    }
}
