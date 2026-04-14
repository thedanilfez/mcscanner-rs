use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn send_packet(stream: &mut TcpStream, data: &[u8]) -> tokio::io::Result<()> {
    let mut buf = Vec::new();
    write_varint(&mut buf, data.len() as i32);
    buf.extend_from_slice(data);
    stream.write_all(&buf).await
}

pub async fn read_varint(stream: &mut TcpStream) -> tokio::io::Result<i32> {
    let mut res = 0;
    let mut pos = 0;
    loop {
        let b = stream.read_u8().await?;
        res |= ((b & 0x7F) as i32) << pos;
        if (b & 0x80) == 0 {
            break;
        }
        pos += 7;
        if pos >= 32 {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "VarInt too big",
            ));
        }
    }
    Ok(res)
}

pub fn write_varint(buf: &mut Vec<u8>, val: i32) {
    let mut uval = val as u32;
    loop {
        let temp = (uval & 0x7F) as u8;
        uval >>= 7;
        if uval != 0 {
            buf.push(temp | 0x80);
        } else {
            buf.push(temp);
            break;
        }
    }
}

pub async fn read_string(stream: &mut TcpStream) -> tokio::io::Result<String> {
    let len = read_varint(stream).await?;
    if len < 0 || len > 2 * 1024 * 1024 {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "String too long",
        ));
    }
    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|e| tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e))
}

pub fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as i32);
    buf.extend_from_slice(s.as_bytes());
}
