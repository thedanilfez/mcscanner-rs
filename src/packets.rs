use crate::protocol::{write_string, write_varint};

pub fn handshake(host: &str, port: u16, proto: i32, state: i32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x00);
    write_varint(&mut buf, proto);
    write_string(&mut buf, &host);
    buf.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut buf, state);
    buf
}

pub fn login(name: &str, proto: i32) -> Vec<u8> {
    let mut login = Vec::new();
    login.push(0x00);
    write_string(&mut login, name);

    // pomogite
    if proto >= 764 {
        login.extend_from_slice(&[0u8; 16]);
    } else if proto >= 761 {
        login.push(0x00);
        login.push(0x01);
        login.extend_from_slice(&[0u8; 16]);
    } else if proto >= 759 {
        login.push(0x00);
        login.push(0x00);
    }
    login
}
