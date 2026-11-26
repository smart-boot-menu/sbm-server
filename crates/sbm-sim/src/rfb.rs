//! A tiny RFB 3.8 server. The framebuffer is a painted rectangle, not a desktop.

use crate::ws::Socket;
use crate::{SimError, SimResult};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

const WIDTH: u16 = 160;
const HEIGHT: u16 = 100;

pub async fn serve_vnc(mut socket: Socket) -> SimResult<()> {
    send(&mut socket, b"RFB 003.008\n").await?;
    let mut buf = Vec::new();
    read_exact(&mut socket, &mut buf, 12).await?;
    buf.drain(..12);
    send(&mut socket, &[1, 1]).await?;
    read_exact(&mut socket, &mut buf, 1).await?;
    buf.drain(..1);
    send(&mut socket, &[0, 0, 0, 0]).await?;
    read_exact(&mut socket, &mut buf, 1).await?;
    buf.drain(..1);
    send(&mut socket, &server_init()).await?;
    send(&mut socket, &framebuffer()).await?;
    loop {
        if !next_message(&mut socket, &mut buf).await? {
            return Ok(());
        }
        let kind = buf[0];
        match kind {
            0 => drain(&mut socket, &mut buf, 20).await?,
            2 => {
                drain(&mut socket, &mut buf, 4).await?;
                let count = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                drain(&mut socket, &mut buf, 4 + count * 4).await?;
                buf.drain(..4 + count * 4);
            }
            3 => {
                drain(&mut socket, &mut buf, 10).await?;
                buf.drain(..10);
                send(&mut socket, &framebuffer()).await?;
            }
            4 => {
                drain(&mut socket, &mut buf, 8).await?;
                buf.drain(..8);
            }
            5 => {
                drain(&mut socket, &mut buf, 6).await?;
                buf.drain(..6);
            }
            6 => {
                drain(&mut socket, &mut buf, 8).await?;
                let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
                drain(&mut socket, &mut buf, 8 + len).await?;
                buf.drain(..8 + len);
            }
            _ => {
                buf.remove(0);
            }
        }
    }
}

fn server_init() -> Vec<u8> {
    let name = b"sbm-sim (no hardware)";
    let mut out = Vec::new();
    out.extend(WIDTH.to_be_bytes());
    out.extend(HEIGHT.to_be_bytes());
    out.extend([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
    out.extend((name.len() as u32).to_be_bytes());
    out.extend(name);
    out
}

fn framebuffer() -> Vec<u8> {
    let mut out = vec![0, 0];
    out.extend(1u16.to_be_bytes());
    out.extend(0u16.to_be_bytes());
    out.extend(0u16.to_be_bytes());
    out.extend(WIDTH.to_be_bytes());
    out.extend(HEIGHT.to_be_bytes());
    out.extend(0i32.to_be_bytes());
    for y in 0..HEIGHT {
        for _x in 0..WIDTH {
            if y < 14 {
                out.extend([40, 44, 48, 0]);
            } else {
                out.extend([51, 115, 184, 0]);
            }
        }
    }
    out
}

async fn send(socket: &mut Socket, bytes: &[u8]) -> SimResult<()> {
    socket
        .send(Message::Binary(bytes.to_vec().into()))
        .await
        .map_err(|err| SimError(err.to_string()))
}

async fn next_message(socket: &mut Socket, buf: &mut Vec<u8>) -> SimResult<bool> {
    if !buf.is_empty() {
        return Ok(true);
    }
    recv(socket, buf).await
}

async fn drain(socket: &mut Socket, buf: &mut Vec<u8>, needed: usize) -> SimResult<()> {
    read_exact(socket, buf, needed).await
}

async fn read_exact(socket: &mut Socket, buf: &mut Vec<u8>, needed: usize) -> SimResult<()> {
    while buf.len() < needed {
        if !recv(socket, buf).await? {
            return Err(SimError("VNC client closed the tunnel".to_string()));
        }
    }
    Ok(())
}

async fn recv(socket: &mut Socket, buf: &mut Vec<u8>) -> SimResult<bool> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                buf.extend_from_slice(&bytes);
                return Ok(true);
            }
            Some(Ok(Message::Text(text))) => {
                buf.extend_from_slice(text.as_bytes());
                return Ok(true);
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Close(_))) | None => return Ok(false),
            Some(Ok(_)) => return Ok(true),
            Some(Err(err)) => return Err(SimError(err.to_string())),
        }
    }
}
