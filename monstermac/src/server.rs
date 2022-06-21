use std::result;

use async_std::fs;
use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use http_types::{Method, Request, Response, StatusCode};
use kv_log_macro::{debug, error};

use crate::config;

type Result<T> = result::Result<T, &'static str>;

pub fn run_forever(listener: std::net::TcpListener) {
    let listener = TcpListener::from(listener);

    task::block_on(serve_forever(listener));
}

async fn serve_forever(listener: TcpListener) {
    while let Some(stream) = listener.incoming().next().await {
        match stream {
            Ok(s) => {
                task::spawn(handle_stream(s));
            }
            Err(e) => {
                debug!("error in tcp stream", {
                    error: format!("{}", e),
                });
            }
        }
    }
}

async fn handle_stream(stream: TcpStream) {
    if let Err(e) = async_h1::accept(stream.clone(), handle_req).await {
        debug!("couldn't send response to client", {
            error: format!("{}", e),
        });
    }
}

async fn handle_req(mut req: Request) -> http_types::Result<Response> {
    if req.method() != Method::Post {
        return Ok(Response::new(StatusCode::BadRequest));
    }

    let body = req.body_bytes().await?;

    match compute_mac(body).await {
        Ok(mac) => {
            let mut resp = Response::new(StatusCode::Ok);
            resp.set_body(&mac[..32]);
            Ok(resp)
        }
        Err(s) => {
            error!("internal server error", {
                error: s,
            });
            Ok(Response::new(StatusCode::InternalServerError))
        }
    }
}

async fn compute_mac(val: Vec<u8>) -> Result<[u8; 32]> {
    let mut hasher = hmac_sha256::Hash::new();
    hasher.update(&val);
    let key_id = fasthash::murmur2::hash32(hasher.finalize());
    let secret = get_secret(key_id).await?;

    // Perform the mac
    let mut maccer = hmac_sha256::HMAC::new(secret);
    maccer.update(val);
    Ok(maccer.finalize())
}

async fn get_secret(key_id: u32) -> Result<Vec<u8>> {
    use config::Mode::*;
    match *config::MODE {
        Mode0 => Ok(config::SECRET0.clone()),
        Mode16 => get_secret32(key_id & 0xffff).await,
        Mode32 => get_secret32(key_id).await,
    }
}

async fn get_secret32(key_id: u32) -> Result<Vec<u8>> {
    let mut path = config::SECRET_PATH.clone();
    let filename = ((key_id & 0xffff0000) >> 16) as u16;
    path.push(&hex::encode(filename.to_le_bytes()));
    let mut file = fs::File::open(&path)
        .await
        .map_err(|_| "couldn't open secret file")?;

    let seek = (key_id & 0xffff) as u64 * 32;
    let seek = io::SeekFrom::Start(seek);
    file.seek(seek).await.map_err(|_| "couldn't seek in file")?;

    let mut secret = vec![0; 32];
    file.read_exact(&mut secret)
        .await
        .map_err(|_| "couldn't read secret from file")?;

    Ok(secret)
}
