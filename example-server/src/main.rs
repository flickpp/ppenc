use hmac_sha256::Hash as Sha256;
use hmac_sha512::Hash as Sha512;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::result;
use std::thread::Builder as ThreadBuilder;

use rand::Rng;

type Result<T> = result::Result<T, &'static str>;

fn read_token(tk: &[u8]) -> Result<(String, [u8; 16], [u8; 16])> {
    let tk = std::str::from_utf8(tk).map_err(|_| "badly formed token")?;

    // Call the monstermac
    if tk.len() != 100 {
        return Err("expected token of length 100");
    }

    let parts = tk.split('.').collect::<Vec<&str>>();
    if parts.len() != 3 {
        return Err("token does not have three parts");
    }
    if parts[0] != "00" {
        return Err("token should have version of 00");
    }
    if parts[1].len() != 64 || parts[2].len() != 32 {
        return Err("badly formed token");
    }
    let name = hex::decode(&parts[1]).map_err(|_| "badly formed token")?;
    let token_mac = hex::decode(&parts[2]).map_err(|_| "badly formed token")?;

    // Compute MonsterMac(name)
    let mmac = idcurl::Request::post("http://127.0.0.1:8081".to_string())
        .body(std::io::Cursor::new(&name))
        .send()
        .map_err(|_| "couldn't call monster mac")?
        .data()
        .map_err(|_| "couldn't read monstermac response body")
        .and_then(|m| {
            if m.len() == 32 {
                Ok(m)
            } else {
                Err("invalid monster mac response body")
            }
        })?;

    // Check the mac
    if &md5::compute(hmac_sha256::HMAC::mac(&name, &mmac))[..] != &token_mac[..] {
        return Err("invalid token mac");
    }

    let device_id = md5::compute(Sha512::hash(&mmac[..]));
    let device_salt = Sha256::hash(&Sha256::hash(&mmac[..]));
    let mut header_key_salt = [0u8; 16];
    let mut body_key_salt = [0u8; 16];
    for (v, d) in device_salt
        .into_iter()
        .zip(header_key_salt.iter_mut().chain(body_key_salt.iter_mut()))
    {
        *d = v;
    }
    Ok((hex::encode(&device_id[..]), header_key_salt, body_key_salt))
}

fn stream_setup(stream: &mut TcpStream) -> Result<(String, ppenc::Receiver)> {
    let mut rng = rand::thread_rng();
    let mut token = vec![0; 100];

    // Read the token
    stream
        .read_exact(&mut token)
        .map_err(|_| "couldn't read token from stream")?;

    let (device_id, header_key_salt, body_key_salt) = read_token(&token)?;

    let header_state_init = rng.gen::<[u8; 32]>();
    let body_key_state0 = rng.gen::<[u8; 32]>();

    stream
        .write_all(&header_state_init)
        .map_err(|_| "couldn't write header salt")?;

    stream
        .write_all(&body_key_state0)
        .map_err(|_| "couldn't write body_key_state0")?;

    // Read 12 byte nonce from network
    let mut header_rng_nonce = [0u8; 12];
    stream
        .read_exact(&mut header_rng_nonce)
        .map_err(|_| "couldn't read header_rng_nonce")?;

    Ok((
        device_id,
        ppenc::Receiver::new(
            &header_key_salt,
            &header_state_init,
            &header_rng_nonce,
            &body_key_salt,
            &body_key_state0,
        ),
    ))
}

fn run_stream_with_res(mut stream: TcpStream) -> Result<()> {
    let (device_id, mut receiver) = match stream_setup(&mut stream) {
        Ok(r) => r,
        Err(s) => {
            return Err("couldn't setup stream");
        }
    };

    println!("new stream device_id={}", device_id);

    let mut header_buf = [0u8; 32];
    let mut body = vec![0u8; 512];

    loop {
        stream
            .read_exact(&mut header_buf)
            .map_err(|_| "couldn't read header")?;

        let header = receiver
            .read_header(&mut header_buf)
            .map_err(|_| "bad header in stream")?;

        body.resize(header.body_padded_len(), 0);

        stream
            .read_exact(&mut body)
            .map_err(|_| "couldn't read body")?;

        println!("{}", hex::encode(&header_buf));

        let resp_mac = match receiver.read_body(header, &mut body) {
            Err(e) => {
                eprintln!("{}", e);
                return Err("bad body in stream");
            }
            Ok(m) => m,
        };

        match std::str::from_utf8(&body) {
            Ok(s) => println!(
                "message\tdevice_id={}\tmessage={}\tmac={}",
                device_id,
                s,
                &hex::encode(&resp_mac[..])[..10]
            ),
            Err(_) => println!(
                "message\tdevice_id={}\tmessage={:?}\tmac={}",
                device_id,
                body,
                &hex::encode(&resp_mac[..])[..10]
            ),
        }

        stream
            .write_all(&resp_mac)
            .map_err(|_| "couldn't write response_mac")?;
    }
}

fn run_stream(stream: TcpStream) {
    if let Err(e) = run_stream_with_res(stream) {
        eprintln!("stream closed {}", e);
    }
}

fn run() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").map_err(|_| "couldn't bind to port 8080")?;
    let mut client_num = 0;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                client_num += 1;
                ThreadBuilder::new()
                    .name(format!("client_{}", client_num))
                    .spawn(move || run_stream(stream))
                    .map_err(|_| "couldn't create client thread")?;
            }
            Err(e) => {
                eprintln!("problem client stream {}", e);
            }
        }
    }

    Ok(())
}

fn main() {
    while let Err(e) = run() {
        eprintln!("server crashed {}", e);
    }
}
