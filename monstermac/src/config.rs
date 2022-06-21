use std::env;
use std::fs;
use std::io::Read;
use std::path;
use std::result;

use lazy_static::lazy_static;

pub struct Config {
    pub bind_addr: String,
}

impl Config {
    pub fn from_env() -> result::Result<Self, String> {
        let bind_addr = String::from("0.0.0.0:8081");
        Ok(Self { bind_addr })
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Mode {
    Mode0,
    Mode16,
    Mode32,
}

lazy_static! {
    pub static ref MODE: Mode = get_mode();
    pub static ref SECRET0: Vec<u8> = get_secret0();
    pub static ref SECRET_PATH: path::PathBuf = get_secret_path();
}

fn get_mode() -> Mode {
    let mut mode = Mode::Mode0;

    for (k, v) in env::vars() {
        if k == "MONSTERMAC_MODE" {
            mode = match v.as_ref() {
                "MODE0" => Mode::Mode0,
                "MODE16" => Mode::Mode16,
                "MODE32" => Mode::Mode32,
                _ => Mode::Mode0,
            }
        }
    }

    mode
}

fn get_secret0() -> Vec<u8> {
    match get_mode() {
        Mode::Mode0 => {
            let mut key = vec![0; 32];
            fs::File::open("secret")
                .expect("couldn't open file secret")
                .read_exact(&mut key)
                .expect("couldn't read secret file");

            key
        }
        _ => vec![],
    }
}

fn get_secret_path() -> path::PathBuf {
    let mut spath = path::PathBuf::from("./secrets");

    for (k, v) in env::vars() {
        if k == "MONSTERMAC_SECRET_PATH" {
            spath = path::PathBuf::from(v);
        }
    }

    spath
}
