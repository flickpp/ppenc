use std::net::TcpListener;
use std::result;

use kv_log_macro::info;

mod config;
mod server;

fn main() -> result::Result<(), String> {
    json_env_logger::init();

    // Load config
    let cfg = config::Config::from_env()?;

    // Bind to port
    let listener =
        TcpListener::bind(&cfg.bind_addr).map_err(|e| format!("couldn't bind to port [{}]", e))?;

    info!("monstermac started");

    server::run_forever(listener);
    unreachable!("monstermac stopped");
}
