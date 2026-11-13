use std::{
    env,
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    process,
    time::Duration,
};

use audio_verifier_host::{Config, PublicResolver, app, download_client};

const USAGE: &str = "usage: audio-verifier-host [options]
  --port <n>                    listen on 127.0.0.1:<n> (4000)
  --enclave <addr:port>         the enclave's TCP bridge (127.0.0.1:3000)
  --allowed-host-suffix <s>     download host suffix, repeatable (.r2.cloudflarestorage.com)
  --max-in-flight <n>           concurrent /measure requests (16)
  --connect-timeout-secs <n>    TCP connect deadline (10)
  --idle-timeout-secs <n>       download idle deadline (20)
  --request-timeout-secs <n>    whole /measure deadline (630)";

fn parse_args() -> Result<(u16, Config), String> {
    let mut port = 4000;
    let mut config = Config::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)));
    let mut suffixes = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            println!("{USAGE}");
            process::exit(0);
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let invalid = || format!("invalid {flag}: {value}");
        let secs = |value: &str| {
            value
                .parse()
                .map(Duration::from_secs)
                .map_err(|_| invalid())
        };
        match flag.as_str() {
            "--port" => port = value.parse().map_err(|_| invalid())?,
            "--enclave" => config.enclave = value.parse().map_err(|_| invalid())?,
            "--allowed-host-suffix" => {
                let suffix = value.to_ascii_lowercase();
                if !suffix.starts_with('.') || suffix.len() < 2 {
                    return Err(format!("{flag} must start with '.': {value}"));
                }
                suffixes.push(suffix);
            }
            "--max-in-flight" => match value.parse() {
                Ok(n) if n > 0 => config.max_in_flight = n,
                _ => return Err(invalid()),
            },
            "--connect-timeout-secs" => config.connect_timeout = secs(&value)?,
            "--idle-timeout-secs" => config.idle_timeout = secs(&value)?,
            "--request-timeout-secs" => config.request_timeout = secs(&value)?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if !suffixes.is_empty() {
        config.policy.host_suffixes = suffixes;
    }
    Ok((port, config))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (port, config) = parse_args().unwrap_or_else(|error| {
        eprintln!("{error}\n{USAGE}");
        process::exit(2);
    });
    let client = download_client(&config, PublicResolver)?;
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "[gateway] listening on {listen}; enclave {}; hosts {}; {} /measure at once",
        config.enclave,
        config.policy.host_suffixes.join(" "),
        config.max_in_flight
    );
    axum::serve(listener, app(config, client)).await?;
    Ok(())
}
