//! ivar-core: the IVAR core service.
//!
//! Usage: ivar-core serve --config /etc/ivar/core.yaml
//!        ivar-core replay --evidence <file> --policies <dir> --keyring <file> --redaction <file> --signer <seed> --out <file>
//!        ivar-core health [host:port]
//!        ivar-core keygen <path>   (writes a 32 byte hex seed)
//!        ivar-core keyring <out.json> <seed file>=<role>[+<role>] ...

use ivar_contracts::sign::{KeyPair, Keyring};
use ivar_server::config::{read_seed, ServerConfig};
use ivar_server::grpc::{pb::ingest_server::IngestServer, IngestService};
use ivar_server::responders::Responders;
use ivar_server::state::{now_ms, AppState, StartOptions};
use ivar_server::store::FileEvidenceStore;
use std::path::Path;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            let path = args.get(2).ok_or_else(|| anyhow::anyhow!("keygen <path>"))?;
            let mut seed = [0u8; 32];
            getrandom(&mut seed)?;
            std::fs::write(path, hex::encode(seed))?;
            let k = KeyPair::ed25519_from_seed("new", seed);
            println!("{}", serde_json::to_string(&k.public())?);
            Ok(())
        }
        Some("health") => {
            // ivar-core health [host:port]: exit 0 when /healthz answers ok.
            // For container healthchecks in images that carry no shell or curl.
            let addr = args.get(2).cloned().unwrap_or_else(|| "127.0.0.1:8080".into());
            std::process::exit(if healthy(&addr) { 0 } else { 1 });
        }
        Some("replay") => {
            // ivar-core replay --evidence <evidence.jsonl> --policies <dir> --keyring <keyring.json>
            //   --redaction <redaction.hex> --signer <seed> [--signer-id evidence-0]
            //   [--entities ip:a,user:b] [--incident <id>] --out <bundle.json>
            let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
            let need = |name: &str| flag(name).ok_or_else(|| anyhow::anyhow!("replay needs {name}"));
            let keyring: Keyring = serde_json::from_str(&std::fs::read_to_string(need("--keyring")?)?)?;
            let signer = KeyPair::ed25519_from_seed(&flag("--signer-id").unwrap_or_else(|| "evidence-0".into()), read_seed(&need("--signer")?)?);
            let bundle = ivar_server::offline::build(&ivar_server::offline::OfflineReplay {
                evidence: Path::new(&need("--evidence")?),
                policies: Path::new(&need("--policies")?),
                keyring: &keyring,
                redaction_key: hex::decode(std::fs::read_to_string(need("--redaction")?)?.trim())?,
                signer: &signer,
                entities: flag("--entities").map(|e| e.split(',').filter(|s| !s.is_empty()).map(String::from).collect()).unwrap_or_default(),
                incident_id: flag("--incident").unwrap_or_else(|| "full_window".into()),
                expected_layers: ["edge", "app_sdk", "host", "network", "database"].iter().map(|s| s.to_string()).collect(),
            })?;
            let out = need("--out")?;
            std::fs::write(&out, serde_json::to_string(&bundle)?)?;
            println!("{out}: {} frames, {} of {} verdicts reproduced, signed by {}", bundle.frames.len(), bundle.re_execution.replayed_verdicts, bundle.re_execution.recorded_verdicts, signer.key_id);
            Ok(())
        }
        Some("keyring") => {
            // ivar-core keyring <out.json> <seed file>=<role>[+<role>] ...
            // The key id is the seed file name without its extension, the
            // same rule ivar-control uses when it signs with a seed file.
            let out = args.get(2).ok_or_else(|| anyhow::anyhow!("keyring <out.json> <seed>=<role>[+<role>] ..."))?;
            let mut ring = Keyring::default();
            for spec in &args[3..] {
                let (file, roles) = spec.split_once('=').ok_or_else(|| anyhow::anyhow!("{spec}: expected <seed file>=<role>"))?;
                let id = std::path::Path::new(file).file_stem().and_then(|s| s.to_str()).ok_or_else(|| anyhow::anyhow!("{file}: no file name"))?;
                let key = KeyPair::ed25519_from_seed(id, read_seed(file)?);
                ring.add(key.public(), &roles.split('+').collect::<Vec<_>>());
            }
            std::fs::write(out, serde_json::to_string_pretty(&ring)?)?;
            Ok(())
        }
        Some("serve") => {
            let cfg_path = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| "/etc/ivar/core.yaml".into());
            serve(ServerConfig::load(&cfg_path)?).await
        }
        _ => {
            eprintln!("usage: ivar-core serve --config <path> | ivar-core health [host:port] | ivar-core keygen <path> | ivar-core keyring <out.json> <seed>=<role>[+<role>] ...");
            std::process::exit(2);
        }
    }
}

fn healthy(addr: &str) -> bool {
    use std::io::{Read, Write};
    let Ok(sock) = addr.parse::<std::net::SocketAddr>() else { return false };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(2)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes()).is_err() {
        return false;
    }
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.starts_with("HTTP/1.1 200") && out.ends_with("ok")
}

fn getrandom(buf: &mut [u8]) -> anyhow::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)?;
    Ok(())
}

async fn serve(cfg: ServerConfig) -> anyhow::Result<()> {
    let keyring: Keyring = serde_json::from_str(&std::fs::read_to_string(&cfg.keyring)?)?;
    let evidence_key = KeyPair::ed25519_from_seed(&format!("evidence-{}", cfg.shard), read_seed(&cfg.evidence_key_seed_file)?);
    let action_key = KeyPair::ed25519_from_seed(&format!("action-{}", cfg.shard), read_seed(&cfg.action_key_seed_file)?);
    let redaction_key = hex::decode(std::fs::read_to_string(&cfg.redaction_key_hex_file)?.trim())?;
    let bundle = std::fs::read_to_string(&cfg.policy_bundle)?;
    let evidence = FileEvidenceStore::open(&Path::new(&cfg.data_dir).join(format!("evidence-{}.jsonl", cfg.shard)))?;
    let sinks = ivar_server::sinks::build(&cfg.sinks, Some(action_key.clone()), &cfg.public_url);
    let responders = Responders::start(&cfg.responders, action_key)?;
    let state = AppState::start(StartOptions {
        evidence,
        policy_archive_b64: bundle,
        keyring,
        evidence_key,
        redaction_key,
        public_url: cfg.public_url.clone(),
        expected_layers: cfg.expected_layers.clone(),
        sinks,
        responders,
        shard: cfg.shard,
        shards: cfg.shards,
        policy_dir: Some(Path::new(&cfg.data_dir).join(format!("policies-{}", cfg.shard))),
    })?;

    // Tamper monitoring: a sensor silent for 60 seconds raises an alert.
    let ticker = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let opened = ticker.inner.lock().expect("state").core.tick(now_ms());
            for id in opened {
                ticker.emit(ivar_server::sinks::Outbound::Alert { kind: "tamper".into(), message: format!("sensor silent, incident {id}") });
            }
        }
    });

    let http = axum::serve(tokio::net::TcpListener::bind(&cfg.http_listen).await?, ivar_server::http::router_with_console(state.clone(), cfg.console_dir.as_deref()));
    let grpc = tonic::transport::Server::builder().add_service(IngestServer::new(IngestService { state })).serve(cfg.grpc_listen.parse()?);
    tracing::info!(http = %cfg.http_listen, grpc = %cfg.grpc_listen, "ivar core serving");
    tokio::select! {
        r = http => r?,
        r = grpc => r?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}
