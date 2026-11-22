//! Measure what one core shard sustains on this machine, without HTTP.
//!
//!     cargo run --release -p ivar-server --example ingest_bench -- [events] [batch] [callers] [distinct users]
//!
//! Runs the full shard path (judging, signed evidence on disk, synced before
//! verdicts are released) with `callers` concurrent batches, as concurrent
//! sensor requests would. Set IVAR_BENCH_HEAP=1 to also report the heap
//! the shard holds per distinct user (slower). See "Capacity and sizing" in the README.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ivar_contracts::sign::{sign_policy, KeyPair, Keyring};
use ivar_contracts::SecurityEvent;
use ivar_core::policy::spec_default_policy;
use ivar_server::access::Access;
use ivar_server::responders::Responders;
use ivar_server::state::{AppState, StartOptions};
use ivar_server::store::FileEvidenceStore;
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

/// Counts live heap bytes when IVAR_BENCH_HEAP is set, so the report shows
/// what the shard keeps. Off by default: counting slows every allocation.
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicBool = AtomicBool::new(false);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            LIVE.fetch_add(l.size(), Relaxed);
        }
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if COUNT.load(Relaxed) {
            LIVE.fetch_sub(l.size(), Relaxed);
        }
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if COUNT.load(Relaxed) {
            LIVE.fetch_add(n, Relaxed);
            LIVE.fetch_sub(l.size(), Relaxed);
        }
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static ALLOC: Counting = Counting;

fn event(i: u64, users: u64) -> SecurityEvent {
    let user = i % users;
    serde_json::from_value(json!({
        "class_uid": 4002, "category_uid": 4, "activity_id": 1, "activity_name": "http.request", "time": 1_795_000_000_000u64 + i, "status_id": 1,
        "src_endpoint": { "ip": format!("10.{}.{}.{}", (user >> 16) & 255, (user >> 8) & 255, user & 255) },
        "actor": { "user": { "uid": format!("u{user}") }, "session": { "uid": format!("s{user}") } },
        "http_request": { "http_method": if i % 5 == 0 { "POST" } else { "GET" }, "url_path": format!("/accounts/u{user}"), "user_agent": "Mozilla/5.0" },
        "http_response": { "code": 200 },
        "ivar": { "sensor_id": "bench", "sensor_type": "app_sdk", "observation_point": "app_sdk", "sensor_seq": i + 1 }
    }))
    .expect("event")
}

fn main() {
    let args: Vec<u64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let total = *args.first().unwrap_or(&200_000);
    let batch = *args.get(1).unwrap_or(&500) as usize;
    let callers = *args.get(2).unwrap_or(&4) as usize;
    let users = (*args.get(3).unwrap_or(&50_000)).max(1);
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_key = KeyPair::ed25519_from_seed("policy-1", [1; 32]);
    let evidence_key = KeyPair::ed25519_from_seed("evidence-0", [2; 32]);
    let mut ring = Keyring::default();
    ring.add(policy_key.public(), &["policy"]);
    ring.add(evidence_key.public(), &["evidence"]);
    let mut p = spec_default_policy(0);
    p.version = 1;
    p.policy_version = "bench-1".into();
    p.expires_at = i64::MAX / 2;
    let state = AppState::start(StartOptions {
        evidence: FileEvidenceStore::open(&dir.path().join("evidence.jsonl")).expect("store"),
        policy_archive_b64: B64.encode(sign_policy(&p, &[&policy_key]).expect("sign").to_archive().expect("archive")),
        keyring: ring,
        evidence_key,
        redaction_key: vec![7; 16],
        public_url: "https://ivar.bench".into(),
        expected_layers: vec!["app_sdk".into()],
        sinks: vec![],
        responders: Responders::empty(KeyPair::ed25519_from_seed("action-0", [3; 32])),
        shard: 0,
        shards: 1,
        policy_dir: None,
        access: Access::new(None, None, vec![]),
        replay_max_records: 0,
    })
    .expect("start");

    let heap = std::env::var_os("IVAR_BENCH_HEAP").is_some();
    // With heap counting, callers build events as they go so the count is the
    // shard's own; otherwise every batch is built before the clock starts.
    let starts: Vec<u64> = (0..total).step_by(batch).collect();
    let built: Vec<Vec<SecurityEvent>> = if heap { Vec::new() } else { starts.iter().map(|&s| (s..(s + batch as u64).min(total)).map(|i| event(i, users)).collect()).collect() };
    let built = std::sync::Mutex::new(built.into_iter());
    COUNT.store(heap, Relaxed);
    let queue = std::sync::Mutex::new(starts.into_iter());
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..callers {
            scope.spawn(|| loop {
                let next = queue.lock().unwrap().next();
                match next {
                    Some(start) => {
                        let ready = built.lock().unwrap().next();
                        state.ingest(ready.unwrap_or_else(|| (start..(start + batch as u64).min(total)).map(|i| event(i, users)).collect()));
                    }
                    None => break,
                }
            });
        }
    });
    let secs = started.elapsed().as_secs_f64();
    let bytes = std::fs::metadata(dir.path().join("evidence.jsonl")).map(|m| m.len()).unwrap_or(0);
    println!("events            {total}");
    println!("batch             {batch} x {callers} concurrent callers");
    println!("shard throughput  {:.0} events/s", total as f64 / secs);
    println!("per event         {:.1} us", secs * 1e6 / total as f64);
    println!("evidence written  {:.0} bytes/event", bytes as f64 / total as f64);
    let rss = std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.split_whitespace().nth(1).unwrap_or("0").parse::<u64>().unwrap_or(0)));
    if let Some(kb) = rss {
        println!("distinct users    {users}");
        println!("peak memory       {} MB resident", kb / 1024);
        if heap {
            println!("state held        {} MB heap ({} bytes per distinct user)", LIVE.load(Relaxed) >> 20, LIVE.load(Relaxed) as u64 / users.min(total));
        }
    }
}
