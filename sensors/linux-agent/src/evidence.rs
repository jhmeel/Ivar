//! Evidence first (section 11.1): volatile evidence is captured before a
//! process is killed or a host isolated.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Capture what disappears when the process dies: command line, executable
/// and its digest, status, open files, network namespace sockets, mappings.
pub fn capture(root: &Path, pid: u32) -> serde_json::Value {
    let dir = root.join(pid.to_string());
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    let exe = std::fs::read_link(dir.join("exe")).map(|p| p.display().to_string()).unwrap_or_default();
    let exe_sha256 = std::fs::read(dir.join("exe")).map(|b| hex::encode(Sha256::digest(&b))).unwrap_or_default();
    let fds: Vec<String> = std::fs::read_dir(dir.join("fd")).map(|d| d.flatten().filter_map(|e| std::fs::read_link(e.path()).ok()).map(|p| p.display().to_string()).take(256).collect()).unwrap_or_default();
    let maps: Vec<String> = read("maps").lines().filter(|l| l.contains('/')).map(|l| l.split_whitespace().last().unwrap_or("").to_string()).collect::<std::collections::BTreeSet<_>>().into_iter().take(128).collect();
    serde_json::json!({
        "pid": pid,
        "cmdline": read("cmdline").replace('\0', " "),
        "exe": exe,
        "exe_sha256": exe_sha256,
        "status": read("status"),
        "open_files": fds,
        "mapped_files": maps,
        "environ_sha256": hex::encode(Sha256::digest(read("environ").as_bytes())),
    })
}
