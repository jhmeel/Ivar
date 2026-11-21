//! Reading process and socket state from /proc.

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    pub uid: u32,
}

pub fn read(root: &Path, pid: u32) -> Option<ProcInfo> {
    let dir = root.join(pid.to_string());
    let status = std::fs::read_to_string(dir.join("status")).ok()?;
    let field = |k: &str| status.lines().find(|l| l.starts_with(k)).map(|l| l[k.len()..].trim().to_string()).unwrap_or_default();
    let cmdline = std::fs::read(dir.join("cmdline")).map(|b| b.split(|c| *c == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).to_string()).collect::<Vec<_>>().join(" ")).unwrap_or_default();
    Some(ProcInfo {
        pid,
        ppid: field("PPid:").parse().unwrap_or(0),
        comm: field("Name:"),
        exe: std::fs::read_link(dir.join("exe")).map(|p| p.display().to_string()).unwrap_or_default(),
        cmdline,
        uid: field("Uid:").split_whitespace().next().and_then(|u| u.parse().ok()).unwrap_or(0),
    })
}

pub fn pids(root: &Path) -> Vec<u32> {
    std::fs::read_dir(root).map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect()).unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TcpConn {
    pub local: String,
    pub remote: String,
    pub remote_port: u16,
    pub inode: u64,
}

fn ipv4(hex_le: &str) -> String {
    let n = u32::from_str_radix(hex_le, 16).unwrap_or(0);
    let b = n.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Established connections from /proc/net/tcp (state 01).
pub fn tcp(text: &str) -> Vec<TcpConn> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 || f[3] != "01" {
                return None;
            }
            let (la, _) = f[1].split_once(':')?;
            let (ra, rp) = f[2].split_once(':')?;
            Some(TcpConn { local: ipv4(la), remote: ipv4(ra), remote_port: u16::from_str_radix(rp, 16).ok()?, inode: f[9].parse().ok()? })
        })
        .collect()
}

/// Socket inode to owning pid.
pub fn socket_owners(root: &Path) -> BTreeMap<u64, u32> {
    let mut out = BTreeMap::new();
    for pid in pids(root) {
        if let Ok(fds) = std::fs::read_dir(root.join(pid.to_string()).join("fd")) {
            for fd in fds.flatten() {
                if let Ok(t) = std::fs::read_link(fd.path()) {
                    let t = t.display().to_string();
                    if let Some(inode) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')).and_then(|s| s.parse().ok()) {
                        out.insert(inode, pid);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_proc_net_tcp() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 FEA9FEA9:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1\n";
        let c = super::tcp(t);
        assert_eq!(c[0].remote, "169.254.169.254");
        assert_eq!(c[0].remote_port, 80);
        assert_eq!(c[0].inode, 12345);
    }

    #[test]
    fn reads_own_process() {
        let me = super::read(std::path::Path::new("/proc"), std::process::id()).unwrap();
        assert!(me.ppid > 0 && !me.comm.is_empty());
    }
}
