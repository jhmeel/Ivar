//! Durable stores: the append only, hash chained evidence log on disk, and
//! the last known signed flag state on local disk (defect F1).

use ivar_core::config::{FlagPersistence, SignedFlag};
use ivar_core::evidence::{verify_chain, EvidenceRecord, EvidenceStore, GENESIS_HASH};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Evidence as JSON lines. Each record is written and synced before the
/// decision that cites it is released. The file is opened append only.
pub struct FileEvidenceStore {
    path: PathBuf,
    file: File,
    records: Vec<EvidenceRecord>,
}

impl FileEvidenceStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut records = Vec::new();
        if path.exists() {
            for line in BufReader::new(File::open(path)?).lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    records.push(serde_json::from_str::<EvidenceRecord>(&line)?);
                }
            }
            verify_chain(&records, None).map_err(|e| anyhow::anyhow!("evidence chain at {} is broken: {e}", path.display()))?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileEvidenceStore { path: path.to_path_buf(), file, records })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl EvidenceStore for FileEvidenceStore {
    fn head(&self) -> (u64, String) {
        self.records.last().map(|r| (r.seq, r.hash.clone())).unwrap_or((0, GENESIS_HASH.into()))
    }

    fn put(&mut self, record: EvidenceRecord) {
        let line = serde_json::to_string(&record).expect("evidence serialises");
        // A failed write must not be silent: evidence is the basis of every verdict.
        writeln!(self.file, "{line}").and_then(|_| self.file.sync_data()).expect("evidence write");
        self.records.push(record);
    }

    fn records(&self) -> Vec<EvidenceRecord> {
        self.records.clone()
    }
}

/// Last known signed flag state, written atomically.
pub struct FileFlagPersistence {
    pub path: PathBuf,
}

impl FlagPersistence for FileFlagPersistence {
    fn load(&self) -> BTreeMap<String, SignedFlag> {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&mut self, flags: &BTreeMap<String, SignedFlag>) {
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(flags).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_core::evidence::EvidenceKind;
    use serde_json::json;

    #[test]
    fn survives_restart_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("evidence.jsonl");
        {
            let mut s = FileEvidenceStore::open(&p).unwrap();
            for i in 0..3 {
                s.append(None, EvidenceKind::Event, i, "", json!({ "n": i }));
            }
        }
        let mut s = FileEvidenceStore::open(&p).unwrap();
        assert_eq!(s.head().0, 3);
        s.append(None, EvidenceKind::Event, 4, "", json!({ "n": 4 }));
        drop(s);
        let text = std::fs::read_to_string(&p).unwrap().replace("\"n\":1", "\"n\":9");
        std::fs::write(&p, text).unwrap();
        assert!(FileEvidenceStore::open(&p).is_err());
    }
}
