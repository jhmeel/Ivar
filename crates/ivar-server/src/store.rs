//! Durable stores: the append only, hash chained evidence log on disk, and
//! the last known signed flag state on local disk (defect F1).

use ivar_core::config::{FlagPersistence, SignedFlag};
use ivar_contracts::sign::{sign_bytes, KeyPair, Keyring};
use ivar_core::evidence::{verify_chain, EvidenceRecord, EvidenceStore, GENESIS_HASH};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};

/// Evidence as JSON lines, in segments.
///
/// Sealing a record only links it into the chain. `commit` hands everything
/// sealed since the last commit to a writer thread, which signs it (spread
/// over every core when the store holds the evidence key), writes it and
/// syncs the file; the returned [`Commit`] resolves once that is durable.
/// The shard lock is therefore held only while events are judged, batches
/// from concurrent requests share one sync, and no verdict or action is
/// released before the evidence it cites is on disk.
///
/// The active segment is `evidence-N.jsonl`. When it passes the segment size
/// it is sealed as `evidence-N.<first seq>.jsonl` beside a small `.idx` file
/// holding its sequence range, the chain hashes at both ends and one byte
/// offset per [`INDEX_STRIDE`] records. Startup verifies the active segment
/// record by record and the links between sealed segments, so a restart
/// takes seconds however much evidence a shard holds; `ivar-core evidence
/// verify` checks every record and signature offline. Sealed segments never
/// change again and can be shipped to WORM storage and removed locally.
pub struct FileEvidenceStore {
    path: PathBuf,
    head: (u64, String),
    /// Sealed, not yet handed to the writer.
    pending: Vec<EvidenceRecord>,
    signer: Option<KeyPair>,
    shared: Arc<Mutex<Written>>,
    writer: Option<(mpsc::SyncSender<Job>, std::thread::JoinHandle<()>)>,
    /// The commit of the last batch handed over; waited on before a read.
    last: Option<Commit>,
}

/// One byte offset is kept per this many records.
pub const INDEX_STRIDE: u64 = 256;
/// Default size at which the active segment is sealed.
pub const DEFAULT_SEGMENT_BYTES: u64 = 1 << 30;

/// A segment's place in the chain, and its sparse index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Segment {
    /// First sequence the segment holds (or will hold, while empty).
    first: u64,
    /// Last sequence it holds; `first - 1` while empty.
    last: u64,
    /// The previous hash of its first record.
    prev_hash: String,
    /// The hash of its last record.
    head: String,
    /// Byte offset of records first, first + STRIDE, first + 2 STRIDE, ...
    index: Vec<u64>,
    #[serde(skip)]
    path: PathBuf,
}

/// What the writer has made durable.
struct Written {
    sealed: Vec<Segment>,
    active: Segment,
    end: u64,
}

struct Job {
    records: Vec<EvidenceRecord>,
    signer: Option<KeyPair>,
    done: mpsc::Sender<()>,
}

/// Resolves when a committed batch is durable.
#[derive(Clone)]
pub struct Commit(Arc<Mutex<Option<mpsc::Receiver<()>>>>);

impl Commit {
    fn done() -> Self {
        Commit(Arc::new(Mutex::new(None)))
    }

    /// Block until the batch is on disk. Panics if the writer failed: a shard
    /// that cannot keep evidence must not keep deciding.
    pub fn wait(&self) {
        let mut rx = self.0.lock().expect("commit");
        if let Some(r) = rx.take() {
            r.recv().expect("evidence writer failed; refusing to release decisions without evidence");
        }
    }
}

/// Below this many records signing stays on the writer thread.
const PARALLEL_SIGNING_FROM: usize = 64;
/// Batches queued for the writer before sealing waits for it.
const WRITER_QUEUE: usize = 64;

fn sealed_name(active: &Path, first: u64, ext: &str) -> PathBuf {
    let stem = active.file_stem().and_then(|s| s.to_str()).unwrap_or("evidence");
    active.with_file_name(format!("{stem}.{first:020}.{ext}"))
}

/// Sealed segment files beside `active`, by first sequence.
fn sealed_files(active: &Path) -> anyhow::Result<Vec<(u64, PathBuf)>> {
    let stem = active.file_stem().and_then(|s| s.to_str()).unwrap_or("evidence").to_string();
    let dir = active.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut out = Vec::new();
    if dir.exists() {
        for entry in std::fs::read_dir(dir)? {
            let name = entry?.file_name().to_string_lossy().to_string();
            let Some(mid) = name.strip_prefix(&format!("{stem}.")).and_then(|r| r.strip_suffix(".jsonl")) else { continue };
            if mid.len() == 20 && mid.bytes().all(|b| b.is_ascii_digit()) {
                out.push((mid.parse()?, dir.join(&name)));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Check one record against its predecessor: sequence, link, content hash
/// and, with a keyring, its signature.
fn check_link(rec: &EvidenceRecord, prev: Option<(u64, &str)>, ring: Option<&Keyring>, path: &Path) -> anyhow::Result<()> {
    verify_chain(std::slice::from_ref(rec), ring).map_err(|e| anyhow::anyhow!("evidence chain at {} is broken: {e}", path.display()))?;
    if let Some((seq, hash)) = prev {
        if rec.seq != seq + 1 || rec.prev_hash != hash {
            anyhow::bail!("evidence chain at {} is broken: record {} does not follow record {seq}", path.display(), rec.seq);
        }
    }
    Ok(())
}

/// Read a segment record by record, verifying its chain (and signatures with
/// a keyring), and build its index. `prev` is what it must follow.
fn scan(path: &Path, prev: Option<(u64, String)>, ring: Option<&Keyring>) -> anyhow::Result<(Segment, u64)> {
    let mut seg = Segment {
        first: prev.as_ref().map(|p| p.0 + 1).unwrap_or(1),
        last: prev.as_ref().map(|p| p.0).unwrap_or(0),
        prev_hash: prev.as_ref().map(|p| p.1.clone()).unwrap_or_else(|| GENESIS_HASH.into()),
        head: prev.as_ref().map(|p| p.1.clone()).unwrap_or_else(|| GENESIS_HASH.into()),
        index: Vec::new(),
        path: path.to_path_buf(),
    };
    let mut end = 0u64;
    if !path.exists() {
        return Ok((seg, 0));
    }
    let mut reader = BufReader::new(File::open(path)?);
    let mut line = String::new();
    let mut prev = prev;
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if !line.trim().is_empty() {
            let rec: EvidenceRecord = serde_json::from_str(line.trim_end())?;
            check_link(&rec, prev.as_ref().map(|(s, h)| (*s, h.as_str())), ring, path)?;
            if seg.index.is_empty() {
                seg.first = rec.seq;
                seg.prev_hash = rec.prev_hash.clone();
            }
            if (rec.seq - seg.first) % INDEX_STRIDE == 0 {
                seg.index.push(end);
            }
            seg.last = rec.seq;
            seg.head = rec.hash.clone();
            prev = Some((rec.seq, rec.hash));
        }
        end += n as u64;
    }
    Ok((seg, end))
}

fn write_index(seg: &Segment) -> anyhow::Result<()> {
    let idx = seg.path.with_extension("idx");
    let tmp = seg.path.with_extension("idx.tmp");
    std::fs::write(&tmp, serde_json::to_vec(seg)?)?;
    File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, &idx)?;
    Ok(())
}

fn sync_dir(path: &Path) {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = File::open(dir).and_then(|d| d.sync_all());
    }
}

impl FileEvidenceStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::open_with(path, DEFAULT_SEGMENT_BYTES)
    }

    /// Open (or create) the evidence at `path`, sealing segments at `segment_bytes`.
    pub fn open_with(path: &Path, segment_bytes: u64) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let mut sealed: Vec<Segment> = Vec::new();
        for (_, file) in sealed_files(path)? {
            let from_index = std::fs::read(file.with_extension("idx")).ok().and_then(|b| serde_json::from_slice::<Segment>(&b).ok());
            let seg = match from_index {
                Some(mut seg) => {
                    seg.path = file.clone();
                    seg
                }
                // Sealed but its index was never written (a crash between the
                // two steps): rebuild it from the records.
                None => {
                    let (mut seg, _) = scan(&file, None, None)?;
                    seg.path = file.clone();
                    write_index(&seg)?;
                    seg
                }
            };
            if let Some(p) = sealed.last() {
                if seg.first != p.last + 1 || seg.prev_hash != p.head {
                    anyhow::bail!("evidence chain is broken between {} and {}", p.path.display(), seg.path.display());
                }
            }
            sealed.push(seg);
        }
        let prev = sealed.last().map(|s| (s.last, s.head.clone()));
        let (active, end) = scan(path, prev, None)?;
        let head = (active.last, active.head.clone());
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let shared = Arc::new(Mutex::new(Written { sealed, active, end }));
        let (tx, rx) = mpsc::sync_channel::<Job>(WRITER_QUEUE);
        let state = shared.clone();
        let active_path = path.to_path_buf();
        let segment_bytes = segment_bytes.max(1);
        let handle = std::thread::Builder::new().name("ivar-evidence".into()).spawn(move || write_loop(file, rx, state, active_path, segment_bytes))?;
        Ok(FileEvidenceStore { path: path.to_path_buf(), head, pending: Vec::new(), signer: None, shared, writer: Some((tx, handle)), last: None })
    }

    /// Hand the store the evidence key: records are then signed by the writer,
    /// in parallel, instead of one at a time as they are sealed.
    pub fn sign_with(&mut self, key: KeyPair) {
        self.signer = Some(key);
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lowest sequence still held locally (older segments may have been archived).
    pub fn first_seq(&self) -> u64 {
        let w = self.shared.lock().expect("evidence index");
        w.sealed.first().map(|s| s.first).unwrap_or(w.active.first)
    }

    /// Hand everything sealed so far to the writer. The caller may release
    /// the shard lock and then wait on the returned commit before releasing
    /// any verdict or action that cites these records.
    pub fn commit(&mut self) -> Commit {
        if self.pending.is_empty() {
            return self.last.clone().unwrap_or_else(Commit::done);
        }
        let (done, rx) = mpsc::channel();
        let job = Job { records: std::mem::take(&mut self.pending), signer: self.signer.clone(), done };
        let (tx, _) = self.writer.as_ref().expect("writer");
        tx.send(job).expect("evidence writer failed; refusing to seal more evidence");
        let c = Commit(Arc::new(Mutex::new(Some(rx))));
        self.last = Some(c.clone());
        c
    }
}

fn write_loop(mut file: File, rx: mpsc::Receiver<Job>, state: Arc<Mutex<Written>>, active_path: PathBuf, segment_bytes: u64) {
    let (mut end, mut seg) = {
        let w = state.lock().expect("evidence index");
        (w.end, w.active.clone())
    };
    while let Ok(first) = rx.recv() {
        // Take every batch already queued: one sync covers them all.
        let mut jobs = vec![first];
        while let Ok(more) = rx.try_recv() {
            jobs.push(more);
        }
        for j in &mut jobs {
            if let Some(key) = &j.signer {
                sign_all(&mut j.records, key);
            }
        }
        let count: usize = jobs.iter().map(|j| j.records.len()).sum();
        let mut buf = Vec::with_capacity(count * 1024);
        for r in jobs.iter().flat_map(|j| &j.records) {
            if seg.last < seg.first {
                seg.first = r.seq;
                seg.prev_hash = r.prev_hash.clone();
            }
            if (r.seq - seg.first) % INDEX_STRIDE == 0 {
                seg.index.push(end + buf.len() as u64);
            }
            seg.last = r.seq;
            seg.head = r.hash.clone();
            serde_json::to_writer(&mut buf, r).expect("evidence serialises");
            buf.push(b'\n');
        }
        // A failed write must not be silent: evidence is the basis of every
        // verdict. Panicking drops every waiting commit, which then refuses
        // to release its decisions.
        file.write_all(&buf).expect("evidence write");
        file.sync_data().expect("evidence sync");
        end += buf.len() as u64;
        {
            let mut w = state.lock().expect("evidence index");
            w.active = seg.clone();
            w.end = end;
            if end >= segment_bytes {
                // Seal under the lock, so no reader opens the active path
                // while it is being renamed.
                let mut sealed = seg.clone();
                sealed.path = sealed_name(&active_path, seg.first, "jsonl");
                std::fs::rename(&active_path, &sealed.path).expect("evidence seal");
                write_index(&sealed).expect("evidence index write");
                file = OpenOptions::new().create(true).append(true).open(&active_path).expect("evidence open");
                sync_dir(&active_path);
                seg = Segment { first: seg.last + 1, last: seg.last, prev_hash: seg.head.clone(), head: seg.head.clone(), index: Vec::new(), path: active_path.clone() };
                end = 0;
                w.sealed.push(sealed);
                w.active = seg.clone();
                w.end = 0;
            }
        }
        for j in jobs {
            let _ = j.done.send(());
        }
    }
}

fn sign_all(records: &mut [EvidenceRecord], key: &KeyPair) {
    let sign = |r: &mut EvidenceRecord| {
        if r.signature.is_none() {
            r.signature = Some(sign_bytes(key, r.hash.as_bytes()));
        }
    };
    if records.len() < PARALLEL_SIGNING_FROM {
        records.iter_mut().for_each(sign);
        return;
    }
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(16);
    let per = records.len().div_ceil(threads);
    std::thread::scope(|scope| {
        for chunk in records.chunks_mut(per) {
            scope.spawn(move || chunk.iter_mut().for_each(sign));
        }
    });
}

/// Verify every local segment of the evidence at `path`, record by record,
/// with signatures when a keyring is given. Returns the record count and the
/// chain head. This is the auditor's check; it reads everything.
pub fn verify_evidence(path: &Path, ring: Option<&Keyring>) -> anyhow::Result<(u64, u64, String)> {
    let mut prev: Option<(u64, String)> = None;
    let mut first = None;
    let mut count = 0;
    let mut files: Vec<PathBuf> = sealed_files(path)?.into_iter().map(|(_, p)| p).collect();
    files.push(path.to_path_buf());
    for file in files {
        let (seg, _) = scan(&file, prev.clone(), ring)?;
        if seg.last >= seg.first {
            first.get_or_insert(seg.first);
            count += seg.last - seg.first + 1;
            prev = Some((seg.last, seg.head));
        }
    }
    let (_, head) = prev.unwrap_or((0, GENESIS_HASH.into()));
    Ok((first.unwrap_or(1), count, head))
}

impl EvidenceStore for FileEvidenceStore {
    fn head(&self) -> (u64, String) {
        self.head.clone()
    }

    fn put(&mut self, record: EvidenceRecord) {
        self.head = (record.seq, record.hash.clone());
        self.pending.push(record);
    }

    fn signs_on_sync(&self) -> bool {
        self.signer.is_some()
    }

    fn sync(&mut self) {
        self.commit().wait();
    }

    fn records(&self) -> Vec<EvidenceRecord> {
        self.records_from(1, usize::MAX)
    }

    fn records_from(&self, from: u64, limit: usize) -> Vec<EvidenceRecord> {
        read_from(&self.shared, self.last.as_ref(), &self.pending, from, limit)
    }
}

/// Reads a shard's evidence without holding the shard lock: take one with
/// [`FileEvidenceStore::reader`] under the lock, then read from it outside.
pub struct EvidenceReader {
    shared: Arc<Mutex<Written>>,
    last: Option<Commit>,
    pending: Vec<EvidenceRecord>,
    head: u64,
}

impl EvidenceReader {
    /// Up to `limit` records from sequence `from`, oldest first.
    pub fn records_from(&self, from: u64, limit: usize) -> Vec<EvidenceRecord> {
        read_from(&self.shared, self.last.as_ref(), &self.pending, from, limit)
    }
    /// The last sequence sealed when the reader was taken.
    pub fn head(&self) -> u64 {
        self.head
    }
    /// The oldest sequence still held locally.
    pub fn first_seq(&self) -> u64 {
        let w = self.shared.lock().expect("evidence index");
        w.sealed.first().map(|s| s.first).unwrap_or(w.active.first)
    }
}

impl FileEvidenceStore {
    /// A handle for reading outside the shard lock.
    pub fn reader(&self) -> EvidenceReader {
        EvidenceReader { shared: self.shared.clone(), last: self.last.clone(), pending: self.pending.clone(), head: self.head.0 }
    }
}

/// Durable records from `from` (or the oldest still held locally), then the
/// sealed ones not yet committed. Waits for batches in flight first, so the
/// files and their index agree.
fn read_from(shared: &Mutex<Written>, last: Option<&Commit>, pending: &[EvidenceRecord], from: u64, limit: usize) -> Vec<EvidenceRecord> {
    use std::io::{Seek, SeekFrom};
    if let Some(c) = last {
        c.wait();
    }
    let mut out = Vec::new();
    let mut from = from.max(1);
    loop {
        if out.len() >= limit {
            break;
        }
        // Find the segment holding `from` and open it under the index lock,
        // so a seal cannot rename the active file between lookup and open.
        let found = {
            let w = shared.lock().expect("evidence index");
            let oldest = w.sealed.first().map(|s| s.first).unwrap_or(w.active.first);
            from = from.max(oldest);
            let seg = w.sealed.iter().find(|s| s.first <= from && from <= s.last).or_else(|| (w.active.first <= from && from <= w.active.last).then_some(&w.active));
            seg.and_then(|seg| {
                let k = ((from - seg.first) / INDEX_STRIDE) as usize;
                let skip = (from - seg.first) % INDEX_STRIDE;
                File::open(&seg.path).ok().map(|f| (f, seg.index[k], skip, seg.last))
            })
        };
        let Some((mut f, offset, skip, last)) = found else { break };
        if f.seek(SeekFrom::Start(offset)).is_err() {
            break;
        }
        let want = (limit - out.len()).min((last - from + 1) as usize);
        let before = out.len();
        for line in BufReader::new(f).lines().skip(skip as usize).take(want) {
            match line.ok().and_then(|l| serde_json::from_str::<EvidenceRecord>(&l).ok()) {
                Some(r) => out.push(r),
                None => break,
            }
        }
        let got = (out.len() - before) as u64;
        if got == 0 {
            break;
        }
        from += got;
    }
    if out.len() < limit {
        let skip = pending.first().map(|p| from.saturating_sub(p.seq) as usize).unwrap_or(0);
        out.extend(pending.iter().skip(skip).take(limit - out.len()).cloned());
    }
    out
}

impl Drop for FileEvidenceStore {
    fn drop(&mut self) {
        // Never lose a sealed record on shutdown: commit, then let the writer
        // finish and stop.
        let last = self.commit();
        if let Some((tx, handle)) = self.writer.take() {
            drop(tx);
            let _ = handle.join();
        }
        let _ = last.0.lock().map(|mut rx| rx.take().map(|r| r.recv()));
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

    #[test]
    fn records_signed_on_sync_verify_under_the_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("evidence.jsonl");
        let key = KeyPair::ed25519_from_seed("evidence-1", [4; 32]);
        let mut ring = ivar_contracts::sign::Keyring::default();
        ring.add(key.public(), &["evidence"]);
        let mut s = FileEvidenceStore::open(&p).unwrap();
        s.sign_with(key.clone());
        for i in 0..300 {
            s.append(Some(&key), EvidenceKind::Event, i, "", json!({ "n": i }));
        }
        assert_eq!(s.records_from(299, 5).len(), 2, "unsynced records are readable under the same lock");
        s.sync();
        s.append(Some(&key), EvidenceKind::Event, 300, "", json!({ "n": 300 }));
        drop(s);
        let s = FileEvidenceStore::open(&p).unwrap();
        let recs = s.records();
        assert_eq!(recs.len(), 301, "the record sealed after the last sync was written on drop");
        assert!(ivar_core::evidence::verify_chain(&recs, Some(&ring)).is_ok());
        assert_eq!(s.records_from(150, 3).iter().map(|r| r.seq).collect::<Vec<_>>(), vec![150, 151, 152]);
    }

    #[test]
    fn segments_seal_reopen_fast_and_verify_offline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("evidence-0.jsonl");
        let key = KeyPair::ed25519_from_seed("evidence-0", [4; 32]);
        let mut ring = Keyring::default();
        ring.add(key.public(), &["evidence"]);
        {
            // Small segments: roughly every 40 records.
            let mut s = FileEvidenceStore::open_with(&p, 4096).unwrap();
            s.sign_with(key.clone());
            for i in 0..1000 {
                s.append(Some(&key), EvidenceKind::Event, i, "", json!({ "n": i }));
                if i % 45 == 0 {
                    s.sync();
                }
            }
        }
        let sealed = sealed_files(&p).unwrap();
        assert!(sealed.len() > 10, "segments were sealed: {}", sealed.len());
        assert!(sealed.iter().all(|(_, f)| f.with_extension("idx").exists()), "each with its index");

        let mut s = FileEvidenceStore::open_with(&p, 4096).unwrap();
        s.sign_with(key.clone());
        assert_eq!(s.head().0, 1000);
        let page: Vec<u64> = s.records_from(255, 600).iter().map(|r| r.seq).collect();
        assert_eq!(page, (255..855).collect::<Vec<_>>(), "a page spans segments in order");
        s.append(Some(&key), EvidenceKind::Event, 1000, "", json!({ "n": 1000 }));
        s.sync();
        drop(s);
        assert_eq!(verify_evidence(&p, Some(&ring)).unwrap().1, 1001, "every record and signature checks offline");

        // Archive (remove) the oldest segments: the store serves what remains.
        for (_, f) in &sealed[..3] {
            std::fs::remove_file(f).unwrap();
            std::fs::remove_file(f.with_extension("idx")).unwrap();
        }
        let s = FileEvidenceStore::open_with(&p, 4096).unwrap();
        assert_eq!(s.first_seq(), sealed[3].0);
        assert_eq!(s.records_from(1, 1)[0].seq, sealed[3].0);

        // A tampered sealed segment fails the offline check.
        drop(s);
        let f = &sealed[5].1;
        std::fs::write(f, std::fs::read_to_string(f).unwrap().replacen("\"n\":", "\"n\":9", 1)).unwrap();
        assert!(verify_evidence(&p, Some(&ring)).is_err());
    }
}
