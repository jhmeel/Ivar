//! Append only, hash chained, signed evidence storage.

use super::record::{EvidenceKind, EvidenceRecord};
use crate::ids;
use ivar_contracts::sign::{sign_bytes, verify_bytes, KeyPair, Keyring};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ChainError {
    #[error("record {seq}: sequence gap")]
    Sequence { seq: u64 },
    #[error("record {seq}: previous hash does not match")]
    Link { seq: u64 },
    #[error("record {seq}: hash does not match content")]
    Hash { seq: u64 },
    #[error("record {seq}: missing or invalid signature")]
    Signature { seq: u64 },
}

/// Storage for evidence. The server implements this on disk; the memory
/// store serves tests, the SDK and the browser.
pub trait EvidenceStore {
    fn head(&self) -> (u64, String);
    fn put(&mut self, record: EvidenceRecord);
    fn records(&self) -> Vec<EvidenceRecord>;

    /// Up to `limit` records starting at sequence `from` (sequences start at 1).
    fn records_from(&self, from: u64, limit: usize) -> Vec<EvidenceRecord> {
        self.records().into_iter().filter(|r| r.seq >= from).take(limit).collect()
    }

    /// Make every record put so far durable. A store that is durable on put
    /// needs nothing here; one that batches writes syncs them now. Called
    /// before any verdict or action that cites the records is released.
    fn sync(&mut self) {}

    /// True when the store holds the evidence key and signs records itself
    /// when it syncs (in parallel, off the per event path). Records are then
    /// appended unsigned and are signed before they are written.
    fn signs_on_sync(&self) -> bool {
        false
    }

    /// Seal a record and return its evidence id.
    fn append(&mut self, signer: Option<&KeyPair>, kind: EvidenceKind, time: i64, incident_hint: &str, payload: serde_json::Value) -> String {
        let (seq, prev) = self.head();
        let seq = seq + 1;
        let input = EvidenceRecord::digest_input(seq, time, kind, &prev, &payload);
        let hash = ids::sha256_hex(&input);
        let record = EvidenceRecord {
            seq,
            evidence_id: ids::derive("evd", &[&hash]),
            time,
            kind,
            incident_hint: incident_hint.into(),
            payload,
            prev_hash: prev,
            signature: if self.signs_on_sync() { None } else { signer.map(|k| sign_bytes(k, hash.as_bytes())) },
            hash,
        };
        let id = record.evidence_id.clone();
        self.put(record);
        id
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryEvidenceStore {
    records: Vec<EvidenceRecord>,
}

impl EvidenceStore for MemoryEvidenceStore {
    fn head(&self) -> (u64, String) {
        self.records.last().map(|r| (r.seq, r.hash.clone())).unwrap_or((0, GENESIS_HASH.into()))
    }
    fn put(&mut self, record: EvidenceRecord) {
        self.records.push(record);
    }
    fn records(&self) -> Vec<EvidenceRecord> {
        self.records.clone()
    }
}

impl MemoryEvidenceStore {
    pub fn from_records(records: Vec<EvidenceRecord>) -> Self {
        MemoryEvidenceStore { records }
    }
}

/// Verify a chain from its first record. With a keyring, every record must
/// carry a valid evidence signature.
pub fn verify_chain(records: &[EvidenceRecord], ring: Option<&Keyring>) -> Result<String, ChainError> {
    let mut prev = records.first().map(|r| r.prev_hash.clone()).unwrap_or_else(|| GENESIS_HASH.into());
    let mut expected_seq = records.first().map(|r| r.seq).unwrap_or(1);
    for r in records {
        if r.seq != expected_seq {
            return Err(ChainError::Sequence { seq: r.seq });
        }
        if r.prev_hash != prev {
            return Err(ChainError::Link { seq: r.seq });
        }
        let h = ids::sha256_hex(&EvidenceRecord::digest_input(r.seq, r.time, r.kind, &r.prev_hash, &r.payload));
        if h != r.hash {
            return Err(ChainError::Hash { seq: r.seq });
        }
        if let Some(ring) = ring {
            let ok = r.signature.as_ref().map(|s| verify_bytes(ring, "evidence", s, r.hash.as_bytes()).is_ok()).unwrap_or(false);
            if !ok {
                return Err(ChainError::Signature { seq: r.seq });
            }
        }
        prev = r.hash.clone();
        expected_seq += 1;
    }
    Ok(prev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tamper_is_detected() {
        let k = KeyPair::ed25519_from_seed("evidence-1", [5; 32]);
        let mut ring = Keyring::default();
        ring.add(k.public(), &["evidence"]);
        let mut s = MemoryEvidenceStore::default();
        for i in 0..5 {
            s.append(Some(&k), EvidenceKind::Event, i, "", json!({"n": i}));
        }
        let mut recs = s.records();
        assert!(verify_chain(&recs, Some(&ring)).is_ok());
        recs[2].payload = json!({"n": 99});
        assert_eq!(verify_chain(&recs, Some(&ring)), Err(ChainError::Hash { seq: 3 }));
        let mut recs = s.records();
        recs.remove(1);
        assert!(verify_chain(&recs, Some(&ring)).is_err());
        let mut recs = s.records();
        recs[0].signature = None;
        assert_eq!(verify_chain(&recs, Some(&ring)), Err(ChainError::Signature { seq: 1 }));
    }
}
