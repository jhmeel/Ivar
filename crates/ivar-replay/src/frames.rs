//! Frames: a time ordered list, each tied to the evidence IDs behind it.
//!
//! Fidelity rules (section 13.2): frames follow each sensor's monotonic
//! sequence and signed timestamp; clock skew between sensors is corrected and
//! shown, never hidden; where no sensor saw a step the timeline shows an
//! unobserved interval rather than an inferred path; playback speed changes
//! only the clock, and real elapsed time is always shown.

use ivar_contracts::{ReplayFrame, SecurityEvent};
use ivar_core::evidence::{EvidenceKind, EvidenceRecord};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Measured skew of one sensor's clock against the core's receipt clock.
#[derive(Debug, Clone, Default)]
pub struct SensorClock {
    pub skew_ms: BTreeMap<String, i64>,
}

impl SensorClock {
    /// Skew is the median of (core receipt time minus sensor time) per sensor.
    pub fn measure(records: &[EvidenceRecord]) -> Self {
        let mut samples: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        for r in records.iter().filter(|r| r.kind == EvidenceKind::Event) {
            if let Ok(ev) = serde_json::from_value::<SecurityEvent>(r.payload.clone()) {
                samples.entry(ev.ext().sensor_id).or_default().push(r.time - ev.time);
            }
        }
        let skew_ms = samples
            .into_iter()
            .map(|(k, mut v)| {
                v.sort();
                (k, v[v.len() / 2])
            })
            .collect();
        SensorClock { skew_ms }
    }
}

fn kind_name(k: EvidenceKind) -> String {
    serde_json::to_value(k).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

fn hops(ev: &SecurityEvent) -> BTreeMap<String, u64> {
    let ext = ev.ext();
    ["sensor", "ingest", "core", "decide", "enforce"]
        .iter()
        .filter_map(|h| ext.attributes.get(&format!("hop_{h}_us")).and_then(|v| v.parse().ok()).map(|v| (h.to_string(), v)))
        .collect()
}

/// Entities that a record touches, for filtering to one incident.
fn touches(payload: &Value, keys: &BTreeSet<String>) -> bool {
    if keys.is_empty() {
        return true;
    }
    let text = payload.to_string();
    keys.iter().any(|k| {
        let (_, id) = k.split_once(':').unwrap_or(("", k));
        !id.is_empty() && text.contains(&format!("\"{id}\""))
    })
}

/// Build frames from verified evidence. `entity_keys` limits frames to the
/// incident's entities; `expected_layers` names the sensor types this
/// platform tier should have, so missing layers show as unobserved.
/// `risks` holds the EntityRisk scores the re execution produced, keyed by
/// the evidence id of the event that moved them; each becomes a risk frame
/// right after its event so the fast and slow timescales can be drawn.
pub fn frames_for(records: &[EvidenceRecord], entity_keys: &BTreeSet<String>, counterfactual: bool, expected_layers: &[&str], risks: &BTreeMap<String, Vec<Value>>) -> (Vec<ReplayFrame>, Vec<String>) {
    let clock = SensorClock::measure(records);
    let mut frames = Vec::new();
    let mut last_seq: BTreeMap<String, u64> = BTreeMap::new();
    let mut seen_layers: BTreeSet<String> = BTreeSet::new();
    let mut current_sensor = (String::new(), 0u64, 0i64, BTreeMap::new());
    for r in records {
        if !touches(&r.payload, entity_keys) && r.kind != EvidenceKind::Tamper {
            continue;
        }
        if r.kind == EvidenceKind::Event {
            if let Ok(ev) = serde_json::from_value::<SecurityEvent>(r.payload.clone()) {
                let ext = ev.ext();
                seen_layers.insert(ext.sensor_type.clone());
                let skew = *clock.skew_ms.get(&ext.sensor_id).unwrap_or(&0);
                if let Some(prev) = last_seq.get(&ext.sensor_id) {
                    if ext.sensor_seq > prev + 1 && entity_keys.is_empty() {
                        frames.push(ReplayFrame {
                            index: 0,
                            time: ev.time + skew,
                            sensor_time: ev.time,
                            clock_skew_ms: skew,
                            sensor_id: ext.sensor_id.clone(),
                            sensor_seq: prev + 1,
                            kind: "gap".into(),
                            evidence_ids: vec![],
                            payload: json!({"unobserved": format!("sequence {} to {} missing from {}", prev + 1, ext.sensor_seq - 1, ext.sensor_id)}),
                            counterfactual,
                            hops_us: BTreeMap::new(),
                            elapsed_ms: 0,
                        });
                    }
                }
                last_seq.insert(ext.sensor_id.clone(), ext.sensor_seq);
                current_sensor = (ext.sensor_id.clone(), ext.sensor_seq, skew, hops(&ev));
                frames.push(ReplayFrame {
                    index: 0,
                    time: ev.time + skew,
                    sensor_time: ev.time,
                    clock_skew_ms: skew,
                    sensor_id: ext.sensor_id,
                    sensor_seq: ext.sensor_seq,
                    kind: "event".into(),
                    evidence_ids: vec![r.evidence_id.clone()],
                    payload: r.payload.clone(),
                    counterfactual,
                    hops_us: current_sensor.3.clone(),
                    elapsed_ms: 0,
                });
                for risk in risks.get(&r.evidence_id).into_iter().flatten().filter(|v| touches(v, entity_keys)) {
                    frames.push(ReplayFrame {
                        index: 0,
                        time: ev.time + skew,
                        sensor_time: ev.time,
                        clock_skew_ms: skew,
                        sensor_id: current_sensor.0.clone(),
                        sensor_seq: current_sensor.1,
                        kind: "risk".into(),
                        evidence_ids: vec![r.evidence_id.clone()],
                        payload: risk.clone(),
                        counterfactual,
                        hops_us: BTreeMap::new(),
                        elapsed_ms: 0,
                    });
                }
                continue;
            }
        }
        let mut ids = vec![r.evidence_id.clone()];
        if let Some(arr) = r.payload.get("evidence_ids").and_then(|v| v.as_array()) {
            ids.extend(arr.iter().filter_map(|x| x.as_str().map(String::from)));
        }
        frames.push(ReplayFrame {
            index: 0,
            time: r.time,
            sensor_time: r.time,
            clock_skew_ms: 0,
            sensor_id: current_sensor.0.clone(),
            sensor_seq: current_sensor.1,
            kind: kind_name(r.kind),
            evidence_ids: ids,
            payload: r.payload.clone(),
            counterfactual,
            hops_us: BTreeMap::new(),
            elapsed_ms: 0,
        });
    }
    // Ordered clock: stable by corrected time, then each sensor's own sequence.
    frames.sort_by(|a, b| a.time.cmp(&b.time).then(a.sensor_id.cmp(&b.sensor_id)).then(a.sensor_seq.cmp(&b.sensor_seq)));
    let start = frames.first().map(|f| f.time).unwrap_or(0);
    for (i, f) in frames.iter_mut().enumerate() {
        f.index = i as u64;
        f.elapsed_ms = f.time - start;
    }
    let unobserved = expected_layers.iter().filter(|l| !seen_layers.contains(**l)).map(|l| l.to_string()).collect();
    (frames, unobserved)
}
