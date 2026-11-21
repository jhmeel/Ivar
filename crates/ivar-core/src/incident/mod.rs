//! Correlation into incidents. An incident opens on containment, a deception
//! hit, an invariant breach, a refused intent, a decoy out of context or a
//! tamper alert, and collects the timeline of everything linked to it.

use crate::ids;
use ivar_contracts::{EntityRef, Incident, IncidentStatus, TimelineEntry, CONTRACT_VERSION};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct IncidentTracker {
    incidents: BTreeMap<String, Incident>,
    by_entity: BTreeMap<String, String>,
}

impl IncidentTracker {
    pub fn get(&self, id: &str) -> Option<&Incident> {
        self.incidents.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &Incident> {
        self.incidents.values()
    }

    pub fn for_entity(&self, key: &str) -> Option<&Incident> {
        self.by_entity.get(key).and_then(|id| self.incidents.get(id))
    }

    /// Open or extend the incident linked to any of these entities.
    #[allow(clippy::too_many_arguments)]
    pub fn open_or_extend(&mut self, title: &str, stage: &str, entities: &[EntityRef], entry: TimelineEntry, policy_version: &str, now: i64) -> String {
        let existing = entities.iter().find_map(|e| self.by_entity.get(&e.key()).cloned());
        let id = existing.unwrap_or_else(|| ids::derive("inc", &[title, &entry.evidence_ids.join(","), &now.to_string()]));
        let inc = self.incidents.entry(id.clone()).or_insert_with(|| Incident {
            contract: CONTRACT_VERSION.into(),
            incident_id: id.clone(),
            title: title.into(),
            opened_at: now,
            status: IncidentStatus::Open,
            attack_stage: stage.into(),
            timeline: vec![],
            affected_entities: vec![],
            verdict_ids: vec![],
            action_request_ids: vec![],
            policy_version: policy_version.into(),
        });
        if !stage.is_empty() {
            inc.attack_stage = stage.into();
        }
        inc.timeline.push(entry);
        for e in entities {
            if !inc.affected_entities.iter().any(|x| x.key() == e.key()) {
                inc.affected_entities.push(e.clone());
            }
            self.by_entity.insert(e.key(), id.clone());
        }
        id
    }

    /// Link an observation to an existing incident without opening one.
    pub fn link(&mut self, entities: &[EntityRef], entry: TimelineEntry) -> Option<String> {
        let id = entities.iter().find_map(|e| self.by_entity.get(&e.key()).cloned())?;
        if let Some(inc) = self.incidents.get_mut(&id) {
            inc.timeline.push(entry);
        }
        Some(id)
    }

    pub fn add_verdict(&mut self, id: &str, verdict_id: &str) {
        if let Some(i) = self.incidents.get_mut(id) {
            if !i.verdict_ids.iter().any(|v| v == verdict_id) {
                i.verdict_ids.push(verdict_id.into());
            }
        }
    }

    pub fn add_action(&mut self, id: &str, action_id: &str) {
        if let Some(i) = self.incidents.get_mut(id) {
            i.action_request_ids.push(action_id.into());
        }
    }

    pub fn set_status(&mut self, id: &str, status: IncidentStatus) {
        if let Some(i) = self.incidents.get_mut(id) {
            i.status = status;
        }
    }
}
