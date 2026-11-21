//! Protobuf contracts generated from proto/ivar/v1, with small helpers.

#[allow(clippy::all)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/ivar.v1.rs"));
}

pub use generated::*;

impl EntityRef {
    pub fn new(t: &str, id: &str, role: EntityRole) -> Self {
        EntityRef { r#type: t.to_string(), id: id.to_string(), role: role as i32 }
    }
    pub fn actor(t: &str, id: &str) -> Self {
        Self::new(t, id, EntityRole::Actor)
    }
    pub fn target(t: &str, id: &str) -> Self {
        Self::new(t, id, EntityRole::Target)
    }
    /// Key that ignores role.
    pub fn key(&self) -> String {
        format!("{}:{}", self.r#type, self.id)
    }
}

impl SecurityEvent {
    pub fn ext(&self) -> IvarExtension {
        self.ivar.clone().unwrap_or_default()
    }
}
