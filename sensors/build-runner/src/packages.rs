//! Installed packages against their lockfile pins.

use ivar_core::declare::compile_npm_lockfile;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;

/// Emits one event per installed package; returns those that differ from the pin.
pub fn verify(sensor: &Sensor, job: &str, lockfile: &str, installed: &str) -> anyhow::Result<Vec<String>> {
    let pins = compile_npm_lockfile("package-lock.json", lockfile)?.packages;
    let inst = compile_npm_lockfile("node_modules/.package-lock.json", installed)?.packages;
    let mut bad = Vec::new();
    for (name, p) in inst {
        let ok = pins.get(&name).map(|pin| pin.version == p.version && (pin.integrity.is_empty() || pin.integrity == p.integrity)).unwrap_or(false);
        if !ok {
            bad.push(format!("{name}@{}", p.version));
        }
        sensor.emit(sensor.event(ocsf_class::APPLICATION_LIFECYCLE, v::PACKAGE_INSTALL).app(job).attr("package", &name).attr("version", &p.version).attr("integrity", &p.integrity).build());
    }
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use ivar_contracts::sign::Keyring;
    use ivar_sensor_kit::{Sensor, SensorConfig};

    #[test]
    fn catches_unpinned_version() {
        let s = Sensor::new(SensorConfig { state_dir: std::env::temp_dir().join("ivar-ci").display().to_string(), ..Default::default() }, Keyring::default());
        let lock = r#"{"packages":{"":{},"node_modules/litellm":{"version":"1.106.2","integrity":"sha512-a"}}}"#;
        let inst = r#"{"packages":{"node_modules/litellm":{"version":"1.107.0","integrity":"sha512-b"}}}"#;
        assert_eq!(super::verify(&s, "build/test", lock, inst).unwrap(), vec!["litellm@1.107.0"]);
        assert!(super::verify(&s, "build/test", lock, lock).unwrap().is_empty());
    }
}
