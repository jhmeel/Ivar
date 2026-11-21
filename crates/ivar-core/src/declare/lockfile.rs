//! Lockfiles compile into pinned packages with expected integrity, so a
//! package without verifiable provenance is refused (principle 4).

use super::{load_doc, DeclareError, DeclaredPackage, Declarations};
use serde_json::Value;

/// npm package-lock.json, lockfileVersion 2 or 3.
pub fn compile_npm_lockfile(file: &str, text: &str) -> Result<Declarations, DeclareError> {
    let doc = load_doc(file, text)?;
    let mut out = Declarations::default();
    if let Some(pkgs) = doc.get("packages").and_then(Value::as_object) {
        for (path, p) in pkgs {
            if path.is_empty() {
                continue;
            }
            let name = p
                .get("name")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| path.rsplit("node_modules/").next().unwrap_or(path).to_string());
            let get = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            out.packages.insert(
                name.clone(),
                DeclaredPackage { name, version: get("version"), integrity: get("integrity"), resolved: get("resolved"), declared_in: file.into() },
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pins_packages() {
        let l = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/litellm-js":{"version":"1.0.0","integrity":"sha512-abc","resolved":"https://registry.npmjs.org/x"}}}"#;
        let d = super::compile_npm_lockfile("package-lock.json", l).unwrap();
        assert_eq!(d.packages["litellm-js"].integrity, "sha512-abc");
    }
}
