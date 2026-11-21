//! CI workflows (GitHub Actions) compile into the secrets each job may hold
//! and the egress each job declares (x ivar egress list, default deny).

use super::{load_doc, DeclareError, Declarations, EgressRule};
use ivar_contracts::{EntityRef, TrustEdge};
use regex::Regex;
use serde_json::Value;

pub fn compile_github_workflow(file: &str, text: &str) -> Result<Declarations, DeclareError> {
    let doc = load_doc(file, text)?;
    let secret_ref = Regex::new(r"secrets\.([A-Za-z0-9_]+)").expect("static regex");
    let mut out = Declarations::default();
    let workflow = doc.get("name").and_then(Value::as_str).unwrap_or(file).to_string();
    let Some(jobs) = doc.get("jobs").and_then(Value::as_object) else { return Ok(out) };
    for (job, body) in jobs {
        let holder = format!("{workflow}/{job}");
        let raw = serde_json::to_string(body).unwrap_or_default();
        let mut secrets: Vec<String> = secret_ref.captures_iter(&raw).map(|c| c[1].to_string()).collect();
        secrets.sort();
        secrets.dedup();
        for s in secrets {
            out.edges.push(TrustEdge {
                holder: Some(EntityRef::actor("ci_job", &holder)),
                resource: format!("secret:{s}"),
                permission: "read".into(),
                granted_by: "workflow".into(),
                purpose: format!("job {job}"),
                declared: true,
                declared_in: file.into(),
                ..Default::default()
            });
        }
        let egress = body
            .get("x-ivar-egress")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for d in egress.iter().filter_map(Value::as_str) {
            out.egress.push(EgressRule { holder: format!("ci_job:{holder}"), destination: d.into(), declared_in: file.into() });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn secrets_per_job() {
        let y = r#"
name: release
jobs:
  publish:
    x-ivar-egress: [registry.npmjs.org]
    steps:
      - run: npm publish
        env: { NODE_AUTH_TOKEN: "${{ secrets.NPM_TOKEN }}" }
"#;
        let d = super::compile_github_workflow("release.yml", y).unwrap();
        assert_eq!(d.edges[0].resource, "secret:NPM_TOKEN");
        assert!(d.egress_declared("ci_job:release/publish", "registry.npmjs.org"));
    }
}
