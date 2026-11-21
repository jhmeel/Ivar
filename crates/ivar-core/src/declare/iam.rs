//! IAM policies (AWS style JSON) compile into declared trust edges.

use super::{load_doc, DeclareError, Declarations};
use ivar_contracts::{EntityRef, TrustEdge};
use serde_json::Value;

fn list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        _ => vec![],
    }
}

/// `holder` is the identity the policy is attached to, e.g. "service:billing".
pub fn compile_iam_policy(file: &str, holder: &str, owner: &str, text: &str) -> Result<Declarations, DeclareError> {
    let doc = load_doc(file, text)?;
    let (t, id) = holder.split_once(':').unwrap_or(("service", holder));
    let mut out = Declarations::default();
    let statements = match doc.get("Statement") {
        Some(Value::Array(a)) => a.clone(),
        Some(v @ Value::Object(_)) => vec![v.clone()],
        _ => vec![],
    };
    for st in statements {
        if st.get("Effect").and_then(Value::as_str) != Some("Allow") {
            continue;
        }
        let purpose = st.get("Sid").and_then(Value::as_str).unwrap_or("").to_string();
        for action in list(st.get("Action")) {
            for resource in list(st.get("Resource")) {
                out.edges.push(TrustEdge {
                    holder: Some(EntityRef::actor(t, id)),
                    resource,
                    permission: action.clone(),
                    granted_by: "iam".into(),
                    purpose: purpose.clone(),
                    declared: true,
                    declared_in: file.to_string(),
                    owner: owner.to_string(),
                    ..Default::default()
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn allow_statements_become_edges() {
        let p = r#"{"Statement":[{"Sid":"ReadInvoices","Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::invoices/*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}"#;
        let d = super::compile_iam_policy("iam.json", "service:billing", "user:ops", p).unwrap();
        assert_eq!(d.edges.len(), 1);
        assert_eq!(d.edges[0].purpose, "ReadInvoices");
    }
}
