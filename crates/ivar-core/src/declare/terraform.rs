//! Terraform plans (`terraform show -json`) compile into declared grants and
//! egress: IAM attachments become edges, security group egress becomes rules.

use super::{load_doc, DeclareError, Declarations, EgressRule};
use ivar_contracts::{EntityRef, TrustEdge};
use serde_json::Value;

fn walk_resources(module: &Value, out: &mut Vec<Value>) {
    if let Some(rs) = module.get("resources").and_then(Value::as_array) {
        out.extend(rs.iter().cloned());
    }
    if let Some(children) = module.get("child_modules").and_then(Value::as_array) {
        for c in children {
            walk_resources(c, out);
        }
    }
}

pub fn compile_terraform_plan(file: &str, text: &str) -> Result<Declarations, DeclareError> {
    let doc = load_doc(file, text)?;
    let mut resources = Vec::new();
    if let Some(root) = doc.pointer("/planned_values/root_module") {
        walk_resources(root, &mut resources);
    }
    let mut out = Declarations::default();
    for r in resources {
        let rtype = r.get("type").and_then(Value::as_str).unwrap_or("");
        let v = r.get("values").cloned().unwrap_or(Value::Null);
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        match rtype {
            "aws_iam_role_policy_attachment" | "google_project_iam_member" | "azurerm_role_assignment" => {
                let holder = [s("role"), s("member"), s("principal_id")].into_iter().find(|x| !x.is_empty()).unwrap_or_default();
                let permission = [s("policy_arn"), s("role_definition_name")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| s("role"));
                out.edges.push(TrustEdge {
                    holder: Some(EntityRef::actor("service", &holder)),
                    resource: [s("project"), s("scope")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "*".into()),
                    permission,
                    granted_by: "terraform".into(),
                    declared: true,
                    declared_in: file.into(),
                    ..Default::default()
                });
            }
            "aws_security_group" => {
                let name = s("name");
                for e in v.get("egress").and_then(Value::as_array).cloned().unwrap_or_default() {
                    for cidr in e.get("cidr_blocks").and_then(Value::as_array).cloned().unwrap_or_default() {
                        if let Some(c) = cidr.as_str() {
                            out.egress.push(EgressRule { holder: format!("service:{name}"), destination: c.into(), declared_in: file.into() });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn plan_to_edges() {
        let p = r#"{"planned_values":{"root_module":{"resources":[{"type":"aws_iam_role_policy_attachment","values":{"role":"billing","policy_arn":"arn:aws:iam::aws:policy/ReadOnly"}}],"child_modules":[{"resources":[{"type":"aws_security_group","values":{"name":"api","egress":[{"cidr_blocks":["10.0.0.0/16"]}]}}]}]}}}"#;
        let d = super::compile_terraform_plan("plan.json", p).unwrap();
        assert_eq!(d.edges.len(), 1);
        assert!(d.egress_declared("service:api", "10.0.0.0/16"));
    }
}
