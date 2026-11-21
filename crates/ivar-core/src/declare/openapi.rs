//! OpenAPI schemas compile into declared routes and request schemas, used by
//! positive security at the sensor (mass assignment, role writes, shadow routes).

use super::{load_doc, DeclareError, Declarations};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Route {
    pub method: String,
    pub template: String,
    /// Body properties the schema permits. Empty means no body is declared.
    pub allowed_properties: Vec<String>,
    /// Properties marked readOnly or x-ivar-privileged: writing them is a
    /// critical positive security violation unless the caller has the role.
    pub privileged_properties: Vec<String>,
    /// Roles required to call the route (x-ivar-roles).
    pub roles: Vec<String>,
    /// Business action bound to this route (x-ivar-action), e.g. payout.
    pub business_action: String,
    /// Admin routes fail closed when their check fails (section 11.2).
    pub admin: bool,
    pub declared_in: String,
}

impl Route {
    pub fn matches(&self, method: &str, path: &str) -> bool {
        if !self.method.eq_ignore_ascii_case(method) {
            return false;
        }
        let path = path.split('?').next().unwrap_or(path);
        let a: Vec<&str> = self.template.trim_matches('/').split('/').collect();
        let b: Vec<&str> = path.trim_matches('/').split('/').collect();
        a.len() == b.len() && a.iter().zip(b.iter()).all(|(t, p)| (t.starts_with('{') && t.ends_with('}') && !p.is_empty()) || t == p)
    }
}

fn resolve<'a>(root: &'a Value, v: &'a Value) -> &'a Value {
    if let Some(r) = v.get("$ref").and_then(Value::as_str) {
        let mut cur = root;
        for part in r.trim_start_matches("#/").split('/') {
            cur = match cur.get(part) {
                Some(next) => next,
                None => return v,
            };
        }
        return cur;
    }
    v
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default()
}

pub fn compile_openapi(file: &str, text: &str) -> Result<Declarations, DeclareError> {
    let doc = load_doc(file, text)?;
    let mut out = Declarations::default();
    let methods = ["get", "put", "post", "delete", "patch", "head", "options"];
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for (template, item) in paths {
            for m in methods {
                let Some(op) = item.get(m) else { continue };
                let mut route = Route {
                    method: m.to_uppercase(),
                    template: template.clone(),
                    roles: strings(op.get("x-ivar-roles")),
                    business_action: op.get("x-ivar-action").and_then(Value::as_str).unwrap_or("").to_string(),
                    admin: op.get("x-ivar-admin").and_then(Value::as_bool).unwrap_or(false) || template.starts_with("/admin"),
                    declared_in: file.to_string(),
                    ..Default::default()
                };
                let schema = op
                    .pointer("/requestBody/content/application~1json/schema")
                    .map(|s| resolve(&doc, s));
                if let Some(schema) = schema {
                    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                        for (name, p) in props {
                            let p = resolve(&doc, p);
                            route.allowed_properties.push(name.clone());
                            let privileged = p.get("readOnly").and_then(Value::as_bool).unwrap_or(false)
                                || p.get("x-ivar-privileged").and_then(Value::as_bool).unwrap_or(false);
                            if privileged {
                                route.privileged_properties.push(name.clone());
                            }
                        }
                    }
                }
                out.routes.push(route);
            }
        }
    }
    out.public_roles = strings(doc.pointer("/x-ivar/public_signup_roles"));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"
openapi: 3.0.3
x-ivar:
  public_signup_roles: [customer]
paths:
  /users/{id}:
    patch:
      x-ivar-roles: [self]
      requestBody:
        content:
          application/json:
            schema: { $ref: '#/components/schemas/UserPatch' }
  /payouts:
    post:
      x-ivar-action: payout
components:
  schemas:
    UserPatch:
      type: object
      properties:
        name: { type: string }
        role: { type: string, readOnly: true }
"#;

    #[test]
    fn compiles_routes_and_privileged_fields() {
        let d = compile_openapi("api.yaml", SPEC).unwrap();
        let r = d.match_route("PATCH", "/users/42").unwrap();
        assert_eq!(r.allowed_properties, vec!["name", "role"]);
        assert_eq!(r.privileged_properties, vec!["role"]);
        assert_eq!(d.match_route("POST", "/payouts").unwrap().business_action, "payout");
        assert!(d.match_route("GET", "/.env").is_none());
        assert_eq!(d.public_roles, vec!["customer"]);
    }
}
