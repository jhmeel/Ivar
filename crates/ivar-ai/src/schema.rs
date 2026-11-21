//! Strict schema validation of model output (guardrail: responses must match
//! a strict schema before anything uses them). Supports the subset our role
//! schemas use: object with required and additionalProperties false, array,
//! string with enum, number with minimum and maximum, integer, boolean.

use serde_json::Value;

pub fn validate(schema: &Value, v: &Value, path: &str) -> Result<(), String> {
    let t = schema.get("type").and_then(Value::as_str).unwrap_or("");
    match t {
        "object" => {
            let o = v.as_object().ok_or(format!("{path}: expected object"))?;
            let props = schema.get("properties").and_then(Value::as_object).cloned().unwrap_or_default();
            for r in schema.get("required").and_then(Value::as_array).cloned().unwrap_or_default() {
                let k = r.as_str().unwrap_or("");
                if !o.contains_key(k) {
                    return Err(format!("{path}: missing {k}"));
                }
            }
            for (k, val) in o {
                match props.get(k) {
                    Some(s) => validate(s, val, &format!("{path}.{k}"))?,
                    None => return Err(format!("{path}: unexpected field {k}")),
                }
            }
            Ok(())
        }
        "array" => {
            let a = v.as_array().ok_or(format!("{path}: expected array"))?;
            if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
                if a.len() as u64 > max {
                    return Err(format!("{path}: more than {max} items"));
                }
            }
            let items = schema.get("items").cloned().unwrap_or(Value::Null);
            for (i, x) in a.iter().enumerate() {
                validate(&items, x, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        "string" => {
            let s = v.as_str().ok_or(format!("{path}: expected string"))?;
            if let Some(e) = schema.get("enum").and_then(Value::as_array) {
                if !e.iter().any(|x| x.as_str() == Some(s)) {
                    return Err(format!("{path}: {s} not allowed"));
                }
            }
            if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
                if s.chars().count() as u64 > max {
                    return Err(format!("{path}: longer than {max}"));
                }
            }
            Ok(())
        }
        "number" | "integer" => {
            let n = v.as_f64().ok_or(format!("{path}: expected number"))?;
            if t == "integer" && n.fract() != 0.0 {
                return Err(format!("{path}: expected integer"));
            }
            if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
                if n < min {
                    return Err(format!("{path}: below {min}"));
                }
            }
            if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
                if n > max {
                    return Err(format!("{path}: above {max}"));
                }
            }
            Ok(())
        }
        "boolean" => v.as_bool().map(|_| ()).ok_or(format!("{path}: expected boolean")),
        _ => Ok(()),
    }
}
