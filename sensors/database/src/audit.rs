//! Audit log readers.
//!
//! pgaudit: "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.persons,select ..." inside the
//!   PostgreSQL log line; the user and client come from log_line_prefix "%m [%p] %u@%d %h ".
//! MySQL: audit_log JSON lines (Enterprise or Percona format).
//! MongoDB: auditLog JSON (atype, users, param).
//! SQL Server: rows of sys.fn_get_audit_file exported FOR JSON.

use crate::sql::classify;
use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use serde_json::Value;

fn query_event(s: &Sensor, user: &str, client: &str, db: &str, sql: &str, rows: u64) -> SecurityEvent {
    let st = classify(sql);
    let activity = if st.schema_change { v::DB_SCHEMA_CHANGE } else { v::DB_QUERY };
    let mut b = s
        .event(ocsf_class::DATASTORE_ACTIVITY, activity)
        .user(user, "service")
        .attr("database", db)
        .attr("table", &st.tables.first().cloned().unwrap_or_default())
        .attr("operation", &st.operation)
        .attr("privileged", if st.privileged { "true" } else { "false" })
        .records(rows);
    if !client.is_empty() {
        b = b.src_ip(client);
    }
    if st.destructive {
        b = b.destructive();
    }
    b.build()
}

pub fn parse(s: &Sensor, kind: &str, line: &str) -> Option<SecurityEvent> {
    match kind {
        "pgaudit" => {
            let i = line.find("AUDIT: ")?;
            let prefix = &line[..i];
            let fields: Vec<&str> = line[i + 7..].splitn(9, ',').collect();
            let sql = fields.get(7).copied().unwrap_or("").trim_matches('"');
            let (user, db) = prefix.split_whitespace().find(|w| w.contains('@')).and_then(|w| w.split_once('@')).unwrap_or(("", ""));
            let client = prefix.split_whitespace().rev().find(|w| w.parse::<std::net::IpAddr>().is_ok()).unwrap_or("");
            Some(query_event(s, user, client, db, sql, 0))
        }
        "mysql" => {
            let j: Value = serde_json::from_str(line).ok()?;
            let user = j.pointer("/account/user").or_else(|| j.get("user")).and_then(Value::as_str).unwrap_or("");
            let ip = j.pointer("/login/ip").or_else(|| j.get("ip")).and_then(Value::as_str).unwrap_or("");
            let sql = j.pointer("/general_data/query").or_else(|| j.get("sqltext")).and_then(Value::as_str)?;
            let rows = j.pointer("/general_data/rows").or_else(|| j.get("rows")).and_then(Value::as_u64).unwrap_or(0);
            let db = j.get("db").and_then(Value::as_str).unwrap_or("");
            Some(query_event(s, user, ip, db, sql, rows))
        }
        "mongodb" => {
            let j: Value = serde_json::from_str(line).ok()?;
            let atype = j.get("atype").and_then(Value::as_str)?;
            let user = j.pointer("/users/0/user").and_then(Value::as_str).unwrap_or("");
            let ip = j.pointer("/remote/ip").and_then(Value::as_str).unwrap_or("");
            let ns = j.pointer("/param/ns").and_then(Value::as_str).unwrap_or("");
            let sql = match atype {
                "dropCollection" | "dropDatabase" => format!("DROP TABLE {ns}"),
                "createUser" | "grantRolesToUser" | "updateUser" => format!("GRANT {atype} {ns}"),
                "authCheck" => format!("SELECT * FROM {}", j.pointer("/param/command").and_then(Value::as_str).map(|_| ns).unwrap_or(ns)),
                other => format!("{other} {ns}"),
            };
            Some(query_event(s, user, ip, ns.split('.').next().unwrap_or(""), &sql, 0))
        }
        "mssql" => {
            let j: Value = serde_json::from_str(line).ok()?;
            let user = j.get("server_principal_name").and_then(Value::as_str).unwrap_or("");
            let ip = j.get("client_ip").and_then(Value::as_str).unwrap_or("");
            let sql = j.get("statement").and_then(Value::as_str)?;
            let rows = j.get("affected_rows").and_then(Value::as_u64).unwrap_or(0);
            let db = j.get("database_name").and_then(Value::as_str).unwrap_or("");
            Some(query_event(s, user, ip, db, sql, rows))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::sign::Keyring;
    use ivar_sensor_kit::SensorConfig;

    fn sensor() -> Sensor {
        Sensor::new(SensorConfig { state_dir: std::env::temp_dir().join("ivar-db-test").display().to_string(), ..Default::default() }, Keyring::default())
    }

    #[test]
    fn readers() {
        let s = sensor();
        let pg = "2026-11-19 02:15:00.000 UTC [77] lookup@registry 10.1.2.3 LOG:  AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.persons,\"select * from persons\",<not logged>";
        let e = parse(&s, "pgaudit", pg).unwrap();
        assert_eq!(e.ext().attributes["table"], "persons");
        assert_eq!(e.src_endpoint.unwrap().ip, "10.1.2.3");
        let my = r#"{"timestamp":"2026-11-19 02:15:00","class":"general","account":{"user":"app","host":"%"},"login":{"ip":"10.0.0.8"},"general_data":{"query":"DROP TABLE backups","rows":0},"db":"ops"}"#;
        let e = parse(&s, "mysql", my).unwrap();
        assert!(e.ext().destructive);
        assert_eq!(e.activity_name, "db.schema_change");
        let mongo = r#"{"atype":"dropDatabase","users":[{"user":"ops","db":"admin"}],"remote":{"ip":"10.0.0.9"},"param":{"ns":"payments"}}"#;
        assert!(parse(&s, "mongodb", mongo).unwrap().ext().destructive);
        let ms = r#"{"server_principal_name":"svc_lookup","client_ip":"10.0.0.7","statement":"SELECT * FROM persons","affected_rows":50000,"database_name":"cpr"}"#;
        assert_eq!(parse(&s, "mssql", ms).unwrap().ext().records_read, 50000);
    }
}
