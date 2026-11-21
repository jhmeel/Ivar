//! Light SQL classification: operation, tables, privileged and schema statements.

#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub operation: String,
    pub tables: Vec<String>,
    pub privileged: bool,
    pub schema_change: bool,
    pub destructive: bool,
}

pub fn classify(sql: &str) -> Statement {
    let lower = sql.trim().to_lowercase();
    let op = lower.split_whitespace().next().unwrap_or("").to_uppercase();
    let words: Vec<&str> = lower.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ';').filter(|w| !w.is_empty()).collect();
    let mut tables = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if matches!(*w, "from" | "join" | "into" | "update" | "table") {
            if let Some(t) = words.get(i + 1) {
                let t = t.trim_matches('"').trim_matches('`').to_string();
                if !t.is_empty() && !["select", "if", "exists", "only"].contains(&t.as_str()) && !tables.contains(&t) {
                    tables.push(t);
                }
            }
        }
    }
    let privileged = ["grant", "revoke", "create role", "alter role", "create user", "alter user", "set role", "copy ", "pg_read_file", "lo_import", "xp_cmdshell", "load data"].iter().any(|k| lower.contains(k));
    let schema_change = matches!(op.as_str(), "CREATE" | "ALTER" | "DROP" | "TRUNCATE");
    let destructive = matches!(op.as_str(), "DROP" | "TRUNCATE") || (op == "DELETE" && !lower.contains(" where "));
    Statement { operation: op, tables, privileged, schema_change, destructive }
}

#[cfg(test)]
mod tests {
    #[test]
    fn classifies() {
        let s = super::classify("SELECT * FROM persons p JOIN addresses a ON a.id = p.id");
        assert_eq!(s.tables, vec!["persons", "addresses"]);
        assert!(super::classify("GRANT ALL ON persons TO mallory").privileged);
        assert!(super::classify("DELETE FROM payments").destructive);
        assert!(!super::classify("DELETE FROM payments WHERE id = 1").destructive);
        assert!(super::classify("DROP TABLE backups").schema_change);
    }
}
