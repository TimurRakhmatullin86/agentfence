use crate::types::DataAccessPolicy;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use sqlparser::ast::{Statement, SetExpr, TableFactor, Select, SelectItem, Expr};

#[derive(Debug)]
pub struct SqlViolation {
    pub table: String,
    pub reason: String,
}

pub fn check_sql_in_params(
    params: &std::collections::HashMap<String, serde_json::Value>,
    policy: &DataAccessPolicy,
) -> Vec<SqlViolation> {
    let mut violations = Vec::new();

    for (_key, value) in params {
        if let Some(sql) = value.as_str() {
            if looks_like_sql(sql) {
                violations.extend(check_sql(sql, policy));
            }
        }
    }

    violations
}

fn looks_like_sql(s: &str) -> bool {
    let upper = s.trim().to_uppercase();
    upper.starts_with("SELECT ")
        || upper.starts_with("INSERT ")
        || upper.starts_with("UPDATE ")
        || upper.starts_with("DELETE ")
        || upper.starts_with("CREATE ")
        || upper.starts_with("DROP ")
        || upper.starts_with("ALTER ")
        || upper.starts_with("WITH ")
}

fn check_sql(sql: &str, policy: &DataAccessPolicy) -> Vec<SqlViolation> {
    let dialect = GenericDialect {};
    let statements = match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => stmts,
        Err(_) => return Vec::new(),
    };

    let mut violations = Vec::new();
    for stmt in &statements {
        let tables = extract_tables(stmt);
        for table in &tables {
            if policy.denied_tables.iter().any(|d| d == table) {
                violations.push(SqlViolation {
                    table: table.clone(),
                    reason: format!("table '{}' is in denied_tables", table),
                });
            }
            if !policy.allowed_tables.is_empty()
                && !policy.allowed_tables.iter().any(|a| a == table)
            {
                violations.push(SqlViolation {
                    table: table.clone(),
                    reason: format!("table '{}' is not in allowed_tables", table),
                });
            }
        }

        let columns = extract_columns(stmt);
        for col in &columns {
            if policy.denied_fields.iter().any(|d| d == col) {
                violations.push(SqlViolation {
                    table: col.clone(),
                    reason: format!("field '{}' is in denied_fields", col),
                });
            }
        }

        if matches!(policy.pii, Some(crate::types::PiiPolicy::Deny)) {
            for table in &tables {
                if table.to_lowercase().contains("pii")
                    || table.to_lowercase().contains("personal")
                    || table.to_lowercase().contains("private")
                {
                    violations.push(SqlViolation {
                        table: table.clone(),
                        reason: format!("table '{}' may contain PII (policy: deny)", table),
                    });
                }
            }
        }
    }

    violations
}

fn extract_tables(stmt: &Statement) -> Vec<String> {
    let mut tables = Vec::new();
    match stmt {
        Statement::Query(query) => {
            extract_tables_from_setexpr(query.body.as_ref(), &mut tables);
        }
        Statement::Insert(insert) => {
            tables.push(insert.table_name.to_string());
            if let Some(ref source) = insert.source {
                extract_tables_from_setexpr(source.body.as_ref(), &mut tables);
            }
        }
        Statement::Update { table, .. } => {
            if let Some(name) = extract_table_name(&table.relation) {
                tables.push(name);
            }
        }
        Statement::Delete(delete) => {
            let from_tables = match &delete.from {
                sqlparser::ast::FromTable::WithFromKeyword(t) => t,
                sqlparser::ast::FromTable::WithoutKeyword(t) => t,
            };
            for from_item in from_tables {
                if let Some(name) = extract_table_name(&from_item.relation) {
                    tables.push(name);
                }
            }
        }
        Statement::Drop { names, .. } => {
            for name in names {
                tables.push(name.to_string());
            }
        }
        _ => {}
    }
    tables
}

fn extract_tables_from_setexpr(set_expr: &SetExpr, tables: &mut Vec<String>) {
    match set_expr {
        SetExpr::Select(select) => {
            extract_tables_from_select(select.as_ref(), tables);
        }
        SetExpr::SetOperation { left, right, .. } => {
            extract_tables_from_setexpr(left.as_ref(), tables);
            extract_tables_from_setexpr(right.as_ref(), tables);
        }
        _ => {}
    }
}

fn extract_tables_from_select(select: &Select, tables: &mut Vec<String>) {
    for from_item in &select.from {
        if let Some(name) = extract_table_name(&from_item.relation) {
            tables.push(name);
        }
        for join in &from_item.joins {
            if let Some(name) = extract_table_name(&join.relation) {
                tables.push(name);
            }
        }
    }
}

fn extract_table_name(factor: &TableFactor) -> Option<String> {
    match factor {
        TableFactor::Table { name, .. } => Some(name.to_string()),
        TableFactor::Derived { subquery, .. } => {
            let mut tables = Vec::new();
            extract_tables_from_setexpr(subquery.body.as_ref(), &mut tables);
            None
        }
        _ => None,
    }
}

fn extract_columns(stmt: &Statement) -> Vec<String> {
    let mut columns = Vec::new();
    if let Statement::Query(query) = stmt {
        if let SetExpr::Select(select) = query.body.as_ref() {
            for item in &select.projection {
                match item {
                    SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                        columns.push(ident.value.clone());
                    }
                    SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                        if let Some(last) = parts.last() {
                            columns.push(last.value.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    columns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DataAccessPolicy, PiiPolicy};

    fn test_policy() -> DataAccessPolicy {
        DataAccessPolicy {
            pii: Some(PiiPolicy::Deny),
            allowed_tables: vec!["orders".into(), "products".into(), "faq".into()],
            denied_tables: vec!["users_private".into(), "payments_raw".into()],
            allowed_fields: vec![],
            denied_fields: vec!["ssn".into(), "credit_card".into()],
        }
    }

    #[test]
    fn test_allowed_select() {
        let policy = test_policy();
        let violations = check_sql("SELECT id, name FROM orders WHERE id = 1", &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_denied_table() {
        let policy = test_policy();
        let violations = check_sql("SELECT * FROM users_private", &policy);
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.table == "users_private"));
    }

    #[test]
    fn test_not_in_allowed() {
        let policy = test_policy();
        let violations = check_sql("SELECT * FROM secret_stuff", &policy);
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.table == "secret_stuff"));
    }

    #[test]
    fn test_denied_field() {
        let policy = test_policy();
        let violations = check_sql("SELECT ssn, name FROM orders", &policy);
        assert!(violations.iter().any(|v| v.reason.contains("ssn")));
    }

    #[test]
    fn test_join_denied() {
        let policy = test_policy();
        let violations = check_sql(
            "SELECT o.id FROM orders o JOIN payments_raw p ON o.id = p.order_id",
            &policy,
        );
        assert!(violations.iter().any(|v| v.table == "payments_raw"));
    }

    #[test]
    fn test_pii_table_name() {
        let policy = test_policy();
        let violations = check_sql("SELECT * FROM customer_private_data", &policy);
        assert!(violations.iter().any(|v| v.reason.contains("PII")));
    }

    #[test]
    fn test_insert_denied() {
        let policy = test_policy();
        let violations = check_sql(
            "INSERT INTO users_private (name) VALUES ('test')",
            &policy,
        );
        assert!(violations.iter().any(|v| v.table == "users_private"));
    }

    #[test]
    fn test_non_sql_ignored() {
        assert!(!looks_like_sql("hello world"));
        assert!(!looks_like_sql("read_file /tmp/data.json"));
        assert!(looks_like_sql("SELECT 1"));
    }
}
