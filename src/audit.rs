use crate::types::*;
use rusqlite::{params, Connection};
use std::path::Path;

pub struct AuditLog {
    conn: Connection,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                effect TEXT NOT NULL,
                policy TEXT NOT NULL,
                rule_index INTEGER,
                reason TEXT NOT NULL,
                parameters TEXT,
                cost REAL,
                session_id TEXT,
                request_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_decisions_agent ON decisions(agent);
            CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_decisions_effect ON decisions(effect);

            CREATE TABLE IF NOT EXISTS budget_usage (
                agent TEXT NOT NULL,
                session_id TEXT NOT NULL,
                date TEXT NOT NULL,
                total_cost REAL NOT NULL DEFAULT 0.0,
                action_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (agent, session_id, date)
            );",
        )?;
        Ok(Self { conn })
    }

    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let log = Self { conn };
        log.conn.execute_batch(
            "CREATE TABLE decisions (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                effect TEXT NOT NULL,
                policy TEXT NOT NULL,
                rule_index INTEGER,
                reason TEXT NOT NULL,
                parameters TEXT,
                cost REAL,
                session_id TEXT,
                request_hash TEXT NOT NULL
            );
            CREATE TABLE budget_usage (
                agent TEXT NOT NULL,
                session_id TEXT NOT NULL,
                date TEXT NOT NULL,
                total_cost REAL NOT NULL DEFAULT 0.0,
                action_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (agent, session_id, date)
            );",
        )?;
        Ok(log)
    }

    #[allow(dead_code)]
    pub fn record(
        &self,
        request: &ActionRequest,
        decision: &Decision,
    ) -> Result<(), rusqlite::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let effect_str = match decision.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::RequireApproval => "require_approval",
        };
        let params_json = serde_json::to_string(&request.parameters).unwrap_or_default();
        let timestamp = decision.timestamp.to_rfc3339();

        self.conn.execute(
            "INSERT INTO decisions (id, timestamp, agent, action, effect, policy, rule_index, reason, parameters, cost, session_id, request_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                id,
                timestamp,
                request.agent,
                request.action,
                effect_str,
                decision.policy,
                decision.rule_index.map(|i| i as i64),
                decision.reason,
                params_json,
                request.cost,
                request.session_id,
                decision.request_hash,
            ],
        )?;

        if let (Some(cost), Some(session_id)) = (request.cost, &request.session_id) {
            let date = decision.timestamp.format("%Y-%m-%d").to_string();
            self.conn.execute(
                "INSERT INTO budget_usage (agent, session_id, date, total_cost, action_count)
                 VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT(agent, session_id, date) DO UPDATE SET
                     total_cost = total_cost + ?4,
                     action_count = action_count + 1",
                params![request.agent, session_id, date, cost],
            )?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn session_cost(&self, agent: &str, session_id: &str) -> f64 {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(total_cost), 0.0) FROM budget_usage WHERE agent = ?1 AND session_id = ?2",
                params![agent, session_id],
                |row| row.get(0),
            )
            .unwrap_or(0.0)
    }

    #[allow(dead_code)]
    pub fn day_cost(&self, agent: &str, date: &str) -> f64 {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(total_cost), 0.0) FROM budget_usage WHERE agent = ?1 AND date = ?2",
                params![agent, date],
                |row| row.get(0),
            )
            .unwrap_or(0.0)
    }

    #[allow(dead_code)]
    pub fn month_cost(&self, agent: &str, year_month: &str) -> f64 {
        let pattern = format!("{}%", year_month);
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(total_cost), 0.0) FROM budget_usage WHERE agent = ?1 AND date LIKE ?2",
                params![agent, pattern],
                |row| row.get(0),
            )
            .unwrap_or(0.0)
    }

    pub fn recent_decisions(&self, limit: usize) -> Vec<AuditRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, agent, action, effect, policy, reason, cost
                 FROM decisions ORDER BY timestamp DESC LIMIT ?1",
            )
            .unwrap();
        stmt.query_map(params![limit as i64], |row| {
            Ok(AuditRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                agent: row.get(2)?,
                action: row.get(3)?,
                effect: row.get(4)?,
                policy: row.get(5)?,
                reason: row.get(6)?,
                cost: row.get(7)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn agent_stats(&self, agent: &str) -> AgentStats {
        let total: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM decisions WHERE agent = ?1",
                params![agent],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let denied: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM decisions WHERE agent = ?1 AND effect = 'deny'",
                params![agent],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let allowed: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM decisions WHERE agent = ?1 AND effect = 'allow'",
                params![agent],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let total_cost: f64 = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(cost), 0.0) FROM decisions WHERE agent = ?1",
                params![agent],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        AgentStats {
            total_actions: total as u64,
            allowed: allowed as u64,
            denied: denied as u64,
            total_cost,
        }
    }
}

pub struct AuditRow {
    #[allow(dead_code)]
    pub id: String,
    pub timestamp: String,
    pub agent: String,
    pub action: String,
    pub effect: String,
    #[allow(dead_code)]
    pub policy: String,
    pub reason: String,
    pub cost: Option<f64>,
}

pub struct AgentStats {
    pub total_actions: u64,
    pub allowed: u64,
    pub denied: u64,
    pub total_cost: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_request(agent: &str, action: &str, cost: Option<f64>) -> ActionRequest {
        ActionRequest {
            agent: agent.into(),
            action: action.into(),
            parameters: HashMap::new(),
            session_id: Some("sess-001".into()),
            cost,
        }
    }

    fn make_decision(effect: Effect, policy: &str, reason: &str) -> Decision {
        Decision {
            effect,
            policy: policy.into(),
            rule_index: Some(0),
            reason: reason.into(),
            timestamp: Utc::now(),
            request_hash: "abc123".into(),
        }
    }

    #[test]
    fn test_record_and_query() {
        let log = AuditLog::in_memory().unwrap();
        let req = make_request("bot-1", "send_email", Some(1.50));
        let dec = make_decision(Effect::Allow, "email-policy", "allowed");
        log.record(&req, &dec).unwrap();

        let rows = log.recent_decisions(10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent, "bot-1");
        assert_eq!(rows[0].effect, "allow");
    }

    #[test]
    fn test_budget_tracking() {
        let log = AuditLog::in_memory().unwrap();

        let req1 = make_request("bot-1", "search", Some(2.0));
        let dec1 = make_decision(Effect::Allow, "p1", "ok");
        log.record(&req1, &dec1).unwrap();

        let req2 = make_request("bot-1", "query", Some(3.0));
        let dec2 = make_decision(Effect::Allow, "p1", "ok");
        log.record(&req2, &dec2).unwrap();

        let cost = log.session_cost("bot-1", "sess-001");
        assert!((cost - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_agent_stats() {
        let log = AuditLog::in_memory().unwrap();

        let req1 = make_request("bot-1", "read", Some(1.0));
        log.record(&req1, &make_decision(Effect::Allow, "p", "ok"))
            .unwrap();
        log.record(&req1, &make_decision(Effect::Allow, "p", "ok"))
            .unwrap();

        let req2 = make_request("bot-1", "write", None);
        log.record(&req2, &make_decision(Effect::Deny, "p", "nope"))
            .unwrap();

        let stats = log.agent_stats("bot-1");
        assert_eq!(stats.total_actions, 3);
        assert_eq!(stats.allowed, 2);
        assert_eq!(stats.denied, 1);
        assert!((stats.total_cost - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_day_cost() {
        let log = AuditLog::in_memory().unwrap();
        let req = make_request("bot-1", "search", Some(4.0));
        let dec = make_decision(Effect::Allow, "p", "ok");
        log.record(&req, &dec).unwrap();

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let cost = log.day_cost("bot-1", &today);
        assert!((cost - 4.0).abs() < 0.01);
    }
}
