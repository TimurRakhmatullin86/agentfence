use crate::sql_checker;
use crate::types::*;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse policy YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid policy: {0}")]
    Validation(String),
}

pub struct PolicyEngine {
    policies: Vec<Policy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn load_file(&mut self, path: &Path) -> Result<(), EngineError> {
        let content = std::fs::read_to_string(path)?;
        let policy: Policy = serde_yaml::from_str(&content)?;
        self.validate_policy(&policy)?;
        self.policies.push(policy);
        Ok(())
    }

    pub fn load_dir(&mut self, dir: &Path) -> Result<usize, EngineError> {
        let mut count = 0;
        let pattern = dir.join("**/*.yaml");
        let pattern_str = pattern.to_string_lossy();
        for entry in glob::glob(&pattern_str).unwrap() {
            if let Ok(path) = entry {
                self.load_file(&path)?;
                count += 1;
            }
        }
        let pattern_yml = dir.join("**/*.yml");
        let pattern_yml_str = pattern_yml.to_string_lossy();
        for entry in glob::glob(&pattern_yml_str).unwrap() {
            if let Ok(path) = entry {
                self.load_file(&path)?;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn load_string(&mut self, yaml: &str) -> Result<(), EngineError> {
        let policy: Policy = serde_yaml::from_str(yaml)?;
        self.validate_policy(&policy)?;
        self.policies.push(policy);
        Ok(())
    }

    fn validate_policy(&self, policy: &Policy) -> Result<(), EngineError> {
        if policy.api_version != "agentfence/v1" {
            return Err(EngineError::Validation(format!(
                "unsupported apiVersion '{}', expected 'agentfence/v1'",
                policy.api_version
            )));
        }
        if policy.kind != "Policy" {
            return Err(EngineError::Validation(format!(
                "unsupported kind '{}', expected 'Policy'",
                policy.kind
            )));
        }
        if policy.metadata.name.is_empty() {
            return Err(EngineError::Validation(
                "policy metadata.name is required".into(),
            ));
        }
        if policy.metadata.name.contains(' ') {
            return Err(EngineError::Validation(
                "policy metadata.name must not contain spaces".into(),
            ));
        }
        if policy.spec.rules.is_empty()
            && policy.spec.budget.is_none()
            && policy.spec.data_access.is_none()
        {
            return Err(EngineError::Validation(
                "policy must have at least one rule, budget, or data_access section".into(),
            ));
        }
        for (i, rule) in policy.spec.rules.iter().enumerate() {
            if rule.action.is_empty() {
                return Err(EngineError::Validation(format!(
                    "rule #{} has empty action",
                    i
                )));
            }
            if rule.action.starts_with("regex:") {
                let pattern = &rule.action["regex:".len()..];
                if regex::Regex::new(pattern).is_err() {
                    return Err(EngineError::Validation(format!(
                        "rule #{} has invalid regex pattern: {}",
                        i, pattern
                    )));
                }
            }
            if matches!(rule.effect, Effect::RequireApproval) && rule.approval.is_none() {
                return Err(EngineError::Validation(format!(
                    "rule #{} has effect require_approval but no approval section",
                    i
                )));
            }
        }
        if let Some(budget) = &policy.spec.budget {
            if let (Some(session), Some(day)) = (budget.max_per_session, budget.max_per_day) {
                if session > day {
                    return Err(EngineError::Validation(
                        "budget: max_per_session cannot exceed max_per_day".into(),
                    ));
                }
            }
            if let (Some(day), Some(month)) = (budget.max_per_day, budget.max_per_month) {
                if day > month {
                    return Err(EngineError::Validation(
                        "budget: max_per_day cannot exceed max_per_month".into(),
                    ));
                }
            }
            if let Some(pct) = budget.alert_at_percent {
                if pct > 100 {
                    return Err(EngineError::Validation(
                        "budget: alert_at_percent must be 0-100".into(),
                    ));
                }
            }
        }
        if let Some(data) = &policy.spec.data_access {
            for table in &data.denied_tables {
                if data.allowed_tables.contains(table) {
                    return Err(EngineError::Validation(format!(
                        "table '{}' is in both allowed_tables and denied_tables",
                        table
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn evaluate(&self, request: &ActionRequest) -> Decision {
        let matching = self.matching_policies(request);

        if matching.is_empty() {
            return Decision {
                effect: Effect::Deny,
                policy: "<default>".into(),
                rule_index: None,
                reason: "no matching policy — default deny".into(),
                timestamp: Utc::now(),
                request_hash: hash_request(request),
            };
        }

        for (policy, rule_idx, rule) in &matching {
            match rule.effect {
                Effect::Deny => {
                    return Decision {
                        effect: Effect::Deny,
                        policy: policy.metadata.name.clone(),
                        rule_index: Some(*rule_idx),
                        reason: rule
                            .reason
                            .clone()
                            .unwrap_or_else(|| format!("denied by rule #{}", rule_idx)),
                        timestamp: Utc::now(),
                        request_hash: hash_request(request),
                    };
                }
                Effect::RequireApproval => {
                    let approver = rule
                        .approval
                        .as_ref()
                        .map(|a| a.approver.clone())
                        .unwrap_or_else(|| "admin".into());
                    return Decision {
                        effect: Effect::RequireApproval,
                        policy: policy.metadata.name.clone(),
                        rule_index: Some(*rule_idx),
                        reason: rule.reason.clone().unwrap_or_else(|| {
                            format!("requires approval from {}", approver)
                        }),
                        timestamp: Utc::now(),
                        request_hash: hash_request(request),
                    };
                }
                Effect::Allow => {}
            }
        }

        // Check SQL content in parameters against data_access policies
        for (policy, _, _) in &matching {
            if let Some(data_access) = &policy.spec.data_access {
                let violations =
                    sql_checker::check_sql_in_params(&request.parameters, data_access);
                if !violations.is_empty() {
                    let reasons: Vec<String> =
                        violations.iter().map(|v| v.reason.clone()).collect();
                    return Decision {
                        effect: Effect::Deny,
                        policy: policy.metadata.name.clone(),
                        rule_index: None,
                        reason: format!("SQL policy violation: {}", reasons.join("; ")),
                        timestamp: Utc::now(),
                        request_hash: hash_request(request),
                    };
                }
            }
        }

        // Check budget constraints
        for (policy, _, _) in &matching {
            if let Some(budget) = &policy.spec.budget {
                if let Some(cost) = request.cost {
                    if let Some(max_session) = budget.max_per_session {
                        if cost > max_session {
                            return Decision {
                                effect: Effect::Deny,
                                policy: policy.metadata.name.clone(),
                                rule_index: None,
                                reason: format!(
                                    "session cost ${:.2} exceeds budget ${:.2}",
                                    cost, max_session
                                ),
                                timestamp: Utc::now(),
                                request_hash: hash_request(request),
                            };
                        }
                    }
                    if let Some(alert_pct) = budget.alert_at_percent {
                        if let Some(max_session) = budget.max_per_session {
                            let threshold = max_session * (alert_pct as f64 / 100.0);
                            if cost > threshold {
                                return Decision {
                                    effect: Effect::RequireApproval,
                                    policy: policy.metadata.name.clone(),
                                    rule_index: None,
                                    reason: format!(
                                        "session cost ${:.2} exceeds {}% alert threshold (${:.2})",
                                        cost, alert_pct, threshold
                                    ),
                                    timestamp: Utc::now(),
                                    request_hash: hash_request(request),
                                };
                            }
                        }
                    }
                }
            }
        }

        let first = &matching[0];
        Decision {
            effect: Effect::Allow,
            policy: first.0.metadata.name.clone(),
            rule_index: matching.first().map(|(_, idx, _)| *idx),
            reason: "allowed by policy".into(),
            timestamp: Utc::now(),
            request_hash: hash_request(request),
        }
    }

    fn matching_policies<'a>(
        &'a self,
        request: &ActionRequest,
    ) -> Vec<(&'a Policy, usize, &'a Rule)> {
        let mut result = Vec::new();

        for policy in &self.policies {
            if let Some(agent_sel) = &policy.spec.agent {
                if let Some(name) = &agent_sel.name {
                    if name != &request.agent {
                        continue;
                    }
                }
            }

            for (idx, rule) in policy.spec.rules.iter().enumerate() {
                if rule_matches(rule, request) {
                    result.push((policy, idx, rule));
                }
            }
        }

        result
    }

    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }
}

fn rule_matches(rule: &Rule, request: &ActionRequest) -> bool {
    if rule.action == "*" || rule.action == request.action {
        return conditions_met(&rule.conditions, request);
    }

    if rule.action.ends_with(".*") {
        let prefix = &rule.action[..rule.action.len() - 2];
        if request.action.starts_with(prefix) {
            return conditions_met(&rule.conditions, request);
        }
    }

    if rule.action.starts_with("regex:") {
        let pattern = &rule.action["regex:".len()..];
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(&request.action) {
                return conditions_met(&rule.conditions, request);
            }
        }
    }

    false
}

fn conditions_met(conditions: &[Condition], request: &ActionRequest) -> bool {
    conditions.iter().all(|c| condition_met(c, request))
}

fn condition_met(condition: &Condition, request: &ActionRequest) -> bool {
    match condition {
        Condition::AmountMax { field, max } => {
            if let Some(val) = request.parameters.get(field) {
                if let Some(n) = val.as_f64() {
                    return n <= *max;
                }
            }
            true
        }
        Condition::AmountMin { field, min } => {
            if let Some(val) = request.parameters.get(field) {
                if let Some(n) = val.as_f64() {
                    return n >= *min;
                }
            }
            true
        }
        Condition::RecipientDomain { allow, deny } => {
            let domain = request
                .parameters
                .get("recipient")
                .or_else(|| request.parameters.get("email"))
                .or_else(|| request.parameters.get("to"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.rsplit('@').next());
            match domain {
                Some(d) => {
                    if !deny.is_empty() && deny.iter().any(|blocked| d == blocked) {
                        return false;
                    }
                    if !allow.is_empty() {
                        return allow.iter().any(|allowed| d == allowed);
                    }
                    true
                }
                None => allow.is_empty(),
            }
        }
        Condition::TimeWindow {
            allow_hours,
            deny_hours,
        } => {
            let hour = Utc::now().format("%H").to_string().parse::<u8>().unwrap_or(0);
            if let Some((start, end)) = deny_hours {
                if *start <= *end {
                    if hour >= *start && hour < *end {
                        return false;
                    }
                } else if hour >= *start || hour < *end {
                    return false;
                }
            }
            if let Some((start, end)) = allow_hours {
                if *start <= *end {
                    return hour >= *start && hour < *end;
                }
                return hour >= *start || hour < *end;
            }
            true
        }
        Condition::RateLimit { .. } => {
            // Rate limiting requires persistent state tracking (not yet implemented).
            // Fail-closed: deny when rate limit is configured but cannot be enforced.
            false
        }
        Condition::FieldMatch {
            field,
            equals,
            contains,
            regex: regex_pat,
        } => {
            if let Some(val) = request.parameters.get(field) {
                if let Some(s) = val.as_str() {
                    if let Some(eq) = equals {
                        return s == eq;
                    }
                    if let Some(cont) = contains {
                        return s.contains(cont.as_str());
                    }
                    if let Some(pat) = regex_pat {
                        if let Ok(re) = regex::Regex::new(pat) {
                            return re.is_match(s);
                        }
                        return false;
                    }
                }
            }
            true
        }
        Condition::Custom { .. } => {
            // Custom expressions cannot be safely evaluated.
            // Fail-closed: deny when custom condition is present.
            false
        }
    }
}

fn hash_request(request: &ActionRequest) -> String {
    let json = serde_json::to_string(request).unwrap_or_default();
    let hash = Sha256::digest(json.as_bytes());
    format!("{:x}", hash)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_policy_yaml() -> &'static str {
        r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: support-bot-policy
  description: Policy for customer support agent
spec:
  agent:
    name: support-bot
  rules:
    - action: refund
      effect: require_approval
      conditions:
        - type: amount_max
          field: amount
          max: 500
      approval:
        approver: manager
        timeout_secs: 300
      reason: "Refunds up to $500 require manager approval"
    - action: refund
      effect: deny
      reason: "Refunds over $500 are not allowed"
    - action: database_write
      effect: deny
      reason: "Support bot cannot write to database"
    - action: "search.*"
      effect: allow
  budget:
    max_per_session: 5.0
    alert_at_percent: 80
  "#
    }

    #[test]
    fn test_parse_policy() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();
        assert_eq!(engine.policies().len(), 1);
        assert_eq!(engine.policies()[0].metadata.name, "support-bot-policy");
    }

    #[test]
    fn test_deny_rule() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();

        let request = ActionRequest {
            agent: "support-bot".into(),
            action: "database_write".into(),
            parameters: HashMap::new(),
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Deny));
        assert_eq!(decision.reason, "Support bot cannot write to database");
    }

    #[test]
    fn test_allow_wildcard() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();

        let request = ActionRequest {
            agent: "support-bot".into(),
            action: "search.orders".into(),
            parameters: HashMap::new(),
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Allow));
    }

    #[test]
    fn test_approval_with_condition() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();

        let mut params = HashMap::new();
        params.insert("amount".into(), serde_json::json!(200));

        let request = ActionRequest {
            agent: "support-bot".into(),
            action: "refund".into(),
            parameters: params,
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::RequireApproval));
    }

    #[test]
    fn test_budget_deny() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();

        let request = ActionRequest {
            agent: "support-bot".into(),
            action: "search.orders".into(),
            parameters: HashMap::new(),
            session_id: None,
            cost: Some(6.0),
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Deny));
        assert!(decision.reason.contains("exceeds budget"));
    }

    #[test]
    fn test_budget_alert() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();

        let request = ActionRequest {
            agent: "support-bot".into(),
            action: "search.orders".into(),
            parameters: HashMap::new(),
            session_id: None,
            cost: Some(4.5),
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::RequireApproval));
        assert!(decision.reason.contains("alert threshold"));
    }

    #[test]
    fn test_no_matching_policy_denies() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();

        let request = ActionRequest {
            agent: "other-agent".into(),
            action: "anything".into(),
            parameters: HashMap::new(),
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Deny));
        assert_eq!(decision.policy, "<default>");
    }

    #[test]
    fn test_refund_over_limit_denied() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sample_policy_yaml()).unwrap();

        let mut params = HashMap::new();
        params.insert("amount".into(), serde_json::json!(600));

        let request = ActionRequest {
            agent: "support-bot".into(),
            action: "refund".into(),
            parameters: params,
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Deny));
    }

    fn sql_policy_yaml() -> &'static str {
        r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: sql-aware-policy
spec:
  agent:
    name: data-agent
  rules:
    - action: "query.*"
      effect: allow
    - action: "sql.*"
      effect: allow
  data_access:
    pii: deny
    allowed_tables: [orders, products, faq]
    denied_tables: [users_private, payments_raw]
    denied_fields: [ssn, credit_card]
  "#
    }

    #[test]
    fn test_sql_denied_table_in_param() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sql_policy_yaml()).unwrap();

        let mut params = HashMap::new();
        params.insert(
            "query".into(),
            serde_json::json!("SELECT * FROM users_private"),
        );

        let request = ActionRequest {
            agent: "data-agent".into(),
            action: "query.execute".into(),
            parameters: params,
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Deny));
        assert!(decision.reason.contains("SQL policy violation"));
    }

    #[test]
    fn test_sql_allowed_table_passes() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sql_policy_yaml()).unwrap();

        let mut params = HashMap::new();
        params.insert(
            "query".into(),
            serde_json::json!("SELECT id, name FROM orders WHERE id = 1"),
        );

        let request = ActionRequest {
            agent: "data-agent".into(),
            action: "query.execute".into(),
            parameters: params,
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Allow));
    }

    #[test]
    fn test_sql_join_with_denied_table() {
        let mut engine = PolicyEngine::new();
        engine.load_string(sql_policy_yaml()).unwrap();

        let mut params = HashMap::new();
        params.insert(
            "sql".into(),
            serde_json::json!("SELECT o.id FROM orders o JOIN payments_raw p ON o.id = p.order_id"),
        );

        let request = ActionRequest {
            agent: "data-agent".into(),
            action: "sql.execute".into(),
            parameters: params,
            session_id: None,
            cost: None,
        };
        let decision = engine.evaluate(&request);
        assert!(matches!(decision.effect, Effect::Deny));
        assert!(decision.reason.contains("payments_raw"));
    }

    #[test]
    fn test_regex_action_matching() {
        let mut engine = PolicyEngine::new();
        engine
            .load_string(
                r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: regex-test
spec:
  agent:
    name: my-agent
  rules:
    - action: "regex:^(read|get|list)_.*"
      effect: allow
    - action: "regex:^(delete|drop|truncate)_.*"
      effect: deny
      reason: "Destructive operations blocked"
"#,
            )
            .unwrap();

        let req_read = ActionRequest {
            agent: "my-agent".into(),
            action: "read_orders".into(),
            parameters: HashMap::new(),
            session_id: None,
            cost: None,
        };
        assert!(matches!(engine.evaluate(&req_read).effect, Effect::Allow));

        let req_delete = ActionRequest {
            agent: "my-agent".into(),
            action: "delete_users".into(),
            parameters: HashMap::new(),
            session_id: None,
            cost: None,
        };
        assert!(matches!(
            engine.evaluate(&req_delete).effect,
            Effect::Deny
        ));
    }

    #[test]
    fn test_validation_bad_api_version() {
        let mut engine = PolicyEngine::new();
        let result = engine.load_string(
            r#"
apiVersion: agentfence/v99
kind: Policy
metadata:
  name: bad
spec:
  rules:
    - action: test
      effect: allow
"#,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("apiVersion"));
    }

    #[test]
    fn test_validation_budget_session_exceeds_day() {
        let mut engine = PolicyEngine::new();
        let result = engine.load_string(
            r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: bad-budget
spec:
  rules:
    - action: test
      effect: allow
  budget:
    max_per_session: 100.0
    max_per_day: 50.0
"#,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("max_per_session cannot exceed"));
    }

    #[test]
    fn test_validation_table_in_both_lists() {
        let mut engine = PolicyEngine::new();
        let result = engine.load_string(
            r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: conflict-tables
spec:
  rules:
    - action: test
      effect: allow
  data_access:
    allowed_tables: [orders, secrets]
    denied_tables: [secrets]
"#,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("both allowed_tables and denied_tables"));
    }

    #[test]
    fn test_validation_approval_missing() {
        let mut engine = PolicyEngine::new();
        let result = engine.load_string(
            r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: missing-approval
spec:
  rules:
    - action: send_email
      effect: require_approval
"#,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no approval section"));
    }
}
