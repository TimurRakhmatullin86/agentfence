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
        if policy.metadata.name.is_empty() {
            return Err(EngineError::Validation(
                "policy metadata.name is required".into(),
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
        Ok(())
    }

    pub fn evaluate(&self, request: &ActionRequest) -> Decision {
        let matching = self.matching_policies(request);

        if matching.is_empty() {
            return Decision {
                effect: Effect::Allow,
                policy: "<default>".into(),
                rule_index: None,
                reason: "no matching policy found, default allow".into(),
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
        Condition::FieldMatch {
            field,
            equals,
            contains,
            regex: _,
        } => {
            if let Some(val) = request.parameters.get(field) {
                if let Some(s) = val.as_str() {
                    if let Some(eq) = equals {
                        return s == eq;
                    }
                    if let Some(cont) = contains {
                        return s.contains(cont.as_str());
                    }
                }
            }
            true
        }
        _ => true,
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
    fn test_no_matching_policy() {
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
        assert!(matches!(decision.effect, Effect::Allow));
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
        // amount > 500 fails the AmountMax condition on rule 0,
        // so it falls through to rule 1 which is deny
        assert!(matches!(decision.effect, Effect::Deny));
    }
}
