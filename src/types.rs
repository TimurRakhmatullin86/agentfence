use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyMetadata,
    pub spec: PolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySpec {
    #[serde(default)]
    pub agent: Option<AgentSelector>,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub budget: Option<BudgetPolicy>,
    #[serde(default)]
    pub data_access: Option<DataAccessPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSelector {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    pub effect: Effect,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub approval: Option<ApprovalRequirement>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    AmountMax {
        field: String,
        max: f64,
    },
    AmountMin {
        field: String,
        min: f64,
    },
    RecipientDomain {
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        deny: Vec<String>,
    },
    TimeWindow {
        #[serde(default)]
        allow_hours: Option<(u8, u8)>,
        #[serde(default)]
        deny_hours: Option<(u8, u8)>,
    },
    RateLimit {
        max_per_minute: Option<u32>,
        max_per_hour: Option<u32>,
        max_per_day: Option<u32>,
    },
    FieldMatch {
        field: String,
        #[serde(default)]
        equals: Option<String>,
        #[serde(default)]
        contains: Option<String>,
        #[serde(default)]
        regex: Option<String>,
    },
    Custom {
        expression: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    pub approver: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub on_timeout: Option<Effect>,
}

fn default_timeout_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPolicy {
    #[serde(default)]
    pub max_per_session: Option<f64>,
    #[serde(default)]
    pub max_per_day: Option<f64>,
    #[serde(default)]
    pub max_per_month: Option<f64>,
    #[serde(default)]
    pub alert_at_percent: Option<u8>,
    #[serde(default)]
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAccessPolicy {
    #[serde(default)]
    pub pii: Option<PiiPolicy>,
    #[serde(default)]
    pub allowed_tables: Vec<String>,
    #[serde(default)]
    pub denied_tables: Vec<String>,
    #[serde(default)]
    pub allowed_fields: Vec<String>,
    #[serde(default)]
    pub denied_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiPolicy {
    Allow,
    Mask,
    Deny,
}

// --- Evaluation types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub agent: String,
    pub action: String,
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub cost: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub policy: String,
    pub rule_index: Option<usize>,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub request_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub request: ActionRequest,
    pub decision: Decision,
    pub session_cost_total: Option<f64>,
    pub day_cost_total: Option<f64>,
}
