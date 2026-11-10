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
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub budget: Option<BudgetPolicy>,
    #[serde(default)]
    pub data_access: Option<DataAccessPolicy>,
    #[serde(default)]
    pub context: Option<BusinessContext>,
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

// --- Business Context types (4 kinds: Policy, Term, AgentRole, Schema) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessContext {
    #[serde(default)]
    pub terms: Vec<Term>,
    #[serde(default)]
    pub agent_roles: Vec<AgentRole>,
    #[serde(default)]
    pub schemas: Vec<SchemaDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Term {
    pub name: String,
    pub definition: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRole {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub denied_actions: Vec<String>,
    #[serde(default)]
    pub max_budget: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDefinition {
    pub table: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub columns: Vec<ColumnDef>,
    #[serde(default)]
    pub pii_columns: Vec<String>,
    #[serde(default)]
    pub classification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
    #[serde(default)]
    pub pii: bool,
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
