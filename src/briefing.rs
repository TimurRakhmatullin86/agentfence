use crate::engine::PolicyEngine;
use crate::types::*;

pub fn generate_briefing(engine: &PolicyEngine, agent_name: &str) -> String {
    let mut lines = Vec::new();
    lines.push(format!("# Agent Briefing: {}", agent_name));
    lines.push(String::new());

    let matching: Vec<&Policy> = engine
        .policies()
        .iter()
        .filter(|p| {
            p.spec
                .agent
                .as_ref()
                .map(|a| a.name.as_deref() == Some(agent_name) || a.name.is_none())
                .unwrap_or(true)
        })
        .collect();

    if matching.is_empty() {
        lines.push("**WARNING**: No policies match this agent. All actions will be DENIED (default-deny).".into());
        return lines.join("\n");
    }

    for policy in &matching {
        lines.push(format!("## Policy: {}", policy.metadata.name));
        if let Some(desc) = &policy.metadata.description {
            lines.push(format!("_{}_", desc));
        }
        lines.push(String::new());

        if !policy.spec.rules.is_empty() {
            lines.push("### Rules".into());
            let mut allowed = Vec::new();
            let mut denied = Vec::new();
            let mut needs_approval = Vec::new();

            for rule in &policy.spec.rules {
                let action = &rule.action;
                let reason = rule.reason.as_deref().unwrap_or("");
                match rule.effect {
                    Effect::Allow => allowed.push(format!("- `{}` {}", action, reason)),
                    Effect::Deny => denied.push(format!("- `{}` {}", action, reason)),
                    Effect::RequireApproval => {
                        let approver = rule
                            .approval
                            .as_ref()
                            .map(|a| a.approver.as_str())
                            .unwrap_or("admin");
                        needs_approval.push(format!(
                            "- `{}` → needs approval from **{}** {}",
                            action, approver, reason
                        ));
                    }
                }
            }

            if !allowed.is_empty() {
                lines.push("**Allowed:**".into());
                lines.extend(allowed);
            }
            if !needs_approval.is_empty() {
                lines.push("**Needs approval:**".into());
                lines.extend(needs_approval);
            }
            if !denied.is_empty() {
                lines.push("**Denied:**".into());
                lines.extend(denied);
            }
            lines.push(String::new());
        }

        if let Some(budget) = &policy.spec.budget {
            lines.push("### Budget".into());
            if let Some(s) = budget.max_per_session {
                lines.push(format!("- Session limit: **${:.2}**", s));
            }
            if let Some(d) = budget.max_per_day {
                lines.push(format!("- Daily limit: **${:.2}**", d));
            }
            if let Some(m) = budget.max_per_month {
                lines.push(format!("- Monthly limit: **${:.2}**", m));
            }
            if let Some(pct) = budget.alert_at_percent {
                lines.push(format!("- Alert at: **{}%** usage", pct));
            }
            lines.push(String::new());
        }

        if let Some(data) = &policy.spec.data_access {
            lines.push("### Data Access".into());
            if let Some(pii) = &data.pii {
                let pii_str = match pii {
                    PiiPolicy::Allow => "allowed",
                    PiiPolicy::Mask => "masked",
                    PiiPolicy::Deny => "**DENIED**",
                };
                lines.push(format!("- PII: {}", pii_str));
            }
            if !data.allowed_tables.is_empty() {
                lines.push(format!(
                    "- Allowed tables: `{}`",
                    data.allowed_tables.join("`, `")
                ));
            }
            if !data.denied_tables.is_empty() {
                lines.push(format!(
                    "- Denied tables: `{}`",
                    data.denied_tables.join("`, `")
                ));
            }
            if !data.denied_fields.is_empty() {
                lines.push(format!(
                    "- Denied fields: `{}`",
                    data.denied_fields.join("`, `")
                ));
            }
            lines.push(String::new());
        }

        if let Some(ctx) = &policy.spec.context {
            if !ctx.terms.is_empty() {
                lines.push("### Business Terms".into());
                for term in &ctx.terms {
                    lines.push(format!("- **{}**: {}", term.name, term.definition));
                    if !term.aliases.is_empty() {
                        lines.push(format!("  aliases: {}", term.aliases.join(", ")));
                    }
                    if !term.constraints.is_empty() {
                        for c in &term.constraints {
                            lines.push(format!("  - constraint: {}", c));
                        }
                    }
                }
                lines.push(String::new());
            }

            if !ctx.schemas.is_empty() {
                lines.push("### Schema Metadata".into());
                for schema in &ctx.schemas {
                    let mut desc = format!("- **{}**", schema.table);
                    if let Some(d) = &schema.description {
                        desc.push_str(&format!(": {}", d));
                    }
                    if let Some(c) = &schema.classification {
                        desc.push_str(&format!(" [{}]", c));
                    }
                    lines.push(desc);
                    if !schema.pii_columns.is_empty() {
                        lines.push(format!(
                            "  PII columns: `{}`",
                            schema.pii_columns.join("`, `")
                        ));
                    }
                }
                lines.push(String::new());
            }
        }
    }

    lines.push("---".into());
    lines.push("*Any action not listed above will be DENIED (default-deny policy).*".into());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::PolicyEngine;

    #[test]
    fn test_briefing_no_matching_policy() {
        let engine = PolicyEngine::new();
        let brief = generate_briefing(&engine, "ghost-agent");
        assert!(brief.contains("No policies match"));
        assert!(brief.contains("DENIED"));
    }

    #[test]
    fn test_briefing_with_policy() {
        let mut engine = PolicyEngine::new();
        engine
            .load_string(
                r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: test-policy
  description: Test
spec:
  agent:
    name: my-bot
  rules:
    - action: "read.*"
      effect: allow
    - action: delete
      effect: deny
      reason: "No deletions"
    - action: refund
      effect: require_approval
      approval:
        approver: manager
  budget:
    max_per_session: 10.0
    alert_at_percent: 80
  data_access:
    pii: deny
    allowed_tables: [orders]
    denied_tables: [secrets]
    denied_fields: [ssn]
"#,
            )
            .unwrap();

        let brief = generate_briefing(&engine, "my-bot");
        assert!(brief.contains("read.*"));
        assert!(brief.contains("Denied"));
        assert!(brief.contains("delete"));
        assert!(brief.contains("manager"));
        assert!(brief.contains("$10.00"));
        assert!(brief.contains("orders"));
        assert!(brief.contains("secrets"));
        assert!(brief.contains("ssn"));
    }

    #[test]
    fn test_briefing_with_context() {
        let mut engine = PolicyEngine::new();
        engine
            .load_string(
                r#"
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: ctx-policy
spec:
  agent:
    name: data-bot
  rules:
    - action: "query.*"
      effect: allow
  context:
    terms:
      - name: churn
        definition: "Customer who cancelled in last 30 days"
        aliases: [churned, attrition]
        constraints: ["Only confirmed cancellations"]
    schemas:
      - table: orders
        description: "Customer orders"
        pii_columns: [email, phone]
        classification: internal
"#,
            )
            .unwrap();

        let brief = generate_briefing(&engine, "data-bot");
        assert!(brief.contains("churn"));
        assert!(brief.contains("cancelled"));
        assert!(brief.contains("churned"));
        assert!(brief.contains("Only confirmed"));
        assert!(brief.contains("orders"));
        assert!(brief.contains("email"));
        assert!(brief.contains("internal"));
    }
}
