# agentfence

[![CI](https://github.com/TimurRakhmatullin86/agentfence/actions/workflows/ci.yml/badge.svg)](https://github.com/TimurRakhmatullin86/agentfence/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/agentfence.svg)](https://crates.io/crates/agentfence)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Rulebook for AI agents** — default-deny policies, SQL-aware enforcement, budget limits, approval chains, and MCP proxy mode. One binary, zero runtime deps.

<p align="center">
  <img src="demo/agentfence-demo.gif" alt="agentfence demo — SQL-aware policy enforcement" width="800">
</p>

## The Problem

AI agents can browse the web, execute code, send emails, process refunds, and run SQL queries. But **who decides what an agent is allowed to do — and what data it can touch?**

Existing tools solve adjacent problems:
- **NeMo Guardrails / Model Armor** → prompt safety (what the LLM says)
- **Guardrails AI** → output validation (schema, PII, toxicity)
- **Microsoft AGT** → agent orchestration with governance primitives
- **AWS AgentCore Policy** → Cedar-based agent policies (cloud-locked)

**agentfence** is different: it's an open-source, vendor-neutral **policy engine + MCP proxy** that inspects what agents *do*, not what they *say*. It parses SQL inside tool call arguments, enforces table/field deny-lists, and applies budget and approval rules — all in a single binary.

## Install

```bash
cargo install agentfence
```

Or build from source:

```bash
git clone https://github.com/TimurRakhmatullin86/agentfence
cd agentfence
cargo install --path .
```

## Quick Start

```bash
# Create a policy directory with a default policy
agentfence init

# Edit the generated policy
vim .agentfence/default.yaml

# Validate your policies
agentfence validate

# Check an action (default-deny: unknown actions are blocked)
agentfence check -a my-agent -A send_email
```

## Policy Format

Policies are declarative YAML files with a Kubernetes-style schema:

```yaml
apiVersion: agentfence/v1
kind: Policy
metadata:
  name: support-bot-policy
  description: Governance rules for customer support agent
  owner: platform-team
spec:
  agent:
    name: support-bot
    role: customer-support
  rules:
    - action: "search.*"
      effect: allow

    - action: refund
      effect: require_approval
      conditions:
        - type: amount_max
          field: amount
          max: 500
      approval:
        approver: manager
        timeout_secs: 300
        on_timeout: deny

    - action: database_write
      effect: deny
      reason: "Direct database writes are prohibited"

  budget:
    max_per_session: 5.00
    max_per_day: 100.00
    alert_at_percent: 80

  data_access:
    pii: deny
    allowed_tables: [orders, products, faq]
    denied_tables: [users_private, payments_raw]
    denied_fields: [ssn, credit_card]

  context:
    terms:
      - name: churn
        definition: "Customer who cancelled in the last 30 days"
        aliases: [churned, attrition]
        constraints: ["Only count confirmed cancellations"]
    schemas:
      - table: orders
        pii_columns: [customer_email, phone]
        classification: internal
```

## SQL-Aware Enforcement

agentfence parses SQL inside tool call arguments (via `sqlparser`) and checks every table and field against your `data_access` policy:

```bash
# Agent tries: SELECT * FROM users_private
$ agentfence check -a data-agent -A query.execute \
    -P query="SELECT * FROM users_private"
DENY
  policy: data-policy
  reason: SQL policy violation: table 'users_private' is in denied_tables

# Agent tries a sneaky JOIN
$ agentfence check -a data-agent -A sql.run \
    -P sql="SELECT o.id FROM orders o JOIN payments_raw p ON o.id = p.id"
DENY
  reason: SQL policy violation: table 'payments_raw' is in denied_tables
```

This catches queries that would pass a simple tool-name check: the tool is `query.execute` (allowed), but the SQL *content* references blocked tables.

## CLI Commands

### `agentfence init [dir]`
Create a policy directory with a starter template.

### `agentfence validate [path]`
Validate policy files for syntax and schema errors.

### `agentfence check`
Evaluate an action against loaded policies. Exit code 0 (allow), 1 (deny), 2 (require approval).

```bash
agentfence check -a support-bot -A database_write
agentfence check -a support-bot -A refund -P amount=200
agentfence check -a support-bot -A search.orders --cost 4.50
agentfence check -a support-bot -A refund -P amount=200 --json
```

### `agentfence list [path]`
Show a summary of all loaded policies.

### `agentfence explain -a <agent>`
Generate a human-readable briefing of what the agent can and cannot do, including data access restrictions and business terms.

### `agentfence audit [--limit N]`
Show recent policy decisions from the SQLite audit log. Includes per-agent stats.

### `agentfence serve [-c config]`
Run as MCP proxy server (stdio transport).

## Features

| Feature | agentfence | Microsoft AGT | AWS AgentCore | NeMo Guardrails | Model Armor |
|---------|-----------|--------------|---------------|-----------------|-------------|
| Default-deny | **yes** | no | yes (Cedar) | n/a | n/a |
| Budget limits | **yes** | no | yes (Dogwood) | no | no |
| Approval chains | **yes** | no | no | no | no |
| SQL content parsing | **yes** | no | no | no | no |
| MCP proxy mode | **yes** | no | no | no | no |
| Declarative YAML | **yes** | Python | Cedar | Colang | API |
| Vendor-neutral | **yes** | Azure | AWS | any | GCP |
| Prompt safety | no | no | no | **yes** | **yes** |
| Output validation | no | no | no | partial | **yes** |
| Open-source | **Apache-2.0** | **MIT** | no | **Apache-2.0** | no |

## How It Works

```
┌─────────────────────────────────────────────────────┐
│  Agent (Claude, Cursor, custom)                     │
│  "SELECT * FROM users_private WHERE id = 42"        │
└─────────────────────┬───────────────────────────────┘
                      │ tool call
┌─────────────────────▼───────────────────────────────┐
│  agentfence (MCP proxy)                             │
│  1. Match agent → policy                            │
│  2. Match action → rules                            │
│  3. Parse SQL in arguments → check tables/fields    │
│  4. Check budget limits                             │
│  5. DENY / ALLOW / REQUIRE_APPROVAL                 │
└─────────────────────┬───────────────────────────────┘
                      │ if ALLOW
┌─────────────────────▼───────────────────────────────┐
│  Downstream MCP server (postgres, filesystem, etc)  │
└─────────────────────────────────────────────────────┘
```

## MCP Proxy Mode

agentfence sits between your MCP client and downstream tool servers:

```yaml
# agentfence.yaml
policy: .agentfence
default_agent: support-bot
log_file: agentfence-audit.jsonl

servers:
  - name: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/workspace"]

  - name: github
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_..."
```

Add to Claude Desktop:

```json
{
  "mcpServers": {
    "agentfence": {
      "command": "agentfence",
      "args": ["serve", "-c", "/path/to/agentfence.yaml"]
    }
  }
}
```

## CI/CD Integration

```bash
agentfence validate .agentfence || exit 1

RESULT=$(agentfence check -a $AGENT -A $ACTION --json)
EFFECT=$(echo $RESULT | jq -r .effect)

case $EFFECT in
  allow) execute_action ;;
  deny) log_denied ;;
  require_approval) request_approval ;;
esac
```

## Roadmap

- [x] Default-deny policy engine
- [x] SQL-aware enforcement (table/field/PII checks)
- [x] MCP proxy mode (middleware between agent and tools)
- [x] Business context (terms, agent roles, schema metadata)
- [x] SQLite audit log with agent stats
- [x] Briefing generation (`agentfence explain`)
- [x] Regex action matching
- [x] Strict YAML validation
- [ ] Real-time budget tracking across sessions
- [ ] Approval channel (Slack/webhook integration)
- [ ] OPA policy import
- [ ] Python/TypeScript SDK

## License

Apache-2.0
