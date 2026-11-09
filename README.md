# agentfence

**Business governance layer for AI agents** — budget limits, approval rules, RBAC, and audit trail.

```
$ agentfence check -p policy.yaml -a support-bot -A database_write
DENY
  policy: support-bot-policy
  rule:   #6
  reason: Direct database writes are prohibited
```

## The Problem

AI agents can now browse the web, execute code, send emails, process refunds, and access databases. But **who decides what an agent is allowed to do?**

Existing tools solve adjacent problems:
- **NeMo Guardrails** → prompt safety (what the LLM says)
- **Guardrails AI** → output validation (schema, PII, toxicity)
- **FailproofAI** → dev tool blocking (file system, shell)

**None of them** handle business governance:
- Budget per agent/customer/session
- Approval chains (refund > $500 → manager approval)
- Role-based access control per agent
- Action-level allow/deny with conditions
- Compliance audit trail

agentfence fills this gap.

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

# Check an action
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
    # Allow read operations
    - action: "search.*"
      effect: allow

    # Refunds under $500 need approval
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

    # Block destructive operations
    - action: database_write
      effect: deny
      reason: "Direct database writes are prohibited"

  budget:
    max_per_session: 5.00
    max_per_day: 100.00
    alert_at_percent: 80

  data_access:
    pii: mask
    allowed_tables: [orders, products, faq]
    denied_tables: [users_private, payments_raw]
```

## CLI Commands

### `agentfence init [dir]`

Create a policy directory with a starter template.

### `agentfence validate [path]`

Validate policy files for syntax and schema errors.

```bash
$ agentfence validate .agentfence
ok: 2 policies validated successfully
  support-bot-policy — 8 rules, budget: yes, data_access: yes
  coding-agent-policy — 7 rules, budget: yes, data_access: no
```

### `agentfence check`

Evaluate an action against loaded policies. Returns exit code 0 (allow), 1 (deny), or 2 (require approval).

```bash
# Simple check
agentfence check -a support-bot -A database_write

# With parameters
agentfence check -a support-bot -A refund -P amount=200

# With cost tracking
agentfence check -a support-bot -A search.orders --cost 4.50

# JSON output for programmatic use
agentfence check -a support-bot -A refund -P amount=200 --json
```

### `agentfence list [path]`

Show a summary of all loaded policies.

### `agentfence serve [-c config]`

Run as MCP proxy server (stdio transport). Reads `agentfence.yaml` by default.

```bash
# Start proxy with default config
agentfence serve

# Start with custom config
agentfence serve -c my-config.yaml
```

## Features

| Feature | agentfence | NeMo | Guardrails AI | FailproofAI | permit0 |
|---------|-----------|------|---------------|-------------|---------|
| Budget limits | **yes** | no | no | no | no |
| Approval chains | **yes** | no | no | no | no |
| RBAC per agent | **yes** | no | no | partial | partial |
| Action conditions | **yes** | no | no | yes | yes |
| Declarative YAML | **yes** | Colang | Python | TypeScript | YAML |
| Audit trail | **yes** | no | no | yes | no |
| Prompt safety | no | **yes** | partial | no | no |
| Output validation | no | partial | **yes** | no | no |
| Data access control | **yes** | no | no | partial | no |
| MCP proxy mode | **yes** | no | no | no | no |

## How It Works

1. **Define policies** as YAML files (one per agent or team)
2. **agentfence evaluates** each action request against matching policies
3. **Three outcomes**: `ALLOW` (proceed), `DENY` (block), `REQUIRE_APPROVAL` (escalate)
4. **Exit codes** enable CI/CD integration (0, 1, 2)
5. **JSON output** for programmatic integration with agent frameworks

## MCP Proxy Mode

agentfence can run as an MCP server that sits between Claude (or any MCP client) and your tool servers. Every tool call passes through the policy engine before reaching the downstream server.

```
Claude/Cursor ←→ agentfence (MCP proxy) ←→ MCP tool servers
```

### Setup

1. Create a proxy config:

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

2. Add to Claude Desktop (`claude_desktop_config.json`):

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

3. Claude now sees all downstream tools, but every call is policy-checked:
   - **ALLOW** → proxied to downstream server
   - **DENY** → blocked, agent sees error with reason
   - **REQUIRE_APPROVAL** → blocked, agent sees approval requirement

### Built-in Meta-tool

The proxy exposes `agentfence_status` — agents can check their governance status:
- Loaded policies count
- Connected downstream servers
- Total proxied tools

## CI/CD Integration

Use agentfence as a policy gate in your agent deployment pipeline:

```bash
# Validate policies before deploy
agentfence validate .agentfence || exit 1

# Runtime: check before executing agent action
RESULT=$(agentfence check -a $AGENT -A $ACTION --json)
EFFECT=$(echo $RESULT | jq -r .effect)

case $EFFECT in
  allow) execute_action ;;
  deny) log_denied ;;
  require_approval) request_approval ;;
esac
```

## Roadmap

- [x] MCP server mode (middleware between agent and tools)
- [ ] Rate limiting enforcement
- [ ] Persistent audit log (SQLite)
- [ ] Real-time budget tracking across sessions
- [ ] OPA policy import
- [ ] SDK for Python/TypeScript agent frameworks
- [ ] Web dashboard

## License

Apache-2.0
