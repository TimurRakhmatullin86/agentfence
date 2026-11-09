mod engine;
mod mcp_server;
mod mcp_types;
mod proxy_config;
mod types;

use clap::{Parser, Subcommand};
use colored::*;
use engine::{EngineError, PolicyEngine};
use std::path::PathBuf;
use types::*;

#[derive(Parser)]
#[command(
    name = "agentfence",
    version,
    about = "Business governance layer for AI agents — budget limits, approval rules, RBAC, and audit trail"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new agentfence policy directory
    Init {
        /// Directory to create policies in
        #[arg(default_value = ".agentfence")]
        dir: PathBuf,
    },
    /// Validate policy files
    Validate {
        /// Policy file or directory
        #[arg(default_value = ".agentfence")]
        path: PathBuf,
    },
    /// Check an action against loaded policies
    Check {
        /// Policy file or directory
        #[arg(short, long, default_value = ".agentfence")]
        policy: PathBuf,
        /// Agent name
        #[arg(short, long)]
        agent: String,
        /// Action to check
        #[arg(short = 'A', long)]
        action: String,
        /// Cost of the action
        #[arg(short, long)]
        cost: Option<f64>,
        /// Parameters as key=value pairs
        #[arg(short = 'P', long, value_parser = parse_param)]
        param: Vec<(String, serde_json::Value)>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show loaded policies summary
    List {
        /// Policy file or directory
        #[arg(default_value = ".agentfence")]
        path: PathBuf,
    },
    /// Run as MCP proxy server (stdio transport)
    Serve {
        /// Proxy config file
        #[arg(short, long, default_value = "agentfence.yaml")]
        config: PathBuf,
    },
}

fn parse_param(s: &str) -> Result<(String, serde_json::Value), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err("expected key=value".into());
    }
    let key = parts[0].to_string();
    let val = if let Ok(n) = parts[1].parse::<f64>() {
        serde_json::json!(n)
    } else if parts[1] == "true" {
        serde_json::json!(true)
    } else if parts[1] == "false" {
        serde_json::json!(false)
    } else {
        serde_json::json!(parts[1])
    };
    Ok((key, val))
}

fn load_engine(path: &PathBuf) -> Result<PolicyEngine, EngineError> {
    let mut engine = PolicyEngine::new();
    if path.is_file() {
        engine.load_file(path)?;
    } else if path.is_dir() {
        let count = engine.load_dir(path)?;
        if count == 0 {
            eprintln!(
                "{} no policy files found in {}",
                "warning:".yellow(),
                path.display()
            );
        }
    } else {
        return Err(EngineError::Validation(format!(
            "path {} does not exist",
            path.display()
        )));
    }
    Ok(engine)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { dir } => cmd_init(&dir),
        Commands::Validate { path } => cmd_validate(&path),
        Commands::Check {
            policy,
            agent,
            action,
            cost,
            param,
            json,
        } => cmd_check(&policy, &agent, &action, cost, param, json),
        Commands::List { path } => cmd_list(&path),
        Commands::Serve { config } => cmd_serve(&config).await,
    }
}

fn cmd_init(dir: &PathBuf) {
    if dir.exists() {
        eprintln!(
            "{} directory {} already exists",
            "error:".red(),
            dir.display()
        );
        std::process::exit(1);
    }
    std::fs::create_dir_all(dir).unwrap();

    let example = r#"apiVersion: agentfence/v1
kind: Policy
metadata:
  name: default-policy
  description: Default governance policy for AI agents
spec:
  agent:
    name: my-agent
  rules:
    - action: "*"
      effect: allow
      reason: "Allow all actions by default"
    - action: database_delete
      effect: deny
      reason: "Destructive database operations are not allowed"
    - action: send_email
      effect: require_approval
      approval:
        approver: admin
        timeout_secs: 300
      reason: "Email sending requires admin approval"
  budget:
    max_per_session: 10.0
    max_per_day: 100.0
    alert_at_percent: 80
"#;
    std::fs::write(dir.join("default.yaml"), example).unwrap();

    println!(
        "{} Created {} with default policy",
        "done:".green(),
        dir.display()
    );
    println!("  Edit {}/default.yaml to configure your agent governance rules", dir.display());
}

fn cmd_validate(path: &PathBuf) {
    match load_engine(path) {
        Ok(engine) => {
            let count = engine.policies().len();
            println!(
                "{} {} polic{} validated successfully",
                "ok:".green(),
                count,
                if count == 1 { "y" } else { "ies" }
            );
            for p in engine.policies() {
                println!(
                    "  {} — {} rules, budget: {}, data_access: {}",
                    p.metadata.name.cyan(),
                    p.spec.rules.len(),
                    if p.spec.budget.is_some() {
                        "yes"
                    } else {
                        "no"
                    },
                    if p.spec.data_access.is_some() {
                        "yes"
                    } else {
                        "no"
                    },
                );
            }
        }
        Err(e) => {
            eprintln!("{} {}", "error:".red(), e);
            std::process::exit(1);
        }
    }
}

fn cmd_check(
    policy_path: &PathBuf,
    agent: &str,
    action: &str,
    cost: Option<f64>,
    params: Vec<(String, serde_json::Value)>,
    json_output: bool,
) {
    let engine = match load_engine(policy_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {}", "error:".red(), e);
            std::process::exit(1);
        }
    };

    let request = ActionRequest {
        agent: agent.into(),
        action: action.into(),
        parameters: params.into_iter().collect(),
        session_id: None,
        cost,
    };

    let decision = engine.evaluate(&request);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&decision).unwrap());
    } else {
        let effect_str = match decision.effect {
            Effect::Allow => "ALLOW".green().bold(),
            Effect::Deny => "DENY".red().bold(),
            Effect::RequireApproval => "REQUIRE_APPROVAL".yellow().bold(),
        };
        println!("{}", effect_str);
        println!("  policy: {}", decision.policy);
        if let Some(idx) = decision.rule_index {
            println!("  rule:   #{}", idx);
        }
        println!("  reason: {}", decision.reason);
    }

    match decision.effect {
        Effect::Allow => std::process::exit(0),
        Effect::Deny => std::process::exit(1),
        Effect::RequireApproval => std::process::exit(2),
    }
}

async fn cmd_serve(config_path: &PathBuf) {
    let config = match proxy_config::ProxyConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} failed to load config: {}", "error:".red(), e);
            std::process::exit(1);
        }
    };

    let engine = match load_engine(&config.policy) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} failed to load policies: {}", "error:".red(), e);
            std::process::exit(1);
        }
    };

    eprintln!(
        "{} agentfence MCP proxy starting ({} policies, {} downstream servers)",
        "info:".cyan(),
        engine.policies().len(),
        config.servers.len()
    );

    let server = mcp_server::McpProxyServer::new(engine, config);
    if let Err(e) = server.run().await {
        eprintln!("{} server error: {}", "error:".red(), e);
        std::process::exit(1);
    }
}

fn cmd_list(path: &PathBuf) {
    let engine = match load_engine(path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {}", "error:".red(), e);
            std::process::exit(1);
        }
    };

    if engine.policies().is_empty() {
        println!("No policies loaded.");
        return;
    }

    for policy in engine.policies() {
        println!("{}", policy.metadata.name.cyan().bold());
        if let Some(desc) = &policy.metadata.description {
            println!("  {}", desc.dimmed());
        }
        if let Some(agent) = &policy.spec.agent {
            if let Some(name) = &agent.name {
                println!("  agent: {}", name);
            }
            if let Some(role) = &agent.role {
                println!("  role:  {}", role);
            }
        }
        println!("  rules:");
        for (i, rule) in policy.spec.rules.iter().enumerate() {
            let effect = match rule.effect {
                Effect::Allow => "allow".green(),
                Effect::Deny => "deny".red(),
                Effect::RequireApproval => "approval".yellow(),
            };
            println!("    #{} {} → {}", i, rule.action, effect);
            if !rule.conditions.is_empty() {
                println!("       conditions: {}", rule.conditions.len());
            }
        }
        if let Some(budget) = &policy.spec.budget {
            println!("  budget:");
            if let Some(s) = budget.max_per_session {
                println!("    session: ${:.2}", s);
            }
            if let Some(d) = budget.max_per_day {
                println!("    day:     ${:.2}", d);
            }
            if let Some(m) = budget.max_per_month {
                println!("    month:   ${:.2}", m);
            }
        }
        println!();
    }
}
