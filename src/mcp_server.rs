use crate::engine::PolicyEngine;
use crate::mcp_types::*;
use crate::proxy_config::ProxyConfig;
use crate::types::*;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write as IoWrite;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::process::{Child as TokioChild, Command as TokioCommand};
use tokio::sync::Mutex;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(100);

fn next_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub struct McpProxyServer {
    engine: PolicyEngine,
    config: ProxyConfig,
    agent_name: String,
}

impl McpProxyServer {
    pub fn new(engine: PolicyEngine, config: ProxyConfig) -> Self {
        let agent_name = config
            .default_agent
            .clone()
            .unwrap_or_else(|| "default".into());
        Self {
            engine,
            config,
            agent_name,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut downstream_servers: Vec<Mutex<DownstreamState>> = Vec::new();

        for server_entry in &self.config.servers {
            let mut cmd = TokioCommand::new(&server_entry.command);
            cmd.args(&server_entry.args);
            for (k, v) in &server_entry.env {
                cmd.env(k, v);
            }
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::null());

            match cmd.spawn() {
                Ok(child) => {
                    downstream_servers.push(Mutex::new(DownstreamState {
                        name: server_entry.name.clone(),
                        child,
                        tools: Vec::new(),
                        initialized: false,
                    }));
                }
                Err(e) => {
                    eprintln!(
                        "agentfence: failed to start downstream server '{}': {}",
                        server_entry.name, e
                    );
                }
            }
        }

        // Initialize downstream servers
        for ds in &downstream_servers {
            let mut state = ds.lock().await;
            if let Err(e) = initialize_downstream(&mut state).await {
                eprintln!("agentfence: failed to initialize '{}': {}", state.name, e);
            }
        }

        // Collect all tools from downstream servers
        let mut all_tools: Vec<Tool> = Vec::new();
        let mut tool_routing: HashMap<String, usize> = HashMap::new();

        for (idx, ds) in downstream_servers.iter().enumerate() {
            let state = ds.lock().await;
            for tool in &state.tools {
                tool_routing.insert(tool.name.clone(), idx);
                all_tools.push(tool.clone());
            }
        }

        // Add agentfence meta-tool
        all_tools.push(Tool {
            name: "agentfence_status".into(),
            description: "Check agentfence governance status: loaded policies, budget usage, recent decisions".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        });

        // Read from stdin, write to stdout (MCP stdio transport)
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let mut reader = TokioBufReader::new(stdin);
        let mut stdout = stdout;
        let mut line = String::new();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    let resp = JsonRpcResponse::error(None, -32700, format!("parse error: {}", e));
                    let out = serde_json::to_string(&resp)? + "\n";
                    stdout.write_all(out.as_bytes()).await?;
                    stdout.flush().await?;
                    continue;
                }
            };

            let response = match request.method.as_str() {
                "initialize" => {
                    let result = InitializeResult {
                        protocol_version: "2024-11-05".into(),
                        capabilities: ServerCapabilities {
                            tools: Some(ToolsCapability {
                                list_changed: false,
                            }),
                        },
                        server_info: Implementation {
                            name: "agentfence".into(),
                            version: env!("CARGO_PKG_VERSION").into(),
                        },
                    };
                    JsonRpcResponse::success(request.id, serde_json::to_value(result)?)
                }
                "notifications/initialized" => {
                    continue;
                }
                "tools/list" => {
                    let result = ToolsListResult {
                        tools: all_tools.clone(),
                    };
                    JsonRpcResponse::success(request.id, serde_json::to_value(result)?)
                }
                "tools/call" => {
                    let params: CallToolParams = match request.params {
                        Some(p) => serde_json::from_value(p)?,
                        None => {
                            JsonRpcResponse::error(request.id, -32602, "missing params".into());
                            continue;
                        }
                    };

                    if params.name == "agentfence_status" {
                        let status = format!(
                            "agentfence v{}\nPolicies loaded: {}\nDownstream servers: {}\nTools proxied: {}",
                            env!("CARGO_PKG_VERSION"),
                            self.engine.policies().len(),
                            downstream_servers.len(),
                            all_tools.len() - 1,
                        );
                        let result = CallToolResult {
                            content: vec![ToolContent::Text { text: status }],
                            is_error: false,
                        };
                        JsonRpcResponse::success(request.id, serde_json::to_value(result)?)
                    } else {
                        // Policy check before proxying
                        let action_request = ActionRequest {
                            agent: self.agent_name.clone(),
                            action: params.name.clone(),
                            parameters: match &params.arguments {
                                Some(Value::Object(map)) => {
                                    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                                }
                                _ => HashMap::new(),
                            },
                            session_id: None,
                            cost: None,
                        };

                        let decision = self.engine.evaluate(&action_request);

                        match decision.effect {
                            Effect::Deny => {
                                let result = CallToolResult {
                                    content: vec![ToolContent::Text {
                                        text: format!(
                                            "[AGENTFENCE DENIED] Action '{}' blocked by policy '{}': {}",
                                            params.name, decision.policy, decision.reason
                                        ),
                                    }],
                                    is_error: true,
                                };
                                JsonRpcResponse::success(request.id, serde_json::to_value(result)?)
                            }
                            Effect::RequireApproval => {
                                let result = CallToolResult {
                                    content: vec![ToolContent::Text {
                                        text: format!(
                                            "[AGENTFENCE APPROVAL REQUIRED] Action '{}' needs approval (policy '{}'): {}",
                                            params.name, decision.policy, decision.reason
                                        ),
                                    }],
                                    is_error: true,
                                };
                                JsonRpcResponse::success(request.id, serde_json::to_value(result)?)
                            }
                            Effect::Allow => {
                                // Proxy to downstream
                                if let Some(&ds_idx) = tool_routing.get(&params.name) {
                                    let mut state = downstream_servers[ds_idx].lock().await;
                                    match proxy_tool_call(&mut state, &params).await {
                                        Ok(result) => JsonRpcResponse::success(request.id, result),
                                        Err(e) => JsonRpcResponse::error(
                                            request.id,
                                            -32603,
                                            format!("downstream error: {}", e),
                                        ),
                                    }
                                } else {
                                    JsonRpcResponse::error(
                                        request.id,
                                        -32601,
                                        format!(
                                            "tool '{}' not found in any downstream server",
                                            params.name
                                        ),
                                    )
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Forward unknown methods to all downstream servers
                    JsonRpcResponse::error(
                        request.id,
                        -32601,
                        format!("method '{}' not supported", request.method),
                    )
                }
            };

            let out = serde_json::to_string(&response)? + "\n";
            stdout.write_all(out.as_bytes()).await?;
            stdout.flush().await?;

            // Log decision if configured
            if let Some(log_path) = &self.config.log_file {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                {
                    let _ = writeln!(f, "{}", serde_json::to_string(&response)?);
                }
            }
        }

        // Clean up downstream servers
        for ds in &downstream_servers {
            let mut state = ds.lock().await;
            let _ = state.child.kill().await;
        }

        Ok(())
    }
}

struct DownstreamState {
    name: String,
    child: TokioChild,
    tools: Vec<Tool>,
    initialized: bool,
}

async fn initialize_downstream(
    state: &mut DownstreamState,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = state.child.stdin.as_mut().ok_or("no stdin")?;
    let stdout = state.child.stdout.as_mut().ok_or("no stdout")?;

    // Send initialize
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "agentfence",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });
    let msg = serde_json::to_string(&init_req)? + "\n";
    stdin.write_all(msg.as_bytes()).await?;
    stdin.flush().await?;

    // Read initialize response
    let mut reader = TokioBufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    // Parse but don't need to use the result
    let _: JsonRpcResponse = serde_json::from_str(line.trim())?;

    // Send initialized notification
    let notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let stdin = state.child.stdin.as_mut().ok_or("no stdin")?;
    let msg = serde_json::to_string(&notif)? + "\n";
    stdin.write_all(msg.as_bytes()).await?;
    stdin.flush().await?;

    // Request tools/list
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    let stdin = state.child.stdin.as_mut().ok_or("no stdin")?;
    let msg = serde_json::to_string(&tools_req)? + "\n";
    stdin.write_all(msg.as_bytes()).await?;
    stdin.flush().await?;

    // Read tools/list response
    let stdout = state.child.stdout.as_mut().ok_or("no stdout")?;
    let mut reader = TokioBufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let resp: JsonRpcResponse = serde_json::from_str(line.trim())?;

    if let Some(result) = resp.result {
        let tools_result: ToolsListResult = serde_json::from_value(result)?;
        state.tools = tools_result.tools;
    }

    state.initialized = true;
    Ok(())
}

async fn proxy_tool_call(
    state: &mut DownstreamState,
    params: &CallToolParams,
) -> Result<Value, Box<dyn std::error::Error>> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": next_id(),
        "method": "tools/call",
        "params": {
            "name": params.name,
            "arguments": params.arguments
        }
    });

    let stdin = state.child.stdin.as_mut().ok_or("no stdin")?;
    let msg = serde_json::to_string(&req)? + "\n";
    stdin.write_all(msg.as_bytes()).await?;
    stdin.flush().await?;

    let stdout = state.child.stdout.as_mut().ok_or("no stdout")?;
    let mut reader = TokioBufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let resp: JsonRpcResponse = serde_json::from_str(line.trim())?;

    if let Some(error) = resp.error {
        return Err(format!("{}: {}", error.code, error.message).into());
    }

    resp.result.ok_or_else(|| "empty result".into())
}
