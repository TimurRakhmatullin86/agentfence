use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub policy: PathBuf,
    pub servers: Vec<ServerEntry>,
    #[serde(default)]
    pub default_agent: Option<String>,
    #[serde(default)]
    pub log_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

impl ProxyConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: ProxyConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}
