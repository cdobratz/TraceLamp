//! Static inventory of agent and MCP configs.
//!
//! This module only parses files that were already read from disk. It does not
//! start MCP servers, spawn package managers, or open the URLs it finds.

use super::rules;
use super::secrets;
use super::Finding;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InventoryGraph {
    pub agents: Vec<InventoryAgent>,
}

impl InventoryGraph {
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    pub fn merge(&mut self, other: InventoryGraph) {
        self.agents.extend(other.agents);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryAgent {
    pub name: String,
    pub source: String,
    pub servers: Vec<InventoryServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryServer {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    pub tools: Vec<InventoryTool>,
    pub data_stores: Vec<InventoryDataStore>,
    pub credentials: Vec<InventoryCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryDataStore {
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryCredential {
    pub name: String,
    pub storage: String,
}

pub struct McpScan {
    pub findings: Vec<Finding>,
    pub inventory: InventoryGraph,
}

struct PackageSpec {
    name: String,
    version: Option<String>,
    token: String,
}

struct ToolDecl {
    name: String,
    description: String,
    approved: bool,
}

pub fn scan(path: &Path, source: &str, language: &str) -> McpScan {
    let empty = McpScan {
        findings: Vec::new(),
        inventory: InventoryGraph::default(),
    };
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if is_mcp_config_name(file_name) {
        return scan_mcp_json(path, source, language);
    }
    if is_langchain_context(path, source) {
        return scan_langchain(path, source, language);
    }
    empty
}

pub fn to_mermaid(graph: &InventoryGraph) -> String {
    if graph.is_empty() {
        return "flowchart LR\n  %% no agent or MCP inventory\n".to_string();
    }
    let mut out = String::from("flowchart LR\n");
    for (ai, agent) in graph.agents.iter().enumerate() {
        let agent_id = format!("agent_{ai}");
        out.push_str(&format!(
            "  {agent_id}[\"{}\"]\n",
            escape_label(&agent.name)
        ));
        for (si, server) in agent.servers.iter().enumerate() {
            let server_id = format!("server_{ai}_{si}");
            out.push_str(&format!(
                "  {agent_id} --> {server_id}[\"{}\"]\n",
                escape_label(&server.name)
            ));
            let bridge = if server.tools.is_empty() {
                server_id.clone()
            } else {
                let tool_id = format!("tool_{ai}_{si}_0");
                for (ti, tool) in server.tools.iter().enumerate() {
                    let id = format!("tool_{ai}_{si}_{ti}");
                    out.push_str(&format!(
                        "  {server_id} --> {id}[\"{}\"]\n",
                        escape_label(&tool.name)
                    ));
                }
                tool_id
            };
            if server.data_stores.is_empty() {
                for (ci, cred) in server.credentials.iter().enumerate() {
                    let cred_id = format!("cred_{ai}_{si}_{ci}");
                    out.push_str(&format!(
                        "  {bridge} --> {cred_id}[\"{}\"]\n",
                        escape_label(&cred.name)
                    ));
                }
                continue;
            }
            for (di, store) in server.data_stores.iter().enumerate() {
                let store_id = format!("store_{ai}_{si}_{di}");
                let label = format!("{} {}", store.kind, store.name);
                out.push_str(&format!(
                    "  {bridge} --> {store_id}[\"{}\"]\n",
                    escape_label(&label)
                ));
                for (ci, cred) in server.credentials.iter().enumerate() {
                    let cred_id = format!("cred_{ai}_{si}_{di}_{ci}");
                    out.push_str(&format!(
                        "  {store_id} --> {cred_id}[\"{}\"]\n",
                        escape_label(&cred.name)
                    ));
                }
            }
        }
    }
    out
}

fn scan_mcp_json(path: &Path, source: &str, language: &str) -> McpScan {
    let mut result = McpScan {
        findings: Vec::new(),
        inventory: InventoryGraph::default(),
    };
    let Ok(root) = serde_json::from_str::<Value>(source) else {
        return result;
    };
    let Some(servers) = server_map(&root) else {
        return result;
    };
    let file_str = path.to_string_lossy().to_string();
    let mut agent = InventoryAgent {
        name: agent_name(path, "mcp"),
        source: file_str.clone(),
        servers: Vec::new(),
    };
    for (name, spec) in servers {
        let Some(obj) = spec.as_object() else {
            continue;
        };
        let command = obj.get("command").and_then(|v| v.as_str()).unwrap_or("");
        let args = string_array(obj.get("args"));
        let (launch, launch_args) = command_and_args(command, &args);
        let env = obj.get("env").and_then(|v| v.as_object());
        let tools = tool_decls(obj);
        let server_approved = obj_approved(obj);
        let packages = launcher_packages(&launch, &launch_args);

        for spec in packages.iter().filter(|spec| spec.name == "mcp-remote") {
            if let Some(version) = spec.version.as_deref() {
                if mcp_remote_vulnerable(version) {
                    result.findings.push(rule_finding(
                        path,
                        language,
                        line_of(source, &spec.token),
                        rules::MCP_REMOTE_CVE,
                        spec.token.clone(),
                        "mcp",
                    ));
                }
            }
        }
        let unpinned = unpinned_packages(&packages);
        for spec in &unpinned {
            result.findings.push(rule_finding(
                path,
                language,
                line_of(source, &spec.token),
                rules::MCP_UNPINNED_PACKAGE,
                spec.token.clone(),
                "mcp",
            ));
        }

        if let Some(env) = env {
            for (key, value) in env {
                let Some(value) = value.as_str() else {
                    continue;
                };
                if literal_secret(key, value) {
                    result.findings.push(rule_finding(
                        path,
                        language,
                        line_of(source, key),
                        rules::MCP_SECRET_IN_ENV,
                        format!("{key}=***REDACTED***"),
                        "mcp",
                    ));
                }
            }
        }

        for root_arg in broad_filesystem_roots(&launch_args) {
            result.findings.push(rule_finding(
                path,
                language,
                line_of(source, &root_arg),
                rules::MCP_FILESYSTEM_ROOT,
                root_arg,
                "mcp",
            ));
        }

        if shell_without_approval(&launch, &launch_args, &tools, server_approved) {
            let snippet = if command.is_empty() {
                name.clone()
            } else {
                secrets::redact_text(format!("{command} {}", args.join(" ")).trim())
            };
            result.findings.push(rule_finding(
                path,
                language,
                line_of(source, name),
                rules::MCP_SHELL_WITHOUT_APPROVAL,
                snippet,
                "mcp",
            ));
        }

        let headers = obj.get("headers").and_then(|value| value.as_object());
        let cloud = cloud_reasons(&launch, &launch_args, env, headers, &tools);
        if !cloud.is_empty() {
            result.findings.push(rule_finding(
                path,
                language,
                line_of(source, name),
                rules::AGENT_CLOUD_SPEND,
                cloud.join("; "),
                "agent",
            ));
        }

        if let Some(headers) = headers {
            for (key, value) in headers {
                let Some(value) = value.as_str() else {
                    continue;
                };
                if literal_secret(key, value) {
                    result.findings.push(rule_finding(
                        path,
                        language,
                        line_of(source, key),
                        rules::MCP_SECRET_IN_ENV,
                        format!("header {key}=***REDACTED***"),
                        "mcp",
                    ));
                }
            }
        }

        let safe_args: Vec<String> = launch_args
            .iter()
            .map(|arg| secrets::redact_text(arg))
            .collect();
        let mut server = inventory_server(
            name,
            &secrets::redact_text(&launch),
            &safe_args,
            env,
            &tools,
            &packages,
            &cloud,
        );
        if let Some(headers) = headers {
            for key in headers.keys() {
                server.credentials.push(InventoryCredential {
                    name: key.clone(),
                    storage: "mcp-header".into(),
                });
            }
        }
        agent.servers.push(server);
    }
    if !agent.servers.is_empty() {
        result.inventory.agents.push(agent);
    }
    result
}

fn scan_langchain(path: &Path, source: &str, language: &str) -> McpScan {
    let mut result = McpScan {
        findings: Vec::new(),
        inventory: InventoryGraph::default(),
    };
    let tools = langchain_tools(source);
    if tools.is_empty() {
        return result;
    }
    let cloud_tools: Vec<&ToolDecl> = tools
        .iter()
        .filter(|t| tool_spends_cloud(&t.name, &t.description))
        .collect();
    if cloud_tools.is_empty() {
        return result;
    }
    let reason = cloud_tools
        .iter()
        .map(|t| format!("cloud write tool {}", t.name))
        .collect::<Vec<_>>()
        .join("; ");
    result.findings.push(rule_finding(
        path,
        language,
        line_of(source, &cloud_tools[0].name),
        rules::AGENT_CLOUD_SPEND,
        reason.clone(),
        "agent",
    ));
    let file_str = path.to_string_lossy().to_string();
    let mut servers = Vec::new();
    for tool in &cloud_tools {
        let stores = cloud_store_names(&[format!("cloud write tool {}", tool.name)]);
        servers.push(InventoryServer {
            name: tool.name.clone(),
            command: String::new(),
            args: Vec::new(),
            tools: vec![InventoryTool {
                name: tool.name.clone(),
                description: tool.description.clone(),
            }],
            data_stores: stores
                .into_iter()
                .map(|name| InventoryDataStore {
                    kind: "cloud".into(),
                    name,
                })
                .collect(),
            credentials: Vec::new(),
        });
    }
    result.inventory.agents.push(InventoryAgent {
        name: "LangChain".into(),
        source: file_str,
        servers,
    });
    result
}

fn inventory_server(
    name: &str,
    command: &str,
    args: &[String],
    env: Option<&serde_json::Map<String, Value>>,
    tools: &[ToolDecl],
    packages: &[PackageSpec],
    cloud: &[String],
) -> InventoryServer {
    let mut inv_tools: Vec<InventoryTool> = tools
        .iter()
        .map(|tool| InventoryTool {
            name: tool.name.clone(),
            description: tool.description.clone(),
        })
        .collect();
    if inv_tools.is_empty() {
        inv_tools.extend(infer_tools(command, args, packages));
    }
    let mut data_stores = Vec::new();
    for path in filesystem_paths(args) {
        data_stores.push(InventoryDataStore {
            kind: "filesystem".into(),
            name: path,
        });
    }
    for name in cloud_store_names(cloud) {
        data_stores.push(InventoryDataStore {
            kind: "cloud".into(),
            name,
        });
    }
    let mut credentials = Vec::new();
    if let Some(env) = env {
        for (key, value) in env {
            let Some(value) = value.as_str() else {
                continue;
            };
            if key_is_credential(key)
                || literal_secret(key, value)
                || CLOUD_ENV.contains(&key.as_str())
            {
                credentials.push(InventoryCredential {
                    name: key.clone(),
                    storage: "mcp-env".into(),
                });
            }
            if looks_like_database_url(value) {
                data_stores.push(InventoryDataStore {
                    kind: "database".into(),
                    name: key.clone(),
                });
            }
        }
    }
    InventoryServer {
        name: name.to_string(),
        command: command.to_string(),
        args: args.to_vec(),
        tools: inv_tools,
        data_stores,
        credentials,
    }
}

fn rule_finding(
    path: &Path,
    language: &str,
    line: usize,
    rule_id: &str,
    snippet: String,
    category: &str,
) -> Finding {
    let rule = rules::by_id(rule_id).unwrap_or_else(|| panic!("missing rule {rule_id}"));
    let mut metadata = HashMap::new();
    metadata.insert("rule_id".into(), rule.id.into());
    metadata.insert("help".into(), rule.help.into());
    metadata.insert("asi".into(), rule.asi.join(","));
    let mut description = rule.help.to_string();
    if !rule.remediation.is_empty() {
        metadata.insert("remediation".into(), rule.remediation.into());
        description.push(' ');
        description.push_str(rule.remediation);
    }
    Finding {
        category: category.into(),
        severity: rule.severity.into(),
        file: path.to_string_lossy().to_string(),
        line,
        title: rule.short_description.into(),
        description,
        snippet,
        language: language.into(),
        metadata,
    }
}

fn is_mcp_config_name(name: &str) -> bool {
    matches!(
        name,
        "mcp.json" | ".mcp.json" | "claude_desktop_config.json"
    )
}

fn is_langchain_context(path: &Path, source: &str) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.contains("langchain") {
        return true;
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(ext, "json" | "yaml" | "yml" | "py" | "toml")
        && source.to_ascii_lowercase().contains("langchain")
}

fn agent_name(path: &Path, kind: &str) -> String {
    if kind == "langchain" {
        return "LangChain".into();
    }
    let normalized = path.to_string_lossy().replace('\\', "/");
    if warp_mcp_config(&normalized) {
        return "Warp".into();
    }
    if normalized.contains("/.cursor/") || normalized.starts_with(".cursor/") {
        return "Cursor".into();
    }
    if normalized.contains("/.vscode/") || normalized.starts_with(".vscode/") {
        return "VS Code".into();
    }
    match path.file_name().and_then(|n| n.to_str()).unwrap_or("") {
        ".mcp.json" => "Claude Code".into(),
        "claude_desktop_config.json" => "Claude Desktop".into(),
        _ => "MCP client".into(),
    }
}

/// Official Warp file locations are `~/.warp/.mcp.json` and `<project>/.warp/.mcp.json`.
fn warp_mcp_config(normalized: &str) -> bool {
    normalized.ends_with("/.warp/.mcp.json") || normalized == ".warp/.mcp.json"
}

fn server_map(root: &Value) -> Option<&serde_json::Map<String, Value>> {
    if let Some(map) = root.get("mcpServers").and_then(|v| v.as_object()) {
        return Some(map);
    }
    if let Some(map) = root.get("servers").and_then(|v| v.as_object()) {
        return Some(map);
    }
    root.get("mcp")
        .and_then(|v| v.get("servers"))
        .and_then(|v| v.as_object())
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn command_and_args(command: &str, args: &[String]) -> (String, Vec<String>) {
    let mut parts = split_ws(command);
    if parts.is_empty() {
        return (String::new(), args.to_vec());
    }
    let cmd = parts.remove(0);
    parts.extend(args.iter().cloned());
    (cmd, parts)
}

fn split_ws(command: &str) -> Vec<String> {
    command.split_whitespace().map(|s| s.to_string()).collect()
}

fn basename(command: &str) -> String {
    let name = command.rsplit(['/', '\\']).next().unwrap_or(command);
    name.strip_suffix(".cmd")
        .or_else(|| name.strip_suffix(".exe"))
        .unwrap_or(name)
        .to_string()
}

fn launcher_packages(command: &str, args: &[String]) -> Vec<PackageSpec> {
    let base = basename(command).to_ascii_lowercase();
    let tokens = match base.as_str() {
        "npx" => npx_package_tokens(args),
        "uvx" => uvx_package_tokens(args),
        _ => return Vec::new(),
    };
    tokens
        .iter()
        .filter_map(|token| parse_spec(token))
        .collect()
}

fn npx_package_tokens(args: &[String]) -> Vec<String> {
    const VALUE_FLAGS: &[&str] = &[
        "-p",
        "--package",
        "--prefix",
        "-c",
        "--call",
        "--userconfig",
        "--cache",
        "--registry",
    ];
    const BOOL_FLAGS: &[&str] = &[
        "-y",
        "--yes",
        "-q",
        "--quiet",
        "--no-install",
        "--ignore-existing",
        "--prefer-offline",
        "--prefer-online",
        "--offline",
    ];
    package_tokens(args, VALUE_FLAGS, BOOL_FLAGS, &["-p", "--package"])
}

fn uvx_package_tokens(args: &[String]) -> Vec<String> {
    const VALUE_FLAGS: &[&str] = &[
        "--from",
        "--with",
        "--python",
        "-p",
        "--index",
        "--index-url",
    ];
    const BOOL_FLAGS: &[&str] = &["--offline", "--no-cache", "-q", "--quiet"];
    package_tokens(args, VALUE_FLAGS, BOOL_FLAGS, &["--from", "--with"])
}

fn package_tokens(
    args: &[String],
    value_flags: &[&str],
    bool_flags: &[&str],
    package_flags: &[&str],
) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut saw_positional = false;
    while index < args.len() {
        let arg = &args[index];
        if let Some((flag, inline)) = arg.split_once('=') {
            if package_flags.contains(&flag) {
                tokens.push(inline.to_string());
            }
            index += 1;
            continue;
        }
        if package_flags.contains(&arg.as_str()) {
            if let Some(next) = args.get(index + 1) {
                tokens.push(next.clone());
                index += 2;
                continue;
            }
        }
        if value_flags.contains(&arg.as_str()) {
            index += 2;
            continue;
        }
        if arg.starts_with('-') || bool_flags.contains(&arg.as_str()) {
            index += 1;
            continue;
        }
        if !saw_positional {
            tokens.push(arg.clone());
            saw_positional = true;
        }
        index += 1;
    }
    tokens
}

fn parse_spec(token: &str) -> Option<PackageSpec> {
    let token = token.trim().trim_matches(|c| c == '"' || c == '\'');
    if token.is_empty() || token.starts_with('-') || token.contains("://") {
        return None;
    }
    if let Some((name, version)) = token.split_once("==") {
        if name.is_empty() {
            return None;
        }
        return Some(PackageSpec {
            name: name.to_string(),
            version: Some(version.to_string()),
            token: token.to_string(),
        });
    }
    if let Some((name, version)) = split_package_version(token) {
        return Some(PackageSpec {
            name,
            version,
            token: token.to_string(),
        });
    }
    Some(PackageSpec {
        name: token.to_string(),
        version: None,
        token: token.to_string(),
    })
}

fn split_package_version(token: &str) -> Option<(String, Option<String>)> {
    if let Some(rest) = token.strip_prefix('@') {
        if let Some((pkg, version)) = rest.rsplit_once('@') {
            if !pkg.is_empty() {
                return Some((format!("@{pkg}"), Some(version.to_string())));
            }
        }
        return Some((token.to_string(), None));
    }
    if let Some((name, version)) = token.rsplit_once('@') {
        if !name.is_empty() {
            return Some((name.to_string(), Some(version.to_string())));
        }
    }
    None
}

fn version_is_pin(version: &str) -> bool {
    version.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn unpinned_packages(specs: &[PackageSpec]) -> Vec<&PackageSpec> {
    let mut pinned_names = HashSet::new();
    for spec in specs {
        if spec.version.as_deref().is_some_and(version_is_pin) {
            pinned_names.insert(spec.name.as_str());
        }
    }
    specs
        .iter()
        .filter(|spec| !pinned_names.contains(spec.name.as_str()))
        .collect()
}

pub fn mcp_remote_vulnerable(version: &str) -> bool {
    let Some((major, minor, patch)) = version_tuple(version) else {
        return false;
    };
    // (major, minor, patch) does not implement std::iter::Step, so an inclusive
    // range cannot be used here.
    #[allow(clippy::manual_range_contains)]
    let in_range = (major, minor, patch) >= (0, 0, 5) && (major, minor, patch) <= (0, 1, 15);
    in_range
}

fn version_tuple(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    if !version_is_pin(core) {
        return None;
    }
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn literal_secret(key: &str, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || is_env_reference(value) || is_placeholder(value) {
        return false;
    }
    if known_secret_value(value) || stripe_live_secret(value) {
        return true;
    }
    key_is_credential(key) && value.chars().count() >= 8
}

fn key_is_credential(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "credential",
        "private_key",
        "access_key",
        "authorization",
    ]
    .iter()
    .any(|part| key.contains(part))
}

fn is_env_reference(value: &str) -> bool {
    (value.starts_with("${") && value.ends_with('}'))
        || (value.starts_with('$') && value.len() > 1 && !value.contains(' '))
        || (value.starts_with('%') && value.ends_with('%') && value.len() > 2)
}

fn is_placeholder(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("example")
        || value.contains("changeme")
        || value.contains("placeholder")
        || value.contains("your-")
        || value.contains("redacted")
        || value == "xxx"
        || value == "todo"
        || value.starts_with('<')
}

fn known_secret_value(value: &str) -> bool {
    static KNOWN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9\-_]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-",
        )
        .unwrap()
    });
    KNOWN.is_match(value)
}

fn broad_filesystem_roots(args: &[String]) -> Vec<String> {
    let mut roots = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--root" | "--allow" | "--allowed-directories") {
            if let Some(next) = args.get(index + 1) {
                if is_broad_root(next) {
                    roots.push(next.clone());
                }
                index += 2;
                continue;
            }
        }
        if let Some(rest) = arg
            .strip_prefix("--root=")
            .or_else(|| arg.strip_prefix("--allow="))
        {
            if is_broad_root(rest) {
                roots.push(rest.to_string());
            }
        } else if is_broad_root(arg) {
            roots.push(arg.clone());
        }
        index += 1;
    }
    roots
}

fn is_broad_root(arg: &str) -> bool {
    matches!(arg, "/" | "~" | "~/")
}

fn filesystem_paths(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| looks_like_fs_path(arg))
        .cloned()
        .collect()
}

fn looks_like_fs_path(arg: &str) -> bool {
    if arg.starts_with('-') || arg.contains("://") {
        return false;
    }
    arg == "/" || arg == "~" || arg == "~/" || arg.starts_with("~/") || arg.starts_with('/')
}

fn tool_decls(obj: &serde_json::Map<String, Value>) -> Vec<ToolDecl> {
    let Some(items) = obj.get("tools").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    items.iter().filter_map(tool_decl).collect()
}

fn tool_decl(value: &Value) -> Option<ToolDecl> {
    if let Some(name) = value.as_str() {
        return Some(ToolDecl {
            name: name.to_string(),
            description: String::new(),
            approved: false,
        });
    }
    let obj = value.as_object()?;
    let name = obj.get("name").and_then(|v| v.as_str()).or_else(|| {
        obj.get("function")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
    })?;
    let description = obj
        .get("description")
        .and_then(|v| v.as_str())
        .or_else(|| {
            obj.get("function")
                .and_then(|v| v.get("description"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
        .to_string();
    Some(ToolDecl {
        name: name.to_string(),
        description,
        approved: obj_approved(obj),
    })
}

fn obj_approved(obj: &serde_json::Map<String, Value>) -> bool {
    const KEYS: &[&str] = &[
        "requireApproval",
        "requiresApproval",
        "needsApproval",
        "approvalRequired",
        "approval",
    ];
    KEYS.iter().any(|key| flag_true(obj.get(*key)))
}

fn flag_true(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(true)) => true,
        Some(Value::String(text)) => {
            matches!(
                text.to_ascii_lowercase().as_str(),
                "true" | "required" | "always" | "yes"
            )
        }
        _ => false,
    }
}

fn shell_without_approval(
    command: &str,
    args: &[String],
    tools: &[ToolDecl],
    server_approved: bool,
) -> bool {
    if !is_shellish(command, args, tools) {
        return false;
    }
    if server_approved {
        return false;
    }
    let shell_tools: Vec<&ToolDecl> = tools
        .iter()
        .filter(|tool| is_shell_tool(&tool.name))
        .collect();
    if shell_tools.is_empty() {
        return true;
    }
    shell_tools.iter().any(|tool| !tool.approved)
}

fn is_shellish(command: &str, args: &[String], tools: &[ToolDecl]) -> bool {
    let base = basename(command).to_ascii_lowercase();
    if matches!(
        base.as_str(),
        "bash" | "sh" | "zsh" | "fish" | "pwsh" | "powershell" | "cmd" | "cmd.exe"
    ) {
        return true;
    }
    let joined = args.join(" ").to_ascii_lowercase();
    if joined.contains("server-shell")
        || joined.contains("mcp-shell")
        || joined.contains("shell-tool")
    {
        return true;
    }
    tools.iter().any(|tool| is_shell_tool(&tool.name))
}

fn is_shell_tool(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "shell"
            | "exec"
            | "bash"
            | "execute"
            | "execute_command"
            | "run_command"
            | "run_shell"
            | "terminal"
            | "shell_exec"
    ) || normalized.contains("shell")
}

fn infer_tools(command: &str, args: &[String], packages: &[PackageSpec]) -> Vec<InventoryTool> {
    let blob = format!(
        "{} {} {}",
        command,
        args.join(" "),
        packages
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_ascii_lowercase();
    if blob.contains("filesystem") {
        return ["read_file", "write_file", "list_directory"]
            .into_iter()
            .map(|name| InventoryTool {
                name: name.into(),
                description: String::new(),
            })
            .collect();
    }
    if blob.contains("shell") {
        return vec![InventoryTool {
            name: "exec".into(),
            description: String::new(),
        }];
    }
    let base = basename(command);
    if base.is_empty() {
        return Vec::new();
    }
    if matches!(
        base.as_str(),
        "aws" | "az" | "gcloud" | "terraform" | "tofu" | "pulumi" | "cdk"
    ) {
        return vec![InventoryTool {
            name: format!("{base} {}", args.join(" ")).trim().to_string(),
            description: String::new(),
        }];
    }
    Vec::new()
}

fn cloud_reasons(
    command: &str,
    args: &[String],
    env: Option<&serde_json::Map<String, Value>>,
    headers: Option<&serde_json::Map<String, Value>>,
    tools: &[ToolDecl],
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Some(reason) = cli_spends(command, args) {
        reasons.push(reason.to_string());
    }
    if args.iter().any(|arg| cloud_cred_path(arg)) || cloud_cred_path(command) {
        reasons.push("cloud credential path".into());
    }
    if args.iter().any(|arg| stripe_live_secret(arg)) || stripe_live_secret(command) {
        reasons.push("stripe live secret".into());
    }
    if let Some(env) = env {
        for (key, value) in env {
            if CLOUD_ENV.contains(&key.as_str()) {
                reasons.push(format!("cloud credential {key}"));
            }
            if value.as_str().is_some_and(stripe_live_secret) {
                reasons.push(format!("stripe live secret {key}"));
            }
        }
    }
    if let Some(headers) = headers {
        for (key, value) in headers {
            if value.as_str().is_some_and(stripe_live_secret) {
                reasons.push(format!("stripe live secret {key}"));
            }
        }
    }
    for tool in tools {
        if tool_spends_cloud(&tool.name, &tool.description) {
            reasons.push(format!("cloud write tool {}", tool.name));
        }
    }
    reasons
}

const CLOUD_ENV: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "ARM_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "STRIPE_SECRET_KEY",
    "STRIPE_API_KEY",
    "STRIPE_RESTRICTED_KEY",
];

fn cli_spends(command: &str, args: &[String]) -> Option<&'static str> {
    let base = basename(command).to_ascii_lowercase();
    let lowered: Vec<String> = args.iter().map(|arg| arg.to_ascii_lowercase()).collect();
    let has = |needle: &str| lowered.iter().any(|arg| arg == needle);
    let has_prefix = |prefix: &str| lowered.iter().any(|arg| arg.starts_with(prefix));
    match base.as_str() {
        "terraform" | "tofu" if has("apply") => Some("terraform apply"),
        "pulumi" if has("up") => Some("pulumi up"),
        "cdk" if has("deploy") => Some("cdk deploy"),
        "az" if has("create") => Some("az create"),
        "az" if has("login") => Some("az login"),
        "aws" if has("run-instances") || has("allocate-address") || has_prefix("create-") => {
            Some("aws write")
        }
        "gcloud" if has("create") => Some("gcloud create"),
        "stripe" if stripe_cli_charges(&lowered) => Some("stripe charge"),
        _ => None,
    }
}

fn stripe_cli_charges(args: &[String]) -> bool {
    let has = |needle: &str| args.iter().any(|arg| arg == needle);
    ((has("charges") || has("charge")) && (has("create") || has("capture")))
        || ((has("payment_intents") || has("payment_intent")) && has("create"))
}

/// Live Stripe secret (`sk_live_`) or restricted (`rk_live_`) key.
/// Test keys and publishable keys cannot charge real cards.
fn stripe_live_secret(value: &str) -> bool {
    let value = value.trim();
    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    let Some(rest) = value
        .strip_prefix("sk_live_")
        .or_else(|| value.strip_prefix("rk_live_"))
    else {
        return false;
    };
    rest.len() >= 24 && rest.chars().all(|c| c.is_ascii_alphanumeric())
}

fn cloud_cred_path(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    normalized.contains("/.aws")
        || normalized.contains("~/.aws")
        || normalized.contains("/.azure")
        || normalized.contains("~/.azure")
        || normalized.contains(".config/gcloud")
}

fn tool_spends_cloud(name: &str, description: &str) -> bool {
    let blob = format!("{name} {description}").to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "pulumi up",
        "pulumi_up",
        "terraform apply",
        "terraform_apply",
        "cdk deploy",
        "cdk_deploy",
        "tofu apply",
        "tofu_apply",
        "run_instances",
        "run-instances",
        "allocate_address",
        "allocate-address",
        "create_vm",
        "az vm create",
        "az_vm_create",
        "create_payment_intent",
        "create_charge",
        "stripe_charge",
        "payment_intents.create",
    ];
    NEEDLES.iter().any(|needle| blob.contains(needle))
}

fn cloud_store_names(reasons: &[String]) -> Vec<String> {
    let blob = reasons.join(" ").to_ascii_lowercase();
    let mut names = Vec::new();
    for (needle, name) in [
        ("aws", "aws"),
        ("azure", "azure"),
        ("az create", "azure"),
        ("az login", "azure"),
        ("gcloud", "gcp"),
        ("google", "gcp"),
        ("pulumi", "pulumi"),
        ("terraform", "terraform"),
        ("cdk", "cdk"),
        ("stripe", "stripe"),
        ("payment_intent", "stripe"),
        ("create_charge", "stripe"),
    ] {
        if blob.contains(needle) && !names.iter().any(|existing: &String| existing == name) {
            names.push(name.to_string());
        }
    }
    names
}

fn looks_like_database_url(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("postgres://")
        || value.contains("postgresql://")
        || value.contains("mysql://")
        || value.contains("mongodb://")
        || value.contains("mongodb+srv://")
        || value.contains("redis://")
}

fn langchain_tools(source: &str) -> Vec<ToolDecl> {
    if let Ok(root) = serde_json::from_str::<Value>(source) {
        if let Some(items) = root.get("tools").and_then(|v| v.as_array()) {
            let tools: Vec<ToolDecl> = items.iter().filter_map(tool_decl).collect();
            if !tools.is_empty() {
                return tools;
            }
        }
    }
    static NAME: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)(?:"name"|name)\s*[:=]\s*["']([^"']+)["']"#).unwrap());
    NAME.captures_iter(source)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .map(|name| ToolDecl {
            name,
            description: source.to_string(),
            approved: false,
        })
        .collect()
}

fn line_of(source: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 1;
    }
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|index| index + 1)
        .unwrap_or(1)
}

fn escape_label(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "'")
        .replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_mcp_remote_range_is_inclusive() {
        assert!(!mcp_remote_vulnerable("0.0.4"));
        assert!(mcp_remote_vulnerable("0.0.5"));
        assert!(mcp_remote_vulnerable("0.1.0"));
        assert!(mcp_remote_vulnerable("0.1.15"));
        assert!(!mcp_remote_vulnerable("0.1.16"));
        assert!(!mcp_remote_vulnerable("0.2.0"));
        assert!(!mcp_remote_vulnerable("latest"));
    }

    #[test]
    fn pinned_npx_spec_is_not_unpinned() {
        let pinned = parse_spec("@scope/pkg@1.2.3").unwrap();
        let loose = parse_spec("@scope/pkg").unwrap();
        let latest = parse_spec("postmark-mcp@latest").unwrap();
        assert!(unpinned_packages(&[pinned]).is_empty());
        assert_eq!(unpinned_packages(&[loose]).len(), 1);
        assert_eq!(unpinned_packages(&[latest]).len(), 1);
    }

    #[test]
    fn warp_mcp_json_is_not_labeled_claude_code() {
        let source = r#"{"mcpServers":{"local":{"command":"tracelamp","args":["mcp","serve"]}}}"#;
        let warp = scan(Path::new("/repo/.warp/.mcp.json"), source, "json");
        assert_eq!(warp.inventory.agents[0].name, "Warp");
        let claude = scan(Path::new("/repo/.mcp.json"), source, "json");
        assert_eq!(claude.inventory.agents[0].name, "Claude Code");
        let home = scan(Path::new("/home/dev/.warp/.mcp.json"), source, "json");
        assert_eq!(home.inventory.agents[0].name, "Warp");
    }

    #[test]
    fn remote_auth_headers_are_named_without_values() {
        let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let source = format!(
            r#"{{"mcpServers":{{"remote":{{"url":"https://example.invalid/mcp","headers":{{"Authorization":"Bearer {token}"}}}}}}}}"#
        );
        let scanned = scan(Path::new("/repo/.warp/.mcp.json"), &source, "json");
        let dumped = serde_json::to_string(&scanned.inventory).unwrap()
            + &scanned
                .findings
                .iter()
                .map(|finding| finding.snippet.clone())
                .collect::<String>();
        assert!(!dumped.contains(token), "{dumped}");
        let cred = &scanned.inventory.agents[0].servers[0].credentials[0];
        assert_eq!(cred.name, "Authorization");
        assert_eq!(cred.storage, "mcp-header");
        assert!(scanned
            .findings
            .iter()
            .any(|finding| finding.snippet == "header Authorization=***REDACTED***"));
    }

    fn rule_ids(scanned: &McpScan) -> Vec<&str> {
        scanned
            .findings
            .iter()
            .filter_map(|finding| finding.metadata.get("rule_id").map(String::as_str))
            .collect()
    }

    fn dumped(scanned: &McpScan) -> String {
        serde_json::to_string(&scanned.inventory).unwrap()
            + &scanned
                .findings
                .iter()
                .map(|finding| format!("{} {}", finding.snippet, finding.description))
                .collect::<String>()
    }

    #[test]
    fn stripe_secret_reference_and_charge_tool_spend_cloud_money() {
        let source = r#"{
            "mcpServers": {
                "billing": {
                    "command": "node",
                    "args": ["billing-server.js"],
                    "env": { "STRIPE_SECRET_KEY": "${STRIPE_SECRET_KEY}" },
                    "tools": [{
                        "name": "create_payment_intent",
                        "description": "Create a card charge"
                    }]
                }
            }
        }"#;
        let scanned = scan(Path::new("/repo/.mcp.json"), source, "json");
        let ids = rule_ids(&scanned);
        assert!(ids.contains(&rules::AGENT_CLOUD_SPEND), "{ids:?}");
        assert!(!ids.contains(&rules::MCP_SECRET_IN_ENV), "{ids:?}");
        let finding = scanned
            .findings
            .iter()
            .find(|finding| {
                finding.metadata.get("rule_id").map(String::as_str)
                    == Some(rules::AGENT_CLOUD_SPEND)
            })
            .unwrap();
        assert!(
            finding.snippet.contains("STRIPE_SECRET_KEY"),
            "{}",
            finding.snippet
        );
        assert!(
            finding.snippet.contains("create_payment_intent"),
            "{}",
            finding.snippet
        );
        assert!(finding.description.contains("azguard guard"));
        let server = &scanned.inventory.agents[0].servers[0];
        assert!(server
            .data_stores
            .iter()
            .any(|store| store.kind == "cloud" && store.name == "stripe"));
        assert!(server
            .credentials
            .iter()
            .any(|cred| cred.name == "STRIPE_SECRET_KEY" && cred.storage == "mcp-env"));
    }

    #[test]
    fn stripe_live_key_is_redacted_and_test_keys_do_not_spend() {
        let live = format!("sk_live_{}", "A".repeat(24));
        let restricted = format!("rk_live_{}", "B".repeat(24));
        let test_key = format!("sk_test_{}", "C".repeat(24));
        let publishable = format!("pk_live_{}", "D".repeat(24));
        let source = format!(
            r#"{{"mcpServers":{{"billing":{{"command":"node","args":["server.js","{live}"],"env":{{"BILLING":"{restricted}","TEST":"{test_key}","PUB":"{publishable}"}}}}}}}}"#
        );
        let scanned = scan(Path::new("/repo/.mcp.json"), &source, "json");
        let text = dumped(&scanned);
        assert!(!text.contains(&live), "{text}");
        assert!(!text.contains(&restricted), "{text}");
        let spend = scanned
            .findings
            .iter()
            .find(|finding| {
                finding.metadata.get("rule_id").map(String::as_str)
                    == Some(rules::AGENT_CLOUD_SPEND)
            })
            .unwrap();
        assert!(spend.snippet.contains("stripe live secret"));
        assert!(spend.snippet.contains("BILLING"));
        assert!(!spend.snippet.contains("TEST"));
        assert!(!spend.snippet.contains("PUB"));

        let quiet = format!(
            r#"{{"mcpServers":{{"web":{{"command":"node","args":["web.js"],"env":{{"STRIPE_PUBLISHABLE_KEY":"${{STRIPE_PUBLISHABLE_KEY}}","TEST":"{test_key}"}}}}}}}}"#
        );
        let quiet_scan = scan(Path::new("/repo/.mcp.json"), &quiet, "json");
        assert!(
            !rule_ids(&quiet_scan).contains(&rules::AGENT_CLOUD_SPEND),
            "{:?}",
            rule_ids(&quiet_scan)
        );
        assert!(!dumped(&quiet_scan).contains(&test_key));
    }

    #[test]
    fn stripe_cli_charge_spends_and_listen_does_not() {
        let charge = r#"{"mcpServers":{"billing":{"command":"stripe","args":["payment_intents","create","--amount","500"]}}}"#;
        let scanned = scan(Path::new("/repo/.mcp.json"), charge, "json");
        assert!(rule_ids(&scanned).contains(&rules::AGENT_CLOUD_SPEND));
        assert!(scanned.inventory.agents[0].servers[0]
            .data_stores
            .iter()
            .any(|store| store.name == "stripe"));

        let listen = r#"{"mcpServers":{"billing":{"command":"stripe","args":["listen","--forward-to","localhost:4242"]}}}"#;
        let scanned = scan(Path::new("/repo/.mcp.json"), listen, "json");
        assert!(!rule_ids(&scanned).contains(&rules::AGENT_CLOUD_SPEND));
    }

    #[test]
    fn stripe_live_header_is_cloud_spend_without_the_value() {
        let live = format!("sk_live_{}", "E".repeat(24));
        let source = format!(
            r#"{{"mcpServers":{{"billing":{{"url":"https://example.invalid/mcp","headers":{{"Authorization":"Bearer {live}"}}}}}}}}"#
        );
        let scanned = scan(Path::new("/repo/.mcp.json"), &source, "json");
        assert!(!dumped(&scanned).contains(&live));
        let ids = rule_ids(&scanned);
        assert!(ids.contains(&rules::AGENT_CLOUD_SPEND), "{ids:?}");
        assert!(ids.contains(&rules::MCP_SECRET_IN_ENV), "{ids:?}");
        let cred = &scanned.inventory.agents[0].servers[0].credentials[0];
        assert_eq!(cred.name, "Authorization");
        assert_eq!(cred.storage, "mcp-header");
    }
}
