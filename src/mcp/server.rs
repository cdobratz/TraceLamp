//! TraceLamp as an MCP server.
//!
//! stdio and streamable HTTP both call the static scanner. `tracelamp scan` does
//! not start either server.

use super::tools;
use crate::config::TraceLampConfig;
use anyhow::{Context, Result};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct TraceLampMcp {
    config: TraceLampConfig,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PathParams {
    /// Repository path to read.
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListParams {
    /// Repository path to read.
    path: String,
    /// Keep findings of this severity only.
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ExplainParams {
    /// Stable rule id, for example recon/shell-execution. The `recon/` prefix is unchanged.
    rule_id: String,
}

#[tool_router]
impl TraceLampMcp {
    #[tool(
        description = "Statically scan a directory inside the configured scan root. Does not execute code or open network connections."
    )]
    async fn scan_repo(
        &self,
        Parameters(PathParams { path }): Parameters<PathParams>,
    ) -> Result<String, String> {
        json_tool(tools::scan_repo(&self.config, &path).await)
    }

    #[tool(
        description = "List static findings inside the configured scan root, optionally filtered by severity."
    )]
    async fn list_findings(
        &self,
        Parameters(ListParams { path, severity }): Parameters<ListParams>,
    ) -> Result<String, String> {
        json_tool(tools::list_findings(&self.config, &path, severity.as_deref()).await)
    }

    #[tool(description = "Explain one TraceLamp rule id: help text, ASI mapping, and remediation.")]
    fn explain_finding(
        &self,
        Parameters(ExplainParams { rule_id }): Parameters<ExplainParams>,
    ) -> String {
        serde_json::to_string_pretty(&tools::explain_finding(&rule_id))
            .unwrap_or_else(|err| json!({"error": err.to_string()}).to_string())
    }

    #[tool(
        description = "Return the agent, MCP server, tool, data store, and credential inventory for a directory inside the configured scan root. Header values are not included."
    )]
    async fn agent_inventory(
        &self,
        Parameters(PathParams { path }): Parameters<PathParams>,
    ) -> Result<String, String> {
        json_tool(tools::agent_inventory(&self.config, &path).await)
    }
}

#[tool_handler(
    name = "tracelamp",
    instructions = "Static TraceLamp scanner. Tools read files only. They do not spawn processes or open network connections."
)]
impl ServerHandler for TraceLampMcp {}

fn json_tool(result: Result<serde_json::Value>) -> Result<String, String> {
    match result {
        Ok(value) => serde_json::to_string_pretty(&value).map_err(|err| err.to_string()),
        Err(err) => Err(err.to_string()),
    }
}

/// Serve MCP over stdin and stdout. Log lines go to stderr so they stay off the protocol stream.
pub async fn serve_stdio(config: &TraceLampConfig) -> Result<()> {
    eprintln!("tracelamp mcp server (stdio)");
    let running = TraceLampMcp {
        config: config.clone(),
    }
    .serve(rmcp::transport::stdio())
    .await
    .map_err(|err| anyhow::anyhow!("mcp serve: {err}"))?;
    running
        .waiting()
        .await
        .map_err(|err| anyhow::anyhow!("mcp serve: {err}"))?;
    Ok(())
}

/// Loopback only. This transport has no authentication.
const HTTP_BIND_HOST: &str = "127.0.0.1";

/// Serve MCP at `http://127.0.0.1:<port>/mcp` until Ctrl-C.
pub async fn serve_http(port: u16, config: &TraceLampConfig) -> Result<()> {
    let listener = TcpListener::bind((HTTP_BIND_HOST, port))
        .await
        .with_context(|| format!("bind {HTTP_BIND_HOST}:{port}"))?;
    let ct = CancellationToken::new();
    let shutdown = ct.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown.cancel();
    });
    serve_on(listener, config, ct).await?;
    Ok(())
}

/// Serve an already-bound listener until `shutdown` is cancelled.
pub async fn serve_on(
    listener: TcpListener,
    config: &TraceLampConfig,
    shutdown: CancellationToken,
) -> Result<SocketAddr> {
    let addr = listener
        .local_addr()
        .context("read MCP HTTP listen address")?;
    eprintln!("tracelamp mcp server (http) http://{addr}/mcp");
    let recon = config.clone();
    let http_config = StreamableHttpServerConfig::default()
        .with_cancellation_token(shutdown.clone())
        .with_allowed_hosts(["localhost", "127.0.0.1", "::1"]);
    let service = StreamableHttpService::new(
        move || {
            Ok(TraceLampMcp {
                config: recon.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        http_config,
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("mcp http server")?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::CallToolRequestParams;
    use rmcp::transport::StreamableHttpClientTransport;
    use rmcp::ServiceExt;

    #[test]
    fn http_bind_host_is_ipv4_loopback() {
        let addr: SocketAddr = format!("{HTTP_BIND_HOST}:3000").parse().unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn http_server_lists_and_explains_a_rule() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let config = TraceLampConfig::default();
        let server_shutdown = shutdown.clone();
        let server = tokio::spawn(async move {
            serve_on(listener, &config, server_shutdown).await.unwrap();
        });

        let url = format!("http://{addr}/mcp");
        let client = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match ().serve(StreamableHttpClientTransport::from_uri(url.clone())).await {
                    Ok(client) => return client,
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
                }
            }
        })
        .await
        .expect("http mcp server accepts a client");

        let info = client.peer_info().expect("server info");
        let implementation = info.server_info.as_ref().expect("server implementation");
        assert_eq!(implementation.name, "tracelamp");

        let tools = client.list_all_tools().await.unwrap();
        let names: Vec<_> = tools.iter().map(|tool| tool.name.to_string()).collect();
        for expected in [
            "scan_repo",
            "list_findings",
            "explain_finding",
            "agent_inventory",
        ] {
            assert!(names.iter().any(|name| name == expected), "{names:?}");
        }

        let arguments = serde_json::json!({"rule_id": "recon/shell-execution"});
        let result = client
            .call_tool(
                CallToolRequestParams::new("explain_finding")
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_ne!(result.is_error, Some(true), "{result:?}");
        let text: String = result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|text| text.text.as_str()))
            .collect();
        assert!(text.contains("db.Exec"), "{text}");

        drop(client);
        shutdown.cancel();
        server.await.unwrap();
    }
}
