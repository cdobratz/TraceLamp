//! Precision and recall for the shell, MCP, and cloud-spend rule pack.

use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const RULES: &[&str] = &[
    "recon/shell-execution",
    "recon/mcp-unpinned-package",
    "recon/mcp-remote-cve-2025-6514",
    "recon/mcp-secret-in-env",
    "recon/mcp-filesystem-root",
    "recon/mcp-shell-without-approval",
    "recon/agent-cloud-spend",
];

#[test]
fn fixture_rule_pack_precision_and_recall() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let expected_doc: Value =
        serde_json::from_str(include_str!("fixtures/expected.json")).expect("expected.json");
    let expected_map = expected_doc["files"].as_object().expect("files");

    let value = scan_json(&root);
    let mut actual: HashMap<String, Vec<String>> = HashMap::new();
    for finding in value["findings"].as_array().expect("findings") {
        let Some(rule) = finding["metadata"]["rule_id"].as_str() else {
            continue;
        };
        if !RULES.contains(&rule) {
            continue;
        }
        let file = finding["file"].as_str().expect("file");
        let rel = Path::new(file)
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("finding outside fixtures: {file}"))
            .to_string_lossy()
            .replace('\\', "/");
        actual.entry(rel).or_default().push(rule.to_string());
    }

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_ = 0usize;
    let mut mismatches = Vec::new();

    for (rel, expected_rules) in expected_map {
        let expected: Vec<String> = expected_rules
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let got = actual.remove(rel).unwrap_or_default();
        let (file_tp, file_fp, file_fn) = multiset_delta(&expected, &got);
        tp += file_tp;
        fp += file_fp;
        fn_ += file_fn;
        if file_fp > 0 || file_fn > 0 {
            mismatches.push(format!("{rel}: expected {expected:?} got {got:?}"));
        }
    }
    for (rel, got) in &actual {
        fp += got.len();
        mismatches.push(format!("{rel}: unexpected {got:?}"));
    }

    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + fn_ == 0 {
        1.0
    } else {
        tp as f64 / (tp + fn_) as f64
    };
    println!(
        "fixture rule pack precision={precision:.3} recall={recall:.3} tp={tp} fp={fp} fn={fn_}"
    );
    assert!(
        mismatches.is_empty(),
        "fixture mismatches:\n{}",
        mismatches.join("\n")
    );
    assert_eq!(fp, 0);
    assert_eq!(fn_, 0);

    assert_pinned_npx_is_clean(&value, &root);
    assert_cloud_fixtures_link_azguard(&value, &root);
    assert_inventory_graph(&value);
}

fn assert_pinned_npx_is_clean(value: &Value, root: &Path) {
    let pinned = root.join("mcp/pinned/.mcp.json");
    let hits: Vec<_> = rule_findings(value, &pinned, "recon/mcp-unpinned-package");
    assert!(
        hits.is_empty(),
        "pinned npx package triggered unpinned: {hits:?}"
    );
}

fn assert_cloud_fixtures_link_azguard(value: &Value, root: &Path) {
    for rel in [
        "cloud/claude-code/.mcp.json",
        "cloud/cursor/.cursor/mcp.json",
        "cloud/langchain/langchain_tools.json",
        "cloud/stripe/.mcp.json",
    ] {
        let path = root.join(rel);
        let hits = rule_findings(value, &path, "recon/agent-cloud-spend");
        assert_eq!(hits.len(), 1, "{rel} cloud findings: {hits:?}");
        let text = format!("{} {}", hits[0]["description"], hits[0]["metadata"]);
        assert!(
            text.contains("azguard guard"),
            "{rel} missing azguard guard remediation: {text}"
        );
        assert!(
            text.contains("https://github.com/cdobratz/AzGuard#agent-guard"),
            "{rel} missing AzGuard link: {text}"
        );
    }
}

fn assert_inventory_graph(value: &Value) {
    let agents = value["inventory"]["agents"].as_array().expect("agents");
    let names: Vec<&str> = agents
        .iter()
        .filter_map(|agent| agent["name"].as_str())
        .collect();
    for required in [
        "Claude Code",
        "Cursor",
        "VS Code",
        "Claude Desktop",
        "MCP client",
        "LangChain",
    ] {
        assert!(
            names.contains(&required),
            "missing agent {required} in {names:?}"
        );
    }

    let chain = agents
        .iter()
        .find(|agent| {
            agent["source"]
                .as_str()
                .unwrap_or("")
                .ends_with("graph/chain/.mcp.json")
        })
        .expect("chain inventory");
    assert_eq!(chain["name"], "Claude Code");
    let server = &chain["servers"][0];
    assert_eq!(server["name"], "filesystem");
    let tools = server["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "read_file"));
    let stores = server["data_stores"].as_array().unwrap();
    assert!(stores
        .iter()
        .any(|store| store["kind"] == "filesystem" && store["name"] == "/"));
    let creds = server["credentials"].as_array().unwrap();
    assert!(creds.iter().any(|cred| cred["name"] == "API_TOKEN"));

    let mermaid = value["inventory_mermaid"].as_str().unwrap_or("");
    assert!(mermaid.contains("flowchart LR"), "{mermaid}");
    assert!(mermaid.contains("Claude Code"), "{mermaid}");
    assert!(mermaid.contains("filesystem"), "{mermaid}");
    assert!(mermaid.contains("API_TOKEN"), "{mermaid}");

    let chain_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/graph/chain");
    let output = Command::new(env!("CARGO_BIN_EXE_tracelamp"))
        .args(["scan", chain_dir.to_str().unwrap(), "--format", "mermaid"])
        .output()
        .expect("mermaid scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("flowchart LR"), "{text}");
    assert!(text.contains("API_TOKEN"), "{text}");
}

fn rule_findings<'a>(value: &'a Value, path: &Path, rule: &str) -> Vec<&'a Value> {
    value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| {
            finding["metadata"]["rule_id"] == rule
                && finding["file"].as_str().unwrap_or("") == path.to_string_lossy()
        })
        .collect()
}

fn scan_json(root: &Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_tracelamp"))
        .args(["scan", root.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("run recon");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "json parse ({err}):\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn multiset_delta(expected: &[String], actual: &[String]) -> (usize, usize, usize) {
    let mut actual = actual.to_vec();
    let mut tp = 0;
    let mut fn_ = 0;
    for rule in expected {
        if let Some(pos) = actual.iter().position(|item| item == rule) {
            actual.remove(pos);
            tp += 1;
        } else {
            fn_ += 1;
        }
    }
    (tp, actual.len(), fn_)
}
