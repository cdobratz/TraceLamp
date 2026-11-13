//! Fixtures for tree-sitter detection, ignores, suppressions, and baselines.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn scan(root: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tracelamp"))
        .arg("scan")
        .arg(root)
        .arg("--format")
        .arg("json")
        .args(extra)
        .output()
        .expect("run recon")
}

fn parse_scan(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "json ({err})\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn project(root: &Path, value: &Value) -> Vec<Value> {
    let mut rows = Vec::new();
    for finding in value["findings"].as_array().expect("findings") {
        let file = finding["file"].as_str().expect("file");
        let rel = Path::new(file)
            .strip_prefix(root)
            .unwrap_or_else(|_| Path::new(file));
        rows.push((
            rel.to_string_lossy().replace('\\', "/"),
            finding["line"].as_u64().unwrap_or(0),
            finding["category"].as_str().unwrap_or("").to_string(),
            finding["severity"].as_str().unwrap_or("").to_string(),
            finding["title"].as_str().unwrap_or("").to_string(),
            finding["snippet"].as_str().unwrap_or("").to_string(),
            finding["metadata"]["rule_id"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            finding["metadata"]["detector"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        ));
    }
    rows.sort();
    rows.into_iter()
        .map(
            |(file, line, category, severity, title, snippet, rule_id, detector)| {
                json!({
                    "file": file,
                    "line": line,
                    "category": category,
                    "severity": severity,
                    "title": title,
                    "snippet": snippet,
                    "rule_id": rule_id,
                    "detector": detector,
                })
            },
        )
        .collect()
}

fn shell_is_clean(findings: &[Value]) {
    for finding in findings {
        if finding["rule_id"] != "recon/shell-execution" {
            continue;
        }
        let snippet = finding["snippet"].as_str().unwrap_or("");
        assert!(
            !snippet.contains(".Exec(")
                && !snippet.contains(".exec(")
                && !snippet.contains("re.exec"),
            "database or regex exec flagged as shell: {snippet}"
        );
    }
}

#[test]
fn language_fixtures_match_snapshots() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for lang in ["python", "javascript", "typescript", "go", "rust"] {
        let dir = root.join(lang);
        let output = scan(&dir, &[]);
        assert!(
            output.status.success(),
            "{lang}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = parse_scan(&output);
        let findings = project(&dir, &value);
        assert!(
            findings
                .iter()
                .any(|f| f["category"] == "function" && f["detector"] == "ast"),
            "{lang} missing an AST function: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f["category"] == "api_endpoint" && f["detector"] == "ast"),
            "{lang} missing an AST endpoint: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f["rule_id"] == "recon/shell-execution" && f["detector"] == "ast"),
            "{lang} missing an AST shell call: {findings:?}"
        );
        shell_is_clean(&findings);
        insta::assert_json_snapshot!(lang, findings);
    }
}

#[test]
fn regex_fallback_for_other_languages() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (name, rel) in [("java", "java"), ("graphql", "other")] {
        let dir = root.join(rel);
        let output = scan(&dir, &[]);
        assert!(output.status.success(), "{name}");
        let findings = project(&dir, &parse_scan(&output));
        assert!(!findings.is_empty(), "{name}");
        assert!(
            findings.iter().all(|f| f["detector"] == "regex"),
            "{name} should stay on the regex fallback: {findings:?}"
        );
        insta::assert_json_snapshot!(name, findings);
    }
}

#[test]
fn ignore_fixture_skips_default_dirs_gitignore_and_binaries() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ignore");
    let output = scan(&dir, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_scan(&output);
    let findings = project(&dir, &value);
    assert_eq!(
        value["files_scanned"].as_u64().unwrap(),
        5,
        "scanned files changed: {findings:?}\n{value}"
    );
    let files: Vec<&str> = findings
        .iter()
        .map(|f| f["file"].as_str().unwrap())
        .collect();
    assert!(files.contains(&"kept.py"), "{files:?}");
    assert!(files.contains(&"keep.gen.py"), "{files:?}");
    for file in &files {
        assert!(
            !file.contains("node_modules")
                && !file.contains("dist/")
                && !file.contains("vendor/")
                && !file.contains("target/")
                && !file.contains(".go/")
                && *file != "skip.gen.py"
                && *file != "local_skip.py"
                && *file != "photo.png"
                && *file != "binary.exe"
                && *file != "weird.txt",
            "{file}"
        );
    }
    insta::assert_json_snapshot!(findings);
}

#[test]
fn suppression_fixture_matches_snapshot() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/suppress");
    let output = scan(&dir, &[]);
    assert!(output.status.success());
    let findings = project(&dir, &parse_scan(&output));
    let shells: Vec<&Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "recon/shell-execution")
        .collect();
    assert_eq!(shells.len(), 3, "{findings:?}");
    assert!(shells
        .iter()
        .any(|f| f["file"] == "previous.py" && f["snippet"] == "os.system(\"whoami\")"));
    assert!(shells
        .iter()
        .any(|f| f["file"] == "same_line.js" && f["snippet"] == "exec(\"ls\");"));
    assert!(shells
        .iter()
        .any(|f| f["file"] == "previous.go" && f["snippet"].as_str().unwrap().contains("aws")));
    assert!(!findings
        .iter()
        .any(|f| f["file"] == "hash_comment.py" && f["rule_id"] == "recon/shell-execution"));
    insta::assert_json_snapshot!(findings);
}

#[test]
fn baseline_reports_only_new_findings() {
    let dir = tempfile::tempdir().unwrap();
    let source =
        "package main\nimport \"os/exec\"\nfunc main() {\n\texec.Command(\"az\").Run()\n}\n";
    std::fs::write(dir.path().join("main.go"), source).unwrap();
    let baseline = dir.path().join("baseline.json");

    let written = scan(
        dir.path(),
        &["--write-baseline", baseline.to_str().unwrap()],
    );
    assert!(
        written.status.success(),
        "write-baseline should not fail the scan\n{}",
        String::from_utf8_lossy(&written.stderr)
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(doc["version"], 1);
    assert!(doc["fingerprints"].as_array().unwrap().iter().any(|entry| {
        entry["path"] == "main.go" && entry["rule_id"] == "recon/shell-execution"
    }));
    insta::assert_json_snapshot!("baseline_file", doc);

    let clean = scan(dir.path(), &["--baseline", baseline.to_str().unwrap()]);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(parse_scan(&clean)["findings"]
        .as_array()
        .unwrap()
        .is_empty());

    let shifted = format!("\n\n{source}");
    std::fs::write(dir.path().join("main.go"), shifted).unwrap();
    let moved = scan(dir.path(), &["--baseline", baseline.to_str().unwrap()]);
    assert!(
        moved.status.success(),
        "line shift should stay baselined\n{}",
        String::from_utf8_lossy(&moved.stderr)
    );
    assert!(parse_scan(&moved)["findings"]
        .as_array()
        .unwrap()
        .is_empty());

    let updated = format!("{source}func extra() {{\n\texec.Command(\"aws\").Run()\n}}\n");
    std::fs::write(dir.path().join("main.go"), updated).unwrap();
    let fresh = scan(dir.path(), &["--baseline", baseline.to_str().unwrap()]);
    assert!(!fresh.status.success(), "new findings should fail CI");
    let findings = project(dir.path(), &parse_scan(&fresh));
    assert!(findings
        .iter()
        .any(|f| f["snippet"].as_str().unwrap().contains("aws")));
    assert!(!findings
        .iter()
        .any(|f| f["snippet"].as_str().unwrap().contains("\"az\"")));
    insta::assert_json_snapshot!("baseline_new", findings);
}

#[test]
fn cli_ignore_and_large_binary_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("kept.go"),
        "package p\nfunc main() { exec.Command(\"az\").Run() }\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("skip.go"),
        "package p\nfunc main() { exec.Command(\"aws\").Run() }\n",
    )
    .unwrap();
    let ignored = scan(dir.path(), &["--ignore", "skip.go"]);
    assert!(ignored.status.success());
    let findings = project(dir.path(), &parse_scan(&ignored));
    assert!(findings
        .iter()
        .any(|f| f["file"] == "kept.go" && f["rule_id"] == "recon/shell-execution"));
    assert!(findings.iter().all(|f| f["file"] != "skip.go"));

    let big_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        big_dir.path().join("ok.py"),
        "import os\nos.system(\"ls\")\n",
    )
    .unwrap();
    let mut big = b"import os\nos.system(\"rm\")\n".to_vec();
    big.resize(1_048_577, b'x');
    std::fs::write(big_dir.path().join("big.py"), big).unwrap();
    std::fs::write(big_dir.path().join("blob.bin"), b"os.system(\"rm\")\0").unwrap();
    std::fs::create_dir_all(big_dir.path().join(".git")).unwrap();
    std::fs::write(big_dir.path().join(".git/config"), "exec.Command(\"az\")\n").unwrap();
    let output = scan(big_dir.path(), &[]);
    assert!(output.status.success());
    let value = parse_scan(&output);
    assert_eq!(value["files_scanned"].as_u64().unwrap(), 1);
    let findings = project(big_dir.path(), &value);
    assert!(findings.iter().all(|f| f["file"] == "ok.py"));
}

#[test]
fn cyclonedx_exports_agent_inventory() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/graph/chain");
    let output = Command::new(env!("CARGO_BIN_EXE_tracelamp"))
        .args(["scan", dir.to_str().unwrap(), "--format", "cyclonedx"])
        .output()
        .expect("cyclonedx scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("json ({err}): {}", String::from_utf8_lossy(&output.stdout)));
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["specVersion"], "1.6");
    assert_eq!(doc["version"], 1);
    assert_eq!(
        doc["metadata"]["tools"]["components"][0]["name"],
        "tracelamp"
    );
    let raw = String::from_utf8(output.stdout.clone()).expect("utf-8");
    assert!(
        !raw.contains("local-mcp-token-abcdefghij"),
        "cyclonedx included a credential value"
    );
    assert_eq!(doc["metadata"]["component"]["type"], "application");
    assert_eq!(doc["metadata"]["component"]["bom-ref"], "tracelamp-scan");
    let components = doc["components"].as_array().unwrap();
    let names: Vec<&str> = components
        .iter()
        .filter_map(|component| component["name"].as_str())
        .collect();
    for required in ["Claude Code", "filesystem", "read_file", "/", "API_TOKEN"] {
        assert!(names.contains(&required), "missing {required} in {names:?}");
    }
    let filesystem = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"] == "filesystem")
        .unwrap();
    assert_eq!(filesystem["type"], "library");
    let cred = components
        .iter()
        .find(|component| component["name"] == "API_TOKEN")
        .unwrap();
    assert_eq!(cred["type"], "cryptographic-asset");
    assert_eq!(cred["properties"][0]["value"], "credential");

    let agent = components
        .iter()
        .find(|component| component["name"] == "Claude Code")
        .unwrap();
    assert_eq!(agent["type"], "application");
    assert_eq!(agent["properties"][0]["value"], "agent");
    let tool = components
        .iter()
        .find(|component| component["name"] == "read_file")
        .unwrap();
    assert_eq!(tool["type"], "library");
    assert_eq!(tool["properties"][0]["value"], "tool");
    let store = components
        .iter()
        .find(|component| component["name"] == "/")
        .unwrap();
    assert_eq!(store["type"], "data");
    assert_eq!(store["properties"][0]["value"], "data-store");

    let refs: Vec<&str> = components
        .iter()
        .filter_map(|component| component["bom-ref"].as_str())
        .collect();
    let deps = doc["dependencies"].as_array().expect("dependencies");
    let root = deps
        .iter()
        .find(|dep| dep["ref"] == "tracelamp-scan")
        .expect("scan root dependency");
    assert!(root["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .any(|child| child == &agent["bom-ref"]));
    let server_dep = deps
        .iter()
        .find(|dep| dep["ref"] == filesystem["bom-ref"])
        .expect("server dependency");
    let server_deps = server_dep["dependsOn"].as_array().unwrap();
    for component in [tool, store, cred] {
        assert!(
            server_deps
                .iter()
                .any(|child| child == &component["bom-ref"]),
            "missing dependency {}",
            component["name"]
        );
    }
    for dep in deps {
        let parent = dep["ref"].as_str().unwrap();
        assert!(
            parent == "tracelamp-scan" || refs.contains(&parent),
            "{parent}"
        );
        for child in dep["dependsOn"].as_array().unwrap() {
            let child = child.as_str().unwrap();
            assert!(refs.contains(&child), "{child}");
        }
    }
}
