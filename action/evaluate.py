#!/usr/bin/env python3
"""Apply fail-on to TraceLamp JSON and rewrite SARIF locations for code scanning.

The scanner prints paths that may be absolute or start with ``./``. GitHub code
scanning keeps results whose artifact URIs are relative to the workspace.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

RANKS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def is_absolute(path: str) -> bool:
    if path.startswith("/"):
        return True
    return len(path) > 2 and path[1] == ":" and path[2] == "/"


def strip_root(path: str, root: str) -> str | None:
    if not root:
        return None
    left, right = path, root.rstrip("/")
    if sys.platform.startswith("win"):
        left, right = left.lower(), right.lower()
    if left == right:
        return ""
    prefix = right + "/"
    if left.startswith(prefix):
        return path[len(prefix) :]
    return None


def clean_relative(path: str) -> str:
    text = path.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def normalize_uri(uri: str, workspace: str, scan_path: str) -> str:
    text = clean_relative(uri)
    if text.startswith("file://"):
        rest = text[len("file://") :]
        if rest.startswith("/"):
            text = rest
        else:
            slash = rest.find("/")
            text = rest[slash:] if slash != -1 else rest
        text = clean_relative(text)

    roots: list[str] = []
    workspace_root = workspace.replace("\\", "/").rstrip("/")
    if workspace_root and workspace_root != ".":
        roots.append(workspace_root)
    scan = scan_path.replace("\\", "/").strip()
    if scan and scan not in (".", "./"):
        if is_absolute(scan):
            roots.append(scan.rstrip("/"))
        elif workspace_root:
            roots.append(workspace_root + "/" + scan.lstrip("/"))

    if is_absolute(text):
        for root in roots:
            relative = strip_root(text, root)
            if relative:
                return clean_relative(relative)
        return text
    return text


def suspicious(uri: str) -> bool:
    if is_absolute(uri):
        return True
    return ".." in uri.split("/")


def rewrite_sarif(document: dict[str, Any], workspace: str, scan_path: str) -> list[str]:
    warnings: list[str] = []
    for run in document.get("runs") or []:
        for result in run.get("results") or []:
            for key in ("locations", "relatedLocations"):
                for location in result.get(key) or []:
                    physical = location.get("physicalLocation") or {}
                    artifact = physical.get("artifactLocation")
                    if not isinstance(artifact, dict) or "uri" not in artifact:
                        continue
                    original = str(artifact["uri"])
                    updated = normalize_uri(original, workspace, scan_path)
                    artifact["uri"] = updated
                    if suspicious(updated):
                        warnings.append(updated)
    return warnings


def blocking_findings(findings: list[dict[str, Any]], fail_on: str) -> list[dict[str, Any]]:
    if fail_on == "none":
        return []
    threshold = RANKS[fail_on]
    kept: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        rank = RANKS.get(severity)
        if rank is None or rank >= threshold:
            kept.append(finding)
    return kept


def evaluate(json_path: str, sarif_path: str, fail_on: str, workspace: str, scan_path: str, result_path: str) -> None:
    if fail_on not in RANKS and fail_on != "none":
        raise SystemExit("fail-on must be critical, high, medium, low, info, or none")

    with open(json_path, encoding="utf-8") as handle:
        document = json.load(handle)
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise SystemExit("scan JSON has no findings array")

    blocking = blocking_findings(findings, fail_on)
    for finding in blocking:
        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        rule_id = str(metadata.get("rule_id") or "")
        severity = str(finding.get("severity") or "unknown")
        location = f"{finding.get('file')}:{finding.get('line')}"
        title = str(finding.get("title") or "")
        label = f"{rule_id} " if rule_id else ""
        print(f"{severity}\t{label}{location}\t{title}", file=sys.stderr)

    with open(sarif_path, encoding="utf-8") as handle:
        sarif = json.load(handle)
    if sarif.get("version") != "2.1.0" or not isinstance(sarif.get("runs"), list):
        raise SystemExit("SARIF output is not a 2.1.0 document")
    warnings = rewrite_sarif(sarif, workspace, scan_path)
    for uri in warnings:
        print(f"warning: SARIF location is outside the workspace: {uri}", file=sys.stderr)
    with open(sarif_path, "w", encoding="utf-8") as handle:
        json.dump(sarif, handle, indent=2)
        handle.write("\n")

    result = {
        "finding_count": len(findings),
        "blocking_count": len(blocking),
        "should_fail": bool(blocking),
    }
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle)
        handle.write("\n")


def self_test() -> None:
    workspace = "/work/repo"
    assert normalize_uri("./.mcp.json", workspace, ".") == ".mcp.json"
    assert normalize_uri("tests\\fixtures\\a.py", workspace, ".") == "tests/fixtures/a.py"
    assert (
        normalize_uri("/work/repo/tests/fixtures/mcp/unpinned/.mcp.json", workspace, ".")
        == "tests/fixtures/mcp/unpinned/.mcp.json"
    )
    assert normalize_uri("file:///work/repo/src/main.rs", workspace, ".") == "src/main.rs"
    assert normalize_uri("/other/a.py", workspace, ".") == "/other/a.py"
    assert suspicious("/other/a.py")
    assert suspicious("foo/../../etc/passwd")
    assert not suspicious("tests/fixtures/a.py")

    findings = [
        {"severity": "info", "file": "a.py", "line": 1, "title": "agent"},
        {
            "severity": "high",
            "file": "a.py",
            "line": 2,
            "title": "unpinned",
            "metadata": {"rule_id": "recon/mcp-unpinned-package"},
        },
        {"severity": "weird", "file": "a.py", "line": 3, "title": "unknown"},
    ]
    assert len(blocking_findings(findings, "none")) == 0
    assert len(blocking_findings(findings, "critical")) == 1
    assert [item["severity"] for item in blocking_findings(findings, "high")] == ["high", "weird"]
    assert len(blocking_findings(findings, "info")) == 3
    assert blocking_findings([], "high") == []

    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"helpUri": "https://tracelamp.dev"}]}},
                "results": [
                    {
                        "ruleId": "recon/mcp-unpinned-package",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "/work/repo/pkg/.mcp.json"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    warnings = rewrite_sarif(sarif, workspace, ".")
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "pkg/.mcp.json", uri
    assert warnings == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"] == "https://tracelamp.dev"
    print("evaluate.py self-test ok")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", required=True)
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--fail-on", required=True)
    parser.add_argument("--workspace", default="")
    parser.add_argument("--scan-path", default=".")
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    evaluate(args.json, args.sarif, args.fail_on.lower(), args.workspace, args.scan_path, args.result)


if __name__ == "__main__":
    main()
