# TraceLamp

[![CI](https://github.com/cdobratz/TraceLamp/actions/workflows/ci.yml/badge.svg)](https://github.com/cdobratz/TraceLamp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Static, no-execute scanner for what AI agents and MCP servers can touch: tools, data stores, credentials, and cloud spend. A scan is **static, no-execute, and CI-safe**. It never spawns processes and never opens network connections, so it can run on untrusted pull requests without a sandbox.

TraceLamp does not start MCP servers to read their tool lists. Config files are parsed as text.

The command is `tracelamp`. Documentation and examples below use that name. See [Compatibility](#compatibility) for the `recon` command and the older config and ignore filenames.

## Implemented / Planned

| Area | Status |
|---|---|
| `tracelamp scan` for API endpoints, functions, DB connections, agents, and secrets | Implemented |
| Terminal, JSON, and SARIF 2.1.0 output | Implemented |
| Shell vs database call precision (`exec.Command` is shell, `db.Exec` is not) | Implemented |
| Static, no-execute, CI-safe scan | Implemented |
| Agent/MCP config inventory (JSON + Mermaid) | Implemented |
| MCP rules (unpinned npx/uvx, mcp-remote CVE-2025-6514, secrets in env, filesystem `/` or `~`, shell without approval) | Implemented |
| "Agent can spend cloud money" rule (cloud credentials, cloud CLIs, IaC apply, Stripe live secret keys), with remediation pointing at AzGuard | Implemented |
| Tree-sitter queries for Python, JavaScript, TypeScript, Go, and Rust (functions, API endpoints, shell vs database calls) | Implemented |
| Regex fallback for other languages | Implemented |
| Default ignores, `.gitignore`, `.tracelampignore`, and `.reconignore` | Implemented |
| Inline `tracelamp:ignore` suppressions (and `recon:ignore`) and a baseline file | Implemented |
| CycloneDX 1.6 AI-BOM export (`--format cyclonedx`) | Implemented |
| GitHub Actions CI (`cargo fmt --check`, build, test, clippy) | Implemented |
| GitHub Action (`action/`): release archive, `SHA256SUMS`, SARIF upload, baseline, fail-on severity | Implemented |
| Opt-in LLM analysis (`tracelamp analyze --llm`, local Ollama by default, hosted OpenAI and Anthropic) | Implemented |
| MCP server (`tracelamp mcp serve`, stdio and streamable HTTP) with `scan_repo`, `list_findings`, `explain_finding`, `agent_inventory` | Implemented |
| MCP client (`tracelamp mcp connect` for a stdio command or an http(s) URL) | Implemented |
| Skills (`tracelamp skill run`) and agent workflows (`tracelamp agent run`) | Implemented |

## Static scan guarantee

`tracelamp scan` and `tracelamp report` only read files under the path you pass. They do not:

- spawn `npx`, `uvx`, shells, or any other process
- connect to MCP server URLs, package registries, or LLM APIs

The check is `tests/static_scan.rs`. It runs `scan` and `analyze` (without `--llm`) under `strace` and fails if the process calls `execve` (other than the scanner itself) or a network syscall.

`tracelamp analyze --llm` is opt-in. It sends findings and short snippets to the model, never whole files, and stops when the estimated cost would pass `llm.max_cost_usd` (0.25 by default). The default provider is local Ollama (`llama3.2` at `http://localhost:11434`, or `OLLAMA_HOST`). `--provider openai` uses `OPENAI_API_KEY` and `--provider anthropic` uses `ANTHROPIC_API_KEY`. Ollama is priced at zero, so it always fits the cap.

`tracelamp mcp serve` speaks MCP over stdio. `tracelamp mcp serve --transport http --port 3000` listens on `127.0.0.1:3000` and serves the same tools at `/mcp` (streamable HTTP). The listener is loopback only and has no authentication. The accepted hosts are `localhost`, `127.0.0.1`, and `::1`. The MCP server name is `tracelamp`. `tracelamp mcp connect` either spawns a stdio command or opens an `http://` / `https://` endpoint. Neither path is used by `scan`.

```bash
tracelamp scan <path>
tracelamp scan <path> --format json
tracelamp scan <path> --format sarif
tracelamp scan <path> --format mermaid
tracelamp scan <path> --format cyclonedx
tracelamp scan <path> --write-baseline tracelamp-baseline.json
tracelamp scan <path> --baseline tracelamp-baseline.json
tracelamp report <path> --format sarif
tracelamp analyze <path>
tracelamp analyze <path> --llm
tracelamp analyze <path> --llm --provider openai --max-cost 0.25
tracelamp mcp serve
tracelamp mcp serve --transport http --port 3000
tracelamp mcp connect "tracelamp mcp serve"
tracelamp mcp connect http://127.0.0.1:3000/mcp
```

JSON output includes `inventory` (agent → MCP server/tool → data store → credential) and `inventory_mermaid`. `--format mermaid` prints only the diagram. `--format cyclonedx` prints a CycloneDX 1.6 JSON document of that inventory (agents, MCP servers, tools, data stores, credentials). Credential values are omitted. SARIF output names the tool driver `tracelamp` and sets `informationUri` to `https://tracelamp.dev`.

`--baseline` prints only findings whose fingerprint is not already in the file and exits 1 when any remain, so CI fails on new findings. `--write-baseline` records the current findings and does not fail the run. A fingerprint is the SHA-256 of the rule id, the path relative to the scan root, and the snippet with whitespace collapsed. Line numbers are not part of it.

Suppress a finding by putting `tracelamp:ignore <rule-id>` on the same line or the previous line. `recon:ignore <rule-id>` still works. `//`, `#`, and `/* */` comments all work. Several rule ids can be separated by spaces or commas.

## Rules

Each rule has a stable id, help text, an [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ASI mapping, and a SARIF `tool.driver.rules[]` entry. Rule ids keep the `recon/` prefix so existing baselines, suppressions, and SARIF results stay valid.

| Rule ID | ASI | What it flags |
|---|---|---|
| `recon/shell-execution` | ASI05 | Real process spawns (`exec.Command`, `subprocess`, `os.system`, `child_process`). Not `db.Exec`. |
| `recon/mcp-unpinned-package` | ASI04 | `npx` / `uvx` package with no exact version. `pkg@1.2.3` and `pkg==1.2.3` do not match. |
| `recon/mcp-remote-cve-2025-6514` | ASI05 | `mcp-remote` versions 0.0.5 through 0.1.15 (CVE-2025-6514). |
| `recon/mcp-secret-in-env` | ASI03 | Literal secret in an MCP `env` value. `${VAR}` references do not match. |
| `recon/mcp-filesystem-root` | ASI02 | Filesystem root set to `/` or `~`. |
| `recon/mcp-shell-without-approval` | ASI02, ASI05 | Shell or exec tool with no approval flag. |
| `recon/agent-cloud-spend` | ASI02 | Agent or MCP server with cloud credentials, a cloud CLI / IaC apply, a cloud write tool, or a Stripe live secret key (`STRIPE_SECRET_KEY`, `STRIPE_API_KEY`, `STRIPE_RESTRICTED_KEY`, `sk_live_` / `rk_live_`, or a charge command). Remediation: least privilege and [`azguard guard`](https://github.com/cdobratz/AzGuard#agent-guard). |

Configs read for the inventory: `mcp.json`, `.mcp.json`, `.warp/.mcp.json` (Warp), `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, and LangChain tool lists. A project `.mcp.json` that is not under `.warp/` stays attributed to Claude Code.

## Compatibility

These aliases keep existing setups working:

| Current | Still accepted |
|---|---|
| `tracelamp` command | `recon` command (same CLI, installed as a second binary) |
| `~/.config/tracelamp/config.toml` | `~/.config/recon/config.toml`, used when the TraceLamp file is absent |
| `.tracelampignore` | `.reconignore` |
| `tracelamp:ignore <rule-id>` | `recon:ignore <rule-id>` |

`tracelamp config init` creates `~/.config/tracelamp/config.toml` when neither file exists. If only the Recon file exists, init and `config set` keep using that file instead of shadowing it with a new one. When both exist, the TraceLamp file wins.

There is no `RECON_` prefix. `TRACELAMP_SCAN_ROOT` is the approved directory for `tracelamp mcp serve` when `mcp.scan_root` is unset. Provider variables stay `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `OLLAMA_HOST`. Log filters follow the crate name, for example `RUST_LOG=tracelamp=debug`.

Warp setup, including the stdio command and the local HTTP listener's lack of authentication, is in [docs/warp.md](docs/warp.md).

Rule ids (`recon/shell-execution` and the rest) are unchanged.

## Build

HTTP uses `reqwest` with `rustls-tls` (no OpenSSL / `libssl-dev`).

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

Default ignores include `.git`, `node_modules`, `target`, `vendor`, `dist`, `build`, `__pycache__`, `.venv`, and `.go` (a vendored Go toolchain). The walk also honors `.gitignore`, `.tracelampignore`, and `.reconignore` (gitignore syntax) and skips binary files (known extensions or a NUL byte) and files larger than `max_file_size` (1 MiB by default). Hidden paths such as `.cursor/mcp.json` are still scanned.

## Project structure

```
tracelamp/
├── Cargo.toml
├── LICENSE
├── NOTICE
├── src/
│   ├── lib.rs
│   ├── main.rs           # tracelamp command
│   ├── bin/recon.rs      # recon command alias
│   ├── config.rs
│   ├── scanner/          # in-process scanners, MCP inventory, rules
│   ├── analysis/         # rule-based scores; optional LLM pass
│   ├── parsers/          # tree-sitter parsers; regex fallback for other languages
│   ├── llm/              # Ollama, OpenAI, and Anthropic (only with --llm)
│   ├── mcp/              # stdio and streamable HTTP MCP server and client
│   ├── skills/
│   ├── agents/
│   └── report/           # terminal, JSON, SARIF, Mermaid, CycloneDX
├── action/               # composite GitHub Action
├── queries/              # tree-sitter .scm queries, one file per language
├── config/default.toml
└── tests/fixtures/       # rule fixtures, language corpus, and expected results
```

## CLI

```
tracelamp scan <path>
tracelamp scan <path> --format json
tracelamp scan <path> --format cyclonedx
tracelamp scan <path> --write-baseline tracelamp-baseline.json
tracelamp scan <path> --baseline tracelamp-baseline.json
tracelamp scan <path> --only agents,mcp
tracelamp analyze <path>
tracelamp analyze <path> --llm
tracelamp report <path> --format sarif
tracelamp skill add ./todo.toml
tracelamp skill run todo --target <path>
tracelamp agent run reviewer --target <path>
tracelamp agent run reviewer --target <path> --llm
tracelamp mcp serve
tracelamp mcp serve --transport http --port 3000
tracelamp mcp connect "tracelamp mcp serve"
tracelamp mcp connect http://127.0.0.1:3000/mcp
tracelamp config show
```

`analyze` scores the static findings. Add `--llm` to also ask a model about those findings. A skill is a TOML file of regex search patterns; `skill run` and `agent run` apply them while reading files. An agent runs the static scan, then its skills, then the rule scores. `--llm` or `use_llm = true` in the agent file is what turns the model on.

## GitHub Action

The composite action in `action/` downloads a release archive for the runner, checks it against `SHA256SUMS`, and runs `tracelamp scan`. A baseline file limits the job failure to new findings. `fail-on` sets the lowest severity that fails the job. Set `upload-sarif: true` to send SARIF to GitHub code scanning, and give that job `security-events: write`. Leave the toggle off and the job only needs `contents: read`.

Example workflows: [docs/github-action.md](docs/github-action.md).

## Site

The product site is static HTML in `site/public`. It is not a scan service. Deploy notes are in [site/DEPLOY.md](site/DEPLOY.md).

## Releases

v0.1.0 archives are on the [GitHub release](https://github.com/cdobratz/TraceLamp/releases/tag/v0.1.0). Each archive contains `tracelamp` and `recon`. Source build: `git checkout v0.1.0` then `cargo build --locked --release`. See [RELEASE.md](RELEASE.md). The workflow does not publish a crate.

## License

TraceLamp is licensed under the [Apache License, Version 2.0](LICENSE). Copyright (c) 2026 Poietes LLC. See [NOTICE](NOTICE).
