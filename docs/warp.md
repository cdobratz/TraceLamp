# TraceLamp in Warp

Source for this setup: [Warp MCP](https://docs.warp.dev/agents/capabilities/mcp/). Skill file layout: [Warp skills](https://docs.warp.dev/agents/capabilities/skills/).

Use stdio. Do not start `tracelamp mcp serve --transport http` for Warp. That listener binds `127.0.0.1` and has no authentication. Its host allowlist is `localhost`, `127.0.0.1`, and `::1`. Other local processes can still open the port. This document does not deploy or expose it.

## Prerequisites

- A TraceLamp checkout and a Rust toolchain that can run `cargo build --locked --release`.
- The built binary. `cargo install` is not available. The crate is not on crates.io.
- An absolute path to that binary, and an absolute path to the repository Warp may read.

`tracelamp mcp serve` reads files only when `mcp.scan_root` or `TRACELAMP_SCAN_ROOT` is an existing directory. A missing root, a file used as the root, a missing path, a `..` path that leaves the root, or a symlink that canonicalizes outside the root is rejected. `tracelamp scan` on the command line is separate and still takes the path you pass.

`explain_finding` does not read the workspace. `scan_repo`, `list_findings`, and `agent_inventory` do. Findings and short snippets from those tools are returned to Warp and can be sent to the model in the conversation. Optional `tracelamp analyze --llm` is a separate CLI flag. The MCP tools do not call a model or open a network connection.

## Add the server

In Warp: Settings > Agents > MCP servers, or the command palette entry `Open MCP Servers`, then + Add. Paste a CLI server. `command` is the executable. `working_directory` must be an absolute directory on your computer. Warp uses it to resolve relative paths.

```json
{
  "mcpServers": {
    "tracelamp": {
      "command": "/absolute/path/to/tracelamp",
      "args": ["mcp", "serve"],
      "working_directory": "/absolute/path/to/the/repo",
      "env": {
        "TRACELAMP_SCAN_ROOT": "/absolute/path/to/the/repo"
      }
    }
  }
}
```

`args` must not include `--transport http`. Stdio is the default. The server name in the protocol is `tracelamp`. Tools:

| Tool | Arguments |
|---|---|
| `scan_repo` | `path` |
| `list_findings` | `path`, optional `severity` |
| `explain_finding` | `rule_id` |
| `agent_inventory` | `path` |

`path` has to stay inside the scan root after canonicalization.

Warp also reads `.warp/.mcp.json` at the project root and `~/.warp/.mcp.json` for your user. Those are the Warp file locations. A `.mcp.json` file that is not under `.warp/` is still recorded as Claude Code. TraceLamp does not invent other Warp filenames.

## Disconnect

On the MCP servers page, Stop the `tracelamp` server. Delete that server entry if you do not want Warp to start it again. Project servers do not auto-spawn. Global Warp servers do, until you stop them. Stopping the server does not delete the scan root or the repository.

## Troubleshooting

- `scan root is not configured`: set `TRACELAMP_SCAN_ROOT` or `mcp.scan_root` to an absolute directory that exists.
- `scan path is outside the approved root`: the requested path, after resolving `..` and symlinks, is not the root or a child of it.
- The binary is not found: `command` is not an absolute path to the built `tracelamp` file, or it is not executable.
- Logs: Warp stores MCP logs on the machine. The current Warp doc lists macOS `$HOME/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/mcp`, Windows `$env:LOCALAPPDATA\warp\Warp\data\logs\mcp`, and Linux `${XDG_STATE_HOME:-$HOME/.local/state}/warp-terminal/mcp`. Remove secrets before you share a log. View Logs is on the server row in the MCP servers page.

A project skill at `.agents/skills/tracelamp-review/SKILL.md` asks the agent to scan, explain, and propose fixes without editing the repository or executing its contents.
