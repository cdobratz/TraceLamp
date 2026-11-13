# Changelog

## Unreleased

- Added a composite GitHub Action in `action/` that downloads a release archive, verifies `SHA256SUMS`, scans with an optional baseline, and can upload SARIF. Example workflows are in `docs/github-action.md`.
- Warp can run TraceLamp over stdio inside `TRACELAMP_SCAN_ROOT`. `.warp/.mcp.json` is attributed to Warp. MCP header values are not copied into findings.
- Link the site install section to the v0.1.0 GitHub release.
- Added a static product site (`site/`) for Cloudflare Workers Static Assets, and a release workflow that builds `tracelamp` and `recon` archives when a matching version tag is pushed. No archives are published yet.
- Renamed the product from Recon to TraceLamp (https://tracelamp.dev). The `recon` command, `~/.config/recon/config.toml`, `.reconignore`, and `recon:ignore` remain as compatibility aliases. Rule ids are unchanged.
- Relicensed under the Apache License, Version 2.0.
