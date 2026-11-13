# Changelog

## Unreleased

- `recon/agent-cloud-spend` also flags Stripe live secret keys (`STRIPE_SECRET_KEY`, `STRIPE_API_KEY`, `STRIPE_RESTRICTED_KEY`, `sk_live_` / `rk_live_` values, charge tools, and `stripe` charge commands). Test and publishable keys do not match.
- `tracelamp mcp serve --transport http` binds `127.0.0.1` by default. The previous default was `0.0.0.0`. The host allowlist is `localhost`, `127.0.0.1`, and `::1`.
- Warp can run TraceLamp over stdio inside `TRACELAMP_SCAN_ROOT`. `.warp/.mcp.json` is attributed to Warp. MCP header values are not copied into findings.
- Link the site install section to the v0.1.0 GitHub release.
- Added a static product site (`site/`) for Cloudflare Workers Static Assets, and a release workflow that builds `tracelamp` and `recon` archives when a matching version tag is pushed. No archives are published yet.
- Renamed the product from Recon to TraceLamp (https://tracelamp.dev). The `recon` command, `~/.config/recon/config.toml`, `.reconignore`, and `recon:ignore` remain as compatibility aliases. Rule ids are unchanged.
- Relicensed under the Apache License, Version 2.0.
