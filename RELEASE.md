# Release binaries

No archives are published yet. Until a tag exists, build from source:

```sh
cargo build --locked --release
```

The binaries are `target/release/tracelamp` and `target/release/recon` (`tracelamp.exe` and `recon.exe` on Windows). `recon` is the compatibility command.

This project is not published to crates.io. Do not add a crate publish step.

## Tag

1. Set `version` in `Cargo.toml` to the release you want, and keep `Cargo.lock` in sync (`cargo update -p tracelamp` is not required for a version-only change; `cargo build --locked` must still succeed).
2. Push a tag `vX.Y.Z` whose `X.Y.Z` equals that `version`. Example: version `0.1.0` uses tag `v0.1.0`.
3. `.github/workflows/release.yml` runs only on tags that match `v[0-9]+.[0-9]+.[0-9]+`. It does not run on pull requests.

The package script exits if the tag version and `Cargo.toml` disagree, so a partial or mis-tagged release is not uploaded.

## What the workflow builds

Each job is a native build on a GitHub-hosted runner. Nothing is cross-compiled.

| Runner | Target | Archive |
|---|---|---|
| `ubuntu-24.04` | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| `ubuntu-24.04-arm` | `aarch64-unknown-linux-gnu` | `.tar.gz` |
| `macos-15-intel` | `x86_64-apple-darwin` | `.tar.gz` |
| `macos-15` | `aarch64-apple-darwin` | `.tar.gz` |
| `windows-2025` | `x86_64-pc-windows-msvc` | `.zip` |

`scripts/package_release.py` puts both commands, `LICENSE`, `NOTICE`, and `README.md` at the root of the archive. Unix binaries are marked executable. The publish job writes `SHA256SUMS` for every archive and opens one GitHub Release titled `TraceLamp X.Y.Z`. If any target fails, the release is not created.

The composite action in `action/` downloads these archives and `SHA256SUMS`. Keep the names `tracelamp-<version>-<target>.tar.gz` (`.zip` on Windows) and the `sha256sum` line format (`<digest><two spaces><filename>`).

The Linux x86_64 archive can be reproduced on a machine that already builds this repo. The other four targets run only in that workflow and were not executed while the workflow was added.
