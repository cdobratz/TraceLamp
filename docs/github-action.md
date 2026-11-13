# GitHub Action

The composite action in [`action/`](../action/action.yml) runs `tracelamp scan` on a GitHub-hosted runner.

It downloads the release archive for the runner OS and architecture, checks the file against `SHA256SUMS` from that same release, and only then runs the binary. Checksum failure stops the job before the archive is extracted. The scan is the release `tracelamp scan` command: it reads files and does not spawn project commands.

Archives match the release workflow: Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, and Windows x86_64.

## Inputs

| Input | Default | Role |
|---|---|---|
| `version` | `0.1.0` | Release to download. `0.1.0` and `v0.1.0` both select tag `v0.1.0`. |
| `path` | `.` | Directory to scan, relative to the workspace or absolute. |
| `baseline` | empty | Baseline file from `tracelamp scan --write-baseline`. Findings already in the file are omitted. Only findings that remain can fail the job. |
| `fail-on` | `high` | Lowest severity that fails the job: `critical`, `high`, `medium`, `low`, `info`, or `none`. `high` fails on high and critical. `none` never fails the job. |
| `upload-sarif` | `false` | Upload the SARIF file with `github/codeql-action/upload-sarif`. |

Set `upload-sarif: true` only on a job that can write code scanning alerts. Other jobs should leave it off.

`TRACELAMP_RELEASE_BASE`, when set, replaces `https://github.com/cdobratz/TraceLamp/releases/download/vX.Y.Z`. The mirror must serve the same archive names and `SHA256SUMS`. The checksum check still runs.

## Permissions

The action does not grant permissions. Put `security-events: write` on the job only when `upload-sarif` is true. A scan that does not upload needs `contents: read` so `actions/checkout` can fetch the repo.

Private repositories that upload SARIF also need `actions: read` on that job. Code scanning uses it to load the workflow run.

## Upload SARIF and fail on new high findings

`security-events: write` is on this workflow because it uploads.

```yaml
name: TraceLamp

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  tracelamp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: cdobratz/TraceLamp/action@main
        with:
          version: "0.1.0"
          path: .
          baseline: tracelamp-baseline.json
          fail-on: high
          upload-sarif: true
```

Create the baseline with the same TraceLamp version the workflow downloads. From a checkout of that release:

```bash
tracelamp scan . --write-baseline tracelamp-baseline.json
```

Commit `tracelamp-baseline.json`. Later runs omit those fingerprints. A new finding at `high` or `critical` fails the job after the SARIF upload. Lower severities are still written into the SARIF file and uploaded, and they do not fail the job.

Pin `@main` to a commit or tag once the ref you want is on the default branch. This file lives in the TraceLamp repo, so a workflow in this repo can call `./action` instead of `cdobratz/TraceLamp/action@main`.

## Scan without uploading

This job does not set `security-events`.

```yaml
name: TraceLamp

on:
  pull_request:

permissions:
  contents: read

jobs:
  tracelamp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: cdobratz/TraceLamp/action@main
        with:
          version: "0.1.0"
          path: .
          baseline: tracelamp-baseline.json
          fail-on: high
          upload-sarif: false
```

## Fixture check in this repo

[`.github/workflows/action.yml`](../.github/workflows/action.yml) calls `./action` on `tests/fixtures/mcp/unpinned`. The baseline in `tests/action/unpinned-baseline.json` was written by the `v0.1.0` release for that directory. The workflow's permissions are `contents: read` only. It does not upload SARIF.
