#!/usr/bin/env bash
# Download a TraceLamp release, verify SHA256SUMS, and scan.
# Exits 0 when the scanner ran. action.yml fails the job when should-fail=true.
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

python_bin() {
  if command -v python3 >/dev/null 2>&1; then
    echo python3
  elif command -v python >/dev/null 2>&1; then
    echo python
  else
    echo "python3 is required to read TraceLamp results" >&2
    return 1
  fi
}

normalize_version() {
  local raw="$1"
  raw="${raw#v}"
  if ! printf '%s' "$raw" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "version must look like 0.1.0 or v0.1.0 (got ${1})" >&2
    return 1
  fi
  printf '%s' "$raw"
}

detect_runner() {
  local os arch
  os="${RUNNER_OS:-}"
  arch="${RUNNER_ARCH:-}"
  if [[ -z "$os" ]]; then
    case "$(uname -s)" in
      Linux) os=Linux ;;
      Darwin) os=macOS ;;
      MINGW*|MSYS*|CYGWIN*) os=Windows ;;
      *)
        echo "unsupported operating system $(uname -s)" >&2
        return 1
        ;;
    esac
  fi
  if [[ -z "$arch" ]]; then
    case "$(uname -m)" in
      x86_64|amd64) arch=X64 ;;
      aarch64|arm64) arch=ARM64 ;;
      *)
        echo "unsupported architecture $(uname -m)" >&2
        return 1
        ;;
    esac
  fi
  printf '%s %s\n' "$os" "$arch"
}

release_target() {
  local os="$1"
  local arch="$2"
  case "${os}-${arch}" in
    Linux-X64) printf '%s %s\n' "x86_64-unknown-linux-gnu" "tar.gz" ;;
    Linux-ARM64) printf '%s %s\n' "aarch64-unknown-linux-gnu" "tar.gz" ;;
    macOS-X64) printf '%s %s\n' "x86_64-apple-darwin" "tar.gz" ;;
    macOS-ARM64) printf '%s %s\n' "aarch64-apple-darwin" "tar.gz" ;;
    Windows-X64) printf '%s %s\n' "x86_64-pc-windows-msvc" "zip" ;;
    *)
      echo "TraceLamp has no release archive for ${os} ${arch}." >&2
      echo "Releases cover Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, and Windows x86_64." >&2
      return 1
      ;;
  esac
}

release_base() {
  local version="$1"
  if [[ -n "${TRACELAMP_RELEASE_BASE:-}" ]]; then
    printf '%s' "${TRACELAMP_RELEASE_BASE%/}"
  else
    printf '%s' "https://github.com/cdobratz/TraceLamp/releases/download/v${version}"
  fi
}

lookup_digest() {
  local sums="$1"
  local name="$2"
  awk -v name="$name" '
    {
      file = $2
      sub(/^\*/, "", file)
      if (file == name) {
        print $1
        count++
      }
    }
    END { exit (count == 1 ? 0 : 1) }
  ' "$sums"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  elif command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '$file').Hash.ToLower()"
  else
    echo "sha256sum or shasum is required to verify SHA256SUMS" >&2
    return 1
  fi
}

verify_checksum() {
  local file="$1"
  local sums="$2"
  local name="$3"
  local expected actual
  if ! expected=$(lookup_digest "$sums" "$name"); then
    echo "SHA256SUMS has no unique entry for ${name}" >&2
    return 1
  fi
  expected=$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
  if ! printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "SHA256SUMS entry for ${name} is not a SHA-256 digest" >&2
    return 1
  fi
  if ! actual=$(sha256_file "$file"); then
    return 1
  fi
  actual=$(printf '%s' "$actual" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
  if [[ "$actual" != "$expected" ]]; then
    echo "checksum mismatch for ${name}" >&2
    echo "expected ${expected}" >&2
    echo "actual   ${actual}" >&2
    return 1
  fi
  printf '%s' "$expected"
}

fetch() {
  local url="$1"
  local dest="$2"
  case "$url" in
    https://*|http://*)
      curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 180 -o "$dest" "$url"
      ;;
    *)
      cp "$url" "$dest"
      ;;
  esac
}

extract_archive() {
  local archive="$1"
  local dest="$2"
  local python="$3"
  mkdir -p "$dest"
  case "$archive" in
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        unzip -q "$archive" -d "$dest"
      else
        "$python" -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$archive" "$dest"
      fi
      ;;
    *)
      tar -xzf "$archive" -C "$dest"
      ;;
  esac
}

json_ok() {
  local python="$1"
  local file="$2"
  "$python" -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$file"
}

write_output() {
  local key="$1"
  local value="$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$key" "$value" >> "$GITHUB_OUTPUT"
  fi
}

run_tracelamp() {
  local bin="$1"
  local python="$2"
  local workdir="$3"
  local scan_path="$4"
  local baseline="$5"
  local format="$6"
  local outfile="$7"
  local errfile="${workdir}/tracelamp-${format}.err"
  local -a args
  local status=0
  args=(scan "$scan_path" --format "$format")
  if [[ -n "$baseline" ]]; then
    args+=(--baseline "$baseline")
  fi
  set +e
  "$bin" "${args[@]}" >"$outfile" 2>"$errfile"
  status=$?
  set -e
  # --baseline exits 1 after it prints the findings that were not in the file.
  # The JSON pass reports that message. The SARIF pass is the same scan.
  if [[ "$status" -eq 1 && -n "$baseline" ]] && json_ok "$python" "$outfile"; then
    if [[ "$format" == "json" && -s "$errfile" ]]; then
      cat "$errfile" >&2
    fi
    return 0
  fi
  if [[ -s "$errfile" ]]; then
    cat "$errfile" >&2
  fi
  if [[ "$status" -eq 0 ]]; then
    return 0
  fi
  echo "tracelamp scan --format ${format} failed with exit ${status}" >&2
  exit "$status"
}

main() {
  local version_input scan_path baseline fail_on version runner os arch target ext
  local base archive_name workdir sums_path archive_path digest extract_dir bin python
  local json_file sarif_file result_file result_lines finding_count blocking_count should_fail
  version_input="${INPUT_VERSION:-0.1.0}"
  scan_path="${INPUT_PATH:-.}"
  baseline="${INPUT_BASELINE:-}"
  fail_on=$(printf '%s' "${INPUT_FAIL_ON:-high}" | tr '[:upper:]' '[:lower:]')

  version=$(normalize_version "$version_input")
  case "$fail_on" in
    critical|high|medium|low|info|none) ;;
    *)
      echo "fail-on must be critical, high, medium, low, info, or none (got ${fail_on})" >&2
      exit 1
      ;;
  esac
  if ! python=$(python_bin); then
    exit 1
  fi
  runner=$(detect_runner)
  os=${runner%% *}
  arch=${runner##* }
  runner=$(release_target "$os" "$arch")
  target=${runner%% *}
  ext=${runner##* }

  base=$(release_base "$version")
  archive_name="tracelamp-${version}-${target}.${ext}"
  workdir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/tracelamp.XXXXXX")
  sums_path="${workdir}/SHA256SUMS"
  archive_path="${workdir}/${archive_name}"

  echo "Downloading ${archive_name} and SHA256SUMS"
  if ! fetch "${base}/SHA256SUMS" "$sums_path"; then
    echo "could not download SHA256SUMS from ${base}/SHA256SUMS" >&2
    exit 1
  fi
  if ! fetch "${base}/${archive_name}" "$archive_path"; then
    echo "could not download ${archive_name} from ${base}/${archive_name}" >&2
    exit 1
  fi
  if ! digest=$(verify_checksum "$archive_path" "$sums_path" "$archive_name"); then
    exit 1
  fi
  echo "Verified SHA-256 ${digest} for ${archive_name}"

  extract_dir="${workdir}/extract"
  extract_archive "$archive_path" "$extract_dir" "$python"
  if [[ "$os" == "Windows" ]]; then
    bin="${extract_dir}/tracelamp.exe"
  else
    bin="${extract_dir}/tracelamp"
    chmod +x "$bin"
  fi
  if [[ ! -f "$bin" ]]; then
    echo "archive ${archive_name} does not contain $(basename "$bin")" >&2
    exit 1
  fi
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    printf '%s\n' "$extract_dir" >> "$GITHUB_PATH"
  fi

  json_file="${workdir}/tracelamp.json"
  sarif_file="${TRACELAMP_SARIF_FILE:-${RUNNER_TEMP:-$workdir}/tracelamp-$$.sarif}"
  run_tracelamp "$bin" "$python" "$workdir" "$scan_path" "$baseline" json "$json_file"
  run_tracelamp "$bin" "$python" "$workdir" "$scan_path" "$baseline" sarif "$sarif_file"

  result_file="${workdir}/result.json"
  "$python" "$SCRIPT_DIR/evaluate.py" \
    --json "$json_file" \
    --sarif "$sarif_file" \
    --fail-on "$fail_on" \
    --workspace "${GITHUB_WORKSPACE:-$PWD}" \
    --scan-path "$scan_path" \
    --result "$result_file"
  result_lines=$("$python" -c '
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
finding_count = data["finding_count"]
blocking_count = data["blocking_count"]
should_fail = data["should_fail"]
if type(finding_count) is not int or type(blocking_count) is not int or should_fail not in (True, False):
    sys.exit("bad result")
if finding_count < 0 or blocking_count < 0:
    sys.exit("bad result")
print(finding_count)
print(blocking_count)
print("true" if should_fail else "false")
' "$result_file")
  finding_count=$(printf '%s\n' "$result_lines" | sed -n '1p')
  blocking_count=$(printf '%s\n' "$result_lines" | sed -n '2p')
  should_fail=$(printf '%s\n' "$result_lines" | sed -n '3p')
  case "$finding_count" in
    ''|*[!0-9]*) echo "bad finding count" >&2; exit 1 ;;
  esac
  case "$blocking_count" in
    ''|*[!0-9]*) echo "bad blocking count" >&2; exit 1 ;;
  esac
  case "$should_fail" in
    true|false) ;;
    *) echo "bad should-fail value" >&2; exit 1 ;;
  esac

  echo "TraceLamp ${version}: ${finding_count} finding(s) after baseline, ${blocking_count} at or above ${fail_on}."
  write_output "sarif_file" "$sarif_file"
  write_output "finding_count" "$finding_count"
  write_output "blocking_count" "$blocking_count"
  write_output "should_fail" "$should_fail"
}

assert_output() {
  local file="$1"
  local key="$2"
  local value="$3"
  if ! grep -qx "${key}=${value}" "$file"; then
    echo "self-test: expected ${key}=${value}" >&2
    cat "$file" >&2
    exit 1
  fi
}

make_fake_release() {
  local dest="$1"
  local name="tracelamp-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
  mkdir -p "$dest/stage"
  cat > "$dest/stage/tracelamp" <<'EOF'
#!/bin/sh
if [ -n "${SENTINEL:-}" ]; then
  : > "$SENTINEL"
fi
format=json
baseline=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--format" ]; then
    format=$arg
  fi
  if [ "$prev" = "--baseline" ]; then
    baseline=$arg
  fi
  prev=$arg
done
workspace=${GITHUB_WORKSPACE:-/work}
uri="${workspace}/pkg/.mcp.json"
if [ -n "$baseline" ] && grep -q EXIT2 "$baseline"; then
  echo "boom" >&2
  exit 2
fi
if [ -n "$baseline" ] && grep -q EXIT1 "$baseline"; then
  if [ "$format" = sarif ]; then
    printf '%s\n' "{\"version\":\"2.1.0\",\"runs\":[{\"results\":[{\"ruleId\":\"recon/mcp-unpinned-package\",\"level\":\"error\",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"${uri}\"},\"region\":{\"startLine\":5}}}]}]}]}"
  else
    printf '%s\n' "{\"findings\":[{\"severity\":\"high\",\"file\":\"${uri}\",\"line\":5,\"title\":\"Unpinned\",\"metadata\":{\"rule_id\":\"recon/mcp-unpinned-package\"}}]}"
  fi
  echo "tracelamp: 1 new finding(s) are not in the baseline" >&2
  exit 1
fi
if [ -n "$baseline" ]; then
  if [ "$format" = sarif ]; then
    printf '%s\n' '{"version":"2.1.0","runs":[{"results":[]}]}'
  else
    printf '%s\n' '{"findings":[]}'
  fi
  exit 0
fi
if [ "$format" = sarif ]; then
  printf '%s\n' "{\"version\":\"2.1.0\",\"runs\":[{\"results\":[{\"ruleId\":\"recon/mcp-unpinned-package\",\"level\":\"error\",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"${uri}\"},\"region\":{\"startLine\":5}}}]}]}]}"
  exit 0
fi
printf '%s\n' "{\"findings\":[{\"severity\":\"high\",\"file\":\"${uri}\",\"line\":5,\"title\":\"Unpinned\",\"metadata\":{\"rule_id\":\"recon/mcp-unpinned-package\"}},{\"severity\":\"info\",\"file\":\"${uri}\",\"line\":2,\"title\":\"MCP agent\"}]}"
exit 0
EOF
  chmod +x "$dest/stage/tracelamp"
  tar -czf "$dest/$name" -C "$dest/stage" tracelamp
  local hash
  hash=$(sha256_file "$dest/$name")
  printf '%s  %s\n' "$hash" "$name" > "$dest/SHA256SUMS"
}

run_fake() {
  local expect="$1"
  local base="$2"
  local workspace="$3"
  local baseline="$4"
  local fail_on="$5"
  local sentinel="$6"
  local sarif="$7"
  local gh_out="$8"
  local status=0
  set +e
  (
    export INPUT_VERSION="v0.1.0"
    export INPUT_PATH="."
    export INPUT_BASELINE="$baseline"
    export INPUT_FAIL_ON="$fail_on"
    export TRACELAMP_RELEASE_BASE="$base"
    export RUNNER_OS="Linux"
    export RUNNER_ARCH="X64"
    export GITHUB_WORKSPACE="$workspace"
    export GITHUB_OUTPUT="$gh_out"
    export SENTINEL="$sentinel"
    export TRACELAMP_SARIF_FILE="$sarif"
    cd "$workspace"
    bash "$SCRIPT_DIR/scan.sh"
  )
  status=$?
  set -e
  if [[ "$status" -ne "$expect" ]]; then
    echo "self-test: exit ${status}, expected ${expect} (fail-on ${fail_on})" >&2
    exit 1
  fi
}

self_test() {
  local tmp hash digest os_arch base workspace sentinel sarif gh_out uri
  unset TRACELAMP_RELEASE_BASE
  python3 "$SCRIPT_DIR/evaluate.py" --self-test

  tmp=$(mktemp -d "${TMPDIR:-/tmp}/tracelamp-self.XXXXXX")
  printf 'hello' > "$tmp/payload"
  hash=$(sha256_file "$tmp/payload")
  printf '%s  %s\n' "$hash" "payload" > "$tmp/SHA256SUMS"
  printf '%s *%s\n' "$hash" "starred" >> "$tmp/SHA256SUMS"
  cp "$tmp/payload" "$tmp/starred"
  digest=$(verify_checksum "$tmp/payload" "$tmp/SHA256SUMS" "payload")
  if [[ "$digest" != "$hash" ]]; then
    echo "self-test: two-space checksum was not accepted" >&2
    exit 1
  fi
  digest=$(verify_checksum "$tmp/starred" "$tmp/SHA256SUMS" "starred")
  if [[ "$digest" != "$hash" ]]; then
    echo "self-test: starred checksum was not accepted" >&2
    exit 1
  fi
  printf 'x' >> "$tmp/payload"
  if verify_checksum "$tmp/payload" "$tmp/SHA256SUMS" "payload" >/dev/null; then
    echo "self-test: mismatched checksum was accepted" >&2
    exit 1
  fi
  if verify_checksum "$tmp/starred" "$tmp/SHA256SUMS" "missing" >/dev/null; then
    echo "self-test: missing checksum entry was accepted" >&2
    exit 1
  fi
  printf '%s  %s\n%s  %s\n' "$hash" "twice" "$hash" "twice" > "$tmp/dup"
  if verify_checksum "$tmp/starred" "$tmp/dup" "twice" >/dev/null; then
    echo "self-test: duplicate checksum entry was accepted" >&2
    exit 1
  fi

  version=$(normalize_version "v0.1.0")
  if [[ "$version" != "0.1.0" ]]; then
    echo "self-test: version prefix was kept" >&2
    exit 1
  fi
  if normalize_version "latest" >/dev/null 2>&1; then
    echo "self-test: bad version was accepted" >&2
    exit 1
  fi
  if [[ "$(release_base "0.1.0")" != "https://github.com/cdobratz/TraceLamp/releases/download/v0.1.0" ]]; then
    echo "self-test: unexpected release URL $(release_base "0.1.0")" >&2
    exit 1
  fi
  os_arch=$(release_target "Linux" "X64")
  if [[ "$os_arch" != "x86_64-unknown-linux-gnu tar.gz" ]]; then
    echo "self-test: unexpected linux target ${os_arch}" >&2
    exit 1
  fi
  if release_target "Windows" "ARM64" >/dev/null 2>&1; then
    echo "self-test: windows arm64 was accepted" >&2
    exit 1
  fi

  base="${tmp}/release"
  make_fake_release "$base"
  workspace="${tmp}/workspace"
  mkdir -p "$workspace/pkg"
  sentinel="${tmp}/ran"
  sarif="${tmp}/out.sarif"
  gh_out="${tmp}/output.txt"

  : > "$gh_out"
  run_fake 0 "$base" "$workspace" "" "critical" "$sentinel" "$sarif" "$gh_out"
  test -f "$sentinel"
  assert_output "$gh_out" "should_fail" "false"
  assert_output "$gh_out" "blocking_count" "0"
  assert_output "$gh_out" "finding_count" "2"
  uri=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])' "$sarif")
  if [[ "$uri" != "pkg/.mcp.json" ]]; then
    echo "self-test: SARIF uri ${uri}" >&2
    exit 1
  fi

  rm -f "$sentinel"
  : > "$gh_out"
  run_fake 0 "$base" "$workspace" "" "high" "$sentinel" "$sarif" "$gh_out"
  assert_output "$gh_out" "should_fail" "true"
  assert_output "$gh_out" "blocking_count" "1"
  assert_output "$gh_out" "finding_count" "2"

  printf '%s\n' '{"version":1,"fingerprints":[]}' > "$workspace/baseline.json"
  : > "$gh_out"
  run_fake 0 "$base" "$workspace" "baseline.json" "high" "$sentinel" "$sarif" "$gh_out"
  assert_output "$gh_out" "should_fail" "false"
  assert_output "$gh_out" "finding_count" "0"

  printf '%s\n' 'EXIT1' > "$workspace/new.txt"
  : > "$gh_out"
  run_fake 0 "$base" "$workspace" "new.txt" "high" "$sentinel" "$sarif" "$gh_out"
  assert_output "$gh_out" "should_fail" "true"
  assert_output "$gh_out" "blocking_count" "1"

  printf '%s\n' 'EXIT2' > "$workspace/bad.txt"
  run_fake 2 "$base" "$workspace" "bad.txt" "high" "$sentinel" "$sarif" "$gh_out"

  rm -f "$sentinel"
  printf 'x' >> "$base/tracelamp-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
  run_fake 1 "$base" "$workspace" "" "high" "$sentinel" "$sarif" "$gh_out"
  if [[ -e "$sentinel" ]]; then
    echo "self-test: archive ran after a checksum mismatch" >&2
    exit 1
  fi

  echo "scan.sh self-test ok"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

main
