#!/usr/bin/env bash
set -euo pipefail

# Re-run the first FreeVRG QL smoke validation on Linux.
#
# Expected layout:
#   first-ql-validation-package/
#     qlpack.yml
#     queries/*.ql
#     minimal-validation-databases/db/<CVE>-<version>/
#     minimal-validation-databases/results/
#     minimal-validation-databases/logs/
#
# Usage:
#   cd first-ql-validation-package
#   CODEQL=/path/to/codeql ./scripts/run_smoke_validation.sh queries/<query>.ql
#
# Optional:
#   ADDITIONAL_PACKS=/path/to/codeql-stdlib ./scripts/run_smoke_validation.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEQL_BIN="${CODEQL:-codeql}"
ADDITIONAL_PACKS="${ADDITIONAL_PACKS:-}"

DB_ROOT="$ROOT_DIR/minimal-validation-databases/db"
RESULTS_DIR="$ROOT_DIR/minimal-validation-databases/results"
LOGS_DIR="$ROOT_DIR/minimal-validation-databases/logs"
SUMMARY="$ROOT_DIR/validation/smoke-summary.tsv"

usage() {
  cat <<EOF
Usage:
  $(basename "$0") <query.ql>

Examples:
  $(basename "$0") queries/missing-array-bounds-check-on-network-controlled-index.ql
  $(basename "$0") queries/missing-minimum-length-check-on-network-protocol-packet.ql

Environment:
  CODEQL=/path/to/codeql
  ADDITIONAL_PACKS=/path/to/codeql-stdlib
EOF
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

INPUT_QUERY="$1"
if [[ "$INPUT_QUERY" = /* ]]; then
  QUERY="$INPUT_QUERY"
else
  QUERY="$ROOT_DIR/$INPUT_QUERY"
fi

if [[ ! -f "$QUERY" ]]; then
  echo "ERROR: query file not found: $QUERY" >&2
  exit 2
fi

QUERY_BASENAME="$(basename "$QUERY")"

mkdir -p "$RESULTS_DIR" "$LOGS_DIR" "$ROOT_DIR/validation"

codeql_args=()
if [[ -n "$ADDITIONAL_PACKS" ]]; then
  codeql_args+=(--additional-packs "$ADDITIONAL_PACKS")
fi

echo "[1/3] CodeQL version"
"$CODEQL_BIN" version

echo
echo "[2/3] Compile query"
"$CODEQL_BIN" query compile --check-only "${codeql_args[@]}" -- "$QUERY"

count_sarif_results() {
  local sarif="$1"
  python3 - "$sarif" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
count = sum(len(run.get("results", [])) for run in data.get("runs", []))
print(count)
PY
}

run_analyze() {
  local cve="$1"
  local version="$2"
  local query="$3"
  local db="$DB_ROOT/${cve}-${version}"
  local out="$RESULTS_DIR/${cve}-${version}.sarif"
  local log="$LOGS_DIR/analyze-${cve}-${version}.log"

  if [[ ! -f "$db/codeql-database.yml" ]]; then
    echo "ERROR: missing CodeQL database: $db" | tee "$log"
    return 1
  fi

  echo "  - $cve $version"
  if "$CODEQL_BIN" database analyze "$db" "$query" \
      --format=sarif-latest \
      --output="$out" \
      "${codeql_args[@]}" >"$log" 2>&1; then
    local n
    n="$(count_sarif_results "$out")"
    local status
    if [[ "$version" == "vulnerable" ]]; then
      if [[ "$n" -gt 0 ]]; then
        status="hit"
      else
        status="miss"
      fi
    elif [[ "$version" == "fixed" ]]; then
      if [[ "$n" -eq 0 ]]; then
        status="clean"
      else
        status="still_reports"
      fi
    else
      status="unknown_version"
    fi
    printf "%s\t%s\t%s\t%s\t%s\n" "$cve" "$version" "$(basename "$query")" "$n" "$status" >> "$SUMMARY"
  else
    printf "%s\t%s\t%s\tERROR\tanalyze_error\n" "$cve" "$version" "$(basename "$query")" >> "$SUMMARY"
    echo "ERROR: analyze failed for $cve $version. See $log"
    return 1
  fi
}

decide_smoke_result() {
  python3 - "$SUMMARY" "$RESULTS_DIR" "$ROOT_DIR/minimal-validation-databases/source" <<'PY'
import csv
import sys
import json
from pathlib import Path

path = sys.argv[1]
results_dir = Path(sys.argv[2])
source_dir = Path(sys.argv[3])
rows = []
with open(path, "r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f, delimiter="\t")
    rows = list(reader)

failures = []
for row in rows:
    status = row.get("status")
    if row.get("version") == "vulnerable" and status != "hit":
        failures.append(row)
    if row.get("version") == "fixed" and status != "clean":
        failures.append(row)

if failures:
    print("SMOKE_RESULT=FAIL")
    print("Failures:")
    for row in failures:
        cve = row["cve"]
        version = row["version"]
        sarif_path = results_dir / f"{cve}-{version}.sarif"
        print(
            f"- {row['cve']} {row['version']}: "
            f"{row['status']} (results={row['result_count']})"
        )
        if row["status"] == "miss":
            print("  reason: vulnerable database produced no SARIF results")
            print(f"  sarif: {sarif_path}")
            continue
        if row["status"] == "analyze_error":
            print("  reason: codeql database analyze failed; inspect analyze log")
            continue
        if not sarif_path.exists():
            print(f"  sarif: missing expected file {sarif_path}")
            continue

        try:
            data = json.loads(sarif_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  sarif: failed to read {sarif_path}: {exc}")
            continue

        shown = 0
        for run in data.get("runs", []):
            artifacts = run.get("artifacts", [])
            for result in run.get("results", []):
                msg = result.get("message", {}).get("text", "").replace("\n", " ")
                for loc in result.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    region = phys.get("region", {})
                    uri = art.get("uri", "<unknown>")
                    line = region.get("startLine")
                    col = region.get("startColumn")
                    print(f"  location: {uri}:{line}:{col}")
                    if msg:
                        print(f"  message: {msg}")
                    src_path = source_dir / f"{cve}-{version}" / uri
                    if line and src_path.exists():
                        try:
                            src_lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
                            start = max(1, line - 2)
                            end = min(len(src_lines), line + 2)
                            print("  source:")
                            for n in range(start, end + 1):
                                marker = ">" if n == line else " "
                                print(f"    {marker} {n:4}: {src_lines[n - 1]}")
                        except Exception as exc:
                            print(f"  source: failed to read {src_path}: {exc}")
                    shown += 1
                    if shown >= 3:
                        break
                if shown >= 3:
                    break
            if shown >= 3:
                break
        if shown == 0:
            print(f"  sarif: no locations found in {sarif_path}")
    sys.exit(1)

print("SMOKE_RESULT=PASS")
sys.exit(0)
PY
}

echo
echo "[3/3] Analyze minimal vulnerable/fixed databases"
printf "cve\tversion\tquery\tresult_count\tstatus\n" > "$SUMMARY"

case "$QUERY_BASENAME" in
  missing-array-bounds-check-on-network-controlled-index.ql)
    run_analyze "CVE-2018-17161" "vulnerable" "$QUERY"
    run_analyze "CVE-2018-17161" "fixed" "$QUERY"
    run_analyze "CVE-2019-5604" "vulnerable" "$QUERY"
    run_analyze "CVE-2019-5604" "fixed" "$QUERY"
    run_analyze "CVE-2021-29631" "vulnerable" "$QUERY"
    run_analyze "CVE-2021-29631" "fixed" "$QUERY"
    ;;
  missing-minimum-length-check-on-network-protocol-packet.ql)
    run_analyze "CVE-2020-7461" "vulnerable" "$QUERY"
    run_analyze "CVE-2020-7461" "fixed" "$QUERY"
    run_analyze "CVE-2021-29629" "vulnerable" "$QUERY"
    run_analyze "CVE-2021-29629" "fixed" "$QUERY"
    ;;
  *)
    echo "ERROR: no smoke validation matrix is defined for query: $QUERY_BASENAME" >&2
    echo "Add a case entry in scripts/run_smoke_validation.sh for this query." >&2
    exit 2
    ;;
esac

echo
echo "Smoke summary:"
column -t -s $'\t' "$SUMMARY" 2>/dev/null || cat "$SUMMARY"
echo
decide_smoke_result
echo
echo "Wrote summary: $SUMMARY"
echo "Wrote SARIF results: $RESULTS_DIR"
echo "Wrote analyze logs: $LOGS_DIR"
