#!/usr/bin/env bash
# tools/orient-pipeline.sh - run ORIENT-phase scope-coverage gate FIRST,
# then the ORIENT prefilter SECOND. Standalone wrapper (Capability Gap 24
# fix, 2026-05-25) to compose the new scope-coverage check ahead of the
# existing orient-prefilter without touching tools/orient-prefilter.py
# (active edits in Codex's lane at the time of fix).
#
# Usage:
#   tools/orient-pipeline.sh \
#     --orient   <path/to/hunt_orient.json> \
#     --workspace <path/to/audit/workspace> \
#     --candidates <path/to/orient-output.json> \
#     --audit-pin <sha> \
#     [--prefilter-json] [--prefilter-days 180] \
#     [--strict-scope-coverage]
#
# Step 1: tools/orient-scope-coverage-check.py (new gate).
#   - Verdict fail-asset-uncovered REFUSES to proceed; the operator must
#     extend hunt_orient.json with drill_candidates for the uncovered
#     in-scope assets BEFORE re-running.
#   - Verdict warn-partial-coverage proceeds with a warning unless
#     --strict-scope-coverage is passed (then refuses).
# Step 2: tools/orient-prefilter.py (existing R45/R46/R47/R48/R53 gate).
#
# Empirical anchor: 2026-05-25 hyperbridge full-hunt - SCOPE.md lists 2
# in-scope assets (Hyperbridge + Solidity Merkle Trees); the ORIENT
# output enumerated 8 drill_candidates ALL targeting the bridge tree
# (0 targeting the merkle library). Without this gate, the prefilter
# and dispatch loop would have skipped the merkle library entirely.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ORIENT=""
WORKSPACE=""
CANDIDATES=""
AUDIT_PIN=""
PREFILTER_JSON=""
PREFILTER_DAYS=""
STRICT_SCOPE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --orient)
      ORIENT="$2"; shift 2;;
    --workspace)
      WORKSPACE="$2"; shift 2;;
    --candidates)
      CANDIDATES="$2"; shift 2;;
    --audit-pin)
      AUDIT_PIN="$2"; shift 2;;
    --prefilter-json)
      PREFILTER_JSON="--json"; shift;;
    --prefilter-days)
      PREFILTER_DAYS="--days $2"; shift 2;;
    --strict-scope-coverage)
      STRICT_SCOPE="--strict"; shift;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0;;
    *)
      echo "ERROR: unknown arg: $1" >&2
      exit 2;;
  esac
done

if [[ -z "${ORIENT}" || -z "${WORKSPACE}" ]]; then
  echo "ERROR: --orient and --workspace are required" >&2
  exit 2
fi

# Default --candidates to --orient if not provided (the same JSON
# typically serves both purposes).
if [[ -z "${CANDIDATES}" ]]; then
  CANDIDATES="${ORIENT}"
fi

echo "================================================================="
echo "ORIENT pipeline (Capability Gap 24)"
echo "  Step 1: scope-coverage check  (NEW)"
echo "  Step 2: orient-prefilter R45/R46/R47/R48/R53"
echo "================================================================="
echo ""

echo "--- Step 1: scope-coverage check ---"
set +e
python3 "${SCRIPT_DIR}/orient-scope-coverage-check.py" \
  --orient "${ORIENT}" \
  --workspace "${WORKSPACE}" \
  ${STRICT_SCOPE}
SCOPE_RC=$?
set -e

if [[ ${SCOPE_RC} -eq 1 ]]; then
  echo ""
  echo "================================================================="
  echo "REFUSE TO PROCEED: scope-coverage check returned exit 1."
  echo "ORIENT must include drill_candidates targeting every uncovered"
  echo "in-scope asset before drill dispatch. Re-run ORIENT (or extend"
  echo "the hunt_orient.json drill_candidates[] list) and re-run this"
  echo "pipeline."
  echo "================================================================="
  exit 1
fi

if [[ ${SCOPE_RC} -eq 2 ]]; then
  echo ""
  echo "ERROR: scope-coverage check returned exit 2 (input shape error)." >&2
  exit 2
fi

echo ""
echo "--- Step 2: orient-prefilter ---"
PREFILTER_CMD=(
  python3 "${SCRIPT_DIR}/orient-prefilter.py"
  --candidates "${CANDIDATES}"
  --workspace "${WORKSPACE}"
)
if [[ -n "${AUDIT_PIN}" ]]; then
  PREFILTER_CMD+=(--audit-pin "${AUDIT_PIN}")
fi
if [[ -n "${PREFILTER_JSON}" ]]; then
  PREFILTER_CMD+=("${PREFILTER_JSON}")
fi
if [[ -n "${PREFILTER_DAYS}" ]]; then
  # shellcheck disable=SC2206
  EXTRA=(${PREFILTER_DAYS})
  PREFILTER_CMD+=("${EXTRA[@]}")
fi

"${PREFILTER_CMD[@]}"
PREFILTER_RC=$?

# r36-rebuttal: lane-CAPABILITY-WORKFLOW-FULLNESS pathspec registered to agent_pathspec.json
# Gap #39 / operator anchor 2026-05-26: "whatever we analyze and audit, we do it full".
# Step 3 (optional, skip-if-missing): when severity hypothesis emitted by
# orient-prefilter implies Medium+, auto-dispatch tools/depth-tools-orchestrator.py
# (sibling lane lane-CAPABILITY-DEPTH-TOOLS-ORCHESTRATOR builds it). The sibling
# tool runs halmos / medusa / echidna / mythril / manticore / fuzz-1M / soak /
# Rule-14-deep where applicable. Default-on; users can opt out with
# AUDITOOOR_ORIENT_SKIP_DEPTH_TOOLS=1.
DEPTH_RC=0
DEPTH_TOOLS="${SCRIPT_DIR}/depth-tools-orchestrator.py"
if [[ "${AUDITOOOR_ORIENT_SKIP_DEPTH_TOOLS:-0}" = "1" ]]; then
  echo ""
  echo "--- Step 3: depth-tools dispatch (SKIPPED by AUDITOOOR_ORIENT_SKIP_DEPTH_TOOLS=1) ---"
elif [[ -f "${DEPTH_TOOLS}" ]]; then
  echo ""
  echo "--- Step 3: depth-tools dispatch (Gap #39 default-full) ---"
  python3 "${DEPTH_TOOLS}" --workspace "${WORKSPACE}" || DEPTH_RC=$?
  if [[ ${DEPTH_RC} -ne 0 ]]; then
    echo "[orient-pipeline] WARN depth-tools-orchestrator returned rc=${DEPTH_RC}; continuing (advisory)"
  fi
else
  echo ""
  echo "--- Step 3: depth-tools dispatch (SKIPPED: ${DEPTH_TOOLS} not present; sibling lane in flight) ---"
fi

echo ""
echo "================================================================="
echo "ORIENT pipeline complete."
echo "  scope-coverage rc: ${SCOPE_RC}"
echo "  prefilter rc:      ${PREFILTER_RC}"
echo "  depth-tools rc:    ${DEPTH_RC}"
echo "================================================================="
exit ${PREFILTER_RC}
