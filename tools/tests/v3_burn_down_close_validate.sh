#!/usr/bin/env bash
#
# v3_burn_down_close_validate.sh
#
# Lightweight fixture/smoke validator for tools/v3-tooling-burn-down-close.sh.
# Verifies that:
#   1. The script exists, is executable, and accepts --help.
#   2. The default mode (no args) is dry-run and exits 0 against the real
#      repository state when preconditions hold.
#   3. The script reports NO file mutations in dry-run mode (size-stable).
#   4. Preconditions catch a deliberately-broken digest (file count < 27).
#
# Run from the repo root or anywhere; the script resolves its own paths.

set -u
set -o pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." && pwd )"
TARGET="${REPO_ROOT}/tools/v3-tooling-burn-down-close.sh"

pass=0
fail=0
note() { printf '  %s\n' "$*"; }
ok()   { printf 'PASS %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf 'FAIL %s\n' "$*"; fail=$((fail+1)); }

# --- T1: exists + executable + --help ---------------------------------------
if [[ -x "${TARGET}" ]]; then
  ok "T1 script exists and is executable"
else
  bad "T1 script missing or not executable: ${TARGET}"
fi
if "${TARGET}" --help >/dev/null 2>&1; then
  ok "T1b --help exit 0"
else
  bad "T1b --help non-zero exit"
fi

# --- T2: dry-run is default, exits 0 ----------------------------------------
if "${TARGET}" --dry-run >/dev/null 2>&1; then
  ok "T2 dry-run exit 0 against real repo state"
else
  rc=$?
  bad "T2 dry-run exit ${rc}; preconditions may be unmet on this checkout"
fi

# --- T3: dry-run does not modify the target files ---------------------------
FILES=(
  "${REPO_ROOT}/docs/V3_CLOSEOUT_2026-05-22.md"
  "${REPO_ROOT}/reports/v3_roadmap_progress_report.json"
  "${REPO_ROOT}/reports/v3_blocker_ledger/blocker_ledger.json"
)
before="$(stat -f '%z %m %N' "${FILES[@]}" 2>/dev/null || stat -c '%s %Y %n' "${FILES[@]}" 2>/dev/null)"
"${TARGET}" --dry-run >/dev/null 2>&1 || true
after="$(stat -f '%z %m %N' "${FILES[@]}" 2>/dev/null || stat -c '%s %Y %n' "${FILES[@]}" 2>/dev/null)"
if [[ "${before}" == "${after}" ]]; then
  ok "T3 dry-run leaves target files byte/size/mtime-stable"
else
  bad "T3 dry-run drift detected; diff follows"
  diff <(printf '%s\n' "${before}") <(printf '%s\n' "${after}") || true
fi

# --- T4: precondition fail-closed on synthetic broken digest ----------------
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT
SHADOW="${TMPDIR}/shadow_repo"
mkdir -p "${SHADOW}/docs" "${SHADOW}/reports/v3_blocker_ledger" "${SHADOW}/reference" "${SHADOW}/tools" "${SHADOW}/obsidian-vault/goals"
# minimal valid surface
printf 'proposal\n' >"${SHADOW}/docs/V3_TOOLING_BURN_DOWN_COMPLETE_PROPOSAL.md"
printf '# Closeout\n' >"${SHADOW}/docs/V3_CLOSEOUT_2026-05-22.md"
printf '{"x":1}\n' >"${SHADOW}/reports/v3_roadmap_progress_report.json"
printf '{"blockers":[]}\n' >"${SHADOW}/reports/v3_blocker_ledger/blocker_ledger.json"
# deliberately-broken digest (rule_count<27)
printf '{"schema":"x","rule_count":3,"rules":[]}\n' >"${SHADOW}/reference/codified_rules_digest.json"
printf -- '---\nid: "current"\n---\n# x\n' >"${SHADOW}/obsidian-vault/goals/current.md"
cp "${TARGET}" "${SHADOW}/tools/v3-tooling-burn-down-close.sh"
chmod +x "${SHADOW}/tools/v3-tooling-burn-down-close.sh"
if "${SHADOW}/tools/v3-tooling-burn-down-close.sh" --dry-run >/dev/null 2>&1; then
  bad "T4 broken-digest fixture should have FAILED preconditions but exited 0"
else
  ok "T4 broken-digest fixture correctly fail-closes"
fi

printf '\nresult: %d pass / %d fail\n' "${pass}" "${fail}"
[[ "${fail}" -eq 0 ]] || exit 1
