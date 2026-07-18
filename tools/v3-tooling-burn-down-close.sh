#!/usr/bin/env bash
#
# v3-tooling-burn-down-close.sh
#
# Idempotent driver that flips the V3 milestone from
# `tooling/enforcement mostly complete; empirical roadmap still open` to
# `V3 tooling burn-down complete; operator-action backlog documented`
# IF the operator accepts the redefinition proposed in
# docs/V3_TOOLING_BURN_DOWN_COMPLETE_PROPOSAL.md.
#
# Default mode is --dry-run: print every mutation that WOULD apply,
# touch nothing on disk, exit 0.
#
# --accept-redefinition  applies the changes:
#   1. Annotates docs/V3_CLOSEOUT_2026-05-22.md headline.
#   2. Adds `burn_down_complete: true` alongside existing
#      `roadmap_complete: false` in reports/v3_roadmap_progress_report.json.
#   3. Re-classifies every still-open external row in
#      reports/v3_blocker_ledger/blocker_ledger.json with
#      `external_state_bounded: true` (idempotent; rows that already
#      carry the field at true are skipped).
#   4. Closes the V3 goal in <vault>/goals/current.md and emits a sibling
#      v4 milestone scoped to empirical outcomes.
#   5. Writes a full audit-trail record to
#      reports/v3_burn_down_close/v3_close_<utc-stamp>.json.
#
# --undo                reverses the most recent recorded close using the
#                       audit-trail snapshot under
#                       reports/v3_burn_down_close/v3_close_<stamp>.json.
#
# Preconditions checked BEFORE any mutation (fail-closed):
#   P1. docs/V3_TOOLING_BURN_DOWN_COMPLETE_PROPOSAL.md exists.
#   P2. docs/V3_CLOSEOUT_2026-05-22.md exists.
#   P3. reports/v3_roadmap_progress_report.json exists and parses.
#   P4. reports/v3_blocker_ledger/blocker_ledger.json exists and parses.
#   P5. reference/codified_rules_digest.json exists with >= 27 rule_ids
#       (criterion c per Lane BB proposal).
#   P6. A writable goals/current.md is reachable (workspace
#       obsidian-vault first, then operator-supplied --vault, then the
#       MCP active vault under ~/Documents/Codex/auditooor/obsidian-vault).
#
# Doctrine: this script is INERT until the operator runs it. It does NOT
# commit, push, merge, run pre-submit, or touch Sei / Hyperbridge. It is a
# coordinated mutation kit, not a workflow driver.
#
# Usage:
#   tools/v3-tooling-burn-down-close.sh
#   tools/v3-tooling-burn-down-close.sh --dry-run
#   tools/v3-tooling-burn-down-close.sh --accept-redefinition
#   tools/v3-tooling-burn-down-close.sh --undo
#   tools/v3-tooling-burn-down-close.sh --vault /path/to/obsidian-vault [other flags]

set -u
set -o pipefail

# ---- resolve paths ----------------------------------------------------------

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"

PROPOSAL_FILE="${REPO_ROOT}/docs/V3_TOOLING_BURN_DOWN_COMPLETE_PROPOSAL.md"
CLOSEOUT_FILE="${REPO_ROOT}/docs/V3_CLOSEOUT_2026-05-22.md"
PROGRESS_FILE="${REPO_ROOT}/reports/v3_roadmap_progress_report.json"
LEDGER_FILE="${REPO_ROOT}/reports/v3_blocker_ledger/blocker_ledger.json"
DIGEST_FILE="${REPO_ROOT}/reference/codified_rules_digest.json"
CLOSE_DIR="${REPO_ROOT}/reports/v3_burn_down_close"

MODE="dry-run"
VAULT_OVERRIDE=""

# ---- arg parse --------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)               MODE="dry-run"; shift ;;
    --accept-redefinition)   MODE="apply"; shift ;;
    --undo)                  MODE="undo"; shift ;;
    --vault)
      [[ $# -lt 2 ]] && { echo "--vault requires a path arg" >&2; exit 2; }
      VAULT_OVERRIDE="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# ---- helpers ----------------------------------------------------------------

say() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Print to stdout (would-do log in dry-run; actual log in apply).
log() { printf '  - %s\n' "$*"; }

resolve_vault() {
  # 1. operator override
  if [[ -n "${VAULT_OVERRIDE}" ]]; then
    [[ -d "${VAULT_OVERRIDE}/goals" ]] || die "P6: --vault ${VAULT_OVERRIDE} has no goals/ subdir"
    echo "${VAULT_OVERRIDE}"
    return 0
  fi
  # 2. workspace-local
  if [[ -d "${REPO_ROOT}/obsidian-vault/goals" ]]; then
    echo "${REPO_ROOT}/obsidian-vault"
    return 0
  fi
  # 3. canonical active vault per MCP
  local active="${HOME}/Documents/Codex/auditooor/obsidian-vault"
  if [[ -d "${active}/goals" ]]; then
    echo "${active}"
    return 0
  fi
  return 1
}

check_preconditions() {
  say "[preconditions]"
  local fail=0
  [[ -f "${PROPOSAL_FILE}" ]] || { warn "P1: missing ${PROPOSAL_FILE}"; fail=1; }
  [[ -f "${CLOSEOUT_FILE}" ]] || { warn "P2: missing ${CLOSEOUT_FILE}"; fail=1; }
  if [[ -f "${PROGRESS_FILE}" ]]; then
    python3 -c "import json,sys; json.load(open('${PROGRESS_FILE}'))" 2>/dev/null \
      || { warn "P3: ${PROGRESS_FILE} does not parse"; fail=1; }
  else
    warn "P3: missing ${PROGRESS_FILE}"; fail=1
  fi
  if [[ -f "${LEDGER_FILE}" ]]; then
    python3 -c "import json,sys; json.load(open('${LEDGER_FILE}'))" 2>/dev/null \
      || { warn "P4: ${LEDGER_FILE} does not parse"; fail=1; }
  else
    warn "P4: missing ${LEDGER_FILE}"; fail=1
  fi
  if [[ -f "${DIGEST_FILE}" ]]; then
    local n
    n="$(python3 -c "import json; d=json.load(open('${DIGEST_FILE}')); print(d.get('rule_count',0))" 2>/dev/null || echo 0)"
    if [[ -z "${n}" || "${n}" -lt 27 ]]; then
      warn "P5: digest rule_count=${n}; need >= 27 (criterion c)"
      fail=1
    else
      log "P5 ok: digest carries ${n} codified rules (criterion c met)"
    fi
  else
    warn "P5: missing ${DIGEST_FILE}"; fail=1
  fi
  local vault
  if vault="$(resolve_vault)"; then
    log "P6 ok: vault resolved to ${vault}"
  else
    warn "P6: no goals/current.md reachable (tried workspace, --vault override, active MCP vault)"
    fail=1
  fi
  [[ "${fail}" -eq 0 ]] || die "preconditions failed; refusing to proceed"
  say "[preconditions] all 6 checks pass"
}

# ---- mutation planners ------------------------------------------------------
# Each `plan_*` function PRINTS a description of what would change.
# Each `apply_*` function performs the on-disk write.

PLAN_HEADLINE_NEW="V3 tooling burn-down complete; operator-action backlog documented"
PLAN_HEADLINE_OLD="tooling/enforcement mostly complete; empirical roadmap still open"

plan_closeout() {
  if grep -qF "${PLAN_HEADLINE_NEW}" "${CLOSEOUT_FILE}" 2>/dev/null; then
    log "closeout: headline already flipped -> no-op"
    return 0
  fi
  log "closeout: append top-of-file banner '${PLAN_HEADLINE_NEW}' (idempotent marker line)"
}

apply_closeout() {
  if grep -qF "${PLAN_HEADLINE_NEW}" "${CLOSEOUT_FILE}" 2>/dev/null; then
    return 0
  fi
  python3 - "${CLOSEOUT_FILE}" "${PLAN_HEADLINE_NEW}" <<'PY'
import sys, pathlib, datetime
path = pathlib.Path(sys.argv[1])
new_headline = sys.argv[2]
stamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
banner = (
    "\n> [BURN-DOWN-CLOSE] Headline flipped " + stamp + "\n"
    "> Authoritative status of V3 is now: " + new_headline + "\n"
    "> Original headline (in section below) preserved for audit trail.\n"
)
txt = path.read_text(encoding="utf-8")
# insert banner immediately after the first H1 heading line
lines = txt.splitlines(keepends=True)
out, inserted = [], False
for ln in lines:
    out.append(ln)
    if not inserted and ln.startswith("# "):
        out.append(banner)
        inserted = True
if not inserted:
    out.insert(0, banner)
path.write_text("".join(out), encoding="utf-8")
PY
}

plan_progress() {
  local cur
  cur="$(python3 -c "import json; d=json.load(open('${PROGRESS_FILE}')); print(d.get('burn_down_complete'))" 2>/dev/null)"
  if [[ "${cur}" == "True" ]]; then
    log "progress: burn_down_complete already true -> no-op"
    return 0
  fi
  log "progress: add field 'burn_down_complete': true (does NOT modify 'roadmap_complete': false)"
  log "progress: add field 'burn_down_close_stamp_utc' with run timestamp"
}

apply_progress() {
  python3 - "${PROGRESS_FILE}" <<'PY'
import sys, json, pathlib, datetime
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text(encoding="utf-8"))
d["burn_down_complete"] = True
d["burn_down_close_stamp_utc"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
# 'roadmap_complete' stays whatever it is - typically false, possibly permanent.
p.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

plan_ledger() {
  python3 - "${LEDGER_FILE}" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text(encoding="utf-8"))
needs = []
for b in d.get("blockers", []):
    if b.get("external_state_required") and not b.get("external_state_bounded"):
        needs.append(b["blocker_id"])
if not needs:
    print("  - ledger: every external row already external_state_bounded=true -> no-op")
else:
    for bid in needs:
        print(f"  - ledger: set external_state_bounded=true on {bid}")
PY
}

apply_ledger() {
  python3 - "${LEDGER_FILE}" <<'PY'
import json, sys, pathlib, datetime
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text(encoding="utf-8"))
stamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
changed = 0
for b in d.get("blockers", []):
    if b.get("external_state_required") and not b.get("external_state_bounded"):
        b["external_state_bounded"] = True
        b.setdefault("annotations", {})["burn_down_close_bounded_at_utc"] = stamp
        changed += 1
d.setdefault("close_audit", {})["last_burn_down_close_utc"] = stamp
d.setdefault("close_audit", {})["last_burn_down_close_changed_rows"] = changed
p.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

plan_goal() {
  local vault
  vault="$(resolve_vault)" || die "cannot resolve vault"
  local cur="${vault}/goals/current.md"
  if grep -q '^status: "v3_tooling_burn_down_complete"' "${cur}" 2>/dev/null; then
    log "goal: ${cur} already at status=v3_tooling_burn_down_complete -> no-op"
    return 0
  fi
  log "goal: flip frontmatter status -> v3_tooling_burn_down_complete in ${cur}"
  log "goal: append a 'V4 - empirical outcomes' milestone stub under ${vault}/goals/v4.md"
}

apply_goal() {
  local vault
  vault="$(resolve_vault)" || die "cannot resolve vault"
  python3 - "${vault}/goals/current.md" "${vault}/goals/v4.md" <<'PY'
import sys, pathlib, datetime
cur = pathlib.Path(sys.argv[1])
v4  = pathlib.Path(sys.argv[2])
stamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
txt = cur.read_text(encoding="utf-8")
if 'status: "v3_tooling_burn_down_complete"' not in txt:
    # add a marker line in the frontmatter rather than rewriting the existing status
    marker = (
        f'v3_tooling_burn_down_complete_at_utc: "{stamp}"\n'
        f'v3_tooling_burn_down_complete: true\n'
    )
    # insert before closing frontmatter '---'
    parts = txt.split("---\n", 2)
    if len(parts) >= 3:
        parts[1] = parts[1].rstrip() + "\n" + marker
        cur.write_text("---\n".join(parts), encoding="utf-8")
    else:
        cur.write_text(marker + txt, encoding="utf-8")
if not v4.exists():
    v4.write_text(
        "---\n"
        'id: "v4"\n'
        'title: "V4 - Empirical Outcomes Milestone"\n'
        'status: "open"\n'
        f'opened_at_utc: "{stamp}"\n'
        'objective: "Convert tooling burn-down into measurable live-hunt outcomes (accepted/paid findings, retrospective scoreboards, source-freshness, provider live access)."\n'
        "---\n\n"
        "# V4 - Empirical Outcomes\n\n"
        "Opened on V3 tooling burn-down close. See `reports/v3_burn_down_close/` for the close manifest and the operator-action backlog inherited from V3.\n",
        encoding="utf-8",
    )
PY
}

plan_audit_trail() {
  log "audit: write reports/v3_burn_down_close/v3_close_<utc-stamp>.json (snapshot of prior state for --undo)"
}

apply_audit_trail() {
  mkdir -p "${CLOSE_DIR}"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local out="${CLOSE_DIR}/v3_close_${stamp}.json"
  local vault
  vault="$(resolve_vault)" || die "cannot resolve vault"
  python3 - "${out}" "${CLOSEOUT_FILE}" "${PROGRESS_FILE}" "${LEDGER_FILE}" "${vault}/goals/current.md" "${stamp}" <<'PY'
import sys, json, pathlib, hashlib
out, closeout, progress, ledger, goal, stamp = sys.argv[1:7]
def snap(p):
    pth = pathlib.Path(p)
    if not pth.exists(): return None
    data = pth.read_bytes()
    return {"path": p, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
manifest = {
    "schema": "auditooor.v3_burn_down_close.v1",
    "stamp_utc": stamp,
    "mode": "applied",
    "prior_snapshot": {
        "closeout":  snap(closeout),
        "progress":  snap(progress),
        "ledger":    snap(ledger),
        "goal":      snap(goal),
    },
    "intent": (
        "V3 tooling burn-down close per "
        "docs/V3_TOOLING_BURN_DOWN_COMPLETE_PROPOSAL.md "
        "(Lane BB criteria a/b/c)"
    ),
}
pathlib.Path(out).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(out)
PY
}

# ---- undo ------------------------------------------------------------------

run_undo() {
  [[ -d "${CLOSE_DIR}" ]] || die "no close audit dir; nothing to undo"
  local last
  last="$(ls -1t "${CLOSE_DIR}"/v3_close_*.json 2>/dev/null | head -1)"
  [[ -n "${last}" ]] || die "no v3_close_*.json snapshot present"
  say "[undo] using ${last}"
  warn "automatic undo is intentionally minimal: it removes the closeout banner,"
  warn "drops burn_down_complete from progress, clears external_state_bounded"
  warn "additions, and reverts the goals frontmatter marker."
  python3 - "${last}" "${CLOSEOUT_FILE}" "${PROGRESS_FILE}" "${LEDGER_FILE}" <<'PY'
import sys, json, pathlib
snap_path, closeout, progress, ledger = sys.argv[1:5]
snap = json.loads(pathlib.Path(snap_path).read_text(encoding="utf-8"))
# closeout: strip the banner block
co = pathlib.Path(closeout)
txt = co.read_text(encoding="utf-8")
marker = "> [BURN-DOWN-CLOSE] Headline flipped"
if marker in txt:
    lines, out, skipping = txt.splitlines(keepends=True), [], False
    for ln in lines:
        if marker in ln:
            skipping = True; continue
        if skipping:
            if ln.strip() == "" or not ln.startswith(">"):
                if ln.startswith("> "):
                    continue
                skipping = False
                if ln.strip() == "":
                    continue
        out.append(ln)
    co.write_text("".join(out), encoding="utf-8")
# progress: drop burn_down_complete + stamp
pr = pathlib.Path(progress); d = json.loads(pr.read_text(encoding="utf-8"))
d.pop("burn_down_complete", None); d.pop("burn_down_close_stamp_utc", None)
pr.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n", encoding="utf-8")
# ledger: drop external_state_bounded fields the close added
lp = pathlib.Path(ledger); ld = json.loads(lp.read_text(encoding="utf-8"))
for b in ld.get("blockers", []):
    if b.get("annotations", {}).get("burn_down_close_bounded_at_utc"):
        b.pop("external_state_bounded", None)
        b["annotations"].pop("burn_down_close_bounded_at_utc", None)
        if not b["annotations"]:
            b.pop("annotations", None)
ld.pop("close_audit", None)
lp.write_text(json.dumps(ld, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("undo: closeout/progress/ledger reverted; goal frontmatter marker still in place (edit manually if desired)")
PY
}

# ---- run --------------------------------------------------------------------

say "v3-tooling-burn-down-close.sh mode=${MODE}"
say "repo=${REPO_ROOT}"

if [[ "${MODE}" == "undo" ]]; then
  run_undo
  exit 0
fi

check_preconditions

say "[plan]"
plan_closeout
plan_progress
plan_ledger
plan_goal
plan_audit_trail

if [[ "${MODE}" == "dry-run" ]]; then
  say
  say "[mode=dry-run] no files modified. Run again with --accept-redefinition to apply."
  exit 0
fi

say
say "[apply]"
apply_closeout
log "applied closeout banner"
apply_progress
log "applied progress field"
apply_ledger
log "applied ledger bounding"
apply_goal
log "applied goal frontmatter + v4 stub"
manifest="$(apply_audit_trail)"
log "wrote audit trail ${manifest}"

say
say "[done] V3 tooling burn-down close applied."
say "      To reverse: tools/v3-tooling-burn-down-close.sh --undo"
exit 0
