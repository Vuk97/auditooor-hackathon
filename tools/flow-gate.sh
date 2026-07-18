#!/usr/bin/env bash
# flow-gate.sh — hard gate enforcing the FULL canonical flow (new R38 tool).
#
# The existing pre-iter-check.sh only verifies a handful of files exist.
# It does NOT verify that the operator ran the canonical flow in order,
# and it does NOT verify that R34/R37 tools were invoked at least once.
#
# This stricter gate checks each step of the canonical flow:
#   Step  1: setup-workspace.sh → workspace exists + SESSION_LOG.md
#   Step  2: fetch-scope.sh → SCOPE.md
#   Step  3: init-rubric-coverage.sh → RUBRIC_COVERAGE.md with ≥1 row
#   Step  4: fetch-targets.sh → targets.tsv populated + src/ cloned
#   Step  5: extract-oos.sh → OOS_CHECKLIST.md + SEVERITY_CAPS.md
#   Step  6: orient-from-audits.sh → PRIOR_CONCERNS.md (if prior audits present)
#   Step  7: pre-iter-check.sh (existing gate)
#   Step  8: scan.sh → PATTERN_HITS.md + SCAN_REPORT.md
#   Step  9: auto-triage.sh → AUTO_TRIAGE_QUEUE.md
#   Step 10: adversarial-read.sh or attack-tree.sh → at least one ATTACK_TREE/ADV_* output
#   Step 11: gen-invariants.sh → at least one poc-tests/Invariant_*.t.sol
#   Step 12: skill-state.sh init → .skill_state.yaml
#   Pre-submit: pre-submit-check.sh on each draft submission
#
# Exit codes:
#   0 — all green
#   1 — HARD STOP — list missing steps
#   2 — SOFT WARN — optional steps skipped (prior_audits absent, gen-invariants not run, etc.)
#
# Usage:
#   ./tools/flow-gate.sh <workspace> [--strict]

set -u
WS="${1:-}"
STRICT=0
POST_ONBOARD=0
DASHBOARD=0
shift 1 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --strict) STRICT=1; shift ;;
    --post-onboard) POST_ONBOARD=1; shift ;;
    --dashboard) DASHBOARD=1; shift ;;
    *) shift ;;
  esac
done

if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <workspace> [--strict] [--post-onboard] [--dashboard]" >&2
  exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARD=0; WARN=0

rubric_coverage_has_rows() {
  local rubric="$1"
  [ -f "$rubric" ] || return 1

  # Preserve the legacy init-rubric-coverage.sh format while accepting newer
  # curated rows such as `BA-C1`, `BDL-H2`, and `SC-M3` that carry checklist IDs
  # plus populated verdict/status cells.
  awk -F'|' '
    function trim(s) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
      return s
    }
    function is_verdict(s) {
      s = trim(s)
      return s ~ /(PASS|SUBMITTED|PARTIAL|NOT CHECKED|OOS|N\/A|N\/A|✅|🚀|⚠️|🚫|❌|📋)/
    }
    /^\|/ {
      first = trim($2)
      if (first == "" || first ~ /^-+$/ || first ~ /^(#|Row|Tier|Finding)$/) {
        next
      }
      # Legacy rows: first cell is the severity tier.
      if (first ~ /^(Critical|High|Medium|Low)$/) {
        found = 1
        exit
      }
      # Generated rows: C1/H1/M1/L1.
      # Curated rows: BA-C1, BDL-H2, SC-M3, etc.
      if (first ~ /^([A-Z]+-)?[CHML][0-9]+([[:space:]]*\([^)]+\))?$/ || first ~ /^C4-(HIGH|MEDIUM|QA|POC|OOS.*)$/) {
        for (i = 3; i <= NF - 1; i++) {
          if (is_verdict($i)) {
            found = 1
            exit
          }
        }
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$rubric"
}

if [ "${FLOW_GATE_RUBRIC_ONLY:-0}" = "1" ]; then
  rubric_coverage_has_rows "$WS/RUBRIC_COVERAGE.md"
  exit $?
fi

source_root_has_solidity() {
  local ws="$1"
  local root
  for root in \
    "$ws/src" \
    "$ws/contracts" \
    "$ws/external/contracts/src" \
    "$ws"/external/*/contracts \
    "$ws"/external/*/src \
    "$ws/packages/contracts-bedrock/src" \
    "$ws/packages/contracts/src" \
    "$ws/external/base/packages/contracts-bedrock/src"
  do
    if [ -d "$root" ] && find "$root" -name "*.sol" -not -path "*/lib/*" -not -path "*/test/*" -not -path "*/mocks/*" -print -quit 2>/dev/null | grep -q .; then
      return 0
    fi
  done
  if [ -f "$ws/targets.tsv" ]; then
    while IFS="$(printf '\t')" read -r target _rest; do
      case "$target" in
        ''|\#*) continue ;;
      esac
      case "$target" in
        /*) root="$target" ;;
        *) root="$ws/$target" ;;
      esac
      if [ -f "$root" ] && [ "${root##*.}" = "sol" ]; then
        return 0
      fi
      if [ -d "$root" ] && find "$root" -name "*.sol" -not -path "*/lib/*" -not -path "*/test/*" -not -path "*/mocks/*" -print -quit 2>/dev/null | grep -q .; then
        return 0
      fi
    done < "$ws/targets.tsv"
  fi
  return 1
}

source_root_has_rust() {
  local ws="$1"
  local root target
  for root in \
    "$ws/src/contracts" \
    "$ws/contracts" \
    "$ws/src" \
    "$ws"
  do
    if [ -d "$root" ] && find "$root" -name "*.rs" -not -path "*/target/*" -not -path "*/tests/*" -not -path "*/fuzz/*" -print -quit 2>/dev/null | grep -q .; then
      return 0
    fi
  done
  if [ -f "$ws/targets.tsv" ]; then
    while IFS="$(printf '\t')" read -r target _rest; do
      case "$target" in
        ''|\#*) continue ;;
      esac
      case "$target" in
        /*) root="$target" ;;
        *) root="$ws/$target" ;;
      esac
      if [ -f "$root" ] && [ "${root##*.}" = "rs" ]; then
        return 0
      fi
      if [ -d "$root" ] && find "$root" -name "*.rs" -not -path "*/target/*" -not -path "*/tests/*" -not -path "*/fuzz/*" -print -quit 2>/dev/null | grep -q .; then
        return 0
      fi
    done < "$ws/targets.tsv"
  fi
  return 1
}

source_root_has_go() {
  local ws="$1"
  local root target
  for root in \
    "$ws/external" \
    "$ws/src" \
    "$ws"
  do
    if [ -d "$root" ] && find "$root" -name "*.go" -not -path "*/vendor/*" -not -path "*/testdata/*" -print -quit 2>/dev/null | grep -q .; then
      return 0
    fi
  done
  if [ -f "$ws/targets.tsv" ]; then
    while IFS="$(printf '\t')" read -r target _rest; do
      case "$target" in
        ''|\#*) continue ;;
      esac
      case "$target" in
        /*) root="$target" ;;
        *) root="$ws/$target" ;;
      esac
      if [ -f "$root" ] && [ "${root##*.}" = "go" ]; then
        return 0
      fi
      if [ -d "$root" ] && find "$root" -name "*.go" -not -path "*/vendor/*" -not -path "*/testdata/*" -print -quit 2>/dev/null | grep -q .; then
        return 0
      fi
    done < "$ws/targets.tsv"
  fi
  return 1
}

source_solidity_count() {
  local ws="$1"
  local root target count total=0
  for root in \
    "$ws/src" \
    "$ws/contracts" \
    "$ws/external/contracts/src" \
    "$ws"/external/*/contracts \
    "$ws"/external/*/src \
    "$ws/packages/contracts-bedrock/src" \
    "$ws/packages/contracts/src" \
    "$ws/external/base/packages/contracts-bedrock/src"
  do
    if [ -d "$root" ]; then
      count=$(find "$root" -name "*.sol" -not -path "*/lib/*" -not -path "*/test/*" -not -path "*/mocks/*" 2>/dev/null | wc -l | tr -d ' ')
      total=$((total + ${count:-0}))
    fi
  done
  if [ -f "$ws/targets.tsv" ]; then
    while IFS="$(printf '\t')" read -r target _rest; do
      case "$target" in
        ''|\#*) continue ;;
      esac
      case "$target" in
        /*) root="$target" ;;
        *) root="$ws/$target" ;;
      esac
      if [ -f "$root" ] && [ "${root##*.}" = "sol" ]; then
        total=$((total + 1))
      elif [ -d "$root" ]; then
        count=$(find "$root" -name "*.sol" -not -path "*/lib/*" -not -path "*/test/*" -not -path "*/mocks/*" 2>/dev/null | wc -l | tr -d ' ')
        total=$((total + ${count:-0}))
      fi
    done < "$ws/targets.tsv"
  fi
  printf "%s\n" "$total"
}

# R64 enforcement: Step 0 — loop-gate. Check prior-round self-improvement loop
# is closed before starting a new round. HARD STOP if any open submission is
# >30 days old without an outcome; SOFT WARN on lesser breakage.
#
# V3 follow-up (operator-reported on dydx / Sei refresh, 2026-05-23):
# loop-gate is a ROUND-CLOSURE gate and must NOT fire on the scan / refresh
# stage. When flow-gate is invoked as --post-onboard (engage.py stage_scan
# always passes this), demote loop-gate to a neutral SKIP. A long-running
# engagement where the team's filings sit in 30+ day triager review is
# normal and should not block a fresh artifact refresh.
printf -- "── Step 0: loop-gate (R64 enforcement — prior-round self-improvement loop) ──\n"
LOOPGATE_SCRIPT="$AUDITOOOR_DIR/tools/loop-gate.sh"
if [ "$POST_ONBOARD" = 1 ]; then
  printf "  [•] SKIP (post-onboard / refresh) — loop-gate is a round-closure gate, not a refresh gate\n"
elif [ -x "$LOOPGATE_SCRIPT" ]; then
  LOOPGATE_RC=0
  bash "$LOOPGATE_SCRIPT" "$WS" || LOOPGATE_RC=$?
  case "$LOOPGATE_RC" in
    0) printf "  [✓] loop healthy\n" ;;
    2) printf "  [!] SOFT WARN — run tools/ledger-sync.sh before next round (gate continues)\n"; WARN=$((WARN+1)) ;;
    3) printf "  [✗] HARD STOP — open submissions stale >30 days without outcome. Update rationale.txt and re-run.\n"; HARD=$((HARD+1)) ;;
    *) printf "  [!] loop-gate returned unexpected code %s — SOFT WARN\n" "$LOOPGATE_RC"; WARN=$((WARN+1)) ;;
  esac
else
  printf "  [•] loop-gate.sh not present — skipping (pre-R64)\n"
fi

# R49 Bug 3: post-onboard mode — when a workspace was just scaffolded by
# onboard.sh and scan.sh has not yet been invoked, Phase 2/3 checks would HARD
# STOP. Auto-detect a fresh workspace (≤ 5 min old) OR honor the explicit flag.
# Phase 2/3 steps become SKIP (neutral) rather than HARD STOP.
#
# I-11 follow-up (PR #159 CI green): the original one-liner combined BSD
# (`stat -f %m`) and GNU (`stat -c %Y`) inside a single `$(... || ... )`. On
# GNU coreutils, `stat -f %m FILE` is parsed as `stat --file-system %m FILE`
# (where `%m` is treated as a non-existent filename). GNU stat still emits its
# multi-line human-readable filesystem block to stdout for the valid FILE arg
# before exiting non-zero, and that output (which begins with `  File: ...`)
# gets captured by the surrounding `$(...)` and concatenated with the GNU
# fallback's numeric mtime. The combined string then enters arithmetic context,
# bash tries to evaluate the bare token `File` as a variable, and `set -u`
# aborts the script BEFORE Step 13 banners are emitted — breaking
# tools/tests/test_flow_gate_orphan_age.py. Fix: capture the mtime into a
# default-initialised intermediate (`WS_MTIME=""`), pick the right `stat`
# invocation by `uname`, and only fall through if both fail. This eliminates
# the cross-tool stdout leak and keeps the variable bound under `set -u`.
WS_MTIME=""
if [ "$(uname 2>/dev/null)" = "Darwin" ]; then
  WS_MTIME=$(stat -f %m "$WS" 2>/dev/null || stat -c %Y "$WS" 2>/dev/null || echo 0)
else
  WS_MTIME=$(stat -c %Y "$WS" 2>/dev/null || stat -f %m "$WS" 2>/dev/null || echo 0)
fi
# Guard against any non-numeric leak (e.g. exotic stat builds): default to 0.
case "$WS_MTIME" in
  ''|*[!0-9]*) WS_MTIME=0 ;;
esac
WS_AGE_S=$(( $(date +%s) - WS_MTIME ))
if [ "$POST_ONBOARD" = 0 ] && [ "$WS_AGE_S" -lt 300 ] && [ "$WS_AGE_S" -ge 0 ]; then
  POST_ONBOARD=1
  printf "[flow-gate] workspace age %ds < 5min — auto-enabling --post-onboard (Phase 2/3 steps will SKIP)\n" "$WS_AGE_S"
fi

# check_skip emits a neutral [skip] marker for onboarding-only workspaces.
check_skip() {
  local label="$1"
  printf "  [•] SKIP (post-onboard) — %s\n" "$label"
}

printf '\n=== auditooor flow-gate: %s ===\n\n' "$WS"

check_hard() {
  local label="$1"; shift
  if eval "$@" >/dev/null 2>&1; then
    printf "  [✓] %s\n" "$label"
  else
    printf "  [✗] HARD STOP — %s\n" "$label"
    HARD=1
  fi
}

check_warn() {
  local label="$1"; shift
  if eval "$@" >/dev/null 2>&1; then
    printf "  [✓] %s\n" "$label"
  else
    printf "  [⚠] SOFT WARN — %s\n" "$label"
    WARN=1
  fi
}

# V3 follow-up (operator-reported on dydx / Sei refresh, 2026-05-23):
# `check_onboarding` wraps a check that is a HARD STOP during onboarding
# but only a SOFT WARN under --post-onboard (refresh / scan stage). The
# onboarding-stage scaffolding files (SESSION_LOG.md, FINDINGS.md,
# AUDIT.md, SCOPE.md sanity, RUBRIC_COVERAGE.md) MUST NOT block an
# artifact refresh on an aged workspace that was onboarded with a prior
# convention. Onboarding-stage flow-gate calls (no --post-onboard) keep
# the HARD STOP behavior, so genuine onboarding is still enforced.
check_onboarding() {
  if [ "$POST_ONBOARD" = 1 ]; then
    check_warn "$@"
  else
    check_hard "$@"
  fi
}

printf -- "── Step 1: setup-workspace.sh ──\n"
check_onboarding "SESSION_LOG.md exists"          "[ -f '$WS/SESSION_LOG.md' ]"
check_onboarding "FINDINGS.md exists"             "[ -f '$WS/FINDINGS.md' ]"
check_onboarding "AUDIT.md exists"                "[ -f '$WS/AUDIT.md' ]"

printf -- "── Step 2: fetch-scope.sh ──\n"
check_hard "SCOPE.md exists"                "[ -f '$WS/SCOPE.md' ]"
check_onboarding "SCOPE.md has > 30 lines"        "[ \$(wc -l < '$WS/SCOPE.md') -gt 30 ]"

printf -- "── Step 3: init-rubric-coverage.sh ──\n"
check_onboarding "RUBRIC_COVERAGE.md exists"      "[ -f '$WS/RUBRIC_COVERAGE.md' ]"
check_onboarding "RUBRIC_COVERAGE.md has rows"    "rubric_coverage_has_rows '$WS/RUBRIC_COVERAGE.md'"

printf -- "── Step 3.5: memory-context requirements ──\n"
MEMORY_STRICT=0
if [ "$STRICT" = 1 ] || [ "${STRICT_MEMORY_CONTEXT:-0}" = "1" ] || [ "${REQUIRE_MEMORY_CONTEXT:-0}" = "1" ]; then
  MEMORY_STRICT=1
fi
MEMORY_AUTO_RC=0
MEMORY_AUTO_OUT=$(python3 "$AUDITOOOR_DIR/tools/memory-auto-link.py" --workspace "$WS" --check 2>&1) || MEMORY_AUTO_RC=$?
case "$MEMORY_AUTO_RC" in
  0) printf "  [✓] memory_requirements.json valid\n" ;;
  1) printf "  [✗] HARD STOP — memory requirements invalid.%b\n" "\n${MEMORY_AUTO_OUT}"; HARD=1 ;;
  2)
    if [ "$MEMORY_STRICT" = 1 ]; then
      printf "  [✗] HARD STOP — memory requirements missing/stale under strict memory context.%b\n" "\n${MEMORY_AUTO_OUT}"
      HARD=1
    else
      printf "  [⚠] SOFT WARN — memory requirements missing/stale. Run: python3 tools/memory-auto-link.py --workspace %s --write%b\n" "$WS" "\n${MEMORY_AUTO_OUT}"
      WARN=1
    fi
    ;;
  *) printf "  [✗] HARD STOP — memory-auto-link returned unexpected code %s.%b\n" "$MEMORY_AUTO_RC" "\n${MEMORY_AUTO_OUT}"; HARD=1 ;;
esac
MEMORY_LOAD_RC=0
MEMORY_LOAD_OUT=$(python3 "$AUDITOOOR_DIR/tools/memory-context-load.py" --workspace "$WS" --check 2>&1) || MEMORY_LOAD_RC=$?
case "$MEMORY_LOAD_RC" in
  0) printf "  [✓] memory_context_receipt.json valid and fresh\n" ;;
  1) printf "  [✗] HARD STOP — memory context receipt invalid.%b\n" "\n${MEMORY_LOAD_OUT}"; HARD=1 ;;
  2)
    if [ "$MEMORY_STRICT" = 1 ]; then
      printf "  [✗] HARD STOP — memory context receipt missing/stale under strict memory context.%b\n" "\n${MEMORY_LOAD_OUT}"
      HARD=1
    else
      printf "  [⚠] SOFT WARN — memory context receipt missing/stale. Run: python3 tools/memory-context-load.py --workspace %s --from-requirements --write-receipt%b\n" "$WS" "\n${MEMORY_LOAD_OUT}"
      WARN=1
    fi
    ;;
  *) printf "  [✗] HARD STOP — memory-context-load returned unexpected code %s.%b\n" "$MEMORY_LOAD_RC" "\n${MEMORY_LOAD_OUT}"; HARD=1 ;;
esac

printf -- "── Step 4: fetch-targets.sh ──\n"
check_hard "targets.tsv populated"          "grep -vE '^#|^\\s*\$' '$WS/targets.tsv' | head -1 | grep -qE '.'"
check_hard "source tree has Solidity, Rust, or Go" "source_root_has_solidity '$WS' || source_root_has_rust '$WS' || source_root_has_go '$WS'"

printf -- "── Step 4.5: env-check.sh (R38 Issue #137) ──\n"
# Only enforce env-check if env-check.sh itself is present (backwards compat)
if [ -x "$AUDITOOOR_DIR/tools/env-check.sh" ]; then
  check_hard "env-check.sh passes (solc / forge build / slither smoke)"  "$AUDITOOOR_DIR/tools/env-check.sh '$WS' >/dev/null 2>&1 || [ \$? = 5 ]"
fi

printf -- "── Step 5: extract-oos.sh (R38) ──\n"
# I-14: previously check_hard's negative case printed "HARD STOP — <file>
# exists" which read as "the file exists" rather than "the assertion that the
# file exists FAILED". Use an inline check so the failure message names the
# missing file directly + tells the operator how to scaffold it.
if [ -f "$WS/OOS_CHECKLIST.md" ]; then
  printf "  [✓] OOS_CHECKLIST.md exists\n"
else
  printf "  [✗] HARD STOP — OOS_CHECKLIST.md MISSING (run tools/extract-oos.sh %s to scaffold)\n" "$WS"
  HARD=1
fi
check_warn "OOS_CHECKLIST has ≥1 bullet"    "grep -qE '^- \\[ \\] \\*\\*OOS-' '$WS/OOS_CHECKLIST.md'"
if [ -f "$WS/SEVERITY_CAPS.md" ]; then
  printf "  [✓] SEVERITY_CAPS.md exists\n"
else
  printf "  [✗] HARD STOP — SEVERITY_CAPS.md MISSING (run tools/extract-oos.sh %s to scaffold)\n" "$WS"
  HARD=1
fi

printf -- "── Step 6: orient-from-audits.sh ──\n"
# R49: fixed guard — `ls ... | head -1 >/dev/null` always succeeded even with
# no matches, falsely claiming "prior audits present". Use compgen or a
# literal glob-expansion check.
_have_prior_audits() {
  # /tmp/audit_*.txt
  for f in /tmp/audit_*.txt; do [ -f "$f" ] && return 0; done
  for f in /tmp/cantina_*.txt /tmp/quantstamp_*.txt; do [ -f "$f" ] && return 0; done
  # <ws>/prior_audits/*.pdf
  for f in "$WS/prior_audits/"*.pdf; do [ -f "$f" ] && return 0; done
  for f in "$WS/prior_audits/"*.txt; do [ -f "$f" ] && return 0; done
  # Some handoff workspaces keep relayed/adjacent prior reports in named
  # sibling dirs after manual intake. Treat those as real prior-audit evidence
  # for the orient check instead of falsely printing "no prior audits".
  for dir in "$WS/cantina-pdfs" "$WS/external-prior-audits" "$WS/known-vulns-pdf"; do
    [ -d "$dir" ] || continue
    for f in "$dir/"*.pdf "$dir/"*.txt; do [ -f "$f" ] && return 0; done
  done
  return 1
}
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "PRIOR_CONCERNS.md (post-onboard: orient step runs later)"
elif _have_prior_audits; then
  check_hard "PRIOR_CONCERNS.md exists (prior audits present)"  "[ -f '$WS/PRIOR_CONCERNS.md' ]"
else
  printf "  [⚠] no prior-audit PDFs/.txts detected — skipping orient check\n"
fi

printf -- "── Step 7: pre-iter-check.sh ──\n"
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "pre-iter-check.sh (post-onboard: no iter yet)"
else
  check_hard "pre-iter-check.sh passes"       "$AUDITOOOR_DIR/tools/pre-iter-check.sh '$WS' >/dev/null 2>&1"
fi

printf -- "── Step 8: scan.sh ──\n"
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "SCAN_REPORT.md / PATTERN_HITS.md / custom-detectors.log (run scan.sh next)"
else
  check_warn "SCAN_REPORT.md exists"          "[ -f '$WS/SCAN_REPORT.md' ]"
  check_warn "PATTERN_HITS.md exists"         "[ -f '$WS/PATTERN_HITS.md' ]"
  check_warn "custom-detectors.log exists"    "[ -f '$WS/custom-detectors.log' ]"
fi
# R38 Issue #140: verify custom-detectors.log has ACTUAL signal, not just exists
if [ "$POST_ONBOARD" = 0 ] && [ -f "$WS/custom-detectors.log" ]; then
  if grep -qE '\[LOW\]|\[MEDIUM\]|\[HIGH\]|\[INFO\]|\[done\] total hits:|\[clean\] 0 findings' "$WS/custom-detectors.log"; then
    printf "  [✓] custom-detectors.log has scan signal (hits OR explicit [done]/[clean])\n"
  else
    printf "  [⚠] SOFT WARN — custom-detectors.log exists but no scan signal found. Either scan failed silently (Issue #133) or detector list only was written. Try tools/scan-per-module.sh \$WS\n"
    WARN=1
  fi
fi

printf -- "── Step 9: auto-triage.sh ──\n"
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "AUTO_TRIAGE_QUEUE.md (runs after scan)"
else
  check_warn "AUTO_TRIAGE_QUEUE.md exists"    "[ -f '$WS/AUTO_TRIAGE_QUEUE.md' ] || [ -f '$WS/auto_triage_brief.md' ]"
fi

printf -- "── Step 10: adversarial-read.sh / attack-tree.sh ──\n"
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "attack-tree / adversarial-read artifacts (runs after scan)"
else
  check_warn "≥1 ATTACK_TREE_* or adversarial_* file" "ls '$WS'/ATTACK_TREE_*.md '$WS'/adversarial_*.md 2>/dev/null | head -1 | grep -qE '.'"
fi

printf -- "── Step 11: gen-invariants.sh ──\n"
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "Invariant_*.t.sol (runs after scan)"
elif ! source_root_has_solidity "$WS"; then
  printf "  [•] SKIP — no Solidity source detected; Forge Invariant_*.t.sol generation is not applicable\n"
else
  check_warn "≥1 Invariant_*.t.sol in poc-tests" "ls '$WS/poc-tests/Invariant_'*.t.sol 2>/dev/null | head -1 | grep -qE '.'"
fi

printf -- "── Step 12: skill-state.sh ──\n"
check_warn ".skill_state.yaml exists"       "[ -f '$WS/.skill_state.yaml' ]"

printf -- "── Step 13: agent-dispatch audit trail (R42C Issue #151, R43 U1 strict, I-11 age-aware) ──\n"
# Every non-brief, non-INDEX agent output must have a corresponding brief_*.md
# whose timestamp ≤ the output's timestamp AND whose name-prefix tokens overlap
# meaningfully (≥1 shared slug/contract token). Otherwise it's an orphan =
# evidence the operator dispatched an agent without OOS/CAPS/PRIOR_CONCERNS.
#
# Naming conventions (see dispatch-capture.sh):
#   brief:   brief_<TS>_<contract>.md           (TS = YYYYMMDDTHHMMSSZ)
#   output:  <TS>_<agent>_<slug>.md
#
# I-11 (PR #158 audit): file mtime determines relevance. Orphans modified within
# THIS_SESSION_HOURS (default 24h) are real flow violations → SOFT WARN (default)
# or HARD STOP (--strict). Orphans older than that are prior-session artefacts →
# auto-archived NON-DESTRUCTIVELY into agent_outputs/_archive_<YYYY-MM-DD>/ and
# reported in the soft-warn message. --strict semantics for fresh orphans are
# unchanged.
THIS_SESSION_HOURS="${THIS_SESSION_HOURS:-24}"
if [ -d "$WS/agent_outputs" ] && ls "$WS/agent_outputs/"*.md >/dev/null 2>&1; then
  ORPHANS=0
  ORPHAN_LIST=""
  ARCHIVED=0
  ARCHIVE_LIST=""
  ARCHIVE_DATE=$(date -u +%Y-%m-%d 2>/dev/null || echo "unknown")
  ARCHIVE_DIR="$WS/agent_outputs/_archive_${ARCHIVE_DATE}"
  # find -mmin works portably on BSD (macOS) and GNU find. +N = strictly older than N min.
  MMIN_THRESHOLD=$(( THIS_SESSION_HOURS * 60 ))
  # Collect briefs as "TS|tokens" records (tokens = lowercase, non-empty, length≥3)
  BRIEFS_TMP=$(mktemp 2>/dev/null || echo "/tmp/flowgate_briefs_$$")
  : > "$BRIEFS_TMP"
  for b in "$WS/agent_outputs/brief_"*.md; do
    [ -f "$b" ] || continue
    bbase=$(basename "$b" .md)
    # Strip leading "brief_"
    rest="${bbase#brief_}"
    # First field = TS, remainder = tokens joined by "_"
    b_ts="${rest%%_*}"
    b_tok="${rest#*_}"
    b_tok_lc=$(echo "$b_tok" | tr '[:upper:]' '[:lower:]' | tr '_.-' '   ')
    printf '%s|%s\n' "$b_ts" "$b_tok_lc" >> "$BRIEFS_TMP"
  done

  for out in "$WS/agent_outputs/"*.md; do
    [ -f "$out" ] || continue
    obase=$(basename "$out" .md)
    # Skip briefs themselves + INDEX
    [[ "$obase" == brief_* ]] && continue
    [[ "$obase" == INDEX ]] && continue
    [[ "$obase" == r3* ]] && continue  # legacy sessions pre-R42C

    # Parse output filename: <TS>_<agent>_<slug> (TS is first token if it matches pattern)
    o_ts="${obase%%_*}"
    # Validate TS looks like YYYYMMDDTHHMMSSZ (17 chars, digit+T+digit+Z). If not,
    # treat the whole name as tokens and use TS=99999999T999999Z (always latest).
    if [[ "$o_ts" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
      o_tok="${obase#*_}"
    else
      o_ts="99999999T999999Z"
      o_tok="$obase"
    fi
    o_tok_lc=$(echo "$o_tok" | tr '[:upper:]' '[:lower:]' | tr '_.-' '   ')

    # Find matching brief: TS ≤ output TS AND ≥1 token overlap (len≥3)
    matched=0
    while IFS='|' read -r b_ts b_tok_lc; do
      [ -z "$b_ts" ] && continue
      # Timestamp comparison: string-compare works because fixed-width ISO.
      if [ "$b_ts" \> "$o_ts" ]; then
        continue
      fi
      # Token overlap check
      for tok in $o_tok_lc; do
        [ ${#tok} -lt 3 ] && continue
        case " $b_tok_lc " in
          *" $tok "*) matched=1; break ;;
        esac
      done
      [ $matched = 1 ] && break
    done < "$BRIEFS_TMP"

    if [ $matched = 0 ]; then
      # I-11: distinguish this-session orphan (fresh, mtime within THIS_SESSION_HOURS)
      # from prior-session orphan (older → auto-archive non-destructively).
      is_old=0
      if find "$out" -maxdepth 0 -mmin "+${MMIN_THRESHOLD}" 2>/dev/null | grep -q .; then
        is_old=1
      fi
      if [ "$is_old" = 1 ]; then
        # Prior-session orphan → auto-archive (non-destructive move).
        mkdir -p "$ARCHIVE_DIR" 2>/dev/null || true
        if mv "$out" "$ARCHIVE_DIR/" 2>/dev/null; then
          ARCHIVED=$((ARCHIVED+1))
          ARCHIVE_LIST="$ARCHIVE_LIST\n      - $(basename "$out") → _archive_${ARCHIVE_DATE}/"
        else
          # Move failed (e.g. read-only FS) — fall back to counting it as an orphan
          # so we don't silently drop the violation.
          ORPHANS=$((ORPHANS+1))
          ORPHAN_LIST="$ORPHAN_LIST\n      - $(basename "$out") (archive move failed)"
        fi
      else
        ORPHANS=$((ORPHANS+1))
        ORPHAN_LIST="$ORPHAN_LIST\n      - $(basename "$out")"
      fi
    fi
  done
  rm -f "$BRIEFS_TMP"

  if [ $ARCHIVED -gt 0 ]; then
    printf "  [⚠] AUTO-ARCHIVE — %d prior-session orphan(s) older than %sh moved to agent_outputs/_archive_%s/ (non-destructive, I-11).%b\n" \
      "$ARCHIVED" "$THIS_SESSION_HOURS" "$ARCHIVE_DATE" "$ARCHIVE_LIST"
    WARN=1
  fi

  if [ $ORPHANS -gt 0 ]; then
    if [ "$STRICT" = 1 ]; then
      printf "  [✗] HARD STOP — %d this-session orphan agent output(s) without matching brief_*.md (Issue #151; mtime ≤%sh).%b\n" "$ORPHANS" "$THIS_SESSION_HOURS" "$ORPHAN_LIST"
      printf "      Remediation: for each orphan, either (a) re-dispatch via tools/agent-dispatch-enforced.sh to generate a matching brief_<TS>_<slug>.md (TS ≤ output TS), or (b) move the orphan into a _legacy/ subdir (pre-R42C artifacts).\n"
      HARD=1
    else
      printf "  [⚠] SOFT WARN — %d this-session orphan agent output(s) without matching brief_*.md (Issue #151 flow violation; mtime ≤%sh).%b\n" "$ORPHANS" "$THIS_SESSION_HOURS" "$ORPHAN_LIST"
      printf "      Run with --strict to HARD STOP. Remediation: dispatch via tools/agent-dispatch-enforced.sh.\n"
      WARN=1
    fi
  elif [ $ARCHIVED -eq 0 ]; then
    printf "  [✓] agent dispatch audit trail intact (every output has a timestamp-ordered matching brief)\n"
  else
    printf "  [✓] agent dispatch audit trail intact for this-session outputs (archived %d prior-session orphan(s))\n" "$ARCHIVED"
  fi
fi

printf -- "── Step 14: invariant-hunt.sh (R61, R71 HARD-STOP) ──\n"
# R71 upgrade: invariant-hunt is now HARD STOP in --strict. In default mode,
# it stays SOFT WARN so operators can iterate. Class-detectable contracts
# (ERC-20/4626/vault/exchange/lending/bridge/staking/perp/amm/prediction-
# market/erc7540) MUST have an invariant_hunt/<class>.report.md.
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "invariant-hunt report (post-onboard: runs after scan + harness)"
else
  if ls "$WS/invariant_hunt/"*.report.md >/dev/null 2>&1; then
    printf "  [✓] invariant-hunt report(s) found in invariant_hunt/\n"
    # If any report contains BROKEN or NOVEL-CANDIDATE, escalate to WARN
    if grep -lE 'BROKEN|NOVEL-CANDIDATE' "$WS/invariant_hunt/"*.report.md >/dev/null 2>&1; then
      printf "  [⚠] SOFT WARN — invariant_hunt/ has BROKEN invariant(s). Investigate before submit.\n"
      WARN=1
    fi
  else
    if [ "$STRICT" = 1 ]; then
      printf "  [✗] HARD STOP — invariant-hunt not run (required under --strict).\n"
      printf "      Remediation: bash tools/invariant-hunt.sh %s <class>\n" "$WS"
      printf "      Classes: erc20 erc4626 erc7540 exchange lending amm bridge staking prediction-market vault perp\n"
      HARD=1
    else
      printf "  [⚠] SOFT WARN — invariant-hunt not yet run. Run: tools/invariant-hunt.sh <ws> <class>\n"
      printf "      (Slow step — does not HARD STOP unless --strict.)\n"
      WARN=1
    fi
  fi
fi

printf -- "── Step 15: composition-fuzz (R71 NEW) ──\n"
# R71 upgrade: composition-fuzz A×B harness caught R60-01 Polymarket Medium.
# Modern million-$ bugs live in cross-contract state desyncs. Flag as SOFT
# WARN if workspace has ≥2 in-scope contracts but no composition_fuzz/ dir
# with a harness; HARD STOP under --strict.
if [ "$POST_ONBOARD" = 1 ]; then
  check_skip "composition-fuzz harness (post-onboard: runs after scan + cold-read)"
else
  _sol_count=$(source_solidity_count "$WS")
  if ! source_root_has_solidity "$WS"; then
    printf "  [•] SKIP — no Solidity source detected; composition-fuzz Forge harness is not applicable\n"
  elif [ "${_sol_count:-0}" -lt 2 ]; then
    printf "  [•] SKIP — single-contract workspace (source tree has %s .sol files; composition-fuzz needs ≥2)\n" "$_sol_count"
  elif ls "$WS/composition_fuzz/"*.t.sol >/dev/null 2>&1; then
    printf "  [✓] composition_fuzz/ has ≥1 A×B harness\n"
    # Surface broken invariants if any report exists
    if ls "$WS/composition_fuzz/"*.report.md >/dev/null 2>&1 && \
       grep -lE 'BROKEN|NOVEL-CANDIDATE' "$WS/composition_fuzz/"*.report.md >/dev/null 2>&1; then
      printf "  [⚠] SOFT WARN — composition_fuzz/ has BROKEN invariant(s) unreviewed\n"
      WARN=1
    fi
  else
    if [ "$STRICT" = 1 ]; then
      printf "  [✗] HARD STOP — composition-fuzz not run (required under --strict).\n"
      printf "      Remediation: identify top-3 A×B pairs by inbound-call density, run:\n"
      printf "        echo \"A:%s/src/A.sol\" > /tmp/ctrs.txt\n" "$WS"
      printf "        echo \"B:%s/src/B.sol\" >> /tmp/ctrs.txt\n" "$WS"
      printf "        bash tools/gen-composition-fuzz.sh %s /tmp/ctrs.txt\n" "$WS"
      printf "      Then: FOUNDRY_PROFILE=composition forge test --invariant-runs 10000 --invariant-depth 50 -vv\n"
      HARD=1
    else
      printf "  [⚠] SOFT WARN — composition-fuzz not run. %s .sol files in src/; ≥2 means A×B surface exists.\n" "$_sol_count"
      printf "      Where modern million-$ bugs live. Run: tools/gen-composition-fuzz.sh <ws> <ctrs.txt>\n"
      WARN=1
    fi
  fi
fi

printf -- "── Pre-submit: pre-submit-check.sh wiring ──\n"
if [ -d "$WS/drafts" ] && ls "$WS/drafts/"*.md >/dev/null 2>&1; then
  printf "  [⚠] drafts/ has files — reminder: run pre-submit-check.sh + novel-vector-check.sh on each before submission\n"
else
  printf "  [⚠] drafts/ empty — skipping pre-submit verification\n"
fi

echo
echo "Summary:"
echo "  HARD STOPs: $HARD"
echo "  SOFT WARNs: $WARN"

# R75/R76 — --dashboard mode also runs the round-close hygiene chain:
# verify-audit-fixes, bug-family-atlas, detector-janitor,
# extract-patterns-from-cold-reads, ast-migrate, pattern-compile,
# attack-path, acl-matrix, integration-assumptions, storage-layout,
# invariant-proposer, dashboard.
if [ "$DASHBOARD" = 1 ]; then
  echo ""
  echo "── Round-close hygiene (R73+R75+R76) ──"
  AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  bash "$AUDITOOOR_DIR/tools/verify-audit-fixes.sh" "$WS" --from-digest 2>&1 | tail -3 || true
  bash "$AUDITOOOR_DIR/tools/bug-family-atlas.sh" 2>&1 | tail -2 || true
  bash "$AUDITOOOR_DIR/tools/detector-janitor.sh" --dry-run 2>&1 | tail -3 || true
  bash "$AUDITOOOR_DIR/tools/extract-patterns-from-cold-reads.sh" --summary 2>&1 | tail -3 || true
  python3 "$AUDITOOOR_DIR/tools/ast-migrate.py" --write --all 2>&1 | tail -1 || true
  python3 "$AUDITOOOR_DIR/tools/pattern-compile.py" --all 2>&1 | tail -1 || true
  # R76: attack-surface analysis
  python3 "$AUDITOOOR_DIR/tools/integration-assumptions.py" "$WS" 2>&1 | tail -2 || true
  python3 "$AUDITOOOR_DIR/tools/attack-path.py" "$WS" 2>&1 | tail -3 || true
  python3 "$AUDITOOOR_DIR/tools/acl-matrix.py" "$WS" 2>&1 | tail -3 || true
  python3 "$AUDITOOOR_DIR/tools/storage-layout.py" "$WS" 2>&1 | tail -2 || true
  python3 "$AUDITOOOR_DIR/tools/invariant-proposer.py" "$WS" 2>&1 | tail -3 || true
  python3 "$AUDITOOOR_DIR/tools/dashboard.py" 2>&1 | tail -2 || true
  echo "── Hygiene chain complete ──"
fi

# Exit code contract (R45 bugfix — Bug 1):
#   HARD > 0                       -> exit 1 (regardless of --strict)
#   --strict && WARN > 0 (HARD=0)  -> exit 2 (soft-warn escalation)
#   else                           -> exit 0
# Previously the script could inherit a stale $? (e.g. from the last `grep` in
# the agent-dispatch audit-trail block) before reaching this tail, which made
# `flow-gate.sh ... --strict; echo $?` print 0 even after "CANNOT PROCEED".
# Explicitly branching + `exit N` here is the load-bearing fix.
if [ "$HARD" -gt 0 ]; then
  echo ""
  echo "[flow-gate] CANNOT PROCEED. Fix the HARD STOPs above."
  exit 1
fi

if [ "$STRICT" = 1 ] && [ "$WARN" -gt 0 ]; then
  echo ""
  echo "[flow-gate] --strict mode: non-zero soft warns → failing (exit 2)."
  exit 2
fi

echo ""
echo "[flow-gate] canonical flow satisfied (hard-stop level). Proceed with iter."
exit 0
