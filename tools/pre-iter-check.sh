#!/usr/bin/env bash
# pre-iter-check.sh — refuse to start an iteration if auditooor invariants are missing
#
# Usage:
#   ./tools/pre-iter-check.sh <workspace-dir>
#
# Exit codes:
#   0 — all checks pass, iteration can proceed
#   1 — HARD STOP: a must-have invariant is missing (SCOPE.md, PRIOR_CONCERNS.md after audit txts exist)
#   2 — SOFT WARN: something worth flagging but not blocking (zero-finding streak high, etc.)
#
# Why this exists: the skill's methodology and anti-patterns are markdown guidelines that
# an LLM *might* read. That's weak enforcement. This script is a HARD GATE: it runs at the
# start of every iteration and refuses to proceed if the invariants aren't satisfied. The
# exit code (1 = hard stop) forces the caller to fix the missing invariant before the
# audit loop can continue.
#
# Enforced invariants (hard stops):
#   1. SCOPE.md exists — if the user gave a bounty URL, scope-match MUST happen before
#      any candidate is verified (fixes Issue 15 / anti-pattern #24).
#   2. PRIOR_CONCERNS.md exists if /tmp has audit .txt files — prior audit context must
#      be loaded at iter 1 (fixes Issue 13).
#   3. SESSION_LOG.md exists and has an iteration index table.
#
# Enforced warnings (soft):
#   a. Zero-finding streak >= 3 iterations → warn about self-challenge (anti-pattern #21).
#   b. Last iter older than 24h → warn about stale workspace.
#   c. /tmp has audit .txt files but PRIOR_CONCERNS.md was never regenerated after new
#      ones appeared → warn to re-run orient-from-audits.sh.

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-dir>"
    exit 1
fi

WS="$1"
AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HARD_STOP=0
SOFT_WARN=0

printf '\n=== auditooor pre-iter check: %s ===\n\n' "$WS"

if [ ! -d "$WS" ]; then
    echo "HARD STOP: workspace $WS not found"
    exit 1
fi

# ---- HARD STOP CHECKS ----

# 1. SESSION_LOG.md exists
if [ ! -f "$WS/SESSION_LOG.md" ]; then
    echo "HARD STOP: $WS/SESSION_LOG.md missing. Create it before starting an iteration."
    HARD_STOP=1
elif ! grep -qE '^\| +[0-9]+ +\|' "$WS/SESSION_LOG.md"; then
    echo "HARD STOP: $WS/SESSION_LOG.md has no iteration index table."
    echo "  Expected a Markdown table with rows matching /^\\| +[0-9]+ +\\|/"
    HARD_STOP=1
else
    last_iter=$(grep -cE '^\| +[0-9]+ +\|' "$WS/SESSION_LOG.md")
    echo "  [ok] SESSION_LOG.md has $last_iter iter rows"
fi

# 2. SCOPE.md exists — this is MANDATORY before any agent dispatch.
if [ ! -f "$WS/SCOPE.md" ]; then
    echo "HARD STOP: $WS/SCOPE.md missing."
    echo "  The full bounty program page (including OUT-OF-SCOPE and KNOWN ISSUES)"
    echo "  MUST be fetched before any agent dispatch. Run:"
    echo ""
    echo "    ./tools/fetch-scope.sh $WS <bounty-program-url>"
    echo ""
    echo "  Pursuing candidates before scope-matching causes wasted verification"
    echo "  on explicit out-of-scope classes. See reference/anti_patterns.md #24."
    HARD_STOP=1
else
    scope_lines=$(wc -l < "$WS/SCOPE.md")
    echo "  [ok] SCOPE.md present ($scope_lines lines)"
    if ! grep -qiE 'out.of.scope|known issue|by design' "$WS/SCOPE.md"; then
        echo "  [warn] SCOPE.md doesn't contain 'out of scope' / 'known issues' / 'by design'"
        echo "         keywords — the file may be incomplete. Re-fetch if needed."
        SOFT_WARN=1
    fi
fi

# 3. PRIOR_CONCERNS.md exists if prior audit txts are present
# Primary source: $WS/prior_audits/*.txt (per-workspace durable, from
# in-repo audits/*.pdf via fetch-targets.sh or manual pdftotext).
# Fallback: /tmp/*.txt (ad-hoc extraction for one-off corpora).
has_audit_txts=0
prior_audit_count=0
if [ -d "$WS/prior_audits" ]; then
    prior_audit_count=$(find "$WS/prior_audits" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')
    if [ "$prior_audit_count" -gt 0 ]; then
        has_audit_txts=1
    fi
fi
for dir in "$WS/cantina-pdfs" "$WS/external-prior-audits" "$WS/known-vulns-pdf"; do
    if [ -d "$dir" ]; then
        extra_count=$(find "$dir" -maxdepth 1 \( -name '*.txt' -o -name '*.pdf' \) 2>/dev/null | wc -l | tr -d ' ')
        if [ "$extra_count" -gt 0 ]; then
            has_audit_txts=1
        fi
    fi
done
for pat in "/tmp/cantina_*.txt" "/tmp/quantstamp_*.txt" "/tmp/audit_*.txt"; do
    for f in $pat; do
        [ -f "$f" ] && has_audit_txts=1
    done
done

# 3a. Audit-digest hard gate (SKILL_ISSUE #56): if prior_audits/ has .txt
# files, we require at least one DIGEST_*.md to exist. This forces the user
# to actually READ the reports (via Sonnet agents using
# templates/audit_digest_agent_brief.md) before iter 1 starts. Prevents
# duplicate-submission waste + captures patterns for future bounties.
if [ "$prior_audit_count" -gt 0 ]; then
    digest_count=$(find "$WS/prior_audits" -maxdepth 1 -name 'DIGEST_*.md' 2>/dev/null | wc -l | tr -d ' ')
    if [ "$digest_count" -eq 0 ]; then
        echo "HARD STOP: $WS/prior_audits/ has $prior_audit_count .txt files but NO DIGEST_*.md exists."
        echo "  Every bounty's prior audits are explicitly OUT OF SCOPE (known-issues"
        echo "  clause). Submitting a finding covered by a prior audit = wasted deposit."
        echo ""
        echo "  Spawn Sonnet agents to read them using the template at:"
        echo "    $AUDITOOOR_DIR/templates/audit_digest_agent_brief.md"
        echo ""
        echo "  Rule of thumb: one agent per 2-3 PDFs (~1500-3000 lines). Run them"
        echo "  in parallel via the Agent tool with run_in_background=true."
        echo ""
        echo "  After digests land, re-run this check — it will synthesize"
        echo "  PRIOR_CONCERNS.md from the digest findings automatically."
        echo ""
        echo "  See SKILL_ISSUE #56."
        HARD_STOP=1
    else
        echo "  [ok] $digest_count DIGEST_*.md file(s) present alongside $prior_audit_count prior-audit .txt files"
        # Auto-synthesize PRIOR_CONCERNS.md from digests if it's missing or stale
        oldest_digest=0
        for f in "$WS/prior_audits/"DIGEST_*.md; do
            [ -f "$f" ] || continue
            m=$(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f")
            [ "$m" -gt "$oldest_digest" ] && oldest_digest=$m
        done
        pc_mtime=0
        [ -f "$WS/PRIOR_CONCERNS.md" ] && pc_mtime=$(stat -f %m "$WS/PRIOR_CONCERNS.md" 2>/dev/null || stat -c %Y "$WS/PRIOR_CONCERNS.md")
        if [ ! -f "$WS/PRIOR_CONCERNS.md" ] || [ "$oldest_digest" -gt "$pc_mtime" ]; then
            {
                echo "# PRIOR_CONCERNS — synthesized from DIGEST_*.md"
                echo ""
                echo "Every entry below was raised in a prior audit of this target. They are"
                echo "explicitly OUT OF SCOPE per the bounty's known-issues clause. Re-submitting"
                echo "any of them wastes the bounty deposit."
                echo ""
                echo "**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ) by pre-iter-check.sh"
                echo ""
                echo "---"
                echo ""
                for f in "$WS/prior_audits/"DIGEST_*.md; do
                    [ -f "$f" ] || continue
                    echo "## Source: $(basename "$f")"
                    echo ""
                    # Pull the H3 finding titles + fix-status lines verbatim
                    grep -E '^### |^- \*\*Fix status:\*\*|^- \*\*Severity:\*\*' "$f" || true
                    echo ""
                    # Also pull "acknowledged not resolved" sections verbatim
                    awk '/^## Known acknowledged risks/,/^## /' "$f" | head -80 || true
                    echo ""
                done
            } > "$WS/PRIOR_CONCERNS.md"
            echo "  [ok] synthesized $WS/PRIOR_CONCERNS.md from digest files"
        fi
        # 3b. Run the learn-from-prior-audits loop
        # Extracts `generalizable pattern` from every DIGEST entry, appends
        # novel patterns to reference/bug_patterns_observed.md, and queues
        # scanner-gap TODOs in $WS/TODO.md for the Crit/High/Med findings
        # the current detector suite didn't surface. See SKILL_ISSUE #57.
        if [ -f "$AUDITOOOR_DIR/tools/digest-to-patterns.py" ]; then
            echo "  [ok] running digest-to-patterns learning loop..."
            python3 "$AUDITOOOR_DIR/tools/digest-to-patterns.py" "$WS" 2>&1 \
                | sed 's/^/      /' || echo "  [warn] digest-to-patterns errored"
        fi
    fi
fi

if [ $has_audit_txts -eq 1 ]; then
    if [ ! -f "$WS/PRIOR_CONCERNS.md" ]; then
        echo "HARD STOP: audit .txt files found but $WS/PRIOR_CONCERNS.md missing."
        echo "  Prior audit acknowledgements ('operational consideration', 'by design',"
        echo "  'risk accepted') must be extracted before iteration starts. Run:"
        echo ""
        echo "    ./tools/orient-from-audits.sh $WS"
        echo ""
        echo "  Not doing this leads to re-litigating classes the auditors already"
        echo "  accepted — guaranteed dupe rejections. See SKILL_ISSUES.md #13."
        HARD_STOP=1
    else
        # Check if it's stale: any audit txt newer than PRIOR_CONCERNS.md?
        pc_mtime=$(stat -f %m "$WS/PRIOR_CONCERNS.md" 2>/dev/null || stat -c %Y "$WS/PRIOR_CONCERNS.md")
        stale=0
        for pat in "/tmp/cantina_*.txt" "/tmp/quantstamp_*.txt" "/tmp/audit_*.txt"; do
            for f in $pat; do
                if [ -f "$f" ]; then
                    f_mtime=$(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f")
                    if [ "$f_mtime" -gt "$pc_mtime" ]; then
                        stale=1
                        break
                    fi
                fi
            done
        done
        if [ $stale -eq 1 ]; then
            echo "  [warn] PRIOR_CONCERNS.md is older than some /tmp audit .txt files."
            echo "         Re-run ./tools/orient-from-audits.sh $WS"
            SOFT_WARN=1
        else
            echo "  [ok] PRIOR_CONCERNS.md fresh"
        fi
    fi
else
    echo "  [info] no /tmp/*.txt audit files — skipping PRIOR_CONCERNS.md check"
fi

# ---- SOFT WARNINGS ----

# 4. Zero-finding streak >= 3 → self-challenge mandatory
if [ -f "$WS/SESSION_LOG.md" ]; then
    # Count trailing iter rows with "| 0 |" (zero findings delta)
    zero_streak=$(grep -E '^\| +[0-9]+ +\|' "$WS/SESSION_LOG.md" \
        | awk -F'|' '{
            # the findings-delta column is usually the 5th cell; be forgiving
            for (i=NF; i>=1; i--) {
                gsub(/[ \t]/, "", $i)
                if ($i ~ /^[0-9]+$/) { print $i; break }
            }
        }' \
        | tac 2>/dev/null || (grep -E '^\| +[0-9]+ +\|' "$WS/SESSION_LOG.md" \
            | awk -F'|' '{
                for (i=NF; i>=1; i--) {
                    gsub(/[ \t]/, "", $i)
                    if ($i ~ /^[0-9]+$/) { print $i; break }
                }
            }' | tail -r 2>/dev/null) \
        | awk 'BEGIN{c=0} {if ($1+0==0) c++; else exit} END{print c}')

    if [ -z "$zero_streak" ]; then zero_streak=0; fi
    echo "  [info] zero-finding streak: $zero_streak iterations"
    if [ "$zero_streak" -ge 3 ] 2>/dev/null; then
        echo "  [warn] zero-finding streak >= 3. Self-challenge step (§3b) is MANDATORY."
        echo "         List 3 alternative hypotheses you DID NOT investigate before"
        echo "         declaring this iter done. See anti_patterns.md #21."
        SOFT_WARN=1
    fi
fi

# 5. FINDINGS.md exists
if [ ! -f "$WS/FINDINGS.md" ]; then
    echo "  [warn] $WS/FINDINGS.md missing — candidates have nowhere to land."
    SOFT_WARN=1
fi

# 5a. Static-analysis baseline (static-analysis-summary.md) — auto-invoked on iter 1.
# Slither/Aderyn/Semgrep should be the STARTING POINT of every audit, not a late-round
# surprise. If the baseline doesn't exist, auto-run run-slither.sh and write the summary.
# Any HIGH finding that isn't already in FINDINGS.md becomes a P0 target for iter 1.
if [ ! -f "$WS/static-analysis-summary.md" ]; then
    if [ -x "$AUDITOOOR_DIR/tools/run-slither.sh" ]; then
        echo "  [auto] static-analysis-summary.md missing — running baseline analyzers"
        echo "         (slither + aderyn + semgrep). This is a one-time iter-1 cost."
        # Export common tool paths so slither/aderyn/semgrep resolve under launchd/cron.
        export PATH="$HOME/.foundry/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
        if "$AUDITOOOR_DIR/tools/run-slither.sh" "$WS" >/dev/null 2>&1; then
            if [ -f "$WS/static-analysis-summary.md" ]; then
                high_count=$(grep -c '^- \*\*' "$WS/static-analysis-summary.md" 2>/dev/null || echo 0)
                echo "  [ok] static-analysis-summary.md written ($high_count finding rows)"
                echo "         Review $WS/static-analysis-summary.md before dispatching agents."
                echo "         Any HIGH row not already in FINDINGS.md is a P0 target."
                SOFT_WARN=1
            else
                echo "  [warn] run-slither.sh ran but no summary was produced — check logs."
                SOFT_WARN=1
            fi
        else
            echo "  [warn] run-slither.sh failed — may need: bash tools/run-slither.sh --install"
            SOFT_WARN=1
        fi
    else
        echo "  [warn] $WS/static-analysis-summary.md missing AND run-slither.sh not executable."
        echo "         Run: chmod +x $AUDITOOOR_DIR/tools/run-slither.sh"
        SOFT_WARN=1
    fi
else
    age_days=$(( ( $(date +%s) - $(stat -f %m "$WS/static-analysis-summary.md" 2>/dev/null || stat -c %Y "$WS/static-analysis-summary.md") ) / 86400 ))
    echo "  [ok] static-analysis-summary.md present (${age_days}d old)"
    if [ "$age_days" -gt 7 ] 2>/dev/null; then
        echo "  [warn] static-analysis-summary.md is >7 days old. Re-run:"
        echo "         bash $AUDITOOOR_DIR/tools/run-slither.sh $WS"
        SOFT_WARN=1
    fi
fi

# 6. EXTERNAL_INTEL.md exists (fixes Issue 19 — user-pasted context should live
# on disk so every future iter can read it, not just the current conversation).
if [ ! -f "$WS/EXTERNAL_INTEL.md" ]; then
    echo "  [warn] $WS/EXTERNAL_INTEL.md missing. If the user has pasted any external"
    echo "         context (articles, Discord chatter, Tweets, ghost-fill writeups)"
    echo "         into the conversation, capture it now:"
    echo ""
    echo "           echo 'context...' | ./tools/capture-intel.sh $WS \"<title>\""
    echo ""
    echo "         Or at least touch the file so future iters see the expected path."
    SOFT_WARN=1
fi

# 7. bug_patterns_observed.md reminder (fixes Issue 23 — the feedback loop for
# found bugs. Every orient should cross-reference the skill's accumulated
# hypothesis-generation catalog against the current target).
if [ -f "$AUDITOOOR_DIR/reference/bug_patterns_observed.md" ]; then
    pat_count=$(grep -cE '^### P[0-9]+' "$AUDITOOOR_DIR/reference/bug_patterns_observed.md" 2>/dev/null || true)
    pat_count=${pat_count:-0}
    echo "  [info] $pat_count bug patterns observed in prior audits — read"
    echo "         $AUDITOOOR_DIR/reference/bug_patterns_observed.md during orient"
    echo "         and ask: does any pattern apply structurally to this target?"
fi

# 8. RUBRIC_COVERAGE.md reminder (fixes Issue 24 — rubric-example coverage
# checklist. Every orient should cross-reference the current iteration's
# target against the bounty's own rubric impact examples. Graceful termination
# requires ≥90% rows in PASS / SUBMITTED / OOS / N/A state.)
if [ ! -f "$WS/RUBRIC_COVERAGE.md" ]; then
    # Hard stop at iter 2+ (fixes SKILL_ISSUE #66): iter 1 is setup, but by iter 2
    # the severity rubric should be populated and RUBRIC_COVERAGE.md initialized.
    if [ "${last_iter:-0}" -ge 2 ] 2>/dev/null; then
        echo "  HARD STOP: $WS/RUBRIC_COVERAGE.md missing at iter $last_iter."
        echo "    1. Populate SEVERITY.md with the bounty's severity rubric"
        echo "    2. Run: ./tools/init-rubric-coverage.sh $WS"
        echo "    3. Update verdicts for rows already covered in prior iters"
        HARD_STOP=1
    else
        echo "  [warn] $WS/RUBRIC_COVERAGE.md missing. Build it now:"
        echo ""
        echo "           ./tools/init-rubric-coverage.sh $WS"
        echo ""
        echo "         This generates a per-impact-example checklist from SEVERITY.md."
        echo "         The assistant should update verdicts after every iteration."
        echo "         Graceful termination REQUIRES ≥90% resolution of this file."
        SOFT_WARN=1
    fi
else
    # Row-scoped counts: parse lines matching `| <id> | <example> | <verdict> |`
    # and classify by which verdict marker appears in the row. This avoids
    # over-matching legend/summary text elsewhere in the file.
    counts=$(awk '
        /^\| [CHML][0-9]+ \|/ {
            total++
            if ($0 ~ /NOT CHECKED/) unchecked++
            else if ($0 ~ /PARTIAL/) partial++
            else if ($0 ~ /PASS/) pass++
            else if ($0 ~ /SUBMITTED/) submitted++
            else if ($0 ~ /OOS/) oos++
            else if ($0 ~ /N\/A/) na++
        }
        END {
            resolved = pass + submitted + oos + na
            printf "%d %d %d %d\n", total, resolved, unchecked, partial
        }
    ' "$WS/RUBRIC_COVERAGE.md")
    read -r total_rows resolved unchecked partial <<< "$counts"

    if [ "$total_rows" -gt 0 ] 2>/dev/null; then
        pct=$((resolved * 100 / total_rows))
        unresolved=$((unchecked + partial))
        echo "  [info] RUBRIC_COVERAGE.md: $resolved/$total_rows rows resolved ($pct%)"
        if [ "$unresolved" -gt 0 ] 2>/dev/null; then
            threshold=$((total_rows / 5))  # 20% of rows
            if [ "$unresolved" -gt "$threshold" ] 2>/dev/null; then
                echo "  [warn] $unresolved rows still NOT CHECKED / PARTIAL (>20% threshold)."
                echo "         Prioritize uncovered rows for this iter's target selection."
                SOFT_WARN=1
            fi
        fi
        if [ "$pct" -lt 90 ] 2>/dev/null; then
            echo "  [info] graceful termination BLOCKED until resolution ≥ 90%"
        else
            echo "  [ok] graceful termination eligible (≥90% resolved)"
        fi
    fi
fi

# 9. Check for build-failed targets (fixes SKILL_ISSUE #68)
if [ -f "$WS/static-analysis-summary.md" ]; then
    BUILD_FAILS=$(grep -ci "build.*fail\|compil.*fail\|Error compiling\|Cannot execute" "$WS/static-analysis-summary.md" 2>/dev/null || true)
    if [ "${BUILD_FAILS:-0}" -gt 0 ]; then
        echo "  [warn] static-analysis-summary.md mentions $BUILD_FAILS build failure(s)."
        echo "         In-scope contracts with build failures have ZERO scanner coverage."
        echo "         Diagnose and retry before declaring exhaustion."
        SOFT_WARN=1
    fi
fi
# Also check for src/ subdirectories that have no slither.json or scan log
if [ -d "$WS/src" ]; then
    for target_dir in "$WS/src"/*/; do
        tname=$(basename "$target_dir")
        if [ ! -f "$WS/slither-${tname}.json" ] && [ ! -f "$target_dir/slither.json" ]; then
            # Check if there are .sol files (some dirs are just config/scripts)
            sol_count=$(find "$target_dir" -name "*.sol" -not -path "*/lib/*" -not -path "*/test/*" 2>/dev/null | head -1 | wc -l)
            if [ "$sol_count" -gt 0 ]; then
                echo "  [info] $tname: no slither scan output found — may need scanning"
            fi
        fi
    done
fi

# 10. Check if PATTERN_HITS.md exists (fixes SKILL_ISSUE #70-72, hardened by #78)
# HARD STOP at iter ≥ 2 per Issue #78.
if [ ! -f "$WS/PATTERN_HITS.md" ] && [ "${last_iter:-0}" -ge 2 ] 2>/dev/null; then
    echo "  [HARD STOP] $WS/PATTERN_HITS.md missing at iter ${last_iter}. Run:"
    echo "              $AUDITOOOR_DIR/tools/apply-patterns.sh $WS"
    echo "              Patterns are the highest-value cross-audit artifact (Issue #71)."
    HARD_STOP=1
fi

# 10b. Check if SCAN_REPORT.md exists (Issue #78)
if [ ! -f "$WS/SCAN_REPORT.md" ] && [ "${last_iter:-0}" -ge 2 ] 2>/dev/null; then
    echo "  [HARD STOP] $WS/SCAN_REPORT.md missing at iter ${last_iter}. Run:"
    echo "              $AUDITOOOR_DIR/tools/scan.sh $WS"
    echo "              scan.sh orchestrates apply-queries + apply-patterns + static analysis."
    HARD_STOP=1
fi

# 6. Print session rules reminder
cat <<'RULES'

  --- session rules reminder ---
  1. Scope-match BEFORE technical verification (anti-pattern #24)
  2. Fan out to Sonnet agents when target > ~300 LOC or multi-file (§2b)
  3. Self-challenge step on any zero-finding iter (§3b)
  4. Verify every agent-reported file:line in source (anti-pattern #2)
  5. Log closures in FINDINGS.md with rationale (anti-pattern #3)
  6. Update SESSION_LOG.md via ./tools/append-iter.sh after execute phase
  7. Run apply-patterns.sh BEFORE adversarial reads — give agents pattern context

RULES

# ---- FINAL VERDICT ----

if [ $HARD_STOP -eq 1 ]; then
    echo "=== RESULT: HARD STOP — fix invariants above before continuing ==="
    exit 1
elif [ $SOFT_WARN -eq 1 ]; then
    echo "=== RESULT: PASS with warnings — proceed carefully ==="
    exit 0
else
    echo "=== RESULT: PASS — proceed to iteration ==="
    exit 0
fi
