#!/usr/bin/env bash
# overnight-pipeline.sh — multi-phase orchestrator. Runs after Phase 1 (already
# in flight) completes. Auto-promotes existing Tier-E based on Minimax verdicts,
# then runs Phase 3 (DSL→fixture-pair) → Phase 4 (Minimax review of new fixture
# pairs) → Phase 5 (auto-register surviving detectors into Tier-B).
#
# Usage:
#   nohup bash tools/overnight-pipeline.sh > /private/tmp/auditooor-overnight/pipeline.log 2>&1 &

set -uo pipefail
WORK="/private/tmp/auditooor-overnight"
ROOT="/Users/wolf/Documents/Codex/auditooor"
LOG="$WORK/pipeline.log"
HELPERS="$ROOT/tools/overnight-pipeline-helpers.py"
LOOP="$ROOT/tools/overnight-llm-loop.sh"

mkdir -p "$WORK"
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf "%s [pipeline] %s\n" "$(ts)" "$*" >> "$LOG"; printf "%s [pipeline] %s\n" "$(ts)" "$*"; }

# ---------------------------------------------------------------------------
# Phase 1: wait for the currently-running queue.jsonl loop to complete
# ---------------------------------------------------------------------------
log "Phase 1: waiting for tools/overnight-llm-loop.sh to finish (current queue.jsonl)"
# Match only the Phase 1 loop. The path '/queue.jsonl ' (leading slash, trailing
# space) does NOT match 'phase3_queue.jsonl' or 'phase4_queue.jsonl'.
while pgrep -f "/queue.jsonl " > /dev/null; do
    sleep 90
done
log "Phase 1: completed"

# ---------------------------------------------------------------------------
# Phase 2: auto-promote existing Tier-E based on Minimax verdicts
# ---------------------------------------------------------------------------
log "Phase 2: auto-promote Tier-E from Minimax reviews"
python3 "$HELPERS" --mode promote-tier-e \
    --reviews-dir "$WORK/outputs" \
    --summary-out "$WORK/phase2_promotion_summary.json" >> "$LOG" 2>&1 || \
    log "Phase 2: helpers script returned non-zero (continuing)"
log "Phase 2: $(python3 -c "import json; d=json.load(open('$WORK/phase2_promotion_summary.json')); print(d.get('promotion_count', 0))" 2>/dev/null || echo '?') promotions written to detectors/_tier_registry.yaml"

# ---------------------------------------------------------------------------
# Phase 3: build queue for DSL → fixture-pair generation, run loop
# ---------------------------------------------------------------------------
log "Phase 3: build queue from new catalog→DSL outputs"
python3 "$HELPERS" --mode build-phase3-queue \
    --catalog-dsl-dir "$WORK/outputs" \
    --queue-out "$WORK/phase3_queue.jsonl" \
    --work-dir "$WORK" >> "$LOG" 2>&1
phase3_count=$(wc -l < "$WORK/phase3_queue.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
log "Phase 3: queued $phase3_count fixture-pair generation tasks"

if [ "$phase3_count" -gt 0 ]; then
    log "Phase 3: starting loop"
    AUDITOOOR_LLM_NETWORK_CONSENT=1 BYPASS_DISPATCH_PREFLIGHT=1 \
        BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-pipeline-phase3" \
        bash "$LOOP" "$WORK/phase3_queue.jsonl" 12 >> "$LOG" 2>&1
    log "Phase 3: loop exited"
fi

# ---------------------------------------------------------------------------
# Phase 4: build queue for adversarial review of new fixture pairs
# ---------------------------------------------------------------------------
log "Phase 4: build queue from new fixture-pair outputs"
python3 "$HELPERS" --mode build-phase4-queue \
    --fixture-dir "$WORK/phase3_outputs" \
    --queue-out "$WORK/phase4_queue.jsonl" \
    --work-dir "$WORK" >> "$LOG" 2>&1
phase4_count=$(wc -l < "$WORK/phase4_queue.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
log "Phase 4: queued $phase4_count adversarial-review tasks"

if [ "$phase4_count" -gt 0 ]; then
    log "Phase 4: starting loop"
    AUDITOOOR_LLM_NETWORK_CONSENT=1 BYPASS_DISPATCH_PREFLIGHT=1 \
        BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-pipeline-phase4" \
        bash "$LOOP" "$WORK/phase4_queue.jsonl" 12 >> "$LOG" 2>&1
    log "Phase 4: loop exited"
fi

# ---------------------------------------------------------------------------
# Phase 5: register surviving phase4 detectors as new Tier-B
# ---------------------------------------------------------------------------
log "Phase 5: register surviving (promote_to_B) detectors as Tier-B"
python3 "$HELPERS" --mode promote-phase4 \
    --reviews-dir "$WORK/phase4_outputs" \
    --summary-out "$WORK/phase5_promotion_summary.json" >> "$LOG" 2>&1 || \
    log "Phase 5: helpers script returned non-zero"
log "Phase 5: $(python3 -c "import json; d=json.load(open('$WORK/phase5_promotion_summary.json')); print(d.get('registration_count', 0))" 2>/dev/null || echo '?') new Tier-B registrations"

# ---------------------------------------------------------------------------
# Phase 6: rewrite previously-demoted Tier-D detectors using Minimax feedback
# ---------------------------------------------------------------------------
log "Phase 6a: build queue for Tier-D rewrites"
python3 "$HELPERS" --mode build-phase6-queue \
    --reviews-dir "$WORK/outputs" \
    --queue-out "$WORK/phase6_queue.jsonl" \
    --work-dir "$WORK" >> "$LOG" 2>&1
phase6_count=$(wc -l < "$WORK/phase6_queue.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
log "Phase 6a: queued $phase6_count Tier-D rewrite tasks"
if [ "$phase6_count" -gt 0 ]; then
    AUDITOOOR_LLM_NETWORK_CONSENT=1 BYPASS_DISPATCH_PREFLIGHT=1 \
        BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-pipeline-phase6" \
        bash "$LOOP" "$WORK/phase6_queue.jsonl" 12 >> "$LOG" 2>&1
fi
log "Phase 6b: build re-review queue for rewrites"
python3 "$HELPERS" --mode build-phase6b-queue \
    --fixture-dir "$WORK/phase6_outputs" \
    --queue-out "$WORK/phase6b_queue.jsonl" \
    --work-dir "$WORK" >> "$LOG" 2>&1
phase6b_count=$(wc -l < "$WORK/phase6b_queue.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
log "Phase 6b: queued $phase6b_count rewrite-review tasks"
if [ "$phase6b_count" -gt 0 ]; then
    AUDITOOOR_LLM_NETWORK_CONSENT=1 BYPASS_DISPATCH_PREFLIGHT=1 \
        BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-pipeline-phase6b" \
        bash "$LOOP" "$WORK/phase6b_queue.jsonl" 12 >> "$LOG" 2>&1
fi
log "Phase 6c: promote rewrites that survived re-review"
python3 "$HELPERS" --mode promote-phase6 \
    --reviews-dir "$WORK/phase6b_outputs" \
    --summary-out "$WORK/phase6_promotion_summary.json" >> "$LOG" 2>&1 || \
    log "Phase 6c: helpers script returned non-zero"
log "Phase 6c: $(python3 -c "import json; d=json.load(open('$WORK/phase6_promotion_summary.json')); print(d.get('promotion_count', 0))" 2>/dev/null || echo '?') Tier-D→B promotions"

# ---------------------------------------------------------------------------
# Phase 7: Rust DSL → cargo-runnable fixture pair (Kimi)
# ---------------------------------------------------------------------------
log "Phase 7a: build queue for Rust DSL→fixture-pair (270 r94 Rust patterns)"
python3 "$HELPERS" --mode build-phase7-queue \
    --queue-out "$WORK/phase7_queue.jsonl" \
    --work-dir "$WORK" >> "$LOG" 2>&1
phase7_count=$(wc -l < "$WORK/phase7_queue.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
log "Phase 7a: queued $phase7_count Rust DSL→fixture tasks"
if [ "$phase7_count" -gt 0 ]; then
    AUDITOOOR_LLM_NETWORK_CONSENT=1 BYPASS_DISPATCH_PREFLIGHT=1 \
        BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-pipeline-phase7" \
        bash "$LOOP" "$WORK/phase7_queue.jsonl" 12 >> "$LOG" 2>&1
fi
log "Phase 7b: build review queue for Rust fixture pairs"
python3 "$HELPERS" --mode build-phase7b-queue \
    --fixture-dir "$WORK/phase7_outputs" \
    --queue-out "$WORK/phase7b_queue.jsonl" \
    --work-dir "$WORK" >> "$LOG" 2>&1
phase7b_count=$(wc -l < "$WORK/phase7b_queue.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
log "Phase 7b: queued $phase7b_count Rust review tasks"
if [ "$phase7b_count" -gt 0 ]; then
    AUDITOOOR_LLM_NETWORK_CONSENT=1 BYPASS_DISPATCH_PREFLIGHT=1 \
        BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-pipeline-phase7b" \
        bash "$LOOP" "$WORK/phase7b_queue.jsonl" 12 >> "$LOG" 2>&1
fi
log "Phase 8: register surviving Rust detectors as Tier-B (flagged needs_cargo_validation)"
python3 "$HELPERS" --mode promote-phase7 \
    --reviews-dir "$WORK/phase7b_outputs" \
    --summary-out "$WORK/phase8_rust_promotion_summary.json" >> "$LOG" 2>&1 || \
    log "Phase 8: helpers script returned non-zero"
log "Phase 8: $(python3 -c "import json; d=json.load(open('$WORK/phase8_rust_promotion_summary.json')); print(d.get('registration_count', 0))" 2>/dev/null || echo '?') new Rust Tier-B registrations"

# ---------------------------------------------------------------------------
# Phase 10: GitHub fix-commit refinement using Solodit URL enrichments
# ---------------------------------------------------------------------------
log "Phase 10: build queue for GitHub fix-commit refinement (uses solodit_url_*.json from Phase 1)"
python3 "$HELPERS" --mode build-phase10-queue \
    --fixture-dir "$WORK/outputs" \
    --queue-out "$WORK/phase10_queue.jsonl" \
    --work-dir "$WORK" >> "$LOG" 2>&1
phase10_count=$(wc -l < "$WORK/phase10_queue.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
log "Phase 10: queued $phase10_count GitHub-diff refinement tasks (others skipped due to missing/unknown commit SHA)"
if [ "$phase10_count" -gt 0 ]; then
    AUDITOOOR_LLM_NETWORK_CONSENT=1 BYPASS_DISPATCH_PREFLIGHT=1 \
        BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-pipeline-phase10" \
        bash "$LOOP" "$WORK/phase10_queue.jsonl" 12 >> "$LOG" 2>&1
fi

# ---------------------------------------------------------------------------
# Phase 6: emit final summary
# ---------------------------------------------------------------------------
log "Phase 11: emit final summary"
python3 - <<PY >> "$LOG" 2>&1
import json, glob
out = {"ts": "$(ts)"}
for sf in [
    "phase2_promotion_summary.json",
    "phase5_promotion_summary.json",
    "phase6_promotion_summary.json",
    "phase8_rust_promotion_summary.json",
]:
    p = "$WORK/" + sf
    try:
        out[sf] = json.load(open(p))
    except Exception as e:
        out[sf] = {"error": str(e)}
out["totals"] = {
    "phase1_outputs": len(glob.glob("$WORK/outputs/*.json")),
    "phase3_fixture_pairs": len(glob.glob("$WORK/phase3_outputs/*.json")),
    "phase4_reviews": len(glob.glob("$WORK/phase4_outputs/*.json")),
    "phase6_rewrites": len(glob.glob("$WORK/phase6_outputs/*.json")),
    "phase6b_re_reviews": len(glob.glob("$WORK/phase6b_outputs/*.json")),
    "phase7_rust_fixture_pairs": len(glob.glob("$WORK/phase7_outputs/*.json")),
    "phase7b_rust_reviews": len(glob.glob("$WORK/phase7b_outputs/*.json")),
    "phase10_github_refinements": len(glob.glob("$WORK/phase10_outputs/*.json")),
}
print(json.dumps(out, indent=2))
PY
log "DONE — all phases complete"
