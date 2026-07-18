#!/usr/bin/env bash
# auto-wire-promote-loop.sh — automatically wire + smoke-test + promote
# new LLM outputs as they trickle in from background loops.
# Idempotent: each wirer only processes files not yet smoke-tested on disk.
# Runs every 30 min via launchd (com.auditooor.auto-wire-promote).
# Trust-calibration audit 2026-05-04: prevent fake detectors with unknown predicate keys.
# All wirers below that invoke tools/pattern-compile.py do so with
# `--strict-unsupported-keys` so that YAMLs containing unknown predicate keys
# (e.g. `function.name_matches_regex`, `function.does_not_call_matching_regex`)
# fail compile instead of silently emitting no-op detectors. Bulk-promote also
# pre-validates `match.*` and `preconditions.*` keys against the engine's
# SUPPORTED_KEYS_BY_FIELD inventory before writing _tier_registry.yaml.

set -uo pipefail

REPO="/Users/wolf/Documents/Codex/auditooor"
TOOLS="$REPO/tools"
INVENTORY="/private/tmp/auditooor-inventory"
LOGFILE="$INVENTORY/auto_wire_promote.log"
TS="$(date +%Y%m%d_%H%M%S)"

PYTHON3="/opt/homebrew/opt/python@3.13/bin/python3.13"
# fallback to system python3 if the versioned one is absent
command -v "$PYTHON3" >/dev/null 2>&1 || PYTHON3="$(command -v python3)"

log() { echo "[$(date +%H:%M:%S)] $*"; }

promoted_total=0

# ── helper: sum promoted_count from a summary JSON ──────────────────────────
sum_promoted() {
    local f="$1"
    if [[ -f "$f" ]]; then
        "$PYTHON3" -c "
import json, sys
d = json.load(open('$f'))
print(d.get('promoted_count', 0))
" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# ── 1. Phase-B-prime wirer ────────────────────────────────────────────────────
PBP_INPUTS="$INVENTORY/phase_b_prime_outputs"
PBP_SUMMARY="$INVENTORY/auto_wire_${TS}.json"
PBP_PROMOTE="$INVENTORY/auto_promote_${TS}.json"
PBP_BULK_SUMMARY="$INVENTORY/auto_promote_summary_${TS}.json"

if [[ -d "$PBP_INPUTS" ]]; then
    log "Phase-B-prime wirer → $PBP_INPUTS"
    "$PYTHON3" "$TOOLS/phase-b-prime-wirer.py" \
        --inputs-dir "$PBP_INPUTS" \
        --summary-out "$PBP_SUMMARY" \
        --promote-queue-out "$PBP_PROMOTE" \
        || log "WARN: phase-b-prime-wirer exited non-zero"

    if [[ -s "$PBP_PROMOTE" ]]; then
        log "Phase-B-prime bulk-promote"
        "$PYTHON3" "$TOOLS/inventory-bulk-promote.py" \
            --promote-queue "$PBP_PROMOTE" \
            --summary-out "$PBP_BULK_SUMMARY" \
            || log "WARN: bulk-promote (pbp) exited non-zero"
        promoted_total=$(( promoted_total + $(sum_promoted "$PBP_BULK_SUMMARY") ))
    else
        log "Phase-B-prime: no new passing fixtures"
    fi
else
    log "SKIP: $PBP_INPUTS does not exist"
fi

# ── 2. FP-repair wirer ───────────────────────────────────────────────────────
FP_QUEUE="$INVENTORY/fp_repair_queue.jsonl"
FP_PROMOTE="$INVENTORY/auto_fp_promote_${TS}.json"
FP_RETRY="$INVENTORY/auto_fp_retry_${TS}.jsonl"
FP_WIRER_SUMMARY="$INVENTORY/auto_fp_wirer_summary_${TS}.json"
FP_BULK_SUMMARY="$INVENTORY/auto_fp_bulk_summary_${TS}.json"

if [[ -f "$FP_QUEUE" ]]; then
    log "FP-repair wirer → queue $FP_QUEUE"
    "$PYTHON3" "$TOOLS/false-positive-batch-wirer.py" \
        --queue "$FP_QUEUE" \
        --promote-queue-out "$FP_PROMOTE" \
        --retry-queue-out "$FP_RETRY" \
        --summary-out "$FP_WIRER_SUMMARY" \
        || log "WARN: false-positive-batch-wirer exited non-zero"

    if [[ -s "$FP_PROMOTE" ]]; then
        log "FP-repair bulk-promote"
        "$PYTHON3" "$TOOLS/inventory-bulk-promote.py" \
            --promote-queue "$FP_PROMOTE" \
            --summary-out "$FP_BULK_SUMMARY" \
            || log "WARN: bulk-promote (fp) exited non-zero"
        promoted_total=$(( promoted_total + $(sum_promoted "$FP_BULK_SUMMARY") ))
    else
        log "FP-repair: no new passing fixtures"
    fi
else
    log "SKIP: fp_repair_queue.jsonl not found"
fi

# ── 3. No-YAML-synthesis wirer ───────────────────────────────────────────────
NY_INPUTS="$INVENTORY/no_yaml_outputs"
NY_SUMMARY="$INVENTORY/auto_noyaml_summary_${TS}.json"

if [[ -d "$NY_INPUTS" ]]; then
    log "No-YAML wirer → $NY_INPUTS"
    "$PYTHON3" "$TOOLS/no-yaml-synthesis-wirer.py" \
        --inputs-dir "$NY_INPUTS" \
        --summary-out "$NY_SUMMARY" \
        --update-registry \
        || log "WARN: no-yaml-synthesis-wirer exited non-zero"

    # no-yaml wirer registers directly; extract its own promoted count
    if [[ -f "$NY_SUMMARY" ]]; then
        ny_promoted=$("$PYTHON3" -c "
import json
d = json.load(open('$NY_SUMMARY'))
print(d.get('registered', d.get('promoted_count', 0)))
" 2>/dev/null || echo 0)
        promoted_total=$(( promoted_total + ny_promoted ))
        log "No-YAML wirer registered: $ny_promoted"
    fi
else
    log "SKIP: $NY_INPUTS does not exist"
fi

# ── 4. Arch-mismatch redesign wirer ─────────────────────────────────────────
# Note: architectural-mismatch-wirer promotes directly into _tier_registry.yaml
# (no separate promote-queue). We parse passing_count from the summary JSON.
AM_QUEUE="$INVENTORY/arch_mismatch_queue.jsonl"
AM_OUTPUTS="$INVENTORY/arch_mismatch_outputs"
AM_SUMMARY="$INVENTORY/auto_arch_mismatch_summary_${TS}.json"

if [[ -f "$AM_QUEUE" && -d "$AM_OUTPUTS" ]]; then
    log "Arch-mismatch wirer → $AM_OUTPUTS"
    "$PYTHON3" "$TOOLS/architectural-mismatch-wirer.py" \
        --queue "$AM_QUEUE" \
        --outputs-dir "$AM_OUTPUTS" \
        --summary-out "$AM_SUMMARY" \
        || log "WARN: architectural-mismatch-wirer exited non-zero"

    if [[ -f "$AM_SUMMARY" ]]; then
        am_promoted=$("$PYTHON3" -c "
import json
d = json.load(open('$AM_SUMMARY'))
print(d.get('passing_count', 0))
" 2>/dev/null || echo 0)
        promoted_total=$(( promoted_total + am_promoted ))
        log "Arch-mismatch wirer promoted: $am_promoted"
    else
        log "Arch-mismatch: no summary written (no outputs yet?)"
    fi
else
    log "SKIP: arch_mismatch_queue.jsonl or arch_mismatch_outputs not found"
fi

# ── 5. Final tally ───────────────────────────────────────────────────────────
REGISTRY="$REPO/detectors/_tier_registry.yaml"
total_verified=0
if [[ -f "$REGISTRY" ]]; then
    total_verified=$(grep -c "verified: true" "$REGISTRY" 2>/dev/null || echo 0)
fi

STATUS="$(date -u +%Y-%m-%dT%H:%M:%SZ) | run=$TS | new_promoted=$promoted_total | total_verified=$total_verified"
log "$STATUS"
echo "$STATUS" >> "$LOGFILE"
