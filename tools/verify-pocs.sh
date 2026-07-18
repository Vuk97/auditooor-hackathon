#!/usr/bin/env bash
# verify-pocs.sh — Phase 42 PoC verification gate.
#
# Runs every draft's inlined forge test against a workspace's foundry project,
# reports PASS/FAIL per-draft, and exits non-zero (under --strict) on failure.
#
# Usage:
#   bash tools/verify-pocs.sh <workspace>
#   bash tools/verify-pocs.sh <workspace> --draft 3
#   bash tools/verify-pocs.sh <workspace> --dry-run
#   bash tools/verify-pocs.sh <workspace> --strict
#
# Workspace layout assumptions:
#   <workspace>/submissions/SUBMISSIONS.md       drafts under "### Draft N — ..."
#   <workspace>/<foundry_project>/foundry.toml   either at root or under pocs/
#   Each draft's expected-output block contains a hint of the form:
#       Ran N tests for <path-to-.t.sol>:<ContractName>
#   from which we derive --match-path and (when present) FOUNDRY_PROFILE.
set -u
set -o pipefail

WORKSPACE=""
DRAFT_FILTER=""
DRY_RUN=0
STRICT=0
TIMEOUT_SECS=300

usage() {
    sed -n '2,17p' "$0" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --draft) DRAFT_FILTER="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --strict) STRICT=1; shift ;;
        -h|--help) usage ;;
        *) [[ -z "$WORKSPACE" ]] && WORKSPACE="$1" && shift || { echo "unexpected arg: $1" >&2; usage; } ;;
    esac
done

[[ -z "$WORKSPACE" ]] && usage
WORKSPACE="${WORKSPACE/#\~/$HOME}"
[[ -d "$WORKSPACE" ]] || { echo "workspace not found: $WORKSPACE" >&2; exit 2; }

SUBS="$WORKSPACE/submissions/SUBMISSIONS.md"
[[ -f "$SUBS" ]] || { echo "missing $SUBS" >&2; exit 2; }

# Locate foundry project root: prefer <workspace>/pocs, else <workspace>.
FPROJ=""
for cand in "$WORKSPACE/pocs" "$WORKSPACE"; do
    if [[ -f "$cand/foundry.toml" ]]; then FPROJ="$cand"; break; fi
done
if [[ -z "$FPROJ" ]]; then
    echo "SKIPPED: no foundry.toml under $WORKSPACE or $WORKSPACE/pocs"
    exit 0
fi

FORGE_BIN=""
if command -v forge >/dev/null 2>&1; then
    FORGE_BIN="$(command -v forge)"
fi
# Prefer Foundry toolchain forge over any other binary named forge
if [[ -x "$HOME/.foundry/bin/forge" ]]; then
    FORGE_BIN="$HOME/.foundry/bin/forge"
fi
if [[ -z "$FORGE_BIN" ]]; then
    echo "SKIPPED: forge not in PATH"
    exit 0
fi

# Pick a portable timeout helper (gtimeout on macOS via coreutils, else bash fallback).
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"
fi
run_with_timeout() {
    if [[ -n "$TIMEOUT_BIN" ]]; then
        "$TIMEOUT_BIN" "$TIMEOUT_SECS" "$@"
    else
        # Fallback: spawn + watchdog.
        ( "$@" ) & local pid=$!
        ( sleep "$TIMEOUT_SECS"; kill -9 "$pid" 2>/dev/null ) & local wd=$!
        wait "$pid" 2>/dev/null; local rc=$?
        kill -9 "$wd" 2>/dev/null; wait "$wd" 2>/dev/null
        return $rc
    fi
}

# Enumerate draft headings (bash 3.2-compatible: no mapfile).
DRAFT_NUMS=(); DRAFT_STARTS=(); DRAFT_ENDS=(); DRAFT_TITLES=()
TMP_HEADINGS=$(mktemp -t verify-pocs-h.XXXXXX)
grep -nE '^### Draft [0-9]+' "$SUBS" > "$TMP_HEADINGS" || true
total_lines=$(wc -l < "$SUBS" | tr -d ' ')

prev_lineno=""; prev_num=""; prev_title=""
while IFS= read -r line; do
    lineno="${line%%:*}"
    rest="${line#*:}"
    num=$(echo "$rest" | sed -E 's/^### Draft ([0-9]+).*/\1/')
    title=$(echo "$rest" | sed -E 's/^### Draft [0-9]+ — //')
    if [[ -n "$prev_lineno" ]]; then
        DRAFT_NUMS+=("$prev_num"); DRAFT_STARTS+=("$prev_lineno")
        DRAFT_ENDS+=("$((lineno-1))"); DRAFT_TITLES+=("$prev_title")
    fi
    prev_lineno="$lineno"; prev_num="$num"; prev_title="$title"
done < "$TMP_HEADINGS"
if [[ -n "$prev_lineno" ]]; then
    DRAFT_NUMS+=("$prev_num"); DRAFT_STARTS+=("$prev_lineno")
    DRAFT_ENDS+=("$total_lines"); DRAFT_TITLES+=("$prev_title")
fi
rm -f "$TMP_HEADINGS"

if [[ ${#DRAFT_NUMS[@]} -eq 0 ]]; then
    echo "no draft sections found in $SUBS"
    exit 0
fi

PASS=0; FAIL=0; SKIP=0
SUMMARY=()

for i in "${!DRAFT_NUMS[@]}"; do
    n="${DRAFT_NUMS[$i]}"
    [[ -n "$DRAFT_FILTER" && "$DRAFT_FILTER" != "$n" ]] && continue
    s="${DRAFT_STARTS[$i]}"; e="${DRAFT_ENDS[$i]}"; t="${DRAFT_TITLES[$i]}"

    # Extract path hint: "Ran N tests for <path>.t.sol:<Contract>" within draft block.
    hint=$(sed -n "${s},${e}p" "$SUBS" | grep -E 'Ran [0-9]+ tests? for [^[:space:]]+\.t\.sol:[A-Za-z0-9_]+' | head -1 || true)
    if [[ -z "$hint" ]]; then
        SUMMARY+=("Draft $n: SKIP (no path hint) — ${t:0:60}")
        SKIP=$((SKIP+1)); continue
    fi
    rel_path=$(echo "$hint" | sed -E 's/.*Ran [0-9]+ tests? for ([^[:space:]:]+)\.t\.sol:.*/\1.t.sol/')
    contract=$(echo "$hint" | sed -E 's/.*\.t\.sol:([A-Za-z0-9_]+).*/\1/')

    # Derive profile from path: test/r77/<profile>/...
    profile=$(echo "$rel_path" | awk -F/ '{print $3}')

    abs_path="$FPROJ/$rel_path"
    if [[ ! -f "$abs_path" ]]; then
        SUMMARY+=("Draft $n: SKIP (test file missing: $rel_path)")
        SKIP=$((SKIP+1)); continue
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        SUMMARY+=("Draft $n: WOULD-RUN profile=$profile path=$rel_path contract=$contract")
        continue
    fi

    echo "[verify] Draft $n  profile=$profile  $rel_path :: $contract"
    out_file=$(mktemp -t verify-pocs.XXXXXX)
    (
        cd "$FPROJ" || exit 99
        FOUNDRY_PROFILE="$profile" run_with_timeout "$FORGE_BIN" test \
            --match-path "$rel_path" --match-contract "$contract" -vv
    ) >"$out_file" 2>&1
    rc=$?

    # Phase 47c retry: if Foundry's auto-detect can't find a solc version
    # (typical when ~/.svm/ is empty or offline), extract a concrete version
    # from the "Encountered invalid solc version ... =0.8.X" error and retry
    # with `--use 0.8.X`. solc-select-installed binaries satisfy this.
    if [[ $rc -ne 0 ]] && grep -q 'Encountered invalid solc version' "$out_file"; then
        retry_ver=$(grep -oE 'matches the version requirement: =?[0-9]+\.[0-9]+\.[0-9]+' "$out_file" \
                    | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        if [[ -n "$retry_ver" ]]; then
            echo "[verify] Draft $n  retry with --use $retry_ver"
            (
                cd "$FPROJ" || exit 99
                FOUNDRY_PROFILE="$profile" run_with_timeout "$FORGE_BIN" test \
                    --match-path "$rel_path" --match-contract "$contract" \
                    --use "$retry_ver" -vv
            ) >"$out_file" 2>&1
            rc=$?
        fi
    fi

    if [[ $rc -eq 0 ]] && grep -q 'Suite result: ok\.' "$out_file"; then
        SUMMARY+=("Draft $n: PASS — $contract")
        PASS=$((PASS+1))
    else
        tail_excerpt=$(tail -3 "$out_file" | tr '\n' ' | ')
        SUMMARY+=("Draft $n: FAIL (rc=$rc) — $contract :: ${tail_excerpt:0:140}")
        FAIL=$((FAIL+1))
    fi
    rm -f "$out_file"
done

echo
echo "==== verify-pocs summary (workspace=$WORKSPACE) ===="
if [[ ${#SUMMARY[@]} -gt 0 ]]; then
    for line in "${SUMMARY[@]}"; do echo "  $line"; done
fi
echo "----"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"

if [[ "$STRICT" -eq 1 && "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
