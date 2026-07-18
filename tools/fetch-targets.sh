#!/usr/bin/env bash
# fetch-targets.sh — clone + pin + submodule-init + forge-build + pdf-extract
# for every in-scope repo of a new bounty.
#
# Usage:
#   ./tools/fetch-targets.sh <workspace-dir>
#
# Reads `<workspace-dir>/targets.tsv` (tab-separated, one row per repo):
#
#     # repo_url  pinned_commit  local_name
#     https://github.com/morpho-org/morpho-blue.git   55d2d99304fb3fb930c688462ae2ccabb1d533ad   morpho-blue
#     https://github.com/morpho-org/morpho-blue-irm.git   a7d9cce3451b4a106bfd40933ac57a785b5228f3   morpho-blue-irm
#     https://github.com/morpho-org/pre-liquidation.git   main   pre-liquidation
#
# Lines starting with `#` and empty lines are skipped.
#
# For each target, this script:
#   1. Clones (shallow if possible) into $WS/src/<local_name>
#   2. Checks out the pinned commit (scope integrity)
#   3. Rewrites .gitmodules from git@github.com: → https://github.com/ to
#      avoid SSH-key requirements on submodules
#   4. git submodule update --init --recursive
#   5. forge build (pre-warms cache so Slither can import compiled artifacts)
#   6. pdftotext -layout every audits/*.pdf into $WS/prior_audits/<name>.txt
#   7. Prints a ready-to-paste audit-digest agent brief
#
# Exit code:
#   0 — every target succeeded
#   1 — at least one target failed; the rest are still attempted
#
# See SKILL_ISSUE #54 for the friction this replaces.

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-dir>"
    echo ""
    echo "Prerequisite: <workspace-dir>/targets.tsv exists with tab-separated rows:"
    echo "    <repo_url>\\t<pinned_commit>\\t<local_name>"
    exit 1
fi

WS="$(cd "$1" 2>/dev/null && pwd)" || { echo "Error: $1 not found"; exit 1; }
TARGETS_FILE="$WS/targets.tsv"
if [ ! -f "$TARGETS_FILE" ]; then
    echo "Error: $TARGETS_FILE not found"
    echo ""
    echo "Create it first. Example:"
    echo "    # repo_url pinned_commit local_name"
    printf '    https://github.com/morpho-org/morpho-blue.git\\t55d2d993...\\tmorpho-blue\n'
    exit 1
fi

mkdir -p "$WS/src" "$WS/prior_audits"

# Ensure foundry is on PATH
export PATH="$HOME/.foundry/bin:$PATH"

FAIL=0
COUNT=0
while IFS=$'\t' read -r repo_url pinned_commit local_name; do
    # Skip comments and empty lines
    case "$repo_url" in
        '#'*|'') continue ;;
    esac
    if [ -z "${local_name:-}" ] || [ -z "${pinned_commit:-}" ]; then
        echo "[skip] malformed row: $repo_url"
        continue
    fi
    COUNT=$((COUNT + 1))
    DEST="$WS/src/$local_name"
    printf '\n=== %s ===\n' "$local_name"

    # If the destination already has a git repo AND an `out/` dir with
    # build artifacts, treat it as fully set up and only re-run the PDF
    # extraction step (cheap). Users can force a full rebuild by deleting
    # the out/ directory.
    ALREADY_BUILT=0
    if [ -d "$DEST/.git" ] && [ -d "$DEST/out" ]; then
        echo "  [skip] already cloned + built at $DEST (delete out/ to force rebuild)"
        ALREADY_BUILT=1
    fi

    if [ "$ALREADY_BUILT" -eq 0 ]; then
        # 1. Clone
        if [ -d "$DEST/.git" ]; then
            echo "  [skip] already cloned at $DEST"
        else
            if ! git clone "$repo_url" "$DEST" 2>&1 | tail -2; then
                echo "  [fail] git clone failed"
                FAIL=1
                continue
            fi
        fi

        # 2. Pin to commit (if not "main"/"master")
        # Fetch enough history (default 300 commits, > the 30-commit
        # FLATTENED_SNAPSHOT_THRESHOLD) so tier-6 commit-mining (R47 dedup +
        # fork-base discovery) has real history to walk. A --depth 1 snapshot
        # silently degrades mining to a scored-ok no-op. Overridable via
        # AUDITOOOR_CLONE_DEPTH for ultra-large repos / bandwidth-constrained hosts.
        if [ "$pinned_commit" != "main" ] && [ "$pinned_commit" != "master" ]; then
            (cd "$DEST" && git fetch --depth "${AUDITOOOR_CLONE_DEPTH:-300}" origin "$pinned_commit" 2>&1 | tail -2 || true)
            if ! (cd "$DEST" && git checkout "$pinned_commit" 2>&1 | tail -2); then
                echo "  [fail] git checkout $pinned_commit failed"
                FAIL=1
                continue
            fi
        fi

        # 3. Rewrite .gitmodules SSH → HTTPS
        if [ -f "$DEST/.gitmodules" ]; then
            sed -i '' -e 's|git@github.com:|https://github.com/|g' "$DEST/.gitmodules" 2>/dev/null || \
                sed -i -e 's|git@github.com:|https://github.com/|g' "$DEST/.gitmodules" 2>/dev/null || true
            (cd "$DEST" && git submodule sync --recursive 2>&1 | tail -2)
        fi

        # 4. Submodule init (recursive)
        (cd "$DEST" && git submodule update --init --recursive 2>&1 | tail -3) || {
            echo "  [warn] submodule update failed (repo may not use submodules)"
        }

        # 5. Forge build (pre-warm cache) — non-blocking on lint errors
        # SKILL_ISSUE #60 (Vault-v2 forge build OOM): serialise solc passes
        # (FOUNDRY_SOLC_JOBS=1) and skip tests + scripts so the compile set is
        # halved and peak RSS stays under ~1 GB even on large multi-solc trees.
        # Production-faithful artefacts are not needed here — Slither only reads
        # library/contract ASTs, and the skipped test/script targets would not
        # otherwise influence detector output.
        # Prefer real Foundry forge over PATH collisions (e.g. AI CLI tool named forge)
        FORGE_BIN=""
        if [[ -x "$HOME/.foundry/bin/forge" ]]; then
            FORGE_BIN="$HOME/.foundry/bin/forge"
        elif command -v forge >/dev/null 2>&1; then
            FORGE_BIN="$(command -v forge)"
        fi
        if [ -f "$DEST/foundry.toml" ] && [ -n "$FORGE_BIN" ]; then
            (cd "$DEST" && FOUNDRY_SOLC_JOBS=1 "$FORGE_BIN" build --skip test --skip script 2>&1 | tail -3) || {
                echo "  [warn] forge build had issues; slither may still work"
                echo "  [hint] retry via: (cd $DEST && FOUNDRY_SOLC_JOBS=1 $FORGE_BIN build --skip test --skip script)"
            }
        fi
    fi

    # 6. Extract audit PDFs → $WS/prior_audits/ (always, cheap)
    if [ -d "$DEST/audits" ]; then
        for pdf in "$DEST/audits"/*.pdf; do
            [ -f "$pdf" ] || continue
            out="$WS/prior_audits/$(basename "$pdf" .pdf).txt"
            if [ -f "$out" ]; then
                continue
            fi
            if command -v pdftotext >/dev/null 2>&1; then
                pdftotext -layout "$pdf" "$out" 2>/dev/null && echo "  [ok] extracted $(basename "$pdf")"
            else
                echo "  [warn] pdftotext not installed; skipped $(basename "$pdf")"
            fi
        done
    fi

    echo "  [done] $local_name ready"
done < "$TARGETS_FILE"

printf '\n=== fetch-targets summary ===\n'
echo "targets processed: $COUNT"
echo "failures: $FAIL"
if [ -d "$WS/prior_audits" ]; then
    txt_count=$(find "$WS/prior_audits" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')
    echo "audit .txt files in $WS/prior_audits/: $txt_count"
    if [ "$txt_count" -gt 0 ]; then
        digest_count=$(find "$WS/prior_audits" -maxdepth 1 -name 'DIGEST_*.md' 2>/dev/null | wc -l | tr -d ' ')
        if [ "$digest_count" -eq 0 ]; then
            echo ""
            echo "NEXT: spawn Sonnet agents to digest the $txt_count audit reports."
            echo "  Template: $(cd "$(dirname "$0")/.." && pwd)/templates/audit_digest_agent_brief.md"
            echo "  Rule of thumb: one agent per 2-3 PDFs."
            echo "  Then run: ./tools/pre-iter-check.sh $WS"
        fi
    fi
fi

exit $FAIL
