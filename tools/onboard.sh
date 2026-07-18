#!/usr/bin/env bash
# onboard.sh — interactive workspace bootstrap helper.
#
# Canonical auditing after bootstrap should continue through:
#   make engage WORKSPACE=<path>
#   python3 tools/engage.py --workspace <path> --stage all
#
# Wraps setup-workspace.sh + fetch-scope.sh + extract-pdfs.sh behind four prompts
# so a fresh operator can go from "nothing" to "ready for engage.py or
# flow-gate.sh" in one command. All prompts are optional — press Enter to skip.
#
# Usage:
#   ./tools/onboard.sh <project-name> [workspace-root]
#
# Non-interactive mode: pipe answers on stdin, one per line, in this order:
#   1. bounty URL (blank for none)
#   2. target repo URL (blank for none)
#   3. tag or commit (blank for HEAD)
#   4. prior-audit PDF directory (blank for none)
#   5. RPC URL (blank for default)
#
# Example:
#   printf 'https://cantina.xyz/bounties/foo\nhttps://github.com/org/repo\nv1.2.0\n\n\n' \
#       | ./tools/onboard.sh my-project
#
# Fixes SKILL_ISSUES #153: "onboarding friction — 5 separate commands, too easy
# to skip scope or targets".

set -uo pipefail

PROJECT_NAME="${1:-}"
WORKSPACE_ROOT="${2:-$HOME/audits}"

if [ -z "$PROJECT_NAME" ]; then
    cat >&2 <<EOF
Usage: $0 <project-name> [workspace-root]

Interactive wizard: scaffolds the workspace, prompts for scope URL,
target repo, prior audits, and RPC, then kicks off fetch-scope.sh and
extract-pdfs.sh automatically.

Example: $0 centrifuge-v3 ~/audits
EOF
    exit 1
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WS="$WORKSPACE_ROOT/$PROJECT_NAME"
SCOPE_STATE="placeholder"

# Detect stdin mode
if [ -t 0 ]; then
    INTERACTIVE=1
else
    INTERACTIVE=0
fi

ask() {
    # ask <var_name> <prompt>
    local var="$1"
    local prompt="$2"
    local val=""
    if [ "$INTERACTIVE" -eq 1 ]; then
        printf "  %s " "$prompt" >&2
    fi
    IFS= read -r val || true
    eval "$var=\"\$val\""
}

printf '\n=== auditooor onboarding wizard: %s ===\n\n' "$PROJECT_NAME" >&2

if [ -e "$WS" ]; then
    echo "  [!] Workspace $WS already exists." >&2
    echo "      To re-run onboard, either pick a new project name or rm -rf the workspace first." >&2
    exit 1
fi

# 1. Scope URL
ask BOUNTY_URL "Bounty URL (e.g. https://cantina.xyz/bounties/...) [optional]:"

# 2. Target repo URL
ask REPO_URL "Target repo URL (e.g. https://github.com/org/repo) [optional]:"

# 3. Tag / commit
TAG=""
if [ -n "${REPO_URL:-}" ]; then
    ask TAG "  Tag / commit (blank = main HEAD):"
fi

# 4. Prior-audit PDFs
ask PRIOR_PDF_DIR "Prior-audit PDF directory (blank = none):"

# 5. RPC URL
ask RPC_URL "Preferred mainnet RPC URL (blank = default ethers.io):"

printf '\n--- scaffolding workspace ---\n' >&2

# Invoke setup-workspace.sh
if ! bash "$AUDITOOOR_DIR/tools/setup-workspace.sh" "$PROJECT_NAME" "$WORKSPACE_ROOT" >/dev/null; then
    echo "  [✗] setup-workspace.sh failed" >&2
    exit 1
fi
echo "  [✓] workspace scaffolded at $WS"

# Pre-populate scope.json with URL if given
if [ -n "${BOUNTY_URL:-}" ]; then
    printf '{\n  "bounty_url": "%s",\n  "project": "%s",\n  "created": "%s"\n}\n' \
        "$BOUNTY_URL" "$PROJECT_NAME" "$(date +%Y-%m-%d)" > "$WS/scope.json"
    echo "  [✓] scope.json populated with bounty URL"
fi

# Pre-populate targets.tsv if repo given
if [ -n "${REPO_URL:-}" ]; then
    # Derive local name from repo URL
    LOCAL_NAME="$(basename "$REPO_URL" .git)"
    REF="${TAG:-main}"
    {
        echo "# Onboarded $(date +%Y-%m-%d) for project: $PROJECT_NAME"
        echo "# Columns: <repo_url>	<tag_or_commit>	<local_name>"
        echo "# Run: ./tools/fetch-targets.sh $WS"
        echo ""
        printf '%s\t%s\t%s\n' "$REPO_URL" "$REF" "$LOCAL_NAME"
    } > "$WS/targets.tsv"
    echo "  [✓] targets.tsv prepopulated ($LOCAL_NAME @ $REF)"
fi

# Record RPC URL
if [ -n "${RPC_URL:-}" ]; then
    printf 'RPC_URL=%s\n' "$RPC_URL" > "$WS/.env"
    echo "  [✓] .env written with RPC_URL"
fi

# Auto-run fetch-scope.sh if bounty URL given
if [ -n "${BOUNTY_URL:-}" ]; then
    printf '\n--- fetching scope from bounty URL ---\n' >&2
    # R67e (SKILL_ISSUES #170): some bounty platforms auth-wall their
    # scope pages (HackenProof, some Immunefi bounties). Detect by URL
    # pattern and provide clear paste-mode guidance instead of silently
    # scraping the sign-in page.
    case "$BOUNTY_URL" in
        *hackenproof.com*|*dashboard.hackenproof.com*)
            SCOPE_STATE="manual_required"
            echo "  [!] HackenProof program page detected — scope is behind sign-in auth-wall."
            echo "      The scrape will return the 'Sign in' HTML, not the scope."
            echo "      Manual paste required:"
            echo "        1. Open $BOUNTY_URL in a browser with your HackenProof session"
            echo "        2. Copy the ENTIRE program page (scope, OOS, severity, rules)"
            echo "        3. Paste into: $WS/SCOPE.md (overwrite the placeholder)"
            echo "        4. Then run: bash tools/extract-oos.sh $WS"
            echo "      (Skipping automated fetch to avoid a misleading stub.)"
            ;;
        *)
            if bash "$AUDITOOOR_DIR/tools/fetch-scope.sh" "$WS" "$BOUNTY_URL" >/dev/null 2>&1; then
                if [ -s "$WS/SCOPE.md" ]; then
                    # R67e — detect "sign in" auth-walled scrapes even on non-HackenProof URLs
                    if grep -qiE 'sign in|sign up|signin|login required|unauthorized' "$WS/SCOPE.md" 2>/dev/null; then
                        SCOPE_STATE="manual_required"
                        echo "  [!] SCOPE.md returned a sign-in page ($(wc -l <"$WS/SCOPE.md" | tr -d ' ') lines)"
                        echo "      Manual paste required — overwrite $WS/SCOPE.md with real scope."
                    else
                        SCOPE_STATE="fetched_ok"
                        echo "  [✓] SCOPE.md populated ($(wc -l <"$WS/SCOPE.md" | tr -d ' ') lines)"
                    fi
                else
                    SCOPE_STATE="manual_required"
                    echo "  [!] fetch-scope.sh ran but SCOPE.md is empty — check bounty URL manually"
                fi
            else
                SCOPE_STATE="manual_required"
                echo "  [!] fetch-scope.sh failed; run manually later:"
                echo "        ./tools/fetch-scope.sh $WS \"$BOUNTY_URL\""
            fi
            ;;
    esac
fi

# Handle prior audits
if [ -n "${PRIOR_PDF_DIR:-}" ] && [ -d "$PRIOR_PDF_DIR" ]; then
    printf '\n--- processing prior-audit PDFs ---\n' >&2
    mkdir -p "$WS/prior_audits"
    PDF_COUNT=0
    for pdf in "$PRIOR_PDF_DIR"/*.pdf "$PRIOR_PDF_DIR"/*.PDF; do
        [ -f "$pdf" ] || continue
        cp "$pdf" "$WS/prior_audits/"
        PDF_COUNT=$((PDF_COUNT + 1))
    done
    if [ "$PDF_COUNT" -gt 0 ]; then
        echo "  [✓] copied $PDF_COUNT prior-audit PDF(s) to prior_audits/"
        if bash "$AUDITOOOR_DIR/tools/extract-pdfs.sh" "$WS/prior_audits" "$WS/prior_audits" >/dev/null 2>&1; then
            TXT_COUNT=$(ls "$WS/prior_audits"/*.txt 2>/dev/null | wc -l | tr -d ' ')
            echo "  [✓] extracted $TXT_COUNT PDF(s) to text"
        else
            echo "  [!] extract-pdfs.sh had issues; inspect $WS/prior_audits manually"
        fi
    else
        echo "  [!] no .pdf files found in $PRIOR_PDF_DIR"
    fi
elif [ -n "${PRIOR_PDF_DIR:-}" ]; then
    echo "  [!] $PRIOR_PDF_DIR does not exist — skipped"
fi

# Write an onboarding summary
AUTO_FILES=()
[ -n "${BOUNTY_URL:-}" ] && AUTO_FILES+=("- scope.json (bounty URL recorded)")
[ "$SCOPE_STATE" = "fetched_ok" ] && AUTO_FILES+=("- SCOPE.md (auto-fetched from bounty URL)")
[ "$SCOPE_STATE" = "manual_required" ] && AUTO_FILES+=("- SCOPE.md (placeholder/manual follow-up still required before flow-gate)")
[ -z "${BOUNTY_URL:-}" ] && [ -f "$WS/SCOPE.md" ] && AUTO_FILES+=("- SCOPE.md (placeholder scaffolded; replace before flow-gate/submission)")
[ -n "${REPO_URL:-}" ] && AUTO_FILES+=("- targets.tsv (ready for fetch-targets.sh)")
[ -n "${PRIOR_PDF_DIR:-}" ] && [ -d "$WS/prior_audits" ] && AUTO_FILES+=("- prior_audits/*.{pdf,txt}")
[ -n "${RPC_URL:-}" ] && AUTO_FILES+=("- .env (RPC_URL)")

if [ "${#AUTO_FILES[@]}" -gt 0 ]; then
    AUTO_FILES_MD=$(printf '%s\n' "${AUTO_FILES[@]}")
else
    AUTO_FILES_MD="- none yet"
fi

NEXT_STEPS=()

if [ -z "${BOUNTY_URL:-}" ]; then
    NEXT_STEPS+=("1. Replace the placeholder \`SCOPE.md\` with the real bounty program text")
    NEXT_STEPS+=("   — run \`./tools/fetch-scope.sh $WS <bounty-url>\` or paste the full program page manually")
elif [ "$SCOPE_STATE" = "fetched_ok" ]; then
    NEXT_STEPS+=("1. Review \`SCOPE.md\` and confirm the fetched bounty text is complete")
    NEXT_STEPS+=("   — if the fetch hit an auth wall or partial page, overwrite it with the real program text before gating")
else
    NEXT_STEPS+=("1. Replace the placeholder / partial \`SCOPE.md\` with the real bounty program text")
    NEXT_STEPS+=("   — the automated fetch did not produce a trustworthy scope file, so fix that before gating")
fi

NEXT_STEPS+=("2. Run \`./tools/extract-oos.sh $WS\`")
NEXT_STEPS+=("   — derives \`OOS_CHECKLIST.md\` and \`SEVERITY_CAPS.md\` from the current \`SCOPE.md\`")

if [ -n "${REPO_URL:-}" ]; then
    NEXT_STEPS+=("3. Run \`./tools/fetch-targets.sh $WS\`")
    NEXT_STEPS+=("   — clones repo(s) from \`targets.tsv\`, pins commits, and build-checks the target")
else
    NEXT_STEPS+=("3. Populate \`targets.tsv\`, then run \`./tools/fetch-targets.sh $WS\`")
    NEXT_STEPS+=("   — the scaffold is ready, but flow-gate will hard-stop until target repos are declared and fetched")
fi

NEXT_STEPS+=("4. Run \`make engage WORKSPACE=$WS\`")
NEXT_STEPS+=("   — this is the canonical entrypoint once scope, OOS extraction, and target fetch are in place")

NEXT_STEPS_MD=$(printf '%s\n' "${NEXT_STEPS[@]}")

cat > "$WS/ONBOARDING.md" <<EOF
# Onboarding summary — $PROJECT_NAME

**Date:** $(date +%Y-%m-%d)

## Inputs collected

- Bounty URL: ${BOUNTY_URL:-<none>}
- Target repo: ${REPO_URL:-<none>}
- Tag/commit: ${TAG:-HEAD}
- Prior audits: ${PRIOR_PDF_DIR:-<none>}
- RPC URL: ${RPC_URL:-<default>}

## Auto-generated files

$AUTO_FILES_MD

## Next steps

$NEXT_STEPS_MD
EOF

printf '\n=== onboarding complete ===\n\n' >&2
echo "Workspace: $WS"
echo ""
echo "Next steps:"
printf '%s\n' "${NEXT_STEPS[@]}"
echo ""
echo "Full summary: $WS/ONBOARDING.md"
