#!/usr/bin/env bash
# mine-to-patterns.sh — R70 SKILL_ISSUES #162 closure: end-to-end pipeline
# from github fix-commit mining to proposed DSL pattern briefs.
#
# Pipeline:
#   1. mine-fix-diffs.sh <org/repo> <since-date>       → /tmp/r55_fixdiffs/<org>-<repo>/
#   2. This tool enumerates each candidate and emits:
#        reference/proposed_patterns/<org>-<repo>/<sha>.brief.md
#      — a per-diff agent brief the operator (or dispatcher) feeds to an
#      LLM to extract a generalizable DSL pattern.
#   3. Summary at reference/proposed_patterns/MINING_MANIFEST.md
#
# Usage:
#   bash tools/mine-to-patterns.sh <org/repo> <since-date> [--max-pages N]
#   bash tools/mine-to-patterns.sh --preset high-roi   # runs pre-seeded list
#
# The `--preset high-roi` list:
#   - morpho-org/morpho-blue
#   - Uniswap/v4-core
#   - compound-finance/compound-protocol
#   - euler-xyz/euler-vault-kit
#   - aave/aave-v3-core
#
# Output structure:
#   reference/proposed_patterns/
#     MINING_MANIFEST.md               — running tally of all mined diffs
#     <org>-<repo>/
#       <sha>.brief.md                 — per-diff brief for pattern extraction
#       <sha>.diff.patch               — raw diff (copied from /tmp)
#       <sha>.meta.json                — commit metadata
#
# After mining, the operator dispatches the briefs as a parallel Task block
# (or uses `tools/dispatch-pattern-briefs.sh`). Each agent returns a proposed
# YAML pattern + confidence score. High-confidence proposals are dropped into
# reference/patterns.dsl/, compiled, and regression-tested per R67g discipline.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINE="$AUDITOOOR_DIR/tools/mine-fix-diffs.sh"
STAGING="$AUDITOOOR_DIR/reference/proposed_patterns"

usage() {
    cat >&2 <<EOF
Usage:
  $0 <org/repo> <since-date> [--max-pages N]
  $0 --preset high-roi

High-ROI preset runs mining against 5 battle-tested protocols whose
audit-fix histories are likely to yield novel pattern classes:

  morpho-org/morpho-blue        since 2023-01-01
  Uniswap/v4-core               since 2024-01-01
  compound-finance/compound-protocol  since 2023-01-01
  euler-xyz/euler-vault-kit     since 2024-01-01
  aave/aave-v3-core             since 2023-01-01
EOF
    exit 1
}

[ $# -lt 1 ] && usage

MODE="custom"
if [ "$1" = "--preset" ] && [ "${2:-}" = "high-roi" ]; then
    MODE="preset"
fi

mkdir -p "$STAGING"
MANIFEST="$STAGING/MINING_MANIFEST.md"

if [ ! -f "$MANIFEST" ]; then
    cat > "$MANIFEST" <<'EOF'
# Fix-diff mining manifest — R70 SKILL_ISSUES #162 closure

Running tally of all mined audit-fix diffs, per (org/repo, since-date)
pair. Each entry links to the per-diff briefs staged for pattern-
extraction agent dispatch.

| Source | Since | Candidates | Briefs generated | Patterns merged |
|---|---|---:|---:|---:|
EOF
fi

mine_one() {
    local spec="$1"; local since="$2"
    local org_repo="$spec"
    local org="${org_repo%%/*}"
    local repo="${org_repo##*/}"
    local slug="${org}-${repo}"
    local mine_out="/tmp/r55_fixdiffs/$slug"
    local staging_dir="$STAGING/$slug"
    mkdir -p "$staging_dir"

    echo "============================================================"
    echo "[mine-to-patterns] mining $org_repo since $since"
    echo "============================================================"
    bash "$MINE" "$org_repo" "$since" ${MAX_PAGES:+--max-pages "$MAX_PAGES"} 2>&1 | tail -10

    local cand=0; local briefs=0
    if [ -d "$mine_out" ]; then
        for commit_dir in "$mine_out"/*/; do
            [ -d "$commit_dir" ] || continue
            local sha; sha=$(basename "$commit_dir")
            [ "$sha" = "findings.json" ] && continue
            cand=$((cand + 1))

            # Copy artifacts
            cp "$commit_dir/diff.patch" "$staging_dir/${sha}.diff.patch" 2>/dev/null || continue
            cp "$commit_dir/meta.json"  "$staging_dir/${sha}.meta.json"  2>/dev/null

            # Generate per-diff pattern-extraction brief
            python3 - "$commit_dir/meta.json" "$commit_dir/diff.patch" "$staging_dir/${sha}.brief.md" "$org_repo" "$sha" <<'PY'
import sys, json, pathlib
meta_path, diff_path, brief_path, repo, sha = sys.argv[1:]
meta = json.loads(pathlib.Path(meta_path).read_text())
diff = pathlib.Path(diff_path).read_text()[:20000]  # cap for brief size

title = meta.get('message', '(no title)')[:140]
full = meta.get('full_message', '')[:600]
tags = ', '.join(meta.get('audit_tags', [])) or '(none)'
files = [f["file"] for f in meta.get('sol_files', [])]

brief = f"""# Pattern-extraction brief — {repo} @ {sha[:8]}

## Commit metadata

- Repo: {repo}
- SHA: `{sha}`
- Title: {title}
- Audit tags: {tags}
- Files changed: {', '.join(files) if files else '(none)'}

## Full commit message (truncated 600)

```
{full}
```

## Agent task

You are a pattern-extraction researcher. Read the audit-fix diff below.
Your job: infer the structural bug-shape this fix addresses, then draft
a candidate DSL pattern YAML that would detect the PRE-fix form on a
fresh codebase.

**Output format** — return valid YAML ready to drop into
`reference/patterns.dsl/<name>.yaml`:

```yaml
pattern: <kebab-case-name>
source: auditooor-R70-fixdiff-mined-{repo.split('/')[1].lower()}-{sha[:8]}
severity: LOW|MEDIUM|HIGH|CRITICAL
confidence: LOW|MEDIUM|HIGH

# Commit message reference:
# {title}

# Bug class generalization:
# <1-3 sentence description of the structural shape the pattern
#  catches. NOT the specific protocol's vulnerability — the
#  generalizable class.>

preconditions:
  - <optional contract-level predicates>

match:
  - function.kind: external_or_public
  - function.name_matches: '<regex if shape-specific>'
  - function.body_contains_regex: '<pre-fix pattern>'
  - function.body_not_contains_regex: '<what the fix adds, so pattern
      stops firing after it's patched>'
  - function.not_in_skip_list: true
  - function.not_leaf_helper: true

help: "<one-line help text>"
wiki_title: "<≤120 char>"
wiki_description: "<≤400 char — mechanism description>"
wiki_exploit_scenario: "<≤400 char — concrete attack path>"
wiki_recommendation: "<≤600 char — the fix this diff applied,
  generalized>"
```

**Guardrails**:
- If the diff is NOT a security fix (refactor, comment, test, gas
  optimization), return `SKIP — not-security-relevant` and stop.
- If the diff fixes a bug class we ALREADY have in `patterns.dsl/`
  (check by searching for keyword overlap), return
  `SKIP — duplicate-of:<existing-pattern-name>`.
- Prefer MEDIUM confidence over HIGH unless the fix is a textbook
  check-addition (require / revert / guard). If the fix is a major
  refactor that rewrites the logic, the pattern is probably
  non-generalizable → SKIP.
- `severity` should mirror the audit-firm's classification if the
  commit message references one (e.g. "H-01" → HIGH, "M-04" →
  MEDIUM). Default to MEDIUM if unknown.

**Diff (first 20000 chars)**:

```diff
{diff}
```

Return only the YAML (or SKIP) — no prose.
"""
pathlib.Path(brief_path).write_text(brief)
print(f"wrote {brief_path}")
PY
            briefs=$((briefs + 1))
        done
    fi

    # Update manifest row
    echo "| \`$org_repo\` | $since | $cand | $briefs | (manual) |" >> "$MANIFEST"
    echo "[mine-to-patterns] $org_repo: $cand candidates → $briefs briefs generated"
}

if [ "$MODE" = "preset" ]; then
    mine_one "morpho-org/morpho-blue"              "2023-01-01"
    mine_one "Uniswap/v4-core"                     "2024-01-01"
    mine_one "compound-finance/compound-protocol"  "2023-01-01"
    mine_one "euler-xyz/euler-vault-kit"           "2024-01-01"
    mine_one "aave/aave-v3-core"                   "2023-01-01"
else
    REPO="$1"
    SINCE="${2:-2023-01-01}"
    MAX_PAGES=""
    shift 2 2>/dev/null || true
    while [ $# -gt 0 ]; do
        case "$1" in
            --max-pages) MAX_PAGES="$2"; shift 2 ;;
            *) echo "[mine-to-patterns] unknown arg: $1" >&2; usage ;;
        esac
    done
    mine_one "$REPO" "$SINCE"
fi

echo ""
echo "============================================================"
echo "[mine-to-patterns] DONE."
echo "  Briefs:   $STAGING/<org>-<repo>/*.brief.md"
echo "  Manifest: $MANIFEST"
echo ""
echo "Next step: dispatch the briefs via Task (or Agent SDK) in"
echo "parallel. Each returns a candidate YAML or SKIP. Merge the"
echo "high-confidence YAMLs into reference/patterns.dsl/ and run:"
echo "  python3 tools/pattern-compile.py --all"
echo "Then regression-scan on 2-3 known-TP workspaces."
echo "============================================================"
