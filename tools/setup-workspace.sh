#!/usr/bin/env bash
# setup-workspace.sh — scaffold a new audit workspace
#
# Usage:
#   ./tools/setup-workspace.sh <project-name> [workspace-dir]
#
# Creates:
#   <workspace-dir>/<project-name>/
#     AUDIT.md
#     SCOPE.md            — placeholder bounty program text (replace via fetch-scope.sh/manual paste)
#     SEVERITY.md          — copy from bounty platform manually
#     STATUS.md            — from templates/
#     FINDINGS.md          — from templates/
#     SESSION_LOG.md       — from templates/
#     BUG_CHECKLIST.md     — from checklists/bug_taxonomy.md
#     TODO.md              — empty
#     scope.json           — machine-readable scope metadata / bounty URL
#     notes/               — empty dir
#     submissions/         — empty dir
#     poc-tests/           — empty dir

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <project-name> [workspace-dir]"
    echo "Example: $0 polymarket-v2 ~/audits"
    exit 1
fi

PROJECT_NAME="$1"
WORKSPACE_DIR="${2:-$HOME/audits}"
AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$WORKSPACE_DIR/$PROJECT_NAME"

if [ -e "$TARGET" ]; then
    echo "Error: $TARGET already exists"
    exit 1
fi

echo "Creating workspace: $TARGET"
# SKILL_ISSUES #152 — `submissions/_oos_rejected/` is the canonical
# evidence-trail home for drafts that were scoped out during review
# (e.g. duplicated in a prior audit, overlaps an OOS-N bullet). Having
# the dir at bootstrap prevents ad-hoc per-workspace names.
mkdir -p "$TARGET"/{notes,submissions,submissions/_oos_rejected,poc-tests}

# Seed submissions/_oos_rejected/README.md so the convention is discoverable.
cat > "$TARGET/submissions/_oos_rejected/README.md" <<'EOF'
# OOS-rejected drafts — evidence trail

Drafts that collapsed to OOS during scope review or prior-audit cross-check
belong here (not in `submissions/` proper, not deleted). One file per draft.

Each file MUST include:
- the original hypothesis + file:line citations
- which OOS-N bullet or PRIOR_CONCERNS entry it duplicated
- a one-line verdict ("CLOSED-OOS: overlaps OOS-3 (admin centralization)")

Listed under `📋 OOS-rejected drafts` in `SUBMISSIONS.md`.
EOF

# Copy templates, renaming to the audit's own files
cp "$AUDITOOOR_DIR/templates/findings.md"         "$TARGET/FINDINGS.md"
cp "$AUDITOOOR_DIR/templates/session_log.md"      "$TARGET/SESSION_LOG.md"
cp "$AUDITOOOR_DIR/checklists/bug_taxonomy.md"    "$TARGET/BUG_CHECKLIST.md"

# Create AUDIT.md skeleton
cat > "$TARGET/AUDIT.md" <<EOF
# $PROJECT_NAME — Audit Plan

**Bounty:** [<platform>/<slug>](<url>)
**Started:** $(date +%Y-%m-%d)
**Auditor:** $(git config user.name 2>/dev/null || whoami)

## Scope

TBD — summarize the in-scope asset list here after fetching \`SCOPE.md\`.
Keep machine-readable scope metadata in \`scope.json\`.

## Reward tiers

| Severity | Max reward |
|---|---|
| Critical | |
| High | |
| Medium | |
| Low | |

## Environment

| Tool | Version |
|---|---|
| Foundry | |
| solc | |
| Chain RPC | |
| Target repo HEAD | |
| Prior audit baseline | |

## Prior audits

List every prior audit of this project with a download link:

- [ ] Audit 1: <firm> (YYYY-MM), URL: <link>
- [ ] Audit 2: ...

Extract each to plain text in /tmp/audit_*.txt for originality grep.

## First iteration targets

- [ ] Scope recon: enumerate every contract address, clone every repo
- [ ] On-chain state enumeration: \`cast call\` every admin/owner/role holder
- [ ] Apply \`BUG_CHECKLIST.md\` first-pass
EOF

# Create empty SEVERITY.md skeleton with a reminder
cat > "$TARGET/SEVERITY.md" <<'EOF'
# Severity Rubric (authoritative — copy from bounty platform)

**TODO:** paste the bounty program's severity matrix, impact examples, and
exclusion lists here. Do not rely on memory.

Cross-reference with `auditooor/methodology/severity_rubric.md` for the
general framework but use THIS file (the bounty's own rubric) as authoritative
when rating findings.
EOF

# Create a placeholder SCOPE.md so downstream gates don't hard-stop on a
# freshly scaffolded workspace before the operator has fetched/pasted the full
# bounty program text. Keep it >30 lines so legacy flow-gate heuristics still
# recognize the scaffold as intentional bootstrap state.
{
    cat <<EOF
# SCOPE — $PROJECT_NAME

Placeholder scaffold created by \`tools/setup-workspace.sh\`.
Replace this file with the full bounty program text before relying on any
scope-sensitive tooling.

Preferred path:
- \`./tools/fetch-scope.sh $TARGET <bounty-program-url>\`

Manual fallback:
- paste the full program page here
- include the in-scope asset list
- include OUT-OF-SCOPE / known-issues language
- include severity caps / reward rules

## In scope
- TODO: paste the exact in-scope contracts / repos / addresses.

## Out of scope
- TODO: paste the exact OOS bullets / exclusions / by-design items.

## Known issues / acknowledgements
- TODO: paste any stated known issues, accepted risks, or prior-audit carryovers.

## Severity / reward notes
- TODO: paste severity caps, examples, and anything that changes triage posture.

## Placeholder rows (remove after real scope is pasted)
EOF
    for i in $(seq 1 20); do
        printf -- "- placeholder row %02d\n" "$i"
    done
} > "$TARGET/SCOPE.md"

# Create empty TODO.md
cat > "$TARGET/TODO.md" <<'EOF'
# Audit TODO — prioritized backlog

## P0 — unblocked, highest EV

- [ ] Scope recon + clone all repos
- [ ] Extract prior audit PDFs to /tmp/audit_*.txt
- [ ] On-chain state enumeration via cast calls
- [ ] Apply BUG_CHECKLIST.md first-pass

## P1

## P2

## Blocked

## Done
EOF

# Create empty STATUS.md from scratch (templates don't have a standalone one)
cat > "$TARGET/STATUS.md" <<EOF
# Audit Status — $PROJECT_NAME

**Last updated:** $(date +%Y-%m-%d) (iter 1)
**Confirmed findings (0 filed):** none yet
**Candidate findings:** 0
**Foundry PoCs passing:** 0 tests

---

## Asset coverage matrix

Legend: ✅ deep reviewed · 🟡 partial · ⬜ not yet · 📝 notes written

| # | Asset | Address | Status | Notes file | Findings |
|---|---|---|---|---|---|

## Cleared via deep review

*(append rows as attack surfaces are cleared)*

## PoC test inventory

| File | Tests | Fuzz | Status |
|---|---|---|---|

**Total:** 0 tests, 0 fuzz runs, 0 failures.
EOF

# Empty scope.json
echo "{}" > "$TARGET/scope.json"

# Auto-initialize HEXENS_COVERAGE.md if the Glider query submodule is present.
# Fixes SKILL_ISSUES.md #18 — operators were forgetting to run hexens-coverage-init.sh
# manually, leaving the coverage tracker uninitialized for entire audit runs.
if [ -d "$AUDITOOOR_DIR/external/glider-query-db/queries" ]; then
    if bash "$AUDITOOOR_DIR/tools/hexens-coverage-init.sh" "$TARGET" >/dev/null 2>&1; then
        echo "  [auto] HEXENS_COVERAGE.md initialized ($(ls "$AUDITOOOR_DIR/external/glider-query-db/queries"/*.py 2>/dev/null | wc -l | tr -d ' ') queries)"
    else
        echo "  [warn] hexens-coverage-init.sh failed; run manually if you need the checklist"
    fi
else
    echo "  [info] glider-query-db submodule not initialized; HEXENS_COVERAGE.md skipped"
    echo "         run 'git submodule update --init --recursive' from auditooor root, then"
    echo "         ./tools/hexens-coverage-init.sh $TARGET"
fi

# Create an ENGAGEMENT_INTENT.md stub the operator MUST fill in before iter 2.
# Fixes SKILL_ISSUES.md #144 — on R38 Centrifuge the "why this target / success
# criteria / non-goals" were stored only in chat transcripts. flow-gate.sh hard-
# stops on the <TODO-…> placeholders after iter 1 to force an explicit fill-in.
cat > "$TARGET/ENGAGEMENT_INTENT.md" <<EOF
# Engagement Intent — $PROJECT_NAME

**Started:** $(date +%Y-%m-%d)
**Operator:** $(git config user.name 2>/dev/null || whoami)

## Why this target
<TODO-WHY — 2-3 sentences: what about this protocol's shape / prior-audit
history / code velocity / reward tiers made it worth the operator-hours?>

## Success criteria
<TODO-SUCCESS — what does "done" look like? e.g. "at least 2 Medium+ submitted
with on-chain PoC", "every in-scope contract cleared against BUG_CHECKLIST",
"20 iters without a new finding".>

## Non-goals (what we are NOT trying to do here)
<TODO-NONGOALS — bullet list. e.g. "not writing formal-verification harnesses",
"not reviewing off-chain indexer", "not chasing admin-centralization-by-design".>

## Stop criteria (when to walk away)
<TODO-STOP — explicit abort triggers, e.g. "5 consecutive zero-finding iters",
"bounty pool depleted", "prior-audit coverage gap closes on re-read".>
EOF

# Create an empty EXTERNAL_INTEL.md stub so capture-intel.sh has somewhere to append.
# Fixes SKILL_ISSUES.md #19 — the file never existed on prior audits because
# capture-intel.sh was only invoked reactively, not as a workspace init step.
cat > "$TARGET/EXTERNAL_INTEL.md" <<'EOF'
# External Intel — user-provided context

This file accumulates articles, Discord chatter, Tweets, and any other
external context the user hands over during the audit. Read during orient
on every iteration. Append with `./tools/capture-intel.sh <workspace> "<title>"`
(reads stdin).

---

*(empty — will populate as the user provides intel)*
EOF

# Create an empty targets.tsv scaffold so fetch-targets.sh has something to read
cat > "$TARGET/targets.tsv" <<'EOF'
# Paste in-scope repo targets here. Tab-separated rows:
#   <repo_url>	<pinned_commit_or_main>	<local_name>
#
# Example:
# https://github.com/morpho-org/morpho-blue.git	55d2d99304fb3fb930c688462ae2ccabb1d533ad	morpho-blue
# https://github.com/morpho-org/morpho-blue-irm.git	a7d9cce3451b4a106bfd40933ac57a785b5228f3	morpho-blue-irm
#
# Then run:
#   ./tools/fetch-targets.sh <this-workspace>
# which clones, pins, inits submodules, forge-builds, and extracts in-repo
# audit PDFs to prior_audits/*.txt.
EOF

echo
echo "Done. Workspace at: $TARGET"
echo
echo "Next steps:"
echo "  1. Paste the bounty's severity rubric into $TARGET/SEVERITY.md"
echo "  2. Replace the placeholder $TARGET/SCOPE.md with the full bounty scope"
echo "     (or run: ./tools/fetch-scope.sh $TARGET <bounty-program-url>)"
echo "  3. Populate $TARGET/scope.json with machine-readable scope metadata if available"
echo "  4. Populate $TARGET/targets.tsv with repo_url / pinned_commit / local_name rows"
echo "  5. Run ./tools/fetch-targets.sh $TARGET"
echo "       -> clones all repos + pins commits + inits submodules + forge build"
echo "       -> extracts every in-repo audits/*.pdf to $TARGET/prior_audits/*.txt"
echo "  5. Spawn Sonnet agents to digest the prior audits"
echo "       template: $AUDITOOOR_DIR/templates/audit_digest_agent_brief.md"
echo "       one agent per 2-3 PDFs, run_in_background=true"
echo "       each agent writes to $TARGET/prior_audits/DIGEST_<slug>.md"
echo "  6. Run ./tools/pre-iter-check.sh $TARGET"
echo "       -> auto-synthesizes PRIOR_CONCERNS.md from the DIGEST_*.md files"
echo "       -> hard-fails if any required invariant is missing"
echo "  7. Start iter 1 per methodology/iteration_workflow.md"
