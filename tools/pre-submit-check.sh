#!/usr/bin/env bash
# pre-submit-check.sh — hard-gate before submitting a finding (Issue #78)
#
# Blocks submission until all checks pass:
#   1. Rubric citation present in the submission file
#   2. $ impact computed (explicit numeric range)
#   3. OOS clause cited (or "N/A: in-scope class" annotation)
#   4. PoC test exists (required for High+)
#   5. Originality posture recorded; High+/Critical explicit FAIL/DUPE blocks
#   6. Fork test exists (if High+) OR isolated-test-only rationale
#   7. Dupe-risk tool run (Issue #79), verdict LOW or explicit override paragraph
#  11. Scope-review sub-agent (U2, Phase 3.5) NOVEL or SAME-CLASS-DIFFERENT-VECTOR
#   8. Rejection classifier (Issue #88) — ML prediction over 19k prior outcomes
#  10. PoC forge test passes (R43 U3)
#  12. Extreme-value realistic bounds (POLY-45)
#  13. Event-only vs state-corruption (POLY-46)
#  14. Cross-chain atomicity awareness (Snowbridge)
#  15. Privileged-attacker realism (POLY-84)
#  16. Incomplete-fix / variant framing (MORPHO #I2.A)
#  17. Same-author same-class splitting (POLY #EV.F2)
#  18. Acknowledged-wont-fix guard (Morpho)
#  19. Theoretical without concrete trigger
#  21. Live proof attached for deployment/config-dependent claims
#  22. High+ fork-replay cited artifacts exist and parse (PR 102)
#  23. Scope-reasoner OOS gate (capv3 iter-003 T3, advisory by default)
#  24. Cross-contract staleness operator mismatch advisory
#  25. OOS prerequisite / root-cause stress gate
#  26. Mock-PoC contamination gate (suspicious-mock + missing precondition)
#  27. Production-path gate (V4 §2 A1 — High/Critical: hard FAIL when
#       `## Production Path` section is missing or items 7-9 are unsatisfied;
#       Medium: SUCCESS_WARN per V4 §9 conservative defaults; Low: pass)
#  4b. PoC section must not be a pointer-only file-path block.
#  4c. Final paste must include substantive inline PoC/test code, not only
#       commands, logs, or short excerpts.
#  28. Live claim-precondition consistency (only hard-fails declared contradictions)
#  29. Operator-pasted OOS per-finding check artifact (only when OOS_PASTED.md exists)
#  77. Program-specific OOS semantic gate (Graph L2GNS anchor): hard-fails a
#       High/Critical draft when (a) no real bounty OOS text was imported into
#       the workspace, or (b) the exploit path semantically matches a
#       frontrunning/sandwich/MEV or natural-network-activity OOS clause and no
#       alternate path is proven via an oos-*-rebuttal marker. Not satisfiable
#       by generic "OOS: in-scope" boilerplate. SCOPE_OOS_SEMANTIC_GATE knob.
#  30. OOS-DUPE-FILTER — block re-claims of encoded rejected/OOS classes from
#       <ws>/.auditooor/invariant_ledger.json (PR #511 Slice 4 follow-up).
#       Strictly additive: workspaces without an OOS-duplicate-filter row are
#       advisory only. Default WARN; STRICT_OOS_DUPE_FILTER=1 escalates to FAIL.
#       Per-draft override: `<!-- oos-dupe-rebuttal: <CLASS-ID> <reason> -->`.
#  31. PROGRAM-IMPACT-MAPPING — fail-closed gate for over-framing class
#       (PR #526 gap 0). For every Critical/High/Medium/`paste-ready` draft, require
#       a `## Program Impact Mapping` block whose `selected_impact:` is a
#       exact listed impact sentence from <ws>/SEVERITY*.md or RUBRIC_COVERAGE.md, and
#       whose `severity_implied:` matches the draft's severity claim. Forces
#       truth-in-mapping (FN7 lesson), NOT severity downgrade.
#       Missing/mismatched mapping is a hard failure for reportable/direct-submit work.
#  32. SEVERITY-CLAIM-GUARD — fail-closed gate against severity over-claim
#       (PR #556 §Priority 4 / Wave 6 Worker L). Scans the workspace
#       `critical_hunt/base_critical_candidate_matrix.json` and FAILS when
#       ANY reportable row lacks exact selected-impact proof. Component-only
#       PoCs (e.g. snappy decode-bomb on an isolated crate) cannot promote to
#       Critical/High/Medium/direct-submit without exact listed-impact evidence.
#       Default FAIL on any Critical violation; rc=2 from the helper is
#       advisory (matrix missing / not generated yet).
#  34. TITLE-SCHEMA (D-08) — first `# <title>` line must follow shape
#       `<Vulnerability Class> in <component> leads to <Impact>` (or allows /
#       causes / results in / enables / permits). Missing class word -> WARN
#       (taxonomy may need expansion); missing transition+impact -> FAIL.
#  35. FINANCIAL-IMPACT-GATE (D-09) — Critical/High SUBMITs that hedge with
#       soft-claim phrases ("structural implication", "would result in", "could
#       allow", "would lead to", "if read by", "implies") near the PoC must
#       ALSO carry an assertion (assertEq / vm.assertEq / assert_eq! /
#       expect_eq!) inside the PoC body. FN2 lesson: structural prose chain
#       "X poisoned, Y reads X" is insufficient without numeric fund-flow proof.
# 149. LIVE-PRECONDITION-GROUNDING - a finding whose impact TIER hinges on a live
#       on-chain precondition ("steal X now" / "currently paused") must carry a
#       live-verified verdict for it, grounded via a per-ws no-secrets public
#       endpoint (<ws>/.auditooor/onchain_access.json) + declarative
#       `<!-- live-precondition: {...} -->` directives. Contradicted-by-chain =
#       hard fail; unverifiable = advisory downgrade (hard under
#       AUDITOOOR_LIVE_PRECONDITION_STRICT). N/A when no config / no directive.
# 148. ABSOLUTE-USD-DERIVATION - a HIGH/CRITICAL fund-loss finding on a program that
#       declares a fund-loss USD floor (e.g. obyte "below USD 1000") must carry a
#       four-part, source-anchored USD derivation: (a) loss-denomination asset named +
#       cited to a file:line, (b) unit->USD scale + a priced source, (c) a market-size /
#       TVL figure, (d) a computed $ result compared to the floor. Also flags a cited
#       evidence artifact absent from the ws. predmkt lesson: "clears $1000 comfortably"
#       citing a nonexistent sweep was ~4 OOM below floor. WARN by default; hard-fail
#       under AUDITOOOR_ABSOLUTE_USD_STRICT. N/A off floor-declaring programs.
#  41. IMPACT-CONTRACT-PREFLIGHT (KLBQ-010) — proof-grade filing artifacts
#       must carry an explicit `## Impact Contract` or JSON impact_contract
#       object with at least one impacted actor/surface, one proof anchor, and
#       all six L27 directives.
#  48. L30-MISSING-GUARD-ENUMERATION — missing-protection/asymmetric-check
#       drafts must enumerate all call sites or include an L30 rebuttal.
#  49. L31-DUPE-PREFLIGHT — runs the platform Q1/Q2 duplicate test against
#       workspace priors and blocks duplicate or partial-overlap filings.
#  58. L32-IN-PROCESS-VS-NODE-LEVEL — High/Critical production-grade claims
#       need node/ABCI/state-machine execution evidence, not keeper-only proof.
#  59. R27-ADJACENT-FINDING-DISCLOSURE — High/Critical drafts must not leak
#       adjacent sibling variants without a filing-boundary disclosure.
#  60. R20-NO-FAULT-INJECTION — High/Critical claims must not depend on
#       synthetic error/panic/fault wrappers under the proof path.
#  61. R22-RESTART-SURVIVAL-REQUIRED — persistence/halt/permanent-impact
#       claims need restart-survival evidence or an honest severity walk-back.
#  42. FINAL-PASTE-FORM-GATE — reportable/paste-ready drafts must include
#       explicit platform selector fields and must not leak internal-only
#       operator caveats or local harness controls.
#  43. FINAL-PASTE-HYGIENE — reuse audit-closeout final/operator paste
#       hygiene against the current draft plus workspace paste artifacts.
#  62. R24-NON-SELF-IMPACT-REQUIRED — High/Critical fund-loss or freeze
#       claims must prove impact on victim/protocol funds not controlled by the
#       attacker, or explicitly walk severity below High.
#  63. R25-DEFENSE-IN-DEPTH-TRAVERSAL — High/Critical downstream-impact
#       claims must show the payload traverses defenses to the claimed impact.
#  64. R26-ANTE-HANDLER-TRAVERSAL — High/Critical Cosmos Msg claims must use
#       the real ante chain, not direct keeper/msg-server calls.
#  65. R23-COMPARATIVE-BASELINE — High/Critical comparative/regression claims
#       need same-workload comparator, measurement method, and threshold.
#  66. R21-PERMANENT-IMPACT-5-ASK-TEMPLATE — permanent-class High/Critical
#       claims must answer the five triager asks near the top of the draft.
#  67. R30-PRODUCTION-PROFILE-PREFLIGHT — High/Critical blockchain
#       DB/storage/IO/timing-sensitive claims must use production-profile PoCs
#       before filing: persistent backend, no DB timing/fault shims, no private
#       field reflection, multi-validator evidence for network-level claims,
#       hardware-envelope disclosure, and bug-class-shift disclosure.
#  68. L33-CHANGELOG-DRIFT-COVERAGE — Solidity stale-invariant / changelog
#       drift prose (`stale`, `outdated`, `no longer`, `ordering changed`,
#       `invariant change`, or CHANGELOG-like line refs) must be backed by
#       changelog-source-drift-miner output with at least one
#       `consumer-NOT-updated-EXPOSED` row, unless the draft includes
#       `<!-- l33-rebuttal: <reason> -->` with a reason up to 200 chars.
#  76. HIGH-PLUS-MCP/LIVE-HARDENING — runs the bounded
#       high-plus-submission-gate wrapper in non-recursive mode so MCP/toolsite
#       exposure, production-reachability, live-topology TARGET_PROTOCOL, and
#       selected-impact blockers use the same local gate semantics as pre-submit.
#  69. R34-CONTROL-TEST-DISCIPLINE - High/Critical drafts must include a
#       control test / alternative-cause exclusion or rebut; tool
#       `tools/control-test-discipline-check.py`.
#  70. PANIC-CONTEXT-AUDIT - panic/abort-impact drafts must carry the
#       surrounding execution-context evidence; tool
#       `tools/panic-context-audit.py`.
#  71. SEVERITY-CALIBRATION - advisory severity-vs-evidence calibration
#       cross-check against the workspace rubric.
#  72. HACKERMAN-RECORD-VERIFICATION-TIER — every record under
#       `audit/corpus_tags/tags/` (hackerman v1 schema) must carry a
#       `verification_tier:tier-N-*` tag in `function_shape.shape_tags`;
#       records under any `_QUARANTINE_*` subtree must be tier-5 and may NOT
#       be cited as a fileable anchor by the draft submission.
#  73. R38-BUG-CLASS-SHIFT — HIGH/CRITICAL drafts whose attack_class does
#       not match the rubric phrase the draft cites (per the Wave-1 bug-
#       class-shift detector's drift table) must either correct the
#       attack_class or rebut via `<!-- r38-rebuttal: <reason> -->` (<=200
#       chars). Also fails when the draft cites a record_id present in
#       `.auditooor/bug_class_shift.jsonl` without acknowledging drift.
#  74. R39-ATTACK-CLASS-ORPHAN — HIGH/CRITICAL drafts whose attack_class is
#       an orphan (single subtree OR <MIN_RECORDS corpus records) must be
#       normalised to a canonical class or rebutted via
#       `<!-- r39-rebuttal: <reason> -->` (<=200 chars). Thresholds tunable
#       via AUDITOOOR_R39_MIN_RECORDS / AUDITOOOR_R39_MIN_SUBTREES.
#  75. R75-WAVE2-W21-POST-MIGRATION — drafts or commits that touch
#       `audit/corpus_tags/tags/` or `audit/corpus_tags/index/` must pass
#       `tools/wave2-w21-post-migration-validator.py --strict`: every record
#       at schema v1.1, verification_tier populated and in taxonomy, all 5
#       additive indexes parse cleanly, and 0 quarantine-CVE leak into
#       `by_cve_id.jsonl`. Scope predicate fires when (a) the draft
#       references corpus paths or hackerman-record schema, OR (b) the
#       `AUDITOOOR_R75_SCOPE=corpus` env override is set, OR (c) the recent
#       commit diff touches `audit/corpus_tags/`. Out-of-scope drafts skip
#       with verdict `pass-out-of-scope`. Override via
#       `<!-- r75-rebuttal: <reason> -->` (<=200 chars).
#  78. HACKER-QUESTION-ANSWERS — High/Critical drafts must not match any
#       still-open `.auditooor/hacker_question_obligations.jsonl` entries.
#       Answer, kill, or promote matching obligations before filing.
#  81. SOURCE-READ-RECEIPTS — default-hard High/Critical scaffolding:
#       unless `AUDITOOOR_STRICT_SOURCE_READ_RECEIPTS=0` is set, every cited
#       production source file in a High/Critical draft must have either a
#       pre-source-read receipt or a hacker-question obligation row.
#  79. OUTCOME-LESSON-GATE — High/Critical drafts are checked against
#       codified triager/outcome lessons (MEV/OOS/admin/economic viability,
#       documented-mechanics, low-severity caps). Hard predicates block
#       filing until the draft proves the required distinction.
#  80. PREFILING-STRESS-ARTIFACT — High/Critical drafts must carry a prior
#       passed `make prefiling-stress-test WS=<ws> DRAFT=<draft>` artifact.
#       This enforces the V3 judgment-before-PoC step without silently
#       generating it during final pre-submit.
#  82. CANDIDATE-JUDGMENT-PACKET — High/Critical drafts must have a matching
#       candidate judgment packet whose local scope/dupe/economics/severity
#       judgment is ready for PoC planning. Packets with
#       `summary.strict_poc_planning_allowed != true` or local blocking packet
#       states fail closed before final paste.
#  83. OPPOSED-TRACE-REQUIRED (HACKERMAN_V3, tiered) — a Direct Loss /
#       Permanent Freeze / Theft / Insolvency / Unauthorized Withdrawal /
#       temporary-freeze claim must include every protocol-owned defense
#       (watchtower, refund, liquidation, slash, pause, challenge, finalize) in
#       the PoC or submission body, and must show the attacker wins despite each
#       defense. Proving only the attacker path (attacker vs empty world) is a
#       proof fallacy at ANY severity. The opposed-trace QUESTION is asked at
#       every tier; ENFORCEMENT scales: HIGH+ -> HARD FAIL (blocks submission);
#       Medium/Low -> MANDATORY ADVISORY (warn the reviewer must clear, not a
#       hard block). Override: `<!-- opposed-trace-rebuttal: <reason up to 200
#       chars> -->` for bounded source-backed exceptions. Empirical anchor:
#       Spark LEAD1 proved the chain-watcher accepted an unrelated exit_txid but
#       did not simulate the lower-timelock connector refund, post-claim refund,
#       or watchtower paths.
#  84. R40-V3-GRADE-POC-REQUIRED - for any Medium+ loss-of-funds /
#       state-corruption / finalization / DoS claim, mocks may only replace
#       EXTERNAL dependencies; the vulnerable protocol-owned path must be real.
#       A PoC is V3-grade only if it proves all six points: (1) real entrypoint
#       -> real vulnerable code -> real impact surface; (2) every protocol-owned
#       defense/rescue/refund/race/finalizer is executed or ruled out with
#       source evidence; (3) mocked components are external dependencies only,
#       each mock assumption stated; (4) a negative control exists (patched
#       code, canonical upstream behavior, or a clean no-impact path); (5) exact
#       victim/asset/attacker balances or state transitions are asserted before
#       and after; (6) every named attack variant has an executed PoC OR the
#       report narrows the claim. Honest narrowing PASSES. Hard-fails Medium+
#       drafts with a non-pass / non-rebuttal verdict. Override: visible line
#       `r40-rebuttal: <reason>` (<=200 chars) or `<!-- r40-rebuttal: <reason>
#       -->`. Empirical anchors: Hyperbridge UniV3 gateway-simulator-vs-real
#       placeOrder case; Optimism source-vs-end-to-end finalization case.
#  85. R41-SUBMISSION-FOLDER-STRUCTURE - every bounty submission's artifacts
#       must live together in a single per-finding folder named by the finding
#       slug, under a status directory:
#       submissions/<status>/<finding-slug>/<finding-slug>.<ext>. Status dirs:
#       staging, ready, filed, packaged, _killed, _oos_rejected. No submission
#       artifact may lie flat directly inside a status directory. When a draft
#       is being checked, this gate fails-closed if the draft is not at
#       submissions/<status>/<slug>/<slug>.md. Standalone --check mode is a hard
#       exit-non-zero gate; --fix reorganizes flat artifacts into per-finding
#       folders. Empirical anchor: Hyperbridge workspace conversion 2026-05-22
#       (3 filed + 3 killed findings regrouped into per-finding folders).
#  86. REACHABILITY-VERIFICATION - Medium+ drafts must document production
#       reachability from a real entrypoint, including dispatch/registration
#       site or source-backed rebuttal.
#  87. PRIOR-AUDIT-DUPE-GATE - staging/paste-ready drafts are checked against
#       workspace prior audits and local extracts; likely-dupe/adjacent rows
#       without originality posture fail before filing.
#  88. CONFIG-DOWNSTREAM-TRACE - Medium+ rollup / bridge / oracle / consensus
#       config-sensitive claims must prove audited deployment/config
#       preconditions and trace the claimed impact into the real downstream
#       consumer. Same-component paths need a source-backed not_applicable
#       marker; bounded exceptions use
#       `<!-- config-downstream-rebuttal: <source-backed reason up to 200 chars> -->`.
#  89. R42-CONFIGURED-IMPACT-TRACE - any Medium+ claim whose impact depends on
#       a deployed/configured component (registered chain/client/router/oracle/
#       adapter, feature flag, role set, asset pool, bridge reserve, runtime
#       pallet, downstream consumer) must carry a "Configured-Impact Trace":
#       (1) a configuration-precondition citation, (2) a downstream-consumer
#       path with file:line/PoC citations per hop, (3) evidence-class match -
#       an upstream-only PoC must word the impact as accepted forged/unfinalized
#       state unless the downstream fund/message path is executed or fully
#       source-traced. Honest narrowing PASSES. Override: visible
#       `r42-rebuttal: <source-backed reason>` line (<=200 chars) or
#       `<!-- r42-rebuttal: <source-backed reason> -->`.
#  90. R35-DOS-CLASS-REFRAME - High/Critical drafts whose demonstrated impact
#       is generic DoS / rate-limit pressure / liveness degradation must either
#       cite a program severity row where DoS is explicitly in scope, prove a
#       separate non-DoS production impact, or walk severity below High.
#       Override: visible `r35-rebuttal: <reason>` line (<=200 chars) or
#       `<!-- r35-rebuttal: <reason> -->`.
# 106. R59-ANTIPATTERN-ATTRIBUTION - High/Critical drafts whose cluster/category
#      maps to P3 anti-pattern catalog rows must cite recognized P3 pattern_id(s)
#      or carry an explicit r59 rebuttal/no-binding reason.
#
# Usage:
#   ./tools/pre-submit-check.sh <submission-file.md> [--severity High|Medium|Low] [--fix]
#
# Exit codes:
#   0 — all checks pass, safe to submit
#   1 — one or more checks failed, review required
#
# With --fix: auto-runs tools/auto-fix-draft.py before checking (fixes
#   originality refs, cross-chain atomicity, dollar impact, rubric citations).

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# MASTER strict switch: flip all advisory AUDITOOOR_*_STRICT gates to strict by
# default (operator 2026-07-04: "flip all advisory to strict, everywhere").
# AUDITOOOR_STRICT_ALL=0 restores advisory-first; a per-gate ENV=0 is respected.
# shellcheck source=lib/strict-all-envs.sh
[ -f "$AUDITOOOR_DIR/tools/lib/strict-all-envs.sh" ] && . "$AUDITOOOR_DIR/tools/lib/strict-all-envs.sh"
# WS_DIR is resolved later (after _WS walk-up at ~line 980), but must be
# declared now so set -u does not abort if any early code path references it
# before the walk-up runs.  Checks #94-#99 use WS_DIR; they are placed after
# the walk-up so the real value is in scope by the time they execute.
WS_DIR=""

if [ $# -lt 1 ]; then
    sed -n '2,20p' "$0" | sed 's/^# //; s/^#//'
    exit 1
fi

SUB="$1"
SEVERITY=""
DO_FIX=0
SKIP_LIVE_VERIFY=0
case "${AUDITOOOR_STRICT_SOURCE_READ_RECEIPTS:-1}" in
    0) STRICT_SOURCE_READ_RECEIPTS=0 ;;
    *) STRICT_SOURCE_READ_RECEIPTS=1 ;;
esac
shift 2>/dev/null || true

while [ $# -gt 0 ]; do
    case "$1" in
        --severity) SEVERITY="$2"; shift 2 ;;
        --fix) DO_FIX=1; shift ;;
        --skip-live-verify) SKIP_LIVE_VERIFY=1; shift ;;
        --strict-source-read-receipts) STRICT_SOURCE_READ_RECEIPTS=1; shift ;;
        *) shift ;;
    esac
done

# --- Auto-fix pass (if --fix requested) ---
if [ "$DO_FIX" -eq 1 ] && [ -f "$AUDITOOOR_DIR/tools/auto-fix-draft.py" ]; then
    echo "  🔧 Running auto-fix on $SUB ..."
    python3 "$AUDITOOOR_DIR/tools/auto-fix-draft.py" "$SUB" --in-place 2>/dev/null || true
    echo "  🔧 Auto-fix complete. Re-checking ..."
    echo ""
    # Re-read text after fix
    text=$(cat "$SUB")
fi

if [ ! -f "$SUB" ]; then
    echo "[error] submission file not found: $SUB" >&2
    exit 1
fi

text=$(cat "$SUB")
fails=0
warns=0

# ===========================================================================
# GHSA-AWARE MODE detection (TASK-B). Mirrors how Check #128 is gated to
# *.hackenproof-plain.txt: a GHSA-format draft (GitHub Security Advisory
# "Report a vulnerability" form) trips a different set of structural gates than
# the Cantina/HackenProof markdown drafts. When detected, GHSA_MODE=1:
#   - SKIP the Cantina-only gates (#11 scope-review, #31 program-impact-mapping,
#     #41 impact-contract, #42 final-paste-form selectors)
#   - require the GHSA equivalents instead (ghsa-requirements-check.py +
#     ghsa-poc-inline-check.py against the .advisory.md paste artifact)
#   - route #43 hygiene at the .advisory.md (the real paste artifact), not the
#     source .md with its leading rebuttal HTML-comments
#   - neutralize the #68 changelog-drift FALSE-trigger for non-Solidity drafts
#   - skip #88 config-trace when the draft declares (rebuttal) it is not a
#     configured-component finding
#   - decouple #72 global corpus tier-debt to a WARN (not a per-draft FAIL)
# Detection + paste-artifact resolution live in tools/ghsa-mode-detect.py.
# ===========================================================================
GHSA_MODE=0
GHSA_PASTE_ARTIFACT="$SUB"
GHSA_DETECTED_VIA=""
_GHSA_DETECT_TOOL="$AUDITOOOR_DIR/tools/ghsa-mode-detect.py"
if [ -f "$_GHSA_DETECT_TOOL" ]; then
    GHSA_MODE=$(python3 "$_GHSA_DETECT_TOOL" "$SUB" --field is_ghsa 2>/dev/null || echo 0)
    if [ "$GHSA_MODE" = "1" ]; then
        GHSA_PASTE_ARTIFACT=$(python3 "$_GHSA_DETECT_TOOL" "$SUB" --field paste_artifact 2>/dev/null || echo "$SUB")
        GHSA_DETECTED_VIA=$(python3 "$_GHSA_DETECT_TOOL" "$SUB" --field detected_via 2>/dev/null || echo "")
        [ -z "$GHSA_PASTE_ARTIFACT" ] && GHSA_PASTE_ARTIFACT="$SUB"
        echo ""
        echo "  🧭 GHSA-AWARE MODE engaged (detected_via: ${GHSA_DETECTED_VIA:-unknown})"
        echo "     Cantina-only gates #11/#31/#41/#42 skipped; GHSA equivalents enforced."
        echo "     Paste artifact for hygiene/PoC: $GHSA_PASTE_ARTIFACT"
    fi
fi
# Default the value when the tool is absent so `set -u` never aborts later.
case "$GHSA_MODE" in 1) : ;; *) GHSA_MODE=0 ;; esac

_check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "  ✅ $label"
    else
        echo "  ❌ $label"
        fails=$((fails + 1))
    fi
}

_warn() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "  ✅ $label"
    else
        echo "  ⚠️  $label"
        warns=$((warns + 1))
    fi
}

_live_proof_depends() {
    python3 - "$SUB" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
patterns = [
    r'0x[a-fA-F0-9]{40}',
    r'\bon[- ]chain\b',
    r'\bpolygon mainnet\b',
    r'\bmainnet\b',
    r'\b(?:currently|live|mainnet)\s+deployed\b',
    r'\bdeployed\s+at\s+0x[a-fA-F0-9]{40}',
    r'\blive[- ]state\b',
    r'\bdeployment topology\b',
    r'\bowner\(\)',
    r'\bpaused\(\)',
    r'\brolesOf\(',
    r'\bhasAnyRole\(',
    r'\bFEE_DENOMINATOR\(\)',
    r'\bDELAY_PERIOD\(\)',
    r'\bgetMaxFeeRate\(\)',
    r'\boracle\(\)',
]
hits = sum(1 for pat in patterns if re.search(pat, text, re.IGNORECASE))
print("1" if hits >= 2 else "0")
PY
}

_live_proof_override() {
    grep -iqE 'live[- ]?(proof|state) evidence:\s*n/?a|source-only rationale|no live proof required|live proof not required|proof relevance override|live proof relevance override' "$SUB"
}

_ambiguous_source_override() {
    # P1-3 burn-down (item #13): an explicit operator opt-out that
    # acknowledges the synthesizer flagged ambiguous getter candidates
    # and that the operator has manually picked one. Without this
    # marker, Check #21 fails closed when any matched live-proof row
    # carries `synthesis_status: ambiguous-source`.
    grep -iqE 'ambiguous[- ]?source[- ]?(override|ack|acknowledged)|ambiguous getter (override|ack|acknowledged)|disambiguated by operator' "$SUB"
}

_live_proof_refs() {
    python3 - "$SUB" "$1" <<'PY'
import json
import re
import sys
from pathlib import Path

draft_path = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])

try:
    payload = json.loads(artifact_path.read_text())
except Exception:
    print("")
    sys.exit(0)

results = payload.get("results", [])
known_ids = {
    str(item.get("id") or "").strip()
    for item in results
    if isinstance(item, dict) and str(item.get("id") or "").strip()
}
text = draft_path.read_text(errors="replace")
lines = text.splitlines()
ids = []
in_section = False
for line in lines:
    stripped = line.strip()
    if re.match(r"^##+\s+Live Proof\b", stripped, flags=re.IGNORECASE):
        in_section = True
        continue
    if in_section and re.match(r"^##+\s+", stripped):
        break
    if not in_section and not re.search(r"live[- ]?proof", stripped, flags=re.IGNORECASE):
        continue
    for candidate in re.findall(r"\b[A-Za-z0-9][A-Za-z0-9._-]{4,}\b", stripped):
        if candidate in known_ids and candidate not in ids:
            ids.append(candidate)
print(",".join(ids))
PY
}

_live_proof_angles() {
    python3 - "$SUB" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
lines = text.splitlines()
angle_ids = []
in_section = False
for line in lines:
    stripped = line.strip()
    if re.match(r"^##+\s+Live Proof\b", stripped, flags=re.IGNORECASE):
        in_section = True
        continue
    if in_section and re.match(r"^##+\s+", stripped):
        break
    if not in_section:
        continue
    for angle_id in re.findall(r"\bA-[A-Z0-9-]+\b", stripped):
        if angle_id not in angle_ids:
            angle_ids.append(angle_id)
print(",".join(angle_ids))
PY
}

echo "==========================================================================="
echo "  pre-submit-check — $(basename "$SUB")"
echo "==========================================================================="
echo ""

# Infer severity from file if not given
if [ -z "$SEVERITY" ]; then
    SEVERITY=$(echo "$text" | grep -iE '^\*\*Severity[^:]*:|^Severity[^:]*:|^- \*\*Severity|severity_tier:|selected_severity:' | head -1 | \
        grep -oiE 'critical|high|medium|low|info' | head -1 | tr '[:lower:]' '[:upper:]' || echo "")
fi
SEVERITY_UPPER=$(printf '%s' "${SEVERITY:-}" | tr '[:lower:]' '[:upper:]')
case "$SEVERITY_UPPER" in
    CRITICAL) SEVERITY_ARG="Critical" ;;
    HIGH) SEVERITY_ARG="High" ;;
    MEDIUM) SEVERITY_ARG="Medium" ;;
    LOW) SEVERITY_ARG="Low" ;;
    INFO|INFORMATIONAL) SEVERITY_ARG="Info" ;;
    *) SEVERITY_ARG="${SEVERITY:-}" ;;
esac
SEVERITY_ARG_LOWER=$(printf '%s' "${SEVERITY_ARG:-}" | tr '[:upper:]' '[:lower:]')
echo "  Detected severity: ${SEVERITY:-unknown}"
echo ""

# --- Check 42: FINAL-PASTE-FORM-GATE --------------------------------------
# Platform submissions need the explicit form selectors, not only narrative
# prose. Keep this intentionally line-oriented: plain `Impact: $100K...`
# remains evidence/prose, while `Impact(s): ...` / `Choose Impact(s): ...`
# is the selector field triagers need in the final paste.
_FINAL_PASTE_FORM_GATE=$(python3 - "$SUB" "$SEVERITY" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
cli_severity = (sys.argv[2] or "").strip().lower()
text = path.read_text(errors="replace")

def strip_fenced_code(body: str) -> str:
    out = []
    in_fence = False
    for line in body.splitlines():
        if re.match(r"^\s*```", line):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)

visible = strip_fenced_code(text)
lower = visible.lower()
severity_match = re.search(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?severity(?:\s+rating)?(?:\*\*)?\s*[:\-]\s*(?:\*\*)?(critical|high|medium|low|info)\b",
    visible,
)
file_severity = (severity_match.group(1).lower() if severity_match else "")
paste_ready = any(
    token in lower
    for token in (
        "paste-ready",
        "paste ready",
        "ready to paste",
        "ready-to-paste",
        "final paste",
        "final-paste",
        "ready to file",
        "status: ready",
        "status:ready",
        "status: paste",
    )
)
reportable = cli_severity in {"critical", "high", "medium"} or file_severity in {"critical", "high", "medium"}
applies = reportable or paste_ready

leak_patterns = [
    ("paste-ready-triagers-caveat", r"\bpaste ready means it(?:'|’)s only for triagers\b"),
    ("dupe-risk-reviewer-warning", r"\bdupe-risk reviewer warning\b"),
    ("skip-live-verify", r"\bskip-live-verify\b"),
    ("not-submit-ready", r"\bNOT_SUBMIT_READY\b"),
    ("harness-internal-caveat", r"\bharness[- ]internal caveats?\b|\binternal[- ]only harness caveats?\b"),
]
leaks = [
    code
    for code, pattern in leak_patterns
    if re.search(pattern, visible, flags=re.IGNORECASE)
]

def clean_line(line: str) -> str:
    return re.sub(r"[`*_]", "", line).strip()

lines = visible.splitlines()

def field_has_value(label_rx: str, value_rx: str | None = None) -> bool:
    label = re.compile(
        r"^\s*(?:[-*]\s*)?(?:" + label_rx + r")\s*(?:[:\-]|$)",
        re.IGNORECASE,
    )
    another_field = re.compile(
        r"^\s*(?:[-*]\s*)?(?:choose\s+)?(?:severity|likelihood|impact\(s\)|selected\s+impact\(s\)|impact\s+selector)\s*(?:[:\-]|$)",
        re.IGNORECASE,
    )
    for idx, raw in enumerate(lines):
        line = clean_line(raw)
        if not label.match(line):
            continue
        values = []
        if ":" in line:
            values.append(line.split(":", 1)[1].strip())
        elif "-" in line:
            values.append(line.split("-", 1)[1].strip())
        for nxt in lines[idx + 1 : idx + 4]:
            nxt_clean = clean_line(nxt)
            if not nxt_clean:
                continue
            if nxt_clean.startswith("#") or another_field.match(nxt_clean):
                break
            values.append(nxt_clean.lstrip("-* ").strip())
            break
        for value in values:
            if not value or value.lower() in {"[]", "n/a", "na", "tbd", "todo", "(none)", "none"}:
                continue
            if value_rx is None or re.search(value_rx, value, flags=re.IGNORECASE):
                return True
    return False

missing = []
if applies:
    if not field_has_value(r"(?:choose\s+)?severity|selected\s+severity|severity\s+selector", r"\b(critical|high|medium|low|informational|info)\b"):
        missing.append("Severity selector")
    if not field_has_value(r"(?:choose\s+)?likelihood|selected\s+likelihood|likelihood\s+selector", r"\b(high|medium|low)\b"):
        missing.append("Likelihood selector")
    if not field_has_value(r"(?:choose\s+)?impact\(s\)|selected\s+impact\(s\)|impact\s+selector"):
        missing.append("Impact(s) selector")

if not applies and not leaks:
    print("ok\tnot reportable/paste-ready")
elif not missing and not leaks:
    print("ok\tplatform selectors present; no internal-only leakage")
else:
    for item in missing:
        print(f"missing\t{item}")
    for item in leaks:
        print(f"leak\t{item}")
PY
)
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  42. FINAL-PASTE-FORM-GATE: SKIPPED under GHSA-AWARE MODE"
    echo "       (GHSA has no Severity/Likelihood/Impact SELECTOR fields; it uses a"
    echo "        CVSS:3.1 vector + CWE - enforced by the GHSA requirement gate.)"
elif echo "$_FINAL_PASTE_FORM_GATE" | grep -q '^ok'; then
    echo "  ✅ 42. FINAL-PASTE-FORM-GATE: $(echo "$_FINAL_PASTE_FORM_GATE" | sed 's/^ok[[:space:]]*//')"
else
    echo "  ❌ 42. FINAL-PASTE-FORM-GATE blocked:"
    echo "$_FINAL_PASTE_FORM_GATE" | sed 's/^/       /'
    echo "       Add explicit Severity/Likelihood/Impact(s) platform selector fields and remove internal-only caveats."
    fails=$((fails + 1))
fi
echo ""

# --- Check 43: final/operator paste hygiene reuses closeout logic ----------
# Keep output-layer hygiene centralized in audit-closeout-check.py. Pre-submit
# imports the closeout helpers and applies them to both the current draft and
# any existing final/operator paste artifacts in the resolved workspace.
#
# GHSA-AWARE MODE: hygiene targets the .advisory.md paste artifact (the real
# maintainer-facing paste with rebuttal HTML-comments + internal gate sections
# already stripped by ghsa-advisory-export.py), NOT the source .md whose leading
# rebuttal comments are expected. If no .advisory.md exists yet, generate one to
# a temp path so #43 runs against the clean paste shape.
_HYGIENE_TARGET="$SUB"
_GHSA_TMP_ADVISORY=""
if [ "$GHSA_MODE" = "1" ]; then
    if [ -f "$GHSA_PASTE_ARTIFACT" ] && [ "$GHSA_PASTE_ARTIFACT" != "$SUB" ]; then
        _HYGIENE_TARGET="$GHSA_PASTE_ARTIFACT"
    else
        # No .advisory.md sibling: render one to temp via the exporter so the
        # hygiene gate evaluates the clean paste, not the source draft.
        _GHSA_EXPORT_TOOL="$AUDITOOOR_DIR/tools/ghsa-advisory-export.py"
        if [ -f "$_GHSA_EXPORT_TOOL" ]; then
            _GHSA_TMP_BASE=$(mktemp 2>/dev/null || echo "/tmp/ghsa_advisory_$$")
            _GHSA_TMP_TXT="${_GHSA_TMP_BASE}.advisory.txt"
            _GHSA_TMP_ADVISORY="${_GHSA_TMP_BASE}.advisory.md"
            python3 "$_GHSA_EXPORT_TOOL" --draft "$SUB" --out "$_GHSA_TMP_TXT" >/dev/null 2>&1 || true
            if [ -f "$_GHSA_TMP_ADVISORY" ]; then
                _HYGIENE_TARGET="$_GHSA_TMP_ADVISORY"
            fi
        fi
    fi
    echo "  🧭 43/GHSA. Hygiene target -> $_HYGIENE_TARGET"
fi
_FINAL_PASTE_HYGIENE_GATE=$(python3 - "$AUDITOOOR_DIR" "$_HYGIENE_TARGET" <<'PY'
import importlib.util
import sys
from pathlib import Path

repo = Path(sys.argv[1])
sub = Path(sys.argv[2]).expanduser().resolve()
tool = repo / "tools" / "audit-closeout-check.py"

spec = importlib.util.spec_from_file_location(
    "_audit_closeout_final_paste_hygiene", tool
)
if spec is None or spec.loader is None:
    print(f"error\tcannot load {tool}")
    raise SystemExit(0)
mod = importlib.util.module_from_spec(spec)
sys.modules["_audit_closeout_final_paste_hygiene"] = mod
try:
    spec.loader.exec_module(mod)
except Exception as exc:
    print(f"error\tcannot import closeout hygiene: {exc}")
    raise SystemExit(0)

def resolve_workspace(path):
    cur = path.parent
    while cur != cur.parent:
        if (
            (cur / "OOS_CHECKLIST.md").exists()
            or (cur / "SCOPE.md").exists()
            or (cur / "AUDIT.md").exists()
        ):
            return cur
        cur = cur.parent
    return None

def key(row):
    raw = Path(str(row.get("file") or ""))
    try:
        raw = raw.resolve()
    except OSError:
        pass
    return (
        str(raw),
        str(row.get("line") or ""),
        str(row.get("kind") or ""),
        str(row.get("excerpt") or ""),
    )

violations = []
seen = set()
ws = resolve_workspace(sub)
if ws is not None:
    result = mod.check_final_paste_hygiene(ws)
    for row in result.detail.get("violations", []):
        marker = key(row)
        if marker not in seen:
            seen.add(marker)
            violations.append(row)

for row in mod._final_paste_hygiene_violations(sub):
    marker = key(row)
    if marker not in seen:
        seen.add(marker)
        violations.append(row)

if violations:
    print("fail")
    for row in violations[:20]:
        file = row.get("file") or sub
        try:
            rel = Path(file).resolve().relative_to(ws) if ws is not None else Path(file).resolve()
        except Exception:
            rel = file
        print(
            f"{row.get('kind', 'unknown')}\t{rel}:{row.get('line', '?')}\t"
            f"{row.get('excerpt', '')}"
        )
    if len(violations) > 20:
        print(f"more\t{len(violations) - 20} additional hygiene issue(s)")
elif ws is None:
    print("ok\tcurrent draft passed; workspace artifact sweep skipped (workspace root not resolved)")
else:
    print("ok\tcurrent draft and workspace final/operator paste artifacts passed")
PY
)
if echo "$_FINAL_PASTE_HYGIENE_GATE" | grep -q '^ok'; then
    echo "  ✅ 43. FINAL-PASTE-HYGIENE: $(echo "$_FINAL_PASTE_HYGIENE_GATE" | sed 's/^ok[[:space:]]*//')"
elif echo "$_FINAL_PASTE_HYGIENE_GATE" | grep -q '^error'; then
    echo "  ❌ 43. FINAL-PASTE-HYGIENE could not run:"
    echo "$_FINAL_PASTE_HYGIENE_GATE" | sed 's/^/       /'
    fails=$((fails + 1))
else
    echo "  ❌ 43. FINAL-PASTE-HYGIENE blocked:"
    echo "$_FINAL_PASTE_HYGIENE_GATE" | sed '1d; s/^/       /'
    echo "       Remove HTML comments, local absolute paths, manual-fill placeholders, and path-only PoC sections before final paste."
    fails=$((fails + 1))
fi
# Clean up any temp .advisory.md rendered for GHSA hygiene routing.
if [ -n "$_GHSA_TMP_ADVISORY" ]; then
    rm -f "$_GHSA_TMP_ADVISORY" "${_GHSA_TMP_TXT:-}" "${_GHSA_TMP_BASE:-}" 2>/dev/null || true
fi
echo ""

# === Check 42b/43b: GHSA-AWARE requirement enforcement =====================
# Under GHSA_MODE the Cantina selectors (#42) and the Cantina impact-contract
# (#41) / program-impact rubric (#31) are skipped; the GHSA contract is enforced
# here instead: 4 advisory sections + Affected + CVSS:3.1 + >=1 CWE + the
# Originality/Supersede sections (R47/R53) on the SOURCE draft, and an inline-PoC
# clean-paste check on the .advisory.md paste artifact.
if [ "$GHSA_MODE" = "1" ]; then
    _GHSA_REQ_TOOL="$AUDITOOOR_DIR/tools/ghsa-requirements-check.py"
    _GHSA_POC_TOOL="$AUDITOOOR_DIR/tools/ghsa-poc-inline-check.py"
    _GHSA_EXPORT_TOOL="$AUDITOOOR_DIR/tools/ghsa-advisory-export.py"

    # (a) requirement gate on the source draft (Originality/Supersede live here)
    if [ -f "$_GHSA_REQ_TOOL" ]; then
        _GHSA_REQ_OUT=$(python3 "$_GHSA_REQ_TOOL" "$SUB" 2>&1)
        _GHSA_REQ_RC=$?
        case "$_GHSA_REQ_RC" in
            0) echo "  ✅ 42b. GHSA-REQUIREMENTS: $_GHSA_REQ_OUT" ;;
            1) echo "  ❌ 42b. GHSA-REQUIREMENTS blocked:"
               echo "$_GHSA_REQ_OUT" | sed 's/^/       /'
               fails=$((fails + 1)) ;;
            *) echo "  ⚠️  42b. GHSA-REQUIREMENTS error rc=$_GHSA_REQ_RC: $_GHSA_REQ_OUT"
               warns=$((warns + 1)) ;;
        esac
    else
        echo "  ⚠️  42b. GHSA-REQUIREMENTS: tool not found ($_GHSA_REQ_TOOL); skipping"
        warns=$((warns + 1))
    fi

    # (b) inline-PoC clean-paste gate on the .advisory.md paste artifact
    _GHSA_POC_TARGET="$GHSA_PASTE_ARTIFACT"
    _GHSA_POC_TMP=""
    if [ "$_GHSA_POC_TARGET" = "$SUB" ] && [ -f "$_GHSA_EXPORT_TOOL" ]; then
        # source draft is not itself an .advisory.md: render one to temp
        _GHSA_POC_BASE=$(mktemp 2>/dev/null || echo "/tmp/ghsa_poc_$$")
        _GHSA_POC_TMP="${_GHSA_POC_BASE}.advisory.md"
        python3 "$_GHSA_EXPORT_TOOL" --draft "$SUB" --out "${_GHSA_POC_BASE}.advisory.txt" >/dev/null 2>&1 || true
        if [ -f "$_GHSA_POC_TMP" ]; then
            _GHSA_POC_TARGET="$_GHSA_POC_TMP"
        fi
    fi
    if [ -f "$_GHSA_POC_TOOL" ] && [ -f "$_GHSA_POC_TARGET" ]; then
        _GHSA_POC_OUT=$(python3 "$_GHSA_POC_TOOL" "$_GHSA_POC_TARGET" 2>&1)
        _GHSA_POC_RC=$?
        case "$_GHSA_POC_RC" in
            0) echo "  ✅ 43b. GHSA-POC-INLINE ($_GHSA_POC_TARGET): $_GHSA_POC_OUT" ;;
            1) echo "  ❌ 43b. GHSA-POC-INLINE blocked ($_GHSA_POC_TARGET):"
               echo "$_GHSA_POC_OUT" | sed 's/^/       /'
               fails=$((fails + 1)) ;;
            *) echo "  ⚠️  43b. GHSA-POC-INLINE error rc=$_GHSA_POC_RC: $_GHSA_POC_OUT"
               warns=$((warns + 1)) ;;
        esac
    else
        echo "  ⚠️  43b. GHSA-POC-INLINE: tool or paste artifact missing; skipping"
        warns=$((warns + 1))
    fi
    [ -n "$_GHSA_POC_TMP" ] && rm -f "$_GHSA_POC_TMP" "${_GHSA_POC_BASE:-}".advisory.txt "${_GHSA_POC_BASE:-}" 2>/dev/null || true
    echo ""
fi

# --- Check 1: Rubric citation ---
_check "1. Rubric citation present (cites specific impact example)" \
    grep -iE '(rubric|impact example|severity justification|maps to|this matches the rubric)' "$SUB"

# --- Check 2: $ impact computed ---
_check "2. Dollar impact computed (explicit numeric \$ figure or TVL reference)" \
    grep -E '\$[0-9]+[KkMmBb]?|USDC|TVL|[0-9]+[KkMmBb] (at risk|of funds|loss)' "$SUB"

# --- Check 3: OOS clause cited or N/A ---
_check "3. OOS/exclusion clause addressed (cites clause OR 'in-scope' annotation)" \
    grep -iE '(out of scope|in-scope|exclusion|scope gotcha|does not fall under|oos|centralization|not applicable)' "$SUB"

# --- Check 4: PoC test exists ---
# Look for references like poc-tests/XXX.t.sol, Rust .rs PoC/unit-test files,
# Go *_test.go PoCs, Node .mjs/.js structural tests, or "PoC: path" fields.
# Non-EVM findings should not be forced through Forge.
POC_REF=$(grep -oE '[a-zA-Z0-9_/.-]+\.t\.sol' "$SUB" | head -1 || true)
RUST_POC_REF=$(grep -oE '[a-zA-Z0-9_/.-]+\.rs' "$SUB" | head -1 || true)
GO_POC_REF=$(grep -oE '[a-zA-Z0-9_/.-]+_test\.go(\.draft)?' "$SUB" | head -1 || true)
JS_POC_REF=$(grep -oE '[a-zA-Z0-9_/.-]+_test\.(mjs|js|ts)' "$SUB" | head -1 || true)
GO_POC_INLINE=0
if grep -qE 'func[[:space:]]+Test[A-Za-z0-9_]*[[:space:]]*\([[:space:]]*t[[:space:]]+\*testing\.T[[:space:]]*\)' "$SUB"; then
    GO_POC_INLINE=1
fi
RUST_POC_INLINE=0
# Detect inline Rust test functions (#[test] attr followed by fn test_*)
if grep -qE '#\[test\]|#\[tokio::test\]|#\[async_std::test\]' "$SUB"; then
    RUST_POC_INLINE=1
fi
JS_POC_INLINE=0
if grep -qE 'node:test|[[:space:]]test[[:space:]]*\([[:space:]]*['"'"'"]' "$SUB" \
   && grep -qE 'assert\.(ok|match|doesNotMatch|strictEqual|deepEqual|equal)' "$SUB"; then
    JS_POC_INLINE=1
fi
# Oscript / Obyte Autonomous Agent PoCs use the aa-testkit harness: files named
# *.test.oscript.js (or *.oscript.js) with mocha (describe/it) + chai (expect().to)
# and assert real value movement via Utils.getExternalPayments - NOT node:test/assert.
# Without this, a runnable+PASSING aa-testkit PoC reads as "no PoC" (Obyte 2026-07-09,
# blocked a CONFIRMED prediction-markets-aa Critical from paste-ready).
OSCRIPT_POC_REF=$(grep -oE '[a-zA-Z0-9_/.-]+\.(test\.oscript\.js|oscript\.js)' "$SUB" | head -1 || true)
OSCRIPT_POC_INLINE=0
if grep -qE 'describe[[:space:]]*\(|[[:space:]]it[[:space:]]*\([[:space:]]*['"'"'"]' "$SUB" \
   && grep -qE 'expect[[:space:]]*\(|\.to\.(be|equal|eql|deep)|aa-testkit|getExternalPayments' "$SUB"; then
    OSCRIPT_POC_INLINE=1
fi
if [ -n "$POC_REF" ]; then
    echo "  ✅ 4. PoC reference in submission ($POC_REF)"
elif { [ -n "$RUST_POC_REF" ] || [ "$RUST_POC_INLINE" -eq 1 ]; } \
     && grep -iqE 'cargo test|cargo nextest|rust poc|rust unit|rust integration|source-only rust|dlt' "$SUB"; then
    echo "  ✅ 4. Rust/DLT PoC reference in submission (${RUST_POC_REF:-inline Rust test})"
elif { [ -n "$GO_POC_REF" ] || [ "$GO_POC_INLINE" -eq 1 ]; } \
     && grep -iqE 'go test|mise test|go poc|go unit|golang|source-only go|dlt|bitcoin|statechain|lightning' "$SUB"; then
    echo "  ✅ 4. Go PoC reference in submission (${GO_POC_REF:-inline Go test})"
elif { [ -n "$JS_POC_REF" ] || [ "$JS_POC_INLINE" -eq 1 ]; } \
     && grep -iqE 'node --test|node:test|javascript poc|typescript poc|structural node|source-only node|indexer' "$SUB"; then
    echo "  ✅ 4. Node/JS PoC reference in submission (${JS_POC_REF:-inline Node test})"
elif { [ -n "$OSCRIPT_POC_REF" ] || [ "$OSCRIPT_POC_INLINE" -eq 1 ]; } \
     && grep -iqE 'aa-testkit|oscript poc|obyte poc|autonomous agent|mocha|chai|\.test\.oscript\.js|\.oscript\b' "$SUB"; then
    echo "  ✅ 4. Oscript/AA (aa-testkit) PoC reference in submission (${OSCRIPT_POC_REF:-inline aa-testkit mocha/chai test})"
else
    if [ "$SEVERITY" = "HIGH" ] || [ "$SEVERITY" = "CRITICAL" ]; then
        echo "  ❌ 4. PoC test required for High+ (no Forge *.t.sol, Rust .rs, Go *_test.go, or Node *_test.mjs PoC reference found)"
        fails=$((fails + 1))
    else
        echo "  ⚠️  4. PoC recommended but not required for ${SEVERITY:-Low} (no Forge *.t.sol, Rust .rs, Go *_test.go, or Node *_test.mjs ref)"
        warns=$((warns + 1))
    fi
fi

# --- Check 4b: PoC section must not be a pointer-only artifact block --------
# Cantina/Code4rena final paste must be self-contained. A path-only block such
# as "PoC file: <path>.t.sol" under "Proof of Concept" is allowed in internal
# bundles, but not in the triager-facing draft that pre-submit promotes.
_POC_POINTER_GATE=$(python3 - "$SUB" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
m = re.search(r"(?im)^#{1,6}\s+Proof of Concept\b.*$", text)
if not m:
    print("missing-proof-of-concept-section")
    raise SystemExit(0)

level = len(re.match(r"^#+", m.group(0)).group(0))
section = text[m.end():]
for n in re.finditer(r"(?im)^(#{1,6})\s+\S.*$", section):
    if len(n.group(1)) <= level:
        section = section[:n.start()]
        break

lines = [ln.strip() for ln in section.splitlines() if ln.strip()]
first_body = lines[0] if lines else ""
poc_path = r"[A-Za-z0-9_./-]+(?:\.t\.sol|\.rs|_test\.go(?:\.draft)?|\.test\.oscript\.js|\.oscript\.js)"
if re.match(r"(?i)^PoC files?:\s*$", first_body):
    print("pointer-only-poc-section")
elif re.search(r"(?im)^\s*PoC files?:\s*\n\s*```(?:text|txt|)?\s*\n(?:" + poc_path + r"\s*\n?)+\s*```", section):
    print("pointer-only-poc-section")
elif re.search(r"(?im)^\s*PoC files?:\s*" + poc_path + r"\s*$", section):
    print("pointer-only-poc-section")
else:
    print("ok")
PY
)
if [ "$_POC_POINTER_GATE" = "ok" ]; then
    echo "  ✅ 4b. PoC section is not pointer-only"
elif [ "$_POC_POINTER_GATE" = "missing-proof-of-concept-section" ]; then
    echo "  ⚠️  4b. Proof of Concept section not found"
    warns=$((warns + 1))
else
    echo "  ❌ 4b. pointer-only PoC section detected — inline the PoC/test excerpts before promotion"
    fails=$((fails + 1))
fi

# --- Check 4c: final paste carries substantive inline PoC/test code --------
_POC_INLINE_GATE=$(python3 - "$SUB" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
m = re.search(r"(?im)^#{1,6}\s+Proof of Concept\b.*$", text)
if not m:
    print("missing-proof-of-concept-section")
    raise SystemExit(0)

level = len(re.match(r"^#+", m.group(0)).group(0))
section = text[m.end():]
for n in re.finditer(r"(?im)^(#{1,6})\s+\S.*$", section):
    if len(n.group(1)) <= level:
        section = section[:n.start()]
        break

fences = re.findall(r"```([A-Za-z0-9_+-]*)\s*\n(.*?)\n```", section, flags=re.DOTALL)
substantive = False
for lang, code in fences:
    code_stripped = code.strip()
    if not code_stripped:
        continue
    nonempty = [ln for ln in code_stripped.splitlines() if ln.strip()]
    if len(nonempty) < 40:
        continue
    lowered_lang = lang.lower()
    lowered_code = code_stripped.lower()
    is_solidity = lowered_lang in {"solidity", "sol"} or "pragma solidity" in lowered_code
    has_test_marker = bool(
        re.search(r"\bfunction\s+(test|invariant|prove|poc)[A-Za-z0-9_]*\s*\(", code_stripped)
        or re.search(r"\bdef\s+test_[A-Za-z0-9_]*\s*\(", code_stripped)
        or re.search(r"(?m)^\s*#\s*\[\s*test\s*\]", code_stripped)
        # Rust test attributes incl. async runtimes (tokio/async-std/actix). Generic
        # false-RED fix: tokio integration tests carry #[tokio::test] not #[test],
        # and idiomatic auditooor PoCs name the fn poc_*/test_*. Still requires the
        # >=40-line + assertion gates below, so this only recognizes MORE genuine tests.
        or re.search(r"(?m)^\s*#\s*\[\s*(?:tokio|async_std|actix(?:_rt|_web)?|smol|test_log)\s*::\s*test\b", code_stripped)
        or re.search(r"(?m)^\s*#\s*\[\s*test\s*\]", code_stripped)
        or re.search(r"\b(?:async\s+)?fn\s+(?:test|poc|prove|invariant)[A-Za-z0-9_]*\s*\(", code_stripped)
        or re.search(r"\bfunc\s+Test[A-Za-z0-9_]*\s*\(\s*t\s+\*testing\.T\s*\)", code_stripped)
        or re.search(r"\b(?:test|it)\s*\(\s*['\"]", code_stripped)
    )
    has_assertion_or_revert = bool(
        re.search(
            r"\b(assert(?:Eq|Gt|Lt|True|False)?|expectRevert|assert_eq!|expect\(|"
            r"require\.(?:Equal|Greater|Less|NoError|True|False)|"
            r"assert\.(?:Equal|Greater|Less|NoError|True|False|ok|match|doesNotMatch|strictEqual|deepEqual)|"
            r"t\.Fatalf|t\.Errorf)",
            code_stripped,
        )
    )
    if is_solidity:
        if re.search(r"\bcontract\s+[A-Za-z0-9_]+", code_stripped) and has_test_marker and has_assertion_or_revert:
            substantive = True
            break
    elif has_test_marker and has_assertion_or_revert:
        substantive = True
        break

print("ok" if substantive else "missing-substantive-inline-poc-code")
PY
)
if [ "$_POC_INLINE_GATE" = "ok" ]; then
    echo "  ✅ 4c. substantive inline PoC/test code is present"
elif [ "$_POC_INLINE_GATE" = "missing-proof-of-concept-section" ]; then
    echo "  ⚠️  4c. Proof of Concept section not found for inline-code gate"
    warns=$((warns + 1))
else
    echo "  ❌ 4c. substantive inline PoC code missing — final paste must include the full test body, not excerpts or file paths"
    fails=$((fails + 1))
fi

# --- Check 5: Originality-before-proof posture ---
_ORIG_GATE_TOOL="$AUDITOOOR_DIR/tools/originality-before-proof-gate.py"
if [ ! -f "$_ORIG_GATE_TOOL" ]; then
    echo "  ⚠️  5. originality-before-proof gate unavailable ($_ORIG_GATE_TOOL)"
    warns=$((warns + 1))
else
    _ORIG_TMP=$(mktemp 2>/dev/null || echo "/tmp/orig_gate_$$.json")
    _ORIG_ERR=$(mktemp 2>/dev/null || echo "/tmp/orig_gate_$$.err")
    set +e
    if [ -n "${SEVERITY:-}" ]; then
        python3 "$_ORIG_GATE_TOOL" --recorded-posture --draft "$SUB" --severity "$SEVERITY_ARG" --json > "$_ORIG_TMP" 2> "$_ORIG_ERR"
    else
        python3 "$_ORIG_GATE_TOOL" --recorded-posture --draft "$SUB" --json > "$_ORIG_TMP" 2> "$_ORIG_ERR"
    fi
    _ORIG_RC=$?
    set -uo pipefail
    _ORIG_SUMMARY=$(
        python3 - "$_ORIG_TMP" "$_ORIG_ERR" <<'PY'
import json
import sys
from pathlib import Path

json_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(json_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print("error\tparse-error\t" + (err or "unparseable originality gate output"))
    raise SystemExit(0)

verdict = str(payload.get("verdict") or "error")
code = str(payload.get("code") or "unknown")
message = str(payload.get("message") or "no message").replace("\t", " ").replace("\n", " ")
print(f"{verdict}\t{code}\t{message}")
PY
    )
    IFS=$'\t' read -r _ORIG_VERDICT _ORIG_CODE _ORIG_MESSAGE <<EOF
$_ORIG_SUMMARY
EOF
    if { [ "$SEVERITY" = "HIGH" ] || [ "$SEVERITY" = "CRITICAL" ]; } && [ "$_ORIG_VERDICT" = "fail" ]; then
        echo "  ❌ 5. originality-before-proof: $_ORIG_MESSAGE"
        fails=$((fails + 1))
    elif [ "$_ORIG_VERDICT" = "pass" ]; then
        echo "  ✅ 5. originality-before-proof: $_ORIG_MESSAGE"
    elif [ "$_ORIG_VERDICT" = "fail" ]; then
        echo "  ⚠️  5. originality-before-proof: $_ORIG_MESSAGE (advisory below High/Critical)"
        warns=$((warns + 1))
    else
        echo "  ⚠️  5. originality-before-proof: $_ORIG_MESSAGE"
        warns=$((warns + 1))
    fi
    python3 - "$_ORIG_TMP" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)

for line in (payload.get("evidence_lines") or [])[:3]:
    print(f"       evidence: {line}")
PY
    rm -f "$_ORIG_TMP" "$_ORIG_ERR"
    if [ "$_ORIG_RC" -eq 2 ]; then
        warns=$((warns + 1))
    fi
fi

# --- Check 6: Fork test requirement for High+ ---
if [ "$SEVERITY" = "HIGH" ] || [ "$SEVERITY" = "CRITICAL" ]; then
    if grep -iqE 'createSelectFork|vm.createFork|fork.?test|rpc.?url|fork_replay|fork-replay|deltas\\.json|balance.?delta' "$SUB" 2>/dev/null; then
        echo "  ✅ 6. Fork/economic-delta proof referenced for High+ severity"
    else
        echo "  ⚠️  6. High+ finding without fork/economic-delta proof reference (isolated PoC acceptable if justified)"
        warns=$((warns + 1))
    fi
else
    echo "  ✅ 6. Fork-test not required for ${SEVERITY:-Low}"
fi

# --- Check 7: Dupe-risk run ---
echo ""
echo "  7. Running dupe-risk check..."
echo ""
DUPE_OUT=$("$AUDITOOOR_DIR/tools/dupe-risk.sh" "$SUB" 2>&1 || true)
DUPE_RC=$?
if echo "$DUPE_OUT" | grep -q "🟢 LOW DUPE RISK"; then
    echo "  ✅ 7. Dupe-risk: LOW"
elif echo "$DUPE_OUT" | grep -q "🟡 NEEDS REVIEW"; then
    if grep -iE '(dupe override|novel vector|distinction|this is novel because)' "$SUB" >/dev/null; then
        echo "  ✅ 7. Dupe-risk: NEEDS REVIEW (override paragraph present)"
    else
        echo "  ⚠️  7. Dupe-risk: NEEDS REVIEW (add distinction paragraph citing how this differs)"
        warns=$((warns + 1))
    fi
elif echo "$DUPE_OUT" | grep -q "🔴 HIGH DUPE RISK"; then
    if grep -iE '(dupe override|novel vector|distinction (paragraph|from prior)|this is novel because)' "$SUB" >/dev/null; then
        echo "  ⚠️  7. Dupe-risk: HIGH (override paragraph present — reviewer should verify strength)"
        warns=$((warns + 1))
    else
        echo "  ❌ 7. Dupe-risk: HIGH — submission lacks override/distinction paragraph"
        echo "       Add a '### Distinction from prior findings' section citing why this is novel."
        fails=$((fails + 1))
    fi
fi

# --- Check 11: Scope-review sub-agent (U2 / Phase 3.5) ---
# Before the rejection classifier, verify that tools/scope-review.sh has been
# dispatched for this draft AND the agent's response was saved to
# <ws>/scope_review/<basename>.agent-review.md. The file must contain a
# VERDICT line whose value is NOVEL or SAME-CLASS-DIFFERENT-VECTOR.
# This enforces that no draft reaches submission without an LLM-level
# attack-path-similarity review (not just keyword grep).
echo ""
echo "  11. Scope-review sub-agent completed..."
# Resolve workspace: assume submission lives under <ws>/submissions/... so
# walk up until we find OOS_CHECKLIST.md or SCOPE.md (same heuristic used by
# other tools).
_SUB_ABS=$(cd "$(dirname "$SUB")" && pwd)
_WS=""
_cur="$_SUB_ABS"
while [ "$_cur" != "/" ] && [ -n "$_cur" ]; do
    if [ -f "$_cur/OOS_CHECKLIST.md" ] || [ -f "$_cur/SCOPE.md" ]; then
        _WS="$_cur"; break
    fi
    _cur=$(dirname "$_cur")
done
# Expose _WS as WS_DIR so Checks #94-#99 (R45/R52/R47/R46/R48/R53) can pass
# --workspace to their tools.  If the walk-up failed, WS_DIR stays "" and
# those checks skip gracefully via their tool's own workspace-not-found path.
WS_DIR="${_WS:-}"
_BASENAME=$(basename "$SUB" .md)
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  11. Scope-review artifact: SKIPPED under GHSA-AWARE MODE"
    echo "       (Cantina .agent-review artifact N/A for GHSA; originality is"
    echo "        enforced via the GHSA Originality/Supersede requirement gate.)"
elif [ -z "$_WS" ]; then
    echo "  ❌ 11. Cannot resolve workspace (no OOS_CHECKLIST.md / SCOPE.md ancestor)"
    echo "       Run tools/scope-review.sh <ws> <draft> and save agent output."
    fails=$((fails + 1))
else
    # Accept either .agent-review.md (LLM-dispatched) or
    # .heuristic-review.md (scope-review-inline.sh, R44 U2/U8 fallback).
    # Prefer the LLM review when both exist.
    _REVIEW_LLM="$_WS/scope_review/${_BASENAME}.agent-review.md"
    _REVIEW_HEU="$_WS/scope_review/${_BASENAME}.heuristic-review.md"
    _REVIEW=""
    _REVIEW_KIND=""
    _FN_PREFIX=""
    case "$_BASENAME" in
        FN[0-9]*-draft) _FN_PREFIX="${_BASENAME%%-draft}" ;;
    esac
    if [ -f "$_REVIEW_LLM" ]; then
        _REVIEW="$_REVIEW_LLM"
        _REVIEW_KIND="agent-review"
    elif [ -f "$_REVIEW_HEU" ]; then
        _REVIEW="$_REVIEW_HEU"
        _REVIEW_KIND="heuristic-review"
    elif [ -n "$_FN_PREFIX" ]; then
        _REVIEW_ALIAS=$(find "$_WS/scope_review" -maxdepth 1 -type f -name "${_FN_PREFIX}-*.agent-review.md" 2>/dev/null | sort | head -1)
        if [ -n "$_REVIEW_ALIAS" ]; then
            _REVIEW="$_REVIEW_ALIAS"
            _REVIEW_KIND="agent-review"
        else
            _REVIEW_ALIAS=$(find "$_WS/scope_review" -maxdepth 1 -type f -name "${_FN_PREFIX}-*.heuristic-review.md" 2>/dev/null | sort | head -1)
            if [ -n "$_REVIEW_ALIAS" ]; then
                _REVIEW="$_REVIEW_ALIAS"
                _REVIEW_KIND="heuristic-review"
            fi
        fi
    fi
    if [ -z "$_REVIEW" ]; then
        echo "  ❌ 11. Scope-review artifact missing (checked .agent-review.md and .heuristic-review.md)"
        echo "       LLM path:      $_REVIEW_LLM"
        echo "       Heuristic path: $_REVIEW_HEU"
        echo "       Run either:"
        echo "         $AUDITOOOR_DIR/tools/scope-review.sh $_WS $SUB  (then dispatch brief + paste VERDICT)"
        echo "         $AUDITOOOR_DIR/tools/scope-review-inline.sh $_WS $SUB  (heuristic fallback)"
        fails=$((fails + 1))
    else
        _VERDICT=$(grep -E '^VERDICT:' "$_REVIEW" | head -1 | sed -E 's/^VERDICT:[[:space:]]*//; s/[[:space:]]*$//')
        case "$_VERDICT" in
            NOVEL|SAME-CLASS-DIFFERENT-VECTOR)
                echo "  ✅ 11. Scope-review VERDICT: $_VERDICT (source: $_REVIEW_KIND)"
                ;;
            DUPE-OF-AUDIT|OOS-ACKNOWLEDGED)
                echo "  ❌ 11. Scope-review VERDICT: $_VERDICT (source: $_REVIEW_KIND) — move draft to _oos_rejected/"
                fails=$((fails + 1))
                ;;
            "")
                echo "  ❌ 11. Scope-review file exists but has no VERDICT: line"
                echo "       File: $_REVIEW"
                fails=$((fails + 1))
                ;;
            *)
                echo "  ❌ 11. Scope-review VERDICT unrecognized: '$_VERDICT'"
                echo "       Allowed: NOVEL | SAME-CLASS-DIFFERENT-VECTOR | DUPE-OF-AUDIT | OOS-ACKNOWLEDGED"
                fails=$((fails + 1))
                ;;
        esac
    fi
fi

# --- Check 8: Rejection classifier (Issue #88) ---
echo ""
echo "  8. Running rejection classifier..."
CLF_MODEL="$AUDITOOOR_DIR/reference/rejection_classifier.pkl"
if [ -f "$CLF_MODEL" ]; then
    CLF_OUT=$(python3 "$AUDITOOOR_DIR/tools/rejection-classifier.py" --predict "$SUB" 2>&1 || true)
    if echo "$CLF_OUT" | grep -qE 'paid\s+[4-9][0-9]\.|paid\s+100\.'; then
        echo "  ✅ 8. Classifier: high predicted-paid probability"
        echo "$CLF_OUT" | grep -E '^\s+(paid|dupe|rejected|unknown)' | sed 's/^/     /'
    elif echo "$CLF_OUT" | grep -qE 'dupe\s+[5-9][0-9]\.|rejected\s+[5-9][0-9]\.'; then
        echo "  ⚠️  8. Classifier: high predicted-dupe/rejected probability"
        echo "$CLF_OUT" | grep -E '^\s+(paid|dupe|rejected|unknown)' | sed 's/^/     /'
        warns=$((warns + 1))
    else
        echo "  ✅ 8. Classifier: no red flags"
        echo "$CLF_OUT" | grep -E '^\s+(paid|dupe|rejected|unknown)' | head -4 | sed 's/^/     /'
    fi
else
    echo "  ⚠️  8. Rejection classifier not trained yet"
    echo "       Train: python3 tools/scrape-outcomes.py && python3 tools/rejection-classifier.py --train"
fi

# --- Check 10: PoC `forge test` pass-required (R43 U3) ---
# If the draft references a .t.sol file, locate it on disk, find the enclosing
# foundry project (first ancestor with foundry.toml — or the nearest sibling),
# derive the contract name from the test file, and run
#   forge test --match-path '*<file>*' --match-contract <ContractName>
# Fail if the test does not pass. Rust, Go, and Node source-level PoCs may cite a
# cargo/go/mise/node transcript instead. If no supported test reference exists,
# emit a WARN and don't fail (some Low/Informational findings don't need a test).
echo ""
echo "  10. Running PoC forge test (R43 U3)..."
# Codex PR-102 blocker 2: Check #22 needs a ground-truth signal for whether
# the PoC actually passed (not just whether a `.t.sol` is mentioned in prose).
# Seed the status vars here and update them below so downstream checks can
# consume a hardened signal.
POC_TEST_ANY_PASSED=0   # 1 if at least one *.t.sol ran and passed
POC_TEST_ANY_FAILED=0   # 1 if any *.t.sol ran and failed
POC_TEST_RAN=0          # 1 if any forge invocation executed for this draft
RUST_POC_ANY_PASSED=0   # 1 if a Rust/DLT cargo-test proof transcript is cited
GO_POC_ANY_PASSED=0     # 1 if a Go test proof transcript is cited
JS_POC_ANY_PASSED=0     # 1 if a Node node:test proof transcript is cited
OSCRIPT_POC_ANY_PASSED=0  # 1 if an Oscript/AA aa-testkit (mocha/chai) PASS transcript is cited
POC_REFS=$(grep -oE '[a-zA-Z0-9_/.-]+\.t\.sol' "$SUB" | sort -u)
if [ -z "$POC_REFS" ]; then
    _has_rust_poc=0
    { [ -n "${RUST_POC_REF:-}" ] || [ "${RUST_POC_INLINE:-0}" -eq 1 ]; } && _has_rust_poc=1
    _rust_transcript_ok=0
    if [ "$_has_rust_poc" -eq 1 ] && grep -iqE 'cargo test|cargo nextest' "$SUB"; then
        # cargo test standard: "test result: ok. N passed; 0 failed"
        if grep -iqE 'test result:[[:space:]]+ok\.' "$SUB"; then
            _rust_transcript_ok=1
        # "N passed; 0 failed" (also matches cargo nextest summary)
        elif grep -iqE '[1-9][0-9]*[[:space:]]+passed;[[:space:]]+0[[:space:]]+failed' "$SUB"; then
            _rust_transcript_ok=1
        # cargo nextest per-test line: "PASS [  0.001s] crate::module::test_name"
        elif grep -iqE 'PASS[[:space:]]+\[' "$SUB"; then
            _rust_transcript_ok=1
        fi
    fi
    if [ "$_rust_transcript_ok" -eq 1 ]; then
        RUST_POC_ANY_PASSED=1
        echo "  ✅ 10. Rust/DLT cargo-test PoC transcript cited (${RUST_POC_REF:-inline Rust test})"
    elif { [ -n "${GO_POC_REF:-}" ] || [ "${GO_POC_INLINE:-0}" -eq 1 ]; } \
       && grep -iqE 'go test|mise test' "$SUB" \
       && grep -iqE -- '--- PASS:[[:space:]]+Test|^PASS$|^ok[[:space:]]+[^[:space:]]+|[1-9][0-9]*[[:space:]]+passed;[[:space:]]+0[[:space:]]+failed' "$SUB"; then
        GO_POC_ANY_PASSED=1
        echo "  ✅ 10. Go test PoC transcript cited (${GO_POC_REF:-inline Go test})"
    elif { [ -n "${JS_POC_REF:-}" ] || [ "${JS_POC_INLINE:-0}" -eq 1 ]; } \
       && grep -iqE 'node --test|node:test' "$SUB" \
       && grep -iqE 'ℹ pass [1-9][0-9]*|[1-9][0-9]*[[:space:]]+pass|✔[[:space:]]+' "$SUB" \
       && grep -iqE 'ℹ fail 0|0[[:space:]]+fail|0[[:space:]]+failed' "$SUB"; then
        JS_POC_ANY_PASSED=1
        echo "  ✅ 10. Node/JS node:test PoC transcript cited (${JS_POC_REF:-inline Node test})"
    elif { [ -n "${OSCRIPT_POC_REF:-}" ] || [ "${OSCRIPT_POC_INLINE:-0}" -eq 1 ]; } \
       && grep -iqE 'aa-testkit|mocha|chai|\.test\.oscript\.js|getExternalPayments' "$SUB" \
       && grep -iqE '[1-9][0-9]*[[:space:]]+passing|[0-9]+/[0-9]+[[:space:]]+(tests?[[:space:]]+)?pass' "$SUB" \
       && ! grep -iqE '[1-9][0-9]*[[:space:]]+failing' "$SUB"; then
        OSCRIPT_POC_ANY_PASSED=1
        echo "  ✅ 10. Oscript/AA aa-testkit PoC transcript cited (${OSCRIPT_POC_REF:-inline aa-testkit mocha/chai test})"
    else
        echo "  ⚠️  10. No executable Forge/Rust/Go/Node/Oscript PoC transcript recognized — skipping local PoC test run (ok for Low/Info)"
        warns=$((warns + 1))
    fi
else
    SUB_DIR=$(cd "$(dirname "$SUB")" && pwd)
    # Walk up from SUB_DIR to find a workspace root (has agent_outputs/ or AUDIT.md)
    WS_ROOT="$SUB_DIR"
    while [ "$WS_ROOT" != "/" ]; do
        if [ -d "$WS_ROOT/poc-tests" ] || [ -f "$WS_ROOT/AUDIT.md" ]; then
            break
        fi
        WS_ROOT=$(dirname "$WS_ROOT")
    done
    [ "$WS_ROOT" = "/" ] && WS_ROOT="$SUB_DIR"

    any_test_run=0
    any_test_fail=0
    for poc in $POC_REFS; do
        poc_base=$(basename "$poc")
        # Locate the actual test file under WS_ROOT (prefer poc-tests/)
        POC_PATH=""
        if [ -f "$WS_ROOT/poc-tests/$poc_base" ]; then
            POC_PATH="$WS_ROOT/poc-tests/$poc_base"
        else
            POC_PATH=$(find "$WS_ROOT" -maxdepth 6 -name "$poc_base" -type f 2>/dev/null | head -1)
        fi
        if [ -z "$POC_PATH" ] || [ ! -f "$POC_PATH" ]; then
            echo "  ⚠️  10. referenced $poc_base but file not found under $WS_ROOT — skipping"
            warns=$((warns + 1))
            continue
        fi

        # Find nearest foundry.toml: walk up from POC_PATH, then scan WS_ROOT/src*, then WS_ROOT parents.
        FORGE_DIR=""
        d=$(dirname "$POC_PATH")
        while [ "$d" != "/" ]; do
            if [ -f "$d/foundry.toml" ]; then FORGE_DIR="$d"; break; fi
            d=$(dirname "$d")
        done
        if [ -z "$FORGE_DIR" ]; then
            # Look under common sibling locations of WS_ROOT: src-v2, src, or WS_ROOT itself
            for cand in "$WS_ROOT/src-v2" "$WS_ROOT/src" "$WS_ROOT"; do
                [ -L "$cand" ] && cand=$(cd "$cand" && pwd -P)
                if [ -f "$cand/foundry.toml" ]; then FORGE_DIR="$cand"; break; fi
                # one level up (symlinks often land in a src/ dir of a larger forge project)
                if [ -n "$cand" ] && [ -d "$cand" ]; then
                    up=$(dirname "$cand")
                    if [ -f "$up/foundry.toml" ]; then FORGE_DIR="$up"; break; fi
                fi
            done
        fi
        if [ -z "$FORGE_DIR" ]; then
            # R65b: prefer $WS_ROOT/src/<name>/foundry.toml over agent_outputs/**
            # (common layout: Centrifuge V3.1 has src/protocol/foundry.toml).
            for cand_toml in "$WS_ROOT"/src/*/foundry.toml; do
                if [ -f "$cand_toml" ]; then
                    FORGE_DIR=$(dirname "$cand_toml")
                    break
                fi
            done
        fi
        if [ -z "$FORGE_DIR" ]; then
            # Last-ditch global search — prune agent_outputs/ so leftover R41 / R41-mining
            # scaffolds don't shadow the real protocol foundry.toml.
            FORGE_DIR=$(find "$WS_ROOT" -maxdepth 7 \
                            -type d \( -name agent_outputs -o -name lib \) -prune -o \
                            -name 'foundry.toml' -type f -print 2>/dev/null | head -1)
            [ -n "$FORGE_DIR" ] && FORGE_DIR=$(dirname "$FORGE_DIR")
        fi
        if [ -z "$FORGE_DIR" ]; then
            echo "  ⚠️  10. could not locate foundry.toml for $poc_base — skipping run"
            warns=$((warns + 1))
            continue
        fi

        # Derive contract name from the contract that owns the first test*
        # function. Many PoCs declare helper/mock contracts before the actual
        # test contract; matching the first declaration can silently run zero
        # tests while forge still exits 0.
        CONTRACT_NAME=$(awk '
            /^[[:space:]]*(abstract[[:space:]]+)?contract[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ {
                for (i = 1; i <= NF; i++) {
                    if ($i == "contract") {
                        current = $(i + 1)
                        sub(/[^A-Za-z0-9_].*$/, "", current)
                        break
                    }
                }
            }
            /^[[:space:]]*function[[:space:]]+test[A-Za-z0-9_]*/ {
                if (current != "") { print current; exit }
            }
        ' "$POC_PATH" 2>/dev/null | head -1)
        if [ -z "$CONTRACT_NAME" ]; then
            CONTRACT_NAME=$(grep -oE '^[[:space:]]*contract[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$POC_PATH" 2>/dev/null \
                            | head -1 | awk '{print $2}')
        fi
        if [ -z "$CONTRACT_NAME" ]; then
            CONTRACT_NAME="${poc_base%.t.sol}"
        fi

        # Use canonical forge resolver (handles PATH collisions with broken forge)
        if [ -z "${FORGE_BIN:-}" ]; then
            source "$AUDITOOOR_DIR/tools/lib/forge-resolve.sh" 2>/dev/null || true
        fi
        if [ -z "${FORGE_BIN:-}" ] || [ ! -x "$FORGE_BIN" ]; then
            echo "  ⚠️  10. forge not found — cannot run $poc_base"
            echo "       Set FORGE_BIN or ensure ~/.foundry/bin/forge exists."
            warns=$((warns + 1))
            continue
        fi

        FORGE_PROFILE=""
        if [ -f "$FORGE_DIR/foundry.toml" ] \
           && grep -qE '^[[:space:]]*\[profile\.poc\]' "$FORGE_DIR/foundry.toml"; then
            FORGE_PROFILE="poc"
        fi

        FORGE_TEST_ARGS=()
        if [ "${AUDITOOOR_FORGE_ONLINE:-0}" != "1" ]; then
            # Keep submission gates deterministic and avoid Foundry's remote
            # signature/proxy path when stdout is redirected to the gate log.
            FORGE_TEST_ARGS+=(--offline)
        fi
        FORGE_TEST_ARGS_DISPLAY="${FORGE_TEST_ARGS[*]}"
        if [ -n "$FORGE_PROFILE" ]; then
            echo "       running: FOUNDRY_PROFILE=$FORGE_PROFILE $FORGE_BIN test ${FORGE_TEST_ARGS_DISPLAY:+$FORGE_TEST_ARGS_DISPLAY }--match-path '*${poc_base}*' --match-contract ${CONTRACT_NAME} (in ${FORGE_DIR})"
        else
            echo "       running: $FORGE_BIN test ${FORGE_TEST_ARGS_DISPLAY:+$FORGE_TEST_ARGS_DISPLAY }--match-path '*${poc_base}*' --match-contract ${CONTRACT_NAME} (in ${FORGE_DIR})"
        fi
        any_test_run=1
        POC_TEST_RAN=1
        FORGE_LOG=$(mktemp 2>/dev/null || echo "/tmp/forge_$$.log")
        # bash 3.2 strict-mode safety: FORGE_TEST_ARGS is empty when
        # AUDITOOOR_FORGE_ONLINE=1; use ${arr[@]+"${arr[@]}"} to expand to
        # zero args without tripping set -u.
        if [ -n "$FORGE_PROFILE" ]; then
            ( cd "$FORGE_DIR" && FOUNDRY_PROFILE="$FORGE_PROFILE" "$FORGE_BIN" test ${FORGE_TEST_ARGS[@]+"${FORGE_TEST_ARGS[@]}"} --match-path "*${poc_base}*" --match-contract "$CONTRACT_NAME" ) \
                > "$FORGE_LOG" 2>&1
        else
            ( cd "$FORGE_DIR" && "$FORGE_BIN" test ${FORGE_TEST_ARGS[@]+"${FORGE_TEST_ARGS[@]}"} --match-path "*${poc_base}*" --match-contract "$CONTRACT_NAME" ) \
                > "$FORGE_LOG" 2>&1
        fi
        rc=$?
        if [ $rc -eq 0 ]; then
            # forge returns 0 even when 0 tests match; require at least one passed
            if grep -qE '[1-9][0-9]* passed' "$FORGE_LOG"; then
                echo "  ✅ 10. PoC $poc_base passed ($CONTRACT_NAME)"
                POC_TEST_ANY_PASSED=1
            elif grep -qE '0 tests? (?:matched|ran|passed)|No tests found|No tests match' "$FORGE_LOG"; then
                echo "  ⚠️  10. PoC $poc_base: no tests matched (--match-contract=$CONTRACT_NAME) — adjust name"
                warns=$((warns + 1))
            else
                echo "  ✅ 10. PoC $poc_base: forge exited 0 (assumed pass)"
                POC_TEST_ANY_PASSED=1
            fi
        else
            # R46: known-environment failures (missing solc version) are not a
            # finding-quality problem — they're an env-setup problem already
            # tracked as SKILL_ISSUE #218. Downgrade these to a WARN so the
            # gate can be enforced for content quality without being held
            # hostage to forge/solc availability on every dev machine.
            if grep -qE 'No solc version exists|Encountered invalid solc version|Failed to install solc|no compiler versions are available|Found Solidity sources, but no compiler' "$FORGE_LOG"; then
                echo "  ⚠️  10. PoC $poc_base: solc version unavailable in this env (SKILL_ISSUE #218) — env-only failure, downgraded to warning"
                warns=$((warns + 1))
            else
                echo "  ❌ 10. PoC $poc_base FAILED ($CONTRACT_NAME, rc=$rc)"
                tail -20 "$FORGE_LOG" | sed 's/^/       /'
                any_test_fail=1
                POC_TEST_ANY_FAILED=1
                fails=$((fails + 1))
            fi
        fi
        rm -f "$FORGE_LOG"
    done

    if [ $any_test_run -eq 0 ] && [ $any_test_fail -eq 0 ]; then
        : # already warned above
    fi
fi

# --- Check 10p: PoC-first fail-fast (operator #1 priority) ------------------
# Rank-1 fix (NUVA presubmit friction). For HIGH/CRITICAL drafts, refuse to
# spend the reviewer's attention on the long *format* body (Checks #12+) until
# the PoC *substance* is actually green. This mirrors the correct order of
# operations: a runnable, node-level PoC over the real CUT comes BEFORE prose
# and formatting. If substance is missing we print a banner pointing at the
# existing multi-validator harness (tools/cosmos_multivalidator_probe_shell.py)
# and exit 1, skipping the format body.
#
# Substance (POC_SUBSTANCE_OK) is computed from the SAME signals the late gates
# use (single source of truth) so nothing is re-litigated:
#   - #4  : a PoC reference/inline test exists (any language).
#   - #10 : no cited Forge PoC actually FAILED (POC_TEST_ANY_FAILED != 1).
#   - #58 : an EARLY re-run of tools/in-process-vs-node-level-check.py returns
#           rc 0 (pass OR accepted l32/r18/r19-rebuttal). The late #58 STAYS as
#           the authoritative gate; this is only a fail-fast pre-check.
#   - cosmos consensus-halt claims additionally require a multi-validator probe
#           artifact (multivalidator_probe_*.{go,json}) to exist under the
#           workspace -- absence means the node-level harness was never run.
#
# Deferral: reuse the EXISTING l32-rebuttal marker (do NOT mint a new one). A
# bounded, source-backed <!-- l32-rebuttal: reason --> defers this block (the
# late #58 still adjudicates the same rebuttal).
#
# Default-OFF for a bare `bash pre-submit-check.sh <draft>` invocation so plain
# lint runs are unchanged; the filing lane (paste-ready-generator ->
# audit-complete STRICT) exports AUDITOOOR_POC_FIRST_STRICT=1 to arm it.
case "${AUDITOOOR_POC_FIRST_STRICT:-0}" in
    1|true|TRUE|yes|YES) _POC_FIRST_ARMED=1 ;;
    *) _POC_FIRST_ARMED=0 ;;
esac
if [ "$_POC_FIRST_ARMED" -eq 1 ] && { [ "$SEVERITY" = "HIGH" ] || [ "$SEVERITY" = "CRITICAL" ]; }; then
    echo ""
    echo "  10p. PoC-first fail-fast (${SEVERITY})..."

    # Deferral marker (reuse existing l32-rebuttal; visible line or HTML comment).
    _POC_FIRST_REBUTTAL=0
    if grep -iqE '<!--[[:space:]]*(l32|r18|r19)-rebuttal:' "$SUB" 2>/dev/null \
       || grep -iqE '^[[:space:]]*(-[[:space:]]*|\*[[:space:]]*)?(l32|r18|r19)[-_ ]rebuttal[[:space:]]*:' "$SUB" 2>/dev/null; then
        _POC_FIRST_REBUTTAL=1
    fi

    POC_SUBSTANCE_OK=1
    _POC_FIRST_REASONS=""

    # (#4) a PoC reference/inline test must exist for High+.
    if [ -z "${POC_REF:-}" ] && [ -z "${RUST_POC_REF:-}" ] && [ -z "${GO_POC_REF:-}" ] \
       && [ -z "${JS_POC_REF:-}" ] && [ -z "${OSCRIPT_POC_REF:-}" ] \
       && [ "${RUST_POC_INLINE:-0}" -ne 1 ] \
       && [ "${GO_POC_INLINE:-0}" -ne 1 ] && [ "${JS_POC_INLINE:-0}" -ne 1 ] \
       && [ "${OSCRIPT_POC_INLINE:-0}" -ne 1 ]; then
        POC_SUBSTANCE_OK=0
        _POC_FIRST_REASONS="${_POC_FIRST_REASONS}
       - #4: no runnable PoC (Forge/Rust/Go/Node/Oscript-aa-testkit) referenced or inlined."
    fi

    # (#10) a cited Forge PoC must not have FAILED.
    if [ "${POC_TEST_ANY_FAILED:-0}" -eq 1 ]; then
        POC_SUBSTANCE_OK=0
        _POC_FIRST_REASONS="${_POC_FIRST_REASONS}
       - #10: a cited Forge PoC FAILED (see Check #10 output above)."
    fi

    # (#58) early re-run of in-process-vs-node-level-check.py (single source of
    # truth stays the LATE #58; this is a fail-fast pre-check only).
    _R18P_TOOL="$AUDITOOOR_DIR/tools/in-process-vs-node-level-check.py"
    if [ -f "$_R18P_TOOL" ]; then
        _R18P_ARGS=("$SUB" "--strict" "--json")
        if [ -n "${SEVERITY:-}" ]; then
            _R18P_ARGS+=("--severity" "$SEVERITY_ARG")
        fi
        set +e
        python3 "$_R18P_TOOL" "${_R18P_ARGS[@]}" >/dev/null 2>&1
        _R18P_RC=$?
        set -uo pipefail
        if [ "$_R18P_RC" -eq 1 ]; then
            POC_SUBSTANCE_OK=0
            _POC_FIRST_REASONS="${_POC_FIRST_REASONS}
       - #58: in-process-only evidence for a node-level claim (L32/R18)."
        fi
    fi

    # (cosmos consensus-halt) require a multi-validator probe artifact.
    if grep -iqE 'consensus[ -]?halt|chain[ -]?halt|network[ -]?halt|apphash|app hash|halt the (chain|network)|liveness|finalizeblock|multi[ -]?validator|MsgSwapOut' "$SUB" 2>/dev/null; then
        # Resolve a workspace root independent of Check #10's local WS_ROOT.
        _POC_FIRST_SUBDIR=$(cd "$(dirname "$SUB")" && pwd)
        _POC_FIRST_WSROOT="$_POC_FIRST_SUBDIR"
        while [ "$_POC_FIRST_WSROOT" != "/" ]; do
            if [ -d "$_POC_FIRST_WSROOT/poc-tests" ] || [ -f "$_POC_FIRST_WSROOT/AUDIT.md" ]; then
                break
            fi
            _POC_FIRST_WSROOT=$(dirname "$_POC_FIRST_WSROOT")
        done
        [ "$_POC_FIRST_WSROOT" = "/" ] && _POC_FIRST_WSROOT="$_POC_FIRST_SUBDIR"
        _MV_ARTIFACT=$(find "$_POC_FIRST_WSROOT" -maxdepth 6 \
            \( -name 'multivalidator_probe_*.go' -o -name 'multivalidator_probe_*.json' \) \
            -type f 2>/dev/null | head -1)
        if [ -z "$_MV_ARTIFACT" ]; then
            POC_SUBSTANCE_OK=0
            _POC_FIRST_REASONS="${_POC_FIRST_REASONS}
       - cosmos consensus-halt claim without a multi-validator probe artifact
         (multivalidator_probe_*.{go,json}) under $_POC_FIRST_WSROOT."
        fi
    fi

    if [ "$POC_SUBSTANCE_OK" -eq 1 ]; then
        echo "  ✅ 10p. PoC substance green (PoC present, no forge fail, node-level evidence ok)"
    elif [ "$_POC_FIRST_REBUTTAL" -eq 1 ]; then
        echo "  ⚠️  10p. PoC substance NOT green, but deferred via l32-rebuttal marker"
        echo "         (the late Check #58 still adjudicates the same rebuttal)"
        echo "$_POC_FIRST_REASONS"
        warns=$((warns + 1))
    else
        echo "  ❌ 10p. PoC-first fail-fast: PoC substance is NOT green for a ${SEVERITY} draft."
        echo "$_POC_FIRST_REASONS"
        echo ""
        echo "  ============================================================"
        echo "   ORDER OF OPERATIONS: runnable, node-level PoC over the real"
        echo "   CUT comes BEFORE prose/formatting. Build the multi-validator"
        echo "   PoC first, then re-run the format gates:"
        echo ""
        echo "     python3 tools/cosmos_multivalidator_probe_shell.py \\"
        echo "       --workspace <ws> --poc-dir <ws>/poc-tests/<candidate> \\"
        echo "       --claim-text '<node-level claim>'"
        echo ""
        echo "   Or, for a bounded source-backed exception, add:"
        echo "     <!-- l32-rebuttal: <reason up to 200 chars> -->"
        echo "  ============================================================"
        exit 1
    fi
fi

# --- Check 12: Realistic bounds / economic feasibility ---
# POLY-45 lesson: uint248 pack overflow was rejected because makerAmount ≥ 2^248
# is not realistically achievable.  Flag any submission that cites extreme
# numeric bounds without justifying real-world achievability.
if echo "$text" | grep -iqE '2\^\s*248|2\*\*\s*248|type\(uint248\)\.max|type\(uint256\)\.max\b|>=?\s*2\^\s*2[0-9]{2}'; then
    if echo "$text" | grep -iqE 'not achievable given|cannot be reached|cannot reach|unreachable with|impossible with|practical exploitability is effectively zero|self-harm only|no third-party funds are at risk|no third-party funds|no reasonable (ui|user|signing pipeline)|voluntarily sign[s]? an (absurd|impossible|unreachable)|absurd `?makeramount|absurd makeramount|unrealistic .*supply'; then
        echo "  ❌ 12. economic-non-viable extreme-value claim: trigger is self-described as unreachable or self-harm only"
        echo "       POLY-45 lesson: do not file arithmetic/packing claims whose threshold exceeds production-reachable supply or caps."
        echo "       Provide a production-bound calculation showing trigger_threshold <= reachable_max, or kill/downgrade to internal hardening."
        fails=$((fails + 1))
    elif echo "$text" | grep -iqE 'realistic(?:ally)?\s+(?:bound|supply|amount|achievable)|token\s+supply|max\s+supply|total\s+supply\s*(?:is|<=?)'; then
        echo "  ✅ 12. Extreme value claim has realistic-bounds justification"
    else
        echo "  ❌ 12. Extreme value (≥2^248 or type(uintN).max) cited without realistic-bounds justification"
        echo "       POLY-45 lesson: programs reject findings that require implausibly large token amounts."
        echo "       Add: 'Given token supply of X, this amount is realistically achievable because ...'"
        fails=$((fails + 1))
    fi
else
    echo "  ✅ 12. No extreme-value claims detected"
fi

# --- Check 13: Event-only vs state-corruption ---
# POLY-46 lesson: wrong event topic was rejected because state (isOperator)
# was correct and CLOB doesn't use events for auth.  Event-only findings
# must not claim High/Medium unless they break off-chain infrastructure
# that leads to real fund loss.
event_focused=$(echo "$text" | grep -icE '\bevent\b.*\b(topic|indexed|param|emit)\b|\bemit\b.*\bevent\b.*\b(wrong|incorrect|missing|misuse)\b' || true)
state_impact=$(echo "$text" | grep -icE '\bstate\b.*\bcorrupt|\bfund|\bloss|\bdrain|\btransfer|\bbalance|\b(exploit|attack)\b.*\b(state|fund|balance)' || true)
if [ "$event_focused" -gt 0 ] && [ "$state_impact" -eq 0 ]; then
    if [ "$SEVERITY" = "HIGH" ] || [ "$SEVERITY" = "CRITICAL" ]; then
        echo "  ❌ 13. Event-only finding claims High+ severity without state-corruption or fund-loss impact"
        echo "       POLY-46 lesson: event cosmetic issues are rejected when on-chain state is correct."
        echo "       Either (a) downgrade to Low/Info, or (b) prove the event bug causes off-chain infra to lose funds."
        fails=$((fails + 1))
    else
        echo "  ⚠️  13. Event-only finding — ensure severity is capped at Low/Info unless off-chain impact is proven"
        warns=$((warns + 1))
    fi
else
    echo "  ✅ 13. Event-only / state-corruption distinction OK"
fi

# --- Check 14: Cross-chain atomicity awareness ---
# Snowbridge lesson: prefund drain was rejected because depositToken and
# prefund are executed within the same transaction from the Polkadot side.
# Any cross-chain finding must acknowledge transaction atomicity or
# trust-domain boundaries.
cross_chain=$(echo "$text" | grep -icE '\bcross.?chain\b|\bbridge\b|\blayer.?zero\b|\blayerzero\b|\b wormhole\b|\bpolkadot\b|\bethereum\b.*\bpolkadot\b|\bsnowbridge\b' || true)
atomicity_ack=$(echo "$text" | grep -icE '\batomic\b.*\btransaction|\bsame\s+transaction|\btrust\s+domain|\binitiat.*\bpolkadot\b|\binitiat.*\bethereum\b|\bsingle\s+tx' || true)
if [ "$cross_chain" -gt 0 ] && [ "$atomicity_ack" -eq 0 ]; then
    echo "  ⚠️  14. Cross-chain finding without atomicity / trust-domain acknowledgment"
    echo "       Snowbridge lesson: operations within the same cross-chain tx are often"
    echo "       protected by atomicity.  Add analysis of whether the attack spans tx boundaries."
    warns=$((warns + 1))
else
    echo "  ✅ 14. Cross-chain atomicity awareness OK"
fi

# --- Check 15: Privileged attacker realism ---
# POLY-84 lesson: cancelOrder reentrancy was downgraded because exploit
# required attacker-as-operator (privileged role).  If finding requires
# operator/admin/owner privilege, severity should reflect that constraint.
priv_attacker=$(echo "$text" | grep -icE '\battacker\b.*\b(operator|admin|owner)\b|\b(operator|admin|owner)\b.*\battacker\b|\brequire\b.*\boperator\b.*\battacker' || true)
priv_mitigation=$(echo "$text" | grep -icE '\bpermissionless|\bany\s+user|\bunauthorized\b.*\buser|\bno\s+role\b|\barbitrary\s+user' || true)
if [ "$priv_attacker" -gt 0 ] && [ "$priv_mitigation" -eq 0 ]; then
    if [ "$SEVERITY" = "HIGH" ] || [ "$SEVERITY" = "CRITICAL" ]; then
        echo "  ⚠️  15. Exploit requires privileged attacker (operator/admin/owner) but claims High+ severity"
        echo "       Many programs cap privileged-attacker findings at Medium/Low or mark them OOS."
        echo "       Either prove the privilege can be obtained permissionlessly, or downgrade severity."
        warns=$((warns + 1))
    else
        echo "  ⚠️  15. Exploit requires privileged attacker — verify this is in-scope for the program"
        warns=$((warns + 1))
    fi
else
    echo "  ✅ 15. Privileged-attacker realism OK"
fi

# --- Check 16: Incomplete-fix / variant framing ---
# MORPHO #I2.A lesson: "Different code path in the same function ≠ novel
# finding when a prior finding already covers the contract+function+outcome."
# Triagers classify by bug class/outcome, not by specific code path.
if echo "$text" | grep -iqE 'incomplete fix|not fixed|still possible|bypass.*prior|\bvariant of\b|same bug class|same outcome|same contract.*same function'; then
    if echo "$text" | grep -iqE 'distinct fix|different remediation|fix commit would differ|requires code change.*not doc|strictly stronger|atomic.*iterative|novel class'; then
        echo "  ✅ 16. Variant framing includes novel-vector / fix-commit-distinction defense"
    else
        echo "  ❌ 16. Submission frames itself as variant/incomplete-fix without proving novel class"
        echo "       MORPHO #I2.A lesson: triagers classify by bug class+outcome, not code path."
        echo "       If this is a variant, prove: (a) attack vector is STRICTLY stronger, AND"
        echo "       (b) the fix is a CODE change (not a README/doc update)."
        fails=$((fails + 1))
    fi
else
    echo "  ✅ 16. No variant/incomplete-fix framing detected"
fi

# --- Check 17: Same-author same-class splitting ---
# POLY #EV.F2 lesson: filing two findings for the same underlying pattern
# is discouraged and marked dupe. If this submission is near another of
# our own findings on the same contract+function, warn.
own_other=$(echo "$text" | grep -icE 'our (other|prior|previous) finding|we also filed|related submission|see also.*finding #[0-9]+' || true)
if [ "$own_other" -gt 0 ]; then
    echo "  ⚠️  17. Submission references our own other finding — verify not same-class split"
    echo "       POLY lesson: triagers penalize pattern-splitting (same underlying bug filed twice)."
    warns=$((warns + 1))
else
    echo "  ✅ 17. No same-author cross-reference detected"
fi

# --- Check 18: Acknowledged-wont-fix guard ---
# Morpho lesson: targeting acknowledged items only works when the attack
# vector is strictly stronger (atomic > iterative) AND the fix is a code
# change. If the submission mentions prior audit acknowledgment, require
# evidence of strictly stronger vector.
if echo "$text" | grep -iqE 'acknowledged|won.t.fix|won.t fix|known issue|prior audit.*(covered|found|reported)|design choice|by design'; then
    if echo "$text" | grep -iqE 'strictly stronger|atomic.*(vs|versus|>)|code change.*(not|vs).*doc|fix requires|different remediation'; then
        echo "  ✅ 18. Acknowledged item with strictly-stronger-vector defense present"
    else
        echo "  ⚠️  18. Submission touches acknowledged/prior-audit territory without strictly-stronger defense"
        echo "       Morpho lesson: only target acknowledged findings when vector is STRICTLY stronger"
        echo "       AND fix is a code change (not doc/README). Add: 'This is strictly stronger than X because...'"
        warns=$((warns + 1))
    fi
else
    echo "  ✅ 18. No acknowledged-wont-fix territory detected"
fi

# --- Check 19: Theoretical without concrete trigger ---
# Multiple programs reject findings that require implausible preconditions
# or where the attack path is purely static (no concrete tx sequence).
if echo "$text" | grep -iqE 'theoretically|in theory|could potentially|might be possible|under certain conditions|if an attacker were to'; then
    if echo "$text" | grep -iqE 'concrete sequence|attack sequence|step [0-9]| PoC |proof of concept|demonstrated|verified' || [ -n "$POC_REFS" ]; then
        echo "  ✅ 19. Theoretical language balanced by concrete PoC / sequence"
    else
        echo "  ⚠️  19. Theoretical language without concrete PoC or step-by-step sequence"
        echo "       Triagers reject 'might be possible' findings without demonstrated exploit path."
        warns=$((warns + 1))
    fi
else
    echo "  ✅ 19. No purely theoretical language detected"
fi

# --- Check 20: Triager historical rejection pattern match ---
# ITEM 1: Learn from past rejections. If the draft matches known rejection
# patterns (event-only, extreme-value, self-dupe, etc.), flag it.
TFC="${AUDITOOOR_DIR:-$(cd "$(dirname "$0")/.." && pwd)}/tools/triage-feedback-collector.py"
if [ -f "$TFC" ]; then
    tfc_out=$(python3 "$TFC" --check-draft "$SUB" --format json 2>/dev/null || echo "[]")
    tfc_blocks=$(echo "$tfc_out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([x for x in d if x.get('severity')=='block']))" 2>/dev/null || echo "0")
    tfc_warns=$(echo "$tfc_out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([x for x in d if x.get('severity')=='warn']))" 2>/dev/null || echo "0")
    if [ "$tfc_blocks" -gt 0 ]; then
        echo "  ❌ 20. Draft matches $tfc_blocks historical REJECTION pattern(s)"
        echo "$tfc_out" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for x in d:
    if x.get('severity') == 'block':
        print(f\"       → {x['pattern_id']}: {x['pattern_name']} (score {x['score']})\")
" 2>/dev/null
        fails=$((fails + 1))
    elif [ "$tfc_warns" -gt 0 ]; then
        echo "  ⚠️  20. Draft matches $tfc_warns historical warning pattern(s)"
        echo "$tfc_out" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for x in d:
    if x.get('severity') == 'warn':
        print(f\"       → {x['pattern_id']}: {x['pattern_name']} (score {x['score']})\")
" 2>/dev/null
        warns=$((warns + 1))
    else
        echo "  ✅ 20. No historical rejection patterns matched"
    fi
else
    echo "  ⏭  20. triage-feedback-collector.py not found — skipping"
fi

# --- Check 21: Live proof for deployment/config-dependent claims ---
echo ""
echo "  21. Live proof attached for deployment/config-dependent claims..."
LIVE_DEPENDS=$(_live_proof_depends)
if [ "$LIVE_DEPENDS" != "1" ]; then
    echo "  ✅ 21. No deployment/live-state proof requirement detected"
else
    if _live_proof_override; then
        echo "  ⚠️  21. Live-proof override present (source-only rationale) — reviewer should verify it is justified"
        warns=$((warns + 1))
    else
        if [ -z "${_WS:-}" ]; then
            echo "  ❌ 21. Draft appears deployment/live-state dependent, but workspace could not be resolved"
            fails=$((fails + 1))
        elif [ ! -f "$_WS/live_topology_checks.json" ]; then
            echo "  ❌ 21. Draft appears deployment/live-state dependent, but $_WS/live_topology_checks.json is missing"
            echo "       Run: python3 tools/engage.py --workspace $_WS --stage live-checks"
            fails=$((fails + 1))
        else
            LIVE_REFS=$(_live_proof_refs "$_WS/live_topology_checks.json")
            LIVE_ANGLES=$(_live_proof_angles)
            if [ -z "$LIVE_REFS" ]; then
                echo "  ❌ 21. Draft appears deployment/live-state dependent, but does not cite exact live-proof row IDs"
                echo "       Add a '## Live Proof' section referencing one or more ids from $_WS/live_topology_checks.json"
                fails=$((fails + 1))
            else
                LIVE_SUMMARY=$(python3 - "$SUB" "$_WS/live_topology_checks.json" "$LIVE_REFS" "$LIVE_ANGLES" "$_WS/live-proof/manifest.json" <<'PY'
import json
import re
import sys
from pathlib import Path

draft_path = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
explicit_refs = {item.strip() for item in sys.argv[3].split(",") if item.strip()}
draft_angle_ids = sorted({item.strip() for item in sys.argv[4].split(",") if item.strip()})
package_manifest_path = Path(sys.argv[5])
text = draft_path.read_text(errors="replace")
text_lower = text.lower()

try:
    payload = json.loads(artifact_path.read_text())
except Exception as exc:
    print(f"error\tmalformed live_topology_checks.json: {exc}")
    sys.exit(0)

results = payload.get("results", [])
if not isinstance(results, list):
    print("error\tlive_topology_checks.json missing results[]")
    sys.exit(0)
proof_contradictions = payload.get("proof_contradictions", [])
if not isinstance(proof_contradictions, list):
    proof_contradictions = []
packaged_pair_integrity = {}
if package_manifest_path.is_file():
    try:
        package_manifest = json.loads(package_manifest_path.read_text())
        packaged_pair_integrity = package_manifest.get("proof_pair_integrity_summary", {})
        if not isinstance(packaged_pair_integrity, dict):
            packaged_pair_integrity = {}
    except Exception:
        packaged_pair_integrity = {}

def as_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0

addresses = {match.lower() for match in re.findall(r'0x[a-fA-F0-9]{40}', text)}
counts = {}
matched = 0
matched_ids = []
matched_results = []
matched_row_ids = set()
referenced_results = []
for result in results:
    if not isinstance(result, dict):
        continue
    contract = str(result.get("contract") or "").strip()
    address = str(result.get("address") or "").strip().lower()
    result_id = str(result.get("id") or "")
    contract_match = contract and contract.lower() in text_lower
    address_match = address and address in addresses
    explicit_match = result_id and result_id in explicit_refs
    if not (explicit_match or contract_match or address_match):
        continue
    matched += 1
    matched_results.append(result)
    if explicit_match:
        referenced_results.append(result)
    if result_id:
        matched_row_ids.add(result_id)
    matched_ids.append(result_id or contract or address)
    status = str(result.get("status") or "unknown")
    counts[status] = counts.get(status, 0) + 1

if matched == 0:
    print("missing\tno matching live-proof rows for draft contracts/addresses")
    sys.exit(0)

order = ["pass", "fail", "dry_run", "blocked_missing_rpc", "blocked_unresolved_address", "error"]
bits = [f"matched={matched}"]
for key in order:
    if counts.get(key):
        bits.append(f"{key}={counts[key]}")
if draft_angle_ids:
    wanted = set(draft_angle_ids)
    angle_linked = []
    angle_unbound = []
    generated_mismatch = []
    for result in referenced_results:
        row_id = str(result.get("id") or "")
        row_angles = {
            str(item).strip()
            for item in result.get("related_angle_ids", [])
            if str(item).strip()
        }
        if row_angles & wanted:
            angle_linked.append(row_id)
        elif not row_angles:
            if row_id:
                angle_unbound.append(row_id)
        elif str(result.get("spec_source") or "").strip() == "generated-relation":
            if row_id:
                generated_mismatch.append(row_id)
    bits.append("angles=" + ",".join(draft_angle_ids))
    bits.append(f"angle_linked={len(angle_linked)}")
    if angle_linked:
        bits.append("angle_ids=" + ",".join(angle_linked[:5]))
    if angle_unbound:
        bits.append("angle_unbound=" + ",".join(angle_unbound[:5]))
    if generated_mismatch:
        bits.append("angle_generated_mismatch=" + ",".join(generated_mismatch[:5]))
topology_rows = []
topology_contracts = set()
topology_blocks = set()
pair_conflicts = []
ambiguous_source_rows = []
for result in matched_results:
    status_val = str(result.get("status") or "").strip()
    synth_status = str(result.get("synthesis_status") or "").strip()
    if status_val == "ambiguous_source" or synth_status == "ambiguous-source":
        rid = str(result.get("id") or "").strip()
        if rid and rid not in ambiguous_source_rows:
            ambiguous_source_rows.append(rid)
    if str(result.get("evidence_class") or "").strip() == "topology-relation":
        topology_rows.append(str(result.get("id") or ""))
        contract = str(result.get("contract") or "").strip()
        if contract:
            topology_contracts.add(contract)
        block = str(result.get("block") or "").strip()
        if block:
            topology_blocks.add(block)
if ambiguous_source_rows:
    bits.append("ambiguous_source=" + ",".join(ambiguous_source_rows[:5]))
pair_angles = {"A-RACE", "A-AUTH", "A-ORACLE"}
pair_required = bool(set(draft_angle_ids) & pair_angles) and bool(topology_rows)
bits.append(f"topology_rows={len([row for row in topology_rows if row])}")
if topology_rows:
    bits.append("topology_ids=" + ",".join([row for row in topology_rows if row][:5]))
if topology_contracts:
    bits.append(f"topology_contracts={len(topology_contracts)}")
if topology_blocks:
    bits.append("topology_blocks=" + ",".join(sorted(topology_blocks)))
if pair_required:
    bits.append("pair_required=1")
    if topology_blocks:
        bits.append(f"pair_shared_block_count={len(topology_blocks)}")
        bits.append("pair_same_block=1" if len(topology_blocks) == 1 else "pair_same_block=0")
    incomplete_pair_ids = [
        str(item).strip()
        for item in packaged_pair_integrity.get("incomplete_pair_ids", [])
        if str(item).strip()
    ]
    cross_block_pair_ids = [
        str(item).strip()
        for item in packaged_pair_integrity.get("cross_block_pair_ids", [])
        if str(item).strip()
    ]
    if as_int(packaged_pair_integrity.get("incomplete")) > 0:
        bits.append("packaged_pair_incomplete=" + ",".join(incomplete_pair_ids[:5] or ["unknown"]))
    if as_int(packaged_pair_integrity.get("cross_block")) > 0:
        bits.append("packaged_pair_cross_block=" + ",".join(cross_block_pair_ids[:5] or ["unknown"]))
for result in matched_results:
    status = str(result.get("status") or "").strip()
    manual_status = str(result.get("manual_proof_status") or "").strip()
    effective_status = status if status in {"pass", "fail"} else manual_status
    if effective_status not in {"pass", "fail"}:
        continue
    row_id = str(result.get("id") or "").strip()
    if not row_id:
        continue
    if status in {"pass", "fail"} and manual_status in {"pass", "fail"} and manual_status != status:
        pair_conflicts.append(row_id)
        continue
    pair_complete = result.get("pair_complete")
    same_block = result.get("same_block")
    pair_blocks = result.get("pair_blocks")
    if pair_complete is True and same_block is False:
        pair_conflicts.append(row_id)
        continue
    if isinstance(pair_blocks, list):
        cleaned_blocks = sorted({
            str(block).strip()
            for block in pair_blocks
            if str(block).strip()
        })
        if len(cleaned_blocks) > 1:
            pair_conflicts.append(row_id)
            continue
contradiction_rows = sorted({
    str(row_id).strip()
    for item in proof_contradictions
    if isinstance(item, dict)
    for row_id in item.get("row_ids", [])
    if str(row_id).strip() and str(row_id).strip() in matched_row_ids
})
if contradiction_rows:
    bits.append("proof_contradictions=" + ",".join(contradiction_rows[:5]))
if pair_conflicts:
    bits.append("pair_conflicts=" + ",".join(pair_conflicts[:5]))
unpinned = []
if counts.get("pass") or counts.get("fail"):
    for result in matched_results:
        if str(result.get("status") or "") in {"pass", "fail"} and not str(result.get("block") or "").strip():
            rid = str(result.get("id") or "")
            if rid:
                unpinned.append(rid)
if unpinned:
    bits.append("unpinned=" + ",".join(unpinned[:5]))
bits.append("refs=" + ",".join(sorted(explicit_refs)))
bits.append("ids=" + ",".join(matched_ids[:5]))
print("ok\t" + " ".join(bits))
PY
)
                LIVE_KIND=$(printf '%s\n' "$LIVE_SUMMARY" | cut -f1)
                LIVE_DETAIL=$(printf '%s\n' "$LIVE_SUMMARY" | cut -f2-)
                case "$LIVE_KIND" in
                    ok)
                        if printf '%s' "$LIVE_DETAIL" | grep -q 'ambiguous_source='; then
                            if _ambiguous_source_override; then
                                echo "  ⚠️  21. Live-proof rows include ambiguous-source candidates but draft carries an explicit override ($LIVE_DETAIL)"
                                warns=$((warns + 1))
                            else
                                echo "  ❌ 21. Referenced live-proof rows have unresolved ambiguous-source candidates ($LIVE_DETAIL)"
                                echo "       Disambiguate the synthesized getter (rerun synth + manual pick) or add an explicit"
                                echo "       'Ambiguous-source override' acknowledgement in the draft before submission."
                                fails=$((fails + 1))
                            fi
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'angles=' && ! printf '%s' "$LIVE_DETAIL" | grep -qE 'angle_linked=[1-9]'; then
                            echo "  ❌ 21. Referenced live-proof rows do not substantiate the cited angle IDs ($LIVE_DETAIL)"
                            echo "       Cite at least one executed row whose related_angle_ids match the draft angle, or add an explicit relevance override."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'pair_required=1' && ! printf '%s' "$LIVE_DETAIL" | grep -qE 'topology_rows=[2-9]|topology_rows=[1-9][0-9]'; then
                            echo "  ❌ 21. Cross-contract topology proof is under-supported ($LIVE_DETAIL)"
                            echo "       Cite at least two executed topology-relation rows so the draft proves both the live edge and its controlling authority/wiring."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'pair_required=1' && ! printf '%s' "$LIVE_DETAIL" | grep -qE 'topology_contracts=[2-9]|topology_contracts=[1-9][0-9]'; then
                            echo "  ❌ 21. Cross-contract topology proof lacks independent counterpart evidence ($LIVE_DETAIL)"
                            echo "       The paired live-proof rows should cover at least two contracts, not one repeated local check."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'proof_contradictions='; then
                            echo "  ❌ 21. Referenced or draft-matched executed live-proof rows contradict each other ($LIVE_DETAIL)"
                            echo "       Reconcile the contradictory pass/fail rows or limit the draft to one coherent executed snapshot before submission."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'pair_conflicts='; then
                            echo "  ❌ 21. Referenced executed live-proof rows contain contradictory pair metadata ($LIVE_DETAIL)"
                            echo "       Re-run the imported manual proof or paired live checks so the reviewer sees one coherent executed snapshot."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'packaged_pair_incomplete='; then
                            echo "  ❌ 21. Packaged live-proof manifest reports incomplete proof pairs ($LIVE_DETAIL)"
                            echo "       Repackage after citing both the live edge and authority/counterparty rows for each required topology pair."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'packaged_pair_cross_block='; then
                            echo "  ❌ 21. Packaged live-proof manifest reports cross-block proof pairs ($LIVE_DETAIL)"
                            echo "       Re-run paired live checks at one block and repackage so manifest proof_pair_integrity_summary is same-block clean."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -q 'pair_same_block=0'; then
                            echo "  ❌ 21. Cross-contract topology proof is not pinned to one shared block ($LIVE_DETAIL)"
                            echo "       Re-run the paired live checks at the same block so the proof bundle is replayable as one coherent snapshot."
                            fails=$((fails + 1))
                        elif printf '%s' "$LIVE_DETAIL" | grep -qE 'pass=[1-9]|fail=[1-9]'; then
                            if printf '%s' "$LIVE_DETAIL" | grep -q 'unpinned='; then
                                echo "  ❌ 21. Referenced executed live-proof rows are missing pinned block metadata ($LIVE_DETAIL)"
                                echo "       Re-run live checks with --block <N> or capture proof at a fixed chain height."
                                fails=$((fails + 1))
                            else
                                echo "  ✅ 21. Live-proof rows attached ($LIVE_DETAIL)"
                            fi
                        elif printf '%s' "$LIVE_DETAIL" | grep -qE 'dry_run=[1-9]|blocked_missing_rpc=[1-9]|blocked_unresolved_address=[1-9]'; then
                            echo "  ❌ 21. Referenced live-proof rows exist but lack executed pass/fail evidence ($LIVE_DETAIL)"
                            echo "       Run live checks with real RPC or add explicit source-only rationale."
                            fails=$((fails + 1))
                        else
                            echo "  ❌ 21. Live-proof dossier is not actionable ($LIVE_DETAIL)"
                            fails=$((fails + 1))
                        fi
                        ;;
                    missing|error)
                        echo "  ❌ 21. $LIVE_DETAIL"
                        fails=$((fails + 1))
                        ;;
                    *)
                        echo "  ❌ 21. Unable to evaluate live proof ($LIVE_SUMMARY)"
                        fails=$((fails + 1))
                        ;;
                esac
            fi
        fi
    fi
fi

# --- Check 22: High+ fork-replay cited artifacts must exist and parse (PR 102) ---
# Distinguish real replay evidence from prose. If a High+ draft explicitly
# cites `fork_replay/*_manifest.json`, `*_deltas.json`, or `*_replay.yaml`,
# each citation must resolve under <ws>/fork_replay/ and (for JSON) parse.
# If no citation exists, allow source-only justification ONLY when the draft
# says so explicitly AND references a passing source-level PoC. Solidity/EVM
# drafts use a passing Forge PoC from Check #10; Rust/DLT and Go/DLT drafts
# may cite cargo/go/mise test transcripts captured in the draft.
# Medium/Low drafts get advisory warnings only — no block.
echo ""
echo "  22. Fork-replay artifact validation (PR 102)..."
# Extract cited fork_replay/* refs, same regex discipline as
# tools/submission-packager.py:FORK_REPLAY_REF_PATTERN. Reject absolute
# paths and `..` traversal. Resolve strictly under <ws>/fork_replay/.
FR_REFS=$(python3 - "$SUB" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
pat = re.compile(
    "(?:^|[\\s(\x60\"'\\[<])"
    r"(?P<rel>(?:<poc-dir>/|workspace/|./|)?fork_replay/[A-Za-z0-9_./-]+"
    r"(?:_manifest\.json|_deltas\.json|_replay\.yaml))"
)
seen = []
for m in pat.finditer(text):
    rel = m.group("rel").strip()
    for prefix in ("<poc-dir>/", "workspace/", "./"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
    if not rel or not rel.startswith("fork_replay/"):
        continue
    if rel in seen:
        continue
    seen.append(rel)
print("\n".join(seen))
PY
)

# Codex capv3-iter1 T2 (roadmap #1): if the draft body has
# `**Claimed victim:** 0x...`, `**Claimed attacker:** 0x...`, and/or
# `**Claimed protocol:** 0x...` markers, extract them. When any marker is
# present, Check #22 additionally enforces that each cited manifest's
# assertions include at least one PASS that references one of those
# actors — preventing "unrelated_addr gains Y" from being counted as
# proof of the claimed economic impact.
_FR_CLAIMS_JSON=$(python3 - "$SUB" <<'PY'
import json
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
claims = {}
# Tolerant matcher: `**Claimed victim:**`, `**Claimed Victim :**`, tolerates
# optional backticks around the address and optional bold/italic on the label.
pat = re.compile(
    r"\*{1,2}\s*claimed\s+(victim|attacker|protocol)\s*:?\s*\*{1,2}\s*:?\s*"
    r"[`\"']?(0x[0-9a-fA-F]{40})[`\"']?",
    re.IGNORECASE,
)
for m in pat.finditer(text):
    role = m.group(1).lower()
    addr = m.group(2).lower()
    claims.setdefault(role, addr)

# Optional direction / min_magnitude markers. Unset → not included.
dir_pat = re.compile(
    r"\*{1,2}\s*claimed\s+direction\s*:?\s*\*{1,2}\s*:?\s*(gain|loss)",
    re.IGNORECASE,
)
dm = dir_pat.search(text)
if dm:
    claims["direction"] = dm.group(1).lower()
mag_pat = re.compile(
    r"\*{1,2}\s*claimed\s+min[_\s]?magnitude\s*:?\s*\*{1,2}\s*:?\s*"
    r"[`\"']?(-?\d+)[`\"']?",
    re.IGNORECASE,
)
mm = mag_pat.search(text)
if mm:
    claims["min_magnitude"] = mm.group(1)

# Only emit if at least one actor role was found.
if any(k in claims for k in ("victim", "attacker", "protocol")):
    print(json.dumps(claims, sort_keys=True))
else:
    print("")
PY
)

# Source-only justification phrases (explicit, narrow — must name fork replay).
_is_source_only_justified() {
    grep -iqE 'source[- ]only|fork[- ]?replay is not applicable|no fork[- ]?replay required|fork[- ]?replay not required|economic replay not applicable' "$SUB"
}

_FR_SEV_HIGH=0
_FR_SEV_UPPER=$(printf '%s' "$SEVERITY" | tr '[:lower:]' '[:upper:]')
if [ "$_FR_SEV_UPPER" = "HIGH" ] || [ "$_FR_SEV_UPPER" = "CRITICAL" ]; then
    _FR_SEV_HIGH=1
fi

if [ -z "$FR_REFS" ]; then
    # No explicit citations. Codex PR-102 blockers 1+2:
    #   - High+ MUST either cite a successful fork_replay/* artifact OR
    #     (a) explicitly claim source-only justification, AND
    #     (b) have at least one source-level PoC that PASSED under check #10
    #     (POC_TEST_ANY_PASSED). A bare `.t.sol` text reference is NOT
    #     enough — check #10 is the ground-truth signal.
    #   - If High+ offers neither an artifact nor a source-only claim,
    #     hard-fail. Previously this printed a green advisory.
    if [ "$_FR_SEV_HIGH" -eq 1 ]; then
        if _is_source_only_justified; then
            # Codex PR-102 re-review hardening: the previous commit added a
            # PRE_SUBMIT_POC_PASS_OVERRIDE=1 env hatch so offline tests could
            # exercise the source-only green path without a real forge run.
            # Codex correctly flagged that as a real attack surface — if the
            # var leaks into any operator shell (.envrc, ~/.zshrc, CI
            # config), a High+ draft with a nonexistent PoC earns a green
            # Check #22. Override removed. Tests now exercise the real
            # check #10 path by shimming a fake `forge` on PATH; see
            # tools/tests/test_pre_submit_fork_replay.py::_stub_forge_env.
            if [ "${POC_TEST_ANY_PASSED:-0}" -eq 1 ]; then
                echo "  ✅ 22. No fork-replay cited; source-only High+ justified with PASSING Forge PoC (check #10)"
            elif [ "${RUST_POC_ANY_PASSED:-0}" -eq 1 ]; then
                echo "  ✅ 22. No fork-replay cited; source-only High+ justified with PASSING Rust cargo-test PoC transcript (check #10)"
            elif [ "${GO_POC_ANY_PASSED:-0}" -eq 1 ]; then
                echo "  ✅ 22. No fork-replay cited; source-only High+ justified with PASSING Go test PoC transcript (check #10)"
            elif [ "${JS_POC_ANY_PASSED:-0}" -eq 1 ]; then
                echo "  ✅ 22. No fork-replay cited; source-only High+ justified with PASSING Node node:test PoC transcript (check #10)"
            elif [ "${OSCRIPT_POC_ANY_PASSED:-0}" -eq 1 ]; then
                echo "  ✅ 22. No fork-replay cited; source-only High+ justified with PASSING Oscript/AA aa-testkit PoC transcript (check #10)"
            elif [ "${POC_TEST_ANY_FAILED:-0}" -eq 1 ]; then
                echo "  ❌ 22. High+ claims source-only but Forge PoC (check #10) FAILED"
                echo "       Source-only High+ requires a PASSING PoC — fix the PoC or cite a fork replay."
                fails=$((fails + 1))
            elif [ "${POC_TEST_RAN:-0}" -eq 0 ] && [ -n "${POC_REF:-}" ]; then
                echo "  ❌ 22. High+ claims source-only and references *.t.sol ($POC_REF) but check #10 did not run the test"
                echo "       Source-only High+ requires check #10 to EXECUTE the PoC and report PASS."
                echo "       Common causes: file not found under workspace, no foundry.toml discovered, forge missing."
                fails=$((fails + 1))
            else
                echo "  ❌ 22. High+ claims source-only but no passing source-level PoC was recognized (Forge *.t.sol, Rust cargo-test, Go test, or Node node:test)"
                echo "       Source-only High+ requires BOTH an explicit 'source-only' statement"
                echo "       AND a Forge PoC (*.t.sol), Rust cargo-test proof, Go test proof, or Node node:test proof that PASSES under check #10."
                fails=$((fails + 1))
            fi
        else
            echo "  ❌ 22. High+ draft has no fork_replay/* citation AND no source-only justification"
            echo "       High/Critical drafts MUST either:"
            echo "         1. Cite a passing fork_replay/*_{manifest,deltas,replay}.{json,yaml}, or"
            echo "         2. Explicitly state 'source-only justification' / 'fork replay not applicable'"
            echo "            AND include a PASSING source-level PoC under check #10."
            fails=$((fails + 1))
        fi
    else
        echo "  ✅ 22. No explicit fork_replay/* citations — advisory only for ${SEVERITY:-Low}"
    fi
else
    # One or more explicit citations. Resolve each strictly under <ws>/fork_replay/.
    _FR_MISSING=""
    _FR_MALFORMED=""
    _FR_OK=""
    if [ -z "${_WS:-}" ]; then
        # Walk up from SUB to locate workspace root (has fork_replay/).
        _fr_cur=$(cd "$(dirname "$SUB")" && pwd)
        _FR_WS=""
        while [ "$_fr_cur" != "/" ] && [ -n "$_fr_cur" ]; do
            if [ -d "$_fr_cur/fork_replay" ] || [ -f "$_fr_cur/OOS_CHECKLIST.md" ] || [ -f "$_fr_cur/SCOPE.md" ]; then
                _FR_WS="$_fr_cur"; break
            fi
            _fr_cur=$(dirname "$_fr_cur")
        done
    else
        _FR_WS="$_WS"
    fi

    if [ -z "$_FR_WS" ]; then
        if [ "$_FR_SEV_HIGH" -eq 1 ]; then
            echo "  ❌ 22. Draft cites fork_replay/* but workspace root could not be resolved"
            fails=$((fails + 1))
        else
            echo "  ⚠️  22. Draft cites fork_replay/* but workspace root could not be resolved (advisory, ${SEVERITY:-Low})"
            warns=$((warns + 1))
        fi
    else
        # Codex PR-102 blocker 3: "JSON parses" is not enough. Validate
        # manifest.status ∈ {executed, success}, pinned integer `block` and
        # `fork_block`, and a non-empty `assertions` array with at least one
        # PASS and no FAIL/INCONCLUSIVE. fork-replay-assert.py already
        # guarantees INCONCLUSIVE-on-failed-replay (blocker 5); here we
        # additionally require *semantic* proof the replay is real.
        _FR_INVALID=""    # semantic problems (bad status / missing pins / FAIL assert)
        _FR_TMP_INVALID=$(mktemp 2>/dev/null || echo "/tmp/fr_invalid_$$.log")
        : > "$_FR_TMP_INVALID"
        while IFS= read -r rel; do
            [ -z "$rel" ] && continue
            # Reject traversal / absolute paths at the bash layer too.
            case "$rel" in
                /*|*..*) _FR_MISSING="$_FR_MISSING $rel"; continue ;;
            esac
            candidate="$_FR_WS/$rel"
            if [ ! -f "$candidate" ]; then
                _FR_MISSING="$_FR_MISSING $rel"
                continue
            fi
            case "$rel" in
                *_manifest.json)
                    if ! python3 -c "import json,sys; json.loads(open(sys.argv[1]).read())" "$candidate" >/dev/null 2>&1; then
                        _FR_MALFORMED="$_FR_MALFORMED $rel"
                        continue
                    fi
                    # Semantic validation — manifest.status + pinned blocks + assertions.
                    _FR_VALIDATION=$(FR_CLAIMS_JSON="$_FR_CLAIMS_JSON" python3 - "$candidate" <<'PYVAL'
import json
import os
import re
import sys
path = sys.argv[1]
try:
    payload = json.loads(open(path).read())
except Exception as exc:
    print(f"load-error:{exc}")
    sys.exit(0)
if not isinstance(payload, dict):
    print("manifest-root-not-object")
    sys.exit(0)
status = payload.get("status")
if str(status).lower() not in {"executed", "success"}:
    print(f"status-not-successful:{status!r}")
    sys.exit(0)
for key in ("block", "fork_block"):
    val = payload.get(key)
    if val is None:
        print(f"missing-pin:{key}")
        sys.exit(0)
    try:
        iv = int(val)
        if iv <= 0:
            print(f"non-positive-pin:{key}={val!r}")
            sys.exit(0)
    except (TypeError, ValueError):
        print(f"non-integer-pin:{key}={val!r}")
        sys.exit(0)
# Codex PR-102 re-review blocker: the previous rule was
#   "if `assertions` is present, require at least one PASS and no FAILs."
# That left a green path for manifests with NO `assertions` key at all —
# a High+ draft could cite a manifest that replayed a tx but never asserted
# any economic delta. Tighten: require `assertions` to be a non-empty list
# with at least one PASS and zero FAIL/INCONCLUSIVE. Medium/Low drafts are
# downgraded to advisory at the bash layer (severity is not in scope here).
asserts = payload.get("assertions")
if asserts is None:
    print("assertions-missing")
    sys.exit(0)
if not isinstance(asserts, list):
    print("assertions-not-list")
    sys.exit(0)
if not asserts:
    print("assertions-empty")
    sys.exit(0)
for a in asserts:
    if not isinstance(a, dict):
        continue
    st = str(a.get("status") or "").upper()
    if st == "FAIL":
        print("assertion-FAIL-present")
        sys.exit(0)
    if st == "INCONCLUSIVE":
        print("assertion-INCONCLUSIVE-present")
        sys.exit(0)
if not any(
    (isinstance(a, dict) and str(a.get("status") or "").upper() == "PASS") for a in asserts
):
    print("no-assertion-PASS")
    sys.exit(0)

# Codex capv3-iter1 T2 (roadmap #1): if the draft declared claimed actors
# via `**Claimed victim/attacker/protocol:** 0x...` markers, require at
# least one PASS assertion to reference one of those addresses. Otherwise
# the replay could "prove" an unrelated delta and still earn green. The
# claim addresses are passed in via FR_CLAIMS_JSON env (same-commit bash
# layer extraction). Addresses are compared case-insensitively.
#
# Codex PR-104 re-review FIX-7A (iter-v3-7 T1 follow-up): a High draft with
# NO markdown `**Claimed victim/attacker/protocol:**` markers could still
# cite a manifest that itself persisted `draft_claims` (e.g. produced by a
# fork-replay runner that echoes the original spec). Without a markdown-
# marker pathway, the gate above never fired and Check #22 printed green
# even when the sole PASS assertion was `impact_bound:false`. The spec:
#   1. Prefer markdown claims if present (keeps pre-existing contracts).
#   2. Otherwise fall back to manifest `draft_claims` for the gate trigger.
#   3. For the per-assertion decision, trust a persisted `impact_bound:true`
#      when present (strongest signal — fork-replay-assert.py computed it
#      with the canonical FIX-3/FIX-6 semantics).
#   4. When `impact_bound` is absent, recompute here using the same
#      actor-extraction shape (native: / erc20:<token>:<holder> / matched_row
#      holder+address only). `<token>` is never an actor.
claims_json = os.environ.get("FR_CLAIMS_JSON", "").strip()
claim_addrs = set()
if claims_json:
    try:
        claims = json.loads(claims_json)
    except Exception:
        claims = {}
    for role in ("victim", "attacker", "protocol"):
        v = claims.get(role)
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            claim_addrs.add(v.lower())
# FIX-7A: manifest-layer fallback. Only consulted when the markdown layer
# did not supply any actor addresses, so the markdown path remains
# authoritative whenever it is populated.
if not claim_addrs:
    mc = payload.get("draft_claims")
    if isinstance(mc, dict):
        for role in ("victim", "attacker", "protocol"):
            v = mc.get(role)
            if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
                claim_addrs.add(v.lower())
if claim_addrs:
    # Reuse the same address-extraction shape as
    # tools/fork-replay-assert.py:selector_addresses().
    _hex_re = re.compile(r"^0x[0-9a-fA-F]{40}$")
    def _addrs(a):
        sel = a.get("selector") or ""
        out = []
        if sel.startswith("native:"):
            x = sel[len("native:"):]
            if _hex_re.match(x):
                out.append(x.lower())
        elif sel.startswith("erc20:"):
            rest = sel[len("erc20:"):]
            if ":" in rest:
                # Codex PR-104 re-review blocker: the ERC20 key form is
                # `erc20:<token>:<holder>`. Only `<holder>` is an actor
                # candidate — `<token>` is the ERC20 contract, not an
                # actor. See tools/fork-replay-assert.py:selector_addresses
                # for the canonical fix this mirrors.
                _tok, hold = rest.split(":", 1)
                if _hex_re.match(hold):
                    out.append(hold.lower())
        row = a.get("matched_row") or {}
        # `token` intentionally omitted from the actor-address list:
        # a targeted_watches row's `token` names the ERC20 contract,
        # not an actor. Only `holder` / `address` can be bound to a
        # claimed actor.
        for key in ("holder", "address"):
            val = row.get(key)
            if isinstance(val, str) and _hex_re.match(val):
                out.append(val.lower())
        return out
    def _is_bound(a):
        # FIX-7A step 5: trust persisted `impact_bound:true` as the
        # strongest signal — the replay runner already computed it with
        # the canonical FIX-3/FIX-6 actor semantics.
        ib = a.get("impact_bound")
        if ib is True:
            return True
        if ib is False:
            # Do NOT recompute when the runner explicitly said False —
            # honour the stronger signal so a mis-shaped selector cannot
            # sneak past by accident.
            return False
        # FIX-7A step 6: no persisted signal → recompute locally with the
        # iter-v3-4 FIX-3 + iter-v3-5 FIX-6 role-distinction semantics.
        return any(x in claim_addrs for x in _addrs(a))
    has_bound_pass = any(
        isinstance(a, dict)
        and str(a.get("status") or "").upper() == "PASS"
        and _is_bound(a)
        for a in asserts
    )
    if not has_bound_pass:
        print("assertion-not-impact-bound")
        sys.exit(0)
print("OK")
PYVAL
)
                    if [ "$_FR_VALIDATION" != "OK" ]; then
                        _FR_INVALID="$_FR_INVALID $rel($_FR_VALIDATION)"
                        echo "$rel: $_FR_VALIDATION" >> "$_FR_TMP_INVALID"
                        continue
                    fi
                    ;;
                *_deltas.json|*_replay.yaml)
                    if [ "${rel%_deltas.json}" != "$rel" ]; then
                        if ! python3 -c "import json,sys; json.loads(open(sys.argv[1]).read())" "$candidate" >/dev/null 2>&1; then
                            _FR_MALFORMED="$_FR_MALFORMED $rel"
                            continue
                        fi
                        _FR_STEM="${candidate%_deltas.json}"
                    else
                        _FR_STEM="${candidate%_replay.yaml}"
                    fi
                    # Codex PR-102 blocker 6 + follow-up: when only a deltas
                    # file or YAML replay summary is cited, locate the sibling
                    # manifest by stem and run the same semantic check on it.
                    _FR_SIBLING_MANIFEST="${_FR_STEM}_manifest.json"
                    if [ -f "$_FR_SIBLING_MANIFEST" ]; then
                        _FR_VALIDATION=$(FR_CLAIMS_JSON="$_FR_CLAIMS_JSON" python3 - "$_FR_SIBLING_MANIFEST" <<'PYVAL'
import json
import os
import re
import sys
path = sys.argv[1]
try:
    payload = json.loads(open(path).read())
except Exception as exc:
    print(f"load-error:{exc}")
    sys.exit(0)
if not isinstance(payload, dict):
    print("manifest-root-not-object")
    sys.exit(0)
status = payload.get("status")
if str(status).lower() not in {"executed", "success"}:
    print(f"status-not-successful:{status!r}")
    sys.exit(0)
for key in ("block", "fork_block"):
    val = payload.get(key)
    if val is None:
        print(f"missing-pin:{key}")
        sys.exit(0)
    try:
        iv = int(val)
        if iv <= 0:
            print(f"non-positive-pin:{key}={val!r}")
            sys.exit(0)
    except (TypeError, ValueError):
        print(f"non-integer-pin:{key}={val!r}")
        sys.exit(0)
# Codex PR-102 re-review blocker: the previous rule was
#   "if `assertions` is present, require at least one PASS and no FAILs."
# That left a green path for manifests with NO `assertions` key at all —
# a High+ draft could cite a manifest that replayed a tx but never asserted
# any economic delta. Tighten: require `assertions` to be a non-empty list
# with at least one PASS and zero FAIL/INCONCLUSIVE. Medium/Low drafts are
# downgraded to advisory at the bash layer (severity is not in scope here).
asserts = payload.get("assertions")
if asserts is None:
    print("assertions-missing")
    sys.exit(0)
if not isinstance(asserts, list):
    print("assertions-not-list")
    sys.exit(0)
if not asserts:
    print("assertions-empty")
    sys.exit(0)
for a in asserts:
    if not isinstance(a, dict):
        continue
    st = str(a.get("status") or "").upper()
    if st == "FAIL":
        print("assertion-FAIL-present")
        sys.exit(0)
    if st == "INCONCLUSIVE":
        print("assertion-INCONCLUSIVE-present")
        sys.exit(0)
if not any(
    (isinstance(a, dict) and str(a.get("status") or "").upper() == "PASS") for a in asserts
):
    print("no-assertion-PASS")
    sys.exit(0)

# Codex capv3-iter1 T2 (roadmap #1): sibling-manifest path mirrors the
# primary-manifest block above — same impact-bound gate, same compact
# `assertion-not-impact-bound` error code. See that block for rationale.
#
# Codex PR-104 re-review FIX-7A (iter-v3-7 T1 follow-up): mirror the
# primary-manifest block's manifest-layer draft_claims fallback + persisted
# `impact_bound` trust. Keeps the two heredocs in lock-step — see the
# primary block above for the narrative comment.
claims_json = os.environ.get("FR_CLAIMS_JSON", "").strip()
claim_addrs = set()
if claims_json:
    try:
        claims = json.loads(claims_json)
    except Exception:
        claims = {}
    for role in ("victim", "attacker", "protocol"):
        v = claims.get(role)
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            claim_addrs.add(v.lower())
# FIX-7A: manifest-layer fallback — see primary block for rationale.
if not claim_addrs:
    mc = payload.get("draft_claims")
    if isinstance(mc, dict):
        for role in ("victim", "attacker", "protocol"):
            v = mc.get(role)
            if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
                claim_addrs.add(v.lower())
if claim_addrs:
    _hex_re = re.compile(r"^0x[0-9a-fA-F]{40}$")
    def _addrs(a):
        sel = a.get("selector") or ""
        out = []
        if sel.startswith("native:"):
            x = sel[len("native:"):]
            if _hex_re.match(x):
                out.append(x.lower())
        elif sel.startswith("erc20:"):
            rest = sel[len("erc20:"):]
            if ":" in rest:
                # Codex PR-104 re-review blocker: the ERC20 key form is
                # `erc20:<token>:<holder>`. Only `<holder>` is an actor
                # candidate — `<token>` is the ERC20 contract, not an
                # actor. See tools/fork-replay-assert.py:selector_addresses
                # for the canonical fix this mirrors.
                _tok, hold = rest.split(":", 1)
                if _hex_re.match(hold):
                    out.append(hold.lower())
        row = a.get("matched_row") or {}
        # `token` intentionally omitted from the actor-address list:
        # a targeted_watches row's `token` names the ERC20 contract,
        # not an actor. Only `holder` / `address` can be bound to a
        # claimed actor.
        for key in ("holder", "address"):
            val = row.get(key)
            if isinstance(val, str) and _hex_re.match(val):
                out.append(val.lower())
        return out
    def _is_bound(a):
        # FIX-7A: trust persisted impact_bound (True/False) before
        # recomputing with the canonical FIX-3/FIX-6 semantics.
        ib = a.get("impact_bound")
        if ib is True:
            return True
        if ib is False:
            return False
        return any(x in claim_addrs for x in _addrs(a))
    has_bound_pass = any(
        isinstance(a, dict)
        and str(a.get("status") or "").upper() == "PASS"
        and _is_bound(a)
        for a in asserts
    )
    if not has_bound_pass:
        print("assertion-not-impact-bound")
        sys.exit(0)
print("OK")
PYVAL
)
                        if [ "$_FR_VALIDATION" != "OK" ]; then
                            _FR_INVALID="$_FR_INVALID $rel(sibling-manifest:$_FR_VALIDATION)"
                            echo "$rel (sibling manifest): $_FR_VALIDATION" >> "$_FR_TMP_INVALID"
                            continue
                        fi
                    else
                        # Deltas without any sibling manifest — we cannot
                        # verify the replay actually executed. Treat as
                        # invalid for High+ so a reviewer cannot rely on
                        # deltas that may have been hand-edited.
                        _FR_INVALID="$_FR_INVALID $rel(no-sibling-manifest)"
                        echo "$rel: no sibling ${_FR_STEM##*/}_manifest.json" >> "$_FR_TMP_INVALID"
                        continue
                    fi
                    ;;
            esac
            _FR_OK="$_FR_OK $rel"
        done <<FR_EOF
$FR_REFS
FR_EOF

        if [ -n "$_FR_MISSING" ] || [ -n "$_FR_MALFORMED" ] || [ -n "$_FR_INVALID" ]; then
            if [ "$_FR_SEV_HIGH" -eq 1 ]; then
                # Keep legacy "fork replay deltas not found" substring for
                # backwards compat with existing test matchers and runbooks,
                # alongside the more accurate "artifacts" wording.
                [ -n "$_FR_MISSING" ] && echo "  ❌ 22. High+ fork replay deltas not found (artifacts missing on disk):$_FR_MISSING"
                [ -n "$_FR_MALFORMED" ] && echo "  ❌ 22. High+ fork replay artifacts failed to parse (not valid JSON):$_FR_MALFORMED"
                if [ -n "$_FR_INVALID" ]; then
                    # Inline the compact `rel(reason)` list on the 22-line so
                    # automated matchers (test harness, CI log greps) see the
                    # failure reason without needing multi-line parsing.
                    echo "  ❌ 22. High+ fork replay artifacts failed semantic validation:$_FR_INVALID"
                    echo "       Required: manifest.status ∈ {executed, success}, positive int"
                    echo "       block+fork_block, a non-empty assertions array, at least one PASS,"
                    echo "       and no FAIL/INCONCLUSIVE. If the draft declares"
                    echo "       **Claimed victim/attacker/protocol:** markers, at least one PASS"
                    echo "       assertion must reference one of those addresses (error code"
                    echo "       'assertion-not-impact-bound'; Codex capv3-iter1 T2 / roadmap #1)."
                    echo "       Re-run tools/fork-replay.sh and tools/fork-replay-assert.py --draft-claims."
                fi
                fails=$((fails + 1))
            else
                [ -n "$_FR_MISSING" ] && echo "  ⚠️  22. ${SEVERITY:-Low} fork replay deltas not found (advisory):$_FR_MISSING"
                [ -n "$_FR_MALFORMED" ] && echo "  ⚠️  22. ${SEVERITY:-Low} fork replay artifacts failed to parse (advisory):$_FR_MALFORMED"
                [ -n "$_FR_INVALID" ] && echo "  ⚠️  22. ${SEVERITY:-Low} fork replay artifacts failed semantic validation (advisory):$_FR_INVALID"
                warns=$((warns + 1))
            fi
        else
            echo "  ✅ 22. All cited fork_replay artifacts exist, parse, and pass semantic validation:$_FR_OK"
        fi
        rm -f "$_FR_TMP_INVALID"
    fi
fi

# --- Check 23: Scope-reasoner OOS advisory/block (capv3 iter-003 T3) ---
# Runs tools/scope-reasoner.py against the submission, then gates on the
# resulting risk_level. Introduces a three-value status vocabulary:
#   in_scope      — reasoner found no OOS pattern hits (silent pass).
#   likely_oos    — reasoner fired ≥1 OOS pattern match after rebuttal-
#                   boilerplate stripping. Warned or blocked per mode.
#   cannot_judge  — no pattern hits AND no SCOPE.md resolvable from the
#                   draft. Always passes advisory (never blocks).
# Mode is controlled by SCOPE_REASONER_FAIL_MODE ∈ {warn, block}; default
# is `warn` (non-blocking advisory) so this gate can ship behind a flag
# without breaking existing flows. `block` turns `likely_oos` into a hard
# fail with the compact failure code `scope-reasoner-likely-oos`.
#
# Rebuttal-boilerplate stripping (FP-prevention): drafts produced by the
# capv3 factory (e.g. agent_outputs/capv3_iter1_T5_factory_R67-F002.md)
# include a pre-emptive "Likely triager pushback: OOS cross-chain
# atomicity. Pre-emptive response: ..." block that mentions the OOS
# territory purely to rebut it, not to claim impact.
#
# Fix (Codex PR#104 bug #5): the stripper now ONLY drops lines wrapped
# between explicit HTML-comment markers `<!-- rebuttal:start -->` /
# `<!-- rebuttal:end -->`. The factory emits the markers around its
# rebuttal block. Legacy drafts without markers are passed through
# unchanged — they lose the FP-prevention benefit but gain semantic
# integrity: any substantive claim line stays visible to the reasoner,
# so a draft cannot bypass Check #23 by writing a real OOS claim on the
# line after "Pre-emptive response:".
#
# This check is non-destructive against the draft and the workspace.
# All temp artefacts go to `mktemp` paths and are cleaned up in-place
# via `rm -rf` on the scratch dir only. (The plan ships a hard-negative
# grep over this region; keeping that grep green is enforced by CI.)
echo ""
echo "  23. Scope-reasoner OOS gate (SCOPE_REASONER_FAIL_MODE=${SCOPE_REASONER_FAIL_MODE:-warn})..."
if [ ! -f "$AUDITOOOR_DIR/tools/scope-reasoner.py" ]; then
    echo "  ⚠️  23. tools/scope-reasoner.py not found — skipping (cannot_judge)"
    warns=$((warns + 1))
else
    _SR_MODE="${SCOPE_REASONER_FAIL_MODE:-warn}"
    case "$_SR_MODE" in
        warn|block) : ;;
        *)
            echo "  ⚠️  23. Unknown SCOPE_REASONER_FAIL_MODE='$_SR_MODE' — defaulting to warn"
            _SR_MODE="warn"
            ;;
    esac

    # Severity gate: advisory for Low / unset, evaluated for Medium+ and
    # always printed for High+. Keep semantics consistent with the rest of
    # the pre-submit: High+ is where the meaningful gating lives. For now
    # run the reasoner on every severity so the warn-mode signal is
    # always visible; only the block-mode hard-fail fires at High+.
    _SR_SEV_HIGH=0
    case "${SEVERITY:-}" in
        High|high|HIGH|Critical|critical|CRITICAL) _SR_SEV_HIGH=1 ;;
    esac

    # Resolve the workspace SCOPE.md path up front (Codex PR#104 bug #3).
    # The reasoner's default walk-upward starts from the draft path it is
    # given; since we feed it a stripped tmp copy under $_SR_TMPDIR, its
    # walk never reaches the real workspace. We resolve the scope path
    # here using the same heuristic as Check #11 and pass it explicitly
    # via --scope.
    _SR_SUB_ABS=$(cd "$(dirname "$SUB")" && pwd)
    _SR_WS=""
    _sr_cur="$_SR_SUB_ABS"
    while [ "$_sr_cur" != "/" ] && [ -n "$_sr_cur" ]; do
        if [ -f "$_sr_cur/SCOPE.md" ]; then
            _SR_WS="$_sr_cur"; break
        fi
        _sr_cur=$(dirname "$_sr_cur")
    done
    _SR_SCOPE_ARGS=""
    if [ -n "$_SR_WS" ]; then
        _SR_SCOPE_ARGS="--scope $_SR_WS/SCOPE.md"
    fi

    # Build a stripped tmp copy of the draft that omits rebuttal blocks
    # wrapped in explicit `<!-- rebuttal:start -->` / `<!-- rebuttal:end -->`
    # markers (Codex PR#104 bug #5). Legacy drafts without markers pass
    # through unchanged — the stripper no longer silently drops any line
    # merely because it sits after `Pre-emptive response:`.
    _SR_TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'scope-reasoner')
    _SR_STRIPPED="$_SR_TMPDIR/stripped.md"
    python3 - "$SUB" "$_SR_STRIPPED" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

START = "<!-- rebuttal:start -->"
END = "<!-- rebuttal:end -->"

lines = src.read_text(errors="replace").splitlines(keepends=True)
out = []
inside = False
for line in lines:
    stripped = line.strip()
    if not inside and stripped == START:
        inside = True
        continue
    if inside and stripped == END:
        inside = False
        continue
    if inside:
        continue
    out.append(line)

dst.write_text("".join(out))
PY

    _SR_JSON="$_SR_TMPDIR/scope_reasoner.json"
    # shellcheck disable=SC2086
    if python3 "$AUDITOOOR_DIR/tools/scope-reasoner.py" --draft "$_SR_STRIPPED" $_SR_SCOPE_ARGS >"$_SR_JSON" 2>/dev/null; then
        _SR_STATUS=$(python3 - "$_SR_JSON" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
flags = data.get("flags") or []
scope_file = (data.get("scope_file") or "").strip()
risk_level = (data.get("risk_level") or "none").strip()

# Translate the reasoner's internal vocabulary
# {none, advisory, likely-OOS} into Check #23's three-value vocabulary
# {in_scope, likely_oos, cannot_judge}.
#
# Codex PR#104 bug #4: do NOT collapse every pattern hit into
# `likely_oos`. Respect the reasoner's risk ladder — `likely-OOS` only
# when at least one flag's `scope_clause_hit` is true (i.e. the draft
# mentions OOS territory AND SCOPE.md enumerates that territory).
# Plain `advisory` fires (pattern matched but no SCOPE.md overlap)
# emit a warn-level advisory only — never a hard-fail in block mode.
if risk_level == "likely-OOS":
    # Prefer the first flag with scope_clause_hit=True for reporting.
    top = next((f for f in flags if f.get("scope_clause_hit")), flags[0] if flags else {})
    status = "likely_oos"
    pattern_name = top.get("pattern_name", "unknown")
elif risk_level == "advisory":
    # Pattern fired but no SCOPE.md clause overlap — advisory nudge,
    # not a gate hit.
    top = flags[0] if flags else {}
    status = "advisory"
    pattern_name = top.get("pattern_name", "unknown")
else:
    # risk_level == "none" (no flags at all).
    if scope_file:
        status = "in_scope"
        pattern_name = ""
    else:
        status = "cannot_judge"
        pattern_name = ""

print(f"{status}\t{pattern_name}")
PY
)
        _SR_CODE=$(printf '%s' "$_SR_STATUS" | cut -f1)
        _SR_PAT=$(printf '%s' "$_SR_STATUS" | cut -f2)

        case "$_SR_CODE" in
            in_scope)
                echo "  ✅ 23. scope-reasoner: in_scope"
                ;;
            cannot_judge)
                echo "  ✅ 23. scope-reasoner: cannot_judge (no SCOPE.md resolvable — advisory log only)"
                ;;
            advisory)
                # Pattern hit without SCOPE.md overlap — nudge, not a gate.
                echo "  ⚠️  23. ADVISORY: scope-reasoner pattern $_SR_PAT hit without SCOPE.md clause overlap (advisory only)"
                warns=$((warns + 1))
                ;;
            likely_oos)
                if [ "$_SR_MODE" = "block" ] && [ "$_SR_SEV_HIGH" -eq 1 ]; then
                    echo "  ❌ 23. scope-reasoner-likely-oos: $SUB pattern=$_SR_PAT (SCOPE_REASONER_FAIL_MODE=block)"
                    fails=$((fails + 1))
                elif [ "$_SR_MODE" = "block" ]; then
                    # block mode but sub-High: still a hard-fail so the
                    # gate fires on any severity. Operators opting into
                    # block mode opt into the strict semantics.
                    echo "  ❌ 23. scope-reasoner-likely-oos: $SUB pattern=$_SR_PAT (SCOPE_REASONER_FAIL_MODE=block)"
                    fails=$((fails + 1))
                else
                    echo "  ⚠️  23. WARN: scope-reasoner flagged $SUB as likely_oos:$_SR_PAT"
                    warns=$((warns + 1))
                fi
                ;;
            *)
                echo "  ⚠️  23. scope-reasoner: unexpected status '$_SR_CODE' — treating as advisory"
                warns=$((warns + 1))
                ;;
        esac
    else
        echo "  ⚠️  23. scope-reasoner failed to execute — treating as cannot_judge advisory"
        warns=$((warns + 1))
    fi

    # Clean up tmp artefacts. Only operates on paths under $_SR_TMPDIR,
    # never on the draft or workspace. rm -rf is the only destructive op
    # in this block and it targets a mktemp-created scratch dir.
    rm -rf "$_SR_TMPDIR"
fi

# --- Check 24: Cross-contract staleness operator mismatch (capv3 iter-10 T0) ---
# Advisory grep lock for Base-Azul Cantina T-9/T-10 shape bugs. If a draft
# presents two verifier/registry contracts with the same freshness boundary but
# mixes strict and inclusive operators (`<` with `<=`, or `>` with `>=`) against
# `block.timestamp`, flag it so the operator must prove the boundary semantics
# are intentional and not a duplicate of known prior-audit coverage.
echo ""
echo "  24. Cross-contract staleness operator mismatch advisory..."
_CC_STALE_TMP=$(mktemp 2>/dev/null || mktemp -t 'cc-staleness')
if python3 - "$SUB" >"$_CC_STALE_TMP" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")

contract_re = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*(?:Verifier|Registry|Oracle|Adapter|Module|Manager|Controller))\b"
)
contracts = set(contract_re.findall(text))

timestamp_terms = r"(?:timestamp|attestationTimestamp|createdAt|issuedAt|validUntil|notAfter|expiresAt|verifiedAt)"
age_terms = r"(?:MAX_AGE|MAXAGE|maxAge|max_age|STALE_AFTER|EXPIRY|EXPIRATION|TIMEOUT|timeout)"
left = rf"{timestamp_terms}\s*\+\s*{age_terms}\s*(<=|<)\s*block\.timestamp"
right = rf"block\.timestamp\s*(>=|>)\s*{timestamp_terms}\s*\+\s*{age_terms}"

operators = set(re.findall(left, text))
operators.update(re.findall(right, text))
has_strict = "<" in operators or ">" in operators
has_inclusive = "<=" in operators or ">=" in operators

if len(contracts) >= 2 and has_strict and has_inclusive:
    print("cross_contract_staleness_operator_mismatch\t" + ",".join(sorted(contracts)[:5]))
    raise SystemExit(1)
raise SystemExit(0)
PY
then
    echo "  ✅ 24. cross-contract staleness operators: no strict/inclusive mismatch detected"
else
    _CC_STALE_RESULT=$(cat "$_CC_STALE_TMP")
    echo "  ⚠️  24. cross_contract_staleness_operator_mismatch: $_CC_STALE_RESULT"
    echo "       Review paired freshness-boundary operators across contracts; if intentional,"
    echo "       document why the boundary is not a duplicate of known Base-Azul T-9/T-10 coverage."
    warns=$((warns + 1))
fi
rm -f "$_CC_STALE_TMP"

# --- Check 25: OOS prerequisite / root-cause stress gate ---
# Base Azul FN5 lesson, generalized: proving downstream impact is not enough
# if the missing exploit prerequisite is OOS. High/Critical drafts that mention
# project inaction, privileged actors, compromised signers/provers, off-chain
# infrastructure, mock verifiers, or similar assumptions must explicitly prove
# the in-scope trigger/root cause. Bridge/anchor-drain drafts get one extra
# hard regression: they must prove how the attacker creates the poisoned state,
# not only that Portal/ASR accepts it after it exists.
echo ""
echo "  25. OOS prerequisite / root-cause stress gate..."
_POISON_TMP=$(mktemp 2>/dev/null || mktemp -t 'poisoned-state')
if python3 - "$SUB" "${SEVERITY:-}" >"$_POISON_TMP" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
severity = (sys.argv[2] or "").lower()
lower = text.lower()

sev_match = re.search(r"\bseverity\s*[:|-]\s*(critical|high|medium|low)\b", lower)
file_severity = sev_match.group(1) if sev_match else ""
high_plus = severity in {"high", "critical"} or file_severity in {"high", "critical"}

bridge_terms = re.search(
    r"\b(bridge|portal|optimismportal|withdrawal|l1\s+escrow|anchor\s+state|"
    r"anchorstate|state\s+root|root\s+claim|dispute\s+game)\b",
    lower,
)
impact_terms = re.search(
    r"\b(drain|drains|drained|theft|steal|stealing|invalid\s+withdrawal|"
    r"fraudulent\s+withdrawal|direct\s+loss|direct\s+theft)\b",
    lower,
)
poison_terms = re.search(
    r"\b(poisoned|fraudulent\s+(?:game|root|claim|state)|invalid\s+(?:game|root|claim|state)|"
    r"false\s+(?:root|claim|state)|blacklisted\s+(?:ancestor|parent|game)|"
    r"descendant|defender_wins|mock\s+verifier)\b",
    lower,
)
oos_prereq_terms = re.search(
    r"\b(base\s+won'?t\s+blacklist|will\s+not\s+blacklist|won'?t\s+blacklist|"
    r"project\s+(?:inaction|does\s+not|won'?t|fails\s+to)|guardian|blacklist|"
    r"admin|owner|governance|multisig|operator|oracle\s+operator|sequencer|"
    r"private\s+key|signer\s+compromise|compromised\s+signer|prover\s+compromise|"
    r"compromised\s+prover|colluding\s+prover|tee\s+compromise|zk\s+prover|"
    r"off[-\s]?chain\s+infrastructure|centralization|privileged|trusted\s+role|"
    r"mock\s+verifier|mock\s+oracle|assume[s]?\s+.*(?:blacklist|admin|guardian|prover|signer|operator))\b",
    lower,
)

if not high_plus:
    print("pass\tnot High/Critical")
    raise SystemExit(0)

bridge_poison_case = bool(bridge_terms and impact_terms and poison_terms)
general_oos_case = bool(impact_terms and oos_prereq_terms)

if not bridge_poison_case and not general_oos_case:
    print("pass\tno high/critical OOS-prerequisite pattern")
    raise SystemExit(0)

headings = list(
    re.finditer(
        r"^(?P<hash>#{1,6})\s+(?P<title>.+?)\s*$",
        text,
        re.IGNORECASE | re.MULTILINE,
    )
)

def section_after(match: re.Match[str]) -> str:
    start = match.end()
    next_heading = re.search(r"^#{1,6}\s+", text[start:], re.MULTILINE)
    return text[start:] if not next_heading else text[start:start + next_heading.start()]

def find_section(title_re: str) -> tuple[str, str] | None:
    rx = re.compile(title_re, re.IGNORECASE)
    for h in headings:
        title = h.group("title")
        if rx.search(title):
            return title, section_after(h)
    return None

root_section = find_section(
    r"(?:in[-\s]?scope\s+(?:trigger|root\s+cause|reachability)|"
    r"root\s+cause|reachability|exploit\s+preconditions|"
    r"scope\s+(?:and\s+)?oos|oos\s+(?:and\s+)?scope|"
    r"poisoned\s+state\s+creation\s+path|false\s+root\s+creation\s+path|"
    r"invalid\s+(?:state|root|claim|game)\s+(?:creation|source|path|primitive))"
)

if not root_section:
    if bridge_poison_case:
        print("fail\tmissing section: add '## Poisoned State Creation Path' proving the in-scope false-state root cause")
        raise SystemExit(1)
    print("fail\tmissing section: add '## In-Scope Trigger / Root Cause' explaining why prerequisites are not OOS")
    raise SystemExit(1)

title, section = root_section
title_l = title.lower()
section_l = section.lower()

in_scope_terms = re.search(
    r"\b(in[-\s]?scope|on[-\s]?chain|permissionless|contract\s+bug|source[-\s]?level|"
    r"proof[-\s]?verification|aggregateverifier|journal|domain[-\s]?separation|"
    r"replay|bypass|forg(?:e|ed|ing)|accepted\s+by|root\s+cause|attacker\s+can|"
    r"non[-\s]?privileged|no\s+privileged|without\s+privileged)\b",
    section_l,
)
oos_terms = re.search(
    r"\b(base\s+won'?t\s+blacklist|will\s+not\s+blacklist|won'?t\s+blacklist|"
    r"private\s+key|signer\s+compromise|off[-\s]?chain\s+infrastructure|"
    r"prover\s+compromise|compromised\s+prover|guardian|admin|owner|governance|"
    r"operator|sequencer|centralization|privileged|mock\s+verifier|mock\s+oracle|"
    r"assume[s]?\s+.*(?:blacklist|admin|guardian|prover|signer|operator))\b",
    section_l,
)

if not in_scope_terms:
    print("fail\troot-cause section exists but does not identify an in-scope/non-privileged trigger")
    raise SystemExit(1)

if oos_terms and not re.search(r"\bdoes\s+not\s+rely|not\s+rely|without\s+relying|independent\s+of\b", section_l):
    print("fail\tsection mentions OOS-style prerequisites without an explicit non-reliance statement")
    raise SystemExit(1)

if bridge_poison_case:
    poison_title = re.search(
        r"(?:poisoned|false|invalid).*(?:state|root|claim|game).*(?:creation|source|path|primitive)|"
        r"(?:poisoned|false|invalid).*(?:creation|source|path|primitive).*(?:state|root|claim|game)",
        title_l,
    )
    if not poison_title:
        print("fail\tbridge/anchor drain case needs an explicit poisoned-state creation-path heading")
        raise SystemExit(1)

print("pass\tin-scope prerequisite/root-cause section present")
raise SystemExit(0)
PY
then
    _POISON_RESULT=$(cat "$_POISON_TMP")
    echo "  ✅ 25. OOS prerequisite gate: $_POISON_RESULT"
else
    _POISON_RESULT=$(cat "$_POISON_TMP")
    echo "  ❌ 25. oos-prerequisite-root-cause-missing: $_POISON_RESULT"
    echo "       High/Critical claims must prove the attacker-controlled prerequisite is"
    echo "       in scope before leaning on downstream impact. Project inaction,"
    echo "       privileged actors, compromised signers/provers, off-chain infra, and"
    echo "       mock components are not root-cause proof. For bridge/anchor drain,"
    echo "       explicitly prove how the false accepted state is created in scope."
    fails=$((fails + 1))
fi
rm -f "$_POISON_TMP"

# --- Check 26: Mock-PoC contamination gate (PR #124 / FN-5+FN-6 lesson) ---
# Hard-fail when a High/Critical claim cites a PoC that uses a *suspicious* mock
# (verifier/oracle/portal/registry/proof/signature/messenger/bridge mock,
# hardcoded `returns true`, seeded proof state, or harness-style verification
# shortcut) AND the draft does NOT include a `## Real-Component Precondition`
# section describing what the mock replaces, why reaching the branch is in
# scope, and what severity remains under the real component.
#
# Warning-only for Medium severity. Benign mocks (MockERC20 / MockToken /
# generic MockSystemConfig / bookkeeping harnesses without verification
# shortcuts) do not trigger the gate.
#
# PR #124 Slice 1 extension (Codex 08:45:26Z, Path A): also scan each cited
# PoC test file (*.t.sol / .test.sol / _test.sol). Closes the FN-6 gap where
# the submission .md is "clean" but the cited PoC (e.g. FN6_PoC.t.sol) imports
# `MockVerifier` / `FixedMockVerifier`. Reuses the same suspicious-mock regex
# and severity policy. Missing/unreadable cited paths are reported as a
# separate warning, not a Check #26 hard fail (Check #4/#10 own availability).
echo ""
echo "  26. Mock-PoC contamination gate..."
_MOCK_TMP=$(mktemp 2>/dev/null || mktemp -t 'mock-poc')

# Resolve cited PoC test paths (mirrors Check #10's WS_ROOT walk + find logic).
# Accept *.t.sol, *.test.sol, *_test.sol citations. We resolve in bash (not in
# the Python heredoc) so missing/malformed paths are reported through the
# existing PoC-availability mental model: each cited path becomes either
# `FOUND <abs>` or `MISSING <basename>` in `_MOCK_CITED_LIST`.
_MOCK_POC_REFS=$(grep -oE '[a-zA-Z0-9_/.-]+\.(t|test)\.sol|[a-zA-Z0-9_/.-]+_test\.sol' "$SUB" | sort -u)
_MOCK_CITED_LIST=$(mktemp 2>/dev/null || mktemp -t 'mock-poc-cited')
if [ -n "$_MOCK_POC_REFS" ]; then
    _MOCK_SUB_DIR=$(cd "$(dirname "$SUB")" && pwd)
    _MOCK_WS_ROOT="$_MOCK_SUB_DIR"
    while [ "$_MOCK_WS_ROOT" != "/" ]; do
        if [ -d "$_MOCK_WS_ROOT/poc-tests" ] || [ -f "$_MOCK_WS_ROOT/AUDIT.md" ]; then
            break
        fi
        _MOCK_WS_ROOT=$(dirname "$_MOCK_WS_ROOT")
    done
    [ "$_MOCK_WS_ROOT" = "/" ] && _MOCK_WS_ROOT="$_MOCK_SUB_DIR"
    for _mock_poc in $_MOCK_POC_REFS; do
        # Absolute citation that exists on disk: take it directly. FN-6's
        # draft uses `/Users/wolf/audits/base-azul/...` form; FN-5/FN-B use
        # the relative form.
        if [ "${_mock_poc#/}" != "$_mock_poc" ] && [ -f "$_mock_poc" ]; then
            echo "FOUND $_mock_poc" >> "$_MOCK_CITED_LIST"
            continue
        fi
        _mock_poc_base=$(basename "$_mock_poc")
        _MOCK_PATH=""
        if [ -f "$_MOCK_WS_ROOT/poc-tests/$_mock_poc_base" ]; then
            _MOCK_PATH="$_MOCK_WS_ROOT/poc-tests/$_mock_poc_base"
        else
            # Fallback 1: external/<repo>/test/ pattern (Revert layout)
            _MOCK_PATH=$(find "$_MOCK_WS_ROOT/external" -maxdepth 4 \( -path "*/test/$_mock_poc_base" -o -path "*/contracts/test/$_mock_poc_base" \) -type f 2>/dev/null | head -1)
        fi
        if [ -z "$_MOCK_PATH" ]; then
            # Fallback 2: generic workspace-relative find (bounded depth)
            _MOCK_PATH=$(find "$_MOCK_WS_ROOT" -maxdepth 6 -name "$_mock_poc_base" -type f 2>/dev/null | head -1)
        fi
        if [ -n "$_MOCK_PATH" ] && [ -f "$_MOCK_PATH" ]; then
            echo "FOUND $_MOCK_PATH" >> "$_MOCK_CITED_LIST"
        else
            echo "MISSING $_mock_poc_base" >> "$_MOCK_CITED_LIST"
        fi
    done
fi

_MOCK_WARN_TMP=$(mktemp 2>/dev/null || mktemp -t 'mock-poc-warn')
set +e
python3 - "$SUB" "${SEVERITY:-}" "$_MOCK_CITED_LIST" "$_MOCK_WARN_TMP" >"$_MOCK_TMP" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
severity = (sys.argv[2] or "").lower()
cited_list_path = sys.argv[3] if len(sys.argv) > 3 else ""
warn_path = sys.argv[4] if len(sys.argv) > 4 else ""
lower = text.lower()

# Reuse the Check #25 severity parser pattern: prefer file-declared severity,
# fall back to CLI flag.
sev_match = re.search(r"\bseverity\s*[:|-]\s*(critical|high|medium|low|insight)\b", lower)
file_severity = sev_match.group(1) if sev_match else ""
high_plus = severity in {"high", "critical"} or file_severity in {"high", "critical"}
medium = severity == "medium" or file_severity == "medium"

# --- Suspicious-mock detection ---
# Targeted names per Codex's PR #124 spec — NOT generic Mock*. We deliberately
# exclude MockERC20 / MockToken / MockCounter / generic MockSystemConfig from
# the suspicious set; those are deployment / bookkeeping convenience.
suspicious_name_rx = re.compile(
    r"(?:^|[^A-Za-z0-9])Mock(?:Verifier|Oracle|Portal|Registry|Proof|Signature|"
    r"Messenger|Bridge|DisputeGame)\w*",
)
# PR #124 Slice 1 extension: catch derivative names (`FixedMockVerifier`,
# `StubMockOracle`, `Fake*Portal`, `Fixed*Verifier`, `*MockVerifier`, etc.)
# that wrap or stand in for the same suspicious classes. The Codex spec calls
# these out explicitly: "Plus derivatives: Fixed*Verifier, *MockVerifier, etc."
# We do NOT match `MockSystemConfig` / `MockERC20` here — those are filtered
# by the benign allowlist below.
suspicious_derivative_rx = re.compile(
    r"\b(?:Fixed|Stub|Fake|Dummy|Test|Trivial|Bypass)?"
    r"Mock(?:Verifier|Oracle|Portal|Registry|Proof|Signature|Messenger|Bridge|DisputeGame)\w*"
    r"|"
    r"\b(?:Fixed|Stub|Fake|Dummy|Trivial|Bypass)"
    r"(?:Verifier|Oracle|Portal|Registry|Proof|Signature|Messenger|Bridge|DisputeGame)\w*",
)
# Harness paired with verification-shortcut helpers (seedProvenWithdrawal,
# setResolvedPrice, hardcoded `returns true` inside a Harness contract).
harness_shortcut_rx = re.compile(
    r"\b\w*Harness\w*\b[\s\S]{0,400}?"
    r"(seedProvenWithdrawal|setResolvedPrice|returns\s+true)",
    re.IGNORECASE,
)
# Hardcoded `returns (bool) { return true; }` — verification-shortcut code smell.
hardcoded_true_rx = re.compile(
    r"returns\s*\(\s*bool\s*\)\s*\{[^}]{0,80}return\s+true\s*;",
    re.IGNORECASE,
)
# `pure returns (bool)` on a verify-style function — deterministic-success smell.
pure_verify_rx = re.compile(
    r"\bverify\w*\s*\([^)]*\)\s*(?:external|public|internal|private)?\s*pure\s+"
    r"returns\s*\(\s*bool\s*\)",
    re.IGNORECASE,
)
# Seeded proof state (e.g. provenWithdrawals[hash] = ...).
seeded_proof_rx = re.compile(
    r"\b(?:provenWithdrawals|finalizedWithdrawals|verifiedProofs|"
    r"resolvedPrices|trustedRoots)\s*\[[^\]]+\]\s*=",
    re.IGNORECASE,
)
# Callbacks that shortcut production verification.
callback_shortcut_rx = re.compile(
    r"//[^\n]*(?:bypass|shortcut|skip)[^\n]*verif",
    re.IGNORECASE,
)

# --- Benign-mock allowlist ---
# These names alone (with no suspicious hit) must not trigger the gate.
# Used both to (a) exempt drafts/PoCs that ONLY have benign mocks, and (b) to
# subtract MockSystemConfig / MockERC20 hits from the derivative regex output
# (e.g. "MockSystemConfig" must NOT count as a `Mock*` derivative).
benign_only_rx = re.compile(
    r"(?:^|[^A-Za-z0-9])Mock(?:ERC20|ERC721|ERC1155|Token|Counter|"
    r"SystemConfig|USDC|DAI|WETH)\b",
    re.IGNORECASE,
)


_RX_TABLE = [
    (suspicious_name_rx, "suspicious-mock-name"),
    (suspicious_derivative_rx, "suspicious-mock-derivative"),
    (harness_shortcut_rx, "harness-with-verification-shortcut"),
    (hardcoded_true_rx, "hardcoded-returns-true"),
    (pure_verify_rx, "pure-verify-returns-bool"),
    (seeded_proof_rx, "seeded-proof-state"),
    (callback_shortcut_rx, "callback-shortcut-comment"),
]


def _scan(blob: str) -> list[str]:
    """Run the full suspicious-mock regex bank against a blob.

    Returns the list of distinct labels that hit. The benign allowlist is
    applied per-pattern: if the only matches for `suspicious-mock-name` /
    `suspicious-mock-derivative` would be benign tokens (MockERC20 /
    MockSystemConfig / etc.), those labels are not added.
    """
    hits: list[str] = []
    for rx, label in _RX_TABLE:
        matches = rx.findall(blob)
        if not matches:
            continue
        if label in ("suspicious-mock-name", "suspicious-mock-derivative"):
            # Filter out matches that fall within the benign allowlist.
            non_benign = []
            for m in matches:
                # `findall` returns either str or tuple depending on groups —
                # the derivative regex has a `(?:...)?` non-capturing optional
                # so the result is a str; defensive normalize anyway.
                token = m if isinstance(m, str) else "".join(m)
                if not benign_only_rx.search(token):
                    non_benign.append(token)
            if non_benign:
                hits.append(label)
        else:
            hits.append(label)
    return hits


# --- Source 1: submission .md ---
md_hits = _scan(text)
benign_present = bool(benign_only_rx.search(text))

# --- Source 2: cited PoC test files (PR #124 Slice 1 extension) ---
cited_hits: list[tuple[str, list[str]]] = []  # [(absolute_path, [labels])]
missing_cited: list[str] = []  # basenames that could not be located/read
unreadable_cited: list[str] = []  # absolute paths that exist but failed to decode

if cited_list_path:
    try:
        cited_lines = Path(cited_list_path).read_text(errors="replace").splitlines()
    except OSError:
        cited_lines = []
    _seen_abs: set[str] = set()
    _seen_missing: set[str] = set()
    for line in cited_lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("MISSING "):
            bn = line[len("MISSING "):].strip()
            if bn not in _seen_missing:
                missing_cited.append(bn)
                _seen_missing.add(bn)
            continue
        if line.startswith("FOUND "):
            poc_path = line[len("FOUND "):].strip()
            # Dedupe by resolved absolute path: drafts often cite both an
            # absolute `/Users/.../FN6_PoC.t.sol` and a relative
            # `differential_fuzz/.../FN6_PoC.t.sol` form for the same file.
            try:
                key = str(Path(poc_path).resolve())
            except OSError:
                key = poc_path
            if key in _seen_abs:
                continue
            _seen_abs.add(key)
            try:
                poc_text = Path(poc_path).read_text(errors="replace")
            except OSError:
                unreadable_cited.append(poc_path)
                continue
            local_hits = _scan(poc_text)
            if local_hits:
                cited_hits.append((poc_path, local_hits))


def _emit_warn(msg: str) -> None:
    """Append a side-channel warning visible to the bash wrapper.

    Used for "cited PoC unreadable" / "cited PoC not located" warnings — these
    are NOT mock contamination, but they relate to the cited-PoC scan and the
    user benefits from seeing them adjacent to the gate result. The bash
    wrapper prints these lines as separate warning entries.
    """
    if not warn_path:
        return
    try:
        with open(warn_path, "a", encoding="utf-8") as fh:
            fh.write(msg.rstrip() + "\n")
    except OSError:
        pass


for _bn in missing_cited:
    _emit_warn(
        "cited PoC not located under workspace root: " + _bn
        + " (Check #4/#10 should have flagged this; not Check #26 contamination)"
    )
for _p in unreadable_cited:
    _emit_warn("cited PoC exists but unreadable: " + _p)


# --- Aggregate hits across submission .md and cited PoC files ---
suspicious_hits: list[str] = []
for h in md_hits:
    if h not in suspicious_hits:
        suspicious_hits.append(h)
for _, labels in cited_hits:
    for h in labels:
        if h not in suspicious_hits:
            suspicious_hits.append(h)

if not suspicious_hits:
    if benign_present:
        print("pass\tbenign mock(s) only (ERC20/Token/SystemConfig/Counter)")
    else:
        print("pass\tno suspicious mock pattern detected")
    raise SystemExit(0)

# --- Required section presence (mirrors Check #25 section-presence regex) ---
headings = list(
    re.finditer(
        r"^(?P<hash>#{1,6})\s+(?P<title>.+?)\s*$",
        text,
        re.IGNORECASE | re.MULTILINE,
    )
)


def section_after(match):
    start = match.end()
    next_heading = re.search(r"^#{1,6}\s+", text[start:], re.MULTILINE)
    return text[start:] if not next_heading else text[start:start + next_heading.start()]


def find_section(title_re):
    rx = re.compile(title_re, re.IGNORECASE)
    for h in headings:
        title = h.group("title")
        if rx.search(title):
            return title, section_after(h)
    return None


precond = find_section(r"real[-\s]?component\s+precondition")

severity_label = "high/critical" if high_plus else ("medium" if medium else "low/insight")

if not high_plus and not medium:
    # Low / Insight / no severity asserted — informational pass.
    print("pass\tsuspicious mock present but severity is " + (severity_label or "unspecified"))
    raise SystemExit(0)

def _source_summary() -> str:
    """Return a compact "in [submission|cited PoC: file.t.sol]" string showing
    where the suspicious-mock hits originated. Helps the user know whether to
    edit the .md or the cited PoC."""
    parts: list[str] = []
    if md_hits:
        parts.append("submission .md")
    for poc_path, _labels in cited_hits:
        parts.append("cited PoC: " + Path(poc_path).name)
    if not parts:
        return ""
    return " in " + " + ".join(parts)


if precond is None:
    if high_plus:
        print(
            "fail\tHigh/Critical claim cites suspicious mock(s) ["
            + ", ".join(suspicious_hits[:4])
            + "]"
            + _source_summary()
            + " but is missing required `## Real-Component Precondition` section"
        )
        raise SystemExit(1)
    # Medium → warning, exit code 2 signals warning to bash wrapper.
    print(
        "warn\tMedium claim cites suspicious mock(s) ["
        + ", ".join(suspicious_hits[:4])
        + "]"
        + _source_summary()
        + "; recommend adding `## Real-Component Precondition` section"
    )
    raise SystemExit(2)

# Section is present — sanity-check the three required pieces.
title, section = precond
section_l = section.lower()

replaces_terms = re.search(
    r"\b(replaces?|stands?\s+in\s+for|substitutes?\s+for|in\s+production|"
    r"in\s+the\s+real\s+system|production\s+contract|real\s+component)\b",
    section_l,
)
in_scope_terms = re.search(
    r"\b(in[-\s]?scope|reachab(?:le|ility)|permissionless|on[-\s]?chain|"
    r"does\s+not\s+rely|not\s+rely|without\s+relying|independent\s+of|"
    r"non[-\s]?privileged|no\s+privileged)\b",
    section_l,
)
residual_terms = re.search(
    r"\b(residual\s+severity|severity\s+remains|downgrade[sd]?\s+to|"
    r"remains\s+(?:critical|high|medium|low)|"
    r"if\s+the\s+real\s+(?:component|verifier|oracle|portal)\s+(?:blocks|prevents|rejects))\b",
    section_l,
)

missing = []
if not replaces_terms:
    missing.append("what the mock replaces in production")
if not in_scope_terms:
    missing.append("why reaching the branch is in-scope")
if not residual_terms:
    missing.append("residual severity if the real component blocks reachability")

if missing and high_plus:
    # Section exists but doesn't address all three required pieces → warning,
    # not hard fail. Hard fail is reserved for missing-section case per spec.
    print(
        "warn\tHigh/Critical: `Real-Component Precondition` present but missing: "
        + "; ".join(missing)
    )
    raise SystemExit(2)

print(
    "pass\tsuspicious mock(s) ["
    + ", ".join(suspicious_hits[:4])
    + "] declared with `Real-Component Precondition`"
)
raise SystemExit(0)
PY
_MOCK_RC=$?
set -uo pipefail
_MOCK_RESULT=$(cat "$_MOCK_TMP")
if [ "$_MOCK_RC" -eq 0 ]; then
    echo "  ✅ 26. Mock-PoC contamination gate: $_MOCK_RESULT"
elif [ "$_MOCK_RC" -eq 2 ]; then
    echo "  ⚠️  26. mock-poc-contamination-warning: $_MOCK_RESULT"
    echo "       Suspicious mock detected at Medium severity (or section incomplete)."
    echo '       Add or extend `## Real-Component Precondition` describing:'
    echo "         (1) what the mock replaces in production,"
    echo "         (2) why reaching the branch is in-scope (no prover/admin/off-chain compromise),"
    echo "         (3) what severity remains if the real component blocks reachability."
    warns=$((warns + 1))
else
    echo "  ❌ 26. mock-poc-contamination: $_MOCK_RESULT"
    echo "       High/Critical claims cannot rest on PoCs that use mocked verifiers,"
    echo "       oracles, portals, registries, signature checks, bridges, or harnesses"
    echo '       with hardcoded `returns true` / seeded proof state. Add a'
    echo '       `## Real-Component Precondition` section describing:'
    echo "         (1) what the mock replaces in production,"
    echo "         (2) why reaching the branch is in-scope (no prover/admin/off-chain compromise),"
    echo "         (3) what severity remains if the real component blocks reachability."
    echo "       Benign MockERC20/MockToken/MockSystemConfig do not trigger this gate."
    fails=$((fails + 1))
fi

# PR #124 Slice 1 extension: surface side-channel warnings about cited PoC
# availability (missing/unreadable). These are NOT Check #26 contamination
# fails — Check #4/#10 own PoC-availability — but they're surfaced here so
# the user sees them adjacent to the gate result.
if [ -s "$_MOCK_WARN_TMP" ]; then
    while IFS= read -r _mock_warn_line; do
        [ -z "$_mock_warn_line" ] && continue
        echo "  ⚠️  26. cited-poc-availability: $_mock_warn_line"
        warns=$((warns + 1))
    done < "$_MOCK_WARN_TMP"
fi

rm -f "$_MOCK_TMP" "$_MOCK_WARN_TMP" "$_MOCK_CITED_LIST"

# --- Check 27: Production-path gate (V4 Phase P1 / Workstream A1) ---
# Mechanical hard FAIL on High/Critical drafts that don't prove an in-scope
# production path. The `tools/lib/production_path.py` helper extracts the
# `## Production Path` section, detects mock-component triggers (MockVerifier,
# MockOracle, etc.), prose triggers ("forged proof", "invalid TEE", ...), and
# local-paths-in-PoC, then maps the result to PASS / WARN / FAIL per V4 §2 A1
# + §9 conservative defaults.
#
# Severity-gated behavior:
#   High/Critical missing section -> hard FAIL
#   Medium missing section        -> SUCCESS_WARN
#   Low / Informational           -> informational PASS
#
# Mock triggers REQUIRE item 8 (Real component replacement for each mock).
# Prose triggers REQUIRE item 9 (OOS clauses checked) to cite an exact clause.
# Local paths inside `## PoC` always FAIL at High/Critical (triagers can't
# resolve `~/audits/...`).
echo ""
echo "  27. Production-path gate (V4 §2 A1)..."
# GHSA-AWARE MODE: a GHSA-format advisory (e.g. a Rust networking HashMap-key
# defect) structurally cannot produce a cosmos/EVM `## Production Path` section
# (MockVerifier replacements, OOS-clause citations, in-scope production-path
# schema items 1-10). Skip this cosmos/EVM exploit-conversion scaffolding gate
# for GHSA drafts; the GHSA requirement gates (#42b/#43b) keep rigor enforced.
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  27. production-path: SKIPPED under GHSA-AWARE MODE (GHSA-N/A: GHSA advisories carry CVSS/CWE + inline PoC, not a cosmos/EVM Production-Path schema)"
else
_PROD_PATH_TMP=$(mktemp 2>/dev/null || echo "/tmp/prod_path_$$.log")
set +e
_PROD_ARGS=("$SUB")
if [ -n "${SEVERITY:-}" ]; then
    _PROD_ARGS+=("--severity" "$SEVERITY_ARG")
fi
if [ -n "${_WS:-}" ] && [ -f "$_WS/.proof_game_strict_check" ]; then
    _PROD_ARGS+=("--strict-preconditions")
fi
python3 "$AUDITOOOR_DIR/tools/lib/production_path.py" "${_PROD_ARGS[@]}" > "$_PROD_PATH_TMP" 2>&1
_PROD_RC=$?
set -uo pipefail
_PROD_RESULT=$(cat "$_PROD_PATH_TMP")
if [ "$_PROD_RC" -eq 0 ]; then
    _PROD_FIRST=$(printf '%s\n' "$_PROD_RESULT" | head -1)
    echo "  ✅ 27. production-path: $_PROD_FIRST"
elif [ "$_PROD_RC" -eq 2 ]; then
    _PROD_FIRST=$(printf '%s\n' "$_PROD_RESULT" | head -1)
    echo "  ⚠️  27. production-path-warning: $_PROD_FIRST"
    printf '%s\n' "$_PROD_RESULT" | tail -n +2 | sed 's/^/     /'
    warns=$((warns + 1))
else
    _PROD_FIRST=$(printf '%s\n' "$_PROD_RESULT" | head -1)
    echo "  ❌ 27. production-path: $_PROD_FIRST"
    printf '%s\n' "$_PROD_RESULT" | tail -n +2 | sed 's/^/     /'
    echo "       V4 §2 A1: High/Critical drafts MUST include a complete"
    echo '       `## Production Path` section with items 1-10. Items 7-9'
    echo "       are hard-blocking; the rest are informational. See"
    echo "       docs/ROADMAP_10_OF_10_V4.md §2 Workstream A for the schema."
    fails=$((fails + 1))
fi
rm -f "$_PROD_PATH_TMP"
fi

# --- Check 28: Declared live claim preconditions match observed state ---
# Backward-compatible by design: drafts without explicit
# `<!-- claim-precondition: ... -->` directives pass. Drafts with directives
# fail only when observed live/captured state contradicts the claim; unresolved
# directives warn unless the caller opts out with --skip-live-verify.
echo ""
echo "  28. Live claim-precondition consistency..."
if [ ! -f "$AUDITOOOR_DIR/tools/claim-precondition-check.py" ]; then
    echo "  ⚠️  28. tools/claim-precondition-check.py not found — skipping"
    warns=$((warns + 1))
else
    _CLAIM_TMP=$(mktemp 2>/dev/null || echo "/tmp/claim_precondition_$$.log")
    _CLAIM_ARGS=("$SUB")
    if [ "$SKIP_LIVE_VERIFY" -eq 1 ]; then
        _CLAIM_ARGS+=("--skip-live-verify")
    fi
    set +e
    python3 "$AUDITOOOR_DIR/tools/claim-precondition-check.py" "${_CLAIM_ARGS[@]}" > "$_CLAIM_TMP" 2>&1
    _CLAIM_RC=$?
    set -uo pipefail
    _CLAIM_RESULT=$(cat "$_CLAIM_TMP")
    if [ "$_CLAIM_RC" -eq 0 ]; then
        echo "  ✅ 28. claim-precondition: $(printf '%s\n' "$_CLAIM_RESULT" | head -1)"
    elif [ "$_CLAIM_RC" -eq 2 ]; then
        echo "  ⚠️  28. claim-precondition-warning: $(printf '%s\n' "$_CLAIM_RESULT" | head -1)"
        printf '%s\n' "$_CLAIM_RESULT" | tail -n +2 | sed 's/^/     /'
        warns=$((warns + 1))
    else
        echo "  ❌ 28. claim-precondition-contradiction: $(printf '%s\n' "$_CLAIM_RESULT" | head -1)"
        printf '%s\n' "$_CLAIM_RESULT" | tail -n +2 | sed 's/^/     /'
        echo "       Declared live-state preconditions contradict observed state."
        echo "       Fix the claim, cite correct live proof, or pass --skip-live-verify"
        echo "       only when deliberately doing source-only review."
        fails=$((fails + 1))
    fi
    rm -f "$_CLAIM_TMP"
fi

# --- Check 29: Operator-pasted OOS applied per finding ----------------------
# This is conditional: many workspaces do not have pasted program scope/OOS
# text. If the operator did paste it and `tools/operator-oos-import.py` wrote
# OOS_PASTED.md, every draft needs a per-finding OOS check artifact written by
# `tools/per-finding-oos-check.py`. Two artifact shapes are accepted:
#   1. <ws>/.auditooor/oos_check_<finding_sha256>.json (canonical, v1)
#   2. <draft-dir>/OOS_CHECK*.md   or   <ws>/scope_review/<base>.OOS_CHECK.md
# A JSON artifact must carry `"verdict": "in-scope"`. A Markdown artifact must
# NOT carry `verdict: \`NEEDS_REVIEW\`` (matches-oos / inconclusive).
echo ""
echo "  29. Operator-pasted OOS per-finding check..."
if [ -z "${_WS:-}" ] || [ ! -f "$_WS/OOS_PASTED.md" ]; then
    echo "  ✅ 29. no operator-pasted OOS artifact detected"
else
    _SUB_DIR=$(cd "$(dirname "$SUB")" && pwd)
    # Canonical JSON path: <ws>/.auditooor/oos_check_<sha>.json
    _OOS_JSON=""
    if command -v shasum >/dev/null 2>&1; then
        _DRAFT_SHA=$(shasum -a 256 "$SUB" 2>/dev/null | awk '{print $1}')
    elif command -v sha256sum >/dev/null 2>&1; then
        _DRAFT_SHA=$(sha256sum "$SUB" 2>/dev/null | awk '{print $1}')
    else
        _DRAFT_SHA=""
    fi
    if [ -n "$_DRAFT_SHA" ] && [ -f "$_WS/.auditooor/oos_check_${_DRAFT_SHA}.json" ]; then
        _OOS_JSON="$_WS/.auditooor/oos_check_${_DRAFT_SHA}.json"
    fi
    # Markdown sidecar fallback. Prefer draft-specific artifacts. A generic
    # OOS_CHECK.md is legacy-only and is accepted only when it names the
    # current draft hash; otherwise one stale sidecar can poison a whole
    # staging/paste directory.
    _OOS_REVIEW=""
    for _candidate in \
        "$_SUB_DIR/${_BASENAME}.OOS_CHECK.md" \
        "$_SUB_DIR/${_BASENAME}.oos-check.md" \
        "$_WS/scope_review/${_BASENAME}.oos-check.md" \
        "$_WS/scope_review/${_BASENAME}.OOS_CHECK.md"
    do
        if [ -f "$_candidate" ]; then
            _OOS_REVIEW="$_candidate"
            break
        fi
    done
    if [ -z "$_OOS_REVIEW" ]; then
        for _candidate in \
            "$_SUB_DIR/OOS_CHECK.md" \
            "$_SUB_DIR"/OOS_CHECK_*.md
        do
            if [ -f "$_candidate" ] && [ -n "$_DRAFT_SHA" ] && grep -q "$_DRAFT_SHA" "$_candidate" 2>/dev/null; then
                _OOS_REVIEW="$_candidate"
                break
            fi
        done
    fi
    if [ -z "$_OOS_JSON" ] && [ -z "$_OOS_REVIEW" ]; then
        echo "  ❌ 29. missing per-finding OOS check artifact for pasted scope"
        echo "       Workspace has $_WS/OOS_PASTED.md. Run:"
        echo "       python3 tools/per-finding-oos-check.py --workspace $_WS --finding $SUB"
        fails=$((fails + 1))
    elif [ -n "$_OOS_JSON" ]; then
        # Authoritative path: parse JSON verdict.
        _OOS_VERDICT=$(python3 -c 'import json,sys
try:
  d=json.load(open(sys.argv[1]));print(d.get("verdict",""))
except Exception:
  pass' "$_OOS_JSON" 2>/dev/null)
        if [ "$_OOS_VERDICT" = "in-scope" ]; then
            echo "  ✅ 29. per-finding OOS check (JSON, verdict=in-scope): $_OOS_JSON"
        elif [ "$_OOS_VERDICT" = "matches-oos" ]; then
            echo "  ❌ 29. per-finding OOS check matched a clause: $_OOS_JSON"
            echo "       Resolve the matched OOS clause before filing."
            fails=$((fails + 1))
        elif [ "$_OOS_VERDICT" = "inconclusive" ]; then
            echo "  ❌ 29. per-finding OOS check inconclusive: $_OOS_JSON"
            echo "       Re-run with --llm or --manual and resolve every clause."
            fails=$((fails + 1))
        else
            echo "  ❌ 29. per-finding OOS JSON artifact has unknown verdict: $_OOS_JSON"
            fails=$((fails + 1))
        fi
    elif grep -q "verdict: \`NEEDS_REVIEW\`" "$_OOS_REVIEW" 2>/dev/null; then
        echo "  ❌ 29. per-finding OOS check needs review: $_OOS_REVIEW"
        echo "       Resolve the matched OOS clause before filing."
        fails=$((fails + 1))
    else
        echo "  ✅ 29. per-finding OOS check present: $_OOS_REVIEW"
    fi
fi

# --- Check 30: OOS-DUPE-FILTER (PR #511 Slice 4 follow-up) -----------------
# Strictly additive: workspaces without an OOS-duplicate-filter row in
# .auditooor/invariant_ledger.json never block (rc=2 advisory). When the row
# is present, drafts that match an encoded rejected/OOS class without a
# `<!-- oos-dupe-rebuttal: <CLASS-ID> <reason> -->` HTML comment are flagged.
# Default policy: WARN (advisory). Set STRICT_OOS_DUPE_FILTER=1 to FAIL
# the gate on un-rebutted matches.
echo ""
echo "  30. OOS-DUPE-FILTER (encoded rejected/OOS class re-claim guard)..."
if [ -z "${_WS:-}" ]; then
    echo "  ⚠️  30. workspace not resolved -- skipping OOS-DUPE-FILTER (advisory)"
elif [ ! -f "$AUDITOOOR_DIR/tools/oos-dupe-filter-check.py" ]; then
    echo "  ⚠️  30. tools/oos-dupe-filter-check.py missing -- skipping (advisory)"
else
    _ODF_OUT=$(python3 "$AUDITOOOR_DIR/tools/oos-dupe-filter-check.py" \
        --workspace "$_WS" --draft "$SUB" 2>&1)
    _ODF_RC=$?
    case "$_ODF_RC" in
        0)
            echo "  ✅ 30. OOS-DUPE-FILTER pass (no encoded-class match, or all rebutted)"
            ;;
        2)
            echo "  ✅ 30. OOS-DUPE-FILTER advisory (no ledger / no OOS row in this workspace)"
            ;;
        1)
            if [ "${STRICT_OOS_DUPE_FILTER:-0}" = "1" ]; then
                echo "  ❌ 30. OOS-DUPE-FILTER blocked (un-rebutted class match):"
                echo "$_ODF_OUT" | sed 's/^/       /'
                echo "       Add '<!-- oos-dupe-rebuttal: <CLASS-ID> <reason> -->' to override."
                fails=$((fails + 1))
            else
                echo "  ⚠️  30. OOS-DUPE-FILTER warn (un-rebutted class match — STRICT_OOS_DUPE_FILTER=1 to FAIL):"
                echo "$_ODF_OUT" | sed 's/^/       /'
                echo "       Add '<!-- oos-dupe-rebuttal: <CLASS-ID> <reason> -->' to override."
                warns=$((warns + 1))
            fi
            ;;
        *)
            echo "  ⚠️  30. OOS-DUPE-FILTER unexpected rc=$_ODF_RC (treating as advisory)"
            ;;
    esac
fi

# --- Check 31: PROGRAM-IMPACT-MAPPING (PR #526 gap 0) ---------------------
# Fail-closed gate that forces every Critical/High/Medium (or `paste-ready`) draft
# to map its proof to a listed program-impact class. Closes the over-framing
# class of bug exposed by FN7. Strictly additive: workspaces without a
# SEVERITY*.md / RUBRIC_COVERAGE.md never block (rc=2 advisory). Default
# policy: FAIL for missing/mismatched mapping on reportable/direct-submit work.
echo ""
echo "  31. PROGRAM-IMPACT-MAPPING (Critical/High/Medium exact listed-impact mapping)..."
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  31. PROGRAM-IMPACT-MAPPING: SKIPPED under GHSA-AWARE MODE"
    echo "       (GHSA uses CVSS:3.1 + CWE, not a Cantina program-impact rubric row;"
    echo "        severity/impact mapping is enforced via the GHSA requirement gate.)"
elif [ -z "${_WS:-}" ]; then
    echo "  ⚠️  31. workspace not resolved -- skipping PROGRAM-IMPACT-MAPPING (advisory)"
elif [ ! -f "$AUDITOOOR_DIR/tools/program-impact-mapping-check.py" ]; then
    echo "  ⚠️  31. tools/program-impact-mapping-check.py missing -- skipping (advisory)"
else
    _PIM_OUT=$(python3 "$AUDITOOOR_DIR/tools/program-impact-mapping-check.py" \
        --draft "$SUB" 2>&1)
    _PIM_RC=$?
    case "$_PIM_RC" in
        0)
            echo "  ✅ 31. PROGRAM-IMPACT-MAPPING pass (mapping exact-row-grounded or not required)"
            ;;
        2)
            echo "  ✅ 31. PROGRAM-IMPACT-MAPPING advisory (no SEVERITY*.md / RUBRIC_COVERAGE.md in workspace)"
            ;;
        1)
            echo "  ❌ 31. PROGRAM-IMPACT-MAPPING blocked (exact-impact over-framing risk):"
            echo "$_PIM_OUT" | sed 's/^/       /'
            echo "       Select one exact program impact sentence and prove that exact row,"
            echo "       or mark NOT_SUBMIT_READY/kill_or_reframe and remove the impact."
            fails=$((fails + 1))
            ;;
        *)
            echo "  ⚠️  31. PROGRAM-IMPACT-MAPPING unexpected rc=$_PIM_RC (treating as advisory)"
            ;;
    esac
fi

# --- Check 32: SEVERITY-CLAIM-GUARD (PR #556 §Priority 4 / Wave 6 L) -------
# Refuses to pass when workspace severity artifacts contain reportable rows
# without listed_impact_proven=true. This is the generic exact-impact proof
# guard; Base critical matrices remain preferred when a workspace has them.
#
# Behavior:
#   * No matrix in workspace -> advisory (rc=2 from helper). Does not
#     warn or fail. Operator can run `make base-critical-matrix WS=...`
#     to generate one.
#   * Matrix exists, no reportable-severity rows OR all such rows have
#     an exact selected impact sentence plus listed_impact_proven=true -> PASS.
#   * Matrix exists, at least one reportable row missing exact-impact proof
#     -> FAIL (hard). Snappy gossip decode cannot use mempool impact and
#     cannot be Critical/direct-ready without measured >=30% node-resource
#     consumption or a quantified node-shutdown threshold.
echo ""
echo "  32. SEVERITY-CLAIM-GUARD (Wave 6 Worker L — reportable severity guard)..."
if [ -z "${_WS:-}" ]; then
    echo "  ⚠️  32. workspace not resolved -- skipping SEVERITY-CLAIM-GUARD (advisory)"
elif [ ! -f "$AUDITOOOR_DIR/tools/severity-claim-guard.py" ]; then
    echo "  ⚠️  32. tools/severity-claim-guard.py missing -- skipping (advisory)"
else
    _SCG_OUT=$(python3 "$AUDITOOOR_DIR/tools/severity-claim-guard.py" \
        --workspace "$_WS" 2>&1)
    _SCG_RC=$?
    case "$_SCG_RC" in
        0)
            echo "  ✅ 32. SEVERITY-CLAIM-GUARD pass (exact-impact proof guard clean)"
            ;;
        2)
            echo "  ✅ 32. SEVERITY-CLAIM-GUARD advisory (workspace artifacts missing or unreadable)"
            ;;
        1)
            echo "  ❌ 32. SEVERITY-CLAIM-GUARD blocked (exact-impact over-claim risk):"
            echo "$_SCG_OUT" | sed 's/^/       /'
            echo "       Select one exact Base Azul impact sentence and prove that exact row,"
            echo "       or mark NOT_SUBMIT_READY/kill_or_reframe and remove the impact."
            fails=$((fails + 1))
            ;;
        *)
            echo "  ⚠️  32. SEVERITY-CLAIM-GUARD unexpected rc=$_SCG_RC (treating as advisory)"
            ;;
    esac
fi

# --- Check 33: UPSTREAM-EQUIVALENT-GATE (Wave J-1A — 5-check promotion gate)
# Catches the "agent-modeled bug exists upstream / cited path doesn't exist
# in audit tree / OOS-shared" over-claim shape that hit the overnight loop
# 4 times (H-1 G-v01, H-2B 4839aea3, I-1A KZG verify, I-2 N8/N9). The gate
# re-runs the 5-check protocol over every promotion_candidates.json file in
# the workspace's `.auditooor/` tree:
#
#   1. audit-tree existence  (file at <ws>/external/<asset>/<path>)
#   2. line-content match    (cited line still contains the claim)
#   3. SCOPE.md OOS check    (path NOT under any OOS marker block)
#   4. SEVERITY.md verbatim  (claimed tier exists under matching ### header)
#   5. upstream equivalent   (gh search/code; SKIPPED in pre-submit via
#                             --max-queries 0 to keep the gate offline-safe)
#
# Behavior:
#   * No promotion_candidates.json files in workspace -> advisory.
#   * All rows verdict=='promotion_allowed' -> PASS.
#   * Any row walked back -> WARN (default) / FAIL when
#     STRICT_UPSTREAM_EQUIVALENT_GATE=1.
#
# Steps 1-4 are filesystem-only and finish in <1s per candidate file.
echo ""
echo "  33. UPSTREAM-EQUIVALENT-GATE (Wave J-1A — 5-check candidate gate)..."
if [ -z "${_WS:-}" ]; then
    echo "  ⚠️  33. workspace not resolved -- skipping UPSTREAM-EQUIVALENT-GATE (advisory)"
elif [ ! -f "$AUDITOOOR_DIR/tools/upstream-equivalent-gate.py" ]; then
    echo "  ⚠️  33. tools/upstream-equivalent-gate.py missing -- skipping (advisory)"
else
    _UEG_FILES=$(find "$_WS/.auditooor" -maxdepth 4 -name "promotion_candidates.json" \
        -type f 2>/dev/null)
    if [ -z "$_UEG_FILES" ]; then
        echo "  ✅ 33. UPSTREAM-EQUIVALENT-GATE advisory (no promotion_candidates.json in workspace)"
    else
        _UEG_TOTAL_WALKBACK=0
        _UEG_TOTAL_ROWS=0
        _UEG_DETAIL=""
        while IFS= read -r _UEG_FILE; do
            [ -z "$_UEG_FILE" ] && continue
            _UEG_OUT=$(python3 "$AUDITOOOR_DIR/tools/upstream-equivalent-gate.py" \
                --workspace "$_WS" \
                --candidate "$_UEG_FILE" \
                --max-queries 0 \
                --print-json 2>/dev/null)
            _UEG_RC=$?
            if [ "$_UEG_RC" -eq 2 ]; then
                continue
            fi
            _UEG_RC_W=$(echo "$_UEG_OUT" | python3 -c \
                "import json,sys; d=json.load(sys.stdin); print(d.get('walked_back_count',0))" \
                2>/dev/null || echo 0)
            _UEG_RC_T=$(echo "$_UEG_OUT" | python3 -c \
                "import json,sys; d=json.load(sys.stdin); print(d.get('row_count',0))" \
                2>/dev/null || echo 0)
            _UEG_TOTAL_WALKBACK=$((_UEG_TOTAL_WALKBACK + _UEG_RC_W))
            _UEG_TOTAL_ROWS=$((_UEG_TOTAL_ROWS + _UEG_RC_T))
            if [ "$_UEG_RC_W" -gt 0 ]; then
                _UEG_REL=${_UEG_FILE#"$_WS/"}
                _UEG_DETAIL="$_UEG_DETAIL\n       $_UEG_REL: $_UEG_RC_W/$_UEG_RC_T walked back"
            fi
        done <<< "$_UEG_FILES"
        if [ "$_UEG_TOTAL_WALKBACK" -eq 0 ]; then
            echo "  ✅ 33. UPSTREAM-EQUIVALENT-GATE pass ($_UEG_TOTAL_ROWS rows, all promotion_allowed)"
        elif [ "${STRICT_UPSTREAM_EQUIVALENT_GATE:-0}" = "1" ]; then
            echo "  ❌ 33. UPSTREAM-EQUIVALENT-GATE blocked ($_UEG_TOTAL_WALKBACK/$_UEG_TOTAL_ROWS rows walked back):"
            printf "%b\n" "$_UEG_DETAIL"
            echo "       Re-run: tools/upstream-equivalent-gate.py --workspace $_WS \\"
            echo "         --candidate <file> --print-json (each candidate must be promotion_allowed)."
            fails=$((fails + 1))
        else
            echo "  ⚠️  33. UPSTREAM-EQUIVALENT-GATE warn ($_UEG_TOTAL_WALKBACK/$_UEG_TOTAL_ROWS rows walked back; STRICT_UPSTREAM_EQUIVALENT_GATE=1 to FAIL):"
            printf "%b\n" "$_UEG_DETAIL"
            warns=$((warns + 1))
        fi
    fi
fi

# --- Check 34: Title schema (D-08) ---
# Required title shape: `<Vulnerability Class> in <component> leads to <Impact>`
# (or "allows" / "causes" / "results in" / "enables" / "permits" instead of
# "leads to"). The check parses the first `# <title>` line of the draft (with
# any leading severity tag like `[Critical]` stripped), then runs two
# case-insensitive regex tests:
#   1. A vulnerability class word from a curated list (reentrancy, replay,
#      missing, lack, access control, domain separation, signature, validation,
#      integer, overflow, underflow, race condition, timestamp, unauthorized,
#      frontrun, sandwich, oracle, slippage, dos, denial of service, gas, ...).
#      MISSING -> WARN (taxonomy may need expansion, not a hard block).
#   2. A transition verb (lead to / allow / cause / result in / enable / permit
#      with their stems) FOLLOWED by non-empty impact text. MISSING -> FAIL.
# The Python helper is inlined to avoid adding a new tool.
echo ""
echo "  34. Title schema (D-08)..."
_TITLE_TMP=$(mktemp 2>/dev/null || echo "/tmp/title_schema_$$.log")
set +e
python3 - "$SUB" > "$_TITLE_TMP" 2>&1 <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")

def _strip_h_title(raw: str) -> str:
    """Strip submission-metadata noise from an H1 or H2 line's text portion."""
    t = raw.strip()
    # Strip leading severity tags like "[Critical]" or "(High)"
    t = re.sub(r"^\s*[\[\(]\s*(critical|high|medium|low|informational)\s*[\]\)]\s*",
               "", t, flags=re.IGNORECASE)
    # Strip "✅ Submission N — #ID — Severity — VERIFIED PoC" framing
    # (handles both en-dash — and ASCII hyphen -)
    t = re.sub(
        r"^[^\w\[]*Submission\s*\d*\s*[—\-]+\s*#?[A-Za-z0-9_\-]+\s*[—\-]+\s*"
        r"(?:(?:Critical|High|Medium|Low|Informational)\s*[—\-]+\s*)?"
        r"(?:VERIFIED|UNVERIFIED|PoC|poc)[^\n]*$",
        "", t, flags=re.IGNORECASE
    ).strip()
    # Fallback: strip simpler "Submission N — #ID — Severity" without PoC suffix
    t = re.sub(r"^[^\w\[]*Submission\s*\d*\s*[—\-]+\s*#?[A-Za-z0-9_\-]+\s*[—\-]+\s*", "", t).strip()
    # Strip inline trailing severity word if the above left just a severity token
    t = re.sub(r"^(Critical|High|Medium|Low|Informational)\s*$", "", t, flags=re.IGNORECASE).strip()
    return t

title = ""
for line in text.splitlines():
    stripped = line.strip()
    if stripped.startswith("# ") and not stripped.startswith("##"):
        title = _strip_h_title(stripped[2:])
        break

if not title:
    # Fall back to first H2 whose stripped text is non-empty after removing
    # submission-metadata noise (e.g. "## ✅ Submission 12 — #R77-07 — Medium — VERIFIED PoC"
    # is metadata and yields empty; a genuine H2 title will survive stripping).
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            candidate = _strip_h_title(stripped[3:])
            if candidate:
                title = candidate
                break

if not title:
    print("FAIL no `# <title>` or `## <title>` line found in draft")
    sys.exit(1)

class_pattern = re.compile(
    r"\b("
    r"reentran(?:cy|t)|replay|missing|lack(?:s|ing)?|access[- ]control|"
    r"domain[- ]separation|signature|validation|integer|overflow|underflow|"
    r"race[- ]condition|timestamp|unauthori[sz]ed|frontrun(?:ning)?|sandwich|"
    r"oracle|slippage|dos|denial[- ]of[- ]service|gas|"
    r"forgery|forge|bypass|injection|collision|"
    r"uninitiali[sz]ed|reinitiali[sz]ation|insufficient|incorrect|"
    r"griefing|liveness|drain|theft|mev|truncation|rounding|"
    r"sufficiency[- ]check|wrong[- ]field|factory[- ]acceptance|"
    r"validation[- ]gap|missing[- ]guard|incorrect[- ]derivation|"
    r"improper[- ]bookkeeping|insufficient[- ]validation"
    r")\b",
    re.IGNORECASE,
)
transition_pattern = re.compile(
    r"\b(lead(?:s|ing)?\s+to|allow(?:s|ing|ed)?|caus(?:e|es|ing|ed)|"
    r"result(?:s|ing|ed)?\s+in|enabl(?:e|es|ing|ed)|permit(?:s|ting|ted)?)"
    r"\s+(\S.+)$",
    re.IGNORECASE,
)

class_hit = class_pattern.search(title)
trans_hit = transition_pattern.search(title)

if not trans_hit or not trans_hit.group(2).strip():
    print(f"FAIL title missing transition+impact: {title!r}")
    print(f"     expected: '<class> in <component> leads to <impact>' "
          f"(or allows/causes/results in/enables/permits)")
    sys.exit(1)

if not class_hit:
    print(f"WARN title missing recognised vulnerability class word: {title!r}")
    print(f"     class taxonomy may need expansion — review tools/pre-submit-check.sh "
          f"Check 34 list")
    sys.exit(2)

print(f"OK class='{class_hit.group(1)}' transition='{trans_hit.group(1)}' "
      f"impact='{trans_hit.group(2).strip()[:60]}'")
sys.exit(0)
PY
_TITLE_RC=$?
set -uo pipefail
_TITLE_RESULT=$(cat "$_TITLE_TMP")
if [ "$_TITLE_RC" -eq 0 ]; then
    echo "  ✅ 34. title-schema: $(printf '%s\n' "$_TITLE_RESULT" | head -1)"
elif [ "$_TITLE_RC" -eq 2 ]; then
    echo "  ⚠️  34. title-schema-warning: $(printf '%s\n' "$_TITLE_RESULT" | head -1)"
    printf '%s\n' "$_TITLE_RESULT" | tail -n +2 | sed 's/^/     /'
    warns=$((warns + 1))
else
    echo "  ❌ 34. title-schema: $(printf '%s\n' "$_TITLE_RESULT" | head -1)"
    printf '%s\n' "$_TITLE_RESULT" | tail -n +2 | sed 's/^/     /'
    echo "       Required shape: '<Vulnerability Class> in <component> leads to <Impact>'"
    echo "       (or allows / causes / results in / enables / permits)."
    fails=$((fails + 1))
fi
rm -f "$_TITLE_TMP"

# --- Check 35: Financial impact gate (D-09) ---
# Critical/High SUBMITs must MEASURE fund-flow delta in the PoC, not just claim
# "structural implication" via prose. FN2 lesson: a chain like "X is poisoned, Y
# reads X to release funds" is insufficient unless the PoC actually wires Y and
# demonstrates Y's loss with `assertEq` / `assert_eq!` / `expect_eq!`.
#
# Logic:
#   1. Only run when --severity is Critical or High.
#   2. Locate the PoC code block (triple-backtick fence containing
#      `function test_`, `forge test`, `cargo test`, `go test`, or a Go
#      `func TestX(t *testing.T)` body).
#   3. Scan ±50 lines around the block for soft-claim phrases ("structural
#      implication", "would result in", "could allow", "would lead to",
#      "if read by", "implies").
#   4. If a soft-claim is present, REQUIRE an assertion in the PoC body
#      (assertEq / vm.assertEq / assert_eq! / expect_eq! / common Go
#      assert/require helpers). No assertion -> FAIL.
#   5. No soft-claim AND no assertion -> PASS (PoC may just print state).
#   6. Soft-claim AND assertion both present -> PASS.
echo ""
echo "  35. Financial impact gate (D-09)..."
case "${SEVERITY:-}" in
    Critical|High|critical|high|CRITICAL|HIGH)
        _FIG_TMP=$(mktemp 2>/dev/null || echo "/tmp/fin_impact_$$.log")
        set +e
        python3 - "$SUB" > "$_FIG_TMP" 2>&1 <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
lines = text.splitlines()

# Locate PoC code block: triple-backtick fence whose body contains a test marker
poc_start = poc_end = -1
i = 0
while i < len(lines):
    stripped = lines[i].lstrip()
    if stripped.startswith("```"):
        fence_start = i
        j = i + 1
        body = []
        while j < len(lines) and not lines[j].lstrip().startswith("```"):
            body.append(lines[j])
            j += 1
        body_text = "\n".join(body)
        if re.search(
            r"function\s+test_|forge\s+test|cargo\s+test|go\s+test|mise\s+test|"
            r"func\s+Test[A-Za-z0-9_]*\s*\(\s*t\s+\*testing\.T\s*\)|"
            r"node\s+--test|node:test|\btest\s*\(\s*['\"]",
            body_text,
        ):
            poc_start = fence_start
            poc_end = j  # closing fence line
            break
        i = j + 1
    else:
        i += 1

if poc_start < 0:
    print("WARN no PoC code block (forge test / cargo test / go test / node --test / function test_ / func Test / node:test) found")
    sys.exit(2)

poc_body = "\n".join(lines[poc_start + 1:poc_end])
window_lo = max(0, poc_start - 50)
window_hi = min(len(lines), poc_end + 50)
window_text = "\n".join(lines[window_lo:window_hi])

soft_pattern = re.compile(
    r"(structural\s+implication|would\s+result\s+in|could\s+allow|"
    r"would\s+lead\s+to|if\s+read\s+by|\bimplies\b)",
    re.IGNORECASE,
)
soft_hits = soft_pattern.findall(window_text)

assert_pattern = re.compile(
    r"(assertEq|vm\.assertEq|assert_eq!|expect_eq!|"
    r"require\.(?:Equal|Greater|Less|NoError|True|False)|"
    r"assert\.(?:Equal|Greater|Less|NoError|True|False|ok|match|doesNotMatch|strictEqual|deepEqual)|"
    r"if\s+[^{}\n]+(?:!=|==|<|>)\s+[^{}\n]+\s*\{[^{}]*(?:t\.Fatalf|t\.Errorf))"
)
assert_hits = assert_pattern.findall(poc_body)

if soft_hits and not assert_hits:
    sample = sorted({h.lower().strip() for h in soft_hits})[:3]
    print(f"FAIL soft-claim phrases present near PoC ({sample}) "
          f"but no fund-flow assertion in PoC body")
    print("     Critical/High requires assertEq / vm.assertEq / assert_eq! / "
          "expect_eq! that proves the soft-claim numerically.")
    print("     FN2 lesson: 'X is poisoned, Y reads X to release funds' is "
          "insufficient unless the PoC wires Y and demonstrates Y's loss.")
    sys.exit(1)

if soft_hits and assert_hits:
    print(f"OK soft-claim present but PoC carries {len(assert_hits)} assertion(s) "
          f"that prove fund-flow delta")
    sys.exit(0)

if assert_hits:
    print(f"OK PoC carries {len(assert_hits)} assertion(s); no soft-claim hedging")
    sys.exit(0)

print("OK no soft-claim phrases and no assertions (PoC may be state-print only)")
sys.exit(0)
PY
        _FIG_RC=$?
        set -uo pipefail
        _FIG_RESULT=$(cat "$_FIG_TMP")
        if [ "$_FIG_RC" -eq 0 ]; then
            echo "  ✅ 35. financial-impact: $(printf '%s\n' "$_FIG_RESULT" | head -1)"
        elif [ "$_FIG_RC" -eq 2 ]; then
            echo "  ⚠️  35. financial-impact-warning: $(printf '%s\n' "$_FIG_RESULT" | head -1)"
            printf '%s\n' "$_FIG_RESULT" | tail -n +2 | sed 's/^/     /'
            warns=$((warns + 1))
        else
            echo "  ❌ 35. financial-impact: $(printf '%s\n' "$_FIG_RESULT" | head -1)"
            printf '%s\n' "$_FIG_RESULT" | tail -n +2 | sed 's/^/     /'
            echo "       Critical/High SUBMITs must measure fund-flow delta with"
            echo "       assertEq / assert_eq! / expect_eq!, not just claim a"
            echo "       'structural implication' in prose. (FN2 lesson)"
            fails=$((fails + 1))
        fi
        rm -f "$_FIG_TMP"
        ;;
    *)
        echo "  ✅ 35. financial-impact-gate skipped (severity='${SEVERITY:-unset}', only runs on Critical/High)"
        ;;
esac

# --- Check 36: Fork-replay log required for Critical-with-replay-tx (F4) ----
# Fires only when the paste-ready references a `replay-tx:` field AND the
# severity is Critical or High.  Does NOT fire when no replay-tx is cited.
# Lesson: FN2 and H-04 required artisanal harnesses; F4 standardises this.
case "${SEVERITY:-Medium}" in
    Critical|High)
        _FRR_TX=$(python3 - "$SUB" <<'PY' 2>/dev/null || true
import re, sys
txt = open(sys.argv[1]).read()
m = re.search(r"replay[_-]tx\s*[=:]\s*(0x[0-9a-fA-F]{6,})", txt, re.IGNORECASE)
print(m.group(1) if m else "")
PY
        )
        if [ -n "$_FRR_TX" ]; then
            # replay-tx found — require a matching replay log in poc_execution/
            _FRR_ID=$(python3 - "$SUB" <<'PYID' 2>/dev/null || true
import re, sys, os
txt = open(sys.argv[1]).read()
m = re.search(r"finding[_-]id\s*[=:]\s*(\S+)", txt, re.IGNORECASE)
if m:
    val = m.group(1)
    for ch in ('"', "'", ",", ".", ":", ";"):
        val = val.strip(ch)
    print(val)
    sys.exit(0)
print(os.path.splitext(os.path.basename(sys.argv[1]))[0])
PYID
            )
            _FRR_LOG_FOUND=0
            if [ -n "${WS:-}" ]; then
                if ls "${WS}/poc_execution/${_FRR_ID}/replay_"*.json 2>/dev/null | head -1 | grep -q .; then
                    _FRR_LOG_FOUND=1
                fi
            else
                # Try workspace relative to submission file directory
                _FRR_SUB_WS=$(python3 -c "import os,sys; p=os.path.abspath(sys.argv[1]); print(os.path.dirname(os.path.dirname(os.path.dirname(p))))" "$SUB" 2>/dev/null || true)
                if [ -n "$_FRR_SUB_WS" ] && ls "${_FRR_SUB_WS}/poc_execution/${_FRR_ID}/replay_"*.json 2>/dev/null | head -1 | grep -q .; then
                    _FRR_LOG_FOUND=1
                fi
            fi
            if [ "$_FRR_LOG_FOUND" -eq 1 ]; then
                echo "  ✅ 36. fork-replay-log: replay_*.json present for finding '${_FRR_ID}' (replay-tx ${_FRR_TX})"
            else
                echo "  ❌ 36. fork-replay-log: paste-ready references replay-tx ${_FRR_TX} but no"
                echo "       poc_execution/${_FRR_ID}/replay_*.json found."
                echo "       Run: python3 tools/fork-replay.py --finding-id ${_FRR_ID} --replay-tx ${_FRR_TX} ..."
                echo "       or:  python3 tools/fork-replay.py --hermetic --finding-id ${_FRR_ID} (CI mode)"
                echo "       (F4 rule: Critical/High with replay-tx citation must carry fork-replay execution log)"
                fails=$((fails + 1))
            fi
        else
            echo "  ✅ 36. fork-replay-log skipped (no replay-tx cited in submission)"
        fi
        ;;
    *)
        echo "  ✅ 36. fork-replay-log skipped (severity='${SEVERITY:-unset}', only fires on Critical/High)"
        ;;
esac

# --- Check 39: Severity-claim historical mismatch (F5 per-platform precision) ---
# Reads obsidian-vault/calibration/per-platform/<target_platform>.md and
# warns (not fails) when the claimed severity has been triaged differently
# in >=2 prior cases on the same platform.
# Only fires when:
#   1. SEVERITY is set AND is not Medium/Low/Info (calibrated for High/Critical)
#   2. The per-platform vault page exists for the target platform
#   3. The pattern found in the submission matches a pattern with prior outcomes
#
# Lesson: F5 — severity mis-calibration costs bounty; warn early.
_C39_PLATFORM="${TARGET_PLATFORM:-}"
_C39_VAULT_PAGE=""
if [ -n "$_C39_PLATFORM" ]; then
    # Normalize to match file naming (replace spaces/special chars with _)
    _C39_PLAT_SAFE=$(echo "$_C39_PLATFORM" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/_/g')
    _C39_VAULT_PAGE="${AUDITOOOR_DIR}/obsidian-vault/calibration/per-platform/${_C39_PLATFORM}.md"
    if [ ! -f "$_C39_VAULT_PAGE" ]; then
        # Try lowercase normalized name
        _C39_VAULT_PAGE="${AUDITOOOR_DIR}/obsidian-vault/calibration/per-platform/${_C39_PLAT_SAFE}.md"
    fi
fi

if [ -n "$_C39_VAULT_PAGE" ] && [ -f "$_C39_VAULT_PAGE" ] && [ -n "${SEVERITY:-}" ]; then
    _C39_RESULT=$(python3 - "$SUB" "$_C39_VAULT_PAGE" "${SEVERITY:-}" 2>/dev/null <<'PY' || true
import re, sys, json
from pathlib import Path

sub_path = Path(sys.argv[1])
vault_page = Path(sys.argv[2])
claimed_sev = sys.argv[3].strip()

# Only run for High/Critical — Medium and below are not surprising
if claimed_sev.lower() not in ("critical", "high"):
    print("SKIP:not_high_critical")
    sys.exit(0)

if not vault_page.is_file():
    print("SKIP:no_vault_page")
    sys.exit(0)

vault_text = vault_page.read_text(encoding="utf-8", errors="replace")

# Extract per-pattern rows from the vault MD table.
table_rows = []
in_table = False
backtick = chr(96)
for line in vault_text.splitlines():
    if "| Pattern |" in line or f"| {backtick}" in line:
        in_table = True
    if in_table and line.startswith(f"| {backtick}"):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7:
            pat_id = parts[1].strip(backtick)
            try:
                rejected = int(parts[3])
                sample = int(parts[5])
            except (ValueError, IndexError):
                continue
            if rejected >= 2:
                table_rows.append((pat_id, rejected, sample))

if not table_rows:
    print("SKIP:no_prior_rejections")
    sys.exit(0)

# Check if the submission title matches any rejected patterns
sub_text = sub_path.read_text(encoding="utf-8", errors="replace").lower()

KEYWORDS = {
    "reentrancy": ["reentr"],
    "access-control": ["access control", "unauthenticat", "authoriz"],
    "oracle-manipulation": ["oracle", "price manipul"],
    "delegatecall": ["delegatecall"],
    "erc4626-inflation": ["erc4626", "inflation"],
    "flash-loan": ["flash loan", "flash-loan"],
    "timestamp-dependence": ["timestamp"],
    "frontrunning": ["frontrun", "front-run"],
    "integer-overflow": ["overflow", "underflow", "arithmetic"],
    "signature-replay": ["signature", "replay", "nonce"],
    "dos": ["denial of service", "dos", "gas griefing"],
}

matched_patterns = []
for pat_slug, keywords in KEYWORDS.items():
    if any(kw in sub_text for kw in keywords):
        matched_patterns.append(pat_slug)

hits = []
for (pat_id, rejected, sample) in table_rows:
    for mp in matched_patterns:
        if mp in pat_id or pat_id in mp:
            hits.append((pat_id, rejected, sample))
            break

if not hits:
    print("SKIP:no_pattern_match")
    sys.exit(0)

# Warn about each matching pattern with >=2 rejections
for (pat_id, rejected, sample) in hits:
    print(f"WARN:pattern='{pat_id}' rejected={rejected}/{sample} times on this platform at {claimed_sev} severity")
PY
    )

    if echo "$_C39_RESULT" | grep -q "^WARN:"; then
        echo "  ⚠️  39. severity-claim-historical-mismatch:"
        echo "$_C39_RESULT" | grep "^WARN:" | while IFS= read -r warn_line; do
            echo "       ${warn_line#WARN:}"
        done
        echo "       This pattern has been rejected at ${SEVERITY} on ${_C39_PLATFORM:-this platform} before."
        echo "       Review prior rejection rationale before claiming ${SEVERITY}."
        echo "       (F5 rule: historical mismatch is a warn, not a fail — operator call)"
        warns=$((warns + 1))
    elif echo "$_C39_RESULT" | grep -q "^SKIP:"; then
        _C39_SKIP_REASON=$(echo "$_C39_RESULT" | grep "^SKIP:" | head -1 | sed 's/^SKIP://')
        echo "  ✅ 39. severity-claim-historical-mismatch skipped (${_C39_SKIP_REASON})"
    else
        echo "  ✅ 39. severity-claim-historical-mismatch: no prior rejections on this platform for matched patterns"
    fi
elif [ -z "${SEVERITY:-}" ]; then
    echo "  ✅ 39. severity-claim-historical-mismatch skipped (no --severity set)"
elif [ -z "$_C39_PLATFORM" ]; then
    echo "  ✅ 39. severity-claim-historical-mismatch skipped (no TARGET_PLATFORM set)"
else
    echo "  ✅ 39. severity-claim-historical-mismatch skipped (no vault page at ${_C39_VAULT_PAGE:-unknown})"
    echo "       Run: python3 tools/per-platform-precision.py to generate vault pages"
fi

# --- Check 40: Cross-workspace duplicate gate (ACT-25 §K) -------------------
# Mandatory dedup check: if the paste-ready is >0.7 cosine-similar to ANY
# prior workspace's staged/submitted markdown, BLOCK and emit BLOCKED_*.md.
_CWDC_TOOL="${AUDITOOOR_DIR}/tools/cross-workspace-duplicate-check.py"
if [ -f "$_CWDC_TOOL" ]; then
    _CWDC_WS=""
    case "$SUB" in
        */audits/*/*)
            _CWDC_WS="$(echo "$SUB" | sed 's|.*/audits/\([^/]*\)/.*|\1|')"
            ;;
    esac
    _CWDC_ARGS=()
    if [ -n "$_CWDC_WS" ]; then
        _CWDC_ARGS+=(--workspace "$_CWDC_WS")
    fi
    if [ -n "${AUDITS_DIR:-}" ]; then
        _CWDC_ARGS+=(--audits-dir "$AUDITS_DIR")
    fi
    # bash 3.2 (macOS default) errors on "${arr[@]}" when array is empty
    # under `set -u`. Use the canonical safe form ${arr[@]+"${arr[@]}"} which
    # expands to zero args (NOT an empty arg) when _CWDC_ARGS is empty. The
    # simpler ${arr[@]:-} pattern injects a stray empty positional that the
    # downstream argparse rejects with rc=2 and a silent WARN downgrade.
    _CWDC_OUT=$(python3 "$_CWDC_TOOL" "$SUB" ${_CWDC_ARGS[@]+"${_CWDC_ARGS[@]}"} 2>&1)
    _CWDC_RC=$?
    if [ "$_CWDC_RC" -eq 0 ]; then
        echo "  ✅ 40. cross-workspace-dedup: no duplicate above threshold"
    elif [ "$_CWDC_RC" -eq 1 ]; then
        echo "  ❌ 40. cross-workspace-dedup: BLOCKED — similar prior submission found"
        echo "$_CWDC_OUT" | grep -E "BLOCKED|Best match|Details" | sed 's/^/     /'
        echo "     Review the BLOCKED_*.md file; lower --threshold if genuinely novel."
        fails=$((fails + 1))
    else
        echo "  ⚠️  40. cross-workspace-dedup: tool error (usage/input issue)"
        echo "$_CWDC_OUT" | head -3 | sed 's/^/     /'
        warns=$((warns + 1))
    fi
else
    echo "  ⚠️  40. cross-workspace-dedup: tool not found (${_CWDC_TOOL}), skipping"
    warns=$((warns + 1))
fi

# --- Check 41: Impact-contract preflight (KLBQ-010) -------------------------
# Strict filing preflight: proof-grade drafts must name the impact contract
# before submission. Planning artifacts can pass advisory-only, but they do not
# become proof-grade filing material without the explicit actor + proof anchor
# plus all six L27 directives.
echo ""
echo "  41. Impact-contract preflight..."
_IMPACT_TOOL="$AUDITOOOR_DIR/tools/impact-contract-preflight.py"
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  41. Impact-contract preflight: SKIPPED under GHSA-AWARE MODE"
    echo "       (the L27 Impact Contract block is a Cantina/HackenProof construct;"
    echo "        GHSA encodes impact in the ### Impact section + CVSS + CWE.)"
elif [ ! -f "$_IMPACT_TOOL" ]; then
    echo "  ❌ 41. impact-contract-preflight: tool missing ($_IMPACT_TOOL)"
    fails=$((fails + 1))
else
    _IMPACT_TMP=$(mktemp 2>/dev/null || echo "/tmp/impact_contract_$$.json")
    _IMPACT_ERR=$(mktemp 2>/dev/null || echo "/tmp/impact_contract_$$.err")
    set +e
    python3 "$_IMPACT_TOOL" "$SUB" --route filing > "$_IMPACT_TMP" 2> "$_IMPACT_ERR"
    _IMPACT_RC=$?
    set -uo pipefail
    _IMPACT_STATUS=$(
        python3 - "$_IMPACT_TMP" "$_IMPACT_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable impact-contract-preflight output")
    raise SystemExit(0)

decision = payload.get("decision") or {}
impact = payload.get("impact_contract") or {}
actors = ", ".join(impact.get("actor_fields_present") or [])
anchors = ", ".join(impact.get("anchor_fields_present") or [])
directives = ", ".join(impact.get("l27_directive_fields_present") or [])
missing_directives = ", ".join(impact.get("missing_l27_directives") or [])
missing = "; ".join(impact.get("missing") or [])
bits = [str(decision.get("code") or "unknown")]
if actors:
    bits.append(f"actors={actors}")
if anchors:
    bits.append(f"anchors={anchors}")
if directives:
    bits.append(f"directives={directives}")
if missing_directives:
    bits.append(f"missing_l27={missing_directives}")
if missing:
    bits.append(f"missing={missing}")
print(" | ".join(bits))
PY
    )
    if [ "$_IMPACT_RC" -eq 0 ]; then
        if grep -q '"advisory_bypass": true' "$_IMPACT_TMP"; then
            echo "  ⚠️  41. impact-contract-planning-bypass: $_IMPACT_STATUS"
            echo "       Planning artifacts may bypass this gate advisory-only; filing still needs"
            echo '       an explicit `## Impact Contract` block before promotion or submission.'
            warns=$((warns + 1))
        else
            echo "  ✅ 41. Impact-contract preflight: $_IMPACT_STATUS"
        fi
    elif [ "$_IMPACT_RC" -eq 2 ]; then
        echo "  ❌ 41. impact-contract-missing: $_IMPACT_STATUS"
        echo '       Add `## Impact Contract` with at least:'
        echo "         (1) one impacted actor/surface (victim/protocol/contract/asset),"
        echo '         (2) one explicit evidence anchor (`source-proof`, `harness-scaffold`,'
        echo '             `exploit-memory`, `fork-replay`, or `live-proof`),'
        echo "         (3) all six L27 directives: selected_impact, severity_tier,"
        echo "             listed_impact_proven, evidence_class, oos_traps, stop_condition."
        fails=$((fails + 1))
    else
        echo "  ❌ 41. impact-contract-preflight error: $_IMPACT_STATUS"
        fails=$((fails + 1))
    fi
    rm -f "$_IMPACT_TMP" "$_IMPACT_ERR"
fi

# --- Checks 44-47: L29-Filing gates (codified 2026-05-08) -------------------
# Four mechanical gates from docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md
# L29-Filing section. Each runs a single function in tools/l29_filing_check.py
# and fails closed on rhetoric-trap / evidence-shortfall / hash-drift /
# manifest-completeness violations.
_L29_TOOL="$AUDITOOOR_DIR/tools/l29_filing_check.py"
if [ -f "$_L29_TOOL" ]; then
    echo ""
    for _L29_CHECK in A B C-record D; do
        case "$_L29_CHECK" in
            A)        _L29_NUM="44"; _L29_LABEL="L29-Filing A (title vs not_proven_impacts)" ;;
            B)        _L29_NUM="45"; _L29_LABEL="L29-Filing B (proven_impact poc_path + pass_evidence_lines)" ;;
            C-record) _L29_NUM="46"; _L29_LABEL="L29-Filing C (paste-content-hash record)" ;;
            D)        _L29_NUM="47"; _L29_LABEL="L29-Filing D (manifest cross-cite + test-name)" ;;
        esac
        _L29_OUT=$(python3 "$_L29_TOOL" "$SUB" --check "$_L29_CHECK" 2>&1)
        _L29_RC=$?
        if [ "$_L29_RC" -eq 0 ]; then
            # If output contains "soft-skip" treat as pass with note
            if echo "$_L29_OUT" | grep -q "soft-skip"; then
                echo "  ✅ ${_L29_NUM}. ${_L29_LABEL}: skipped"
                echo "       ${_L29_OUT}" | sed 's/^[[:space:]]*//'
            else
                echo "  ✅ ${_L29_NUM}. ${_L29_LABEL}"
            fi
        else
            echo "  ❌ ${_L29_NUM}. ${_L29_LABEL}: FAILED"
            echo "$_L29_OUT" | sed 's/^/       /'
            fails=$((fails + 1))
        fi
    done
else
    echo "  ⚠️  44-47. L29-Filing gates: tool not found ($_L29_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 48: L30 missing-guard call-site enumeration ----------------------
_L30_RESULT=$(
    python3 - "$SUB" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
trigger_re = re.compile(
    r"\b("
    r"missing[- ](?:guard|protection|check|validation|access control|input validation|"
    r"reentrancy guard|pause check|slippage check|replay protection|bounds check)|"
    r"missing[- ][A-Za-z0-9_]+[- ](?:guard|check|validation)|"
    r"asymmetric[- ](?:check|guard|validation|path|path pair)|"
    r"unguarded (?:call site|path|function)|"
    r"lacks? (?:the )?(?:guard|protection|validation|access control|modifier)|"
    r"without (?:the )?(?:guard|protection|validation|access control|modifier)"
    r")\b",
    re.IGNORECASE,
)
section_re = re.compile(r"(?im)^\s*##\s+Enumerated Call Sites\b")
rebuttal_re = re.compile(r"<!--\s*l30-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)

import os
trigger = trigger_re.search(text)
if not trigger:
    print("SKIP:no_missing_guard_framing")
    raise SystemExit(0)
_sec = section_re.search(text)
if _sec:
    # L30 (enforcement-gap 2026-07-03): a bare `## Enumerated Call Sites` HEADER with no
    # actual sites passed - the superset-or-equal (|AST| >= |grep|) completeness invariant
    # was only a docstring, never asserted. Require the section BODY to list >= 1 concrete
    # call site (a file:line ref, a .sol/.go/.rs/.vy reference, or a `-`/`*` bullet naming a
    # call). ADVISORY-FIRST: an empty header WARN-passes by default; it hard-fails only
    # under AUDITOOOR_L30_CALLSITE_STRICT (the runtime assertion the invariant always
    # implied). callsite-selector.py remains the AST-exact enumerator the operator runs.
    _tail = text[_sec.end():]
    _nexthdr = re.search(r"^\s*##\s+\S", _tail, re.MULTILINE)
    _body = _tail[:_nexthdr.start()] if _nexthdr else _tail
    # a concrete call site = a source-file ref, a :line ref, or a `-`/`*` bullet naming a call.
    _site_re = re.compile(r"[A-Za-z0-9_./-]+\.(?:sol|go|rs|vy|cairo|move)\b|:\d+\b", re.IGNORECASE)
    _bullet_re = re.compile(r"^\s*[-*]\s+.*\w+\s*\(")
    _sites = len(_site_re.findall(_body)) + sum(
        1 for _ln in _body.splitlines() if _bullet_re.match(_ln))
    if _sites >= 1:
        print(f"PASS:enumerated_call_sites_present sites={_sites}")
        raise SystemExit(0)
    _l30_strict = os.environ.get("AUDITOOOR_L30_CALLSITE_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
    if _l30_strict:
        print("FAIL:enumerated_call_sites_section_empty (header present but 0 concrete sites listed - "
              "run tools/callsite-selector.py --target <fn> --path <repo> and list the AST call sites)")
        raise SystemExit(1)
    print("WARN:enumerated_call_sites_section_empty (0 concrete sites; AUDITOOOR_L30_CALLSITE_STRICT=1 to hard-fail)")
    raise SystemExit(0)
rebuttal = rebuttal_re.search(text)
if rebuttal:
    reason = " ".join(rebuttal.group(1).split())
    if reason and len(reason) <= 200:
        print("PASS:l30_rebuttal_present")
        raise SystemExit(0)
    print("FAIL:l30_rebuttal_empty_or_too_long")
    raise SystemExit(1)
print(f"FAIL:missing_enumerated_call_sites trigger={trigger.group(0)[:80]}")
raise SystemExit(1)
PY
)
_L30_RC=$?
if [ "$_L30_RC" -eq 0 ]; then
    if echo "$_L30_RESULT" | grep -q "^SKIP:"; then
        echo "  ✅ 48. L30-MISSING-GUARD-ENUMERATION skipped (${_L30_RESULT#SKIP:})"
    else
        echo "  ✅ 48. L30-MISSING-GUARD-ENUMERATION: ${_L30_RESULT#PASS:}"
    fi
else
    echo "  ❌ 48. L30-MISSING-GUARD-ENUMERATION blocked: ${_L30_RESULT#FAIL:}"
    echo '       Add `## Enumerated Call Sites` with all checked call sites and dispositions,'
    echo '       or add `<!-- l30-rebuttal: <reason> -->` if the finding is genuinely single-site.'
    echo "       Helper: tools/missing-guard-callsite-enumerator.sh <repo> <guard> <resource-pattern>"
    fails=$((fails + 1))
fi

# --- Check 49: L31 duplicate preflight --------------------------------------
_L31_TOOL="$AUDITOOOR_DIR/tools/duplicate-preflight-check.py"
if [ -f "$_L31_TOOL" ]; then
    _L31_WS=$(
        python3 - "$SUB" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve()
for parent in [path.parent, *path.parents]:
    if (parent / "submissions").is_dir():
        print(parent)
        raise SystemExit(0)
    if parent.name == "submissions":
        print(parent.parent)
        raise SystemExit(0)
print("")
PY
    )
    if [ -z "$_L31_WS" ]; then
        echo "  ⚠️  49. L31-DUPE-PREFLIGHT: workspace could not be resolved; skipping"
        warns=$((warns + 1))
    else
        _L31_TMP=$(mktemp 2>/dev/null || echo "/tmp/l31_dupe_$$.json")
        _L31_ERR=$(mktemp 2>/dev/null || echo "/tmp/l31_dupe_$$.err")
        _L31_PLATFORM="${TARGET_PLATFORM:-${PLATFORM:-auto}}"
        _L31_ARGS=("$SUB" "--workspace" "$_L31_WS" "--platform" "$_L31_PLATFORM" "--strict" "--json" "--self-skip-same-family")
        if [ -d "$_L31_WS/prior_reports" ]; then
            _L31_ARGS+=("--prior-reports-dir" "$_L31_WS/prior_reports")
        fi
        set +e
        python3 "$_L31_TOOL" "${_L31_ARGS[@]}" > "$_L31_TMP" 2> "$_L31_ERR"
        _L31_RC=$?
        set -uo pipefail
        _L31_SUMMARY=$(
            python3 - "$_L31_TMP" "$_L31_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable duplicate-preflight output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("platform"):
    bits.append(f"platform={payload.get('platform')}")
duplicates = payload.get("duplicates") or []
if duplicates:
    bits.append(f"flagged={len(duplicates)}")
    first = duplicates[0]
    bits.append(f"first={first.get('prior_id') or '?'}:{first.get('verdict') or '?'}")
skipped = payload.get("self_skipped_priors") or []
if skipped:
    bits.append(f"self_skipped={len(skipped)}")
print(" | ".join(bits))
PY
        )
        if [ "$_L31_RC" -eq 0 ]; then
            echo "  ✅ 49. L31-DUPE-PREFLIGHT: $_L31_SUMMARY"
        elif [ "$_L31_RC" -eq 2 ]; then
            echo "  ✅ 49. L31-DUPE-PREFLIGHT: $_L31_SUMMARY"
            echo "       No prior reports to compare; treating as first filing."
        elif [ "$_L31_RC" -eq 1 ]; then
            echo "  ❌ 49. L31-DUPE-PREFLIGHT blocked:"
            echo "       $_L31_SUMMARY"
            python3 - "$_L31_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in (payload.get("duplicates") or [])[:3]:
    print(f"- {item.get('prior_id')} ({item.get('prior_lane')}): {item.get('verdict')}")
    if item.get("q1_overlapping_files"):
        print("  q1_files=" + ", ".join(item.get("q1_overlapping_files")[:5]))
    if item.get("q2_shared_fix_refs"):
        print("  q2_fix_refs=" + ", ".join(item.get("q2_shared_fix_refs")[:5]))
    if item.get("q2_shared_guards"):
        print("  q2_guards=" + ", ".join(item.get("q2_shared_guards")[:5]))
print("Add `<!-- l31-rebuttal: <prior-id> <reason> -->` only for a sourced non-duplicate exception.")
PY
            fails=$((fails + 1))
        else
            echo "  ⚠️  49. L31-DUPE-PREFLIGHT error: $_L31_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_L31_TMP" "$_L31_ERR"
    fi
else
    echo "  ⚠️  49. L31-DUPE-PREFLIGHT: tool not found ($_L31_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Checks 50-57: Rules 10/11/12/13 + D13/15/16/D20 (codified 2026-05-11) ---
# Eight mechanical gates from dydx engagement closeout. Each runs a single
# function in tools/pre-submit-rules-13-16-checks.py. Empirical anchors:
#   #50 Rule 10  wrong-rubric cross-engagement contamination (Spark/dydx mix)
#   #51 Rule 11  default-vs-opt-in claim must cite code path
#   #52 Rule 12  L17 build-path itemization (≥3 steps)
#   #53 Rule 13  advisory-ID OOS-leak scrub (ASA/GHSA/CVE/CSA/ICRA/OF/RUSTSEC)
#   #54 D13      escalation-history narrative scrub (single-run framing)
#   #55 Rule 15  but-for causation gate (Critical/High only)
#   #56 Rule 16  parity-precedent citation when severity escalated by parity
#   #57 D20      consolidation linter (multiple test-file paths smell)
_R1316_TOOL="$AUDITOOOR_DIR/tools/pre-submit-rules-13-16-checks.py"
if [ -f "$_R1316_TOOL" ]; then
    echo ""
    for _R1316_NUM in 50 51 52 53 54 55 56 57; do
        case "$_R1316_NUM" in
            50) _R1316_LABEL="Rule 10 wrong-rubric cross-engagement contamination" ;;
            51) _R1316_LABEL="Rule 11 default-vs-opt-in claim cites code path" ;;
            52) _R1316_LABEL="Rule 12 L17 build-path itemization" ;;
            53) _R1316_LABEL="Rule 13 advisory-ID OOS-leak scrub" ;;
            54) _R1316_LABEL="D13 escalation-history narrative scrub" ;;
            55) _R1316_LABEL="Rule 15 but-for causation gate" ;;
            56) _R1316_LABEL="Rule 16 parity-precedent citation" ;;
            57) _R1316_LABEL="D20 consolidation linter" ;;
        esac
        _R1316_OUT=$(python3 "$_R1316_TOOL" "$SUB" --check "$_R1316_NUM" 2>&1)
        _R1316_RC=$?
        if [ "$_R1316_RC" -eq 0 ]; then
            if echo "$_R1316_OUT" | grep -q "soft-skip"; then
                echo "  ✅ ${_R1316_NUM}. ${_R1316_LABEL}: skipped"
                echo "       ${_R1316_OUT}" | sed 's/^[[:space:]]*//'
            else
                echo "  ✅ ${_R1316_NUM}. ${_R1316_LABEL}"
            fi
        else
            echo "  ❌ ${_R1316_NUM}. ${_R1316_LABEL}: FAILED"
            echo "$_R1316_OUT" | sed 's/^/       /'
            fails=$((fails + 1))
        fi
    done
else
    echo "  ⚠️  50-57. Rules 13-16 gates: tool not found ($_R1316_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 58: L32/R18/R19 in-process vs node-level evidence ----------------
_R18_TOOL="$AUDITOOOR_DIR/tools/in-process-vs-node-level-check.py"
if [ -f "$_R18_TOOL" ]; then
    echo ""
    _R18_TMP=$(mktemp 2>/dev/null || echo "/tmp/r18_node_$$.json")
    _R18_ERR=$(mktemp 2>/dev/null || echo "/tmp/r18_node_$$.err")
    _R18_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R18_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R18_TOOL" "${_R18_ARGS[@]}" > "$_R18_TMP" 2> "$_R18_ERR"
    _R18_RC=$?
    set -uo pipefail
    _R18_SUMMARY=$(
        python3 - "$_R18_TMP" "$_R18_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable in-process-vs-node-level output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (
    ("r18", "r18_trigger_hits"),
    ("r19", "r19_trigger_hits"),
    ("node", "node_level_hits"),
    ("inproc", "in_process_only_hits"),
):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R18_RC" -eq 0 ]; then
        echo "  ✅ 58. L32-IN-PROCESS-VS-NODE-LEVEL: $_R18_SUMMARY"
    elif [ "$_R18_RC" -eq 1 ]; then
        echo "  ❌ 58. L32-IN-PROCESS-VS-NODE-LEVEL blocked:"
        echo "       $_R18_SUMMARY"
        python3 - "$_R18_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = payload.get("evidence") or {}
for label, key in (
    ("r18-trigger", "r18_trigger_hits"),
    ("r19-trigger", "r19_trigger_hits"),
    ("in-process", "in_process_only_hits"),
):
    for hit in (evidence.get(key) or [])[:3]:
        print(f"{label}:{hit.get('line')} {hit.get('text')}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  58. L32-IN-PROCESS-VS-NODE-LEVEL error: $_R18_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R18_TMP" "$_R18_ERR"
else
    echo "  ⚠️  58. L32-IN-PROCESS-VS-NODE-LEVEL: tool not found ($_R18_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 59: R27 adjacent-finding disclosure ------------------------------
_R27_TOOL="$AUDITOOOR_DIR/tools/adjacent-finding-disclosure-check.py"
if [ -f "$_R27_TOOL" ]; then
    echo ""
    _R27_TMP=$(mktemp 2>/dev/null || echo "/tmp/r27_adjacent_$$.json")
    _R27_ERR=$(mktemp 2>/dev/null || echo "/tmp/r27_adjacent_$$.err")
    _R27_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R27_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R27_TOOL" "${_R27_ARGS[@]}" > "$_R27_TMP" 2> "$_R27_ERR"
    _R27_RC=$?
    set -uo pipefail
    _R27_SUMMARY=$(
        python3 - "$_R27_TMP" "$_R27_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable adjacent-finding-disclosure output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (("triggers", "trigger_hits"), ("boundary", "boundary_hits")):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R27_RC" -eq 0 ]; then
        echo "  ✅ 59. R27-ADJACENT-FINDING-DISCLOSURE: $_R27_SUMMARY"
    elif [ "$_R27_RC" -eq 1 ]; then
        echo "  ❌ 59. R27-ADJACENT-FINDING-DISCLOSURE blocked:"
        echo "       $_R27_SUMMARY"
        python3 - "$_R27_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = payload.get("evidence") or {}
for hit in (evidence.get("trigger_hits") or [])[:4]:
    source = hit.get("source") or ""
    line = hit.get("line")
    text = hit.get("text") or ""
    suffix = f":{line}" if line else ""
    print(f"adjacent-trigger: {source}{suffix} {text}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  59. R27-ADJACENT-FINDING-DISCLOSURE error: $_R27_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R27_TMP" "$_R27_ERR"
else
    echo "  ⚠️  59. R27-ADJACENT-FINDING-DISCLOSURE: tool not found ($_R27_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 60: R20 no fault injection --------------------------------------
_R20_TOOL="$AUDITOOOR_DIR/tools/no-fault-injection-check.py"
if [ -f "$_R20_TOOL" ]; then
    echo ""
    _R20_TMP=$(mktemp 2>/dev/null || echo "/tmp/r20_fault_$$.json")
    _R20_ERR=$(mktemp 2>/dev/null || echo "/tmp/r20_fault_$$.err")
    _R20_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R20_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R20_TOOL" "${_R20_ARGS[@]}" > "$_R20_TMP" 2> "$_R20_ERR"
    _R20_RC=$?
    set -uo pipefail
    _R20_SUMMARY=$(
        python3 - "$_R20_TMP" "$_R20_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable no-fault-injection output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
hits = evidence.get("actionable_fault_hits") or []
if hits:
    bits.append(f"fault_hits={len(hits)}")
print(" | ".join(bits))
PY
    )
    if [ "$_R20_RC" -eq 0 ]; then
        echo "  ✅ 60. R20-NO-FAULT-INJECTION: $_R20_SUMMARY"
    elif [ "$_R20_RC" -eq 1 ]; then
        echo "  ❌ 60. R20-NO-FAULT-INJECTION blocked:"
        echo "       $_R20_SUMMARY"
        python3 - "$_R20_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for hit in ((payload.get("evidence") or {}).get("actionable_fault_hits") or [])[:4]:
    source = hit.get("source") or ""
    line = hit.get("line")
    token = hit.get("token") or ""
    text = hit.get("text") or ""
    print(f"{source}:{line} token={token} {text}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  60. R20-NO-FAULT-INJECTION error: $_R20_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R20_TMP" "$_R20_ERR"
else
    echo "  ⚠️  60. R20-NO-FAULT-INJECTION: tool not found ($_R20_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 61: R22 restart-survival required -------------------------------
_R22_TOOL="$AUDITOOOR_DIR/tools/restart-survival-check.py"
if [ -f "$_R22_TOOL" ]; then
    echo ""
    _R22_TMP=$(mktemp 2>/dev/null || echo "/tmp/r22_restart_$$.json")
    _R22_ERR=$(mktemp 2>/dev/null || echo "/tmp/r22_restart_$$.err")
    set +e
    python3 "$_R22_TOOL" "$SUB" --json > "$_R22_TMP" 2> "$_R22_ERR"
    _R22_RC=$?
    set -uo pipefail
    _R22_SUMMARY=$(
        python3 - "$_R22_TMP" "$_R22_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable restart-survival output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (
    ("triggers", "trigger_hits"),
    ("restart_tests", "restart_test_hits"),
    ("reopen", "close_reopen_hits"),
    ("disclosures", "honest_disclosure_hits"),
):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R22_RC" -eq 0 ]; then
        if grep -q '"verdict": "pass-honest-disclosure"' "$_R22_TMP"; then
            echo "  ⚠️  61. R22-RESTART-SURVIVAL-REQUIRED: $_R22_SUMMARY"
            echo "       Restart-heals disclosure present; ensure severity is walked to a non-persistent tier."
            warns=$((warns + 1))
        else
            echo "  ✅ 61. R22-RESTART-SURVIVAL-REQUIRED: $_R22_SUMMARY"
        fi
    elif [ "$_R22_RC" -eq 1 ]; then
        echo "  ❌ 61. R22-RESTART-SURVIVAL-REQUIRED blocked:"
        echo "       $_R22_SUMMARY"
        python3 - "$_R22_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for hit in ((payload.get("evidence") or {}).get("trigger_hits") or [])[:4]:
    line = hit.get("line")
    text = hit.get("text") or ""
    print(f"trigger:{line} {text}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  61. R22-RESTART-SURVIVAL-REQUIRED error: $_R22_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R22_TMP" "$_R22_ERR"
else
    echo "  ⚠️  61. R22-RESTART-SURVIVAL-REQUIRED: tool not found ($_R22_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 62: R24 non-self-impact required -------------------------------
_R24_TOOL="$AUDITOOOR_DIR/tools/non-self-impact-check.py"
if [ -f "$_R24_TOOL" ]; then
    echo ""
    _R24_TMP=$(mktemp 2>/dev/null || echo "/tmp/r24_nonself_$$.json")
    _R24_ERR=$(mktemp 2>/dev/null || echo "/tmp/r24_nonself_$$.err")
    _R24_ARGS=("$SUB" "--strict")
    if [ -n "${SEVERITY:-}" ]; then
        _R24_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R24_TOOL" "${_R24_ARGS[@]}" > "$_R24_TMP" 2> "$_R24_ERR"
    _R24_RC=$?
    set -uo pipefail
    _R24_SUMMARY=$(
        python3 - "$_R24_TMP" "$_R24_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable non-self-impact-check output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("scope_keywords"):
    bits.append("scope=" + ", ".join(payload.get("scope_keywords") or []))
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (
    ("explicit", "explicit_non_self_hits"),
    ("characters", "non_self_character_hits"),
    ("assertions", "assertion_hits"),
):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R24_RC" -eq 0 ]; then
        if grep -q '"verdict": "pass-self-harm-disclosed"' "$_R24_TMP"; then
            echo "  ⚠️  62. R24-NON-SELF-IMPACT-REQUIRED: $_R24_SUMMARY"
            echo "       Self-harm is disclosed with a walk-back; do not file as High/Critical."
            warns=$((warns + 1))
        elif grep -q '"verdict": "ok-rebuttal"' "$_R24_TMP"; then
            echo "  ✅ 62. R24-NON-SELF-IMPACT-REQUIRED rebuttal accepted: $_R24_SUMMARY"
        else
            echo "  ✅ 62. R24-NON-SELF-IMPACT-REQUIRED: $_R24_SUMMARY"
        fi
    elif [ "$_R24_RC" -eq 1 ]; then
        echo "  ❌ 62. R24-NON-SELF-IMPACT-REQUIRED blocked:"
        echo "       $_R24_SUMMARY"
        python3 - "$_R24_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
for label, key in (
    ("non-self character", "non_self_character_hits"),
    ("attacker character", "attacker_character_hits"),
    ("assertion", "assertion_hits"),
):
    hits = (payload.get("evidence") or {}).get(key) or []
    for hit in hits[:2]:
        source = hit.get("source") or ""
        line = hit.get("line")
        text = hit.get("text") or ""
        suffix = f":{line}" if line else ""
        print(f"{label}: {source}{suffix} {text}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  62. R24-NON-SELF-IMPACT-REQUIRED error: $_R24_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R24_TMP" "$_R24_ERR"
else
    echo "  ⚠️  62. R24-NON-SELF-IMPACT-REQUIRED: tool not found ($_R24_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 63: R25 defense-in-depth traversal required ----------------------
_R25_TOOL="$AUDITOOOR_DIR/tools/defense-in-depth-traversal-check.py"
if [ -f "$_R25_TOOL" ]; then
    echo ""
    _R25_TMP=$(mktemp 2>/dev/null || echo "/tmp/r25_defense_$$.json")
    _R25_ERR=$(mktemp 2>/dev/null || echo "/tmp/r25_defense_$$.err")
    _R25_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R25_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R25_TOOL" "${_R25_ARGS[@]}" > "$_R25_TMP" 2> "$_R25_ERR"
    _R25_RC=$?
    set -uo pipefail
    _R25_SUMMARY=$(
        python3 - "$_R25_TMP" "$_R25_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable defense-in-depth output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (("triggers", "trigger_hits"), ("traversal", "traversal_hits"), ("local", "local_only_hits"), ("walkback", "walkback_hits")):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R25_RC" -eq 0 ]; then
        echo "  ✅ 63. R25-DEFENSE-IN-DEPTH-TRAVERSAL: $_R25_SUMMARY"
    elif [ "$_R25_RC" -eq 1 ]; then
        echo "  ❌ 63. R25-DEFENSE-IN-DEPTH-TRAVERSAL blocked:"
        echo "       $_R25_SUMMARY"
        python3 - "$_R25_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = payload.get("evidence") or {}
for label, key in (("trigger", "trigger_hits"), ("local-only", "local_only_hits")):
    for hit in (evidence.get(key) or [])[:3]:
        print(f"{label}:{hit.get('line')} {hit.get('text')}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  63. R25-DEFENSE-IN-DEPTH-TRAVERSAL error: $_R25_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R25_TMP" "$_R25_ERR"
else
    echo "  ⚠️  63. R25-DEFENSE-IN-DEPTH-TRAVERSAL: tool not found ($_R25_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 64: R26 ante-handler traversal required --------------------------
_R26_TOOL="$AUDITOOOR_DIR/tools/ante-handler-traversal-check.py"
if [ -f "$_R26_TOOL" ]; then
    echo ""
    _R26_TMP=$(mktemp 2>/dev/null || echo "/tmp/r26_ante_$$.json")
    _R26_ERR=$(mktemp 2>/dev/null || echo "/tmp/r26_ante_$$.err")
    _R26_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R26_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R26_TOOL" "${_R26_ARGS[@]}" > "$_R26_TMP" 2> "$_R26_ERR"
    _R26_RC=$?
    set -uo pipefail
    _R26_SUMMARY=$(
        python3 - "$_R26_TMP" "$_R26_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable ante-handler output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (("msgs", "cosmos_msg_hits"), ("ante", "ante_traversal_hits"), ("bypass", "ante_bypass_hits"), ("walkback", "walkback_hits")):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R26_RC" -eq 0 ]; then
        echo "  ✅ 64. R26-ANTE-HANDLER-TRAVERSAL: $_R26_SUMMARY"
    elif [ "$_R26_RC" -eq 1 ]; then
        echo "  ❌ 64. R26-ANTE-HANDLER-TRAVERSAL blocked:"
        echo "       $_R26_SUMMARY"
        python3 - "$_R26_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = payload.get("evidence") or {}
for label, key in (("msg", "cosmos_msg_hits"), ("bypass", "ante_bypass_hits")):
    for hit in (evidence.get(key) or [])[:3]:
        print(f"{label}:{hit.get('line')} {hit.get('text')}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  64. R26-ANTE-HANDLER-TRAVERSAL error: $_R26_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R26_TMP" "$_R26_ERR"
else
    echo "  ⚠️  64. R26-ANTE-HANDLER-TRAVERSAL: tool not found ($_R26_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 65: R23 comparative-baseline required ----------------------------
_R23_TOOL="$AUDITOOOR_DIR/tools/comparative-baseline-check.py"
if [ -f "$_R23_TOOL" ]; then
    echo ""
    _R23_TMP=$(mktemp 2>/dev/null || echo "/tmp/r23_comparative_$$.json")
    _R23_ERR=$(mktemp 2>/dev/null || echo "/tmp/r23_comparative_$$.err")
    _R23_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R23_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R23_TOOL" "${_R23_ARGS[@]}" > "$_R23_TMP" 2> "$_R23_ERR"
    _R23_RC=$?
    set -uo pipefail
    _R23_SUMMARY=$(
        python3 - "$_R23_TMP" "$_R23_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable comparative-baseline output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
if payload.get("missing"):
    bits.append("missing=" + ",".join(payload.get("missing") or []))
for label, key in (
    ("triggers", "trigger_hits"),
    ("comparators", "comparator_hits"),
    ("methods", "measurement_method_hits"),
    ("thresholds", "pass_fail_threshold_hits"),
):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R23_RC" -eq 0 ]; then
        echo "  ✅ 65. R23-COMPARATIVE-BASELINE: $_R23_SUMMARY"
    elif [ "$_R23_RC" -eq 1 ]; then
        echo "  ❌ 65. R23-COMPARATIVE-BASELINE blocked:"
        echo "       $_R23_SUMMARY"
        python3 - "$_R23_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = payload.get("evidence") or {}
for hit in (evidence.get("trigger_hits") or [])[:4]:
    print(f"comparative-trigger:{hit.get('line')} {hit.get('text')}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  65. R23-COMPARATIVE-BASELINE error: $_R23_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R23_TMP" "$_R23_ERR"
else
    echo "  ⚠️  65. R23-COMPARATIVE-BASELINE: tool not found ($_R23_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 66: R21 permanent-impact five-ask template -----------------------
_R21_TOOL="$AUDITOOOR_DIR/tools/permanent-impact-five-ask-template-check.py"
if [ -f "$_R21_TOOL" ]; then
    echo ""
    _R21_TMP=$(mktemp 2>/dev/null || echo "/tmp/r21_five_ask_$$.json")
    _R21_ERR=$(mktemp 2>/dev/null || echo "/tmp/r21_five_ask_$$.err")
    set +e
    python3 "$_R21_TOOL" "$SUB" --strict --json > "$_R21_TMP" 2> "$_R21_ERR"
    _R21_RC=$?
    set -uo pipefail
    _R21_SUMMARY=$(
        python3 - "$_R21_TMP" "$_R21_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable permanent-impact-five-ask output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
missing = evidence.get("missing_asks") or []
if missing:
    bits.append("missing=" + ",".join(missing))
coverage = evidence.get("ask_coverage") or {}
covered = [key for key, present in coverage.items() if present]
if covered:
    bits.append("covered=" + str(len(covered)))
print(" | ".join(bits))
PY
    )
    if [ "$_R21_RC" -eq 0 ]; then
        if grep -q '"verdict": "pass-honest-walkback"' "$_R21_TMP"; then
            echo "  ⚠️  66. R21-PERMANENT-IMPACT-5-ASK-TEMPLATE: $_R21_SUMMARY"
            echo "       Permanent-class claim is walked back; verify selected severity reflects that."
            warns=$((warns + 1))
        else
            echo "  ✅ 66. R21-PERMANENT-IMPACT-5-ASK-TEMPLATE: $_R21_SUMMARY"
        fi
    elif [ "$_R21_RC" -eq 1 ]; then
        echo "  ❌ 66. R21-PERMANENT-IMPACT-5-ASK-TEMPLATE blocked:"
        echo "       $_R21_SUMMARY"
        python3 - "$_R21_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = payload.get("evidence") or {}
for hit in (evidence.get("trigger_hits") or [])[:4]:
    print(f"permanent-trigger:{hit.get('line')} {hit.get('text')}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  66. R21-PERMANENT-IMPACT-5-ASK-TEMPLATE error: $_R21_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R21_TMP" "$_R21_ERR"
else
    echo "  ⚠️  66. R21-PERMANENT-IMPACT-5-ASK-TEMPLATE: tool not found ($_R21_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 67: R30 production-profile PoC preflight -------------------------
_R30_TOOL="$AUDITOOOR_DIR/tools/production-profile-preflight-check.py"
if [ -f "$_R30_TOOL" ]; then
    echo ""
    _R30_TMP=$(mktemp 2>/dev/null || echo "/tmp/r30_preflight_$$.json")
    _R30_ERR=$(mktemp 2>/dev/null || echo "/tmp/r30_preflight_$$.err")
    set +e
    python3 "$_R30_TOOL" "$SUB" > "$_R30_TMP" 2> "$_R30_ERR"
    _R30_RC=$?
    set -uo pipefail
    _R30_SUMMARY=$(
        python3 - "$_R30_TMP" "$_R30_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable production-profile-preflight output")
    raise SystemExit(0)

verdict = payload.get("verdict") or "unknown"
failed = payload.get("failed_constraints") or []
scope = ", ".join(payload.get("scope_keywords") or [])
poc_dirs = ", ".join(payload.get("poc_dirs") or [])
bits = [f"verdict={verdict}"]
if scope:
    bits.append(f"scope={scope}")
if poc_dirs:
    bits.append(f"poc={poc_dirs}")
if failed:
    constraints = ", ".join(str(item.get("constraint") or "?") for item in failed)
    bits.append(f"failed={constraints}")
print(" | ".join(bits))
PY
    )
    if [ "$_R30_RC" -eq 0 ]; then
        echo "  ✅ 67. R30-PRODUCTION-PROFILE-PREFLIGHT: $_R30_SUMMARY"
    elif [ "$_R30_RC" -eq 1 ]; then
        echo "  ❌ 67. R30-PRODUCTION-PROFILE-PREFLIGHT blocked:"
        echo "       $_R30_SUMMARY"
        python3 - "$_R30_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in payload.get("failed_constraints") or []:
    constraint = item.get("constraint") or "?"
    reason = item.get("reason") or "Rule 30 violation"
    print(f"clause ({constraint}): {reason}")
    for hit in (item.get("hits") or [])[:3]:
        loc = hit.get("path") or ""
        line = hit.get("line")
        text = hit.get("text") or ""
        suffix = f":{line}" if line else ""
        print(f"  {loc}{suffix} {text}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  67. R30-PRODUCTION-PROFILE-PREFLIGHT error: $_R30_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R30_TMP" "$_R30_ERR"
else
    echo "  ⚠️  67. R30-PRODUCTION-PROFILE-PREFLIGHT: tool not found ($_R30_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 68: L33 changelog drift coverage ---------------------------------
# GHSA-AWARE MODE: L33 is a SOLIDITY stale-invariant / changelog-drift gate. On a
# non-Solidity GHSA draft (e.g. a Rust/Zebra advisory) the word "stale" is normal
# prose and false-fires the gate. Neutralize: under GHSA_MODE skip #68 UNLESS the
# draft is actually Solidity (mentions `.sol`, `pragma solidity`, or `solidity`).
_L33_GHSA_SKIP=0
if [ "$GHSA_MODE" = "1" ]; then
    # Strip HTML comments before the solidity-detection grep: a GHSA draft may
    # carry an `<!-- l33-changelog-rebuttal: ... not a Solidity ... -->` marker
    # whose own word "Solidity" would otherwise false-trip the skip-defeat and
    # re-arm a Solidity-only gate against a Rust/Zebra advisory.
    _L33_TEXT_NOCOMMENT=$(printf '%s' "$text" | perl -0pe 's/<!--.*?-->//gs' 2>/dev/null || printf '%s' "$text")
    if printf '%s' "$_L33_TEXT_NOCOMMENT" | grep -qiE '\.sol\b|pragma solidity|\bsolidity\b'; then
        _L33_GHSA_SKIP=0
    else
        _L33_GHSA_SKIP=1
    fi
fi
_L33_TOOL="$AUDITOOOR_DIR/tools/l33-changelog-drift-check.py"
if [ "$_L33_GHSA_SKIP" = "1" ]; then
    echo ""
    echo "  ⏭️  68. L33-CHANGELOG-DRIFT-COVERAGE: SKIPPED under GHSA-AWARE MODE"
    echo "       (Solidity-only changelog-drift gate; this GHSA draft is non-Solidity,"
    echo "        so the word 'stale' is prose, not a stale-invariant claim.)"
elif [ -f "$_L33_TOOL" ]; then
    echo ""
    _L33_TMP=$(mktemp 2>/dev/null || echo "/tmp/l33_changelog_drift_$$.json")
    _L33_ERR=$(mktemp 2>/dev/null || echo "/tmp/l33_changelog_drift_$$.err")
    _L33_ARGS=("$SUB" "--mode" "gate" "--json")
    if [ -n "${_WS:-}" ]; then
        _L33_ARGS+=("--workspace" "$_WS")
    fi
    set +e
    python3 "$_L33_TOOL" "${_L33_ARGS[@]}" > "$_L33_TMP" 2> "$_L33_ERR"
    _L33_RC=$?
    set -uo pipefail
    _L33_SUMMARY=$(
        python3 - "$_L33_TMP" "$_L33_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable l33 changelog drift output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("triggered"):
    reasons = ",".join(payload.get("trigger_reasons") or [])
    if reasons:
        bits.append(f"trigger={reasons}")
stale_hits = payload.get("stale_hits") or []
if stale_hits:
    bits.append("phrases=" + ",".join(sorted({str(item.get("phrase") or "") for item in stale_hits if item.get("phrase")})))
refs = payload.get("changelog_refs") or []
if refs:
    bits.append(f"refs={len(refs)}")
miner = payload.get("miner") or {}
if miner.get("attempted"):
    bits.append(f"exposed={miner.get('exposed_count', 0)}")
reason = payload.get("reason") or ""
if reason:
    bits.append(reason)
print(" | ".join(bits))
PY
    )
    if [ "$_L33_RC" -eq 0 ]; then
        echo "  ✅ 68. L33-CHANGELOG-DRIFT-COVERAGE: $_L33_SUMMARY"
    elif [ "$_L33_RC" -eq 1 ]; then
        echo "  ❌ 68. L33-CHANGELOG-DRIFT-COVERAGE blocked:"
        echo "       $_L33_SUMMARY"
        python3 - "$_L33_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in (payload.get("changelog_refs") or [])[:5]:
    print(f"ref:{item.get('path')}:{item.get('line_ref')} (draft line {item.get('draft_line')})")
for item in (payload.get("stale_hits") or [])[:5]:
    print(f"phrase:{item.get('phrase')} (draft line {item.get('draft_line')})")
for site in ((payload.get("miner") or {}).get("exposed_call_sites") or [])[:3]:
    print(f"exposed:{site.get('file_path')}:{site.get('line')} {site.get('function')}")
print("Add `<!-- l33-rebuttal: <reason> -->` only when the stale changelog framing is still valid without an exposed consumer.")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  68. L33-CHANGELOG-DRIFT-COVERAGE error: $_L33_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_L33_TMP" "$_L33_ERR"
else
    echo "  ⚠️  68. L33-CHANGELOG-DRIFT-COVERAGE: tool not found ($_L33_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 69: R34 control-test / alternative-cause discipline -------------
_R34_TOOL="$AUDITOOOR_DIR/tools/control-test-discipline-check.py"
if [ -f "$_R34_TOOL" ]; then
    echo ""
    _R34_TMP=$(mktemp 2>/dev/null || echo "/tmp/r34_control_$$.json")
    _R34_ERR=$(mktemp 2>/dev/null || echo "/tmp/r34_control_$$.err")
    _R34_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R34_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R34_TOOL" "${_R34_ARGS[@]}" > "$_R34_TMP" 2> "$_R34_ERR"
    _R34_RC=$?
    set -uo pipefail
    _R34_SUMMARY=$(
        python3 - "$_R34_TMP" "$_R34_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable control-test-discipline output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (
    ("triggers", "trigger_hits"),
    ("controls", "control_hits"),
    ("sections", "alternative_rebuttal_section_hits"),
):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_R34_RC" -eq 0 ]; then
        echo "  ✅ 69. R34-CONTROL-TEST-DISCIPLINE: $_R34_SUMMARY"
    elif [ "$_R34_RC" -eq 1 ]; then
        echo "  ❌ 69. R34-CONTROL-TEST-DISCIPLINE blocked:"
        echo "       $_R34_SUMMARY"
        python3 - "$_R34_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for hit in ((payload.get("evidence") or {}).get("trigger_hits") or [])[:4]:
    source = hit.get("source") or ""
    line = hit.get("line")
    text = hit.get("text") or ""
    suffix = f":{line}" if line else ""
    print(f"trigger: {source}{suffix} {text}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  69. R34-CONTROL-TEST-DISCIPLINE error: $_R34_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R34_TMP" "$_R34_ERR"
else
    echo "  ⚠️  69. R34-CONTROL-TEST-DISCIPLINE: tool not found ($_R34_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 70: panic-context audit -----------------------------------------
_PCA_TOOL="$AUDITOOOR_DIR/tools/panic-context-audit.py"
if [ -f "$_PCA_TOOL" ]; then
    echo ""
    _PCA_TMP=$(mktemp 2>/dev/null || echo "/tmp/panic_context_$$.json")
    _PCA_ERR=$(mktemp 2>/dev/null || echo "/tmp/panic_context_$$.err")
    _PCA_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _PCA_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_PCA_TOOL" "${_PCA_ARGS[@]}" > "$_PCA_TMP" 2> "$_PCA_ERR"
    _PCA_RC=$?
    set -uo pipefail
    _PCA_SUMMARY=$(
        python3 - "$_PCA_TMP" "$_PCA_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable panic-context-audit output")
    raise SystemExit(0)

evidence = payload.get("evidence") or {}
bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')}")
for label, key in (
    ("live", "live_claim_hits"),
    ("panic", "panic_hits"),
    ("teardown", "teardown_hits"),
    ("stable", "stable_evidence_hits"),
):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_PCA_RC" -eq 0 ]; then
        echo "  ✅ 70. PANIC-CONTEXT-AUDIT: $_PCA_SUMMARY"
    elif [ "$_PCA_RC" -eq 1 ]; then
        echo "  ❌ 70. PANIC-CONTEXT-AUDIT blocked:"
        echo "       $_PCA_SUMMARY"
        python3 - "$_PCA_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = payload.get("evidence") or {}
for label, key in (("panic", "panic_hits"), ("teardown", "teardown_hits")):
    for hit in (evidence.get(key) or [])[:3]:
        source = hit.get("source") or ""
        line = hit.get("line")
        text = hit.get("text") or ""
        suffix = f":{line}" if line else ""
        print(f"{label}: {source}{suffix} {text}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  70. PANIC-CONTEXT-AUDIT error: $_PCA_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_PCA_TMP" "$_PCA_ERR"
else
    echo "  ⚠️  70. PANIC-CONTEXT-AUDIT: tool not found ($_PCA_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 71: severity-calibration ----------------------------------------
_SEVCAL_TOOL="$AUDITOOOR_DIR/tools/severity-calibration-check.py"
if [ -f "$_SEVCAL_TOOL" ]; then
    echo ""
    _SEVCAL_TMP=$(mktemp 2>/dev/null || echo "/tmp/severity_calibration_$$.json")
    _SEVCAL_ERR=$(mktemp 2>/dev/null || echo "/tmp/severity_calibration_$$.err")
    _SEVCAL_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _SEVCAL_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_SEVCAL_TOOL" "${_SEVCAL_ARGS[@]}" > "$_SEVCAL_TMP" 2> "$_SEVCAL_ERR"
    _SEVCAL_RC=$?
    set -uo pipefail
    _SEVCAL_SUMMARY=$(
        python3 - "$_SEVCAL_TMP" "$_SEVCAL_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable severity-calibration output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("claimed_severity"):
    bits.append(f"claimed={payload.get('claimed_severity')}")
if payload.get("predicted_triager_tier"):
    bits.append(f"predicted={payload.get('predicted_triager_tier')}")
if payload.get("overclaim_reasons"):
    bits.append("overclaim=" + ",".join(payload.get("overclaim_reasons") or []))
if payload.get("advisory_reasons"):
    bits.append("advisory=" + ",".join(payload.get("advisory_reasons") or []))
print(" | ".join(bits))
PY
    )
    if [ "$_SEVCAL_RC" -eq 0 ]; then
        if grep -q '"verdict": "pass-with-advisory"' "$_SEVCAL_TMP"; then
            echo "  ⚠️  71. SEVERITY-CALIBRATION: $_SEVCAL_SUMMARY"
            warns=$((warns + 1))
        else
            echo "  ✅ 71. SEVERITY-CALIBRATION: $_SEVCAL_SUMMARY"
        fi
    elif [ "$_SEVCAL_RC" -eq 1 ]; then
        echo "  ❌ 71. SEVERITY-CALIBRATION blocked:"
        echo "       $_SEVCAL_SUMMARY"
        python3 - "$_SEVCAL_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for reason in payload.get("overclaim_reasons") or []:
    print(f"overclaim: {reason}")
for label, key in (
    ("yield", "yield_hits"),
    ("internal", "protocol_internal_hits"),
    ("privileged", "privileged_hits"),
    ("restart", "restart_heals_hits"),
):
    for hit in ((payload.get("evidence") or {}).get(key) or [])[:2]:
        print(f"{label}:{hit.get('line')} {hit.get('text')}")
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  71. SEVERITY-CALIBRATION error: $_SEVCAL_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_SEVCAL_TMP" "$_SEVCAL_ERR"
else
    echo "  ⚠️  71. SEVERITY-CALIBRATION: tool not found ($_SEVCAL_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 72: HACKERMAN-RECORD-VERIFICATION-TIER ---------------------------
# Enforces verification_tier presence on every Hackerman v1 corpus record AND
# refuses to PASS when the submission cites a tier-5 quarantine record. The
# tool runs read-only against `audit/corpus_tags/tags/` and against the draft
# submission body. Missing corpus tree is downgraded to a warning so non-
# auditooor consumers of pre-submit-check still benefit from the rest of the
# pipeline.
_HKVT_TOOL="$AUDITOOOR_DIR/tools/hackerman-record-verification-tier-check.py"
if [ -f "$_HKVT_TOOL" ]; then
    echo ""
    _HKVT_TMP=$(mktemp 2>/dev/null || echo "/tmp/hackerman_vtier_$$.json")
    _HKVT_ERR=$(mktemp 2>/dev/null || echo "/tmp/hackerman_vtier_$$.err")
    _HKVT_ARGS=("--json" "--submission" "$SUB" "--allow-missing-tags-dir")
    set +e
    python3 "$_HKVT_TOOL" "${_HKVT_ARGS[@]}" > "$_HKVT_TMP" 2> "$_HKVT_ERR"
    _HKVT_RC=$?
    set -uo pipefail
    _HKVT_SUMMARY=$(
        python3 - "$_HKVT_TMP" "$_HKVT_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable hackerman-record-verification-tier output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
audited = payload.get("audited_hackerman_v1")
skipped = payload.get("skipped_non_hackerman_v1")
if audited is not None:
    bits.append(f"audited={audited}")
if skipped:
    bits.append(f"skipped_non_v1={skipped}")
fail_counts = {
    k: v for k, v in (payload.get("verdict_counts") or {}).items()
    if k not in {"pass", "quarantine", "skipped-non-hackerman-v1"}
}
if fail_counts:
    bits.append("fails=" + ",".join(f"{k}:{v}" for k, v in sorted(fail_counts.items())))
refs = payload.get("submission_quarantine_refs") or []
if refs:
    bits.append(f"quarantine_refs={len(refs)}")
reason = payload.get("reason") or ""
if reason and payload.get("verdict") != "pass":
    bits.append(reason)
print(" | ".join(bits))
PY
    )
    # DECOUPLE (TASK-B, applied GENERALLY): the tool's rc=1 conflates two very
    # different things - (i) GLOBAL corpus tier-debt (failed_records: records in
    # audit/corpus_tags/ that lack a verification_tier), which is unrelated to the
    # individual draft being checked, and (ii) a DRAFT-SPECIFIC tier-5 quarantine
    # citation (submission_quarantine_refs: the draft cites a fabricated record).
    # Only (ii) should block a single draft's rc. (i) is corpus-health telemetry
    # and is downgraded to a WARN so global tier-debt never blocks a clean draft.
    # This closes the documented Check-#72-coupling gap.
    _HKVT_SUB_REFS=$(python3 - "$_HKVT_TMP" 2>/dev/null <<'PY'
import json, sys
from pathlib import Path
try:
    p = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(len(p.get("submission_quarantine_refs") or []))
except Exception:
    print(0)
PY
)
    case "$_HKVT_SUB_REFS" in ''|*[!0-9]*) _HKVT_SUB_REFS=0 ;; esac
    if [ "$_HKVT_RC" -eq 0 ]; then
        echo "  ✅ 72. HACKERMAN-RECORD-VERIFICATION-TIER: $_HKVT_SUMMARY"
    elif [ "$_HKVT_RC" -eq 1 ] && [ "$_HKVT_SUB_REFS" -eq 0 ]; then
        # Pure global corpus tier-debt, draft cites zero tier-5 records: WARN only.
        echo "  ⚠️  72. HACKERMAN-RECORD-VERIFICATION-TIER (decoupled): $_HKVT_SUMMARY"
        echo "       Global corpus tier-debt (failed_records) does NOT block this draft."
        echo "       The draft cites ZERO tier-5 quarantine records. Corpus-health WARN:"
        echo "       run tools/hackerman-stratify-verification-tier.py + apply to label missing-tier records."
        warns=$((warns + 1))
    elif [ "$_HKVT_RC" -eq 1 ]; then
        # Draft itself cites tier-5 quarantine record(s): hard fail (draft-specific).
        echo "  ❌ 72. HACKERMAN-RECORD-VERIFICATION-TIER blocked (draft cites tier-5 quarantine):"
        echo "       $_HKVT_SUMMARY"
        python3 - "$_HKVT_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for ref in (payload.get("submission_quarantine_refs") or [])[:5]:
    rid = ref.get("record_id") or "?"
    via = ",".join(ref.get("matched_via") or [])
    path = ref.get("rel_path") or ref.get("file") or ""
    print(f"submission cites tier-5 quarantine: {rid} (via {via})")
    if path:
        print(f"  {path}")
print("remove any references to _QUARANTINE_FABRICATED_* records from the submission body before re-running.")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  72. HACKERMAN-RECORD-VERIFICATION-TIER error: $_HKVT_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_HKVT_TMP" "$_HKVT_ERR"
else
    echo "  ⚠️  72. HACKERMAN-RECORD-VERIFICATION-TIER: tool not found ($_HKVT_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 73: R38 bug-class-shift detection -------------------------------
# HIGH/CRITICAL drafts whose attack_class does not match the rubric phrase
# the draft cites must be corrected, OR rebutted via
# <!-- r38-rebuttal: <reason> --> (<=200 chars). Also fails when the draft
# cites a record_id present in .auditooor/bug_class_shift.jsonl without
# acknowledging the drift category. Source: docs/WAVE2_W29_NEW_GATES_SPEC.
_R38_TOOL="$AUDITOOOR_DIR/tools/bug-class-shift-check.py"
_R38_INDEX="$AUDITOOOR_DIR/.auditooor/bug_class_shift.jsonl"
if [ -f "$_R38_TOOL" ]; then
    echo ""
    _R38_TMP=$(mktemp 2>/dev/null || echo "/tmp/r38_shift_$$.json")
    _R38_ERR=$(mktemp 2>/dev/null || echo "/tmp/r38_shift_$$.err")
    _R38_ARGS=("$SUB" "--allow-missing-index" "--json")
    if [ -f "$_R38_INDEX" ]; then
        _R38_ARGS+=("--bug-class-shift-index" "$_R38_INDEX")
    fi
    if [ -n "${SEVERITY:-}" ]; then
        _R38_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R38_TOOL" "${_R38_ARGS[@]}" > "$_R38_TMP" 2> "$_R38_ERR"
    _R38_RC=$?
    set -uo pipefail
    _R38_SUMMARY=$(
        python3 - "$_R38_TMP" "$_R38_ERR" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    err = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable r38 output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
sev = payload.get("severity_observed")
if sev:
    bits.append(f"sev={sev}")
ac = payload.get("attack_class_observed")
if ac:
    bits.append(f"attack_class={ac}")
phrases = payload.get("rubric_phrases_observed") or []
if phrases:
    bits.append(f"rubric_phrases={len(phrases)}")
expected = payload.get("expected_impact_class") or []
if expected:
    bits.append(f"expected={','.join(expected)}")
hits = payload.get("record_ids_in_drift_index") or []
if hits:
    bits.append(f"drift_hits={len(hits)}")
reason = payload.get("reason") or ""
if reason and payload.get("verdict", "").startswith("fail"):
    bits.append(reason)
print(" | ".join(bits))
PY
    )
    if [ "$_R38_RC" -eq 0 ]; then
        echo "  ✅ 73. R38-BUG-CLASS-SHIFT: $_R38_SUMMARY"
    elif [ "$_R38_RC" -eq 1 ]; then
        echo "  ❌ 73. R38-BUG-CLASS-SHIFT blocked:"
        echo "       $_R38_SUMMARY"
        echo "       Fix: correct attack_class to match the rubric phrase,"
        echo "       OR add <!-- r38-rebuttal: <reason> --> (<=200 chars)."
        fails=$((fails + 1))
    else
        echo "  ⚠️  73. R38-BUG-CLASS-SHIFT error: $_R38_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R38_TMP" "$_R38_ERR"
else
    echo "  ⚠️  73. R38-BUG-CLASS-SHIFT: tool not found ($_R38_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 74: R39 attack-class-orphan flag --------------------------------
# HIGH/CRITICAL drafts whose attack_class is an orphan (single subtree OR
# <MIN_RECORDS corpus records) must be normalised to a canonical class OR
# rebutted via <!-- r39-rebuttal: <reason> --> (<=200 chars).
# Source: docs/WAVE2_W29_NEW_GATES_SPEC.
_R39_TOOL="$AUDITOOOR_DIR/tools/attack-class-orphan-check.py"
_R39_DIST="$AUDITOOOR_DIR/audit/corpus_tags/derived/attack_class_distribution.json"
_R39_TAX="$AUDITOOOR_DIR/audit/corpus_tags/derived/attack_class_taxonomy.json"
if [ -f "$_R39_TOOL" ]; then
    echo ""
    _R39_TMP=$(mktemp 2>/dev/null || echo "/tmp/r39_orphan_$$.json")
    _R39_ERR=$(mktemp 2>/dev/null || echo "/tmp/r39_orphan_$$.err")
    # A3: generate the attack-class distribution index ON-DEMAND if absent, so the R39
    # orphan gate is LIVE instead of silently skipped (Check #74 used to pass-out-of-scope
    # for every draft because the index was never produced). Best-effort: if the producer
    # fails, --allow-missing-index still degrades gracefully (no hard-fail on every draft).
    if [ ! -f "$_R39_DIST" ] && [ -f "$AUDITOOOR_DIR/tools/hackerman-attack-class-distribution.py" ]; then
        python3 "$AUDITOOOR_DIR/tools/hackerman-attack-class-distribution.py" --mode full --json \
            --out-json "$_R39_DIST" >/dev/null 2>&1 || true
    fi
    _R39_ARGS=("$SUB" "--allow-missing-index" "--json")
    if [ -f "$_R39_DIST" ]; then
        _R39_ARGS+=("--distribution-index" "$_R39_DIST")
    fi
    if [ -f "$_R39_TAX" ]; then
        _R39_ARGS+=("--taxonomy-index" "$_R39_TAX")
    fi
    if [ -n "${SEVERITY:-}" ]; then
        _R39_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R39_TOOL" "${_R39_ARGS[@]}" > "$_R39_TMP" 2> "$_R39_ERR"
    _R39_RC=$?
    set -uo pipefail
    _R39_SUMMARY=$(
        python3 - "$_R39_TMP" "$_R39_ERR" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    err = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable r39 output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
sev = payload.get("severity_observed")
if sev:
    bits.append(f"sev={sev}")
ac = payload.get("attack_class_observed")
if ac:
    bits.append(f"attack_class={ac}")
rc = payload.get("corpus_record_count")
sc = payload.get("corpus_subtree_count")
if rc is not None:
    bits.append(f"records={rc}")
if sc is not None:
    bits.append(f"subtrees={sc}")
near = payload.get("nearest_canonical_class")
if near:
    bits.append(f"nearest={near}")
reason = payload.get("reason") or ""
if reason and payload.get("verdict", "").startswith("fail"):
    bits.append(reason)
print(" | ".join(bits))
PY
    )
    if [ "$_R39_RC" -eq 0 ]; then
        echo "  ✅ 74. R39-ATTACK-CLASS-ORPHAN: $_R39_SUMMARY"
    elif [ "$_R39_RC" -eq 1 ]; then
        echo "  ❌ 74. R39-ATTACK-CLASS-ORPHAN blocked:"
        echo "       $_R39_SUMMARY"
        echo "       Fix: normalise attack_class to canonical class with"
        echo "       >=20 records and >=2 subtrees, OR add"
        echo "       <!-- r39-rebuttal: <reason> --> (<=200 chars)."
        fails=$((fails + 1))
    else
        echo "  ⚠️  74. R39-ATTACK-CLASS-ORPHAN error: $_R39_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R39_TMP" "$_R39_ERR"
else
    echo "  ⚠️  74. R39-ATTACK-CLASS-ORPHAN: tool not found ($_R39_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 75: R75 Wave-2-W21 post-migration validator ---------------------
# Fires only when the draft / recent commit touches audit/corpus_tags/.
# Scope predicate:
#   (a) draft text references `audit/corpus_tags/` or hackerman-record schema
#   (b) AUDITOOOR_R75_SCOPE=corpus env override
#   (c) `git diff --name-only HEAD~1 HEAD` shows audit/corpus_tags/* paths
# Out-of-scope drafts → verdict pass-out-of-scope (silent skip, no fail).
# Override via <!-- r75-rebuttal: <reason text up to 200 chars> -->.
# r36-rebuttal: lane bug-fix-and-haiku-2026-05-28 — typo fix (was _R76_TOOL, should reference _R75_TOOL defined immediately above)
_R75_TOOL="$AUDITOOOR_DIR/tools/wave2-w21-post-migration-validator.py"
if [ -f "$_R75_TOOL" ]; then
    # Scope predicate
    _R75_IN_SCOPE=0
    if [ "${AUDITOOOR_R75_SCOPE:-}" = "corpus" ]; then
        _R75_IN_SCOPE=1
    fi
    if [ "$_R75_IN_SCOPE" -eq 0 ] && grep -qE "audit/corpus_tags/|auditooor\.hackerman_record\.v1|hackerman v1|corpus migration|wave2-w21|wave-2 corpus" "$SUB" 2>/dev/null; then
        _R75_IN_SCOPE=1
    fi
    if [ "$_R75_IN_SCOPE" -eq 0 ] && [ -d "$AUDITOOOR_DIR/.git" ]; then
        if git -C "$AUDITOOOR_DIR" diff --name-only HEAD~1 HEAD 2>/dev/null | grep -qE "^audit/corpus_tags/"; then
            _R75_IN_SCOPE=1
        fi
    fi

    if [ "$_R75_IN_SCOPE" -eq 0 ]; then
        echo ""
        echo "  ✅ 75. R75-WAVE2-W21-POST-MIGRATION: verdict=pass-out-of-scope"
    else
        # Rebuttal probe: <!-- r75-rebuttal: <reason text up to 200 chars> -->
        _R75_REBUT=$(grep -oE '<!--[[:space:]]*r75-rebuttal:[^>]*-->' "$SUB" 2>/dev/null | head -1)
        _R75_REBUT_OK=0
        if [ -n "$_R75_REBUT" ]; then
            _R75_REBUT_REASON=$(printf "%s" "$_R75_REBUT" | sed -E 's/^<!--[[:space:]]*r75-rebuttal:[[:space:]]*//; s/[[:space:]]*-->$//')
            _R75_REBUT_LEN=$(printf "%s" "$_R75_REBUT_REASON" | wc -c | tr -d '[:space:]')
            if [ "$_R75_REBUT_LEN" -le 200 ]; then
                _R75_REBUT_OK=1
            fi
        fi

        echo ""
        _R75_TMP=$(mktemp 2>/dev/null || echo "/tmp/r75_w21_$$.json")
        _R75_ERR=$(mktemp 2>/dev/null || echo "/tmp/r75_w21_$$.err")
        _R75_WS="${AUDITOOOR_R75_WORKSPACE:-$AUDITOOOR_DIR}"
        set +e
        python3 "$_R75_TOOL" --workspace "$_R75_WS" --json --strict > "$_R75_TMP" 2> "$_R75_ERR"
        _R75_RC=$?
        set -uo pipefail

        _R75_VERDICT=$(
            python3 - "$_R75_TMP" "$_R75_ERR" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    err = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip()
    print(f"verdict=error|reason={err or 'unparseable r75 output'}")
    raise SystemExit(0)

status = payload.get("overall_status", "ERROR")
v1 = int(payload.get("v1_record_count", 0) or 0)
tier_missing = int(payload.get("verification_tier_missing", 0) or 0)
tier_invalid = int(payload.get("verification_tier_invalid_value", 0) or 0)
leak = payload.get("quarantine_leak_check", {}) or {}
leak_count = int(leak.get("by_cve_id_leak_count", 0) or 0)
leak_status = leak.get("status", "OK")
idx_health = payload.get("index_health", {}) or {}
corrupt = [n for n, info in idx_health.items() if info.get("status") not in ("OK", None)]

if status == "PASS":
    verdict = "pass-validator-clean"
elif status == "ERROR":
    verdict = "error"
elif v1 > 0:
    verdict = "fail-v1-residual"
elif leak_count > 0 or leak_status not in ("OK", None):
    verdict = "fail-quarantine-leak"
elif tier_missing > 0 or tier_invalid > 0:
    verdict = "fail-tier-missing"
elif corrupt:
    verdict = "fail-index-corrupt"
else:
    verdict = "fail-validator"

bits = [f"verdict={verdict}"]
bits.append(f"status={status}")
bits.append(f"v1={v1}")
bits.append(f"v1.1={int(payload.get('v1_1_record_count', 0) or 0)}")
bits.append(f"tier_missing={tier_missing}")
bits.append(f"tier_invalid={tier_invalid}")
bits.append(f"cve_leak={leak_count}")
if corrupt:
    bits.append(f"corrupt_indexes={','.join(corrupt)}")
fails_list = payload.get("failures") or []
if fails_list and verdict.startswith("fail"):
    bits.append("reason=" + fails_list[0][:120])
print("|".join(bits))
PY
        )

        case "$_R75_VERDICT" in
            verdict=pass-*)
                echo "  ✅ 75. R75-WAVE2-W21-POST-MIGRATION: $_R75_VERDICT"
                ;;
            verdict=error*)
                if [ "$_R75_REBUT_OK" -eq 1 ]; then
                    echo "  ✅ 75. R75-WAVE2-W21-POST-MIGRATION: verdict=ok-rebuttal | underlying=$_R75_VERDICT"
                else
                    echo "  ⚠️  75. R75-WAVE2-W21-POST-MIGRATION error: $_R75_VERDICT"
                    warns=$((warns + 1))
                fi
                ;;
            verdict=fail-*)
                if [ "$_R75_REBUT_OK" -eq 1 ]; then
                    echo "  ✅ 75. R75-WAVE2-W21-POST-MIGRATION: verdict=ok-rebuttal | underlying=$_R75_VERDICT"
                else
                    echo "  ❌ 75. R75-WAVE2-W21-POST-MIGRATION blocked: $_R75_VERDICT"
                    echo "       Fix: re-run tools/hackerman-schema-v1-to-v1.1-migrator.py +"
                    echo "       regenerate corpus_tags/index/ until validator returns PASS,"
                    echo "       OR add <!-- r75-rebuttal: <reason> --> (<=200 chars)."
                    fails=$((fails + 1))
                fi
                ;;
            *)
                echo "  ⚠️  75. R75-WAVE2-W21-POST-MIGRATION error: $_R75_VERDICT"
                warns=$((warns + 1))
                ;;
        esac
        rm -f "$_R75_TMP" "$_R75_ERR"
    fi
else
    echo "  ⚠️  75. R75-WAVE2-W21-POST-MIGRATION: tool not found ($_R75_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 76: HIGH+ MCP/toolsite live hardening wrapper --------------------
# GHSA-AWARE MODE: the HIGH+ live-hardening gate demands cosmos/EVM
# exploit-conversion artifacts (live target-protocol placeholder, on-chain
# production-reachability declaration, selected-impact selector) that a
# GHSA-format advisory cannot and should not produce. Skip for GHSA drafts;
# GHSA requirement gates (#42b/#43b) keep rigor enforced.
_HP_GATE_TOOL="$AUDITOOOR_DIR/tools/high-plus-submission-gate.py"
if [ "$GHSA_MODE" = "1" ]; then
    echo ""
    echo "  ⏭️  76. HIGH-PLUS-MCP-LIVE-HARDENING: SKIPPED under GHSA-AWARE MODE (GHSA-N/A: no cosmos/EVM live target-protocol / on-chain production-reachability artifacts for a GHSA advisory)"
elif [ -f "$_HP_GATE_TOOL" ]; then
    echo ""
    _HP_GATE_TMP=$(mktemp 2>/dev/null || echo "/tmp/high_plus_gate_$$.json")
    _HP_GATE_ERR=$(mktemp 2>/dev/null || echo "/tmp/high_plus_gate_$$.err")
    _HP_GATE_ARGS=("$SUB" "--skip-pre-submit" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _HP_GATE_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_HP_GATE_TOOL" "${_HP_GATE_ARGS[@]}" > "$_HP_GATE_TMP" 2> "$_HP_GATE_ERR"
    _HP_GATE_RC=$?
    set -uo pipefail
    _HP_GATE_SUMMARY=$(
        python3 - "$_HP_GATE_TMP" "$_HP_GATE_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable high-plus-submission-gate output")
    raise SystemExit(0)

bits = [
    f"status={payload.get('status') or 'unknown'}",
    f"severity={payload.get('severity') or 'unknown'}",
    f"blockers={payload.get('blocker_count', 0)}",
]
live = payload.get("live_hardening") or {}
if live.get("live_claim_detected"):
    bits.append("live_claim=true")
if live.get("target_protocol_placeholder_detected"):
    bits.append("target_protocol_placeholder=true")
if not live.get("selected_impact_present"):
    bits.append("selected_impact=missing")
if not live.get("production_reachability_declared"):
    bits.append("production_reachability=missing")
print(" | ".join(bits))
PY
    )
    if [ "$_HP_GATE_RC" -eq 0 ]; then
        echo "  ✅ 76. HIGH-PLUS-MCP-LIVE-HARDENING: $_HP_GATE_SUMMARY"
    elif [ "$_HP_GATE_RC" -eq 1 ]; then
        echo "  ❌ 76. HIGH-PLUS-MCP-LIVE-HARDENING blocked:"
        echo "       $_HP_GATE_SUMMARY"
        python3 - "$_HP_GATE_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for blocker in payload.get("blockers") or []:
    print(f"{blocker.get('code')}: {blocker.get('message')}")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  76. HIGH-PLUS-MCP-LIVE-HARDENING error: $_HP_GATE_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_HP_GATE_TMP" "$_HP_GATE_ERR"
else
    echo "  ⚠️  76. HIGH-PLUS-MCP-LIVE-HARDENING: tool not found ($_HP_GATE_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 77: Program-specific OOS semantic gate (Graph L2GNS anchor) ------
# A filed Graph CRITICAL was closed OUT OF SCOPE because the workspace had no
# real bounty OOS text imported (OOS_CHECKLIST.md still TBD, no OOS_PASTED.md)
# and the exploit path matched a frontrunning / sandwich / natural-network-
# activity OOS clause that no gate ever saw. This check fixes the general
# class:
#   (a) For every High/Critical draft, the full current bounty OOS text MUST
#       be imported into the workspace. If OOS_CHECKLIST.md is TBD and there
#       is no OOS_PASTED.md with clauses -> HARD FAIL (missing-real-oos).
#   (b) When real OOS text exists, a per-finding SEMANTIC check compares the
#       exploit path to every OOS clause (economic-sequencing trap +
#       natural-network-activity trap). A `matches-oos` verdict -> HARD FAIL.
#       The traps already downgrade to NO_MATCH when the draft carries a
#       non-empty `<!-- oos-economic-sequencing-rebuttal: ... -->` /
#       `<!-- oos-natural-activity-rebuttal: ... -->` marker, so a surviving
#       `matches-oos` means no alternate path was proven.
# This gate CANNOT be satisfied by generic "OOS: in-scope" boilerplate -- it
# runs the actual semantic comparison against the imported clauses. It is
# advisory (warn) for severities below High.
#
# SCOPE_OOS_SEMANTIC_GATE controls hard-fail: default `block` for High+, set
# to `warn` to downgrade to advisory. Below High the check is always advisory.
echo ""
echo "  77. Program-specific OOS semantic gate (Graph L2GNS anchor)..."
_OOS_SEM_TOOL="$AUDITOOOR_DIR/tools/per-finding-oos-check.py"
_OOS_SEM_MODE="${SCOPE_OOS_SEMANTIC_GATE:-block}"
_OOS_SEM_SEV_HIGH=0
case "${SEVERITY:-}" in
    High|high|HIGH|Critical|critical|CRITICAL) _OOS_SEM_SEV_HIGH=1 ;;
esac
if [ ! -f "$_OOS_SEM_TOOL" ]; then
    echo "  ⚠️  77. tools/per-finding-oos-check.py not found — skipping (advisory)"
    warns=$((warns + 1))
elif [ "$_OOS_SEM_SEV_HIGH" -ne 1 ]; then
    echo "  ✅ 77. severity ${SEVERITY:-Low} below High — OOS semantic gate advisory only"
elif [ -z "${_WS:-}" ]; then
    echo "  ⚠️  77. workspace not resolved — cannot run OOS semantic gate (advisory)"
    warns=$((warns + 1))
else
    # Step (a): real bounty OOS text must be imported into the workspace.
    _OOS_SEM_REALOUT=$(python3 "$_OOS_SEM_TOOL" \
        --workspace "$_WS" --finding "$SUB" --require-real-oos 2>&1)
    _OOS_SEM_REALRC=$?
    if [ "$_OOS_SEM_REALRC" -eq 4 ]; then
        if [ "$_OOS_SEM_MODE" = "warn" ]; then
            echo "  ⚠️  77. WARN: no real bounty OOS text imported (SCOPE_OOS_SEMANTIC_GATE=warn):"
            echo "$_OOS_SEM_REALOUT" | sed 's/^/       /'
            warns=$((warns + 1))
        else
            echo "  ❌ 77. oos-semantic-gate: missing-real-oos for High/Critical draft"
            echo "$_OOS_SEM_REALOUT" | sed 's/^/       /'
            echo "       Import the current bounty Out-of-Scope text into"
            echo "       $_WS/OOS_PASTED.md (operator-oos-import.py) or fill"
            echo "       $_WS/OOS_CHECKLIST.md with real non-TBD bullets."
            fails=$((fails + 1))
        fi
    elif [ "$_OOS_SEM_REALRC" -ne 0 ]; then
        echo "  ⚠️  77. OOS semantic gate real-oos probe rc=$_OOS_SEM_REALRC (advisory):"
        echo "$_OOS_SEM_REALOUT" | sed 's/^/       /'
        warns=$((warns + 1))
    else
        # Step (b): real OOS text exists — run the per-finding semantic check.
        _OOS_SEM_TMPWS=$(mktemp -d 2>/dev/null || mktemp -d -t 'oos-sem')
        _OOS_SEM_OUT=$(python3 "$_OOS_SEM_TOOL" \
            --workspace "$_OOS_SEM_TMPWS" --finding "$SUB" \
            --oos-file "$_WS/OOS_PASTED.md" 2>&1)
        _OOS_SEM_RC=$?
        _OOS_SEM_VERDICT=$(printf '%s\n' "$_OOS_SEM_OUT" \
            | grep -oE 'verdict=[a-z-]+' | head -1 | cut -d= -f2)
        rm -rf "$_OOS_SEM_TMPWS"
        if [ "$_OOS_SEM_RC" -ne 0 ]; then
            echo "  ⚠️  77. OOS semantic check rc=$_OOS_SEM_RC (advisory):"
            echo "$_OOS_SEM_OUT" | sed 's/^/       /'
            warns=$((warns + 1))
        elif [ "$_OOS_SEM_VERDICT" = "matches-oos" ]; then
            if [ "$_OOS_SEM_MODE" = "warn" ]; then
                echo "  ⚠️  77. WARN: exploit path matches an OOS clause (SCOPE_OOS_SEMANTIC_GATE=warn)"
                warns=$((warns + 1))
            else
                echo "  ❌ 77. oos-semantic-gate: exploit path semantically matches an OOS clause"
                echo "       The economic-sequencing or natural-network-activity trap fired."
                echo "       Either prove an alternate exploit path without the excluded"
                echo "       sequencing/activity and add an"
                echo "       <!-- oos-economic-sequencing-rebuttal: ... --> or"
                echo "       <!-- oos-natural-activity-rebuttal: ... --> marker, or drop."
                fails=$((fails + 1))
            fi
        elif [ "$_OOS_SEM_VERDICT" = "inconclusive" ]; then
            echo "  ⚠️  77. OOS semantic check inconclusive — review clauses (advisory)"
            warns=$((warns + 1))
        elif [ "$_OOS_SEM_VERDICT" = "in-scope" ]; then
            echo "  ✅ 77. OOS semantic gate: exploit path clears every OOS clause"
        else
            echo "  ⚠️  77. OOS semantic check unexpected verdict '$_OOS_SEM_VERDICT' (advisory)"
            warns=$((warns + 1))
        fi
    fi
fi

# --- Check 78: HACKER-QUESTION-ANSWERS gate --------------------------------
# Blocks only High/Critical drafts that match still-open hacker-question
# obligations. Helper/workspace/JSON issues are advisory so older workspaces do
# not brick unrelated filing work.
echo ""
echo "  78. HACKER-QUESTION-ANSWERS (open obligation answers)..."
_HQA_TOOL="$AUDITOOOR_DIR/tools/hacker-question-obligations.py"
_HQA_SEV_HIGH=0
case "${SEVERITY_ARG:-${SEVERITY:-}}" in
    High|Critical) _HQA_SEV_HIGH=1 ;;
esac

if [ "$_HQA_SEV_HIGH" -ne 1 ]; then
    echo "  ✅ 78. severity ${SEVERITY_ARG:-${SEVERITY:-unknown}} below High — hacker-question answers advisory only"
elif [ -z "${_WS:-}" ]; then
    echo "  ⚠️  78. workspace not resolved — cannot run HACKER-QUESTION-ANSWERS gate (advisory)"
    warns=$((warns + 1))
elif [ ! -f "$_HQA_TOOL" ]; then
    echo "  ⚠️  78. HACKER-QUESTION-ANSWERS: tool not found ($_HQA_TOOL); skipping"
    warns=$((warns + 1))
else
    _HQA_TMP=$(mktemp 2>/dev/null || echo "/tmp/hacker_question_answers_$$.json")
    _HQA_ERR=$(mktemp 2>/dev/null || echo "/tmp/hacker_question_answers_$$.err")
    set +e
    python3 "$_HQA_TOOL" --json gate-draft "$_WS" "$SUB" > "$_HQA_TMP" 2> "$_HQA_ERR"
    _HQA_RC=$?
    set -uo pipefail

    _HQA_SUMMARY=$(
        python3 - "$_HQA_TMP" "$_HQA_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable hacker-question-obligations gate-draft output")
    raise SystemExit(0)

counts = payload.get("counts") or {}
bits = [
    f"status={payload.get('status') or 'unknown'}",
    f"blocking={counts.get('blocking', 0)}",
    f"considered={counts.get('high_signal_considered', 0)}",
]
if payload.get("draft_path"):
    bits.append(f"draft={payload.get('draft_path')}")
print(" | ".join(bits))
PY
    )

    _HQA_OPEN_COUNT=$(
        python3 - "$_HQA_TMP" <<'PY' 2>/dev/null || echo 0
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(int((payload.get("counts") or {}).get("blocking", 0)))
PY
    )

    if [ "$_HQA_RC" -eq 0 ]; then
        echo "  ✅ 78. HACKER-QUESTION-ANSWERS: $_HQA_SUMMARY"
    elif [ "${_HQA_OPEN_COUNT:-0}" -gt 0 ]; then
        echo "  ❌ 78. HACKER-QUESTION-ANSWERS blocked:"
        echo "       $_HQA_SUMMARY"
        python3 - "$_HQA_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for row in (payload.get("blocking_obligations") or [])[:5]:
    oid = row.get("obligation_id") or "?"
    file_path = row.get("file") or ""
    fn = row.get("function_name") or ""
    question = row.get("question") or ""
    reasons = ",".join(row.get("match_reasons") or [])
    print(f"{oid}: {file_path} {fn} [{reasons}] {question}".strip())
print("Answer, kill, or promote matching open obligations before filing High/Critical.")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  78. HACKER-QUESTION-ANSWERS helper issue: $_HQA_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_HQA_TMP" "$_HQA_ERR"
fi

echo ""
echo "  81. SOURCE-READ-RECEIPTS (default High/Critical cited source coverage)..."
# GHSA-AWARE MODE: source-read receipts are emitted by the cosmos/EVM
# pre-source-read injector / hacker-question orchestration loop against an
# exploit-conversion workspace; a GHSA-format advisory (e.g. a Rust networking
# HashMap-key defect grep-verified by hand at the audit pin) produces no such
# receipt artifact. Skip for GHSA drafts; the GHSA requirement gates (#42b/#43b)
# plus the inline-PoC gate keep source rigor enforced.
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  81. SOURCE-READ-RECEIPTS: SKIPPED under GHSA-AWARE MODE (GHSA-N/A: no cosmos/EVM pre-source-read-injector receipt artifact for a GHSA advisory; source cites are grep-verified at the audit pin)"
elif [ "${STRICT_SOURCE_READ_RECEIPTS:-1}" = "0" ]; then
    echo "  ✅ 81. SOURCE-READ-RECEIPTS explicitly disabled by AUDITOOOR_STRICT_SOURCE_READ_RECEIPTS=0"
elif [ "$_HQA_SEV_HIGH" -ne 1 ]; then
    echo "  ✅ 81. severity ${SEVERITY_ARG:-${SEVERITY:-unknown}} below High — source-read receipt strict gate skipped"
elif [ -z "${_WS:-}" ]; then
    echo "  ❌ 81. SOURCE-READ-RECEIPTS strict mode enabled but workspace not resolved"
    fails=$((fails + 1))
elif [ ! -f "$_HQA_TOOL" ]; then
    echo "  ❌ 81. SOURCE-READ-RECEIPTS tool not found ($_HQA_TOOL)"
    fails=$((fails + 1))
else
    _SRR_TMP=$(mktemp 2>/dev/null || echo "/tmp/source_read_receipts_$$.json")
    _SRR_ERR=$(mktemp 2>/dev/null || echo "/tmp/source_read_receipts_$$.err")
    set +e
    python3 "$_HQA_TOOL" --json gate-source-read-receipts "$_WS" "$SUB" > "$_SRR_TMP" 2> "$_SRR_ERR"
    _SRR_RC=$?
    set -uo pipefail

    _SRR_SUMMARY=$(
        python3 - "$_SRR_TMP" "$_SRR_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable source-read receipt gate output")
    raise SystemExit(0)

counts = payload.get("counts") or {}
print(
    " | ".join(
        [
            f"status={payload.get('status') or 'unknown'}",
            f"cited={counts.get('cited_source_files', 0)}",
            f"with_receipts={counts.get('with_receipts', 0)}",
            f"missing={counts.get('missing_receipts', 0)}",
            f"stale={counts.get('stale_receipts', 0)}",
        ]
    )
)
PY
    )

    _SRR_MISSING_COUNT=$(
        python3 - "$_SRR_TMP" <<'PY' 2>/dev/null || echo 0
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(int((payload.get("counts") or {}).get("missing_receipts", 0)))
PY
    )
    _SRR_STALE_COUNT=$(
        python3 - "$_SRR_TMP" <<'PY' 2>/dev/null || echo 0
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(int((payload.get("counts") or {}).get("stale_receipts", 0)))
PY
    )

    if [ "$_SRR_RC" -eq 0 ]; then
        echo "  ✅ 81. SOURCE-READ-RECEIPTS: $_SRR_SUMMARY"
    elif [ "${_SRR_MISSING_COUNT:-0}" -gt 0 ] || [ "${_SRR_STALE_COUNT:-0}" -gt 0 ]; then
        echo "  ❌ 81. SOURCE-READ-RECEIPTS missing or stale cited source receipts:"
        echo "       $_SRR_SUMMARY"
        python3 - "$_SRR_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in (payload.get("missing_receipts") or [])[:8]:
    print(f"missing receipt: {item}")
stale = set(payload.get("stale_receipts") or [])
for row in payload.get("cited_source_files") or []:
    if row.get("file") not in stale:
        continue
    receipt = row.get("receipt") or {}
    source_path = receipt.get("source_path") or row.get("file")
    print(f"stale receipt: {row.get('file')} (current source changed at {source_path})")
print("Run the pre-source-read injector with --workspace, or answer/kill/promote the matching hacker-question obligations.")
PY
        fails=$((fails + 1))
    else
        echo "  ❌ 81. SOURCE-READ-RECEIPTS helper issue: $_SRR_SUMMARY"
        fails=$((fails + 1))
    fi
    rm -f "$_SRR_TMP" "$_SRR_ERR"
fi

echo ""
echo "  79. OUTCOME-LESSON-GATE..."
_OLG_TOOL="$AUDITOOOR_DIR/tools/outcome-lesson-gate.py"
_OLG_SEV_HIGH=0
case "${SEVERITY_ARG:-${SEVERITY:-}}" in
    High|Critical) _OLG_SEV_HIGH=1 ;;
esac

if [ "$_OLG_SEV_HIGH" -ne 1 ]; then
    echo "  ✅ 79. severity ${SEVERITY_ARG:-${SEVERITY:-unknown}} below High — outcome lessons advisory only"
elif [ ! -f "$_OLG_TOOL" ]; then
    echo "  ⚠️  79. OUTCOME-LESSON-GATE: tool not found ($_OLG_TOOL); skipping"
    warns=$((warns + 1))
else
    _OLG_TMP=$(mktemp 2>/dev/null || echo "/tmp/outcome_lesson_gate_$$.json")
    _OLG_ERR=$(mktemp 2>/dev/null || echo "/tmp/outcome_lesson_gate_$$.err")
    _OLG_ARGS=("--draft" "$SUB" "--format" "json" "--strict")
    if [ -f "$AUDITOOOR_DIR/.auditooor/lesson_enforcement_inventory.json" ]; then
        _OLG_ARGS+=("--inventory" "$AUDITOOOR_DIR/.auditooor/lesson_enforcement_inventory.json")
    fi
    if [ -f "$AUDITOOOR_DIR/.auditooor/lesson_source_inventory.json" ]; then
        _OLG_ARGS+=("--source-inventory" "$AUDITOOOR_DIR/.auditooor/lesson_source_inventory.json")
    fi
    set +e
    python3 "$_OLG_TOOL" "${_OLG_ARGS[@]}" > "$_OLG_TMP" 2> "$_OLG_ERR"
    _OLG_RC=$?
    set -uo pipefail

    _OLG_SUMMARY=$(
        python3 - "$_OLG_TMP" "$_OLG_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable outcome-lesson-gate output")
    raise SystemExit(0)

summary = payload.get("summary") or {}
bits = [
    f"status={payload.get('status') or 'unknown'}",
    f"hard_blockers={summary.get('hard_blocker_count', 0)}",
    f"warnings={summary.get('advisory_warning_count', 0)}",
    f"source_warnings={summary.get('inventory_coverage_warning_count', 0)}",
    f"matched={summary.get('matched_count', 0)}",
]
print(" | ".join(bits))
PY
    )

    _OLG_STATUS=$(
        python3 - "$_OLG_TMP" <<'PY' 2>/dev/null || echo unknown
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload.get("status") or "unknown")
PY
    )

    # HACKERMAN_V3 Lane J5a: standard rNN-rebuttal override convention.
    # <!-- r79-rebuttal: <reason text up to 200 chars> --> converts a hard
    # outcome-lesson FAIL into a warning when a bounded reason is supplied.
    _OLG_REBUT=$(grep -oE '<!--[[:space:]]*r79-rebuttal:[^>]*-->' "$SUB" 2>/dev/null | head -1)
    _OLG_REBUT_OK=0
    if [ -n "$_OLG_REBUT" ]; then
        _OLG_REBUT_REASON=$(printf "%s" "$_OLG_REBUT" | sed -E 's/^<!--[[:space:]]*r79-rebuttal:[[:space:]]*//; s/[[:space:]]*-->$//')
        _OLG_REBUT_LEN=$(printf "%s" "$_OLG_REBUT_REASON" | wc -c | tr -d '[:space:]')
        if [ -n "$_OLG_REBUT_REASON" ] && [ "$_OLG_REBUT_LEN" -le 200 ]; then
            _OLG_REBUT_OK=1
        fi
    fi

    if [ "$_OLG_RC" -eq 0 ] && [ "$_OLG_STATUS" = "pass" ]; then
        echo "  ✅ 79. OUTCOME-LESSON-GATE: $_OLG_SUMMARY"
    elif [ "$_OLG_RC" -eq 0 ] && [ "$_OLG_STATUS" = "warn" ]; then
        echo "  ⚠️  79. OUTCOME-LESSON-GATE warning: $_OLG_SUMMARY"
        python3 - "$_OLG_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for row in (payload.get("warnings") or [])[:5]:
    pred = row.get("predicate") or "?"
    signals = ",".join(row.get("matched_signals") or [])
    print(f"{pred}: signals={signals}")
PY
        warns=$((warns + 1))
    elif [ "$_OLG_STATUS" = "fail" ] && [ "$_OLG_REBUT_OK" -eq 1 ]; then
        echo "  ⚠️  79. OUTCOME-LESSON-GATE rebutted (r79-rebuttal): $_OLG_SUMMARY"
        echo "       reason: $_OLG_REBUT_REASON"
        warns=$((warns + 1))
    elif [ "$_OLG_STATUS" = "fail" ]; then
        echo "  ❌ 79. OUTCOME-LESSON-GATE blocked:"
        echo "       $_OLG_SUMMARY"
        python3 - "$_OLG_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for row in (payload.get("blockers") or [])[:5]:
    pred = row.get("predicate") or "?"
    level = row.get("enforcement_level") or "?"
    signals = ",".join(row.get("matched_signals") or [])
    obligations = row.get("suggested_proof_obligations") or []
    print(f"{pred} level={level} signals={signals}")
    for obligation in obligations[:2]:
        print(f"  proof: {obligation}")
print("Resolve the codified outcome lesson or add concrete proof that this draft is outside the trap.")
print("OR add <!-- r79-rebuttal: <reason text up to 200 chars> --> with a bounded source-backed exception.")
PY
        fails=$((fails + 1))
    else
        echo "  ⚠️  79. OUTCOME-LESSON-GATE helper issue: $_OLG_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_OLG_TMP" "$_OLG_ERR"
fi

echo ""
echo "  80. PREFILING-STRESS-ARTIFACT..."
_PST_SEV_HIGH=0
case "${SEVERITY_ARG:-${SEVERITY:-}}" in
    High|Critical) _PST_SEV_HIGH=1 ;;
esac

# GHSA-AWARE MODE: the prefiling stress artifact is produced by
# `make prefiling-stress-test` against a cosmos/EVM exploit-conversion workspace
# and has no analogue for a GHSA-format advisory. Skip for GHSA drafts; GHSA
# requirement gates (#42b/#43b) keep rigor enforced.
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  80. PREFILING-STRESS-ARTIFACT: SKIPPED under GHSA-AWARE MODE (GHSA-N/A: no cosmos/EVM prefiling-stress-test artifact for a GHSA advisory)"
elif [ "$_PST_SEV_HIGH" -ne 1 ]; then
    echo "  ✅ 80. severity ${SEVERITY_ARG:-${SEVERITY:-unknown}} below High — prefiling stress artifact advisory only"
elif [ -z "${_WS:-}" ]; then
    echo "  ⚠️  80. PREFILING-STRESS-ARTIFACT: workspace not resolved — Check 11 already hard-fails this"
    warns=$((warns + 1))
else
    _PST_TMP=$(mktemp 2>/dev/null || echo "/tmp/prefiling_stress_artifact_$$.txt")
    set +e
    python3 - "$_WS" "$SUB" > "$_PST_TMP" <<'PY'
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.prefiling_stress_test.v1"
workspace = Path(sys.argv[1]).expanduser().resolve()
draft = Path(sys.argv[2]).expanduser().resolve()
draft_stem = draft.stem

def norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")

def read_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def row_candidates() -> list[tuple[Path, dict]]:
    rows: list[tuple[Path, dict]] = []
    stress_dir = workspace / ".auditooor" / "prefiling_stress_tests"
    if stress_dir.is_dir():
        for path in sorted(stress_dir.glob("*.prefiling_stress_test.json")):
            payload = read_json(path)
            if isinstance(payload, dict):
                rows.append((path, payload))
    aggregate = workspace / ".auditooor" / "prefiling_stress_test.json"
    payload = read_json(aggregate)
    if isinstance(payload, dict):
        for result in payload.get("results") or []:
            if isinstance(result, dict):
                rows.append((aggregate, result))
    return rows

def matches(path: Path, row: dict) -> bool:
    candidate_id = str(row.get("candidate_id") or row.get("lead_id") or "").strip()
    if path.name == f"{draft_stem}.prefiling_stress_test.json":
        return True
    if norm(candidate_id) and norm(candidate_id) == norm(draft_stem):
        return True
    source_path = str(row.get("source_path") or "").strip()
    if source_path:
        try:
            if Path(source_path).expanduser().resolve() == draft:
                return True
        except Exception:
            pass
    return False

rows = row_candidates()
matches_found = [(path, row) for path, row in rows if matches(path, row)]

if not rows:
    print("status=missing | no prefiling stress artifacts found")
    raise SystemExit(1)
if not matches_found:
    ids = []
    for _, row in rows[:8]:
        cid = str(row.get("candidate_id") or row.get("lead_id") or "").strip()
        if cid:
            ids.append(cid)
    suffix = f" | available={','.join(ids)}" if ids else ""
    print(f"status=missing | no artifact matched draft={draft_stem}{suffix}")
    raise SystemExit(1)

path, row = max(matches_found, key=lambda item: item[0].stat().st_mtime if item[0].exists() else 0)
schema = row.get("schema_version")
verdict = str(row.get("verdict") or row.get("status") or "").lower()
if schema != SCHEMA:
    print(f"status=invalid | schema={schema or 'missing'} | artifact={path}")
    raise SystemExit(1)
if verdict != "pass":
    blockers = row.get("blocked_reasons") or row.get("blockers") or []
    warnings = row.get("warnings") or []
    reason = ",".join(str(x) for x in blockers[:4]) or ",".join(str(x) for x in warnings[:4]) or "verdict_not_pass"
    print(f"status={verdict or 'unknown'} | artifact={path} | blockers={reason}")
    raise SystemExit(1)

print(f"status=pass | artifact={path} | candidate={row.get('candidate_id') or draft_stem}")
PY
    _PST_RC=$?
    set -uo pipefail
    _PST_SUMMARY=$(cat "$_PST_TMP")
    if [ "$_PST_RC" -eq 0 ]; then
        echo "  ✅ 80. PREFILING-STRESS-ARTIFACT: $_PST_SUMMARY"
    else
        echo "  ❌ 80. PREFILING-STRESS-ARTIFACT blocked:"
        echo "       $_PST_SUMMARY"
        echo "       Run: make prefiling-stress-test WS=\"$_WS\" DRAFT=\"$SUB\""
        echo "       Fix every blocker until the artifact verdict is pass before filing High/Critical."
        fails=$((fails + 1))
    fi
    rm -f "$_PST_TMP"
fi

echo ""
echo "  82. CANDIDATE-JUDGMENT-PACKET..."
_CJP_SEV_HIGH=0
case "${SEVERITY_ARG:-${SEVERITY:-}}" in
    High|Critical) _CJP_SEV_HIGH=1 ;;
esac

# GHSA-AWARE MODE: the candidate judgment packet is produced by
# `make prove-top-leads` / `make exploit-conversion-loop` against a cosmos/EVM
# exploit-conversion workspace and has no analogue for a GHSA-format advisory.
# Skip for GHSA drafts; GHSA requirement gates (#42b/#43b) keep rigor enforced.
if [ "$GHSA_MODE" = "1" ]; then
    echo "  ⏭️  82. CANDIDATE-JUDGMENT-PACKET: SKIPPED under GHSA-AWARE MODE (GHSA-N/A: no cosmos/EVM prove-top-leads judgment packet for a GHSA advisory)"
elif [ "$_CJP_SEV_HIGH" -ne 1 ]; then
    echo "  ✅ 82. severity ${SEVERITY_ARG:-${SEVERITY:-unknown}} below High — candidate judgment packet advisory only"
elif [ -z "${_WS:-}" ]; then
    echo "  ⚠️  82. CANDIDATE-JUDGMENT-PACKET: workspace not resolved — Check 11 already hard-fails this"
    warns=$((warns + 1))
else
    _CJP_TMP=$(mktemp 2>/dev/null || echo "/tmp/candidate_judgment_packet_$$.txt")
    set +e
    python3 - "$_WS" "$SUB" > "$_CJP_TMP" <<'PY'
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.candidate_judgment_packet.v1"
READY = "ready_for_poc_planning"
LOCAL_BLOCKING_STATES = {
    "blocked_admin_gated_or_by_design",
    "blocked_by_dupe",
    "blocked_by_economics",
    "blocked_by_falsification",
    "blocked_by_scope",
    "blocked_intended_actor_mismatch",
    "blocked_missing_truth",
    "blocked_prior_disclosure",
    "blocked_severity_cap",
    "blocked_weak_proof",
}

workspace = Path(sys.argv[1]).expanduser().resolve()
draft = Path(sys.argv[2]).expanduser().resolve()
draft_text = draft.read_text(errors="replace")
draft_stem = draft.stem


def norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")


def read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def packet_paths() -> list[Path]:
    aud = workspace / ".auditooor"
    candidates = [
        aud / "candidate_judgment_packet.json",
        aud / "prove_top_leads_candidate_judgment_packet.json",
    ]
    if aud.is_dir():
        candidates.extend(sorted(aud.glob("*candidate_judgment_packet.json")))
    out: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path
        if path.is_file() and resolved not in seen:
            out.append(path)
            seen.add(resolved)
    return out


def packet_matches(packet: dict) -> bool:
    cid = str(packet.get("candidate_id") or "").strip()
    title = str(packet.get("title") or "").strip()
    if cid:
        cid_norm = norm(cid)
        if cid_norm and cid_norm == norm(draft_stem):
            return True
        if cid_norm and cid_norm in norm(draft_stem):
            return True
        if cid.lower() in draft_text.lower():
            return True
    if title:
        title_norm = norm(title)
        if title_norm and title_norm == norm(draft_stem):
            return True
    return False


if not packet_paths():
    print("status=missing | no candidate judgment packet found")
    raise SystemExit(1)

matching_artifacts: list[tuple[Path, dict, list[dict]]] = []
available: list[str] = []
invalid: list[str] = []
for path in packet_paths():
    payload = read_json(path)
    if not payload or payload.get("schema") != SCHEMA:
        invalid.append(path.as_posix())
        continue
    packets = [row for row in payload.get("packets") or [] if isinstance(row, dict)]
    for packet in packets:
        cid = str(packet.get("candidate_id") or "").strip()
        if cid:
            available.append(cid)
    matches = [packet for packet in packets if packet_matches(packet)]
    if matches:
        matching_artifacts.append((path, payload, matches))

if not matching_artifacts:
    suffix = f" | available={','.join(available[:12])}" if available else ""
    if invalid and not available:
        suffix = f" | invalid={','.join(invalid[:4])}"
    print(f"status=missing | no packet matched draft={draft_stem}{suffix}")
    raise SystemExit(1)

path, payload, matches = max(
    matching_artifacts,
    key=lambda item: item[0].stat().st_mtime if item[0].exists() else 0,
)
summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
if summary.get("strict_poc_planning_allowed") is not True:
    blockers = payload.get("strict_blockers") if isinstance(payload.get("strict_blockers"), list) else []
    details = []
    for blocker in blockers[:4]:
        if not isinstance(blocker, dict):
            continue
        details.append(
            f"{blocker.get('candidate_id') or blocker.get('packet_id')}:"
            f"{blocker.get('packet_state') or 'blocked'}"
        )
    detail = ",".join(details) or f"blocked_before_poc={summary.get('blocked_before_poc_count', 'unknown')}"
    print(f"status=blocked | artifact={path} | strict_poc_planning_allowed=false | {detail}")
    raise SystemExit(1)

bad: list[str] = []
for packet in matches:
    state = str(packet.get("packet_state") or "").strip()
    verdict = str(packet.get("verdict") or "").strip()
    cid = packet.get("candidate_id") or packet.get("packet_id") or "unknown"
    blockers = packet.get("promotion_blockers") if isinstance(packet.get("promotion_blockers"), list) else []
    if state in LOCAL_BLOCKING_STATES or verdict == "blocked_before_poc":
        bad.append(f"{cid}:{state or verdict}:{','.join(str(x) for x in blockers[:3])}")
    elif state != READY or verdict != READY:
        bad.append(f"{cid}:{state or 'unknown'}:{verdict or 'unknown'}")
    elif not packet.get("required_evidence_class"):
        bad.append(f"{cid}:missing_required_evidence_class")

if bad:
    print(f"status=blocked | artifact={path} | blockers={' ; '.join(bad[:4])}")
    raise SystemExit(1)

matched_ids = ",".join(str(packet.get("candidate_id") or packet.get("packet_id")) for packet in matches)
print(f"status=pass | artifact={path} | candidates={matched_ids}")
PY
    _CJP_RC=$?
    set -uo pipefail
    _CJP_SUMMARY=$(cat "$_CJP_TMP")
    if [ "$_CJP_RC" -eq 0 ]; then
        echo "  ✅ 82. CANDIDATE-JUDGMENT-PACKET: $_CJP_SUMMARY"
    else
        echo "  ❌ 82. CANDIDATE-JUDGMENT-PACKET blocked:"
        echo "       $_CJP_SUMMARY"
        echo "       Run: make prove-top-leads WS=\"$_WS\" TOP_N=10 STRICT=1 JSON=1"
        echo "       Or: make exploit-conversion-loop WS=\"$_WS\" TOP_N=10 STRICT=1 JSON=1"
        echo "       Regenerate a matching packet with all local judgment blockers cleared before filing High/Critical."
        fails=$((fails + 1))
    fi
    rm -f "$_CJP_TMP"
fi

# --- Check 83: OPPOSED-TRACE-REQUIRED (HACKERMAN_V3) -----------------------
_OT_TOOL="$AUDITOOOR_DIR/tools/opposed-trace-check.py"
if [ -f "$_OT_TOOL" ]; then
    echo ""
    _OT_TMP=$(mktemp 2>/dev/null || echo "/tmp/opposed_trace_$$.json")
    _OT_ERR=$(mktemp 2>/dev/null || echo "/tmp/opposed_trace_$$.err")
    _OT_ARGS=("$SUB")
    if [ -n "${SEVERITY:-}" ]; then
        _OT_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_OT_TOOL" "${_OT_ARGS[@]}" > "$_OT_TMP" 2> "$_OT_ERR"
    _OT_RC=$?
    set -uo pipefail
    _OT_SUMMARY=$(
        python3 - "$_OT_TMP" "$_OT_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable opposed-trace-check output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')[:120]}")
evidence = payload.get("evidence") or {}
for label, key in (
    ("triggers", "trigger_hits"),
    ("defenses", "defense_hits"),
    ("attacker_wins", "attacker_wins_hits"),
    ("defender_wins", "defender_wins_hits"),
):
    count = len(evidence.get(key) or [])
    if count:
        bits.append(f"{label}={count}")
print(" | ".join(bits))
PY
    )
    if [ "$_OT_RC" -eq 0 ]; then
        if grep -q '"verdict": "warn-unopposed-trace"' "$_OT_TMP" || grep -q '"verdict": "warn-defender-wins"' "$_OT_TMP"; then
            # Medium/Low advisory tier: the opposed-trace question is asked at
            # every severity, but below HIGH+ it is a mandatory advisory the
            # reviewer must clear - NOT a hard block.
            _OT_VERDICT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('verdict','unknown'))" "$_OT_TMP" 2>/dev/null || echo "unknown")
            echo "  ⚠️  83. OPPOSED-TRACE-REQUIRED advisory ($_OT_VERDICT):"
            echo "       $_OT_SUMMARY"
            echo "       Advisory only at this severity tier (not a hard block); the reviewer must"
            echo "       confirm no protocol-owned defense neutralizes the claimed impact."
            python3 - "$_OT_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
            echo "       Override: <!-- opposed-trace-rebuttal: <reason up to 200 chars> -->"
            warns=$((warns + 1))
        elif grep -q '"verdict": "ok-rebuttal"' "$_OT_TMP"; then
            echo "  ✅ 83. OPPOSED-TRACE-REQUIRED rebuttal accepted: $_OT_SUMMARY"
        elif grep -q '"verdict": "pass-out-of-scope"' "$_OT_TMP"; then
            echo "  ✅ 83. OPPOSED-TRACE-REQUIRED: out of scope — $_OT_SUMMARY"
        else
            echo "  ✅ 83. OPPOSED-TRACE-REQUIRED: $_OT_SUMMARY"
        fi
    elif [ "$_OT_RC" -eq 1 ]; then
        _OT_VERDICT=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('verdict','unknown'))" "$_OT_TMP" 2>/dev/null || echo "unknown")
        echo "  ❌ 83. OPPOSED-TRACE-REQUIRED blocked ($_OT_VERDICT):"
        echo "       $_OT_SUMMARY"
        python3 - "$_OT_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        echo "       Override: <!-- opposed-trace-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  83. OPPOSED-TRACE-REQUIRED error: $_OT_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_OT_TMP" "$_OT_ERR"
else
    echo "  ⚠️  83. OPPOSED-TRACE-REQUIRED: tool not found ($_OT_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 84: R40-V3-GRADE-POC-REQUIRED -----------------------------------
# Medium+ loss-of-funds / state-corruption / finalization / DoS claims must
# carry a V3-grade PoC: mocks may replace EXTERNAL dependencies only, and the
# vulnerable protocol-owned path must be real and exercised. Honest narrowing
# (claim narrowed to the source-level gap) PASSES. Override:
# `r40-rebuttal: <reason>` visible line or `<!-- r40-rebuttal: <reason> -->`.
_R40_TOOL="$AUDITOOOR_DIR/tools/v3-grade-poc-check.py"
if [ -f "$_R40_TOOL" ]; then
    echo ""
    _R40_TMP=$(mktemp 2>/dev/null || echo "/tmp/r40_v3poc_$$.json")
    _R40_ERR=$(mktemp 2>/dev/null || echo "/tmp/r40_v3poc_$$.err")
    _R40_ARGS=("$SUB" "--json")
    if [ -n "${SEVERITY:-}" ]; then
        _R40_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R40_TOOL" "${_R40_ARGS[@]}" > "$_R40_TMP" 2> "$_R40_ERR"
    _R40_RC=$?
    set -uo pipefail
    _R40_SUMMARY=$(
        python3 - "$_R40_TMP" "$_R40_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable v3-grade-poc-check output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')[:140]}")
points = payload.get("points") or {}
missing = [k for k, v in points.items() if not v]
if missing:
    bits.append("missing=" + ",".join(missing))
print(" | ".join(bits))
PY
    )
    if [ "$_R40_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R40_TMP"; then
            echo "  ✅ 84. R40-V3-GRADE-POC-REQUIRED rebuttal accepted: $_R40_SUMMARY"
        elif grep -q '"verdict": "pass-out-of-scope"' "$_R40_TMP"; then
            echo "  ✅ 84. R40-V3-GRADE-POC-REQUIRED: out of scope - $_R40_SUMMARY"
        elif grep -q '"verdict": "pass-claim-narrowed"' "$_R40_TMP"; then
            echo "  ✅ 84. R40-V3-GRADE-POC-REQUIRED: claim narrowed - $_R40_SUMMARY"
        else
            echo "  ✅ 84. R40-V3-GRADE-POC-REQUIRED: $_R40_SUMMARY"
        fi
    elif [ "$_R40_RC" -eq 1 ]; then
        echo "  ❌ 84. R40-V3-GRADE-POC-REQUIRED blocked:"
        echo "       $_R40_SUMMARY"
        python3 - "$_R40_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        echo "       Override: r40-rebuttal: <reason up to 200 chars>"
        echo "       or <!-- r40-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  84. R40-V3-GRADE-POC-REQUIRED error: $_R40_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R40_TMP" "$_R40_ERR"
else
    echo "  ⚠️  84. R40-V3-GRADE-POC-REQUIRED: tool not found ($_R40_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 85: R41-SUBMISSION-FOLDER-STRUCTURE -----------------------------
# Every bounty submission's artifacts must live together in a single per-finding
# folder named by the finding slug, under a status directory:
#   submissions/<status>/<slug>/<slug>.<ext>
# This check uses the per-draft form: it fails-closed if the draft being
# checked is not at submissions/<status>/<slug>/<slug>.md. Run the standalone
# tool with --workspace ... --check for the full status-dir scan, or --fix to
# reorganize flat artifacts.
_R41_TOOL="$AUDITOOOR_DIR/tools/submission-folder-structure-check.py"
if [ -f "$_R41_TOOL" ]; then
    echo ""
    _R41_TMP=$(mktemp 2>/dev/null || echo "/tmp/r41_subfolder_$$.json")
    _R41_ERR=$(mktemp 2>/dev/null || echo "/tmp/r41_subfolder_$$.err")
    set +e
    python3 "$_R41_TOOL" --draft "$SUB" --json > "$_R41_TMP" 2> "$_R41_ERR"
    _R41_RC=$?
    set -uo pipefail
    _R41_SUMMARY=$(
        python3 - "$_R41_TMP" "$_R41_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable submission-folder-structure-check output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("reason"):
    bits.append(f"reason={payload.get('reason')[:160]}")
print(" | ".join(bits))
PY
    )
    if [ "$_R41_RC" -eq 0 ]; then
        echo "  ✅ 85. R41-SUBMISSION-FOLDER-STRUCTURE: $_R41_SUMMARY"
    elif [ "$_R41_RC" -eq 1 ]; then
        echo "  ❌ 85. R41-SUBMISSION-FOLDER-STRUCTURE blocked:"
        echo "       $_R41_SUMMARY"
        python3 - "$_R41_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        echo "       Expected layout: submissions/<status>/<slug>/<slug>.md"
        fails=$((fails + 1))
    else
        echo "  ⚠️  85. R41-SUBMISSION-FOLDER-STRUCTURE error: $_R41_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R41_TMP" "$_R41_ERR"
else
    echo "  ⚠️  85. R41-SUBMISSION-FOLDER-STRUCTURE: tool not found ($_R41_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 86: REACHABILITY-VERIFICATION -----------------------------------
_REACH_TOOL="$AUDITOOOR_DIR/tools/reachability-verification-check.py"
if [ -f "$_REACH_TOOL" ]; then
    echo ""
    _REACH_TMP=$(mktemp 2>/dev/null || echo "/tmp/reachability_$$.json")
    _REACH_ERR=$(mktemp 2>/dev/null || echo "/tmp/reachability_$$.err")
    _REACH_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY_ARG:-}" ]; then
        _REACH_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_REACH_TOOL" "${_REACH_ARGS[@]}" > "$_REACH_TMP" 2> "$_REACH_ERR"
    _REACH_RC=$?
    set -uo pipefail
    _REACH_SUMMARY=$(
        python3 - "$_REACH_TMP" "$_REACH_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable reachability-verification-check output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={str(payload.get('reason'))[:140]}")
trace = payload.get("trace") or payload.get("evidence") or {}
if isinstance(trace, dict):
    for key in ("entrypoint", "dispatch_site", "registration_site", "override_site"):
        if trace.get(key):
            bits.append(f"{key}={str(trace.get(key))[:80]}")
print(" | ".join(bits))
PY
    )
    if [ "$_REACH_RC" -eq 0 ]; then
        echo "  ✅ 86. REACHABILITY-VERIFICATION: $_REACH_SUMMARY"
    elif [ "$_REACH_RC" -eq 1 ]; then
        echo "  ❌ 86. REACHABILITY-VERIFICATION blocked:"
        echo "       $_REACH_SUMMARY"
        echo "       Add a reachability_trace with production entrypoint + dispatch/registration site,"
        echo "       or a bounded <!-- reachability-rebuttal: <source-backed reason> -->."
        fails=$((fails + 1))
    else
        echo "  ⚠️  86. REACHABILITY-VERIFICATION error: $_REACH_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_REACH_TMP" "$_REACH_ERR"
else
    echo "  ⚠️  86. REACHABILITY-VERIFICATION: tool not found ($_REACH_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 87: PRIOR-AUDIT-DUPE-GATE ---------------------------------------
_PAD_TOOL="$AUDITOOOR_DIR/tools/prior-audit-dupe-gate.py"
if [ -f "$_PAD_TOOL" ]; then
    echo ""
    if [ -z "${_WS:-}" ]; then
        echo "  ⚠️  87. PRIOR-AUDIT-DUPE-GATE: workspace not resolved — Check 11 should already catch this"
        warns=$((warns + 1))
    else
        _PAD_TMP=$(mktemp 2>/dev/null || echo "/tmp/prior_audit_dupe_$$.json")
        _PAD_ERR=$(mktemp 2>/dev/null || echo "/tmp/prior_audit_dupe_$$.err")
        set +e
        python3 "$_PAD_TOOL" --workspace "$_WS" --draft "$SUB" --strict --json > "$_PAD_TMP" 2> "$_PAD_ERR"
        _PAD_RC=$?
        set -uo pipefail
        _PAD_SUMMARY=$(
            python3 - "$_PAD_TMP" "$_PAD_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable prior-audit-dupe-gate output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or payload.get('status') or 'unknown'}"]
for key in ("risk", "workspace", "draft"):
    if payload.get(key):
        bits.append(f"{key}={str(payload.get(key))[:100]}")
rows = payload.get("matches") or payload.get("hits") or payload.get("rows") or []
if isinstance(rows, list):
    bits.append(f"matches={len(rows)}")
blockers = payload.get("blockers") or payload.get("blocking_reasons") or []
if isinstance(blockers, list) and blockers:
    bits.append("blockers=" + ",".join(str(x)[:60] for x in blockers[:3]))
print(" | ".join(bits))
PY
        )
        if [ "$_PAD_RC" -eq 0 ]; then
            echo "  ✅ 87. PRIOR-AUDIT-DUPE-GATE: $_PAD_SUMMARY"
        elif [ "$_PAD_RC" -eq 1 ]; then
            echo "  ❌ 87. PRIOR-AUDIT-DUPE-GATE blocked:"
            echo "       $_PAD_SUMMARY"
            echo "       Add a real originality/distinction section or do not file a prior-audit duplicate."
            fails=$((fails + 1))
        else
            echo "  ⚠️  87. PRIOR-AUDIT-DUPE-GATE error: $_PAD_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_PAD_TMP" "$_PAD_ERR"
    fi
else
    echo "  ⚠️  87. PRIOR-AUDIT-DUPE-GATE: tool not found ($_PAD_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 88: CONFIG-DOWNSTREAM-TRACE -------------------------------------
# GHSA-AWARE MODE: #88 is the prose-only configured-component downstream-trace
# gate. A GHSA draft that is NOT a configured-component finding (a self-contained
# crate-level resource-leak / deserialization / panic bug) can declare so via a
# bounded rebuttal marker; under GHSA_MODE that skips #88. Marker forms:
#   <!-- not-configured-component: <reason up to 200 chars> -->
#   <!-- r88-not-config-rebuttal: <reason up to 200 chars> -->
#   <!-- config-downstream-rebuttal: <reason up to 200 chars> -->
_CDT_GHSA_SKIP=0
if [ "$GHSA_MODE" = "1" ]; then
    if printf '%s' "$text" | grep -qiE '<!--[[:space:]]*(not-configured-component|r88-not-config-rebuttal|config-downstream-rebuttal):[[:space:]]*[^>]+-->'; then
        _CDT_GHSA_SKIP=1
    fi
fi
_CDT_TOOL="$AUDITOOOR_DIR/tools/config-downstream-trace-check.py"
if [ "$_CDT_GHSA_SKIP" = "1" ]; then
    echo ""
    echo "  ⏭️  88. CONFIG-DOWNSTREAM-TRACE: SKIPPED under GHSA-AWARE MODE"
    echo "       (draft declares it is not a configured-component finding via"
    echo "        a not-configured-component rebuttal marker.)"
elif [ -f "$_CDT_TOOL" ]; then
    echo ""
    _CDT_TMP=$(mktemp 2>/dev/null || echo "/tmp/config_downstream_trace_$$.json")
    _CDT_ERR=$(mktemp 2>/dev/null || echo "/tmp/config_downstream_trace_$$.err")
    _CDT_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY_ARG:-}" ]; then
        _CDT_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_CDT_TOOL" "${_CDT_ARGS[@]}" > "$_CDT_TMP" 2> "$_CDT_ERR"
    _CDT_RC=$?
    set -uo pipefail
    _CDT_SUMMARY=$(
        python3 - "$_CDT_TMP" "$_CDT_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable config-downstream-trace-check output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={str(payload.get('reason'))[:140]}")
blockers = payload.get("blockers") or []
if isinstance(blockers, list) and blockers:
    bits.append("blockers=" + ",".join(str(x)[:60] for x in blockers[:4]))
evidence = payload.get("evidence") or {}
if isinstance(evidence, dict):
    surfaces = evidence.get("surface_hits") or []
    downstream = evidence.get("downstream_impact_hits") or []
    if isinstance(surfaces, list):
        bits.append(f"surface_hits={len(surfaces)}")
    if isinstance(downstream, list):
        bits.append(f"downstream_hits={len(downstream)}")
print(" | ".join(bits))
PY
    )
    if [ "$_CDT_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_CDT_TMP"; then
            echo "  ✅ 88. CONFIG-DOWNSTREAM-TRACE rebuttal accepted: $_CDT_SUMMARY"
        elif grep -q '"verdict": "pass-out-of-scope"' "$_CDT_TMP"; then
            echo "  ✅ 88. CONFIG-DOWNSTREAM-TRACE: out of scope - $_CDT_SUMMARY"
        elif grep -q '"verdict": "pass-not-applicable"' "$_CDT_TMP"; then
            echo "  ✅ 88. CONFIG-DOWNSTREAM-TRACE: not applicable - $_CDT_SUMMARY"
        else
            echo "  ✅ 88. CONFIG-DOWNSTREAM-TRACE: $_CDT_SUMMARY"
        fi
    elif [ "$_CDT_RC" -eq 1 ]; then
        echo "  ❌ 88. CONFIG-DOWNSTREAM-TRACE blocked:"
        echo "       $_CDT_SUMMARY"
        python3 - "$_CDT_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        echo "       Override: <!-- config-downstream-rebuttal: <source-backed reason up to 200 chars, e.g. file:line> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  88. CONFIG-DOWNSTREAM-TRACE error: $_CDT_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_CDT_TMP" "$_CDT_ERR"
else
    echo "  ⚠️  88. CONFIG-DOWNSTREAM-TRACE: tool not found ($_CDT_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 93: R45-DESIGNED-AS-INTENDED-PRECHECK ----------------------------
# Scope: HIGH+ drafts. Before accepting a "missing protection" or "omission"
# claim at High/Critical, verify that the omission is not documented by the
# protocol authors as a deliberate design decision. If the public spec/docs
# explicitly describe the behaviour as intentional (and defense-in-depth
# alternatives are named), the claim must be dropped or filed Informative max.
# Tool: tools/designed-as-intended-precheck.py <draft> --workspace <ws>
#       --strict --json
# Verdict vocabulary: pass-out-of-scope, pass-not-omission-claim,
#   pass-not-documented-as-intentional, pass-documented-not-defended,
#   pass-public-doc-oos-undisclosed, ok-rebuttal,
#   fail-designed-as-intended-with-defense-in-depth, error
# Override: visible `r45-rebuttal: <reason>` or
#           `<!-- r45-rebuttal: <reason> -->` (max 200 chars).
# Ordering note: fires BEFORE Check #89 (R42) because if R45 hits,
#   R42 narrowing is unhelpful.
_R45_TOOL="$AUDITOOOR_DIR/tools/designed-as-intended-precheck.py"
if [ -f "$_R45_TOOL" ]; then
    _R45_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|high|critical|High|Critical) _R45_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R45_SEVERITY_TRIGGER" = "true" ]; then
        _R45_TMP=$(mktemp 2>/dev/null || echo "/tmp/r45_dai_$$.json")
        _R45_ERR=$(mktemp 2>/dev/null || echo "/tmp/r45_dai_$$.err")
        _R45_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
        [ -n "$SEVERITY_ARG" ] && _R45_ARGS+=("--severity" "$SEVERITY_ARG")
        python3 "$_R45_TOOL" "${_R45_ARGS[@]}" > "$_R45_TMP" 2> "$_R45_ERR"
        _R45_RC=$?

        _R45_SUMMARY=$(
            python3 - "$_R45_TMP" "$_R45_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R45_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R45_TMP"; then
                echo "  ✅ 93. R45-DESIGNED-AS-INTENDED-PRECHECK rebuttal accepted: $_R45_SUMMARY"
            elif grep -qE '"verdict": "pass-' "$_R45_TMP"; then
                echo "  ✅ 93. R45-DESIGNED-AS-INTENDED-PRECHECK: $_R45_SUMMARY"
            else
                echo "  ✅ 93. R45-DESIGNED-AS-INTENDED-PRECHECK: $_R45_SUMMARY"
            fi
        elif [ "$_R45_RC" -eq 1 ]; then
            echo "  ❌ 93. R45-DESIGNED-AS-INTENDED-PRECHECK blocked:"
            echo "       $_R45_SUMMARY"
            python3 - "$_R45_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("  hint: " + str(h))
    doc = d.get("doc_reference", "")
    if doc:
        print("  doc: " + doc)
except Exception:
    pass
PY
            fails=$((fails + 1))
        else
            echo "  ⚠️  93. R45-DESIGNED-AS-INTENDED-PRECHECK error: $_R45_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R45_TMP" "$_R45_ERR"
    else
        echo "  ✅ 93. R45-DESIGNED-AS-INTENDED-PRECHECK: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  93. R45-DESIGNED-AS-INTENDED-PRECHECK: tool not found ($_R45_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 89: R42-CONFIGURED-IMPACT-TRACE ---------------------------------
# Any Medium+ claim whose impact depends on a deployed/configured component -
# a registered chain/client/router/oracle/adapter, feature flag, role set,
# asset pool, bridge reserve, runtime pallet, or downstream consumer - must
# carry a "Configured-Impact Trace": a configuration-precondition citation, a
# downstream-consumer path with file:line/PoC citations per hop, and an
# evidence-class match (an upstream-only PoC must word the impact as accepted
# forged/unfinalized state unless the downstream fund/message path is executed
# or fully source-traced). Honest narrowing PASSES. Fail-closed for Medium+
# drafts with a non-pass / non-rebuttal verdict. Override: visible
# `r42-rebuttal: <source-backed reason>` line or
# `<!-- r42-rebuttal: <source-backed reason> -->`.
_R42_TOOL="$AUDITOOOR_DIR/tools/configured-impact-trace-check.py"
if [ -f "$_R42_TOOL" ]; then
    echo ""
    _R42_TMP=$(mktemp 2>/dev/null || echo "/tmp/r42_configured_impact_$$.json")
    _R42_ERR=$(mktemp 2>/dev/null || echo "/tmp/r42_configured_impact_$$.err")
    _R42_ARGS=("$SUB" "--json")
    if [ -n "${SEVERITY_ARG:-}" ]; then
        _R42_ARGS+=("--severity" "$SEVERITY_ARG")
    fi
    set +e
    python3 "$_R42_TOOL" "${_R42_ARGS[@]}" > "$_R42_TMP" 2> "$_R42_ERR"
    _R42_RC=$?
    set -uo pipefail
    _R42_SUMMARY=$(
        python3 - "$_R42_TMP" "$_R42_ERR" <<'PY'
import json
import sys
from pathlib import Path

out_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
try:
    payload = json.loads(out_path.read_text(encoding="utf-8"))
except Exception:
    err = err_path.read_text(encoding="utf-8", errors="replace").strip()
    print(err or "unparseable configured-impact-trace-check output")
    raise SystemExit(0)

bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
if payload.get("severity"):
    bits.append(f"severity={payload.get('severity')}")
if payload.get("reason"):
    bits.append(f"reason={str(payload.get('reason'))[:140]}")
trace = payload.get("trace") or {}
if isinstance(trace, dict):
    missing = [k for k, v in trace.items() if v is False]
    if missing:
        bits.append("missing=" + ",".join(missing))
print(" | ".join(bits))
PY
    )
    if [ "$_R42_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R42_TMP"; then
            echo "  ✅ 89. R42-CONFIGURED-IMPACT-TRACE rebuttal accepted: $_R42_SUMMARY"
        elif grep -q '"verdict": "pass-out-of-scope"' "$_R42_TMP"; then
            echo "  ✅ 89. R42-CONFIGURED-IMPACT-TRACE: out of scope - $_R42_SUMMARY"
        elif grep -q '"verdict": "pass-not-config-dependent"' "$_R42_TMP"; then
            echo "  ✅ 89. R42-CONFIGURED-IMPACT-TRACE: not config-dependent - $_R42_SUMMARY"
        elif grep -q '"verdict": "pass-claim-narrowed"' "$_R42_TMP"; then
            echo "  ✅ 89. R42-CONFIGURED-IMPACT-TRACE: claim narrowed - $_R42_SUMMARY"
        else
            echo "  ✅ 89. R42-CONFIGURED-IMPACT-TRACE: $_R42_SUMMARY"
        fi
    elif [ "$_R42_RC" -eq 1 ]; then
        echo "  ❌ 89. R42-CONFIGURED-IMPACT-TRACE blocked:"
        echo "       $_R42_SUMMARY"
        python3 - "$_R42_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        echo "       Override: r42-rebuttal: <source-backed reason up to 200 chars>"
        echo "       or <!-- r42-rebuttal: <source-backed reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  89. R42-CONFIGURED-IMPACT-TRACE error: $_R42_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R42_TMP" "$_R42_ERR"
else
    echo "  ⚠️  89. R42-CONFIGURED-IMPACT-TRACE: tool not found ($_R42_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 97: R52-RUBRIC-ROW-COVERAGE ----------------------------------------
# Scope: LOW+ (severity-agnostic). Every draft must reference at least one
# verbatim rubric row from the target program's SEVERITY.md. If the draft's
# claimed impact cannot be matched to a rubric row, the submission is either
# out-of-scope or underbaked.
# Tool: tools/rubric-row-coverage-check.py <draft> --workspace <ws>
#       --strict --json
# Verdict vocabulary: pass-out-of-scope, pass-rubric-row-matched,
#   ok-rebuttal, fail-no-rubric-row-matched, error
# Override: visible `r52-rebuttal: <reason>` or
#           `<!-- r52-rebuttal: <reason> -->` (max 200 chars).
# Ordering note: fires FIRST among rubric-coverage checks, ahead of R35
#   (Check #90 DoS-class reframe). Per Rule 52 doctrine, R52 is structurally
#   UPSTREAM of R35: R52 catches "no row at all" (program does not list this
#   impact class); R35 then catches "wrong row" / "DoS-class-but-OOS" (program
#   lists the impact class but the specific DoS framing is OOS). Physical
#   ordering in this script matches the doctrine: R52 (#97) at line ~7280
#   fires before R35 (#90) at line ~7351. Check-number gap is intentional
#   and tolerated by the script's existing gap-numbering scheme.
_R52_TOOL="$AUDITOOOR_DIR/tools/rubric-row-coverage-check.py"
if [ -f "$_R52_TOOL" ]; then
    echo ""
    _R52_TMP=$(mktemp 2>/dev/null || echo "/tmp/r52_rubric_$$.json")
    _R52_ERR=$(mktemp 2>/dev/null || echo "/tmp/r52_rubric_$$.err")
    _R52_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
    [ -n "$SEVERITY_ARG" ] && _R52_ARGS+=("--severity" "$SEVERITY_ARG")
    python3 "$_R52_TOOL" "${_R52_ARGS[@]}" > "$_R52_TMP" 2> "$_R52_ERR"
    _R52_RC=$?

    _R52_SUMMARY=$(
        python3 - "$_R52_TMP" "$_R52_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_R52_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R52_TMP"; then
            echo "  ✅ 97. R52-RUBRIC-ROW-COVERAGE rebuttal accepted: $_R52_SUMMARY"
        elif grep -qE '"verdict": "pass-' "$_R52_TMP"; then
            echo "  ✅ 97. R52-RUBRIC-ROW-COVERAGE: $_R52_SUMMARY"
        else
            echo "  ✅ 97. R52-RUBRIC-ROW-COVERAGE: $_R52_SUMMARY"
        fi
    elif [ "$_R52_RC" -eq 1 ]; then
        echo "  ❌ 97. R52-RUBRIC-ROW-COVERAGE blocked:"
        echo "       $_R52_SUMMARY"
        python3 - "$_R52_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("  hint: " + str(h))
    rows = d.get("matched_rows", [])
    if not rows:
        print("  hint: no verbatim rubric row found - verify SEVERITY.md contains impact row matching draft claim")
except Exception:
    pass
PY
        echo "       Override: r52-rebuttal: <reason up to 200 chars>"
        echo "       or <!-- r52-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  97. R52-RUBRIC-ROW-COVERAGE error: $_R52_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R52_TMP" "$_R52_ERR"
else
    echo "  ⚠️  97. R52-RUBRIC-ROW-COVERAGE: tool not found ($_R52_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 90: R35-DOS-CLASS-REFRAME ---------------------------------------
_R35_TOOL="$AUDITOOOR_DIR/tools/dos-class-reframe-check.py"
if [ -f "$_R35_TOOL" ]; then
    _R35_TMP=$(mktemp 2>/dev/null || echo "/tmp/r35_dos_class_$$.json")
    _R35_ERR=$(mktemp 2>/dev/null || echo "/tmp/r35_dos_class_$$.err")
    _R35_ARGS=("$SUB" "--strict" "--json")
    if [ -n "${SEVERITY_ARG:-}" ]; then
        _R35_ARGS+=("--severity" "$SEVERITY_ARG")
    fi

    python3 "$_R35_TOOL" "${_R35_ARGS[@]}" > "$_R35_TMP" 2> "$_R35_ERR"
    _R35_RC=$?

    _R35_SUMMARY=$(
        python3 - "$_R35_TMP" "$_R35_ERR" <<'PY'
import json
import sys
from pathlib import Path

tmp = Path(sys.argv[1])
err = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip()
try:
    payload = json.loads(tmp.read_text(encoding="utf-8"))
    bits = [payload.get("verdict") or "unknown"]
    reason = payload.get("reason") or payload.get("error")
    if reason:
        bits.append(str(reason))
    evidence = payload.get("evidence") or {}
    dos_hits = evidence.get("dos_class_hits") or []
    nondos_hits = evidence.get("nondos_impact_hits") or []
    if isinstance(dos_hits, list):
        bits.append(f"dos_hits={len(dos_hits)}")
    if isinstance(nondos_hits, list):
        bits.append(f"nondos_hits={len(nondos_hits)}")
    print(" | ".join(bits))
except Exception:
    print(err or "unparseable dos-class-reframe output")
PY
    )

    if [ "$_R35_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R35_TMP"; then
            echo "  ✅ 90. R35-DOS-CLASS-REFRAME rebuttal accepted: $_R35_SUMMARY"
        elif grep -q '"verdict": "pass-out-of-scope"' "$_R35_TMP"; then
            echo "  ✅ 90. R35-DOS-CLASS-REFRAME: out of scope - $_R35_SUMMARY"
        elif grep -q '"verdict": "pass-dos-in-scope"' "$_R35_TMP"; then
            echo "  ✅ 90. R35-DOS-CLASS-REFRAME: DoS explicitly in scope - $_R35_SUMMARY"
        elif grep -q '"verdict": "pass-dos-reframed-to-nondos"' "$_R35_TMP"; then
            echo "  ✅ 90. R35-DOS-CLASS-REFRAME: reframed - $_R35_SUMMARY"
        else
            echo "  ✅ 90. R35-DOS-CLASS-REFRAME: $_R35_SUMMARY"
        fi
    elif [ "$_R35_RC" -eq 1 ]; then
        echo "  ❌ 90. R35-DOS-CLASS-REFRAME blocked:"
        echo "       $_R35_SUMMARY"
        python3 - "$_R35_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
        echo "       Override: r35-rebuttal: <reason up to 200 chars>"
        echo "       or <!-- r35-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  90. R35-DOS-CLASS-REFRAME error: $_R35_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R35_TMP" "$_R35_ERR"
else
    echo "  ⚠️  90. R35-DOS-CLASS-REFRAME: tool not found ($_R35_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 91: R43-LOAD-BEARING-BYTES-ATTRIBUTION ---------------------------
# Scope: Medium+ drafts that argue against a defender's narrative (multisig,
# committee threshold, timelock, operator whitelist). Requires a 7-field
# Load-Bearing Bytes Attribution section or r43-rebuttal override.
_R43_TOOL="$AUDITOOOR_DIR/tools/load-bearing-bytes-attribution-check.py"
if [ -f "$_R43_TOOL" ]; then
    # Skip if r43-rebuttal present in draft
    if grep -qiE 'r43-rebuttal' "$SUB" 2>/dev/null; then
        echo "  ✅ 91. R43-LOAD-BEARING-BYTES-ATTRIBUTION: r43-rebuttal present - skipping"
    else
        _R43_TMP=$(mktemp 2>/dev/null || echo "/tmp/r43_lbba_$$.json")
        _R43_ERR=$(mktemp 2>/dev/null || echo "/tmp/r43_lbba_$$.err")
        _R43_ARGS=("$SUB" "--strict" "--json")
        if [ -n "${SEVERITY_ARG:-}" ]; then
            _R43_ARGS+=("--severity" "$SEVERITY_ARG")
        fi
        set +e
        python3 "$_R43_TOOL" "${_R43_ARGS[@]}" > "$_R43_TMP" 2> "$_R43_ERR"
        _R43_RC=$?
        set -uo pipefail

        _R43_SUMMARY=$(
            python3 - "$_R43_TMP" "$_R43_ERR" <<'PY'
import json
import sys
from pathlib import Path

tmp = Path(sys.argv[1])
err = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip()
try:
    payload = json.loads(tmp.read_text(encoding="utf-8"))
    bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
    if payload.get("severity"):
        bits.append(f"severity={payload.get('severity')}")
    if payload.get("reason"):
        bits.append(f"reason={str(payload.get('reason'))[:140]}")
    trace = payload.get("trace") or {}
    if isinstance(trace, dict):
        missing = [k for k, v in trace.items() if v is False]
        if missing:
            bits.append("missing=" + ",".join(missing))
    print(" | ".join(bits))
except Exception:
    print(err or "unparseable load-bearing-bytes-attribution output")
PY
        )

        if [ "$_R43_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R43_TMP"; then
                echo "  ✅ 91. R43-LOAD-BEARING-BYTES-ATTRIBUTION rebuttal accepted: $_R43_SUMMARY"
            elif grep -q '"verdict": "pass-out-of-scope"' "$_R43_TMP"; then
                echo "  ✅ 91. R43-LOAD-BEARING-BYTES-ATTRIBUTION: out of scope - $_R43_SUMMARY"
            elif grep -q '"verdict": "pass-not-defender-narrative"' "$_R43_TMP"; then
                echo "  ✅ 91. R43-LOAD-BEARING-BYTES-ATTRIBUTION: no defender narrative - $_R43_SUMMARY"
            else
                echo "  ✅ 91. R43-LOAD-BEARING-BYTES-ATTRIBUTION: $_R43_SUMMARY"
            fi
        elif [ "$_R43_RC" -eq 1 ]; then
            echo "  ❌ 91. R43-LOAD-BEARING-BYTES-ATTRIBUTION blocked:"
            echo "       $_R43_SUMMARY"
            python3 - "$_R43_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
            echo "       Override: r43-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r43-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  91. R43-LOAD-BEARING-BYTES-ATTRIBUTION error: $_R43_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R43_TMP" "$_R43_ERR"
    fi
else
    echo "  ⚠️  91. R43-LOAD-BEARING-BYTES-ATTRIBUTION: tool not found ($_R43_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 92: R44-OPPOSED-TRACE-ACTOR-SEPARATION ---------------------------
# Scope: HIGH+ drafts whose PoC dir is resolvable from the draft. Fires when
# an opposed trace (attacker vs defender) is present but per-actor state
# assertions are absent. Requires before/after balance/state assertions for
# each actor, or r44-rebuttal override.
_R44_TOOL="$AUDITOOOR_DIR/tools/opposed-trace-actor-separation-check.py"
if [ -f "$_R44_TOOL" ]; then
    # Only run R44 on HIGH+ severity
    _R44_SEVERITY_OK=0
    case "${SEVERITY_ARG:-}" in
        High|Critical) _R44_SEVERITY_OK=1 ;;
    esac

    if [ "$_R44_SEVERITY_OK" -eq 0 ]; then
        echo "  ✅ 92. R44-OPPOSED-TRACE-ACTOR-SEPARATION: severity below HIGH - skipping"
    else
        # Resolve PoC dir: look for Proof artifacts / PoC line in draft
        _R44_POC_DIR=$(python3 - "$SUB" <<'PY' 2>/dev/null
import re
import sys
from pathlib import Path

draft = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
patterns = [
    r'(?:Proof artifacts?|PoC(?:\s+dir(?:ectory)?)?):\s*[`]?([~/\w.\-]+(?:poc[_-]tests?|poc|tests?)[/\w.\-]*)[`]?',
    r'(?:poc[_-]dir|harness)[:\s]+[`]?([~/\w.\-]+)[`]?',
]
for p in patterns:
    m = re.search(p, draft, re.IGNORECASE)
    if m:
        print(m.group(1).strip('`').strip())
        break
PY
)

        if [ -z "${_R44_POC_DIR:-}" ]; then
            echo "  ⚠️  92. R44-OPPOSED-TRACE-ACTOR-SEPARATION: PoC dir not resolvable from draft - skipping"
            warns=$((warns + 1))
        else
            _R44_TMP=$(mktemp 2>/dev/null || echo "/tmp/r44_actor_sep_$$.json")
            _R44_ERR=$(mktemp 2>/dev/null || echo "/tmp/r44_actor_sep_$$.err")
            _R44_ARGS=("$_R44_POC_DIR" "--strict" "--json")
            # Lane ZZZZZ iter17 fix: R44 tool's argparse only accepts UPPERCASE
            # severity choices {auto,LOW,MEDIUM,HIGH,CRITICAL}. Passing the
            # title-case SEVERITY_ARG ("High"/"Critical") caused argparse
            # to error out with "invalid choice: 'High'" - silent fail.
            # Use SEVERITY_UPPER (already computed at line 450).
            if [ -n "${SEVERITY_UPPER:-}" ]; then
                _R44_ARGS+=("--severity" "$SEVERITY_UPPER")
            fi
            set +e
            python3 "$_R44_TOOL" "${_R44_ARGS[@]}" > "$_R44_TMP" 2> "$_R44_ERR"
            _R44_RC=$?
            set -uo pipefail

            _R44_SUMMARY=$(
                python3 - "$_R44_TMP" "$_R44_ERR" <<'PY'
import json
import sys
from pathlib import Path

tmp = Path(sys.argv[1])
err = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip()
try:
    payload = json.loads(tmp.read_text(encoding="utf-8"))
    bits = [f"verdict={payload.get('verdict') or 'unknown'}"]
    if payload.get("severity"):
        bits.append(f"severity={payload.get('severity')}")
    if payload.get("reason"):
        bits.append(f"reason={str(payload.get('reason'))[:140]}")
    trace = payload.get("trace") or {}
    if isinstance(trace, dict):
        missing = [k for k, v in trace.items() if v is False]
        if missing:
            bits.append("missing=" + ",".join(missing))
    print(" | ".join(bits))
except Exception:
    print(err or "unparseable opposed-trace-actor-separation output")
PY
            )

            if [ "$_R44_RC" -eq 0 ]; then
                if grep -q '"verdict": "ok-rebuttal"' "$_R44_TMP"; then
                    echo "  ✅ 92. R44-OPPOSED-TRACE-ACTOR-SEPARATION rebuttal accepted: $_R44_SUMMARY"
                elif grep -q '"verdict": "pass-out-of-scope"' "$_R44_TMP"; then
                    echo "  ✅ 92. R44-OPPOSED-TRACE-ACTOR-SEPARATION: out of scope - $_R44_SUMMARY"
                elif grep -q '"verdict": "pass-no-opposed-trace"' "$_R44_TMP"; then
                    echo "  ✅ 92. R44-OPPOSED-TRACE-ACTOR-SEPARATION: no opposed trace - $_R44_SUMMARY"
                else
                    echo "  ✅ 92. R44-OPPOSED-TRACE-ACTOR-SEPARATION: $_R44_SUMMARY"
                fi
            elif [ "$_R44_RC" -eq 1 ]; then
                echo "  ❌ 92. R44-OPPOSED-TRACE-ACTOR-SEPARATION blocked:"
                echo "       $_R44_SUMMARY"
                python3 - "$_R44_TMP" <<'PY' | sed 's/^/       /'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for line in payload.get("remediation_options") or []:
    print(f"- {line}")
PY
                echo "       Override: r44-rebuttal: <reason up to 200 chars>"
                echo "       or <!-- r44-rebuttal: <reason up to 200 chars> -->"
                fails=$((fails + 1))
            else
                echo "  ⚠️  92. R44-OPPOSED-TRACE-ACTOR-SEPARATION error: $_R44_SUMMARY"
                warns=$((warns + 1))
            fi
            rm -f "$_R44_TMP" "$_R44_ERR"
        fi
    fi
else
    echo "  ⚠️  92. R44-OPPOSED-TRACE-ACTOR-SEPARATION: tool not found ($_R44_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 96: R47-ACKNOWLEDGED-WONT-FIX --------------------------------------
# Scope: HIGH+ drafts. Before filing at High/Critical, verify the claimed bug
# is not already acknowledged by the protocol team as a known limitation or
# wont-fix. Acknowledged-wont-fix bugs typically cannot earn a bounty and may
# be closed by triagers as informational or OOS.
# Tool: tools/acknowledged-wont-fix-check.py <draft> --workspace <ws>
#       --strict --json
# Verdict vocabulary: pass-out-of-scope, pass-not-acknowledged,
#   pass-acknowledged-but-no-fix, ok-rebuttal,
#   fail-acknowledged-wont-fix, error
# Override: visible `r47-rebuttal: <reason>` or
#           `<!-- r47-rebuttal: <reason> -->` (max 200 chars).
_R47_TOOL="$AUDITOOOR_DIR/tools/acknowledged-wont-fix-check.py"
if [ -f "$_R47_TOOL" ]; then
    _R47_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R47_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R47_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R47_TMP=$(mktemp 2>/dev/null || echo "/tmp/r47_awnf_$$.json")
        _R47_ERR=$(mktemp 2>/dev/null || echo "/tmp/r47_awnf_$$.err")
        _R47_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
        [ -n "$SEVERITY_ARG" ] && _R47_ARGS+=("--severity" "$SEVERITY_ARG")
        python3 "$_R47_TOOL" "${_R47_ARGS[@]}" > "$_R47_TMP" 2> "$_R47_ERR"
        _R47_RC=$?

        _R47_SUMMARY=$(
            python3 - "$_R47_TMP" "$_R47_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R47_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R47_TMP"; then
                echo "  ✅ 96. R47-ACKNOWLEDGED-WONT-FIX rebuttal accepted: $_R47_SUMMARY"
            elif grep -qE '"verdict": "pass-' "$_R47_TMP"; then
                echo "  ✅ 96. R47-ACKNOWLEDGED-WONT-FIX: $_R47_SUMMARY"
            else
                echo "  ✅ 96. R47-ACKNOWLEDGED-WONT-FIX: $_R47_SUMMARY"
            fi
        elif [ "$_R47_RC" -eq 1 ]; then
            echo "  ❌ 96. R47-ACKNOWLEDGED-WONT-FIX blocked:"
            echo "       $_R47_SUMMARY"
            python3 - "$_R47_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("  hint: " + str(h))
    refs = d.get("wontfix_references", [])
    for r in refs[:3]:
        print("  ref: " + str(r))
except Exception:
    pass
PY
            echo "       Override: r47-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r47-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  96. R47-ACKNOWLEDGED-WONT-FIX error: $_R47_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R47_TMP" "$_R47_ERR"
    else
        echo "  ✅ 96. R47-ACKNOWLEDGED-WONT-FIX: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  96. R47-ACKNOWLEDGED-WONT-FIX: tool not found ($_R47_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 95: R46-TRUSTED-INFRA-COMPROMISE ------------------------------------
# Scope: HIGH+ drafts. Claims that depend on an attacker having already
# compromised trusted infrastructure (a validator, an oracle node, a bridge
# relayer, a multisig signer) are typically OOS for most bounty programs.
# The gate checks whether the draft's attack preconditions assume a trusted
# component is already adversarial.
# Tool: tools/trusted-infrastructure-compromise-check.py <draft>
#       --workspace <ws> --strict --json
# Verdict vocabulary: pass-out-of-scope, pass-no-trusted-infra-precondition,
#   pass-trusted-infra-in-scope, ok-rebuttal,
#   fail-trusted-infra-precondition, error
# Override: visible `r46-rebuttal: <reason>` or
#           `<!-- r46-rebuttal: <reason> -->` (max 200 chars).
_R46_TOOL="$AUDITOOOR_DIR/tools/trusted-infrastructure-compromise-check.py"
if [ -f "$_R46_TOOL" ]; then
    _R46_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R46_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R46_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R46_TMP=$(mktemp 2>/dev/null || echo "/tmp/r46_tic_$$.json")
        _R46_ERR=$(mktemp 2>/dev/null || echo "/tmp/r46_tic_$$.err")
        _R46_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
        [ -n "$SEVERITY_ARG" ] && _R46_ARGS+=("--severity" "$SEVERITY_ARG")
        python3 "$_R46_TOOL" "${_R46_ARGS[@]}" > "$_R46_TMP" 2> "$_R46_ERR"
        _R46_RC=$?

        _R46_SUMMARY=$(
            python3 - "$_R46_TMP" "$_R46_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R46_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R46_TMP"; then
                echo "  ✅ 95. R46-TRUSTED-INFRA-COMPROMISE rebuttal accepted: $_R46_SUMMARY"
            elif grep -qE '"verdict": "pass-' "$_R46_TMP"; then
                echo "  ✅ 95. R46-TRUSTED-INFRA-COMPROMISE: $_R46_SUMMARY"
            else
                echo "  ✅ 95. R46-TRUSTED-INFRA-COMPROMISE: $_R46_SUMMARY"
            fi
        elif [ "$_R46_RC" -eq 1 ]; then
            echo "  ❌ 95. R46-TRUSTED-INFRA-COMPROMISE blocked:"
            echo "       $_R46_SUMMARY"
            python3 - "$_R46_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("  hint: " + str(h))
    triggers = d.get("trusted_infra_triggers", [])
    for t in triggers[:3]:
        print("  trigger: " + str(t))
except Exception:
    pass
PY
            echo "       Override: r46-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r46-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  95. R46-TRUSTED-INFRA-COMPROMISE error: $_R46_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R46_TMP" "$_R46_ERR"
    else
        echo "  ✅ 95. R46-TRUSTED-INFRA-COMPROMISE: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  95. R46-TRUSTED-INFRA-COMPROMISE: tool not found ($_R46_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 94: R29-COMMITMENT-VS-VALIDATION-GAP --------------------------------
# Scope: HIGH+ drafts. For cooperative / multi-party-exit protocol findings,
# the paste-ready MUST contain a top-level "Commitment & Protection Analysis"
# section enumerating: (a) commitment point (file:line where funds become
# irrecoverable), (b) validation gap class (POST-commit vs PRE-commit),
# (c) protection cardinality (number of independent guards between bug and
# impact). Without these three fields, triager will close as "user is facing
# fund loss anyway" / spam.
# Tool: tools/commitment-vs-validation-check.py <draft> --workspace <ws>
#       --strict --json
# Verdict vocabulary: pass-out-of-scope, pass-not-cooperative-exit,
#   pass-commitment-analysis-present, ok-rebuttal,
#   fail-missing-commitment-analysis, fail-missing-commitment-point,
#   fail-missing-validation-gap-class, fail-missing-protection-cardinality,
#   error
# Override: visible `r29-rebuttal: <reason>` or
#           `<!-- r29-rebuttal: <reason> -->` (max 200 chars).
_R29_TOOL="$AUDITOOOR_DIR/tools/commitment-vs-validation-check.py"
if [ -f "$_R29_TOOL" ]; then
    _R29_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R29_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R29_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R29_TMP=$(mktemp 2>/dev/null || echo "/tmp/r29_cvv_$$.json")
        _R29_ERR=$(mktemp 2>/dev/null || echo "/tmp/r29_cvv_$$.err")
        _R29_ARGS=("$SUB" "--strict" "--json")
        [ -n "$SEVERITY_ARG" ] && _R29_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
        python3 "$_R29_TOOL" "${_R29_ARGS[@]}" > "$_R29_TMP" 2> "$_R29_ERR"
        _R29_RC=$?

        _R29_SUMMARY=$(
            python3 - "$_R29_TMP" "$_R29_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R29_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R29_TMP"; then
                echo "  ✅ 94. R29-COMMITMENT-VS-VALIDATION-GAP rebuttal accepted: $_R29_SUMMARY"
            elif grep -qE '"verdict": "pass-' "$_R29_TMP"; then
                echo "  ✅ 94. R29-COMMITMENT-VS-VALIDATION-GAP: $_R29_SUMMARY"
            else
                echo "  ✅ 94. R29-COMMITMENT-VS-VALIDATION-GAP: $_R29_SUMMARY"
            fi
        elif [ "$_R29_RC" -eq 1 ]; then
            echo "  ❌ 94. R29-COMMITMENT-VS-VALIDATION-GAP blocked:"
            echo "       $_R29_SUMMARY"
            python3 - "$_R29_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("  hint: " + str(h))
    missing = d.get("missing_fields", [])
    for f in missing:
        print("  missing: " + str(f))
except Exception:
    pass
PY
            echo "       Override: r29-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r29-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  94. R29-COMMITMENT-VS-VALIDATION-GAP error: $_R29_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R29_TMP" "$_R29_ERR"
    else
        echo "  ✅ 94. R29-COMMITMENT-VS-VALIDATION-GAP: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  94. R29-COMMITMENT-VS-VALIDATION-GAP: tool not found ($_R29_TOOL); skipping"
    warns=$((warns + 1))
fi

# --- Check 98: R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE ----------------------
# Scope: HIGH+ drafts. When the contested vulnerability is gated by a specific
# deployment topology (restricted wallet type, env flag, testnet-only path),
# the draft MUST include a "Deployment Topology Attack Surface" section with 4
# required fields. Without it, drafts get closed as "POLY_1271 restricted to
# Deposit Wallets" or "testnet-only".
# Tool: tools/deployment-topology-vs-attack-surface-check.py <draft>
#       --workspace <ws> --strict --json
# Verdict vocabulary: pass-out-of-scope, pass-no-topology-restriction,
#   pass-restricted-but-population-non-empty, ok-rebuttal,
#   fail-no-topology-tabulation, fail-restricted-and-empty-population,
#   fail-test-only-deployment, error
# Override: visible `r48-rebuttal: <reason>` or
#           `<!-- r48-rebuttal: <reason> -->` (max 200 chars).
# Ordering note: fires AFTER Check #97 R52 (rubric coverage) and BEFORE
#   Check #96 R47 (acknowledged-wont-fix) - OOS topology is upstream.
_R48_TOOL="$AUDITOOOR_DIR/tools/deployment-topology-vs-attack-surface-check.py"
if [ -f "$_R48_TOOL" ]; then
    _R48_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R48_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R48_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R48_TMP=$(mktemp 2>/dev/null || echo "/tmp/r48_deptop_$$.json")
        _R48_ERR=$(mktemp 2>/dev/null || echo "/tmp/r48_deptop_$$.err")
        _R48_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
        [ -n "$SEVERITY_ARG" ] && _R48_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
        python3 "$_R48_TOOL" "${_R48_ARGS[@]}" > "$_R48_TMP" 2> "$_R48_ERR"
        _R48_RC=$?

        _R48_SUMMARY=$(
            python3 - "$_R48_TMP" "$_R48_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R48_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R48_TMP"; then
                echo "  ✅ 98. R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE rebuttal accepted: $_R48_SUMMARY"
            elif grep -qE '"verdict": "pass-' "$_R48_TMP"; then
                echo "  ✅ 98. R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE: $_R48_SUMMARY"
            else
                echo "  ✅ 98. R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE: $_R48_SUMMARY"
            fi
        elif [ "$_R48_RC" -eq 1 ]; then
            echo "  ❌ 98. R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE blocked:"
            echo "       $_R48_SUMMARY"
            python3 - "$_R48_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("  hint: " + str(h))
    missing = d.get("missing_fields", [])
    for f in missing:
        print("  missing: " + str(f))
except Exception:
    pass
PY
            echo "       Override: r48-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r48-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  98. R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE error: $_R48_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R48_TMP" "$_R48_ERR"
    else
        echo "  ✅ 98. R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  98. R48-DEPLOYMENT-TOPOLOGY-VS-ATTACK-SURFACE: tool not found ($_R48_TOOL); skipping"
    warns=$((warns + 1))
fi

# ==========================================================================
# Check #99: R53-PRIOR-AUDIT-FINDING-SUPERSEDE (Rule 53)
#
# Generalizes L31 (dupe-preflight) from in-workspace dashboard-grep to in-tree
# prior_audits/* corpus deep-scan. L31 catches workspace-local dupes (other
# findings filed by this engagement). R53 catches EXTERNAL prior-audit
# acknowledgements - findings in published audit reports under
# <workspace>/prior_audits/* that supersede the current finding.
#
# Trigger: HIGH+ drafts before paste_ready promotion.
# Required section: "Prior-Audit Supersede Scan" with 4 sub-fields:
#   1. Workspace prior_audits/ inventory
#   2. Matched prior finding (verbatim quote + file:line citation if found)
#   3. Extension-distinct evidence (new bypass / new surface)
#   4. Verdict
# Tool: tools/prior-audit-finding-supersede-check.py <draft>
#       --workspace <ws> --strict --json
# Verdicts: pass-out-of-scope, pass-no-prior-audits-corpus,
#   pass-no-matching-prior-finding, pass-extension-distinct-from-prior,
#   ok-rebuttal, fail-superseded-by-prior-audit, fail-no-supersede-scan, error
# Override: visible `r53-rebuttal: <reason>` or
#           `<!-- r53-rebuttal: <reason> -->` (max 200 chars).
# Distinct from R47: R47 scans GHSA/SECURITY.md/SRL catalogs;
#   R53 scans prior_audits/ audit-report corpus.
# Ordering note: fires AFTER Check #98 R48 (deployment topology).
_R53_TOOL="$AUDITOOOR_DIR/tools/prior-audit-finding-supersede-check.py"
if [ -f "$_R53_TOOL" ]; then
    _R53_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R53_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R53_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R53_TMP=$(mktemp 2>/dev/null || echo "/tmp/r53_supersede_$$.json")
        _R53_ERR=$(mktemp 2>/dev/null || echo "/tmp/r53_supersede_$$.err")
        _R53_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
        [ -n "$SEVERITY_ARG" ] && _R53_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
        python3 "$_R53_TOOL" "${_R53_ARGS[@]}" > "$_R53_TMP" 2> "$_R53_ERR"
        _R53_RC=$?

        _R53_SUMMARY=$(
            python3 - "$_R53_TMP" "$_R53_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R53_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R53_TMP"; then
                echo "  ✅ 99. R53-PRIOR-AUDIT-FINDING-SUPERSEDE rebuttal accepted: $_R53_SUMMARY"
            elif grep -qE '"verdict": "pass-' "$_R53_TMP"; then
                echo "  ✅ 99. R53-PRIOR-AUDIT-FINDING-SUPERSEDE: $_R53_SUMMARY"
            else
                echo "  ✅ 99. R53-PRIOR-AUDIT-FINDING-SUPERSEDE: $_R53_SUMMARY"
            fi
        elif [ "$_R53_RC" -eq 1 ]; then
            echo "  ❌ 99. R53-PRIOR-AUDIT-FINDING-SUPERSEDE blocked:"
            echo "       $_R53_SUMMARY"
            python3 - "$_R53_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("  hint: " + str(h))
    for o in d.get("overlapping_prior_audits", [])[:2]:
        print("  prior: " + o.get("file","?") + " tokens=" + str(o.get("common_tokens",[])))
    for o in d.get("overlapping_corpus_prior_audits", [])[:2]:
        print("  corpus-prior: " + o.get("record_id","?")
              + " files=" + str(o.get("common_file_refs",[]))
              + " tokens=" + str(o.get("common_tokens",[])))
except Exception:
    pass
PY
            echo "       Override: r53-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r53-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  99. R53-PRIOR-AUDIT-FINDING-SUPERSEDE error: $_R53_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R53_TMP" "$_R53_ERR"
    else
        echo "  ✅ 99. R53-PRIOR-AUDIT-FINDING-SUPERSEDE: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  99. R53-PRIOR-AUDIT-FINDING-SUPERSEDE: tool not found ($_R53_TOOL); skipping"
    warns=$((warns + 1))
fi

# ==========================================================================
# Check #100: R28-MULTI-PATH-ESCALATION-MERGE (Rule 28)
#
# When >=2 in-flight harness / escalation paths target the same filed Cantina
# submission ID, DO NOT paste any single one into Cantina. Wait for ALL paths
# to land, MERGE into a single unified triager response, paste once.
#
# Trigger: HIGH+ drafts that reference a filed Cantina submission ID (e.g.
# #192, cantina-192, cantina/#192, submission #192) where TWO OR MORE drafts
# targeting the same submission ID exist across submissions/staging/,
# submissions/paste_ready/, submissions/held/, submissions/superseded/,
# submissions/ready/, submissions/filed/ in the workspace.
#
# Tool: tools/multi-path-escalation-merge-check.py <draft>
#       --workspace <ws> --strict --json
# Verdicts: pass-out-of-scope, pass-no-cantina-id-cited,
#   pass-only-one-path-in-flight, pass-merged-into-unified-response,
#   ok-rebuttal, fail-multiple-paths-in-flight-unmerged, error
# Override: visible `r28-rebuttal: <reason>` or
#           `<!-- r28-rebuttal: <reason up to 200 chars> -->`.
# Ordering note: fires AFTER Check #99 R53 (prior-audit supersede) and
# BEFORE Check #101 R54 (external URL liveness).
#
# Empirical anchor: 2026-05-11 #213 / ASA-2024-0012 / #213-v4 - three
# in-flight refile paths for the same MaxUnpackAnySubCalls cap weakening
# bug; v3 said walk-back-to-MEDIUM, v4 in-flight said HIGH-via-all-validators
# -DoS, ASA-2024 in-progress aimed at CRIT. Operator caught the conflation
# risk before any of the three was pasted. R28 codifies "merge before paste".
_R28_TOOL="$AUDITOOOR_DIR/tools/multi-path-escalation-merge-check.py"
if [ -f "$_R28_TOOL" ]; then
    _R28_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R28_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R28_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R28_TMP=$(mktemp 2>/dev/null || echo "/tmp/r28_multi_path_$$.json")
        _R28_ERR=$(mktemp 2>/dev/null || echo "/tmp/r28_multi_path_$$.err")
        _R28_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
        [ -n "$SEVERITY_ARG" ] && _R28_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
        python3 "$_R28_TOOL" "${_R28_ARGS[@]}" > "$_R28_TMP" 2> "$_R28_ERR"
        _R28_RC=$?

        _R28_SUMMARY=$(
            python3 - "$_R28_TMP" "$_R28_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R28_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R28_TMP"; then
                echo "  ✅ 100. R28-MULTI-PATH-ESCALATION-MERGE rebuttal accepted: $_R28_SUMMARY"
            elif grep -qE '"verdict": "pass-' "$_R28_TMP"; then
                echo "  ✅ 100. R28-MULTI-PATH-ESCALATION-MERGE: $_R28_SUMMARY"
            else
                echo "  ✅ 100. R28-MULTI-PATH-ESCALATION-MERGE: $_R28_SUMMARY"
            fi
        elif [ "$_R28_RC" -eq 1 ]; then
            echo "  ❌ 100. R28-MULTI-PATH-ESCALATION-MERGE blocked:"
            echo "       $_R28_SUMMARY"
            python3 - "$_R28_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("hints", []):
        print("hint: " + str(h))
    for p in d.get("sibling_paths", [])[:3]:
        print("sibling: " + str(p))
except Exception:
    pass
PY
            echo "       Override: r28-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r28-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  100. R28-MULTI-PATH-ESCALATION-MERGE error: $_R28_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R28_TMP" "$_R28_ERR"
    else
        echo "  ✅ 100. R28-MULTI-PATH-ESCALATION-MERGE: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  100. R28-MULTI-PATH-ESCALATION-MERGE: tool not found ($_R28_TOOL); skipping"
    warns=$((warns + 1))
fi

# ==========================================================================
# Check #101: R54-EXTERNAL-URL-LIVENESS (Rule 54)
#
# Every external URL cited by a draft must be LIVE at promotion time. Dead
# URLs (HTTP 404 / 410 / 5xx) in HIGH+ dispute/triager-response/finding
# drafts are load-bearing evidence the triager will attempt to verify; a
# 404 collapses the disputed claim on first click.
#
# Trigger: ANY draft (LOW+) before promotion to paste_ready/ or filed/.
# Severity-agnostic because mismatched-URL closures happen at all severities.
#
# Tool: tools/external-url-liveness-check.py <draft>
#       --strict --timeout 8 --json
# Verdicts: pass-no-external-urls, pass-all-urls-live, ok-rebuttal,
#   fail-dead-url-cited, fail-network-validation-failed-strict, error
# Override: visible `r54-rebuttal: <reason>` or
#           `<!-- r54-rebuttal: <reason> -->` (max 200 chars).
# Network failures degrade to warn unless --strict.
# Ordering note: fires AFTER Check #99 R53 (prior-audit supersede).
#
# Empirical anchor: 2026-05-23 iter16 MMMMM Hyperbridge OP dispute draft
# cited dead gist URL (9d055289..., HTTP 404); fixed manually at HackenProof
# paste time. R54 codifies "validate external URLs before paste-ready".
_R54_TOOL="$AUDITOOOR_DIR/tools/external-url-liveness-check.py"
if [ -f "$_R54_TOOL" ]; then
    echo ""
    _R54_TMP=$(mktemp 2>/dev/null || echo "/tmp/r54_url_liveness_$$.json")
    _R54_ERR=$(mktemp 2>/dev/null || echo "/tmp/r54_url_liveness_$$.err")
    _R54_ARGS=("$SUB" "--timeout" "8" "--json")
    [ -n "$SEVERITY_ARG" ] && _R54_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
    # Note: --strict NOT passed by default; network failures are warn-only.
    python3 "$_R54_TOOL" "${_R54_ARGS[@]}" > "$_R54_TMP" 2> "$_R54_ERR"
    _R54_RC=$?

    _R54_SUMMARY=$(
        python3 - "$_R54_TMP" "$_R54_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_R54_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R54_TMP"; then
            echo "  ✅ 101. R54-EXTERNAL-URL-LIVENESS rebuttal accepted: $_R54_SUMMARY"
        elif grep -qE '"verdict": "pass-' "$_R54_TMP"; then
            echo "  ✅ 101. R54-EXTERNAL-URL-LIVENESS: $_R54_SUMMARY"
        else
            echo "  ✅ 101. R54-EXTERNAL-URL-LIVENESS: $_R54_SUMMARY"
        fi
    elif [ "$_R54_RC" -eq 1 ]; then
        echo "  ❌ 101. R54-EXTERNAL-URL-LIVENESS blocked:"
        echo "       $_R54_SUMMARY"
        python3 - "$_R54_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for u in d.get("dead_urls", [])[:5]:
        print("DEAD: " + u.get("url","?") + " -> HTTP " + str(u.get("status","?")))
    for u in d.get("network_failures", [])[:3]:
        print("NETFAIL: " + u.get("url","?") + " -> " + str(u.get("error","?")))
except Exception:
    pass
PY
        echo "       Override: r54-rebuttal: <reason up to 200 chars>"
        echo "       or <!-- r54-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  101. R54-EXTERNAL-URL-LIVENESS error: $_R54_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R54_TMP" "$_R54_ERR"
else
    echo "  ⚠️  101. R54-EXTERNAL-URL-LIVENESS: tool not found ($_R54_TOOL); skipping"
    warns=$((warns + 1))
fi

# ==========================================================================
# Check #102: R56-RUBRIC-FIT-PROGRAM-LEVEL (Rule 56)
#
# For MEDIUM+ drafts that reference a cosmos-sdk module / Substrate pallet /
# smart-contract subsystem AS THE AFFECTED COMPONENT, verify the component
# is on the program's CORE PRODUCT surface. Distinct from R52 ("no row at
# all") and R35 ("wrong impact class"); R56 catches "program lists the
# impact class but the affected module is non-core for the program's
# product".
#
# Trigger: MEDIUM+ drafts whose draft body cites an affected_component /
# module / pallet / subsystem (or has a recognizable x/<module> /
# pallet-<name> / ismp-<name> token in its body).
#
# Tool: tools/rubric-fit-program-level-check.py <draft.md>
#       --workspace <ws> --strict --json
# Verdicts: pass-out-of-scope, pass-no-component-cited,
#   pass-component-is-program-core, pass-component-context-unknown,
#   ok-rebuttal, fail-component-is-non-core-for-program,
#   fail-no-core-product-claim, error.
# Override: visible `r56-rebuttal: <reason>` or
#           `<!-- r56-rebuttal: <reason> -->` (<=200 chars).
# Ordering note: fires AFTER Check #101 R54 (external URL liveness) and
# BEFORE Check #103 L34-PATH-CLASSIFIER (informational classifier).
#
# Empirical anchor: dydx cantina-238 (2026-05-23) "x/feegrant revoke MEDIUM"
# killed with verbatim triager rationale: "x/feegrant is a non-core module
# on dYdX v4. dYdX is a perpetual futures exchange where the core product is
# orderbook trading, matching, and settlement." The bug was real + triager
# acknowledged the resurrection scenario. The kill rationale was "non-core
# for THIS program's product." R56 codifies "check core-product surface
# before filing" as a hard pre-submit gate.
_R56_TOOL="$AUDITOOOR_DIR/tools/rubric-fit-program-level-check.py"
if [ -f "$_R56_TOOL" ]; then
    echo ""
    _R56_TMP=$(mktemp 2>/dev/null || echo "/tmp/r56_rubric_fit_$$.json")
    _R56_ERR=$(mktemp 2>/dev/null || echo "/tmp/r56_rubric_fit_$$.err")
    _R56_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
    [ -n "$SEVERITY_ARG" ] && _R56_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
    python3 "$_R56_TOOL" "${_R56_ARGS[@]}" > "$_R56_TMP" 2> "$_R56_ERR"
    _R56_RC=$?

    _R56_SUMMARY=$(
        python3 - "$_R56_TMP" "$_R56_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("error","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_R56_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R56_TMP"; then
            echo "  ✅ 102. R56-RUBRIC-FIT-PROGRAM-LEVEL rebuttal accepted: $_R56_SUMMARY"
        elif grep -qE '"verdict": "pass-' "$_R56_TMP"; then
            echo "  ✅ 102. R56-RUBRIC-FIT-PROGRAM-LEVEL: $_R56_SUMMARY"
        else
            echo "  ✅ 102. R56-RUBRIC-FIT-PROGRAM-LEVEL: $_R56_SUMMARY"
        fi
    elif [ "$_R56_RC" -eq 1 ]; then
        echo "  ❌ 102. R56-RUBRIC-FIT-PROGRAM-LEVEL blocked:"
        echo "       $_R56_SUMMARY"
        python3 - "$_R56_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for c in d.get("evidence", {}).get("classifications", [])[:5]:
        print("CITED: " + c.get("component","?") + " -> " + c.get("classification","?"))
except Exception:
    pass
PY
        echo "       Override: r56-rebuttal: <reason up to 200 chars>"
        echo "       or <!-- r56-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  102. R56-RUBRIC-FIT-PROGRAM-LEVEL error: $_R56_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R56_TMP" "$_R56_ERR"
else
    echo "  ⚠️  102. R56-RUBRIC-FIT-PROGRAM-LEVEL: tool not found ($_R56_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #103: L34-PATH-CLASSIFIER (non-fatal audit visibility)
#
# Classifies the draft being checked under the L34 v2 5-bucket scheme
# (draft-file / tracker-file / workspace-ledger / lesson-anchor / out-of-scope).
# Pure-informational - emits the bucket so logs make L34 applicability obvious
# at submission time. NOT a hard fail; if the file is a tracker-file or
# workspace-ledger, L34 does not require per-draft op auth.
#
# Trigger: every invocation of pre-submit-check.sh, regardless of severity.
#
# Tool: tools/l34-path-classifier.py <path> --json
# Override: n/a (informational only). Honor L34 v2 doctrine for actual edits.
#
# Empirical anchor: iter17 YYYYY (2026-05-23) executed SUBMISSIONS.md edits
# across spark/hyperbridge/polymarket without operator interruption because
# trackers are auto-executable metadata. L34 v2 codifies the bucket; this
# check surfaces the bucket on every pre-submit run for audit visibility.
# ============================================================================
_L34_TOOL="$AUDITOOOR_DIR/tools/l34-path-classifier.py"
if [ -f "$_L34_TOOL" ]; then
    echo ""
    _L34_TMP=$(mktemp 2>/dev/null || echo "/tmp/l34_path_classify_$$.json")
    python3 "$_L34_TOOL" "$SUB" --json > "$_L34_TMP" 2>/dev/null
    _L34_RC=$?
    if [ "$_L34_RC" -eq 0 ]; then
        _L34_LINE=$(python3 - "$_L34_TMP" <<'PY'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    rec = d.get("results", [{}])[0]
    bucket = rec.get("bucket", "?")
    auth = rec.get("requires_per_draft_op_auth", True)
    marker = "AUTH-required" if auth else "auto-executable"
    print(f"{bucket} ({marker})")
except Exception:
    print("classify-error")
PY
        )
        echo "  ℹ️  103. L34-PATH-CLASSIFIER: $_L34_LINE"
    else
        echo "  ⚠️  103. L34-PATH-CLASSIFIER: classifier returned rc=$_L34_RC (non-fatal)"
    fi
    rm -f "$_L34_TMP"
fi

# ============================================================================
# Check #104: R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION (Rule 57)
#
# Fail-closed when a HIGH+ draft argues against a defender narrative without
# enumerating every defense call site in the defender's codebase. Reads the
# workspace .auditooor/r57_protection_modules.json registry (or per-call
# --protection-module-dir flags) to determine which directories to grep.
#
# Ordering note: fires LAST in the defender-narrative family (after R25
# Check #63, R29 Check #94, R43 Check #91, R44 Check #92, R45 Check #93).
# R57 needs their outputs (named defenses, attribution, harness,
# designed-as-intended) to meaningfully verify exhaustiveness.
#
# Trigger: HIGH+ drafts before paste_ready promotion (severity-scoped).
# Tool: tools/exhaustive-defense-chain-enumeration-check.py <draft>
#       [--workspace <ws>] [--protection-module-dir <dir>] [--strict] [--json]
# Verdicts: pass-out-of-scope, pass-no-defense-narrative,
#           pass-all-defense-paths-enumerated, ok-rebuttal,
#           fail-no-enumeration-section, fail-table-missing,
#           fail-row-without-citation,
#           fail-defense-paths-missing-from-enumeration,
#           fail-ruling-without-source-citation, error
# Override: visible `r57-rebuttal: <reason>` or
#           `<!-- r57-rebuttal: <reason> -->` (max 200 chars).
#
# Empirical anchor: Spark LEAD 1 v8 (2026-05-23) addressed 2 of 3 defense
# families; missed root-tx-CPFP-based intermediate refund. R25/R29/R43/R44/R45
# all passed because they verify named defenses, not codebase exhaustiveness.
# ============================================================================
_R57_TOOL="$AUDITOOOR_DIR/tools/exhaustive-defense-chain-enumeration-check.py"
if [ -f "$_R57_TOOL" ]; then
    _R57_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R57_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R57_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R57_TMP=$(mktemp 2>/dev/null || echo "/tmp/r57_defense_enum_$$.json")
        _R57_ERR=$(mktemp 2>/dev/null || echo "/tmp/r57_defense_enum_$$.err")
        _R57_ARGS=("$SUB" "--workspace" "$WS_DIR" "--json")
        [ -n "$SEVERITY_ARG" ] && _R57_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
        python3 "$_R57_TOOL" "${_R57_ARGS[@]}" > "$_R57_TMP" 2> "$_R57_ERR"
        _R57_RC=$?

        _R57_SUMMARY=$(
            python3 - "$_R57_TMP" "$_R57_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R57_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R57_TMP"; then
                echo "  ✅ 104. R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION rebuttal accepted: $_R57_SUMMARY"
            else
                echo "  ✅ 104. R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION: $_R57_SUMMARY"
            fi
        elif [ "$_R57_RC" -eq 1 ]; then
            echo "  ❌ 104. R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION blocked:"
            echo "       $_R57_SUMMARY"
            python3 - "$_R57_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for h in d.get("evidence", {}).get("unaccounted_call_sites", [])[:5]:
        print("  unaccounted: " + h.get("file","?") + ":" + str(h.get("line","?")) + " (" + h.get("token","?") + ")")
    for h in d.get("evidence", {}).get("rows_without_citation", [])[:3]:
        print("  row-no-citation: " + str(h)[:120])
    for h in d.get("evidence", {}).get("unresolved_citations", [])[:3]:
        print("  unresolved: " + str(h))
except Exception:
    pass
PY
            echo "       Override: r57-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r57-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  104. R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION error: $_R57_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R57_TMP" "$_R57_ERR"
    else
        echo "  ✅ 104. R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  104. R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION: tool not found ($_R57_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #105: R58-INVARIANT-GROUNDED-FINDING (Rule 58)
#
# Fail-closed when a HIGH/CRITICAL finding draft or proof packet does not cite
# an indexed INV-* invariant or explicitly justify no invariant binding. Also
# fail-closed when a MEDIUM draft declares an attack_class that already maps to
# the invariant library but does not cite an indexed INV-* invariant. Reads
# audit/corpus_tags/derived/invariant_library_index.json plus the pilot and
# extracted invariant JSONL files.
#
# Trigger: MEDIUM+ artifacts before paste_ready promotion (severity-scoped).
# Tool: tools/invariant-grounded-finding-check.py <draft>
#       [--workspace <ws>] [--severity <severity>] [--discover-sidecars] [--json]
# Verdicts: pass-out-of-scope, pass-invariant-cited-and-indexed,
#           ok-rebuttal, fail-invariant-cited-but-not-indexed,
#           fail-no-invariant-cited-but-class-has-known-invariant,
#           fail-no-invariant-cited-or-binding-justification, error
# Override: visible `r58-rebuttal: <reason>` or
#           `<!-- r58-rebuttal: <reason> -->`; preferred explicit no-binding
#           marker is `<!-- r58-no-invariant-binding: <reason> -->`
#           (max 200 chars).
# ============================================================================
_R58_TOOL="$AUDITOOOR_DIR/tools/invariant-grounded-finding-check.py"
if [ -f "$_R58_TOOL" ]; then
    _R58_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in MEDIUM|HIGH|CRITICAL|Medium|High|Critical|medium|high|critical) _R58_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R58_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R58_TMP=$(mktemp 2>/dev/null || echo "/tmp/r58_invariant_grounded_$$.json")
        _R58_ERR=$(mktemp 2>/dev/null || echo "/tmp/r58_invariant_grounded_$$.err")
        _R58_ARGS=("$SUB" "--workspace" "$WS_DIR" "--discover-sidecars" "--json")
        [ -n "$SEVERITY_ARG" ] && _R58_ARGS+=("--severity" "$SEVERITY_ARG")
        python3 "$_R58_TOOL" "${_R58_ARGS[@]}" > "$_R58_TMP" 2> "$_R58_ERR"
        _R58_RC=$?

        _R58_SUMMARY=$(
            python3 - "$_R58_TMP" "$_R58_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", "no detail"))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R58_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R58_TMP"; then
                echo "  ✅ 105. R58-INVARIANT-GROUNDED-FINDING rebuttal accepted: $_R58_SUMMARY"
            else
                echo "  ✅ 105. R58-INVARIANT-GROUNDED-FINDING: $_R58_SUMMARY"
            fi
        elif [ "$_R58_RC" -eq 1 ]; then
            echo "  ❌ 105. R58-INVARIANT-GROUNDED-FINDING blocked:"
            echo "       $_R58_SUMMARY"
            python3 - "$_R58_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    payloads = []
    if d.get("results"):
        for row in d.get("results", []):
            if row.get("rc") == 1 and isinstance(row.get("payload"), dict):
                print("  artifact: " + str(row.get("kind", "artifact")) + " " + str(row.get("path", "")))
                payloads.append(row["payload"])
    else:
        payloads.append(d)
    for payload in payloads:
        attack_class = payload.get("attack_class_observed")
        if attack_class:
            print("  attack_class: " + str(attack_class))
        unknown = payload.get("unknown_cited_invariant_ids") or []
        for inv_id in unknown[:8]:
            print("  unknown-invariant: " + str(inv_id))
        evidence = payload.get("evidence", {})
        for inv_id in (evidence.get("class_matched_invariant_ids") or [])[:8]:
            print("  known-class-invariant: " + str(inv_id))
        for hit in (evidence.get("class_match_evidence") or [])[:3]:
            print("  class-match: " + str(hit)[:160])
except Exception:
    pass
PY
            echo "       Override: r58-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r58-rebuttal: <reason up to 200 chars> -->"
            echo "       preferred no-binding marker: <!-- r58-no-invariant-binding: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  105. R58-INVARIANT-GROUNDED-FINDING error: $_R58_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R58_TMP" "$_R58_ERR"
    else
        echo "  ✅ 105. R58-INVARIANT-GROUNDED-FINDING: not MEDIUM+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  105. R58-INVARIANT-GROUNDED-FINDING: tool not found ($_R58_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #106: R59-ANTIPATTERN-ATTRIBUTION (Rule 59)
#
# Fail-closed when a HIGH/CRITICAL finding draft declares a cluster/category
# that maps to entries in the P3 anti-pattern catalog but does not cite a
# recognized catalog pattern_id. This keeps anti-pattern attribution grounded
# in obsidian-vault/anti-patterns/v2 instead of free-text class names.
#
# Trigger: HIGH+ artifacts before paste_ready promotion (severity-scoped).
# Tool: tools/antipattern-attribution-check.py <draft>
#       [--workspace <ws>] [--severity <severity>] [--json]
# Verdicts: pass-out-of-scope, pass-antipattern-cited-and-recognized,
#           pass-no-catalog-binding, ok-rebuttal,
#           fail-no-antipattern-id-cited-for-bound-category,
#           fail-antipattern-id-does-not-match-bound-category, error
# Override: visible `r59-rebuttal: <reason>` or
#           `<!-- r59-rebuttal: <reason> -->`; preferred explicit no-binding
#           marker is `<!-- r59-no-binding: <reason> -->` (max 200 chars).
# ============================================================================
_R59_TOOL="$AUDITOOOR_DIR/tools/antipattern-attribution-check.py"
if [ -f "$_R59_TOOL" ]; then
    _R59_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R59_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R59_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R59_TMP=$(mktemp 2>/dev/null || echo "/tmp/r59_antipattern_attribution_$$.json")
        _R59_ERR=$(mktemp 2>/dev/null || echo "/tmp/r59_antipattern_attribution_$$.err")
        _R59_ARGS=("$SUB" "--workspace" "$WS_DIR" "--json")
        [ -n "$SEVERITY_ARG" ] && _R59_ARGS+=("--severity" "$SEVERITY_ARG")
        python3 "$_R59_TOOL" "${_R59_ARGS[@]}" > "$_R59_TMP" 2> "$_R59_ERR"
        _R59_RC=$?

        _R59_SUMMARY=$(
            python3 - "$_R59_TMP" "$_R59_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", "no detail"))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R59_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R59_TMP"; then
                echo "  ✅ 106. R59-ANTIPATTERN-ATTRIBUTION rebuttal accepted: $_R59_SUMMARY"
            else
                echo "  ✅ 106. R59-ANTIPATTERN-ATTRIBUTION: $_R59_SUMMARY"
            fi
        elif [ "$_R59_RC" -eq 1 ]; then
            echo "  ❌ 106. R59-ANTIPATTERN-ATTRIBUTION blocked:"
            echo "       $_R59_SUMMARY"
            python3 - "$_R59_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for term in (d.get("binding_terms_observed") or [])[:8]:
        print("  binding-term: " + str(term))
    for pattern_id in (d.get("evidence", {}).get("matched_catalog_pattern_ids") or [])[:8]:
        print("  matched-antipattern: " + str(pattern_id))
except Exception:
    pass
PY
            echo "       Override: r59-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r59-rebuttal: <reason up to 200 chars> -->"
            echo "       preferred no-binding marker: <!-- r59-no-binding: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  106. R59-ANTIPATTERN-ATTRIBUTION error: $_R59_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R59_TMP" "$_R59_ERR"
    else
        echo "  ✅ 106. R59-ANTIPATTERN-ATTRIBUTION: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  106. R59-ANTIPATTERN-ATTRIBUTION: tool not found ($_R59_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #107: R60-REACHABILITY-PROACTIVE-EMBED (Rule 60)
#
# For MEDIUM+ drafts that contain reachability-uncertainty prose
# ("operator-only assessment", "extraordinary", "if reachable",
# "production-plausible", "depends on accumulation", "may not be reachable",
# "calibration question", etc.) in Disposition / Reachability sections,
# require a `## Reachability` section embedding all FOUR inline-proof fields:
#   (1) upstream-entry citation = file:line + actor-control keyword
#       (user-controlled / attacker-controlled / unsigned origin /
#        permissionless / anyone can call / unprivileged / etc.)
#   (2) bound-evidence = explicit grep-count statement OR "no overflow guard /
#       no MAX_FEE / no bound check exists" claim
#   (3) at least one single-shot scenario verb phrase
#       ("single tx", "one call", "even one occurrence", "single-shot")
#   (4) at least one real-world prior-art anchor
#       (CVE / GHSA / Solodit / Cyfrin / OpenZeppelin / Trail of Bits /
#        Halborn / Spearbit / SRL / Sherlock / Code4rena / Cantina /
#        Immunefi / prior_audits/DIGEST citation)
#
# Anchor lesson: DRILL-6 Medium (hb-pallet-relayer-u256-truncation) was
# filed with the Disposition disclosing reachability uncertainty without
# an inline upstream-source proof; operator caught it post-file and
# upgraded the body to embed the proof. R60 mechanizes the
# "always-escalate-by-default" rule so future Medium+ drafts cannot
# ship without the proof.
#
# Tool: tools/reachability-proactive-embed-check.py <draft.md>
#       [--severity <severity>] [--strict] [--json]
# Verdicts: pass-out-of-scope, pass-no-uncertainty-prose,
#   pass-reachability-section-complete, ok-rebuttal,
#   fail-no-reachability-section, fail-missing-upstream-citation,
#   fail-missing-bound-evidence, fail-missing-single-shot-scenario,
#   fail-missing-prior-art-anchor, error.
# Override: visible `r60-rebuttal: <reason>` (<=200 chars) or
#           `<!-- r60-rebuttal: <reason> -->`.
# ============================================================================
_R60_TOOL="$AUDITOOOR_DIR/tools/reachability-proactive-embed-check.py"
if [ -f "$_R60_TOOL" ]; then
    _R60_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in MEDIUM|HIGH|CRITICAL|Medium|High|Critical|medium|high|critical) _R60_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R60_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R60_TMP=$(mktemp 2>/dev/null || echo "/tmp/r60_reachability_proactive_embed_$$.json")
        _R60_ERR=$(mktemp 2>/dev/null || echo "/tmp/r60_reachability_proactive_embed_$$.err")
        _R60_ARGS=("$SUB" "--json")
        [ -n "$SEVERITY_ARG" ] && _R60_ARGS+=("--severity" "$SEVERITY_ARG")
        python3 "$_R60_TOOL" "${_R60_ARGS[@]}" > "$_R60_TMP" 2> "$_R60_ERR"
        _R60_RC=$?

        _R60_SUMMARY=$(
            python3 - "$_R60_TMP" "$_R60_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("error", "no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R60_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R60_TMP"; then
                echo "  ✅ 107. R60-REACHABILITY-PROACTIVE-EMBED rebuttal accepted: $_R60_SUMMARY"
            else
                echo "  ✅ 107. R60-REACHABILITY-PROACTIVE-EMBED: $_R60_SUMMARY"
            fi
        elif [ "$_R60_RC" -eq 1 ]; then
            echo "  ❌ 107. R60-REACHABILITY-PROACTIVE-EMBED blocked:"
            echo "       $_R60_SUMMARY"
            python3 - "$_R60_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    ev = d.get("evidence", {})
    for hit in (ev.get("uncertainty_hits") or [])[:3]:
        print("uncertainty: line " + str(hit.get("line", "?")) + " - " + str(hit.get("token", ""))[:80])
    for fld in ("upstream_citation", "bound_evidence", "single_shot_scenario", "prior_art_anchor"):
        info = ev.get(fld)
        if isinstance(info, dict):
            print(fld + ": ok=" + str(info.get("ok")))
except Exception:
    pass
PY
            echo "       Override: r60-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r60-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  107. R60-REACHABILITY-PROACTIVE-EMBED error: $_R60_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R60_TMP" "$_R60_ERR"
    else
        echo "  ✅ 107. R60-REACHABILITY-PROACTIVE-EMBED: not MEDIUM+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  107. R60-REACHABILITY-PROACTIVE-EMBED: tool not found ($_R60_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #108: R61-CLAIM-SOURCE-ANCHOR-REQUIRED (Rule 61)
#
# For HIGH+ drafts that contain structural-negation claims about
# codebase behavior ("X is unreachable", "Y does not apply",
# "Z never executes", "stays NULL", "stays zero", "never confirms",
# "no in-tree consumer", "0 callers", "structurally blocked",
# "cannot be reached", "fails to fire", etc.), every such claim
# MUST be paired with an inline source anchor in the same sentence
# or paragraph. Accepted anchor forms:
#   - `[src: path/to/file.ext:NNN]` or `[src: path/to/file.ext:NNN-NNN]`
#   - inline `path/to/file.ext:NNN` citation (recognized source
#     extensions: .rs .go .sol .py .ts .move .vy .cairo .yul .huff
#     .c .cpp .h .java .kt .swift .rb .php .cs)
#
# Anchor lesson: Spark LEAD 1 dispute v1-v10 culminated in HONEST
# CONCESSION (commit 9e84c4c322) because the v9 row 2 claim
# "QueryBroadcastableTransferLeaves unreachable because leaf
# NodeConfirmationHeight stays NULL" was structurally wrong from v1 -
# asserted from mental model rather than anchored to source.
# Source-verify at audit pin proved leaf.RawTxid == cpfpRootTx.TxHash()
# (finalize_deposit_tree.go:969 + ent/schema/tree_node.go:325-336 +
# tree/tree.go:30-36) so MarkExitingNodes DOES match -> watchtower
# path IS reachable -> Critical claim falsified. If R61 had existed
# at v1, the unanchored claim would have been refused pre-submit,
# saving 9 dispute rounds + ~3 weeks of compute + credibility cost.
#
# Tool: tools/claim-source-anchor-check.py <draft.md>
#       [--severity <severity>] [--strict] [--json]
# Verdicts: pass-out-of-scope, pass-no-structural-assertions,
#   pass-all-anchored, ok-rebuttal,
#   fail-unanchored-claim, error.
# Override: visible `r61-rebuttal: <reason>` (<=200 chars) or
#           `<!-- r61-rebuttal: <reason> -->`.
# ============================================================================
_R61_TOOL="$AUDITOOOR_DIR/tools/claim-source-anchor-check.py"
if [ -f "$_R61_TOOL" ]; then
    _R61_SEVERITY_TRIGGER=false
    case "$SEVERITY_ARG" in HIGH|CRITICAL|High|Critical|high|critical) _R61_SEVERITY_TRIGGER=true ;; esac
    if [ "$_R61_SEVERITY_TRIGGER" = "true" ]; then
        echo ""
        _R61_TMP=$(mktemp 2>/dev/null || echo "/tmp/r61_claim_source_anchor_$$.json")
        _R61_ERR=$(mktemp 2>/dev/null || echo "/tmp/r61_claim_source_anchor_$$.err")
        _R61_ARGS=("$SUB" "--json")
        [ -n "$SEVERITY_ARG" ] && _R61_ARGS+=("--severity" "$SEVERITY_ARG")
        python3 "$_R61_TOOL" "${_R61_ARGS[@]}" > "$_R61_TMP" 2> "$_R61_ERR"
        _R61_RC=$?

        _R61_SUMMARY=$(
            python3 - "$_R61_TMP" "$_R61_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("error", "no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
        )

        if [ "$_R61_RC" -eq 0 ]; then
            if grep -q '"verdict": "ok-rebuttal"' "$_R61_TMP"; then
                echo "  ✅ 108. R61-CLAIM-SOURCE-ANCHOR-REQUIRED rebuttal accepted: $_R61_SUMMARY"
            else
                echo "  ✅ 108. R61-CLAIM-SOURCE-ANCHOR-REQUIRED: $_R61_SUMMARY"
            fi
        elif [ "$_R61_RC" -eq 1 ]; then
            echo "  ❌ 108. R61-CLAIM-SOURCE-ANCHOR-REQUIRED blocked:"
            echo "       $_R61_SUMMARY"
            python3 - "$_R61_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    ev = d.get("evidence", {})
    print("total negation scopes: " + str(ev.get("total_negation_scopes", 0)))
    print("anchored: " + str(ev.get("anchored_count", 0)))
    print("unanchored: " + str(ev.get("unanchored_count", 0)))
    for item in (ev.get("unanchored") or [])[:5]:
        excerpt = str(item.get("sentence_excerpt", ""))[:120]
        print("  line ~" + str(item.get("paragraph_start_line", "?")) + ": " + excerpt)
except Exception:
    pass
PY
            echo "       Override: r61-rebuttal: <reason up to 200 chars>"
            echo "       or <!-- r61-rebuttal: <reason up to 200 chars> -->"
            fails=$((fails + 1))
        else
            echo "  ⚠️  108. R61-CLAIM-SOURCE-ANCHOR-REQUIRED error: $_R61_SUMMARY"
            warns=$((warns + 1))
        fi
        rm -f "$_R61_TMP" "$_R61_ERR"
    else
        echo "  ✅ 108. R61-CLAIM-SOURCE-ANCHOR-REQUIRED: not HIGH+ (severity=$SEVERITY_ARG); skipping"
    fi
else
    echo "  ⚠️  108. R61-CLAIM-SOURCE-ANCHOR-REQUIRED: tool not found ($_R61_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #109: GAP-37-EXHAUSTION-VERDICT-TOOLS-ATTEMPT-REQUIRED
#
# r36-rebuttal: lane-CAPABILITY-DEPTH-TOOLS-ORCHESTRATOR-PLUS-EXHAUSTION-VERDICT-GATE
# registered via tools/agent-pathspec-register.py.
#
# r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION
# For draft / lane-result files claiming an exhaustion-class verdict
# (EXHAUSTED / GENUINELY-EXHAUSTED / NEGATIVE-CLOSED-EXHAUSTED /
# NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE (Gap #48) /
# HUNT-DONE / HUNT-EXHAUSTED / SALVAGE-EXHAUSTED), require evidence-of-
# attempt for the depth-tool families:
#   - orient-prefilter
#   - hacker-mcp (vault_hacker_brief_for_lane*)
#   - audit-deep
#   - foundry-fuzz-1m   (or justified-skip)
#   - halmos             (or justified-skip)
#   - differential-fuzz  (or justified-skip)
#   - symbolic-exec      (mythril OR manticore; or justified-skip)
#   - rule14-deep        (triager-amend-asymmetry deep integration)
#
# Justified-skip = a row in <ws>/.auditooor/depth_tools_log.jsonl with
# status=SKIPPED and a non-empty skip_reason text. Emitted by
# tools/depth-tools-orchestrator.py.
#
# Anchor: operator pushback 2026-05-26 - "why have we not done this?".
# Halmos / Foundry-1M / Mythril / Manticore / differential / soak /
# Rule-14-deep tools existed but no mechanical rule REQUIRED their
# attempt before "EXHAUSTED" was accepted as a verdict - same pattern
# as prior gaps. Gap #37 closes that loop.
#
# Tool: tools/exhaustion-verdict-tools-attempt-required-check.py
#       <lane_results.md> --workspace <ws> [--strict] [--json]
# Verdicts: pass-no-exhaustion-verdict, pass-all-tools-attempted,
#   ok-rebuttal, fail-exhaustion-tools-incomplete, error.
# Override: <!-- gap37-rebuttal: <reason up to 200 chars> --> or visible
#   `gap37-rebuttal: <reason>` line.
# ============================================================================
_GAP37_TOOL="$AUDITOOOR_DIR/tools/exhaustion-verdict-tools-attempt-required-check.py"
if [ -f "$_GAP37_TOOL" ]; then
    echo ""
    _GAP37_TMP=$(mktemp 2>/dev/null || echo "/tmp/gap37_$$.json")
    _GAP37_ERR=$(mktemp 2>/dev/null || echo "/tmp/gap37_$$.err")
    _GAP37_WS="${WORKSPACE:-$AUDITOOOR_DIR}"
    python3 "$_GAP37_TOOL" "$SUB" --workspace "$_GAP37_WS" --json \
        > "$_GAP37_TMP" 2> "$_GAP37_ERR"
    _GAP37_RC=$?

    _GAP37_SUMMARY=$(
        python3 - "$_GAP37_TMP" "$_GAP37_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    verdict = d.get("verdict","?")
    reason = d.get("reason","no detail")
    ev = d.get("evidence",{})
    missing = ev.get("missing_families") or []
    extra = ""
    if missing:
        extra = " | missing: " + ",".join(missing)
    print(verdict + ": " + reason[:200] + extra)
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_GAP37_RC" -eq 0 ]; then
        echo "  ✅ 109. GAP-37-EXHAUSTION-VERDICT-TOOLS-ATTEMPT: $_GAP37_SUMMARY"
    elif [ "$_GAP37_RC" -eq 1 ]; then
        echo "  ❌ 109. GAP-37-EXHAUSTION-VERDICT-TOOLS-ATTEMPT blocked:"
        echo "       $_GAP37_SUMMARY"
        echo "       Remediation: run tools/depth-tools-orchestrator.py for each missing family"
        echo "       Override: <!-- gap37-rebuttal: <reason up to 200 chars> -->"
        echo "       or visible 'gap37-rebuttal: <reason>' line."
        fails=$((fails + 1))
    else
        echo "  ⚠️  109. GAP-37-EXHAUSTION-VERDICT-TOOLS-ATTEMPT error: $_GAP37_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_GAP37_TMP" "$_GAP37_ERR"
else
    echo "  ⚠️  109. GAP-37-EXHAUSTION-VERDICT-TOOLS-ATTEMPT: tool not found ($_GAP37_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #110: GAP39-WORKFLOW-FULLNESS (Gap #39)
#
# r36-rebuttal: lane-CAPABILITY-WORKFLOW-FULLNESS-AUDIT-PLUS-GAP-39-DEFAULT-FULL
# registered via tools/agent-pathspec-register.py to agent_pathspec.json.
#
# Operator anchor 2026-05-26: "whatever we analyze and audit, we do it full".
# For ANY draft (LOW+) that contains a fullness-claim phrase ("full audit
# complete", "comprehensive review", "all engines ran", "exhaustively
# reviewed", etc.), the gate refuses promotion unless the cited workflow
# log proves the full toolset ran OR the draft acknowledges the cheap path
# OR a `gap39-rebuttal:` is present (visible bounded line or HTML comment,
# <=200 chars, non-empty).
#
# Companion to Gap #37 (Check #109): Gap #37 catches missing tool-attempt
# evidence under EXHAUSTION verdicts; Gap #39 catches the more general
# "fullness claim without full evidence" anti-pattern at the prose layer
# (drafts that say "comprehensive audit complete" without a workflow log
# proving the deep engines ran).
#
# Hard gate: refuses paste_ready promotion for fullness-claim drafts that
# do not present full-workflow evidence. Severity-agnostic (fires LOW+).
#
# Tool: tools/workflow-fullness-check.py <draft.md> [--workspace <ws>]
#       [--strict] [--json]
# Verdicts: pass-out-of-scope, pass-cheap-path-acknowledged,
#   pass-full-workflow-evidence, ok-rebuttal,
#   fail-workflow-cheap-default-without-acknowledgement, error.
# Override: visible `gap39-rebuttal: <reason>` (<=200 chars) or
#           `<!-- gap39-rebuttal: <reason> -->`.
# ============================================================================
_GAP39_TOOL="$AUDITOOOR_DIR/tools/workflow-fullness-check.py"
if [ -f "$_GAP39_TOOL" ]; then
    echo ""
    _GAP39_TMP=$(mktemp 2>/dev/null || echo "/tmp/gap39_workflow_fullness_$$.json")
    _GAP39_ERR=$(mktemp 2>/dev/null || echo "/tmp/gap39_workflow_fullness_$$.err")
    _GAP39_ARGS=("$SUB" "--json")
    if [ -n "$WS_DIR" ]; then
        _GAP39_ARGS+=("--workspace" "$WS_DIR")
    fi
    python3 "$_GAP39_TOOL" "${_GAP39_ARGS[@]}" > "$_GAP39_TMP" 2> "$_GAP39_ERR"
    _GAP39_RC=$?

    _GAP39_SUMMARY=$(
        python3 - "$_GAP39_TMP" "$_GAP39_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("error", "no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_GAP39_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_GAP39_TMP"; then
            echo "  ✅ 110. GAP39-WORKFLOW-FULLNESS rebuttal accepted: $_GAP39_SUMMARY"
        else
            echo "  ✅ 110. GAP39-WORKFLOW-FULLNESS: $_GAP39_SUMMARY"
        fi
    elif [ "$_GAP39_RC" -eq 1 ]; then
        echo "  ❌ 110. GAP39-WORKFLOW-FULLNESS blocked:"
        echo "       $_GAP39_SUMMARY"
        python3 - "$_GAP39_TMP" <<'PY' | sed 's/^/       /'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    ev = d.get("evidence", {})
    draft = ev.get("draft", {})
    wf = ev.get("workflow", {})
    phrases = draft.get("fullness_phrases_hit", [])
    if phrases:
        print("fullness phrases hit: " + ", ".join(phrases[:3]))
    print("workflow log: " + str(wf.get("log_path", "?")) + " (exists=" + str(wf.get("log_exists", False)) + ")")
    missing = wf.get("missing_engines", [])
    if missing:
        print("missing engines: " + ", ".join(missing))
except Exception:
    pass
PY
        echo "       Either:"
        echo "         (a) re-run with \`make audit-deep-full WS=<ws>\` (live engines)"
        echo "         (b) walk back the fullness wording to acknowledge cheap path (--cheap-path-acknowledged)"
        echo "         (c) add: gap39-rebuttal: <reason up to 200 chars>"
        echo "             or <!-- gap39-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  110. GAP39-WORKFLOW-FULLNESS error: $_GAP39_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_GAP39_TMP" "$_GAP39_ERR"
else
    echo "  ⚠️  110. GAP39-WORKFLOW-FULLNESS: tool not found ($_GAP39_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #111: GAP37B-SALVAGE-NEGATION-VERDICT (Gap #37b)
#
# r36-rebuttal: lane-gap37b-salvage-negation registered via
# tools/agent-pathspec-register.py.
#
# Companion to Gap #37 (Check #109): Gap #37 catches missing tool-attempt
# evidence under EXHAUSTION-class verdicts; Gap #37b enforces that the
# verdict prose ITSELF frames the negation exhaustively when a salvage /
# exhaustion / drop / killed / closeout conclusion is declared.
#
# Trigger: verdict / report files under
#   - reports/v3_iter_*/lane_*/results.md
#   - agent_outputs/**/results.md
#   - submissions/**/_killed/**/*.md
# whose body asserts salvage / exhaustion / drop / killed / closeout
# verdict phrasing.
#
# Fail-closed unless the verdict body includes ALL of:
#   (1) An explicit negation framing token: NOT-SALVAGEABLE-CONFIRMED,
#       DROP-CONFIRMED, EXHAUSTION-CONFIRMED, KILLED-CONFIRMED, or
#       NEGATIVE-CLOSED.
#   (2) A "Negation evidence" section listing AT LEAST 3 specific paths
#       attempted that did NOT yield (one-line reason per path).
#   (3) A "What would flip this" clause naming the specific new evidence
#       (artifact, callsite, predicate) that would re-open the verdict.
#
# Empirical anchors (operator pushback 2026-05-26): three real cases
# where the orchestrator declared "salvageable" / "exhausted" / "drop"
# without exhaustive negation framing:
#   A. DRILL-2 R60-bounded "drop" without framing.
#   B. Wave 3 dedup "exhausted" without framing.
#   C. iter-1 dropped-items resurrection "0/16 salvageable" without framing.
# Gap #37 (Check #109) catches missing tool-attempt; Gap #37b (this
# Check #111) catches missing negation-framing prose. The two gates
# compose: #109 requires tools were tried; #111 requires the verdict
# frames the negation exhaustively.
#
# Tool: tools/salvage-negation-verdict-check.py <verdict.md>
#       [--strict] [--json]
# Verdicts: pass-out-of-scope, pass-no-verdict-language,
#   pass-negation-framing-complete, ok-rebuttal,
#   fail-no-negation-token, fail-no-negation-evidence-list,
#   fail-no-flip-clause, error.
# Override: <!-- gap37b-rebuttal: <reason up to 200 chars> --> or
#   visible `gap37b-rebuttal: <reason>` line.
# ============================================================================
_GAP37B_TOOL="$AUDITOOOR_DIR/tools/salvage-negation-verdict-check.py"
if [ -f "$_GAP37B_TOOL" ]; then
    echo ""
    _GAP37B_TMP=$(mktemp 2>/dev/null || echo "/tmp/gap37b_$$.json")
    _GAP37B_ERR=$(mktemp 2>/dev/null || echo "/tmp/gap37b_$$.err")
    python3 "$_GAP37B_TOOL" "$SUB" --json \
        > "$_GAP37B_TMP" 2> "$_GAP37B_ERR"
    _GAP37B_RC=$?

    _GAP37B_SUMMARY=$(
        python3 - "$_GAP37B_TMP" "$_GAP37B_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    verdict = d.get("verdict","?")
    reason = d.get("reason","no detail")
    ev = d.get("evidence",{})
    extras = []
    if ev.get("negation_token"):
        extras.append("token=" + ev["negation_token"])
    if ev.get("negation_evidence_row_count") is not None:
        extras.append("evidence-rows=" + str(ev["negation_evidence_row_count"]))
    if "has_flip_clause" in ev:
        extras.append("flip=" + ("yes" if ev["has_flip_clause"] else "no"))
    extra = (" | " + ", ".join(extras)) if extras else ""
    print(verdict + ": " + reason[:240] + extra)
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_GAP37B_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_GAP37B_TMP"; then
            echo "  ✅ 111. GAP37B-SALVAGE-NEGATION-VERDICT rebuttal accepted: $_GAP37B_SUMMARY"
        else
            echo "  ✅ 111. GAP37B-SALVAGE-NEGATION-VERDICT: $_GAP37B_SUMMARY"
        fi
    elif [ "$_GAP37B_RC" -eq 1 ]; then
        echo "  ❌ 111. GAP37B-SALVAGE-NEGATION-VERDICT blocked:"
        echo "       $_GAP37B_SUMMARY"
        # r36-rebuttal: lane-ENUM-FIX-NEGATIVE-CLOSED-WITH-OBSERVATION
        echo "       Remediation (add ALL three):"
        echo "         (1) Negation framing token: one of NOT-SALVAGEABLE-CONFIRMED,"
        echo "             DROP-CONFIRMED, EXHAUSTION-CONFIRMED, KILLED-CONFIRMED,"
        echo "             NEGATIVE-CLOSED,"
        echo "             NEGATIVE-CLOSED-WITH-OBSERVATION-FOR-EXISTING-BUNDLE"
        echo "             (Gap #48, codified 2026-05-26: incremental fold-in"
        echo "              candidate for an already-staged bundle; lane MAY NOT"
        echo "              auto-stage per L34 v2; include an observation: block)."
        echo "         (2) ## Negation evidence section with >=3 bullet rows:"
        echo "             - <tool/approach>: <one-line reason>"
        echo "         (3) ## What would flip this section naming the new evidence"
        echo "             (artifact, callsite, predicate) that would re-open verdict."
        echo "       Override: <!-- gap37b-rebuttal: <reason up to 200 chars> -->"
        echo "       or visible 'gap37b-rebuttal: <reason>' line."
        fails=$((fails + 1))
    else
        echo "  ⚠️  111. GAP37B-SALVAGE-NEGATION-VERDICT error: $_GAP37B_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_GAP37B_TMP" "$_GAP37B_ERR"
else
    echo "  ⚠️  111. GAP37B-SALVAGE-NEGATION-VERDICT: tool not found ($_GAP37B_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #112: GAP36-R41-ARTIFACT-COMPLETENESS (Gap #36)
#
# r36-rebuttal: lane-CAPABILITY-GAP-36-R41-ARTIFACT-COMPLETENESS registered
# via tools/agent-pathspec-register.py to .auditooor/agent_pathspec.json.
#
# Operator anchor (2026-05-26): DRILL-9 paste-ready
# (smt-eth-branch-isempty-value-conflation) was promoted to paste-ready
# citing "13/13 Foundry tests PASS" but the per-finding folder was missing
# the -poc.zip + .poc-transcript.txt artifacts. Operator caught it at
# HackenProof paste time.
#
# Companion to Check #85 (R41-SUBMISSION-FOLDER-STRUCTURE): Check #85 verifies
# artifacts are GROUPED in a per-finding folder. Check #112 (this gate)
# verifies the per-finding folder holds the COMPLETE artifact set when the
# draft cites executed-PoC evidence.
#
# Trigger: ANY draft (severity-agnostic) whose body contains executed-PoC
# evidence phrasing - "PoC PASS", "X/X Foundry tests PASS", "Suite result:
# ok", "forge test", "cargo test", "Foundry PoC", "--- PASS:", PoC transcript
# reference. The full default pattern set lives in the tool; extend via the
# env hook AUDITOOOR_R41_POC_EVIDENCE_PATTERNS.
#
# Required artifact bundle when triggered (suffix-match against folder
# contents):
#   - <slug>-poc.zip (or <slug-base>-poc.zip - severity-tag-dropped form)
#   - <slug>.poc-transcript.txt
#
# Tool: tools/submission-folder-structure-check.py --draft <draft> --completeness
# Verdicts: pass-out-of-scope, pass-all-artifacts-present, ok-rebuttal,
#   fail-artifact-missing, error.
# Override: <!-- r41-completeness-rebuttal: <reason up to 200 chars> --> or
#   visible bounded line `r41-completeness-rebuttal: <reason>`.
# ============================================================================
_GAP36_TOOL="$AUDITOOOR_DIR/tools/submission-folder-structure-check.py"
if [ -f "$_GAP36_TOOL" ]; then
    echo ""
    _GAP36_TMP=$(mktemp 2>/dev/null || echo "/tmp/gap36_r41_completeness_$$.json")
    _GAP36_ERR=$(mktemp 2>/dev/null || echo "/tmp/gap36_r41_completeness_$$.err")
    python3 "$_GAP36_TOOL" --draft "$SUB" --completeness --json \
        > "$_GAP36_TMP" 2> "$_GAP36_ERR"
    _GAP36_RC=$?

    _GAP36_SUMMARY=$(
        python3 - "$_GAP36_TMP" "$_GAP36_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    verdict = d.get("verdict", "?")
    reason = d.get("reason", "no detail")
    missing = d.get("missing_artifact_suffixes", [])
    markers = d.get("poc_evidence_markers_hit", [])
    extras = []
    if missing:
        extras.append("missing=" + ",".join(missing))
    if markers:
        extras.append("markers=" + str(len(markers)))
    extra = (" | " + ", ".join(extras)) if extras else ""
    print(verdict + ": " + reason[:240] + extra)
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_GAP36_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_GAP36_TMP"; then
            echo "  ✅ 112. GAP36-R41-ARTIFACT-COMPLETENESS rebuttal accepted: $_GAP36_SUMMARY"
        else
            echo "  ✅ 112. GAP36-R41-ARTIFACT-COMPLETENESS: $_GAP36_SUMMARY"
        fi
    elif [ "$_GAP36_RC" -eq 1 ]; then
        echo "  ❌ 112. GAP36-R41-ARTIFACT-COMPLETENESS blocked:"
        echo "       $_GAP36_SUMMARY"
        echo "       Either:"
        echo "         (a) place the missing artifact(s) in the per-finding folder:"
        echo "             <slug>-poc.zip (or <slug-base>-poc.zip) and"
        echo "             <slug>.poc-transcript.txt"
        echo "         (b) walk back the executed-PoC evidence wording in the draft"
        echo "             (the check skips drafts without trigger phrases)"
        echo "         (c) add: r41-completeness-rebuttal: <reason up to 200 chars>"
        echo "             or <!-- r41-completeness-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  112. GAP36-R41-ARTIFACT-COMPLETENESS error: $_GAP36_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_GAP36_TMP" "$_GAP36_ERR"
else
    echo "  ⚠️  112. GAP36-R41-ARTIFACT-COMPLETENESS: tool not found ($_GAP36_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #113: GAP29-HUNT-PHASE-ORDERING (Gap #29)
#
# r36-rebuttal: lane GAP-FIX-1-gap29 registered in
# .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py.
#
# Operator anchor (2026-05-26): drill / hunt / composition lanes spawned
# before `make audit` completed read a stale LIVE_TARGET_REPORT.md and
# pursued stale hypotheses. This gate is the spawn-worker.sh sibling: the
# standalone tool is invoked by spawn-worker.sh; pre-submit-check fires
# this informational variant for any draft whose workspace has an audit
# marker, surfacing staleness as a warning so the operator can decide
# whether to refresh audit state before filing.
#
# Trigger: ANY draft (severity-agnostic) when WS_DIR is resolved AND the
# workspace has either .auditooor/last_audit_complete_marker OR
# docs/LIVE_TARGET_REPORT.md.
#
# Tool: tools/hunt-phase-ordering-check.py --workspace <WS> --lane-id presub-context --lane-type filing
# Verdicts: pass-* and ok-rebuttal are silent; fail-stale-audit-state +
#   fail-drill-before-audit become advisory warns (since pre-submit-check
#   may legitimately fire before audit, this is informational only).
# Override: <!-- gap29-rebuttal: <reason up to 200 chars> --> on the draft.
# ============================================================================
_GAP29_TOOL="$AUDITOOOR_DIR/tools/hunt-phase-ordering-check.py"
if [ -f "$_GAP29_TOOL" ] && [ -n "$WS_DIR" ]; then
    echo ""
    _GAP29_MARKER="$WS_DIR/.auditooor/last_audit_complete_marker"
    _GAP29_LIVE_TGT="$WS_DIR/docs/LIVE_TARGET_REPORT.md"
    if [ -f "$_GAP29_MARKER" ] || [ -f "$_GAP29_LIVE_TGT" ]; then
        _GAP29_TMP=$(mktemp 2>/dev/null || echo "/tmp/gap29_phase_ordering_$$.json")
        # Use lane-id "presub-context" + lane-type "filing" so the gate
        # passes with pass-not-drill-lane. We are NOT enforcing drill
        # ordering here - only surfacing audit-state staleness as info.
        python3 "$_GAP29_TOOL" \
            --workspace "$WS_DIR" \
            --lane-id "presub-context" \
            --lane-type "filing" \
            --prompt-file "$SUB" \
            --json > "$_GAP29_TMP" 2>/dev/null
        _GAP29_RC=$?
        _GAP29_VERDICT=$(grep -oE '"verdict": "[^"]*"' "$_GAP29_TMP" | head -1 | sed 's/"verdict": "\(.*\)"/\1/')
        if [ -z "$_GAP29_VERDICT" ]; then
            _GAP29_VERDICT="parse-error"
        fi

        # For pre-submit context the lane-type is filing so we always
        # get pass-not-drill-lane unless rebuttal short-circuits.  We
        # ALSO want to surface audit-marker staleness as an advisory
        # warn; do a direct mtime comparison.
        if [ -f "$_GAP29_MARKER" ] && [ -f "$_GAP29_LIVE_TGT" ]; then
            if [ "$_GAP29_LIVE_TGT" -nt "$_GAP29_MARKER" ]; then
                echo "  ⚠️  113. GAP29-HUNT-PHASE-ORDERING: LIVE_TARGET_REPORT.md is newer than audit-marker; consider re-running 'make audit' before filing"
                warns=$((warns + 1))
            else
                echo "  ✅ 113. GAP29-HUNT-PHASE-ORDERING: audit-marker fresh ($_GAP29_VERDICT)"
            fi
        elif [ ! -f "$_GAP29_MARKER" ] && [ -f "$_GAP29_LIVE_TGT" ]; then
            echo "  ⚠️  113. GAP29-HUNT-PHASE-ORDERING: LIVE_TARGET_REPORT.md present but no audit-marker; 'make audit' may not have completed"
            warns=$((warns + 1))
        else
            echo "  ✅ 113. GAP29-HUNT-PHASE-ORDERING: audit-marker present"
        fi
        rm -f "$_GAP29_TMP"
    else
        echo "  ✅ 113. GAP29-HUNT-PHASE-ORDERING: no audit-marker / live-target artifacts (not-applicable)"
    fi
else
    if [ -z "$WS_DIR" ]; then
        :  # workspace not resolved -- silent skip (handled by earlier check #11)
    else
        echo "  ⚠️  113. GAP29-HUNT-PHASE-ORDERING: tool not found ($_GAP29_TOOL); skipping"
        warns=$((warns + 1))
    fi
fi

# ============================================================================
# Check #114: R62-TRIAGER-MINDSET-PRECHECK (Rule 62)
#
# r36-rebuttal: lane TRIAGER-MINDSET-WIRE registered in
# .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py.
#
# Operator anchor 2026-05-26: existing tools/triager-pre-filing-simulator.py
# (1477 LOC) and reference/triager_patterns.json (R1..R23 patterns) were
# NOT wired into pre-submit-check.sh. DRILL-6 (Hyperbridge pallet-relayer
# u256 truncation) was filed Medium and triager-closed with rationale
# "BRIDGE supply far below u128::MAX, structurally unreachable" - the
# existing R2 / new R18 pattern would have surfaced this at hypothesis
# stage if the simulator had been run. R62 codifies "invoke the simulator
# BEFORE drafting and BEFORE staging promotion" as a hard gate.
#
# Trigger: ANY draft (severity-agnostic, LOW+) when both tool and
# workspace are resolvable.
#
# Verdicts: pass-no-triager-pattern-match / pass-all-guards-addressed /
#   pass-out-of-scope / ok-rebuttal / fail-triager-pattern-matched-no-
#   guard-addressed / error.
#
# Override: <!-- r62-rebuttal: <reason up to 200 chars> --> on the draft.
# ============================================================================
_R62_TOOL="$AUDITOOOR_DIR/tools/triager-pre-filing-simulator.py"
if [ -f "$_R62_TOOL" ] && [ -n "$WS_DIR" ]; then
    echo ""
    # Honor rebuttal short-circuit early (avoid running the simulator if
    # the operator has explicitly authorized the bypass). Accept either
    # the HTML-comment form `<!-- r62-rebuttal: <reason> -->` or the
    # visible bounded line form `r62-rebuttal: <reason>` (<=200 chars).
    if grep -qE '<!--[[:space:]]*r62-rebuttal:[[:space:]]*[^[:space:]].*-->' "$SUB" 2>/dev/null \
       || grep -qE '^r62-rebuttal:[[:space:]]+[^[:space:]]' "$SUB" 2>/dev/null; then
        echo "  ✅ 114. R62-TRIAGER-MINDSET-PRECHECK: ok-rebuttal (r62-rebuttal marker present)"
    else
        _R62_TMP=$(mktemp 2>/dev/null || echo "/tmp/r62_triager_precheck_$$.json")
        _R62_SEV_ARG=""
        if [ -n "${SEVERITY:-}" ]; then
            _R62_SEV_ARG="--severity ${SEVERITY}"
        fi
        # The simulator is read-only and bounded; rc=0 with valid JSON or
        # we treat the gate as advisory (skip-on-error fail-open).
        python3 "$_R62_TOOL" --draft "$SUB" --workspace "$WS_DIR" $_R62_SEV_ARG \
            > "$_R62_TMP" 2>/dev/null
        _R62_RC=$?
        if [ "$_R62_RC" -ne 0 ] || [ ! -s "$_R62_TMP" ]; then
            echo "  ⚠️  114. R62-TRIAGER-MINDSET-PRECHECK: simulator returned rc=$_R62_RC; skipping (advisory)"
            warns=$((warns + 1))
        else
            # Parse matched_patterns count + recommended_action from the JSON.
            # We treat ANY matched pattern as a fail unless the
            # recommended_action is the no-match passthrough.
            _R62_REC_ACTION=$(grep -oE '"recommended_action":[[:space:]]*"[^"]*"' "$_R62_TMP" \
                | head -1 | sed -E 's/.*"recommended_action":[[:space:]]*"([^"]*)"/\1/')
            _R62_MATCHED_COUNT=$(python3 - "$_R62_TMP" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1], "r") as f:
        d = json.load(f)
    matched = d.get("matched_patterns") or []
    # Exclude the synthetic R9 workspace-duplicateish row from the count;
    # R9 has its own treatment in pre-submit-check via L31 (Check #49).
    real = [r for r in matched if isinstance(r, dict) and r.get("id") != "R9"]
    print(len(real))
except Exception:
    print(0)
PYEOF
)
            _R62_MATCHED_COUNT="${_R62_MATCHED_COUNT:-0}"
            _R62_TOP_PATTERN=$(python3 - "$_R62_TMP" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1], "r") as f:
        d = json.load(f)
    rows = [r for r in (d.get("matched_patterns") or []) if isinstance(r, dict) and r.get("id") != "R9"]
    if rows:
        rows.sort(key=lambda r: -int(r.get("score") or 0))
        print(f"{rows[0].get('id','?')} ({rows[0].get('name','?')})")
except Exception:
    print("")
PYEOF
)
            if [ "$_R62_MATCHED_COUNT" -eq 0 ]; then
                echo "  ✅ 114. R62-TRIAGER-MINDSET-PRECHECK: no triager rejection patterns matched ($_R62_REC_ACTION)"
            else
                echo "  ❌ 114. R62-TRIAGER-MINDSET-PRECHECK: $_R62_MATCHED_COUNT triager rejection pattern(s) matched — top: $_R62_TOP_PATTERN"
                echo "      Run: python3 tools/triager-pre-filing-simulator.py --draft '$SUB' --workspace '$WS_DIR'"
                echo "      Either address each matched pattern's pre_submit_guard, or add"
                echo "      <!-- r62-rebuttal: <reason up to 200 chars> --> to the draft."
                fails=$((fails + 1))
            fi
        fi
        rm -f "$_R62_TMP"
    fi
else
    if [ -z "$WS_DIR" ]; then
        :  # workspace not resolved -- silent skip
    else
        echo "  ⚠️  114. R62-TRIAGER-MINDSET-PRECHECK: tool not found ($_R62_TOOL); skipping"
        warns=$((warns + 1))
    fi
fi

# ============================================================================
# Check #115: R63-AUTO-TIER-ASSIGNMENT (Rule 63)
#
# r36-rebuttal: lane-RULE-63 registered in .auditooor/agent_pathspec.json
# via tools/agent-pathspec-register.py.
#
# Operator anchor 2026-05-26: existing R52 / R56 only check rubric-row
# presence and component fit; they do NOT verify the SEMANTIC tier of
# the impact text matches the claimed tier. R63 codifies "parse SEVERITY.md
# into per-tier keyword sets and score the draft's impact text against
# each tier; refuse when the claimed tier mismatches the top-scoring tier".
#
# Trigger: ANY draft (severity-agnostic, LOW+) when both tool and
# workspace SEVERITY.md are resolvable.
#
# Verdicts: pass-tier-matches-impact-semantics / pass-out-of-scope /
#   pass-low-confidence / ok-rebuttal / fail-tier-overclaim /
#   fail-tier-underclaim / fail-no-impact-section / error.
#
# Override: <!-- r63-rebuttal: <reason up to 200 chars> --> on the draft.
# ============================================================================
_R63_TOOL="$AUDITOOOR_DIR/tools/rubric-auto-tier-assigner.py"
if [ -f "$_R63_TOOL" ]; then
    echo ""
    # Honor rebuttal short-circuit early.
    if grep -qE '<!--[[:space:]]*r63-rebuttal:[[:space:]]*[^[:space:]].*-->' "$SUB" 2>/dev/null \
       || grep -qE '^r63-rebuttal:[[:space:]]+[^[:space:]]' "$SUB" 2>/dev/null; then
        echo "  ✅ 115. R63-AUTO-TIER-ASSIGNMENT: ok-rebuttal (r63-rebuttal marker present)"
    else
        _R63_TMP=$(mktemp 2>/dev/null || echo "/tmp/r63_auto_tier_$$.json")
        _R63_SEV_ARG=""
        if [ -n "${SEVERITY:-}" ]; then
            _R63_SEV_ARG="--severity ${SEVERITY}"
        fi
        _R63_WS_ARG=""
        if [ -n "$WS_DIR" ]; then
            _R63_WS_ARG="--workspace $WS_DIR"
        fi
        python3 "$_R63_TOOL" "$SUB" $_R63_WS_ARG $_R63_SEV_ARG --json \
            > "$_R63_TMP" 2>/dev/null
        _R63_RC=$?
        _R63_VERDICT=$(grep -oE '"verdict":[[:space:]]*"[^"]*"' "$_R63_TMP" 2>/dev/null \
            | head -1 | sed -E 's/.*"verdict":[[:space:]]*"([^"]*)"/\1/')
        _R63_REASON=$(grep -oE '"reason":[[:space:]]*"[^"]*"' "$_R63_TMP" 2>/dev/null \
            | head -1 | sed -E 's/.*"reason":[[:space:]]*"([^"]*)"/\1/' | head -c 240)
        case "$_R63_VERDICT" in
            pass-tier-matches-impact-semantics)
                echo "  ✅ 115. R63-AUTO-TIER-ASSIGNMENT: tier matches impact semantics"
                ;;
            pass-out-of-scope|pass-low-confidence)
                echo "  ✅ 115. R63-AUTO-TIER-ASSIGNMENT: $_R63_VERDICT"
                ;;
            ok-rebuttal)
                echo "  ✅ 115. R63-AUTO-TIER-ASSIGNMENT: ok-rebuttal"
                ;;
            fail-tier-overclaim|fail-tier-underclaim|fail-no-impact-section)
                echo "  ❌ 115. R63-AUTO-TIER-ASSIGNMENT: $_R63_VERDICT"
                echo "      Reason: $_R63_REASON"
                echo "      Run: python3 tools/rubric-auto-tier-assigner.py '$SUB' --workspace '${WS_DIR:-<ws>}'"
                echo "      Either re-tier the draft to match impact semantics, or add"
                echo "      <!-- r63-rebuttal: <reason up to 200 chars> --> to the draft."
                fails=$((fails + 1))
                ;;
            error|"")
                if [ "$_R63_RC" -eq 2 ]; then
                    echo "  ⚠️  115. R63-AUTO-TIER-ASSIGNMENT: input error rc=$_R63_RC; skipping (advisory)"
                    warns=$((warns + 1))
                else
                    echo "  ⚠️  115. R63-AUTO-TIER-ASSIGNMENT: tool returned rc=$_R63_RC; skipping (advisory)"
                    warns=$((warns + 1))
                fi
                ;;
            *)
                echo "  ⚠️  115. R63-AUTO-TIER-ASSIGNMENT: unknown verdict '$_R63_VERDICT'; skipping (advisory)"
                warns=$((warns + 1))
                ;;
        esac
        rm -f "$_R63_TMP"
    fi
else
    echo "  ⚠️  115. R63-AUTO-TIER-ASSIGNMENT: tool not found ($_R63_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #116: R64-PROMPT-CLAIM-VERIFICATION (Rule R64)
#
# Codified 2026-05-26 after the TOK-A "10K Cantina rationales" hallucination
# was found embedded in an orchestrator-issued sub-agent prompt. R64 catches
# unverified factual claims (tool paths, MCP callables, Check #N, R-rule
# IDs, schema names, record counts) in any prompt-bearing draft body BEFORE
# the worker is dispatched. L25/L26 trust-but-verify only catches this
# AFTER the worker reads source files; R64 catches it pre-dispatch.
#
# Trigger: ANY draft (severity-agnostic, LOW+).
#
# Verdicts: pass-all-verified / pass-no-claims / ok-rebuttal /
#   fail-prompt-contains-unverified-claim / error.
#
# Override: <!-- r64-rebuttal: <reason up to 200 chars> --> on the draft,
# or an inline `r64-rebuttal: <reason>` line.
# ============================================================================
_R64_TOOL="$AUDITOOOR_DIR/tools/r64-prompt-claim-verifier.py"
if [ -f "$_R64_TOOL" ]; then
    echo ""
    if grep -qE '<!--[[:space:]]*r64-rebuttal:[[:space:]]*[^[:space:]].*-->' "$SUB" 2>/dev/null \
       || grep -qE '^r64-rebuttal:[[:space:]]+[^[:space:]]' "$SUB" 2>/dev/null; then
        echo "  ✅ 116. R64-PROMPT-CLAIM-VERIFICATION: ok-rebuttal (r64-rebuttal marker present)"
    else
        _R64_TMP=$(mktemp 2>/dev/null || echo "/tmp/r64_claim_verify_$$.json")
        _R64_WS_ARG=""
        if [ -n "$WS_DIR" ]; then
            _R64_WS_ARG="--workspace $WS_DIR"
        fi
        python3 "$_R64_TOOL" "$SUB" $_R64_WS_ARG --json \
            > "$_R64_TMP" 2>/dev/null
        _R64_RC=$?
        _R64_VERDICT=$(grep -oE '"overall_verdict":[[:space:]]*"[^"]*"' "$_R64_TMP" 2>/dev/null \
            | head -1 | sed -E 's/.*"overall_verdict":[[:space:]]*"([^"]*)"/\1/')
        _R64_UNVERIFIED=$(grep -oE '"unverified_count":[[:space:]]*[0-9]+' "$_R64_TMP" 2>/dev/null \
            | head -1 | sed -E 's/.*"unverified_count":[[:space:]]*([0-9]+)/\1/')
        case "$_R64_VERDICT" in
            pass-all-verified|pass-no-claims)
                echo "  ✅ 116. R64-PROMPT-CLAIM-VERIFICATION: $_R64_VERDICT"
                ;;
            ok-rebuttal)
                echo "  ✅ 116. R64-PROMPT-CLAIM-VERIFICATION: ok-rebuttal"
                ;;
            fail-prompt-contains-unverified-claim)
                echo "  ❌ 116. R64-PROMPT-CLAIM-VERIFICATION: $_R64_VERDICT (${_R64_UNVERIFIED:-?} unverified)"
                echo "      Run: python3 tools/r64-prompt-claim-verifier.py '$SUB' --workspace '${WS_DIR:-<ws>}'"
                echo "      Either replace fabricated claims with real ones, or add"
                echo "      <!-- r64-rebuttal: <reason up to 200 chars> --> to the draft."
                fails=$((fails + 1))
                ;;
            error|"")
                echo "  ⚠️  116. R64-PROMPT-CLAIM-VERIFICATION: tool returned rc=$_R64_RC; skipping (advisory)"
                warns=$((warns + 1))
                ;;
            *)
                echo "  ⚠️  116. R64-PROMPT-CLAIM-VERIFICATION: unknown verdict '$_R64_VERDICT'; skipping (advisory)"
                warns=$((warns + 1))
                ;;
        esac
        rm -f "$_R64_TMP"
    fi
else
    echo "  ⚠️  116. R64-PROMPT-CLAIM-VERIFICATION: tool not found ($_R64_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #117: R65-MODEL-ROUTING-CALIBRATION (Rule R65)
#
# Codified 2026-05-26 after the TOK-B-CL $11 commitment based on the catalog
# "Pro because reasoning" hypothesis (not evidence) was surfaced by the
# operator. R65 catches budget-bearing dispatches where the model choice has
# no fresh paired-comparison evidence in reference/deepseek_task_routing.json.
# R37 polices per-emit tier; R64 polices per-dispatch claim verification;
# R65 polices per-spend calibration.
#
# Trigger: ANY draft (severity-agnostic) whose body cites a budget-bearing
# dispatch ("Fire TOK-X via deepseek-pro at $X", "make deepseek-fire TASK=X
# BUDGET=Y", "spend $X on <model>" / equivalent).
#
# Verdicts: pass-calibration-fresh / pass-calibration-not-required /
#   ok-rebuttal / fail-no-calibration / fail-calibration-stale / error.
#
# Override: <!-- r65-rebuttal: <reason up to 200 chars> --> on the draft,
# or env AUDITOOOR_R65_BYPASS=1 with rationale.
# ============================================================================
_R65_TOOL="$AUDITOOOR_DIR/tools/deepseek-task-router.py"
if [ -f "$_R65_TOOL" ]; then
    echo ""
    # Detect budget-bearing dispatch citation in the draft body.
    _R65_DISPATCH_HIT=$(grep -nEo \
        'make[[:space:]]+deepseek-fire[[:space:]]+TASK=[A-Z0-9_-]+|Fire[[:space:]]+TOK-[A-Z0-9_-]+|deepseek-pro|deepseek-flash|--budget-cap-usd[[:space:]]+[0-9]+|spend[[:space:]]+\$[0-9]+' \
        "$SUB" 2>/dev/null | head -3)

    if [ -z "$_R65_DISPATCH_HIT" ]; then
        echo "  ✅ 117. R65-MODEL-ROUTING-CALIBRATION: pass-no-budget-dispatch-cited"
    elif grep -qE '<!--[[:space:]]*r65-rebuttal:[[:space:]]*[^[:space:]].*-->' "$SUB" 2>/dev/null \
       || grep -qE '^r65-rebuttal:[[:space:]]+[^[:space:]]' "$SUB" 2>/dev/null; then
        echo "  ✅ 117. R65-MODEL-ROUTING-CALIBRATION: ok-rebuttal (r65-rebuttal marker present)"
    else
        # Extract the TASK= or TOK-X reference to feed the router.
        _R65_TASK=$(echo "$_R65_DISPATCH_HIT" | grep -oE 'TOK-[A-Z0-9_-]+' | head -1)
        if [ -z "$_R65_TASK" ]; then
            _R65_TASK=$(echo "$_R65_DISPATCH_HIT" | grep -oE 'TASK=[A-Z0-9_-]+' | head -1 | sed 's/TASK=//')
        fi

        if [ -z "$_R65_TASK" ]; then
            echo "  ⚠️  117. R65-MODEL-ROUTING-CALIBRATION: dispatch cited but TASK id not extractable; advisory"
            warns=$((warns + 1))
        else
            # Default to $11 as the test budget (above $1 R65 threshold).
            _R65_BUDGET="${AUDITOOOR_R65_TEST_BUDGET_USD:-11.0}"
            _R65_TMP=$(mktemp 2>/dev/null || echo "/tmp/r65_router_$$.json")
            python3 "$_R65_TOOL" \
                --task-id "$_R65_TASK" \
                --budget-usd "$_R65_BUDGET" \
                --json > "$_R65_TMP" 2>/dev/null
            _R65_RC=$?
            _R65_VERDICT=$(grep -oE '"verdict":[[:space:]]*"[^"]*"' "$_R65_TMP" 2>/dev/null \
                | head -1 | sed -E 's/.*"verdict":[[:space:]]*"([^"]*)"/\1/')
            case "$_R65_VERDICT" in
                pass-calibration-fresh|pass-calibration-not-required|ok-rebuttal)
                    echo "  ✅ 117. R65-MODEL-ROUTING-CALIBRATION: $_R65_VERDICT (TASK=$_R65_TASK)"
                    ;;
                fail-no-calibration)
                    echo "  ❌ 117. R65-MODEL-ROUTING-CALIBRATION: $_R65_VERDICT (TASK=$_R65_TASK)"
                    echo "      Draft cites budget-bearing dispatch but routing.json has no entry for $_R65_TASK."
                    echo "      Run: make deepseek-calibrate TASK=$_R65_TASK [MOCK=1]"
                    echo "      Or add <!-- r65-rebuttal: <reason up to 200 chars> --> to the draft."
                    fails=$((fails + 1))
                    ;;
                fail-calibration-stale)
                    _R65_DAYS=$(grep -oE '"calibration_days_old":[[:space:]]*[0-9]+' "$_R65_TMP" 2>/dev/null \
                        | head -1 | sed -E 's/.*:[[:space:]]*([0-9]+)/\1/')
                    echo "  ❌ 117. R65-MODEL-ROUTING-CALIBRATION: $_R65_VERDICT (TASK=$_R65_TASK, ${_R65_DAYS:-?}d old)"
                    echo "      Routing entry is stale (>90 days). Re-run: make deepseek-calibrate TASK=$_R65_TASK"
                    fails=$((fails + 1))
                    ;;
                error|"")
                    echo "  ⚠️  117. R65-MODEL-ROUTING-CALIBRATION: tool returned rc=$_R65_RC; skipping (advisory)"
                    warns=$((warns + 1))
                    ;;
                *)
                    echo "  ⚠️  117. R65-MODEL-ROUTING-CALIBRATION: unknown verdict '$_R65_VERDICT'; skipping (advisory)"
                    warns=$((warns + 1))
                    ;;
            esac
            rm -f "$_R65_TMP"
        fi
    fi
else
    echo "  ⚠️  117. R65-MODEL-ROUTING-CALIBRATION: tool not found ($_R65_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #118: R67-CORPUS-ATOMIC-WRITE-ROTATION (Rule R67)
#
# Codified 2026-05-26 after the LIFT-9 940-record loss
# (invariants_pilot_audited.jsonl 2.0M -> 216K silent shrinkage). LIFT-22
# closed R55's trigger gap; LIFT-26 (this rule) closes the no-rotation
# policy gap.
#
# Trigger: ANY draft (severity-agnostic) whose body cites a derived corpus
# file (audit/corpus_tags/{derived,tags}/**/*.{jsonl,json,yaml,yml}).
#
# Tool: tools/r67-rotation-cursor-verifier.py (one file at a time via
#       --file). Emits per-file verdict; FAIL on
#       fail-shrinkage-over-50pct-no-log-entry.
#
# Override: <!-- r67-rebuttal: <reason up to 200 chars> --> in the draft,
#           or `r67-rebuttal: <reason>` as a visible bounded line.
# r36-rebuttal: lane-LIFT-26-R67 registered in agent_pathspec.json
# ============================================================================
_R67_TOOL="$AUDITOOOR_DIR/tools/r67-rotation-cursor-verifier.py"
if [ -f "$_R67_TOOL" ]; then
    echo ""
    # Extract any cited derived-corpus path from the draft body.
    _R67_CORPUS_HITS=$(grep -oE \
        'audit/corpus_tags/(derived|tags)/[A-Za-z0-9_./-]+\.(jsonl|json|yaml|yml)' \
        "$SUB" 2>/dev/null | sort -u | head -5)

    if [ -z "$_R67_CORPUS_HITS" ]; then
        echo "  ✅ 118. R67-CORPUS-ATOMIC-WRITE-ROTATION: pass-no-corpus-file-cited"
    elif grep -qE '<!--[[:space:]]*r67-rebuttal:[[:space:]]*[^[:space:]].*-->' "$SUB" 2>/dev/null \
       || grep -qE '^r67-rebuttal:[[:space:]]+[^[:space:]]' "$SUB" 2>/dev/null; then
        echo "  ✅ 118. R67-CORPUS-ATOMIC-WRITE-ROTATION: ok-rebuttal (r67-rebuttal marker present)"
    else
        _R67_ANY_FAIL=0
        _R67_ANY_WARN=0
        while IFS= read -r _R67_PATH; do
            [ -z "$_R67_PATH" ] && continue
            # Resolve relative paths against AUDITOOOR_DIR if not absolute.
            case "$_R67_PATH" in
                /*) _R67_ABS="$_R67_PATH" ;;
                *)  _R67_ABS="$AUDITOOOR_DIR/$_R67_PATH" ;;
            esac
            if [ ! -f "$_R67_ABS" ]; then
                # Cited path may not exist in this workspace; advisory skip.
                continue
            fi
            _R67_TMP=$(mktemp 2>/dev/null || echo "/tmp/r67_verifier_$$.json")
            python3 "$_R67_TOOL" --file "$_R67_ABS" --json > "$_R67_TMP" 2>/dev/null
            _R67_VERDICT=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    rs = d.get("results", [])
    if rs:
        print(rs[0].get("verdict", ""))
except Exception:
    print("")
' "$_R67_TMP" 2>/dev/null)
            case "$_R67_VERDICT" in
                pass-fresh-rotation-and-stable)
                    echo "  ✅ 118. R67-CORPUS-ATOMIC-WRITE-ROTATION: pass-fresh-rotation-and-stable ($_R67_PATH)"
                    ;;
                fail-shrinkage-over-50pct-no-log-entry)
                    echo "  ❌ 118. R67-CORPUS-ATOMIC-WRITE-ROTATION: $_R67_VERDICT ($_R67_PATH)"
                    echo "      File shrunk >50% since last rotation_log entry without a fresh log record."
                    echo "      Migrate writer to tools/lib/atomic_corpus_writer.py::atomic_write_corpus_file()"
                    echo "      Or add <!-- r67-rebuttal: <reason up to 200 chars> --> to the draft."
                    _R67_ANY_FAIL=1
                    ;;
                warn-no-rotation-log|warn-stale-rotation-log)
                    echo "  ⚠️  118. R67-CORPUS-ATOMIC-WRITE-ROTATION: $_R67_VERDICT ($_R67_PATH)"
                    _R67_ANY_WARN=1
                    ;;
                error|"")
                    # Advisory skip; do not block.
                    ;;
            esac
            rm -f "$_R67_TMP"
        done <<< "$_R67_CORPUS_HITS"
        if [ "$_R67_ANY_FAIL" -eq 1 ]; then
            fails=$((fails + 1))
        elif [ "$_R67_ANY_WARN" -eq 1 ]; then
            warns=$((warns + 1))
        fi
    fi
else
    echo "  ⚠️  118. R67-CORPUS-ATOMIC-WRITE-ROTATION: tool not found ($_R67_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #119: R69-CALLABLE-WIRING-VERIFIER (Rule R69)
#
# Codified 2026-05-26 after the LIFT-21 + LIFT-25 pattern. Codex Phase 3
# takeover reported 3 MCP callables LANDED; in fact 2/3 wiring branches
# were missing (vault_global_chain_template_match was absent from
# choices/schemas/dispatcher; vault_chained_attack_plan_context's
# seed_from_global_templates kwarg was silently discarded). R69 catches
# the pattern at draft-submit time by extracting any vault_X callable name
# the draft claims is wired and verifying it against the live
# tools/vault-mcp-server.py source.
#
# Trigger: draft body cites a vault_X callable name (severity-agnostic).
#
# Verdicts (per callable):
#   wired-and-callable / wired-but-degraded -> PASS
#   missing-from-choices / -tool-schemas / -method / -dispatcher /
#   silently-ignored-kwarg / live-call-error -> warn (advisory by default)
#
# Override: <!-- r69-rebuttal: <reason up to 200 chars> --> on the draft.
# r36-rebuttal: lane LANE-217-R69-CALLABLE-WIRING-VERIFIER declared via
# tools/agent-pathspec-register.py.
# ============================================================================
_R69_TOOL="$AUDITOOOR_DIR/tools/r69-callable-wiring-verifier.py"
_R69_SERVER="$AUDITOOOR_DIR/tools/vault-mcp-server.py"
if [ -f "$_R69_TOOL" ] && [ -f "$_R69_SERVER" ]; then
    echo ""
    if grep -qE '<!--[[:space:]]*r69-rebuttal:[[:space:]]*[^[:space:]].*-->' "$SUB" 2>/dev/null \
       || grep -qE '^r69-rebuttal:[[:space:]]+[^[:space:]]' "$SUB" 2>/dev/null; then
        echo "  ✅ 119. R69-CALLABLE-WIRING-VERIFIER: ok-rebuttal (r69-rebuttal marker present)"
    else
        # Extract claimed vault_X callable names from the draft body. We
        # use the conservative shape: any token starting with `vault_`
        # followed by [a-zA-Z0-9_]. De-dup; cap at 20 to bound the
        # subprocess call.
        _R69_NAMES=$(grep -oE 'vault_[a-zA-Z0-9_]+' "$SUB" 2>/dev/null \
            | sort -u | head -20 | tr '\n' ',' | sed 's/,$//')
        if [ -z "$_R69_NAMES" ]; then
            echo "  ✅ 119. R69-CALLABLE-WIRING-VERIFIER: pass-no-callables-cited"
        else
            _R69_TMP=$(mktemp 2>/dev/null || echo "/tmp/r69_wiring_$$.json")
            python3 "$_R69_TOOL" \
                --claimed-callables "$_R69_NAMES" \
                --server "$_R69_SERVER" \
                --no-live-call \
                --json > "$_R69_TMP" 2>/dev/null
            _R69_RC=$?
            _R69_VERDICT=$(grep -oE '"overall_verdict":[[:space:]]*"[^"]*"' "$_R69_TMP" 2>/dev/null \
                | head -1 | sed -E 's/.*"overall_verdict":[[:space:]]*"([^"]*)"/\1/')
            _R69_FAILS=$(grep -oE '"fail_count":[[:space:]]*[0-9]+' "$_R69_TMP" 2>/dev/null \
                | head -1 | sed -E 's/.*"fail_count":[[:space:]]*([0-9]+)/\1/')
            _R69_TOTAL=$(grep -oE '"total_count":[[:space:]]*[0-9]+' "$_R69_TMP" 2>/dev/null \
                | head -1 | sed -E 's/.*"total_count":[[:space:]]*([0-9]+)/\1/')
            case "$_R69_VERDICT" in
                pass)
                    echo "  ✅ 119. R69-CALLABLE-WIRING-VERIFIER: pass (${_R69_TOTAL:-?} callable(s) wired)"
                    ;;
                fail)
                    # Default is WARN, not FAIL: many drafts mention
                    # vault_X for documentation purposes (callable refs
                    # in prose) without asserting wiring; blocking on
                    # those would generate noise. Operators can elevate
                    # via env AUDITOOOR_R69_STRICT=1.
                    if [ "${AUDITOOOR_R69_STRICT:-0}" = "1" ]; then
                        echo "  ❌ 119. R69-CALLABLE-WIRING-VERIFIER: fail (${_R69_FAILS:-?}/${_R69_TOTAL:-?} callable(s) not wired)"
                        echo "      Run: python3 tools/r69-callable-wiring-verifier.py --claimed-callables '$_R69_NAMES'"
                        echo "      Either fix the wiring, scrub the unverified vault_X reference, or add"
                        echo "      <!-- r69-rebuttal: <reason up to 200 chars> --> to the draft."
                        fails=$((fails + 1))
                    else
                        echo "  ⚠️  119. R69-CALLABLE-WIRING-VERIFIER: warn (${_R69_FAILS:-?}/${_R69_TOTAL:-?} unverified vault_X reference(s); advisory)"
                        echo "      Run with AUDITOOOR_R69_STRICT=1 to hard-fail."
                        warns=$((warns + 1))
                    fi
                    ;;
                error|"")
                    echo "  ⚠️  119. R69-CALLABLE-WIRING-VERIFIER: tool returned rc=$_R69_RC; skipping (advisory)"
                    warns=$((warns + 1))
                    ;;
                *)
                    echo "  ⚠️  119. R69-CALLABLE-WIRING-VERIFIER: unknown verdict '$_R69_VERDICT'; skipping (advisory)"
                    warns=$((warns + 1))
                    ;;
            esac
            rm -f "$_R69_TMP"
        fi
    fi
else
    echo "  ⚠️  119. R69-CALLABLE-WIRING-VERIFIER: tool or server not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #120: R70-FILE-TRACKED-IN-GIT (Rule R70)
#
# Codified 2026-05-26 after 3 cases this session of LANDED claims with
# files that were untracked in git (LIFT-9 #194 corpus-refresh hook script,
# Codex Phase 3 takeover claiming vault_global_chain_template_match wiring
# with the underlying seed module + JSONL untracked, and the chain
# templates JSONL itself). R70 is the file-existence + git-tracking
# sibling of R69 (callable-wiring verifier, Check #119).
#
# Trigger: ANY draft / lane result that cites tool-tree file paths.
# The verifier extracts paths from the draft body and checks each one
# against four rules: file exists, file is git-tracked, file is in HEAD,
# file is non-empty.
#
# Verdicts: pass-all-tracked-and-committed / pass-no-paths-claimed /
#   ok-rebuttal / warn-some-uncommitted / fail-untracked-or-missing /
#   fail-strict / error.
#
# Override: <!-- r70-rebuttal: <reason up to 200 chars> --> on the draft,
# or an inline `r70-rebuttal: <reason>` line. Use when an untracked file
# is intentionally excluded from VCS (build artifact, gitignored
# calibration log, lane lacks commit permission).
#
# Coordination: LANE-218 originally targeted Check #118 but LIFT-26 (R67)
# claimed it first; R69 then took #119. R70 lands at #120. R36 pathspec
# for LANE-218-R70-FILE-TRACKED-VERIFIER declared via
# tools/agent-pathspec-register.py.
# ============================================================================
_R70_TOOL="$AUDITOOOR_DIR/tools/r70-file-tracked-verifier.py"
if [ -f "$_R70_TOOL" ]; then
    echo ""
    if grep -qE '<!--[[:space:]]*r70-rebuttal:[[:space:]]*[^[:space:]].*-->' "$SUB" 2>/dev/null \
       || grep -qE '^r70-rebuttal:[[:space:]]+[^[:space:]]' "$SUB" 2>/dev/null; then
        echo "  ✅ 120. R70-FILE-TRACKED-IN-GIT: ok-rebuttal (r70-rebuttal marker present)"
    else
        _R70_TMP=$(mktemp 2>/dev/null || echo "/tmp/r70_file_tracked_$$.json")
        python3 "$_R70_TOOL" --draft "$SUB" --json > "$_R70_TMP" 2>/dev/null
        _R70_RC=$?
        _R70_VERDICT=$(grep -oE '"verdict":[[:space:]]*"[^"]*"' "$_R70_TMP" 2>/dev/null \
            | head -1 | sed -E 's/.*"verdict":[[:space:]]*"([^"]*)"/\1/')
        _R70_COUNT=$(grep -oE '"claimed_path_count":[[:space:]]*[0-9]+' "$_R70_TMP" 2>/dev/null \
            | head -1 | sed -E 's/.*"claimed_path_count":[[:space:]]*([0-9]+)/\1/')
        case "$_R70_VERDICT" in
            pass-all-tracked-and-committed|pass-no-paths-claimed)
                echo "  ✅ 120. R70-FILE-TRACKED-IN-GIT: $_R70_VERDICT (${_R70_COUNT:-0} paths)"
                ;;
            ok-rebuttal)
                echo "  ✅ 120. R70-FILE-TRACKED-IN-GIT: ok-rebuttal"
                ;;
            warn-some-uncommitted)
                echo "  ⚠️  120. R70-FILE-TRACKED-IN-GIT: $_R70_VERDICT (${_R70_COUNT:-0} paths claimed)"
                echo "      Some paths are tracked but not yet committed (staged or modified)."
                echo "      Run: python3 tools/r70-file-tracked-verifier.py --draft '$SUB'"
                warns=$((warns + 1))
                ;;
            fail-untracked-or-missing|fail-strict)
                echo "  ❌ 120. R70-FILE-TRACKED-IN-GIT: $_R70_VERDICT (${_R70_COUNT:-0} paths claimed)"
                echo "      At least one claimed path is untracked-on-disk or missing-from-disk."
                echo "      Run: python3 tools/r70-file-tracked-verifier.py --draft '$SUB'"
                echo "      Either git-add + commit the file, or add"
                echo "      <!-- r70-rebuttal: <reason up to 200 chars> --> to the draft."
                fails=$((fails + 1))
                ;;
            error|"")
                echo "  ⚠️  120. R70-FILE-TRACKED-IN-GIT: tool returned rc=$_R70_RC; skipping (advisory)"
                warns=$((warns + 1))
                ;;
            *)
                echo "  ⚠️  120. R70-FILE-TRACKED-IN-GIT: unknown verdict '$_R70_VERDICT'; skipping (advisory)"
                warns=$((warns + 1))
                ;;
        esac
        rm -f "$_R70_TMP"
    fi
else
    echo "  ⚠️  120. R70-FILE-TRACKED-IN-GIT: tool not found ($_R70_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #121: R71-LANE-VERDICT-BUS-CONSULT (Rule R71)
#
# Drill, hunt, triage, and dispatch-derived lane drafts must show that they
# consulted the lane verdict bus before proceeding. The gate accepts the
# canonical `## Lane-Verdict-Bus Consultation` section and Section 15n aliases,
# passes fresh workspaces with an empty bus, and accepts a bounded rebuttal.
#
# Trigger: lane-like draft / brief / result bodies.
#
# Verdicts: pass-section-present / pass-empty-bus / pass-out-of-scope /
#   ok-rebuttal / fail-no-consult / fail-malformed-bus-snapshot / error.
#
# Override: <!-- r71-rebuttal: <reason up to 200 chars> --> on the draft,
# or an inline `r71-rebuttal: <reason>` line.
# ============================================================================
_R71_TOOL="$AUDITOOOR_DIR/tools/lane-verdict-bus-consult-check.py"
if [ -f "$_R71_TOOL" ]; then
    echo ""
    _R71_TMP=$(mktemp 2>/dev/null || echo "/tmp/r71_lane_verdict_bus_$$.json")
    _R71_ARGS=("$SUB" "--json")
    if [ -n "$WS_DIR" ]; then
        _R71_ARGS+=("--workspace" "$WS_DIR")
    fi
    python3 "$_R71_TOOL" "${_R71_ARGS[@]}" > "$_R71_TMP" 2>/dev/null
    _R71_RC=$?
    _R71_SUMMARY=$(
        python3 - "$_R71_TMP" <<'PY' 2>/dev/null
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    verdict = data.get("verdict", "?")
    reason = data.get("reason", "no detail")
    evidence = data.get("evidence") or {}
    bus = evidence.get("bus") or {}
    extra = ""
    if bus.get("record_count") is not None:
        extra = " | records=" + str(bus.get("record_count"))
    print(verdict + ": " + reason[:220] + extra)
except Exception:
    print("parse-error")
PY
    )
    _R71_VERDICT=$(python3 - "$_R71_TMP" <<'PY' 2>/dev/null
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("verdict", ""))
except Exception:
    print("")
PY
)
    case "$_R71_VERDICT" in
        pass-section-present|pass-empty-bus|pass-out-of-scope|ok-rebuttal)
            echo "  [OK] 121. R71-LANE-VERDICT-BUS-CONSULT: $_R71_SUMMARY"
            ;;
        fail-no-consult|fail-malformed-bus-snapshot)
            echo "  [FAIL] 121. R71-LANE-VERDICT-BUS-CONSULT: $_R71_SUMMARY"
            echo "      Add a '## Lane-Verdict-Bus Consultation' section with the bus snapshot"
            echo "      path and timestamp, or add <!-- r71-rebuttal: <reason up to 200 chars> -->."
            fails=$((fails + 1))
            ;;
        error|"")
            echo "  [WARN] 121. R71-LANE-VERDICT-BUS-CONSULT: tool returned rc=$_R71_RC; skipping"
            warns=$((warns + 1))
            ;;
        *)
            echo "  [WARN] 121. R71-LANE-VERDICT-BUS-CONSULT: unknown verdict '$_R71_VERDICT'; skipping"
            warns=$((warns + 1))
            ;;
    esac
    rm -f "$_R71_TMP"
else
    echo "  [WARN] 121. R71-LANE-VERDICT-BUS-CONSULT: tool not found ($_R71_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #122: R72-FIX-REACH-SPREADER-CHECK (Rule R72)
# L30 missing-guard / asymmetric-pair claim must cite
# tools/fix-semantic-reach-spreader.py output. Override <!-- r72-rebuttal: -->.
# ============================================================================
_R72_TOOL="$AUDITOOOR_DIR/tools/r72-fix-reach-spreader-check.py"
if [ -f "$_R72_TOOL" ]; then
    echo ""
    _R72_OUT=$(python3 "$_R72_TOOL" "$SUB" ${WS_DIR:+--workspace "$WS_DIR"} 2>&1)
    _R72_RC=$?
    case "$_R72_RC" in
        0) echo "  [OK] 122. R72-FIX-REACH-SPREADER: $_R72_OUT" ;;
        1) echo "  [FAIL] 122. R72-FIX-REACH-SPREADER: $_R72_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 122. R72-FIX-REACH-SPREADER: rc=$_R72_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 122. R72-FIX-REACH-SPREADER: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #123: R73-CHAIN-DERIVED-CHECK (Rule R73)
# Chain-derived / compositional-attack draft must cite
# tools/chain-synthesizer-hunt-time.py output. Override <!-- r73-rebuttal: -->.
# ============================================================================
_R73_TOOL="$AUDITOOOR_DIR/tools/r73-chain-derived-check.py"
if [ -f "$_R73_TOOL" ]; then
    echo ""
    _R73_OUT=$(python3 "$_R73_TOOL" "$SUB" ${WS_DIR:+--workspace "$WS_DIR"} 2>&1)
    _R73_RC=$?
    case "$_R73_RC" in
        0) echo "  [OK] 123. R73-CHAIN-DERIVED: $_R73_OUT" ;;
        1) echo "  [FAIL] 123. R73-CHAIN-DERIVED: $_R73_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 123. R73-CHAIN-DERIVED: rc=$_R73_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 123. R73-CHAIN-DERIVED: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #124: R74-DOLLAR-IMPACT-GATE (Rule R74)
# HIGH+ draft with dollar_impact sidecar: gate verdict SKIP/DROP fails.
# Warn-only if no sidecar. Override <!-- r74-rebuttal: -->.
# ============================================================================
_R74_TOOL="$AUDITOOOR_DIR/tools/r74-dollar-impact-gate.py"
if [ -f "$_R74_TOOL" ]; then
    echo ""
    _R74_OUT=$(python3 "$_R74_TOOL" "$SUB" ${WS_DIR:+--workspace "$WS_DIR"} ${SEVERITY:+--severity "$SEVERITY"} 2>&1)
    _R74_RC=$?
    case "$_R74_RC" in
        0) echo "  [OK] 124. R74-DOLLAR-IMPACT: $_R74_OUT" ;;
        1) echo "  [FAIL] 124. R74-DOLLAR-IMPACT: $_R74_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 124. R74-DOLLAR-IMPACT: rc=$_R74_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 124. R74-DOLLAR-IMPACT: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #125: R76-HALLUCINATION-GUARD (Rule R76)
# Refuses CONFIRMED verdicts where file_line is empty/N-A/contains
# "conceptual"|"pattern"|"typical" or where code_excerpt is not greppable
# in the workspace source. Override: <!-- r76-rebuttal: <reason> -->
# Empirical anchor: hb-pallet-ismp-claim 2026-05-27 MIMO hallucinated
# keccak256(abi.encodePacked(...)) pattern that does NOT exist in real
# Hyperbridge source (real uses Leaf::Request enum encoding).
# ============================================================================
_R76_TOOL="$AUDITOOOR_DIR/tools/r76-hallucination-guard.py"
if [ -f "$_R76_TOOL" ]; then
    echo ""
    _R76_OUT=$(python3 "$_R76_TOOL" "$SUB" ${WS_DIR:+--workspace "$WS_DIR"} 2>&1)
    _R76_RC=$?
    case "$_R76_RC" in
        0) echo "  [OK] 125. R76-HALLUCINATION-GUARD: $_R76_OUT" ;;
        1) echo "  [FAIL] 125. R76-HALLUCINATION-GUARD: $_R76_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 125. R76-HALLUCINATION-GUARD: rc=$_R76_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 125. R76-HALLUCINATION-GUARD: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #126: GAP30-ALWAYS-ESCALATE-PLATFORM-OOS
# Draft text must not use always-escalate framing that matches platform OOS
# clauses from SCOPE.md / SEVERITY.md. Override:
#   <!-- gap30-rebuttal: <reason up to 200 chars> -->
# or visible:
#   gap30-rebuttal: <reason up to 200 chars>
# ============================================================================
_GAP30_TOOL="$AUDITOOOR_DIR/tools/always-escalate-platform-oos-check.py"
if [ -f "$_GAP30_TOOL" ]; then
    echo ""
    _GAP30_OUT=$(python3 "$_GAP30_TOOL" --workspace "${WS_DIR:-$AUDITOOOR_DIR}" --framing-file "$SUB" --rebuttal-file "$SUB" 2>&1)
    _GAP30_RC=$?
    case "$_GAP30_RC" in
        0) echo "  [OK] 126. GAP30-ALWAYS-ESCALATE-PLATFORM-OOS: $_GAP30_OUT" ;;
        1) echo "  [FAIL] 126. GAP30-ALWAYS-ESCALATE-PLATFORM-OOS: $_GAP30_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 126. GAP30-ALWAYS-ESCALATE-PLATFORM-OOS: rc=$_GAP30_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 126. GAP30-ALWAYS-ESCALATE-PLATFORM-OOS: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #127: R-ESCALATE-FIRST-REQUIRED (max-escalate-then-fully-prove)
# Medium+ drafts that narrow/cap severity AND walk away from a higher tier must
# prove the higher tier was attempted + EXECUTED end-to-end, OR cite a justified
# out-of-tree / platform-OOS infeasibility. Closes the R40 pass-claim-narrowed
# loophole (narrowing was an accepted free PASS).
# STRENGTHENED 2026-06-02 (zebra getaddresstxids anchor): the higher-tier
# detector now covers DoS/liveness HIGH->MEDIUM tier-drops, and a de-escalation
# walk-back that rests on REASONING-ONLY prose (capacity / pool-size /
# architecture) with no MEASURED/EXECUTED refutation (numbers with units, PASS
# transcript, control run) fails closed: fail-reasoned-walkback-not-measured.
# Overrides:
#   <!-- r-escalate-first-rebuttal: <reason up to 200 chars> -->   (escalate-first)
#   <!-- r-escalate-measure-rebuttal: <reason up to 200 chars> --> (reasoned walk-back)
# r36-rebuttal: lane WIRE-ESCFIRST
# ============================================================================
_ESCFIRST_TOOL="$AUDITOOOR_DIR/tools/escalate-first-required-check.py"
if [ -f "$_ESCFIRST_TOOL" ]; then
    echo ""
    # PROVE-IMPOSSIBLE-OR-ESCALATE (operator directive 2026-07-02): advisory-first
    # behind the named env AUDITOOOR_ESCALATE_FIRST_STRICT. When set truthy, the
    # gate additionally fail-closes a draft that walks away from a higher tier on
    # a PUNT blocker (single-process / cannot-model / would-require-a-testnet /
    # considered-and-not-claimed) with NO cited PROOF-OF-IMPOSSIBILITY. The tool
    # also self-detects the env; forwarding --strict makes the STRICT path
    # explicit in the pre-submit/audit STRICT invocation.
    _ESCFIRST_STRICT_ARG=""
    case "$(printf '%s' "${AUDITOOOR_ESCALATE_FIRST_STRICT:-}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) _ESCFIRST_STRICT_ARG="--strict" ;;
    esac
    _ESCFIRST_OUT=$(python3 "$_ESCFIRST_TOOL" "$SUB" ${SEVERITY:+--severity "$SEVERITY"} $_ESCFIRST_STRICT_ARG 2>&1)
    _ESCFIRST_RC=$?
    case "$_ESCFIRST_RC" in
        0) echo "  [OK] 127. R-ESCALATE-FIRST-REQUIRED: $_ESCFIRST_OUT" ;;
        1) echo "  [FAIL] 127. R-ESCALATE-FIRST-REQUIRED: $_ESCFIRST_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 127. R-ESCALATE-FIRST-REQUIRED: rc=$_ESCFIRST_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 127. R-ESCALATE-FIRST-REQUIRED: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #141: ESCALATION-WORKFLOW-REQUIRED (companion to #127)
# #127 is a TEXT gate - it accepts a SINGLE agent's *sentence* that the higher
# tier "was attempted". This gate additionally requires, for a finding filed
# BELOW its max reachable in-scope tier, a LOGGED, MULTI-LANE escalation workflow
# in <ws>/.auditooor/escalation_attempts.jsonl (produced by
# tools/escalation-workflow-planner.py): every higher rubric candidate must be
# terminally resolved (escalated-with-poc OR proof-of-impossibility-with-citation)
# by >=2 independent verification lanes. Advisory-first; STRICT under
# AUDITOOOR_ESCALATION_WORKFLOW_STRICT=1 (the tool self-detects the env).
# Override: <!-- escalation-workflow-rebuttal: <reason up to 200 chars> -->
# r36-rebuttal: lane WIRE-ESCALATION-WORKFLOW
# ============================================================================
_ESCWF_TOOL="$AUDITOOOR_DIR/tools/escalation-workflow-required-check.py"
if [ -f "$_ESCWF_TOOL" ]; then
    echo ""
    _ESCWF_OUT=$(python3 "$_ESCWF_TOOL" --draft "$SUB" 2>&1)
    _ESCWF_RC=$?
    case "$_ESCWF_RC" in
        0) case "$_ESCWF_OUT" in
               *fail-*) echo "  [WARN] 141. ESCALATION-WORKFLOW-REQUIRED (advisory): $_ESCWF_OUT"
                        warns=$((warns + 1)) ;;
               *) echo "  [OK] 141. ESCALATION-WORKFLOW-REQUIRED: $_ESCWF_OUT" ;;
           esac ;;
        1) echo "  [FAIL] 141. ESCALATION-WORKFLOW-REQUIRED: $_ESCWF_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 141. ESCALATION-WORKFLOW-REQUIRED: rc=$_ESCWF_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 141. ESCALATION-WORKFLOW-REQUIRED: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #128: HACKENPROOF-POC-NOT-INLINE (HackenProof-only)
# A *.hackenproof-plain.txt MUST NOT inline the full PoC harness source - on
# HackenProof the harness + transcript ship in the attached -poc.zip and the
# .txt PoC section is a concise description that REFERENCES the attachment.
# This check fires ONLY for *.hackenproof-plain.txt drafts; Cantina / Immunefi
# markdown drafts keep inline PoC ("never pointer-only") and are skipped here.
# r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE
# ============================================================================
case "$SUB" in
  *.hackenproof-plain.txt)
    _HP_POC_TOOL="$AUDITOOOR_DIR/tools/hackenproof-poc-not-inline-check.py"
    if [ -f "$_HP_POC_TOOL" ]; then
        echo ""
        _HP_POC_OUT=$(python3 "$_HP_POC_TOOL" "$SUB" 2>&1)
        _HP_POC_RC=$?
        case "$_HP_POC_RC" in
            0) echo "  [OK] 128. HACKENPROOF-POC-NOT-INLINE: $_HP_POC_OUT" ;;
            1) echo "  [FAIL] 128. HACKENPROOF-POC-NOT-INLINE: $_HP_POC_OUT"
               fails=$((fails + 1)) ;;
            *) echo "  [WARN] 128. HACKENPROOF-POC-NOT-INLINE: rc=$_HP_POC_RC; skipping"
               warns=$((warns + 1)) ;;
        esac
    else
        echo "  [WARN] 128. HACKENPROOF-POC-NOT-INLINE: tool not found; skipping"
        warns=$((warns + 1))
    fi
    ;;
esac

# ============================================================================
# Check #129: R77-EXTERNAL-DEP-BEHAVIOR (Rule 77)
# Refuses HIGH+ drafts whose load-bearing / amplification argument makes a
# BEHAVIORAL claim about a THIRD-PARTY dependency's runtime behavior
# (concurrency/batch/async/thread-pool/connection handling) without citing the
# dependency's ACTUAL source (a path under .cargo/registry / vendor /
# node_modules / go/pkg/mod / site-packages + snippet) or an executed test
# transcript against it. Override: <!-- r77-rebuttal: <reason> -->
# Inter-rule note: R76 (Check #125) checks WORKSPACE source-existence of a cited
# code_excerpt; R77 (this check) checks EXTERNAL-dependency runtime BEHAVIOR.
# They compose without overlap.
# Empirical anchor: zebra batch over-claim 2026-06-02 - "one JSON-RPC batch
# launches K concurrent scans" assumed jsonrpsee batch concurrency; the real
# jsonrpsee-server-0.24.10/src/server.rs:1318 processes a batch SEQUENTIALLY.
# The over-claim survived every gate; finding corrected HIGH -> MEDIUM.
# ============================================================================
_R77_TOOL="$AUDITOOOR_DIR/tools/external-dependency-behavior-check.py"
if [ -f "$_R77_TOOL" ]; then
    echo ""
    _R77_OUT=$(python3 "$_R77_TOOL" "$SUB" ${SEVERITY:+--severity "$SEVERITY"} 2>&1)
    _R77_RC=$?
    case "$_R77_RC" in
        0) echo "  [OK] 129. R77-EXTERNAL-DEP-BEHAVIOR: $_R77_OUT" ;;
        1) echo "  [FAIL] 129. R77-EXTERNAL-DEP-BEHAVIOR: $_R77_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 129. R77-EXTERNAL-DEP-BEHAVIOR: rc=$_R77_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 129. R77-EXTERNAL-DEP-BEHAVIOR: tool not found; skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #130: R78-LOAD-BEARING-ASSUMPTION-AUDIT (Rule 78) - UMBRELLA meta-gate
# Refuses HIGH+ drafts that lack a "Load-Bearing Assumption Ledger" enumerating
# each load-bearing assumption + how it is verified, and fails when any ledger
# row is UNVERIFIED (esp. the four out-of-direct-tree classes: external-
# dependency behavior, external-library DEFAULTS, deployment/config, and
# protocol-version / external-chain semantics). Override:
# <!-- r78-rebuttal: <reason> --> (whole gate) or inline per-row
# 'r78-unverified-rebuttal: <reason>'.
# Composition note: R78 enforces the ledger EXISTS + is complete; it does NOT
# re-verify each class. R76 (Check #125) verifies workspace source-existence,
# R77 (Check #129) external-dependency behavior, R42 (Check #89) configured-
# impact trace, R46 (Check #95) trusted-infra. R78 is the upstream enumerator
# that makes those narrow gates' targets visible; they compose without overlap.
# Empirical anchor: zebra batch over-claim 2026-06-02 - the amplification
# rested on TWO unverified assumptions (jsonrpsee batch concurrency + unbounded
# default); neither was written down, so neither was recognised as an
# assumption. The ledger discipline surfaces both at brief time.
# ============================================================================
_R78_TOOL="$AUDITOOOR_DIR/tools/load-bearing-assumption-audit-check.py"
if [ -f "$_R78_TOOL" ]; then
    echo ""
    _R78_OUT=$(python3 "$_R78_TOOL" "$SUB" ${SEVERITY:+--severity "$SEVERITY"} 2>&1)
    _R78_RC=$?
    case "$_R78_RC" in
        0) echo "  [OK] 130. R78-LOAD-BEARING-ASSUMPTION-AUDIT: $_R78_OUT" ;;
        1) echo "  [FAIL] 130. R78-LOAD-BEARING-ASSUMPTION-AUDIT: $_R78_OUT"
           fails=$((fails + 1)) ;;
        *) echo "  [WARN] 130. R78-LOAD-BEARING-ASSUMPTION-AUDIT: rc=$_R78_RC; skipping"
           warns=$((warns + 1)) ;;
    esac
else
    echo "  [WARN] 130. R78-LOAD-BEARING-ASSUMPTION-AUDIT: tool not found; skipping"
    warns=$((warns + 1))
fi

# Check #131: R80-FINDING-EVIDENCE-HONESTY (Rule 80)
#
# Per-draft finding-facing honesty gate. A draft may not cite a harness /
# coverage / engine run as LOAD-BEARING proof evidence unless that evidence is
# real-in-scope-executed + mutation-verified-non-vacuous + non-mock-CUT. This
# is the finding-facing companion to the whole-workspace gate
# tools/audit-honesty-check.py (run at audit-completion). Five sub-principles:
#   R-A real coverage (budget-skipped / vendored units do NOT count as covered)
#   R-B real engine execution (engine-error / no-execution / assert(true) cannot
#       be cited as proof)
#   R-C mutation-verified non-vacuous harness (inject bug -> fails -> restore ->
#       passes)
#   R-D no mock / reimplementation cited as in-scope proof (CUT must be real src/)
#   R-E in-scope denominator (coverage over in-scope, not vendored deps)
#
# Trigger: drafts that cite harness / fuzz / symbolic / invariant / coverage /
# engine runs as load-bearing evidence. Prose-only drafts pass with
# pass-no-harness-evidence-cited (other gates cover them).
# Tool: tools/finding-evidence-honesty-check.py <draft> --workspace <ws>
#       --strict --json
# Verdicts: pass-out-of-scope, pass-no-harness-evidence-cited,
#   pass-real-in-scope-proof, ok-rebuttal, fail-hollow-engine-cited,
#   fail-non-mutation-verified, fail-mock-cut-cited, error
# Override: visible `r80-rebuttal: <reason>` or
#           `<!-- r80-rebuttal: <reason up to 200 chars> -->`.
# Ordering note: fires AFTER Check #130 R78 (load-bearing assumption audit).
_R80_TOOL="$AUDITOOOR_DIR/tools/finding-evidence-honesty-check.py"
if [ -f "$_R80_TOOL" ]; then
    echo ""
    _R80_TMP=$(mktemp 2>/dev/null || echo "/tmp/r80_honesty_$$.json")
    _R80_ERR=$(mktemp 2>/dev/null || echo "/tmp/r80_honesty_$$.err")
    _R80_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
    [ -n "$SEVERITY_ARG" ] && _R80_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
    python3 "$_R80_TOOL" "${_R80_ARGS[@]}" > "$_R80_TMP" 2> "$_R80_ERR"
    _R80_RC=$?

    _R80_SUMMARY=$(
        python3 - "$_R80_TMP" "$_R80_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", d.get("summary","no detail")))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )

    if [ "$_R80_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R80_TMP"; then
            echo "  ✅ 131. R80-FINDING-EVIDENCE-HONESTY rebuttal accepted: $_R80_SUMMARY"
        else
            echo "  ✅ 131. R80-FINDING-EVIDENCE-HONESTY: $_R80_SUMMARY"
        fi
    elif [ "$_R80_RC" -eq 1 ]; then
        echo "  ❌ 131. R80-FINDING-EVIDENCE-HONESTY blocked:"
        echo "       $_R80_SUMMARY"
        echo "       A cited harness/coverage/engine run is not real-in-scope-executed,"
        echo "       not mutation-verified, or stands on a mock/reimplementation CUT."
        echo "       Override: r80-rebuttal: <reason up to 200 chars>"
        echo "       or <!-- r80-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  131. R80-FINDING-EVIDENCE-HONESTY error: $_R80_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R80_TMP" "$_R80_ERR"
else
    echo "  ⚠️  131. R80-FINDING-EVIDENCE-HONESTY: tool not found ($_R80_TOOL); skipping"
    warns=$((warns + 1))
fi

# Check #132: R82-IMPACT-RECOVERY-FALSIFICATION (Rule 82)
# The missing POST-impact axis: for a Medium+ permanent loss/freeze/theft/stuck-state
# claim against victim V, the draft must prove V cannot RECOVER after the impact lands -
# by driving each of V's in-protocol recovery entrypoints to FAILURE, or source-tracing
# each unreachable. A live un-falsified recovery path makes the "permanent loss" claim
# false (V was made whole). Inverse of R57's defender table.
# Tool: tools/impact-recovery-falsification-check.py <draft> --workspace <ws> --strict --json
# Verdicts: pass-out-of-scope, pass-not-permanent-impact-claim,
#   pass-recovery-enumeration-complete, pass-out-of-protocol-recovery-only,
#   pass-claim-narrowed, ok-rebuttal, fail-no-recovery-enumeration-section,
#   fail-no-impact-lands-citation, fail-recovery-row-without-citation,
#   fail-recovery-path-survives-claim-false, fail-recovery-path-not-enumerated,
#   fail-recovery-not-falsified-in-poc, fail-ruling-without-source-citation, error
# Override: visible `r82-rebuttal: <reason>` or `<!-- r82-rebuttal: <reason up to 200 chars> -->`.
# Ordering: fires LAST in the impact/defense family (R24->R25->R29->R40->R44->R57->R82),
# because it is the only gate that presupposes the impact landed.
_R82_TOOL="$AUDITOOOR_DIR/tools/impact-recovery-falsification-check.py"
if [ -f "$_R82_TOOL" ]; then
    echo ""
    _R82_TMP=$(mktemp 2>/dev/null || echo "/tmp/r82_recovery_$$.json")
    _R82_ERR=$(mktemp 2>/dev/null || echo "/tmp/r82_recovery_$$.err")
    _R82_ARGS=("$SUB" "--workspace" "$WS_DIR" "--strict" "--json")
    [ -n "$SEVERITY_ARG" ] && _R82_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
    python3 "$_R82_TOOL" "${_R82_ARGS[@]}" > "$_R82_TMP" 2> "$_R82_ERR"
    _R82_RC=$?
    _R82_SUMMARY=$(
        python3 - "$_R82_TMP" "$_R82_ERR" <<'PY'
import sys, json
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get("verdict","?") + ": " + d.get("reason", "no detail"))
except Exception:
    err = open(sys.argv[2]).read().strip()[:120] if len(sys.argv) > 2 else ""
    print("parse-error" + (": " + err if err else ""))
PY
    )
    if [ "$_R82_RC" -eq 0 ]; then
        if grep -q '"verdict": "ok-rebuttal"' "$_R82_TMP"; then
            echo "  ✅ 132. R82-IMPACT-RECOVERY-FALSIFICATION rebuttal accepted: $_R82_SUMMARY"
        else
            echo "  ✅ 132. R82-IMPACT-RECOVERY-FALSIFICATION: $_R82_SUMMARY"
        fi
    elif [ "$_R82_RC" -eq 1 ]; then
        echo "  ❌ 132. R82-IMPACT-RECOVERY-FALSIFICATION blocked:"
        echo "       $_R82_SUMMARY"
        echo "       A Medium+ permanent-loss claim must falsify the victim's in-protocol"
        echo "       recovery (## Victim Recovery Enumeration). A live un-falsified recovery"
        echo "       path makes the permanent claim false."
        echo "       Override: r82-rebuttal: <reason up to 200 chars>"
        fails=$((fails + 1))
    else
        echo "  ⚠️  132. R82-IMPACT-RECOVERY-FALSIFICATION error: $_R82_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R82_TMP" "$_R82_ERR"
else
    echo "  ⚠️  132. R82-IMPACT-RECOVERY-FALSIFICATION: tool not found ($_R82_TOOL); skipping"
    warns=$((warns + 1))
fi

# Check #133: SELF-DEAD-END-RECALL (block re-litigating a claim WE already disproved)
# R47 blocks externally-acknowledged claims; L31 blocks our own filed dupes; this blocks
# an impact claim our own source-verification (SV-class) already disproved at the same pin
# (anchor: Spark LEAD-1, where SV4 already proved receiver self-recovery yet v8..v12 re-litigated).
# Tool: tools/self-dead-end-recall-check.py <draft> --workspace <ws> --strict --json
# Verdicts: pass-no-self-dead-ends, pass-no-match, pass-extension-distinct, ok-rebuttal,
#   fail-blocked-self-dead-end, error. Override: `self-dead-end-rebuttal: <reason>`.
_SDE_TOOL="$AUDITOOOR_DIR/tools/self-dead-end-recall-check.py"
if [ -f "$_SDE_TOOL" ]; then
    echo ""
    _SDE_TMP=$(mktemp 2>/dev/null || echo "/tmp/sde_$$.json")
    python3 "$_SDE_TOOL" "$SUB" --workspace "$WS_DIR" --strict --json > "$_SDE_TMP" 2>/dev/null
    _SDE_RC=$?
    _SDE_SUMMARY=$(python3 - "$_SDE_TMP" <<'PY'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    print(d.get("verdict","?") + ": " + d.get("reason","no detail"))
except Exception:
    print("parse-error")
PY
    )
    if [ "$_SDE_RC" -eq 0 ]; then
        echo "  ✅ 133. SELF-DEAD-END-RECALL: $_SDE_SUMMARY"
    elif [ "$_SDE_RC" -eq 1 ]; then
        echo "  ❌ 133. SELF-DEAD-END-RECALL blocked:"
        echo "       $_SDE_SUMMARY"
        echo "       This impact claim was already disproved by our own source-verification lane."
        echo "       Override: self-dead-end-rebuttal: <reason up to 200 chars>"
        fails=$((fails + 1))
    else
        echo "  ⚠️  133. SELF-DEAD-END-RECALL error: $_SDE_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_SDE_TMP"
else
    echo "  ⚠️  133. SELF-DEAD-END-RECALL: tool not found ($_SDE_TOOL); skipping"
    warns=$((warns + 1))
fi

# Check #134: R83-HARDENING-VS-VULNERABILITY (Rule 83)
# For HIGH+ resource/availability/cap/rate-limit/keying findings, force the draft to
# affirmatively establish P1 (default-config reachability), P2 (survives every defense),
# P3 (non-self victim), P4 (crosses harm threshold). A real defect failing >=1 of P1-P4 is
# a correctness/hardening bug, not a vulnerability. Anchors: zebra GHSA-x3g2 (self-throttle
# + below-threshold) and GHSA-4wjg (blocked by default max_connections_per_ip, unit-test seam).
# Tool: tools/hardening-vs-vulnerability-check.py <draft> --severity <sev> --json
# Verdicts: pass-out-of-scope/pass-not-resource-class/pass-vulnerability-established/ok-rebuttal,
#   fail-self-impact-only/fail-blocked-by-default-defense/fail-below-threshold/
#   fail-no-classification-section. Override: `r83-rebuttal: <reason up to 200 chars>`.
_R83_TOOL="$AUDITOOOR_DIR/tools/hardening-vs-vulnerability-check.py"
if [ -f "$_R83_TOOL" ]; then
    echo ""
    _R83_TMP=$(mktemp 2>/dev/null || echo "/tmp/r83_$$.json")
    python3 "$_R83_TOOL" "$SUB" --severity "${SEVERITY:-auto}" --json > "$_R83_TMP" 2>/dev/null
    _R83_RC=$?
    _R83_SUMMARY=$(python3 - "$_R83_TMP" <<'PYJSON'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    print(d.get("verdict","?") + ": " + d.get("reason","no detail"))
except Exception:
    print("parse-error")
PYJSON
    )
    if [ "$_R83_RC" -eq 0 ]; then
        echo "  ✅ 134. R83-HARDENING-VS-VULNERABILITY: $_R83_SUMMARY"
    elif [ "$_R83_RC" -eq 1 ]; then
        echo "  ❌ 134. R83-HARDENING-VS-VULNERABILITY blocked:"
        echo "       $_R83_SUMMARY"
        echo "       A resource/cap defect is only a vulnerability if it is reachable on default"
        echo "       config (P1), survives every defense (P2), harms a non-self victim (P3), and"
        echo "       crosses the harm threshold (P4). Establish all four or drop as hardening."
        echo "       Override: r83-rebuttal: <reason up to 200 chars>"
        fails=$((fails + 1))
    else
        echo "  ⚠️  134. R83-HARDENING-VS-VULNERABILITY error: $_R83_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_R83_TMP"
else
    echo "  ⚠️  134. R83-HARDENING-VS-VULNERABILITY: tool not found ($_R83_TOOL); skipping"
    warns=$((warns + 1))
fi

# Check #135: EXPLOITABILITY-LEDGER (universal 5-axis gate)
# Every HIGH+ finding must affirmatively establish all five universal axes
# (REACH / TRAVERSE / IMPACT / ORIGINAL / PROVEN) via an '## Exploitability Ledger'
# section with cited evidence. A finding is fileable only when the ledger is
# present and all axes are established. Verdicts:
#   pass-fileable-vulnerability / pass-out-of-scope / ok-rebuttal
#   fail-no-ledger / fail-axis-unestablished
# Tool: tools/exploitability-ledger.py <draft> --severity <sev> --json
# Override: `exploitability-ledger-rebuttal: <reason up to 200 chars>`
_EL_TOOL="$AUDITOOOR_DIR/tools/exploitability-ledger.py"
if [ -f "$_EL_TOOL" ]; then
    echo ""
    _EL_TMP=$(mktemp 2>/dev/null || echo "/tmp/el_$$.json")
    python3 "$_EL_TOOL" "$SUB" --severity "${SEVERITY:-auto}" --json > "$_EL_TMP" 2>/dev/null
    _EL_RC=$?
    _EL_SUMMARY=$(python3 - "$_EL_TMP" <<'PYJSON'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    print(d.get("verdict","?") + ": " + d.get("reason","no detail"))
except Exception:
    print("parse-error")
PYJSON
    )
    if [ "$_EL_RC" -eq 0 ]; then
        echo "  ✅ 135. EXPLOITABILITY-LEDGER: $_EL_SUMMARY"
    elif [ "$_EL_RC" -eq 1 ]; then
        echo "  ❌ 135. EXPLOITABILITY-LEDGER blocked:"
        echo "       $_EL_SUMMARY"
        echo "       Add an '## Exploitability Ledger' section and affirmatively establish"
        echo "       REACH / TRAVERSE / IMPACT / ORIGINAL / PROVEN with cited evidence."
        echo "       Override: exploitability-ledger-rebuttal: <reason up to 200 chars>"
        fails=$((fails + 1))
    else
        echo "  ⚠️  135. EXPLOITABILITY-LEDGER error: $_EL_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_EL_TMP"
else
    echo "  ⚠️  135. EXPLOITABILITY-LEDGER: tool not found ($_EL_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #136: DATAFLOW-ENFORCEMENT (wiring 49d - DefUsePath accountability)
# Makes a HIGH+ finding ACCOUNTABLE to the data-flow slice. When the draft's
# impact maps onto an UNGUARDED value-flow path (by file:line) in
# <ws>/.auditooor/dataflow_paths.jsonl, the paste MUST cite a real DefUsePath
# id (dfp-/svp-/sdp-####), a closure verdict, or carry an honest walk-back
# marker. Fail-closed ONLY for path-relevant HIGH+; everything else PASSES:
#   - no slice in workspace          -> pass-no-slice (no-op)
#   - severity below High            -> pass-below-high
#   - prose-only / non-path finding  -> pass-not-path-relevant
#   - cites a DefUsePath / closure   -> pass-cited
#   - <!-- dataflow-rebuttal: ... -->-> ok-rebuttal
# Companion: the VICE-VERSA on-demand backward slice
#   tools/dataflow-slice.py --from-sink <file:line>  (PULL a slice for one sink).
# Tool: tools/dataflow-enforcement-check.py <draft> --workspace <ws>
#       --severity <sev> --json
# Override: <!-- dataflow-rebuttal: <reason up to 200 chars> -->
# ============================================================================
_DF_ENF_TOOL="$AUDITOOOR_DIR/tools/dataflow-enforcement-check.py"
if [ -f "$_DF_ENF_TOOL" ]; then
    echo ""
    _DF_ENF_TMP=$(mktemp 2>/dev/null || echo "/tmp/df_enf_$$.json")
    _DF_ENF_ARGS=("$SUB" "--json")
    [ -n "$WS_DIR" ] && _DF_ENF_ARGS+=("--workspace" "$WS_DIR")
    [ -n "$SEVERITY_ARG" ] && _DF_ENF_ARGS+=("--severity" "$SEVERITY_ARG_LOWER")
    python3 "$_DF_ENF_TOOL" "${_DF_ENF_ARGS[@]}" > "$_DF_ENF_TMP" 2>/dev/null
    _DF_ENF_RC=$?
    _DF_ENF_SUMMARY=$(python3 - "$_DF_ENF_TMP" <<'PYJSON'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    print(d.get("verdict","?") + ": " + d.get("reason","no detail"))
except Exception:
    print("parse-error")
PYJSON
    )
    if [ "$_DF_ENF_RC" -eq 0 ]; then
        echo "  ✅ 136. DATAFLOW-ENFORCEMENT: $_DF_ENF_SUMMARY"
    elif [ "$_DF_ENF_RC" -eq 1 ]; then
        echo "  ❌ 136. DATAFLOW-ENFORCEMENT blocked:"
        echo "       $_DF_ENF_SUMMARY"
        echo "       Cite the DefUsePath id (dfp-/svp-/sdp-####) the finding lands on,"
        echo "       a closure verdict, or pull a targeted slice:"
        echo "         python3 tools/dataflow-slice.py --workspace <ws> --from-sink <file:line>"
        echo "       Override: <!-- dataflow-rebuttal: <reason up to 200 chars> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  136. DATAFLOW-ENFORCEMENT error: $_DF_ENF_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_DF_ENF_TMP"
else
    echo "  ⚠️  136. DATAFLOW-ENFORCEMENT: tool not found ($_DF_ENF_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Check #137: IMPACT-CHARACTERIZATION-COMPLETENESS
# Keyed on the CLAIMED impact class (via severity-calibration-gate.classify_axes),
# require that class's tier-deciding axes (read at runtime from
# audit/corpus_tags/impact_hunting_methodology.yaml) to be ANSWERED in the draft's
# `## Impact Characterization` section, and assert CLAIMED_TIER <= EVIDENCE_TIER
# derived from DELEGATED verdicts (R82 recovery, in-process evidence-class,
# panic-context panic-vs-slowness, R24 self-impact). Additive-only: never passes
# where a delegate fails. Closes the gap the corpus itself flagged (temp-freeze
# existing_tooling_coverage: R82 fires only for PERMANENT, never the inverse
# confirm-recovery for temporary).
# ADVISORY-FIRST: absent AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT the tool returns
# rc=0 (computes + prints only). Registered AFTER the delegated checks (#132 R82,
# in-process, panic-context) so their standalone verdicts are already computed.
# Tool: tools/impact-characterization-completeness-check.py <draft> --workspace <ws>
#       --poc-dir <dir> --severity <sev> --json
# Override (net-new axes only): <!-- impact-characterization-rebuttal: <reason> -->
# ============================================================================
_ICC_TOOL="$AUDITOOOR_DIR/tools/impact-characterization-completeness-check.py"
if [ -f "$_ICC_TOOL" ]; then
    echo ""
    _ICC_TMP=$(mktemp 2>/dev/null || echo "/tmp/icc_$$.json")
    _ICC_ARGS=("$SUB" "--json")
    [ -n "$WS_DIR" ] && _ICC_ARGS+=("--workspace" "$WS_DIR")
    [ -n "${POC_DIR:-}" ] && _ICC_ARGS+=("--poc-dir" "$POC_DIR")
    [ -n "$SEVERITY_ARG" ] && _ICC_ARGS+=("--severity" "$SEVERITY_ARG")
    # Strict only when the named env is set (advisory-first).
    case "$(printf '%s' "${AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT:-}" | tr 'A-Z' 'a-z')" in
        1|true|yes|on) _ICC_ARGS+=("--strict") ;;
    esac
    python3 "$_ICC_TOOL" "${_ICC_ARGS[@]}" > "$_ICC_TMP" 2>/dev/null
    _ICC_RC=$?
    _ICC_SUMMARY=$(python3 - "$_ICC_TMP" <<'PYJSON'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    fails = d.get("failures", [])
    print(d.get("verdict","?") + " (" + str(len(fails)) + " axis issue(s))")
except Exception:
    print("parse-error")
PYJSON
    )
    if [ "$_ICC_RC" -eq 0 ]; then
        echo "  ✅ 137. IMPACT-CHARACTERIZATION-COMPLETENESS: $_ICC_SUMMARY"
    elif [ "$_ICC_RC" -eq 1 ]; then
        echo "  ❌ 137. IMPACT-CHARACTERIZATION-COMPLETENESS blocked:"
        echo "       $_ICC_SUMMARY"
        echo "       Fill the ## Impact Characterization axes (stub:"
        echo "         python3 tools/impact-characterization-completeness-check.py --emit-stub <impact_id>)"
        echo "       Override net-new axes: <!-- impact-characterization-rebuttal: <reason> -->"
        fails=$((fails + 1))
    else
        echo "  ⚠️  137. IMPACT-CHARACTERIZATION-COMPLETENESS error: $_ICC_SUMMARY"
        warns=$((warns + 1))
    fi
    rm -f "$_ICC_TMP"
else
    echo "  ⚠️  137. IMPACT-CHARACTERIZATION-COMPLETENESS: tool not found ($_ICC_TOOL); skipping"
    warns=$((warns + 1))
fi

# ============================================================================
# Checks #138-140: previously-ORPHANED paste-ready guards (enforcement-gap audit
# 2026-07-03). Each was built but had ZERO callers on the submit path, so a drifted
# PoC / ambiguous-selector PoC / anomaly-laundered down-tier reached paste-ready
# unchecked. Wired ADVISORY-FIRST: each runs and WARNs, and hard-blocks ONLY under
# its own named strict env (default OFF -> byte-compatible; promote per-env).
# ============================================================================
# --- Check #138: POC-FRESHNESS-RECHECK (drifted paste-ready/filed PoC vs current src)
_PFR_TOOL="$AUDITOOOR_DIR/tools/poc-freshness-recheck.py"
if [ -f "$_PFR_TOOL" ] && [ -n "$WS_DIR" ]; then
    echo ""
    python3 "$_PFR_TOOL" --workspace "$WS_DIR" --json > /dev/null 2>&1; _PFR_RC=$?
    case "$(printf '%s' "${AUDITOOOR_POC_FRESHNESS_STRICT:-}" | tr 'A-Z' 'a-z')" in 1|true|yes|on) _PFR_STRICT=1 ;; *) _PFR_STRICT=0 ;; esac
    if [ "$_PFR_RC" -eq 0 ]; then
        echo "  ✅ 138. POC-FRESHNESS-RECHECK: paste-ready/filed PoCs fresh vs current src"
    elif [ "$_PFR_STRICT" -eq 1 ]; then
        echo "  ❌ 138. POC-FRESHNESS-RECHECK blocked: a PoC drifted vs current src (re-run: python3 tools/poc-freshness-recheck.py --workspace $WS_DIR)"
        fails=$((fails + 1))
    else
        echo "  ⚠️  138. POC-FRESHNESS-RECHECK: a PoC may have drifted vs current src (advisory; AUDITOOOR_POC_FRESHNESS_STRICT=1 to hard-fail)"
        warns=$((warns + 1))
    fi
fi
# --- Check #139: POC-REVERT-SELECTOR-SOUNDNESS (ambiguous custom-error vm.expectRevert(X.selector))
_PRS_TOOL="$AUDITOOOR_DIR/tools/poc-revert-selector-soundness-check.py"
if [ -f "$_PRS_TOOL" ]; then
    echo ""
    _PRS_TARGET="${POC_DIR:-$SUB}"
    _PRS_ARGS=("$_PRS_TARGET" "--json")
    case "$(printf '%s' "${AUDITOOOR_POC_REVERT_SELECTOR_STRICT:-}" | tr 'A-Z' 'a-z')" in 1|true|yes|on) _PRS_ARGS+=("--strict"); _PRS_STRICT=1 ;; *) _PRS_STRICT=0 ;; esac
    python3 "$_PRS_TOOL" "${_PRS_ARGS[@]}" > /dev/null 2>&1; _PRS_RC=$?
    if [ "$_PRS_RC" -eq 0 ]; then
        echo "  ✅ 139. POC-REVERT-SELECTOR-SOUNDNESS: no ambiguous custom-error selector"
    elif [ "$_PRS_STRICT" -eq 1 ]; then
        echo "  ❌ 139. POC-REVERT-SELECTOR-SOUNDNESS blocked: vm.expectRevert(X.selector) may pass for the WRONG reason (ambiguous 4-byte selector)"
        fails=$((fails + 1))
    else
        echo "  ⚠️  139. POC-REVERT-SELECTOR-SOUNDNESS: possible ambiguous revert selector (advisory; AUDITOOOR_POC_REVERT_SELECTOR_STRICT=1 to hard-fail)"
        warns=$((warns + 1))
    fi
fi
# --- Check #140: ANOMALY-ESCALATION-GUARD (down-tier/not-a-bug resting on an UNEXPLAINED anomaly)
_AEG_TOOL="$AUDITOOOR_DIR/tools/anomaly-escalation-guard.py"
if [ -f "$_AEG_TOOL" ]; then
    echo ""
    python3 "$_AEG_TOOL" --finding "$SUB" --json > /dev/null 2>&1; _AEG_RC=$?
    case "$(printf '%s' "${AUDITOOOR_ANOMALY_ESCALATION_STRICT:-}" | tr 'A-Z' 'a-z')" in 1|true|yes|on) _AEG_STRICT=1 ;; *) _AEG_STRICT=0 ;; esac
    if [ "$_AEG_RC" -eq 0 ]; then
        echo "  ✅ 140. ANOMALY-ESCALATION-GUARD: no down-tier resting on an unexplained anomaly"
    elif [ "$_AEG_STRICT" -eq 1 ]; then
        echo "  ❌ 140. ANOMALY-ESCALATION-GUARD blocked: a not-a-bug/down-tier verdict rests on an UNEXPLAINED anomaly (explain it or escalate)"
        fails=$((fails + 1))
    else
        echo "  ⚠️  140. ANOMALY-ESCALATION-GUARD: verdict may rest on an unexplained anomaly (advisory; AUDITOOOR_ANOMALY_ESCALATION_STRICT=1 to hard-fail)"
        warns=$((warns + 1))
    fi
fi

# --- Check #143: POC-TRANSCRIPT-RECEIPTS (a claimed PoC PASS must carry the run
# transcript + a what-it-proves summary; 2026-07-05 operator-caught gap - #4c checks the
# PoC *code* is inline, #10 runs a forge test, but nothing verified a claimed "PoC PASSES"
# actually embeds the executed command + captured output + the assertion it proves).
_PTC_TOOL="$AUDITOOOR_DIR/tools/poc-transcript-check.py"
if [ -f "$_PTC_TOOL" ]; then
    echo ""
    _PTC_OUT=$(python3 "$_PTC_TOOL" "$SUB" 2>&1); _PTC_RC=$?
    case "$_PTC_RC" in
        0) echo "  ✅ 143. POC-TRANSCRIPT-RECEIPTS: $_PTC_OUT" ;;
        1) echo "  ❌ 143. POC-TRANSCRIPT-RECEIPTS blocked:"
           echo "$_PTC_OUT" | sed 's/^/       /'
           fails=$((fails + 1)) ;;
        *) echo "  ⚠️  143. POC-TRANSCRIPT-RECEIPTS error rc=$_PTC_RC: $_PTC_OUT"
           warns=$((warns + 1)) ;;
    esac
fi

# ---------------------------------------------------------------------------
# Check #144 SUBMISSION-CLARITY (advisory): does the finding READ clearly to a
# human triager, not just pass the impact/scope/severity gates? Enforces a lead
# `## Summary`, a named `## What the PoC proves`, and no HTML-comment wall before
# the first human sentence. Motivated 2026-07-06: our SEI evmrpc-filter Medium
# passed every correctness gate yet a duplicate report of the SAME bug read more
# clearly (it led with the bug + a measured-impact narrative). Advisory only:
# bumps warns, never fails - a correct finding is never blocked on presentation.
# ---------------------------------------------------------------------------
_SCC_TOOL="$AUDITOOOR_DIR/tools/submission-clarity-check.py"
if [ -f "$_SCC_TOOL" ]; then
    echo ""
    _SCC_OUT=$(python3 "$_SCC_TOOL" "$SUB" 2>&1); _SCC_RC=$?
    if echo "$_SCC_OUT" | grep -q 'pass-clarity'; then
        echo "  ✅ 144. SUBMISSION-CLARITY: reads clearly (lead Summary + what-PoC-proves + narrative-first)"
    elif echo "$_SCC_OUT" | grep -qE 'warn-clarity-issues|fail-'; then
        echo "  ⚠️  144. SUBMISSION-CLARITY (advisory) — sharpen presentation for the triager:"
        echo "$_SCC_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    else
        echo "  ⚠️  144. SUBMISSION-CLARITY: could not evaluate (rc=$_SCC_RC): $_SCC_OUT"
    fi
fi

# ---------------------------------------------------------------------------
# Check #145 PROGRAM-RULES: enforce the bounty program's own PoC/scope rules
# (<ws>/.auditooor/program_rules.json). Motivated 2026-07-07: a Strata finding
# was drafted to High while its impact PROVABLY required Junior NAV -> 0
# (< ONE_ASSET) - exactly the program's "closed as invalid" condition - which no
# generic gate knew. HARD FAIL if the draft's impact text states a program-
# excluded condition or its PoC seeds an entity below the floor; WARN if a High+
# finding does not affirmatively ATTEST it meets each PoC rule (>= min seed AND
# no dependence on the floor). N/A when the workspace has no program_rules.json.
# ---------------------------------------------------------------------------
_PRC_TOOL="$AUDITOOOR_DIR/tools/program-rules-check.py"
if [ -f "$_PRC_TOOL" ] && [ -n "$WS_DIR" ]; then
    echo ""
    _PRC_OUT=$(python3 "$_PRC_TOOL" --workspace "$WS_DIR" --draft "$SUB" 2>&1); _PRC_RC=$?
    if echo "$_PRC_OUT" | grep -q 'program-rules-check: n/a'; then
        : # no program_rules.json for this workspace -> silent N/A
    elif echo "$_PRC_OUT" | grep -q 'program-rules-check: fail'; then
        echo "  ❌ 145. PROGRAM-RULES blocked: finding violates a program PoC/scope rule (impact depends on an excluded condition, or PoC seeds below the floor):"
        echo "$_PRC_OUT" | sed 's/^/       /'
        fails=$((fails + 1))
    elif echo "$_PRC_OUT" | grep -q 'program-rules-check: warn'; then
        echo "  ⚠️  145. PROGRAM-RULES (advisory) — affirm PoC-requirements compliance before filing:"
        echo "$_PRC_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    else
        echo "  ✅ 145. PROGRAM-RULES: finding attests compliance with the program PoC/scope rules"
    fi
fi

# ---------------------------------------------------------------------------
# Check #146 DISPOSITION-RATIONALE: every _killed/ and _oos_rejected/ disposed
# finding must carry a machine-recorded WHY (verdict + rule + proof). Motivated
# 2026-07-07: a Strata finding was moved to _killed/ with NO citable rationale on
# disk, so "why wasn't this filed?" could not be answered from artifacts. This
# WORKSPACE sweep makes the rationale mandatory so every kill/OOS is self-
# documenting. WARN by default; hard-fail under AUDITOOOR_L37_STRICT.
# ---------------------------------------------------------------------------
_DRC_TOOL="$AUDITOOOR_DIR/tools/disposition-rationale-check.py"
if [ -f "$_DRC_TOOL" ] && [ -n "$WS_DIR" ]; then
    echo ""
    _DRC_OUT=$(python3 "$_DRC_TOOL" --workspace "$WS_DIR" 2>&1); _DRC_RC=$?
    if echo "$_DRC_OUT" | grep -q 'fail-disposition-missing-rationale'; then
        echo "  ❌ 146. DISPOSITION-RATIONALE blocked: a _killed/ or _oos_rejected/ finding has NO machine-recorded WHY (verdict+rule+proof):"
        echo "$_DRC_OUT" | sed 's/^/       /'
        echo "       Write _KILL_RATIONALE.json (_killed) or _OOS_REJECTION.json (_oos_rejected) with verdict+rule+proof, or add <!-- disposition-rationale-rebuttal: <reason> --> to the finding md."
        fails=$((fails + 1))
    elif echo "$_DRC_OUT" | grep -q 'warn-disposition-missing-rationale'; then
        echo "  ⚠️  146. DISPOSITION-RATIONALE (advisory) — a disposed finding lacks a citable WHY:"
        echo "$_DRC_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    elif echo "$_DRC_OUT" | grep -q 'pass-disposition-rationale'; then
        echo "  ✅ 146. DISPOSITION-RATIONALE: every disposed finding carries a machine-recorded rationale"
    fi
fi

# ---------------------------------------------------------------------------
# Check #146a DISPOSITION-SOUNDNESS (E6): a NEGATIVE disposition killed on a GUARD
# or PRECONDITION basis must cite a file:line at the guard/consumer site; a bare
# "unreachable in practice" is unfalsifiable. This arm shipped in
# disposition-rationale-check.py but was never wired here (orphan) - wiring it now.
# Advisory-first + byte-compatible: hard-fail ONLY under the arm's own
# AUDITOOOR_DISPOSITION_SOUNDNESS_STRICT. E6's _e6_strict() also honours
# AUDITOOOR_L37_STRICT, so we NEUTRALISE L37 for this invocation (L37 runs strict-
# by-default in the pipeline; coupling would retro-red previously-passing audits).
# ---------------------------------------------------------------------------
if [ -f "$_DRC_TOOL" ] && [ -n "$WS_DIR" ]; then
    _DSND_OUT=$(AUDITOOOR_L37_STRICT= python3 "$_DRC_TOOL" --workspace "$WS_DIR" --soundness 2>&1); _DSND_RC=$?
    if echo "$_DSND_OUT" | grep -q 'fail-disposition-unsound'; then
        echo ""
        echo "  ❌ 146a. DISPOSITION-SOUNDNESS blocked: a guard/precondition kill lacks a file:line at the guard/consumer site (unfalsifiable):"
        echo "$_DSND_OUT" | sed 's/^/       /'
        echo "       Cite the guard/consumer file:line in the kill proof, or add <!-- disposition-soundness-rebuttal: <reason> --> to the finding md."
        fails=$((fails + 1))
    elif echo "$_DSND_OUT" | grep -q 'warn-disposition-unsound'; then
        echo ""
        echo "  ⚠️  146a. DISPOSITION-SOUNDNESS (advisory) - a guard/precondition kill lacks a guard-site file:line (AUDITOOOR_DISPOSITION_SOUNDNESS_STRICT=1 to enforce):"
        echo "$_DSND_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    elif echo "$_DSND_OUT" | grep -q 'pass-disposition-soundness'; then
        echo "  ✅ 146a. DISPOSITION-SOUNDNESS: every guard/precondition kill cites a guard-site file:line"
    fi
fi

# ---------------------------------------------------------------------------
# Check #146b DISPOSITION-PROPERTY-ALIGNMENT (E7): for every NEGATIVE FALSIFICATION/
# mechanism kill on a severity-eligible finding, the property the kill REFUTES must
# be the SAME property the finding CLAIMS. A kill that soundly disproves property X
# while the finding claims a distinct property Y does NOT refute the finding.
# Motivated by the nuva swapout mis-kill: a prior falsification refuted
# "processPendingSwapOuts is capped at MaxSwapOutBatchSize=100 (bounded)" while the
# real Critical is "paused entries BYPASS the cap => unbounded permanent chain-halt"
# - a distinct property; the wrong-property refutation silently buried a FILED
# Critical. NEITHER #146 (field-non-empty) nor #146a (guard-site file:line) catches
# a wrong-property refutation. Advisory-first, NO-AUTO-CREDIT (verdict=needs-review);
# hard-fail under the arm's own AUDITOOOR_DISPOSITION_PROPERTY_ALIGN_STRICT /
# AUDITOOOR_KILL_ANCHOR_SOUNDNESS OR the global AUDITOOOR_L37_STRICT (R5 E7 GRADUATED
# to the L37 umbrella 2026-07-10, fleet-validated real-fleet-FP-0; the mis-kill now
# retro-reds a strict-pipeline audit that buried a distinct-property finding).
# ---------------------------------------------------------------------------
if [ -f "$_DRC_TOOL" ] && [ -n "$WS_DIR" ]; then
    _DPAL_OUT=$(python3 "$_DRC_TOOL" --workspace "$WS_DIR" --property-align 2>&1); _DPAL_RC=$?
    if echo "$_DPAL_OUT" | grep -q 'fail-disposition-property-misaligned'; then
        echo ""
        echo "  ❌ 146b. DISPOSITION-PROPERTY-ALIGNMENT blocked: a kill refutes a DIFFERENT property than the finding claims (mismatched-hypothesis mis-kill):"
        echo "$_DPAL_OUT" | sed 's/^/       /'
        echo "       Refute the property the finding actually claims, or add <!-- disposition-property-alignment-rebuttal: <why the X-refutation disposes Y> --> to the finding md."
        fails=$((fails + 1))
    elif echo "$_DPAL_OUT" | grep -q 'warn-disposition-property-misaligned'; then
        echo ""
        echo "  ⚠️  146b. DISPOSITION-PROPERTY-ALIGNMENT (advisory) - a kill may refute a different property than the finding claims (AUDITOOOR_DISPOSITION_PROPERTY_ALIGN_STRICT=1 or AUDITOOOR_L37_STRICT=1 to enforce):"
        echo "$_DPAL_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    elif echo "$_DPAL_OUT" | grep -q 'pass-disposition-property-align'; then
        echo "  ✅ 146b. DISPOSITION-PROPERTY-ALIGNMENT: every kill refutes the property its finding claims"
    fi
fi

# ---------------------------------------------------------------------------
# Check #146c DISPOSITION-REFRAME-SOUNDNESS (GEN-5A/5B/5C/5D): a KILL / OOS-rejection
# that DOWNGRADES a confirmed primitive by REFRAMING its impact (griefing/DoS-only,
# unreachable-by-a-deployment-constant, mathematically-impossible-single-step, or
# trusted-actor-only) must carry the reframe's specific SOUNDNESS PROOF. If the
# reframe is asserted WITHOUT its required proof, the disposition is UNSOUND -> a
# needs-fuzz REOPEN row. Net-new plane vs #146 (WHY-exists), #146a (guard-site
# file:line) and #146b (claimed-vs-refuted alignment): here each of the four named
# impact-downgrade reframes must discharge its own soundness burden. Advisory-first
# (WARN); hard-fail under AUDITOOOR_DISPOSITION_REFRAME_STRICT or AUDITOOOR_L37_STRICT.
# Rebuttal marker: <!-- disposition-reframe-rebuttal: <reason> -->.
# ---------------------------------------------------------------------------
_DRSC_TOOL="$AUDITOOOR_DIR/tools/disposition-reframe-soundness-check.py"
if [ -f "$_DRSC_TOOL" ] && [ -n "$WS_DIR" ]; then
    _DRSC_OUT=$(python3 "$_DRSC_TOOL" --workspace "$WS_DIR" 2>&1); _DRSC_RC=$?
    if echo "$_DRSC_OUT" | grep -q 'fail-disposition-reframe-unsound'; then
        echo ""
        echo "  ❌ 146c. DISPOSITION-REFRAME-SOUNDNESS blocked: an impact-reframe kill/OOS lacks its required soundness proof (GEN-5A/5B/5C/5D):"
        echo "$_DRSC_OUT" | sed 's/^/       /'
        echo "       Add the reframe's soundness proof (5A: not-permanent + rubric-floor cite + downstream-composition; 5B: immutable-constant + all-deployments; 5C: multi-step-considered; 5D: actor-trusted-per-scope + no-escape-hatch), or add <!-- disposition-reframe-rebuttal: <reason> --> to the finding md."
        fails=$((fails + 1))
    elif echo "$_DRSC_OUT" | grep -q 'warn-disposition-reframe-unsound'; then
        echo ""
        echo "  ⚠️  146c. DISPOSITION-REFRAME-SOUNDNESS (advisory) - an impact-reframe kill lacks its required soundness proof (AUDITOOOR_DISPOSITION_REFRAME_STRICT=1 or AUDITOOOR_L37_STRICT=1 to enforce):"
        echo "$_DRSC_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    elif echo "$_DRSC_OUT" | grep -q 'pass-disposition-reframe-sound'; then
        echo "  ✅ 146c. DISPOSITION-REFRAME-SOUNDNESS: every impact-reframe kill carries its soundness proof"
    fi
fi

# Check #147 MOCK-REFERENCE-DIVERGENCE: a harness/PoC that ROLLS ITS OWN mock of a
# protocol-specific external dependency the workspace ALREADY ships a reference for
# is presumptively unfaithful (Strata 2026-07-07: a lane's rolled-own
# MockDepositVault pulled the raw 18-dec amount while the shipped
# test/midas/MockDepositVault.sol converts base18->native, producing a false-
# positive Medium after a 1.2M-call campaign). Flags reuse-the-reference-or-justify.
# WARN by default; hard-fail under AUDITOOOR_L37_STRICT / AUDITOOOR_MOCK_REFERENCE_STRICT.
# ---------------------------------------------------------------------------
_MRD_TOOL="$AUDITOOOR_DIR/tools/mock-reference-divergence-check.py"
if [ -f "$_MRD_TOOL" ] && [ -n "$WS_DIR" ]; then
    echo ""
    _MRD_OUT=$(python3 "$_MRD_TOOL" --workspace "$WS_DIR" 2>&1); _MRD_RC=$?
    if echo "$_MRD_OUT" | grep -q 'fail-mock-reference-divergence'; then
        echo "  ❌ 147. MOCK-REFERENCE-DIVERGENCE blocked: a harness/PoC re-implements a mock of a protocol dependency the workspace already ships a reference for:"
        echo "$_MRD_OUT" | sed 's/^/       /'
        echo "       Import the shipped reference mock (test/**/Mock<Dep>.sol) instead of rolling your own, or add <!-- mock-reference-divergence-rebuttal: <why the reference is unusable> --> to the harness."
        fails=$((fails + 1))
    elif echo "$_MRD_OUT" | grep -q 'warn-mock-reference-divergence'; then
        echo "  ⚠️  147. MOCK-REFERENCE-DIVERGENCE (advisory) — a harness/PoC rolls its own mock where the workspace ships a reference (faithfulness risk):"
        echo "$_MRD_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    elif echo "$_MRD_OUT" | grep -q 'pass-no-mock-divergence'; then
        echo "  ✅ 147. MOCK-REFERENCE-DIVERGENCE: no rolled-own mock diverges from a shipped reference"
    fi
fi

# ---------------------------------------------------------------------------
# Check #148 ABSOLUTE-USD-DERIVATION: a HIGH/CRITICAL fund-loss finding on a program that
# declares a fund-loss USD floor must carry a four-part source-anchored USD derivation
# (asset-identity file:line + unit->USD priced source + market-size + $-vs-floor) and must
# not cite an evidence artifact absent from the workspace. Motivated 2026-07-09 (predmkt):
# a driver over-claimed a redeem-slippage sandwich as "clears $1000 comfortably" citing a
# Node.js sweep artifact that did NOT exist in the ws; the honest figure (~$0.13, GBYTE
# reserve) was ~4 orders of magnitude UNDER the program's USD-1000 floor. Every existing
# impact-family gate (#124/#145/#137/#35) missed it. N/A when the workspace declares no
# fund-loss USD floor. Advisory-first: WARN by default; hard-fail ONLY under the gate's own
# AUDITOOOR_ABSOLUTE_USD_STRICT (NOT AUDITOOOR_L37_STRICT), so it stays byte-compatible in
# the L37-strict-by-default pipeline (pattern of Checks #138-140).
# ---------------------------------------------------------------------------
_AUD_TOOL="$AUDITOOOR_DIR/tools/absolute-usd-derivation-check.py"
if [ -f "$_AUD_TOOL" ] && [ -n "$WS_DIR" ]; then
    _AUD_ARGS=(--workspace "$WS_DIR" --draft "$SUB")
    if [ -n "${SEVERITY_ARG:-}" ]; then _AUD_ARGS+=(--severity "$SEVERITY_ARG"); fi
    # Advisory-first (pattern of Checks #138-140): hard-block ONLY under this gate's OWN
    # named env var, NOT AUDITOOOR_L37_STRICT. The audit flow runs L37-strict by default,
    # so coupling to it would make this net-new gate block previously-passing findings
    # (not byte-compatible). Keep it advisory in the default pipeline.
    case "$(printf '%s' "${AUDITOOOR_ABSOLUTE_USD_STRICT:-}" | tr 'A-Z' 'a-z')" in
        1|true|yes|on) _AUD_ARGS+=(--strict) ;;
    esac
    _AUD_OUT=$(python3 "$_AUD_TOOL" "${_AUD_ARGS[@]}" 2>&1); _AUD_RC=$?
    if echo "$_AUD_OUT" | grep -q 'pass-not-applicable'; then
        : # gate N/A (not HIGH+, no fund-loss floor, or not a fund-loss finding) -> silent
    elif echo "$_AUD_OUT" | grep -q 'ok-rebuttal'; then
        echo ""
        echo "  ✅ 148. ABSOLUTE-USD-DERIVATION: absolute-usd-rebuttal accepted (independent-verification receipt validated)"
    elif echo "$_AUD_OUT" | grep -q 'fail-rebuttal-unverified'; then
        # Task 3: a bare-prose (or unvalidated-receipt) rebuttal hard-blocks ONLY under
        # AUDITOOOR_ABSOLUTE_USD_STRICT / AUDITOOOR_VERIFICATION_RECEIPT_STRICT.
        echo ""
        echo "  ❌ 148. ABSOLUTE-USD-DERIVATION blocked: absolute-usd-rebuttal is not backed by a valid independent-verification receipt (strict):"
        echo "$_AUD_OUT" | sed 's/^/       /'
        echo "       Use the receipt-backed form <!-- absolute-usd-rebuttal: receipt:<id> <reason> --> and dispatch an independent verify lane (tools/emit-verification-task.py --gate absolute-usd), or complete the source-anchored USD derivation."
        fails=$((fails + 1))
    elif echo "$_AUD_OUT" | grep -q 'warn-rebuttal-unverified'; then
        # Advisory-first (byte-compatible): a bare-prose rebuttal still clears by default
        # but is flagged as not receipt-backed.
        echo ""
        echo "  ⚠️  148. ABSOLUTE-USD-DERIVATION (advisory) - absolute-usd-rebuttal is NOT backed by an independent-verification receipt (AUDITOOOR_ABSOLUTE_USD_STRICT=1 or AUDITOOOR_VERIFICATION_RECEIPT_STRICT=1 to enforce):"
        echo "$_AUD_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    elif echo "$_AUD_OUT" | grep -q 'fail-derivation-incomplete'; then
        echo ""
        echo "  ❌ 148. ABSOLUTE-USD-DERIVATION blocked: a HIGH+ fund-loss claim on a floor-declaring program lacks a complete source-anchored USD derivation (or cites a nonexistent artifact):"
        echo "$_AUD_OUT" | sed 's/^/       /'
        echo "       Add the asset-identity file:line + unit->USD priced source + market-size + \$-vs-floor derivation (python3 tools/absolute-usd-derivation-check.py --workspace $WS_DIR --emit-stub), or add <!-- absolute-usd-rebuttal: <reason> -->."
        fails=$((fails + 1))
    elif echo "$_AUD_OUT" | grep -q 'warn-derivation-incomplete'; then
        echo ""
        echo "  ⚠️  148. ABSOLUTE-USD-DERIVATION (advisory) - a HIGH+ fund-loss claim on a floor-declaring program lacks a complete source-anchored USD derivation (AUDITOOOR_ABSOLUTE_USD_STRICT=1 to hard-fail):"
        echo "$_AUD_OUT" | sed 's/^/       /'
        warns=$((warns + 1))
    elif echo "$_AUD_OUT" | grep -q 'pass-derivation-complete'; then
        echo ""
        echo "  ✅ 148. ABSOLUTE-USD-DERIVATION: HIGH+ fund-loss finding carries a complete source-anchored USD derivation vs the program floor"
    fi
fi

# --- Check 149: LIVE-PRECONDITION-GROUNDING --------------------------------
# A finding whose impact TIER hinges on a live on-chain precondition ("steal X
# now" / "currently paused" / "marker holds funds") must carry a `live-verified`
# verdict for that precondition, else its severity is downgraded to
# conditional/latent (or flagged unverifiable). The draft declares preconditions
# with `<!-- live-precondition: {"id":..,"op":..,"expected":..} -->` directives;
# the workspace declares a no-secrets public endpoint at
# <ws>/.auditooor/onchain_access.json. `onchain-live-precondition-check.py
# --gate` joins the directives against previously-emitted (authoring-time)
# verdicts in <ws>/.auditooor/live_precondition_verdicts.jsonl.
#   rc 0 => all severity-dependent preconditions live-verified, or N/A
#           (no config / no directives / no severity-dependent spec)
#   rc 1 => a precondition is CONTRADICTED by chain -> hard fail (like #28)
#   rc 2 => a severity-dependent precondition is UNVERIFIABLE -> advisory
#           downgrade; hard-fails only under AUDITOOOR_LIVE_PRECONDITION_STRICT=1
#           (default-ON under the master AUDITOOOR_STRICT_ALL switch).
_LPG_TOOL="$AUDITOOOR_DIR/tools/onchain-live-precondition-check.py"
if [ -f "$_LPG_TOOL" ] && [ -n "${WS_DIR:-}" ]; then
    echo ""
    _LPG_TMP=$(mktemp 2>/dev/null || echo "/tmp/lpg_$$.log")
    set +e
    python3 "$_LPG_TOOL" --workspace "$WS_DIR" --submission "$SUB" --gate > "$_LPG_TMP" 2>&1
    _LPG_RC=$?
    set -uo pipefail
    _LPG_FIRST=$(head -1 "$_LPG_TMP")
    case "$_LPG_RC" in
        0)
            echo "  ✅ 149. LIVE-PRECONDITION-GROUNDING: $_LPG_FIRST" ;;
        1)
            echo "  ❌ 149. LIVE-PRECONDITION-GROUNDING contradicted-by-chain:"
            sed 's/^/       /' "$_LPG_TMP"
            echo "       A live precondition this finding's severity depends on is CONTRADICTED"
            echo "       by current on-chain state. Fix the claim, re-ground the precondition,"
            echo "       or walk the severity down to conditional/latent."
            fails=$((fails + 1)) ;;
        2)
            if [ "${AUDITOOOR_LIVE_PRECONDITION_STRICT:-0}" = "1" ]; then
                echo "  ❌ 149. LIVE-PRECONDITION-GROUNDING unverifiable (strict):"
                sed 's/^/       /' "$_LPG_TMP"
                echo "       Run tools/onchain-live-precondition-check.py --allow-network during"
                echo "       authoring to emit a live-verified verdict, or downgrade the claim to"
                echo "       conditional/latent. Set AUDITOOOR_LIVE_PRECONDITION_STRICT=0 for advisory."
                fails=$((fails + 1))
            else
                echo "  ⚠️  149. LIVE-PRECONDITION-GROUNDING (advisory) - a severity-dependent live"
                echo "       precondition is UNVERIFIED; impact tier is conditional/latent until"
                echo "       grounded. Ground it (--allow-network) or downgrade. Enforce with"
                echo "       AUDITOOOR_LIVE_PRECONDITION_STRICT=1."
                sed 's/^/       /' "$_LPG_TMP"
                warns=$((warns + 1))
            fi ;;
        *)
            echo "  ⚠️  149. LIVE-PRECONDITION-GROUNDING error (rc=$_LPG_RC): $_LPG_FIRST"
            warns=$((warns + 1)) ;;
    esac
    rm -f "$_LPG_TMP"
fi

echo ""
echo "==========================================================================="
if [ $fails -eq 0 ] && [ $warns -eq 0 ]; then
    echo "  ✅ ALL CHECKS PASSED — safe to submit"
    exit 0
elif [ $fails -eq 0 ]; then
    echo "  ⚠️  $warns warning(s) — review before submitting"
    echo "  Not a hard block, but address these for a stronger submission."
    if [ "$DO_FIX" -eq 0 ] && [ -f "$AUDITOOOR_DIR/tools/auto-fix-draft.py" ]; then
        echo ""
        echo "  💡 Tip: Some warnings may be auto-fixable. Re-run with --fix:"
        echo "     $0 '$SUB' --severity ${SEVERITY:-Medium} --fix"
    fi
    exit 0
else
    echo "  ❌ $fails check(s) failed, $warns warning(s) — FIX BEFORE SUBMITTING"
    if [ "$DO_FIX" -eq 0 ] && [ -f "$AUDITOOOR_DIR/tools/auto-fix-draft.py" ]; then
        echo ""
        echo "  💡 Tip: Some issues may be auto-fixable. Re-run with --fix:"
        echo "     $0 '$SUB' --severity ${SEVERITY:-Medium} --fix"
    fi
    exit 1
fi
