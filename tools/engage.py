#!/usr/bin/env python3
"""engage.py — UNIFIED ENGAGEMENT COMMAND (Phase 88, 32-stage canonical chain).

`make engage WORKSPACE=<path>` runs the entire auditooor pipeline end-to-end.

Canonical stage order (32 stages, `--stage all`):

  INTAKE (mechanical baseline before agents/manual review):
    intake-baseline → file/intel/PDF extraction/scanner-artifact baseline

  ORIENT + ENV-CHECK + MINE-PRIORITIZE (priming, Phase 87+):
    orient          → prior audits + skill state + CCIA cross-contract analysis
    live-checks     → declarative deployment/config/role checks
    env-check       → solc version + forge dependency health
    scan-rust       → asset-conditional Rust scan
    mine-prioritize → rank CCIA attack angles by exploitability

  SCAN (detector execution):
    scan            → flow-gate.sh + workspace-scan-orchestrator + scan.sh
                      (detector logs + workspace scan artifacts)

  CORRELATE / DEDUPE (per-hit enrichment):
    correlate       → reverse-correlator per-hit anchors
    dedupe          → dupe-risk.sh classification per hit

  CROSS-WS + MINE-BRIEFS (Phase 87+ leverage):
    cross-ws-patterns  → map patterns across all audit workspaces
    pattern-migration  → alert on unmined paid patterns
    mine-briefs        → generate investigation briefs for top targets

  SYNTHESIS (Phase 44b):
    adversarial-read    → contrarian review of top-hit contract
    attack-tree         → STRIDE attack-tree generation
    invariants          → Foundry invariant harness scaffold
    economic-hypotheses → enumerate economic attack surface

  REPORT:
    report              → cluster hits + emit engagement report

  DISPATCH (Phase 45a):
    dispatch-brief  → compose agent brief per mining candidate
    capture-intel   → append engage tick to EXTERNAL_INTEL.md
    record-triage   → log UNKNOWN triage rows

  SYNTHESIZE + QUALITY (Phase 87+):
    agent-synthesize → structured verdict extraction from agent outputs
    quality-score    → numerical quality score per draft
    auto-fix         → auto-fix common pre-submit warnings
    package          → build review bundles for validated staging drafts

  CLOSE-OUT (Phase 45b):
    pre-submit            → run 22-check gate on clean submissions
    pre-submit-llm-review → dual-LLM scope+severity review of every staging draft
                            (Kimi+Minimax) via tools/llm-scope-triage.py; logs
                            scope-triage INDETERMINATE rows to
                            llm_calibration_log.jsonl and surfaces consensus
                            BEFORE track-submissions close-out
    track-submissions     → sync managed draft block in canonical SUBMISSIONS.md
    engagement-retro      → per-engagement retrospective
    post-audit-review     → print SUBMISSIONS-derived status table
    corpus-detectorization → advisory Swival/ZKBugs/ReCon/source-mining inventory
    campaign-source-mine  → opt-in long-context source mining campaign

`--stage <name>` selects a single stage. `--stages a,b,c` selects a subset.
`--dry-run` lists the plan without executing. `--fail-fast` halts on first failure.
Every stage is independently invocable.

Stdlib only. Graceful degradation: missing tools are SKIPPED, not fatal.
Per-hit subprocess timeouts (30s) keep one bad detector from stalling the run.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from submission_paths import find_submission_file, submission_file_location
from lib.program_impact_mapping import discover_workspace_drafts
from mining_brief_context import get_proof_context

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

# PR 210 — cost telemetry. Optional; loaded via importlib because the module
# name uses a hyphen. If the file is missing (e.g. a stripped-down checkout),
# cost hooks degrade to no-ops so engage.py still runs.
try:
    import importlib.util as _importlib_util
    _ct_spec = _importlib_util.spec_from_file_location(
        "cost_telemetry", HERE / "cost-telemetry.py"
    )
    if _ct_spec and _ct_spec.loader:
        _cost_telemetry = _importlib_util.module_from_spec(_ct_spec)
        _ct_spec.loader.exec_module(_cost_telemetry)
    else:
        _cost_telemetry = None
except Exception:
    _cost_telemetry = None

FLOW_GATE        = HERE / "flow-gate.sh"
INTAKE_BASELINE  = HERE / "intake-baseline.py"
ORCHESTRATOR     = HERE / "workspace-scan-orchestrator.py"
SCAN_FACADE      = HERE / "scan.sh"
DUPE_RISK        = HERE / "dupe-risk.sh"
REVERSE_CORR     = HERE / "reverse-correlator.py"
CROSS_WS_LOOKUP  = HERE / "cross-workspace-lookup.py"
CORRELATOR       = HERE / "exploit-chain-correlator.py"
# Phase 44a — priming stage scripts (run BEFORE scan).
ORIENT_FROM_AUDITS = HERE / "orient-from-audits.sh"
SKILL_STATE        = HERE / "skill-state.sh"
# Phase 44b — synthesis stage scripts (run AFTER correlate/dedupe, BEFORE report).
ADVERSARIAL_READ = HERE / "adversarial-read.sh"
ATTACK_TREE      = HERE / "attack-tree.sh"
INVARIANT_HUNT   = HERE / "invariant-hunt.sh"
GEN_INVARIANTS   = HERE / "gen-invariants.sh"
ECON_HYPOTHESES  = HERE / "economic-hypotheses.sh"
# Phase 45a — dispatch stages (run AFTER report, on MINING-CANDIDATE clusters).
DISPATCH_BRIEF_ENFORCED = HERE / "agent-dispatch-enforced.sh"
DISPATCH_BRIEF          = HERE / "dispatch-brief.sh"
CAPTURE_INTEL           = HERE / "capture-intel.sh"
RECORD_TRIAGE           = HERE / "record-triage.sh"
# Phase 45b — close-out stages (run AFTER report, before/after submission).
PRE_SUBMIT_CHECK   = HERE / "pre-submit-check.sh"
REJECTION_LEARN    = HERE / "rejection-learn.sh"
ENGAGEMENT_RETRO   = HERE / "engagement-retro.sh"
POST_AUDIT_REVIEW  = HERE / "post-audit-review.sh"
SUBMISSION_SYNC   = HERE / "submission-sync.sh"
SOURCE_MINING_CAMPAIGN = HERE / "source-mining-campaign.py"
CORPUS_DETECTORIZATION_INVENTORY = HERE / "corpus-detectorization-inventory.py"
# Phase 87+ — new tools from audit-loop.sh integration.
SOLC_VERSION_MANAGER    = HERE / "solc-version-manager.py"
FORGE_DEPS_CHECKER      = HERE / "forge-deps-checker.py"
MINING_PRIORITIZER      = HERE / "mining-prioritizer.py"
MINING_BRIEF_GENERATOR  = HERE / "mining-brief-generator.py"
CROSS_WS_MAPPER         = HERE / "cross-ws-pattern-mapper.py"
PATTERN_MIGRATION_ALERT = HERE / "pattern-migration-alert.py"
AGENT_OUTPUT_SYNTHESIZER = HERE / "agent-output-synthesizer.py"
FINDING_QUALITY_SCORER  = HERE / "finding-quality-scorer.py"
AUTO_FIX_DRAFT          = HERE / "auto-fix-draft.py"
SUBMISSION_PACKAGER     = HERE / "submission-packager.py"
SUBMISSIONS_TRACKER     = HERE / "submissions-tracker.py"
VARIANT_DETECTOR        = HERE / "variant-detector.py"
# PR pre-submit-llm-review — dual-LLM scope+severity review of staging drafts.
# Wires the Kimi+Minimax pipeline pioneered by `tools/llm-pr-review.py` into
# the canonical close-out chain so every draft gets a consensus check BEFORE
# the submission ledger close-out (track-submissions). Offline-safe: dispatch
# failures degrade to "skipped" rather than blocking the chain.
LLM_DISPATCH            = HERE / "llm-dispatch.py"
LLM_CALIBRATION_LOG     = HERE / "llm-calibration-log.py"
LLM_SCOPE_TRIAGE        = HERE / "llm-scope-triage.py"
PRE_SUBMIT_LLM_TIMEOUT  = 90   # per provider/draft outer guard
PRE_SUBMIT_LLM_MAX_DRAFT_CHARS = 24_000  # truncation guard for prompt
# Kimi 20/10 Step 5 — adversarial co-pilot per-engagement close-out hook.
ADVERSARIAL_COPILOT     = HERE / "adversarial-copilot.py"
CCIA_RUST               = HERE / "ccia-rust.py"
DEPLOYMENT_TOPOLOGY_BUILDER = HERE / "deployment-topology-builder.py"
LIVE_CHECK_SPEC_SYNTH     = HERE / "live-check-spec-synthesizer.py"
LIVE_CHECK_RUNNER       = HERE / "live-check-runner.py"
RUST_RUNTIME_SEMANTIC_BLOCKERS = HERE / "rust-runtime-semantic-blockers.py"
BASE_SCAN_PREFLIGHT      = HERE / "base-scan-preflight.py"
AUTOMATION_CLOSURE       = HERE / "automation-closure.py"
AGENT_RECALL_DETECTOR_QUEUE = HERE / "agent-recall-detector-queue.py"
HIGH_IMPACT_EXECUTION_BRIDGE = HERE / "high-impact-execution-bridge.py"
# Gap E — asset-conditional rust scan. Prefers rust-scan-runner.sh (written
# by a separate agent); falls back to the in-tree rust-scan.sh if the runner
# is not yet shipped.
RUST_SCAN_RUNNER        = HERE / "rust-scan-runner.sh"
RUST_SCAN_FALLBACK      = HERE / "rust-scan.sh"
RUST_SCAN_TIMEOUT       = 2700  # 45 minutes (per roadmap L128-129)

# SPARK-GAP-001 — Go-source pattern scanner. No-op (clean SKIP) when the
# workspace has no .go files, so it's safe to wire unconditionally.
GO_DETECTOR_RUNNER      = HERE / "go-detector-runner.py"
GO_SCAN_TIMEOUT         = 600  # 10 minutes — pure-Python regex scan

# Valid --stage values. `all` runs the canonical 32-step order:
#   intake-baseline -> orient -> live-checks -> env-check -> scan-rust -> mine-prioritize -> scan ->
#   correlate -> dedupe ->
#   cross-ws-patterns -> pattern-migration -> mine-briefs ->
#   adversarial-read -> attack-tree -> invariants -> economic-hypotheses ->
#   report -> dispatch-brief -> capture-intel -> record-triage ->
#   agent-synthesize -> quality-score -> auto-fix -> package ->
#   pre-submit -> track-submissions -> engagement-retro -> post-audit-review ->
#   corpus-detectorization -> campaign-source-mine
# scan-rust is asset-conditional — it only runs when Blockchain/DLT or Rust
# roots are in scope (signaled by INTAKE_BASELINE.json). It is sequenced
# BEFORE `mine-prioritize` so that on a fresh BDL/Rust workspace the chain
# can actually produce the scan-rust evidence required by the `_rust_gate_ok`
# guard on `mine-prioritize` / `mine-briefs`. (Codex review on PR #116:
# placing it after mine-prioritize made the chain deadlock on first run.)
# `rejection-learn` is a standalone trigger (runs only when --stage
# rejection-learn is invoked OR --rejection <file> is given); NOT in the
# `all` chain to avoid retraining the classifier on every run.
# Each named stage is independently runnable.
STAGES = (
    "intake-baseline", "orient", "live-checks", "env-check", "scan-rust", "scan-go", "mine-prioritize", "scan",
    "correlate", "dedupe",
    "cross-ws-patterns", "pattern-migration", "mine-briefs",
    "adversarial-read", "attack-tree", "invariants", "economic-hypotheses",
    "report",
    "dispatch-brief", "capture-intel", "record-triage",
    "agent-synthesize", "quality-score", "auto-fix", "package",
    "pre-submit", "pre-submit-llm-review", "track-submissions",
    "engagement-retro", "adversarial-copilot", "post-audit-review",
    "corpus-detectorization",
    "campaign-source-mine",
    "rejection-learn", "all",
)

# The ordered Makefile driver owns these after substrate and reasoning. When
# Step 1 invokes engage.py with AUDITOOOR_DEFER_DRIVE=1, running them here
# would pull the drive and closeout half ahead of the deep engines.
ORDERED_DRIVE_TAIL_STAGES = frozenset({
    "agent-synthesize", "quality-score", "auto-fix", "package",
    "pre-submit", "pre-submit-llm-review", "track-submissions",
    "engagement-retro", "adversarial-copilot", "post-audit-review",
    "corpus-detectorization", "campaign-source-mine",
})

# Phase 49b: stage table for --dry-run, --stages <list>, --help listing.
# Maps stage name -> (one-line description, artifact path template).
# `{ws}` is substituted with the workspace path at render time.
# Order here is the canonical "all" chain order minus rejection-learn (which
# is standalone) and minus the "all" alias.
STAGE_TABLE: list[tuple[str, str, str]] = [
    ("intake-baseline",     "Mechanical first-pass: workspace files, PDFs, intel, scanner readiness",
     "{ws}/INTAKE_BASELINE.json, {ws}/INTAKE_BASELINE.md"),
    ("orient",              "Prime workspace: prior audits + skill state + CCIA + deployment topology",
     "{ws}/PRIOR_CONCERNS.md, {ws}/.skill_state.yaml, {ws}/ccia_report.md, {ws}/deployment_topology.json, {ws}/deployment_topology.md"),
    ("live-checks",         "Run declarative live topology / config checks",
     "{ws}/live_topology_checks.json, {ws}/LIVE_TOPOLOGY.md"),
    ("env-check",           "solc version + forge dependency health check",
     "(reporting only; no artifact)"),
    ("scan-rust",           "Asset-conditional Rust scan (cargo audit / semgrep / clippy) when BDL or Rust roots are in scope",
     "{ws}/scanners/rust/SCAN_RUST_SUMMARY.md (PR #115) or {ws}/audit/rust-scan/summary.md (legacy)"),
    ("scan-go",             "SPARK-GAP-001 Go-source pattern scan (3 seed patterns: txid_eq, guard_only_one_path, self_heal_status); SKIPPED when no .go files",
     "{ws}/.auditooor/go_findings.json"),
    ("mine-prioritize",     "Rank CCIA attack angles by exploitability + topology evidence",
     "{ws}/swarm/mining_priorities.json"),
    ("scan",                "flow-gate + workspace-scan-orchestrator + scan.sh",
     "{out}/run_custom.log, {out}/apply_queries.log, {out}/rust-detect.log; "
     "{ws}/SCAN_REPORT.md, {ws}/PATTERN_HITS.md, {ws}/static-analysis-summary.md, "
     "{ws}/SOLODIT_SEARCH_PLAN.md, {ws}/HYPOTHESIS_PROMPT.md"),
    ("correlate",           "Per-hit reverse-correlator + cross-workspace lookup",
     "(in-memory enrichment; feeds report)"),
    ("dedupe",              "Per-hit dupe-risk classification",
     "(in-memory enrichment; feeds report)"),
    ("cross-ws-patterns",   "Map patterns across all audit workspaces",
     "{ws}/cross_ws_patterns.md"),
    ("pattern-migration",   "Alert on unmined patterns that paid in other workspaces",
     "{ws}/pattern_migration_alert.md"),
    ("mine-briefs",         "Generate investigation briefs for top mining targets",
     "{ws}/swarm/mining_briefs/*.md"),
    ("adversarial-read",    "Adversarial contrarian review of top-hit contract",
     "{ws}/adversarial_<contract>.md"),
    ("attack-tree",         "STRIDE attack-tree for top-hit contract",
     "{ws}/ATTACK_TREE_<Contract>.md"),
    ("invariants",          "Foundry invariant harness scaffold",
     "{ws}/poc-tests/Invariant_<Contract>.t.sol"),
    ("economic-hypotheses", "Enumerate economic attack surface",
     "{ws}/economic_hypotheses.md"),
    ("report",              "Cluster hits + emit engagement report",
     "{out}/engage_report.md"),
    ("dispatch-brief",      "Compose agent brief per mining candidate",
     "{ws}/agent_outputs/dispatch_<slug>.md"),
    ("capture-intel",       "Append engage tick marker to EXTERNAL_INTEL.md",
     "{ws}/EXTERNAL_INTEL.md"),
    ("record-triage",       "Log UNKNOWN triage rows for mining candidates",
     "(audit ledger append)"),
    ("agent-synthesize",    "Structured verdict extraction from agent outputs",
     "{ws}/swarm/agent_verdicts.json + {ws}/swarm/brief_candidates.json"),
    ("quality-score",       "Numerical quality score per draft submission",
     "(reporting only; per-draft scores)"),
    ("auto-fix",            "Auto-fix common pre-submit warnings in-place",
     "(in-place draft fixes)"),
    ("package",             "Build review bundles for validated staging drafts",
     "{ws}/submissions/packaged/"),
    ("pre-submit",          "Run 22-check gate on clean submissions",
     "(reporting only; no artifact)"),
    ("pre-submit-llm-review", "Dual-LLM (Kimi+Minimax) scope+severity review of every staging draft via tools/llm-scope-triage.py (single source of truth — uses OOS_CHECKLIST.md + SEVERITY_CAPS.md); logs scope-triage INDETERMINATE rows to llm_calibration_log.jsonl and surfaces consensus before track-submissions",
     "{ws}/submissions/llm_review/draft_*.json (per-draft artefact); calibration ledger appended in tools/calibration/llm_calibration_log.jsonl"),
    ("track-submissions",   "Sync managed draft block in nested SUBMISSIONS.md",
     "{ws}/submissions/SUBMISSIONS.md (root-level SUBMISSIONS.md is skipped)"),
    ("engagement-retro",    "Per-engagement retrospective",
     "{ws}/RETROSPECTIVE.md"),
    ("adversarial-copilot", "Kimi 20/10 Step 5: dispute NOT-A-BUG verdicts; on break, emit candidate DSL pattern",
     "{ws}/agent_outputs/adversarial_*.md (break artifacts), reference/patterns.dsl/_novelty/<slug>.yaml (promotions)"),
    ("post-audit-review",   "Print SUBMISSIONS-derived status table",
     "(stdout summary; refreshes {ws}/STATUS.md header when present)"),
    ("corpus-detectorization", "Advisory PR #560 corpus-to-detector/harness inventory; impact-neutral and never submit-ready",
     "{ws}/.auditooor/corpus_detectorization_inventory.json + .md"),
    ("campaign-source-mine", "Opt-in V5 source-mining campaign after close-out; set CAMPAIGN_SOURCE_MINE=1 and AUDITOOOR_LLM_NETWORK_CONSENT=1",
     "{ws}/source_mining/engage-latest/manifest.json + typed deep_candidates/"),
    ("rejection-learn",     "Feed rejection outcomes into classifier (standalone)",
     "(classifier corpus update)"),
]

SUMMARY_ARTIFACT_PATTERNS: dict[str, list[str]] = {
    "intake-baseline": ["{ws}/INTAKE_BASELINE.json", "{ws}/INTAKE_BASELINE.md"],
    "orient": [
        "{ws}/PRIOR_CONCERNS.md",
        "{ws}/.skill_state.yaml",
        "{ws}/ccia_report.md",
        "{ws}/deployment_topology.json",
        "{ws}/deployment_topology.md",
        "{ws}/monitoring/live_checks.generated.json",
    ],
    "live-checks": ["{ws}/live_topology_checks.json", "{ws}/LIVE_TOPOLOGY.md"],
    "mine-prioritize": ["{ws}/swarm/mining_priorities.json"],
    "scan": [
        "{out}/run_custom.log",
        "{out}/apply_queries.log",
        "{out}/rust-detect.log",
        "{out}/circom-detect.log",
        "{ws}/SCAN_REPORT.md",
        "{ws}/PATTERN_HITS.md",
        "{ws}/static-analysis-summary.md",
        "{ws}/SOLODIT_SEARCH_PLAN.md",
        "{ws}/HYPOTHESIS_PROMPT.md",
    ],
    "scan-rust": [
        "{ws}/scanners/rust/SCAN_RUST_SUMMARY.md",
        "{ws}/scanners/rust/SCAN_RUST_SUMMARY.json",
        "{ws}/audit/rust-scan/summary.md",
        "{ws}/audit/rust-scan/rust-scan.log",
    ],
    "scan-go": [
        "{ws}/.auditooor/go_findings.json",
        "{ws}/.auditooor/SCAN_GO_SUMMARY.json",
    ],
    "cross-ws-patterns": ["{ws}/cross_ws_patterns.md"],
    "pattern-migration": ["{ws}/pattern_migration_alert.md"],
    "mine-briefs": ["{ws}/swarm/mining_briefs/*.md"],
    "economic-hypotheses": ["{ws}/economic_hypotheses.md"],
    "report": ["{out}/engage_report.md"],
    "dispatch-brief": ["{ws}/agent_outputs/dispatch_*.md"],
    "capture-intel": ["{ws}/EXTERNAL_INTEL.md"],
    "agent-synthesize": ["{ws}/swarm/agent_verdicts.json", "{ws}/swarm/brief_candidates.json"],
    "package": ["{ws}/submissions/packaged"],
    "pre-submit-llm-review": ["{ws}/submissions/llm_review"],
    "track-submissions": ["{ws}/submissions/SUBMISSIONS.md"],
    "engagement-retro": ["{ws}/RETROSPECTIVE.md"],
    "adversarial-copilot": ["{ws}/agent_outputs/adversarial_*.md"],
    "post-audit-review": ["{ws}/STATUS.md"],
    "corpus-detectorization": [
        "{ws}/.auditooor/corpus_detectorization_inventory.json",
        "{ws}/.auditooor/corpus_detectorization_inventory.md",
    ],
    "campaign-source-mine": [
        "{ws}/source_mining/engage-latest/manifest.json",
        "{ws}/source_mining/engage-latest/survivors.json",
        "{ws}/deep_candidates/*.json",
    ],
}

# Cap on dispatch-brief invocations per engage run; mining candidates can
# easily produce 20+ LOW-sev hits and we don't want to spam agent_outputs/.
DISPATCH_BRIEF_MAX = 5

ENRICH_TIMEOUT    = 30   # seconds per per-hit subprocess
SCAN_TIMEOUT      = 1200 # 20m floor for the orchestrator (small workspaces)


def _solidity_scan_timeout(ws: Path) -> int:
    """Scan-orchestrator stage timeout, SCALED by total in-scope SOURCE file count
    (.sol + .rs + .go), not .sol alone.

    The flat 1200s (20m) was both (a) SHORTER than the orchestrator's own
    internal per-tool budget (1800s, run_tool in workspace-scan-orchestrator.py)
    - so the stage wrapper killed the orchestrator mid-tool with rc=124 - and (b)
    far too short for a large workspace. The orchestrator runs ALL present-language
    detectors (rust-detect over every .rs, run_custom/slither over every .sol,
    cosmos-detector over .go), so a RUST-heavy workspace (near-intents: ~573 .rs,
    18 .sol) hit the <=40-.sol floor at 1200s and was killed mid-rust-detect even
    though rust-detect's own per-tool budget is 1800s. Counting only .sol was the
    bug. Now: count .sol+.rs+.go via a PRUNED walk (never descend target/.git/
    node_modules - else the count itself stalls on multi-GB build artifacts);
    1200s floor (<=40 files), else ~12s/file clamped to [1900, 3600] so it always
    EXCEEDS the 1800s internal budget yet stays bounded. Env override
    AUDITOOOR_SCAN_TIMEOUT (seconds) wins outright."""
    import os as _os
    env = _os.environ.get("AUDITOOOR_SCAN_TIMEOUT")
    if env and env.strip().isdigit():
        return int(env.strip())
    _SKIP = {"node_modules", "lib", "out", "cache", ".git", "target", "artifacts",
             "vendor", "third_party", "dist", "build", ".cargo", "__pycache__"}
    n = 0
    try:
        for dirpath, dirnames, filenames in _os.walk(ws):
            dirnames[:] = [d for d in dirnames if d not in _SKIP]
            for fn in filenames:
                if fn.endswith((".sol", ".rs", ".go")):
                    n += 1
    except Exception:
        n = 0
    if n <= 40:
        return SCAN_TIMEOUT
    return min(3600, max(1900, SCAN_TIMEOUT + n * 12))
SYNTHESIS_TIMEOUT = 300  # 5m per Phase 44b synthesis stage
# I10 — campaign-scope timeout. Source-mine campaigns dispatch one Kimi +
# one Minimax call per workspace domain (~10-15 domains on a real workspace
# like polymarket), so a single full run is multi-minute by design.
# Reusing SYNTHESIS_TIMEOUT (intended for bounded LLM calls of seconds each)
# was a category error. Default 1h leaves room for resume-skipped re-runs and
# wide workspaces; operator override via AUDITOOOR_CAMPAIGN_TIMEOUT.
CAMPAIGN_TIMEOUT  = int(os.environ.get("AUDITOOOR_CAMPAIGN_TIMEOUT", "3600"))
# Phase 87+ timeouts for new audit-loop tools.
ENV_CHECK_TIMEOUT        = 60   # solc + forge deps
LIVE_CHECKS_TIMEOUT      = 180
MINE_PRIORITIZE_TIMEOUT  = 60
DEPLOYMENT_TOPOLOGY_TIMEOUT = 120
CROSS_WS_TIMEOUT         = 120
PATTERN_MIGRATION_TIMEOUT = 120
MINE_BRIEF_TIMEOUT       = 120
AGENT_SYNTHESIZE_TIMEOUT = 60
QUALITY_SCORE_TIMEOUT    = 30   # per draft
AUTO_FIX_TIMEOUT         = 30   # per draft
PACKAGE_TIMEOUT          = 60   # per draft
TRACK_SUBMISSIONS_TIMEOUT = 30
CORPUS_DETECTORIZATION_TIMEOUT = 60

# Phase 40b: drop hits in test/mock/script/archive paths.
# These are the dominant FP source observed in Phase 40 triage of Polymarket
# (3/15 hits on FeeModuleTestHelper.sol, 3/15 on already-OOS ProxyFactory).
# Patterns are matched against the normalized (POSIX) file path with
# re.search — so a leading or anchoring slash means "path segment".
PATH_BLACKLIST = [
    r"/test/", r"/tests/", r"/mocks?/", r"/ARCHIVED_FOR_SCAN/",
    r"/_archive/", r"/scripts?/", r"/examples?/", r"/lib/",
    r"\.t\.sol$", r"\.s\.sol$",  # Foundry test / script
    r"Test\.sol$", r"Mock\.sol$",
    # NOTE: bare `Helper.sol$` would suppress legitimate library helpers
    # (e.g. CalculatorHelper.sol). Only suppress when the basename clearly
    # signals test infra: TestHelper / MockHelper / FuzzHelper.
    r"(?:Test|Mock|Fuzz)Helper\.sol$",
    r"Harness\.sol$", r"Fixture\.sol$",
    # Phase 40c: interface files contain only declarations (no bodies), so
    # implementation-level detectors (unprotected-initialize, missing access
    # control, etc.) are guaranteed FP on them. Suppress both lower- and
    # upper-case folder conventions plus the `IFoo.sol` basename convention.
    r"/interfaces?/", r"/Interfaces?/",
]
# Applied AFTER path-blacklist on the file basename's contract-name suffix.
# Same rationale: `Helper$` is too broad (matches CalculatorHelper); restrict
# to Test/Mock/Fuzz-prefixed helpers.
_CONTRACT_BLACKLIST = [
    r"Test$", r"Mock$",
    r"(?:Test|Mock|Fuzz)Helper$",
    r"Harness$", r"Fixture$",
]


def _is_blacklisted(file_path: str, extra_patterns: list[str] | None = None) -> bool:
    """True if file_path matches any PATH_BLACKLIST or _CONTRACT_BLACKLIST entry."""
    if not file_path:
        return False
    # Normalize to POSIX-style for stable regex matching.
    norm = file_path.replace("\\", "/")
    patterns = list(PATH_BLACKLIST)
    if extra_patterns:
        patterns.extend(extra_patterns)
    for pat in patterns:
        if re.search(pat, norm):
            return True
    stem = Path(norm).stem  # e.g. FeeModuleTestHelper from .../FeeModuleTestHelper.sol
    for pat in _CONTRACT_BLACKLIST:
        if re.search(pat, stem):
            return True
    return False

# rust-detect.log / circom-detect.log lines:  [sev] file:line:col message...
_RUST_HIT = re.compile(
    r"^\s*\[(?P<sev>\w+)\]\s+(?P<file>\S+?):(?P<line>\d+):\d+\s+(?P<msg>.*)$"
)
# run_custom slither lines:  [SEV] description (file#Lline)  or  [SEV] desc :: file:line
_SLITHER_DET = re.compile(r"^=== Running (?P<name>[\w\-]+) ===")
_SLITHER_HIT = re.compile(
    r"^\s*\[(?P<sev>HIGH|MEDIUM|LOW|INFO|INFORMATIONAL|CRITICAL)\]\s*(?P<msg>.*)$"
)
_FILE_LINE = re.compile(r"(?P<file>[\w./\-_]+\.(?:sol|rs))(?:[#:](?:L)?(?P<line>\d+))?")
# rust-detect / circom-detect block header:  === <name>  (N hits) ===
_RUST_BLOCK = re.compile(r"^=== (?P<name>[\w\-]+)\s+\((?P<n>\d+) hits\) ===")
# apply-queries.sh real format:
#   [HITS]  <category>  <query-name>   (N hits)
#       /abs/path/file.sol:LINE: snippet
_AQ_HEADER = re.compile(
    r"^\s*\[HITS\]\s+(?P<cat>\S+)\s+(?P<name>\S+)\s+\((?P<n>\d+)\s+hits\)"
)
_AQ_HIT = re.compile(
    r"^\s+(?P<file>/[^:]+\.(?:sol|rs)):(?P<line>\d+):\s*(?P<snip>.*)$"
)


# ------------------------------ helpers ------------------------------------

def log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg, flush=True)


def run(cmd: list[str], timeout: int, capture: bool = True) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True,
                           timeout=timeout, errors="replace")
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)
    except Exception as e:
        return 1, "", repr(e)


CANONICAL_STRICT_ENV = "AUDITOOOR_CANONICAL_STRICT"
NO_FAIL_FAST_ENV = "AUDITOOOR_AUDIT_NO_FAIL_FAST"


def _canonical_strict() -> bool:
    """Whether this invocation must reject legacy fail-open behavior."""
    return os.environ.get(CANONICAL_STRICT_ENV) == "1"


class CanonicalStrictJsonError(ValueError):
    """A required JSON artifact was present but could not be parsed."""


def _load_json_or_empty(path: Path, *, artifact: str) -> dict:
    """Load JSON, preserving legacy empty-on-error behavior outside strict mode."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if _canonical_strict() and path.exists():
            raise CanonicalStrictJsonError(
                f"malformed {artifact}: {path} ({exc})"
            ) from exc
        return {}
    if not isinstance(payload, dict):
        if _canonical_strict():
            raise CanonicalStrictJsonError(
                f"malformed {artifact}: {path} (expected JSON object)"
            )
        return {}
    return payload


def _read_json(path: Path) -> dict:
    return _load_json_or_empty(path, artifact=path.name)


_IGNORED_FOUNDRY_SEARCH_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "lib",
    "out",
    "cache",
    "broadcast",
}


def _has_foundry_project(ws: Path, max_descendant_depth: int = 4) -> bool:
    """Return True when `ws` or a shallow child contains `foundry.toml`.

    Audit workspaces often wrap the actual repository under `external/<repo>`
    or `src/<repo>`. The env-check stage should not skip Forge dependency
    checks just because the workspace root is not itself the Foundry project.
    """
    ws = ws.resolve()
    if (ws / "foundry.toml").is_file():
        return True
    for common in ("src", "src-v2", "contracts", "external"):
        if (ws / common / "foundry.toml").is_file():
            return True

    for dirpath, dirnames, filenames in os.walk(ws):
        path = Path(dirpath)
        try:
            depth = len(path.relative_to(ws).parts)
        except ValueError:
            depth = 0
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in _IGNORED_FOUNDRY_SEARCH_DIRS
            and not d.startswith(".")
        )
        if depth >= max_descendant_depth:
            dirnames[:] = []
        if "foundry.toml" in filenames:
            return True
    return False


def _slither_python_candidates() -> list[str]:
    candidates = [
        os.environ.get("AUDITOOOR_PYTHON_SLITHER", "").strip(),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "python3",
    ]
    out: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def _select_slither_python() -> tuple[str, int, str, str]:
    """Find a Python interpreter that can import slither-analyzer."""
    first_result: tuple[str, int, str, str] | None = None
    for candidate in _slither_python_candidates():
        rc, so, se = run([candidate, "-c", "import slither"], 15)
        if first_result is None:
            first_result = (candidate, rc, so, se)
        if rc == 0:
            return candidate, rc, so, se
    if first_result is not None:
        return first_result
    return sys.executable, 127, "", "no Python candidates"


# ------------------------------ parsers ------------------------------------

def _extract_file_line(text: str) -> tuple[str, str]:
    m = _FILE_LINE.search(text)
    if not m:
        return "", ""
    return m.group("file"), (m.group("line") or "")


def parse_rust_log(path: Path) -> list[dict]:
    return parse_block_hit_log(path, source="rust")


def parse_circom_log(path: Path) -> list[dict]:
    return parse_block_hit_log(path, source="circom")


def parse_block_hit_log(path: Path, *, source: str) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    current = None
    for ln in path.read_text(errors="replace").splitlines():
        m = _RUST_BLOCK.match(ln)
        if m:
            current = m.group("name"); continue
        m = _RUST_HIT.match(ln)
        if m and current:
            out.append({
                "detector": current,
                "severity": m.group("sev").upper(),
                "file":     m.group("file"),
                "line":     m.group("line"),
                "function": "",
                "snippet":  m.group("msg").strip()[:240],
                "source":   source,
            })
    return out


def parse_slither_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    current = None
    for ln in path.read_text(errors="replace").splitlines():
        m = _SLITHER_DET.match(ln)
        if m:
            current = m.group("name"); continue
        m = _SLITHER_HIT.match(ln)
        if m and current:
            sev = m.group("sev").upper()
            if sev in ("INFORMATIONAL", "INFO"):
                sev = "LOW"
            f, lno = _extract_file_line(m.group("msg"))
            out.append({
                "detector": current,
                "severity": sev,
                "file":     f,
                "line":     lno,
                "function": "",
                "snippet":  m.group("msg").strip()[:240],
                "source":   "slither",
            })
    return out


def parse_apply_queries_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    current = None
    for ln in path.read_text(errors="replace").splitlines():
        m = _AQ_HEADER.match(ln)
        if m:
            current = {"cat": m.group("cat"), "name": m.group("name")}
            continue
        if current:
            mh = _AQ_HIT.match(ln)
            if mh:
                # Filter out library/test noise; keep only first-party paths
                fpath = mh.group("file")
                if any(seg in fpath for seg in
                       ("/lib/", "/node_modules/", "/forge-std/", "/test/",
                        "/tests/", "/mocks/", "/script/")):
                    continue
                out.append({
                    "detector": current["name"],
                    "severity": "LOW",
                    "file":     fpath,
                    "line":     mh.group("line"),
                    "function": "",
                    "snippet":  mh.group("snip").strip()[:240],
                    "source":   "glider",
                })
    return out


def _normalize_severity(value: object, default: str = "LOW") -> str:
    sev = str(value or "").strip().upper()
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return sev
    if sev in {"INFO", "INFORMATIONAL"}:
        return "LOW"
    return default


def parse_go_findings(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = _load_json_or_empty(path, artifact="go detector findings")

    patterns = data.get("patterns")
    if not isinstance(patterns, dict):
        return []

    out: list[dict] = []
    for pattern_key, pattern in patterns.items():
        if not isinstance(pattern, dict):
            continue
        detector = str(pattern.get("id") or pattern_key)
        pattern_severity = _normalize_severity(pattern.get("severity"))
        hits = pattern.get("hits")
        if not isinstance(hits, list):
            continue
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            extra = hit.get("extra")
            if not isinstance(extra, dict):
                extra = {}
            out.append({
                "detector": detector,
                "severity": _normalize_severity(hit.get("severity"), pattern_severity),
                "file":     str(hit.get("file") or ""),
                "line":     str(hit.get("line") or ""),
                "function": str(hit.get("function") or extra.get("function") or ""),
                "snippet":  str(hit.get("snippet") or "").strip()[:240],
                "source":   "go",
            })
    return out


def parse_cosmos_findings(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = _load_json_or_empty(path, artifact="cosmos detector findings")

    findings = data.get("findings")
    if not isinstance(findings, list):
        return []

    out: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        out.append({
            "detector": str(finding.get("pattern") or "<unknown>"),
            "severity": _normalize_severity(finding.get("severity"), "MEDIUM"),
            "file":     str(finding.get("file") or ""),
            "line":     str(finding.get("line") or ""),
            "function": str(finding.get("function") or ""),
            "snippet":  str(finding.get("help") or "").strip()[:240],
            "source":   "cosmos",
        })
    return out


def parse_regex_manifest(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = _load_json_or_empty(path, artifact="regex detector manifest")

    findings = data.get("findings")
    if not isinstance(findings, list):
        return []

    out: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        out.append({
            "detector": str(finding.get("detector") or "<unknown>"),
            "severity": _normalize_severity(finding.get("severity")),
            "file":     str(finding.get("file") or ""),
            "line":     str(finding.get("line") or ""),
            "function": str(finding.get("function") or ""),
            "snippet":  str(finding.get("message") or "").strip()[:240],
            "source":   "regex",
        })
    return out


def collect_hits(out_dir: Path, *, workspace: Path | None = None,
                 apply_blacklist: bool = True,
                 extra_blacklist: list[str] | None = None) -> tuple[list[dict], int]:
    """Parse all scan logs and return (kept_hits, dropped_count).

    When apply_blacklist=True (default), hits whose file path matches
    PATH_BLACKLIST / _CONTRACT_BLACKLIST (plus any extra_blacklist regexes)
    are silently dropped and counted in dropped_count.
    """
    hits: list[dict] = []
    hits += parse_slither_log(out_dir / "run_custom.log")
    hits += parse_apply_queries_log(out_dir / "apply_queries.log")
    hits += parse_rust_log(out_dir / "rust-detect.log")
    hits += parse_circom_log(out_dir / "circom-detect.log")
    hits += parse_regex_manifest(out_dir / "regex_detectors_manifest.json")
    hits += parse_cosmos_findings(out_dir / "cosmos_findings.json")
    hits += parse_go_findings(out_dir / ".auditooor" / "go_findings.json")
    if workspace is not None and workspace.resolve() != out_dir.resolve():
        hits += parse_cosmos_findings(workspace / ".auditooor" / "cosmos_findings.json")
        hits += parse_go_findings(workspace / ".auditooor" / "go_findings.json")
    if not apply_blacklist:
        return hits, 0
    kept: list[dict] = []
    dropped = 0
    for h in hits:
        if _is_blacklisted(h.get("file", ""), extra_blacklist):
            dropped += 1
            continue
        kept.append(h)
    return kept, dropped


# ------------------------------ enrichment ---------------------------------

def enrich_dupe(hit: dict, workspace: Path, scratch: Path) -> dict:
    if not DUPE_RISK.exists():
        return {"status": "SKIPPED", "reason": "tool missing"}
    title = f"{hit['detector']} in {hit.get('file','?')}"
    # Unique per-call draft path so concurrent enrichment (ThreadPoolExecutor in
    # the correlate loop) never has two threads write+read the SAME draft file
    # (titles can collide across hits with the same detector+file).
    draft = scratch / f"dupe_draft_{abs(hash(title)) & 0xffffffff:x}_{os.urandom(4).hex()}.md"
    body = (
        f"# {title}\n\n"
        f"Contract: {Path(hit.get('file','')).stem}\n"
        f"Function: {hit.get('function','')}\n"
        f"Outcome class: {hit['detector']}\n\n"
        f"{hit.get('snippet','')}\n"
    )
    draft.write_text(body)
    rc, _so, _se = run(["bash", str(DUPE_RISK), str(draft)], ENRICH_TIMEOUT)
    risk = {0: "LOW", 1: "HIGH", 2: "NEEDS_REVIEW"}.get(rc, f"rc={rc}")
    return {"status": "OK", "risk": risk}


def enrich_reverse(hit: dict, scratch: Path) -> dict:
    if not REVERSE_CORR.exists():
        return {"status": "SKIPPED", "reason": "reverse-correlator not yet shipped",
                "anchors": []}
    snip = scratch / f"snip_{abs(hash(hit['snippet'])) & 0xffffffff:x}.txt"
    snip.write_text(hit["snippet"] or hit["detector"])
    rc, so, _ = run(
        ["python3", str(REVERSE_CORR), "--detector", hit["detector"],
         "--code", str(snip), "--export-json"], ENRICH_TIMEOUT)
    if rc != 0:
        return {"status": f"ERR rc={rc}", "anchors": []}
    try:
        data = json.loads(so)
        anchors = data.get("anchors") or data.get("matches") or []
        return {"status": "OK", "anchors": anchors[:3]}
    except json.JSONDecodeError:
        return {"status": "ERR parse", "anchors": []}


def enrich_cross_workspace(hit: dict) -> dict:
    # cross-workspace-lookup.py is ARCHIVED; per-hit cross-workspace lookup
    # is superseded by the `cross-ws-patterns` stage (workspace-level mapping
    # via cross-ws-pattern-mapper.py). Keep this function as a graceful NO-OP
    # so existing report rendering doesn't break.
    return {"status": "SKIPPED",
            "reason": "use 'cross-ws-patterns' stage instead (cross-workspace-lookup archived)",
            "matches": []}


def cluster_analogical(hits: list[dict]) -> dict[str, list[int]]:
    """Cluster hits by analogical family using exploit-chain-correlator --analogical.
    Returns {family_key: [hit_index, ...]}.
    """
    clusters: dict[str, list[int]] = defaultdict(list)
    if not CORRELATOR.exists():
        # Fallback: cluster by detector name
        for i, h in enumerate(hits):
            clusters[h["detector"]].append(i)
        return clusters

    detector_to_family: dict[str, str] = {}
    seen_dets = sorted({h["detector"] for h in hits})
    for det in seen_dets:
        rc, so, _ = run(
            ["python3", str(CORRELATOR), "--analogical", det, "--export-json"],
            ENRICH_TIMEOUT)
        family = det
        if rc == 0:
            try:
                data = json.loads(so)
                analogs = data.get("analogs") or []
                if analogs:
                    # Family key = sorted (target, top-analog) for stable grouping
                    top = analogs[0]
                    top_name = (top.get("name") or top.get("detector")
                                or top.get("class") or "")
                    if top_name:
                        family = "::".join(sorted([det, top_name]))
            except json.JSONDecodeError:
                pass
        detector_to_family[det] = family

    for i, h in enumerate(hits):
        clusters[detector_to_family.get(h["detector"], h["detector"])].append(i)
    return clusters


# ------------------------------ report -------------------------------------

def render_report(workspace: Path, out_path: Path, hits: list[dict],
                  enriched: list[dict], clusters: dict[str, list[int]]) -> None:
    per_sev = Counter(h["severity"] for h in hits)
    per_det = Counter(h["detector"] for h in hits)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    L: list[str] = []
    L += [
        f"# Engagement Report — {workspace.name}",
        "",
        f"- Workspace: `{workspace}`",
        f"- Generated: {ts}",
        f"- Total hits: **{len(hits)}**",
        f"- Severity: HIGH={per_sev.get('HIGH',0)}  MEDIUM={per_sev.get('MEDIUM',0)}  LOW={per_sev.get('LOW',0)}",
        f"- Distinct detectors: {len(per_det)}",
        f"- Analogical clusters: {len(clusters)}",
        "",
    ]

    # Mining candidates: hits with no anchor AND no cross-workspace match
    mining: list[int] = []
    for i, e in enumerate(enriched):
        rev = e.get("reverse", {})
        cwl = e.get("cross_ws", {})
        no_anchor = not rev.get("anchors")
        no_cwl    = not cwl.get("matches")
        if no_anchor and no_cwl:
            mining.append(i)

    # Triage candidates: HIGH severity + LOW dupe risk
    triage: list[int] = []
    for i, h in enumerate(hits):
        if h["severity"] == "HIGH" and enriched[i].get("dupe", {}).get("risk") == "LOW":
            triage.append(i)

    # Dupe-check candidates: HIGH dupe risk
    dupe_check = [i for i, e in enumerate(enriched)
                  if e.get("dupe", {}).get("risk") == "HIGH"]

    L += [
        "## Actionable Next Steps",
        "",
        f"- Triage (HIGH severity, LOW dupe risk): **{len(triage)}** hits",
        f"- Dupe-check (HIGH dupe risk): **{len(dupe_check)}** hits",
        f"- Mine for novelty (no anchor + no cross-ws match): **{len(mining)}** hits",
        "",
    ]

    L += ["## Clusters", ""]
    sorted_clusters = sorted(clusters.items(), key=lambda kv: -len(kv[1]))
    for fam, idxs in sorted_clusters[:30]:
        L += [f"### Cluster: `{fam}` ({len(idxs)} hits)", ""]
        for i in idxs[:6]:
            h = hits[i]
            e = enriched[i]
            L += [
                f"- **[{h['severity']}] `{h['detector']}`** — `{h.get('file','?')}:{h.get('line','?')}`",
                f"  - snippet: `{(h.get('snippet','') or '')[:160]}`",
                f"  - dupe-risk: **{e.get('dupe',{}).get('risk', e.get('dupe',{}).get('status','?'))}**",
            ]
            anchors = e.get("reverse", {}).get("anchors", [])
            if anchors:
                for a in anchors[:3]:
                    label = (a.get("source") or a.get("anchor")
                             or a.get("ref") or a.get("name") or str(a))
                    score = a.get("score", a.get("similarity", ""))
                    suffix = f" (score={score})" if score != "" else ""
                    L += [f"  - resembles {label}{suffix}"]
            elif e.get("reverse", {}).get("status") == "SKIPPED":
                L += ["  - resembles: (reverse-correlator SKIPPED)"]
            else:
                L += ["  - resembles: (no anchor match)"]
            cwl_m = e.get("cross_ws", {}).get("matches", [])
            if cwl_m:
                for m in cwl_m[:3]:
                    label = (m.get("workspace") or m.get("repo")
                             or m.get("path") or str(m))
                    L += [f"  - cross-ws: {label}"]
            elif e.get("cross_ws", {}).get("status") == "SKIPPED":
                L += ["  - cross-ws: (lookup SKIPPED)"]
        if len(idxs) > 6:
            L += [f"_(+{len(idxs) - 6} more in this cluster)_", ""]
        L += [""]

    L += ["## No close historical match (best mining candidates)", ""]
    if not mining:
        L += ["_(none — every hit resembles an anchor or cross-ws match)_", ""]
    else:
        for i in mining[:25]:
            h = hits[i]
            L += [
                f"- **[{h['severity']}] `{h['detector']}`** — `{h.get('file','?')}:{h.get('line','?')}`",
                f"  - {(h.get('snippet','') or '')[:160]}",
            ]
        if len(mining) > 25:
            L += [f"_(+{len(mining) - 25} more)_"]
        L += [""]

    out_path.write_text("\n".join(L))


def _safe_sidecar_relpath(value: object) -> str | None:
    text = str(value if value is not None else "").strip()
    if not text or any(ord(ch) < 32 or ch in "`" for ch in text):
        return None
    rel = Path(text)
    if rel.is_absolute():
        return None
    parts = tuple(part for part in rel.parts if part and part != ".")
    if not parts or any(part == ".." or part.startswith(".") for part in parts):
        return None
    return Path(*parts).as_posix()


def _sidecar_hit_path(workspace: Path, value: object) -> str:
    text = str(value if value is not None else "").strip().rstrip("`").strip()
    if not text or any(ord(ch) < 32 or ch in "`" for ch in text):
        return "?"

    line_suffix = ""
    path_text = text
    if ":" in text:
        prefix, _, maybe_line = text.rpartition(":")
        if prefix and maybe_line.isdigit():
            path_text = prefix
            line_suffix = f":{maybe_line}"

    rel_candidate = _safe_sidecar_relpath(path_text)
    if rel_candidate:
        return f"{rel_candidate}{line_suffix}"

    try:
        raw_path = Path(path_text).expanduser()
    except (OSError, RuntimeError):
        return f"?{line_suffix}"

    rel_text = ""
    if raw_path.is_absolute():
        try:
            rel_text = raw_path.relative_to(workspace.resolve()).as_posix()
        except ValueError:
            parts = tuple(part for part in raw_path.parts if part not in {raw_path.anchor, ""})
            workspace_name = workspace.name
            if workspace_name in parts:
                idx = parts.index(workspace_name)
                rel_text = Path(*parts[idx + 1 :]).as_posix() if idx + 1 < len(parts) else ""
            elif len(parts) >= 2:
                rel_text = Path(*parts[-2:]).as_posix()
            elif parts:
                rel_text = parts[-1]

    safe_rel = _safe_sidecar_relpath(rel_text)
    return f"{safe_rel}{line_suffix}" if safe_rel else f"?{line_suffix}"


def _sanitize_sidecar_snippet(workspace: Path, value: object, max_chars: int = 160) -> str:
    text = str(value if value is not None else "").strip()
    if not text or any(ord(ch) < 32 for ch in text):
        return ""
    text = text.replace(str(workspace), f"workspace:{workspace.name}")
    absolute_path_re = re.compile(
        r"(^|[\s(\[{\"'])/(?:[^\s`'\")\]]+/)+[^\s`'\")\]]*"
    )
    text = absolute_path_re.sub(r"\1[redacted-local-path]", text)
    return text[:max_chars]


def build_report_sidecar(workspace: Path, hits: list[dict], enriched: list[dict],
                         clusters: dict[str, list[int]]) -> dict:
    """Build structured engage-report sidecar payload.

    Schema aligns with vault_engage_report_context cluster shape:
    clusters[] -> {detector_slug, hit_count, hits[{severity,file_path,snippet}]}.
    """
    per_sev = Counter(h["severity"] for h in hits)
    per_det = Counter(h["detector"] for h in hits)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    # Mining candidates: hits with no anchor AND no cross-workspace match.
    mining: list[int] = []
    for i, e in enumerate(enriched):
        rev = e.get("reverse", {})
        cwl = e.get("cross_ws", {})
        no_anchor = not rev.get("anchors")
        no_cwl = not cwl.get("matches")
        if no_anchor and no_cwl:
            mining.append(i)

    # Triage candidates: HIGH severity + LOW dupe risk.
    triage: list[int] = []
    for i, h in enumerate(hits):
        if h["severity"] == "HIGH" and enriched[i].get("dupe", {}).get("risk") == "LOW":
            triage.append(i)

    # Dupe-check candidates: HIGH dupe risk.
    dupe_check = [i for i, e in enumerate(enriched)
                  if e.get("dupe", {}).get("risk") == "HIGH"]

    def _file_with_line(hit: dict) -> str:
        file_path = _sidecar_hit_path(workspace, hit.get("file", "?") or "?")
        line = hit.get("line", "?")
        return f"{file_path}:{line}"

    sidecar_clusters: list[dict] = []
    sorted_clusters = sorted(clusters.items(), key=lambda kv: -len(kv[1]))
    for family, idxs in sorted_clusters[:30]:
        cluster_hits: list[dict] = []
        for i in idxs[:6]:
            hit = hits[i]
            snippet = _sanitize_sidecar_snippet(workspace, hit.get("snippet", "") or "")
            cluster_hits.append(
                {
                    "severity": str(hit.get("severity", "UNKNOWN") or "UNKNOWN"),
                    "file_path": _file_with_line(hit),
                    "snippet": snippet,
                }
            )
        sidecar_clusters.append(
            {
                "detector_slug": family,
                "hit_count": len(idxs),
                "hits": cluster_hits,
            }
        )

    return {
        "schema": "auditooor.engage_report.sidecar.v1",
        "kind": "engage_report_sidecar",
        "workspace": workspace.name,
        "workspace_name": workspace.name,
        "generated": ts,
        "total_hits": len(hits),
        "distinct_detectors": len(per_det),
        "analogical_clusters": len(clusters),
        "severity_summary": {
            "HIGH": per_sev.get("HIGH", 0),
            "MEDIUM": per_sev.get("MEDIUM", 0),
            "LOW": per_sev.get("LOW", 0),
        },
        "actionable_next_steps": {
            "triage": len(triage),
            "dupe_check": len(dupe_check),
            "mine": len(mining),
        },
        "clusters": sidecar_clusters,
    }


# ------------------------------ pipeline -----------------------------------

def stage_intake_baseline(ws: Path, args) -> str:
    """Run the mechanical intake baseline before orientation, scanners, or agents.

    This stage makes missing PDF extraction, missing known-intel markdown, and
    absent scan artifacts visible before human/agent time is spent on synthesis.
    Missing or placeholder bounty rubric coverage is a hard stop; warnings for
    extraction/scanner readiness still redirect the next action without blocking
    bootstrap work.
    """
    if not INTAKE_BASELINE.exists():
        log("[stage: intake-baseline] intake-baseline.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    out_json = ws / "INTAKE_BASELINE.json"
    out_md = ws / "INTAKE_BASELINE.md"
    log("[stage: intake-baseline] indexing workspace files, intel, PDFs, and scanner artifacts ...", args.quiet)
    def _run_intake():
        cmd = [
            sys.executable,
            str(INTAKE_BASELINE),
            str(ws),
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
        ]
        if os.environ.get("AUDITOOOR_STRICT_OPERATOR_TRUTH") == "1":
            cmd.append("--strict-operator-truth")
        return run(cmd, 120)

    rc, so, se = _run_intake()
    # Generic self-heal (any workspace/language): a freshly bootstrapped workspace
    # ships a placeholder RUBRIC_COVERAGE.md that intake-baseline hard-blocks on.
    # When SEVERITY.md (or split sources) is already populated, auto-populate the
    # rubric from it via init-rubric-coverage.sh --force and retry once, instead of
    # making the operator know that incantation. Only fires when the rubric
    # placeholder/missing blocker is the SOLE remaining blocker class.
    if rc != 0 and out_json.exists():
        try:
            _p = json.loads(out_json.read_text())
        except (json.JSONDecodeError, OSError):
            _p = {}
        _blockers = _p.get("blockers") or []
        _rubric_block = [
            b for b in _blockers
            if "RUBRIC_COVERAGE.md" in b
            and ("placeholder" in b or "no rubric rows" in b or "missing" in b)
        ]
        _other = [b for b in _blockers if b not in _rubric_block]
        _sev_ok = int((_p.get("summary") or {}).get("severity_sources_populated", 0) or 0) > 0
        _init = HERE / "init-rubric-coverage.sh"
        if _rubric_block and not _other and _sev_ok and _init.is_file():
            log(
                "[stage: intake-baseline]   self-heal: RUBRIC_COVERAGE.md is a "
                "placeholder; populating from SEVERITY.md (init-rubric-coverage.sh --force)",
                args.quiet,
            )
            hrc, hso, hse = run(["bash", str(_init), str(ws), "--force"], 60)
            if hrc == 0:
                rc, so, se = _run_intake()
            else:
                log(
                    f"[stage: intake-baseline]   self-heal failed rc={hrc}: "
                    f"{(hse or hso or '').strip()[:200]}",
                    args.quiet,
                )
    if rc != 0:
        if se:
            log(f"[stage: intake-baseline]   stderr: {se.strip()[:400]}", args.quiet)
        return f"FAIL rc={rc}"
    if so.strip():
        log(f"[stage: intake-baseline]   {so.strip().splitlines()[-1][:400]}", args.quiet)
    if not out_json.exists() or not out_md.exists():
        return "FAIL missing intake baseline artifact"
    try:
        payload = json.loads(out_json.read_text())
    except json.JSONDecodeError:
        return "FAIL invalid INTAKE_BASELINE.json"
    warning_count = int((payload.get("summary") or {}).get("warning_count", 0) or 0)
    if warning_count:
        return f"SUCCESS_WARN {warning_count} intake warning(s)"
    return "SUCCESS"


def _classify_orient_outcome(
    failures: list[str],
    hard_failures: list[str],
    warnings: list[str],
) -> str:
    """I-10: stage_orient outcome classifier.

    `failures`       → original FAIL signals (missing CCIA, etc.).
    `hard_failures`  → real per-error breakdowns (topology errors > 0,
                       skill-state init nonzero) that previously got
                       silently buried under SUCCESS_WARN. These now escalate
                       to FAIL with the full breakdown so downstream stages
                       don't proceed on partial/broken priming output.
    `warnings`       → soft notes (missing optional artifact, etc.).

    Returns the engage.py status string ("FAIL ...", "SUCCESS_WARN ...",
    or "SUCCESS"). All hard failures are surfaced (not truncated) so the
    operator can see every per-error category at once.
    """
    if failures or hard_failures:
        parts = list(failures) + list(hard_failures)
        return f"FAIL {', '.join(parts)}"
    if warnings:
        return f"SUCCESS_WARN {', '.join(warnings[:2])}"
    return "SUCCESS"


def stage_orient(ws: Path, quiet: bool) -> str:
    """Phase 44a: PRIMING — runs BEFORE scan to establish prior-audit context,
    severity caps, and OOS checklist used by all later stages.

    Two scripts (each independently optional / graceful):
      a. orient-from-audits.sh <ws>  → writes <ws>/PRIOR_CONCERNS.md
      b. skill-state.sh init <ws>    → writes <ws>/.skill_state.yaml
    """
    log("[stage: orient] priming workspace (prior-audit context + skill state) ...",
        quiet)
    warnings: list[str] = []
    failures: list[str] = []
    # I-10: real per-error signals that previously got buried under
    # SUCCESS_WARN. These escalate to FAIL with a breakdown.
    hard_failures: list[str] = []
    source_only_mode = os.environ.get("AUDITOOOR_SOURCE_ONLY") == "1"

    if ORIENT_FROM_AUDITS.exists():
        log(f"[stage: orient]   running {ORIENT_FROM_AUDITS.name} (timeout 120s) ...",
            quiet)
        rc, _so, se = run(["bash", str(ORIENT_FROM_AUDITS), str(ws)], 120)
        log(f"[stage: orient]   orient-from-audits rc={rc}", quiet)
        if rc != 0 and se:
            log(f"[stage: orient]   stderr: {se.strip()[:400]}", quiet)
            warnings.append("orient-from-audits failed")
        elif rc == 0 and not (ws / "PRIOR_CONCERNS.md").exists():
            warnings.append("missing PRIOR_CONCERNS.md")
    else:
        log("[stage: orient]   orient-from-audits.sh missing — SKIPPED", quiet)
        warnings.append("orient-from-audits missing")

    if SKILL_STATE.exists():
        log(f"[stage: orient]   running {SKILL_STATE.name} init (timeout 30s) ...",
            quiet)
        # NB: skill-state.sh's argv signature is `<workspace> <cmd>`, NOT
        # `<cmd> <workspace>` (verified against the script's `WS=$1; CMD=$2`).
        rc, _so, se = run(["bash", str(SKILL_STATE), str(ws), "init"], 30)
        log(f"[stage: orient]   skill-state init rc={rc}", quiet)
        if rc != 0:
            # I-10: skill-state init failure used to wrap as SUCCESS_WARN
            # even though `.skill_state.yaml` (consumed by downstream stages)
            # is now absent/stale. Escalate to FAIL with rc breakdown.
            if se:
                log(f"[stage: orient]   stderr: {se.strip()[:400]}", quiet)
            hard_failures.append(f"skill-state init failed (rc={rc})")
        elif rc == 0 and not (ws / ".skill_state.yaml").exists():
            warnings.append("missing .skill_state.yaml")
    else:
        log("[stage: orient]   skill-state.sh missing — SKIPPED", quiet)
        warnings.append("skill-state missing")

    # Phase 87: Run CCIA for cross-contract analysis (no compilation needed)
    CCIA = HERE / "ccia.py"
    if CCIA.exists():
        ccia_out = ws / "ccia_report.md"
        log(f"[stage: orient]   running CCIA cross-contract analysis ...", quiet)
        # Do NOT pass `--src src` — let ccia.resolve_source_root() walk
        # `.auditooor.json` source_roots, then COMMON_SOURCE_ROOTS,
        # then monorepo-aware expansions. Hardcoding `src` deadlocked
        # multi-package HH layouts (Graph, etc.) — see PR #120.
        rc, _so, se = run([sys.executable, str(CCIA), str(ws),
                           "--out", str(ccia_out)], 60)
        log(f"[stage: orient]   CCIA rc={rc}", quiet)
        if rc == 0:
            log(f"[stage: orient]   CCIA report: {ccia_out}", quiet)
            if not ccia_out.exists():
                failures.append("missing ccia_report.md")
        elif se:
            log(f"[stage: orient]   CCIA stderr: {se.strip()[:400]}", quiet)
            failures.append("ccia failed")
    else:
        log("[stage: orient]   ccia.py missing — SKIPPED", quiet)
        failures.append("ccia missing")

    # PATCH-2: Rust/Soroban fallback. ccia.py is Solidity-only and writes no
    # report on a workspace with no .sol files (it exits rc=1 no-Solidity-found).
    # When ccia.py produced no Solidity report AND the workspace looks Rust
    # (Cargo.toml or any .rs under the source root), run ccia-rust.py to emit
    # ccia_rust_report.json so mine-prioritize / mine-briefs have angles to rank.
    if not (ws / "ccia_report.md").exists() and not (ws / "ccia_report.json").exists():
        is_rust = any(ws.glob("**/Cargo.toml")) or any(ws.rglob("*.rs"))
        if is_rust and CCIA_RUST.exists():
            ccia_rust_out = ws / "ccia_rust_report.json"
            log("[stage: orient]   no Solidity CCIA report, running Rust CCIA (ccia-rust.py) ...", quiet)
            rc, _so, se = run([sys.executable, str(CCIA_RUST),
                               "--workspace", str(ws),
                               "--out", str(ccia_rust_out)], 90)
            log(f"[stage: orient]   Rust CCIA rc={rc}", quiet)
            if rc == 0 and ccia_rust_out.exists():
                log(f"[stage: orient]   Rust CCIA report: {ccia_rust_out}", quiet)
                failures[:] = [f for f in failures if f not in ("ccia failed", "ccia missing")]
            elif se:
                log(f"[stage: orient]   Rust CCIA stderr: {se.strip()[:400]}", quiet)
                failures.append("ccia-rust failed")
        elif is_rust and not CCIA_RUST.exists():
            log("[stage: orient]   ccia-rust.py missing, SKIPPED Rust CCIA", quiet)
            failures.append("ccia-rust missing")

    if DEPLOYMENT_TOPOLOGY_BUILDER.exists():
        topology_out = ws / "deployment_topology.json"
        topology_md = ws / "deployment_topology.md"
        log(f"[stage: orient]   running {DEPLOYMENT_TOPOLOGY_BUILDER.name} "
            f"(timeout {DEPLOYMENT_TOPOLOGY_TIMEOUT}s) ...", quiet)
        rc, so, se = run(
            [sys.executable, str(DEPLOYMENT_TOPOLOGY_BUILDER), str(ws), "--out", str(topology_out)],
            DEPLOYMENT_TOPOLOGY_TIMEOUT,
        )
        log(f"[stage: orient]   deployment topology rc={rc}", quiet)
        if rc == 0:
            tail = so.strip().splitlines()[-1] if so.strip() else f"wrote {topology_out}"
            log(f"[stage: orient]   {tail[:400]}", quiet)
            if not topology_out.exists():
                warnings.append("missing deployment_topology.json")
            else:
                try:
                    topology_payload = json.loads(topology_out.read_text())
                    summary = topology_payload.get("summary", {})
                except json.JSONDecodeError:
                    warnings.append("invalid deployment_topology.json")
                else:
                    resolved = int(summary.get("resolved", 0) or 0)
                    ambiguous = int(summary.get("ambiguous", 0) or 0)
                    unresolved = int(summary.get("unresolved", 0) or 0)
                    errors = int(summary.get("errors", 0) or 0)
                    rpc_ready = "yes" if summary.get("rpc_ready") else "no"
                    log(
                        "[stage: orient]   topology summary: "
                        f"resolved={resolved} ambiguous={ambiguous} "
                        f"unresolved={unresolved} errors={errors} rpc_ready={rpc_ready}",
                        quiet,
                    )
                    if source_only_mode:
                        # A GitHub-only review must never fabricate addresses or
                        # downgrade missing live state into an implicit pass.
                        # Persist the operator-selected disposition so every
                        # downstream consumer can distinguish source-only from
                        # resolved deployment evidence.
                        entries = topology_payload.get("entries") or []
                        error_entries = [
                            e for e in entries
                            if isinstance(e, dict) and e.get("status") == "error"
                        ] if isinstance(entries, list) else []
                        timeout_only = (
                            not summary.get("rpc_ready")
                            and len(error_entries) == errors
                            and bool(error_entries)
                            and all(
                                "timed out" in str(e.get("error", "")).lower()
                                for e in error_entries
                            )
                        )
                        if errors and not timeout_only:
                            hard_failures.append(
                                "topology builder errors "
                                f"({errors} contract(s); "
                                f"{ambiguous} ambiguous, {unresolved} unresolved)"
                            )
                        topology_payload["disposition"] = {
                            "mode": "github-source-only",
                            "operator_declared": True,
                            "live_state": "not_collected",
                            "lookup_timeout_count": errors if timeout_only else 0,
                            "reason": (
                                "Operator selected GitHub/source-only review; "
                                "deployment addresses and RPC state are outside this run; "
                                "timeout-only lookup failures are recorded as N/A."
                            ),
                        }
                        summary["disposition"] = "github-source-only"
                        topology_payload["summary"] = summary
                        topology_out.write_text(
                            json.dumps(topology_payload, indent=2) + "\n"
                        )
                        log(
                            "[stage: orient]   topology disposition: "
                            "github-source-only (live state not collected)",
                            quiet,
                        )
                    elif errors:
                        # I-10: a non-zero `errors` count means the topology
                        # builder failed on individual contracts (entry status
                        # == "error"). That is a real failure that downstream
                        # live-checks/dispatch consume - do NOT bury under
                        # SUCCESS_WARN. Ambiguous/unresolved remain warnings
                        # because they're expected during early triage.
                        entries = topology_payload.get("entries") or []
                        error_entries = [
                            e
                            for e in entries
                            if isinstance(e, dict) and e.get("status") == "error"
                        ] if isinstance(entries, list) else []
                        timeout_only = (
                            not summary.get("rpc_ready")
                            and len(error_entries) == errors
                            and bool(error_entries)
                            and all(
                                "timed out" in str(e.get("error", "")).lower()
                                for e in error_entries
                            )
                        )
                        if timeout_only:
                            warnings.append(
                                "topology lookup timed out with rpc_ready=no "
                                f"({errors} contract(s)); source-only mode"
                            )
                        else:
                            hard_failures.append(
                                "topology builder errors "
                                f"({errors} contract(s); "
                                f"{ambiguous} ambiguous, {unresolved} unresolved)"
                            )
                    elif ambiguous or unresolved:
                        warnings.append(
                            "topology partial "
                            f"({ambiguous} ambiguous, {unresolved} unresolved, {errors} errors)"
                        )
            if not topology_md.exists():
                warnings.append("missing deployment_topology.md")
        elif se:
            log(f"[stage: orient]   topology stderr: {se.strip()[:400]}", quiet)
            warnings.append("deployment topology failed")
    else:
        log("[stage: orient]   deployment-topology-builder.py missing — SKIPPED", quiet)
        warnings.append("deployment-topology-builder missing")

    if LIVE_CHECK_SPEC_SYNTH.exists():
        generated_spec = ws / "monitoring" / "live_checks.generated.json"
        log(
            f"[stage: orient]   running {LIVE_CHECK_SPEC_SYNTH.name} "
            f"(timeout {DEPLOYMENT_TOPOLOGY_TIMEOUT}s) ...",
            quiet,
        )
        rc, so, se = run(
            [sys.executable, str(LIVE_CHECK_SPEC_SYNTH), str(ws), "--out", str(generated_spec)],
            DEPLOYMENT_TOPOLOGY_TIMEOUT,
        )
        log(f"[stage: orient]   live-check synth rc={rc}", quiet)
        if rc == 0:
            tail = so.strip().splitlines()[-1] if so.strip() else f"wrote {generated_spec}"
            log(f"[stage: orient]   {tail[:400]}", quiet)
            if not generated_spec.exists():
                warnings.append("missing live_checks.generated.json")
        elif rc == 2:
            log("[stage: orient]   live-check synth skipped — no CCIA angles yet", quiet)
        elif se:
            log(f"[stage: orient]   live-check synth stderr: {se.strip()[:400]}", quiet)
            warnings.append("live-check synth failed")
    else:
        log("[stage: orient]   live-check-spec-synthesizer.py missing — SKIPPED", quiet)
        warnings.append("live-check synth missing")

    return _classify_orient_outcome(failures, hard_failures, warnings)


def stage_scan(ws: Path, out_dir: Path, args) -> int:
    """Run the strict scan chain for engage.

    Order matters:
      1. flow-gate pre-check (can HARD STOP the whole pipeline)
      2. workspace-scan-orchestrator for parseable detector logs consumed by
         correlate/dedupe/report
      3. scan.sh for broader workspace artifacts (SCAN_REPORT, PATTERN_HITS,
         static-analysis-summary, SOLODIT_SEARCH_PLAN, HYPOTHESIS_PROMPT)

    Returns 0 on success, nonzero on a hard scan failure.
    """
    if not args.skip_flow_gate:
        if FLOW_GATE.exists():
            log("[stage: scan] flow-gate.sh --post-onboard ...", args.quiet)
            # V3 workflow-gap fix (operator-reported on dydx / Sei refresh):
            # the scan stage IS the post-onboard / artifact-refresh phase. It
            # produces the engage_report + scan logs that subsequent iters
            # consume. Iter-readiness gates like pre-iter-check.sh's
            # RUBRIC_COVERAGE >=90% hard-stop MUST NOT fire here - they
            # belong on mid-iter flow-gate calls, not the first or refresh
            # scan. Pass --post-onboard so those Phase-2/3 iter checks SKIP
            # cleanly. (Without this, any aged workspace that has not yet
            # had a manual iter fail-stops audit-deep with rc=1 in ~1s.)
            rc, so, se = run(["bash", str(FLOW_GATE), str(ws), "--post-onboard"], 120)
            if rc == 1:
                print("[stage: scan] FATAL flow-gate HARD STOP — aborting.\n"
                      "         Re-run with --skip-flow-gate to bypass.\n"
                      f"---stdout---\n{so[-2000:]}\n---stderr---\n{se[-1000:]}",
                      file=sys.stderr)
                return 1
            log(f"[stage: scan]   flow-gate rc={rc} (0=green, 2=soft-warn)",
                args.quiet)
        else:
            log("[stage: scan]   flow-gate.sh missing — SKIPPED", args.quiet)

    _scan_to = _solidity_scan_timeout(ws)
    log(f"[stage: scan] workspace-scan-orchestrator.py ... (timeout {_scan_to}s, scaled by .sol count)", args.quiet)
    rc, so, se = run(
        ["python3", str(ORCHESTRATOR), "--workspace", str(ws), "--out", str(out_dir)],
        _scan_to, capture=True)
    log(f"[stage: scan]   orchestrator rc={rc}", args.quiet)
    (out_dir / "engage_orchestrator.stdout").write_text(so)
    (out_dir / "engage_orchestrator.stderr").write_text(se)
    if rc != 0:
        print("[stage: scan] FATAL workspace-scan-orchestrator failed — aborting.\n"
              "         Downstream correlate/dedupe stages need parseable scan logs.\n"
              f"---stdout---\n{so[-2000:]}\n---stderr---\n{se[-1000:]}",
              file=sys.stderr)
        return 1

    if SCAN_FACADE.exists():
        log("[stage: scan] scan.sh ...", args.quiet)
        rc, so, se = run(["bash", str(SCAN_FACADE), str(ws)], SCAN_TIMEOUT,
                         capture=True)
        log(f"[stage: scan]   scan.sh rc={rc}", args.quiet)
        (out_dir / "engage_scan.stdout").write_text(so)
        (out_dir / "engage_scan.stderr").write_text(se)
        if rc != 0:
            print("[stage: scan] FATAL scan.sh failed — aborting.\n"
                  "         The canonical scan stage now requires the workspace "
                  "scan facade to complete.\n"
                  f"---stdout---\n{so[-2000:]}\n---stderr---\n{se[-1000:]}",
                  file=sys.stderr)
            return 1
    else:
        log("[stage: scan]   scan.sh missing — SKIPPED", args.quiet)

    return 0


# ---------------------------------------------------------------------------
# Gap E — asset-coverage hard-gate helpers
# ---------------------------------------------------------------------------

def _load_intake_baseline(ws: Path) -> dict:
    """Load INTAKE_BASELINE.json if present; return {} on any failure."""
    path = ws / "INTAKE_BASELINE.json"
    if not path.is_file():
        return {}
    return _load_json_or_empty(path, artifact="INTAKE_BASELINE.json")


def _asset_coverage_ready(ws: Path) -> tuple[bool, str]:
    """Return (ready, reason). ready=True iff every in-scope asset has
    plan_status == 'ready' OR an explicit waiver is cited on the entry.
    """
    payload = _load_intake_baseline(ws)
    if not payload:
        return (True, "no INTAKE_BASELINE.json — intake-baseline stage skipped")
    plan = payload.get("asset_coverage_plan") or {}
    assets = payload.get("assets_in_scope") or []
    if not assets:
        return (True, "no assets_in_scope")
    missing: list[str] = []
    for asset in assets:
        entry = plan.get(asset, {}) if isinstance(plan, dict) else {}
        if not isinstance(entry, dict):
            missing.append(f"{asset} (bad entry)")
            continue
        status = entry.get("plan_status", "missing")
        if status == "ready":
            continue
        if entry.get("waiver"):
            continue
        missing.append(f"{asset} (plan_status={status})")
    if missing:
        return (False, "asset coverage blocker: " + ", ".join(missing))
    return (True, "")


def _rust_scan_artifact_present(ws: Path) -> bool:
    """Return True when either PR #115's default artifact (scanners/rust/
    SCAN_RUST_SUMMARY.{json,md}) or the legacy audit/rust-scan/summary.md
    exists in the workspace.
    """
    candidates = (
        ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md",
        ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json",
        ws / "audit" / "rust-scan" / "summary.md",
        ws / "audit" / "rust-scan" / "rust-scan.log",
    )
    return any(p.is_file() for p in candidates)


def _bdl_asset_requires_rust_scan(ws: Path) -> tuple[bool, str]:
    """Return (needs_rust_scan, reason). True when Rust roots are detected
    (with a BDL asset in scope) AND no scan-rust evidence exists AND no
    ASSET_WAIVER_Blockchain_DLT.md waiver. Evidence can be either PR #115's
    scanners/rust/SCAN_RUST_SUMMARY.{json,md} or the legacy audit/rust-scan/
    summary.md.
    """
    payload = _load_intake_baseline(ws)
    assets = payload.get("assets_in_scope") or []
    rust_roots = payload.get("rust_roots") or []
    summary = payload.get("summary") or {}
    if not rust_roots:
        return (False, "no Rust roots in workspace")
    art_present = bool(summary.get("rust_scan_artifact_present"))
    if art_present or _rust_scan_artifact_present(ws):
        return (False, "scan-rust artifact present")
    waiver = ws / "ASSET_WAIVER_Blockchain_DLT.md"
    if waiver.is_file() and waiver.stat().st_size > 0:
        return (False, f"waived via `{waiver.name}`")
    needs = ("Blockchain/DLT" in assets) or bool(rust_roots)
    if needs:
        return (True,
                "Rust roots detected but scan-rust artifact missing "
                "(expected scanners/rust/SCAN_RUST_SUMMARY.md or "
                "audit/rust-scan/summary.md)")
    return (False, "")


def stage_scan_rust(ws: Path, args) -> str:
    """Gap E — asset-conditional Rust scan.

    Runs rust-scan-runner.sh (PR #115) when BDL / Rust roots are in scope.
    The runner discovers ALL Rust roots from the workspace root, so we
    always invoke it with the workspace path — never pre-narrow to a single
    Cargo.toml. Falls back to the in-tree rust-scan.sh (legacy, single-root)
    when the dedicated runner is not yet installed; in that case we pick
    the first recorded rust_root so the asset-gate can still be satisfied.

    Artifacts accepted as evidence (either contract counts):
      * PR #115 default: <ws>/scanners/rust/SCAN_RUST_SUMMARY.{json,md}
      * Legacy fallback: <ws>/audit/rust-scan/summary.md (+ rust-scan.log)
    """
    payload = _load_intake_baseline(ws)
    assets = payload.get("assets_in_scope") or []
    rust_roots = payload.get("rust_roots") or []
    if "Blockchain/DLT" not in assets and not rust_roots:
        log("[stage: scan-rust] SKIPPED — no BDL/Rust asset detected in INTAKE_BASELINE.json",
            args.quiet)
        return "SKIPPED no BDL/Rust asset"

    # Cargo.toml presence is a hard prereq for the scanner.
    if not (ws / "Cargo.toml").exists() and not rust_roots:
        log("[stage: scan-rust] SKIPPED — no Cargo.toml found in workspace", args.quiet)
        return "SKIPPED no Cargo.toml"

    # Prefer the dedicated runner (owned by a separate agent); fall back to
    # in-tree rust-scan.sh so the asset-gate can still be satisfied.
    runner: Path | None = None
    use_workspace_root = False
    if RUST_SCAN_RUNNER.exists():
        runner = RUST_SCAN_RUNNER
        # PR #115's runner performs its own multi-root discovery when
        # invoked at the workspace root. Do NOT pre-narrow to rust_roots[0]
        # — that would silently skip sibling Rust roots.
        use_workspace_root = True
    elif RUST_SCAN_FALLBACK.exists():
        # Multi-root + legacy fallback = fail loudly (Codex review PR #116).
        # The legacy single-root rust-scan.sh would silently scan only
        # rust_roots[0], recreating the very blind-spot Gap E exists to
        # prevent. Operators must install rust-scan-runner.sh (PR #115) or
        # add an explicit ASSET_WAIVER_Blockchain_DLT.md.
        if len(rust_roots) > 1:
            msg = (
                f"legacy rust-scan.sh cannot handle multi-root workspaces "
                f"({len(rust_roots)} Rust roots: {', '.join(rust_roots)}); "
                "install rust-scan-runner.sh (PR #115) or add "
                "ASSET_WAIVER_Blockchain_DLT.md"
            )
            log(f"[stage: scan-rust] FAIL — {msg}", args.quiet)
            print(f"[engage] ERR scan-rust: {msg}", file=sys.stderr)
            return f"FAIL multi-root legacy fallback — {msg}"
        runner = RUST_SCAN_FALLBACK
    else:
        log("[stage: scan-rust] SKIPPED — neither rust-scan-runner.sh nor rust-scan.sh present",
            args.quiet)
        return "SKIPPED runner missing"

    log(f"[stage: scan-rust] running {runner.name} on {ws} (timeout {RUST_SCAN_TIMEOUT}s) ...",
        args.quiet)
    # Pick a scan root.
    # * For PR #115's runner: always the workspace (enables multi-root discovery).
    # * For the legacy single-root fallback: use ws when ws/Cargo.toml exists,
    #   else the first recorded rust_root.
    scan_root = ws
    if not use_workspace_root:
        if not (ws / "Cargo.toml").exists() and rust_roots:
            candidate = ws / rust_roots[0]
            if (candidate / "Cargo.toml").exists():
                scan_root = candidate
    rc, _so, se = run(["bash", str(runner), str(scan_root)], RUST_SCAN_TIMEOUT)
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    # Accept either PR #115's default artifact or the legacy layout. Check
    # both at the workspace root AND inside scan_root (legacy tool writes
    # relative to its argument).
    artifact_candidates: list[Path] = [
        ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md",
        ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json",
        ws / "audit" / "rust-scan" / "summary.md",
        scan_root / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md",
        scan_root / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json",
        scan_root / "audit" / "rust-scan" / "summary.md",
    ]
    art = next((p for p in artifact_candidates if p.exists()), None)
    log(f"[stage: scan-rust] {status}" +
        (f" — {art}" if art else " — (no scan-rust summary written)"), args.quiet)
    if rc != 0 and se:
        log(f"[stage: scan-rust]   stderr: {se.strip()[:400]}", args.quiet)
    if rc == 0 and RUST_RUNTIME_SEMANTIC_BLOCKERS.exists():
        blockers_out = ws / ".auditooor" / "rust_runtime_semantic_blockers.json"
        blockers_rc, blockers_so, blockers_se = run(
            [
                sys.executable,
                str(RUST_RUNTIME_SEMANTIC_BLOCKERS),
                "--workspace",
                str(ws),
                "--out-json",
                str(blockers_out),
                "--generate",
            ],
            120,
        )
        if blockers_rc == 0 and blockers_out.is_file():
            blockers_payload = _read_json(blockers_out)
            blocker_status = str(blockers_payload.get("status") or "unknown")
            queue = blockers_payload.get("runtime_semantic_blocker_queue") or []
            handoffs = blockers_payload.get("safe_detectorization_handoff") or []
            log(
                "[stage: scan-rust]   rust-runtime follow-on: "
                f"{blocker_status} rows={len(queue)} handoffs={len(handoffs)}",
                args.quiet,
            )
        else:
            if blockers_se.strip():
                log(f"[stage: scan-rust]   blockers stderr: {blockers_se.strip()[:400]}", args.quiet)
            elif blockers_so.strip():
                log(f"[stage: scan-rust]   blockers stdout: {blockers_so.strip()[:400]}", args.quiet)
    if rc == 0 and "Smart Contract" in assets and ("Blockchain/DLT" in assets or rust_roots):
        if BASE_SCAN_PREFLIGHT.exists():
            preflight_out = ws / ".auditooor" / "base_scan_preflight.json"
            pf_rc, pf_so, pf_se = run(
                [
                    sys.executable,
                    str(BASE_SCAN_PREFLIGHT),
                    "--workspace",
                    str(ws),
                    "--out-json",
                    str(preflight_out),
                ],
                120,
            )
            if pf_rc == 0 and preflight_out.is_file():
                preflight_payload = _read_json(preflight_out)
                preflight_status = str(preflight_payload.get("status") or "unknown")
                can_start = bool(preflight_payload.get("can_start_base_scan"))
                log(
                    "[stage: scan-rust]   base preflight follow-on: "
                    f"{preflight_status} can_start_base_scan={str(can_start).lower()}",
                    args.quiet,
                )
            else:
                if pf_se.strip():
                    log(f"[stage: scan-rust]   base-preflight stderr: {pf_se.strip()[:400]}", args.quiet)
                elif pf_so.strip():
                    log(f"[stage: scan-rust]   base-preflight stdout: {pf_so.strip()[:400]}", args.quiet)
    if rc == 0 and art is None:
        return "SUCCESS_WARN no scan-rust summary"
    return status


def stage_scan_go(ws: Path, args) -> str:
    """SPARK-GAP-001 — Go-source pattern scan (Phase B seed: 3 of 10).

    Wraps ``tools/go-detector-runner.py``. The runner is itself a no-op
    when no ``*.go`` files are present, but we short-circuit here too so
    non-Go workspaces don't even invoke Python startup.

    Artifact: ``<ws>/.auditooor/go_findings.json``.
    """
    if not GO_DETECTOR_RUNNER.exists():
        log("[stage: scan-go] SKIPPED — go-detector-runner.py not present",
            args.quiet)
        return "SKIPPED runner missing"

    # Cheap preflight: any .go files at all?
    has_go = False
    for path in ws.rglob("*.go"):
        # Mirror the runner's skip list so we don't probe vendored trees.
        if any(part in {".git", "node_modules", "vendor", "_archive",
                        "_archived", ".auditooor", "third_party"}
               for part in path.parts):
            continue
        has_go = True
        break
    if not has_go:
        log("[stage: scan-go] SKIPPED — no .go files in workspace", args.quiet)
        return "SKIPPED no go files"

    log(f"[stage: scan-go] running go-detector-runner.py on {ws} "
        f"(timeout {GO_SCAN_TIMEOUT}s) ...", args.quiet)
    rc, _so, se = run(
        [sys.executable, str(GO_DETECTOR_RUNNER), "--workspace", str(ws)],
        GO_SCAN_TIMEOUT,
    )
    art = ws / ".auditooor" / "go_findings.json"
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    log(f"[stage: scan-go] {status}" +
        (f" — {art}" if art.exists() else " — (no go_findings.json written)"),
        args.quiet)
    if rc != 0 and se:
        log(f"[stage: scan-go]   stderr: {se.strip()[:400]}", args.quiet)
    return status


def stage_dedupe_correlate_report(ws: Path, out_dir: Path, scratch: Path,
                                  args, *, do_dedupe: bool, do_correlate: bool,
                                  do_report: bool) -> int:
    """Combined pass over the parsed hits. Splitting these per-hit would mean
    re-parsing logs three times, so we share one collect_hits() pass and let
    the caller pick which enrichment + report writes to perform."""
    hits, dropped = collect_hits(
        out_dir,
        workspace=ws,
        apply_blacklist=not args.no_blacklist,
        extra_blacklist=args.blacklist_extra,
    )
    if dropped:
        log(f"[stage: dedupe] blacklisted {dropped} hits "
            f"(test/mock/archive paths)", args.quiet)
    if args.only_detector:
        hits = [h for h in hits if h["detector"] == args.only_detector]
    log(f"[stage: dedupe] parsed {len(hits)} hits from logs", args.quiet)

    enriched: list[dict] = []
    if do_dedupe or do_correlate:
        log("[stage: correlate] per-hit enrichment "
            f"(dedupe={do_dedupe} correlate={do_correlate}) ...", args.quiet)
        def _enrich_one(h: dict) -> dict:
            e: dict = {}
            if do_dedupe:
                e["dupe"] = enrich_dupe(h, ws, scratch)
            else:
                e["dupe"] = {"status": "SKIPPED", "reason": "stage not requested"}
            if do_correlate:
                e["reverse"]  = enrich_reverse(h, scratch)
                e["cross_ws"] = enrich_cross_workspace(h)
            else:
                e["reverse"]  = {"status": "SKIPPED",
                                 "reason": "stage not requested", "anchors": []}
                e["cross_ws"] = {"status": "SKIPPED",
                                 "reason": "stage not requested", "matches": []}
            return e
        # Per-hit enrichment is independent + subprocess/MCP-bound (the GIL is
        # released during the dupe-risk.sh / reverse / cross-ws calls), so a
        # bounded thread pool parallelizes it with NO coverage loss and PRESERVES
        # input order (executor.map). On a large hit set (e.g. 2527) this turns an
        # ~hour sequential sweep into minutes. AUDITOOOR_ENGAGE_ENRICH_WORKERS
        # overrides the worker count (1 = serial, for debugging).
        _ew = os.environ.get("AUDITOOOR_ENGAGE_ENRICH_WORKERS", "").strip()
        try:
            _workers = int(_ew) if _ew else min(16, (os.cpu_count() or 4))
        except ValueError:
            _workers = min(16, (os.cpu_count() or 4))
        _workers = max(1, _workers)
        if _workers == 1 or len(hits) <= 1:
            for i, h in enumerate(hits):
                if i % 20 == 0:
                    log(f"[stage: correlate]   enriching hit {i+1}/{len(hits)}",
                        args.quiet)
                enriched.append(_enrich_one(h))
        else:
            from concurrent.futures import ThreadPoolExecutor
            log(f"[stage: correlate]   enriching {len(hits)} hits in parallel "
                f"({_workers} workers) ...", args.quiet)
            with ThreadPoolExecutor(max_workers=_workers) as _ex:
                enriched = list(_ex.map(_enrich_one, hits))
    else:
        enriched = [{"dupe":     {"status": "SKIPPED"},
                     "reverse":  {"status": "SKIPPED", "anchors": []},
                     "cross_ws": {"status": "SKIPPED", "matches": []}}
                    for _ in hits]

    if do_report:
        log("[stage: report] clustering by analogical family ...", args.quiet)
        clusters = cluster_analogical(hits)
        report_path = out_dir / "engage_report.md"
        render_report(ws, report_path, hits, enriched, clusters)
        sidecar_path = out_dir / "engage_report.json"
        sidecar = build_report_sidecar(ws, hits, enriched, clusters)
        sidecar_path.write_text(
            json.dumps(sidecar, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        log(f"[stage: report] wrote {report_path}", args.quiet)
        log(f"[stage: report] wrote {sidecar_path}", args.quiet)
        print(str(report_path))
    return 0


# ------------------------------ Phase 44b synthesis stages -----------------
# Each synthesis stage is a thin wrapper around an external shell tool with a
# 300s timeout, graceful missing-tool handling, and `[stage: <name>] <status>`
# logging. Stages run AFTER scan+correlate+dedupe but BEFORE final report so
# their artifacts can inform the report's mining/triage sections.

# r36-rebuttal: single-agent edit, lane near-engage-rust-target registered in agent_pathspec.json
# Language-aware target detection. The synthesis stages (adversarial-read,
# attack-tree, invariants, economic-hypotheses) were originally Solidity-only
# and selected `.sol` files exclusively. Rust/NEAR workspaces (e.g.
# near-intents `defuse`) ship `#[near]` / `#[near_bindgen]` / `near_sdk`
# contract crates whose entrypoint is `src/lib.rs`, which the `.sol`-only
# filter rejected, yielding "no target contract found". The helpers below make
# selection language-aware without breaking Solidity (which still picks `.sol`).
# r36-rebuttal: single-agent edit, lane near-engage-rust-target registered in agent_pathspec.json
# A NEAR contract crate is recognised by a near-sdk contract marker appearing
# ANYWHERE in the crate's `src/` tree, not only in `lib.rs`. In real near-sdk
# crates (e.g. defuse) the `#[near]` impl block lives in a submodule
# (`src/contract/mod.rs`) while `lib.rs` only re-exports `mod contract;`. The
# crate entrypoint selected for synthesis is still `<crate>/src/lib.rs`.
_NEAR_CONTRACT_MARKERS = (
    "#[near]",
    "#[near_bindgen]",
    "near_sdk",
    "near_contract_standards",
)


def _crate_root_lib(p: Path) -> Path | None:
    """Resolve a Rust source file (any `*.rs`) to its crate entrypoint
    `<crate>/src/lib.rs`.

    Walks up from p looking for the nearest ancestor `src` directory whose
    parent holds a `Cargo.toml`; returns that `src/lib.rs` when it exists.
    Returns None for non-Rust paths or when no crate root is found.
    """
    if p.suffix != ".rs":
        return None
    for parent in p.parents:
        if parent.name == "src" and (parent.parent / "Cargo.toml").exists():
            lib = parent / "lib.rs"
            if lib.exists():
                return lib
            return None
    return None


def _crate_has_near_marker(lib: Path) -> bool:
    """True if the crate rooted at `lib` (=<crate>/src/lib.rs) carries a
    near-sdk contract marker anywhere under `<crate>/src/`.

    Read failures are treated as non-matching (graceful). The scan is bounded
    to `.rs` files under the crate's own `src/` dir.
    """
    src_dir = lib.parent
    if not src_dir.is_dir():
        return False
    for rs in src_dir.rglob("*.rs"):
        try:
            body = rs.read_text(errors="replace")
        except OSError:
            continue
        if any(marker in body for marker in _NEAR_CONTRACT_MARKERS):
            return True
    return False


def _is_near_contract_lib(p: Path) -> bool:
    """True if p is the `lib.rs` entrypoint of a NEAR contract crate."""
    if p.name != "lib.rs" or p.suffix != ".rs":
        return False
    return _crate_has_near_marker(p)


def _is_target_contract_file(p: Path) -> bool:
    """True if p is a selectable per-contract synthesis target.

    Language-aware:
      * Solidity: any `.sol` file (unchanged from the original behaviour).
      * Rust/NEAR: the `lib.rs` entrypoint of a near-sdk contract crate.
    """
    if p.suffix == ".sol":
        return True
    return _is_near_contract_lib(p)


def _rust_target_for(p: Path) -> Path | None:
    """Map an arbitrary Rust hit file to the `lib.rs` of its NEAR contract
    crate, or None if it does not belong to one.

    This lets hit-density on deep crate files (e.g.
    `defuse/src/contract/fees.rs`) drive selection of the crate entrypoint
    `defuse/src/lib.rs`, exactly as `.sol` hit-density drives Solidity
    selection.
    """
    lib = _crate_root_lib(p)
    if lib is None:
        return None
    if _is_blacklisted(str(lib)):
        return None
    if _crate_has_near_marker(lib):
        return lib
    return None


def _pick_top_rust_contract(ws: Path, *, limit: int = 1) -> list[Path]:
    """Fallback selector for Rust/NEAR workspaces with no parseable hits.

    Scans `ws/src` for `lib.rs` entrypoints of near-sdk contract crates,
    restricted to crates under a `contracts/` path segment (first-party
    contract crates, not helper/core/library crates). Prefers a crate named
    `defuse` (the top in-scope NEAR contract for near-intents) and otherwise
    returns the shallowest (top-level) contract crate first. Test/mock paths
    are excluded via the shared blacklist.
    """
    src = ws / "src"
    if not src.is_dir():
        return []
    found: list[Path] = []
    for p in src.rglob("lib.rs"):
        sp = str(p).replace("\\", "/")
        if "/contracts/" not in sp:
            continue
        if _is_blacklisted(sp):
            continue
        if _crate_has_near_marker(p):
            found.append(p)
    if not found:
        return []

    def _rank(p: Path) -> tuple[int, int, str]:
        sp = str(p).replace("\\", "/")
        # Prefer the canonical top in-scope contract crate (defuse), then
        # shallower crate paths, then lexical order for determinism.
        is_defuse = 0 if "/contracts/defuse/" in sp else 1
        return (is_defuse, sp.count("/"), sp)

    found.sort(key=_rank)
    return found[:limit]


def _pick_top_contracts(ws: Path, args, *, limit: int = 1) -> list[Path]:
    """Pick the top-N first-party contracts to feed into per-contract synthesis
    tools (adversarial-read, attack-tree, invariants, economic-hypotheses).

    Strategy (best-effort, all graceful):
      1. If hits are parseable from logs, pick the contracts with the most hits.
      2. Otherwise, look for `targets.tsv` (column 1 is path).
      3. Otherwise, fall back to scanning ws/src for the first non-blacklisted
         target contract file (Solidity `.sol`, or a Rust/NEAR `lib.rs`).

    Selection is language-aware: Solidity workspaces pick `.sol` files exactly
    as before; Rust/NEAR workspaces pick the entrypoint `lib.rs` of a near-sdk
    contract crate (`#[near]` / `#[near_bindgen]` / `near_sdk`).
    """
    candidates: list[Path] = []
    # BUGFIX: collect_hits reads scan logs (run_custom.log, etc.) which live in
    # out_dir, not ws.  When --out is used the logs are outside the workspace.
    out_dir = (args.out.expanduser().resolve() if args.out else ws)
    try:
        hits, _ = collect_hits(
            out_dir,
            workspace=ws,
            apply_blacklist=not args.no_blacklist,
            extra_blacklist=args.blacklist_extra,
        )
    except Exception:
        hits = []
    if hits:
        # r36-rebuttal: lane near-engage-rust-target in agent_pathspec.json
        # Density is accumulated on the *selected target* path so that, for
        # Rust/NEAR, many hits across a crate's source tree all fold onto that
        # crate's `lib.rs` entrypoint. Solidity hits select the `.sol` file
        # itself (unchanged). Target resolution per hit file:
        #   * `.sol`  -> the file itself (if it is a target contract file)
        #   * `.rs`   -> the NEAR contract crate's `lib.rs` (via _rust_target_for)
        target_density: Counter = Counter()
        for fpath, _n in Counter(
            h.get("file", "") for h in hits if h.get("file")
        ).items():
            p = Path(fpath)
            if not p.is_absolute():
                p = (ws / fpath).resolve()
            if not p.exists():
                continue
            if p.suffix == ".sol":
                if _is_target_contract_file(p):
                    target_density[p] += _n
            elif p.suffix == ".rs":
                tgt = _rust_target_for(p)
                if tgt is not None:
                    target_density[tgt] += _n
        for tgt, _n in target_density.most_common():
            candidates.append(tgt)
            if len(candidates) >= limit:
                return candidates
    targets_tsv = ws / "targets.tsv"
    if not candidates and targets_tsv.exists():
        for ln in targets_tsv.read_text(errors="replace").splitlines():
            parts = ln.split("\t")
            if not parts or not parts[0].strip():
                continue
            p = Path(parts[0].strip())
            if not p.is_absolute():
                p = (ws / p).resolve()
            if p.exists() and _is_target_contract_file(p) and not _is_blacklisted(str(p)):  # r36-rebuttal: lane near-engage-rust-target in agent_pathspec.json
                candidates.append(p)
                if len(candidates) >= limit:
                    return candidates
    if not candidates:
        src = ws / "src"
        if src.is_dir():
            for p in sorted(src.rglob("*.sol")):
                if not _is_blacklisted(str(p)):
                    candidates.append(p)
                    if len(candidates) >= limit:
                        return candidates
    # Language-aware Rust/NEAR fallback: if the Solidity src-scan found nothing
    # (e.g. a pure Rust workspace with no parseable hits and no .sol files),
    # select the top near-sdk contract crate's lib.rs under contracts/.
    if not candidates:  # r36-rebuttal: lane near-engage-rust-target in agent_pathspec.json
        candidates.extend(_pick_top_rust_contract(ws, limit=limit))
    return candidates[:limit]


def stage_adversarial_read(ws: Path, args) -> int:
    """Phase 44b: adversarial contrarian review of the top-hit contract.
    Output artifact: <ws>/adversarial_<slug>.md (operator brief).
    """
    if not ADVERSARIAL_READ.exists():
        log("[stage: adversarial-read] SKIPPED — adversarial-read.sh missing",
            args.quiet)
        return 0
    targets = _pick_top_contracts(ws, args, limit=1)
    if not targets:
        log("[stage: adversarial-read] SKIPPED — no target contract found",
            args.quiet)
        return 0
    target = targets[0]
    try:
        rel = target.relative_to(ws)
    except ValueError:
        rel = Path(target.name)
    log(f"[stage: adversarial-read] running on {rel} (timeout {SYNTHESIS_TIMEOUT}s) ...",
        args.quiet)
    rc, _so, se = run(["bash", str(ADVERSARIAL_READ), str(ws), str(rel)],
                      SYNTHESIS_TIMEOUT)
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    slug = re.sub(r"[^a-z0-9]+", "_", target.stem.lower()).strip("_")
    artifacts = list(ws.glob(f"adversarial_{slug}.md"))
    if not artifacts:
        artifacts = sorted(ws.glob("adversarial_*.md"),
                           key=lambda p: p.stat().st_mtime, reverse=True)[:1]
    art = artifacts[0] if artifacts else None
    log(f"[stage: adversarial-read] {status}"
        + (f" — {art}" if art else ""), args.quiet)
    if rc != 0 and se:
        log(f"[stage: adversarial-read]   stderr: {se.strip()[:400]}", args.quiet)
    return 0


def stage_attack_tree(ws: Path, args) -> int:
    """Phase 44b: STRIDE-style attack-tree expansion for the top-hit contract.
    Output artifact: <ws>/ATTACK_TREE_<Contract>.md.
    """
    if not ATTACK_TREE.exists():
        log("[stage: attack-tree] SKIPPED — attack-tree.sh missing", args.quiet)
        return 0
    targets = _pick_top_contracts(ws, args, limit=1)
    if not targets:
        log("[stage: attack-tree] SKIPPED — no target contract found", args.quiet)
        return 0
    target = targets[0]
    log(f"[stage: attack-tree] running on {target.name} (timeout {SYNTHESIS_TIMEOUT}s) ...",
        args.quiet)
    rc, _so, se = run(["bash", str(ATTACK_TREE), str(target), str(ws)],
                      SYNTHESIS_TIMEOUT)
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    art = ws / f"ATTACK_TREE_{target.stem}.md"
    if not art.exists():
        cand = sorted(ws.glob("ATTACK_TREE*.md"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        art = cand[0] if cand else art
    log(f"[stage: attack-tree] {status}"
        + (f" — {art}" if art.exists() else " — (no artifact)"), args.quiet)
    if rc != 0 and se:
        log(f"[stage: attack-tree]   stderr: {se.strip()[:400]}", args.quiet)
    return 0


def stage_invariants(ws: Path, args) -> int:
    """Phase 44b: scaffold a Foundry invariant harness for the top-hit contract.
    Prefers gen-invariants.sh (lightweight scaffold). Falls back to
    invariant-hunt.sh only if gen-invariants is missing.
    Output artifact: <ws>/poc-tests/Invariant_<Contract>.t.sol.
    """
    targets = _pick_top_contracts(ws, args, limit=1)
    if not targets:
        log("[stage: invariants] SKIPPED — no target contract found", args.quiet)
        return 0
    target = targets[0]
    if GEN_INVARIANTS.exists():
        log(f"[stage: invariants] running gen-invariants.sh on {target.name} "
            f"(timeout {SYNTHESIS_TIMEOUT}s) ...", args.quiet)
        rc, _so, se = run(
            ["bash", str(GEN_INVARIANTS), str(target), str(ws)],
            SYNTHESIS_TIMEOUT)
    elif INVARIANT_HUNT.exists():
        log(f"[stage: invariants] running invariant-hunt.sh on {target.name} "
            f"(timeout {SYNTHESIS_TIMEOUT}s) ...", args.quiet)
        # invariant-hunt needs a class; default to 'generic' to maximise success.
        rc, _so, se = run(
            ["bash", str(INVARIANT_HUNT), str(ws), "generic",
             "--contract", str(target)],
            SYNTHESIS_TIMEOUT)
    else:
        log("[stage: invariants] SKIPPED — neither gen-invariants.sh nor "
            "invariant-hunt.sh found", args.quiet)
        return 0
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    art = ws / "poc-tests" / f"Invariant_{target.stem}.t.sol"
    if not art.exists():
        cand = sorted((ws / "poc-tests").glob("Invariant_*.t.sol"),
                      key=lambda p: p.stat().st_mtime, reverse=True) \
               if (ws / "poc-tests").is_dir() else []
        art = cand[0] if cand else art
    log(f"[stage: invariants] {status}"
        + (f" — {art}" if art.exists() else " — (no artifact)"), args.quiet)
    if rc != 0 and se:
        log(f"[stage: invariants]   stderr: {se.strip()[:400]}", args.quiet)
    return 0


def _write_hypotheses_placeholder(ws: Path, prompt_path: Path,
                                  reason: str, quiet: bool) -> None:
    """V5 Gap-23: ensure ``<ws>/HYPOTHESES.md`` exists even when the
    LLM dispatch path that would normally answer ``HYPOTHESIS_PROMPT.md``
    is unavailable (offline, no API key, or no consent). Downstream
    stages (mining briefs, attack-tree, audit-closeout-check) treat the
    file's *absence* as a silent failure (Gap-23). We instead write a
    minimal, clearly-marked placeholder so the chain is not blocked,
    while making it visible that the operator must complete the file.

    The placeholder is intentionally NOT structured as a valid
    hypothesis table — that would mask the real bug that no LLM ran. It
    contains a TBD banner and a pointer to the prompt so a later operator
    knows exactly what to run.
    """
    final_path = ws / "HYPOTHESES.md"
    # Treat 0-byte AND whitespace-only files as "absent" so a crashed
    # write or an empty LLM response doesn't perpetuate the silent
    # failure (Kimi + Minimax pre-review caught the regression risk).
    if final_path.exists() and final_path.stat().st_size > 0:
        try:
            existing = final_path.read_text(errors="replace")
        except OSError:
            existing = ""
        if existing.strip():
            return
    rel_prompt = prompt_path.name
    prompt_size = (
        prompt_path.stat().st_size if prompt_path.exists() else 0
    )
    # Distinct header — Minimax pre-review flagged that "# Hypotheses for"
    # collides with the real generated form. Use [PLACEHOLDER] prefix so a
    # downstream grep for "^# Hypotheses for" cannot accidentally match.
    body = (
        f"# [PLACEHOLDER] Hypotheses pending for {ws.name} — TBD\n"
        f"\n"
        f"<!-- AUDIT_STATUS: PLACEHOLDER_PENDING_LLM_DISPATCH -->\n"
        f"\n"
        f"**Status:** placeholder. The hypothesis-generation prompt was "
        f"emitted by stage 7 (`scan`) but the LLM dispatch that turns the "
        f"prompt into a hypothesis table did not run.\n"
        f"\n"
        f"- **Reason:** {reason}\n"
        f"- **Prompt file:** `{rel_prompt}` ({prompt_size} bytes)\n"
        f"- **Generated:** "
        f"{datetime.now(timezone.utc).isoformat()}\n"
        f"\n"
        f"## Operator action required\n"
        f"\n"
        f"To replace this placeholder with real hypotheses:\n"
        f"\n"
        f"```bash\n"
        f"# Option A — local pipe (requires Anthropic-compatible CLI on PATH):\n"
        f"cat '{prompt_path}' | claude --model claude-opus-4-5 \\\n"
        f"  > '{final_path}'\n"
        f"\n"
        f"# Option B — re-run stage 16 with LLM dispatch enabled:\n"
        f"AUDITOOOR_LLM_NETWORK_CONSENT=1 \\\n"
        f"  python3 tools/engage.py --workspace '{ws}' "
        f"--stage economic-hypotheses\n"
        f"```\n"
        f"\n"
        f"## Why this file exists\n"
        f"\n"
        f"V5 Gap-23 (audit-closeout-check `hypotheses` row) treats the "
        f"asymmetric `HYPOTHESIS_PROMPT.md` present + `HYPOTHESES.md` "
        f"missing case as a silent stage-16 failure. Writing this "
        f"placeholder converts the silent failure into a loud, "
        f"operator-visible TBD that downstream stages can read without "
        f"crashing while still surfacing the real gap in the engagement "
        f"summary.\n"
    )
    final_path.write_text(body)
    log(
        f"[stage: economic-hypotheses] WARN — wrote placeholder "
        f"{final_path.name} (reason: {reason}). Operator must run LLM "
        f"dispatch to replace it.",
        quiet,
    )


def _ensure_hypotheses_md(ws: Path, args) -> None:
    """V5 Gap-23 helper: backfill ``HYPOTHESES.md`` whenever the prompt
    exists but the answer does not.

    Best-effort attempt order:
      1. If ``HYPOTHESES.md`` already exists, do nothing.
      2. If ``HYPOTHESIS_PROMPT.md`` is missing, do nothing (stage 7
         did not run; not our concern).
      3. Try LLM dispatch via ``tools/llm-dispatch.py``. Network consent
         is required; if not granted (the offline default), skip.
      4. On any LLM failure / timeout / non-substantive response, fall
         through to the placeholder writer so the file always exists.

    This mirrors the gate-vs-detector split that audit-closeout-check
    enforces: stage 16 is the *fix* site, the closeout is the gate.
    """
    final_path = ws / "HYPOTHESES.md"
    prompt_path = ws / "HYPOTHESIS_PROMPT.md"
    # Kimi pre-review caught: a 0-byte HYPOTHESES.md (e.g. left by a
    # crashed write) would otherwise be treated as "real output" and
    # skipped, perpetuating the silent failure. Minimax pre-review
    # extended the case to whitespace-only content. Treat both as
    # "absent" for the purposes of Gap-23.
    if final_path.exists() and final_path.stat().st_size > 0:
        try:
            existing_text = final_path.read_text(errors="replace")
        except OSError:
            existing_text = ""
        if existing_text.strip():
            return  # already produced (manual or earlier run)
    if not prompt_path.exists():
        return  # no prompt yet → nothing to answer
    # Attempt real LLM dispatch only when consent is wired. The
    # llm-dispatch.py guard exits 2 (`cannot-run`) without consent; we
    # short-circuit here to avoid a noisy subprocess + bogus audit-trail
    # JSON in agent_outputs/.
    consent = (
        os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1"
        or os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1"
    )
    if consent and LLM_DISPATCH.exists():
        log(
            "[stage: economic-hypotheses] HYPOTHESES.md missing — "
            "attempting LLM dispatch to fill from prompt ...",
            args.quiet,
        )
        rc, so, se = run(
            [
                sys.executable, str(LLM_DISPATCH),
                "--prompt-file", str(prompt_path),
                "--timeout", str(min(SYNTHESIS_TIMEOUT, 240)),
            ],
            min(SYNTHESIS_TIMEOUT + 30, 270),
        )
        if rc == 0 and so.strip():
            final_path.write_text(so)
            log(
                f"[stage: economic-hypotheses] HYPOTHESES.md written via "
                f"LLM dispatch ({len(so)} chars).",
                args.quiet,
            )
            return
        # Distinguish offline-class (rc=2 cannot-run) from hard failures
        # in the WARN log so operators can act.
        offline_class = rc == 2 or "cannot-run" in (se or "")
        reason = (
            "LLM dispatch unavailable (offline / no API key / no consent)"
            if offline_class
            else f"LLM dispatch failed rc={rc}"
        )
        log(
            f"[stage: economic-hypotheses] LLM dispatch did not produce "
            f"HYPOTHESES.md — falling back to placeholder. {reason}.",
            args.quiet,
        )
        _write_hypotheses_placeholder(ws, prompt_path, reason, args.quiet)
        return
    # No consent or no dispatch tool: write the placeholder loudly.
    reason = (
        "LLM dispatch not invoked: AUDITOOOR_LLM_NETWORK_CONSENT not set"
        if not consent
        else "LLM dispatch tool missing (tools/llm-dispatch.py)"
    )
    _write_hypotheses_placeholder(ws, prompt_path, reason, args.quiet)


def stage_economic_hypotheses(ws: Path, args) -> int:
    """Phase 44b: enumerate the economic attack surface for the top-hit contract.
    Output artifact: <contract-dir>/economic_hypotheses/<basename>.md
    (or <ws>/economic_hypotheses.md when targeting a directory).

    V5 Gap-23: also ensures ``<ws>/HYPOTHESES.md`` exists when
    ``HYPOTHESIS_PROMPT.md`` is present. Stage 7 (`scan`) emits the
    prompt, but the LLM dispatch that turns the prompt into the final
    file is operator-driven and historically silent on failure. We
    convert that silent failure into either:

      (a) a real ``HYPOTHESES.md`` if an LLM dispatch is wired and
          succeeds within ``SYNTHESIS_TIMEOUT`` (best effort), or
      (b) a clearly-marked TBD placeholder pointing back at the prompt
          (so downstream stages do not crash on a missing file).

    The placeholder is the conservative path. We intentionally do NOT
    fabricate a hypothesis table from the economic-surface enumeration;
    that would mask the gap (Codex Gap-23 directive: "fix the actual
    generation bug, not just detect its absence").
    """
    if not ECON_HYPOTHESES.exists():
        log("[stage: economic-hypotheses] SKIPPED — economic-hypotheses.sh missing",
            args.quiet)
        # V5 Gap-23: still try to backfill HYPOTHESES.md if the prompt is
        # there — the upstream tool's absence does not absolve us of the
        # asymmetric-artefact silent-failure mode.
        _ensure_hypotheses_md(ws, args)
        return 0
    targets = _pick_top_contracts(ws, args, limit=1)
    if not targets:
        log("[stage: economic-hypotheses] SKIPPED — no target contract found",
            args.quiet)
        _ensure_hypotheses_md(ws, args)
        return 0
    target = targets[0]
    out_path = ws / "economic_hypotheses.md"
    log(f"[stage: economic-hypotheses] running on {target.name} "
        f"(timeout {SYNTHESIS_TIMEOUT}s) ...", args.quiet)
    rc, _so, se = run(
        ["bash", str(ECON_HYPOTHESES), str(target), "--out", str(out_path)],
        SYNTHESIS_TIMEOUT)
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    art = out_path if out_path.exists() else None
    if not art:
        # fall back: tool may have written to its default location.
        cand = list(ws.rglob("economic_hypotheses/*.md"))
        if cand:
            art = max(cand, key=lambda p: p.stat().st_mtime)
    log(f"[stage: economic-hypotheses] {status}"
        + (f" — {art}" if art else " — (no artifact)"), args.quiet)
    if rc != 0 and se:
        log(f"[stage: economic-hypotheses]   stderr: {se.strip()[:400]}",
            args.quiet)
    # V5 Gap-23: backfill HYPOTHESES.md after the economic-hypothesis
    # subrun, regardless of its outcome. The two artefacts are
    # independent (economic_hypotheses.md is enumeration, HYPOTHESES.md
    # is the LLM-answered prompt) but stage 16 is the natural seam.
    _ensure_hypotheses_md(ws, args)
    return 0


# ----------------------------- Phase 45a dispatch stages ------------------- #
# These run AFTER the final synthesis report so they can act on the
# MINING-CANDIDATE clusters surfaced there.

# Mining-candidate line in engage_report.md looks like:
#   - **[LOW] `detector-name`** — `/abs/path/File.sol:123`
#     - snippet text...
# The em-dash (—) is U+2014; we match it as a literal so a stray hyphen
# rendering would break the parse loudly rather than silently corrupting hits.
_MINING_LINE = re.compile(
    r"^\s*-\s+\*\*\[(?P<sev>HIGH|MEDIUM|LOW)\]\s+`(?P<det>[^`]+)`\*\*\s+"
    r"\S+\s+`(?P<file>[^:`]+):(?P<line>\d+)`"
)


def parse_mining_candidates(report_path: Path) -> list[dict]:
    """Extract MINING-CANDIDATE hits from engage_report.md.

    Mining candidates live in the `## No close historical match` section.
    Returns a list of {detector, severity, file, line, snippet} dicts.
    Empty list if the section is absent or contains the
    `_(none — every hit ...)_` marker.
    """
    if not report_path.exists():
        return []
    in_section = False
    out: list[dict] = []
    last_hit: dict | None = None
    for ln in report_path.read_text(errors="replace").splitlines():
        if ln.startswith("## No close historical match"):
            in_section = True
            continue
        if in_section:
            if ln.startswith("## "):
                break  # next top-level section
            if "_(none" in ln:
                return []
            m = _MINING_LINE.match(ln)
            if m:
                last_hit = {
                    "detector": m.group("det"),
                    "severity": m.group("sev"),
                    "file":     m.group("file"),
                    "line":     m.group("line"),
                    "snippet":  "",
                }
                out.append(last_hit)
                continue
            sub = re.match(r"^\s+-\s+(?P<snip>.+)$", ln)
            if sub and last_hit is not None and not last_hit["snippet"]:
                last_hit["snippet"] = sub.group("snip").strip()[:240]
    return out


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


# V5 Gap-22: classify dispatch-brief subprocess errors as SOFT-SKIP
# (offline/setup/transient — audit chain can continue) vs HARD-FATAL
# (malformed args / wrong paths — audit chain MUST stop).
#
# The dispatch tools (`tools/dispatch-brief.sh`, `tools/agent-dispatch-enforced.sh`)
# emit specific exit codes and stderr+stdout markers we pattern-match on:
#
#   * exit 2 + usage stderr           → HARD: missing CLI args (caller bug)
#   * exit 1 + "workspace not found"  → HARD: path not on disk (caller bug)
#   * exit 1 + "contract not found"   → HARD: path not on disk (caller bug)
#   * exit 1 + "HARD STOP"            → SOFT: missing OOS/CAPS/PRIOR setup
#                                       (workspace prep gap, not chain-killer).
#                                       NOTE: agent-dispatch-enforced.sh emits
#                                       this on STDOUT, not stderr — the
#                                       classifier scans both streams (Kimi
#                                       pre-review confirmed: foot-gun would
#                                       be stderr-only matching).
#   * exit 4 + "brief empty"          → SOFT: dispatch produced no output
#   * stderr/stdout matches /(api|    → SOFT: provider unreachable / auth
#       network|unauthorized|consent| failed; chain can continue offline.
#       offline|cannot-run|timeout|
#       429|5\d\d)/i
#   * any other non-zero exit          → SOFT (default lenient: avoid
#                                       chain-halts on unclassified errors;
#                                       Codex Gap-22 prefers continuation)
#
# This boundary is documented so future maintainers can extend the soft
# class with new offline markers without reading the full call site.
_DISPATCH_BRIEF_HARD_STDERR = re.compile(
    r"workspace not found|contract not found|Unknown arg:|^Usage:\s|"
    r"\[HARD\]|HARD STOP|prior_audits/.*DIGEST",
    re.IGNORECASE | re.MULTILINE,
)
_DISPATCH_BRIEF_SOFT_STDERR = re.compile(
    r"brief empty|api[- ]?key|cannot-run|no-consent|"
    r"unauthorized|forbidden|network|offline|timeout|"
    r"\b(?:429|5\d\d)\b",
    re.IGNORECASE,
)


def _classify_dispatch_brief_error(rc: int, stderr: str, stdout: str) -> str:
    """V5 Gap-22 classifier. Returns ``"hard"`` or ``"soft"``.

    Mapping (see comment above for rationale):
      rc == 0                               → "soft" (defensive; not invoked)
      rc == 2                               → "hard" (CLI usage / args)
      stderr/stdout matches HARD markers    → "hard" (caller wrong path)
      stderr/stdout matches SOFT markers    → "soft"
      otherwise (default lenient)           → "soft"

    Both streams are scanned because `agent-dispatch-enforced.sh` emits
    its `=== HARD STOP ===` marker on stdout (verified empirically;
    Kimi pre-review flagged the stderr-only foot-gun).
    """
    if rc == 0:
        # Caller should not invoke us on success; treat defensively as soft.
        return "soft"
    blob = (stderr or "") + "\n" + (stdout or "")
    # Hard markers take precedence — these signal caller-bug paths that
    # downstream stages cannot recover from.
    if rc == 2:
        return "hard"
    if _DISPATCH_BRIEF_HARD_STDERR.search(blob):
        return "hard"
    if _DISPATCH_BRIEF_SOFT_STDERR.search(blob):
        return "soft"
    # Unknown shape: prefer SOFT to keep the chain moving (Gap-22 directive).
    return "soft"


def _source_root_candidates(ws: Path) -> list[Path]:
    """Return likely protocol source roots for nested-workspace path repair."""
    roots: list[Path] = []
    readiness = ws / ".auditooor" / "project_source_root_readiness.json"
    try:
        payload = json.loads(readiness.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    for row in payload.get("roots", []) if isinstance(payload, dict) else []:
        if not isinstance(row, dict):
            continue
        for key in ("resolved_path", "workspace_relative_path", "declared_path"):
            raw = str(row.get(key) or "").strip()
            if not raw:
                continue
            p = Path(raw)
            if not p.is_absolute():
                p = ws / p
            roots.append(p)
    roots.extend(
        [
            ws,
            ws / "contracts",
            ws / "src",
            ws / "external" / "contracts",
            ws / "external" / "contracts" / "src",
        ]
    )
    # Multi-repository workspaces commonly clone repositories below
    # ``<workspace>/src/<repo>``. Scanner manifests still report paths such
    # as ``src/Foo.sol`` relative to the repository root, so include the
    # nested repository source roots when repairing those paths.
    for pattern in (
        "external/*/contracts",
        "external/*/src",
        "src/*/contracts",
        "src/*/src",
        "src/*/lib/*/contracts",
        "src/*/lib/*/src",
    ):
        roots.extend(ws.glob(pattern))
    out: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            resolved = root
        if resolved in seen:
            continue
        seen.add(resolved)
        out.append(resolved)
    return out


def _resolve_workspace_contract_path(ws: Path, contract: str) -> Path:
    """Resolve scanner-reported source paths across nested cloned repos."""
    raw = Path(contract)
    if raw.is_absolute():
        return raw
    direct = (ws / raw).resolve()
    if direct.is_file():
        return direct
    parts = raw.parts
    suffixes = [raw]
    # Scanner reports may be rendered relative to the auditooor repository,
    # for example ``../audits/project/src/Foo.sol``. Recover the portion below
    # the active workspace instead of treating that report-relative path as a
    # workspace-relative path.
    workspace_parts = [i for i, part in enumerate(parts) if part == ws.name]
    if workspace_parts and workspace_parts[-1] + 1 < len(parts):
        suffixes.append(Path(*parts[workspace_parts[-1] + 1 :]))
    if len(parts) > 1:
        suffixes.append(Path(*parts[1:]))
    if len(parts) > 2:
        suffixes.append(Path(*parts[-2:]))
    suffixes.append(Path(raw.name))
    for root in _source_root_candidates(ws):
        for suffix in suffixes:
            candidate = (root / suffix).resolve()
            if candidate.is_file():
                return candidate
    return direct


def stage_dispatch_brief(ws: Path, out_dir: Path, args) -> str:
    """Phase 45a: for each MINING-CANDIDATE cluster (no anchor + no cross-ws),
    invoke agent-dispatch-enforced.sh to compose a paste-ready agent brief.
    Output artifacts: <ws>/agent_outputs/dispatch_<slug>.md.

    Capped at DISPATCH_BRIEF_MAX briefs per run. Gracefully SKIPs when:
      - tool missing
      - engage_report.md missing
      - zero mining candidates (the empty/expected case)

    V5 Gap-22: subprocess failures are classified into "soft" (offline /
    setup gap — log WARN, mark SUCCESS_WARN, do NOT propagate to fail-fast
    halt) vs "hard" (malformed args / wrong path — keep current FAIL).
    See ``_classify_dispatch_brief_error`` for the boundary table.
    """
    if not DISPATCH_BRIEF_ENFORCED.exists() and not DISPATCH_BRIEF.exists():
        log("[stage: dispatch-brief] SKIPPED — agent-dispatch-enforced.sh "
            "and dispatch-brief.sh both missing", args.quiet)
        return "SKIPPED"
    report_path = out_dir / "engage_report.md"
    candidates = parse_mining_candidates(report_path)
    if not candidates:
        log("[stage: dispatch-brief] no mining candidates — SKIPPED",
            args.quiet)
        return "SKIPPED no mining candidates"

    # The report contains raw detector hits, but only hits with a completed
    # reasoning brief are eligible for a drive-phase dispatch. Preserve every
    # other hit as an explicit open obligation so it cannot disappear or be
    # mistaken for a hunt-ready candidate.
    grounded: list[dict] = []
    open_obligations: list[dict] = []
    for hit in candidates:
        contract_path = _resolve_workspace_contract_path(ws, hit["file"])
        context = get_proof_context(ws, contract_path.stem)
        row = dict(hit)
        row["resolved_contract"] = str(contract_path)
        row["matched_mining_brief"] = context.get("matched_brief")
        row["proof_context"] = bool(context.get("has_context"))
        if context.get("has_context"):
            grounded.append(row)
        else:
            row["obligation_status"] = "OPEN-missing-reasoning-context"
            open_obligations.append(row)
    obligation_path = ws / ".auditooor" / "dispatch_open_obligations.json"
    obligation_path.parent.mkdir(parents=True, exist_ok=True)
    obligation_path.write_text(json.dumps({
        "schema_version": "auditooor.dispatch_open_obligations.v1",
        "source": "engage_report.md",
        "total_report_candidates": len(candidates),
        "grounded_candidates": len(grounded),
        "open_count": len(open_obligations),
        "obligations": open_obligations,
    }, indent=2) + "\n")
    if open_obligations:
        log(
            f"[stage: dispatch-brief] {len(open_obligations)} raw candidate(s) remain "
            f"OPEN without reasoning context; recorded {obligation_path}",
            args.quiet,
        )
    candidates = grounded
    if not candidates:
        return "FAIL no proof-grounded dispatch candidates"

    tool = DISPATCH_BRIEF_ENFORCED if DISPATCH_BRIEF_ENFORCED.exists() \
           else DISPATCH_BRIEF
    out_subdir = ws / "agent_outputs"
    out_subdir.mkdir(parents=True, exist_ok=True)
    n = min(len(candidates), DISPATCH_BRIEF_MAX)
    log(f"[stage: dispatch-brief] composing {n} brief(s) "
        f"(of {len(candidates)} mining candidates) via {tool.name} ...",
        args.quiet)
    succeeded = 0
    warned = 0
    failed_hard = 0
    failed_soft = 0
    for hit in candidates[:n]:
        contract = hit["file"]
        contract_path = _resolve_workspace_contract_path(ws, contract)
        if not contract_path.is_file():
            log(f"[stage: dispatch-brief]   FAIL {contract} - file missing",
                args.quiet)
            failed_hard += 1
            continue
        slug = _slugify(f"{hit['detector']}_{contract_path.stem}_{hit['line']}")
        hyp = (
            f"Verify whether `{hit['detector']}` at "
            f"{contract_path.name}:{hit['line']} is a real bug. "
            f"Snippet: {hit['snippet']}"
        )
        rc, so, se = run([
            "bash", str(tool), str(ws), str(contract_path), hyp,
        ], 60)
        generated_brief = None
        brief_hint = (so or "").strip().splitlines()
        if brief_hint:
            last = brief_hint[-1].strip()
            if last:
                candidate = Path(last)
                if candidate.exists():
                    generated_brief = candidate
        if generated_brief is None:
            m = re.search(r"Brief:\s+(.+)", so or "")
            if m:
                candidate = Path(m.group(1).strip())
                if candidate.exists():
                    generated_brief = candidate
        out_path = out_subdir / f"dispatch_{slug}.md"
        out_path.write_text(
            f"# dispatch-brief: {hit['detector']} @ {Path(contract).name}:{hit['line']}\n\n"
            f"- exit_code: {rc}\n"
            f"- tool: {tool.name}\n\n"
            f"## stdout\n\n```\n{so.strip()[:4000]}\n```\n\n"
            f"## stderr\n\n```\n{se.strip()[:2000]}\n```\n"
        )
        if rc == 0:
            status = "SUCCESS"
            err_class = None
        else:
            err_class = _classify_dispatch_brief_error(rc, se, so)
            status = (
                f"FAIL rc={rc}" if err_class == "hard"
                else f"WARN rc={rc} (soft-skip)"
            )
        if rc == 0 and generated_brief is not None:
            text = generated_brief.read_text(errors="replace")
            if "no matching mining brief with proof context found" in text.lower():
                warned += 1
        elif rc != 0:
            if err_class == "hard":
                failed_hard += 1
            else:
                failed_soft += 1
                log(
                    f"[stage: dispatch-brief]   soft-skip {out_path.name} — "
                    f"reason: rc={rc} stderr={(se or '').strip()[:200]}",
                    args.quiet,
                )
        log(f"[stage: dispatch-brief]   {status} — {out_path.name}",
            args.quiet)
        if rc == 0:
            succeeded += 1
    suffix_parts: list[str] = []
    if warned:
        suffix_parts.append(f"{warned} missing proof context")
    if failed_soft:
        suffix_parts.append(f"{failed_soft} soft-skipped")
    if failed_hard:
        suffix_parts.append(f"{failed_hard} hard-failed")
    suffix = (", " + ", ".join(suffix_parts)) if suffix_parts else ""
    log(f"[stage: dispatch-brief] DONE — {succeeded}/{n} succeeded{suffix}",
        args.quiet)
    # Every missing proof-context handoff is a hard gate. A dispatch brief
    # without its matched mining context cannot safely feed a downstream hunt.
    # Keep subprocess setup failures distinct, but never let missing evidence
    # continue as an advisory warning.
    if failed_hard:
        return f"FAIL {failed_hard}/{n}"
    if warned:
        if failed_soft:
            return (
                f"FAIL missing proof context in {warned}/{n}; "
                f"{failed_soft} dispatch subprocess soft-fail(s)"
            )
        return f"FAIL missing proof context in {warned}/{n}"
    if failed_soft:
        return f"SUCCESS_WARN soft-skipped {failed_soft}/{n}"
    return f"SUCCESS {succeeded} briefs"


def stage_capture_intel(ws: Path, args) -> int:
    """Phase 45a: invoke capture-intel.sh to fold an `engage tick` checkpoint
    marker into the workspace's running EXTERNAL_INTEL.md log.

    capture-intel.sh reads stdin and appends to EXTERNAL_INTEL.md. We feed
    it a one-line checkpoint so the stage stays graceful even when no fresh
    intel is queued (the tool errors out on empty stdin).
    """
    if not CAPTURE_INTEL.exists():
        log("[stage: capture-intel] SKIPPED — capture-intel.sh missing",
            args.quiet)
        return 0
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    title = f"engage tick {ts}"
    payload = (
        f"engage.py --stage capture-intel checkpoint at {ts}. "
        "No new external intel queued; this marker confirms the stage ran."
    )
    try:
        proc = subprocess.run(
            ["bash", str(CAPTURE_INTEL), str(ws), title],
            input=payload, text=True, capture_output=True,
            timeout=30, errors="replace",
        )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        rc = 124
    except Exception as e:
        log(f"[stage: capture-intel] FAIL — {e!r}", args.quiet)
        return 0
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    log(f"[stage: capture-intel] {status} — {ws}/EXTERNAL_INTEL.md",
        args.quiet)
    return 0


def stage_record_triage(ws: Path, out_dir: Path, args) -> int:
    """Phase 45a: log triage decisions to the audit ledger.

    record-triage.sh signature: `<detector> <workspace> <finding-id> <verdict>`.
    Engage runs are pre-triage by definition — no human verdict yet — so we
    record one UNKNOWN row per MINING-CANDIDATE detector to keep the ledger
    sync'd with the engagement. Verdicts are later overwritten via direct
    record-triage.sh invocations after a human triages each hit (the script
    is idempotent on (detector, workspace, finding) tuples).
    """
    if not RECORD_TRIAGE.exists():
        log("[stage: record-triage] SKIPPED — record-triage.sh missing",
            args.quiet)
        return 0
    candidates = parse_mining_candidates(out_dir / "engage_report.md")
    if not candidates:
        log("[stage: record-triage] no mining candidates — SKIPPED",
            args.quiet)
        return 0
    ws_name = ws.name
    seen: set[tuple[str, str]] = set()
    n_logged = 0
    n_failed = 0
    for hit in candidates:
        key = (hit["detector"], f"{Path(hit['file']).name}:{hit['line']}")
        if key in seen:
            continue
        seen.add(key)
        finding_id = f"engage-{key[1]}"
        rc, _so, se = run(
            ["bash", str(RECORD_TRIAGE), hit["detector"], ws_name,
             finding_id, "UNKNOWN"], 30)
        if rc == 0:
            n_logged += 1
        else:
            n_failed += 1
            if se:
                log(f"[stage: record-triage]   FAIL {hit['detector']} — "
                    f"{se.strip()[:200]}", args.quiet)
    log(f"[stage: record-triage] DONE — {n_logged} rows recorded, "
        f"{n_failed} failed", args.quiet)
    return 0


# ----------------------------- Phase 45b stages ----------------------------- #

def stage_pre_submit(ws: Path, args) -> str | int:
    """Phase 45b: run pre-submit-check.sh on every clean-rendered submission.

    Scans <ws>/submissions/clean/*.md and
          <ws>/submissions/engage_candidates/clean/*.md and gates each
    candidate through the current 22-check pre-submit gate (rubric citation,
    $ impact, OOS clause, PoC/test evidence, originality, dupe-risk,
    scope-review, rejection history, realism checks, and related hard guards).

    Aggregates PASS / FAIL counts and reports them in the stage status so the
    summary reflects real gate outcomes.
    """
    if not PRE_SUBMIT_CHECK.exists():
        log("[stage: pre-submit] SKIPPED — pre-submit-check.sh missing",
            args.quiet)
        return "SKIPPED"
    candidates: list[Path] = []
    for sub in (ws / "submissions" / "clean",
                ws / "submissions" / "engage_candidates" / "clean"):
        if sub.is_dir():
            candidates.extend(sorted(p for p in sub.glob("*.md")
                                      if p.name.upper() != "INDEX.MD"))
    if not candidates:
        log("[stage: pre-submit] SKIPPED — no clean submissions found "
            "(submissions/clean/*.md or submissions/engage_candidates/clean/*.md)",
            args.quiet)
        return "SKIPPED"
    log(f"[stage: pre-submit] running on {len(candidates)} candidate(s) "
        f"(timeout {SYNTHESIS_TIMEOUT}s each) ...", args.quiet)
    n_pass = 0
    n_fail = 0
    for f in candidates:
        try:
            rel = f.relative_to(ws)
        except ValueError:
            rel = Path(f.name)
        rc, _so, _se = run(["bash", str(PRE_SUBMIT_CHECK), str(f)],
                           SYNTHESIS_TIMEOUT)
        if rc == 0:
            n_pass += 1
            log(f"[stage: pre-submit]   PASS {rel}", args.quiet)
        else:
            n_fail += 1
            log(f"[stage: pre-submit]   FAIL rc={rc} {rel}", args.quiet)
    log(f"[stage: pre-submit] {n_pass} PASS / {n_fail} FAIL "
        f"(of {len(candidates)})", args.quiet)
    if n_fail:
        return f"FAIL {n_fail}/{len(candidates)}"
    return f"SUCCESS {n_pass} PASS"


# ---------------------------------------------------------------------------
# pre-submit-llm-review — delegates dual-LLM scope+severity review to the
# standalone `tools/llm-scope-triage.py` (single source of truth).
#
# Wires the Kimi+Minimax dual-LLM pipeline (already validated by
# `tools/llm-pr-review.py` and `tools/llm-pr-review-merge-hook.py`) into the
# canonical close-out chain so every draft gets a consensus check BEFORE the
# submission ledger close-out. Mechanics:
#
#   1. Walk staging drafts via `_collect_drafts(ws)` (same helper used by
#      quality-score / auto-fix / package).
#   2. Invoke `tools/llm-scope-triage.py` per draft. The standalone tool:
#        * loads `OOS_CHECKLIST.md` + `SEVERITY_CAPS.md` from the engagement
#          directory (engagement = ws.name, engage-root = ws.parent),
#        * asks Kimi + Minimax for a structured SCOPE/SEVERITY/CONFIDENCE
#          verdict,
#        * computes consensus,
#        * writes a per-finding JSON artefact,
#        * appends `scope-triage` rows with `INDETERMINATE` verdicts to the
#          calibration ledger (correct semantics — see Codex P0 #2).
#   3. Read each artefact and map the consensus into the engage stage's
#      vocabulary (AGREED-IN-SCOPE / AGREED-OFF-SCOPE / DISAGREED /
#      LLM-FAILURE) for `_classify_pre_submit_llm_outcomes`.
#   4. Copy the artefact into `<ws>/submissions/llm_review/draft_<slug>.json`
#      so the stage's published artefact contract is unchanged.
#   5. Aggregate into a stage status:
#         SUCCESS_WARN  if any draft got AGREED-OFF-SCOPE (advisory until
#                       scope-triage calibration matures — see
#                       PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE for the
#                       future opt-in hard-block path; Codex HOLD on PR #227)
#         SUCCESS_WARN  if no AGREED-OFF-SCOPE but >=1 DISAGREED or no drafts
#         SUCCESS       otherwise (every draft got AGREED-IN-SCOPE)
#         SKIPPED       when `llm-scope-triage.py` is missing OR every
#                       invocation fails (offline-safe: agent test envs
#                       typically have no API keys; we never hard-fail).
#
# Codex P0 fixes baked in (2026-04-26 review of PR #220):
#   1. Reuses scope-triage tool — the engage stage no longer re-invents a
#      WEAKER prompt that omits `OOS_CHECKLIST.md` / `SEVERITY_CAPS.md`.
#   2. Calibration logging is delegated to the standalone tool, which writes
#      `scope-triage` task-type with `INDETERMINATE` verdict (the human-
#      verified TRUE/FALSE comes later when triage outcomes confirm the
#      LLM call). The old buggy mapping (`pr-review` task-type +
#      IN-SCOPE→TRUE / OFF-SCOPE→FALSE before human verification) is gone.
#
# Idempotency: the standalone tool's prompt is byte-stable for identical
# inputs, so the prompt_hash dedup the calibration ledger uses still holds
# across re-runs on unchanged drafts.
# ---------------------------------------------------------------------------

PRE_SUBMIT_LLM_VERDICTS = (
    "IN-SCOPE", "OFF-SCOPE", "NEEDS-MORE-EVIDENCE", "SEVERITY-OVERSTATED",
)

# Opt-in switch for the FUTURE hard-block mode on consensus AGREED-OFF-SCOPE.
#
# Codex review of PR #227 (HOLD comment-4321534683) flagged that hard-FAILing
# on AGREED-OFF-SCOPE while the calibration ledger has only ONE `scope-triage`
# row preserves exactly the risky gate behavior #224 called out: a single
# false-positive OOS classification would block a real submission.
#
# Default: advisory. AGREED-OFF-SCOPE classifies as SUCCESS_WARN so the chain
# surfaces the warning to the operator (and the per-draft artefact + scope-
# triage ledger row both still land) without auto-blocking `track-submissions`.
#
# Opt-in: when this constant flips to True (or a future flag wires it from
# config), AGREED-OFF-SCOPE restores its FAIL semantics. Flip the switch only
# AFTER N verified-no-false-blocking `scope-triage` rows accumulate on the
# calibration ledger (target: at least the same order of magnitude that the
# `pr-review` task-type already has — see `tools/calibration/` for current
# counts). Until then, hard-blocking is unsafe.
PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE = False


def _classify_pre_submit_llm_outcomes(
    consensuses: list[str],
) -> str:
    """Classifier for the stage status. Pure / unit-testable.

    Args:
        consensuses: list of consensus labels — one per draft. Vocabulary:
                     AGREED-IN-SCOPE / AGREED-OFF-SCOPE / DISAGREED /
                     LLM-FAILURE.

    Returns:
        FAIL / SUCCESS_WARN / SUCCESS / SKIPPED.

    Note on AGREED-OFF-SCOPE:
        Default behaviour is ADVISORY (SUCCESS_WARN). The risky hard-block
        path is gated behind ``PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE``
        and stays off until scope-triage calibration matures (see the module-
        level constant for the rationale).
    """
    if not consensuses:
        return "SUCCESS_WARN no drafts to review"
    # All dispatches failed — degrade to SKIPPED so a missing API key in a
    # test env doesn't block the chain.
    if all(c == "LLM-FAILURE" for c in consensuses):
        return "SKIPPED dispatch unavailable"
    n_off    = sum(1 for c in consensuses if c == "AGREED-OFF-SCOPE")
    n_disagr = sum(1 for c in consensuses if c == "DISAGREED")
    n_fail   = sum(1 for c in consensuses if c == "LLM-FAILURE")
    n_total  = len(consensuses)
    if n_off and PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE:
        # Future opt-in path: restore the original hard-block semantics
        # once the scope-triage calibration ledger has enough verified-no-
        # false-blocking rows to trust HIGH/MEDIUM-confidence OOS verdicts.
        return f"FAIL {n_off}/{n_total} AGREED-OFF-SCOPE"
    if n_off:
        # Advisory default (Codex HOLD on PR #227): surface the warning but
        # do not block `track-submissions`. The per-draft artefact + scope-
        # triage ledger row still land; an operator can act on the warning.
        return (f"SUCCESS_WARN {n_off}/{n_total} AGREED-OFF-SCOPE (advisory; "
                "scope-triage calibration immature)"
                + (f" + {n_disagr} DISAGREED" if n_disagr else "")
                + (f" + {n_fail} dispatch-fail" if n_fail else ""))
    if n_disagr:
        return (f"SUCCESS_WARN {n_disagr}/{n_total} DISAGREED"
                + (f" ({n_fail} dispatch-fail)" if n_fail else ""))
    if n_fail:
        return f"SUCCESS_WARN {n_fail}/{n_total} dispatch-fail"
    return f"SUCCESS {n_total} draft(s) AGREED-IN-SCOPE"


def _scope_triage_consensus_to_label(
    consensus: dict | None,
    *,
    errors: list | None = None,
) -> str:
    """Map a `tools/llm-scope-triage.py` consensus dict to the engage
    stage's consensus vocabulary.

    The standalone tool emits ``confidence`` ∈ {HIGH, MEDIUM, LOW, DISAGREED}
    and ``scope`` ∈ {IN_SCOPE, OOS_<KEY>_<N>, None}. We collapse those into:

      AGREED-IN-SCOPE   - confidence in {HIGH, MEDIUM} AND scope == IN_SCOPE
      AGREED-OFF-SCOPE  - confidence in {HIGH, MEDIUM} AND scope startswith OOS_
      DISAGREED         - confidence == DISAGREED, OR confidence == LOW (the
                          tool flags LOW-confidence consensus as not
                          actionable — treat as DISAGREED for the gate)
      LLM-FAILURE       - missing consensus, or both providers errored
                          (every entry in `errors` indicates a failed call).
    """
    if not consensus:
        return "LLM-FAILURE"
    confidence = (consensus.get("confidence") or "").upper()
    scope = (consensus.get("scope") or "").upper()
    if not confidence:
        return "LLM-FAILURE"
    # The standalone tool reports DISAGREED when at least one side missed
    # the scope tag (e.g. dispatch failure). If BOTH sides missed it the
    # ``errors`` field will list both providers as failed — promote to
    # LLM-FAILURE so SKIPPED is reachable in offline test envs.
    if confidence == "DISAGREED":
        if errors:
            failed_providers = {
                e.split("-failed", 1)[0]
                for e in errors
                if isinstance(e, str) and "-failed" in e
            }
            if {"kimi", "minimax"}.issubset(failed_providers):
                return "LLM-FAILURE"
        return "DISAGREED"
    if confidence == "LOW":
        # LOW-confidence agreement is not actionable as an OFF-SCOPE block —
        # surface it as DISAGREED so a human reviews before track-submissions.
        return "DISAGREED"
    if confidence in ("HIGH", "MEDIUM"):
        if scope == "IN_SCOPE":
            return "AGREED-IN-SCOPE"
        if scope.startswith("OOS_"):
            return "AGREED-OFF-SCOPE"
        return "DISAGREED"
    return "LLM-FAILURE"


def _invoke_scope_triage(
    draft: Path,
    *,
    engagement: str,
    engage_root: Path,
    output_dir: Path,
    timeout: float,
) -> tuple[int, str, str]:
    """Run `tools/llm-scope-triage.py` for one finding draft.

    Returns (rc, stdout, stderr). Offline-safe: any subprocess failure is
    bubbled up as rc!=0 and the caller treats it as a dispatch-failure
    (no exception). The standalone tool itself handles missing API keys
    gracefully (raises per-provider errors that surface in the artefact's
    ``errors`` list).
    """
    if not LLM_SCOPE_TRIAGE.exists():
        return 127, "", f"missing-tool: {LLM_SCOPE_TRIAGE}"
    env = dict(os.environ)
    env.setdefault("AUDITOOOR_LLM_NETWORK_CONSENT", "1")
    cmd = [
        sys.executable, str(LLM_SCOPE_TRIAGE),
        str(draft),
        "--engagement", engagement,
        "--engage-root", str(engage_root),
        "--output-dir", str(output_dir),
        "--timeout", str(timeout),
    ]
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True,
            timeout=timeout * 4 + 60,
        )
        return proc.returncode, (proc.stdout or ""), (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "", "scope-triage timeout"
    except Exception as e:
        return 1, "", repr(e)


def _find_scope_triage_artefact(
    triage_dir: Path,
    *,
    engagement: str,
    draft: Path,
) -> Path | None:
    """Locate the per-finding artefact written by `llm-scope-triage.py`.

    Filename pattern is ``triage-{engagement}-{draft.stem}-{hash[:12]}.json``.
    Multiple runs can leave multiple artefacts — return the most recently
    modified one (the one this stage just wrote).
    """
    if not triage_dir.is_dir():
        return None
    pattern = f"triage-{engagement}-{draft.stem}-*.json"
    matches = sorted(
        triage_dir.glob(pattern),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return matches[0] if matches else None


def stage_pre_submit_llm_review(ws: Path, args) -> str:
    """Dual-LLM (Kimi + Minimax) scope+severity review of every staging draft.

    Delegates to ``tools/llm-scope-triage.py`` so the engagement's
    ``OOS_CHECKLIST.md`` and ``SEVERITY_CAPS.md`` drive the prompt — fixing
    Codex P0 #1 (the prior inline prompt was weaker than the standalone tool
    because it omitted scope context). The standalone tool also writes the
    correct calibration row shape (``scope-triage`` task-type +
    ``INDETERMINATE`` verdict) — fixing Codex P0 #2.

    Idempotent: the standalone tool's prompt is byte-stable for identical
    inputs, so the prompt_hash dedup the calibration ledger uses still holds
    across re-runs on unchanged drafts. Offline-safe: when
    ``llm-scope-triage.py`` is missing or every invocation returns rc!=0
    (typical in a test env with no API keys), the stage degrades to
    ``SKIPPED dispatch unavailable`` rather than failing the chain.
    """
    drafts = _collect_drafts(ws)
    if not drafts:
        log("[stage: pre-submit-llm-review] SUCCESS_WARN — no drafts to "
            "review (submissions/staging/ empty)", args.quiet)
        return "SUCCESS_WARN no drafts to review"

    if not LLM_SCOPE_TRIAGE.exists():
        log("[stage: pre-submit-llm-review] SKIPPED — llm-scope-triage.py "
            "missing (offline-safe degrade)", args.quiet)
        return "SKIPPED dispatch unavailable"

    out_dir = ws / "submissions" / "llm_review"
    out_dir.mkdir(parents=True, exist_ok=True)
    triage_dir = out_dir / "_triage"
    triage_dir.mkdir(parents=True, exist_ok=True)
    timeout = float(PRE_SUBMIT_LLM_TIMEOUT)
    engagement = ws.name
    engage_root = ws.parent
    log(f"[stage: pre-submit-llm-review] reviewing {len(drafts)} draft(s) "
        f"via tools/llm-scope-triage.py "
        f"(engagement={engagement}, timeout {int(timeout)}s/provider) ...",
        args.quiet)

    consensuses: list[str] = []

    for draft in drafts:
        rc, out, err = _invoke_scope_triage(
            draft,
            engagement=engagement,
            engage_root=engage_root,
            output_dir=triage_dir,
            timeout=timeout,
        )
        artefact_path = _find_scope_triage_artefact(
            triage_dir, engagement=engagement, draft=draft,
        )
        if rc != 0 and artefact_path is None:
            log(f"[stage: pre-submit-llm-review]   "
                f"{draft.name}: LLM-FAILURE (rc={rc} {err.strip()[:160]})",
                args.quiet)
            consensuses.append("LLM-FAILURE")
            continue

        record: dict | None = None
        if artefact_path is not None:
            try:
                record = json.loads(artefact_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                log(f"[stage: pre-submit-llm-review]   "
                    f"{draft.name}: artefact-parse-fail {e}", args.quiet)
                record = None

        consensus_dict = (record or {}).get("consensus")
        errors = (record or {}).get("errors") or []
        consensus = _scope_triage_consensus_to_label(
            consensus_dict, errors=errors,
        )
        consensuses.append(consensus)

        # Mirror the artefact under the canonical engage path for the
        # published artefact contract (see SUMMARY_ARTIFACT_PATTERNS).
        try:
            stage_artefact = {
                "draft": (
                    str(draft.relative_to(ws))
                    if ws in draft.parents else str(draft)
                ),
                "engagement": engagement,
                "consensus": consensus,
                "scope_triage_artefact": (
                    str(artefact_path) if artefact_path else None
                ),
                "scope_triage_record": record,
                "scope_triage_rc": rc,
                "scope_triage_stderr_tail": (err or "").strip()[-400:],
            }
            (out_dir / f"draft_{draft.stem}.json").write_text(
                json.dumps(stage_artefact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError as e:
            log(f"[stage: pre-submit-llm-review]   artefact-write-fail "
                f"{draft.name}: {e}", args.quiet)

        log(f"[stage: pre-submit-llm-review]   {draft.name}: {consensus}",
            args.quiet)

    status = _classify_pre_submit_llm_outcomes(consensuses)
    log(f"[stage: pre-submit-llm-review] {status}", args.quiet)
    return status


def stage_rejection_learn(ws: Path, args) -> int:
    """Phase 45b: feed Cantina rejection outcomes into the classifier.

    rejection-learn.sh accepts <workspace> [<workspace> ...] and walks the
    active workspace submission ledger for submitted findings missing
    rationale.txt. If there is no submissions data, skip gracefully.
    """
    if not REJECTION_LEARN.exists():
        log("[stage: rejection-learn] SKIPPED — rejection-learn.sh missing",
            args.quiet)
        return 0
    subs_md = find_submission_file(ws)
    if subs_md is None:
        log("[stage: rejection-learn] SKIPPED — no SUBMISSIONS.md "
            "(no triage data to learn from)", args.quiet)
        return 0
    log(f"[stage: rejection-learn] running on {ws} "
        f"(timeout {SYNTHESIS_TIMEOUT}s) ...", args.quiet)
    rc, _so, se = run(["bash", str(REJECTION_LEARN), str(ws)],
                      SYNTHESIS_TIMEOUT)
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    log(f"[stage: rejection-learn] {status}", args.quiet)
    if rc != 0 and se:
        log(f"[stage: rejection-learn]   stderr: {se.strip()[:400]}",
            args.quiet)
    return 0


def stage_campaign_source_mine(ws: Path, args) -> str:
    """V5 G1: opt-in source-mining campaign at the end of `make audit`.

    The campaign is intentionally off by default because it spends LLM tokens.
    When explicitly enabled, missing network consent is a hard, loud failure so
    operators do not mistake "0 survivors" for a real mining result.
    """
    if os.environ.get("CAMPAIGN_SOURCE_MINE") != "1":
        log(
            "[stage: campaign-source-mine] SKIPPED opt-in disabled "
            "(set CAMPAIGN_SOURCE_MINE=1 to run)",
            args.quiet,
        )
        return "SKIPPED opt-in disabled"
    if not SOURCE_MINING_CAMPAIGN.exists():
        log("[stage: campaign-source-mine] FAIL source-mining-campaign.py missing",
            args.quiet)
        return "FAIL missing tool"
    if os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") != "1":
        log(
            "[stage: campaign-source-mine] FAIL cannot-run: "
            "CAMPAIGN_SOURCE_MINE=1 requires AUDITOOOR_LLM_NETWORK_CONSENT=1",
            args.quiet,
        )
        return "FAIL cannot-run: no-network-consent"

    out_dir = ws / "source_mining" / "engage-latest"
    cmd = [
        sys.executable,
        str(SOURCE_MINING_CAMPAIGN),
        "--workspace",
        str(ws),
        "--out",
        str(out_dir),
    ]
    log(
        f"[stage: campaign-source-mine] running source-mining campaign -> "
        f"{out_dir} (timeout {CAMPAIGN_TIMEOUT}s)",
        args.quiet,
    )
    rc, so, se = run(cmd, CAMPAIGN_TIMEOUT)
    if so.strip():
        log(f"[stage: campaign-source-mine]   stdout: {so.strip()[-400:]}",
            args.quiet)
    if rc == 0:
        log("[stage: campaign-source-mine] SUCCESS", args.quiet)
        return "SUCCESS"
    if se.strip():
        log(f"[stage: campaign-source-mine]   stderr: {se.strip()[-600:]}",
            args.quiet)
    if rc == 124:
        # Partial-progress timeout: the campaign tool's per-packet resume
        # cache (packets/<domain>_<provider>_done.json) means a re-run
        # picks up where the wrapper killed it. Surface this to the
        # operator as TIMEOUT_PARTIAL so it's distinguishable from a
        # generic FAIL.
        status = "TIMEOUT_PARTIAL re-run to resume"
    else:
        status = f"FAIL rc={rc}"
    log(f"[stage: campaign-source-mine] {status}", args.quiet)
    return status


def stage_corpus_detectorization(ws: Path, args) -> str:
    """PR #560 Lane 4: advisory corpus-to-detector/harness inventory.

    This stage makes `make audit` discover Swival/ZKBugs/ReCon/source-mining
    corpus rows, but it is intentionally impact-neutral. The inventory rows
    remain detector/harness tasks until a downstream exact impact contract
    proves a selected program-impact row.
    """
    if not CORPUS_DETECTORIZATION_INVENTORY.exists():
        log(
            "[stage: corpus-detectorization] SKIPPED missing "
            "corpus-detectorization-inventory.py",
            args.quiet,
        )
        return "SKIPPED missing tool"

    out_dir = ws / ".auditooor"
    cmd = [
        sys.executable,
        str(CORPUS_DETECTORIZATION_INVENTORY),
        "--workspace",
        str(ws),
        "--out-dir",
        str(out_dir),
    ]
    log(
        f"[stage: corpus-detectorization] running advisory inventory -> "
        f"{out_dir} (timeout {CORPUS_DETECTORIZATION_TIMEOUT}s)",
        args.quiet,
    )
    rc, so, se = run(cmd, CORPUS_DETECTORIZATION_TIMEOUT)
    if so.strip():
        log(f"[stage: corpus-detectorization]   stdout: {so.strip()[-400:]}",
            args.quiet)
    if se.strip():
        log(f"[stage: corpus-detectorization]   stderr: {se.strip()[-600:]}",
            args.quiet)
    if rc == 0:
        inventory = out_dir / "corpus_detectorization_inventory.json"
        row_count = None
        if inventory.is_file():
            try:
                payload = json.loads(inventory.read_text(encoding="utf-8"))
                row_count = (payload.get("summary") or {}).get("row_count")
            except Exception:
                row_count = None
        suffix = f" rows={row_count}" if row_count is not None else ""
        log(f"[stage: corpus-detectorization] SUCCESS{suffix}", args.quiet)
        return "SUCCESS"
    if rc == 124:
        status = "SUCCESS_WARN timeout"
    else:
        status = f"SUCCESS_WARN rc={rc}"
    log(f"[stage: corpus-detectorization] {status}", args.quiet)
    return status


def _per_asset_dispatch_traces(ws: Path) -> dict[str, list[str]]:
    """Bucket agent_outputs/dispatch_*.md files by asset based on the file
    paths they reference matching each asset's `roots` list.

    Returns {asset: [dispatch filename, ...]}.
    """
    payload = _load_intake_baseline(ws)
    plan = payload.get("asset_coverage_plan") or {}
    assets = payload.get("assets_in_scope") or []
    result: dict[str, list[str]] = {asset: [] for asset in assets}
    agent_dir = ws / "agent_outputs"
    if not agent_dir.is_dir():
        return result
    trace_files = sorted({
        *agent_dir.glob("dispatch_*.md"),
        *agent_dir.glob("brief_*.md"),
    })
    for disp in trace_files:
        try:
            text = disp.read_text(errors="ignore")
        except OSError:
            continue
        # dispatch-brief writes a small wrapper file whose stdout points at the
        # full generated brief. The asset roots usually live in that linked
        # brief, so include it in the text scanned by the retro gate.
        for match in re.finditer(r"(?:Brief:|^/)[ \t]*(?P<path>/[^\s`]+brief_[^\s`]+\.md)", text, re.MULTILINE):
            linked = Path(match.group("path"))
            try:
                if linked.is_file() and linked.resolve().is_relative_to(agent_dir.resolve()):
                    text += "\n" + linked.read_text(errors="ignore")
            except (OSError, RuntimeError):
                continue
        for asset in assets:
            entry = plan.get(asset, {}) if isinstance(plan, dict) else {}
            roots = entry.get("roots") or []
            for root in roots:
                if root and root in text:
                    result.setdefault(asset, []).append(disp.name)
                    break
    return result


def _total_dispatch_count(ws: Path) -> int:
    """Count generated dispatch and brief files under <ws>/agent_outputs/."""
    agent_dir = ws / "agent_outputs"
    if not agent_dir.is_dir():
        return 0
    return len({
        *agent_dir.glob("dispatch_*.md"),
        *agent_dir.glob("brief_*.md"),
    })


def _spawn_worker_event_count(ws: Path) -> int:
    log_path = ws / ".auditooor" / "spawn_worker_events.jsonl"
    if not log_path.is_file():
        return 0
    count = 0
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and not row.get("refused"):
            count += 1
    return count


def _non_dispatch_agent_output_count(ws: Path) -> int:
    agent_dir = ws / "agent_outputs"
    if not agent_dir.is_dir():
        return 0
    count = 0
    for path in agent_dir.iterdir():
        if not path.is_file():
            continue
        name = path.name
        if name.startswith(("dispatch_", "brief_")):
            continue
        count += 1
    return count


def _submission_activity_count(ws: Path) -> int:
    sub_dir = ws / "submissions"
    if not sub_dir.is_dir():
        return 0
    count = 0
    status_dirs = (
        "staging",
        "ready",
        "paste_ready",
        "filed",
        "packaged",
        "held",
        "superseded",
    )
    for status in status_dirs:
        root = sub_dir / status
        if not root.is_dir():
            continue
        count += sum(1 for p in root.rglob("*.md") if p.is_file())
        count += sum(1 for p in root.rglob("*.json") if p.is_file())
    return count


def _fresh_workspace_without_worker_activity(ws: Path) -> bool:
    """True when audit has only generated setup or brief artifacts so far."""
    return (
        _spawn_worker_event_count(ws) == 0
        and _non_dispatch_agent_output_count(ws) == 0
        and _submission_activity_count(ws) == 0
    )


def _asset_retro_gate(ws: Path) -> tuple[str, list[str]]:
    """Return (verdict, errors) where verdict is one of:

      - ``"ok"``    : every in-scope asset has a dispatch trace or waiver.
      - ``"warn"``  : missing-coverage on a fresh engagement (no worker
        spawn events, no non-dispatch agent outputs, no submission activity).
        A brand-new workspace can have generated dispatch briefs before any
        worker has produced asset coverage, so those planning files are not
        enough to make the retro gate hard-fail.
      - ``"fail"``  : dispatches exist but at least one in-scope asset
        has no trace AND no ``ASSET_WAIVER_<asset>.md`` file. Operator
        is selectively skipping coverage; this stays a hard block.
    """
    payload = _load_intake_baseline(ws)
    assets = payload.get("assets_in_scope") or []
    if not assets:
        return ("ok", [])
    traces = _per_asset_dispatch_traces(ws)
    errors: list[str] = []
    for asset in assets:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", asset).strip("_")
        waiver = ws / f"ASSET_WAIVER_{slug}.md"
        if traces.get(asset):
            continue
        if waiver.is_file() and waiver.stat().st_size > 0:
            continue
        errors.append(
            f"asset '{asset}' has 0 dispatch traces in agent_outputs/ "
            f"and no {waiver.name} waiver"
        )
    if not errors:
        return ("ok", [])
    # I-16 / CAP-GAP-90: distinguish fresh engagement setup from real worker
    # or submission activity. Generated dispatch briefs alone do not prove
    # the operator has had a chance to cover every in-scope asset.
    if _fresh_workspace_without_worker_activity(ws):
        return ("warn", errors)
    return ("fail", errors)


def stage_engagement_retro(ws: Path, args) -> str:
    """Phase 45b: per-engagement retrospective (Issue #135).

    engagement-retro.sh writes <ws>/RETROSPECTIVE.md and updates the
    cross-engagement recurring-bug-families corpus.

    Gap E: enforce at least one dispatch trace OR explicit operator waiver
    per in-scope asset. Fail closed when no evidence exists.

    I-16 / CAP-GAP-90: a fresh workspace with no worker or submission
    activity cannot satisfy that gate yet. Generated dispatch briefs alone
    are planning artifacts, so the stage softens to ``SUCCESS_WARN`` instead
    of blocking first-run setup.
    """
    verdict, retro_errors = _asset_retro_gate(ws)
    if verdict == "warn":
        for err in retro_errors:
            log(f"[stage: engagement-retro]   ASSET-COVERAGE WARN {err}",
                args.quiet)
        note = ws / "RETROSPECTIVE_ASSET_COVERAGE_BLOCKERS.md"
        note.write_text(
            "# Asset-Coverage Warnings at engagement-retro\n\n"
            "Workspace has no worker spawn events, no non-dispatch agent "
            "outputs, and no submission activity; treating missing per-asset "
            "traces as a fresh-engagement warn rather than a hard fail "
            "(I-16 / CAP-GAP-90).\n\n"
            + "\n".join(f"- {e}" for e in retro_errors) + "\n"
        )
        log(
            "[stage: engagement-retro] ASSET-COVERAGE WARN — fresh "
            f"engagement, wrote {note.name}",
            args.quiet,
        )
        return (
            f"SUCCESS_WARN asset-coverage fresh-engagement "
            f"({len(retro_errors)} asset(s) without trace or waiver)"
        )
    if verdict == "fail":
        # CAP-GAP-90 (2026-05-27): engagement-retro is a retrospective health
        # check, not a precondition for downstream phases. Asset-coverage gaps
        # are operator-driven workflow signals, not audit-pipeline failures.
        # Soften FAIL -> SUCCESS_WARN unconditionally so make audit exits 0
        # and the audit-completion marker write proceeds (CAP-GAP-88 cascade).
        # Operator can re-enable hard-fail via
        # AUDITOOOR_STRICT_ENGAGEMENT_RETRO=1 when explicitly auditing
        # coverage discipline post-iter-1.
        # r36-rebuttal: build lane / hacker-mcp-rebuttal: capability not drill
        strict = (
            os.environ.get("AUDITOOOR_STRICT_ENGAGEMENT_RETRO", "").strip()
            not in ("", "0", "false", "no")
        )
        for err in retro_errors:
            log(f"[stage: engagement-retro]   ASSET-COVERAGE {'FAIL' if strict else 'WARN'} {err}",
                args.quiet)
        note = ws / "RETROSPECTIVE_ASSET_COVERAGE_BLOCKERS.md"
        if strict:
            note.write_text(
                "# Asset-Coverage Blockers at engagement-retro\n\n"
                + "\n".join(f"- {e}" for e in retro_errors) + "\n"
            )
            log(f"[stage: engagement-retro] ASSET-COVERAGE BLOCKED — wrote {note.name}",
                args.quiet)
            return f"FAIL asset-coverage ({len(retro_errors)} asset(s) without trace or waiver)"
        note.write_text(
            "# Asset-Coverage Warnings at engagement-retro\n\n"
            "Workspace has at least one asset with no dispatch trace and no "
            "waiver, but engagement-retro is advisory by default per CAP-GAP-90 "
            "(2026-05-27). Set AUDITOOOR_STRICT_ENGAGEMENT_RETRO=1 to "
            "hard-fail.\n\n"
            + "\n".join(f"- {e}" for e in retro_errors) + "\n"
        )
        log(
            "[stage: engagement-retro] ASSET-COVERAGE WARN — wrote "
            f"{note.name} (CAP-GAP-90 degrade-permissive; set "
            "AUDITOOOR_STRICT_ENGAGEMENT_RETRO=1 to hard-fail)",
            args.quiet,
        )
        return (
            f"SUCCESS_WARN asset-coverage advisory "
            f"({len(retro_errors)} asset(s) without trace or waiver)"
        )
    if not ENGAGEMENT_RETRO.exists():
        log("[stage: engagement-retro] SKIPPED — engagement-retro.sh missing",
            args.quiet)
        return "SKIPPED missing tool"
    log(f"[stage: engagement-retro] running on {ws} "
        f"(timeout {SYNTHESIS_TIMEOUT}s) ...", args.quiet)
    rc, _so, se = run(["bash", str(ENGAGEMENT_RETRO), str(ws)],
                      SYNTHESIS_TIMEOUT)
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    art = ws / "RETROSPECTIVE.md"
    log(f"[stage: engagement-retro] {status}"
        + (f" — {art}" if art.exists() else " — (no artifact)"), args.quiet)
    if rc != 0 and se:
        log(f"[stage: engagement-retro]   stderr: {se.strip()[:400]}",
            args.quiet)
    return status


def stage_adversarial_copilot(ws: Path, args) -> str:
    """Kimi 20/10 Step 5 — per-engagement adversarial co-pilot close-out hook.

    Scans ``<ws>/agent_outputs/*.md`` for NOT-A-BUG verdicts. When at least
    one is present, runs ``tools/adversarial-copilot.py --per-engagement``.
    On every break verdict, the copilot emits a candidate DSL pattern under
    ``reference/patterns.dsl/_novelty/<slug>.yaml`` and appends a record to
    ``tools/novelty_promotion_log.json`` (tracked centrally, not per-ws).

    Hard rules:
      - SKIPPED when ``adversarial-copilot.py`` is missing.
      - SKIPPED when ``<ws>/agent_outputs/`` has no NOT-A-BUG verdicts —
        the copilot itself emits the same skip reason and exits 0; this
        early-exit is purely an optimisation.
      - The stage NEVER passes ``--live`` automatically. Live dispatch is
        a manual operator action that requires
        ``AUDITOOOR_LLM_NETWORK_CONSENT=1``.
    """
    if not ADVERSARIAL_COPILOT.exists():
        log("[stage: adversarial-copilot] SKIPPED — adversarial-copilot.py missing",
            args.quiet)
        return "SKIPPED missing tool"
    agent_dir = ws / "agent_outputs"
    if not agent_dir.is_dir():
        log("[stage: adversarial-copilot] SKIPPED — no agent_outputs/ "
            "(nothing to dispute)", args.quiet)
        return "SKIPPED no agent_outputs"
    md_files = list(agent_dir.glob("*.md"))
    if not md_files:
        log("[stage: adversarial-copilot] SKIPPED — agent_outputs/ empty",
            args.quiet)
        return "SKIPPED empty agent_outputs"
    log(f"[stage: adversarial-copilot] running --per-engagement on {ws} "
        f"(timeout {SYNTHESIS_TIMEOUT}s, dry-run dispatch) ...", args.quiet)
    rc, so, se = run(
        [sys.executable, str(ADVERSARIAL_COPILOT), str(ws), "--per-engagement"],
        SYNTHESIS_TIMEOUT,
    )
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    log(f"[stage: adversarial-copilot] {status}", args.quiet)
    # Surface the summary line if present.
    if so:
        for ln in so.splitlines():
            if "summary:" in ln or "calibration:" in ln:
                log(f"[stage: adversarial-copilot]   {ln.strip()[:400]}",
                    args.quiet)
    if rc != 0 and se:
        log(f"[stage: adversarial-copilot]   stderr: {se.strip()[:400]}",
            args.quiet)
    return status


def stage_post_audit_review(ws: Path, args) -> str:
    """Phase 45b: capture per-finding outcomes (paid/dupe/rejected/pending).

    post-audit-review.sh in workspace-only mode (no --finding flag) prints an
    active-ledger-derived status table — non-interactive, safe to chain. Per-
    finding outcome capture remains a manual operator action via CLI flags.
    """
    if not POST_AUDIT_REVIEW.exists():
        log("[stage: post-audit-review] SKIPPED — post-audit-review.sh missing",
            args.quiet)
        return "SKIPPED missing tool"
    subs_md = find_submission_file(ws)
    if subs_md is None:
        log("[stage: post-audit-review] SKIPPED — no SUBMISSIONS.md "
            "(nothing to review)", args.quiet)
        return "SKIPPED no submissions"
    log(f"[stage: post-audit-review] running on {ws} "
        f"(timeout {SYNTHESIS_TIMEOUT}s) ...", args.quiet)
    rc, so, se = run(["bash", str(POST_AUDIT_REVIEW), str(ws)],
                      SYNTHESIS_TIMEOUT)
    status = ("SUCCESS" if rc == 0 else
              "TIMEOUT" if rc == 124 else
              f"FAIL rc={rc}")
    log(f"[stage: post-audit-review] {status}", args.quiet)
    if rc != 0 and se:
        log(f"[stage: post-audit-review]   stderr: {se.strip()[:400]}",
            args.quiet)
        return status
    contradiction_warn = False
    if rc == 0 and so:
        if "Potential staging-vs-final contradictions:" in so and \
                "Potential staging-vs-final contradictions: 0" not in so:
            contradiction_warn = True
            log("[stage: post-audit-review]   contradiction summary detected",
                args.quiet)
        if "Live-proof contradictions:" in so and \
                "Live-proof contradictions: 0" not in so and \
                "No live-proof contradictions detected" not in so:
            contradiction_warn = True
            log("[stage: post-audit-review]   live-proof contradiction summary detected",
                args.quiet)
    if rc == 0 and SUBMISSION_SYNC.exists() and (ws / "STATUS.md").exists():
        sync_rc, sync_so, sync_se = run(["bash", str(SUBMISSION_SYNC), str(ws), "--apply-status"], 60)
        sync_status = "updated" if sync_rc == 0 else f"FAIL rc={sync_rc}"
        log(f"[stage: post-audit-review]   STATUS sync: {sync_status}", args.quiet)
        if sync_rc != 0 and sync_se:
            log(f"[stage: post-audit-review]   STATUS sync stderr: {sync_se.strip()[:400]}", args.quiet)
            return (
                f"SUCCESS_WARN contradiction summary; status-sync rc={sync_rc}"
                if contradiction_warn
                else f"SUCCESS_WARN status-sync rc={sync_rc}"
            )
        elif sync_so.strip():
            last = sync_so.strip().splitlines()[-1]
            log(f"[stage: post-audit-review]   {last[:400]}", args.quiet)
    elif rc == 0 and SUBMISSION_SYNC.exists():
        log("[stage: post-audit-review]   STATUS sync: SKIPPED no STATUS.md", args.quiet)
        return "SUCCESS_WARN contradiction summary" if contradiction_warn else "SUCCESS_WARN no STATUS.md"
    bridge_warn = False
    if rc == 0 and HIGH_IMPACT_EXECUTION_BRIDGE.exists() and (ws / ".auditooor" / "invariant_ledger.json").is_file():
        bridge_out = ws / ".auditooor" / "high_impact_execution_bridge.json"
        bridge_rc, bridge_so, bridge_se = run(
            [
                sys.executable,
                str(HIGH_IMPACT_EXECUTION_BRIDGE),
                "--workspace",
                str(ws),
                "--out-json",
                str(bridge_out),
            ],
            SYNTHESIS_TIMEOUT,
        )
        if bridge_rc == 0 and bridge_out.is_file():
            bridge_payload = _read_json(bridge_out)
            bridge_summary = bridge_payload.get("summary") or {}
            log(
                "[stage: post-audit-review]   high-impact execution bridge: "
                f"runnable={int(bridge_summary.get('runnable_harness_rows', 0) or 0)} "
                f"blocked_missing_impact_contract={int(bridge_summary.get('blocked_missing_impact_contract', 0) or 0)}",
                args.quiet,
            )
        else:
            bridge_warn = True
            if bridge_se.strip():
                log(f"[stage: post-audit-review]   execution-bridge stderr: {bridge_se.strip()[:400]}", args.quiet)
            elif bridge_so.strip():
                log(f"[stage: post-audit-review]   execution-bridge stdout: {bridge_so.strip()[:400]}", args.quiet)
    if contradiction_warn:
        if bridge_warn:
            return "SUCCESS_WARN contradiction summary; high-impact execution bridge failed"
        return "SUCCESS_WARN contradiction summary"
    if bridge_warn:
        return "SUCCESS_WARN high-impact execution bridge failed"
    return status


# ---------------------------------------------------------------------------
# Phase 87+ — new stages from audit-loop.sh integration
# ---------------------------------------------------------------------------

def stage_env_check(ws: Path, args) -> int:
    """Check solc versions and forge dependencies."""
    any_ran = False
    slither_py, rc, _so, se = _select_slither_python()
    if rc == 0:
        log(f"[stage: env-check]   python slither import: SUCCESS ({slither_py})", args.quiet)
    else:
        log(
            "[stage: env-check]   python slither import: WARN "
            f"({slither_py} cannot import slither; set AUDITOOOR_PYTHON_SLITHER "
            "to a Python with slither-analyzer for Python-API scanners)",
            args.quiet,
        )
        if se:
            log(f"[stage: env-check]     stderr: {se.strip()[:400]}", args.quiet)
    any_ran = True
    if SOLC_VERSION_MANAGER.exists():
        log(f"[stage: env-check] running solc-version-manager (timeout {ENV_CHECK_TIMEOUT}s) ...", args.quiet)
        rc, _so, se = run([sys.executable, str(SOLC_VERSION_MANAGER), str(ws), "--check"], ENV_CHECK_TIMEOUT)
        status = "SUCCESS" if rc == 0 else ("TIMEOUT" if rc == 124 else f"FAIL rc={rc}")
        log(f"[stage: env-check]   solc-version-manager: {status}", args.quiet)
        if rc != 0 and se:
            log(f"[stage: env-check]     stderr: {se.strip()[:400]}", args.quiet)
        any_ran = True
    else:
        log("[stage: env-check]   solc-version-manager.py missing — SKIPPED", args.quiet)

    if FORGE_DEPS_CHECKER.exists():
        if _has_foundry_project(ws):
            log(f"[stage: env-check] running forge-deps-checker (timeout {ENV_CHECK_TIMEOUT}s) ...", args.quiet)
            rc, _so, se = run([sys.executable, str(FORGE_DEPS_CHECKER), str(ws)], ENV_CHECK_TIMEOUT)
            status = "SUCCESS" if rc == 0 else ("TIMEOUT" if rc == 124 else f"FAIL rc={rc}")
            log(f"[stage: env-check]   forge-deps-checker: {status}", args.quiet)
            if rc != 0 and se:
                log(f"[stage: env-check]     stderr: {se.strip()[:400]}", args.quiet)
            any_ran = True
        else:
            log("[stage: env-check]   no foundry project detected — forge-deps-checker SKIPPED", args.quiet)
    else:
        log("[stage: env-check]   forge-deps-checker.py missing — SKIPPED", args.quiet)

    if not any_ran:
        log("[stage: env-check] all checks SKIPPED", args.quiet)
    return 0


def stage_live_checks(ws: Path, args) -> str:
    """Run declarative workspace live-topology checks."""
    if not LIVE_CHECK_RUNNER.exists():
        log("[stage: live-checks] live-check-runner.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    out_json = ws / "live_topology_checks.json"
    out_md = ws / "LIVE_TOPOLOGY.md"
    if os.environ.get("AUDITOOOR_SOURCE_ONLY") == "1":
        payload = {
            "schema": "auditooor.live_topology_checks.v1",
            "workspace": str(ws),
            "disposition": {
                "mode": "github-source-only",
                "operator_declared": True,
                "live_state": "not_collected",
                "reason": "GitHub/source-only review does not collect RPC state.",
            },
            "summary": {
                "pass": 0,
                "fail": 0,
                "blocked_unresolved_address": 0,
                "blocked_missing_rpc": 0,
                "dry_run": 0,
                "error": 0,
                "source_only": 1,
            },
            "checks": [],
        }
        out_json.write_text(json.dumps(payload, indent=2) + "\n")
        out_md.write_text(
            "# Live Topology\n\n"
            "- Disposition: `github-source-only`\n"
            "- Live RPC state: `not_collected`\n"
            "- This artifact is an explicit N/A boundary, not live proof.\n"
        )
        log(
            "[stage: live-checks] source-only disposition: "
            "live state not collected",
            args.quiet,
        )
        return "SUCCESS source-only live state not collected"
    log(f"[stage: live-checks] running (timeout {LIVE_CHECKS_TIMEOUT}s) ...", args.quiet)
    rc, so, se = run([sys.executable, str(LIVE_CHECK_RUNNER), str(ws)], LIVE_CHECKS_TIMEOUT)
    if rc == 3:
        log("[stage: live-checks] SKIPPED — no live check spec", args.quiet)
        return "SKIPPED no live-check spec"
    status = "SUCCESS" if rc == 0 else ("FAIL timeout" if rc == 124 else f"FAIL rc={rc}")
    log(f"[stage: live-checks] {status}", args.quiet)
    if rc != 0 and se:
        log(f"[stage: live-checks]   stderr: {se.strip()[:400]}", args.quiet)
        return status
    if so.strip():
        last = so.strip().splitlines()[-1]
        log(f"[stage: live-checks]   {last[:400]}", args.quiet)
    if not out_json.exists():
        return "FAIL missing live_topology_checks.json"
    try:
        payload = json.loads(out_json.read_text())
    except json.JSONDecodeError:
        return "FAIL invalid live_topology_checks.json"
    summary = payload.get("summary", {})
    pass_count = int(summary.get("pass", 0) or 0)
    fail_count = int(summary.get("fail", 0) or 0)
    blocked_count = int(summary.get("blocked_unresolved_address", 0) or 0) + int(summary.get("blocked_missing_rpc", 0) or 0)
    dry_count = int(summary.get("dry_run", 0) or 0)
    error_count = int(summary.get("error", 0) or 0)
    if error_count:
        return f"FAIL {error_count} live check error(s)"
    warnings: list[str] = []
    if fail_count:
        warnings.append(f"{fail_count} mismatched")
    if blocked_count:
        warnings.append(f"{blocked_count} blocked")
    if dry_count:
        warnings.append(f"{dry_count} dry-run")
    if not out_md.exists():
        warnings.append("missing LIVE_TOPOLOGY.md")
    if warnings:
        return f"SUCCESS_WARN {', '.join(warnings[:3])}"
    return f"SUCCESS {pass_count} checked"


def stage_mine_prioritize(ws: Path, args) -> str:
    """Rank CCIA attack angles by exploitability score."""
    if not MINING_PRIORITIZER.exists():
        log("[stage: mine-prioritize] mining-prioritizer.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    ccia_json = ws / "ccia_report.json"
    ccia_md = ws / "ccia_report.md"
    ccia_rust_json = ws / "ccia_rust_report.json"
    if not ccia_json.exists() and not ccia_md.exists() and not ccia_rust_json.exists():
        log("[stage: mine-prioritize] SKIPPED — no CCIA output (run orient first)", args.quiet)
        return "SKIPPED no CCIA output"
    out_file = ws / "swarm" / "mining_priorities.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    log(f"[stage: mine-prioritize] running (timeout {MINE_PRIORITIZE_TIMEOUT}s) ...", args.quiet)
    rc, so, se = run(
        [sys.executable, str(MINING_PRIORITIZER), str(ws), "--top", "15", "--out", str(out_file)],
        MINE_PRIORITIZE_TIMEOUT,
    )
    status = "SUCCESS" if rc == 0 else ("FAIL timeout" if rc == 124 else f"FAIL rc={rc}")
    log(f"[stage: mine-prioritize] {status}", args.quiet)
    if rc == 0 and out_file.exists():
        log(f"[stage: mine-prioritize]   wrote {out_file}", args.quiet)
        return "SUCCESS"
    if rc == 0 and so.strip():
        last = so.strip().splitlines()[-1]
        log(f"[stage: mine-prioritize]   {last[:400]}", args.quiet)
    if rc == 0:
        # Missing artifact on a clean exit is advisory, not a hard failure.
        return "SUCCESS_WARN mine-prioritize produced no priorities file (ranking hint only)"
    if rc != 0 and se:
        log(f"[stage: mine-prioritize]   stderr: {se.strip()[:400]}", args.quiet)
    # mine-prioritize only RANKS CCIA attack angles into a swarm hint - it is NOT
    # load-bearing for the deep engines or the per-fn hunt (they read the CCIA /
    # inscope manifest directly). On a large workspace the prioritizer can exceed
    # its wall-clock cap; under engage --fail-fast a hard FAIL here aborts the
    # WHOLE audit-deep before any engine runs. Per G9 (Step-1 ORIENT failures must
    # not block the engines) a timeout/crash here is advisory (SUCCESS_WARN), so
    # the summary still surfaces it but the deep engines proceed. Generic.
    return f"SUCCESS_WARN mine-prioritize {status.lower()} (advisory; ranking hint only)"


def stage_cross_ws_patterns(ws: Path, args) -> str:
    """Map patterns across all audit workspaces."""
    if not CROSS_WS_MAPPER.exists():
        log("[stage: cross-ws-patterns] cross-ws-pattern-mapper.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    out_file = ws / "cross_ws_patterns.md"
    log(f"[stage: cross-ws-patterns] running (timeout {CROSS_WS_TIMEOUT}s) ...", args.quiet)
    rc, so, se = run([sys.executable, str(CROSS_WS_MAPPER), "--audits-dir", str(ws.parent),
                       "--out", str(out_file)],
                      CROSS_WS_TIMEOUT)
    status = "SUCCESS" if rc == 0 else ("FAIL timeout" if rc == 124 else f"FAIL rc={rc}")
    log(f"[stage: cross-ws-patterns] {status}", args.quiet)
    if rc != 0 and se:
        log(f"[stage: cross-ws-patterns]   stderr: {se.strip()[:400]}", args.quiet)
    if rc == 0:
        if out_file.exists():
            log(f"[stage: cross-ws-patterns]   wrote {ws}/cross_ws_patterns.md ({out_file.stat().st_size} bytes)", args.quiet)
        elif so:
            out_file.write_text(so)
            log(f"[stage: cross-ws-patterns]   wrote {ws}/cross_ws_patterns.md ({len(so)} bytes)", args.quiet)
        else:
            out_file.write_text("# Cross-Workspace Patterns\n\nNo cross-workspace pattern output was produced.\n")
            log(f"[stage: cross-ws-patterns]   wrote {ws}/cross_ws_patterns.md (placeholder)", args.quiet)
            return "SUCCESS_WARN placeholder artifact"
        return "SUCCESS"
    return status


def stage_pattern_migration(ws: Path, args) -> str:
    """Alert on unmined patterns that paid in other workspaces."""
    if not PATTERN_MIGRATION_ALERT.exists():
        log("[stage: pattern-migration] pattern-migration-alert.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    out_file = ws / "pattern_migration_alert.md"
    log(f"[stage: pattern-migration] running (timeout {PATTERN_MIGRATION_TIMEOUT}s) ...", args.quiet)
    rc, so, se = run([sys.executable, str(PATTERN_MIGRATION_ALERT), "--audits-dir", str(ws.parent),
                      "--out", str(out_file)],
                      PATTERN_MIGRATION_TIMEOUT)
    status = "SUCCESS" if rc == 0 else ("FAIL timeout" if rc == 124 else f"FAIL rc={rc}")
    log(f"[stage: pattern-migration] {status}", args.quiet)
    if rc != 0 and se:
        log(f"[stage: pattern-migration]   stderr: {se.strip()[:400]}", args.quiet)
    if rc == 0:
        if out_file.exists():
            log(f"[stage: pattern-migration]   wrote {ws}/pattern_migration_alert.md ({out_file.stat().st_size} bytes)", args.quiet)
        elif so:
            out_file.write_text(so)
            log(f"[stage: pattern-migration]   wrote {ws}/pattern_migration_alert.md ({len(so)} bytes)", args.quiet)
        else:
            out_file.write_text("# Pattern Migration Alert\n\nNo migrating patterns met the current threshold.\n")
            log(f"[stage: pattern-migration]   wrote {ws}/pattern_migration_alert.md (placeholder)", args.quiet)
            return "SUCCESS_WARN placeholder artifact"
        return "SUCCESS"
    return status


def stage_mine_briefs(ws: Path, args) -> str:
    """Generate investigation briefs for top mining targets."""
    if not MINING_BRIEF_GENERATOR.exists():
        log("[stage: mine-briefs] mining-brief-generator.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    ccia_json = ws / "ccia_report.json"
    ccia_md = ws / "ccia_report.md"
    ccia_rust_json = ws / "ccia_rust_report.json"
    if not ccia_json.exists() and not ccia_md.exists() and not ccia_rust_json.exists():
        log("[stage: mine-briefs] SKIPPED — no CCIA output (run orient first)", args.quiet)
        return "SKIPPED no CCIA output"
    out_dir = ws / "swarm" / "mining_briefs"
    log(f"[stage: mine-briefs] running (timeout {MINE_BRIEF_TIMEOUT}s) ...", args.quiet)
    rc, _so, se = run([sys.executable, str(MINING_BRIEF_GENERATOR), str(ws),
                       "--top", "10", "--out-dir", str(out_dir)],
                      MINE_BRIEF_TIMEOUT)
    status = "SUCCESS" if rc == 0 else ("FAIL timeout" if rc == 124 else f"FAIL rc={rc}")
    log(f"[stage: mine-briefs] {status}", args.quiet)
    if rc == 0:
        n = len(list(out_dir.glob("*.md"))) if out_dir.exists() else 0
        log(f"[stage: mine-briefs]   generated {n} brief(s) in {out_dir}", args.quiet)
        if n == 0:
            return "FAIL no briefs generated"
        unresolved = []
        for brief_path in sorted(out_dir.glob("*.md")):
            try:
                brief_text = brief_path.read_text(errors="replace")
            except OSError:
                unresolved.append(brief_path.name)
                continue
            if re.search(r"\*\*Target:\*\*\s*`UNKNOWN`", brief_text):
                unresolved.append(brief_path.name)
        if unresolved:
            log(
                f"[stage: mine-briefs] unresolved target identity in {len(unresolved)} brief(s): "
                + ", ".join(unresolved[:5]),
                args.quiet,
            )
            return f"FAIL unresolved brief target identity {len(unresolved)}/{n}"
        live_dossier = ws / "live_topology_checks.json"
        if not live_dossier.exists():
            return "FAIL missing live_topology_checks.json"
        try:
            payload = json.loads(live_dossier.read_text())
        except json.JSONDecodeError:
            return "FAIL malformed live_topology_checks.json"
        results = payload.get("results", [])
        if not isinstance(results, list):
            return "FAIL malformed live_topology_checks.json"
        return "SUCCESS"
    if rc != 0 and se:
        log(f"[stage: mine-briefs]   stderr: {se.strip()[:400]}", args.quiet)
    return status


def stage_agent_synthesize(ws: Path, args) -> str | int:
    """Structured verdict extraction from agent outputs."""
    if not AGENT_OUTPUT_SYNTHESIZER.exists():
        log("[stage: agent-synthesize] agent-output-synthesizer.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    agent_dir = ws / "agent_outputs"
    swarm_dir = ws / "swarm"
    if not any(d.exists() and any(d.iterdir()) for d in (agent_dir, swarm_dir) if d.exists()):
        log("[stage: agent-synthesize] SKIPPED — no agent_outputs/ or swarm/ directory", args.quiet)
        return "SKIPPED"
    swarm_dir.mkdir(parents=True, exist_ok=True)
    verdict_out = swarm_dir / "agent_verdicts.json"
    candidate_out = swarm_dir / "brief_candidates.json"
    log(f"[stage: agent-synthesize] running (timeout {AGENT_SYNTHESIZE_TIMEOUT}s) ...", args.quiet)
    rc, _so, se = run(
        [
            sys.executable,
            str(AGENT_OUTPUT_SYNTHESIZER),
            str(ws),
            "--out",
            str(verdict_out),
        ],
        AGENT_SYNTHESIZE_TIMEOUT,
    )
    status = "SUCCESS" if rc == 0 else ("TIMEOUT" if rc == 124 else f"FAIL rc={rc}")
    log(f"[stage: agent-synthesize] {status}", args.quiet)
    if rc != 0 and se:
        log(f"[stage: agent-synthesize]   stderr: {se.strip()[:400]}", args.quiet)
        return status

    brief_rc, _brief_so, brief_se = run(
        [
            sys.executable,
            str(AGENT_OUTPUT_SYNTHESIZER),
            str(ws),
            "--brief-candidates",
            "--out",
            str(candidate_out),
        ],
        AGENT_SYNTHESIZE_TIMEOUT,
    )
    if brief_rc != 0:
        brief_status = "TIMEOUT" if brief_rc == 124 else f"rc={brief_rc}"
        log(f"[stage: agent-synthesize]   brief-candidates WARN {brief_status}", args.quiet)
        if brief_se:
            log(f"[stage: agent-synthesize]   brief-candidates stderr: {brief_se.strip()[:400]}", args.quiet)
        return "SUCCESS_WARN brief candidate synthesis failed"

    try:
        payload = json.loads(candidate_out.read_text())
    except Exception:
        return "SUCCESS_WARN malformed brief_candidates.json"

    summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
    count = summary.get("candidate_count", 0)
    findings = summary.get("candidate_findings", 0)
    plans = summary.get("poc_plans", 0)
    log(
        f"[stage: agent-synthesize]   wrote {verdict_out.name} and {candidate_out.name}"
        f" ({count} candidates = {findings} findings / {plans} poc plans)",
        args.quiet,
    )
    if AGENT_RECALL_DETECTOR_QUEUE.exists() or AUTOMATION_CLOSURE.exists():
        queue_out = ws / ".auditooor" / "agent_recall_detector_queue.json"
        if AGENT_RECALL_DETECTOR_QUEUE.exists():
            queue_cmd = [
                sys.executable,
                str(AGENT_RECALL_DETECTOR_QUEUE),
                "--workspace",
                str(ws),
                "--out-json",
                str(queue_out),
            ]
        else:
            queue_cmd = [
                sys.executable,
                str(AUTOMATION_CLOSURE),
                "--workspace",
                str(ws),
                "--mode",
                "agent-recall-detector-queue",
                "--json",
            ]
        queue_rc, queue_so, queue_se = run(queue_cmd, AGENT_SYNTHESIZE_TIMEOUT)
        if queue_rc == 0 and queue_out.is_file():
            queue_payload = _read_json(queue_out)
            queue_summary = queue_payload.get("summary") or {}
            row_count = int(queue_summary.get("row_count", 0) or 0)
            queue_status = str(queue_payload.get("status") or "ok")
            log(
                "[stage: agent-synthesize]   recall queue: "
                f"{queue_status} rows={row_count}",
                args.quiet,
            )
        else:
            if queue_se.strip():
                log(f"[stage: agent-synthesize]   recall-queue stderr: {queue_se.strip()[:400]}", args.quiet)
            elif queue_so.strip():
                log(f"[stage: agent-synthesize]   recall-queue stdout: {queue_so.strip()[:400]}", args.quiet)
            return "SUCCESS_WARN recall detector queue follow-on failed"
    if count == 0:
        return "SUCCESS_WARN no brief candidates"
    return "SUCCESS"


def _filter_submission_drafts(drafts: list[Path]) -> list[Path]:
    excluded = {".block.md", ".notes.md"}
    out = []
    for draft in drafts:
        upper_name = draft.name.upper()
        if upper_name in {"README.MD", "INDEX.MD", "OOS_CHECK.MD"}:
            continue
        if upper_name.startswith("OOS_CHECK_") or upper_name.endswith(".OOS_CHECK.MD"):
            continue
        if any(draft.name.endswith(suffix) for suffix in excluded):
            continue
        try:
            disposition = draft.read_text(encoding="utf-8", errors="replace")
        except OSError:
            disposition = ""
        # An explicitly OOS draft is disposition evidence, not an active
        # package candidate. Keeping it in staging must not block the ordered
        # audit pipeline; active filing gates still reject any promoted copy.
        if "OOS-DISPOSITION" in disposition or re.search(
            r"(?im)^\s*severity_tier:\s*OOS\s*$", disposition
        ):
            continue
        out.append(draft)
    return sorted(set(out))


def _collect_staging_drafts(ws: Path) -> list[Path]:
    """Collect mutation/package candidate drafts from staging only."""
    staging_dir = ws / "submissions" / "staging"
    if not staging_dir.is_dir():
        return []
    return _filter_submission_drafts(list(staging_dir.glob("*.md")))


def _collect_quality_drafts(ws: Path) -> list[Path]:
    """Collect reportable drafts for read-only quality diagnostics."""
    return _filter_submission_drafts(discover_workspace_drafts(ws))


def _collect_drafts(ws: Path) -> list[Path]:
    """Backward-compatible staging draft collector."""
    return _collect_staging_drafts(ws)


def _read_only_draft_mode() -> bool:
    """Return true when close-out stages must not mutate existing drafts."""
    return os.environ.get("AUDITOOOR_READ_ONLY_DRAFTS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def stage_quality_score(ws: Path, args) -> str | int:
    """Numerical quality score per draft submission."""
    if not FINDING_QUALITY_SCORER.exists():
        log("[stage: quality-score] finding-quality-scorer.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    drafts = _collect_quality_drafts(ws)
    if not drafts:
        log("[stage: quality-score] SKIPPED — no submission drafts found", args.quiet)
        return "SKIPPED"
    log(f"[stage: quality-score] scoring {len(drafts)} draft(s) ...", args.quiet)
    ok = 0
    failed = 0
    for draft in drafts:
        rc, _so, se = run([sys.executable, str(FINDING_QUALITY_SCORER), str(ws), str(draft)],
                          QUALITY_SCORE_TIMEOUT)
        if rc == 0:
            ok += 1
        else:
            failed += 1
            if se:
                log(f"[stage: quality-score]   FAIL {draft.name}: {se.strip()[:200]}", args.quiet)
    log(f"[stage: quality-score] {ok} pass, {failed} fail ({len(drafts)} total)", args.quiet)
    if failed:
        # Quality scoring is a diagnostic input to the following auto-fix and
        # packaging stages. A low score must remain visible, but it must not
        # prevent those ordered remediation stages from running.
        return f"SUCCESS_WARN quality-score failed {failed}/{len(drafts)}"
    return f"SUCCESS {ok} scored"


def stage_auto_fix(ws: Path, args) -> str | int:
    """Auto-fix common pre-submit warnings in-place."""
    if _read_only_draft_mode():
        log("[stage: auto-fix] SKIPPED - AUDITOOOR_READ_ONLY_DRAFTS=1",
            args.quiet)
        return "SKIPPED read-only draft mode"
    if not AUTO_FIX_DRAFT.exists():
        log("[stage: auto-fix] auto-fix-draft.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    drafts = _collect_staging_drafts(ws)
    if not drafts:
        log("[stage: auto-fix] SKIPPED — no submission drafts in submissions/staging/", args.quiet)
        return "SKIPPED"
    log(f"[stage: auto-fix] fixing {len(drafts)} draft(s) ...", args.quiet)
    fixed_count = 0
    warn_count = 0
    failed = 0
    for draft in drafts:
        rc, so, se = run([sys.executable, str(AUTO_FIX_DRAFT), str(draft), "--in-place"],
                         AUTO_FIX_TIMEOUT)
        if rc == 0:
            # Parse output for fix/warn counts
            fixes = len([l for l in (so or "").splitlines() if l.strip().startswith("+")])
            warns = len([l for l in (so or "").splitlines() if l.strip().startswith("!")])
            fixed_count += fixes
            warn_count += warns
        else:
            failed += 1
            if se:
                log(f"[stage: auto-fix]   FAIL {draft.name}: {se.strip()[:200]}", args.quiet)
    log(f"[stage: auto-fix] {fixed_count} fix(es), {warn_count} warning(s) remaining, {failed} fail ({len(drafts)} total)", args.quiet)
    if failed:
        return f"FAIL {failed}/{len(drafts)}"
    if warn_count:
        return f"SUCCESS_WARN {warn_count} warning(s)"
    return f"SUCCESS {fixed_count} fix(es)"


def stage_package(ws: Path, args) -> str | int:
    """Build review bundles for validated staging drafts."""
    if _read_only_draft_mode():
        log("[stage: package] SKIPPED - AUDITOOOR_READ_ONLY_DRAFTS=1",
            args.quiet)
        return "SKIPPED read-only draft mode"
    if not SUBMISSION_PACKAGER.exists():
        log("[stage: package] submission-packager.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    drafts = _collect_staging_drafts(ws)
    if not drafts:
        log("[stage: package] SKIPPED — no submission drafts in submissions/staging/", args.quiet)
        return "SKIPPED"
    log(f"[stage: package] packaging {len(drafts)} draft(s) ...", args.quiet)
    ok = 0
    failed = 0
    warned = 0
    for draft in drafts:
        rc, so, se = run([sys.executable, str(SUBMISSION_PACKAGER), str(ws), str(draft), "--json"],
                          PACKAGE_TIMEOUT)
        payload = {}
        parse_error = ""
        if so.strip():
            try:
                payload = json.loads(so)
            except json.JSONDecodeError:
                parse_error = "malformed JSON response from submission-packager.py"
                payload = {}
        if rc == 0:
            pkg_dir = payload.get("package_dir")
            if parse_error:
                failed += 1
                log(f"[stage: package]   FAIL {draft.name}: {parse_error}", args.quiet)
                continue
            if not pkg_dir:
                failed += 1
                log(f"[stage: package]   FAIL {draft.name}: missing package_dir in packager response", args.quiet)
                continue
            ok += 1
            warnings = payload.get("warnings") or []
            if warnings:
                warned += 1
            log(f"[stage: package]   OK {draft.name} — {pkg_dir}", args.quiet)
            for warning in warnings:
                log(f"[stage: package]     warn: {warning}", args.quiet)
        else:
            failed += 1
            err = payload.get("error") or se.strip() or so.strip()
            if err:
                log(f"[stage: package]   FAIL {draft.name}: {err[:200]}", args.quiet)
    warn_suffix = f", {warned} with warnings" if warned else ""
    log(f"[stage: package] {ok} packaged{warn_suffix}, {failed} failed ({len(drafts)} total)", args.quiet)
    if failed:
        return f"FAIL {failed} draft(s)"
    if warned:
        return f"SUCCESS_WARN {warned} draft(s)"
    return "SUCCESS"


def stage_track_submissions(ws: Path, args) -> str | int:
    """Sync the auditooor-managed nested SUBMISSIONS.md tracker from staging."""
    if not SUBMISSIONS_TRACKER.exists():
        log("[stage: track-submissions] submissions-tracker.py missing — SKIPPED", args.quiet)
        return "SKIPPED"
    subs_md = find_submission_file(ws)
    if subs_md is None:
        log("[stage: track-submissions] SKIPPED — no SUBMISSIONS.md", args.quiet)
        return "SKIPPED"
    if submission_file_location(ws) == "root":
        log("[stage: track-submissions] SKIPPED — root-level SUBMISSIONS.md is manual "
            "and auto-sync would create a shadow ledger", args.quiet)
        return "SKIPPED root tracker"
    log(f"[stage: track-submissions] running (timeout {TRACK_SUBMISSIONS_TIMEOUT}s) ...", args.quiet)
    rc, so, se = run([sys.executable, str(SUBMISSIONS_TRACKER), str(ws), "--sync"],
                      TRACK_SUBMISSIONS_TIMEOUT)
    status = "SUCCESS_WARN unknown outcome"
    if rc == 124:
        status = "FAIL timeout"
    elif rc != 0:
        status = f"FAIL rc={rc}"
    elif "Manual or curated SUBMISSIONS.md detected" in so:
        status = "SKIPPED curated tracker"
    elif "Root-level SUBMISSIONS.md detected" in so:
        status = "SKIPPED root tracker"
    elif "Updated:" in so:
        status = "SUCCESS updated"
    elif "is up to date:" in so or "SUBMISSIONS.md is up to date" in so:
        status = "SUCCESS no changes"
    log(f"[stage: track-submissions] {status}", args.quiet)
    if rc == 0 and so.strip():
        first = so.strip().splitlines()[0]
        log(f"[stage: track-submissions]   {first[:400]}", args.quiet)
    if rc != 0 and se:
        log(f"[stage: track-submissions]   stderr: {se.strip()[:400]}", args.quiet)
    return status


def _build_stage_help_epilog() -> str:
    """Phase 49b: render STAGE_TABLE for --help epilog."""
    lines = ["", "Available stages (for --stage and --stages):", ""]
    name_w = max(len(n) for n, _, _ in STAGE_TABLE)
    for name, desc, art in STAGE_TABLE:
        lines.append(f"  {name:<{name_w}}  {desc}")
        lines.append(f"  {'':<{name_w}}    artifact: {art}")
    lines += [
        "",
        "  all               Run the canonical chain (all stages above except",
        "                    rejection-learn, which is standalone).",
        "",
        "Examples:",
        "  engage.py --workspace ~/audits/foo --stage all",
        "  engage.py --workspace ~/audits/foo --stages orient,scan,report",
        "  engage.py --workspace ~/audits/foo --dry-run",
        "  engage.py --workspace ~/audits/foo --fail-fast --no-stage-logs",
        "",
    ]
    return "\n".join(lines)


def _print_summary(results: list[dict], out_stream=sys.stdout) -> None:
    """Phase 49b: print the final stage | status | duration | artifact table."""
    if not results:
        return
    headers = ("stage", "status", "duration", "artifact")
    rows = [headers] + [
        (r["stage"], r["status"], f"{r['duration']:.1f}s", r.get("artifact") or "-")
        for r in results
    ]
    widths = [max(len(str(r[i])) for r in rows) for i in range(4)]
    sep = "  "
    print("", file=out_stream)
    print("=" * (sum(widths) + len(sep) * 3), file=out_stream)
    print("ENGAGE SUMMARY", file=out_stream)
    print("=" * (sum(widths) + len(sep) * 3), file=out_stream)
    for i, row in enumerate(rows):
        line = sep.join(str(row[j]).ljust(widths[j]) for j in range(4))
        print(line, file=out_stream)
        if i == 0:
            print(sep.join("-" * widths[j] for j in range(4)), file=out_stream)


def _overall_engage_status(results: list[dict]) -> str:
    """Collapse per-stage statuses into one truthful operator-facing footer."""
    if any(str(row.get("status", "")).startswith("FAIL") for row in results):
        return "DONE WITH ISSUES"
    if any(str(row.get("status", "")).startswith("SUCCESS_WARN")
           for row in results):
        return "DONE WITH WARNINGS"
    return "DONE"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Unified engagement pipeline with truthful per-stage summaries.",
        epilog=_build_stage_help_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--skip-flow-gate", action="store_true",
                    help="Bypass the 12-step flow-gate HARD STOP pre-check.")
    ap.add_argument("--only-detector", default=None,
                    help="Restrict enrichment to hits matching this detector name.")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-blacklist", action="store_true",
                    help="Disable PATH_BLACKLIST / _CONTRACT_BLACKLIST filtering "
                         "(keep test/mock/script/archive hits — debugging only).")
    ap.add_argument("--blacklist-extra", action="append", default=[],
                    metavar="REGEX",
                    help="Extra path-blacklist regex (repeatable). "
                         "Use for per-workspace custom suppression.")
    ap.add_argument("--stage", choices=STAGES, default="all",
                    help="Run a single pipeline stage (default: all). "
                         "See epilog for the full list of stages + artifact "
                         "paths. Each stage is independently runnable.")
    ap.add_argument("--stages", default=None, metavar="LIST",
                    help="Phase 49b: comma-separated subset to run, e.g. "
                         "'orient,scan,report'. Mutually exclusive with "
                         "--stage (other than default 'all').")
    ap.add_argument("--dry-run", action="store_true",
                    help="Phase 49b: print what stages would run + expected "
                         "artifact paths, then exit without executing.")
    ap.add_argument("--fail-fast", action="store_true",
                    help="Phase 49b: halt the chain if any stage FAILs. "
                         "Default: continue and record FAIL/SUCCESS_WARN "
                         "states in the summary/footer.")
    ap.add_argument("--summary", dest="summary", action="store_true",
                    default=True,
                    help="Phase 49b: print final summary table (default ON).")
    ap.add_argument("--no-summary", dest="summary", action="store_false",
                    help="Suppress the final summary table.")
    ap.add_argument("--no-stage-logs", action="store_true",
                    help="Phase 49b: suppress per-stage log lines (the "
                         "summary table still prints unless --no-summary).")
    ap.add_argument("--no-cost-telemetry", dest="cost_telemetry",
                    action="store_false", default=True,
                    help="PR 210: disable per-stage cost telemetry. Default: "
                         "ON. Emits <ws>/cost_runs/<ts>/stage_*.json "
                         "(advisory walltime + est_cost_usd).")
    ap.add_argument("--rejection", type=Path, default=None,
                    help="Path to a rejection/triage outcome file (or any "
                         "marker path). When given, force --stage "
                         "rejection-learn at the end of the run; otherwise "
                         "rejection-learn does NOT run as part of --stage "
                         "all.")
    args = ap.parse_args()

    canonical_strict = _canonical_strict()
    if canonical_strict:
        if os.environ.get(NO_FAIL_FAST_ENV) == "1":
            print(
                f"[engage] ERR {NO_FAIL_FAST_ENV}=1 is incompatible with "
                f"{CANONICAL_STRICT_ENV}=1",
                file=sys.stderr,
            )
            return 2
        args.fail_fast = True

    # --no-stage-logs collapses into --quiet for the log() helper; the final
    # summary still prints unless --no-summary is also set.
    if args.no_stage_logs:
        args.quiet = True

    # Resolve --stages into an explicit subset (overrides --stage when given).
    selected_stages: list[str] | None = None
    if args.stages:
        requested = [s.strip() for s in args.stages.split(",") if s.strip()]
        valid = {n for n, _, _ in STAGE_TABLE} | {"all"}
        bad = [s for s in requested if s not in valid]
        if bad:
            print(f"[engage] ERR unknown stage(s) in --stages: {bad}. "
                  f"See --help for the list.", file=sys.stderr)
            return 2
        if args.stage != "all":
            print(f"[engage] ERR --stages is mutually exclusive with "
                  f"--stage (got --stage {args.stage}).", file=sys.stderr)
            return 2
        # Preserve canonical chain order, not user order.
        order = [n for n, _, _ in STAGE_TABLE]
        selected_stages = [n for n in order if n in requested]

    ws = args.workspace.expanduser().resolve()
    if not ws.exists() or not ws.is_dir():
        print(f"[engage] ERR workspace not found / not a dir: {ws}", file=sys.stderr)
        return 2

    out_dir = (args.out.expanduser().resolve() if args.out else ws)
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch = out_dir / ".engage_scratch"
    scratch.mkdir(exist_ok=True)

    # --dry-run: list the planned stages + artifacts and exit before any work.
    if args.dry_run:
        if selected_stages is not None:
            plan = selected_stages
        elif args.stage == "all":
            plan = [n for n, _, _ in STAGE_TABLE if n != "rejection-learn"]
            if args.rejection is not None:
                plan.append("rejection-learn")
        else:
            plan = [args.stage]
        art_map = {n: a for n, _, a in STAGE_TABLE}
        print(f"[engage] DRY-RUN workspace={ws}")
        print(f"[engage] DRY-RUN out={out_dir}")
        print(f"[engage] DRY-RUN {len(plan)} stage(s) would run:")
        for n in plan:
            art = art_map.get(n, "?").format(ws=str(ws), out=str(out_dir))
            print(f"  - {n:<20} artifact: {art}")
        print("[engage] DRY-RUN no execution performed.")
        return 0

    t0 = time.time()
    log(f"[engage] workspace={ws}", args.quiet)
    log(f"[engage] out={out_dir}", args.quiet)
    if selected_stages is not None:
        log(f"[engage] stages={','.join(selected_stages)}", args.quiet)
    else:
        log(f"[engage] stage={args.stage}", args.quiet)

    stage = args.stage

    # Phase 49b: track per-stage results for --summary and honor --fail-fast.
    summary_rows: list[dict] = []

    def _should_run(name: str) -> bool:
        """True iff `name` is allowed by --stage / --stages selection."""
        if selected_stages is not None:
            return name in selected_stages
        if (os.environ.get("AUDITOOOR_DEFER_DRIVE") == "1"
                and name in ORDERED_DRIVE_TAIL_STAGES
                and stage == "all"):
            return False
        return stage in ("all", name)

    def _record(name: str, status: str, duration: float,
                artifact: str | None = None) -> None:
        log(f"[stage: {name}] {status}", args.quiet)
        summary_rows.append({
            "stage": name, "status": status,
            "duration": duration, "artifact": artifact or "",
        })

    def _summary_artifact_for(name: str, status: str) -> str:
        """Resolve summary artifacts from the filesystem instead of static templates."""
        if status.startswith("SKIPPED"):
            return "-"
        patterns = SUMMARY_ARTIFACT_PATTERNS.get(name, [])
        if not patterns:
            tpl = next((a for n, _, a in STAGE_TABLE if n == name), "")
            if tpl.startswith("("):
                return "-"
            return "(not checked)"

        matches: list[str] = []
        for pattern in patterns:
            try:
                resolved = pattern.format(ws=str(ws), out=str(out_dir))
            except Exception:
                continue
            expanded = sorted(glob.glob(resolved))
            if expanded:
                matches.extend(expanded)
                continue
            path = Path(resolved)
            if path.exists():
                matches.append(str(path))

        if matches:
            unique_matches = list(dict.fromkeys(matches))
            if len(unique_matches) > 2:
                return f"{', '.join(unique_matches[:2])} (+{len(unique_matches) - 2} more)"
            return ", ".join(unique_matches)

        if status.startswith("SUCCESS") or status.startswith("FAIL"):
            return "(missing)"
        return "-"

    def _artifact_for(name: str) -> str:
        """Compatibility wrapper for shared scan/correlate/dedupe/report paths.

        Most stages record via `_run`, which knows the final status before it
        resolves artifacts. The hand-written shared scan/report path predates
        that helper and still calls `_artifact_for(name)`. Keep this small alias
        so those paths use the same filesystem-backed artifact resolver instead
        of crashing before the summary can be emitted.
        """
        return _summary_artifact_for(name, "SUCCESS")

    def _abort_if_fail_fast(name: str, status: str) -> bool:
        """Return True to propagate a halt (only when --fail-fast + FAIL)."""
        if args.fail_fast and status.startswith("FAIL"):
            log(f"[engage] --fail-fast: halting after {name} ({status})",
                args.quiet)
            return True
        return False

    # PR 210: pin a single run timestamp for this engage invocation so all
    # stages land under the same <ws>/cost_runs/<ts>/ dir.
    cost_enabled = bool(args.cost_telemetry and _cost_telemetry is not None)
    if cost_enabled:
        _cost_telemetry.start_run()

    # Wrapper that runs one stage, records summary, and honors --fail-fast.
    # `fn` takes no args (closure-capture what it needs); returns a status
    # string such as "SUCCESS", "SUCCESS_WARN ...", "SKIPPED", or "FAIL ...".
    # Returns True to halt.
    def _run(name: str, fn) -> bool:
        t_stage = time.time()
        # PR 210: every engage.py stage is a subprocess-or-shell dispatcher
        # (not a direct LLM call). Record walltime with model=None → cost=0;
        # upstream wrappers can call `_cost_telemetry.record_stage(...)` with
        # a model and est_tokens if an LLM ever gets inlined here.
        if cost_enabled:
            cm = _cost_telemetry.record_stage(name, ws, model=None)
            cm.__enter__()
        else:
            cm = None
        try:
            try:
                status = fn() or "SUCCESS"
            except Exception as e:
                status = f"FAIL exc={type(e).__name__}"
                log(f"[engage] EXC in stage {name}: {e!r}", args.quiet)
        finally:
            if cm is not None:
                try:
                    cm.__exit__(None, None, None)
                except Exception as e:
                    log(f"[engage] cost-telemetry warn: {e!r}", args.quiet)
        # Strict ordered runs cannot treat an unresolved stage disposition as
        # advisory. Preserve the diagnostic while changing the stage class so
        # both engage.py and the outer pipeline runner halt at the boundary.
        if (canonical_strict or os.environ.get("PIPELINE_STRICT") == "1") and status.startswith("SUCCESS_WARN"):
            status = f"FAIL strict-pipeline: {status}"
        _record(name, status, time.time() - t_stage,
                _summary_artifact_for(name, status))
        return _abort_if_fail_fast(name, status)

    # INTAKE — mechanical baseline. Runs before orientation/scanners/agents.
    if _should_run("intake-baseline"):
        if _run("intake-baseline", lambda: (stage_intake_baseline(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # Gap E — asset-coverage hard-gate. Block orient/mine-prioritize/mine-briefs
    # when any in-scope asset plan is missing/placeholder/not_started and no
    # waiver is present. Only enforced in chain mode OR when the gated stage
    # is actually selected.
    _asset_ready_cache: dict[str, tuple[bool, str]] = {}

    def _asset_gate_ok(stage_name: str) -> bool:
        try:
            cached = _asset_ready_cache.get("coverage")
            if cached is None:
                cached = _asset_coverage_ready(ws)
                _asset_ready_cache["coverage"] = cached
        except CanonicalStrictJsonError as exc:
            _record(stage_name, f"FAIL {exc}", 0.0, "(invalid intake JSON)")
            print(f"[engage] ERR {exc}", file=sys.stderr)
            return False
        ready, reason = cached
        if not ready:
            _record(stage_name, f"FAIL {reason}", 0.0, "(blocked by asset-coverage gate)")
            print(f"[engage] ERR asset-coverage gate: {reason}", file=sys.stderr)
            return False
        return True

    def _rust_gate_ok(stage_name: str) -> bool:
        try:
            needs, reason = _bdl_asset_requires_rust_scan(ws)
        except CanonicalStrictJsonError as exc:
            _record(stage_name, f"FAIL {exc}", 0.0, "(invalid intake JSON)")
            print(f"[engage] ERR {exc}", file=sys.stderr)
            return False
        if needs:
            _record(stage_name, f"FAIL scan-rust evidence required — {reason}", 0.0,
                    "(blocked by scan-rust gate)")
            print(f"[engage] ERR scan-rust evidence gate: {reason}", file=sys.stderr)
            return False
        return True

    # ORIENT — priming. Runs BEFORE scan when stage=='all'.
    if _should_run("orient"):
        if not _asset_gate_ok("orient"):
            if args.summary: _print_summary(summary_rows)
            return 2
        if _run("orient", lambda: (stage_orient(ws, args.quiet) or "SUCCESS")):
            return 1

    if _should_run("live-checks"):
        if _run("live-checks", lambda: (stage_live_checks(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # Phase 87+ — env-check (before detector scan)
    if _should_run("env-check"):
        if _run("env-check", lambda: (stage_env_check(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # Gap E — scan-rust (asset-conditional). Sequenced BEFORE mine-prioritize
    # so the chain on a fresh BDL/Rust workspace can produce the scan-rust
    # evidence required by `_rust_gate_ok` on `mine-prioritize` / `mine-briefs`.
    # Internally SKIPs when no BDL/Rust asset is in scope.
    # (Codex review on PR #116: placing this after mine-prioritize made the
    # chain deadlock on first run because mine-prioritize gates on the
    # artifact this stage writes.)
    if _should_run("scan-rust"):
        if _run("scan-rust", lambda: (stage_scan_rust(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # SPARK-GAP-001 — scan-go runs unconditionally; the stage itself SKIPs
    # cleanly when no .go files are present, so non-Go workspaces are
    # unaffected. Sequenced after scan-rust to match the canonical chain.
    if _should_run("scan-go"):
        if _run("scan-go", lambda: (stage_scan_go(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    if _should_run("mine-prioritize"):
        if not _asset_gate_ok("mine-prioritize"):
            if args.summary: _print_summary(summary_rows)
            return 2
        if not _rust_gate_ok("mine-prioritize"):
            if args.summary: _print_summary(summary_rows)
            return 2
        if _run("mine-prioritize", lambda: (stage_mine_prioritize(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # SCAN — flow-gate HARD STOP still aborts the whole pipeline (pre-existing
    # behavior) regardless of --fail-fast.
    if _should_run("scan"):
        t_stage = time.time()
        rc = stage_scan(ws, out_dir, args)
        if rc != 0:
            _record("scan", f"FAIL rc={rc}", time.time() - t_stage,
                    _artifact_for("scan"))
            if args.summary:
                _print_summary(summary_rows)
            return rc
        _record("scan", "SUCCESS", time.time() - t_stage, _artifact_for("scan"))

    # CORRELATE / DEDUPE — share one hits-parse pass.
    do_dedupe    = _should_run("dedupe")
    do_correlate = _should_run("correlate")
    # Standalone report ONLY when report is the sole selection (not part of
    # the full chain — the chain emits report after synthesis stages below).
    is_chain = (selected_stages is None and stage == "all")
    do_report_now = (_should_run("report") and not is_chain
                     and not (do_dedupe or do_correlate))
    if do_dedupe or do_correlate or do_report_now:
        t_stage = time.time()
        try:
            rc = stage_dedupe_correlate_report(
                ws, out_dir, scratch, args,
                do_dedupe=do_dedupe, do_correlate=do_correlate,
                do_report=do_report_now)
        except CanonicalStrictJsonError as exc:
            log(f"[engage] {exc}", args.quiet)
            rc = 2
        dur = time.time() - t_stage
        status = "SUCCESS" if rc == 0 else f"FAIL rc={rc}"
        if do_dedupe:
            _record("dedupe", status, dur, _artifact_for("dedupe"))
        if do_correlate:
            _record("correlate", status, dur, _artifact_for("correlate"))
        if do_report_now:
            _record("report", status, dur, _artifact_for("report"))
        if rc != 0:
            if args.summary:
                _print_summary(summary_rows)
            return rc

    # Phase 87+ — cross-workspace patterns, pattern migration, mine-briefs
    if _should_run("cross-ws-patterns"):
        if _run("cross-ws-patterns", lambda: (stage_cross_ws_patterns(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("pattern-migration"):
        if _run("pattern-migration", lambda: (stage_pattern_migration(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("mine-briefs"):
        if not _asset_gate_ok("mine-briefs"):
            if args.summary: _print_summary(summary_rows)
            return 2
        if not _rust_gate_ok("mine-briefs"):
            if args.summary: _print_summary(summary_rows)
            return 2
        if _run("mine-briefs", lambda: (stage_mine_briefs(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # Phase 44b SYNTHESIS
    if _should_run("adversarial-read"):
        if _run("adversarial-read",
                lambda: (stage_adversarial_read(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("attack-tree"):
        if _run("attack-tree",
                lambda: (stage_attack_tree(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("invariants"):
        if _run("invariants",
                lambda: (stage_invariants(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("economic-hypotheses"):
        if _run("economic-hypotheses",
                lambda: (stage_economic_hypotheses(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # FINAL REPORT — emitted as part of the chain (after synthesis, before
    # Phase 45b close-out). Only in chain mode; standalone report handled above.
    chain_runs_report = is_chain or (selected_stages is not None
                                     and "report" in (selected_stages or [])
                                     and (do_dedupe or do_correlate))
    if chain_runs_report and not do_report_now:
        t_stage = time.time()
        rc = stage_dedupe_correlate_report(
            ws, out_dir, scratch, args,
            do_dedupe=False, do_correlate=False, do_report=True)
        dur = time.time() - t_stage
        status = "SUCCESS" if rc == 0 else f"FAIL rc={rc}"
        _record("report", status, dur, _artifact_for("report"))
        if rc != 0:
            if args.summary:
                _print_summary(summary_rows)
            return rc

    # Phase 45a DISPATCH
    if _should_run("dispatch-brief"):
        if _run("dispatch-brief",
                lambda: (stage_dispatch_brief(ws, out_dir, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("capture-intel"):
        if _run("capture-intel",
                lambda: (stage_capture_intel(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("record-triage"):
        if _run("record-triage",
                lambda: (stage_record_triage(ws, out_dir, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # Phase 87+ — agent synthesis, quality gates, packaging
    if _should_run("agent-synthesize"):
        if _run("agent-synthesize", lambda: (stage_agent_synthesize(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("quality-score"):
        if _run("quality-score", lambda: (stage_quality_score(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("auto-fix"):
        if _run("auto-fix", lambda: (stage_auto_fix(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("package"):
        if _run("package", lambda: (stage_package(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # Phase 45b CLOSE-OUT
    if _should_run("pre-submit"):
        if _run("pre-submit",
                lambda: (stage_pre_submit(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    # pre-submit-llm-review: dual-LLM scope+severity review of staging drafts.
    # Runs AFTER the 22-check gate (so the cheap deterministic checks fail
    # fast first) and BEFORE track-submissions (so a consensus OFF-SCOPE
    # never reaches the submission ledger close-out). Offline-safe: degrades
    # to SKIPPED when llm-dispatch.py is missing or every provider call
    # fails (e.g. test env without API keys).
    if _should_run("pre-submit-llm-review"):
        if _run("pre-submit-llm-review",
                lambda: (stage_pre_submit_llm_review(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("track-submissions"):
        if _run("track-submissions", lambda: (stage_track_submissions(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("engagement-retro"):
        if _run("engagement-retro",
                lambda: (stage_engagement_retro(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    # Kimi 20/10 Step 5 — adversarial copilot per-engagement close-out hook.
    # Runs AFTER engagement-retro (so dispatch traces are stable) and BEFORE
    # post-audit-review (so any novelty patterns are visible in the final
    # status table). Dry-run dispatch by default; --live requires explicit
    # AUDITOOOR_LLM_NETWORK_CONSENT and is operator-only.
    if _should_run("adversarial-copilot"):
        if _run("adversarial-copilot",
                lambda: (stage_adversarial_copilot(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    if _should_run("post-audit-review"):
        if _run("post-audit-review",
                lambda: (stage_post_audit_review(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    # PR #560 Lane 4: cheap advisory corpus inventory. Keeps Swival/ZKBugs/
    # ReCon/source-mining rows as detector/harness tasks until exact impact
    # contracts prove a program-impact sentence.
    if _should_run("corpus-detectorization"):
        if _run("corpus-detectorization",
                lambda: (stage_corpus_detectorization(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1
    # V5 G1: expensive source-mining campaign hook. The stage is part of the
    # canonical chain but no-ops unless CAMPAIGN_SOURCE_MINE=1 is explicit.
    if _should_run("campaign-source-mine"):
        if _run("campaign-source-mine",
                lambda: (stage_campaign_source_mine(ws, args) or "SUCCESS")):
            if args.summary: _print_summary(summary_rows)
            return 1

    # rejection-learn: standalone trigger only.
    want_rejection = (stage == "rejection-learn" or args.rejection is not None
                      or (selected_stages is not None
                          and "rejection-learn" in selected_stages))
    if want_rejection:
        _run("rejection-learn",
             lambda: (stage_rejection_learn(ws, args) or "SUCCESS"))

    elapsed = time.time() - t0
    overall = _overall_engage_status(summary_rows)
    log(f"[engage] {overall} in {elapsed:.1f}s", args.quiet)
    if args.summary:
        _print_summary(summary_rows)

    # PR 210: append a one-liner cost footer. Advisory only — never a bill.
    if cost_enabled:
        try:
            ct_summary = _cost_telemetry.summarize_workspace(ws)
            n = ct_summary.get("stage_count", 0)
            if n:
                cost = ct_summary.get("total_est_cost_usd", 0.0)
                dur = ct_summary.get("total_duration_s", 0.0)
                partial = " (partial — some stages walltime-only)" \
                    if ct_summary.get("cost_is_partial") else ""
                log(
                    f"[engage] engagement est cost: ${cost:.4f}, "
                    f"{dur / 60.0:.1f} min across {n} stage(s){partial}. "
                    f"See `make cost-summary WORKSPACE=...` for the full "
                    f"breakdown.",
                    args.quiet,
                )
        except Exception as e:
            log(f"[engage] cost-summary footer warn: {e!r}", args.quiet)
    if canonical_strict and any(
        str(row.get("status", "")).startswith("FAIL") for row in summary_rows
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
