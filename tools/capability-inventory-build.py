#!/usr/bin/env python3
"""
capability-inventory-build.py -- Builds reference/capability_inventory.jsonl
and reference/canonical_flows.jsonl from existing audit artifacts.

Schema: auditooor.capability_inventory.v1
Schema: auditooor.canonical_flow.v1

Each capability_inventory record carries a machine-derivable `role` field, one
of {"finder", "referee", "infra"} (see classify_role), stamped at SOURCE at the
single build point that sees 100% of records. `make capability-role-enum-check`
(under docs-check) fails closed if any record's role is outside that 3-value set.

Usage:
  python3 tools/capability-inventory-build.py [--refresh] [--diff] [--json]

Flags:
  --refresh  Rebuild outputs from current metadata; does not run verification commands
  --diff     Show JSONL capability and flow changes without writing files
  --json     Emit JSON summary instead of human-readable output

Sources consolidated:
  - reports/v3_iter_2026-05-24/lane_WIRING_COMPLETENESS_AUDIT_V3/wiring_completeness_v3.json
  - reports/v3_iter_2026-05-24/lane_MCP_WIRING_AUDIT/mcp_wiring_audit.json
  - reports/v3_iter_2026-05-24/capability_patch_queue.md
  - tools/vault-mcp-server.py (TOOL_SCHEMAS)
  - Makefile (.PHONY + target list)
  - ~/.claude/CLAUDE.md (R-rule registry)
  - tools/*.py (top tools by size)
"""

from __future__ import annotations
import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_DIR = REPO_ROOT / "reference"
INVENTORY_OUT = REFERENCE_DIR / "capability_inventory.jsonl"
FLOWS_OUT = REFERENCE_DIR / "canonical_flows.jsonl"
DOCS_DIR = REPO_ROOT / "docs"

WIRING_V3_JSON = REPO_ROOT / "reports/v3_iter_2026-05-24/lane_WIRING_COMPLETENESS_AUDIT_V3/wiring_completeness_v3.json"
MCP_WIRING_JSON = REPO_ROOT / "reports/v3_iter_2026-05-24/lane_MCP_WIRING_AUDIT/mcp_wiring_audit.json"
CAP_PATCH_QUEUE = REPO_ROOT / "reports/v3_iter_2026-05-24/capability_patch_queue.md"
VAULT_MCP_SERVER = REPO_ROOT / "tools/vault-mcp-server.py"
MAKEFILE = REPO_ROOT / "Makefile"
CLAUDE_MD = Path.home() / ".claude/CLAUDE.md"

NOW_ISO = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _ascii_dash_text(value: str) -> str:
    return value.replace("\u2014", "-").replace("\u2013", "-")


def _ascii_dash_payload(value: Any) -> Any:
    if isinstance(value, str):
        return _ascii_dash_text(value)
    if isinstance(value, list):
        return [_ascii_dash_payload(v) for v in value]
    if isinstance(value, dict):
        return {k: _ascii_dash_payload(v) for k, v in value.items()}
    return value

# ---------------------------------------------------------------------------
# Status constants
# ---------------------------------------------------------------------------
STATUS_LANDED = "LANDED"
STATUS_NOMINAL = "NOMINAL-WIRED"
STATUS_PARTIAL = "PARTIAL"
STATUS_BROKEN = "KNOWN-BROKEN"
STATUS_DEPRECATED = "DEPRECATED"

# ---------------------------------------------------------------------------
# Role classification (WAVE-2 items 11+12)
# ---------------------------------------------------------------------------
# A machine-derivable {finder, referee, infra} role stamped at SOURCE so
# vault_capability_inventory can be filtered by WHAT a capability does:
#   - finder  : discovers candidate bugs (detectors, hunters)
#   - referee : adjudicates a draft/finding (gates, checks, guards, verifiers)
#   - infra   : everything else (build/load/context/report/orchestration)
# Pure, first-match, single stamping point in build_inventory() (sees 100%).
VALID_ROLES = ("finder", "referee", "infra")

# REFEREE stems: gates/checks/guards/verifiers that adjudicate a finding.
REFEREE_RE = re.compile(
    r"check|verify|guard|gate|preflight|enforce|precheck|conformance|attest|validat|lint|refut"
)
# FINDER stems: detectors that discover candidate bugs.
FINDER_RE = re.compile(r"\bdetector")


def classify_role(cap: dict) -> str:
    """Pure first-match role classifier; returns one of VALID_ROLES.

    Precedence (first match wins):
      1. category r-rule / gate      -> referee (rules + gates adjudicate)
      2. category detector-pattern   -> finder  (a detector finds bugs)
      3. REFEREE_RE matches the stem -> referee
      4. FINDER_RE matches the stem  -> finder
      5. default                     -> infra
    """
    cat = cap.get("category") or ""
    if cat in ("r-rule", "gate"):
        return "referee"
    if cat == "detector-pattern":
        return "finder"
    stem = (cap.get("name") or "").lower()
    if REFEREE_RE.search(stem):
        return "referee"
    if FINDER_RE.search(stem):
        return "finder"
    return "infra"

# Description overrides for auto-indexed tools whose module stem contains "_"
# (so they cannot go in KEY_PYTHON_TOOLS without producing an invalid
# underscore-bearing CAP-tool-<stem> id). Keyed by module stem; the value
# replaces the auto-derived docstring summary so the front door is honest.
AUTO_TOOL_DESC_OVERRIDES = {
    "realfn_token_guard": (
        "realfn_token_guard.py - shared anti-fabrication guard for the EVM/Rust "
        "auto-converters: refuses to emit a 'proof' unless the cited fn/token is "
        "REAL in the target source, so an unbundled real target returns "
        "blocked-with-obligation instead of a synthesized pass. Proven on the "
        "converter fixtures; not yet exercised on a blind real target."
    ),
}


def _load_json_safe(path: Path) -> Any:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Source 1: vault-mcp-server.py - extract all callable names + descriptions
# ---------------------------------------------------------------------------
def extract_mcp_callables() -> list[dict]:
    content = _read_text_safe(VAULT_MCP_SERVER)
    # Extract callable names from "name": "vault_..." pattern
    names = re.findall(r'"name":\s*"(vault_[^"]+)"', content)
    unique_names = sorted(set(names))

    # Extract brief descriptions from docstring comments near each callable
    # Pattern: the callable name appears in a def _handle_ block or a dict entry
    caps = []
    for name in unique_names:
        # Try to find a description nearby
        pattern = rf'"name":\s*"{re.escape(name)}".*?"description":\s*"([^"]+)"'
        m = re.search(pattern, content, re.DOTALL)
        desc = m.group(1)[:200] if m else f"MCP callable: {name}"

        caps.append({
            "id": f"CAP-mcp-{name.replace('_', '-')}",
            "name": name,
            "category": "mcp-callable",
            "description": desc,
            "inputs": [],
            "outputs": [{"name": "json_response", "type": "dict", "destination": "caller"}],
            "file_paths": ["tools/vault-mcp-server.py"],
            "dependencies": [],
            "consumers": [],
            "verification_command": f"cd /Users/wolf/auditooor-mcp && python3 tools/vault-mcp-server.py --call {name} --args '{{\"limit\":1}}' 2>&1 | head -3",
            "expected_verification_output": r"\{|error",
            "status": STATUS_NOMINAL,
            "known_bugs": [],
            "last_verified_at": None,
            "verification_history": [],
            "canonical_flow_refs": [],
            "notes": "",
        })
    return caps


# ---------------------------------------------------------------------------
# Source 2: Makefile targets
# ---------------------------------------------------------------------------
KEY_MAKE_TARGETS = {
    "audit": ("make-target", "Run full audit pipeline: engage, detect, cluster, MCP index all findings",
               "make audit WS=<workspace> [DRY_RUN=1]", STATUS_LANDED,
               "make audit WS=/tmp/test-ws DRY_RUN=1 2>&1 | head -5", r"Usage:|ERR|audit"),
    "audit-run-full": ("make-target", "Canonical end-to-end workspace front door: strict intake truth, bounded preflight, hunt, conversion/proof artifact planning, formal-spec obligations, and closeout gates. Autonomous proof conversion is advisory by default and hard-fails only with AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1; the target exports its child-target proof flag internally from that make variable.",
                       "make audit-run-full WS=<workspace> STRICT=1 EXECUTE_READY=1 [TOP_N=10] [MAX_FUNCTIONS=0] [AUDIT_RUN_FULL_MIN_FREE_MB=25600] [AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=0|1] [JSON=1]", STATUS_LANDED,
                       "cd /Users/wolf/auditooor-mcp && make audit-run-full 2>&1 | head -4", r"Usage:|audit-run-full"),
    "audit-fast": ("make-target", "Fast audit: generate LIVE_TARGET_REPORT.md and adversarial hypothesis top-5 (skips full MCP index)",
                   "make audit-fast WS=<workspace> [TOP_N=50]", STATUS_LANDED,
                   "cd /Users/wolf/auditooor-mcp && make audit-fast 2>&1 | head -3", r"Usage:|TOP_N"),
    "audit-deep": ("make-target", "Deep audit: run all detectors with full predicate matching + MCP context enrichment",
                   "make audit-deep WS=<workspace>", STATUS_PARTIAL,
                   "cd /Users/wolf/auditooor-mcp && make audit-deep 2>&1 | head -3", r"Usage:|ERR|audit-deep"),
    "hunt": ("make-target", "4-step hunting workflow: audit-fast + brain_prime + exploit_queue + known_dead_ends",
             "make hunt WS=<workspace> [TOP_N=10]", STATUS_LANDED,
             "cd /Users/wolf/auditooor-mcp && make hunt 2>&1 | head -3", r"Usage:|hunt bundles"),
    "evm-0day-proof": ("make-target", "Run the EVM proof pipeline on one candidate or exploit-queue row",
                       "make evm-0day-proof WS=<workspace> CANDIDATE=<row.json>|QUEUE=<exploit_queue.json> [LEAD_ID=<id>]",
                       STATUS_LANDED,
                       "cd /Users/wolf/auditooor-mcp && make evm-0day-proof 2>&1 | head -3", r"Usage:|evm-0day-proof"),
    "corpus-driven-hunt": ("make-target", "Convert trusted corpus invariants and hacker questions into target-grounded proof-queue fuel",
                           "make corpus-driven-hunt WS=<workspace> [TOP_N=25] [MAX_FUNCTIONS=all] [EMIT_PROOF_QUEUE=1] [JSON=1]",
                           STATUS_LANDED,
                           "cd /Users/wolf/auditooor-mcp && make corpus-driven-hunt 2>&1 | head -3", r"Usage:|corpus-driven-hunt"),
    "fresh-target-forward-test": ("make-target", "Run a locked fresh-target forward test and write measurement evidence",
                                  "make fresh-target-forward-test WS=<workspace> REPO=github.com/Owner/Repo PIN=<sha> [CANDIDATE=<row.json>] [JSON=1]",
                                  STATUS_LANDED,
                                  "cd /Users/wolf/auditooor-mcp && make fresh-target-forward-test 2>&1 | head -3", r"Usage:|fresh-target-forward-test"),
    "cvl-spec-risk-scan": ("make-target", "Inventory Certora/CVL spec assumptions, summaries, filters, ghosts, and vacuity risks as proof obligations",
                           "make cvl-spec-risk-scan WS=<workspace> [JSON=1] [OUT=<path>]",
                           STATUS_LANDED,
                           "cd /Users/wolf/auditooor-mcp && make cvl-spec-risk-scan 2>&1 | head -4", r"Usage:|cvl-spec-risk-scan"),
    "pre-submit-check": ("make-target", "Run 100+ pre-submission checks on a draft (R-rules, v3-grade PoC, etc.)",
                         "bash tools/pre-submit-check.sh <draft.md> [--severity HIGH]", STATUS_LANDED,
                         "bash /Users/wolf/auditooor-mcp/tools/pre-submit-check.sh --help 2>&1 | head -5", r"Usage:|pre-submit|Check"),
    "docs-check": ("make-target", "Cross-link validation + MCP callable count check + doc cascade check",
                   "make docs-check", STATUS_NOMINAL,
                   "cd /Users/wolf/auditooor-mcp && make docs-check 2>&1 | tail -5", r"ok|broken|mcp-callable"),
    "capability-status": ("make-target", "Show capability readiness: detectors, MCP callables, workspaces",
                          "make capability-status WS=<workspace>", STATUS_NOMINAL,
                          "cd /Users/wolf/auditooor-mcp && make capability-status 2>&1 | head -5", r"Usage:|capability"),
    "r28-check": ("make-target", "R28: multi-path escalation merge check for a draft",
                  "make r28-check WS=<ws> DRAFT=<draft>", STATUS_NOMINAL,
                  "cd /Users/wolf/auditooor-mcp && make r28-check 2>&1 | head -3", r"Usage:|r28"),
    "r43-check": ("make-target", "R43: load-bearing bytes attribution check",
                  "make r43-check WS=<ws> DRAFT=<draft>", STATUS_NOMINAL,
                  "cd /Users/wolf/auditooor-mcp && make r43-check 2>&1 | head -3", r"Usage:|r43"),
    "r45-check": ("make-target", "R45: designed-as-intended precheck for HIGH+ omission findings",
                  "make r45-check WS=<ws> DRAFT=<draft>", STATUS_NOMINAL,
                  "cd /Users/wolf/auditooor-mcp && make r45-check 2>&1 | head -3", r"Usage:|r45"),
    "r52-check": ("make-target", "R52: rubric row coverage check",
                  "make r52-check WS=<ws> DRAFT=<draft>", STATUS_NOMINAL,
                  "cd /Users/wolf/auditooor-mcp && make r52-check 2>&1 | head -3", r"Usage:|r52"),
    "r57-check": ("make-target", "R57: exhaustive defense chain enumeration check",
                  "make r57-check WS=<ws> DRAFT=<draft>", STATUS_NOMINAL,
                  "cd /Users/wolf/auditooor-mcp && make r57-check 2>&1 | head -3", r"Usage:|r57"),
    "capability-check": ("make-target", "Run capability verification for a specific capability ID",
                         "make capability-check NAME=<cap-id>", STATUS_LANDED,
                         "cd /Users/wolf/auditooor-mcp && make capability-check 2>&1 | head -3", r"Usage:|capability"),
    "capability-check-all": ("make-target", "Run all capability verifications",
                             "make capability-check-all", STATUS_LANDED,
                             "cd /Users/wolf/auditooor-mcp && make capability-check-all 2>&1 | head -3", r"capability|check"),
    "audit-prep": ("make-target", "Prepare workspace for audit: create .auditooor/ scaffolding",
                   "make audit-prep WS=<workspace>", STATUS_NOMINAL,
                   "cd /Users/wolf/auditooor-mcp && make audit-prep 2>&1 | head -3", r"Usage:|audit-prep"),
    "wave3-originality-scan": ("make-target", "Originality scan against public sources for a draft",
                               "make wave3-originality-scan DRAFT=<path> TARGET=<protocol>", STATUS_NOMINAL,
                               "cd /Users/wolf/auditooor-mcp && make wave3-originality-scan 2>&1 | head -3", r"Usage:|originality"),
    "wave3-cluster-to-hacker-brief": ("make-target", "Convert engage_report.md clusters to hacker briefs",
                                      "make wave3-cluster-to-hacker-brief WS=<ws> ALL=1", STATUS_NOMINAL,
                                      "cd /Users/wolf/auditooor-mcp && make wave3-cluster-to-hacker-brief 2>&1 | head -3", r"Usage:|cluster|brief"),
    "forge-test": ("make-target", "Operator-friendly Foundry forge test runner wrapper",
                   "make forge-test WS=<ws>", STATUS_NOMINAL,
                   "cd /Users/wolf/auditooor-mcp && make forge-test 2>&1 | head -3", r"Usage:|forge"),
    "r28-check-all": ("make-target", "R28: run multi-path escalation merge check on ALL drafts in WS",
                      "make r28-check-all WS=<ws>", STATUS_NOMINAL,
                      "cd /Users/wolf/auditooor-mcp && make r28-check-all 2>&1 | head -3", r"Usage:|r28"),
    "rule-sync": ("make-target", "Sync rule digest from ~/.claude/CLAUDE.md to codified_rules_digest.json",
                  "make rule-sync", STATUS_NOMINAL,
                  "cd /Users/wolf/auditooor-mcp && make rule-sync 2>&1 | head -3", r"Sync|rule|ok"),
}

def extract_make_targets() -> list[dict]:
    caps = []
    for target, (cat, desc, usage, status, verify_cmd, verify_pat) in KEY_MAKE_TARGETS.items():
        caps.append({
            "id": f"CAP-make-{target}",
            "name": f"make {target}",
            "category": cat,
            "description": desc,
            "inputs": [{"name": "WS", "type": "path", "required": True, "source": "env/arg"}],
            "outputs": [{"name": "stdout", "type": "text", "destination": "terminal"}],
            "file_paths": ["Makefile"],
            "dependencies": [],
            "consumers": [],
            "verification_command": verify_cmd,
            "expected_verification_output": verify_pat,
            "status": status,
            "known_bugs": [],
            "last_verified_at": None,
            "verification_history": [],
            "canonical_flow_refs": [],
            "notes": f"Usage: {usage}",
        })
    return caps


# ---------------------------------------------------------------------------
# Source 3: R-rules from CLAUDE.md
# ---------------------------------------------------------------------------
CRITICAL_R_RULES = [
    ("R18", "L32", "in-process-vs-node-level-evidence", "HIGH/CRIT submissions with production-runtime rubric must include node-level PoC (not in-process microbenchmark)", "tools/in-process-vs-node-level-check.py", "Check #58", STATUS_LANDED),
    ("R19", "R19", "real-execution-path-required", "State-machine-write-path claims (AppHash, block execution, commit pipeline) must use real ABCI surface", "tools/in-process-vs-node-level-check.py", "Check #58", STATUS_LANDED),
    ("R20", "R20", "no-fault-injection", "Do not inject CheckTx-side faults (sleep/delay/latency shims) in HIGH/CRIT PoC", None, "Check #60", STATUS_LANDED),
    ("R21", "R21", "permanent-impact-five-ask-template", "Permanent-class impact claims must address 5 triager asks in top-of-response section", "tools/permanent-impact-five-ask-template-check.py", "Check #66", STATUS_LANDED),
    ("R22", "R22", "restart-survival-required", "HIGH/CRIT permanent-class claims must include restart-survival evidence", "tools/restart-survival-check.py", "Check #61", STATUS_LANDED),
    ("R23", "R23", "comparative-baseline-required", "HIGH/CRIT with weakened parameter must include same-workload comparative run", "tools/comparative-baseline-check.py", "Check #65", STATUS_LANDED),
    ("R24", "R24", "non-self-impact-required", "HIGH+ fund-loss claims must prove impact on funds attacker does NOT control", "tools/non-self-impact-check.py", "Check #62", STATUS_LANDED),
    ("R25", "R25", "defense-in-depth-traversal-required", "HIGH/CRIT must demonstrate attack tx survives every defense layer to reach claimed impact", "tools/defense-in-depth-traversal-check.py", "Check #63", STATUS_LANDED),
    ("R26", "R26", "ante-handler-traversal-required", "Cosmos-SDK Msg findings at HIGH/CRIT must traverse real ante decorator chain", "tools/ante-handler-traversal-check.py", "Check #64", STATUS_LANDED),
    ("R27", "R27", "adjacent-finding-disclosure", "Do not paste when adjacent in-flight submission shares evidence that discloses current attack surface", "tools/adjacent-finding-disclosure-check.py", "Check #59", STATUS_LANDED),
    ("R28", "R28", "multi-path-escalation-merge", "Wait for ALL in-flight paths targeting same bug class to land, merge into one response, paste once", "tools/multi-path-escalation-merge-check.py", "Check #100", STATUS_LANDED),
    ("R29", "R29", "commitment-vs-validation-gap", "HIGH+ multi-party/cooperative claims must have Commitment & Protection Analysis section", "tools/commitment-vs-validation-check.py", "Check #94", STATUS_LANDED),
    ("R30", "R30", "production-profile-poc-required", "HIGH/CRIT DB/storage/IO/timing claims must use production backends (goleveldb etc.), no timing shims", "tools/production-profile-preflight-check.py", "Check #67", STATUS_LANDED),
    ("R34", "R34", "control-test-discipline-required", "HIGH/CRIT single-correlation causation must include control-run PoC or alternative-cause exclusion", "tools/control-test-discipline-check.py", "Check #69", STATUS_LANDED),
    ("R35", "R35", "dos-class-reframe-before-filing", "Do not file HIGH+ generic DoS findings without separately proven non-DoS production impact", "tools/dos-class-reframe-check.py", "Check #90", STATUS_LANDED),
    ("R38", "R38", "bug-class-shift-detection", "HIGH/CRIT attack_class must match cited rubric row's expected class", "tools/bug-class-shift-check.py", "Check #73", STATUS_LANDED),
    ("R39", "R39", "attack-class-orphan-flag", "HIGH/CRIT orphan attack_class (< 20 corpus records) must be normalized or rebutted", "tools/attack-class-orphan-check.py", "Check #74", STATUS_LANDED),
    ("R40", "R40", "v3-grade-poc-required", "MEDIUM+ fund-loss/state-corruption claims must have V3-grade PoC (real entrypoint, real defense traversal, negative control, before/after assertions)", "tools/v3-grade-poc-check.py", "Check #84", STATUS_LANDED),
    ("R41", "R41", "per-finding-submission-folder-structure", "All submission artifacts must live in submissions/<status>/<slug>/<slug>.<ext> per-finding folder", "tools/submission-folder-structure-check.py", "Check #85", STATUS_LANDED),
    ("R42", "R42", "configured-impact-trace-required", "MEDIUM+ config-dependent claims must have Configured-Impact Trace with 5 fields", "tools/configured-impact-trace-check.py", "Check #89", STATUS_LANDED),
    ("R43", "R43", "load-bearing-bytes-attribution-required", "Dispute/triager-response drafts arguing against defender narrative must enumerate load-bearing bytes with signer set", "tools/load-bearing-bytes-attribution-check.py", "Check #91", STATUS_LANDED),
    ("R44", "R44", "opposed-trace-actor-separation", "Opposed-trace harness must separate attacker/defender roles with distinct signing material", "tools/opposed-trace-actor-separation-check.py", "Check #92", STATUS_LANDED),
    ("R45", "R45", "designed-as-intended-precheck-required", "HIGH+ omission findings must include Designed-As-Intended Precheck section searching public docs", "tools/designed-as-intended-precheck.py", "Check #93", STATUS_LANDED),
    ("R46", "R46", "trusted-infrastructure-compromise", "HIGH+ findings requiring trusted-infra compromise must include Trusted Infrastructure Tabulation", "tools/trusted-infrastructure-compromise-check.py", "Check #95", STATUS_LANDED),
    ("R47", "R47", "acknowledged-wont-fix", "HIGH+ with team-acknowledged-in-public root cause must include Acknowledgement Scan + extension-distinct evidence", "tools/acknowledged-wont-fix-check.py", "Check #96", STATUS_LANDED),
    ("R48", "R48", "deployment-topology-vs-attack-surface", "HIGH+ topology-restricted findings must include Deployment Topology Attack Surface section", "tools/deployment-topology-vs-attack-surface-check.py", "Check #98", STATUS_LANDED),
    ("R52", "R52", "rubric-row-coverage", "ANY draft must verbatim-match at least one rubric row in SEVERITY.md before paste_ready promotion", "tools/rubric-row-coverage-check.py", "Check #97", STATUS_LANDED),
    ("R53", "R53", "prior-audit-finding-supersede-check", "HIGH+ drafts must include Prior-Audit Supersede Scan when prior_audits/ exists", "tools/prior-audit-finding-supersede-check.py", "Check #99", STATUS_LANDED),
    ("R54", "R54", "external-url-liveness-required", "ANY draft with external URLs must verify all URLs live before paste_ready promotion", "tools/external-url-liveness-check.py", "Check #101", STATUS_LANDED),
    ("R55", "R55", "integration-commit-preserves-sibling-work", "No destructive git ops while sibling lanes have uncommitted edits in R36-declared pathspec", "tools/git-hooks/pre-destructive-op-sibling-check.sh", "pre-commit hook", STATUS_LANDED),
    ("R56", "R56", "rubric-fit-at-program-level", "MEDIUM+ findings must demonstrate affected component is on program's CORE product surface", "tools/rubric-fit-program-level-check.py", "Check #102", STATUS_LANDED),
    ("R57", "R57", "exhaustive-defense-chain-enumeration", "HIGH+ defender-contesting drafts must enumerate every defense code path in defender codebase", "tools/exhaustive-defense-chain-enumeration-check.py", "Check #104", STATUS_LANDED),
    ("R58", "R58", "invariant-grounded-finding-required", "MEDIUM+ drafts for attack classes covered by P1 invariant library must cite an indexed INV-* ID", "tools/invariant-grounded-finding-check.py", "Check #105", STATUS_LANDED),
    ("L30", "L30", "missing-guard-callsite-enumeration", "Missing-guard-class findings must enumerate ALL call sites (not just the found one) before filing", "tools/missing-guard-callsite-enumerator.sh", "Check #48", STATUS_LANDED),
    ("L31", "L31", "dupe-preflight", "Pre-filing duplicate check using Q1 (different files?) and Q2 (same fix?) against prior reports", "tools/duplicate-preflight-check.py", "Check #49", STATUS_LANDED),
    ("L34", "L34", "draft-modification-requires-operator-auth", "Do not modify existing draft files under submissions/<status>/<slug>/ without per-draft operator authorization", "tools/l34-path-classifier.py", "Check #102 (informational)", STATUS_LANDED),
    ("R36", "R36", "parallel-worktree-commit-pathspec-discipline", "Every git commit in shared worktree must stage with explicit per-file pathspec (no git add -A)", "tools/git-hooks/pre-commit-pathspec-discipline.sh", "pre-commit hook", STATUS_LANDED),
    ("R37", "R37", "hackerman-record-tier-declared-at-emit", "Every corpus record emit must declare verification_tier in first-class field at emit time", None, "Check #72", STATUS_LANDED),
]

def extract_r_rules() -> list[dict]:
    caps = []
    for r_id, short_id, slug, desc, tool_path, check_num, status in CRITICAL_R_RULES:
        caps.append({
            "id": f"CAP-rule-{short_id.lower()}-{slug}",
            "name": f"Rule {r_id}: {slug}",
            "category": "r-rule",
            "description": desc,
            "inputs": [{"name": "draft_path", "type": "path", "required": True, "source": "operator"}],
            "outputs": [{"name": "verdict", "type": "text", "destination": "stdout"}],
            "file_paths": [p for p in [tool_path, "tools/pre-submit-check.sh"] if p],
            "dependencies": [],
            "consumers": ["CAP-make-pre-submit-check"],
            "verification_command": f"cd /Users/wolf/auditooor-mcp && python3 {tool_path} --help 2>&1 | head -3" if tool_path and tool_path.endswith(".py") else f"bash /Users/wolf/auditooor-mcp/{tool_path} --help 2>&1 | head -3" if tool_path and tool_path.endswith(".sh") else None,
            "expected_verification_output": r"usage|Usage|help",
            "status": status,
            "known_bugs": [],
            "last_verified_at": None,
            "verification_history": [],
            "canonical_flow_refs": ["FLOW-pre-submit-check"],
            "notes": f"{check_num} in pre-submit-check.sh. Override: <!-- {short_id.lower()}-rebuttal: <reason> -->",
        })
    return caps


# ---------------------------------------------------------------------------
# Source 4: Known bugs from CAP patch queue
# ---------------------------------------------------------------------------
def extract_cap_bugs() -> list[dict]:
    """Parse CAP-YYYY-MM-DD-NNN entries from capability_patch_queue.md."""
    text = _read_text_safe(CAP_PATCH_QUEUE)
    bugs = []
    # Extract CAP entries: ### CAP-.... - title
    cap_pattern = re.compile(r"^### (CAP-[^\n]+)\n(.*?)(?=^### CAP-|\Z)", re.MULTILINE | re.DOTALL)
    for m in cap_pattern.finditer(text):
        cap_id = m.group(1).strip()
        body = m.group(2).strip()

        # Parse symptom / root cause / patch needed
        symptom = ""
        root_cause = ""
        patch = ""
        for line in body.split("\n"):
            if line.startswith("- Symptom:"):
                symptom = line[len("- Symptom:"):].strip()[:300]
            elif line.startswith("- Root cause:"):
                root_cause = line[len("- Root cause:"):].strip()[:200]
            elif line.startswith("- Patch needed:"):
                patch = line[len("- Patch needed:"):].strip()[:200]

        bugs.append({
            "cap_id": cap_id,
            "severity": "MEDIUM",
            "description": symptom[:250] if symptom else body[:250],
            "root_cause": root_cause,
            "workaround": patch or "See cap_id entry in capability_patch_queue.md",
            "status": "OPEN",
        })
    return bugs


# ---------------------------------------------------------------------------
# Source 5: Key Python tools (top 30 by file size = most substantial)
# ---------------------------------------------------------------------------
KEY_PYTHON_TOOLS = {
    "tools/vault-mcp-server.py": ("python-tool", "MCP server with 107 vault_ callables for context, routing, evidence lookup, and dispatch", STATUS_LANDED),
    "tools/pre-submit-check.sh": ("shell-tool", "Pre-submission gate: runs 100+ checks (R18-R58, L28-L34) against a draft before paste_ready promotion", STATUS_LANDED),
    "tools/live-target-intelligence-report.py": ("python-tool", "Generates LIVE_TARGET_REPORT.md: ranked candidates with P1/P3/P5 scores, adversarial hypotheses top-5", STATUS_PARTIAL),
    "tools/agent-pathspec-register.py": ("python-tool", "R36/R55: register per-lane file ownership declaration in .auditooor/agent_pathspec.json", STATUS_LANDED),
    "tools/lane-integrator.py": ("python-tool", "Integrates lane outputs into main branch: discovers changed files, stages, commits with MCP pack_id", STATUS_LANDED),
    "tools/capability-inventory-build.py": ("python-tool", "Builds reference/capability_inventory.jsonl and reference/canonical_flows.jsonl from audit artifacts", STATUS_LANDED),
    "tools/state-coupling-graph.py": ("python-tool", "State-Coupling Graph (SCG) emitter: builds state_coupling_edges.jsonl (the Aptos-class coupled-state axis) - conserved-with / co-accumulation / freshness / interruption / shared-cursor plus the 14th kind stale-handle-after-recycle (R1 handle-freshness arm: a reusable identity handle whose slot is freed+reissued and a persisted holder resolves it BLINDLY without a binding-freshness re-check, the Hexens Aptos Move-VM struct-hijack shape). The handle-freshness arm EMITS under env SCG_HANDLE_FRESHNESS (set by check_state_coupling so it feeds the hunt + exploit-queue) and FAILS-CLOSED under AUDITOOOR_HANDLE_FRESHNESS_ENFORCE (advisory-first; un-analyzed-inscope anti-silent-suppression block). Consumed by state-coupling-completeness-check.py (L37 state-coupling signal) + exploit-queue.py _gather_from_state_coupling.", STATUS_PARTIAL),
    "tools/capability-check.py": ("python-tool", "Runs verification_command for a specific capability and updates verification_history", STATUS_LANDED),
    "tools/wave3-capability-dashboard.py": ("python-tool", "Single-command capability state snapshot across detectors, MCP callables, workspaces, Wave criteria", STATUS_NOMINAL),
    "tools/hackerman-etl-from-solodit.py": ("python-tool", "ETL miner: ingests Solodit findings into tier-2 corpus records at audit/corpus_tags/tags/", STATUS_NOMINAL),
    "tools/engage-report-generator.py": ("python-tool", "Generates engage_report.md from detector hits, clustered by bug class, with per-cluster scoring", STATUS_LANDED),
    "tools/evm-0day-proof-pipeline.py": ("python-tool", "EVM proof driver: converts one candidate or queue row into proof-backed, refuted, or blocked verdict. Detects obl3 inherited-ERC4626 first-depositor/share-inflation surface (inherited deposit -> share math denominator donation) and obl4 multi-arg role-ctor authoring + OZ super.deposit->ERC4626 base->_deposit override binder. Proven on tool-authored UNSEEN fixtures only; the blind real-target +1 (out-of-project OZ-override binder) is NOT yet fired - unbundled real targets return blocked-with-obligation, never a fabricated proof.", STATUS_LANDED),
    "tools/engine-auto-convert.py": ("python-tool", "Rust/Go 0-day PROOF driver: auto-converts a candidate {target_file,fn,vuln_class,language} into a vulnerable+fixed pair and runs it. Carries Rust-parity families signature-replay/missing-nonce (guard=used-nonce-check), unchecked-external-call-return (guard=call-return-check), missing-deadline/slippage-bound (guard=deadline-bound-check). Proven on the 2 bundled IN_PLACE_SPECS fixtures only; an unbundled real target returns blocked-with-obligation, NOT a proof - does not convert arbitrary real targets yet.", STATUS_PARTIAL),
    "tools/cvl-spec-risk-scan.py": ("python-tool", "Scans Certora/CVL specs and confs for vacuity, summary, ghost, filter, revert-pruning, and assumption obligations", STATUS_LANDED),
    "tools/audit-mcp-preflight.py": ("python-tool", "MCP preflight: verifies vault context is fresh before audit-deep proceeds", STATUS_NOMINAL),
    "tools/detector-runner.py": ("python-tool", "Runs all pattern-DSL detectors against a workspace; feeds engage_report generation", STATUS_LANDED),
    "tools/duplicate-preflight-check.py": ("python-tool", "L31 dupe preflight: Q1+Q2 duplicate check against prior submissions in workspace", STATUS_LANDED),
    "tools/l34-path-classifier.py": ("python-tool", "L34: classifies a path as draft-file/tracker-file/workspace-ledger/lesson-anchor/out-of-scope", STATUS_LANDED),
    "tools/v3-grade-poc-check.py": ("python-tool", "R40: verifies PoC is V3-grade (real entrypoint, defense traversal, negative control, before/after assertions)", STATUS_LANDED),
    "tools/rubric-row-coverage-check.py": ("python-tool", "R52: verifies draft impact wording verbatim-matches at least one SEVERITY.md rubric row", STATUS_LANDED),
    "tools/configured-impact-trace-check.py": ("python-tool", "R42: verifies Configured-Impact Trace section with all 5 fields for config-dependent claims", STATUS_LANDED),
    "tools/designed-as-intended-precheck.py": ("python-tool", "R45: verifies HIGH+ omission findings include Designed-As-Intended Precheck section", STATUS_LANDED),
    "tools/exhaustive-defense-chain-enumeration-check.py": ("python-tool", "R57: verifies every defense code path in defender codebase is enumerated in draft table", STATUS_LANDED),
    "tools/external-url-liveness-check.py": ("python-tool", "R54: verifies all cited external URLs in a draft are live (HTTP HEAD probe)", STATUS_LANDED),
    "tools/deployment-topology-vs-attack-surface-check.py": ("python-tool", "R48: verifies HIGH+ topology-restricted findings have Deployment Topology Attack Surface section", STATUS_LANDED),
    "tools/prior-audit-finding-supersede-check.py": ("python-tool", "R53: scans prior_audits/ corpus for prior acknowledgement of draft's root cause", STATUS_LANDED),
    "tools/acknowledged-wont-fix-check.py": ("python-tool", "R47: scans GHSA/SECURITY.md/SRL catalogs for team-acknowledged won't-fix of draft's root cause", STATUS_LANDED),
    "tools/load-bearing-bytes-attribution-check.py": ("python-tool", "R43: verifies dispute drafts enumerate load-bearing bytes, production site, signer set, attacker intersect", STATUS_LANDED),
    "tools/dos-class-reframe-check.py": ("python-tool", "R35: blocks HIGH+ generic DoS filings without separately proven non-DoS production impact", STATUS_LANDED),
    "tools/production-profile-preflight-check.py": ("python-tool", "R30: verifies HIGH/CRIT DB/storage/IO claims use production backends, no timing shims", STATUS_LANDED),
    "tools/multi-path-escalation-merge-check.py": ("python-tool", "R28: detects multiple in-flight escalation paths for same Cantina submission ID", STATUS_LANDED),
    "tools/memory-context-load.py": ("python-tool", "Verifies MCP context freshness and loads memory sections; use --check --json at session start", STATUS_NOMINAL),
    "tools/reasoner-triple-to-hacker-q.py": ("python-tool", "Pre-hunt reasoner-triple lift: parses _REASONER_LEDGERS from logic-obligation-resolution-check.py, extracts each reasoner's docstring LOGIC TRIPLE (ASSUMPTION/INVARIANT/TRUST-BOUNDARY/FINDING) or REASONING QUERY, and appends one OPEN row per reasoner into the flat hacker_questions_library.jsonl (source=reasoner-triple:<name>) so corpus-driven-hunt.py / mimo-per-file-batch-gen.py steer on the SAME reasoned obligation the reasoner emits. Append-only, dedup-safe, routing-integrity-safe target_languages.", STATUS_LANDED),
    "tools/hackerman-q-to-detector-promote.py": ("python-tool", "Question -> reasoner EVOLUTION pipeline: sequences four pre-existing promotion primitives (hypothesis-to-detector -> overnight-detector-wirer -> detector-promote) behind an honest candidate-selection gate. A hacker-question class with >= --min-tp source-anchored answered/TP resolutions across >= --min-workspaces engagements and NO crystallized detector is promoted from prose obligation into a durable DSL detector (D->E->S).", STATUS_LANDED),
}

def extract_all_python_tools_auto() -> list[dict]:
    """CAP-GAP-102: auto-index EVERY tools/*.py + tools/lib/*.py not in the
    curated KEY_PYTHON_TOOLS set, so vault_capability_inventory is a COMPLETE
    queryable tools map (was 193/1105). Per-tool: docstring->description,
    wired-vs-orphan via Makefile/hooks/pre-submit cross-ref, related vault_*
    callables grepped from source. Curated records (richer) win dedup."""
    import ast as _ast
    import re as _re2
    caps = []
    curated = {Path(pp).stem for pp in KEY_PYTHON_TOOLS}
    wired_corpus = _read_text_safe(REPO_ROOT / "Makefile")
    hooks_dir = REPO_ROOT / "tools" / "hooks"
    if hooks_dir.is_dir():
        for h in hooks_dir.glob("*.sh"):
            wired_corpus += _read_text_safe(h)
    wired_corpus += _read_text_safe(REPO_ROOT / "tools" / "pre-submit-check.sh")
    # Also scan top-level wiring shell tools that invoke other tools (e.g. the
    # L30 missing-guard-callsite-enumerator invokes callsite-selector.py), so a
    # tool wired ONLY by a sibling .sh is detected as NOMINAL, not orphan.
    for _sh in sorted((REPO_ROOT / "tools").glob("*.sh")):
        wired_corpus += _read_text_safe(_sh)
    paths = sorted((REPO_ROOT / "tools").glob("*.py"))
    lib_dir = REPO_ROOT / "tools" / "lib"
    if lib_dir.is_dir():
        paths += sorted(lib_dir.glob("*.py"))
    for pth in paths:
        stem = pth.stem
        if stem in curated:
            continue
        rel = str(pth.relative_to(REPO_ROOT))
        text = _read_text_safe(pth)
        desc = ""
        try:
            doc = _ast.get_docstring(_ast.parse(text))
            if doc:
                desc = " ".join(doc.strip().splitlines()[:2]).strip()[:240]
        except Exception:
            mm = _re2.search(r'"""(.*?)"""', text, _re2.DOTALL)
            if mm:
                desc = " ".join(mm.group(1).strip().splitlines()[:2]).strip()[:240]
        if not desc:
            desc = f"Python tool {stem} (no module docstring)"
        if stem in AUTO_TOOL_DESC_OVERRIDES:
            desc = AUTO_TOOL_DESC_OVERRIDES[stem]
        wired = (pth.name in wired_corpus) or (rel in wired_corpus)
        # Map auto-index wired/orphan to the canonical VALID_STATUSES vocabulary:
        # a wired tool is NOMINAL-WIRED; an orphan tool is LANDED-on-disk but not
        # integrated into any flow -> PARTIAL. (The legacy "landed-wired" /
        # "landed-orphan" strings were not in the schema's status enum.)
        status = STATUS_NOMINAL if wired else STATUS_PARTIAL
        # Capability IDs must match ^CAP-[a-zA-Z0-9][a-zA-Z0-9\-\.]+$ (no underscores).
        # Python module stems can contain "_" (e.g. "_analyzer_common",
        # "fuzz_target_corpus"); encode "_" as "." (allowed, reversible, and
        # collision-preserving vs the dash-form stems already in the tree).
        cap_id = f"CAP-tool-{stem.replace('_', '.')}"
        rel_callables = sorted(set(_re2.findall(r"vault_[a-z_]{4,}", text)))[:8]
        caps.append({
            "id": cap_id,
            "name": stem,
            "category": "python-tool",
            "description": desc,
            "inputs": [],
            "outputs": [],
            "file_paths": [rel],
            "dependencies": [],
            "consumers": [],
            "verification_command": f"python3 /Users/wolf/auditooor-mcp/{rel} --help 2>&1 | head -3",
            "expected_verification_output": r"usage|Usage|help|error",
            "status": status,
            "known_bugs": [],
            "last_verified_at": None,
            "verification_history": [],
            "canonical_flow_refs": [],
            "related_callables": rel_callables,
            "notes": "auto-indexed (CAP-GAP-102 full tool coverage)",
        })
    return caps


def extract_python_tools() -> list[dict]:
    caps = []
    for tool_path, (cat, desc, status) in KEY_PYTHON_TOOLS.items():
        tool_name = Path(tool_path).stem
        cap_id = f"CAP-tool-{tool_name}"
        abs_path = REPO_ROOT / tool_path
        verify_cmd = f"python3 /Users/wolf/auditooor-mcp/{tool_path} --help 2>&1 | head -3" if tool_path.endswith(".py") else f"bash /Users/wolf/auditooor-mcp/{tool_path} --help 2>&1 | head -3"
        actual_status = STATUS_LANDED if abs_path.exists() else STATUS_BROKEN

        caps.append({
            "id": cap_id,
            "name": tool_name,
            "category": cat,
            "description": desc,
            "inputs": [],
            "outputs": [],
            "file_paths": [tool_path],
            "dependencies": [],
            "consumers": [],
            "verification_command": verify_cmd,
            "expected_verification_output": r"usage|Usage|help|error",
            "status": actual_status,
            "known_bugs": [],
            "last_verified_at": None,
            "verification_history": [],
            "canonical_flow_refs": [],
            "notes": "",
        })
    return caps


# ---------------------------------------------------------------------------
# Attach known bugs from CAP patch queue to relevant capabilities
# ---------------------------------------------------------------------------
def attach_known_bugs(caps: list[dict], bugs: list[dict]) -> list[dict]:
    # Map symptom keywords to cap ids (cap_id is the stripped ID before the " - " description)
    # The full ID in bug dict has form "CAP-YYYY-MM-DD-NNN - Title"
    # We strip to get just "CAP-YYYY-MM-DD-NNN"
    bug_mappings = {
        "CAP-2026-05-24-001": "CAP-make-audit-fast",  # LIVE_TARGET_REPORT P5 ranking
        "CAP-2026-05-24-002": "CAP-make-audit-fast",  # P3 placeholders
        "CAP-2026-05-24-003": "CAP-make-audit-fast",  # P1 invariant matching zero hits
        "CAP-2026-05-24-004": "CAP-make-audit-fast",  # FP inverted-verify-return
        "CAP-2026-05-24-005": "CAP-make-audit-fast",  # FP division-by-zero constant
        "CAP-2026-05-24-006": "CAP-make-audit-fast",  # FP erc-2771
        "CAP-2026-05-24-007": "CAP-make-audit-fast",  # FP external-call-before-state-update
        "CAP-2026-05-24-008": "CAP-make-audit",       # make audit WS=. inside workspace
        "CAP-2026-05-24-009": "CAP-mcp-vault-exploit-context",  # blocks on missing artifact
        "CAP-2026-05-24-010": "CAP-tool-agent-pathspec-register",  # CLI mismatch
        "CAP-2026-05-24-011": "CAP-mcp-vault-lane-cooldown-check",  # state_file_not_found
        "CAP-2026-05-24-012": "CAP-make-audit",       # make audit exits non-zero on legacy calibration
        "CAP-2026-05-24-013": "CAP-make-audit",       # wall-clock exceeds 10-min
        "CAP-2026-05-24-014": "CAP-make-audit-fast",  # P5 ranking tied entries
        "CAP-2026-05-24-015": "CAP-make-audit-fast",  # P1 invariants topical not exploit-suggestive
        "CAP-2026-05-24-016": "CAP-mcp-vault-invariant-library",  # --limit N ignored
        "CAP-2026-05-24-017": "CAP-mcp-vault-lane-cooldown-check",  # state_file_not_found ambiguous
        "CAP-2026-05-24-018": "CAP-make-audit-fast",  # pausable-no-unpause-exposed FP
        "CAP-2026-05-24-019": "CAP-make-audit-fast",  # lzReceive-no-sender-check FP
        "CAP-2026-05-24-020": "CAP-make-audit-fast",  # P1 SEMANTIC-MATCH label topical
        "CAP-MORPHO-2026-05-25-A": "CAP-make-audit-fast",  # LIVE_TARGET_REPORT EMPTY for morpho
        "CAP-MORPHO-2026-05-25-B": "CAP-make-audit",  # SCOPE.md pin reference missing
        "CAP-MORPHO-2026-05-25-C": "CAP-make-audit",  # deployed-contract ambiguity
        "CAP-MORPHO-2026-05-25-D": "CAP-make-audit",  # workspace staleness check missing
        "CAP-MORPHO-2026-05-25-E": "CAP-mcp-vault-active-roadmap",  # unknown_item_id silent
    }

    cap_by_id = {c["id"]: c for c in caps}

    for bug in bugs:
        # Normalize bug cap_id: strip " - Description" suffix
        raw_id = bug["cap_id"]
        normalized_id = raw_id.split(" - ")[0].strip()
        cap_id = bug_mappings.get(normalized_id)
        bug["cap_id"] = normalized_id  # update to normalized form
        if cap_id and cap_id in cap_by_id:
            cap_by_id[cap_id]["known_bugs"].append({
                "cap_id": bug["cap_id"],
                "severity": bug.get("severity", "MEDIUM"),
                "description": bug["description"][:200],
                "workaround": bug.get("workaround", "See capability_patch_queue.md")[:200],
            })
            # If multiple known bugs, mark as PARTIAL
            if cap_by_id[cap_id]["status"] == STATUS_LANDED:
                cap_by_id[cap_id]["status"] = STATUS_PARTIAL

    return list(cap_by_id.values())


# ---------------------------------------------------------------------------
# Canonical flows
# ---------------------------------------------------------------------------
CANONICAL_FLOWS = [
    {
        "id": "FLOW-universal-workspace-run",
        "name": "Universal Workspace Run",
        "purpose": "Run the end-to-end audit process for any new or existing operator-provided workspace",
        "prerequisites": ["CAP-make-audit-run-full", "CAP-make-cvl-spec-risk-scan", "CAP-tool-audit-completeness-check"],
        "steps": [
            {"command": "cd /Users/wolf/auditooor-mcp && make audit-run-full WS=<workspace> STRICT=1 EXECUTE_READY=1 JSON=1 TOP_N=10 MAX_FUNCTIONS=0", "expected_output": "audit_run_full_manifest.jsonl", "on_failure": "Read the manifest tail. If intake-truth fails, reconcile SCOPE.md, SEVERITY.md, OOS_CHECKLIST.md, SEVERITY_CAPS.md, prior_audits, and INTAKE_BASELINE.json before hunting."},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/audit-deep-manifest.py --workspace <workspace> --check-fresh --audit-run-manifest <workspace>/.auditooor/audit_run_full_manifest.jsonl --run-id <auditrun-id> --json", "expected_output": "pass-fresh-deep-manifest|pass-explicit-deep-skip", "on_failure": "Do not trust legacy complete rows. For exact replay, bind the freshness check to the audit-run manifest and run_id. A full run is not complete until deep manifests are fresh for the current run or a typed deep-engine skip reason is recorded."},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/audit-completeness-check.py <workspace> --strict --json", "expected_output": "pass-audit-complete|fail-", "on_failure": "Close the listed L37 signal failures; do not call the audit done while any fail-* verdict remains."},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_capability_inventory --args '{\"query\":\"audit-run-full\",\"limit\":10}'", "expected_output": "audit-run-full", "on_failure": "Rebuild capability inventory and refresh Obsidian tools-api notes."},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_capability_inventory --args '{\"query\":\"cvl-spec-risk-scan\",\"limit\":10}'", "expected_output": "cvl-spec-risk-scan", "on_failure": "Rebuild capability inventory and refresh Obsidian tools-api notes."},
        ],
        "expected_duration": "30-180 min",
        "common_failures": [
            {"failure_mode": "STRICT=1 without EXECUTE_READY=1 exits before stages", "root_cause": "Strict mode refuses to start proof execution without operator readiness.", "fix": "Pass EXECUTE_READY=1 only when the operator is ready for proof stages to execute. Proof conversion failures remain advisory by default and hard-fail only with AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1; the raw child-target proof flag is an internal export inside audit-run-full."},
            {"failure_mode": "intake-truth fails on severity caps or OOS placeholders", "root_cause": "Workspace operator-truth files are missing, stale, or placeholder", "fix": "Run extract-oos.sh, verify caps against the live program, rerun intake-baseline strict."},
            {"failure_mode": "audit-complete fails on formal-spec-obligations", "root_cause": "Certora/CVL specs exist but no .auditooor/cvl_coverage_audit.json was produced", "fix": "Run make cvl-spec-risk-scan WS=<workspace> JSON=1 and convert listed risks into proof obligations."},
        ],
        "references": ["README.md", "docs/AUDITOR_9_5_INTEGRITY_PLAN_2026-05-30.md", "docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-fresh-audit-startup",
        "name": "Fresh Audit Startup",
        "purpose": "Initialize a new workspace for auditing a smart contract/protocol target",
        "prerequisites": ["CAP-make-audit-prep", "CAP-mcp-vault-active-roadmap"],
        "steps": [
            {"command": "cd /Users/wolf/auditooor-mcp && make audit-prep WS=<workspace>", "expected_output": "Created .auditooor/", "on_failure": "Check workspace path exists; create with mkdir -p"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_active_roadmap --args '{\"side\":\"claude\",\"claim\":false}'", "expected_output": "roadmap_path", "on_failure": "Check MCP server is running; verify vault path"},
            {"command": "cd /Users/wolf/auditooor-mcp && make audit WS=<workspace>", "expected_output": "audit complete", "on_failure": "Check CAP-2026-05-24-008: must call from auditooor-mcp/, not workspace dir"},
            {"command": "cat <workspace>/engage_report.md | head -50", "expected_output": "=== Engage Report ===", "on_failure": "audit did not complete; check make audit stderr"},
            {"command": "cat <workspace>/INTAKE_BASELINE.md | head -30", "expected_output": "asset-coverage", "on_failure": "populate manually if missing"},
        ],
        "expected_duration": "15-30 min",
        "common_failures": [
            {"failure_mode": "make audit WS=. fails with No rule to make target", "root_cause": "CAP-2026-05-24-008: must run from auditooor-mcp/, not inside workspace", "fix": "cd /Users/wolf/auditooor-mcp && make audit WS=/abs/path/to/workspace"},
            {"failure_mode": "make audit exits non-zero on provider-fanout-discipline-check", "root_cause": "CAP-2026-05-24-012: legacy calibration log sparsity triggers hard fail", "fix": "Ignore for now; audit output is valid; gate needs relaxation for legacy rows"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md", "docs/CANONICAL_FLOWS.md"],
    },
    {
        "id": "FLOW-daily-hunt",
        "name": "Daily Hunting Workflow",
        "purpose": "Get ranked candidates for a known workspace with fresh intelligence",
        "prerequisites": ["CAP-make-hunt", "CAP-make-audit-fast", "CAP-mcp-vault-brain-prime-context"],
        "steps": [
            {"command": "python3 tools/vault-mcp-server.py --call vault_active_roadmap --args '{\"side\":\"claude\",\"claim\":false}'", "expected_output": "roadmap_path", "on_failure": "Verify MCP server path"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_resume_context --args '{\"workspace_path\":\"<ws>\",\"limit\":4}'", "expected_output": "context_pack_id", "on_failure": "Fresh workspace may not have context; run audit first"},
            {"command": "cd /Users/wolf/auditooor-mcp && make hunt WS=<workspace> TOP_N=30", "expected_output": "Step 1/4", "on_failure": "Check audit-fast prerequisite; see CAP-2026-05-24-001 for ranking issues"},
            {"command": "cat <workspace>/docs/LIVE_TARGET_REPORT.md | head -100", "expected_output": "LIVE TARGET REPORT", "on_failure": "audit-fast failed to generate report"},
        ],
        "expected_duration": "5-10 min",
        "common_failures": [
            {"failure_mode": "All entries in LIVE_TARGET_REPORT scored identically (51.9/MEDIUM)", "root_cause": "CAP-2026-05-24-001: engage_severity_score copy-propagation not yet stratified", "fix": "Known bug; use engage_report.md cluster ordering as supplement"},
            {"failure_mode": "P3 matched_anti_patterns shows TBD-P3-<cluster>", "root_cause": "CAP-2026-05-24-002: P3 catalog MVP2 not yet shipped", "fix": "Discount P3 column; use P1 invariant_hits instead"},
            {"failure_mode": "vault_exploit_context blocks on missing live_topology_proof_requirements.json", "root_cause": "CAP-2026-05-24-009: vault_exploit_context requires artifact not created by make audit", "fix": "Skip vault_exploit_context for fresh workspaces; or run make audit-deep first"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-mcp-layer1-sequence",
        "name": "MCP Layer-1 Session Startup",
        "purpose": "Mandatory MCP recall sequence at start of every session/iteration",
        "prerequisites": ["CAP-mcp-vault-resume-context", "CAP-mcp-vault-active-roadmap"],
        "steps": [
            {"command": "python3 tools/vault-mcp-server.py --call vault_active_roadmap --args '{\"side\":\"claude\",\"claim\":false}'", "expected_output": "roadmap_path", "on_failure": "Check vault-mcp-server.py path"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_resume_context --args '{\"workspace_path\":\"<ws>\",\"limit\":4}'", "expected_output": "context_pack_id", "on_failure": "Record error; continue without pack_id"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_exploit_context --args '{\"workspace_path\":\"<ws>\",\"limit\":5}'", "expected_output": "brief_blocked|angle-", "on_failure": "See CAP-2026-05-24-009 if brief_blocked on missing artifact"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_knowledge_gap_context --args '{\"workspace_path\":\"<ws>\",\"limit\":5}'", "expected_output": "knowledge_gaps", "on_failure": "Empty result is acceptable for fresh workspaces"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_engagement_status --args '{\"workspace_path\":\"<ws>\"}'", "expected_output": "engagement_status", "on_failure": "Empty result is acceptable"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_known_dead_ends --args '{\"workspace_path\":\"<ws>\",\"limit\":5}'", "expected_output": "dead_ends|\\[\\]", "on_failure": "Empty result is acceptable for fresh workspaces"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_invariant_library --args '{\"workspace_path\":\"<ws>\",\"limit\":5}'", "expected_output": "invariants|\\[\\]", "on_failure": "See CAP-2026-05-24-016: --limit N may be ignored"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_anti_pattern_corpus --args '{\"limit\":5}'", "expected_output": "anti_patterns", "on_failure": "Check vault server"},
            {"command": "python3 tools/vault-mcp-server.py --call vault_live_target_report --args '{\"workspace_path\":\"<ws>\",\"limit\":5}'", "expected_output": "live_target|candidates|error", "on_failure": "Run make audit-fast WS=<ws> first"},
        ],
        "expected_duration": "2-5 min",
        "common_failures": [
            {"failure_mode": "vault_lane_cooldown_check returns state_file_not_found", "root_cause": "CAP-2026-05-24-011: hardcoded spark_hunt_loop_state.json path for non-Spark engagements", "fix": "Ignore for non-Spark workspaces; treat as no-cooldown"},
            {"failure_mode": "vault_exploit_context blocks on missing live_topology_proof_requirements.json", "root_cause": "CAP-2026-05-24-009", "fix": "Skip; use vault_resume_context instead for exploit context"},
        ],
        "references": ["~/.claude/CLAUDE.md (Layer-1 sequence)", "docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-pre-submit-check",
        "name": "Pre-Submit Gating for a Draft",
        "purpose": "Run all pre-submission gates on a finding draft before paste_ready promotion",
        "prerequisites": ["CAP-make-pre-submit-check", "CAP-rule-r52-rubric-row-coverage", "CAP-rule-r40-v3-grade-poc-required"],
        "steps": [
            {"command": "bash /Users/wolf/auditooor-mcp/tools/pre-submit-check.sh <draft.md> --severity HIGH 2>&1 | tail -20", "expected_output": "PASS|exit 0", "on_failure": "Read each FAIL line; apply rule-specific fix or add rebuttal marker"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/rubric-row-coverage-check.py <draft.md> --workspace <ws>", "expected_output": "pass-rubric-row-matched", "on_failure": "R52: impact wording does not match any rubric row in SEVERITY.md"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/external-url-liveness-check.py <draft.md>", "expected_output": "pass-all-urls-live|pass-no-external-urls", "on_failure": "R54: one or more cited URLs returned HTTP 404/5xx; fix URL or add r54-rebuttal"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/v3-grade-poc-check.py <draft.md> --poc-dir <poc-dir>", "expected_output": "pass-v3-grade|pass-claim-narrowed|pass-out-of-scope", "on_failure": "R40: PoC is not V3-grade; see 6 required properties in R40 doctrine"},
        ],
        "expected_duration": "5-15 min",
        "common_failures": [
            {"failure_mode": "pre-submit-check.sh exits non-zero on R52 with no row match", "root_cause": "Program SEVERITY.md does not list the claimed impact class", "fix": "Check SEVERITY.md for available rubric rows; narrow claim or add r52-rebuttal"},
            {"failure_mode": "pre-submit-check.sh exits non-zero on R45 designed-as-intended", "root_cause": "Target docs explicitly document the contested behavior as design choice", "fix": "Verify design-intent statement exists in-tree; if triager rationale is factually inverted, add r45-rebuttal citing asymmetric in-tree guard"},
            {"failure_mode": "pre-submit-check.sh exits non-zero on R28 multi-path", "root_cause": "Multiple in-flight escalation paths for same Cantina ID exist", "fix": "Wait for all paths to land; merge into single triager response; paste once"},
        ],
        "references": ["docs/CANONICAL_CANTINA_PASTE_TEMPLATE.md", "docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-paste-ready-promotion",
        "name": "Paste-Ready Promotion",
        "purpose": "Promote a staging draft to paste_ready/ status after all gates pass",
        "prerequisites": ["CAP-make-pre-submit-check", "CAP-rule-r41-per-finding-submission-folder-structure"],
        "steps": [
            {"command": "bash /Users/wolf/auditooor-mcp/tools/pre-submit-check.sh <draft.md> --severity <SEVERITY> 2>&1; echo \"Exit: $?\"", "expected_output": "Exit: 0", "on_failure": "Fix each failing gate; do not promote until exit 0"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/submission-folder-structure-check.py --draft <draft.md>", "expected_output": "pass-compliant", "on_failure": "R41: move draft to submissions/paste_ready/<slug>/<slug>.md"},
            {"command": "mkdir -p <workspace>/submissions/paste_ready/<slug> && mv <draft.md> <workspace>/submissions/paste_ready/<slug>/<slug>.md", "expected_output": "", "on_failure": "Check permissions; verify slug matches draft stem"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/external-url-liveness-check.py <workspace>/submissions/paste_ready/<slug>/<slug>.md", "expected_output": "pass-all-urls-live", "on_failure": "R54: fix dead URLs before pasting"},
        ],
        "expected_duration": "10-30 min",
        "common_failures": [
            {"failure_mode": "submission-folder-structure-check fails with flat-artifact", "root_cause": "R41: artifacts lying flat in status directory, not in per-finding folder", "fix": "python3 tools/submission-folder-structure-check.py --workspace <ws> --fix"},
        ],
        "references": ["docs/CANONICAL_CANTINA_PASTE_TEMPLATE.md", "docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-dispute-response",
        "name": "Dispute / Triager Response",
        "purpose": "Prepare and validate a triager response after a finding is challenged",
        "prerequisites": ["CAP-rule-r43-load-bearing-bytes-attribution-required", "CAP-rule-r28-multi-path-escalation-merge", "CAP-rule-r54-external-url-liveness-required"],
        "steps": [
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/multi-path-escalation-merge-check.py <draft.md> --workspace <ws>", "expected_output": "pass-single-path|pass-merged", "on_failure": "R28: multiple in-flight paths for same ID; wait for all to land; merge first"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/load-bearing-bytes-attribution-check.py <draft.md>", "expected_output": "pass-attribution-complete|pass-no-defender-narrative", "on_failure": "R43: add Load-Bearing Bytes Attribution section enumerating all 5 fields"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/external-url-liveness-check.py <draft.md>", "expected_output": "pass-all-urls-live", "on_failure": "R54: fix dead URLs before posting response"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/exhaustive-defense-chain-enumeration-check.py <draft.md> --workspace <ws>", "expected_output": "pass-all-defense-paths-enumerated", "on_failure": "R57: add exhaustive defense chain table covering all code paths"},
        ],
        "expected_duration": "30-120 min",
        "common_failures": [
            {"failure_mode": "R43 fails on missing Load-Bearing Bytes Attribution section", "root_cause": "Dispute endorses defender narrative without identifying who produces the key bytes", "fix": "Ask: who builds the load-bearing artifact? Enumerate signer set. Check if attacker is in signer set."},
            {"failure_mode": "R57 fails: grep finds defense paths absent from table", "root_cause": "Defense chain table only covers named defenses, not all code paths in defender codebase", "fix": "Grep defender's protection-module dirs for canonical defense-action patterns; add every call site to table with ruled-in/ruled-out verdict"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-poc-build",
        "name": "PoC Build and Verification",
        "purpose": "Build a V3-grade PoC for a Medium+ finding candidate",
        "prerequisites": ["CAP-rule-r40-v3-grade-poc-required", "CAP-rule-r18-l32-in-process-vs-node-level-evidence", "CAP-rule-r24-non-self-impact-required"],
        "steps": [
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/v3-grade-poc-check.py <draft.md> --poc-dir <poc-dir> --severity <SEVERITY>", "expected_output": "pass-v3-grade|pass-claim-narrowed", "on_failure": "See 6 V3-grade requirements; build missing element"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/in-process-vs-node-level-check.py <draft.md> --poc-dir <poc-dir> --severity <SEVERITY>", "expected_output": "pass-production-grade|pass-rubric-no-production-keyword", "on_failure": "R18/R19: PoC must use node-level surface for production-runtime rubric claims"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/non-self-impact-check.py <draft.md> --poc-dir <poc-dir>", "expected_output": "pass-non-self-impact", "on_failure": "R24: PoC must include non-attacker character with balance/state assertion"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/production-profile-preflight-check.py <draft.md>", "expected_output": "pass|ok-rebuttal", "on_failure": "R30: use goleveldb/rocksdb etc.; remove timing shims; no reflection into unexported fields"},
        ],
        "expected_duration": "60-240 min",
        "common_failures": [
            {"failure_mode": "R18/R19 fails: in-process PoC with production-runtime rubric claim", "root_cause": "Unit test exercises production type but not production ABCI/node surface", "fix": "Wrap in simapp.Setup / app.FinalizeBlock / BroadcastTxSync surface, or narrow rubric claim"},
            {"failure_mode": "R40 fails: mock replaces protocol-owned vulnerable path", "root_cause": "PoC uses a simulator/stub instead of the real protocol function", "fix": "Drive unmodified protocol-owned function; mock only external dependencies"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-capability-fix-dispatch",
        "name": "Capability Bug Fix Dispatch",
        "purpose": "Dispatch a lane to fix a known capability bug (CAP-YYYY-MM-DD-NNN)",
        "prerequisites": ["CAP-tool-capability-inventory-build", "CAP-tool-capability-check"],
        "steps": [
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/capability-check.py --capability <cap-id>", "expected_output": "PASS|FAIL", "on_failure": "Check capability ID matches an entry in reference/capability_inventory.jsonl"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/capability-inventory-build.py --diff", "expected_output": "changed|new|deprecated", "on_failure": "Inventory may not have been built yet; run --refresh first"},
            {"command": "python3 tools/agent-pathspec-register.py register --lane lane-<LANE-ID> --files <files> --ttl 7200", "expected_output": "registered", "on_failure": "CAP-2026-05-24-010: use --lane not --agent-id; use --files (comma-separated) not --pathspec"},
        ],
        "expected_duration": "30-90 min",
        "common_failures": [
            {"failure_mode": "agent-pathspec-register.py CLI syntax mismatch", "root_cause": "CAP-2026-05-24-010: lane brief boilerplate uses --agent-id/--pathspec, tool uses --lane/--files", "fix": "Use: python3 tools/agent-pathspec-register.py register --lane <ID> --files <comma-csv> --ttl <secs>"},
        ],
        "references": ["reports/v3_iter_2026-05-24/capability_patch_queue.md", "docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-workspace-refresh",
        "name": "Workspace Refresh",
        "purpose": "Refresh an existing workspace with latest MCP context, corpus, and detector output",
        "prerequisites": ["CAP-make-audit", "CAP-mcp-vault-resume-context"],
        "steps": [
            {"command": "cd /Users/wolf/auditooor-mcp && git fetch origin main && git status", "expected_output": "up to date|ahead|behind", "on_failure": "Network issue; continue with local copy"},
            {"command": "cd /Users/wolf/auditooor-mcp && python3 tools/vault-mcp-server.py --call vault_resume_context --args '{\"workspace_path\":\"<ws>\",\"limit\":4}'", "expected_output": "context_pack_id", "on_failure": "Stale workspace; run make audit WS=<ws> first"},
            {"command": "cd /Users/wolf/auditooor-mcp && make audit WS=<workspace> FORCE=1", "expected_output": "audit complete|done", "on_failure": "See CAP-2026-05-24-008: run from auditooor-mcp/, not from workspace dir"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/memory-context-load.py --workspace <ws> --check --json", "expected_output": "fresh|ok", "on_failure": "Context is stale; may need make audit-deep"},
        ],
        "expected_duration": "15-30 min",
        "common_failures": [
            {"failure_mode": "make audit exits non-zero", "root_cause": "Usually CAP-2026-05-24-012 legacy calibration sparsity or missing workspace artifacts", "fix": "Check stderr; for calibration sparsity, continue (bug is known); for other errors, check workspace path"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-r36-commit-discipline",
        "name": "R36 Commit with Explicit Pathspec",
        "purpose": "Commit changes in a shared worktree without stomping sibling lanes",
        "prerequisites": ["CAP-rule-r36-parallel-worktree-commit-pathspec-discipline", "CAP-tool-agent-pathspec-register"],
        "steps": [
            {"command": "python3 tools/agent-pathspec-register.py register --lane lane-<LANE-ID> --files <comma-csv-of-files> --ttl 7200", "expected_output": "registered", "on_failure": "See CAP-2026-05-24-010 for CLI syntax"},
            {"command": "git add <file1> <file2> <file3>", "expected_output": "", "on_failure": "Stage ONLY files this lane owns; NEVER git add -A or git add ."},
            {"command": "git diff --staged --stat", "expected_output": "", "on_failure": "ABORT if staged files do not match this lane's intent exactly"},
            {"command": "git commit -m \"$(cat <<'EOF'\n<message>\n\nCo-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>\nEOF\n)\"", "expected_output": "main", "on_failure": "Check pre-commit hooks; do not use --no-verify"},
        ],
        "expected_duration": "2-5 min",
        "common_failures": [
            {"failure_mode": "R36 hook refuses commit: staged files exceed declared pathspec", "root_cause": "git add absorbed sibling lane files", "fix": "git reset HEAD; stage only lane-owned files; retry"},
            {"failure_mode": "R55: git reset --hard wipes sibling lane uncommitted edits", "root_cause": "Integration lane ran destructive op while sibling had uncommitted edits", "fix": "Check .auditooor/agent_pathspec.json for sibling lanes; use git-reset-safe.sh wrapper"},
        ],
        "references": ["docs/COMMIT_DISCIPLINE.md", "docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-add-capability",
        "name": "Add a New Capability to Inventory",
        "purpose": "Document a newly landed capability in the inventory",
        "prerequisites": ["CAP-tool-capability-inventory-build"],
        "steps": [
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/capability-inventory-build.py --refresh --json 2>&1 | tail -10", "expected_output": "total_capabilities", "on_failure": "Fix syntax error in capability-inventory-build.py"},
            {"command": "cat /Users/wolf/auditooor-mcp/reference/capability_inventory.jsonl | python3 -c \"import sys,json; [print(r['id']) for r in (json.loads(l) for l in sys.stdin) if '<name>' in r['name']]\"", "expected_output": "CAP-", "on_failure": "New capability not yet in inventory; add to KEY_MAKE_TARGETS or KEY_PYTHON_TOOLS in capability-inventory-build.py"},
            {"command": "python3 -m unittest /Users/wolf/auditooor-mcp/tools/tests/test_capability_inventory -v 2>&1 | tail -5", "expected_output": "OK", "on_failure": "Fix failing test; likely Test 4 (>=80 capabilities) or Test 5 (>=15 flows)"},
        ],
        "expected_duration": "5-15 min",
        "common_failures": [
            {"failure_mode": "New capability not appearing in inventory", "root_cause": "Not added to KEY_MAKE_TARGETS, KEY_PYTHON_TOOLS, or CRITICAL_R_RULES in capability-inventory-build.py", "fix": "Add entry to appropriate dict in capability-inventory-build.py; re-run --refresh"},
        ],
        "references": ["tools/capability-inventory-build.py", "docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-morpho-audit-session",
        "name": "Morpho Audit Session Startup",
        "purpose": "Start an audit session on the Morpho workspace with proper context",
        "prerequisites": ["CAP-make-audit-fast", "CAP-mcp-vault-active-roadmap"],
        "steps": [
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_active_roadmap --args '{\"side\":\"claude\",\"claim\":false}'", "expected_output": "roadmap_path", "on_failure": "MCP server not running or vault path wrong"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_resume_context --args '{\"workspace_path\":\"/Users/wolf/audits/morpho\",\"limit\":4}'", "expected_output": "context_pack_id", "on_failure": "Workspace may not have been indexed; run make audit WS=/Users/wolf/audits/morpho"},
            {"command": "cat /Users/wolf/audits/morpho/engage_report.md | head -30", "expected_output": "Engage Report", "on_failure": "Run make audit WS=/Users/wolf/audits/morpho to generate engage_report.md"},
            {"command": "cat /Users/wolf/audits/morpho/INTAKE_BASELINE.md 2>/dev/null | head -20", "expected_output": "asset-coverage|scope", "on_failure": "INTAKE_BASELINE.md missing; this is a known gap (CAP-MORPHO-2026-05-25-D)"},
        ],
        "expected_duration": "5-15 min",
        "common_failures": [
            {"failure_mode": "vault_active_roadmap rejects PHASE-II.15-CAPABILITY-INVENTORY-MCP-AND-DOCS with no_available_item", "root_cause": "CAP-MORPHO-2026-05-25-E: vault_active_roadmap silently rejects unknown_item_id with no fallback", "fix": "Use claim:false; do not attempt to claim the item_id; proceed with side:claude context"},
            {"failure_mode": "LIVE_TARGET_REPORT MVP2 SEMANTIC promotion returns EMPTY for morpho corpus", "root_cause": "CAP-MORPHO-2026-05-25-A: morpho corpus not yet indexed in semantic promotion layer", "fix": "Use engage_report.md cluster scoring as fallback; SEMANTIC column is unreliable for Morpho"},
            {"failure_mode": "SCOPE.md pin reference does not exist in repository", "root_cause": "CAP-MORPHO-2026-05-25-B: audit pin SHA in SCOPE.md does not exist in target repo", "fix": "Verify pin SHA against target repo; update SCOPE.md with correct SHA"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md", "reports/v3_iter_2026-05-24/capability_patch_queue.md"],
    },
    {
        "id": "FLOW-r-rule-rebuttal",
        "name": "R-Rule Override / Rebuttal",
        "purpose": "Add a rebuttal marker when a pre-submit gate fires but the finding is still valid",
        "prerequisites": ["CAP-make-pre-submit-check"],
        "steps": [
            {"command": "bash /Users/wolf/auditooor-mcp/tools/pre-submit-check.sh <draft.md> 2>&1 | grep FAIL", "expected_output": "FAIL", "on_failure": "No failures to rebuttal"},
            {"command": "# Add rebuttal marker to draft: <!-- rNN-rebuttal: <reason up to 200 chars> -->", "expected_output": "", "on_failure": "Reason must be non-empty and <= 200 chars; check rule docs for valid rebuttal anchors"},
            {"command": "bash /Users/wolf/auditooor-mcp/tools/pre-submit-check.sh <draft.md> 2>&1 | grep -c FAIL", "expected_output": "0", "on_failure": "Rebuttal marker not accepted; check reason length and format"},
        ],
        "expected_duration": "5-15 min",
        "common_failures": [
            {"failure_mode": "Rebuttal marker not accepted: reason oversized or empty", "root_cause": "All R-rule gates require non-empty reason <= 200 chars", "fix": "Shorten rebuttal reason to <= 200 chars; ensure marker is not an empty HTML comment"},
            {"failure_mode": "r28-rebuttal does not silence r43-rebuttal and vice versa", "root_cause": "Each rule gate checks only its own rebuttal marker; they are independent", "fix": "Add separate rebuttal for each failing gate"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-corpus-mining",
        "name": "Corpus Mining Session",
        "purpose": "Mine new findings into the hackerman corpus from a public source",
        "prerequisites": ["CAP-mcp-vault-corpus-mining-state"],
        "steps": [
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/vault-mcp-server.py --call vault_corpus_mining_state --args '{\"limit\":5}'", "expected_output": "mining_state", "on_failure": "Check vault server; corpus_mining_state may be empty for fresh sessions"},
            {"command": "python3 /Users/wolf/auditooor-mcp/tools/hackerman-etl-from-solodit.py --language solidity --limit 100 --apply 2>&1 | tail -10", "expected_output": "emitted|records", "on_failure": "Check SOLODIT_API_KEY is set in both ~/.claude.json AND ~/.zshrc (L33)"},
            {"command": "make tier-stratify 2>&1 | tail -5", "expected_output": "tier|stratif", "on_failure": "Run from auditooor-mcp/ directory"},
        ],
        "expected_duration": "15-60 min",
        "common_failures": [
            {"failure_mode": "SOLODIT_API_KEY missing in shell tool invocations", "root_cause": "L33: MCP env vars are siloed; not exported to shell", "fix": "Add export SOLODIT_API_KEY=... to ~/.zshrc; source ~/.zshrc"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md"],
    },
    {
        "id": "FLOW-r28-multi-path-merge",
        "name": "R28: Multi-Path Escalation Merge",
        "purpose": "Merge multiple in-flight escalation paths for same Cantina submission into one response",
        "prerequisites": ["CAP-rule-r28-multi-path-escalation-merge"],
        "steps": [
            {"command": "make r28-check-all WS=<workspace> 2>&1 | grep -E 'FAIL|WARN'", "expected_output": "pass|empty", "on_failure": "R28 fires: multiple paths for same Cantina ID found in workspace"},
            {"command": "# Identify all in-flight paths targeting same Cantina ID; review each", "expected_output": "", "on_failure": ""},
            {"command": "# Merge all paths into single unified triager response draft; add <!-- r28: merged-unified-response --> signal", "expected_output": "", "on_failure": ""},
            {"command": "make r28-check WS=<ws> DRAFT=<merged-draft.md> 2>&1 | tail -5", "expected_output": "pass-single-path|pass-merged", "on_failure": "Merged signal not recognized; verify signal phrase"},
        ],
        "expected_duration": "30-120 min",
        "common_failures": [
            {"failure_mode": "R28 fires even after merge because old drafts still reference same ID", "root_cause": "Old drafts in staging/paste_ready/held/superseded still visible to gate", "fix": "Move old drafts to superseded/ or add r28-rebuttal to merged draft citing it is the canonical unified response"},
        ],
        "references": ["docs/CAPABILITY_INVENTORY.md"],
    },
]


# ---------------------------------------------------------------------------
# Full-record wiring overrides (source-registration; survives regen)
# ---------------------------------------------------------------------------
# These tools are auto-indexed with empty inputs/outputs/consumers, so the
# wiring-integrity checker classifies them "unknown" (feeds_to=None). Prior
# sessions registered them by DIRECT-APPENDING rich rows to the generated
# capability_inventory.jsonl - which a concurrent `capability-inventory-build.py`
# regen silently wipes (the checker stays green because a dropped cap falls into
# "unknown", not "orphan": a silent de-registration false-green). Register the
# real invoked+emit+consume wiring HERE so every regen re-derives WIRED. Each
# (output, consumer) pair is grep-proven (the tool writes the artifact; the named
# consumer reads its basename) and DAG-order-verified (emit_phase <= consumer_phase
# per capability-wiring-integrity-check.py). state-coupling-graph.py is
# deliberately EXCLUDED: its emit phase (audit-complete=5) exceeds its consumer
# phase (exploit-queue=4), which would classify it BROKEN-FLOW, not WIRED.
CURATED_FULL_WIRING = {
    "tools/wsitb-enforcement-plane.py": {
        "inputs": ["inscope_units.jsonl", "state_coupling_edges.jsonl"],
        "outputs": ["wsitb_enforcement_plane.json", "wsitb_enforcement_accounting.json"],
        "consumers": ["tools/audit-completeness-check.py:check_enforcement_point"],
    },
    "tools/enforcement-layer-census.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["enforcement_layer_census.json"],
        "consumers": ["tools/audit-completeness-check.py:check_enforcement_layer_census"],
    },
    "tools/go-detector-runner.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["consensus_write_determinism_census_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/rust-detector-runner.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["rust_panic_reach_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/state-coupling-completeness-check.py": {
        "inputs": ["state_coupling_edges.jsonl"],
        "outputs": ["state_coupling_completeness.json"],
        "consumers": ["tools/audit-completeness-check.py:check_state_coupling"],
    },
    # gen-ext caps (2026-07-11 external-corpus refresh wf_682bcedf; mutation-verified
    # on real fleet code + distinct-adversarial-verify CONFIRMED). Step 5f + folded
    # by auto-coverage-closer (NETNEW advisory list).
    "tools/abci-phase-predicate-symmetry-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["abci_phase_predicate_symmetry_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/verifier-executor-divergence-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["verifier_executor_divergence_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/raii-drop-glue-bypass-on-error-path-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["raii_drop_glue_bypass_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # gen-ext wave-2 (2026-07-11; adversarial-verifier-fixed then re-CONFIRMED).
    "tools/multi-source-field-authority-differential-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["multi_source_field_authority_differential_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/cross-layer-cardinality-divergence-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["cross_layer_cardinality_divergence_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/nested-length-prefix-parent-bound-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["nested_length_prefix_parent_bound_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/rust-send-sync-bound-omission-share-boundary-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["send_sync_bound_omission_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/guard-predicate-soundness-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["guard_predicate_soundness_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # gen-ext round-2 (wf_0768c38f, 2026-07-11): mutation-verified on real fleet
    # code + distinct-adversarial-verify CONFIRMED. Advisory-first (needs-fuzz),
    # auto-run in audit-deep Step 5f, folded by auto-coverage-closer NETNEW list.
    "tools/mid-transition-snapshot-phase-freshness-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["mid_transition_snapshot_phase_freshness_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/generic-type-vs-runtime-selector-desync-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["generic_type_selector_desync_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/non-monotonic-guard-composition-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["non_monotonic_guard_composition_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # gen-ext round-2 remainder EXT2-02/03/04 (wired 2026-07-11; smoke-verified sane
    # low fire counts nuva/morpho/monero-oxide, no FP-spray). Advisory-first needs-fuzz.
    "tools/object-graph-xref-consistency-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["object_graph_xref_consistency_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/failopen-classifier-default-arm-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["failopen_classifier_default_arm_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/queue-fairness-resource-mutation-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["queue_fairness_resource_mutation_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-A1 arch-deep parse-consume byte-conservation seam (Sol+Go; Rust arm =
    # rust-non-exact-decode-trailing-bytes-scan). wf_ba1ca1ee, SHIP + mutation-verified.
    "tools/parse-consume-byte-conservation-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["byte_conservation_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-A2 arch-deep traversal terminal-state canonicalization (Sol+Go+Rust arms).
    # wf_608a6684, SHIP + mutation-verified (lido fx-portal Merkle.checkMembership).
    "tools/traversal-terminal-canonicalization-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["terminal_canonicalization_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-A3 arch-deep ephemeral-store reset-conservation + write-tier fidelity.
    # wf_5fd34f86, SHIP + mutation-verified (lido CircuitBreaker nonReentrant).
    "tools/ephemeral-reset-conservation-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["reset_conservation_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-A4 arch-deep external-call boundary state-invalidation (Sol+Rust+Go arms).
    # wf_7123a76c, SHIP + distinct-from-reentrancy confirmed (etherfi Liquifier witness).
    "tools/extcall-boundary-invalidation-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["extcall_boundary_invalidation_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-A5 arch-deep implicit domain-disjointness assumption (Sol+Rust/Go arms).
    # wf_bae5b614, SHIP defects=[] (morpho-blue setAuthorizationWithSig witness).
    "tools/domain-disjointness-assumption-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["domain_disjointness_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-EL1 enforcement-layer compiler-known-bug shape-JOIN (closes the E2 source-trigger
    # gap; strict subset of compiler-feature-screen). wf_7a1ba4e3, SHIP + both-halves-verified.
    "tools/compiler-known-bug-shape-join-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["compiler_shape_join_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-EL4 enforcement-layer crypto-preimage soundness census (domain-sep/nonce/
    # low-s/empty-signer). wf_0eea2b06, SHIP defects=[], distinct-from-A5 confirmed.
    "tools/crypto-preimage-soundness-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["crypto_preimage_soundness_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-EL3 enforcement-layer non-canonical serialization acceptance (Go proto/
    # amino/json primary, Rust borsh/serde + Sol abi.decode). Decode -> canonicality-
    # sensitive sink (hash/mapkey/dedup/equality/merkle-leaf/replay-nonce) keyed on
    # RAW bytes with no re-encode/canonical check. Mutation-verified (sei cosmos
    # unknownproto extractFileDescMessageDesc: cache-key gzippedPb -> raw protoBlob).
    "tools/noncanonical-serialization-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["noncanonical_serialization_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-EL2 enforcement-layer=compiler-dispatch: ABI selector/dispatch collision
    # soundness. A selector->fn dispatch STRUCTURE (Diamond facet map / transparent-
    # proxy admin+impl selector clash / assembly switch / router bytes4->addr) that
    # lacks collision rejection routes a colliding/duplicate selector into a
    # privileged fn (last-wins shadow). Flags the UNGUARDED STRUCTURE only, never a
    # numeric keccak4 brute-force. wf_0498f4f7, SHIP defects=[]. Mutation-verified on
    # beanstalk LibDiamond (strip add-collision require -> fires); etherfi 2 leads.
    "tools/selector-dispatch-collision-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["selector_dispatch_collision_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-EL5 enforcement-layer=consensus-gas: gas-metering/opcode-repricing
    # fragility. A safety argument resting on a gas magic-number (2300-stipend
    # transfer/send to a stored addr as reentrancy protection, fixed-gas call,
    # gasleft() threshold gate, gas-bounded loop, 63/64 forward) that an EIP-1884/
    # 2929/3529 repricing shifts to re-enable reentrancy/DoS. FP-scoped to LOAD-
    # BEARING gas constants (stored-addr = medium, msg.sender = low, ERC20 2-arg +
    # robust .call{value} = silent). wf_ac45a18b, SHIP defects=2-low-bounded.
    # Mutation-verified on lido AssetRecoverer (call{value} -> transfer -> fires).
    "tools/gas-repricing-fragility-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["gas_repricing_fragility_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-EL6 enforcement-layer=build-config: toolchain-flag semantic-drift. A build
    # flag that changes SEMANTICS not just optimization silently invalidates a source
    # safety assumption (Rust [profile.release] overflow-checks=off JOINed against a
    # real bare-arith site; Solidity evmVersion cancun/prague enabling tstore/mcopy;
    # viaIR+inline-assembly; a negated go build-tag gating a validation path). FP-
    # scoped to SEMANTIC flags (optimizer/opt-level never flagged; Rust arm needs
    # BOTH config-off AND a source site). Upgrades stale-pin-check via a flag/
    # evmVersion axis (sibling, exposes check_toolchain_flag_drift()). wf_53626f39,
    # SHIP defects=1-low. Mutation-verified (near Cargo overflow flip + lido foundry
    # evmVersion paris->cancun flip); lido 9 / morpho 14 leads; near/nuva silent-TN.
    "tools/toolchain-flag-drift-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["toolchain_flag_drift_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-R3 lang-intrinsic=rust-soundness: unsound transmute/pointer-cast type-
    # confusion. Every reinterpreting cast must discharge size-eq + alignment + all-
    # bit-patterns-valid + no-lifetime-extension; the DISCRIMINATING screen fires ONLY
    # the four undischargeable forms (generic-param transmute, lifetime transmute,
    # bytes->niche-type, stricter-align ptr-cast-deref) and stays SILENT on sound
    # repr-C POD / repr-transparent / bytemuck-Pod (unlike R13 blanket inventory).
    # wf_2fb20bb7, SHIP defects=[]. Mutation-verified on near key_conversion.rs
    # (RistrettoPoint transmute -> bool/lifetime fires). Rust-only (nuva N/A).
    "tools/transmute-type-confusion-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["transmute_type_confusion_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-R1 lang-intrinsic=rust-soundness: panic-during-Drop double-drop/UAF. An
    # unsafe manual drop/dealloc loop (drop_in_place / ptr::read+drop / ManuallyDrop /
    # rebuild-drop-then-write) must consume-before-drop (set_len(0) / progress guard
    # BEFORE a panicking element Drop) else unwind re-observes an already-freed slot =
    # double-drop/UAF. FP-scoped (consume-first + POD drops silent). wf_4e22c363, SHIP
    # defects=1-low. Mutation-verified on a faithful Vec::truncate synthetic (no real
    # consume-before-drop loop in fleet - stated); near 1 lead. Rust-only (nuva N/A).
    "tools/panic-during-drop-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["panic_during_drop_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-R5 lang-intrinsic=rust-soundness: release-mode silent integer overflow to
    # alloc/index. An untrusted numeric length/offset tainted through bare + - * << /
    # narrowing-as into a memory-safety sink (with_capacity/reserve/get_unchecked/
    # slice-range/ptr-add/from_raw_parts) with no checked_/try_into guard wraps
    # silently in release -> undersized alloc + OOB. Requires BOTH untrusted taint AND
    # a memory sink (owned .len() arith + guarded sites silent). INVERSE of rust-panic-
    # reach; COMPOSES with GEN-EL6 (config). wf_6e6fb391, SHIP defects=[]. Mutation-
    # verified on near vmctx_plus_offset (try_from -> as fires); near 19 leads.
    "tools/release-silent-overflow-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["release_silent_overflow_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-4C cross-lang=pattern-lift: width-narrowing cast on attacker operand.
    # Cross-lang lift of Glider gap #2 (EVM-downcast, Solidity-only). A narrowing
    # integer cast (wider->narrower) on a value-bearing operand truncates the high
    # bits -> a large amount/id/index wraps small (value confusion, not memory).
    # FP-scoped: source genuinely wider AND value-bearing; widening/masked/SafeCast/
    # try_into-guarded silent. Mutation-verified on morpho VaultV2.sol:639 (toUint128
    # SafeCast -> bare narrowing fires); nuva silent-TN (Go+EVM walked).
    "tools/width-narrowing-cast-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["width_narrowing_cast_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-4A cross-lang=pattern-lift: vault max-exit helper rounding-vs-paired-exit.
    # An ERC-4626-family max*/preview* helper and its paired state-changing exit
    # (withdraw/redeem/deposit/mint) must round CONSISTENTLY; opposite rounding lets
    # a caller passing maxWithdraw() over-exit (dilute other holders) or revert. A
    # CROSS-FUNCTION rounding-consistency check (distinct from GEN-4B single-
    # expression). FP-scoped: both fns exist + convert the same conserved pair +
    # round provably-opposite. SHIP defects=[]. nuva silent-clean-TN.
    "tools/vault-maxexit-rounding-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["vault_maxexit_rounding_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-4D cross-lang=pattern-lift: discarded-fallible-result-on-a-value-path.
    # A fallible value-moving call (transfer/mint/burn/send*coins/withdraw/settle)
    # whose error/Result/bool-success is DISCARDED lets a FAILED transfer proceed
    # as success -> phantom credit / lost funds. Go arm: `_ =`/`x, _ =` blank in
    # the ERROR (last) position + a curated bare-statement cosmos-bank op (receiver-
    # dot required, excludes interface method SIGNATURES). Rust arm: `let _ =` +
    # `.ok();` discard + `let _ = <bal>.checked_sub()`. Move arm: `let _ =` coin op.
    # FP-scoped: word-exact value verbs (STRONG fire alone; WEAK send/pay/... need a
    # value-noun co-token, `value` excluded as too generic), checked/`if err`/`?`/
    # unwrap/named-error silent. DEDUP: Solidity low-level-call return defers to
    # W6-P1 (not scanned here). SHIP defects=[]. Mutation-verified on sei ibc-go
    # relay.go:296 (checked SendCoins -> `_ =` fires); nuva silent-TN (0, interface
    # decls suppressed); sei/polygon WithdrawValidatorCommission TP (dev //nolint).
    "tools/discarded-fallible-result-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["discarded_fallible_result_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-D lang-intrinsic=go-consensus: consensus-nondeterministic-return-ordering.
    # A `for k := range map` appending to a slice that reaches a consensus-serialized
    # return (ValidatorUpdate/EndBlock event/proposal tx-order/genesis-export/denom)
    # with no dominating sort -> per-validator AppHash divergence -> chain halt.
    # FP-scoped (sorted + pre-sorted-key + keyed-map-write + len()-only reads
    # silent). Sibling of consensus-write-determinism-census (adds ABCI/genesis
    # return-slice sink). Mutation-verified on polygon nft ExportGenesis (strip
    # sort.Strings(owners) -> fires); nuva/sei silent-TN. Main-loop-verified (build
    # subagent's distinct-verify cut by weekly limit; FP fixed in main loop).
    "tools/consensus-map-order-return-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["consensus_map_order_return_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # GEN-4B cross-lang=pattern-lift: value-conserving division rounds-against-
    # beneficiary. Cross-lang lift of EVM-W3 (divide-before-multiply, Solidity-only)
    # + net-new wrong-rounding-direction arm, over a CONSERVED-quantity split
    # (assets<->shares/fee<->principal/reward<->stake). Two arms: DBM (infix a/b*c +
    # method-chain .Quo().Mul() across sol/rust/go/move) + wrong-direction (round-up
    # payout / round-down debt, medium). FP-scoped (conserved-hint required; multiply-
    # before-divide silent). SHIP defects=[]. Mutation-verified on etherfi
    # GlobalIndexLibrary.sol:73 (a*b/c -> a/c*b fires); nuva/near silent-TN.
    "tools/division-rounds-against-beneficiary-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["division_rounds_against_beneficiary_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # Net-new general-logic advisory screens (wave 2026-07-11), auto-run in
    # audit-deep Step 5f, folded by auto-coverage-closer (NETNEW/GO advisory lists).
    "tools/cache-source-writer-set-coherence.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["cache_source_writer_set_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/cross-module-sibling-reentrancy.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["cross_module_sibling_reentrancy.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/stale-grant-survival-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["stale_grant_survival_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/ordering-dependent-invariant-tagger.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["ordering_dependent_invariant_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/go-slice-aliasing-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["go_slice_aliasing.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/go-goroutine-lifecycle-census.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["goroutine_lifecycle_safety_census_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/rust-eager-alloc-nomax-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["rust_eager_alloc_nomax_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/proxy-storage-slot-bijection-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["storage_slot_bijection_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # wave-2 net-new caps (2026-07-11), auto-run in audit-deep Step 5f.
    "tools/deserialize-precap-amplification-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["e7_precap_amplification_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/deploy-initialize-ordering-window.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["deploy_initialize_ordering_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/arch-invariant-suspension-window.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["invariant_suspension_window_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/async-cancel-coupled-state-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["async_cancel_coupled_state_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/inclusion-proof-positional-soundness.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["e12_inclusion_position_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/cross-client-consensus-divergence.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["cross_client_consensus_divergence_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/zk-lookup-membership-bound.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["zk_lookup_membership_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # wave-2 needs-fix caps (refuter-fixed, 2026-07-11).
    "tools/js-oscript-value-moving-surface.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["js_oscript_value_moving_surface_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/arch-delegation-trust-closure.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["delegation_trust_closure.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/rust-unsafe-soundness-obligation.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["rust_unsafe_soundness_obligation_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # G9 unbounded-alloc / no-progress-loop (2026-07-11).
    "tools/go-unbounded-alloc-noprogress-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["go_unbounded_alloc_noprogress_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    # gen-2 caps (2026-07-11 self-sustaining generator).
    "tools/lifecycle-transition-graph-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["lifecycle_transition_graph_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/deferred-execution-param-binding-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["deferred_execution_param_binding_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/quorum-degradation-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["quorum_degradation_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/total-order-comparator-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["total_order_comparator_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/declared-control-mutator-completeness-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["declared_control_mutator_completeness_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/narrowing-lossy-cast-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["narrowing_lossy_cast_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/recover-completeness-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["recover_completeness_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/rounding-direction-consistency-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["rounding_direction_consistency_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/operand-commensurability-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["operand_commensurability_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
    "tools/randomness-unbiasability-screen.py": {
        "inputs": ["inscope_units.jsonl"],
        "outputs": ["randomness_unbiasability_hypotheses.jsonl"],
        "consumers": ["tools/auto-coverage-closer.py"],
    },
}


# ---------------------------------------------------------------------------
# Merge-preserve: keep manually-registered rich rows the build does not
# reproduce, so a regen never silently de-registers a direct-appended capability
# (the silent-de-registration false-green class - a dropped cap falls into
# "unknown", not "orphan", so the integrity checker stays green while the
# attestation is gone). Guarded on on-disk existence so a DELETED tool's stale
# row is still dropped.
# ---------------------------------------------------------------------------
_AUTO_ID_PREFIXES = ("CAP-tool-", "CAP-make-", "CAP-mcp-", "CAP-rule-", "CAP-hook-")


def _load_existing_inventory() -> list[dict]:
    if not INVENTORY_OUT.exists():
        return []
    rows: list[dict] = []
    try:
        with open(INVENTORY_OUT) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
    except (json.JSONDecodeError, OSError):
        return []
    return rows


def _is_preservable_rich_row(row: dict) -> bool:
    cid = row.get("id", "")
    if not cid or any(cid.startswith(p) for p in _AUTO_ID_PREFIXES):
        # Auto-derived rows are reproduced by the build - never "preserve" them.
        return False
    if not (row.get("outputs") or row.get("consumers")):
        # Only rows carrying real wiring are worth preserving.
        return False
    fps = [
        p for p in (row.get("file_paths") or [])
        if isinstance(p, str) and (p.endswith(".py") or p.endswith(".sh"))
        and "/tests/" not in p and not Path(p).name.startswith("test_")
    ]
    if not fps:
        return False
    # At least one executable tool file must still exist on disk.
    return any((REPO_ROOT / p).exists() for p in fps)


# ---------------------------------------------------------------------------
# Main build logic
# ---------------------------------------------------------------------------
def build_inventory(refresh: bool = False) -> tuple[list[dict], list[dict]]:
    REFERENCE_DIR.mkdir(parents=True, exist_ok=True)

    # Collect all capability records
    all_caps: list[dict] = []

    # MCP callables
    mcp_caps = extract_mcp_callables()
    all_caps.extend(mcp_caps)

    # Make targets
    make_caps = extract_make_targets()
    all_caps.extend(make_caps)

    # R-rules
    r_rule_caps = extract_r_rules()
    all_caps.extend(r_rule_caps)

    # Python tools - auto-discovered (all 1100+) FIRST, then curated (richer) overwrites dups
    all_caps.extend(extract_all_python_tools_auto())
    tool_caps = extract_python_tools()
    all_caps.extend(tool_caps)

    # Load known bugs
    bugs = extract_cap_bugs()

    # Attach bugs to capabilities
    all_caps = attach_known_bugs(all_caps, bugs)

    # Deduplicate by id (prefer later entries)
    seen = {}
    for cap in all_caps:
        seen[cap["id"]] = cap
    all_caps = list(seen.values())

    # Apply full-record wiring overrides (source-registration; see CURATED_FULL_WIRING).
    # Patch inputs/outputs/consumers onto the matching auto-indexed cap so the
    # wiring-integrity checker re-derives WIRED on every regen instead of the
    # fragile direct-append rows that a prior regen silently wiped.
    _wiring_by_base = {Path(k).name: v for k, v in CURATED_FULL_WIRING.items()}
    for cap in all_caps:
        for fp in cap.get("file_paths", []) or []:
            if not isinstance(fp, str):
                continue
            wiring = _wiring_by_base.get(Path(fp).name)
            if wiring:
                cap["inputs"] = list(wiring["inputs"])
                cap["outputs"] = list(wiring["outputs"])
                cap["consumers"] = list(wiring["consumers"])
                cap["status"] = STATUS_LANDED
                base_notes = (cap.get("notes") or "").strip()
                cap["notes"] = (base_notes + " | full-record wiring (regen-stable)").strip(" |")
                break

    # Merge-preserve manually-registered rich rows the build does not reproduce
    # (see _is_preservable_rich_row). Kills the silent-de-registration class: a
    # direct-appended capability survives every regen instead of being wiped.
    built_ids = {c["id"] for c in all_caps}
    for old in _load_existing_inventory():
        oid = old.get("id", "")
        if oid and oid not in built_ids and _is_preservable_rich_row(old):
            notes = (old.get("notes") or "").strip()
            if "preserved-across-regen" not in notes:
                old["notes"] = (notes + " | preserved-across-regen").strip(" |")
            all_caps.append(old)
            built_ids.add(oid)

    # WAVE-2 items 11+12: stamp the machine-derivable role at the single point
    # that sees 100% of records (post preserve-merge, pre-sort). Enum is
    # fail-closed via `make capability-role-enum-check` under docs-check.
    for cap in all_caps:
        cap["role"] = classify_role(cap)

    # Sort by category then id
    cat_order = {"make-target": 0, "mcp-callable": 1, "r-rule": 2, "python-tool": 3, "shell-tool": 4, "hook": 5, "workflow-stage": 6}
    all_caps.sort(key=lambda c: (cat_order.get(c["category"], 99), c["id"]))

    return all_caps, CANONICAL_FLOWS


def write_jsonl(path: Path, records: list[dict]) -> None:
    with open(path, "w") as f:
        for record in records:
            f.write(json.dumps(_ascii_dash_payload(record), ensure_ascii=False) + "\n")


def write_capability_md(path: Path, caps: list[dict]) -> None:
    caps = _ascii_dash_payload(caps)
    lines = [
        "# Capability Inventory",
        "",
        "Auto-generated by `tools/capability-inventory-build.py`. Do not edit by hand.",
        f"Generated: {NOW_ISO}",
        "",
        "## Table of Contents",
        "",
        "- [Make Targets](#make-targets)",
        "- [MCP Callables](#mcp-callables)",
        "- [R-Rules / Pre-Submit Gates](#r-rules--pre-submit-gates)",
        "- [Python Tools](#python-tools)",
        "- [Known Bugs Cross-Reference](#known-bugs-cross-reference)",
        "- [How to Add a Capability](#how-to-add-a-capability)",
        "",
    ]

    # Per-category sections
    categories = [
        ("make-target", "Make Targets"),
        ("mcp-callable", "MCP Callables"),
        ("r-rule", "R-Rules / Pre-Submit Gates"),
        ("python-tool", "Python Tools"),
        ("shell-tool", "Shell Tools"),
    ]

    for cat_key, cat_title in categories:
        cat_caps = [c for c in caps if c["category"] == cat_key]
        if not cat_caps:
            continue
        lines.append(f"## {cat_title}")
        lines.append("")
        lines.append(f"Total: {len(cat_caps)}")
        lines.append("")
        for cap in cat_caps:
            status_emoji = {"LANDED": "OK", "NOMINAL-WIRED": "OK", "PARTIAL": "PARTIAL", "KNOWN-BROKEN": "BROKEN", "DEPRECATED": "DEPRECATED"}.get(cap["status"], cap["status"])
            lines.append(f"### {cap['id']} [{status_emoji}]")
            lines.append("")
            lines.append(f"**Name**: {cap['name']}")
            lines.append(f"**Description**: {cap['description']}")
            if cap.get("file_paths"):
                lines.append(f"**Files**: {', '.join(cap['file_paths'])}")
            if cap.get("verification_command"):
                lines.append(f"**Verify**: `{cap['verification_command']}`")
            if cap.get("known_bugs"):
                lines.append("**Known bugs**:")
                for bug in cap["known_bugs"]:
                    if isinstance(bug, dict):
                        lines.append(f"  - [{bug.get('cap_id','?')}] {str(bug.get('description',''))[:120]}")
                        lines.append(f"    Workaround: {bug.get('workaround','see capability_patch_queue.md')[:120]}")
                    else:
                        # Legacy/preserved rows may carry known_bugs as bare strings.
                        lines.append(f"  - {str(bug)[:120]}")
            if cap.get("notes"):
                lines.append(f"**Notes**: {cap['notes'][:200]}")
            lines.append("")

    # Known bugs cross-reference
    lines.append("## Known Bugs Cross-Reference")
    lines.append("")
    lines.append("| Cap ID | Bug ID | Description | Workaround |")
    lines.append("|--------|--------|-------------|------------|")
    for cap in caps:
        for bug in cap.get("known_bugs", []):
            if not isinstance(bug, dict):
                # Legacy/preserved rows may carry known_bugs as bare strings.
                lines.append(f"| {cap['id']} | - | {str(bug)[:80].replace('|', '/')} | - |")
                continue
            desc = str(bug.get("description", ""))[:80].replace("|", "/")
            wkrd = str(bug.get("workaround", ""))[:80].replace("|", "/")
            lines.append(f"| {cap['id']} | {bug.get('cap_id','-')} | {desc} | {wkrd} |")
    lines.append("")

    # How to add
    lines.append("## How to Add a Capability")
    lines.append("")
    lines.append("1. For a new make target: add entry to `KEY_MAKE_TARGETS` dict in `tools/capability-inventory-build.py`")
    lines.append("2. For a new MCP callable: it is auto-discovered from `tools/vault-mcp-server.py` TOOL_SCHEMAS `\"name\"` fields")
    lines.append("3. For a new R-rule: add entry to `CRITICAL_R_RULES` list in `tools/capability-inventory-build.py`")
    lines.append("4. For a new Python tool: add entry to `KEY_PYTHON_TOOLS` dict in `tools/capability-inventory-build.py`")
    lines.append("5. Re-run: `python3 tools/capability-inventory-build.py --refresh`")
    lines.append("6. Run tests: `python3 -m unittest tools.tests.test_capability_inventory -v`")
    lines.append("")

    path.write_text(_ascii_dash_text("\n".join(lines)))


def write_flows_md(path: Path, flows: list[dict]) -> None:
    flows = _ascii_dash_payload(flows)
    lines = [
        "# Canonical Operational Flows",
        "",
        "Auto-generated by `tools/capability-inventory-build.py`. Do not edit by hand.",
        f"Generated: {NOW_ISO}",
        "",
        "## Index",
        "",
    ]
    for flow in flows:
        lines.append(f"- [{flow['name']}](#{flow['id'].lower()}) - {flow['purpose']}")
    lines.append("")

    for flow in flows:
        lines.append(f"## {flow['id']}")
        lines.append("")
        lines.append(f"**Name**: {flow['name']}")
        lines.append(f"**Purpose**: {flow['purpose']}")
        lines.append(f"**Duration**: {flow.get('expected_duration', 'unknown')}")
        lines.append("")
        if flow.get("prerequisites"):
            lines.append("**Prerequisites**: " + ", ".join(flow["prerequisites"]))
            lines.append("")
        lines.append("**Steps**:")
        lines.append("")
        for i, step in enumerate(flow.get("steps", []), 1):
            lines.append(f"{i}. Command:")
            lines.append("")
            lines.append("```bash")
            lines.append(step["command"])
            lines.append("```")
            if step.get("expected_output"):
                lines.append(f"   Expected output: `{step['expected_output']}`")
            if step.get("on_failure"):
                lines.append(f"   On failure: {step['on_failure']}")
            lines.append("")
        lines.append("")
        if flow.get("common_failures"):
            lines.append("**Common failures**:")
            lines.append("")
            for f_item in flow["common_failures"]:
                lines.append(f"- **{f_item['failure_mode']}**")
                lines.append(f"  - Root cause: {f_item['root_cause']}")
                lines.append(f"  - Fix: {f_item['fix']}")
            lines.append("")

    path.write_text(_ascii_dash_text("\n".join(lines)))


def _load_jsonl_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def _diff_record_sets(existing: list[dict], generated: list[dict]) -> dict[str, list[str]]:
    old = {str(r.get("id")): _ascii_dash_payload(r) for r in existing if r.get("id")}
    new = {str(r.get("id")): _ascii_dash_payload(r) for r in generated if r.get("id")}
    added = sorted(set(new) - set(old))
    deprecated = sorted(set(old) - set(new))
    changed = sorted(
        rid for rid in set(old).intersection(new)
        if json.dumps(old[rid], sort_keys=True) != json.dumps(new[rid], sort_keys=True)
    )
    return {"new": added, "changed": changed, "deprecated": deprecated}


def build_diff_summary(caps: list[dict], flows: list[dict]) -> dict[str, Any]:
    cap_diff = _diff_record_sets(_load_jsonl_records(INVENTORY_OUT), caps)
    flow_diff = _diff_record_sets(_load_jsonl_records(FLOWS_OUT), flows)
    return {
        "schema": "auditooor.capability_inventory_diff.v1",
        "generated_at": NOW_ISO,
        "read_only": True,
        "capabilities": cap_diff,
        "flows": flow_diff,
        "totals": {
            "new": len(cap_diff["new"]) + len(flow_diff["new"]),
            "changed": len(cap_diff["changed"]) + len(flow_diff["changed"]),
            "deprecated": len(cap_diff["deprecated"]) + len(flow_diff["deprecated"]),
        },
    }


def print_diff_summary(summary: dict[str, Any]) -> None:
    totals = summary["totals"]
    print(
        "new={new} changed={changed} deprecated={deprecated} read_only=true".format(
            **totals,
        )
    )
    for section in ("capabilities", "flows"):
        diff = summary[section]
        for bucket in ("new", "changed", "deprecated"):
            values = diff[bucket]
            if values:
                print(f"{section}.{bucket}: " + ", ".join(values[:25]))
                if len(values) > 25:
                    print(f"{section}.{bucket}: ... {len(values) - 25} more")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build capability inventory + canonical flows")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Rebuild outputs from current metadata; does not run verification commands",
    )
    parser.add_argument("--diff", action="store_true", help="Show JSONL changes without writing files")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    args = parser.parse_args()

    caps, flows = build_inventory(refresh=args.refresh)

    if args.diff:
        diff_summary = build_diff_summary(caps, flows)
        if args.json:
            print(json.dumps(diff_summary, indent=2))
        else:
            print_diff_summary(diff_summary)
        return 0

    # Write JSONL
    write_jsonl(INVENTORY_OUT, caps)
    write_jsonl(FLOWS_OUT, flows)

    # Write docs
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    write_capability_md(DOCS_DIR / "CAPABILITY_INVENTORY.md", caps)
    write_flows_md(DOCS_DIR / "CANONICAL_FLOWS.md", flows)

    # Summary
    by_cat = {}
    for cap in caps:
        by_cat.setdefault(cap["category"], 0)
        by_cat[cap["category"]] += 1

    bugs_total = sum(len(c.get("known_bugs", [])) for c in caps)

    summary = {
        "schema": "auditooor.capability_inventory_build_summary.v1",
        "generated_at": NOW_ISO,
        "total_capabilities": len(caps),
        "total_flows": len(flows),
        "by_category": by_cat,
        "total_known_bugs": bugs_total,
        "output_files": [str(INVENTORY_OUT), str(FLOWS_OUT), str(DOCS_DIR / "CAPABILITY_INVENTORY.md"), str(DOCS_DIR / "CANONICAL_FLOWS.md")],
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Capability Inventory built: {NOW_ISO}")
        print(f"  Total capabilities: {len(caps)}")
        print(f"  Total flows: {len(flows)}")
        print(f"  Known bugs: {bugs_total}")
        print(f"  By category:")
        for cat, count in sorted(by_cat.items()):
            print(f"    {cat}: {count}")
        print(f"  Output: {INVENTORY_OUT}")
        print(f"  Docs: {DOCS_DIR / 'CAPABILITY_INVENTORY.md'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
