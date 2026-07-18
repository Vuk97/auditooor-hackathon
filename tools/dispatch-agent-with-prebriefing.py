#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dispatch-agent-with-prebriefing.py

iter15 Lane XXXX (2026-05-23) - PRE-SPAWN HOOK that closes the META-1
shelfware gap left open by iter14 LLLL.

Background
----------
iter14 LLLL shipped the ``vault_dispatch_brief_skeleton`` MCP callable
(22/22 tests). LLLL's honest verdict noted "Adoption still depends on
iter7 follow-up wiring this into the agent-dispatch pre-spawn hook."
Without a pre-spawn hook the callable is shelfware again - the same trap
META-1 was supposed to fix (iter12 VVV anchor: 0/16 post-META-1 outputs
cited Section 15a/15b).

This script is the orchestrator-side pre-spawn hook. It is a wrapper
that operators and cron jobs call INSTEAD of writing the Agent prompt
raw. It:

1. Detects the lane_type from the prompt text (keyword inference).
2. Detects the severity from the prompt text (keyword inference).
3. Detects the workspace_path from the prompt text or current cwd.
4. Calls ``vault_dispatch_brief_skeleton`` with the inferred metadata.
5. Formats the skeleton response as a markdown Section 15a / 15b /
   15c / 15d block (matching ``tools/agent-brief-prefetch.py`` output).
6. Prepends the block to the original prompt.
7. Emits the enriched prompt to stdout (operator copies into Claude),
   OR if ``--dispatch`` is set, pipes it to ``claude`` CLI directly.
   Direct ``--dispatch`` is fail-closed unless the process proves it was
   launched by ``tools/spawn-worker.sh`` or uses an audited bypass.

Usage examples
--------------
Operator pre-flight (paste enriched prompt into Claude session):

    $ python3 tools/dispatch-agent-with-prebriefing.py \\
          --prompt-file my_lane_prompt.txt \\
          --lane-type dispute \\
          --severity HIGH \\
          --workspace /Users/wolf/audits/dydx
    (enriched prompt on stdout)

Cron / scripted dispatch (pipe into claude CLI):

    $ python3 tools/dispatch-agent-with-prebriefing.py \\
          --prompt "Lane X: refile cantina-202 with R30 evidence" \\
          --lane-type filing \\
          --severity CRITICAL \\
          --workspace /Users/wolf/audits/dydx \\
          --dispatch

Auto-infer everything (read prompt from stdin, infer the rest):

    $ cat my_prompt.txt | \\
          python3 tools/dispatch-agent-with-prebriefing.py --infer-all

Hard rules
----------
* NEVER modifies drafts under submissions/* (L34).
* Workspace path auto-inference is best-effort; missing workspace =
  graceful degradation (workspace-specific fields empty, no crash).
* MCP call failure = graceful fallback (skeleton block still emits a
  diagnostic warning section, the original prompt still flows through).
* The wrapper NEVER mutates the operator's prompt content; the prefix
  block is a clean addendum with BEGIN/END markers.

Tests: tools/tests/test_dispatch_agent_with_prebriefing.py
Hook variant (option B): see ~/.claude/settings.json snippet in
docs/AGENT_DISPATCH_PATTERN.md / report.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

REPO = pathlib.Path(__file__).resolve().parent.parent

# G13: shared SEVERITY.md discovery + tier-row parser (single source of truth
# with tools/rubric-row-coverage-check.py). Read directly so the full rubric
# reaches the brief even when the MCP skeleton payload is degraded.
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
try:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from lib import severity_rubric as _severity_rubric  # type: ignore
except Exception:  # pragma: no cover - lib optional; injection degrades gracefully
    _severity_rubric = None

# Shared dollar-impact derivation labels (single source of truth with the pre-submit
# Check #148 gate, tools/absolute-usd-derivation-check.py). The brief INSTRUCTS what to
# write; the gate CHECKS it - binding both to this tuple means they cannot drift (a test
# asserts brief-mandate labels == gate required-derivation labels). Fallback keeps the
# brief renderable if the lib is unavailable.
try:
    from lib import dollar_impact_labels as _dollar_labels  # type: ignore
    _DOLLAR_IMPACT_LABELS: Tuple[str, ...] = tuple(
        _dollar_labels.DOLLAR_IMPACT_DERIVATION_LABELS)
except Exception:  # pragma: no cover - lib optional
    _DOLLAR_IMPACT_LABELS = (
        "Asset identity", "Unit->USD", "Market-size scenario", "Absolute $ vs floor")
_LBL_ASSET, _LBL_UNIT, _LBL_MARKET, _LBL_ABS_VS_FLOOR = _DOLLAR_IMPACT_LABELS

SCHEMA = "auditooor.dispatch_agent_with_prebriefing.v1"
DISPATCH_GUARD_SCHEMA = "auditooor.spawn_worker_dispatch_guard.v1"
BRIEF_CLI_VALIDATOR_SCHEMA = "auditooor.brief_cli_validator_preflight.v1"
EXIT_DISPATCH_GUARD_REFUSED = 2
EXIT_BRIEF_CLI_VALIDATOR_REFUSED = 3
EXIT_HUNT_BRIEF_COMPLETENESS_REFUSED = 4

# PR9a-1: hunt-brief completeness gate. Fail-closed for hunt-class lanes
# whose enriched brief lacks the MCP-first recall block, the canonical
# hunt-definition + skip-set, or the capability-adoption (brain-prime +
# per-function hacker-questions) requirements. Worker module:
# tools/hunt-brief-completeness-check.py.
# r36-rebuttal: lane PR9a-1 registered in .auditooor/agent_pathspec.json agents[]
HUNT_BRIEF_COMPLETENESS_SCHEMA = "auditooor.pr9a_hunt_brief_completeness.v1"
# Default is fail-closed (the gate's reason for existing). Set this env var
# to "1" to downgrade to warn-only (dispatch proceeds, summary on stderr).
HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR = (
    "AUDITOOOR_HUNT_BRIEF_COMPLETENESS_WARN_ONLY"
)
# Disable the gate entirely (no preflight at all).
HUNT_BRIEF_COMPLETENESS_DISABLE_ENV_VAR = (
    "AUDITOOOR_HUNT_BRIEF_COMPLETENESS_DISABLE"
)
# Hunt-class lane types the completeness gate fires on. Mirrors the G13.2
# full-tier-coverage gate set so the two completeness gates fire on the
# same lanes.
HUNT_BRIEF_COMPLETENESS_LANE_TYPES = frozenset(
    {"hunt", "drill", "comp", "fuzz", "opposed-trace-harness", "escalation"}
)

# HUNT-BRIEF LEAN (2026-07-01, generic/all-languages): a HUNT worker's job is to
# FIND a bug in a unit, not to FILE one. Measured: the enriched hunt brief was
# 60-82KB, ~40% of which is FILE-TIME submission discipline (R62 triager
# pre-filing simulator, R63 auto-tier assignment, the OOS/AI-FP preflight, R78
# load-bearing-assumption audit, R82 recovery-falsification). Those fire when a
# CANDIDATE exists (drafting / filing lanes + pre-submit-check), not while
# reading a function - carrying them at hunt time causes vulnerability drift
# (the model slides toward filing-mindset) and attention dilution. When lean is
# ON (default), a pure hunt-class lane DEFERS those file-time sections; they
# still land in full on filing/drafting lanes and in pre-submit-check. Reversible
# via AUDITOOOR_HUNT_BRIEF_LEAN=0 (restores the pre-2026-07-01 fat hunt brief).
HUNT_BRIEF_LEAN_ENV_VAR = "AUDITOOOR_HUNT_BRIEF_LEAN"
# lane_types that are PURELY hunting (find, don't file). A lane that is both a
# hunt and a filing lane (none currently) would not lean.
_PURE_HUNT_LANE_TYPES = frozenset({"hunt", "drill", "comp", "fuzz"})


def _hunt_brief_lean(lane_type: Optional[str]) -> bool:
    """True when the file-time submission sections should be DEFERRED for this
    lane (a pure hunt lane, with lean enabled). False -> the full fat brief."""
    if os.environ.get(HUNT_BRIEF_LEAN_ENV_VAR, "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    return (lane_type or "").strip().lower() in _PURE_HUNT_LANE_TYPES

# r36-rebuttal: lane-LIFT-23-BRIEF-CLI-VALIDATOR-WIRE registered via
# tools/agent-pathspec-register.py - LIFT-23 wires the brief-cli-validator
# preflight into the dispatch flow per LIFT-20 audit recommendation (c).
BRIEF_CLI_VALIDATOR_DISABLE_ENV_VAR = "AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE"
BRIEF_CLI_VALIDATOR_TIMEOUT_ENV_VAR = "AUDITOOOR_BRIEF_CLI_VALIDATOR_TIMEOUT"
BRIEF_CLI_VALIDATOR_DEFAULT_TIMEOUT = 60

# F4-safe (spec E4.4): hunt-mode selector. Two modes share the source-read
# mandate but differ on the negative default:
#   verify-strict (default) = current R76 anchor-or-drop, EXCEPT an
#     unable-to-anchor finding is routed to the hunt_quarantine sink for a
#     re-dispatch-with-full-source second pass, NOT silently set
#     applies_to_target='no' (which fcc miscounts as ruled-out).
#   generate-broad = recall-first: a confidence field, kill-rubric prior OFF,
#     uncertain findings ALLOWED and routed to quarantine rather than dropped.
# Selected via this env var or the --hunt-mode CLI flag (flag wins). Any
# unrecognised value falls back to verify-strict (fail-safe to the stricter
# negative default).
DISPATCH_HUNT_MODE_ENV_VAR = "AUDITOOOR_DISPATCH_HUNT_MODE"
HUNT_MODE_VERIFY_STRICT = "verify-strict"
HUNT_MODE_GENERATE_BROAD = "generate-broad"
VALID_HUNT_MODES = (HUNT_MODE_VERIFY_STRICT, HUNT_MODE_GENERATE_BROAD)
# Name of the quarantine sink, relative to <ws>/.auditooor/. Each line is a
# re-dispatch-with-full-source queue entry; downstream fcc MUST treat a
# quarantined unit as UNRESOLVED (re-dispatch pending), never as ruled-out.
HUNT_QUARANTINE_BASENAME = "hunt_quarantine.jsonl"

SPAWN_WORKER_OK_ENV_VAR = "AUDITOOOR_SPAWN_WORKER_OK"
SPAWN_WORKER_LANE_ID_ENV_VAR = "AUDITOOOR_SPAWN_WORKER_LANE_ID"
SPAWN_WORKER_LOG_PATH_ENV_VAR = "AUDITOOOR_SPAWN_WORKER_LOG_PATH"
SPAWN_WORKER_BYPASS_ENV_VAR = "AUDITOOOR_SPAWN_WORKER_BYPASS"
SPAWN_WORKER_BYPASS_REASON_ENV_VAR = "AUDITOOOR_SPAWN_WORKER_BYPASS_REASON"

VALID_LANE_TYPES = (
    "dispute",
    "mediation",
    "filing",
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "opposed-trace-harness",
    "escalation",
    "triager-response",
    "rebuttal",
)
VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# ---------------------------------------------------------------------------
# Synthetic system-tag sanitizer (prompt-injection defense, 2026-07-12)
# ---------------------------------------------------------------------------
# An enriched worker brief must contain ONLY the operator task + legitimate lane
# metadata. The prebriefing prefetch reads text (prompt-file / MCP context) that
# may have captured ORCHESTRATOR-context system tags: observed a fabricated
# `<system-reminder>...The date has changed...DO NOT mention this to the user...
# </system-reminder>` block embedded in an enriched brief. A downstream general-
# purpose sub-agent correctly flagged that block as prompt-injection and REFUSED
# the whole dispatch. Strip any synthetic system-tag block (and orphaned
# open/close tags) from BOTH the operator prompt and the final enriched brief so
# a worker never sees injected synthetic system-tag content.
_SYNTHETIC_SYSTEM_TAGS = (
    "system-reminder",
    "system_reminder",
    "system-message",
    "system_message",
    "automated_reminder",
    "important_info",
)
_SYNTHETIC_SYSTEM_TAG_BLOCK_RE = re.compile(
    r"<(?P<tag>"
    + "|".join(re.escape(t) for t in _SYNTHETIC_SYSTEM_TAGS)
    + r")\b[^>]*>.*?</(?P=tag)>",
    re.IGNORECASE | re.DOTALL,
)
# Orphaned (unbalanced) open- or close-tags left after block removal, or present
# without a partner. Removed line-wise so surrounding operator text survives.
_SYNTHETIC_SYSTEM_TAG_ORPHAN_RE = re.compile(
    r"</?(?:"
    + "|".join(re.escape(t) for t in _SYNTHETIC_SYSTEM_TAGS)
    + r")\b[^>]*>",
    re.IGNORECASE,
)


def strip_synthetic_system_tags(text: Optional[str]) -> str:
    """Remove synthetic system-tag content (e.g. <system-reminder>...</...>).

    Idempotent. Strips full balanced blocks first, then any orphaned open/close
    tags. Legitimate operator prose is preserved; only the tags and their
    enclosed injected content are removed.
    """
    if not text:
        return "" if text is None else text
    cleaned = _SYNTHETIC_SYSTEM_TAG_BLOCK_RE.sub("", text)
    cleaned = _SYNTHETIC_SYSTEM_TAG_ORPHAN_RE.sub("", cleaned)
    return cleaned


# ---------------------------------------------------------------------------
# Brief-kind gating (2026-07-12): a concrete tooling-fix brief must NOT be
# wrapped in the vulnerability-HUNT template (bridge-proof-domain, hacker
# questions, R36-R45 skeleton) - that corrupts the operator's task into an
# unrelated hunt brief. brief_kind == "tooling" passes the operator prompt
# through RAW (like --no-prebriefing) minus the hunt template. "auto" heuristic-
# infers tooling vs hunt; "hunt" forces the full skeleton.
VALID_BRIEF_KINDS = ("auto", "tooling", "hunt")

# Lane types that are by-definition NOT vulnerability hunts (concrete
# tooling/infra/docs work). These pass through raw under brief_kind=auto.
TOOLING_LANE_TYPES = frozenset(
    {"tool-build", "infra", "capability", "wire-audit", "corpus", "docs", "cleanup"}
)

# Heuristic signals that a neutral-lane prompt is a concrete tooling fix rather
# than a vulnerability hunt. Kept conservative: hunt keywords always win.
_TOOLING_HEURISTIC_KEYWORDS = (
    "tools/",
    "regression test",
    "make docs-check",
    "commit ritual",
    "commit hash",
    ".py:",
    ".sh:",
    "tooling-fix",
    "tooling fix",
    "spawn-worker",
    "pre-submit-check.sh",
)
_HUNT_HEURISTIC_KEYWORDS = (
    "vulnerabilit",
    "exploit",
    "attack surface",
    "hacker question",
    "bridge-proof",
    "invariant",
    "poc",
    "severity",
    "finding",
)


def infer_brief_kind(prompt_text: str, lane_type: Optional[str]) -> str:
    """Return 'tooling' or 'hunt' for a brief_kind=auto request.

    A tooling lane_type (tool-build/infra/capability/wire-audit/corpus/docs/
    cleanup) is tooling. Otherwise a keyword heuristic: hunt signals win over
    tooling signals (fail toward the richer hunt brief), so a genuine finding
    prompt that happens to mention a tool path is still hunt-wrapped.
    """
    lt = (lane_type or "").strip().lower()
    if lt in TOOLING_LANE_TYPES:
        return "tooling"
    lower = (prompt_text or "").lower()
    if any(kw in lower for kw in _HUNT_HEURISTIC_KEYWORDS):
        return "hunt"
    if any(kw in lower for kw in _TOOLING_HEURISTIC_KEYWORDS):
        return "tooling"
    return "hunt"

# Lane-type keyword inference. Order matters: more-specific keywords
# (escalation, opposed-trace) must beat less-specific (dispute, filing).
LANE_KEYWORD_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "opposed-trace-harness",
        (
            "opposed-trace",
            "opposed_trace",
            "defense-matrix",
            "defense_matrix",
            "actor-separation",
            "actor_separation",
            "harness-matrix",
        ),
    ),
    (
        "escalation",
        ("escalat", "walk-back", "walk_back", "refile", "re-file"),
    ),
    (
        "dispute",
        ("dispute", "rebuttal", "triager-response", "triager_response"),
    ),
    (
        "mediation",
        ("mediation", "mediator", "negotiation"),
    ),
    (
        "hunt",
        (
            "hunt",
            "h1-",
            "h2-",
            "h3-",
            "h4-",
            "h5-",
            "discover",
            "scout",
            "mine",
            "fan-out",
            "fanout",
        ),
    ),
    (
        "drill",
        ("drill", "prove lane", "proof lane", "poc lane"),
    ),
    (
        "comp",
        ("competition", "contest", "comp lane"),
    ),
    (
        "fuzz",
        ("fuzz", "fuzzer", "fuzzing"),
    ),
    (
        "filing",
        (
            "filing",
            "file ",
            "paste-ready",
            "paste_ready",
            "submit",
            "submission",
            "promote",
            "package",
        ),
    ),
)

# ---------------------------------------------------------------------------
# Filing Finalization - platform-aware Definition-of-Done (Section 15q)
# r36-rebuttal: lane spawn-worker-filing-dod registered in
# .auditooor/agent_pathspec.json agents[].
# ---------------------------------------------------------------------------

# Lane types that get the Filing Finalization Definition-of-Done injected.
FILING_FINALIZATION_LANE_TYPES = frozenset(
    {"filing", "triager-response", "rebuttal", "escalation"}
)

# Lane types that get the Load-Bearing Assumption Audit block (Rule 78 proactive
# injection). Filing-class lanes (so the ledger is built before promotion) plus
# hunt-class lanes (so assumptions are surfaced while the impact chain is being
# built, not just at submit time).
LOAD_BEARING_ASSUMPTION_LANE_TYPES = (
    FILING_FINALIZATION_LANE_TYPES | HUNT_BRIEF_COMPLETENESS_LANE_TYPES
)

# Lane types whose lane authors a harness / invariant / coverage / PoC / fuzz
# scaffold. These get the Rule 80 Harness-Authoring Honesty Requirements block
# injected up front so the harness is built real the FIRST time (CUT is the real
# in-scope contract, invariants are mutation-verified non-vacuous, the engine
# actually executes, and coverage counts only real reviewed/fuzzed units).
# Some entries (poc, prove, invariant, coverage, exploit-conversion) are not in
# VALID_LANE_TYPES; they are recognized here for direct lane_type pass-through.
HARNESS_AUTHORING_LANE_TYPES = frozenset(
    {
        "harness",
        "invariant",
        "coverage",
        "poc",
        "fuzz",
        "prove",
        "exploit-conversion",
    }
)

# Prompt keywords that indicate a harness-authoring lane even when the lane_type
# itself is not in HARNESS_AUTHORING_LANE_TYPES (matched case-insensitively).
HARNESS_AUTHORING_PROMPT_KEYWORDS = (
    "harness",
    "invariant",
    "chimera",
    "recon",
    "setup.sol",
    "targetfunctions",
    "properties",
    "medusa",
    "echidna",
    "halmos",
    "mutation",
    "write a poc",
    "scaffold",
)


def is_harness_authoring_lane(lane_type: str, prompt_text: str = "") -> bool:
    """True when the lane authors a harness / invariant / coverage / PoC / fuzz
    scaffold - either by lane_type membership or by prompt-keyword detection."""
    if (lane_type or "").strip().lower() in HARNESS_AUTHORING_LANE_TYPES:
        return True
    lower = (prompt_text or "").lower()
    return any(kw in lower for kw in HARNESS_AUTHORING_PROMPT_KEYWORDS)

# Platform registry path (Deliverable 1).
PLATFORM_REQUIREMENTS_PATH = REPO / "reference" / "platform_submission_requirements.json"

# Platform-keyword resolution rules. Order matters: more-specific platform
# signals (zebra/zcash/GHSA/ZCG -> github-ghsa) must beat a generic "immunefi"
# substring that also appears in some workspaces' rubric prose. Each tuple is
# (platform_id, (keyword, ...)). Keywords matched case-insensitively against
# the workspace SCOPE.md / SEVERITY.md / README.md / .auditooor text + the
# workspace directory name.
PLATFORM_KEYWORD_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "github-ghsa",
        (
            "github-ghsa",
            "github advisor",
            "ghsa",
            "report a vulnerability",
            "zcg",
            "zcash community grants",
            "zcash",
            "zebra",
        ),
    ),
    (
        "hackenproof",
        ("hackenproof", "hacken proof", "hyperbridge"),
    ),
    (
        "cantina",
        ("cantina",),
    ),
    (
        "immunefi",
        ("immunefi", "primacy of impact"),
    ),
)

# Severity keyword inference. Higher priority first.
SEVERITY_KEYWORD_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("CRITICAL", ("critical", "crit-1", "crit-2", "crit_", "permanent freezing")),
    ("HIGH", ("high severity", "high-severity", "high ", " high", "high-1")),
    ("MEDIUM", ("medium", "med-", "medium severity")),
    ("LOW", ("low severity", "low-severity", "informational")),
)

# Workspace inference - common explicit-path patterns. Matches absolute
# paths under /Users/wolf/audits/<name> or operator's tilde-expanded
# equivalent. Also supports a workspace-name shorthand.
_WS_ABS_RE = re.compile(
    r"(?:^|\s)(/Users/[\w./_-]+/audits/[\w._-]+|/Users/[\w./_-]+/auditooor[\w/._-]*)",
    re.MULTILINE,
)
_WS_NAMED_RE = re.compile(
    r"workspace[^\n]{0,80}?[`\"']?(?:~/)?audits/([\w_-]+)[`\"']?",
    re.IGNORECASE,
)
KNOWN_WORKSPACES_ROOT = pathlib.Path("/Users/wolf/audits")

try:
    from dispatch_oos_preflight import evaluate_preflight as _dispatch_oos_evaluate
    from dispatch_oos_preflight import render_markdown as _dispatch_oos_render
except ImportError:  # pragma: no cover - exercised only when loaded off-path.
    _DISPATCH_OOS_TOOL = pathlib.Path(__file__).resolve().parent / "dispatch_oos_preflight.py"
    _dispatch_oos_evaluate = None
    _dispatch_oos_render = None
    if _DISPATCH_OOS_TOOL.is_file():
        import importlib.util as _importlib_util

        _spec = _importlib_util.spec_from_file_location("dispatch_oos_preflight", _DISPATCH_OOS_TOOL)
        if _spec is not None and _spec.loader is not None:
            _mod = _importlib_util.module_from_spec(_spec)
            sys.modules["dispatch_oos_preflight"] = _mod
            _spec.loader.exec_module(_mod)  # type: ignore[attr-defined]
            _dispatch_oos_evaluate = getattr(_mod, "evaluate_preflight", None)
            _dispatch_oos_render = getattr(_mod, "render_markdown", None)


# ---------------------------------------------------------------------------
# Lazy-load function-source-extractor (same pattern as inscope-hunt-batch-builder).
# Used to embed real function bodies in the pre-flight pack section so agents
# have the REAL source inline and are not forced to rely on stale pack summaries
# (pack-only hunting produced 5/10 false-positive HIGHs in testing).
# ---------------------------------------------------------------------------
_FSE_MOD = None


def _fse():
    """Return the function_source_extractor module, loaded once on first use."""
    global _FSE_MOD
    if _FSE_MOD is None:
        import importlib.util as _il
        _p = pathlib.Path(__file__).resolve().parent / "function-source-extractor.py"
        if _p.is_file():
            _s = _il.spec_from_file_location("function_source_extractor", _p)
            if _s is not None and _s.loader is not None:
                _m = _il.module_from_spec(_s)
                _s.loader.exec_module(_m)  # type: ignore[attr-defined]
                _FSE_MOD = _m
    return _FSE_MOD


# ---------------------------------------------------------------------------
# Lazy-load hacker_question_renderer (the impact-attach SINGLE SOURCE OF TRUTH).
#
# The dispatch impact-methodology section MUST partition impacts the same way
# the renderer (render_impact_questions) does. The renderer is the canonical
# classifier: it owns `_CONTRACT_KIND_RULES` (the contract-kind inference) and
# `kind_family` (the fine->family reconciliation that lets a coarse inferred
# kind match a corpus playbook authored against a FINE kind). Forking a second
# `_CONTRACT_KIND_RULES` here caused the G5 divergence (dispatch saw `amm-dex`/
# `zk-verifier` where the renderer sees `amm`/`zk-circuit`, and dispatch's
# literal-only attach missed the family reconciliation). Importing the renderer
# eliminates the fork: dispatch infers kind via `classify_impact_target` and
# attaches via `kind_family`, exactly as the renderer does.
#
# Graceful-degrade: if the renderer module is missing / unimportable, the
# callers fall back to the local literal rules (see `_infer_contract_kind` /
# `_impact_playbook_attaches`), so the dispatch brief never raises.
# ---------------------------------------------------------------------------
_RENDERER_MOD: Any = None
_RENDERER_LOAD_TRIED = False


def _renderer():
    """Return the hacker_question_renderer module, loaded once on first use.

    Returns None when the module cannot be imported (the callers degrade to
    their local literal rules). The module is registered in sys.modules BEFORE
    exec_module so a self-referential import resolves on Python 3.14.
    """
    global _RENDERER_MOD, _RENDERER_LOAD_TRIED
    if _RENDERER_MOD is not None or _RENDERER_LOAD_TRIED:
        return _RENDERER_MOD
    _RENDERER_LOAD_TRIED = True
    try:
        import importlib.util as _il

        _p = (
            pathlib.Path(__file__).resolve().parent
            / "hacker_question_renderer.py"
        )
        if not _p.is_file():
            return None
        _s = _il.spec_from_file_location("hacker_question_renderer", _p)
        if _s is None or _s.loader is None:
            return None
        _m = _il.module_from_spec(_s)
        # Python 3.14: register before exec so a self-referential import
        # (the renderer importing its own name) resolves.
        sys.modules["hacker_question_renderer"] = _m
        _s.loader.exec_module(_m)  # type: ignore[attr-defined]
        _RENDERER_MOD = _m
    except Exception:
        _RENDERER_MOD = None
    return _RENDERER_MOD


def _pack_embedded_body_block(
    source_ref: str,
    workspace_path: Optional[pathlib.Path],
    fn: str = "",
) -> str:
    """Try to extract the real function body for the pack's source_ref.

    Returns an inline body block string (same shape as inscope-hunt-batch-builder
    _embedded_body_block) or '' if the file cannot be resolved / body is empty.
    source_ref is expected as 'relative/path/to/file.sol:LINE' or absolute.
    """
    if not source_ref or ":" not in source_ref:
        return ""
    fse = _fse()
    if fse is None:
        return ""
    # Parse file + line from source_ref.
    parts = source_ref.rsplit(":", 1)
    rel_file = parts[0]
    try:
        line = int(parts[1])
    except (ValueError, IndexError):
        return ""
    if line <= 0:
        return ""
    ws = workspace_path if workspace_path is not None else pathlib.Path(".")
    try:
        body, _end, dep_count = fse.extract_self_contained(ws, rel_file, line)
    except Exception:
        return ""
    if not body.strip():
        return ""
    fn_label = fn or rel_file.split("/")[-1]
    dep_note = (
        f"The target body PLUS its {dep_count} referenced same-file guard/callee/modifier "
        "definition(s) are included below (SELF-CONTAINED). Read the file ONLY for a "
        "CROSS-FILE/imported callee a finding genuinely hinges on."
        if dep_count else
        "The target body is below. It references no resolvable same-file callees; if a "
        "finding hinges on an external/inherited symbol, Read the file for just that symbol."
    )
    return (
        f"TARGET FUNCTION + CONTEXT (mechanically extracted VERBATIM from "
        f"{rel_file}:{line} - REAL code, your primary input; cite from it):\n"
        f"```\n{body}\n```\n"
        f"  !! {dep_note}\n\n"
    )


# Hard source-read mandate emitted whenever a pre-flight pack is present.
# Grounded in the empirical finding: pack-only hunting hallucinated 5/10
# false-positive HIGH findings in testing (R76-class failures).
#
# F4-safe (spec E4.3 + E4.4): the source-read mandate is present in BOTH hunt
# modes. The modes differ ONLY in the negative default for a finding that
# cannot be anchored to a real file:line:
#   - verify-strict: route the unanchorable finding to the hunt_quarantine
#     sink (a re-dispatch-with-full-source queue) instead of silently setting
#     applies_to_target='no'. The OLD silent-drop default let fcc miscount the
#     unit as "examined + ruled out", suppressing recall.
#   - generate-broad: recall-first. Emit a confidence field, do NOT apply the
#     kill-rubric prior, allow uncertain findings, and route the uncertain /
#     unanchorable ones to the SAME quarantine sink for a second pass.
# In NEITHER mode is an unanchorable finding silently ruled out.

# Shared opening clause - the R76 source-read requirement itself (identical in
# both modes).
_PACK_SOURCE_READ_MANDATE_PREFIX = (
    "**SOURCE-READ MANDATE (R76 HARD RULE - pack-only hunting hallucinated "
    "5/10 false-positive HIGHs in testing)**: This pack is a CONDENSED PRIMING "
    "SIGNAL - it contains NO reliable function body and may be stale. "
    "You MUST read the real source file(s) cited in source_ref before forming "
    "any finding. Cite only lines you actually read. NEVER treat pack excerpts "
    "as code."
)

# Per-mode negative-default clause (what to do when a finding cannot be
# anchored to a real file:line you read).
_PACK_NEG_DEFAULT_VERIFY_STRICT = (
    " If you cannot anchor a finding to a real file:line you read, do NOT set "
    "applies_to_target='no' (that is silently counted as ruled-out and "
    "suppresses recall). Instead route it to the quarantine queue: set "
    "notes='unable-to-anchor', quarantine=true, and emit a "
    "`hunt_quarantine.jsonl` row {unit, source_ref, reason:'unable-to-anchor', "
    "needs_full_source:true} so it is RE-DISPATCHED with the full source file. "
    "A quarantined unit is UNRESOLVED, never ruled out (R76)."
)
_PACK_NEG_DEFAULT_GENERATE_BROAD = (
    " GENERATE-BROAD MODE (recall-first): the kill-rubric prior is OFF - do "
    "NOT pre-suppress a candidate because it looks like a known dead end or a "
    "likely false positive. For EVERY finding emit a `confidence` field "
    "(0.0-1.0). UNCERTAIN findings are ALLOWED: if you cannot fully anchor a "
    "finding to a real file:line you read, do NOT drop it and do NOT set "
    "applies_to_target='no'. Route it to the quarantine queue instead: set "
    "notes='unable-to-anchor', quarantine=true, confidence=<your estimate>, "
    "and emit a `hunt_quarantine.jsonl` row {unit, source_ref, "
    "reason:'unable-to-anchor', needs_full_source:true, confidence:<n>} so it "
    "is RE-DISPATCHED with the full source file. A quarantined unit is "
    "UNRESOLVED, never ruled out."
)


def resolve_hunt_mode(cli_mode: Optional[str] = None) -> str:
    """Resolve the active hunt mode (E4.4). CLI flag wins over env var; any
    unrecognised value falls back to the stricter verify-strict default."""
    raw = cli_mode if cli_mode else os.environ.get(DISPATCH_HUNT_MODE_ENV_VAR, "")
    mode = (raw or "").strip().lower()
    if mode in VALID_HUNT_MODES:
        return mode
    return HUNT_MODE_VERIFY_STRICT


def pack_source_read_mandate(mode: Optional[str] = None) -> str:
    """Return the source-read mandate text for the given hunt mode (E4.3 +
    E4.4). The R76 source-read requirement is present in BOTH modes; only the
    negative-default clause differs. Falls back to verify-strict on an
    unknown / None mode."""
    resolved = resolve_hunt_mode(mode)
    if resolved == HUNT_MODE_GENERATE_BROAD:
        return _PACK_SOURCE_READ_MANDATE_PREFIX + _PACK_NEG_DEFAULT_GENERATE_BROAD
    return _PACK_SOURCE_READ_MANDATE_PREFIX + _PACK_NEG_DEFAULT_VERIFY_STRICT


# Backward-compatible module-level alias (verify-strict default). Existing
# callers that reference the constant keep working; new call sites should call
# pack_source_read_mandate(mode) to honour the active hunt mode.
_PACK_SOURCE_READ_MANDATE = pack_source_read_mandate(HUNT_MODE_VERIFY_STRICT)


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def infer_lane_type(prompt_text: str) -> str:
    """Infer lane_type from prompt body via keyword scan."""
    lower = (prompt_text or "").lower()
    for lane, keywords in LANE_KEYWORD_RULES:
        for kw in keywords:
            if kw in lower:
                return lane
    return "filing"  # safe default


def infer_severity(prompt_text: str) -> str:
    """Infer severity from prompt body via keyword scan. Default HIGH."""
    lower = (prompt_text or "").lower()
    for sev, keywords in SEVERITY_KEYWORD_RULES:
        for kw in keywords:
            if kw in lower:
                return sev
    return "HIGH"  # safe default; matches vault_dispatch_brief_skeleton auto


def infer_workspace(
    prompt_text: str, cwd: Optional[pathlib.Path] = None
) -> Optional[pathlib.Path]:
    """Infer workspace_path. Priority:
    1. Explicit absolute path in prompt (/Users/wolf/audits/<name> or
       /Users/wolf/auditooor*).
    2. Named ``workspace audits/<name>`` shorthand.
    3. cwd if it sits under /Users/wolf/audits/.
    4. cwd if it equals the REPO root (auditooor-mcp self-hosted lane).
    Returns None on no match.
    """
    text = prompt_text or ""
    m = _WS_ABS_RE.search(text)
    if m:
        cand = pathlib.Path(m.group(1)).expanduser()
        if cand.exists() and cand.is_dir():
            return cand.resolve()
    m2 = _WS_NAMED_RE.search(text)
    if m2:
        cand = KNOWN_WORKSPACES_ROOT / m2.group(1)
        if cand.exists() and cand.is_dir():
            return cand.resolve()
    # cwd fallback
    if cwd is None:
        try:
            cwd = pathlib.Path(os.getcwd()).resolve()
        except (OSError, ValueError):
            cwd = None
    if cwd:
        for ancestor in [cwd, *cwd.parents]:
            if ancestor == KNOWN_WORKSPACES_ROOT:
                break
            if ancestor.parent == KNOWN_WORKSPACES_ROOT and ancestor.exists():
                return ancestor
        try:
            git_root = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=str(cwd),
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            git_root = None
        if git_root is not None and git_root.returncode == 0:
            candidate = pathlib.Path(git_root.stdout.strip()).expanduser()
            if candidate.exists() and candidate.is_dir():
                return candidate.resolve()
        return cwd
    return None


# ---------------------------------------------------------------------------
# MCP call wrapper
# ---------------------------------------------------------------------------

def call_vault_dispatch_brief_skeleton(
    lane_type: str,
    severity: str,
    workspace_path: Optional[pathlib.Path],
    target_finding_class: str = "",
    timeout: int = 45,
    server_path: Optional[pathlib.Path] = None,
) -> Optional[Dict[str, Any]]:
    """Call vault_dispatch_brief_skeleton via the local MCP server CLI."""
    server = server_path or (REPO / "tools" / "vault-mcp-server.py")
    if not server.is_file():
        print(
            f"[dispatch-agent-with-prebriefing] WARN: server tool not found "
            f"at {server}",
            file=sys.stderr,
        )
        return None
    args: Dict[str, Any] = {
        "lane_type": lane_type,
        "severity": severity,
    }
    if workspace_path is not None:
        args["workspace_path"] = str(workspace_path)
    if target_finding_class:
        args["target_finding_class"] = target_finding_class
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(server),
                "--call",
                "vault_dispatch_brief_skeleton",
                "--args",
                json.dumps(args, sort_keys=True),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(
            "[dispatch-agent-with-prebriefing] WARN: skeleton call timed out",
            file=sys.stderr,
        )
        return None
    except Exception as exc:  # noqa: BLE001
        print(
            f"[dispatch-agent-with-prebriefing] WARN: skeleton subprocess "
            f"failed: {exc!r}",
            file=sys.stderr,
        )
        return None
    if proc.returncode != 0:
        print(
            f"[dispatch-agent-with-prebriefing] WARN: skeleton rc="
            f"{proc.returncode}; stderr head: "
            f"{(proc.stderr or '').splitlines()[:1]}",
            file=sys.stderr,
        )
        return None
    out = (proc.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return None


def _json_from_helper_stdout(stdout: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from helper stdout, tolerating banner lines."""
    out = (stdout or "").strip()
    if not out:
        return None
    try:
        parsed = json.loads(out)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    lines = out.splitlines()
    for start in range(len(lines)):
        candidate = "\n".join(lines[start:]).strip()
        if not candidate.startswith("{"):
            continue
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            continue
    return None


def call_local_mcp_tool(
    tool_name: str,
    args: Dict[str, Any],
    *,
    timeout: int = 45,
    server_path: Optional[pathlib.Path] = None,
) -> Optional[Dict[str, Any]]:
    """Call a local MCP server tool via the repo CLI helper."""
    server = server_path or (REPO / "tools" / "vault-mcp-server.py")
    if not server.is_file():
        return None
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(server),
                "--call",
                tool_name,
                "--args",
                json.dumps(args, sort_keys=True),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    return _json_from_helper_stdout(proc.stdout)


def call_antipattern_catalog_helper(
    *,
    limit: int = 5,
    timeout: int = 30,
    tool_path: Optional[pathlib.Path] = None,
) -> Optional[Dict[str, Any]]:
    """Read the P3 v2 anti-pattern catalog through its local CLI helper."""
    tool = tool_path or (REPO / "tools" / "antipattern-catalog-build.py")
    if not tool.is_file():
        return None
    try:
        proc = subprocess.run(
            [sys.executable, str(tool), "--list", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    payload = _json_from_helper_stdout(proc.stdout)
    if not isinstance(payload, dict):
        return None
    patterns = list(payload.get("patterns") or [])
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    patterns.sort(
        key=lambda p: (
            severity_rank.get(str(p.get("severity_ceiling") or "").lower(), 9),
            float(p.get("fpr_estimate") or 1.0),
            str(p.get("pattern_id") or ""),
        )
    )
    top = patterns[: max(1, min(limit, 20))]
    pack_body = {
        "schema": str(payload.get("schema_version") or ""),
        "pattern_count": payload.get("pattern_count"),
        "top_pattern_ids": [str(p.get("pattern_id") or "") for p in top],
    }
    digest = hashlib.sha256(
        json.dumps(pack_body, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "schema": "auditooor.antipattern_catalog.v1",
        "context_pack_id": f"auditooor.antipattern_catalog.v1:{digest[:16]}",
        "context_pack_hash": digest,
        "pattern_count": payload.get("pattern_count"),
        "patterns": top,
    }


def _live_target_report_staleness(
    workspace_path: Optional[pathlib.Path],
    *,
    now: Optional[_dt.datetime] = None,
) -> Dict[str, Any]:
    """Return LIVE_TARGET_REPORT.md freshness metadata for prebriefing."""
    if workspace_path is None:
        return {
            "status": "not_checked",
            "warning": "LIVE_TARGET_REPORT.md staleness not checked: no workspace.",
        }
    report_path = workspace_path / "docs" / "LIVE_TARGET_REPORT.md"
    if not report_path.is_file():
        return {
            "status": "missing",
            "path": str(report_path),
            "warning": f"LIVE_TARGET_REPORT.md missing at {report_path}.",
        }
    try:
        mtime = _dt.datetime.fromtimestamp(
            report_path.stat().st_mtime, tz=_dt.timezone.utc
        )
    except OSError:
        return {
            "status": "stat_failed",
            "path": str(report_path),
            "warning": f"LIVE_TARGET_REPORT.md could not be stat'ed at {report_path}.",
        }
    ref_now = now or _dt.datetime.now(_dt.timezone.utc)
    if ref_now.tzinfo is None:
        ref_now = ref_now.replace(tzinfo=_dt.timezone.utc)
    age = max(0.0, (ref_now - mtime).total_seconds())
    age_hours = age / 3600.0
    status = "stale" if age_hours > 24.0 else "fresh"
    warning = ""
    if status == "stale":
        warning = (
            "LIVE_TARGET_REPORT.md is stale "
            f"({age_hours:.1f}h old; threshold 24h) at {report_path}."
        )
    return {
        "status": status,
        "path": str(report_path),
        "mtime_utc": mtime.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "age_hours": round(age_hours, 1),
        "warning": warning,
    }


def infer_invariant_category_hint(*parts: str) -> str:
    """Best-effort P1 category hint for vault_invariant_library filtering."""
    text = " ".join(p for p in parts if p).lower()
    if not text:
        return ""
    category_keywords = (
        ("authorization", ("authorization", "authorisation", "access control", "privilege", "permission")),
        ("atomicity", ("reentrancy", "callback", "partial commit", "atomic", "check-effects")),
        ("uniqueness", ("replay", "nonce", "signature", "duplicate", "unique", "eip-712", "permit")),
        ("freshness", ("stale", "oracle", "finality", "timestamp", "deadline", "expiry")),
        ("custody", ("custody", "locked value", "escrow", "withdraw", "deposit", "funds")),
        ("conservation", ("conservation", "balance", "reserve", "supply", "accounting", "solvency")),
        ("bounds", ("bound", "overflow", "underflow", "cap", "limit", "range", "size")),
        ("ordering", ("order", "sequence", "front-run", "frontrun", "priority")),
        ("monotonicity", ("monotonic", "decrease", "increase", "share price")),
        ("determinism", ("determinism", "canonical", "nondeterministic", "non-deterministic")),
    )
    for category, keywords in category_keywords:
        if any(keyword in text for keyword in keywords):
            return category
    return ""


def build_phase_a_pillar_context(
    *,
    workspace_path: Optional[pathlib.Path],
    query_text: str = "",
    target_finding_class: str = "",
    invariant_caller=None,
    antipattern_caller=None,
    live_target_caller=None,
    now: Optional[_dt.datetime] = None,
) -> Dict[str, Any]:
    """Fetch P1/P3/P5 Phase A context using local callable-style helpers."""
    workspace_arg = str(workspace_path) if workspace_path else ""

    inv_caller = invariant_caller or (
        lambda **kwargs: call_local_mcp_tool("vault_invariant_library", kwargs)
    )
    anti_caller = antipattern_caller or call_antipattern_catalog_helper
    live_caller = live_target_caller or (
        lambda **kwargs: call_local_mcp_tool("vault_live_target_report", kwargs)
    )

    invariant_args: Dict[str, Any] = {
        "workspace_path": workspace_arg,
        "quality_mode": "audited_primary",
        "limit": 5,
    }
    category_hint = infer_invariant_category_hint(query_text, target_finding_class)
    if category_hint:
        invariant_args["category"] = category_hint
    p1 = inv_caller(**invariant_args)
    # Coverage-preserving fallback: if audited-primary returns no rows, retry
    # once in breadth mode so workers still receive category context.
    if (
        isinstance(p1, dict)
        and not p1.get("degraded")
        and not (p1.get("invariants") or [])
    ):
        fallback_args = dict(invariant_args)
        fallback_args["quality_mode"] = "breadth"
        p1_fallback = inv_caller(**fallback_args)
        if isinstance(p1_fallback, dict):
            p1 = p1_fallback
    if not isinstance(p1, dict):
        p1 = {"degraded": True, "reason": "vault_invariant_library unavailable"}

    p3 = anti_caller(limit=5)
    if not isinstance(p3, dict):
        p3 = {"degraded": True, "reason": "anti-pattern catalog unavailable"}

    if workspace_path is not None:
        p5 = live_caller(
            workspace_path=workspace_arg,
            limit=5,
            min_priority="MEDIUM-PRIORITY",
        )
        if not isinstance(p5, dict):
            p5 = {"degraded": True, "reason": "vault_live_target_report unavailable"}
    else:
        p5 = {
            "degraded": True,
            "reason": "workspace_path required for vault_live_target_report",
            "entry_points": [],
        }

    staleness = _live_target_report_staleness(workspace_path, now=now)

    return {
        "schema": "auditooor.dispatch_phase_a_pillar_context.v1",
        "p1": p1,
        "p3": p3,
        "p5": p5,
        "live_target_staleness": staleness,
    }


# ---------------------------------------------------------------------------
# Skeleton -> Section 15a/15b/15c/15d markdown formatter
# ---------------------------------------------------------------------------

_OOS_PREFLIGHT_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "dispute",
    "escalation",
    "mediation",
    "opposed-trace-harness",
    "triager-response",
    "rebuttal",
    "filing",
}


def build_oos_preflight_context(
    *,
    workspace_path: Optional[pathlib.Path],
    prompt_text: str,
    lane_type: str,
    severity: str,
) -> Optional[Dict[str, Any]]:
    """Build CAP-GAP-93 pre-drill OOS context for dispatch prompts."""
    if (lane_type or "").strip().lower() not in _OOS_PREFLIGHT_LANE_TYPES:
        return None
    if workspace_path is None or _dispatch_oos_evaluate is None:
        return {
            "schema": "auditooor.dispatch_oos_preflight.v1",
            "verdict": "not-run",
            "reason": "workspace path or dispatch_oos_preflight.py unavailable",
            "matches": [],
            "existing_poc_hits": [],
            "dryruns": {},
            "original_severity": severity,
            "recommended_severity": "UNCHANGED",
        }
    candidate = {
        "id": f"prebrief:{lane_type}",
        "severity": severity,
        "candidate_text": prompt_text,
        "hypothesis": prompt_text,
    }
    try:
        result = _dispatch_oos_evaluate(workspace_path, candidate)
    except Exception as exc:  # noqa: BLE001
        return {
            "schema": "auditooor.dispatch_oos_preflight.v1",
            "verdict": "error",
            "reason": repr(exc),
            "matches": [],
            "existing_poc_hits": [],
            "dryruns": {},
            "original_severity": severity,
            "recommended_severity": "UNCHANGED",
        }
    if isinstance(result, dict):
        result.update(_oos_index_metadata(workspace_path))
    return result


def _oos_index_metadata(workspace_path: pathlib.Path) -> Dict[str, Any]:
    """Return M1-4a bug-bounty OOS index metadata for Section 15l."""
    path = workspace_path / ".auditooor" / "bug_bounty_oos_index.json"
    meta: Dict[str, Any] = {
        "oos_index_path": str(path),
        "oos_index_present": path.is_file(),
        "oos_index_row_count": 0,
    }
    if not path.is_file():
        return meta
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        meta["oos_index_parse_error"] = True
        return meta
    rows: Any = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = (
            payload.get("clauses")
            or payload.get("rows")
            or payload.get("items")
            or payload.get("entries")
            or payload.get("oos_clauses")
            or []
        )
    if isinstance(rows, list):
        meta["oos_index_row_count"] = len(rows)
    return meta


def _format_oos_preflight_section(oos_preflight: Optional[Dict[str, Any]]) -> List[str]:
    """Render Section 15l for CAP-GAP-93."""
    if not isinstance(oos_preflight, dict):
        return []
    lines: List[str] = [
        "## Section 15l - Mandatory Brief-Time OOS / AI-FP / Known-Issue Preflight (CAP-GAP-93)",
        "",
        (
            "_Mandatory gate: resolve this section before source drilling. If it surfaces a "
            "BUG_BOUNTY.md / SEVERITY.md / SCOPE.md / prior-audit clause, "
            "the worker must either stop as OOS or prove an extension-distinct "
            "argument with file:line or PoC evidence._"
        ),
        "",
        (
            f"- M1-4a OOS index: `{oos_preflight.get('oos_index_path', '')}` "
            f"present=`{bool(oos_preflight.get('oos_index_present'))}` "
            f"rows=`{oos_preflight.get('oos_index_row_count', 0)}`"
        ),
        "",
    ]
    if _dispatch_oos_render is None:
        lines.append("_(dispatch_oos_preflight.py renderer unavailable)_")
        lines.append("")
        return lines
    rendered = _dispatch_oos_render(oos_preflight)
    # Avoid nested top-level heading noise inside Section 15l.
    rendered_lines = rendered.splitlines()
    if rendered_lines and rendered_lines[0].startswith("## Brief-Time"):
        rendered_lines = rendered_lines[2:]
    lines.extend(rendered_lines)
    lines.append("")
    return lines


_BRIEF_STOPWORDS = {
    "about",
    "after",
    "again",
    "against",
    "audit",
    "brief",
    "build",
    "candidate",
    "context",
    "drill",
    "finding",
    "from",
    "high",
    "lane",
    "medium",
    "path",
    "proof",
    "prove",
    "source",
    "task",
    "test",
    "this",
    "with",
    "work",
    "worker",
}


def _brief_tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[A-Za-z0-9_]{3,}", (text or "").lower())
        if token not in _BRIEF_STOPWORDS
    }


def _read_json_object(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _row_text(row: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in (
        "lead_id",
        "id",
        "title",
        "attack_class",
        "root_cause_hypothesis",
        "impact_probe",
        "description",
        "recommended_next_step",
        "likely_triager_objection",
    ):
        value = row.get(key)
        if value:
            parts.append(str(value))
    for key in ("blockers", "kill_conditions", "preconditions", "postconditions"):
        value = row.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value[:6])
    return " ".join(parts)


def _normalise_exploit_queue_row(row: Dict[str, Any], score: int) -> Dict[str, Any]:
    return {
        "lead_id": str(row.get("lead_id") or row.get("id") or "")[:48],
        "attack_class": str(row.get("attack_class") or "")[:80],
        "likely_severity": str(row.get("likely_severity") or row.get("severity") or "")[:24],
        "proof_status": str(row.get("proof_status") or "")[:48],
        "quality_gate_status": str(row.get("quality_gate_status") or "")[:48],
        "impact_contract_status": str(row.get("impact_contract_status") or "")[:48],
        "dupe_risk": str(row.get("dupe_risk") or "unknown")[:40],
        "learning_route": str(row.get("learning_route") or "")[:60],
        "priority_score": row.get("priority_score", ""),
        "match_score": score,
        "root_cause_hypothesis": str(row.get("root_cause_hypothesis") or row.get("title") or "")[:220],
        "next_command": str(row.get("next_command") or "")[:220],
        "blockers": [str(item)[:120] for item in (row.get("blockers") or [])[:4]],
        "kill_conditions": [
            str(item)[:120] for item in (row.get("kill_conditions") or [])[:3]
        ],
    }


def _normalise_ccia_angle(row: Dict[str, Any], score: int) -> Dict[str, Any]:
    contracts = row.get("contracts") if isinstance(row.get("contracts"), list) else []
    return {
        "id": str(row.get("id") or row.get("angle_id") or "")[:48],
        "severity": str(row.get("severity") or "")[:24],
        "title": str(row.get("title") or row.get("description") or "")[:180],
        "contracts": [str(item)[:80] for item in contracts[:4]],
        "line": row.get("line", ""),
        "match_score": score,
    }


def build_exploit_queue_prior_context(
    *,
    workspace_path: Optional[pathlib.Path],
    prompt_text: str,
    limit: int = 5,
) -> Dict[str, Any]:
    """Read workspace exploit-queue and CCIA attack-angle artifacts."""
    context: Dict[str, Any] = {
        "schema": "auditooor.dispatch_prebrief_exploit_queue_prior.v1",
        "workspace_path": str(workspace_path) if workspace_path else "",
        "degraded": False,
        "exploit_queue_path": "",
        "exploit_queue_present": False,
        "exploit_queue_total_rows": 0,
        "exploit_queue_matches": [],
        "ccia_attack_angles_path": "",
        "ccia_attack_angles_present": False,
        "ccia_attack_angles_total_rows": 0,
        "ccia_attack_angle_matches": [],
    }
    if workspace_path is None:
        context["degraded"] = True
        context["degraded_reason"] = "workspace_path_required"
        return context

    auditooor_dir = workspace_path / ".auditooor"
    queue_path = auditooor_dir / "exploit_queue.json"
    ccia_path = auditooor_dir / "ccia_attack_angles.json"
    context["exploit_queue_path"] = str(queue_path)
    context["ccia_attack_angles_path"] = str(ccia_path)
    prompt_terms = _brief_tokens(prompt_text)

    queue_payload = _read_json_object(queue_path)
    queue_rows: List[Dict[str, Any]] = []
    if isinstance(queue_payload, list):
        queue_rows = [row for row in queue_payload if isinstance(row, dict)]
    elif isinstance(queue_payload, dict):
        rows = queue_payload.get("queue") or queue_payload.get("rows") or []
        if isinstance(rows, list):
            queue_rows = [row for row in rows if isinstance(row, dict)]
    context["exploit_queue_present"] = queue_path.is_file()
    context["exploit_queue_total_rows"] = len(queue_rows)
    scored_queue: List[Tuple[int, int, Dict[str, Any]]] = []
    for idx, row in enumerate(queue_rows):
        score = len(prompt_terms & _brief_tokens(_row_text(row)))
        scored_queue.append((score, idx, row))
    scored_queue.sort(key=lambda item: (-item[0], item[1]))
    context["exploit_queue_matches"] = [
        _normalise_exploit_queue_row(row, score)
        for score, _idx, row in scored_queue[: max(1, limit)]
    ]

    ccia_payload = _read_json_object(ccia_path)
    ccia_rows: List[Dict[str, Any]] = []
    if isinstance(ccia_payload, list):
        ccia_rows = [row for row in ccia_payload if isinstance(row, dict)]
    elif isinstance(ccia_payload, dict):
        rows = ccia_payload.get("attack_angles") or ccia_payload.get("rows") or []
        if isinstance(rows, list):
            ccia_rows = [row for row in rows if isinstance(row, dict)]
    context["ccia_attack_angles_present"] = ccia_path.is_file()
    context["ccia_attack_angles_total_rows"] = len(ccia_rows)
    scored_ccia: List[Tuple[int, int, Dict[str, Any]]] = []
    for idx, row in enumerate(ccia_rows):
        score = len(prompt_terms & _brief_tokens(_row_text(row)))
        scored_ccia.append((score, idx, row))
    scored_ccia.sort(key=lambda item: (-item[0], item[1]))
    context["ccia_attack_angle_matches"] = [
        _normalise_ccia_angle(row, score)
        for score, _idx, row in scored_ccia[: max(1, min(limit, 3))]
    ]
    return context


def _format_exploit_queue_prior_section(context: Optional[Dict[str, Any]]) -> List[str]:
    """Render Section 15m for workspace exploit-queue prior verdicts."""
    if not isinstance(context, dict):
        return []
    lines: List[str] = [
        "## Section 15m - Workspace exploit-queue prior verdicts",
        "",
        (
            "_Read before source drilling. Treat these as prior lane verdicts, "
            "blockers, kill conditions, and proof-status hints. Do not re-prove "
            "a lane that the queue or CCIA angle already falsified without a "
            "new trigger-state change._"
        ),
        "",
        (
            f"- Exploit queue: `{context.get('exploit_queue_path', '')}` "
            f"present=`{bool(context.get('exploit_queue_present'))}` "
            f"rows=`{context.get('exploit_queue_total_rows', 0)}`"
        ),
        (
            f"- CCIA attack angles: `{context.get('ccia_attack_angles_path', '')}` "
            f"present=`{bool(context.get('ccia_attack_angles_present'))}` "
            f"rows=`{context.get('ccia_attack_angles_total_rows', 0)}`"
        ),
        "",
    ]
    rows = context.get("exploit_queue_matches")
    if isinstance(rows, list) and rows:
        lines.append("### Exploit-queue matches")
        lines.append("")
        lines.append(
            "| Lead | Class | Severity | Proof status | Gate | Dupe | Match | Next |"
        )
        lines.append("|---|---|---|---|---|---|---:|---|")
        for row in rows[:5]:
            if not isinstance(row, dict):
                continue
            next_cmd = str(row.get("next_command") or "").replace("|", "\\|")
            lines.append(
                f"| `{row.get('lead_id', '')}` | `{row.get('attack_class', '')}` | "
                f"`{row.get('likely_severity', '')}` | `{row.get('proof_status', '')}` | "
                f"`{row.get('quality_gate_status', '')}` | `{row.get('dupe_risk', '')}` | "
                f"{row.get('match_score', 0)} | {next_cmd[:180]} |"
            )
        lines.append("")
        for row in rows[:3]:
            if not isinstance(row, dict):
                continue
            blockers = row.get("blockers") if isinstance(row.get("blockers"), list) else []
            kills = (
                row.get("kill_conditions")
                if isinstance(row.get("kill_conditions"), list)
                else []
            )
            if blockers or kills:
                lead = row.get("lead_id", "")
                lines.append(f"- `{lead}` blockers: {', '.join(blockers) or 'none'}")
                lines.append(f"- `{lead}` kill conditions: {', '.join(kills) or 'none'}")
        lines.append("")
    else:
        lines.append("_No exploit-queue rows available._")
        lines.append("")

    angles = context.get("ccia_attack_angle_matches")
    if isinstance(angles, list) and angles:
        lines.append("### CCIA attack-angle matches")
        lines.append("")
        lines.append("| ID | Severity | Title | Contracts | Line | Match |")
        lines.append("|---|---|---|---|---:|---:|")
        for row in angles[:3]:
            if not isinstance(row, dict):
                continue
            title = str(row.get("title") or "").replace("|", "\\|")
            contracts = ", ".join(str(item) for item in (row.get("contracts") or []))
            lines.append(
                f"| `{row.get('id', '')}` | `{row.get('severity', '')}` | "
                f"{title[:160]} | {contracts} | {row.get('line', '')} | "
                f"{row.get('match_score', 0)} |"
            )
        lines.append("")
    else:
        lines.append("_No CCIA attack-angle rows available._")
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Defense Surface (Section 15r) + Full-Audit Results (Section 15s)
#
# Hunt/drill briefs need two things the prior context blocks do not supply:
#   (1) the PRESENT guards/modifiers in the target tree the attacker must
#       traverse or bypass (R57 exhaustive-defense-chain input), and
#   (2) the AUDIT-RESULT artifacts the pipeline already produced (engage_report
#       detector clusters, deep-engine counterexamples, exploit_queue summary)
#       so the hunt does not re-walk already-hot regions blindly.
# Both are gated to hunt-class lanes only and omit gracefully when absent.
# r36-rebuttal: lane PR-DEFENSE-AUDIT-CONTEXT registered in
# .auditooor/agent_pathspec.json agents[].
# ---------------------------------------------------------------------------

# Hunt-class lane types these two sections fire on. Mirrors the
# hunt-brief-completeness gate set so defense-surface / full-audit-results
# land on exactly the hunt-class briefs the completeness gate checks.
DEFENSE_AUDIT_CONTEXT_LANE_TYPES = frozenset(
    {"hunt", "drill", "comp", "fuzz", "opposed-trace-harness", "escalation"}
)

# Per-language present-guard grep patterns. Each entry: a precompiled regex
# applied line-by-line to in-scope source. Keep the union small + cheap.
_DEFENSE_GUARD_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    (
        "evm",
        re.compile(
            r"\b(?:modifier\s+\w+|nonReentrant|onlyOwner|onlyRole|whenNotPaused|"
            r"_requireCallerIs|_checkRole|AccessControl|onlyAdmin|onlyOperator|"
            r"onlyOracle|onlyNotFlagged|require\s*\(|revert\b)"
        ),
    ),
    (
        "rust",
        re.compile(
            # Intentionally narrow: real authorization / validation guards only.
            # Excluded from this pattern:
            #   assert! / assert_eq! - test / panic macros, not access control
            #   unwrap_or_else       - error-propagation idiom, not a guard
            #   .ok_or / .ok_or_else - Result conversion, not a guard
            # Kept: substrate ensure!/require! (pallet dispatch guards),
            #   ensure_signed/ensure_root (origin checks), #[access_control]
            #   attribute, require_keys_eq (Anchor CPI signer check),
            #   SignedExtension (Substrate signed-extension trait),
            #   .verify( (signature or proof verification call),
            #   AccessControl (OpenZeppelin-style role trait name in Rust/Ink).
            r"\b(?:ensure!|require!|ensure_signed|ensure_root|"
            r"#\[access_control\]|require_keys_eq|SignedExtension|"
            r"AccessControl)"
            r"|\.verify\s*\("
        ),
    ),
    (
        "go",
        re.compile(
            r"\b(?:ValidateBasicDecorator|SigVerificationDecorator|"
            r"ValidateNestedMsg|RejectExtensionOptions|AnteHandler|"
            r"authz\.|govtypes\.|\.ValidateBasic\()"
        ),
    ),
)

# Source-file extensions per language family (for the in-scope walk).
_DEFENSE_SOURCE_EXTS = {
    ".sol": "evm",
    ".vy": "evm",
    ".rs": "rust",
    ".go": "go",
}

# Directory names excluded from the present-guard grep (tests / deps / build).
_DEFENSE_EXCLUDE_DIRS = frozenset(
    {
        "lib",
        "test",
        "tests",
        "node_modules",
        "target",
        "vendor",
        "out",
        "cache",
        ".git",
        "mock",
        "mocks",
        "fixtures",
        "testdata",
        "examples",
        # Rust-specific noise sources: benchmarks, fuzz harnesses, arbitrary impls.
        "benches",
        "bench",
        "fuzz",
        "arbitrary",
    }
)

# Rust file-name suffixes (after stripping .rs) that are always noise.
_DEFENSE_EXCLUDE_RUST_STEMS = frozenset({"test", "tests", "arbitrary", "bench", "benches"})

# Candidate in-scope source roots to walk, in priority order.
_DEFENSE_SOURCE_ROOTS = ("src", "contracts", "pallets", "x", "modules", "crates")


def build_defense_surface_context(
    *,
    workspace_path: Optional[pathlib.Path],
    lane_type: str,
    max_guards: int = 20,
    max_files_scanned: int = 400,
) -> Optional[Dict[str, Any]]:
    """Grep the in-scope source tree for PRESENT guards/modifiers.

    Cheap line-by-line scan of the workspace source root(s). Returns the
    guard inventory (file:line + guard name) the hunt agent must traverse
    or bypass, plus the R57 protection-module directory roots and the
    engage_report MISSING-guard detector hits (the inverse signal).

    Returns None for non-hunt-class lanes. Returns a degraded context
    (with ``degraded=True``) when the workspace or source tree is absent
    so the formatter can omit gracefully.
    """
    if (lane_type or "").strip().lower() not in DEFENSE_AUDIT_CONTEXT_LANE_TYPES:
        return None
    context: Dict[str, Any] = {
        "schema": "auditooor.dispatch_prebrief_defense_surface.v1",
        "workspace_path": str(workspace_path) if workspace_path else "",
        "degraded": False,
        "language": "unknown",
        "source_roots": [],
        "guards": [],
        "guard_total": 0,
        "protection_module_dirs": [],
        "missing_guard_signals": [],
        "files_scanned": 0,
    }
    if workspace_path is None or not workspace_path.is_dir():
        context["degraded"] = True
        context["degraded_reason"] = "workspace_path_absent"
        return context

    # Resolve which source roots actually exist.
    roots: List[pathlib.Path] = []
    for name in _DEFENSE_SOURCE_ROOTS:
        cand = workspace_path / name
        if cand.is_dir():
            roots.append(cand)
    if not roots:
        # Fall back to the workspace root itself (shallow walk).
        roots = [workspace_path]
    context["source_roots"] = [str(r) for r in roots]

    guards: List[Dict[str, Any]] = []
    protection_dirs: set[str] = set()
    files_scanned = 0
    languages_seen: Dict[str, int] = {}
    done = False
    for root in roots:
        if done:
            break
        for path in sorted(root.rglob("*")):
            if files_scanned >= max_files_scanned or len(guards) >= max_guards:
                done = True
                break
            if not path.is_file():
                continue
            lang = _DEFENSE_SOURCE_EXTS.get(path.suffix.lower())
            if lang is None:
                continue
            rel_parts = {p.lower() for p in path.parts}
            if rel_parts & _DEFENSE_EXCLUDE_DIRS:
                continue
            # Skip Rust test/bench/arbitrary files by stem (e.g. foo_test.rs,
            # arbitrary.rs) even when they don't live under an excluded dir.
            if lang == "rust":
                stem = path.stem.lower()
                if stem in _DEFENSE_EXCLUDE_RUST_STEMS or stem.endswith("_test"):
                    continue
            pattern = None
            for name, pat in _DEFENSE_GUARD_PATTERNS:
                if name == lang:
                    pattern = pat
                    break
            if pattern is None:
                continue
            files_scanned += 1
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            languages_seen[lang] = languages_seen.get(lang, 0) + 1
            for lineno, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("//", "#", "*")):
                    continue
                m = pattern.search(line)
                if not m:
                    continue
                try:
                    rel = path.relative_to(workspace_path)
                except ValueError:
                    rel = path
                guards.append(
                    {
                        "file_line": f"{rel}:{lineno}",
                        "guard": m.group(0).strip()[:48],
                        "snippet": stripped[:90],
                    }
                )
                protection_dirs.add(str(path.parent.relative_to(workspace_path))
                                    if _is_under(path.parent, workspace_path)
                                    else str(path.parent))
                if len(guards) >= max_guards:
                    done = True
                    break

    context["files_scanned"] = files_scanned
    context["guards"] = guards
    context["guard_total"] = len(guards)
    context["protection_module_dirs"] = sorted(protection_dirs)[:12]
    if languages_seen:
        context["language"] = max(languages_seen, key=languages_seen.get)

    # Surface engage_report MISSING-guard detector hits (the inverse signal).
    context["missing_guard_signals"] = _read_missing_guard_signals(workspace_path)

    if not guards and not context["missing_guard_signals"]:
        context["degraded"] = True
        context.setdefault("degraded_reason", "no_guards_or_missing_signals_found")
    return context


def _is_under(child: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


# detector-slug substrings that denote a MISSING-guard signal (attack surface).
_MISSING_GUARD_SLUG_HINTS = (
    "guard_missing",
    "missing_guard",
    "missing_slippage",
    "missing_access",
    "missing_check",
    "missing_validation",
    "guard_only",
    "_unchecked",
)


def _read_missing_guard_signals(
    workspace_path: pathlib.Path, limit: int = 6
) -> List[Dict[str, Any]]:
    """Parse engage_report.md for MISSING-guard detector clusters."""
    report = workspace_path / "engage_report.md"
    if not report.is_file():
        return []
    try:
        text = report.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    signals: List[Dict[str, Any]] = []
    cluster_re = re.compile(r"^###\s+Cluster:\s+`(.+?)`\s+\((\d+)\s+hits\)")
    hit_re = re.compile(r"\*\*\[(\w+)\]\s+`.+?`\*\*\s+--\s+`(.+?)`")
    current: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        cm = cluster_re.match(line.strip())
        if cm:
            slug = cm.group(1)
            if any(h in slug.lower() for h in _MISSING_GUARD_SLUG_HINTS):
                current = {
                    "detector": slug,
                    "hits": int(cm.group(2)),
                    "file_line": "",
                    "severity": "",
                }
                signals.append(current)
            else:
                current = None
            continue
        if current is not None and not current["file_line"]:
            hm = hit_re.search(line)
            if hm:
                current["severity"] = hm.group(1)
                current["file_line"] = hm.group(2)
    return signals[:limit]


def _format_defense_surface_section(
    context: Optional[Dict[str, Any]],
) -> List[str]:
    """Render Section 15r - present guards the attacker must traverse/bypass."""
    if not isinstance(context, dict):
        return []
    if context.get("degraded") and not context.get("guards") and not context.get(
        "missing_guard_signals"
    ):
        return []
    lines: List[str] = [
        "## Section 15r - Defense Surface (traverse/bypass these)",
        "",
        (
            "_Present guards/modifiers in the audit-pin tree. These are the "
            "defense-in-depth layers an attack must traverse or bypass. Use as "
            "R57 (exhaustive-defense-chain-enumeration) input: enumerate every "
            "one in the attack scenario and rule each in or out with a "
            "source-cited reason._"
        ),
        "",
        (
            f"- Target language: `{context.get('language', 'unknown')}` "
            f"- files scanned: `{context.get('files_scanned', 0)}` "
            f"- guards found: `{context.get('guard_total', 0)}`"
        ),
        "",
    ]
    guards = context.get("guards")
    if isinstance(guards, list) and guards:
        lines.append("| file:line | guard / modifier | snippet |")
        lines.append("|---|---|---|")
        for g in guards[:20]:
            if not isinstance(g, dict):
                continue
            snip = str(g.get("snippet", "")).replace("|", "\\|")
            lines.append(
                f"| `{g.get('file_line', '')}` | `{g.get('guard', '')}` | "
                f"{snip[:80]} |"
            )
        lines.append("")
    else:
        lines.append("_No present guards extracted from in-scope source._")
        lines.append("")

    pdirs = context.get("protection_module_dirs")
    if isinstance(pdirs, list) and pdirs:
        lines.append(
            "**R57 protection-module dirs** (for "
            "exhaustive-defense-chain-enumeration-check):"
        )
        for d in pdirs[:8]:
            lines.append(f"- `{d}`")
        lines.append("")

    missing = context.get("missing_guard_signals")
    if isinstance(missing, list) and missing:
        lines.append(
            "**MISSING-guard signals** (engage_report - attack surface, NOT "
            "present-guard inventory):"
        )
        for sig in missing[:6]:
            if not isinstance(sig, dict):
                continue
            lines.append(
                f"- `{sig.get('detector', '')}` "
                f"[{sig.get('severity', '?')}] "
                f"`{sig.get('file_line', '')}` ({sig.get('hits', 0)} hits)"
            )
        lines.append("")
    return lines


def build_audit_results_context(
    *,
    workspace_path: Optional[pathlib.Path],
    lane_type: str,
    top_n_clusters: int = 5,
) -> Optional[Dict[str, Any]]:
    """Read the AUDIT-RESULT artifacts the pipeline already produced.

    Sources (all optional, skipped if absent):
      - ``engage_report.md`` -> header stats + top-N detector clusters
      - ``.auditooor/deep-engine-findings/findings.json`` -> counterexamples
      - ``.auditooor/exploit_queue.json`` -> benchmark summary + top entries
      - ``.auditooor/audit_run_full_manifest.jsonl`` -> failed pipeline stages

    Returns None for non-hunt-class lanes; degraded context when no artifact
    is present so the formatter can omit gracefully.
    """
    if (lane_type or "").strip().lower() not in DEFENSE_AUDIT_CONTEXT_LANE_TYPES:
        return None
    context: Dict[str, Any] = {
        "schema": "auditooor.dispatch_prebrief_audit_results.v1",
        "workspace_path": str(workspace_path) if workspace_path else "",
        "degraded": False,
        "engage_header": {},
        "clusters": [],
        "deep_engine": {},
        "exploit_queue_benchmark": {},
        "exploit_queue_top": [],
        "failed_stages": [],
    }
    if workspace_path is None or not workspace_path.is_dir():
        context["degraded"] = True
        context["degraded_reason"] = "workspace_path_absent"
        return context

    auditooor_dir = workspace_path / ".auditooor"

    # (1) engage_report.md
    header, clusters = _parse_engage_report(
        workspace_path / "engage_report.md", top_n_clusters
    )
    context["engage_header"] = header
    context["clusters"] = clusters

    # (2) deep-engine-findings
    df_path = auditooor_dir / "deep-engine-findings" / "findings.json"
    df = _read_json_object(df_path)
    if isinstance(df, dict):
        per_engine = []
        for f in df.get("findings") or []:
            if not isinstance(f, dict):
                continue
            per_engine.append(
                {
                    "engine": str(f.get("engine", ""))[:24],
                    "verdict": str(f.get("verdict", ""))[:24],
                    "has_counterexample": bool(f.get("has_counterexample")),
                    "target_function": str(f.get("target_function") or "")[:80],
                    "input_sequence": [
                        str(s)[:80] for s in (f.get("input_sequence") or [])[:4]
                    ],
                    "tooling_failure_pattern": str(
                        f.get("tooling_failure_pattern") or ""
                    )[:48],
                }
            )
        context["deep_engine"] = {
            "present": True,
            "has_counterexample": bool(df.get("has_counterexample")),
            "counterexample_count": df.get("counterexample_count", 0),
            "tooling_failure_count": df.get("tooling_failure_count", 0),
            "engines": per_engine[:6],
        }

    # (3) exploit_queue benchmark + top entries
    eq = _read_json_object(auditooor_dir / "exploit_queue.json")
    if isinstance(eq, dict):
        bench = eq.get("benchmark")
        if isinstance(bench, dict):
            context["exploit_queue_benchmark"] = bench
        rows = eq.get("entries") or eq.get("queue") or eq.get("rows") or []
        if isinstance(rows, list):
            scored = [r for r in rows if isinstance(r, dict)]
            scored.sort(
                key=lambda r: _safe_float(r.get("priority_score")),
                reverse=True,
            )
            context["exploit_queue_top"] = [
                {
                    "title": str(r.get("title") or r.get("lead_id") or "")[:120],
                    "likely_severity": str(
                        r.get("likely_severity") or r.get("severity") or ""
                    )[:24],
                    "proof_status": str(r.get("proof_status") or "")[:32],
                    "source_ref": (
                        str((r.get("source_refs") or [""])[0])[:80]
                        if isinstance(r.get("source_refs"), list)
                        else str(r.get("source_refs") or "")[:80]
                    ),
                }
                for r in scored[:3]
            ]

    # (4) audit_run_full_manifest.jsonl -> failed stages
    context["failed_stages"] = _read_failed_stages(
        auditooor_dir / "audit_run_full_manifest.jsonl"
    )

    if (
        not context["clusters"]
        and not context["deep_engine"]
        and not context["exploit_queue_benchmark"]
        and not context["exploit_queue_top"]
        and not context["failed_stages"]
    ):
        context["degraded"] = True
        context.setdefault("degraded_reason", "no_audit_artifacts_present")
    return context


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("-inf")


def _parse_engage_report(
    report_path: pathlib.Path, top_n: int
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Parse engage_report.md header + top-N clusters by hit count."""
    header: Dict[str, Any] = {}
    clusters: List[Dict[str, Any]] = []
    if not report_path.is_file():
        return header, clusters
    try:
        text = report_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return header, clusters
    tot_re = re.compile(r"Total hits:\s*\**(\d+)")
    sev_re = re.compile(r"HIGH=(\d+)\s+MEDIUM=(\d+)\s+LOW=(\d+)")
    cluster_re = re.compile(r"^###\s+Cluster:\s+`(.+?)`\s+\((\d+)\s+hits\)")
    hit_re = re.compile(r"\*\*\[(\w+)\]\s+`.+?`\*\*\s+--\s+`(.+?)`")
    snip_re = re.compile(r"snippet:\s*`(.+?)`")
    current: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        s = line.strip()
        tm = tot_re.search(s)
        if tm and "total_hits" not in header:
            header["total_hits"] = int(tm.group(1))
        smv = sev_re.search(s)
        if smv:
            header["high"] = int(smv.group(1))
            header["medium"] = int(smv.group(2))
            header["low"] = int(smv.group(3))
        cm = cluster_re.match(s)
        if cm:
            current = {
                "detector": cm.group(1),
                "hits": int(cm.group(2)),
                "severity": "",
                "file_line": "",
                "snippet": "",
            }
            clusters.append(current)
            continue
        if current is not None:
            if not current["file_line"]:
                hm = hit_re.search(line)
                if hm:
                    current["severity"] = hm.group(1)
                    current["file_line"] = hm.group(2)
            if not current["snippet"]:
                sm = snip_re.search(line)
                if sm:
                    current["snippet"] = sm.group(1)[:80]
    clusters.sort(key=lambda c: c.get("hits", 0), reverse=True)
    header["cluster_count"] = len(clusters)
    return header, clusters[:top_n]


def _read_failed_stages(manifest_path: pathlib.Path, limit: int = 12) -> List[str]:
    """Collect stage-fail stage names from audit_run_full_manifest.jsonl."""
    if not manifest_path.is_file():
        return []
    failed: List[str] = []
    try:
        with manifest_path.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or '"stage-fail"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("event") == "stage-fail":
                    stage = str(rec.get("stage") or "").strip()
                    if stage and stage not in failed:
                        failed.append(stage)
                if len(failed) >= limit:
                    break
    except OSError:
        return failed
    return failed


def _format_audit_results_section(
    context: Optional[Dict[str, Any]],
) -> List[str]:
    """Render Section 15s - what the audit pipeline already found."""
    if not isinstance(context, dict):
        return []
    has_data = (
        context.get("clusters")
        or context.get("deep_engine")
        or context.get("exploit_queue_benchmark")
        or context.get("exploit_queue_top")
        or context.get("failed_stages")
    )
    if not has_data:
        return []
    lines: List[str] = [
        "## Section 15s - Full-Audit Results (what the audit already found)",
        "",
        (
            "_The pipeline already ran detectors, deep engines, and built the "
            "exploit queue. Read these so you do not re-walk hot regions blindly "
            "or propose harnesses for engines that build-failed._"
        ),
        "",
    ]
    header = context.get("engage_header") or {}
    clusters = context.get("clusters")
    if isinstance(clusters, list) and clusters:
        lines.append(
            f"### Detector clusters (engage_report.md) - "
            f"total `{header.get('total_hits', '?')}` hits across "
            f"`{header.get('cluster_count', len(clusters))}` clusters "
            f"(H={header.get('high', '?')} M={header.get('medium', '?')} "
            f"L={header.get('low', '?')})"
        )
        lines.append("")
        lines.append("| detector | hits | sev | file:line | snippet |")
        lines.append("|---|---:|---|---|---|")
        for c in clusters[:5]:
            if not isinstance(c, dict):
                continue
            snip = str(c.get("snippet", "")).replace("|", "\\|")
            lines.append(
                f"| `{c.get('detector', '')}` | {c.get('hits', 0)} | "
                f"{c.get('severity', '?')} | `{c.get('file_line', '')}` | "
                f"{snip[:60]} |"
            )
        lines.append("")

    de = context.get("deep_engine")
    if isinstance(de, dict) and de.get("present"):
        lines.append(
            f"### Deep-engine results - has_counterexample="
            f"`{bool(de.get('has_counterexample'))}` "
            f"counterexamples=`{de.get('counterexample_count', 0)}` "
            f"tooling_failures=`{de.get('tooling_failure_count', 0)}`"
        )
        for eng in de.get("engines") or []:
            if not isinstance(eng, dict):
                continue
            if eng.get("has_counterexample"):
                seq = ", ".join(eng.get("input_sequence") or [])
                lines.append(
                    f"- [COUNTEREXAMPLE] `{eng.get('engine')}`: "
                    f"`{eng.get('target_function')}` - seq: {seq[:120]}"
                )
            else:
                tf = eng.get("tooling_failure_pattern")
                detail = f" ({tf})" if tf else ""
                lines.append(
                    f"- `{eng.get('engine')}`: {eng.get('verdict')}{detail}"
                )
        lines.append("")

    bench = context.get("exploit_queue_benchmark")
    if isinstance(bench, dict) and bench:
        lines.append(
            "### Exploit-queue summary: "
            + "  ".join(
                f"{k.replace('rows_', '')}=`{v}`"
                for k, v in bench.items()
                if isinstance(v, (int, float))
            )
        )
        lines.append("")
    top = context.get("exploit_queue_top")
    if isinstance(top, list) and top:
        for t in top[:3]:
            if not isinstance(t, dict):
                continue
            lines.append(
                f"- [{t.get('likely_severity', '?')}] {t.get('title', '')} "
                f"- proof=`{t.get('proof_status', '')}` "
                f"`{t.get('source_ref', '')}`"
            )
        lines.append("")

    failed = context.get("failed_stages")
    if isinstance(failed, list) and failed:
        lines.append(
            "### Pipeline stages FAILED (ATTENTION - evidence may be absent): "
            + ", ".join(f"`{s}`" for s in failed[:12])
        )
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Section 15t - Deep-Analysis Silos (math-invariant spec + guard probe packets)
#
# Two deep-analysis silos run in the pipeline but were never surfaced into the
# hunt brief:
#   - tools/math-invariant-miner.py  -> <ws>/math_invariants/math_spec.json
#       (per-contract conservation laws, monotonicity, rounding hints,
#        one-sided-mutation VIOLATIONS, fuzz candidates).
#   - tools/guard-context-extract.py -> <ws>/.auditooor/guard_probe_packets.jsonl
#       (per-guard "what this guard does NOT check" negative-space context).
# Both encode where the math invariants live and where each guard's blind spot
# is. Mirrors how _format_audit_results_section surfaces the audit-pipeline
# artifacts. Hunt-class lanes only (same gating as audit-results).
# r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
# ---------------------------------------------------------------------------
def build_deep_analysis_silos_context(
    *,
    workspace_path: Optional[pathlib.Path],
    lane_type: str,
    max_violation_contracts: int = 6,
    max_candidate_contracts: int = 6,
    max_guard_packets: int = 8,
) -> Optional[Dict[str, Any]]:
    """Read the two deep-analysis silo artifacts and distil a compact feed.

    Returns None for non-hunt-class lanes. Returns a (possibly degraded)
    context dict when at least one silo artifact is present; returns None when
    neither artifact exists so the formatter omits the section entirely.
    """
    if (lane_type or "").strip().lower() not in DEFENSE_AUDIT_CONTEXT_LANE_TYPES:
        return None
    if not workspace_path:
        return None
    ws = pathlib.Path(workspace_path)

    context: Dict[str, Any] = {
        "schema": "auditooor.dispatch_prebrief_deep_silos.v1",
        "workspace_path": str(ws),
        "math_spec_present": False,
        "math_violations": [],
        "math_candidates": [],
        "guard_probe_present": False,
        "guard_packets": [],
        # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered
        "economic_present": False,
        "economic_categories": [],
        "per_chain_present": False,
        "per_chain_summary": {},
    }

    # --- Silo 1: math_spec.json ------------------------------------------
    math_spec = _read_json_object(ws / "math_invariants" / "math_spec.json")
    if isinstance(math_spec, dict):
        contracts = math_spec.get("contracts")
        if isinstance(contracts, dict) and contracts:
            context["math_spec_present"] = True
            for cname in sorted(contracts.keys()):
                cdata = contracts.get(cname)
                if not isinstance(cdata, dict):
                    continue
                viols = cdata.get("violations")
                if isinstance(viols, list) and viols:
                    rows = []
                    for v in viols[:4]:
                        if isinstance(v, dict):
                            rows.append({
                                "function": str(v.get("function") or v.get("fn") or "?")[:80],
                                "law": str(v.get("law") or v.get("conservation_law")
                                          or v.get("hint") or "")[:160],
                            })
                    if rows and len(context["math_violations"]) < max_violation_contracts:
                        context["math_violations"].append(
                            {"contract": cname[:80], "rows": rows}
                        )
                cands = cdata.get("candidates")
                if isinstance(cands, list) and cands:
                    items = []
                    for c in cands[:4]:
                        if isinstance(c, dict):
                            items.append(
                                str(c.get("invariant") or c.get("description")
                                    or c.get("hint") or "")[:160]
                            )
                        elif isinstance(c, str):
                            items.append(c[:160])
                    items = [s for s in items if s]
                    if items and len(context["math_candidates"]) < max_candidate_contracts:
                        context["math_candidates"].append(
                            {"contract": cname[:80], "items": items}
                        )

    # --- Silo 2: guard_probe_packets.jsonl -------------------------------
    gpp = ws / ".auditooor" / "guard_probe_packets.jsonl"
    if gpp.is_file():
        try:
            with gpp.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(r, dict):
                        continue
                    context["guard_probe_present"] = True
                    if len(context["guard_packets"]) >= max_guard_packets:
                        continue
                    context["guard_packets"].append({
                        "guard_id": str(r.get("guard_id") or "?")[:80],
                        "file_line": str(r.get("file_line") or "?")[:120],
                        "guard_line": str(r.get("guard_line") or "")[:160],
                        "invariant_hint": str(
                            r.get("invariant_hint") or r.get("checks") or ""
                        )[:200],
                        "incomplete": bool(r.get("invariant_context_incomplete")),
                    })
        except OSError:
            pass

    # --- Silo 3: economic_hypotheses.json (FIX 1) ------------------------
    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered
    econ = _read_json_object(ws / ".auditooor" / "economic_hypotheses.json")
    if isinstance(econ, dict):
        per_file = econ.get("per_file")
        if isinstance(per_file, list):
            for rec in per_file:
                if not isinstance(rec, dict) or not rec.get("markdown_written"):
                    continue
                md = rec.get("markdown")
                if not isinstance(md, str) or not md:
                    continue
                cats = _parse_economic_summary_categories_dispatch(pathlib.Path(md))
                if not cats:
                    continue
                context["economic_present"] = True
                if len(context["economic_categories"]) < 6:
                    context["economic_categories"].append({
                        "file": str(rec.get("file") or "?")[:160],
                        "categories": cats[:8],
                    })

    # --- Silo 4: per-chain blast-radius workspace summary (FIX 2) ---------
    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered
    pcb = _read_json_object(
        ws / ".auditooor" / "per_chain_blast_radius" / "_workspace_summary.json"
    )
    if isinstance(pcb, dict) and pcb.get("is_cross_chain_target"):
        context["per_chain_present"] = True
        chains = pcb.get("registered_chains")
        chain_names = []
        if isinstance(chains, list):
            for c in chains[:12]:
                if isinstance(c, dict) and c.get("name"):
                    chain_names.append(str(c.get("name"))[:40])
        context["per_chain_summary"] = {
            "registration_anchor_count": int(pcb.get("registration_anchor_count") or 0),
            "blast_radius_count": int(pcb.get("blast_radius_count") or 0),
            "registered_chains": chain_names,
        }

    if (
        not context["math_spec_present"]
        and not context["guard_probe_present"]
        and not context["economic_present"]
        and not context["per_chain_present"]
    ):
        return None
    return context


# r36-rebuttal: lane orphan-queue-wiring-2026-06 registered
def _parse_economic_summary_categories_dispatch(md_path: pathlib.Path) -> List[Any]:
    """Parse the '## Summary table' of an economic_hypotheses markdown and
    return [(Category, Hits)] rows with a non-zero hit count. Best-effort."""
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError:
        return []
    rows: List[Any] = []
    in_table = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("## Summary table"):
            in_table = True
            continue
        if in_table:
            if s.startswith("## ") and "Summary table" not in s:
                break
            if not s.startswith("|"):
                continue
            cells = [c.strip() for c in s.strip("|").split("|")]
            if len(cells) < 3:
                continue
            cat, hits = cells[1], cells[2]
            if cat.lower() in {"category", ""} or set(cat) <= {"-", ":"}:
                continue
            try:
                n = int(re.sub(r"[^0-9]", "", hits) or "0")
            except ValueError:
                n = 0
            if n > 0:
                rows.append((cat[:40], n))
    return rows


def _format_deep_analysis_silos_section(
    context: Optional[Dict[str, Any]],
) -> List[str]:
    """Render Section 15t - the math-invariant spec + guard-probe-packet silos.

    Surfaces the per-function math invariants (FIX 1, math_spec.json) and the
    per-guard 'what this guard does NOT check' context (FIX 2,
    guard_probe_packets.jsonl) into the hunt/MIMO brief so the LLM actually
    uses these deep-analysis silos. Returns [] when no silo artifact applies.
    """
    if not isinstance(context, dict):
        return []
    has_math = context.get("math_violations") or context.get("math_candidates")
    has_guards = context.get("guard_packets")
    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered
    has_econ = context.get("economic_categories")
    has_per_chain = context.get("per_chain_present") and context.get("per_chain_summary")
    if not (has_math or has_guards or has_econ or has_per_chain):
        return []
    lines: List[str] = [
        "## Section 15t - Deep-Analysis Silos (math invariants + guard blind-spots)",
        "",
        (
            "_Two deep-analysis passes already ran. The math-invariant miner "
            "extracted per-contract conservation laws + one-sided-mutation "
            "violations; the guard-context extractor distilled what each guard "
            "does NOT check. Anchor candidate findings to these gaps instead of "
            "re-deriving them from raw source._"
        ),
        "",
    ]

    viols = context.get("math_violations")
    if isinstance(viols, list) and viols:
        lines.append(
            "### Math-spec VIOLATIONS (one-sided mutation of a conservation law)"
        )
        for cv in viols:
            if not isinstance(cv, dict):
                continue
            lines.append(f"- contract `{cv.get('contract', '?')}`:")
            for row in cv.get("rows") or []:
                if isinstance(row, dict):
                    lines.append(
                        f"  - `{row.get('function', '?')}` may break: "
                        f"{row.get('law', '')}"
                    )
        lines.append("")

    cands = context.get("math_candidates")
    if isinstance(cands, list) and cands:
        lines.append("### Math invariants worth fuzzing (per contract)")
        for cc in cands:
            if not isinstance(cc, dict):
                continue
            lines.append(f"- contract `{cc.get('contract', '?')}`:")
            for item in cc.get("items") or []:
                lines.append(f"  - {item}")
        lines.append("")

    guards = context.get("guard_packets")
    if isinstance(guards, list) and guards:
        lines.append("### Guard negative-space (what each guard does NOT check)")
        for g in guards:
            if not isinstance(g, dict):
                continue
            flag = " [context-incomplete: escalate to full read]" if g.get("incomplete") else ""
            lines.append(
                f"- guard `{g.get('guard_id', '?')}` @ `{g.get('file_line', '?')}`"
                f"{flag}"
            )
            if g.get("guard_line"):
                lines.append(f"  - condition: `{g.get('guard_line')}`")
            if g.get("invariant_hint"):
                lines.append(f"  - blind spot: {g.get('invariant_hint')}")
        lines.append("")

    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered (FIX 1)
    econ = context.get("economic_categories")
    if isinstance(econ, list) and econ:
        lines.append("### Economic attack surface (live economic hit categories per contract)")
        for ec in econ:
            if not isinstance(ec, dict):
                continue
            cats = ec.get("categories") or []
            rendered = ", ".join(
                f"{str(c)[:40]} ({int(n)} hit(s))"
                for c, n in cats if isinstance(n, int) or str(n).isdigit()
            )
            if rendered:
                lines.append(f"- `{ec.get('file', '?')}`: {rendered}")
        lines.append("")

    # r36-rebuttal: lane orphan-queue-wiring-2026-06 registered (FIX 2)
    pcs = context.get("per_chain_summary")
    if context.get("per_chain_present") and isinstance(pcs, dict) and pcs:
        lines.append("### Cross-chain blast radius (this target registers multiple chains)")
        names = pcs.get("registered_chains") or []
        lines.append(
            f"- registration anchors: {pcs.get('registration_anchor_count', 0)}; "
            f"blast-radius count: {pcs.get('blast_radius_count', 0)}"
        )
        if names:
            lines.append(f"- registered chains: {', '.join(str(n) for n in names)}")
        lines.append(
            "- _If a finding in one chain's client/config path also routes "
            "through these registered siblings, widen the finding or file a "
            "sibling submission per chain._"
        )
        lines.append("")

    lines.append(
        "_Use these silos: if a math violation or a guard blind-spot above can "
        "be reached by an unprivileged caller, anchor your finding to that exact "
        "gap (cite the contract/guard and file:line)._"
    )
    lines.append("")
    return lines


def _extract_candidate_id(prompt_text: str) -> str:
    match = re.search(r"\b(?:EQ|CAND|LEAD|DRILL|M1)[-_][A-Za-z0-9_.:-]+\b", prompt_text or "")
    return match.group(0) if match else ""


def _call_lane_verdict_bus_direct(
    *,
    workspace_path: pathlib.Path,
    candidate_id: str = "",
    attack_class: str = "",
    limit: int = 5,
) -> Optional[Dict[str, Any]]:
    tool = REPO / "tools" / "lane-verdict-bus.py"
    if not tool.is_file():
        return None
    cmd = [
        sys.executable,
        str(tool),
        "consult",
        "--workspace",
        str(workspace_path),
        "--limit",
        str(limit),
        "--json",
    ]
    if candidate_id:
        cmd.extend(["--candidate-id", candidate_id])
    if attack_class:
        cmd.extend(["--attack-class", attack_class])
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    payload = _json_from_helper_stdout(proc.stdout)
    if not isinstance(payload, dict):
        return None
    payload["schema"] = "auditooor.lane_verdict_bus.consult.v1"
    payload["kind"] = "lane_verdict_bus"
    payload["degraded"] = False
    payload["direct_tool_fallback"] = True
    payload.setdefault("records", [])
    payload.setdefault("verdicts", payload.get("records") or [])
    payload.setdefault("verdicts_returned", len(payload.get("verdicts") or []))
    return payload


def build_lane_verdict_bus_context(
    *,
    workspace_path: Optional[pathlib.Path],
    prompt_text: str,
    target_finding_class: str = "",
    limit: int = 5,
) -> Dict[str, Any]:
    """Consult M1-1/M1-2 lane verdict bus for prior lane outcomes."""
    candidate_id = _extract_candidate_id(prompt_text)
    attack_class = (target_finding_class or "").strip()
    base: Dict[str, Any] = {
        "schema": "auditooor.lane_verdict_bus.consult.v1",
        "kind": "lane_verdict_bus",
        "workspace_path": str(workspace_path) if workspace_path else "",
        "candidate_id": candidate_id,
        "attack_class": attack_class,
        "limit": limit,
        "degraded": False,
        "verdicts": [],
        "verdicts_returned": 0,
        "bus_empty": True,
        "consult_source": "none",
    }
    if workspace_path is None:
        base.update(
            {
                "degraded": True,
                "degraded_reason": "workspace_path_required",
                "consult_source": "not-run",
            }
        )
        return base
    args: Dict[str, Any] = {"workspace_path": str(workspace_path), "limit": limit}
    if candidate_id:
        args["candidate_id"] = candidate_id
    if attack_class:
        args["attack_class"] = attack_class
    payload = call_local_mcp_tool("vault_lane_verdict_bus", args, timeout=30)
    if isinstance(payload, dict):
        payload = dict(payload)
        payload["consult_source"] = "vault_lane_verdict_bus"
    else:
        payload = _call_lane_verdict_bus_direct(
            workspace_path=workspace_path,
            candidate_id=candidate_id,
            attack_class=attack_class,
            limit=limit,
        )
        if isinstance(payload, dict):
            payload["consult_source"] = "tools/lane-verdict-bus.py"
    if not isinstance(payload, dict):
        base.update(
            {
                "degraded": True,
                "degraded_reason": "lane_verdict_bus_unavailable",
                "consult_source": "unavailable",
            }
        )
        return base
    if "verdicts" not in payload and isinstance(payload.get("records"), list):
        payload["verdicts"] = list(payload["records"])
    if not isinstance(payload.get("verdicts"), list):
        payload["verdicts"] = []
    payload.setdefault("verdicts_returned", len(payload["verdicts"]))
    payload.setdefault("bus_empty", len(payload["verdicts"]) == 0)
    payload.setdefault("candidate_id", candidate_id)
    payload.setdefault("attack_class", attack_class)
    payload.setdefault("limit", limit)
    payload.setdefault("workspace_path", str(workspace_path))
    return payload


def _format_lane_verdict_bus_section(context: Optional[Dict[str, Any]]) -> List[str]:
    """Render Section 15n for lane-verdict-bus consultation."""
    if not isinstance(context, dict):
        return []
    verdicts = context.get("verdicts")
    if not isinstance(verdicts, list):
        verdicts = []
    lines: List[str] = [
        "## Section 15n - Lane-Verdict-Bus consultation",
        "",
        (
            "_Consult sibling-lane outcomes before drilling. If a prior lane "
            "already DROPPED this candidate or attack class, proceed only with "
            "a new trigger-state change or stronger evidence._"
        ),
        "",
        f"- Consult source: `{context.get('consult_source', 'unknown')}`",
        f"- Bus empty: `{bool(context.get('bus_empty', not verdicts))}`",
        f"- Verdict rows returned: `{context.get('verdicts_returned', len(verdicts))}`",
        f"- Candidate filter: `{context.get('candidate_id', '') or 'none'}`",
        f"- Attack-class filter: `{context.get('attack_class', '') or 'none'}`",
        "",
    ]
    if context.get("degraded"):
        lines.append(f"- Degraded reason: `{context.get('degraded_reason', 'unknown')}`")
        lines.append("")
    if verdicts:
        lines.append("| Lane | Candidate | Class | Verdict | Summary |")
        lines.append("|---|---|---|---|---|")
        for row in verdicts[:5]:
            if not isinstance(row, dict):
                continue
            summary = str(row.get("summary") or row.get("details") or "").replace("|", "\\|")
            lines.append(
                f"| `{row.get('lane_id', '')}` | `{row.get('candidate_id', '')}` | "
                f"`{row.get('attack_class', '')}` | `{row.get('verdict', '')}` | "
                f"{summary[:180]} |"
            )
        lines.append("")
        lines.append(
            "If any row is `DROPPED`, `OOS`, or `BLOCKED`, your reply must "
            "state why this lane is materially different."
        )
    else:
        lines.append(
            "_Lane verdict bus is empty for this workspace/filter. Continue, "
            "but emit your final `VERDICT:` so the bus can capture it._"
        )
    lines.append("")
    return lines


def _safe_pack_excerpt(path: pathlib.Path, max_chars: int = 6000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return json.dumps(
            {
                "schema": "auditooor.pre_flight_pack.v1",
                "status": "unreadable",
                "path": str(path),
                "error": str(exc)[:200],
            },
            sort_keys=True,
            indent=2,
        )
    if len(text) <= max_chars:
        return text.rstrip()
    return text[:max_chars].rstrip() + "\n... truncated by dispatch prebriefing ..."


def _detector_hit_file(ref: str) -> str:
    """Strip a trailing ``:<line>`` from a ``file:line`` ref, return the path part.

    ``src/.../Foo.sol:58`` -> ``src/.../Foo.sol``. A ref with no numeric line
    suffix is returned unchanged. Used to join detector hits to a function pack
    by SOURCE FILE (an honest file-level corroboration, not an over-claimed
    per-line match - the line is preserved in the rendered hit for the agent to
    judge proximity itself).
    """
    ref = (ref or "").strip()
    if ":" in ref:
        head, tail = ref.rsplit(":", 1)
        if tail.isdigit():
            return head.strip()
    return ref


def _collect_per_fn_detector_hits(
    workspace_path: Optional[pathlib.Path],
    source_ref: str,
    *,
    limit: int = 6,
) -> List[Dict[str, Any]]:
    """Gap #9 join: static-analyzer hits whose source FILE matches this function.

    Producer = ``.auditooor/detector_action_graph.json`` (single ``detector_hit``)
    plus ``.auditooor/detector_action_graphs/*.json`` (one ``detector_hit`` each).
    Consumer = the per-function dispatch brief. Joining by file (not regenerating
    the pack) means EXISTING packs gain corroboration with no re-run, and a stale
    pack never silently drops the signal. Returns [] when no producer artifact is
    present (honest absence, never a fabricated hit).
    """
    if workspace_path is None:
        return []
    fn_file = _detector_hit_file(source_ref)
    if not fn_file:
        return []
    det_dir = workspace_path / ".auditooor"
    candidates: List[pathlib.Path] = []
    main_graph = det_dir / "detector_action_graph.json"
    if main_graph.is_file():
        candidates.append(main_graph)
    graphs_dir = det_dir / "detector_action_graphs"
    if graphs_dir.is_dir():
        candidates.extend(sorted(graphs_dir.glob("*.json")))
    seen: set = set()
    hits: List[Dict[str, Any]] = []
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        dh = data.get("detector_hit")
        rows = dh if isinstance(dh, list) else ([dh] if isinstance(dh, dict) else [])
        for row in rows:
            if not isinstance(row, dict):
                continue
            hit_ref = str(row.get("file_path") or "")
            if _detector_hit_file(hit_ref) != fn_file:
                continue
            key = (str(row.get("detector_slug") or ""), hit_ref)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "detector_slug": str(row.get("detector_slug") or ""),
                    "file_path": hit_ref,
                    "severity": str(row.get("severity") or ""),
                    "snippet": str(row.get("snippet") or "")[:200],
                }
            )
            if len(hits) >= limit:
                return hits
    return hits


def build_pre_flight_pack_context(
    *,
    workspace_path: Optional[pathlib.Path],
    prompt_text: str = "",
    target_finding_class: str = "",
) -> Dict[str, Any]:
    """Locate a CAP-GAP-97 pre-flight pack for this dispatch.

    The pack producer is intentionally separate from this consumer. Until the
    producer exists in every workspace, this returns a conservative placeholder
    rather than fabricating per-function intelligence.
    """
    if workspace_path is None:
        return {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "missing-workspace",
            "matched": False,
            "reason": "workspace path unavailable",
            "expected_dir": "",
        }

    pack_dir = workspace_path / ".auditooor" / "pre_flight_packs"
    expected_glob = "pre_flight_pack_*.json"
    if not pack_dir.is_dir():
        return {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "missing-pack-dir",
            "matched": False,
            "reason": "pre-flight pack directory not present",
            "expected_dir": str(pack_dir),
            "expected_glob": expected_glob,
        }

    packs = sorted(pack_dir.glob(expected_glob), key=lambda p: p.stat().st_mtime, reverse=True)
    if not packs:
        return {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "empty-pack-dir",
            "matched": False,
            "reason": "pre-flight pack directory has no pack JSON files",
            "expected_dir": str(pack_dir),
            "expected_glob": expected_glob,
        }

    prompt_l = (prompt_text or "").lower()
    target_l = (target_finding_class or "").lower()

    chosen = None
    chosen_reason = ""
    for pack in packs:
        if pack.name in prompt_text:
            chosen = pack
            chosen_reason = "prompt names exact pack filename"
            break
    if chosen is None:
        for pack in packs:
            stem_l = pack.stem.lower()
            if stem_l and stem_l in prompt_l:
                chosen = pack
                chosen_reason = "prompt mentions pack stem"
                break
    if chosen is None and target_l:
        for pack in packs:
            if target_l in pack.stem.lower():
                chosen = pack
                chosen_reason = "target_finding_class matched pack stem"
                break
    if chosen is None:
        chosen = packs[0]
        chosen_reason = "no exact dispatch target match; using newest pack as workspace anchor"

    return {
        "schema": "auditooor.pre_flight_pack_context.v1",
        "status": "matched",
        "matched": True,
        "path": str(chosen),
        "reason": chosen_reason,
        "pack_count": len(packs),
        "excerpt": _safe_pack_excerpt(chosen),
    }


def _format_pre_flight_pack_section(
    context: Optional[Dict[str, Any]],
    workspace_path: Optional[pathlib.Path] = None,
) -> List[str]:
    lines = [
        "**CAP-GAP-97 pre-flight pack**:",
        "",
    ]
    if not isinstance(context, dict):
        lines.extend(
            [
                "- Status: `missing-context`",
                "- Pack unavailable; do not infer per-function intelligence from this placeholder.",
                "",
            ]
        )
        return lines

    if context.get("matched"):
        # ANCHOR-FALLBACK GUARD (2026-07-03): build_pre_flight_pack_context, when the
        # dispatch prompt names NO specific pack (a HAND-WRITTEN brief, or a target with no
        # pack produced), falls back to the NEWEST pack in the dir as a bare "workspace
        # anchor" (reason "no exact dispatch target match..."). That pack can be a
        # COMPLETELY UNRELATED function/contract - observed: an EVM
        # pre_flight_pack_RedemptionProxy_sweep.json injected into a Go/Cosmos
        # reconcile.go/valuation_engine.go hunt. Rendering that unrelated body under the
        # "TARGET FUNCTION + CONTEXT ... REAL code, your primary input" header actively
        # MISLEADS the agent into hunting the wrong function (a careful agent caught it and
        # complained; a careless one would not). So on the fallback path we SUPPRESS the
        # target-framed body block + same-file detector hits (they are for the wrong file)
        # and emit an explicit NOT-YOUR-TARGET warning. A genuine match (prompt names the
        # pack / stem / target_finding_class) is unchanged.
        _reason = str(context.get("reason", ""))
        _is_anchor_fallback = (
            "no exact dispatch target match" in _reason
            or "workspace anchor" in _reason.lower()
        )
        lines.append(f"- Status: `matched`")
        lines.append(f"- Pack path: `{context.get('path', '')}`")
        lines.append(f"- Match reason: {_reason}")
        lines.append(f"- Workspace pack count: `{context.get('pack_count', 0)}`")
        lines.append("")
        if _is_anchor_fallback:
            lines.append(
                "> !! NON-TARGET WORKSPACE-ANCHOR PACK: this pack was the newest-in-dir "
                "fallback (the dispatch prompt named no specific pre-flight pack), so it is "
                "very likely for a DIFFERENT function/contract than your assignment - "
                "cross-language mismatches happen (an EVM pack on a Go/Cosmos lane). DO NOT "
                "treat its function/body as your target. Work STRICTLY from your own "
                "assignment + the REAL source files you were told to hunt (R76). The pack "
                "body + same-file detector hits are SUPPRESSED below to avoid misdirecting you."
            )
            lines.append("")
        # Always emit the source-read mandate BEFORE the pack excerpt so agents
        # cannot miss it. Grounded in empirical FP rate: 5/10 false-positive
        # HIGHs were observed when agents relied on pack summaries alone (R76).
        # Emit the mandate for the ACTIVE hunt mode (E4.4): generate-broad vs
        # verify-strict. Both keep the R76 source-read requirement; they differ
        # only in the negative default (quarantine, never silent ruled-out).
        lines.append(pack_source_read_mandate())
        lines.append("")
        # Try to embed the real function body from source_ref so agents have
        # real code inline and can fulfil the source-read mandate cheaply.
        source_ref = ""
        fn_name = ""
        pack_path_str = context.get("path") or ""
        if pack_path_str:
            try:
                pack_data = json.loads(
                    pathlib.Path(pack_path_str).read_text(encoding="utf-8", errors="replace")
                )
                source_ref = str(pack_data.get("source_ref") or "")
                fn_name = str(pack_data.get("function") or "")
            except Exception:
                pass
        # On the anchor-fallback path, DO NOT embed the (unrelated) pack body under the
        # "TARGET FUNCTION" header - it would misdirect the hunt.
        body_block = "" if _is_anchor_fallback else _pack_embedded_body_block(
            source_ref, workspace_path, fn_name)
        if body_block:
            lines.append(body_block)
        elif source_ref:
            pass  # source-ref fallback handled below
        # Gap #9: surface static-analyzer hits in THIS function's source file as
        # a corroborating prior, so the per-fn brief carries the same detector
        # signal the workspace-level engage_report cluster table already shows -
        # but scoped to the function under hunt. SUPPRESSED on the anchor-fallback
        # path (source_ref is the unrelated newest-pack's file, not the target's).
        det_hits = [] if _is_anchor_fallback else _collect_per_fn_detector_hits(
            workspace_path, source_ref)
        if det_hits:
            lines.append(
                "**Static-analyzer corroboration (same source file as this "
                "function)** - a prior, not a verdict; READ the cited line and "
                "judge relevance yourself (R76):"
            )
            lines.append("")
            lines.append("| detector | sev | file:line | snippet |")
            lines.append("|---|---|---|---|")
            for h in det_hits:
                snip = h["snippet"].replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| `{h['detector_slug']}` | {h['severity']} | "
                    f"`{h['file_path']}` | {snip} |"
                )
            lines.append("")
        if not body_block and source_ref:
            # Body extraction failed but we know the ref - surface it.
            lines.append(
                f"- Source ref (body extraction unavailable - READ THIS FILE): "
                f"`{source_ref}`"
            )
            lines.append("")
        lines.append("```json")
        lines.append(str(context.get("excerpt") or "").rstrip())
        lines.append("```")
        lines.append("")
    else:
        lines.append(f"- Status: `{context.get('status', 'missing')}`")
        lines.append(f"- Expected directory: `{context.get('expected_dir', '')}`")
        if context.get("expected_glob"):
            lines.append(f"- Expected glob: `{context.get('expected_glob')}`")
        lines.append(f"- Reason: {context.get('reason', 'pre-flight pack unavailable')}")
        lines.append(
            "- Placeholder: no CAP-GAP-97 pack was available at dispatch time; "
            "run or wire the pre-flight pack producer before relying on per-function pack context."
        )
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Filing Finalization - Definition of Done (Section 15q)
# r36-rebuttal: lane spawn-worker-filing-dod registered in
# .auditooor/agent_pathspec.json agents[].
# ---------------------------------------------------------------------------

# Drive-and-Verify Paste-Ready Mandate (canonical text).
#
# Appended to _format_filing_finalization_section so it lands ONLY on
# filing-class briefs (build_filing_finalization_context returns None for
# hunt/drill/comp/fuzz => the formatter returns [] before this is reached, so
# the mandate is structurally impossible to leak into a lean hunt brief).
#
# The predmkt lesson (ground truth this enforces): a driver asserted
# "clears $1000 comfortably" citing a Node.js sweep artifact that does NOT
# exist in the workspace. The truth: reserve asset = GBYTE at
# factory.oscript:58, victim loss 26,341,593 bytes, 1 GBYTE = 1e9 bytes,
# GBYTE ~ $5 => ~$0.13 - about four orders of magnitude under the $1000 floor
# - and the finding was OOS as front-running per the program's DEDAUB-M2
# precedent. A raw-unit PoC delta is NOT a dollar impact.
#
# The four proof-lines below MIRROR the forthcoming absolute-$ gate (sibling
# task #172) so brief and gate cannot drift. Header marker string is unique +
# grep-checked absent from tools/ so the regression guard can key on it.
_DRIVE_AND_VERIFY_MANDATE_LINES: List[str] = [
    "## Drive-and-Verify Paste-Ready Mandate",
    "",
    (
        "_Before you call ANY draft paste-ready, you MUST complete the three "
        "blocks below. The predmkt lesson: a driver claimed a finding "
        "\"clears $1000 comfortably\" citing a sweep artifact that did not "
        "exist in the workspace; the true impact was ~$0.13 (a raw-unit PoC "
        "delta is NOT a dollar impact), and the class was OOS as "
        "front-running. Self-certification is banned - drive AND verify._"
    ),
    "",
    "**(A) ABSOLUTE $-IMPACT PROOF (all four labelled lines are mandatory):**",
    (
        f"- `{_LBL_ASSET}:` name the loss/reserve asset and cite the EXACT "
        "in-scope `file:line` that fixes it (the predmkt reserve_asset was "
        "`factory.oscript:58`). No asset-identity cite = not paste-ready."
    ),
    (
        f"- `{_LBL_UNIT}:` give the raw-unit total, the unit->USD factor, and the "
        "asset price WITH a cited source (e.g. `1 GBYTE = 1e9 bytes, "
        "GBYTE ~ $5`). A raw-unit delta with no conversion is NOT a $ figure."
    ),
    (
        f"- `{_LBL_MARKET}:` state a realistic position / liquidity / "
        "TVL figure the attack needs, not a hypothetical maximum."
    ),
    (
        f"- `{_LBL_ABS_VS_FLOOR}:` compute the ABSOLUTE $ figure and compare it to "
        "the program's $ floor. Under-floor => downgrade or drop; do not overclaim."
    ),
    (
        "- `Backing artifact:` give a path to a quantification/PoC artifact "
        "that ACTUALLY EXISTS in this workspace (verify with `ls`/`test -f`). "
        "A cited sweep/log/script that is not on disk is an automatic "
        "non-paste-ready (the predmkt phantom-artifact failure mode)."
    ),
    "",
    "**(B) OOS ATTACK-CLASS ADJUDICATION (rule out or concede EACH):**",
    (
        "- Front-running / sandwich / MEV via the public mempool; basic "
        "economic or governance; Sybil; unclaimed-yield; privileged-actor; "
        "attacker-expense <= ~200% of profit. Judge EACH against THIS "
        "program's `SCOPE.md` / `SEVERITY.md` OOS clauses + precedent, citing "
        "the exact lines (the predmkt case was OOS front-running per the "
        "program's DEDAUB-M2 precedent)."
    ),
    (
        "- RUN `python3 tools/per-finding-oos-check.py` (and "
        "`tools/dispatch_oos_preflight.py` at dispatch) and record the "
        "verdict. A finding that lands in an OOS class is NOT paste-ready."
    ),
    "",
    "**(C) INDEPENDENT ADVERSARIAL VERIFY (distinct verifier mindset):**",
    (
        "- BEFORE promoting `staging/` -> `paste_ready/`, re-derive the "
        "$-impact AND the OOS-disposition from SOURCE without trusting the "
        "driver's own numbers - run "
        "`python3 tools/adversarial-candidate-verify.py` or spawn an "
        "independent verify lane. A bare $-assertion with no independent "
        "backing computation is an automatic non-paste-ready."
    ),
    "",
]

_PLATFORM_REQUIREMENTS_CACHE: Optional[Dict[str, Any]] = None


def _load_platform_requirements() -> Dict[str, Any]:
    """Load + cache reference/platform_submission_requirements.json.

    Returns the ``platforms`` map; empty dict on any read/parse error so the
    injection degrades gracefully (no crash, the DoD block still emits its
    static gate checklist without the per-platform required_sections).
    """
    global _PLATFORM_REQUIREMENTS_CACHE
    if _PLATFORM_REQUIREMENTS_CACHE is not None:
        return _PLATFORM_REQUIREMENTS_CACHE
    platforms: Dict[str, Any] = {}
    try:
        data = json.loads(PLATFORM_REQUIREMENTS_PATH.read_text(encoding="utf-8"))
        maybe = data.get("platforms")
        if isinstance(maybe, dict):
            platforms = maybe
    except (OSError, ValueError, AttributeError):
        platforms = {}
    _PLATFORM_REQUIREMENTS_CACHE = platforms
    return platforms


def resolve_workspace_platform(
    workspace_path: Optional[pathlib.Path],
) -> str:
    """Resolve the bounty platform id for a workspace.

    Reads the workspace SCOPE.md / SEVERITY.md / README.md / .auditooor text
    plus the workspace directory name and maps a platform keyword to one of
    ``cantina`` / ``github-ghsa`` / ``immunefi`` / ``hackenproof``. Defaults
    to ``generic`` when no keyword resolves. Robust + cheap: grep-style text
    scan, no network. More-specific signals win (PLATFORM_KEYWORD_RULES is
    ordered) so e.g. a zebra workspace whose rubric prose mentions "immunefi"
    still resolves to github-ghsa via the zcash/ZCG/GHSA/zebra signals.
    """
    blob_parts: List[str] = []
    name = ""
    if workspace_path is not None:
        try:
            name = workspace_path.name.lower()
        except (AttributeError, ValueError):
            name = ""
        blob_parts.append(name)
        for rel in (
            "SCOPE.md",
            "SEVERITY.md",
            "README.md",
            ".auditooor/engagement.json",
            ".auditooor/engagement_status.json",
        ):
            try:
                p = workspace_path / rel
                if p.is_file():
                    blob_parts.append(p.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, ValueError):
                continue
    blob = "\n".join(blob_parts).lower()

    for platform_id, keywords in PLATFORM_KEYWORD_RULES:
        for kw in keywords:
            if kw in blob:
                return platform_id
    return "generic"


def build_filing_finalization_context(
    *,
    lane_type: str,
    workspace_path: Optional[pathlib.Path],
) -> Optional[Dict[str, Any]]:
    """Build the Filing Finalization Definition-of-Done context.

    Returns None when ``lane_type`` is not a filing-class lane (so the
    section is injected ONLY for filing / triager-response / rebuttal /
    escalation). Otherwise resolves the platform + its template + required
    sections from the registry.
    """
    if (lane_type or "").strip().lower() not in FILING_FINALIZATION_LANE_TYPES:
        return None
    platform_id = resolve_workspace_platform(workspace_path)
    platforms = _load_platform_requirements()
    entry = platforms.get(platform_id) or platforms.get("generic") or {}
    return {
        "schema": "auditooor.filing_finalization_dod.v1",
        "lane_type": lane_type,
        "platform_id": platform_id,
        "display_name": str(entry.get("display_name", platform_id)),
        "canonical_template": str(entry.get("canonical_template", "")),
        "required_sections": list(entry.get("required_sections") or []),
        "poc_inline_required": bool(entry.get("poc_inline_required", True)),
        "field_notes": str(entry.get("field_notes", "")),
        "output_format": str(entry.get("output_format", "markdown")),
        "markdown_allowed": bool(entry.get("markdown_allowed", True)),
        "poc_delivery": str(entry.get("poc_delivery", "")),
        "field_rules": list(entry.get("field_rules") or []),
    }


def _format_filing_finalization_section(
    context: Optional[Dict[str, Any]],
) -> List[str]:
    """Render Section 15q - Filing Finalization Definition of Done.

    Concise (<= ~40 lines): a mandatory-gate checklist + the resolved
    platform template pointer + its required_sections. Returns [] when
    context is None (non-filing lane), so hunt-class briefs never get it.
    """
    if not context:
        return []
    platform_id = str(context.get("platform_id", "generic"))
    display = str(context.get("display_name", platform_id))
    template = str(context.get("canonical_template", "")) or "(none)"
    sections = context.get("required_sections") or []
    field_notes = str(context.get("field_notes", ""))
    output_format = str(context.get("output_format", "markdown"))
    markdown_allowed = bool(context.get("markdown_allowed", True))
    poc_delivery = str(context.get("poc_delivery", ""))
    field_rules = context.get("field_rules") or []

    lines: List[str] = [
        "## Filing Finalization - Definition of Done",
        "",
        (
            "_Injected for filing-class lanes only (filing / triager-response "
            "/ rebuttal / escalation). A draft is NOT paste-ready until ALL "
            "gates below pass. Do not call a draft paste-ready while "
            "pre-submit-check.sh is failing - that is the real miss this block "
            "prevents (a pointer-PoC draft promoted while 11 checks were red)._"
        ),
        "",
        f"**Resolved platform**: `{platform_id}` ({display})",
        f"**Canonical template**: `{template}` (align your draft to it)",
        "",
    ]

    # --- Platform output format + PoC delivery (new - mined from filed artifacts) ---
    md_flag = "YES - markdown rendered" if markdown_allowed else "NO - PLAIN TEXT ONLY"
    lines += [
        f"**Output format**: `{output_format}` | **Markdown allowed**: {md_flag}",
    ]
    if not markdown_allowed:
        lines.append(
            "**CRITICAL**: Export as PLAIN .txt - NO markdown. "
            "Strip all # headings, ``` fenced code blocks, **bold**, *italic*, "
            "pipe tables, and [text](url) links before pasting. "
            "ASCII characters only (no em-dashes, smart quotes, codepoint > 127)."
        )
    if poc_delivery:
        lines.append(f"**PoC delivery**: {poc_delivery[:300]}")
    lines.append("")

    lines += [
        "**MANDATORY gates (all must hold before promoting staging/ -> paste_ready/):**",
        "",
        (
            "1. Run `bash tools/pre-submit-check.sh <draft>` and iterate until "
            "rc=0 - the FULL gate, not a subset. Promote staging/ -> "
            "paste_ready/ ONLY after rc=0."
        ),
    ]
    if markdown_allowed:
        lines.append(
            "2. PoC MUST be inline in the `.md` body (Hard-do-not #6); also "
            "generate `<slug>-poc.zip` + `<slug>.poc-transcript.txt`. "
            "AST-only / pointer-only PoC = NOT paste-ready."
        )
    else:
        lines.append(
            "2. PoC harness ships as an ATTACHED `<slug>-poc.zip` (NOT inlined). "
            "The .txt body references the zip by filename in section 4. "
            "Executed transcript lines (test result block) ARE kept inline as "
            "plain text in section 3."
        )
    lines += [
        (
            "3. Attempt escalation (Rule 14 / A7) and document the outcome; "
            "never silently settle or overclaim the impact vs the evidence "
            "class actually proven."
        ),
        (
            f"4. Align to the `{platform_id}` template (`{template}`): the "
            "required sections below MUST all be present and platform-correct."
        ),
        "",
    ]
    if sections:
        lines.append(f"**Required sections for `{platform_id}`:**")
        lines.append("")
        for s in sections:
            lines.append(f"- {str(s)[:200]}")
        lines.append("")
    if field_rules:
        lines.append(f"**Platform output rules for `{platform_id}`** (mined from filed artifacts):")
        lines.append("")
        for r in field_rules[:8]:  # cap at 8 rules to keep the section concise
            lines.append(f"- {str(r)[:250]}")
        lines.append("")
    if field_notes:
        lines.append(f"_Platform field-notes_: {field_notes[:600]}")
        lines.append("")
    # Drive-and-Verify Paste-Ready Mandate: appended for every filing-class
    # brief on both injection paths (skeleton-available + skeleton-unavailable)
    # via this single formatter. Inherits filing-only gating for free - context
    # is None for hunt/drill/comp/fuzz, so this line is never reached for them.
    lines += _DRIVE_AND_VERIFY_MANDATE_LINES
    return lines


# ---------------------------------------------------------------------------
# Load-Bearing Assumption Audit (Rule 78 proactive injection)
# r36-rebuttal: lane R78-ASSUMPTION-AUDIT-WIRE registered in
# .auditooor/agent_pathspec.json agents[].
# ---------------------------------------------------------------------------


def _format_load_bearing_assumption_audit_section(*, lane_type: str) -> List[str]:
    """Render the Rule 78 Load-Bearing Assumption Audit block.

    Filing- and hunt-class lanes only (returns [] otherwise). Tells the agent,
    BEFORE claiming any load-bearing mechanism, to list its assumptions and
    verify each against SOURCE or MEASUREMENT - flagging the four out-of-tree
    classes the narrow gates (R76/R77/R42/R46) each cover only partially:
    external-dependency behavior, external-library DEFAULTS, deployment/config,
    and protocol-version / external-chain semantics. The reactive
    pre-submit-check.sh Check #130 enforces the ledger EXISTS + is complete.
    """
    if (lane_type or "").strip().lower() not in LOAD_BEARING_ASSUMPTION_LANE_TYPES:
        return []
    return [
        "## Load-Bearing Assumption Audit (Rule 78)",
        "",
        (
            "_Before you claim ANY load-bearing mechanism (amplification, impact "
            "chain, defense-bypass), list its assumptions and VERIFY each against "
            "SOURCE or MEASUREMENT. A HIGH+ draft is blocked at "
            "pre-submit-check.sh Check #130 unless a 'Load-Bearing Assumption "
            "Ledger' section enumerates them with no UNVERIFIED row._"
        ),
        "",
        "Add this table to the draft (one row per load-bearing assumption):",
        "",
        "| # | Assumption (verbatim) | Class | How verified | Source / measurement |",
        "|---|----------------------|-------|--------------|----------------------|",
        "| 1 | <state it> | <class> | <read source / ran test / cited config> | <file:line OR transcript line OR config path> |",
        "",
        (
            "**Classes**: `in-tree-source` / `external-dep-source` / "
            "`measured-executed` / `config-cited` / `accepted-as-OOS` / "
            "`UNVERIFIED`."
        ),
        "",
        (
            "**Explicitly flag and READ the actual source for any assumption "
            "resting on:**"
        ),
        (
            "- external-dependency runtime behavior (concurrency / batching / "
            "scheduling) - read the dep source under ~/.cargo/registry, "
            "node_modules, go/pkg/mod (-> R77 verifies depth)."
        ),
        (
            "- external-library DEFAULTS not overridden (a config default you "
            "rely on, e.g. a server's max_connections / batch cap) - cite the "
            "default's source line."
        ),
        (
            "- deployment / config assumptions (component registered, pool has "
            "liquidity, role set) - cite the deploy config / live state (-> R42)."
        ),
        (
            "- protocol-version / external-chain semantics (finalization, "
            "reorg depth, opcode behavior) - cite the spec or version."
        ),
        "",
        (
            "Do NOT assume - read the dependency/config source and cite the path. "
            "Any row left `UNVERIFIED` is a required investigation before "
            "promotion (or carry inline `r78-unverified-rebuttal: <reason>`)."
        ),
        "",
    ]


_HARNESS_AUTHORING_SECTION_HEADER = (
    "## Harness-Authoring Honesty Requirements (Rule 80 / R-A..R-E)"
)


def _load_semantic_harness_failure_modes() -> List[Dict[str, str]]:
    """Import the 20 confirmed semantic harness-failure mode seeds from
    tools/harness-failure-memory.py (the accessor Lane C added) and return them
    as a list of {mode, fix} dicts for rendering as "do NOT reproduce" bullets.

    Graceful-degrade: if the sibling module cannot be imported (missing file,
    load error, accessor absent), return [] so the dispatch brief still renders
    its concrete mandates. The import is best-effort and never raises.
    """
    try:
        import importlib.util as _il

        _p = pathlib.Path(__file__).resolve().parent / "harness-failure-memory.py"
        if not _p.is_file():
            return []
        _s = _il.spec_from_file_location("harness_failure_memory", _p)
        if _s is None or _s.loader is None:
            return []
        _m = _il.module_from_spec(_s)
        # Python 3.14: register before exec so a self-referential import resolves.
        sys.modules["harness_failure_memory"] = _m
        _s.loader.exec_module(_m)  # type: ignore[attr-defined]
        accessor = getattr(_m, "semantic_mode_seeds", None)
        if not callable(accessor):
            return []
        out: List[Dict[str, str]] = []
        for seed in accessor():
            if not isinstance(seed, dict):
                continue
            mode = str(seed.get("root_cause_id") or "").strip()
            fix = str(seed.get("known_fix") or "").strip()
            if mode:
                out.append({"mode": mode, "fix": fix})
        return out
    except Exception:
        return []


def _poc_build_env_block(workspace_path) -> List[str]:
    """Surface the ALREADY-PRESENT forge build env (foundry shim + reusable
    poc-tests/chimera harness dirs + forge-std) so a PoC/harness lane does NOT
    re-derive foundry.toml/remappings/node_modules/forge-std (observed recurrence:
    NUVA 2026-06-30 two agents each spent ~10 steps rediscovering it). Delegates to
    tools/poc-harness-bootstrap.py::brief_block. Graceful-degrade to [] on any error."""
    if workspace_path is None:
        return []
    try:
        import importlib.util as _ilu
        _p = pathlib.Path(__file__).resolve().parent / "poc-harness-bootstrap.py"
        _spec = _ilu.spec_from_file_location("poc_harness_bootstrap", _p)
        _m = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_m)
        block = _m.brief_block(pathlib.Path(workspace_path))
        return block.splitlines() if block else []
    except Exception:
        return []


def _format_harness_authoring_requirements_section(
    *, lane_type: str, prompt_text: str = "", workspace_path=None
) -> List[str]:
    """Render the Rule 80 Harness-Authoring Honesty Requirements block.

    Fires only when the lane authors a harness / invariant / coverage / PoC /
    fuzz scaffold (lane_type in HARNESS_AUTHORING_LANE_TYPES OR a harness-ish
    prompt keyword present). Returns [] otherwise.

    The block is the CONCRETE authoring brief from
    agent_outputs/harness_enforcement_2026-06-27/HARNESS_AUTHORING_PLAYBOOK.md
    (sections 0-9): surface-what-is-already-built, attempt-the-violation,
    the variant matrix, the reachability-witness requirement, the
    behavior-changing-mutant rule, the engine-choice rule, the
    do-not-emit-a-sentinel rule, and the done-check. It also renders the 20
    confirmed semantic harness-failure modes (imported from
    tools/harness-failure-memory.py::semantic_mode_seeds, graceful-degrade) as
    "KNOWN HARNESS-FAILURE MODES - do NOT reproduce" bullets. Build it real the
    FIRST time, not patched at submit time. Idempotency is handled by the caller
    (it skips injection when the header already appears in the assembled brief).
    """
    if not is_harness_authoring_lane(lane_type, prompt_text):
        return []
    out: List[str] = [
        _HARNESS_AUTHORING_SECTION_HEADER,
        "",
        (
            "_This lane authors a harness / invariant / coverage / PoC / fuzz "
            "scaffold. Build it real the FIRST time - the mandates below are "
            "gated at submit time by pre-submit Check #131 "
            "(R80-FINDING-EVIDENCE-HONESTY) and at audit-completion by "
            "audit-honesty-check.py._"
        ),
        "",
        # -- Section 0: surface what is already built --------------------------
        "### 0. BEFORE YOU WRITE A LINE - surface what is already built",
        "",
        (
            "A harness corpus that LOOKS large is usually 90% dead sentinels. Do "
            "NOT add to the pile. Run these in the workspace FIRST and paste the "
            "result into your reply:"
        ),
        "",
        "```",
        (
            "python3 tools/lib/harness_vacuity.py --scan src/ chimera_harnesses/ "
            "poc-tests/ --report   # genuine (non-sentinel) harnesses on disk"
        ),
        "ls .auditooor/mvc_sidecar/*.json 2>/dev/null              # already mutation-credited",
        "head .auditooor/inscope_units.jsonl                       # your CUT MUST be in here",
        "```",
        "",
        (
            "- If a GENUINE (non-sentinel) harness already covers your function, "
            "EXTEND it - do NOT emit a new scaffold over it (never run a generator "
            "with --overwrite against a function that already has a real harness)."
        ),
        (
            "- If genuine evidence is on disk but uncredited (serving-join), your "
            "job is to REGISTER it (write the mvc_sidecar entry), not re-author."
        ),
        (
            "- Your CUT path MUST appear in .auditooor/inscope_units.jsonl. "
            "Targeting reference/, vendored OZ, or bare IERC20/IDiamond interfaces "
            "is an out-of-scope (wrong-cut-oos-target) waste."
        ),
        "",
        # -- Section 1: real CUT bound in setUp -------------------------------
        "### 1. THE CUT IS THE REAL IN-SCOPE CONTRACT - bind it in setUp",
        "",
        (
            "- The Contract-Under-Test (CUT) MUST be the REAL in-scope src/ "
            "contract (behind its real proxy if it ships one). Mock ONLY "
            "genuinely-external dependencies (oracle, off-chain relayer key, OOS "
            "collaborator). A mock/reimplementation standing in for the in-scope "
            "CUT is forbidden (R-D)."
        ),
        (
            "- setUp() MUST deploy the real CUT and MUST call bindTarget() / "
            "assign the target. A harness whose target stays address(0) (the "
            "`if(address(target)!=address(0))` dead-CUT-guard) asserts nothing. "
            "Mirror the repo's own test setUp - that is how the genuine harnesses "
            "were built (etherfi CashSolvencyHarness, morpho VaultV2InvariantHandler, "
            "near-intents OmniBridge_FuzzProps)."
        ),
        (
            "- If a constructor needs an address that does not exist yet (ctor "
            "cycle), use CREATE-nonce prediction (polygon sPOLController "
            "_computeCreateAddress) - do NOT stub the CUT to escape it."
        ),
        (
            "- FORBIDDEN: `function setUp() { handler = new Handler(); }` that "
            "never calls bindTarget so every `target.f()` is silently skipped."
        ),
        "",
        # -- Section 2: attempt the violation ---------------------------------
        "### 2. ATTEMPT THE VIOLATION - bound by AVAILABLE BALANCE, not by the valid range",
        "",
        (
            "The handler MUST let the fuzzer ATTEMPT the invariant-violating "
            "action. Bound inputs by what the attacker actually has (token balance "
            "/ idle), NOT by a `cap - headroom` that keeps every call valid. The "
            "baseline reverts on the over-cap attempt; try/catch swallows the "
            "baseline revert; the guard-removal source mutant then lets the action "
            "LAND and the invariant assert FAILS."
        ),
        "",
        "```solidity",
        "// PROVEN morpho VaultV2 mode-2 fix: bound by AVAILABLE BALANCE",
        "function h_deposit(uint256 seed) external {",
        "    uint256 amt = bound(seed, 1, token.balanceOf(address(this))); // NOT cap-headroom",
        "    token.approve(address(vault), amt);",
        "    try vault.deposit(amt, address(this)) { /* ATTEMPT the over-cap action */ }",
        "    catch { /* baseline correctly reverts on over-cap -> swallow, do NOT pre-avoid */ }",
        "}",
        "```",
        "",
        (
            "FORBIDDEN: `bound(x, 1, cap - headroom)` / `bound(x, 1, "
            "rec.cluster.balance)` - any pre-bounding to the always-valid range "
            "means the violation is never attempted (self-bounded-handler)."
        ),
        "",
        # -- Section 3: reachability witness ----------------------------------
        "### 3. PROVE AT LEAST ONE VALUE-MOVING ACTION LANDED (reachability witness)",
        "",
        (
            "Maintain a witness counter / ghost counter incremented ONLY on a "
            "successful state change, and assert each is >0 at least once. This "
            "catches silent-revert-actions (every action reverts in try/catch so "
            "invariants hold trivially) and mock-callpath-vacuity (the value-moving "
            "fn never executes)."
        ),
        "",
        "```solidity",
        "uint256 wBorrow;                                  // reachability witness",
        "function h_borrow(uint256 s) external {",
        "    uint256 a = bound(s, 1, 200_000e6);           // attempt, bound by available",
        "    try debt.borrow(a) { wBorrow++; } catch {}    // count only on SUCCESS",
        "}",
        "function invariant_reachability() public { assertGt(wBorrow, 0); }",
        "```",
        "",
        (
            "If you mock a value-delivery dependency where prod force-sends "
            "(SafeSend/selfdestruct), add receive()/fallback() to the mock CUT "
            "subclass so the value-moving fn actually executes - else its witness "
            "counter stays 0 (the automated backstop fires)."
        ),
        "",
        # -- Section 4: variant matrix ----------------------------------------
        "### 4. VARIANT MATRIX - each variant needs its OWN behavior-changing mutant",
        "",
        (
            "For every value-moving function in your lane, author the applicable "
            "variant invariants below. EACH credited invariant needs its OWN "
            "attributed behavior-changing mutant that KILLS it (a cluster cannot "
            "ride on `mutants_killed>=3` while some invariants have no mutant). "
            "The mutant MUST change behavior (auth/cap/state/guard), NOT be "
            "EVM-enforced (a `+=`->`-=` that only panics is an equivalent-mutant)."
        ),
        "",
        "| Variant | Invariant asserts (REAL storage) | Behavior-changing mutant that MUST kill it |",
        "|---------|----------------------------------|--------------------------------------------|",
        "| Conservation | totalAssets == idle + sum(adapter.realAssets()) | drop a balance decrement / over-credit (+5%) |",
        "| Supply/share monotonicity | convertToAssets(UNIT) non-decreasing | mint extra shares / inflate rate |",
        "| Cap / bound | allocation <= absoluteCap | require(cap) -> require(true) |",
        "| Authorization | only the authorized actor can move funds; forged sig rejected | remove the auth/sig/whenNotPaused guard |",
        "| Custody / solvency | weeth fully-backed; payout credits the CLAIMER | drop the over-release guard / double-release |",
        "| Rounding direction | deposit-then-redeem <= deposited (no free shares) | flip rounding up<->down / +1 share favorable |",
        "| No-replay / uniqueness | completed[id] sticky; nullifier never reused | remove the `completed[id]=true` write |",
        "",
        (
            "Attacker-vs-victim separation (R24/R44): for fund-loss invariants, "
            "instantiate the attacker with its OWN keys and assert the impact "
            "reaches funds the attacker does NOT control."
        ),
        "",
        # -- Section 5: behavior-changing-mutant rule -------------------------
        "### 5. MUTATION-VERIFY EACH INVARIANT - the kill must be a behavior-changing mutant",
        "",
        (
            "Every invariant/property MUST be MUTATION-VERIFIED non-vacuous: "
            "inject a bug into the CUT, confirm the invariant FAILS, restore, "
            "confirm it PASSES. An assert(true) / always-true property is NOT "
            "proof (R-C). Run the oracle and confirm EACH invariant has >=1 "
            "non-panic, behavior-changing kill:"
        ),
        "",
        "```",
        (
            "python3 tools/mutation-verify-coverage.py --harness <Harness.t.sol> "
            "--ws . --require-behavior-changing"
        ),
        "```",
        "",
        (
            "- A kill whose output_tail names only setUp() is a FALSE KILL "
            "(setup-crash-false-kill). The kill must name an "
            "invariant_/property_/echidna_ assertion frame."
        ),
        (
            "- A 1/1 panic-only kill (Panic(0x11)/0x01 underflow/overflow) is an "
            "equivalent-mutant and does NOT count - pick a guard/auth/cap/state "
            "mutant instead."
        ),
        (
            "- If you hand-authored a whole-contract mutant harness "
            "(*_MutantVacuity.t.sol), REGISTER it: "
            "`mutation-verify-coverage.py --register-manual-mvc <path>` (else your "
            "genuine proof is invisible to the gate - serving-join)."
        ),
        "",
        # -- Section 6: engine choice and call budget -------------------------
        "### 6. ENGINE CHOICE AND CALL BUDGET",
        "",
        (
            "- The engine MUST actually execute: an engine-error / no-execution / "
            "build-failure run cannot be cited as evidence (R-B). Resolve harness "
            "deps (tools/foundry-harness-dep-resolve.py) so forge build succeeds."
        ),
        (
            "- READING RESULTS (do not misread): a forge `--- PASS` means EVERY "
            "assertion ran and held, INCLUDING any post-revert / recovery branch. "
            "forge buffers and TRUNCATES the `Logs:` block, so a missing console.log "
            "line does NOT mean that branch did not execute - never infer "
            "'execution stopped early' from an absent log. To confirm a SPECIFIC "
            "branch ran (e.g. an R82 recovery path), read the `-vvv` call trace, not "
            "which logs printed. (NUVA 2026-06-30: a verify lane nearly doubted its "
            "own recovery proof because the recovery console.logs were truncated.)"
        ),
        (
            "- Use echidna for selfdestruct / SafeSend / force-send ETH-delivery "
            "paths - medusa stack-underflows on selfdestruct and a break from a "
            "vm-error trace is NOT a finding. Grep the CUT for "
            "selfdestruct/SafeSend; if present, do NOT credit a medusa-only "
            "campaign. medusa otherwise (coverage-guided, fast)."
        ),
        (
            "- CALL BUDGET: >= 1,000,000 calls, seqLen >= 50 for the credited "
            "step-2c campaign. A 500K run or a status=skipped dry-run does NOT "
            "count. Verify the executed call count in the campaign artifact "
            "yourself - do NOT defer the 1,000,000 run to an orchestrator you "
            "cannot confirm ran."
        ),
        (
            "- Coverage claims count only REAL in-scope, REVIEWED-or-fuzzed units. "
            "Budget-skipped or vendored-dep units do NOT count as covered (R-A, "
            "R-E). Do NOT emit a Solidity .t.sol wrapper for a .rs/.cairo/.move "
            "CUT - route cross-language CUTs to a cargo/proptest harness."
        ),
        "",
        # -- Section 7/8: do-not-emit-a-sentinel ------------------------------
        "### 7. DO-NOT-EMIT-A-SENTINEL rule",
        "",
        (
            "Never emit assert(true), assertTrue(false, \"TODO\"), `a>=b||b>=a`, "
            "or a `controlCase && realInvariant` where controlCase is a reflexive "
            "tautology. If you lack the pre-flight pack / source-grounded "
            "property, REPORT the blocker (honest-negative) - do NOT emit a "
            "scaffold counted in the coverage denominator. An assert(true) / "
            "always-true property is NOT proof."
        ),
        "",
        # -- Section 9: done-check --------------------------------------------
        "### 9. DONE-CHECK - run before you reply",
        "",
        "```",
        "python3 tools/harness-author-accept.py --harness <path> --ws .",
        "```",
        "",
        (
            "It must print `pass-harness-accept`: real CUT bound in setUp; >=1 "
            "witness counter asserted >0; each invariant killed by an attributed "
            "non-panic behavior-changing mutant; no sentinel/tautology body; "
            "engine = echidna if selfdestruct; >= 1,000,000 calls; CUT path in "
            "inscope_units.jsonl; sidecar registered. Your reply MUST paste the "
            "`pass-harness-accept` line - \"I built a harness\" is intent, not "
            "result (L26). This brief is gated at submit time by pre-submit Check "
            "#131 (R80-FINDING-EVIDENCE-HONESTY) and at audit-completion by "
            "audit-honesty-check.py."
        ),
        "",
    ]

    # Inject the ALREADY-BUILT forge env right under Section 0 so the agent reuses
    # it instead of re-deriving foundry.toml/remappings/forge-std (NUVA recurrence).
    env_block = _poc_build_env_block(workspace_path)
    if env_block:
        try:
            idx = out.index(
                "### 0. BEFORE YOU WRITE A LINE - surface what is already built"
            ) + 1
        except ValueError:
            idx = len(out)
        out[idx:idx] = ["", *env_block]

    # -- KNOWN HARNESS-FAILURE MODES (semantic-mode seeds from Lane C) --------
    modes = _load_semantic_harness_failure_modes()
    if modes:
        out.append(
            "### KNOWN HARNESS-FAILURE MODES - do NOT reproduce"
        )
        out.append("")
        out.append(
            "These are the confirmed harness-vacuity / false-coverage modes "
            "observed across morpho, ssv-network, etherfi, near-intents, "
            "polygon, and beanstalk. Each carries its proven fix:"
        )
        out.append("")
        for entry in modes:
            mode = entry["mode"]
            fix = entry["fix"] or "(see docs/HARNESS_FAILURE_TAXONOMY.md)"
            out.append(f"- {mode}: {fix}")
        out.append("")

    return out


# --------------------------------------------------------------------------
# Rule 81 depth-layer mandate (audit / hunt / harness lanes).
#
# Audit and hunt lanes must run the per-UNIT depth layer, not just per-surface
# coverage: per-guard NEGATIVE-SPACE ("what does each guard NOT check?") +
# proactive SIBLING-PATH guard-diff (claim/finalize, sender/receiver, ...).
# And: 0 findings is a SMELL, not a success - a no-finding outcome is only
# honest WHEN the depth passes ran with evidence. This block lands the mandate
# UP FRONT so the worker runs the depth layer the first time. Submit-time gate:
# pre-submit Check #132 (R81-DEPTH-COVERAGE-FINDING); audit-completion gate: L37
# fail-no-depth-certificate + audit-honesty-check fail-depth-not-run.
# --------------------------------------------------------------------------
_DEPTH_LAYER_SECTION_HEADER = (
    "## Depth-Layer Requirements (Rule 81 / negative-space + sibling-diff)"
)

# Lane types whose lane runs/owns the audit or hunt surface (depth layer applies).
DEPTH_LAYER_LANE_TYPES = frozenset(
    {"hunt", "drill", "comp", "audit", "audit-deep", "deep"}
)

# Prompt keywords that indicate an audit / hunt lane even when lane_type misses.
DEPTH_LAYER_PROMPT_KEYWORDS = (
    "audit-deep",
    "audit deep",
    "make audit",
    "negative-space",
    "negative space",
    "sibling-path",
    "sibling path",
    "guard-diff",
    "guard diff",
    "depth certificate",
    "full audit",
    "hunt the",
    "audit the",
)


def is_depth_layer_lane(lane_type: str, prompt_text: str = "") -> bool:
    """True when the lane runs an audit / hunt surface that the depth layer
    (per-guard negative-space + sibling-path guard-diff) applies to - either by
    lane_type membership, by harness-authoring membership (a harness lane that
    builds the depth evidence), or by prompt-keyword detection."""
    lt = (lane_type or "").strip().lower()
    if lt in DEPTH_LAYER_LANE_TYPES:
        return True
    if is_harness_authoring_lane(lane_type, prompt_text):
        return True
    lower = (prompt_text or "").lower()
    return any(kw in lower for kw in DEPTH_LAYER_PROMPT_KEYWORDS)


def _format_depth_layer_requirements_section(
    *, lane_type: str, prompt_text: str = ""
) -> List[str]:
    """Render the Rule 81 Depth-Layer Requirements block.

    Fires for audit / hunt / harness lanes (is_depth_layer_lane). Returns []
    otherwise. Idempotency is handled by the caller (skip when the header is
    already in the assembled brief)."""
    if not is_depth_layer_lane(lane_type, prompt_text):
        return []
    return [
        _DEPTH_LAYER_SECTION_HEADER,
        "",
        (
            "_This audit / hunt lane MUST run the per-UNIT depth layer, not just "
            "per-surface coverage. Run it the FIRST time - it is gated at "
            "submit time by pre-submit Check #132 (R81-DEPTH-COVERAGE-FINDING) "
            "and at audit-completion by L37 `fail-no-depth-certificate` + "
            "audit-honesty-check `fail-depth-not-run`._"
        ),
        "",
        (
            "- Run the per-guard NEGATIVE-SPACE pass: for every in-scope guard / "
            "validation, ask what it does NOT check - can an input pass the guard "
            "yet violate the invariant it protects? "
            "(`make audit-depth WS=<ws>` runs guard-negative-space-analyzer + "
            "sibling-path-guard-diff + depth-certificate-check)."
        ),
        (
            "- Run the proactive SIBLING-PATH guard-diff: enumerate sibling code "
            "paths (claim/finalize, sender/receiver, deposit/withdraw, mint/burn, "
            "lock/unlock, propose/execute, escrow/release, vote/tally) and diff "
            "the two paths' guards. An asymmetry (guard present on path A, absent "
            "on path B) is a candidate finding."
        ),
        (
            "- Every surviving incomplete-guard delta / sibling asymmetry MUST "
            "carry an exploitation-attempt artifact (PoC path) OR a source-cited "
            "ruled-out reason. A delta with no disposition is unfinished work."
        ),
        (
            "- 0 findings is a SMELL, not a success. A no-finding outcome is only "
            "honest WHEN both depth passes RAN WITH EVIDENCE and the cert at "
            ".auditooor/depth_certificate.json clears the zero-findings smell."
        ),
        "",
    ]


# --------------------------------------------------------------------------
# Rule 82 phase-1 adversarial-recovery falsification (impact / dispute lanes).
#
# Every existing impact/defense gate (R24 non-self-impact, R25 defense-in-depth,
# R29 commitment-vs-validation, R40 V3-grade-PoC, R44 opposed-trace, R57
# exhaustive-defense-chain) asserts a fact AT OR BEFORE the impact commit. NONE
# asks whether, AFTER the bad state is realized, the victim restores themselves
# in-protocol. R82 owns that post-impact victim-recovery axis. This block lands
# the mandate UP FRONT so the worker runs phase-1 recovery FALSIFICATION BEFORE
# writing the attack PoC: a live un-falsified recovery path makes the
# "permanent loss/freeze/theft" claim false (the victim was made whole), so the
# attack should not be built until every recovery hypothesis is falsified.
# Submit-time gate: tools/impact-recovery-falsification-check.py (R82).
# --------------------------------------------------------------------------
_ADVERSARIAL_RECOVERY_SECTION_HEADER = (
    "## Phase-1 Adversarial Recovery Falsification (Rule 82)"
)

# Lane types where a loss / freeze / theft / unauthorized-stuck-state impact is
# claimed or disputed - the dispute / filing family plus the hunt-class set (so
# recovery is falsified while the impact chain is being built, not just at
# submit time). Mirrors LOAD_BEARING_ASSUMPTION_LANE_TYPES coverage so R82 lands
# on the same impact-bearing briefs Rule 78 does.
ADVERSARIAL_RECOVERY_LANE_TYPES = (
    FILING_FINALIZATION_LANE_TYPES
    | HUNT_BRIEF_COMPLETENESS_LANE_TYPES
    | {"dispute", "mediation"}
)

# Prompt keywords that indicate an impact / loss / freeze / theft / dispute lane
# even when the inferred lane_type is a generic "filing" / "hunt" (matched
# case-insensitively). These catch the impact CLAIM in the prompt body so the
# falsification block fires on the briefs that actually assert permanent harm.
ADVERSARIAL_RECOVERY_PROMPT_KEYWORDS = (
    "loss of funds",
    "fund loss",
    "direct loss",
    "theft of funds",
    "stolen",
    "drain",
    "freez",  # freeze / freezing / frozen
    "frozen",
    "permanent",
    "irrecoverable",
    "irreversible",
    "stuck funds",
    "stranded",
    "locked funds",
    "unrecoverable",
    "victim",
    "dispute",
    "walk-back",
    "walk_back",
)


def is_adversarial_recovery_lane(lane_type: str, prompt_text: str = "") -> bool:
    """True when the lane claims / disputes a loss / freeze / theft impact that
    the phase-1 victim-recovery falsification (Rule 82) applies to - either by
    lane_type membership or by impact-claim prompt-keyword detection."""
    if (lane_type or "").strip().lower() in ADVERSARIAL_RECOVERY_LANE_TYPES:
        return True
    lower = (prompt_text or "").lower()
    return any(kw in lower for kw in ADVERSARIAL_RECOVERY_PROMPT_KEYWORDS)


def _format_adversarial_recovery_falsification_section(
    *, lane_type: str, prompt_text: str = "", workspace_path: Optional[pathlib.Path] = None
) -> List[str]:
    """Render the Rule 82 Phase-1 Adversarial Recovery Falsification block.

    Fires only for impact / loss / freeze / theft / dispute lanes
    (is_adversarial_recovery_lane). Returns [] otherwise. The block instructs
    the worker, BEFORE writing the attack PoC, to enumerate the victim's
    in-protocol recovery surfaces, try to PROVE the victim recovers, and only
    build the attack once every recovery hypothesis is FALSIFIED. If a recovery
    survives, the worker emits the `sv-falsifies` marker and STOPS. Idempotency
    is handled by the caller (skip when the header already appears in the
    assembled brief).
    """
    if not is_adversarial_recovery_lane(lane_type, prompt_text):
        return []
    ws = str(workspace_path) if workspace_path else "<ws>"
    return [
        _ADVERSARIAL_RECOVERY_SECTION_HEADER,
        "",
        (
            "_ADVERSARIAL-RECOVERY-FIRST: this lane claims or disputes a "
            "permanent loss / freeze / theft / unauthorized-stuck-state impact. "
            "BEFORE you write the attack PoC, try to PROVE the victim RECOVERS "
            "in-protocol after the bad state is realized. A live un-falsified "
            "recovery path makes the 'permanent loss' claim FALSE (the victim "
            "was made whole). Submit-time gate: "
            "tools/impact-recovery-falsification-check.py (Rule 82)._"
        ),
        "",
        "Do this FIRST, in order:",
        "",
        (
            "1. Enumerate the victim's in-protocol recovery surfaces - run:"
        ),
        "",
        "```",
        (
            "python3 tools/impact-recovery-falsification-check.py "
            "--emit-recovery-worklist " + ws
        ),
        "```",
        "",
        (
            "2. For EACH listed recovery surface, try to PROVE the victim "
            "recovers (drive the recovery path in the PoC, or source-trace it "
            "to a working refund / re-claim / sweep / withdraw / unlock)."
        ),
        (
            "3. ONLY build the attack PoC if EVERY recovery hypothesis is "
            "FALSIFIED - each recovery path must FAIL when driven for the "
            "victim, or be source-traced as unreachable. A surviving recovery "
            "path means the impact is not permanent; do NOT build the attack."
        ),
        (
            "4. If a recovery SURVIVES (the victim can self-cure), emit this "
            "marker and STOP - do not write the attack:"
        ),
        "",
        "```",
        (
            "<!-- sv-falsifies: <claim> | axis:victim-recovery | "
            "recovery:<file:line> -->"
        ),
        "```",
        "",
        (
            "When you DO proceed, the draft must carry a `Victim Recovery "
            "Enumeration` section: one row per recovery surface showing it "
            "FAILS for the victim (driven in PoC) or is unreachable "
            "(source-traced with file:line). This is the inverse of R57's "
            "defender table - R57 enumerates the defender's pre-impact "
            "stop-the-attack paths; R82 enumerates the victim's post-impact "
            "self-cure paths."
        ),
        "",
    ]


# --------------------------------------------------------------------------
# Per-Impact Hunting Methodology (how THIS impact class is actually found).
#
# This INVERTS the per-impact playbook corpus
# (audit/corpus_tags/impact_hunting_methodology.yaml, schema
# auditooor.impact_hunting_methodology.v1, 32 mined impact_ids) into a
# hunt-time brief, the same way _format_harness_authoring_requirements_section
# inverts the harness playbook and _format_adversarial_recovery_falsification_
# section inverts the R82 submit gate. The hunter is handed the critical_paths,
# attack_surface, impact-specific hacker_questions + kill_conditions, caveats,
# and severity_mapping for the impact class the lane is actually chasing -
# instead of generic DeFi carryover. For a Go/cosmos consensus target the
# chain-halt-shutdown playbook attaches; for a DeFi vault target the
# direct-theft / share-inflation playbooks attach and chain-halt does NOT
# (contract-kind gated). Submit-time companions: Check #31 program-impact-
# mapping (rubric-row match), R82 (#132) recovery, R35 (#90) dos-reframe.
#
# Mirrors the harness-section wiring: header const (idempotency key) +
# is_..._lane gate + a _format_..._section renderer + an idempotent append at
# both assembly points. Additive: a non-impact lane gets [] (no behavior
# change). Graceful-degrade: a missing / corrupt corpus renders the generic
# "identify your target impact class first" stub, never raises.
# --------------------------------------------------------------------------
_IMPACT_METHODOLOGY_SECTION_HEADER = (
    "## Per-Impact Hunting Methodology (how this impact class is actually found)"
)

_IMPACT_HUNTING_METHODOLOGY_PATH = (
    REPO / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
)

# Lane types that hunt / prove / convert a specific impact class. A union with
# the harness + depth lane sets so the methodology lands on the same impact-
# bearing briefs those do.
IMPACT_METHODOLOGY_LANE_TYPES = frozenset(
    {
        "hunt",
        "audit",
        "audit-deep",
        "deep",
        "drill",
        "comp",
        "exploit-conversion",
        "harness",
        "invariant",
        "poc",
        "prove",
    }
)

# Prompt keywords that indicate an impact-hunting lane even when the inferred
# lane_type is a generic "filing" / "dispute" (matched case-insensitively
# against the prompt body so the methodology fires on the briefs that actually
# chase an impact class).
IMPACT_METHODOLOGY_PROMPT_KEYWORDS = (
    "impact",
    "exploit",
    "theft",
    "steal",
    "drain",
    "freez",  # freeze / frozen / freezing
    "frozen",
    "halt",
    "insolven",
    "manipulation",
    "mint",
    "inflation",
    "replay",
    "reentran",
    "liquidation",
    "double spend",
    "double-spend",
)


def is_impact_methodology_lane(lane_type: str, prompt_text: str = "") -> bool:
    """True when the lane hunts / proves / converts a specific impact class -
    either by lane_type membership or by impact-keyword presence in the
    prompt. Mirrors is_harness_authoring_lane / is_adversarial_recovery_lane.
    """
    if (lane_type or "").strip().lower() in IMPACT_METHODOLOGY_LANE_TYPES:
        return True
    lower = (prompt_text or "").lower()
    return any(kw in lower for kw in IMPACT_METHODOLOGY_PROMPT_KEYWORDS)


# Ordered most-specific-first impact-class inference rules. The first rule whose
# keyword appears in (prompt + scope) text wins; "" when none matches. The ids
# are exactly the 32 mined impact_ids in
# audit/corpus_tags/impact_hunting_methodology.yaml (so the inferred id always
# resolves to a real playbook).
_IMPACT_KEYWORD_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("chain-split-fork", ("chain split", "consensus fork", "state divergence", "apphash")),
    ("chain-halt-shutdown", ("chain halt", "node halt", "network shutdown", "liveness", "block production stops", "total network shutdown")),
    ("bc-consensus-transient-failure", ("transient consensus", "rejected proposed block", "proposal rejected")),
    ("bc-permanent-freeze-hardfork", ("hardfork", "hard fork", "permanent network freeze")),
    ("bc-node-resource-exhaustion", ("node resource exhaustion", "node oom", "validator oom", "memory exhaustion")),
    ("bc-rpc-api-crash", ("rpc crash", "rpc api crash", "api node crash")),
    ("bc-direct-loss-of-funds", ("blockchain direct loss", "bc direct loss")),
    ("bridge-cross-chain-drain", ("bridge drain", "cross-chain drain", "bridge theft", "bridge funds")),
    ("cross-chain-replay-double-spend", ("cross-chain replay", "double spend", "double-spend")),
    ("signature-replay-forgery", ("signature replay", "sig forgery", "signature forgery", "permit replay")),
    ("unauthorized-mint", ("unauthorized mint", "infinite mint", "mint without", "arbitrary mint")),
    ("share-supply-inflation", ("share inflation", "first depositor", "first-depositor", "donation attack", "share-price")),
    ("oracle-manipulation", ("oracle manipulation", "price manipulation", "stale price", "oracle price")),
    ("liquidation-abuse", ("liquidation abuse", "self-liquidat", "wrongful liquidation", "liquidation manipulation")),
    ("governance-manipulation", ("governance capture", "governance takeover", "vote manipulation", "proposal hijack", "governance manipulation")),
    ("permanent-freeze-yield", ("permanent freeze yield", "stranded yield", "yield permanently")),
    ("theft-unclaimed-yield", ("unclaimed yield", "theft of yield", "reward theft", "yield theft", "reward redirect")),
    ("permanent-freeze-funds", ("permanent freeze", "permanently locked", "funds stuck forever", "irrecoverable freeze")),
    ("temporary-freeze-funds", ("temporary freeze", "funds locked temporarily", "temporarily frozen")),
    ("protocol-insolvency", ("insolven", "bad debt", "undercollateral", "protocol insolvency")),
    ("reentrancy", ("reentran",)),
    ("gas-theft-fee-vault", ("gas theft", "fee vault theft", "fee-vault")),
    ("griefing-dos-blockstuffing", ("block stuffing", "block-stuffing", "griefing", "block stuff")),
    ("operability-lack-of-funds", ("lack of funds", "inoperable", "contract insolvent of gas")),
    ("dispute-game-resolution", ("dispute game", "dispute-game", "fault dispute", "game resolution")),
    ("unauthorized-upgrade-impl-swap", ("unauthorized upgrade", "impl swap", "implementation swap", "proxy upgrade")),
    ("crypto-key-recovery-leak", ("key recovery", "nonce reuse", "private key leak", "key leak")),
    ("crypto-incorrect-formula-verifier", ("verifier soundness", "incorrect formula", "proof verifier bug", "verifier bug")),
    ("arithmetic-precision-corruption", ("precision loss", "rounding corruption", "arithmetic precision", "rounding direction")),
    ("fails-promised-returns", ("fails promised", "promised returns", "underdelivers yield")),
    ("access-control-bypass", ("access control bypass", "missing modifier", "unauthorized call", "auth bypass")),
    ("direct-theft-funds", ("theft of funds", "direct theft", "drain funds", "steal funds", "steal", "theft")),
)

# Contract-kind inference: FALLBACK ONLY.
#
# The canonical contract-kind inference lives in the renderer
# (hacker_question_renderer._CONTRACT_KIND_RULES, consumed via
# classify_impact_target). `_infer_contract_kind` below delegates to the
# renderer so the dispatch section partitions impacts EXACTLY as the renderer
# does (single source of truth). These local rules are used ONLY when the
# renderer module cannot be imported, so the dispatch brief still degrades to a
# coarse partition instead of raising. They intentionally emit the renderer's
# canonical family tokens (`amm`, `zk-circuit`) - NOT the old divergent
# `amm-dex` / `zk-verifier` - so even the degraded path stays consistent with
# the renderer's attach vocabulary (the G5 divergence the fork introduced).
_CONTRACT_KIND_RULES_FALLBACK: Tuple[Tuple[str, str], ...] = (
    ("consensus", r"consensus|tendermint|cometbft|abci|baseapp|finalizeblock|finalize block|finalizecommit|fork-choice|block production|beginblock|endblock"),
    ("bridge", r"bridge|cross-chain|lzreceive|ccipreceive|relayer|messageid|portal|\bism\b"),
    ("amm", r"\bamm\b|swap|liquidity pool|x\*y=k|uniswap|curve|balancer"),
    ("lending", r"lending|borrow|collateral|liquidat|health factor|aave|compound|morpho"),
    ("vault", r"erc4626|\bvault\b|converttoshares|totalassets|previewdeposit"),
    ("governance", r"govern|proposal|votingpower|timelock|quorum"),
    ("staking", r"\bstak|validator|delegat|operator|cluster|slashing"),
    ("zk-circuit", r"verifier|nullifier|groth16|plonk|attestation|\bproof\b"),
)


def infer_target_impact_class(prompt_text: str = "", scope_text: str = "") -> str:
    """Infer the single impact_id this lane targets from prompt + scope text.

    Ordered, most-specific-first; "" when nothing matches. Net-new (the
    dispatch analog of which-impact-is-this-lane-chasing). Every returned id is
    a real impact_id in audit/corpus_tags/impact_hunting_methodology.yaml.
    """
    blob = f"{prompt_text}\n{scope_text}".lower()
    for impact_id, kws in _IMPACT_KEYWORD_RULES:
        if any(kw in blob for kw in kws):
            return impact_id
    return ""


def _infer_contract_kind(*, prompt_text: str = "", scope_text: str = "") -> str:
    """Infer a contract_kind from prompt + scope text.

    SINGLE SOURCE OF TRUTH: delegates to the renderer's
    ``classify_impact_target`` (which owns ``_CONTRACT_KIND_RULES``) so the
    dispatch section partitions impacts EXACTLY as ``render_impact_questions``
    does. The renderer scans ``scope_text + signature + name``; we pass the
    prompt as the signature/name blob and the scope text as scope so the same
    rules fire. First match wins, "" if none.

    Graceful-degrade: when the renderer is unimportable, fall back to the local
    ``_CONTRACT_KIND_RULES_FALLBACK`` (same canonical tokens) instead of raising.
    """
    rend = _renderer()
    classify = getattr(rend, "classify_impact_target", None) if rend else None
    if callable(classify):
        try:
            res = classify(
                prompt_text,  # function_name blob (carries prompt verbs)
                "",  # function_signature
                scope_text=scope_text,
            )
            if isinstance(res, dict):
                return str(res.get("contract_kind") or "").strip().lower()
        except Exception:
            pass
    blob = f"{scope_text}\n{prompt_text}".lower()
    for kind, pat in _CONTRACT_KIND_RULES_FALLBACK:
        if re.search(pat, blob):
            return kind
    return ""


def _infer_workspace_language(
    workspace_path: Optional[pathlib.Path],
    *,
    max_files_scanned: int = 600,
) -> str:
    """Infer the workspace's dominant source language for impact partition.

    Reuses the same source-tree shape the defense-surface scan walks
    (``_DEFENSE_SOURCE_ROOTS`` + ``_DEFENSE_SOURCE_EXTS`` + the
    ``_DEFENSE_EXCLUDE_DIRS`` filter), counts the in-scope source-file
    extensions, and returns the dominant ext-derived language token NORMALIZED
    to the impact corpus' ``applies_to_languages`` vocabulary via the renderer's
    ``language_alias`` (``.sol``/``.vy`` -> ``solidity``, ``.rs`` -> ``rust``,
    ``.go`` -> ``go``, ``.cairo`` -> ``cairo``, ``.move`` -> ``move``).

    The returned language is the EXCLUSION key the playbook language guard uses:
    a Solidity workspace returns ``"solidity"``, which excludes every
    ``[go, rust]``-only chain-halt / bc-* playbook (FAIL-CLOSED partition) while
    admitting the DeFi playbooks that list ``solidity``. Returns ``""`` (admit
    all - never over-drop) when the workspace is absent or no in-scope source
    file is found, so the section degrades exactly like the renderer's empty-
    language admit-all default.
    """
    if workspace_path is None or not workspace_path.is_dir():
        return ""
    # Extend the defense-scan ext map with the corpus' other source languages so
    # a cairo / move / zk workspace also partitions correctly. These tokens are
    # normalized through language_alias below.
    ext_map: Dict[str, str] = dict(_DEFENSE_SOURCE_EXTS)
    ext_map.setdefault(".cairo", "cairo")
    ext_map.setdefault(".move", "move")
    ext_map.setdefault(".nr", "noir")
    ext_map.setdefault(".circom", "circom")
    ext_map.setdefault(".leo", "leo")

    roots: List[pathlib.Path] = []
    for name in _DEFENSE_SOURCE_ROOTS:
        cand = workspace_path / name
        if cand.is_dir():
            roots.append(cand)
    if not roots:
        roots = [workspace_path]

    counts: Dict[str, int] = {}
    scanned = 0
    done = False
    for root in roots:
        if done:
            break
        try:
            walker = sorted(root.rglob("*"))
        except OSError:
            continue
        for path in walker:
            if scanned >= max_files_scanned:
                done = True
                break
            try:
                if not path.is_file():
                    continue
            except OSError:
                continue
            lang = ext_map.get(path.suffix.lower())
            if lang is None:
                continue
            parts = {p.lower() for p in path.parts}
            if parts & _DEFENSE_EXCLUDE_DIRS:
                continue
            if lang == "rust":
                stem = path.stem.lower()
                if stem in _DEFENSE_EXCLUDE_RUST_STEMS or stem.endswith("_test"):
                    continue
            counts[lang] = counts.get(lang, 0) + 1
            scanned += 1
    if not counts:
        return ""
    dominant = max(counts, key=lambda k: counts[k])
    # Normalize the ext-derived token (e.g. "evm") onto the corpus vocabulary
    # ("solidity") via the renderer's alias table - the SINGLE SOURCE OF TRUTH
    # the renderer's render_impact_questions uses. Degrade to a local alias only
    # if the renderer is unimportable.
    rend = _renderer()
    alias = getattr(rend, "language_alias", None) if rend else None
    if callable(alias):
        try:
            return str(alias(dominant) or "").strip().lower()
        except Exception:
            pass
    # Degraded local alias (mirrors the renderer's _LANGUAGE_ALIAS subset).
    local = {
        "evm": "solidity",
        "sol": "solidity",
        "vy": "vyper",
        "rs": "rust",
        "golang": "go",
    }
    return local.get(dominant, dominant)


def load_impact_playbooks(
    path: Optional[pathlib.Path] = None,
) -> List[Dict[str, Any]]:
    """Load the per-impact hunting-methodology playbooks corpus.

    Reads audit/corpus_tags/impact_hunting_methodology.yaml (top key
    ``playbooks:``) and returns the list of playbook dicts, each requiring a
    non-empty ``impact_id``. Graceful-degrade: returns [] on any error
    (missing file, corrupt YAML, PyYAML absent) - the dispatch brief must never
    raise on a missing / corrupt corpus. Mirrors load_economic_primitives
    (tools/hacker_question_renderer.py).
    """
    p = path if path is not None else _IMPACT_HUNTING_METHODOLOGY_PATH
    try:
        import yaml  # local import: dispatch must not hard-depend on PyYAML

        if not pathlib.Path(p).is_file():
            return []
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return []
        rows = data.get("playbooks", [])
        if not isinstance(rows, list):
            return []
        out: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if not str(row.get("impact_id") or "").strip():
                continue
            out.append(row)
        return out
    except Exception:
        return []


def _impact_playbook_attaches(
    playbook: Dict[str, Any],
    *,
    language: str = "",
    contract_kind: str = "",
) -> bool:
    """Union-of-optional-filters attach predicate (mirrors the renderer).

    A playbook's ``applies_to_languages`` / ``applies_to_contract_kinds``, when
    present and non-empty, must contain the target's language / contract_kind -
    UNLESS the target value is "" (unknown -> do not exclude). Absent / empty
    filters never exclude. This is what lets the consensus-gated chain-halt
    playbook stay OFF a DeFi target while the EVM playbooks attach on any kind.
    """
    langs = playbook.get("applies_to_languages") or []
    if isinstance(langs, list) and langs:
        lang = (language or "").strip().lower()
        if lang and lang not in {str(x).strip().lower() for x in langs}:
            return False
    kinds = playbook.get("applies_to_contract_kinds") or []
    if isinstance(kinds, list) and kinds:
        kind = (contract_kind or "").strip().lower()
        if kind:
            # SINGLE SOURCE OF TRUTH: normalize BOTH the target kind and the
            # playbook's fine kinds to their canonical FAMILY via the renderer's
            # kind_family, then intersect - exactly as render_impact_questions
            # does. This lets a coarse inferred kind (e.g. `lending`) admit a
            # playbook authored against a FINE kind (e.g. `cdp-vault`,
            # `lending-market`), so the dispatch path and the renderer agree.
            rend = _renderer()
            kind_family = (
                getattr(rend, "kind_family", None) if rend else None
            )
            if callable(kind_family):
                try:
                    tgt_fam = kind_family(kind)
                    pb_fams = {
                        kind_family(str(x))
                        for x in kinds
                        if str(x).strip()
                    }
                    if tgt_fam and tgt_fam not in pb_fams:
                        return False
                    return True
                except Exception:
                    pass
            # Degraded path: literal lower-cased membership.
            if kind not in {str(x).strip().lower() for x in kinds}:
                return False
    return True


def select_lane_impact_playbooks(
    playbooks: List[Dict[str, Any]],
    *,
    prompt_text: str = "",
    language: str = "",
    contract_kind: str = "",
    max_playbooks: int = 6,
) -> List[Dict[str, Any]]:
    """Select the impact playbooks that apply to THIS lane, partition-aligned
    with the renderer's ``render_impact_questions`` kind/language attach.

    The previous lane brief derived a SINGLE impact id from a prompt keyword
    (``infer_target_impact_class``) and language was never consulted, so the
    renderer's per-fn attach (which surfaces EVERY playbook whose
    ``applies_to_contract_kinds`` family matches the target kind, with language
    as an EXCLUSION guard) and the lane brief diverged: an SSV lending/Solidity
    workspace got a single keyword-matched impact (and, when the prompt named a
    consensus verb, even chain-halt) instead of the full liquidation-abuse +
    direct-theft + permanent-freeze + oracle + reward set.

    This selector uses the SAME predicate the renderer uses:
      - language EXCLUSION via ``_impact_playbook_attaches`` (a Solidity ws ->
        every ``[go, rust]``-only chain-halt / bc-* playbook is dropped;
        FAIL-CLOSED), and
      - contract-kind FAMILY attach via ``_impact_playbook_attaches`` (kind_family
        reconciliation), so a coarse inferred kind admits a playbook authored
        against a FINE kind in the same family.

    The prompt-keyword-inferred id (``infer_target_impact_class``) is kept as an
    ADDITIONAL ranking signal: when it resolves to an admitted playbook it is
    placed FIRST so the lane's named target leads, then the remaining
    kind/language-admitted playbooks follow (stable corpus order). Returns at
    most ``max_playbooks`` dicts; ``[]`` when nothing is admitted (caller renders
    the generic stub). When ``contract_kind`` is "" (unknown) the kind arm
    admits nothing, so only the prompt-keyword id (if admitted by language) is
    returned - never over-attaching every DeFi impact to an unclassified target.
    """
    if not playbooks:
        return []
    # Kind/language-admitted set. A playbook is admitted only when its (optional)
    # language filter admits the ws language AND its contract-kind family
    # includes the inferred kind. We require a KNOWN kind for the kind arm so an
    # unclassified target does not pull every DeFi impact.
    kind_lc = (contract_kind or "").strip().lower()
    admitted: List[Dict[str, Any]] = []
    if kind_lc:
        for pb in playbooks:
            kinds = pb.get("applies_to_contract_kinds") or []
            # Only kind-bearing playbooks attach on the kind arm; a kind-less
            # playbook would otherwise attach to every target (the renderer
            # gates those on shape, which the lane brief has no per-fn shape for).
            if not (isinstance(kinds, list) and kinds):
                continue
            if _impact_playbook_attaches(
                pb, language=language, contract_kind=contract_kind
            ):
                admitted.append(pb)

    # Prompt-keyword-inferred id as the lead signal (when language-admitted).
    by_id = {str(pb.get("impact_id") or ""): pb for pb in playbooks}
    keyword_id = infer_target_impact_class(prompt_text)
    lead_id = ""
    if keyword_id:
        cand = by_id.get(keyword_id)
        if cand is not None and _impact_playbook_attaches(
            cand, language=language, contract_kind=contract_kind
        ):
            lead_id = keyword_id

    # Rank the kind-admitted playbooks by prompt-token relevance so a prompt that
    # names an impact theme (e.g. "liquidation") floats the matching playbook
    # (liquidation-abuse) into the top-N even when the strict keyword rule did
    # not fire. The exact keyword-inferred id (if any) always leads. The score is
    # a token-overlap count between the prompt and each playbook's
    # impact_id / title / keywords; ties keep corpus order (stable).
    prompt_tokens = {
        t for t in re.split(r"[^a-z0-9]+", (prompt_text or "").lower()) if len(t) >= 4
    }

    def _kind_directness(pb: Dict[str, Any]) -> int:
        # 0 = the inferred kind appears LITERALLY in a listed kind (e.g. inferred
        # "vault" in "erc4626-vault"/"cdp-vault") -> kind-native, ranks first;
        # 1 = the playbook only attaches via family-expansion of an unrelated
        # fine kind (e.g. "settlement"->vault family). This floats kind-native
        # DeFi impacts (direct-theft / freeze) above family-tangential ones
        # (bridge-drain via "settlement") for a plain vault target, while still
        # surfacing the family matches below them.
        if not kind_lc:
            return 1
        kinds = pb.get("applies_to_contract_kinds") or []
        if isinstance(kinds, list):
            for k in kinds:
                if kind_lc in str(k).strip().lower():
                    return 0
        return 1

    def _relevance(pb: Dict[str, Any]) -> int:
        hay_parts = [
            str(pb.get("impact_id") or ""),
            str(pb.get("title") or ""),
        ]
        kws = pb.get("keywords") or pb.get("prompt_keywords") or []
        if isinstance(kws, list):
            hay_parts.extend(str(k) for k in kws)
        hay = " ".join(hay_parts).lower()
        hay_tokens = {
            t for t in re.split(r"[^a-z0-9]+", hay) if len(t) >= 4
        }
        return len(prompt_tokens & hay_tokens)

    indexed = list(enumerate(admitted))
    indexed.sort(
        key=lambda pair: (
            0 if str(pair[1].get("impact_id") or "") == lead_id else 1,
            -_relevance(pair[1]),
            _kind_directness(pair[1]),
            pair[0],
        )
    )

    ordered: List[Dict[str, Any]] = []
    seen: set = set()
    for _idx, pb in indexed:
        iid = str(pb.get("impact_id") or "")
        if not iid or iid in seen:
            continue
        seen.add(iid)
        ordered.append(pb)
        if len(ordered) >= max_playbooks:
            break
    # If the keyword lead was admitted by language but NOT kind-bearing (so it is
    # not in `admitted`), prepend it so the lane's named target still leads.
    if lead_id and lead_id not in seen:
        ordered.insert(0, by_id[lead_id])
        if len(ordered) > max_playbooks:
            ordered = ordered[:max_playbooks]
    return ordered


def _impact_bullet(item: Any, *, sub_keys: Tuple[str, ...] = ()) -> str:
    """Render one playbook list element (str OR dict) to a single bullet line.

    Defensive: the corpus mixes plain strings and structured dicts across
    impacts. For a dict, join the first present of ``sub_keys`` (e.g. q/path/
    what/actor) with any ``why`` / ``kill_condition`` / ``axis`` / ``note``
    detail. Always returns a non-empty-safe string.
    """
    if isinstance(item, str):
        return item.strip()
    if not isinstance(item, dict):
        return str(item)
    head = ""
    for k in sub_keys:
        v = item.get(k)
        if isinstance(v, str) and v.strip():
            head = v.strip()
            break
    if not head:
        # fall back to the first string value in the dict
        for v in item.values():
            if isinstance(v, str) and v.strip():
                head = v.strip()
                break
    tail_parts: List[str] = []
    for tk, label in (
        ("why", "why"),
        ("axis", "axis"),
        ("kill_condition", "KILL"),
        ("note", "note"),
        ("anchor", "anchor"),
    ):
        tv = item.get(tk)
        if isinstance(tv, str) and tv.strip():
            tail_parts.append(f"{label}: {tv.strip()}")
    if tail_parts:
        return f"{head} ({'; '.join(tail_parts)})"
    return head


def _format_impact_methodology_section(
    *,
    lane_type: str,
    prompt_text: str = "",
    workspace_path: Optional[pathlib.Path] = None,
) -> List[str]:
    """Render the Per-Impact Hunting Methodology block.

    Fires only for impact-hunting lanes (is_impact_methodology_lane); returns
    [] otherwise. Infers the target impact class from prompt + workspace
    SCOPE/SEVERITY text, loads the matching playbook from
    audit/corpus_tags/impact_hunting_methodology.yaml, and renders its
    critical_paths, attack_surface, hacker_questions (each with the kill
    condition), caveats, and severity_mapping inline as a concrete hunt brief -
    so the hunter gets the "how exploits in THIS impact class were actually
    found" axis at iter 1.

    Graceful-degrade: when no impact_id is inferred, no playbook matches, or
    the corpus is missing / corrupt, render a SHORT generic stub (non-empty, so
    the lane still gets the axis) - never raise. Idempotency is handled by the
    caller (skip when the header already appears in the assembled brief).
    """
    if not is_impact_methodology_lane(lane_type, prompt_text):
        return []

    # Resolve scope text once (best-effort, no network). Reused for both impact
    # inference and contract-kind gating.
    scope_parts: List[str] = []
    if workspace_path is not None:
        for rel in ("SCOPE.md", "SEVERITY.md", "README.md"):
            try:
                fp = workspace_path / rel
                if fp.is_file():
                    scope_parts.append(
                        fp.read_text(encoding="utf-8", errors="ignore")
                    )
            except (OSError, ValueError):
                continue
    scope_text = "\n".join(scope_parts)

    contract_kind = _infer_contract_kind(
        prompt_text=prompt_text, scope_text=scope_text
    )
    # FAIL-CLOSED language partition: derive the workspace's dominant source
    # language so the playbook language guard (_impact_playbook_attaches /
    # _impact_filter_admits) excludes language-mismatched impacts. A Solidity ws
    # -> chain-halt and every [go, rust]-only bc-* playbook is dropped; the DeFi
    # playbooks that list solidity survive. "" (unknown) admits all (no over-
    # drop), exactly like the renderer's empty-language default.
    language = _infer_workspace_language(workspace_path)

    playbooks = load_impact_playbooks()

    # Lane impact SELECTION aligned with the renderer (render_impact_questions):
    # derive ALL playbooks whose contract-kind FAMILY matches the inferred kind
    # and whose language filter admits the ws language, with the prompt-keyword-
    # inferred id placed FIRST as the lane's named target. This replaces the
    # previous single-keyword pick so an SSV lending/Solidity ws surfaces
    # liquidation-abuse + direct-theft + permanent-freeze + oracle + reward, not
    # one keyword hit (and never chain-halt).
    selected = select_lane_impact_playbooks(
        playbooks,
        prompt_text=prompt_text,
        language=language,
        contract_kind=contract_kind,
    )

    if not selected:
        # Generic stub: still hands the lane the impact axis + the obligation
        # to name its target impact and pull the playbook. Non-empty.
        return [
            _IMPACT_METHODOLOGY_SECTION_HEADER,
            "",
            (
                "_This lane hunts / proves an impact class, but no specific "
                "per-impact playbook was matched from the prompt + workspace "
                "scope. FIRST: name the exact impact class you are chasing "
                "(one of the 32 mined ids in "
                "`audit/corpus_tags/impact_hunting_methodology.yaml`, e.g. "
                "`direct-theft-funds`, `chain-halt-shutdown`, "
                "`share-supply-inflation`), then read that playbook's "
                "critical_paths + hacker_questions before you write a line._"
            ),
            "",
            (
                "Hunt-time obligation for ANY impact class: prove an "
                "attacker-reachable entry on the PRODUCTION path, the affected "
                "non-self state/funds (R24), the realized impact magnitude, and "
                "a negative control where the impact does NOT occur. KILL the "
                "lead if the impact is self-inflicted, only reachable by a "
                "trusted actor, recoverable by an in-protocol path (R82), or "
                "only reproduced in a test-only / single-process / "
                "injected-fault setup (R20/R30)."
            ),
            "",
            (
                "The selected impact MUST verbatim-match a row in the workspace "
                "SEVERITY.md at filing (pre-submit Check #31 / "
                "program-impact-mapping)."
            ),
            "",
        ]

    impact_ids = [str(p.get("impact_id") or "") for p in selected]
    lead_id = impact_ids[0] if impact_ids else ""
    others = ", ".join(f"`{i}`" for i in impact_ids[1:]) if len(impact_ids) > 1 else ""

    out: List[str] = [
        _IMPACT_METHODOLOGY_SECTION_HEADER,
        "",
        (
            f"_This lane's target ({contract_kind or 'unknown-kind'} / "
            f"{language or 'unknown-lang'}) admits the **{lead_id}** impact "
            "class as its lead, plus the additional impact classes below. The "
            "mined playbooks (audit/corpus_tags/impact_hunting_methodology.yaml) "
            "below show how exploits in EACH of these impact classes were "
            "actually found - critical paths, attack surface, the impact-"
            "specific hacker questions + kill conditions, caveats, and the "
            "severity mapping. These are the ONLY impact classes that apply to "
            "this target's contract-kind + language; do not carry over impacts "
            "from another kind/language (e.g. a Solidity DeFi target does NOT "
            "get chain-halt). Hunt these FIRST._"
        ),
        "",
        f"**Lead impact:** `{lead_id}`"
        + (f" | **also in scope for this target:** {others}" if others else ""),
        "",
        (
            "**SCOPE = IMPACT, NOT MECHANISM.** You label and scope a finding by the "
            "IMPACT it ACHIEVES (theft / freeze / governance-takeover / yield-"
            "redistribution / ...), never by its mechanism. The SAME in-scope impact is "
            "reachable through many mechanisms - a chain-halt or unbounded-loop that LOCKS "
            "funds IS a permanent/temporary freeze; an overflow or missing access-control "
            "that drains IS theft; reentrancy that bricks state IS a freeze. Do NOT discard "
            "a lead because its mechanism 'looks like' a generic DoS/overflow/reentrancy - "
            "trace it to the in-scope impact it produces and cite THAT rubric row. See the "
            "`mechanism_to_impacts:` crosswalk in "
            "`audit/corpus_tags/impact_hunting_methodology.yaml`. The ONLY mechanism->impact "
            "claims that are over-claims (and get rejected by R38): a halt claimed as direct "
            "theft/governance-seizure, griefing claimed as theft (destruction != capture), "
            "precision-loss claimed as freeze/governance, and READ-ONLY/view reentrancy "
            "claimed as direct in-scope theft/freeze (it only corrupts a view another "
            "protocol reads)."
        ),
        "",
    ]
    for playbook in selected:
        out.extend(
            _render_one_impact_playbook(
                playbook, language=language, contract_kind=contract_kind
            )
        )

    out.append(
        "Cross-gate reminder: the selected impact must verbatim-match a "
        "workspace SEVERITY.md row at filing (Check #31); permanent-loss / "
        "freeze claims must survive R82 recovery-falsification; DoS-class "
        "leads must reframe to a proven non-DoS impact (R35); non-self impact "
        "(R24) and production-path reachability are mandatory."
    )
    out.append("")
    return out


def validate_impact_section_present(
    brief: str,
    lane_type: str,
    *,
    prompt_text: str = "",
    workspace_path: Optional[pathlib.Path] = None,
) -> List[str]:
    """Self-check: a lane whose (ORIGINAL, pre-downgrade) type is in
    ``IMPACT_METHODOLOGY_LANE_TYPES`` MUST carry the Per-Impact Hunting
    Methodology section in its assembled ``brief``; a non-impact lane is exempt.

    This makes a silent miss VISIBLE. The G3 wiring (commits fa1a36282a /
    f55382498a) gates the section on the pre-downgrade lane_type, but NOTHING
    failed if the renderer returned [] (or the header was somehow dropped) on a
    bona-fide impact lane. ``lane_type`` here is the value the caller already
    chose to gate on (``impact_lane_type`` = original_lane_type or lane_type),
    so the check mirrors the exact gate it is auditing.

    Returns a list of human-readable defect strings (empty == clean). Advisory
    only: callers log the defects to stderr; dispatch behavior is unchanged.
    Never raises - a degraded environment must not break dispatch.

    Two checks:
      1. impact-section-presence: on an impact lane the
         ``_IMPACT_METHODOLOGY_SECTION_HEADER`` must appear in the brief and have
         non-empty body text after it. Exempt for non-impact lanes (any presence
         is fine, since keyword-triggered briefs may legitimately carry it).
      2. language-agreement sanity: ``_infer_workspace_language`` and the
         renderer's ``classify_impact_target`` language view must agree (or one
         be empty / unavailable). A divergence means the per-fn renderer and the
         dispatch partition would select different playbooks - a silent skew.
    """
    defects: List[str] = []
    lt = (lane_type or "").strip().lower()
    is_impact_lane = lt in IMPACT_METHODOLOGY_LANE_TYPES
    brief_text = brief or ""

    if is_impact_lane:
        idx = brief_text.find(_IMPACT_METHODOLOGY_SECTION_HEADER)
        if idx < 0:
            defects.append(
                "impact-section-missing: lane_type "
                f"'{lt}' is in IMPACT_METHODOLOGY_LANE_TYPES but the brief has "
                f"no '{_IMPACT_METHODOLOGY_SECTION_HEADER}' header (silent drop)"
            )
        else:
            body = brief_text[idx + len(_IMPACT_METHODOLOGY_SECTION_HEADER):]
            if not body.strip():
                defects.append(
                    "impact-section-empty: header present for lane_type "
                    f"'{lt}' but no body text follows it"
                )

    # Sanity: _infer_workspace_language must agree with the renderer's language
    # view so the dispatch partition and the per-fn renderer pick the SAME
    # playbooks. An empty value on either side (admit-all / unavailable) is not a
    # divergence - only two non-empty, unequal tokens are.
    try:
        dispatch_lang = (_infer_workspace_language(workspace_path) or "").strip().lower()
    except Exception:
        dispatch_lang = ""
    renderer_lang = ""
    try:
        rend = _renderer()
        alias = getattr(rend, "language_alias", None) if rend else None
        if callable(alias) and dispatch_lang:
            renderer_lang = (alias(dispatch_lang) or "").strip().lower()
    except Exception:
        renderer_lang = ""
    if dispatch_lang and renderer_lang and dispatch_lang != renderer_lang:
        defects.append(
            "language-skew: _infer_workspace_language returned "
            f"'{dispatch_lang}' but the renderer's language_alias normalized it "
            f"to '{renderer_lang}'; dispatch and per-fn renderer would partition "
            "impacts differently"
        )

    return defects


# Foreign-ecosystem tokens that tag an inner example LINE (critical_path /
# attack_surface / hacker_question / anchor) to a non-Solidity ecosystem. A
# multi-ecosystem playbook (one that lists solidity AND go/rust) renders its
# body verbatim, so for a Solidity DeFi lane these example lines pollute the
# brief with cosmos / op-stack text that does not apply. The two groups mirror
# the language-partition the selector already enforces at the PLAYBOOK level:
#   - Go/Cosmos: cosmos / cosmwasm / ibc / authz / fee-payer / *Block / baseapp
#   - OP-Stack / L2-fault: FaultDisputeGame / DisputeGameFactory / cannon / ...
# Lower-cased substring match; the whole rendered bullet text is the haystack.
_FOREIGN_ECOSYSTEM_LINE_TOKENS: Tuple[str, ...] = (
    # Go / Cosmos / CometBFT
    "cosmos",
    "cosmwasm",
    "cosmos-wasm",
    "ibc",
    "authz",
    "fee-payer",
    "beginblock",
    "endblock",
    "baseapp",
    # OP-Stack / L2-fault-proof
    "faultdisputegame",
    "disputegamefactory",
    "cannon",
    "anchorstateregistry",
    "op-stack",
    "opfaultverifier",
    # Other-chain consensus / privacy-chain example lines that must never
    # appear in a Solidity (or vyper) brief regardless of contract_kind.
    "tendermint",
    "penumbra",
)

# Solidity DeFi contract-kind families. RETAINED for backward compatibility /
# documentation; the foreign-ecosystem drop is NO LONGER gated on this finite
# allowlist (that caused recurring whack-a-mole: a Solidity target with a kind
# OUTSIDE the set - e.g. strata's contract_kind='oracle' - leaked cosmos / ABCI
# / OP-Stack example lines). The drop is now gated on LANGUAGE alone.
_SOLIDITY_DEFI_KINDS: frozenset = frozenset(
    {"vault", "proxy", "lending", "amm", "bridge", "token", "governance"}
)

# Source-side EVM languages: a target in any of these MUST NEVER carry a
# foreign (Go/Cosmos or OP-Stack/other-chain) example line, no matter what
# contract_kind the classifier assigned. Gating on language (not a finite
# contract_kind allowlist) is the generic fix - it cannot be defeated by a new
# kind label.
_EVM_SOURCE_LANGUAGES: frozenset = frozenset({"solidity", "vyper"})


def _is_solidity_defi_lane(language: str, contract_kind: str) -> bool:
    """True when the lane is a Solidity/Vyper (EVM source) ws - then foreign-
    ecosystem inner-line filtering is applied REGARDLESS of contract_kind. A
    Solidity (or Vyper) target must never carry cosmos / cosmwasm / ibc / authz /
    beginblock / endblock / baseapp (Go/Cosmos) or faultdisputegame / cannon /
    op-stack / tendermint / penumbra (OP-Stack/other-chain) example lines, even
    when the classifier assigns a kind outside the historic DeFi allowlist
    (oracle, etc.) - that allowlist gating was the recurring leak. ``contract_kind``
    is accepted for signature/back-compat but no longer narrows the gate.
    A Go/cosmos/rust or unknown-language lane keeps every line (additive,
    fail-open, language-gated)."""
    return (language or "").strip().lower() in _EVM_SOURCE_LANGUAGES


def _line_is_foreign_ecosystem(text: str) -> bool:
    """True when a rendered inner example line is tagged to a non-Solidity
    ecosystem (lower-cased substring match against _FOREIGN_ECOSYSTEM_LINE_TOKENS).
    Used to DROP cosmos / op-stack example lines from a Solidity DeFi lane's
    playbook body while keeping every Solidity-relevant line."""
    low = (text or "").lower()
    return any(tok in low for tok in _FOREIGN_ECOSYSTEM_LINE_TOKENS)


def _render_one_impact_playbook(
    playbook: Dict[str, Any],
    *,
    language: str = "",
    contract_kind: str = "",
) -> List[str]:
    """Render ONE impact playbook's body (severity mapping, critical paths,
    attack surface, hacker questions + kills, caveats, incident anchors, sharpest
    kill) as markdown lines. Extracted so _format_impact_methodology_section can
    render the FULL set of contract-kind/language-admitted playbooks inline (the
    renderer-aligned selection), not a single keyword-inferred one.

    When ``language`` is an EVM source language (solidity/vyper), inner EXAMPLE
    lines (severity_mapping / critical_paths / attack_surface / hacker_questions /
    incident_anchors) whose rendered text is tagged to a foreign ecosystem
    (cosmos/cosmwasm/ibc/authz/fee-payer/*Block/baseapp or FaultDisputeGame/
    DisputeGameFactory/cannon/anchorstateregistry/op-stack/opfaultverifier/
    tendermint/penumbra) are DROPPED - they pollute a Solidity/Vyper brief with
    chain-halt / L2-fault example text that does not apply. The drop is gated on
    LANGUAGE alone (NOT on a finite contract_kind allowlist) so a Solidity target
    classified with any kind outside the historic DeFi set (e.g. 'oracle') is
    still cleaned - that allowlist gating was the recurring leak. The playbook-
    level select is unchanged; this only filters the INNER lines of a multi-
    ecosystem playbook. Additive + language-gated: a Go/cosmos/rust or unknown-
    language lane keeps every line (defaults render verbatim, exactly as
    before)."""
    _drop_foreign = _is_solidity_defi_lane(language, contract_kind)
    impact_id = str(playbook.get("impact_id") or "")
    title = str(playbook.get("title") or impact_id)
    severity_hint = str(playbook.get("severity_hint") or "").strip()
    rubric_hint = str(playbook.get("rubric_row_hint") or "").strip()

    out: List[str] = [f"### Impact: `{impact_id}` - {title}", ""]
    if severity_hint:
        out.append(f"**Severity ceiling (hint):** {severity_hint}")
    if rubric_hint:
        out.append(
            f"**Rubric-row hint (Check #31 will demand a verbatim match):** "
            f"{rubric_hint}"
        )
    out.append("")

    # -- severity_mapping (impact -> verdict + rubric rows) ------------------
    sev_map = playbook.get("severity_mapping")
    if isinstance(sev_map, dict) and sev_map:
        out.append("#### Severity mapping (which sub-impact grades how)")
        out.append("")
        for variant, spec in sev_map.items():
            if isinstance(spec, dict):
                verdict = str(spec.get("verdict") or "").strip()
                rows = spec.get("rubric_rows") or []
                row0 = ""
                if isinstance(rows, list) and rows:
                    row0 = str(rows[0]).strip()
                line = f"- **{variant}**"
                if verdict:
                    line += f" -> {verdict}"
                if row0:
                    line += f' (rubric: "{row0}")'
            else:
                line = f"- **{variant}**: {str(spec).strip()}"
            # Drop foreign-ecosystem severity rows (e.g. a
            # 'chain_halt_via_div_by_zero_or_panic' variant) from an EVM-source
            # lane. The variant key AND the full rendered line are screened so a
            # foreign token in either side is caught.
            if _drop_foreign and _line_is_foreign_ecosystem(
                f"{variant} {line}"
            ):
                continue
            out.append(line)
        out.append("")

    # -- critical_paths -----------------------------------------------------
    crit = playbook.get("critical_paths")
    if isinstance(crit, list) and crit:
        out.append("#### Critical paths (where this impact lives)")
        out.append("")
        for it in crit:
            b = _impact_bullet(it, sub_keys=("path", "what", "id"))
            if b and not (_drop_foreign and _line_is_foreign_ecosystem(b)):
                out.append(f"- {b}")
        out.append("")

    # -- attack_surface -----------------------------------------------------
    surf = playbook.get("attack_surface")
    if isinstance(surf, list) and surf:
        out.append("#### Attack surface (who can trigger it, from where)")
        out.append("")
        for it in surf:
            b = _impact_bullet(it, sub_keys=("actor", "surface", "what"))
            if b and not (_drop_foreign and _line_is_foreign_ecosystem(b)):
                out.append(f"- {b}")
        out.append("")

    # -- hacker_questions (the load-bearing axis) ---------------------------
    hqs = playbook.get("hacker_questions")
    if isinstance(hqs, list) and hqs:
        out.append("#### Impact-specific hacker questions (+ kill conditions)")
        out.append("")
        for it in hqs:
            if isinstance(it, dict):
                q = str(it.get("q") or it.get("question") or "").strip()
                axis = str(it.get("axis") or "").strip()
                kc = str(it.get("kill_condition") or "").strip()
                if not q:
                    continue
                if _drop_foreign and _line_is_foreign_ecosystem(
                    f"{q} {axis} {kc}"
                ):
                    continue
                line = f"- {q}"
                if axis:
                    line += f" _(axis: {axis})_"
                out.append(line)
                if kc:
                    out.append(f"    - KILL if: {kc}")
            elif isinstance(it, str) and it.strip():
                if _drop_foreign and _line_is_foreign_ecosystem(it):
                    continue
                out.append(f"- {it.strip()}")
        out.append("")

    # -- caveats (look-alike / over-claim guards) ---------------------------
    cav = playbook.get("caveats")
    if isinstance(cav, list) and cav:
        out.append("#### Caveats (look-alikes / over-claim guards - read before filing)")
        out.append("")
        for it in cav:
            b = _impact_bullet(it, sub_keys=("caveat", "note", "what"))
            if b:
                out.append(f"- {b}")
        out.append("")

    # -- incident anchors (real prior exploits / filed verdicts) ------------
    anchors = playbook.get("incident_anchors") or playbook.get(
        "incident_anchors_public"
    )
    if isinstance(anchors, list) and anchors:
        out.append("#### Incident anchors (real prior exploits / filed verdicts)")
        out.append("")
        for it in anchors[:8]:
            b = _impact_bullet(it, sub_keys=("anchor", "incident", "what"))
            if b and not (_drop_foreign and _line_is_foreign_ecosystem(b)):
                out.append(f"- {b}")
        out.append("")

    # -- kill_if / proof obligations closer ---------------------------------
    kill_if = playbook.get("kill_if")
    if isinstance(kill_if, str) and kill_if.strip():
        out.append(f"**Single sharpest KILL condition:** {kill_if.strip()}")
        out.append("")

    return out


def format_skeleton_as_markdown(
    payload: Optional[Dict[str, Any]],
    *,
    lane_type: str,
    severity: str,
    workspace_path: Optional[pathlib.Path],
    phase_a_context: Optional[Dict[str, Any]] = None,
    oos_preflight: Optional[Dict[str, Any]] = None,
    exploit_queue_context: Optional[Dict[str, Any]] = None,
    lane_verdict_bus_context: Optional[Dict[str, Any]] = None,
    pre_flight_pack_context: Optional[Dict[str, Any]] = None,
    prompt_text: str = "",
    original_lane_type: Optional[str] = None,
) -> str:
    """Render a ``vault_dispatch_brief_skeleton`` payload as the same
    Section 15a/15b/15c/15d block ``tools/agent-brief-prefetch.py`` emits.

    Output always includes the BEGIN/END markers so downstream tools
    (and humans) can locate and strip the prefix.

    ``original_lane_type`` carries the lane_type as it was BEFORE
    build_enriched_prompt downgrades a non-VALID_LANE_TYPES lane to "filing".
    The per-impact methodology section is gated on this pre-downgrade value so a
    hunt-class lane (harness/poc/invariant/prove/exploit-conversion/audit/audit-
    deep/deep) still receives the section even on a neutral prompt - the
    downgrade used to mask the lane membership and silently drop it (G3). When
    None (callers that never downgrade, e.g. tests), it falls back to
    ``lane_type`` so the historical behavior is preserved.
    """
    ws_name = workspace_path.name if workspace_path else "(none)"
    # The impact-methodology lane gate must see the pre-downgrade lane_type.
    impact_lane_type = (
        original_lane_type if original_lane_type is not None else lane_type
    )
    lines: List[str] = [
        "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->",
        "",
        (
            f"_Pre-fetched by `tools/dispatch-agent-with-prebriefing.py` "
            f"at lane `{lane_type}` severity `{severity}` workspace "
            f"`{ws_name}`. Paste this block into the Agent-tool prompt "
            f"verbatim - it supplies Section 15a/15b/15c/15d that the "
            f"Agent tool does NOT auto-inject._"
        ),
        "",
    ]

    # r36-rebuttal: lane generic-escalate-or-prove-impossible registered.
    # Standing never-give-up-on-escalation directive - prepended to EVERY
    # dispatch brief on BOTH the skeleton-available and skeleton-unavailable
    # paths so every future worker prompt carries the prove-impossible-or-
    # escalate contract (codified as R-ESCALATE-FIRST / Rule 14 / A7).
    lines.extend(_format_escalate_first_standing_directive())
    # Standing ATTACKER-SELECTABLE-PRECONDITION directive - prepended to EVERY
    # dispatch brief so no worker refutes a finding by assuming a permissionlessly-
    # configurable / user-supplied / attacker-owned value takes its benign /
    # documented / reference-deployment / test-fixture value (R-ADVERSARIAL-CONFIG).
    lines.extend(_format_attacker_config_standing_directive())
    # Standing EVERYTHING-CITED-TO-IN-SCOPE-CODE directive (R-CODE-CITED). The
    # universal parent of R76 / R-ADVERSARIAL-CONFIG: EVERY load-bearing claim must
    # cite exact in-scope source at file:line + reasoning; an unsourced assertion is
    # an inadmissible assumption. Prepended to EVERY brief.
    lines.extend(_format_code_cited_standing_directive())

    if payload is None:
        lines.extend(
            [
                "## Section 15a - Lane-specific R-rules you MUST address",
                "",
                (
                    "_(warn: vault_dispatch_brief_skeleton unavailable - "
                    "paste section verbatim from CLAUDE.md if R-rule "
                    "context is needed)_"
                ),
                "",
                "## Section 15b - Rule-section skeleton templates",
                "",
                (
                    "_(warn: vault_dispatch_brief_skeleton unavailable - "
                    "no skeleton templates injected)_"
                ),
                "",
            ]
        )
        lines.extend(_format_phase_a_pillar_sections(phase_a_context))
        lines.extend(_format_pre_flight_pack_section(pre_flight_pack_context, workspace_path))
        # r36-rebuttal: lane-TRIAGER-MINDSET-WIRE registered; Section 15h is
        # injected even on the skeleton-unavailable path so triager mindset
        # context lands at iter 1 even when MCP skeleton is degraded.
        lines.extend(_format_triager_mindset_section(lane_type=lane_type))
        # r36-rebuttal: lane-RULE-63 registered; Section 15i (auto-tier-
        # assignment) injected on the skeleton-unavailable path as well.
        lines.extend(_format_auto_tier_assignment_section(lane_type=lane_type))
        # G13.1: full SEVERITY.md rubric (ALL tiers) injected on the
        # skeleton-unavailable path so the cold-run / MCP-degraded case still
        # tells the worker every fileable tier (Low -> Critical).
        # r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
        lines.extend(
            _format_full_rubric_tier_section(
                lane_type=lane_type, workspace_path=workspace_path
            )
        )
        # r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS registered;
        # Section 15j (LIFT-10 hacker-questions) is also injected on the
        # skeleton-unavailable path so the worker sees concrete hunting-
        # questions even when the vault_dispatch_brief_skeleton MCP call
        # is degraded.
        lines.extend(
            _format_hacker_questions_section(
                lane_type=lane_type,
                payload=payload,
            )
        )
        # r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY declared in .auditooor/agent_pathspec.json
        # Section 15k (LIFT-28 per-function hunter brief) injected on the
        # skeleton-unavailable path so per-function context lands at iter 1
        # even when MCP skeleton is degraded.
        lines.extend(
            _format_per_function_hunter_brief_section(
                lane_type=lane_type,
                payload=payload,
            )
        )
        lines.extend(_format_oos_preflight_section(oos_preflight))
        lines.extend(_format_exploit_queue_prior_section(exploit_queue_context))
        # r36-rebuttal: lane PR-DEFENSE-AUDIT-CONTEXT registered; Section 15r
        # (Defense Surface) + Section 15s (Full-Audit Results) are hunt-class
        # only (returns [] for filing/dispute/etc.) and omit gracefully when
        # the source tree / audit artifacts are absent.
        lines.extend(
            _format_defense_surface_section(
                build_defense_surface_context(
                    workspace_path=workspace_path, lane_type=lane_type
                )
            )
        )
        lines.extend(
            _format_audit_results_section(
                build_audit_results_context(
                    workspace_path=workspace_path, lane_type=lane_type
                )
            )
        )
        # r36-rebuttal: lane silo-brief-injection-2026-06 registered; Section 15t
        # Deep-Analysis Silos (math_spec.json + guard_probe_packets.jsonl).
        # Hunt-class lanes only (returns [] otherwise).
        lines.extend(
            _format_deep_analysis_silos_section(
                build_deep_analysis_silos_context(
                    workspace_path=workspace_path, lane_type=lane_type
                )
            )
        )
        lines.extend(_format_lane_verdict_bus_section(lane_verdict_bus_context))
        # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered; Section 15p dedup-first (L36).
        lines.extend(_format_dedup_first_section(workspace_path))
        # r36-rebuttal: lane spawn-worker-filing-dod registered; Section 15q
        # Filing Finalization Definition-of-Done. Filing-class lanes only
        # (returns [] for hunt/drill/etc.). Injected on the skeleton-
        # unavailable path too so the DoD lands at iter 1 when MCP is degraded.
        lines.extend(
            _format_filing_finalization_section(
                build_filing_finalization_context(
                    lane_type=lane_type, workspace_path=workspace_path
                )
            )
        )
        # r36-rebuttal: lane R78-ASSUMPTION-AUDIT-WIRE registered; Rule 78
        # Load-Bearing Assumption Audit (filing + hunt lanes only). Injected on
        # the skeleton-unavailable path too so it lands at iter 1 when degraded.
        lines.extend(
            _format_load_bearing_assumption_audit_section(lane_type=lane_type)
        )
        # r36-rebuttal: lane R80-HARNESS-AUTHORING-WIRE registered; Rule 80
        # Harness-Authoring Honesty Requirements (harness/invariant/coverage/PoC/
        # fuzz lanes only). Idempotent: skip when the header is already present.
        if _HARNESS_AUTHORING_SECTION_HEADER not in lines:
            lines.extend(
                _format_harness_authoring_requirements_section(
                    lane_type=lane_type, prompt_text=prompt_text,
                    workspace_path=workspace_path,
                )
            )
        # r36-rebuttal: lane R81-DEPTH-LAYER-WIRE registered; Rule 81 Depth-Layer
        # Requirements (audit/hunt/harness lanes only). Idempotent.
        if _DEPTH_LAYER_SECTION_HEADER not in lines:
            lines.extend(
                _format_depth_layer_requirements_section(
                    lane_type=lane_type, prompt_text=prompt_text
                )
            )
        # r36-rebuttal: lane R82-ADVERSARIAL-RECOVERY-WIRE registered; Rule 82
        # Phase-1 Adversarial Recovery Falsification (impact / loss / freeze /
        # theft / dispute lanes only). Idempotent: skip when already present.
        if _ADVERSARIAL_RECOVERY_SECTION_HEADER not in lines:
            lines.extend(
                _format_adversarial_recovery_falsification_section(
                    lane_type=lane_type,
                    prompt_text=prompt_text,
                    workspace_path=workspace_path,
                )
            )
        # r36-rebuttal: lane R-IMPACT-METHODOLOGY-WIRE registered; Per-Impact
        # Hunting Methodology (hunt/audit/drill/exploit-conversion/harness/poc
        # lanes only). Idempotent: skip when the header is already present.
        # Injected on the skeleton-unavailable path too so the methodology
        # lands at iter 1 even when MCP is degraded.
        # G3: gate on the PRE-downgrade lane_type so a hunt-class lane that was
        # downgraded to "filing" still renders the section.
        if _IMPACT_METHODOLOGY_SECTION_HEADER not in lines:
            lines.extend(
                _format_impact_methodology_section(
                    lane_type=impact_lane_type,
                    prompt_text=prompt_text,
                    workspace_path=workspace_path,
                )
            )
        _plane = build_impact_mechanism_plane_block(workspace_path)
        if _plane.strip():
            lines.append("")
            lines.append(_plane.rstrip())
        # C1: top-K historical exploit anchors (env-gated, default OFF). '' -> no-op.
        _anchors = build_exploit_anchor_block(prompt_text, workspace_path)
        if _anchors.strip():
            lines.append("")
            lines.append(_anchors.rstrip())
        lines.extend(
            [
                "<!-- END dispatch-agent-with-prebriefing META-1 block -->",
                "",
            ]
        )
        assembled = "\n".join(lines)
        _emit_impact_section_defects(
            assembled,
            impact_lane_type,
            prompt_text=prompt_text,
            workspace_path=workspace_path,
        )
        return assembled

    pack_id = str(payload.get("context_pack_id") or "")
    if pack_id:
        lines.append(f"_Source pack: `{pack_id}`_")
        lines.append("")

    # --- 15a: lane-specific R-rules to address ---
    lines.append("## Section 15a - Lane-specific R-rules you MUST address")
    lines.append("")
    lines.append(f"_Lane type: `{lane_type}`. Severity: `{severity}`._")
    lines.append("")
    must_address = payload.get("lane_specific_rules") or []
    if must_address:
        lines.append(
            f"**Lane-mandated rules** ({len(must_address)} must be addressed):"
        )
        lines.append("")
        for rid in must_address:
            lines.append(f"- **{rid}**")
        lines.append("")

    warnings_top = payload.get("routine_violation_warnings") or []
    if warnings_top:
        lines.append("**Top routine-violation warnings**:")
        lines.append("")
        for w in warnings_top[:5]:
            if isinstance(w, dict):
                wid = str(w.get("rule_id", "?"))
                remediation = str(w.get("one_line_remediation", ""))[:120]
                lines.append(f"- **{wid}**: {remediation}")
            else:
                lines.append(f"- {str(w)[:160]}")
        lines.append("")

    lines.append(
        "Cite each rule by ID in your reply OR include the override marker. "
        "Non-zero pre-submit-check.sh exit = NOT paste-ready."
    )
    lines.append("")

    # --- 15b: skeleton templates ---
    lines.append(
        "## Section 15b - Rule-section skeleton templates "
        "(fill in <<placeholders>>)"
    )
    lines.append("")
    skeleton_sections = payload.get("skeleton_sections") or {}
    if not isinstance(skeleton_sections, dict):
        skeleton_sections = {}
    if not skeleton_sections:
        lines.append(
            f"_(no skeleton templates for lane `{lane_type}` at severity "
            f"`{severity}`)_"
        )
        lines.append("")
    else:
        for rid, skeleton_text in skeleton_sections.items():
            lines.append(f"### Skeleton for {rid}")
            lines.append("")
            lines.append("```")
            lines.append(str(skeleton_text).rstrip())
            lines.append("```")
            lines.append("")

    # --- 15c: rubric excerpt + originality anchors + recall summary ---
    lines.append("## Section 15c - Workspace anchors (rubric + originality + recall)")
    lines.append("")
    rubric = payload.get("rubric_excerpt") or {}
    if isinstance(rubric, dict) and rubric.get("rows"):
        rows = rubric["rows"][:6]
        lines.append("**Rubric rows** (from workspace SEVERITY.md):")
        lines.append("")
        for r in rows:
            if isinstance(r, dict):
                rid = str(r.get("rubric_id", "?"))[:24]
                sentence = str(r.get("listed_impact_sentence", ""))[:140]
                tier = str(r.get("tier", "?"))[:12]
                lines.append(f"- **{rid}** ({tier}): {sentence}")
        lines.append("")
    elif isinstance(rubric, dict) and rubric.get("parsed") is False:
        lines.append("_(no SEVERITY.md found in workspace)_")
        lines.append("")

    originality = payload.get("originality_anchors") or []
    if originality:
        lines.append("**Originality anchors** (prior closures / acknowledgements):")
        lines.append("")
        for o in originality[:5]:
            if isinstance(o, dict):
                src = str(o.get("source", "?"))
                kind = str(o.get("kind", ""))
                excerpt = str(o.get("excerpt", ""))[:160]
                lines.append(f"- `{src}` ({kind}): {excerpt}")
        lines.append("")

    recall = str(payload.get("recall_summary") or "")
    if recall and recall != "(no recall context available)":
        lines.append(f"**Recall summary**: {recall[:480]}")
        lines.append("")

    lines.extend(_format_pre_flight_pack_section(pre_flight_pack_context, workspace_path))

    # --- 15d: busywork-to-refuse + pre-submit preview ---
    lines.append("## Section 15d - Busywork to REFUSE + pre-submit preview")
    lines.append("")
    busywork = payload.get("busywork_refusals") or []
    if busywork:
        for b in busywork:
            if isinstance(b, dict):
                rid = str(b.get("refusal_id", "?"))
                reason = str(b.get("reason", ""))[:240]
                lines.append(f"- **{rid}**: {reason}")
        lines.append("")

    pre_submit = payload.get("pre_submit_preview") or []
    if pre_submit:
        lines.append("**Pre-submit checks likely to fire** (preempt them):")
        lines.append("")
        for ps in pre_submit[:10]:
            if isinstance(ps, dict):
                check = str(ps.get("check", ps.get("name", "?")))
                lines.append(f"- {check}")
            else:
                lines.append(f"- {str(ps)[:160]}")
        lines.append("")

    usage = str(payload.get("usage_note") or "")
    if usage:
        lines.append(f"_{usage[:600]}_")
        lines.append("")

    lines.extend(_format_phase_a_pillar_sections(phase_a_context))
    # HUNT-BRIEF LEAN: R62 triager pre-filing simulator (15h) + R63 auto-tier
    # assignment (15i) are FILE-time discipline; defer them for a pure hunt lane.
    if not _hunt_brief_lean(lane_type):
        lines.extend(_format_triager_mindset_section(lane_type=lane_type))
        # r36-rebuttal: lane-RULE-63 registered; Section 15i (R63 auto-tier-
        # assignment) sits after Section 15h (R62 triager mindset) so workers
        # see triager-rejection patterns first, then validate tier semantics.
        lines.extend(_format_auto_tier_assignment_section(lane_type=lane_type))
    # G13.1: full SEVERITY.md rubric (ALL tiers) on the skeleton-present
    # path. Read directly from the workspace SEVERITY.md (not the skeleton
    # payload) so the full fileable-tier surface always lands.
    # r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
    lines.extend(
        _format_full_rubric_tier_section(
            lane_type=lane_type, workspace_path=workspace_path
        )
    )
    # r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS registered;
    # Section 15j (LIFT-10 hacker-questions) sits after Section 15i so
    # the worker validates the rubric/tier first and then receives the
    # concrete hunting-questions for the lane's attack class.
    lines.extend(
        _format_hacker_questions_section(
            lane_type=lane_type,
            payload=payload,
        )
    )
    # r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY declared in .auditooor/agent_pathspec.json
    # Section 15k (LIFT-28 per-function hunter brief) sits after Section 15j
    # so the worker first sees the broad workspace-level hacker questions,
    # then the per-function refinement when contract:function metadata is
    # specified on the lane payload.
    lines.extend(
        _format_per_function_hunter_brief_section(
            lane_type=lane_type,
            payload=payload,
        )
    )
    # HUNT-BRIEF LEAN: the OOS/AI-FP/known-issue preflight (15l) is a FILE-time
    # candidate check; defer for a pure hunt lane (it re-lands at drafting/filing).
    if not _hunt_brief_lean(lane_type):
        lines.extend(_format_oos_preflight_section(oos_preflight))
    lines.extend(_format_exploit_queue_prior_section(exploit_queue_context))
    # r36-rebuttal: lane PR-DEFENSE-AUDIT-CONTEXT registered; Section 15r
    # (Defense Surface) + Section 15s (Full-Audit Results) are hunt-class only
    # and omit gracefully when source tree / audit artifacts are absent.
    lines.extend(
        _format_defense_surface_section(
            build_defense_surface_context(
                workspace_path=workspace_path, lane_type=lane_type
            )
        )
    )
    lines.extend(
        _format_audit_results_section(
            build_audit_results_context(
                workspace_path=workspace_path, lane_type=lane_type
            )
        )
    )
    # r36-rebuttal: lane silo-brief-injection-2026-06 registered; Section 15t
    # Deep-Analysis Silos (math_spec.json + guard_probe_packets.jsonl) on the
    # skeleton-unavailable path too, so the silos land at iter 1 when degraded.
    lines.extend(
        _format_deep_analysis_silos_section(
            build_deep_analysis_silos_context(
                workspace_path=workspace_path, lane_type=lane_type
            )
        )
    )
    lines.extend(_format_lane_verdict_bus_section(lane_verdict_bus_context))
    # r36-rebuttal: registered lane mimo-harness-build-2026-05-27
    # MIMO mining-loop health section (added 2026-05-27, R76 wave).
    lines.extend(_format_mining_health_section(workspace_path))
    # r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
    # Section 15p - dedup-first + canonical hunt definition (L36).
    lines.extend(_format_dedup_first_section(workspace_path))
    # r36-rebuttal: lane spawn-worker-filing-dod registered in
    # .auditooor/agent_pathspec.json - Section 15q Filing Finalization
    # Definition-of-Done. Gated on lane_type: returns [] for hunt-class lanes,
    # so only filing / triager-response / rebuttal / escalation briefs get it.
    lines.extend(
        _format_filing_finalization_section(
            build_filing_finalization_context(
                lane_type=lane_type, workspace_path=workspace_path
            )
        )
    )
    # r36-rebuttal: lane R78-ASSUMPTION-AUDIT-WIRE registered; Rule 78
    # Load-Bearing Assumption Audit. HUNT-BRIEF LEAN: this validates a
    # candidate's assumptions (file-time); defer for a pure hunt lane.
    if not _hunt_brief_lean(lane_type):
        lines.extend(
            _format_load_bearing_assumption_audit_section(lane_type=lane_type)
        )
    # r36-rebuttal: lane R80-HARNESS-AUTHORING-WIRE registered; Rule 80
    # Harness-Authoring Honesty Requirements (harness/invariant/coverage/PoC/
    # fuzz lanes only). Idempotent: skip when the header is already present.
    if _HARNESS_AUTHORING_SECTION_HEADER not in lines:
        lines.extend(
            _format_harness_authoring_requirements_section(
                lane_type=lane_type, prompt_text=prompt_text,
                workspace_path=workspace_path,
            )
        )
    # r36-rebuttal: lane R81-DEPTH-LAYER-WIRE registered; Rule 81 Depth-Layer
    # Requirements (audit/hunt/harness lanes only). Idempotent.
    if _DEPTH_LAYER_SECTION_HEADER not in lines:
        lines.extend(
            _format_depth_layer_requirements_section(
                lane_type=lane_type, prompt_text=prompt_text
            )
        )
    # r36-rebuttal: lane R82-ADVERSARIAL-RECOVERY-WIRE registered; Rule 82
    # Phase-1 Adversarial Recovery Falsification (impact / loss / freeze /
    # theft / dispute lanes only). Idempotent: skip when already present.
    # HUNT-BRIEF LEAN: R82 recovery-falsification fires on an IMPACT candidate
    # (file-time); defer for a pure hunt lane.
    if _ADVERSARIAL_RECOVERY_SECTION_HEADER not in lines and not _hunt_brief_lean(lane_type):
        lines.extend(
            _format_adversarial_recovery_falsification_section(
                lane_type=lane_type,
                prompt_text=prompt_text,
                workspace_path=workspace_path,
            )
        )
    # r36-rebuttal: lane R-IMPACT-METHODOLOGY-WIRE registered; Per-Impact
    # Hunting Methodology (hunt/audit/drill/exploit-conversion/harness/poc
    # lanes only). Idempotent: skip when the header is already present.
    # G3: gate on the PRE-downgrade lane_type so a hunt-class lane that was
    # downgraded to "filing" still renders the section.
    if _IMPACT_METHODOLOGY_SECTION_HEADER not in lines:
        lines.extend(
            _format_impact_methodology_section(
                lane_type=impact_lane_type,
                prompt_text=prompt_text,
                workspace_path=workspace_path,
            )
        )

    _plane = build_impact_mechanism_plane_block(workspace_path)
    if _plane.strip():
        lines.append("")
        lines.append(_plane.rstrip())
    # C1: top-K historical exploit anchors (env-gated, default OFF). '' -> no-op.
    _anchors = build_exploit_anchor_block(prompt_text, workspace_path)
    if _anchors.strip():
        lines.append("")
        lines.append(_anchors.rstrip())
    lines.append("<!-- END dispatch-agent-with-prebriefing META-1 block -->")
    lines.append("")
    assembled = "\n".join(lines)
    # Post-build self-check (advisory): a downgraded hunt-class lane MUST still
    # carry the impact-methodology section. Logs to stderr; never alters output.
    _emit_impact_section_defects(
        assembled,
        impact_lane_type,
        prompt_text=prompt_text,
        workspace_path=workspace_path,
    )
    return assembled


def _emit_impact_section_defects(
    brief: str,
    lane_type: str,
    *,
    prompt_text: str = "",
    workspace_path: Optional[pathlib.Path] = None,
) -> List[str]:
    """Run ``validate_impact_section_present`` and log any defects to stderr.

    Advisory only - returns the defect list (empty == clean) and NEVER raises so
    a degraded environment cannot break dispatch. The visible warning is the
    whole point: a silent drop of the impact-methodology section on a
    pre-downgrade impact lane is now surfaced.
    """
    try:
        defects = validate_impact_section_present(
            brief,
            lane_type,
            prompt_text=prompt_text,
            workspace_path=workspace_path,
        )
    except Exception:
        return []
    for d in defects:
        print(
            f"[dispatch-prebrief][impact-section-check] WARN: {d}",
            file=sys.stderr,
        )
    return defects


# r36-rebuttal: lane mimo-harness-build-2026-05-27 - mining-loop health brief injection
def _format_mining_health_section(workspace_path: str) -> list[str]:
    """Section 15o - Mining-loop health (R76 wave, 2026-05-27).

    Brief-injection block that surfaces the workspace's MIMO mining-loop
    state: coverage heatmap presence, hacker-q reweight ledger snapshot,
    known-dead-end record count, and R76 hallucination signal count.
    Workers picking up this lane see the mining-state up-front and avoid
    re-running scans the harness already produced.
    """
    lines = [
        "## Section 15o - Mining-loop health + R76 hallucination guard",
        "",
        (
            "_Before drilling, call `vault_mining_health` to see the active "
            "MIMO state for this workspace. Avoid re-hypothesizing candidates "
            "already in `reports/known_dead_ends.jsonl`. If a CONFIRMED "
            "candidate cites `file_line='N/A conceptual pattern'`, treat it as "
            "R76-hallucinated and drop unless source-grep confirms._"
        ),
        "",
        "```",
        ("python3 tools/vault-mcp-server.py --call vault_mining_health "
         "--args '{\"workspace_path\":\"" + str(workspace_path or "<ws>") + "\"}'"),
        "```",
        "",
        ("Hard gate: `pre-submit-check.sh` Check #125 "
         "(`R76-HALLUCINATION-GUARD`) fails closed for drafts whose "
         "`code_excerpt` does not appear in the workspace tree via grep. "
         "Override: `<!-- r76-rebuttal: <reason> -->` (200 chars max)."),
        "",
        ("Companion tooling: `tools/workspace-coverage-heatmap.py` "
         "(per-contract MIMO density), `tools/hacker-q-reweighter.py` "
         "(auto-deprioritize high-NO-rate questions), "
         "`tools/triage-kill-promoter.py` (kills auto-flow into "
         "`vault_known_dead_ends`). PostToolUse hook "
         "`auditooor-corpus-change-refresh.sh` Steps C+D auto-fire after "
         "every MIMO sidecar write."),
        "",
        # G15.2: surface the coverage gate at brief-time so workers enumerate
        # every in-scope contract (libraries included) rather than freestyle a
        # partial drill. r36-rebuttal: lane IMP-ZK-ENFORCE registered.
        ("Coverage (G15): run `python3 tools/hunt-coverage-gate.py "
         "--workspace " + str(workspace_path or "<ws>") + " --json` to see "
         "the UNCOVERED contracts. A hunt that skips the library surface is "
         "presumed incomplete - drill them or log skips in "
         "`<ws>/.auditooor/hunt_coverage_skips.txt`. Emit every candidate via "
         "`tools/workflow-drill-sidecar-emit.py` (G14) so coverage counts it."),
        "",
    ]
    return lines


# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
def _format_dedup_first_section(workspace_path: str) -> list[str]:
    """Section 15p - dedup-first directive + canonical hunt definition (L36).

    Injected into every brief so workers (a) know a hunt is the FULL
    pipeline and a shallow/partial/repeated pass is rejected by
    hunt-completeness-check, and (b) consult the skip-set FIRST and skip
    anything already filed / killed / dead-ended. This is the brief-time
    half of the L36 dedup-first rule; the orchestrator step 0 produces the
    skip-set this section tells the worker to read.
    """
    ws = str(workspace_path or "<ws>")
    return [
        "## Section 15p - DEDUP-FIRST + canonical hunt definition (L36)",
        "",
        (
            "A hunt is the FULL pipeline (dedup-first + deep clone + Tier-6 "
            "bidirectional mining + audit-deep + all-cluster coverage + "
            "artifact mining). FIRST consult `" + ws + "/.auditooor/"
            "hunt_skip_set.json` and SKIP anything already filed/killed/"
            "dead-ended. A shallow/partial/repeated pass is NOT a hunt and "
            "is rejected by hunt-completeness-check."
        ),
        "",
        (
            "Re-deriving a known dead-end or re-filing a prior finding is a "
            "wasted-cycle defect. The skip-set consolidates prior submissions, "
            "`reports/known_dead_ends.jsonl`, prior hunt sidecars (incl -FP), "
            "and MCP recall (`vault_known_dead_ends` / `vault_originality_context`)."
        ),
        "",
        "```",
        ("python3 tools/hunt-dedup-load.py " + ws + " --json   "
         "# step 0 (re)materialize the skip-set"),
        ("python3 -c \"import json;d=json.load(open('" + ws + "/.auditooor/"
         "hunt_skip_set.json'));print(d['source_counts']);"
         "[print(e['slug'],e['verdict'],e['file_line']) for e in d['entries'][:25]]\""),
        "```",
        "",
    ]


# r36-rebuttal: lane-TRIAGER-MINDSET-WIRE registered via tools/agent-pathspec-register.py
# (.auditooor/agent_pathspec.json includes tools/dispatch-agent-with-prebriefing.py)
_TRIAGER_MINDSET_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "dispute",
    "escalation",
    "mediation",
    "opposed-trace-harness",
    "triager-response",
    "rebuttal",
    "filing",
}


def _load_triager_pattern_summary(top: int = 6) -> List[Dict[str, Any]]:
    """Read reference/triager_patterns.json and return the top N rejection
    patterns most relevant to triager-mindset prefilling. Returns a list of
    dicts with id / name / triager_language sample / pre_submit_guard.
    r36-rebuttal: lane-TRIAGER-MINDSET-WIRE registered via tools/agent-pathspec-register.py
    """
    patterns_path = REPO / "reference" / "triager_patterns.json"
    if not patterns_path.is_file():
        return []
    try:
        with patterns_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    rows = payload.get("rejections") or []
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rid = str(row.get("id") or "").strip()
        if not rid:
            continue
        # Highlight the newer R18-R23 patterns first (Rule 62 codification,
        # 2026-05-26) plus the classics R1/R2/R11/R17 that triagers cite most.
        out.append({
            "id": rid,
            "name": str(row.get("name") or rid),
            "language_sample": (row.get("triager_language") or [None])[0],
            "guard_excerpt": str(row.get("pre_submit_guard") or "")[:240],
            "_rank_key": rid,
        })

    def _rank(row: Dict[str, Any]) -> int:
        rid = row.get("_rank_key", "")
        # New R18-R23 first (lane goal), then R11 / R17 / R12 / R13, then rest.
        priority = {
            "R18": 0, "R19": 1, "R20": 2, "R21": 3, "R22": 4, "R23": 5,
            "R11": 6, "R17": 7, "R12": 8, "R13": 9,
            "R1": 10, "R2": 11, "R5": 12,
        }
        return priority.get(rid, 99)

    out.sort(key=_rank)
    return out[:top]


def _format_code_cited_standing_directive() -> List[str]:
    """Render the standing EVERYTHING-CITED-TO-IN-SCOPE-CODE directive.

    Prepended to EVERY dispatch brief. Encodes the operator directive
    (2026-07-04): everything must be verified against actual IN-SCOPE code at
    exact file:line + reasoning - no assumptions, no narrative, no inference from
    names, "no bullshit". This is the universal parent rule of R76 (the cited
    excerpt must be a verbatim substring of real source) and R-ADVERSARIAL-CONFIG
    (no benign-config assumption): it extends the cite-or-inadmissible standard to
    EVERY load-bearing claim in a verdict / finding / refutation, not just the
    single code_excerpt.

    Enforced by tools/claim-citation-check.py under AUDITOOOR_CLAIM_CITATION_STRICT
    (advisory-first).
    """
    return [
        "## Section 15-EVIDENCE - Standing directive: EVERY claim cited to in-scope code",
        "",
        (
            "_Cite-or-inadmissible (R-CODE-CITED). Flagged by "
            "`tools/claim-citation-check.py` under `AUDITOOOR_CLAIM_CITATION_STRICT`. "
            "The universal parent of R76 + R-ADVERSARIAL-CONFIG._"
        ),
        "",
        (
            "EVERYTHING you assert MUST be grounded in ACTUAL IN-SCOPE SOURCE at an "
            "exact `file:line` you have READ, plus reasoning tying that line to the "
            "claim. This applies to EVERY load-bearing claim, not just the "
            "code_excerpt: a GUARD claim ('X is checked / validated / gated / "
            "nonReentrant'), a REACHABILITY claim ('X is / is not reachable / "
            "callable / attacker-controlled'), a SCOPE claim ('X is out-of-scope / "
            "privileged / vendored'), an IMPACT claim ('the loss is capped / "
            "recoverable / bounded'), a CONFIG claim ('the value is X'), a DEDUP "
            "claim ('same root as finding Y'), and a MATH claim ('no net gain / no "
            "overflow'). Each needs its own file:line."
        ),
        "",
        (
            "An assertion WITHOUT a cited in-scope `file:line` you have actually read "
            "is an ASSUMPTION and is INADMISSIBLE - it does not support a terminal "
            "verdict. BANNED as evidence: narrative / whitepaper / README / comments "
            "/ 'typically' / 'should' / 'is designed to' / inference from a function "
            "or variable NAME / 'the tests suggest' / 'presumably'. If you write 'it "
            "is validated upstream', you MUST cite the exact validating line; if you "
            "cannot, you have NOT verified it - go READ the code and cite it, or state "
            "the claim as UNVERIFIED. Only what the in-scope code at file:line "
            "ACTUALLY does counts. When in doubt, read more source and cite it. No "
            "bullshit: exact lines + reasoning, or it did not happen."
        ),
        "",
    ]


def _format_attacker_config_standing_directive() -> List[str]:
    """Render the standing ATTACKER-SELECTABLE-PRECONDITION directive.

    Prepended to EVERY dispatch brief. Encodes the operator directive
    (2026-07-04, NUVA donation lead): a KILL / REFUTED / NOT-FILEABLE verdict may
    NEVER rest on the assumption that a security-relevant value takes its BENIGN /
    documented / reference-deployment / test-fixture value when that value is
    ATTACKER-SELECTABLE. The NUVA donation lane wrongly refuted "the marker is
    restricted (per the KYC/RWA program description + fixtures)" while CreateVault
    is PERMISSIONLESS and does NOT enforce a restricted underlying marker in code -
    so the attacker instantiates the adversarial config. Documentation / narrative /
    README / program-description / test-fixtures are NOT enforced constraints.

    Enforced by tools/benign-config-refutation-check.py under
    AUDITOOOR_ADVERSARIAL_CONFIG_STRICT (advisory-first).
    """
    return [
        "## Section 15-CFG - Standing directive: assume the ATTACKER-SELECTED config",
        "",
        (
            "_Adversarial-config-or-code-guard (R-ADVERSARIAL-CONFIG). Flagged by "
            "`tools/benign-config-refutation-check.py` under "
            "`AUDITOOOR_ADVERSARIAL_CONFIG_STRICT`._"
        ),
        "",
        (
            "You may NOT refute / kill / down-tier a finding by ASSUMING a "
            "security-relevant value takes its benign / documented / "
            "reference-deployment / 'realistic' / test-fixture value when that "
            "value is ATTACKER-SELECTABLE. A value is attacker-selectable when it "
            "is set via a PERMISSIONLESS entrypoint (permissionless create / "
            "register / configure / deploy), a USER-SUPPLIED call argument, or the "
            "SELF-ADMIN of an attacker-owned resource. The audit scope is the CODE "
            "(a permissionlessly-deployable module @ HEAD), NOT one reference "
            "deployment - if the code LETS an attacker instantiate the adversarial "
            "config, you MUST assume the adversarial config."
        ),
        "",
        (
            "Documentation / whitepaper / README / program-description (e.g. "
            "'it's a KYC/RWA vault so the denom is restricted') / test fixtures / "
            "'the deployed instance is configured safely' / 'not evidenced as the "
            "real config' are NOT enforced constraints and may NEVER ground a "
            "refutation. A valid refutation must instead cite ONE of: (a) a CODE "
            "guard at file:line that STRUCTURALLY forbids the adversarial config on "
            "the exploit path (e.g. `require(markerType == Restricted)` at "
            "creation); (b) the adversarial-config economic MATH proving no net "
            "attacker gain (with numbers + the capped params, file:line); (c) an "
            "access-control code check proving the config is privileged-only AND the "
            "privileged setter cannot be an attacker (permissionless creation of an "
            "attacker-OWNED instance does NOT count as privileged). Before you "
            "refute on a config, ASK: 'can an attacker create/choose this value?' - "
            "if yes, assume they did."
        ),
        "",
    ]


def _format_escalate_first_standing_directive() -> List[str]:
    """Render the standing NEVER-GIVE-UP-ON-ESCALATION directive.

    Prepended to EVERY dispatch brief (both the skeleton-available and
    skeleton-unavailable paths). Encodes the operator directive
    (2026-07-02, lane generic-escalate-or-prove-impossible): a finding may
    NEVER fall to a lower tier via a PUNT ("attempted but could not build the
    evidence" / "measurement limitation" / "would require a testnet" /
    "single-process cannot model it"). The ONLY valid fallback is a PROVEN
    IMPOSSIBILITY of the higher tier: a source/config/economics-cited argument
    (code-guard file:line, numeric config bound, economic infeasibility with
    numbers, or a named recovery mechanism that caps the impact).

    Enforced by pre-submit-check.sh Check #127 (R-ESCALATE-FIRST-REQUIRED) via
    tools/escalate-first-required-check.py under AUDITOOOR_ESCALATE_FIRST_STRICT.
    """
    return [
        "## Section 15-ESC - Standing directive: NEVER give up on escalation",
        "",
        (
            "_Prove-impossible-or-escalate (R-ESCALATE-FIRST / Rule 14 / A7). "
            "Enforced at pre-submit-check.sh Check #127 "
            "(`tools/escalate-first-required-check.py`) under "
            "`AUDITOOOR_ESCALATE_FIRST_STRICT`._"
        ),
        "",
        (
            "NEVER give up on escalation. Attempt the HIGHEST impact the "
            "mechanism can plausibly reach FIRST, and drive it end-to-end. "
            "Fall back to a lower tier ONLY with a cited PROOF-OF-IMPOSSIBILITY "
            "for the higher tier. 'Evidence too hard to build' / 'measurement "
            "limitation' / 'would require a testnet / multi-node / consensus "
            "instrumentation' / 'a single-process test cannot model it' / "
            "'considered and deliberately not claimed' are NOT valid fallbacks "
            "- they are PUNTs and fail the gate closed."
        ),
        "",
        (
            "A valid PROOF-OF-IMPOSSIBILITY is ONE of: (a) a code guard at "
            "`file:line` that structurally caps the higher impact; (b) a numeric "
            "config or economic bound (with units) that makes the higher impact "
            "unreachable; (c) a named, in-protocol recovery mechanism that caps "
            "or reverses the loss. If you cannot cite one of these, ESCALATE and "
            "prove the higher tier - do not narrow. 'Agents never give up - they "
            "prove not-possible.'"
        ),
        "",
    ]


def _format_triager_mindset_section(*, lane_type: str) -> List[str]:
    """Render Section 15h - Triager-Mindset Pre-Checks (Rule 62).

    Auto-injects the top triager rejection patterns from
    reference/triager_patterns.json so the worker drafts with the
    triager rationales in mind from iteration 1. Wired in by lane
    TRIAGER-MINDSET-WIRE 2026-05-26 (Rule 62 codification).
    """
    lane_norm = (lane_type or "").strip().lower()
    if lane_norm not in _TRIAGER_MINDSET_LANE_TYPES:
        return []
    patterns = _load_triager_pattern_summary(top=6)
    if not patterns:
        return []

    lines: List[str] = []
    lines.append("## Section 15h - Triager-Mindset Pre-Checks (Rule 62)")
    lines.append("")
    lines.append(
        "_Rule 62 (triager-mindset-precheck-required) - codified 2026-05-26 "
        "by lane TRIAGER-MINDSET-WIRE. Run "
        "`python3 tools/triager-pre-filing-simulator.py --draft <draft.md> "
        "--workspace <ws>` at hypothesis stage AND before staging promotion. "
        "Pre-submit-check Check #114 fail-closes drafts whose simulator output "
        "lists matched patterns without addressed pre_submit_guards or a "
        "`<!-- r62-rebuttal: ... -->` marker._"
    )
    lines.append("")
    lines.append(
        "**Top triager rejection patterns to PRE-empt for this lane** "
        "(verbatim from `reference/triager_patterns.json`):"
    )
    lines.append("")
    for row in patterns:
        rid = row.get("id", "?")
        name = row.get("name", "?")
        lang = row.get("language_sample")
        lang_str = f' (triager language: "{lang}")' if lang else ""
        guard = row.get("guard_excerpt") or ""
        lines.append(f"- **{rid} - {name}**{lang_str}")
        if guard:
            lines.append(f"  - guard: {guard}")
    lines.append("")
    lines.append(
        "**Required action**: address each matched pattern's "
        "`pre_submit_guard` directly in the draft body, OR add the "
        "override `<!-- r62-rebuttal: <reason up to 200 chars> -->` "
        "when the pattern is structurally inapplicable. See "
        "`docs/RULE_62_TRIAGER_MINDSET_PRECHECK_2026-05-26.md`."
    )
    lines.append("")
    return lines


# r36-rebuttal: lane-RULE-63 registered in .auditooor/agent_pathspec.json
# via tools/agent-pathspec-register.py.
_AUTO_TIER_ASSIGNMENT_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "dispute",
    "escalation",
    "mediation",
    "opposed-trace-harness",
    "triager-response",
    "rebuttal",
    "filing",
}


def _format_auto_tier_assignment_section(*, lane_type: str) -> List[str]:
    """Render Section 15i - Auto-Tier-Assignment from SEVERITY.md (Rule 63).

    Injects a one-block reminder that the worker should validate the draft's
    claimed Severity tier against the impact semantics implied by the
    workspace SEVERITY.md, BEFORE staging promotion. Pre-submit-check
    Check #115 enforces; this section primes the worker so the gate fails
    less often at staging time.

    r36-rebuttal: lane-RULE-63 registered in .auditooor/agent_pathspec.json
    """
    lane_norm = (lane_type or "").strip().lower()
    if lane_norm not in _AUTO_TIER_ASSIGNMENT_LANE_TYPES:
        return []

    lines: List[str] = []
    lines.append("## Section 15i - Auto-Tier-Assignment from SEVERITY.md (Rule 63)")
    lines.append("")
    lines.append(
        "_Rule 63 (auto-tier-assignment-required) - codified 2026-05-26 by "
        "lane RULE-63. Run "
        "`python3 tools/rubric-auto-tier-assigner.py <draft.md> "
        "--workspace <ws>` at hypothesis stage AND before staging promotion. "
        "Pre-submit-check Check #115 fail-closes drafts whose claimed Severity "
        "tier mismatches the impact text's semantic tier inferred from the "
        "workspace SEVERITY.md, unless `<!-- r63-rebuttal: ... -->` is set._"
    )
    lines.append("")
    lines.append(
        "**Tier semantics**: the tool re-parses THIS workspace's SEVERITY.md "
        "authoritatively at run-time - the target's own rubric tiers are the "
        "single source of truth (do not assume a generic / cross-target tier "
        "table). Read the workspace SEVERITY.md for the verbatim tier rows."
    )
    lines.append("")
    lines.append(
        "**Required action**: ensure the draft's Impact section uses the "
        "load-bearing nouns from the rubric tier matching the claimed Severity. "
        "Cantina / Immunefi / HackenProof triagers re-tier downward on impact-"
        "semantic mismatch (anchor: dydx cantina-213 HIGH closed for "
        "'localized rate-limit pressure / bounded impact'). When the impact "
        "honestly is at a lower tier, re-tier the draft to match. When the "
        "auto-scorer disagrees with a justified higher claim, add an "
        "`<!-- r63-rebuttal: <reason up to 200 chars> -->` override."
    )
    lines.append("")
    return lines


# G13.1: hunt-class lane set for the full-tier rubric injection. Narrower
# than the auto-tier set (which includes dispute/triager-response/etc) -
# full-tier coverage matters for hunt-class lanes that should sweep every
# fileable tier rather than dispute lanes that target one filed finding.
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
_FULL_RUBRIC_TIER_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "opposed-trace-harness",
    "escalation",
}


def _format_full_rubric_tier_section(
    *, lane_type: str, workspace_path: Optional[pathlib.Path]
) -> List[str]:
    """Render Section 15i-FULL - the workspace's REAL SEVERITY.md tier rows
    (ALL tiers, NOT capped) + a mandatory "hunt EVERY tier" directive (G13).

    Anchor: an Aztec cold-run freestyled a Critical-only hunt and never
    enumerated the Low/Medium-rich library surface. This section injects the
    full rubric verbatim so a hunt-class worker sees that Low + Medium are
    fileable and paid, and is explicitly told not to bias toward Critical.

    Reads the workspace SEVERITY.md DIRECTLY via the shared
    ``lib.severity_rubric`` parser (NOT the MCP skeleton payload), so the
    full rubric lands even when the skeleton is degraded - the exact
    cold-run silent-miss failure mode.

    r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
    """
    lane_norm = (lane_type or "").strip().lower()
    if lane_norm not in _FULL_RUBRIC_TIER_LANE_TYPES:
        return []

    lines: List[str] = []
    lines.append("## Section 15i-FULL - Full SEVERITY.md rubric (hunt EVERY tier)")
    lines.append("")

    sev_md = None
    rows: List[Any] = []
    if _severity_rubric is not None:
        try:
            sev_md = _severity_rubric.find_severity_md(workspace_path)
            if sev_md is not None:
                rows = _severity_rubric.parse_tier_rows(
                    sev_md.read_text(encoding="utf-8", errors="replace")
                )
        except Exception:
            sev_md = None
            rows = []

    if sev_md is None or not rows:
        lines.append(
            "_(no SEVERITY.md in workspace; run `make audit-prep WS=<ws>` to "
            "scaffold the rubric before hunting)_"
        )
        lines.append("")
        return lines

    # Order tiers low -> critical so the Low/Medium fileable surface is the
    # first thing the worker reads (counters Critical-bias).
    order = getattr(_severity_rubric, "TIER_ORDER", {})
    try:
        rows_sorted = sorted(rows, key=lambda r: order.get(r.tier, 99))
    except Exception:
        rows_sorted = rows

    lines.append(
        f"_Parsed verbatim from `{sev_md}` - ALL tier rows below are "
        f"fileable. Do NOT cap your hunt at Critical._"
    )
    lines.append("")
    for r in rows_sorted:
        tier_label = r.tier.capitalize() if r.tier else "?"
        rid = (r.rubric_id or "").strip()
        prefix = f"{tier_label}/{rid}" if rid else tier_label
        payout = (r.payout or "").strip()
        sentence = (r.sentence or "").strip() or "(see SEVERITY.md)"
        if payout:
            lines.append(f"- **{prefix}** ({payout}): {sentence}")
        else:
            lines.append(f"- **{prefix}**: {sentence}")
    lines.append("")
    lines.append(
        "MANDATORY: hunt and file EVERY tier Low -> Critical. Low and Medium "
        "findings ARE fileable and ARE paid (cite payouts above). Do NOT "
        "freestyle a Critical-only hunt. A hunt that reports zero Low/Medium "
        "candidates on a library-heavy target is presumed incomplete."
    )
    lines.append("")
    lines.append(
        "Every candidate (CONFIRMED and KILL) MUST be emitted via "
        "`python3 tools/workflow-drill-sidecar-emit.py ...` before you return. "
        "Findings that exist only in your return value are LOST and do not "
        "feed the learning loop (G14)."
    )
    lines.append("")
    return lines


# r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS declared in
# .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py at
# lane start. Hacker-questions Section 15j is auto-injected on the same
# lane-type set as Section 15h / 15i (hunt/drill/dispute/escalation/etc).
_HACKER_QUESTIONS_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "dispute",
    "escalation",
    "mediation",
    "opposed-trace-harness",
    "triager-response",
    "rebuttal",
    "filing",
}


def _load_hacker_questions_for_lane(
    *,
    attack_class_hint: str = "",
    target_language_hint: str = "",
    invariant_id_hint: str = "",
    top: int = 7,
) -> List[Dict[str, Any]]:
    """Pull top-N hacker-questions from
    ``audit/corpus_tags/derived/hacker_questions_library.jsonl`` via the
    local MCP server CLI. Caller passes optional filter hints from the
    dispatch payload (attack_class / target_language / linked invariant
    id); empty hints surface the ZetaChain anchor questions first.

    Returns a list of dicts with question_id / question_text /
    grep_patterns / attack_class_anchor / linked_invariant_ids.

    Best-effort: failure -> empty list (the rest of the dispatch brief
    still renders).
    """
    cli = REPO / "tools" / "vault-mcp-server.py"
    if not cli.is_file():
        return []
    args: Dict[str, Any] = {"limit": max(1, min(int(top), 50))}
    ac = (attack_class_hint or "").strip()
    if ac:
        args["attack_class"] = ac
    tl = (target_language_hint or "").strip()
    if tl:
        args["target_language"] = tl
    iv = (invariant_id_hint or "").strip()
    if iv:
        args["invariant_id"] = iv
    try:
        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "--call",
                "vault_hacker_questions",
                "--args",
                json.dumps(args),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    try:
        payload = json.loads(result.stdout)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    rows = payload.get("questions") or []
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append({
            "question_id": str(row.get("question_id") or ""),
            "question_text": str(row.get("question_text") or ""),
            "attack_class_anchor": str(row.get("attack_class_anchor") or ""),
            "grep_patterns": list(row.get("grep_patterns") or []),
            "linked_invariant_ids": list(row.get("linked_invariant_ids") or []),
            "source_case_study": str(row.get("source_case_study") or ""),
        })
    return out


def _load_hacker_questions_subset(
    *,
    source_incident_id: str,
    limit: int = 7,
) -> List[Dict[str, Any]]:
    """Pull hacker-questions filtered by source_incident_id.

    Companion to :func:`_load_hacker_questions_for_lane`; this variant
    targets the anchor incident (e.g. ZetaChain 2026-04-26) for the
    no-filter dispatch path so the worker sees the 7 canonical
    questions instead of the alphabetically-first slice.

    r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS pathspec registered.
    """
    cli = REPO / "tools" / "vault-mcp-server.py"
    if not cli.is_file():
        return []
    args: Dict[str, Any] = {
        "source_incident_id": str(source_incident_id),
        "limit": max(1, min(int(limit), 50)),
    }
    try:
        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "--call",
                "vault_hacker_questions",
                "--args",
                json.dumps(args),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    try:
        payload = json.loads(result.stdout)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    rows = payload.get("questions") or []
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append({
            "question_id": str(row.get("question_id") or ""),
            "question_text": str(row.get("question_text") or ""),
            "attack_class_anchor": str(row.get("attack_class_anchor") or ""),
            "grep_patterns": list(row.get("grep_patterns") or []),
            "linked_invariant_ids": list(row.get("linked_invariant_ids") or []),
            "source_case_study": str(row.get("source_case_study") or ""),
        })
    return out


def _format_hacker_questions_section(
    *,
    lane_type: str,
    payload: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Render Section 15j - LIFT-10 Hacker Questions (per attack class).

    Auto-injects top-N hunting-questions from
    ``audit/corpus_tags/derived/hacker_questions_library.jsonl`` so the
    worker draft has the question stack in hand at iteration 1. Wired
    in by lane LIFT-10-VAULT-HACKER-QUESTIONS on 2026-05-26.

    r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS declared in .auditooor/agent_pathspec.json
    """
    lane_norm = (lane_type or "").strip().lower()
    if lane_norm not in _HACKER_QUESTIONS_LANE_TYPES:
        return []

    # Pull optional filter hints from the lane payload metadata.
    attack_class_hint = ""
    target_language_hint = ""
    invariant_id_hint = ""
    if isinstance(payload, dict):
        meta = payload.get("metadata") or {}
        if isinstance(meta, dict):
            attack_class_hint = str(meta.get("attack_class") or "")
            target_language_hint = str(meta.get("target_language") or "")
            invariant_id_hint = str(meta.get("invariant_id") or "")

    # r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS pathspec registered.
    # When no filter is hinted, surface the ZetaChain anchor set (the 7
    # canonical hunting questions). When a filter is hinted, let the
    # corpus deliver the lane-specific subset.
    questions: List[Dict[str, Any]]
    if attack_class_hint or target_language_hint or invariant_id_hint:
        questions = _load_hacker_questions_for_lane(
            attack_class_hint=attack_class_hint,
            target_language_hint=target_language_hint,
            invariant_id_hint=invariant_id_hint,
            top=7,
        )
    else:
        # r36-rebuttal: lane LIFT-10-VAULT-HACKER-QUESTIONS pathspec registered.
        # Surface the 7 ZetaChain anchor questions when no filter is hinted.
        zeta_subset = _load_hacker_questions_subset(
            source_incident_id="zetachain-arbitrary-call-2026-04-26",
            limit=7,
        )
        if zeta_subset:
            questions = zeta_subset
        else:
            # Fall back to the unfiltered top-7 if the ZetaChain anchor is
            # absent from the corpus (e.g. dev environment with synthetic
            # fixture only).
            questions = _load_hacker_questions_for_lane(
                attack_class_hint="",
                target_language_hint="",
                invariant_id_hint="",
                top=7,
            )

    if not questions:
        return []

    lines: List[str] = []
    lines.append("## Section 15j - LIFT-10 Hacker Questions (per attack class)")
    lines.append("")
    lines.append(
        "_LIFT-10 (2026-05-26): hunting-question library. Anchored on the 7 "
        "ZetaChain arbitrary-call hunting-questions extracted from "
        "`case_study/zetachain_arbitrary_call_2026_04_26.md` (extended by "
        "LIFT-13 to ~4.7k records covering anti-patterns and bridge incidents). "
        "Call directly: `python3 tools/vault-mcp-server.py --call "
        "vault_hacker_questions --args '{\"attack_class\":\"<class>\","
        "\"limit\":7}'`. Schema: `auditooor.vault_hacker_questions.v1`._"
    )
    lines.append("")
    if attack_class_hint or target_language_hint or invariant_id_hint:
        filters: List[str] = []
        if attack_class_hint:
            filters.append(f"attack_class={attack_class_hint}")
        if target_language_hint:
            filters.append(f"target_language={target_language_hint}")
        if invariant_id_hint:
            filters.append(f"invariant_id={invariant_id_hint}")
        lines.append(f"**Hunting-questions for this lane** (filtered: {', '.join(filters)}):")
    else:
        lines.append("**Hunting-questions surfaced for this lane** (no filter):")
    lines.append("")
    for idx, q in enumerate(questions, start=1):
        qid = q.get("question_id") or "?"
        qtext = q.get("question_text") or ""
        ac = q.get("attack_class_anchor") or ""
        inv_ids = q.get("linked_invariant_ids") or []
        grep = q.get("grep_patterns") or []
        # Clip the question text for the brief; full text is in the
        # corpus and via the live MCP call.
        if len(qtext) > 480:
            qtext = qtext[:477].rstrip() + "..."
        head = f"{idx}. **{qid}** _(attack_class: {ac})_"
        if inv_ids:
            head += f" - linked invariants: `{', '.join(inv_ids[:3])}`"
        lines.append(head)
        lines.append(f"   - question: {qtext}")
        if grep:
            sample = ", ".join(f"`{g}`" for g in grep[:6])
            lines.append(f"   - grep_patterns sample: {sample}")
    lines.append("")
    lines.append(
        "**Required action**: ASK at least the first 5 hunting-questions of "
        "the loaded set against the lane target before drafting; carry "
        "answers (yes/no + file:line evidence or counter-example) into the "
        "lane's verdict / draft. The hunting-questions corpus is rebuilt "
        "from real-world post-mortems; ignoring them is the M14-trap shape."
    )
    lines.append("")
    return lines


# r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY declared in .auditooor/agent_pathspec.json
_PER_FUNCTION_HUNTER_BRIEF_LANE_TYPES = {
    "hunt",
    "drill",
    "comp",
    "fuzz",
    "dispute",
    "escalation",
    "mediation",
    "opposed-trace-harness",
    "triager-response",
    "rebuttal",
    "filing",
}


def _load_per_function_hunter_brief(
    *,
    workspace_path: str,
    contract_path: str,
    function_name: str = "",
    contract_kind_hint: str = "",
    target_language: str = "",
    max_questions: int = 7,
    max_templates: int = 3,
) -> Optional[Dict[str, Any]]:
    """LIFT-28 (2026-05-26): pull per-function hunter brief via the MCP CLI.

    Returns the full payload dict (or None on failure). Best-effort: a
    non-zero exit / malformed JSON degrades to None so Section 15k
    silently disappears.

    r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY pathspec registered.
    """
    cli = REPO / "tools" / "vault-mcp-server.py"
    if not cli.is_file() or not workspace_path or not contract_path:
        return None
    args: Dict[str, Any] = {
        "workspace_path": workspace_path,
        "contract_path": contract_path,
        "max_questions": max(1, min(int(max_questions), 50)),
        "max_templates": max(1, min(int(max_templates), 20)),
    }
    if function_name:
        args["function_name"] = function_name
    if contract_kind_hint:
        args["contract_kind_hint"] = contract_kind_hint
    if target_language:
        args["target_language"] = target_language
    try:
        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                str(cli),
                "--call",
                "vault_per_function_hunter_brief",
                "--args",
                json.dumps(args),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _format_per_function_hunter_brief_section(
    *,
    lane_type: str,
    payload: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Render Section 15k - LIFT-28 Per-Function Hunter Brief.

    Auto-injects matched hacker_questions + chain_templates + relevant
    invariants for a SPECIFIC contract:function when the worker brief
    declares one in lane metadata (``metadata.contract_path`` plus
    optional ``metadata.function_name`` / ``metadata.contract_kind``).
    When no contract is specified, the section is omitted (workspace-
    level Section 15j already covers the broad case).

    r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY pathspec registered.
    """
    lane_norm = (lane_type or "").strip().lower()
    if lane_norm not in _PER_FUNCTION_HUNTER_BRIEF_LANE_TYPES:
        return []
    if not isinstance(payload, dict):
        return []
    meta = payload.get("metadata") or {}
    if not isinstance(meta, dict):
        return []
    contract_path = str(meta.get("contract_path") or "").strip()
    function_name = str(meta.get("function_name") or "").strip()
    contract_kind = str(
        meta.get("contract_kind") or meta.get("contract_kind_hint") or ""
    ).strip()
    target_language = str(meta.get("target_language") or "").strip()
    workspace_path = str(
        payload.get("workspace_path")
        or payload.get("workspace")
        or meta.get("workspace_path")
        or ""
    ).strip()
    if not contract_path or not workspace_path:
        return []

    brief = _load_per_function_hunter_brief(
        workspace_path=workspace_path,
        contract_path=contract_path,
        function_name=function_name,
        contract_kind_hint=contract_kind,
        target_language=target_language,
        max_questions=7,
        max_templates=3,
    )
    if not brief:
        return []

    summary = brief.get("summary") or {}
    questions = brief.get("matched_hacker_questions") or []
    templates = brief.get("matched_chain_templates") or []
    invariants = brief.get("relevant_invariants") or []

    lines: List[str] = []
    lines.append("## Section 15k - LIFT-28 Per-Function Hunter Brief")
    lines.append("")
    target_blob = f"`{contract_path}`"
    if function_name:
        target_blob += f"::`{function_name}()`"
    if contract_kind:
        target_blob += f" (kind: `{contract_kind}`)"
    lines.append(
        "_LIFT-28 (2026-05-26): per-function / per-contract hunter brief. "
        f"Target: {target_blob}. Composed from hacker_questions_library + "
        "global_chain_templates corpora filtered by per-target patterns. "
        "Call directly: `python3 tools/vault-mcp-server.py --call "
        "vault_per_function_hunter_brief --args '{...}'`. Schema: "
        "`auditooor.vault_per_function_hunter_brief.v1`._"
    )
    lines.append("")
    lines.append(
        f"**Summary**: {summary.get('questions_returned', 0)} questions / "
        f"{summary.get('templates_returned', 0)} chain templates / "
        f"{summary.get('invariants_returned', 0)} relevant invariants."
    )
    lines.append("")
    if questions:
        lines.append("**Top per-function hunting-questions** (ranked by target match):")
        lines.append("")
        for idx, q in enumerate(questions[:5], start=1):
            qid = q.get("question_id") or "?"
            ac = q.get("attack_class_anchor") or ""
            inv = q.get("linked_invariant_ids") or []
            scope = q.get("scope_specificity") or "?"
            qtext = q.get("question_text") or ""
            if len(qtext) > 320:
                qtext = qtext[:317].rstrip() + "..."
            head = f"{idx}. **{qid}** (class: `{ac}`, scope: `{scope}`)"
            if inv:
                head += f" - linked: `{', '.join(inv[:3])}`"
            lines.append(head)
            lines.append(f"   - question: {qtext}")
        lines.append("")
    if templates:
        lines.append("**Top applicable chain templates**:")
        lines.append("")
        for idx, t in enumerate(templates[:3], start=1):
            tid = t.get("chain_template_id") or "?"
            kinds = t.get("applicable_contract_kinds") or []
            roles = t.get("applicable_function_role_patterns") or []
            density = t.get("match_density")
            matched = t.get("matched_count")
            tuple_size = t.get("tuple_size")
            head = (
                f"{idx}. **{tid}** - kinds: `{', '.join(kinds[:4])}` - "
                f"roles: `{', '.join(roles[:4])}`"
            )
            lines.append(head)
            lines.append(
                f"   - matched {matched}/{tuple_size} invariants "
                f"(density={density})"
            )
            members = t.get("member_invariant_ids") or []
            if members:
                lines.append(f"   - members: `{', '.join(members[:6])}`")
        lines.append("")
    if invariants:
        lines.append(
            f"**Relevant invariants** ({len(invariants)} total): "
            f"`{', '.join(invariants[:10])}`"
        )
        lines.append("")
    lines.append(
        "**Required action**: traverse the top hacker-questions against the "
        "target contract:function FIRST (each question carries a "
        "grep_patterns array + linked_invariant_ids). Then check whether the "
        "applicable chain templates fire end-to-end (member_invariant_ids "
        "must all be broken in the target). Advisory only - matched rows "
        "still require runnable PoC, originality check, defense traversal, "
        "and pre-submit gates before any filing posture."
    )
    lines.append("")
    return lines


def _format_phase_a_pillar_sections(
    phase_a_context: Optional[Dict[str, Any]]
) -> List[str]:
    """Render Phase A P1/P3/P5 context after the existing Section 15d."""
    if not isinstance(phase_a_context, dict):
        return []

    lines: List[str] = []
    p1 = phase_a_context.get("p1") or {}
    p3 = phase_a_context.get("p3") or {}
    p5 = phase_a_context.get("p5") or {}
    staleness = phase_a_context.get("live_target_staleness") or {}

    lines.append("## Section 15e - Phase A P1 invariant context")
    lines.append("")
    p1_pack = str(p1.get("context_pack_id") or "")
    p1_hash = str(p1.get("context_pack_hash") or "")
    if p1_pack:
        receipt = f"_MCP recall receipt: `{p1_pack}`"
        if p1_hash:
            receipt += f" / `{p1_hash[:16]}`"
        receipt += "_"
        lines.append(receipt)
        lines.append("")
    invariants = list(p1.get("invariants") or [])
    top_invariants = [i for i in invariants if isinstance(i, dict)][:5]
    if top_invariants:
        lines.append("**Relevant invariant snippets**:")
        lines.append("")
        for inv in top_invariants:
            inv_id = str(inv.get("invariant_id") or "?")
            category = str(inv.get("category") or "").strip()
            statement = str(inv.get("statement") or "").strip()
            target_lang = str(inv.get("target_lang") or "").strip()
            tier = str(inv.get("verification_tier") or "").strip()
            source_ids = list(inv.get("source_finding_ids") or [])
            line = f"- `{inv_id}`"
            labels = [x for x in (category, target_lang, tier) if x]
            if labels:
                line += f" ({', '.join(labels)})"
            if statement:
                line += f": {statement[:260]}"
            lines.append(line)
            commit_point = str(inv.get("commit_point_pattern") or "").strip()
            defense = str(inv.get("defense_layer") or "").strip()
            details = []
            if commit_point:
                details.append(f"commit point: {commit_point[:180]}")
            if defense:
                details.append(f"defense: {defense[:180]}")
            if details:
                lines.append(f"  - {'; '.join(details)}")
            if source_ids:
                refs = ", ".join(f"`{str(ref)[:96]}`" for ref in source_ids[:2])
                lines.append(f"  - source refs: {refs}")
        lines.append("")
    else:
        reason = str(p1.get("reason") or "no invariant rows returned")
        lines.append(f"_(P1 unavailable: {reason})_")
        lines.append("")

    lines.append("## Section 15f - Phase A P3 anti-pattern context")
    lines.append("")
    p3_pack = str(p3.get("context_pack_id") or "")
    if p3_pack:
        lines.append(f"_Source pack: `{p3_pack}`_")
        lines.append("")
    patterns = list(p3.get("patterns") or p3.get("anti_patterns") or [])
    top_pattern_ids = []
    for pat in patterns:
        if not isinstance(pat, dict):
            continue
        pid = str(pat.get("pattern_id") or pat.get("anti_pattern_id") or "")
        if pid:
            top_pattern_ids.append(pid)
    top_pattern_ids = top_pattern_ids[:5]
    if top_pattern_ids:
        lines.append("**Top pattern IDs**:")
        lines.append("")
        for pattern_id in top_pattern_ids:
            lines.append(f"- `{pattern_id}`")
        lines.append("")
    else:
        reason = str(p3.get("reason") or "no anti-pattern rows returned")
        lines.append(f"_(P3 unavailable: {reason})_")
        lines.append("")

    lines.append("## Section 15g - Phase A P5 live-target context")
    lines.append("")
    p5_pack = str(p5.get("context_pack_id") or "")
    if p5_pack:
        lines.append(f"_Source pack: `{p5_pack}`_")
        lines.append("")
    stale_warning = str(staleness.get("warning") or "")
    if stale_warning:
        lines.append(f"**LIVE_TARGET_REPORT.md staleness warning**: {stale_warning}")
        lines.append("")
    entries = list(p5.get("entry_points") or [])
    if entries:
        lines.append("**Top live-target entries**:")
        lines.append("")
        for idx, entry in enumerate(entries[:5], start=1):
            if not isinstance(entry, dict):
                continue
            file_line = str(entry.get("file_line") or "?")[:160]
            cluster = str(entry.get("cluster_id") or "?")[:120]
            priority = str(entry.get("hunt_priority") or "?")[:40]
            lines.append(f"- {idx}. `{file_line}` ({priority}, `{cluster}`)")
        lines.append("")
    else:
        reason = str(p5.get("reason") or "no live-target entries returned")
        lines.append(f"_(P5 unavailable: {reason})_")
        lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Top-level assembly
# ---------------------------------------------------------------------------

def build_impact_mechanism_plane_block(workspace_path: Optional[pathlib.Path]) -> str:
    """Section 0.8 - the impact x mechanism completeness PLANE + the
    agent_mechanism_verdicts write-instruction, injected into the CANONICAL hunt
    brief. REUSES agent-prompt-hacker-augmenter._build_sec08_impact_mechanism_plane
    (R47 tool-dedup - never re-implement the plane). Without this, the plane lived
    ONLY in the augmenter, which the hunt-scoped dispatch does NOT call, so the
    closed-loop cell-clearing capability never reached the real per-fn hunt
    (operator-caught: 'is this the proper flow?' - it was orphaned). Degrades to
    empty string when the workspace or the augmenter is unavailable."""
    if workspace_path is None:
        return ""
    try:
        import importlib.util
        tool = pathlib.Path(__file__).resolve().parent / "agent-prompt-hacker-augmenter.py"
        if not tool.is_file():
            return ""
        spec = importlib.util.spec_from_file_location("_augmenter_for_plane", str(tool))
        if spec is None or spec.loader is None:
            return ""
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        text, _meta = mod._build_sec08_impact_mechanism_plane(pathlib.Path(workspace_path))
        return text or ""
    except Exception:
        return ""


def build_exploit_anchor_block(
    prompt_text: str,
    workspace_path: Optional[pathlib.Path],
) -> str:
    """C1 - top-K historical exploit anchors most similar to this hunt, attached to the
    dispatched brief. REUSES tools/lib/exploit_anchor_prompt (which reuses
    reverse-correlator.load_anchors + its ranker) - do NOT rebuild a ranker. Gated by
    the shared default-OFF env AUDITOOOR_EXPLOIT_ANCHOR_PROMPT; returns '' when OFF /
    corpus missing / nothing clears the similarity threshold, so the brief is
    byte-identical whenever this returns ''."""
    try:
        import importlib.util
        lib = pathlib.Path(__file__).resolve().parent / "lib" / "exploit_anchor_prompt.py"
        if not lib.is_file():
            return ""
        spec = importlib.util.spec_from_file_location("_c1_exploit_anchor_prompt", str(lib))
        if spec is None or spec.loader is None:
            return ""
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        ws_name = workspace_path.name if workspace_path else ""
        context = f"{ws_name} {prompt_text or ''}"
        return mod.render_exploit_anchor_block(context, top_k=3, fmt="markdown") or ""
    except Exception:
        return ""


def build_enriched_prompt(
    *,
    prompt_text: str,
    lane_type: Optional[str] = None,
    severity: Optional[str] = None,
    workspace_path: Optional[pathlib.Path] = None,
    target_finding_class: str = "",
    cwd: Optional[pathlib.Path] = None,
    infer_missing: bool = True,
    mcp_caller=None,
    pillar_context_caller=None,
    brief_kind: str = "auto",
) -> Tuple[str, Dict[str, Any]]:
    """Build the full enriched prompt = prefix block + original prompt.

    Args:
        prompt_text: the operator's raw Agent-tool prompt.
        lane_type / severity / workspace_path: explicit overrides. If
            None and ``infer_missing=True``, we keyword-infer from the
            prompt body.
        target_finding_class: optional pass-through to skeleton filler.
        cwd: optional override for cwd-based workspace inference.
        infer_missing: when False, missing args stay None (caller may
            pass explicit None to skip workspace context entirely).
        mcp_caller: optional injection point for tests; if set, called
            instead of ``call_vault_dispatch_brief_skeleton``.
        pillar_context_caller: optional injection point for tests; if set,
            called instead of ``build_phase_a_pillar_context``.

    Returns:
        (enriched_prompt, meta) where meta documents what was inferred,
        what MCP returned, and which fallback path (if any) fired.
    """
    if prompt_text is None:
        prompt_text = ""

    # PROMPT-INJECTION DEFENSE (2026-07-12): scrub any synthetic system-tag
    # content the operator prompt may have captured from orchestrator context
    # BEFORE it is inferred over or embedded. A worker brief must never carry a
    # `<system-reminder>` (or similar) block.
    prompt_text = strip_synthetic_system_tags(prompt_text)

    inferred: Dict[str, Any] = {}

    # BRIEF-KIND GATING (2026-07-12): a concrete tooling-fix brief must NOT be
    # wrapped in the vulnerability-HUNT skeleton. Resolve brief_kind (auto ->
    # heuristic) and, when tooling, pass the operator prompt through RAW (like
    # --no-prebriefing) with no hunt template.
    _bk = (brief_kind or "auto").strip().lower()
    if _bk not in VALID_BRIEF_KINDS:
        _bk = "auto"
    resolved_brief_kind = _bk
    if _bk == "auto":
        resolved_brief_kind = infer_brief_kind(prompt_text, lane_type)
    if resolved_brief_kind == "tooling":
        enriched_raw = strip_synthetic_system_tags(prompt_text).lstrip()
        raw_meta: Dict[str, Any] = {
            "schema": SCHEMA,
            "brief_kind": "tooling",
            "brief_kind_requested": _bk,
            "prebriefing": "bypassed-tooling-raw",
            "lane_type": lane_type,
            "severity": (severity or None),
            "workspace_path": (str(workspace_path) if workspace_path else None),
            "inferred": {},
            "hunt_template_wrapped": False,
        }
        return enriched_raw, raw_meta

    # Treat an empty-string lane_type like None so inference runs. spawn-worker.sh
    # defaults LANE_TYPE="" with no required-check, so an unset lane previously
    # skipped inference and was downgraded straight to "filing" (silently losing
    # the impact-methodology section even on a clearly-hunting prompt). Empty ->
    # infer, exactly as None does.
    if (lane_type is None or lane_type == "") and infer_missing:
        lane_type = infer_lane_type(prompt_text)
        inferred["lane_type"] = lane_type
    if severity is None and infer_missing:
        severity = infer_severity(prompt_text)
        inferred["severity"] = severity
    if workspace_path is None and infer_missing:
        workspace_path = infer_workspace(prompt_text, cwd=cwd)
        inferred["workspace_path"] = (
            str(workspace_path) if workspace_path else None
        )

    # Preserve the lane_type as the operator/inference produced it BEFORE the
    # filing-downgrade below. IMPACT_METHODOLOGY_LANE_TYPES (hunt/audit/audit-
    # deep/deep/harness/poc/invariant/prove/exploit-conversion/drill/comp) is
    # largely DISJOINT from VALID_LANE_TYPES, so the downgrade at this point used
    # to mask the lane membership and the impact section never rendered for 8 of
    # the 11 impact lane types on a neutral prompt (G3). The per-rule sections
    # (impact methodology) are evaluated against this original value, while the
    # rest of the brief keeps using the downgraded value for skeleton lookup.
    original_lane_type = lane_type

    if lane_type not in VALID_LANE_TYPES:
        # Keep prebriefing best-effort; downgrade unknown lane to filing.
        inferred["lane_type_fallback_from"] = lane_type
        lane_type = "filing"

    sev_upper = (severity or "HIGH").upper()
    if sev_upper not in VALID_SEVERITIES:
        inferred["severity_fallback_from"] = sev_upper
        sev_upper = "HIGH"

    caller = mcp_caller or call_vault_dispatch_brief_skeleton
    skeleton_payload = caller(
        lane_type=lane_type,
        severity=sev_upper,
        workspace_path=workspace_path,
        target_finding_class=target_finding_class,
    )
    phase_a_builder = pillar_context_caller or build_phase_a_pillar_context
    phase_a_context = phase_a_builder(
        workspace_path=workspace_path,
        query_text=prompt_text,
        target_finding_class=target_finding_class,
    )
    oos_preflight = build_oos_preflight_context(
        workspace_path=workspace_path,
        prompt_text=prompt_text,
        lane_type=lane_type,
        severity=sev_upper,
    )
    exploit_queue_context = build_exploit_queue_prior_context(
        workspace_path=workspace_path,
        prompt_text=prompt_text,
    )
    lane_verdict_bus_context = build_lane_verdict_bus_context(
        workspace_path=workspace_path,
        prompt_text=prompt_text,
        target_finding_class=target_finding_class,
    )
    pre_flight_pack_context = build_pre_flight_pack_context(
        workspace_path=workspace_path,
        prompt_text=prompt_text,
        target_finding_class=target_finding_class,
    )

    prefix = format_skeleton_as_markdown(
        skeleton_payload,
        lane_type=lane_type,
        severity=sev_upper,
        workspace_path=workspace_path,
        phase_a_context=phase_a_context,
        oos_preflight=oos_preflight,
        exploit_queue_context=exploit_queue_context,
        lane_verdict_bus_context=lane_verdict_bus_context,
        pre_flight_pack_context=pre_flight_pack_context,
        prompt_text=prompt_text,
        original_lane_type=original_lane_type,
    )

    # Section 0.8 (impact x mechanism plane) is injected INSIDE
    # format_skeleton_as_markdown, BEFORE the END marker, so it survives the
    # --skeleton-only truncation that the hunt-scoped fanout path uses.
    enriched = prefix.rstrip() + "\n\n" + prompt_text.lstrip()
    # Final belt-and-suspenders scrub: a skeleton/context builder could re-inject
    # captured system-tag content; never let it reach the worker brief.
    enriched = strip_synthetic_system_tags(enriched)

    meta: Dict[str, Any] = {
        "schema": SCHEMA,
        "brief_kind": resolved_brief_kind,
        "brief_kind_requested": _bk,
        "hunt_template_wrapped": True,
        "lane_type": lane_type,
        "original_lane_type": original_lane_type,
        "severity": sev_upper,
        "workspace_path": (
            str(workspace_path) if workspace_path else None
        ),
        "target_finding_class": target_finding_class,
        "inferred": inferred,
        "skeleton_pack_id": (
            skeleton_payload.get("context_pack_id")
            if isinstance(skeleton_payload, dict)
            else None
        ),
        "phase_a_context_pack_ids": {
            "p1": (
                ((phase_a_context.get("p1") or {}).get("context_pack_id"))
                if isinstance(phase_a_context, dict)
                else None
            ),
            "p3": (
                ((phase_a_context.get("p3") or {}).get("context_pack_id"))
                if isinstance(phase_a_context, dict)
                else None
            ),
            "p5": (
                ((phase_a_context.get("p5") or {}).get("context_pack_id"))
                if isinstance(phase_a_context, dict)
                else None
            ),
        },
        "phase_a_context_pack_hashes": {
            "p1": (
                ((phase_a_context.get("p1") or {}).get("context_pack_hash"))
                if isinstance(phase_a_context, dict)
                else None
            ),
            "p3": (
                ((phase_a_context.get("p3") or {}).get("context_pack_hash"))
                if isinstance(phase_a_context, dict)
                else None
            ),
            "p5": (
                ((phase_a_context.get("p5") or {}).get("context_pack_hash"))
                if isinstance(phase_a_context, dict)
                else None
            ),
        },
        "live_target_report_staleness": (
            phase_a_context.get("live_target_staleness")
            if isinstance(phase_a_context, dict)
            else None
        ),
        "oos_preflight_verdict": (
            oos_preflight.get("verdict") if isinstance(oos_preflight, dict) else None
        ),
        "oos_preflight_match_count": (
            len(oos_preflight.get("matches") or [])
            if isinstance(oos_preflight, dict)
            else 0
        ),
        "exploit_queue_prior_rows": (
            len(exploit_queue_context.get("exploit_queue_matches") or [])
            if isinstance(exploit_queue_context, dict)
            else 0
        ),
        "ccia_attack_angle_rows": (
            len(exploit_queue_context.get("ccia_attack_angle_matches") or [])
            if isinstance(exploit_queue_context, dict)
            else 0
        ),
        "lane_verdict_bus_rows": (
            len(lane_verdict_bus_context.get("verdicts") or [])
            if isinstance(lane_verdict_bus_context, dict)
            else 0
        ),
        "lane_verdict_bus_empty": (
            bool(lane_verdict_bus_context.get("bus_empty"))
            if isinstance(lane_verdict_bus_context, dict)
            else True
        ),
        "pre_flight_pack_status": (
            pre_flight_pack_context.get("status")
            if isinstance(pre_flight_pack_context, dict)
            else None
        ),
        "pre_flight_pack_path": (
            pre_flight_pack_context.get("path")
            if isinstance(pre_flight_pack_context, dict)
            else None
        ),
        "skeleton_unavailable": skeleton_payload is None,
        "prefix_chars": len(prefix),
        "prompt_chars": len(prompt_text),
    }
    return enriched, meta


def dispatch_via_claude_cli(
    enriched_prompt: str,
    *,
    claude_bin: str = "claude",
    extra_args: Optional[List[str]] = None,
    timeout: int = 600,
) -> Tuple[int, str, str]:
    """Pipe the enriched prompt to ``claude -p`` (one-shot mode) so a
    scripted dispatch lands the same prompt the operator would paste.

    Returns ``(returncode, stdout, stderr)``.
    """
    cmd = [claude_bin, "-p", enriched_prompt]
    if extra_args:
        cmd.extend(extra_args)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        return (127, "", f"claude binary not found at {claude_bin}")
    except subprocess.TimeoutExpired:
        return (124, "", f"claude dispatch timed out after {timeout}s")
    return (proc.returncode, proc.stdout or "", proc.stderr or "")


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# <!-- r36-rebuttal: lane-LIFT-23-BRIEF-CLI-VALIDATOR-WIRE registered via
# tools/agent-pathspec-register.py (lane TTL 7200s, file set:
# tools/dispatch-agent-with-prebriefing.py + test + docs sidecar). The
# brief-cli-validator preflight helper below wires the LIFT-20 audit
# recommendation (c) into the dispatch flow. -->
#
# ---------------------------------------------------------------------------
# Brief-CLI-validator preflight (LIFT-23, wires LIFT-20 audit recommendation c)
#
# Catches stale CLI flags / missing-tool references in lane briefs BEFORE
# dispatch. Default behavior: warn-only - briefs with findings still
# dispatch, but a `[BRIEF-CLI-VALIDATOR] findings=N` summary is emitted to
# stderr. Strict mode (--strict-cli-validation OR
# AUDITOOOR_BRIEF_CLI_VALIDATOR_STRICT=1) hard-fails on any finding and
# prints an operator-actionable report.
#
# Disable entirely via AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE=1 (e.g. for
# in-flight sessions during rollout). Backward-compatible: when the
# validator binary is missing the helper returns a soft-pass record and
# emits a single WARN line so existing flows keep working.
# ---------------------------------------------------------------------------


def _brief_cli_validator_path() -> pathlib.Path:
    """Resolve tools/brief-cli-validator.py relative to this script."""
    return REPO / "tools" / "brief-cli-validator.py"


def run_brief_cli_validator_on_text(
    prompt_text: str,
    *,
    workspace_path: Optional[pathlib.Path] = None,
    validator_path: Optional[pathlib.Path] = None,
    timeout: Optional[int] = None,
    runner=None,
) -> Dict[str, Any]:
    """Run tools/brief-cli-validator.py against the given prompt text.

    The validator takes a markdown file as positional argument; we write
    ``prompt_text`` to a tempfile (deleted on exit) and parse the JSON
    output. Returns a stable result dict regardless of underlying failure
    so callers do not have to special-case missing binaries.

    The result dict carries:

      - ``schema``: BRIEF_CLI_VALIDATOR_SCHEMA
      - ``status``: one of ``ok``, ``disabled``, ``binary-missing``,
        ``run-error``, ``json-parse-error``, ``timeout``.
      - ``findings_count``: count of findings (0 when status != ``ok``).
      - ``highest_severity``: ``high`` if any ``fail-tool-missing-or-help-broken``
        finding is present, ``medium`` if only ``fail-stale-flag`` findings,
        else ``none``.
      - ``findings``: pass-through list (empty unless status == ``ok``).
      - ``report``: full JSON report from the validator (empty dict on
        non-``ok`` status).

    ``runner`` is an optional injection point for tests (callable taking
    cmd list and returning ``(rc, stdout, stderr)``).
    """
    out: Dict[str, Any] = {
        "schema": BRIEF_CLI_VALIDATOR_SCHEMA,
        "status": "ok",
        "findings_count": 0,
        "highest_severity": "none",
        "findings": [],
        "report": {},
    }

    if os.environ.get(BRIEF_CLI_VALIDATOR_DISABLE_ENV_VAR, "").strip() == "1":
        out["status"] = "disabled"
        return out

    if validator_path is None:
        validator_path = _brief_cli_validator_path()
    if not validator_path.is_file():
        out["status"] = "binary-missing"
        out["detail"] = f"validator not found at {validator_path}"
        return out

    if timeout is None:
        try:
            timeout = int(
                os.environ.get(
                    BRIEF_CLI_VALIDATOR_TIMEOUT_ENV_VAR,
                    str(BRIEF_CLI_VALIDATOR_DEFAULT_TIMEOUT),
                )
            )
        except ValueError:
            timeout = BRIEF_CLI_VALIDATOR_DEFAULT_TIMEOUT

    tmp_path: Optional[pathlib.Path] = None
    try:
        fd, name = tempfile.mkstemp(
            prefix="dispatch_brief_cli_preflight_",
            suffix=".md",
        )
        tmp_path = pathlib.Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(prompt_text)

        cmd = [sys.executable, str(validator_path), str(tmp_path), "--json"]
        if workspace_path is not None and pathlib.Path(workspace_path).exists():
            cmd.extend(["--workspace", str(workspace_path)])

        if runner is not None:
            rc, stdout, stderr = runner(cmd)
        else:
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                rc, stdout, stderr = (
                    proc.returncode,
                    proc.stdout or "",
                    proc.stderr or "",
                )
            except subprocess.TimeoutExpired:
                out["status"] = "timeout"
                out["detail"] = f"brief-cli-validator timed out after {timeout}s"
                return out
            except (OSError, subprocess.SubprocessError) as exc:
                out["status"] = "run-error"
                out["detail"] = f"{type(exc).__name__}: {exc}"
                return out

        # rc=0 -> no findings (validator pass); rc=1 -> findings (validator
        # fail); rc=2 -> internal error in validator (file unreadable etc.).
        # Anything else is unexpected.
        if rc not in (0, 1):
            out["status"] = "run-error"
            out["detail"] = (
                f"brief-cli-validator exited rc={rc}; "
                f"stderr={stderr.strip()[:200]}"
            )
            return out

        try:
            report = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError as exc:
            out["status"] = "json-parse-error"
            out["detail"] = f"{exc}; stdout={stdout[:200]}"
            return out

        findings = list(report.get("findings") or [])
        out["report"] = report
        out["findings"] = findings
        out["findings_count"] = len(findings)
        if any(
            f.get("verdict") == "fail-tool-missing-or-help-broken"
            for f in findings
        ):
            out["highest_severity"] = "high"
        elif findings:
            out["highest_severity"] = "medium"
        else:
            out["highest_severity"] = "none"
        return out
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def emit_brief_cli_validator_summary(
    result: Dict[str, Any],
    *,
    stream=None,
    strict: bool = False,
) -> None:
    """Emit a one-line summary to stderr and (in strict mode w/ findings)
    an operator-actionable report enumerating each finding.

    Always-on contract: a single
    ``[BRIEF-CLI-VALIDATOR] findings=<N> status=<S> severity=<sev>``
    line is emitted unconditionally so downstream tooling can grep for
    it. The detailed per-finding block only fires when at least one
    finding is present (warn) or strict-mode FAIL is triggered.
    """
    if stream is None:
        stream = sys.stderr

    status = result.get("status", "ok")
    findings_count = int(result.get("findings_count", 0) or 0)
    severity = result.get("highest_severity", "none")

    stream.write(
        f"[BRIEF-CLI-VALIDATOR] findings={findings_count} "
        f"status={status} severity={severity}\n"
    )

    findings = result.get("findings") or []
    if not findings:
        return

    label = "FAIL" if strict else "WARN"
    stream.write(
        f"[BRIEF-CLI-VALIDATOR] {label}: {findings_count} stale brief "
        f"references detected. Per-finding detail:\n"
    )
    for f in findings:
        verdict = f.get("verdict", "<no-verdict>")
        tool_path = f.get("tool_path", "<no-tool>")
        flag = f.get("flag", "-")
        line = f.get("line", "-")
        stream.write(
            f"  - {verdict} | tool={tool_path} | flag={flag} | line={line}\n"
        )

    if strict:
        stream.write(
            "[BRIEF-CLI-VALIDATOR] strict mode: dispatch refused. Operator "
            "action: update brief to use the current CLI surface, or "
            "remove --strict-cli-validation to dispatch with WARN.\n"
        )
    else:
        stream.write(
            "[BRIEF-CLI-VALIDATOR] warn mode: dispatch proceeding. To "
            "fail closed on these findings re-run with "
            "--strict-cli-validation.\n"
        )


# ---------------------------------------------------------------------------
# PR9a-1: hunt-brief completeness gate (MCP-first + hunt-definition/skip-set
# + capability-adoption). Worker module: tools/hunt-brief-completeness-check.py
# r36-rebuttal: lane PR9a-1 registered in .auditooor/agent_pathspec.json agents[]
# ---------------------------------------------------------------------------

_HUNT_BRIEF_COMPLETENESS_EVALUATOR = None


def _load_hunt_brief_completeness_evaluator():
    """Lazy-load tools/hunt-brief-completeness-check.py:evaluate_brief.

    Returns the callable, or None when the worker module cannot be loaded
    (graceful degradation - the gate then reports status ``module-missing``
    and does NOT block dispatch).
    """
    global _HUNT_BRIEF_COMPLETENESS_EVALUATOR
    if _HUNT_BRIEF_COMPLETENESS_EVALUATOR is not None:
        return _HUNT_BRIEF_COMPLETENESS_EVALUATOR

    tool_path = REPO / "tools" / "hunt-brief-completeness-check.py"
    if not tool_path.is_file():
        return None
    try:
        import importlib.util as _il

        spec = _il.spec_from_file_location(
            "hunt_brief_completeness_check", str(tool_path)
        )
        if spec is None or spec.loader is None:
            return None
        mod = _il.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        evaluator = getattr(mod, "evaluate_brief", None)
        if callable(evaluator):
            _HUNT_BRIEF_COMPLETENESS_EVALUATOR = evaluator
            return evaluator
    except Exception:  # pragma: no cover - defensive; degrade gracefully
        return None
    return None


def run_hunt_brief_completeness_check(
    brief_text: str,
    *,
    lane_type: Optional[str],
    evaluator=None,
) -> Dict[str, Any]:
    """Evaluate the (enriched) hunt brief for the three completeness pillars.

    Returns a stable result dict regardless of whether the worker module is
    present. The result carries:

      - ``schema``: HUNT_BRIEF_COMPLETENESS_SCHEMA
      - ``status``: one of ``ok``, ``disabled``, ``module-missing``,
        ``not-hunt-lane``.
      - ``verdict``: pass-through from the evaluator (None when status !=
        ``ok``).
      - ``missing_pillars`` / ``pillar_evidence`` / ``detail``: pass-through.

    ``evaluator`` is an optional injection point for tests (callable taking
    ``(brief_text, lane_type=...)`` and returning the evaluator result dict).
    """
    out: Dict[str, Any] = {
        "schema": HUNT_BRIEF_COMPLETENESS_SCHEMA,
        "status": "ok",
        "verdict": None,
        "missing_pillars": [],
        "pillar_evidence": {},
        "detail": "",
    }

    if os.environ.get(
        HUNT_BRIEF_COMPLETENESS_DISABLE_ENV_VAR, ""
    ).strip() == "1":
        out["status"] = "disabled"
        return out

    lane_norm = (lane_type or "").strip().lower()
    if lane_norm not in HUNT_BRIEF_COMPLETENESS_LANE_TYPES:
        out["status"] = "not-hunt-lane"
        out["verdict"] = "pass-not-hunt-lane"
        out["detail"] = f"lane_type={lane_type!r} is not hunt-class"
        return out

    fn = evaluator or _load_hunt_brief_completeness_evaluator()
    if fn is None:
        out["status"] = "module-missing"
        out["detail"] = "hunt-brief-completeness-check.py not loadable"
        return out

    try:
        result = fn(brief_text, lane_type=lane_norm)
    except Exception as exc:  # pragma: no cover - defensive
        out["status"] = "run-error"
        out["detail"] = f"{type(exc).__name__}: {exc}"
        return out

    out["verdict"] = result.get("verdict")
    out["missing_pillars"] = result.get("missing_pillars") or []
    out["pillar_evidence"] = result.get("pillar_evidence") or {}
    out["detail"] = result.get("detail", "")
    out["rebuttal"] = result.get("rebuttal")
    return out


def emit_hunt_brief_completeness_summary(
    result: Dict[str, Any],
    *,
    stream=None,
    warn_only: bool = False,
) -> None:
    """Emit a one-line summary (always) + remediation detail (on fail)."""
    if stream is None:
        stream = sys.stderr

    status = result.get("status", "ok")
    verdict = result.get("verdict") or "n/a"
    missing = result.get("missing_pillars") or []

    stream.write(
        f"[HUNT-BRIEF-COMPLETENESS] verdict={verdict} status={status} "
        f"missing={missing}\n"
    )

    is_fail = isinstance(verdict, str) and verdict.startswith("fail-")
    if not is_fail:
        return

    label = "WARN" if warn_only else "REFUSED"
    detail = result.get("detail", "")
    stream.write(
        f"[HUNT-BRIEF-COMPLETENESS] {label}: hunt brief is incomplete - "
        f"{detail}\n"
    )
    stream.write(
        "[HUNT-BRIEF-COMPLETENESS] remediation: the dispatched hunt brief "
        "MUST carry (a) an MCP-first recall block citing vault_resume_context "
        "+ vault_brain_prime_context + vault_known_dead_ends, (b) the "
        "canonical hunt-definition (full pipeline) + skip-set directive, and "
        "(c) capability-adoption (brain-prime + per-function hacker-"
        "questions). See the canonical dispatch preamble in CLAUDE.md.\n"
    )
    if warn_only:
        stream.write(
            "[HUNT-BRIEF-COMPLETENESS] warn-only mode: dispatch proceeding. "
            "Unset "
            f"{HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR} to fail closed.\n"
        )
    else:
        stream.write(
            "[HUNT-BRIEF-COMPLETENESS] fail-closed: dispatch refused. Add the "
            "missing pillars to the brief, or add a bounded "
            "`<!-- pr9a-rebuttal: <reason> -->` marker, or set "
            f"{HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR}=1 to downgrade to warn.\n"
        )


def _default_repo_root() -> pathlib.Path:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=os.getcwd(),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            candidate = pathlib.Path(proc.stdout.strip()).expanduser()
            if candidate.exists() and candidate.is_dir():
                return candidate.resolve()
    except OSError:
        pass
    return pathlib.Path(os.getcwd()).resolve()


def _spawn_worker_log_is_recent(
    log_path: Optional[str],
    *,
    max_age_seconds: int = 900,
) -> bool:
    if not log_path:
        return False
    path = pathlib.Path(log_path).expanduser()
    if not path.is_file():
        return False
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return False
    return age <= max_age_seconds


def _dispatch_guard_audit_path(workspace_path: Optional[pathlib.Path]) -> pathlib.Path:
    base = _default_repo_root()
    if workspace_path is not None:
        candidate = pathlib.Path(workspace_path).expanduser()
        if candidate.exists() and candidate.is_dir():
            base = candidate
    return base / ".auditooor" / "spawn_worker_dispatch_guard.jsonl"


def _append_dispatch_guard_audit(
    workspace_path: Optional[pathlib.Path],
    row: Dict[str, Any],
) -> Optional[pathlib.Path]:
    audit_path = _dispatch_guard_audit_path(workspace_path)
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        return audit_path
    except OSError as exc:
        print(
            f"[dispatch-agent-with-prebriefing] WARN: could not write "
            f"spawn-worker dispatch guard audit at {audit_path}: {exc}",
            file=sys.stderr,
        )
        return None


def hunt_quarantine_path(workspace_path: Optional[pathlib.Path]) -> pathlib.Path:
    """Resolve the hunt_quarantine.jsonl sink for a workspace (E4.3).

    The sink is a re-dispatch-with-full-source queue: an unable-to-anchor
    finding lands here instead of being silently set applies_to_target='no'.
    Downstream fcc MUST treat a quarantined unit as UNRESOLVED (re-dispatch
    pending), NEVER as ruled-out.
    """
    base = _default_repo_root()
    if workspace_path is not None:
        candidate = pathlib.Path(workspace_path).expanduser()
        if candidate.exists() and candidate.is_dir():
            base = candidate
    return base / ".auditooor" / HUNT_QUARANTINE_BASENAME


def quarantine_unable_to_anchor(
    workspace_path: Optional[pathlib.Path],
    *,
    unit: str,
    source_ref: str = "",
    reason: str = "unable-to-anchor",
    confidence: Optional[float] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Optional[pathlib.Path]:
    """Append an unable-to-anchor finding to the hunt_quarantine.jsonl sink
    (E4.3) for a re-dispatch-with-full-source second pass.

    This is the programmatic counterpart to the SOURCE-READ MANDATE: a finding
    the hunter could not anchor is QUARANTINED (status 'quarantined',
    needs_full_source true), explicitly NOT ruled out. The row records
    ruled_out=False so no downstream consumer can miscount it as examined +
    dismissed.
    """
    row: Dict[str, Any] = {
        "unit": unit,
        "source_ref": source_ref,
        "reason": reason,
        "status": "quarantined",
        "needs_full_source": True,
        "ruled_out": False,
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    if confidence is not None:
        row["confidence"] = confidence
    if extra:
        # Caller-supplied fields never override the load-bearing invariants
        # (ruled_out / status / needs_full_source).
        for key, value in extra.items():
            if key not in row:
                row[key] = value
    sink = hunt_quarantine_path(workspace_path)
    try:
        sink.parent.mkdir(parents=True, exist_ok=True)
        with sink.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        return sink
    except OSError as exc:
        print(
            f"[dispatch-agent-with-prebriefing] WARN: could not write "
            f"hunt quarantine row at {sink}: {exc}",
            file=sys.stderr,
        )
        return None


def check_spawn_worker_dispatch_guard(
    *,
    prompt_text: str,
    workspace_path: Optional[pathlib.Path],
    lane_type: Optional[str],
    severity: Optional[str],
    claude_bin: str,
) -> Tuple[bool, Dict[str, Any], str]:
    """Fail closed for direct worker dispatch unless spawn-worker.sh is proven.

    This guard only applies to ``--dispatch``. Plain enrichment remains usable
    because ``spawn-worker.sh`` calls this script to build the prompt before
    handing it to the operator/orchestrator.
    """
    prompt_sha = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    bypass_active = os.environ.get(SPAWN_WORKER_BYPASS_ENV_VAR, "").strip() == "1"
    bypass_reason = os.environ.get(SPAWN_WORKER_BYPASS_REASON_ENV_VAR, "").strip()
    spawn_ok = os.environ.get(SPAWN_WORKER_OK_ENV_VAR, "").strip() == "1"
    spawn_log_path = os.environ.get(SPAWN_WORKER_LOG_PATH_ENV_VAR, "").strip()
    spawn_log_recent = _spawn_worker_log_is_recent(spawn_log_path)

    row: Dict[str, Any] = {
        "ts": _utc_now_iso(),
        "tool": "dispatch-agent-with-prebriefing.py",
        "schema": DISPATCH_GUARD_SCHEMA,
        "prompt_sha256": prompt_sha,
        "workspace": str(workspace_path) if workspace_path is not None else None,
        "lane_type": lane_type,
        "severity": severity,
        "claude_bin": claude_bin,
        "spawn_worker_ok": spawn_ok,
        "spawn_worker_lane_id": os.environ.get(SPAWN_WORKER_LANE_ID_ENV_VAR, "").strip() or None,
        "spawn_worker_log_path": spawn_log_path or None,
        "spawn_worker_log_recent": spawn_log_recent,
    }

    if spawn_ok or spawn_log_recent:
        row["status"] = "DISPATCH_ALLOWED"
        row["allow_reason"] = "spawn-worker-env" if spawn_ok else "recent-spawn-worker-log"
        audit_path = _append_dispatch_guard_audit(workspace_path, row)
        if audit_path is not None:
            row["audit_path"] = str(audit_path)
        return True, row, ""

    if bypass_active:
        if not bypass_reason:
            row.update(
                {
                    "status": "REFUSED",
                    "missing_inputs": [SPAWN_WORKER_BYPASS_REASON_ENV_VAR],
                    "refusal": "spawn-worker-bypass-reason-required",
                }
            )
            audit_path = _append_dispatch_guard_audit(workspace_path, row)
            if audit_path is not None:
                row["audit_path"] = str(audit_path)
            msg = (
                f"[dispatch-agent-with-prebriefing] REFUSED: "
                f"{SPAWN_WORKER_BYPASS_ENV_VAR}=1 requires "
                f"{SPAWN_WORKER_BYPASS_REASON_ENV_VAR}=<reason>.\n"
            )
            return False, row, msg
        row.update(
            {
                "status": "BYPASSED",
                "bypass_reason": bypass_reason,
                "allow_reason": "audited-bypass",
            }
        )
        audit_path = _append_dispatch_guard_audit(workspace_path, row)
        if audit_path is not None:
            row["audit_path"] = str(audit_path)
        msg = (
            f"[dispatch-agent-with-prebriefing] WARN: spawn-worker dispatch "
            f"guard bypassed: {bypass_reason}\n"
        )
        return True, row, msg

    row.update(
        {
            "status": "REFUSED",
            "missing_inputs": [
                f"{SPAWN_WORKER_OK_ENV_VAR}=1",
                f"{SPAWN_WORKER_LOG_PATH_ENV_VAR}=<recent file>",
            ],
            "refusal": "spawn-worker-required",
        }
    )
    audit_path = _append_dispatch_guard_audit(workspace_path, row)
    if audit_path is not None:
        row["audit_path"] = str(audit_path)
    msg = (
        "[dispatch-agent-with-prebriefing] REFUSED: direct worker dispatch "
        "must go through tools/spawn-worker.sh and leave a recent "
        "spawn_worker_log.jsonl entry. Re-run via spawn-worker.sh, "
        f"or set {SPAWN_WORKER_BYPASS_ENV_VAR}=1 with "
        f"{SPAWN_WORKER_BYPASS_REASON_ENV_VAR}=<reason> for an audited bypass.\n"
    )
    return False, row, msg


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read_prompt(args: argparse.Namespace) -> str:
    if args.prompt is not None:
        return args.prompt
    if args.prompt_file:
        return pathlib.Path(args.prompt_file).expanduser().read_text(
            encoding="utf-8"
        )
    # stdin fallback
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit(
        "[dispatch-agent-with-prebriefing] ERROR: no prompt source - pass "
        "--prompt, --prompt-file, or pipe via stdin."
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dispatch-agent-with-prebriefing",
        description=(
            "Pre-spawn hook wrapper: prepends a Section 15a/15b/15c/15d "
            "META-1 block (sourced from vault_dispatch_brief_skeleton) "
            "to an Agent-tool prompt BEFORE the orchestrator spawns the "
            "worker. Closes the iter14 LLLL shelfware gap."
        ),
    )
    p.add_argument(
        "--prompt",
        default=None,
        help="Raw prompt text (or use --prompt-file or stdin).",
    )
    p.add_argument(
        "--prompt-file",
        default=None,
        help="Path to a file containing the prompt text.",
    )
    p.add_argument(
        "--lane-type",
        default=None,
        # NOTE: intentionally NOT restricted via choices= so that
        # spawn-worker.sh can pass extended lane types (tool-build,
        # wire-audit, capability, infra) without triggering argparse rc=2.
        # Unknown lane types are gracefully downgraded to "filing" inside
        # build_enriched_prompt() via the lane_type_fallback_from path.
        # Root cause of 100% failed-raw-fallback in 2026-05-26 session:
        # spawn-worker.sh passed --lane-type tool-build which was not in
        # the old choices list, causing argparse to exit rc=2 before any
        # stdout was written, leaving ENRICHED_FILE empty.
        help=(
            "Lane type. Keyword-inferred from the prompt body if omitted. "
            "Canonical types: dispute, mediation, filing, hunt, "
            "opposed-trace-harness, escalation. Extended types accepted "
            "(tool-build, wire-audit, capability, infra) and downgraded "
            "to 'filing' for skeleton purposes."
        ),
    )
    p.add_argument(
        "--severity",
        default=None,
        help="Severity (LOW|MEDIUM|HIGH|CRITICAL). Keyword-inferred if omitted.",
    )
    p.add_argument(
        "--workspace",
        default=None,
        help="Workspace absolute path. cwd-inferred if omitted.",
    )
    p.add_argument(
        "--target-finding-class",
        default="",
        help="Optional finding-class hint passed to skeleton filler.",
    )
    p.add_argument(
        "--no-infer",
        action="store_true",
        help="Disable inference - explicit args only.",
    )
    p.add_argument(
        "--dispatch",
        action="store_true",
        help=(
            "Pipe the enriched prompt to `claude -p` instead of just "
            "emitting to stdout. Returns claude's stdout / exit code."
        ),
    )
    p.add_argument(
        "--claude-bin",
        default="claude",
        help="Path to claude CLI when --dispatch is used (default: claude).",
    )
    p.add_argument(
        "--json-meta",
        action="store_true",
        help=(
            "Emit a JSON meta block on stderr documenting inferred lane "
            "type / severity / skeleton pack ID / fallback path."
        ),
    )
    p.add_argument(
        "--skeleton-only",
        action="store_true",
        help=(
            "Emit only the META-1 Section 15 block. This is intended for "
            "wrappers that need to inject the block into another prompt."
        ),
    )
    p.add_argument(
        "--infer-all",
        action="store_true",
        help=(
            "Convenience flag: implies prompt-from-stdin and full "
            "inference of lane/severity/workspace."
        ),
    )
    # F4-safe (spec E4.4): hunt-mode selector. generate-broad raises recall
    # (kill-rubric prior OFF, uncertain allowed -> quarantine); verify-strict
    # is the current R76 anchor-or-quarantine default. The flag wins over the
    # AUDITOOOR_DISPATCH_HUNT_MODE env var.
    p.add_argument(
        "--hunt-mode",
        default=None,
        choices=list(VALID_HUNT_MODES),
        help=(
            "Hunt mode for the source-read mandate. 'verify-strict' (default): "
            "R76 anchor-or-quarantine. 'generate-broad': recall-first - "
            "kill-rubric prior OFF, uncertain findings allowed and routed to "
            "the hunt_quarantine sink rather than dropped. Overrides "
            "AUDITOOOR_DISPATCH_HUNT_MODE. Neither mode silently rules out an "
            "unanchorable finding."
        ),
    )
    # BRIEF-KIND GATING (2026-07-12): opt-in/gate the hunt template. A
    # tooling/concrete-fix brief passes through RAW (no bridge-proof-domain /
    # hacker-question / R36-R45 skeleton wrap). 'auto' heuristic-infers.
    p.add_argument(
        "--brief-kind",
        default="auto",
        choices=list(VALID_BRIEF_KINDS),
        help=(
            "Brief intent. 'hunt': full META-1 vulnerability-hunt skeleton "
            "(default for hunt-class prompts). 'tooling': pass the operator "
            "prompt through RAW (no hunt template) for concrete tooling/infra "
            "fixes. 'auto' (default): heuristic-infer tooling vs hunt from the "
            "lane-type + prompt body."
        ),
    )
    # LIFT-23: brief-cli-validator preflight. <!-- r36-rebuttal: lane-LIFT-23 -->
    p.add_argument(
        "--strict-cli-validation",
        action="store_true",
        help=(
            "Hard-fail (rc=3) if tools/brief-cli-validator.py reports any "
            "stale CLI flag or missing tool path in the prompt body. "
            "Default behavior is warn-only: dispatch proceeds and a "
            "[BRIEF-CLI-VALIDATOR] summary is emitted to stderr. The "
            "preflight can be disabled entirely via "
            "AUDITOOOR_BRIEF_CLI_VALIDATOR_DISABLE=1."
        ),
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # F4-safe (E4.4): a --hunt-mode flag wins over the env var. Export it so the
    # env-based pack_source_read_mandate() resolve (used deep in the prompt
    # builder) sees the flag without threading a param through every call.
    if getattr(args, "hunt_mode", None):
        os.environ[DISPATCH_HUNT_MODE_ENV_VAR] = args.hunt_mode

    prompt_text = _read_prompt(args)

    workspace = None
    if args.workspace:
        workspace = pathlib.Path(args.workspace).expanduser()
        if not workspace.exists():
            print(
                f"[dispatch-agent-with-prebriefing] WARN: workspace "
                f"{workspace} does not exist; passing through anyway "
                "(graceful degradation).",
                file=sys.stderr,
            )

    # LIFT-23 brief-cli-validator preflight. <!-- r36-rebuttal: lane-LIFT-23 -->
    # Always run unless explicitly disabled via env var. Default mode is
    # warn-only (dispatch proceeds, summary emitted). Strict mode hard-
    # fails with rc=EXIT_BRIEF_CLI_VALIDATOR_REFUSED so cron / scripted
    # callers can opt in to fail-closed behavior.
    strict_cli_validation = bool(
        getattr(args, "strict_cli_validation", False)
        or os.environ.get(
            "AUDITOOOR_BRIEF_CLI_VALIDATOR_STRICT", ""
        ).strip()
        == "1"
    )
    brief_cli_validator_result = run_brief_cli_validator_on_text(
        prompt_text,
        workspace_path=workspace,
    )
    emit_brief_cli_validator_summary(
        brief_cli_validator_result,
        stream=sys.stderr,
        strict=strict_cli_validation,
    )
    if (
        strict_cli_validation
        and brief_cli_validator_result.get("findings_count", 0) > 0
    ):
        if args.json_meta:
            sys.stderr.write(
                json.dumps(
                    {"brief_cli_validator": brief_cli_validator_result},
                    sort_keys=True,
                )
                + "\n"
            )
        return EXIT_BRIEF_CLI_VALIDATOR_REFUSED

    dispatch_guard_meta: Optional[Dict[str, Any]] = None
    if args.dispatch:
        guard_ok, dispatch_guard_meta, guard_msg = check_spawn_worker_dispatch_guard(
            prompt_text=prompt_text,
            workspace_path=workspace,
            lane_type=args.lane_type,
            severity=args.severity,
            claude_bin=args.claude_bin,
        )
        if guard_msg:
            sys.stderr.write(guard_msg)
        if not guard_ok:
            if args.json_meta:
                sys.stderr.write(
                    json.dumps(
                        {"dispatch_guard": dispatch_guard_meta},
                        sort_keys=True,
                    )
                    + "\n"
                )
            return EXIT_DISPATCH_GUARD_REFUSED

    enriched, meta = build_enriched_prompt(
        prompt_text=prompt_text,
        lane_type=args.lane_type,
        severity=args.severity,
        workspace_path=workspace,
        target_finding_class=args.target_finding_class,
        infer_missing=(not args.no_infer),
        brief_kind=getattr(args, "brief_kind", "auto"),
    )

    # PR9a-1 hunt-brief completeness gate. Validate the ENRICHED brief (the
    # exact text the worker will see) for the three completeness pillars.
    # Default is FAIL-CLOSED for hunt-class lanes; warn-only via
    # AUDITOOOR_HUNT_BRIEF_COMPLETENESS_WARN_ONLY=1; disabled via
    # AUDITOOOR_HUNT_BRIEF_COMPLETENESS_DISABLE=1. The gate only blocks the
    # --dispatch flow (the spawn path); plain enrichment to stdout still
    # emits the summary so spawn-worker.sh / operators see the verdict.
    # r36-rebuttal: lane PR9a-1 registered in .auditooor/agent_pathspec.json
    effective_lane_type = meta.get("lane_type") or args.lane_type
    hunt_brief_completeness_result = run_hunt_brief_completeness_check(
        enriched,
        lane_type=effective_lane_type,
    )
    hunt_brief_completeness_warn_only = (
        os.environ.get(
            HUNT_BRIEF_COMPLETENESS_WARN_ENV_VAR, ""
        ).strip()
        == "1"
    )
    emit_hunt_brief_completeness_summary(
        hunt_brief_completeness_result,
        stream=sys.stderr,
        warn_only=hunt_brief_completeness_warn_only,
    )
    _hbc_verdict = hunt_brief_completeness_result.get("verdict")
    hunt_brief_completeness_fail = (
        isinstance(_hbc_verdict, str) and _hbc_verdict.startswith("fail-")
    )
    if (
        args.dispatch
        and hunt_brief_completeness_fail
        and not hunt_brief_completeness_warn_only
    ):
        if args.json_meta:
            sys.stderr.write(
                json.dumps(
                    {
                        "hunt_brief_completeness": (
                            hunt_brief_completeness_result
                        )
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        return EXIT_HUNT_BRIEF_COMPLETENESS_REFUSED

    if args.dispatch:
        rc, out, err = dispatch_via_claude_cli(
            enriched, claude_bin=args.claude_bin
        )
        sys.stdout.write(out)
        if err:
            sys.stderr.write(err)
        if args.json_meta:
            sys.stderr.write(
                json.dumps(
                    {
                        **meta,
                        "dispatch_rc": rc,
                        "dispatch_guard": dispatch_guard_meta,
                        # LIFT-23 <!-- r36-rebuttal: lane-LIFT-23 -->
                        "brief_cli_validator": brief_cli_validator_result,
                        # PR9a-1 hunt-brief completeness gate result.
                        "hunt_brief_completeness": (
                            hunt_brief_completeness_result
                        ),
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        return rc

    output = enriched
    if args.skeleton_only:
        end_marker = "<!-- END dispatch-agent-with-prebriefing META-1 block -->"
        pos = enriched.find(end_marker)
        if pos >= 0:
            output = enriched[: pos + len(end_marker)] + "\n"

    sys.stdout.write(output)
    if not output.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()

    if args.json_meta:
        sys.stderr.write(
            json.dumps(
                {
                    **meta,
                    # LIFT-23 <!-- r36-rebuttal: lane-LIFT-23 -->
                    "brief_cli_validator": brief_cli_validator_result,
                    # PR9a-1 hunt-brief completeness gate result.
                    "hunt_brief_completeness": hunt_brief_completeness_result,
                },
                sort_keys=True,
            )
            + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
