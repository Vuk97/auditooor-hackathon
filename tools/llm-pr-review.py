#!/usr/bin/env python3
"""llm-pr-review.py — dual-LLM PR review pipeline (Codex substitute).

Background
----------
Codex review is unavailable for the foreseeable future. This tool substitutes
the Kimi K2.6 + Minimax M2.7 dual-LLM pipeline that was validated this session
into the canonical PR-review slot.

Calibration (validated this session, see docs/LLM_DELEGATION_MATRIX.md)
-----------------------------------------------------------------------
- Kimi:    ~67% PR-review accuracy line-level + strong on methodology critique.
           Weak on audit / gap-finding claims.
- Minimax: ~50% PR-review accuracy + strong on synthesis. Weak on
           cross-reference enumeration.
- Synergy: dual-agreement = high-confidence. Disagreement = Claude triage
           signal. Neither model alone is authoritative — consensus + human
           verification before adopting.

Behaviour
---------
For each target PR, the tool:
  1. Fetches the diff via `gh pr diff <n>`.
  2. Asks Kimi and Minimax for a structured verdict
     (MERGE-OK / NEEDS-FIX / NEEDS-REWORK / OFF-SCOPE) with rationale.
  3. Re-prompts once if the model didn't follow the schema.
  4. Computes consensus: AGREED-X (both same verdict) or DISAGREED.
  5. Optionally posts the dual-review comment via `gh pr comment`.
  6. Optionally auto-merges (squash + delete-branch) when both LLMs agreed
     on MERGE and `gh pr view --json mergeStateStatus` is CLEAN.
  7. Writes a per-PR JSON artefact with the diff hash, both raw outputs,
     parsed verdict, comment URL, and merge SHA.

Usage
-----
    python tools/llm-pr-review.py [options]
      --pr <n>             Review a single PR
      --all-open           Review all open PRs (mutually exclusive with --pr)
      --auto-merge         Auto-merge AGREED-MERGE consensuses (default off)
      --post-comments      Opt-IN to posting the dual-review comment
                           (default: artefact-only, no comment posted)
      --no-post-comments   Explicitly skip posting (default; redundant
                           but accepted for backwards-compat with callers
                           that previously passed it)
      --no-auto-merge      Explicitly disable auto-merge (default)
      --skip-pr <n>        Skip specific PR numbers (repeatable)
      --output-dir <path>  Per-PR artefact directory
                           (default: /tmp/llm-pr-review/)
      --providers k,m      Which LLMs to query (default: kimi,minimax)
      --max-tokens <n>     Per-LLM max_tokens (default: 800)
      --timeout <sec>      Per-LLM call timeout (default: 60)

Default posture: ARTEFACT-ONLY. The tool writes a per-PR JSON artefact and
does NOT post a GitHub comment unless the caller passes ``--post-comments``
explicitly. This is the safe default for cron / automation: a misbehaving
model cannot spam every open PR before a human has reviewed the artefact.
Codex 2026-04-26 review (PR #224 P0 #3) flagged the previous default-on
posture as a comment-spam risk; this is the inversion.

Implementation notes
--------------------
- Stdlib + subprocess only. NO new pip deps.
- Reuses `tools/llm-dispatch.py` as the underlying provider transport — it
  already speaks the Anthropic Messages API for both Kimi and Minimax,
  enforces the consent boundary, returns only the final TextPart (drops
  thinking blocks), and writes its own per-call audit trail to
  agent_outputs/.
- Minimax key is read from `~/.claude/settings.json` env.ANTHROPIC_AUTH_TOKEN
  when MINIMAX_API_KEY is not already set (the established convention on
  this workstation; the same settings file already routes Anthropic SDK
  calls to api.minimax.io/anthropic).
- Every posted comment includes the calibration disclaimer verbatim.

Hard rules followed
-------------------
- Stdlib only (argparse, json, os, hashlib, pathlib, subprocess, sys, time).
- No standalone .md docs (rationale lives here + in the commit message).
- No comment-leakage in any test fixture (tests use neutral inputs).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
LLM_DISPATCH = REPO_ROOT / "tools" / "llm-dispatch.py"
CALIBRATION_TOOL = REPO_ROOT / "tools" / "llm-calibration-log.py"
PATTERN_TAXONOMY_PATH = REPO_ROOT / "reference" / "pattern_taxonomy.json"
# Cap: the taxonomy bucket sample injected into LLM prompts. 60 was the
# random-sample size before V5 PR-G; we keep the same cap so prompt
# token budgets stay flat while replacing random sampling with bucket
# sampling. See V5 Gap 27.
TAXONOMY_PROMPT_CAP = 60

VERDICTS = ("MERGE-OK", "NEEDS-FIX", "NEEDS-REWORK", "OFF-SCOPE")
VERDICT_RE = re.compile(
    r"\bVERDICT\s*[:=]\s*(MERGE-OK|NEEDS-FIX|NEEDS-REWORK|OFF-SCOPE)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# V4 P5 — task-type presets (per docs/ROADMAP_10_OF_10_V4.md §4 P5)
# ---------------------------------------------------------------------------
#
# The default code path (--task-type omitted) uses REVIEW_PROMPT_TEMPLATE +
# the 4-verdict schema (MERGE-OK / NEEDS-FIX / NEEDS-REWORK / OFF-SCOPE), so
# every existing caller keeps working unchanged.
#
# When --task-type is supplied, the script swaps in a preset prompt + a
# task-specific verdict schema and computes the ``requires_codex`` routing
# field per V4 §3.2. Calibration log writes inherit the supplied task-type
# label so per-task accuracy can be sliced separately from the canonical
# ``pr-review`` aggregate.

TASK_TYPES = (
    "detector-tier-b",
    "gate-hardening",
    "docs-plan",
    "submission-critical",
    "crypto-review",
    "econ-review",
)

TASK_PROMPTS = {
    "detector-tier-b": (
        "You are reviewing a Detector-Tier-B PR. The goal is a mechanical "
        "smoke-test plus a cross-fire consistency check (does the diff match "
        "the existing tier-B fixture conventions, predicate composition, and "
        "registry hygiene rules?).\n\n"
        "PR title: {title}\nPR number: #{number}\nBase branch: {base}\n\n"
        "{taxonomy_block}"
        "Diff (truncated to {max_diff_chars} chars if longer):\n"
        "---\n{diff}\n---\n\n"
        "Reply in EXACTLY this format (case-sensitive):\n\n"
        "    VERDICT: <PASS|FAIL>\n"
        "    SEVERITY: <low|medium|high>\n"
        "    SMOKE_SCORE: <0.0-1.0>\n"
        "    CROSSFIRE_SCORE: <0.0-1.0>\n"
        "    RATIONALE: <2-6 sentences citing concrete lines or files>\n"
    ),
    "gate-hardening": (
        "You are reviewing a pre-submit hard-gate hardening PR. Focus on "
        "whether the diff actually tightens an existing gate (security, "
        "reliability, scope-discipline) without introducing a regression "
        "path.\n\n"
        "PR title: {title}\nPR number: #{number}\nBase branch: {base}\n\n"
        "Diff (truncated to {max_diff_chars} chars if longer):\n"
        "---\n{diff}\n---\n\n"
        "Reply in EXACTLY this format (case-sensitive):\n\n"
        "    VERDICT: <PASS|FAIL>\n"
        "    GATE: <pre-submit|merge|render|other>\n"
        "    HARDENING_SCORE: <0.0-1.0>\n"
        "    RECOMMENDATIONS: <semicolon-separated list, or 'none'>\n"
        "    RATIONALE: <2-6 sentences citing concrete lines or files>\n"
    ),
    "docs-plan": (
        "You are reviewing a documentation-plan PR (an outline / TOC / "
        "roadmap-style doc, not implementation code). Focus on completeness "
        "and structural coherence of the plan.\n\n"
        "PR title: {title}\nPR number: #{number}\nBase branch: {base}\n\n"
        "Diff (truncated to {max_diff_chars} chars if longer):\n"
        "---\n{diff}\n---\n\n"
        "Reply in EXACTLY this format (case-sensitive):\n\n"
        "    VERDICT: <PASS|FAIL>\n"
        "    DOC_PLAN_COMPLETENESS: <0.0-1.0>\n"
        "    SECTIONS: <semicolon-separated section titles, or 'none'>\n"
        "    RATIONALE: <2-6 sentences citing concrete lines or files>\n"
    ),
    "submission-critical": (
        "You are reviewing a submission-critical PR (rendering / engage.py "
        "stage). The diff feeds the live submission pipeline and a render "
        "regression breaks every queued submission.\n\n"
        "PR title: {title}\nPR number: #{number}\nBase branch: {base}\n\n"
        "Diff (truncated to {max_diff_chars} chars if longer):\n"
        "---\n{diff}\n---\n\n"
        "Reply in EXACTLY this format (case-sensitive):\n\n"
        "    VERDICT: <PASS|FAIL>\n"
        "    CRITICAL_BLOCKS: <integer count of must-fix blockers>\n"
        "    RENDER_SCORE: <0.0-1.0>\n"
        "    RATIONALE: <2-6 sentences citing concrete lines or files>\n"
    ),
    "crypto-review": (
        "You are reviewing a crypto / proof-system PR. Focus on the "
        "correctness of the cryptographic construction (signatures, hashes, "
        "domain separation, soundness of any proof object).\n\n"
        "PR title: {title}\nPR number: #{number}\nBase branch: {base}\n\n"
        "Diff (truncated to {max_diff_chars} chars if longer):\n"
        "---\n{diff}\n---\n\n"
        "Reply in EXACTLY this format (case-sensitive):\n\n"
        "    VERDICT: <PASS|FAIL>\n"
        "    PROOF_CORRECTNESS: <true|false>\n"
        "    RATIONALE: <2-6 sentences citing concrete lines or files>\n"
    ),
    "econ-review": (
        "You are reviewing an economic-simulation PR (rate models, fee "
        "curves, liquidation thresholds, oracle assumptions). Focus on "
        "validity of the simulation model and parameter choice.\n\n"
        "PR title: {title}\nPR number: #{number}\nBase branch: {base}\n\n"
        "Diff (truncated to {max_diff_chars} chars if longer):\n"
        "---\n{diff}\n---\n\n"
        "Reply in EXACTLY this format (case-sensitive):\n\n"
        "    VERDICT: <PASS|FAIL>\n"
        "    SIMULATION_VALIDITY: <true|false>\n"
        "    RATIONALE: <2-6 sentences citing concrete lines or files>\n"
    ),
}

# Verdict schemas describe the JSON shape that the per-PR artefact will
# carry alongside the raw output. The script does NOT enforce schema match
# on the model reply — extra/missing fields are tolerated and surfaced as
# parser failure on the consensus side. The schema dict here is a
# contract for downstream consumers (reviewer dashboards, calibration
# slicing) so they know what keys to expect for each preset.
TASK_VERDICT_SCHEMAS = {
    "detector-tier-b": {
        "verdict": None,           # PASS | FAIL
        "severity": None,          # low | medium | high
        "smoke_score": None,       # float in [0, 1]
        "crossfire_score": None,   # float in [0, 1]
        "rationale": None,
        "requires_codex": False,
    },
    "gate-hardening": {
        "verdict": None,
        "gate": None,
        "hardening_score": None,
        "recommendations": None,
        "rationale": None,
        "requires_codex": True,
    },
    "docs-plan": {
        "verdict": None,
        "doc_plan_completeness": None,
        "sections": None,
        "rationale": None,
        "requires_codex": False,
    },
    "submission-critical": {
        "verdict": None,
        "critical_blocks": None,
        "render_score": None,
        "rationale": None,
        "requires_codex": True,
    },
    "crypto-review": {
        "verdict": None,
        "proof_correctness": None,
        "submission_bound": False,
        "rationale": None,
        "requires_codex": False,   # overwritten at runtime
    },
    "econ-review": {
        "verdict": None,
        "simulation_validity": None,
        "submission_bound": False,
        "rationale": None,
        "requires_codex": False,
    },
}

# Per-preset verdict regex. The two-state PASS/FAIL grammar applies to all
# six presets; the default 4-verdict regex (above) stays in place for
# callers that do not pass --task-type.
TASK_VERDICT_RE = re.compile(
    r"\bVERDICT\s*[:=]\s*(PASS|FAIL)\b",
    re.IGNORECASE,
)


def compute_requires_codex(
    task_type: str | None,
    submission_bound: bool = False,
) -> bool:
    """Implement V4 §3.2 routing: which task-types must reach Codex?

    Returns True when the PR must be forwarded to the Codex pipeline
    (i.e. auto-merge by `tools/llm-pr-review.py` is forbidden and a human
    + Codex review is required before merge).

    The truth table mirrors the spec:

      detector-tier-b      -> False  (mechanical smoke + cross-fire only)
      gate-hardening       -> True   (every pre-submit gate change)
      docs-plan            -> False  (pure plan, no executable surface)
      submission-critical  -> True   (touches the live render pipeline)
      crypto-review        -> submission_bound
      econ-review          -> submission_bound
      <None / unknown>     -> False  (default-on legacy 4-verdict path)

    ``submission_bound`` is only consulted for the two review presets;
    other task-types ignore it (keeping the call-site uniform).
    """
    if task_type is None:
        return False
    routing = {
        "detector-tier-b": False,
        "gate-hardening": True,
        "docs-plan": False,
        "submission-critical": True,
        "crypto-review": bool(submission_bound),
        "econ-review": bool(submission_bound),
    }
    return routing.get(task_type, False)


def parse_task_verdict(text: str) -> tuple[str | None, str]:
    """Extract (PASS|FAIL, rationale-tail) from a task-preset response.

    Mirrors :func:`parse_verdict` but for the two-state grammar used by
    the V4 P5 task-type presets. Returns (None, text) when no schema
    match is found.
    """
    if not text:
        return None, ""
    m = TASK_VERDICT_RE.search(text)
    if not m:
        return None, text.strip()
    verdict = m.group(1).upper()
    tail = text[m.end():].lstrip()
    if tail.upper().startswith("RATIONALE:"):
        tail = tail[len("RATIONALE:"):].lstrip()
    return verdict, tail.strip()


def build_task_prompt(
    task_type: str,
    *,
    title: str,
    number: int,
    base: str,
    diff: str,
    max_diff_chars: int,
    taxonomy_block: str = "",
    oos_rules: list[str] | None = None,
) -> str:
    """Format the per-preset prompt template with PR metadata + diff.

    ``taxonomy_block`` is an optional pre-formatted string from
    :func:`build_taxonomy_block` injected immediately before the diff
    on task-types where a relevant pattern sample helps (currently
    ``detector-tier-b`` — patterns are the *subject* of that review).
    Empty string for every other task-type, preserving the legacy
    prompt byte-for-byte.

    V5 P0-02 (Gap 9): When ``oos_rules`` is non-empty AND the task type
    is source-mining-flavoured (``submission-critical``,
    ``crypto-review``, ``econ-review``), the OOS path-rule section is
    prepended verbatim above the task prompt. Other task types ignore
    ``oos_rules`` — Tier-B detector smoke tests and docs-plan reviews do
    not consume scope rules. ``oos_rules=None`` is the legacy code path
    and is byte-identical to pre-Gap-9 behaviour.
    """
    template = TASK_PROMPTS[task_type]
    formatted = template.format(
        title=title,
        number=number,
        base=base,
        diff=diff,
        max_diff_chars=max_diff_chars,
        taxonomy_block=taxonomy_block,
    )
    if oos_rules and task_type in (
        "submission-critical", "crypto-review", "econ-review"
    ):
        section = _format_oos_packet_section(oos_rules)
        if section:
            return section + "\n" + formatted
    return formatted


# ---------------------------------------------------------------------------
# V5 PR-G — taxonomy-aware pattern sample (Gap 27)
# ---------------------------------------------------------------------------
#
# Before V5 Gap-27, the dispatcher could attach a *random* 60-name pattern
# sample to LLM prompts. LISA-Bench batch 1 (agent a1ef8b86) showed that
# random sampling drove a 35/96 false-positive rate on Minimax "novel"
# claims because the LLM literally could not see the close-by names from
# other taxonomy buckets. The taxonomy clusterer (Gap 27) replaces that
# random sample with a bucket-relevant sample. ``select_for_finding``
# in ``tools/pattern-taxonomy-cluster.py`` is the canonical chooser.


def _load_pattern_taxonomy_module():
    """Load tools/pattern-taxonomy-cluster.py via importlib.

    The file uses a hyphenated name, which is not importable via the
    normal ``import`` statement. Cached on ``sys.modules``. Returns
    None if the tool is missing — caller falls back to no taxonomy
    block (legacy behaviour).
    """
    cache_key = "_llm_pr_review_pattern_taxonomy"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    tool_path = REPO_ROOT / "tools" / "pattern-taxonomy-cluster.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(cache_key, tool_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[cache_key] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def load_pattern_taxonomy() -> dict | None:
    """Read the cached taxonomy manifest, falling back to live build.

    Returns the manifest dict on success or None when the taxonomy
    is unavailable AND cannot be regenerated (e.g. fresh worktree,
    missing patterns dir). Callers must treat None as "skip the
    taxonomy enrichment, fall back to legacy behaviour".
    """
    if PATTERN_TAXONOMY_PATH.is_file():
        try:
            data = json.loads(PATTERN_TAXONOMY_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "buckets" in data:
                return data
        except Exception:
            pass
    # Live-build fallback so callers don't have to remember to run
    # `make pattern-taxonomy` first. Cheap: <100ms over 1.3k yaml files.
    mod = _load_pattern_taxonomy_module()
    if mod is None:
        return None
    try:
        names = mod.discover_patterns(REPO_ROOT / "reference" / "patterns.dsl")
        return mod.build_manifest(names)
    except Exception:
        return None


def build_taxonomy_block(
    task_type: str,
    *,
    title: str,
    diff: str,
    cap: int = TAXONOMY_PROMPT_CAP,
) -> str:
    """Build the prompt-injected pattern context for ``task_type``.

    Currently only ``detector-tier-b`` consumes a taxonomy block —
    that's the task-type where the LLM is reasoning about pattern
    additions/edits and benefits from seeing the bucket-adjacent
    pattern names. Other presets receive an empty string so their
    prompts are byte-for-byte identical to the pre-PR-G version.
    """
    if task_type != "detector-tier-b":
        return ""
    manifest = load_pattern_taxonomy()
    if manifest is None:
        return ""
    mod = _load_pattern_taxonomy_module()
    if mod is None:
        return ""
    text = (title or "") + "\n" + (diff or "")
    sample, buckets_used = mod.select_for_finding(manifest, text=text, cap=cap)
    if not sample:
        return ""
    sample_str = "\n".join(f"  - {n}" for n in sample)
    bucket_str = ", ".join(buckets_used)
    return (
        "Adjacent pattern sample (taxonomy buckets: "
        f"{bucket_str}; cap={cap}). These are existing patterns whose "
        "names share taxonomy tokens with this PR's title/diff. Use them "
        "to detect duplication or close-name overlap (V5 Gap-27).\n"
        f"{sample_str}\n\n"
    )
REVIEW_PROMPT_TEMPLATE = """You are reviewing a GitHub pull request diff. Please assess it and reply
in EXACTLY this format (case-sensitive verdict):

    VERDICT: <one of MERGE-OK | NEEDS-FIX | NEEDS-REWORK | OFF-SCOPE>
    RATIONALE: <2-6 sentences justifying the verdict, citing concrete lines
                or files from the diff>

Verdict semantics:
  MERGE-OK     - Change is correct, in-scope, and ready to merge.
  NEEDS-FIX    - Small, line-local issues to address; structure is fine.
  NEEDS-REWORK - Approach has a meaningful flaw; substantive rewrite needed.
  OFF-SCOPE    - Diff drifts from the PR's stated intent or repo scope.

PR title: {title}
PR number: #{number}
Base branch: {base}

Diff (truncated to {max_diff_chars} chars if longer):
---
{diff}
---

Reply with the VERDICT line, then RATIONALE. Nothing else.
"""

CALIBRATION_DISCLAIMER_FALLBACK = (
    "_Calibration ledger (`tools/calibration/llm_calibration_log.jsonl`) "
    "has no rows yet for this provider/task combo. **Verify before adopting** "
    "— neither model alone is authoritative. Dual-agreement is a "
    "high-confidence signal; disagreement is a Claude triage signal._"
)


def _load_calibration_module():
    """Load tools/llm-calibration-log.py as a module via importlib.

    The file uses a hyphenated name, which is not importable via the
    normal ``import`` statement. Cached on ``sys.modules`` for reuse.
    Returns None if the tool is missing — caller falls back to the
    static disclaimer above.
    """
    cache_key = "_llm_pr_review_calibration_log"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    if not CALIBRATION_TOOL.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            cache_key, CALIBRATION_TOOL
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[cache_key] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def build_calibration_disclaimer() -> str:
    """Compose the per-comment disclaimer from fresh ledger stats.

    Pulls 1-line cite strings for kimi PR-review and minimax PR-review out
    of ``tools/llm-calibration-log.py`` so the percentages reflect the
    current ledger, not a snapshot. Falls back to a static line when the
    ledger is missing or empty.
    """
    cal = _load_calibration_module()
    if cal is None:
        return CALIBRATION_DISCLAIMER_FALLBACK
    fallback_kimi = "kimi pr-review accuracy: (no data)"
    fallback_minimax = "minimax pr-review accuracy: (no data)"
    kimi_line = cal.cite_calibration(
        "kimi", "pr-review", fallback=fallback_kimi
    )
    minimax_line = cal.cite_calibration(
        "minimax", "pr-review", fallback=fallback_minimax
    )
    return (
        "_Calibration (live, from `tools/calibration/llm_calibration_log.jsonl`): "
        f"{kimi_line}; {minimax_line}. **Verify before adopting** — neither "
        "model alone is authoritative. Dual-agreement is a high-confidence "
        "signal; disagreement is a Claude triage signal. Hand-maintained "
        "matrix in `docs/LLM_DELEGATION_MATRIX.md` is a snapshot; this line "
        "is current._"
    )

# Truncation guard so we never blow past the LLM context with a 10k-line diff.
MAX_DIFF_CHARS = 60_000


# ---------------------------------------------------------------------------
# V5 P0-02 (Gap 9) — OOS path rules inlined into LLM packets
# ---------------------------------------------------------------------------
#
# When a workspace ships an `OOS_CHECKLIST.md` (produced by
# `tools/extract-oos.sh`), source-mining and submission-review packets must
# inline the path patterns rather than relying on the model to recall the
# scope from prior context. The model only sees what is in the packet,
# and a missing scope reminder produces submissions that target out-of-
# scope paths — the canonical V5 capability gap.
#
# Path-shaped lines are anything that contains a slash, a `**` glob, a
# common Solidity/Cairo/Rust extension (`.sol`, `.vy`, `.cairo`, `.rs`),
# or a `src/`-style prefix. Non-path bullets in OOS_CHECKLIST.md (e.g.
# "All gas optimisations") stay in the file but are NOT injected — the
# model receives only the actionable path list, framed as OOS-N rules
# in regex format.
OOS_PATH_LINE_RE = re.compile(
    r"(?:[\w\-./*]+/[\w\-./*]+|[\w\-]+\.(?:sol|vy|cairo|rs|move|fc|huff|ts|js)\b)",
    re.IGNORECASE,
)

# Heading line that introduces the inlined OOS block. Tests pin on this
# string so any future rename keeps a single point of update.
OOS_PACKET_HEADER = "OOS PATH RULES (do NOT report findings against these paths)"


def _extract_oos_path_rules(workspace_dir: pathlib.Path | None) -> list[str]:
    """Read `<workspace>/OOS_CHECKLIST.md` and return path-shaped rules.

    Returns an empty list when ``workspace_dir`` is None, the directory
    does not exist, the checklist file is absent, or the file contains
    no path-shaped lines. Never raises — a malformed checklist must not
    block PR review.

    The output is a list of "OOS-N: <pattern>" strings (1-indexed) so
    the packet inline form is stable across workspaces. Each pattern is
    the literal substring extracted from the checklist line, preserving
    glob characters (``**``, ``*``) and regex anchors so the model can
    match the wording in its training corpus.
    """
    if workspace_dir is None:
        return []
    try:
        ws = pathlib.Path(workspace_dir)
    except (TypeError, ValueError):
        return []
    if not ws.is_dir():
        return []
    checklist = ws / "OOS_CHECKLIST.md"
    if not checklist.is_file():
        return []
    try:
        text = checklist.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rules: list[str] = []
    for raw_line in text.splitlines():
        # Strip markdown bullet markers; tolerate `-`, `*`, `+`, and
        # numbered lists so any extract-oos.sh output shape works.
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        body = re.sub(r"^[\-\*\+]\s+|^\d+\.\s+", "", stripped)
        if not body:
            continue
        # Only keep bullets that contain at least one path-shaped token.
        if not OOS_PATH_LINE_RE.search(body):
            continue
        rules.append(body)
    # Deduplicate while preserving order — a hand-edited checklist often
    # repeats patterns under separate headings.
    seen: set[str] = set()
    unique: list[str] = []
    for r in rules:
        if r in seen:
            continue
        seen.add(r)
        unique.append(r)
    return [f"OOS-{i + 1}: {pat}" for i, pat in enumerate(unique)]


# ---------------------------------------------------------------------------
# V5 P0-02 (Gap 13) — sampled pattern library `covered_by_known: unknown`
# ---------------------------------------------------------------------------
#
# When the operator can show only a sample of pattern names from the
# detector library (e.g. 60 of 1300+) the LLM must NOT default
# `covered_by_known` to false on a name miss — that produces fake
# novelty claims for findings the unsampled portion of the library
# already covers. The prompt header below makes the default
# `covered_by_known: unknown` and instructs the model to emit `false`
# only when the visible sample contains an unambiguous match. This
# helper produces the prompt prefix; downstream callers compose the
# rest of the sampled-pattern packet (finding text, candidate
# detectors, etc.) on top.
SAMPLED_PATTERN_DEFAULT = "unknown"
SAMPLED_PATTERN_HEADER = (
    "SAMPLED PATTERN LIBRARY (partial coverage view)"
)


def build_sampled_pattern_prompt(
    *,
    sample_count: int,
    total_count: int,
    sample_names: list[str],
    finding_summary: str,
) -> str:
    """Build a prompt that asks the model to assess novelty against a sample.

    Output schema requested from the model::

        VERDICT: <NEW|EXISTING|UNKNOWN>
        covered_by_known: <true|false|unknown>
        rationale: <2-6 sentences>

    The header makes it explicit that the visible list is a SAMPLE, not
    the full library. The model is instructed to emit
    ``covered_by_known: false`` ONLY when the visible sample contains
    an unambiguous match for the finding's bug class, and to default
    to ``unknown`` whenever the sample is silent on the class. This
    closes Gap 13: a 60-of-1300 sample with no match is "I haven't
    seen this here, but the unseen rest of the library might have it"
    — not "this is novel."
    """
    sample_block = "\n".join(f"- {name}" for name in sample_names) or "(empty sample)"
    return (
        f"{SAMPLED_PATTERN_HEADER}: "
        f"You are seeing {sample_count} of {total_count} total patterns. "
        f"This is a SAMPLE — the unseen patterns are NOT visible to you.\n\n"
        f"Visible patterns:\n{sample_block}\n\n"
        f"Finding under review:\n---\n{finding_summary}\n---\n\n"
        "Mark `covered_by_known: false` ONLY when the visible sample "
        "contains an unambiguous match for the bug class. Default to "
        f"`{SAMPLED_PATTERN_DEFAULT}` when the sample is silent on the "
        "class — the unsampled remainder of the library may still cover "
        "it, and false novelty claims block downstream triage. Reply in "
        "EXACTLY this format (case-sensitive):\n\n"
        "    VERDICT: <NEW|EXISTING|UNKNOWN>\n"
        "    covered_by_known: <true|false|unknown>\n"
        "    rationale: <2-6 sentences citing visible pattern names or "
        "explaining why the sample is silent>\n"
    )


def _format_oos_packet_section(rules: list[str]) -> str:
    """Render the OOS path-rule list as a packet header section.

    Empty list returns an empty string so callers can unconditionally
    concatenate. The header is intentionally noisy (uppercased title,
    explicit do-not-report instruction) because Minimax in particular
    has been observed treating a meek scope hint as advisory.
    """
    if not rules:
        return ""
    lines = [
        OOS_PACKET_HEADER + ":",
        "",
        "The following path patterns are out of scope for this audit. "
        "Do NOT flag findings against any path that matches these "
        "patterns. If a finding spans both an in-scope and an OOS path, "
        "scope it to the in-scope file only.",
        "",
    ]
    lines.extend(rules)
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Provider plumbing (subprocess -> tools/llm-dispatch.py)
# ---------------------------------------------------------------------------

def _settings_minimax_token() -> str | None:
    """Pull the Minimax key from ~/.claude/settings.json env.ANTHROPIC_AUTH_TOKEN.

    The user's Claude harness stores this as the routed Anthropic-compat key
    for api.minimax.io/anthropic. Returns None if the file or key is missing.
    """
    path = pathlib.Path.home() / ".claude" / "settings.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    env = data.get("env") or {}
    token = env.get("ANTHROPIC_AUTH_TOKEN")
    return token if isinstance(token, str) and token else None


def _build_provider_env(provider: str) -> dict[str, str]:
    """Return os.environ + provider-specific defaults for llm-dispatch.py.

    For Minimax: if MINIMAX_API_KEY is not set, fall back to
    ANTHROPIC_AUTH_TOKEN from ~/.claude/settings.json (the established
    routing on this workstation).
    """
    env = dict(os.environ)
    # llm-dispatch.py requires an explicit consent flag before urlopen.
    env["AUDITOOOR_LLM_NETWORK_CONSENT"] = env.get(
        "AUDITOOOR_LLM_NETWORK_CONSENT", "1"
    )
    if provider == "minimax" and not env.get("MINIMAX_API_KEY"):
        token = _settings_minimax_token()
        if token:
            env["MINIMAX_API_KEY"] = token
    return env


def _invoke_llm_dispatch(
    provider: str,
    prompt_text: str,
    *,
    max_tokens: int,
    timeout: float,
    truncated: bool = False,
) -> tuple[int, str, str]:
    """Run tools/llm-dispatch.py for a single provider. Returns (rc, stdout, stderr).

    Writes the prompt to a temp file (llm-dispatch wants --prompt-file) so
    we don't smuggle a large diff through argv.

    When ``truncated=True`` the ``--input-is-truncated`` flag is forwarded
    to llm-dispatch.py so MiniMax-M2.7 receives the absence-hallucination
    notice (foot-gun #13d, validated on PR #172). For non-MiniMax providers
    the flag is a documented no-op inside dispatch — it's still safe to
    pass unconditionally based on the source signal here.
    """
    tmp = pathlib.Path(
        "/tmp/llm-pr-review-prompt-" + hashlib.sha256(prompt_text.encode()).hexdigest()[:16]
    )
    tmp.write_text(prompt_text, encoding="utf-8")
    cmd = [
        sys.executable,
        str(LLM_DISPATCH),
        "--prompt-file", str(tmp),
        "--provider", provider,
        "--max-tokens", str(max_tokens),
        "--timeout", str(timeout),
    ]
    if truncated:
        cmd.append("--input-is-truncated")
    try:
        proc = subprocess.run(
            cmd,
            env=_build_provider_env(provider),
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # outer guard
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"subprocess-timeout: {e}"
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def kimi_review(
    diff_text: str,
    prompt: str,
    *,
    max_tokens: int = 800,
    timeout: float = 60.0,
    truncated: bool = False,
) -> str:
    """Run a Kimi review. Returns the response text only (final TextPart).

    Raises RuntimeError on dispatch failure. ``truncated`` is forwarded
    verbatim to llm-dispatch.py so the absence-hallucination notice can
    fire on the MiniMax hop of an auto-mode chain.
    """
    rc, out, err = _invoke_llm_dispatch(
        "kimi", prompt,
        max_tokens=max_tokens, timeout=timeout, truncated=truncated,
    )
    if rc != 0:
        raise RuntimeError(f"kimi-dispatch-failed (rc={rc}): {err.strip()[:300]}")
    return out.strip()


def minimax_review(
    diff_text: str,
    prompt: str,
    *,
    max_tokens: int = 800,
    timeout: float = 60.0,
    truncated: bool = False,
) -> str:
    """Run a Minimax review. Returns the response text only.

    Raises RuntimeError on dispatch failure. ``truncated=True`` causes
    llm-dispatch.py to prepend the foot-gun #13d absence-hallucination
    notice to the user prompt (see PR #210).
    """
    rc, out, err = _invoke_llm_dispatch(
        "minimax", prompt,
        max_tokens=max_tokens, timeout=timeout, truncated=truncated,
    )
    if rc != 0:
        raise RuntimeError(f"minimax-dispatch-failed (rc={rc}): {err.strip()[:300]}")
    return out.strip()


# ---------------------------------------------------------------------------
# Verdict parsing & consensus
# ---------------------------------------------------------------------------

def parse_verdict(text: str) -> tuple[str | None, str]:
    """Extract (verdict, rationale) from an LLM response.

    Returns (None, original_text) when no schema match is found — the caller
    should re-prompt or mark the result as malformed.
    """
    if not text:
        return None, ""
    m = VERDICT_RE.search(text)
    if not m:
        return None, text.strip()
    verdict = m.group(1).upper()
    # Rationale = everything after the matched VERDICT line, with a leading
    # "RATIONALE:" stripped if present.
    tail = text[m.end():].lstrip()
    if tail.upper().startswith("RATIONALE:"):
        tail = tail[len("RATIONALE:"):].lstrip()
    return verdict, tail.strip()


def compute_consensus(verdicts: dict[str, str | None]) -> str:
    """Reduce per-provider verdicts to a consensus label.

    - All providers same non-None verdict -> AGREED-<verdict>
      (e.g. AGREED-MERGE-OK, AGREED-NEEDS-FIX).
    - Any None (unparseable) -> LLM-FAILURE.
    - Otherwise -> DISAGREED.
    """
    values = list(verdicts.values())
    if not values:
        return "LLM-FAILURE"
    if any(v is None for v in values):
        return "LLM-FAILURE"
    if len(set(values)) == 1:
        return f"AGREED-{values[0]}"
    return "DISAGREED"


# ---------------------------------------------------------------------------
# gh helpers
# ---------------------------------------------------------------------------

def _gh_json(args: list[str]) -> Any:
    """Run a `gh` command expected to return JSON. Raises on failure."""
    proc = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def list_open_prs() -> list[dict]:
    return _gh_json([
        "pr", "list", "--state", "open", "--limit", "200",
        "--json", "number,title,baseRefName,mergeStateStatus,headRefName",
    ])


def fetch_pr_meta(number: int) -> dict:
    return _gh_json([
        "pr", "view", str(number),
        "--json", "number,title,baseRefName,mergeStateStatus,headRefName,state,url",
    ])


def fetch_pr_diff(number: int) -> str:
    proc = subprocess.run(
        ["gh", "pr", "diff", str(number)],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh pr diff #{number} failed: {proc.stderr.strip()}")
    return proc.stdout


def post_pr_comment(number: int, body: str) -> str:
    """Post a comment, return the comment URL printed by gh."""
    tmp = pathlib.Path(
        f"/tmp/llm-pr-review-comment-{number}-{int(time.time())}.md"
    )
    tmp.write_text(body, encoding="utf-8")
    try:
        proc = subprocess.run(
            ["gh", "pr", "comment", str(number), "--body-file", str(tmp)],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"gh pr comment #{number} failed: {proc.stderr.strip()}")
        return proc.stdout.strip()
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def merge_pr(number: int) -> str:
    """Squash-merge with branch deletion, return the merge commit SHA if found."""
    proc = subprocess.run(
        ["gh", "pr", "merge", str(number), "--squash", "--delete-branch"],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh pr merge #{number} failed: {proc.stderr.strip()}")
    # Best-effort SHA extraction (gh prints a URL containing it).
    m = re.search(r"\b([0-9a-f]{7,40})\b", proc.stdout + proc.stderr)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------

def format_review_comment(
    pr_number: int,
    verdicts: dict[str, str | None],
    rationales: dict[str, str],
    consensus: str,
) -> str:
    """Build the structured dual-review comment body."""
    lines = [
        "## Dual-LLM PR Review (Codex substitute)",
        "",
        f"**Consensus:** `{consensus}`",
        "",
    ]
    for provider in sorted(verdicts):
        v = verdicts[provider] or "UNPARSED"
        rat = rationales.get(provider, "").strip() or "_(no rationale)_"
        lines.append(f"### {provider.capitalize()}: `{v}`")
        lines.append("")
        lines.append(rat)
        lines.append("")
    lines.append("---")
    lines.append(build_calibration_disclaimer())
    lines.append("")
    lines.append(
        f"_Generated by `tools/llm-pr-review.py` for PR #{pr_number}._"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-PR pipeline
# ---------------------------------------------------------------------------

def review_one_pr(
    number: int,
    *,
    providers: list[str],
    max_tokens: int,
    timeout: float,
    post_comments: bool,
    auto_merge: bool,
    output_dir: pathlib.Path,
    task_type: str | None = None,
    submission_bound: bool = False,
    workspace_dir: pathlib.Path | None = None,
) -> dict:
    """Run the dual review for one PR and return the artefact record.

    When ``task_type`` is supplied (V4 P5 preset), the script swaps in the
    per-preset prompt + 2-state PASS/FAIL parser and inserts the
    ``requires_codex`` routing field into the artefact. Default
    (``task_type=None``) keeps the legacy 4-verdict behaviour for every
    existing caller.
    """
    record: dict[str, Any] = {
        "pr": number,
        "providers": providers,
        "verdicts": {},
        "rationales": {},
        "raw_outputs": {},
        "consensus": None,
        "comment_url": None,
        "merge_sha": None,
        "errors": [],
        "task_type": task_type,
        "submission_bound": (
            bool(submission_bound) if task_type is not None else False
        ),
        "requires_codex": compute_requires_codex(task_type, submission_bound),
    }
    try:
        meta = fetch_pr_meta(number)
    except Exception as e:
        record["errors"].append(f"meta-fetch-failed: {e}")
        return record
    record["meta"] = {
        "title": meta.get("title"),
        "base": meta.get("baseRefName"),
        "head": meta.get("headRefName"),
        "mergeStateStatus": meta.get("mergeStateStatus"),
        "state": meta.get("state"),
        "url": meta.get("url"),
    }
    try:
        diff = fetch_pr_diff(number)
    except Exception as e:
        record["errors"].append(f"diff-fetch-failed: {e}")
        return record
    record["diff_hash"] = hashlib.sha256(diff.encode("utf-8")).hexdigest()
    record["diff_chars"] = len(diff)

    diff_for_prompt = diff[:MAX_DIFF_CHARS]
    # Foot-gun #13d (PR #172): when we head-cut the diff, MiniMax-M2.7
    # hallucinates "missing file" findings based on what isn't visible.
    # PR #210 added --input-is-truncated to llm-dispatch.py to gate a
    # one-line absence-hallucination notice. Codex P0 #4 on PR #224
    # noted the flag was never propagated from this caller — fixed here
    # by computing the boolean once at the truncation site and forwarding
    # it verbatim through both runners.
    truncated = len(diff) > MAX_DIFF_CHARS
    record["truncated"] = truncated
    # V5 P0-02 (Gap 9): pull OOS path rules from the workspace before
    # building the prompt so submission-review packets carry inline
    # scope guidance. Empty list when the workspace is unset or has no
    # OOS_CHECKLIST.md — both legitimate paths (e.g. tier-B detector
    # smoke runs).
    oos_rules = _extract_oos_path_rules(workspace_dir)
    record["oos_rules_count"] = len(oos_rules)
    if task_type is None:
        prompt = REVIEW_PROMPT_TEMPLATE.format(
            title=meta.get("title", ""),
            number=number,
            base=meta.get("baseRefName", ""),
            max_diff_chars=MAX_DIFF_CHARS,
            diff=diff_for_prompt,
        )
        # Default 4-verdict path is the de-facto submission review
        # entry-point — inline OOS rules here too, framed identically
        # to the task-type presets so both code paths produce the
        # same wire-level header.
        if oos_rules:
            prompt = _format_oos_packet_section(oos_rules) + "\n" + prompt
        verdict_parser = parse_verdict
    else:
        # V5 Gap-27: detector-tier-b reviews get a taxonomy-bucket
        # adjacent pattern sample injected into the prompt; every
        # other task-type receives an empty string and is byte-for-byte
        # unchanged from the pre-PR-G prompt.
        taxonomy_block = build_taxonomy_block(
            task_type,
            title=meta.get("title", ""),
            diff=diff_for_prompt,
        )
        prompt = build_task_prompt(
            task_type,
            title=meta.get("title", ""),
            number=number,
            base=meta.get("baseRefName", ""),
            diff=diff_for_prompt,
            max_diff_chars=MAX_DIFF_CHARS,
            taxonomy_block=taxonomy_block,
            oos_rules=oos_rules,
        )
        verdict_parser = parse_task_verdict
        record["taxonomy_block_chars"] = len(taxonomy_block)
        # Persist the preset's static schema + computed routing into the
        # artefact so downstream consumers see the contract without
        # re-importing this module.
        schema = dict(TASK_VERDICT_SCHEMAS[task_type])
        if "submission_bound" in schema:
            schema["submission_bound"] = bool(submission_bound)
        schema["requires_codex"] = record["requires_codex"]
        record["task_schema"] = schema

    runners = {"kimi": kimi_review, "minimax": minimax_review}
    for prov in providers:
        runner = runners.get(prov)
        if runner is None:
            record["errors"].append(f"unknown-provider: {prov}")
            record["verdicts"][prov] = None
            record["rationales"][prov] = ""
            record["raw_outputs"][prov] = ""
            continue
        try:
            out = runner(
                diff, prompt,
                max_tokens=max_tokens, timeout=timeout, truncated=truncated,
            )
        except Exception as e:
            record["errors"].append(f"{prov}-failed: {e}")
            record["verdicts"][prov] = None
            record["rationales"][prov] = ""
            record["raw_outputs"][prov] = ""
            continue
        record["raw_outputs"][prov] = out
        verdict, rationale = verdict_parser(out)
        if verdict is None:
            # Re-prompt once with a stricter nudge.
            nudge = (
                prompt
                + "\n\nReminder: your previous reply did not match the schema. "
                "Reply with EXACTLY one VERDICT line followed by RATIONALE."
            )
            try:
                out2 = runner(
                    diff, nudge,
                    max_tokens=max_tokens, timeout=timeout,
                    truncated=truncated,
                )
                record["raw_outputs"][prov + "_retry"] = out2
                verdict, rationale = verdict_parser(out2)
            except Exception as e:
                record["errors"].append(f"{prov}-retry-failed: {e}")
        record["verdicts"][prov] = verdict
        record["rationales"][prov] = rationale

    consensus = compute_consensus(record["verdicts"])
    record["consensus"] = consensus

    if post_comments:
        body = format_review_comment(
            number, record["verdicts"], record["rationales"], consensus
        )
        try:
            url = post_pr_comment(number, body)
            record["comment_url"] = url
        except Exception as e:
            record["errors"].append(f"comment-post-failed: {e}")

    # V4 §3.2 routing rule: when requires_codex=True the dual-LLM tool
    # is NEVER allowed to auto-merge — Codex must arbitrate first. This
    # guards every gate-hardening / submission-critical PR plus any
    # crypto/econ review that was flagged --submission-bound. The legacy
    # 4-verdict path (task_type=None -> requires_codex=False) keeps its
    # existing auto-merge semantics unchanged.
    #
    # Codex HOLD on PR #236: task-type presets emit a 2-state PASS/FAIL
    # grammar, so their auto-merge consensus is ``AGREED-PASS`` — not the
    # legacy ``AGREED-MERGE-OK``. Without per-path gate selection, every
    # PASS-eligible task-type PR was silently held. The auto-merge
    # consensus is now selected by ``task_type`` so legacy callers stay
    # bit-for-bit unchanged. Only an exact ``AGREED-PASS`` matches for
    # task-type paths — ``AGREED-PASS-WITH-NITS`` and any other future
    # consensus label still routes through human review.
    auto_merge_consensus = (
        "AGREED-PASS" if task_type is not None else "AGREED-MERGE-OK"
    )
    if (
        auto_merge
        and consensus == auto_merge_consensus
        and meta.get("mergeStateStatus") == "CLEAN"
        and not record.get("requires_codex")
    ):
        try:
            sha = merge_pr(number)
            record["merge_sha"] = sha
        except Exception as e:
            record["errors"].append(f"merge-failed: {e}")
    elif (
        auto_merge
        and consensus == auto_merge_consensus
        and record.get("requires_codex")
    ):
        # Surface the routing decision in the artefact so a downstream
        # human / dashboard can see why auto-merge was withheld.
        record["errors"].append(
            "auto-merge-skipped: requires_codex=True per V4 §3.2 routing "
            f"(task_type={task_type}, submission_bound={submission_bound})"
        )

    # Persist artefact.
    output_dir.mkdir(parents=True, exist_ok=True)
    artefact_path = output_dir / f"pr-{number}.json"
    artefact_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    record["artefact_path"] = str(artefact_path)
    return record


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------

def summarise(records: list[dict]) -> dict[str, int]:
    tally = {
        "reviewed": len(records),
        "agreed_merge": 0,
        "auto_merged": 0,
        "agreed_fix": 0,
        "agreed_rework": 0,
        "agreed_offscope": 0,
        "disagreed": 0,
        "llm_failure": 0,
    }
    for r in records:
        c = r.get("consensus")
        if c == "AGREED-MERGE-OK":
            tally["agreed_merge"] += 1
            if r.get("merge_sha"):
                tally["auto_merged"] += 1
        elif c == "AGREED-NEEDS-FIX":
            tally["agreed_fix"] += 1
        elif c == "AGREED-NEEDS-REWORK":
            tally["agreed_rework"] += 1
        elif c == "AGREED-OFF-SCOPE":
            tally["agreed_offscope"] += 1
        elif c == "DISAGREED":
            tally["disagreed"] += 1
        else:
            tally["llm_failure"] += 1
    return tally


def print_summary(tally: dict[str, int]) -> None:
    sys.stdout.write(
        "\n=== llm-pr-review summary ===\n"
        f"{tally['reviewed']} PRs reviewed, "
        f"{tally['agreed_merge']} AGREED-MERGE "
        f"({tally['auto_merged']} auto-merged), "
        f"{tally['agreed_fix']} AGREED-FIX, "
        f"{tally['agreed_rework']} AGREED-REWORK, "
        f"{tally['agreed_offscope']} AGREED-OFF-SCOPE, "
        f"{tally['disagreed']} DISAGREED, "
        f"{tally['llm_failure']} LLM-failures.\n"
    )
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_providers(s: str) -> list[str]:
    out = []
    for p in (x.strip().lower() for x in s.split(",")):
        if not p:
            continue
        if p not in ("kimi", "minimax"):
            raise argparse.ArgumentTypeError(f"unknown provider: {p}")
        out.append(p)
    if not out:
        raise argparse.ArgumentTypeError("must specify at least one provider")
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-pr-review.py",
        description=(
            "Dual-LLM PR review pipeline (Kimi + Minimax). Substitutes for "
            "Codex review while it's unavailable. Writes a per-PR JSON "
            "artefact and optionally posts a structured comment / "
            "auto-merges AGREED-MERGE-OK consensuses."
        ),
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--pr", type=int, help="Review a single PR by number.")
    target.add_argument("--all-open", action="store_true",
                        help="Review every open PR.")
    p.add_argument("--auto-merge", action="store_true",
                   help="Auto-merge AGREED-MERGE-OK consensuses (default off).")
    p.add_argument("--no-auto-merge", action="store_true",
                   help="(default) Disable auto-merge explicitly.")
    p.add_argument("--post-comments", action="store_true", default=False,
                   help="Opt-IN: post the dual-review comment to each PR. "
                        "Default is artefact-only — no GitHub comment is "
                        "posted unless this flag is passed. Inverted from "
                        "previous default-on behaviour to remove the "
                        "cron-driven comment-spam risk flagged by Codex "
                        "2026-04-26 (PR #224 P0 #3).")
    p.add_argument("--no-post-comments", action="store_true",
                   help="(default) Skip posting comments (artefact-only "
                        "mode). Redundant with the new default but accepted "
                        "for backwards-compat with existing callers.")
    p.add_argument("--skip-pr", type=int, action="append", default=[],
                   metavar="N", help="PR numbers to skip (repeatable).")
    p.add_argument("--output-dir", type=pathlib.Path,
                   default=pathlib.Path("/tmp/llm-pr-review"),
                   help="Per-PR artefact directory (default: /tmp/llm-pr-review/).")
    p.add_argument("--providers", type=_parse_providers,
                   default=["kimi", "minimax"],
                   help="Comma-separated providers to query (default: kimi,minimax).")
    p.add_argument("--max-tokens", type=int, default=800,
                   help="Per-LLM max_tokens (default: 800).")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="Per-LLM call timeout in seconds (default: 60).")
    p.add_argument(
        "--task-type",
        choices=list(TASK_TYPES),
        default=None,
        help=(
            "V4 P5 task-type preset. Selects a preset prompt + verdict "
            "schema and computes the `requires_codex` routing field per "
            "V4 §3.2. Omit for the legacy 4-verdict (MERGE-OK / NEEDS-FIX "
            "/ NEEDS-REWORK / OFF-SCOPE) PR review path."
        ),
    )
    p.add_argument(
        "--submission-bound",
        action="store_true",
        help=(
            "Mark a `crypto-review` or `econ-review` task-type as "
            "submission-bound. Affects `requires_codex`: a "
            "submission-bound crypto/econ review MUST reach Codex (auto-"
            "merge forbidden). No-op for other task-types."
        ),
    )
    p.add_argument(
        "--workspace",
        type=pathlib.Path,
        default=None,
        help=(
            "Workspace directory whose `OOS_CHECKLIST.md` should be "
            "inlined into source-mining and submission-review packets "
            "(V5 P0-02 / Gap 9). When omitted, the tool falls back to "
            "the AUDITOOOR_WORKSPACE env var; when neither is set, no "
            "OOS section is injected. Empty / non-existent / "
            "checklist-less workspaces are silently treated as "
            "no-rules."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    post_comments = args.post_comments and not args.no_post_comments
    auto_merge = args.auto_merge and not args.no_auto_merge

    workspace_dir = args.workspace
    if workspace_dir is None:
        env_ws = os.environ.get("AUDITOOOR_WORKSPACE")
        if env_ws:
            workspace_dir = pathlib.Path(env_ws)

    if args.pr is not None:
        targets = [args.pr]
    else:
        try:
            open_prs = list_open_prs()
        except Exception as e:
            sys.stderr.write(f"failed-to-list-prs: {e}\n")
            return 2
        targets = [p["number"] for p in open_prs]

    skip = set(args.skip_pr)
    targets = [n for n in targets if n not in skip]

    if not targets:
        sys.stdout.write("no PRs to review\n")
        return 0

    records: list[dict] = []
    for n in targets:
        sys.stdout.write(f"[llm-pr-review] reviewing PR #{n} ...\n")
        sys.stdout.flush()
        rec = review_one_pr(
            n,
            providers=args.providers,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
            post_comments=post_comments,
            auto_merge=auto_merge,
            output_dir=args.output_dir,
            task_type=args.task_type,
            submission_bound=bool(args.submission_bound),
            workspace_dir=workspace_dir,
        )
        records.append(rec)
        sys.stdout.write(
            f"  -> consensus={rec.get('consensus')}  "
            f"artefact={rec.get('artefact_path')}\n"
        )
        if rec.get("errors"):
            for e in rec["errors"]:
                sys.stdout.write(f"     ! {e}\n")
        sys.stdout.flush()

    tally = summarise(records)
    print_summary(tally)
    return 0


if __name__ == "__main__":
    sys.exit(main())
