#!/usr/bin/env python3
"""
adversarial-copilot.py — Adversarial Co-pilot (Phase I skeleton + Step 5
per-engagement mode).

Reads `<workspace>/agent_outputs/*.md` for NOT-A-BUG / FALSE-POSITIVE verdicts,
composes a counter-brief per verdict ("prove this wrong, or list the invariant
that makes it correct"), dispatches it through either:
  - `tools/swarm-orchestrator.py --dispatch` (default, black-box mode), OR
  - `tools/llm-dispatch.py` with Kimi+Minimax (when ``--use-llm-dispatch``)
and classifies the response into one of the locked statuses
`break` / `hold` / `skipped` / `error`.

On `break`   → writes `<ws>/agent_outputs/adversarial_<slug>.md` AND
               (Step 5) emits a candidate DSL pattern at
               `reference/patterns.dsl/_novelty/<slug>.yaml` AND appends an
               entry to `tools/novelty_promotion_log.json` AND seeds a new
               angle into `<ws>/mining_priorities.json`.
On `hold`    → appends a row to `<ws>/reference/provisional_non_bugs.md` with
               the mandatory human/source-invariant review marker.
On `skipped` → prints a reason line and exits 0. Skipped inputs never produce
               a break or a hold.
On `error`   → prints reason to stderr, exits non-zero.

Per-engagement mode (Kimi 20/10 Step 5):
  ``--per-engagement`` is a marker flag used by ``engage.py`` close-out so
  the copilot understands it is being run as a stage in the engagement pipe
  rather than ad-hoc. It enables novelty-to-pattern promotion (DSL emission)
  and adds calibration cite lines to the brief.

Hard constraints (PR 204 truth-audit):
  1. `--dry-run` is the DEFAULT. Real swarm dispatch requires `--live`.
  2. The tool NEVER writes under `<ws>/submissions/` — an explicit guard
     refuses any such target path even if the caller forces it.
  3. Status vocabulary is fixed to {break, hold, skipped, error}; no other
     values are ever emitted.
  4. Agent output is raw material, not proof. A `break` seeds an angle for
     the next mining pass; it does not itself promote a candidate to
     `submissions/ready/`.
  5. Step 5 novelty patterns land in the ``_novelty/`` quarantine subdir —
     they are NOT auto-promoted to durable patterns. Promotion is a manual
     step gated by gap-analyzer and human review.

Usage:
  python3 tools/adversarial-copilot.py <workspace>                # dry-run default
  python3 tools/adversarial-copilot.py <workspace> --live         # real dispatch
  python3 tools/adversarial-copilot.py --input <file.md> <ws>     # single file
  python3 tools/adversarial-copilot.py <ws> --per-engagement      # Step 5 mode

Exit codes:
  0 — tool ran to completion (any mix of break / hold / skipped verdicts)
  1 — error (malformed workspace, missing swarm-orchestrator, dispatch failure)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Locked status vocabulary (docs/10_OF_10_PLAYBOOK.md §5 compatible)
# ---------------------------------------------------------------------------
STATUS_BREAK = "break"
STATUS_HOLD = "hold"
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"
ALLOWED_STATUSES = frozenset({STATUS_BREAK, STATUS_HOLD, STATUS_SKIPPED, STATUS_ERROR})

# Patterns we look for in agent_outputs/*.md to decide if this output is a
# candidate NOT-A-BUG verdict the co-pilot should try to break.
#
# Iter-v3-2 T1 grammar extension: real drafts use three distinct idioms
# beyond the original narrow ``VERDICT:`` inline form. We keep the original
# regex (tests 1-4 depend on it) and add two additional heading-form anchors
# plus a title-prefix anchor used by ``*.notes.md`` drop-notes.
#
# All patterns use MULTILINE mode and are joined into a tuple; any match in
# the tuple counts as "has a verdict line". ``extract_not_a_bug_verdicts``
# iterates all of them and filters by ``NOT_A_BUG_TOKENS``.

# 1. Original narrow inline form. Matches:
#       VERDICT: NOT-A-BUG ...
#       Verdict: false positive
#       **Verdict**: FP
#    Also covers the bold-inline form ``**Verdict**: X`` via the ``\*+``
#    alternation (two stars on each side are both eaten).
VERDICT_INLINE_RE = re.compile(
    r"^\s*(?:\*+\s*)?(?:VERDICT|Verdict)(?:\*+)?\s*[:\-]\s*(?P<verdict>.+?)\s*$",
    re.MULTILINE,
)

# 2. Heading form. Matches ``## Verdict: <disposition>`` (1-6 `#` marks).
#    Real drafts emit ``## Verdict: NOT EXPLOITABLE``, ``## Verdict:
#    false positive``, ``## Verdict: DUPE of existing submission``, etc.
VERDICT_HEADING_RE = re.compile(
    r"^\s*#{1,6}\s*Verdict\s*[:\-]\s*(?P<verdict>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# 3. Title-prefix form. Matches the ``*.notes.md`` first-line grammar:
#       # R87-H1 — INVESTIGATED — FALSE POSITIVE
#       # R83-A — INVESTIGATED — DUPLICATE of Cantina #84 (paid)
#    Separator is an em-dash (—), en-dash (–), or one-or-more hyphens (-).
VERDICT_TITLE_PREFIX_RE = re.compile(
    r"^\s*#{1,6}\s+.+?[\s]*[—–\-]{1,3}\s*INVESTIGATED\s*[—–\-]{1,3}\s*(?P<verdict>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# 4. Bold-inline explicit form (backward compat). Already covered by
#    ``VERDICT_INLINE_RE`` via ``\*+``, but we expose it as its own anchor
#    so the test suite can assert directly against ``**Verdict**:`` input.
VERDICT_BOLD_INLINE_RE = re.compile(
    r"^\s*\*\*Verdict\*\*\s*[:\-]\s*(?P<verdict>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Tuple of all accepted verdict-line patterns. Order matters only for
# ``extract_not_a_bug_verdicts`` output stability — de-duplication happens
# via a seen-set on (line-offset, verdict-text).
VERDICT_PATTERNS: Tuple[re.Pattern, ...] = (
    VERDICT_INLINE_RE,
    VERDICT_HEADING_RE,
    VERDICT_TITLE_PREFIX_RE,
    VERDICT_BOLD_INLINE_RE,
)

# Public alias kept for backward compatibility — the original tests reference
# ``VERDICT_RE`` (via tool-module import), so we keep the name pointing at
# the inline anchor. The tuple ``VERDICT_PATTERNS`` is the one that drives
# parsing/is_malformed.
VERDICT_RE = VERDICT_INLINE_RE

# NOT-A-BUG / investigated-false-positive dispositions we recognise. Matched
# case-insensitively against the verdict text after stripping whitespace.
# Covers inline, heading, and title-prefix forms.
NOT_A_BUG_TOKENS = (
    "NOT-A-BUG",
    "NOT A BUG",
    "FALSE-POSITIVE",
    "FALSE POSITIVE",
    "FP",
    "NO FINDING",
    "INVESTIGATED",
    "CLEARED",
    "REFUTED",
    "NOT EXPLOITABLE",
    "NO NEW BUG",
    "DUPE",
    "DUPLICATE",
    "WITHDRAWN",
    "DROPPED",
    "SUPERSESSION",
)

# Markers in the co-pilot response that we classify as `break` vs `hold`.
BREAK_MARKERS = ("VERDICT CONTESTED", "BREAK", "VERDICT BROKEN", "CONTESTED")
HOLD_MARKERS = ("VERDICT HOLDS", "HOLD", "VERDICT STANDS")

# Required marker written into provisional_non_bugs.md rows. The phrase is
# load-bearing — the test in tools/tests/test_adversarial_copilot.py asserts
# substring equality on it.
HUMAN_REVIEW_MARKER = (
    "requires human/source-invariant review before promotion to durable"
)


# ---------------------------------------------------------------------------
# Agent-output parsing
# ---------------------------------------------------------------------------
def iter_agent_outputs(workspace: Path, override: Optional[Path]) -> List[Path]:
    if override is not None:
        return [override] if override.is_file() else []
    agent_dir = workspace / "agent_outputs"
    if not agent_dir.is_dir():
        return []
    return sorted(p for p in agent_dir.glob("*.md") if p.is_file())


def _iter_verdict_matches(text: str):
    """Yield (span_start, verdict_text) for each matched verdict line across
    all accepted grammar forms. De-duplicates on (start-offset, text)."""
    seen: set = set()
    for pat in VERDICT_PATTERNS:
        for m in pat.finditer(text):
            v = m.group("verdict").strip()
            key = (m.start(), v)
            if key in seen:
                continue
            seen.add(key)
            yield m.start(), v


def extract_not_a_bug_verdicts(text: str) -> List[str]:
    """Return the set of verdict lines in `text` that look like NOT-A-BUG
    across all accepted grammar forms (inline, heading, title-prefix,
    bold-inline). De-duplicates identical verdict strings found by different
    patterns at the same offset."""
    out: List[str] = []
    seen_texts: set = set()
    for _start, v in _iter_verdict_matches(text):
        up = v.upper()
        if any(tok in up for tok in NOT_A_BUG_TOKENS):
            if v not in seen_texts:
                out.append(v)
                seen_texts.add(v)
    return out


def is_malformed(text: str) -> bool:
    """Heuristic: malformed = empty, or has a literal ``MALFORMED`` token
    with no verdict line anywhere, or has no verdict line across any of
    the accepted grammar forms."""
    stripped = text.strip()
    if not stripped:
        return True
    up = stripped.upper()
    # Any of the four accepted grammar forms hits → well-formed.
    for pat in VERDICT_PATTERNS:
        if pat.search(text):
            return False
    # No verdict line at all. Still flag the explicit MALFORMED sentinel for
    # the regression test, but really the fall-through already catches it.
    if "MALFORMED" in up and "VERDICT" not in up:
        return True
    return True


def slug_from_path(p: Path) -> str:
    s = p.stem
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s)
    return s.strip("-") or "unknown"


# ---------------------------------------------------------------------------
# Dispatch (black-box over swarm-orchestrator.py)
# ---------------------------------------------------------------------------
def build_counter_brief(source: Path, verdicts: List[str]) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Adversarial counter-brief",
        f"**Source:** {source}",
        f"**Generated:** {ts}",
        "",
        "## Instruction to co-pilot",
        "",
        "Prove the NOT-A-BUG verdict(s) below wrong, OR explicitly list the",
        "source invariant that makes each verdict correct. You may not return",
        "an unqualified 'agree'. Acceptable outputs:",
        "",
        "- `VERDICT CONTESTED: <reason>` — the primary agent missed a path.",
        "- `VERDICT HOLDS: invariant <X> at <file:line>` — cite the invariant.",
        "",
        "## Primary-agent verdicts under contest",
        "",
    ]
    for v in verdicts:
        lines.append(f"- {v}")
    lines.append("")
    return "\n".join(lines)


def dispatch_counter_brief(
    workspace: Path,
    brief_text: str,
    live: bool,
    swarm_tool: Path,
) -> Tuple[str, str]:
    """Return (raw_response_text, dispatch_mode).

    In --dry-run mode (default), returns the brief itself as the "response"
    so downstream classification can be exercised in tests via a monkey-patch
    of this function, and in production a human operator pastes the brief
    into Claude Code (same model the swarm uses).

    In --live mode, shells out to swarm-orchestrator.py --dispatch as a black
    box. We do NOT fork the orchestrator.
    """
    if not live:
        return brief_text, "dry-run"
    if not swarm_tool.is_file():
        raise FileNotFoundError(f"swarm-orchestrator.py not found at {swarm_tool}")
    cmd = [sys.executable, str(swarm_tool), str(workspace), "--dispatch"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"swarm-orchestrator.py --dispatch failed rc={proc.returncode}: "
            f"{proc.stderr[:400]}"
        )
    return proc.stdout, "live"


def classify_response(response: str) -> str:
    """Map a co-pilot response to exactly one status ∈ ALLOWED_STATUSES.

    We check BREAK markers first — a response that literally says "VERDICT
    CONTESTED" is a break even if it also includes reflection language.
    Unrecognized responses default to `skipped` so the tool never silently
    produces a `hold` it cannot justify.
    """
    if not response or not response.strip():
        return STATUS_SKIPPED
    up = response.upper()
    if any(m in up for m in BREAK_MARKERS):
        return STATUS_BREAK
    if any(m in up for m in HOLD_MARKERS):
        return STATUS_HOLD
    return STATUS_SKIPPED


# ---------------------------------------------------------------------------
# Output writers (with submissions/ guard)
# ---------------------------------------------------------------------------
def _guard_target(workspace: Path, target: Path) -> None:
    """Refuse to write anywhere under `<ws>/submissions/`.

    Also refuses escapes via ``..``. This is the PR 204 hard constraint.
    """
    try:
        resolved_ws = workspace.resolve()
        resolved_target = target.resolve()
    except OSError as e:
        raise ValueError(f"could not resolve path {target}: {e}") from e
    try:
        rel = resolved_target.relative_to(resolved_ws)
    except ValueError:
        raise ValueError(
            f"refusing to write outside workspace: {resolved_target}"
        )
    parts = rel.parts
    if parts and parts[0] == "submissions":
        raise ValueError(
            f"adversarial-copilot MUST NEVER write under submissions/: {target}"
        )


def write_break_artifact(
    workspace: Path,
    source: Path,
    verdicts: List[str],
    response: str,
) -> Path:
    slug = slug_from_path(source)
    out = workspace / "agent_outputs" / f"adversarial_{slug}.md"
    _guard_target(workspace, out)
    out.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    body = [
        f"# Adversarial break — {slug}",
        f"**Source:** {source}",
        f"**Generated:** {ts}",
        f"**Status:** {STATUS_BREAK}",
        "",
        "## Contested verdicts",
        "",
    ]
    for v in verdicts:
        body.append(f"- {v}")
    body += ["", "## Co-pilot response (raw)", "", "```", response.strip(), "```", ""]
    out.write_text("\n".join(body), encoding="utf-8")
    return out


def seed_new_angle(workspace: Path, source: Path, verdicts: List[str]) -> Path:
    """Append an adversarial-sourced angle to <ws>/mining_priorities.json.

    Schema matches what mining-prioritizer.py emits: a JSON array of angle
    records, each with at least ``angle`` (dict) and ``score`` (number).
    Anything we add is tagged with ``source: adversarial-copilot`` so the
    next mining pass can recognize and re-rank it.
    """
    path = workspace / "mining_priorities.json"
    _guard_target(workspace, path)
    existing: List[dict] = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                existing = loaded
        except json.JSONDecodeError:
            existing = []
    slug = slug_from_path(source)
    angle_id = f"ADV-{slug}-{len(existing) + 1:03d}"
    new_angle = {
        "angle": {
            "id": angle_id,
            "title": f"Adversarial contest: {slug}",
            "category": "A-ADVERSARIAL",
            "notes": "seeded by adversarial-copilot after break verdict",
            "contested_verdicts": verdicts,
        },
        "score": 5.0,
        "rationale": [
            "seeded by adversarial-copilot.py (PR 204 skeleton)",
            f"source agent output: {source}",
        ],
        "source": "adversarial-copilot",
    }
    existing.append(new_angle)
    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path


def append_provisional_row(
    workspace: Path,
    source: Path,
    verdicts: List[str],
    response: str,
) -> Path:
    path = workspace / "reference" / "provisional_non_bugs.md"
    _guard_target(workspace, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    slug = slug_from_path(source)
    ts = datetime.now(timezone.utc).isoformat()
    if not path.exists():
        header = (
            "# Provisional non-bugs\n\n"
            "Rows appended here are verdicts the adversarial co-pilot could\n"
            "NOT break. Each row is explicitly marked as requiring human or\n"
            "source-invariant review before it can be promoted to a durable\n"
            "non-bug. Presence in this file is NOT proof of correctness.\n\n"
            "| slug | source | ts | first verdict | status | marker |\n"
            "|------|--------|----|---------------|--------|--------|\n"
        )
        path.write_text(header, encoding="utf-8")
    first_verdict = verdicts[0] if verdicts else "(no verdict extracted)"
    # Escape pipes so markdown stays well-formed.
    fv = first_verdict.replace("|", "\\|")
    src_str = str(source).replace("|", "\\|")
    row = (
        f"| {slug} | {src_str} | {ts} | {fv} | {STATUS_HOLD} "
        f"| {HUMAN_REVIEW_MARKER} |\n"
    )
    with path.open("a", encoding="utf-8") as f:
        f.write(row)
    return path


# ---------------------------------------------------------------------------
# Step 5 — novelty-to-pattern promotion
# ---------------------------------------------------------------------------
# The novelty log is repo-local (NOT workspace-local) so that promoted
# candidates aggregate across engagements. Path is computed lazily so tests
# can override REPO_ROOT for hermetic runs.
DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent
NOVELTY_LOG_REL = Path("tools") / "novelty_promotion_log.json"
NOVELTY_PATTERN_DIR_REL = Path("reference") / "patterns.dsl" / "_novelty"


def _novelty_log_path(repo_root: Path) -> Path:
    return repo_root / NOVELTY_LOG_REL


def _novelty_pattern_dir(repo_root: Path) -> Path:
    return repo_root / NOVELTY_PATTERN_DIR_REL


def emit_novelty_pattern(
    repo_root: Path,
    workspace: Path,
    source: Path,
    verdicts: List[str],
    response: str,
) -> Path:
    """Emit a candidate DSL pattern under reference/patterns.dsl/_novelty/.

    The shape matches existing DSL files (pattern, source, severity, match...)
    but ``severity`` is forced to UNKNOWN and ``confidence`` to LOW because
    the pattern is auto-generated from a single co-pilot break. Promotion
    out of ``_novelty/`` is a manual step, gated by gap-analyzer + human
    review (per Step 5 spec).
    """
    slug = slug_from_path(source)
    out_dir = _novelty_pattern_dir(repo_root)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{slug}.yaml"
    ts = datetime.now(timezone.utc).isoformat()
    # Normalise verdicts and response into safe single-line YAML strings.
    first_verdict = verdicts[0] if verdicts else "(no verdict extracted)"
    response_excerpt = " ".join(response.split())[:400]
    body = [
        "# Auto-generated by tools/adversarial-copilot.py (Kimi 20/10 Step 5)",
        f"# Source agent output: {source}",
        f"# Workspace: {workspace}",
        f"# Generated: {ts}",
        f"pattern: novelty-{slug}",
        f"source: adversarial-copilot",
        f"severity: UNKNOWN",
        f"confidence: LOW",
        f"status: candidate",
        "preconditions:",
        "  - contract.source_matches_regex: '.*'",
        "match:",
        "  - function.kind: external_or_public",
        f"help: |-",
        f"  Co-pilot disputed NOT-A-BUG verdict: {first_verdict!r}",
        f"  Co-pilot rationale (excerpt): {response_excerpt!r}",
        "wiki_title: |-",
        f"  Adversarial-copilot novelty candidate from {slug}",
        "wiki_description: |-",
        "  Auto-generated DSL stub. The match block is intentionally broad — a",
        "  human reviewer must narrow preconditions/match before promoting out",
        "  of _novelty/. Validation: gap-analyzer + clean-codebase-calibrate.",
        "wiki_recommendation: |-",
        "  Refine preconditions/match. Confirm root-cause shape against the",
        "  source agent output. Then move out of _novelty/ to durable.",
        "",
    ]
    out.write_text("\n".join(body), encoding="utf-8")
    return out


def append_novelty_log(
    repo_root: Path,
    workspace: Path,
    source: Path,
    verdicts: List[str],
    response: str,
    pattern_path: Path,
) -> Path:
    """Append a JSON record to tools/novelty_promotion_log.json.

    Schema (validated by tests):
        [
          {
            "ts": "<iso>",
            "slug": "<slug>",
            "workspace": "<abs>",
            "source": "<abs>",
            "first_verdict": "<text>",
            "pattern_path": "<abs>",
            "status": "candidate",
            "origin": "adversarial-copilot",
            "validation": "pending"
          },
          ...
        ]
    """
    log_path = _novelty_log_path(repo_root)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    existing: List[dict] = []
    if log_path.exists():
        try:
            loaded = json.loads(log_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                existing = loaded
        except json.JSONDecodeError:
            existing = []
    slug = slug_from_path(source)
    first_verdict = verdicts[0] if verdicts else "(no verdict extracted)"
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "slug": slug,
        "workspace": str(workspace),
        "source": str(source),
        "first_verdict": first_verdict,
        "pattern_path": str(pattern_path),
        "status": "candidate",
        "origin": "adversarial-copilot",
        "validation": "pending",
    }
    existing.append(record)
    log_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    return log_path


# ---------------------------------------------------------------------------
# Step 5 — llm-dispatch.py integration (Kimi + Minimax)
# ---------------------------------------------------------------------------
def _cite_calibration_lines(repo_root: Path) -> List[str]:
    """Return calibration cite lines for kimi pr-review and minimax synthesis.

    Imports llm-calibration-log.py via importlib because of the hyphen in the
    filename. Returns ``[]`` if the module is missing — calibration is a
    nice-to-have, not a hard prerequisite.
    """
    cal_path = repo_root / "tools" / "llm-calibration-log.py"
    if not cal_path.is_file():
        return []
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_advcopilot_llm_calibration", cal_path)
        if not spec or not spec.loader:
            return []
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception:
        return []
    out: List[str] = []
    try:
        kimi = mod.cite_calibration("kimi", "pr-review",
                                     fallback="kimi pr-review accuracy: (no data)")
        minimax = mod.cite_calibration("minimax", "synthesis",
                                        fallback="minimax synthesis accuracy: (no data)")
        out = [kimi, minimax]
    except Exception:
        pass
    return out


def dispatch_via_llm_dispatch(
    workspace: Path,
    brief_text: str,
    live: bool,
    swarm_tool: Path,
    *,
    repo_root: Optional[Path] = None,
    provider: str = "kimi",
) -> Tuple[str, str]:
    """Alternative dispatcher that shells out to ``tools/llm-dispatch.py``.

    Drop-in replacement for ``dispatch_counter_brief``. In dry-run mode it
    behaves identically (returns the brief itself). In live mode it requires
    ``AUDITOOOR_LLM_NETWORK_CONSENT=1`` plus a provider API key — both
    enforced by ``llm-dispatch.py`` itself, NOT here.
    """
    if not live:
        return brief_text, "dry-run"
    rr = repo_root or DEFAULT_REPO_ROOT
    dispatch_tool = rr / "tools" / "llm-dispatch.py"
    if not dispatch_tool.is_file():
        raise FileNotFoundError(
            f"llm-dispatch.py not found at {dispatch_tool}. "
            f"Re-run with the default --swarm-tool path or install the dispatcher."
        )
    # Write the brief to a temp file because llm-dispatch.py reads --prompt-file.
    import tempfile
    with tempfile.NamedTemporaryFile(
        "w", suffix=".md", prefix="advcopilot_brief_",
        delete=False, encoding="utf-8",
    ) as fh:
        fh.write(brief_text)
        prompt_path = Path(fh.name)
    cmd = [
        sys.executable, str(dispatch_tool),
        "--prompt-file", str(prompt_path),
        "--provider", provider,
        "--audit-dir", str(workspace / "agent_outputs"),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    finally:
        try:
            prompt_path.unlink()
        except OSError:
            pass
    if proc.returncode != 0:
        raise RuntimeError(
            f"llm-dispatch.py rc={proc.returncode}: {proc.stderr[:400]}"
        )
    return proc.stdout, f"live-{provider}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def process_one(
    workspace: Path,
    source: Path,
    live: bool,
    swarm_tool: Path,
    dispatcher=dispatch_counter_brief,
    *,
    per_engagement: bool = False,
    repo_root: Optional[Path] = None,
) -> Tuple[str, Optional[str]]:
    """Process a single agent output file. Returns (status, reason)."""
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return STATUS_ERROR, f"cannot read {source}: {e}"

    if is_malformed(text):
        return STATUS_SKIPPED, f"malformed agent output: {source}"

    verdicts = extract_not_a_bug_verdicts(text)
    if not verdicts:
        return STATUS_SKIPPED, f"no NOT-A-BUG verdicts in {source}"

    brief = build_counter_brief(source, verdicts)
    try:
        response, mode = dispatcher(workspace, brief, live, swarm_tool)
    except Exception as e:
        return STATUS_ERROR, f"dispatch failed for {source}: {e}"

    status = classify_response(response)
    if status not in ALLOWED_STATUSES:
        # Defensive: classify_response is supposed to only return locked values.
        return STATUS_ERROR, f"internal: classify_response returned {status!r}"

    if status == STATUS_BREAK:
        write_break_artifact(workspace, source, verdicts, response)
        seed_new_angle(workspace, source, verdicts)
        if per_engagement:
            # Step 5: novelty-to-pattern promotion. Best-effort — failures
            # here MUST NOT downgrade the break verdict.
            rr = repo_root or DEFAULT_REPO_ROOT
            try:
                pattern_path = emit_novelty_pattern(
                    rr, workspace, source, verdicts, response)
                append_novelty_log(
                    rr, workspace, source, verdicts, response, pattern_path)
            except Exception as e:
                # Non-fatal; print but keep the break.
                print(
                    f"[adversarial-copilot] WARN novelty-promotion failed: {e}",
                    file=sys.stderr,
                )
    elif status == STATUS_HOLD:
        append_provisional_row(workspace, source, verdicts, response)
    return status, mode if status in (STATUS_BREAK, STATUS_HOLD) else None


# ---------------------------------------------------------------------------
# PR 9 (wave 8) — duplicate-root surfacing for adversarial-review reports
# ---------------------------------------------------------------------------
# The copilot's report path needs to surface back-filled
# ``duplicate_of_<accepted|rejected>`` rows so reviewers see the inherited
# parent-state context BEFORE deciding whether to argue against a verdict.
# Loaded lazily from `tools/track-submissions.py` via importlib (filename
# carries a hyphen).
import importlib.util as _adv_importlib_util  # noqa: E402

_ADV_TS_CACHE_KEY = "_adversarial_track_submissions_lib"


def _load_adv_track_submissions_lib():
    cached = sys.modules.get(_ADV_TS_CACHE_KEY)
    if cached is not None:
        return cached
    repo_root = Path(__file__).resolve().parent.parent
    spec_path = repo_root / "tools" / "track-submissions.py"
    if not spec_path.is_file():
        return None
    try:
        spec = _adv_importlib_util.spec_from_file_location(_ADV_TS_CACHE_KEY, spec_path)
        if spec is None or spec.loader is None:
            return None
        module = _adv_importlib_util.module_from_spec(spec)
        sys.modules[_ADV_TS_CACHE_KEY] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        sys.modules.pop(_ADV_TS_CACHE_KEY, None)
        return None


def render_duplicate_root_report(
    workspace: Path, ledger_path: Optional[Path] = None
) -> str:
    """Return the dup-root surfacing block for adversarial-review reports.

    The block is empty when no back-filled row matches the workspace. This
    keeps the report stable for workspaces that have not yet been processed
    by `tools/track-submissions.py backfill`.
    """
    ts = _load_adv_track_submissions_lib()
    if ts is None:
        return ""
    if ledger_path is None:
        repo_root = Path(__file__).resolve().parent.parent
        ledger_path = repo_root / "reference" / "outcomes.jsonl"
    if not ledger_path.is_file():
        return ""
    rows = ts._iter_outcomes(ledger_path)
    latest = ts._latest_rows_by_report_id(rows)
    workspace_name = workspace.name
    relevant = [
        row for row in latest.values()
        if str(row.get("workspace") or "") == workspace_name
    ]
    return ts.render_duplicate_root_summary(relevant)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="PR 204 Adversarial Co-pilot skeleton (dry-run by default)",
    )
    parser.add_argument(
        "workspace",
        nargs="?",
        default=None,
        help="Workspace directory (optional when --agent-output is used)",
    )
    parser.add_argument(
        "--input",
        "--agent-output",
        dest="input_override",
        default=None,
        help="Process a single agent-output file instead of scanning the dir",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Dispatch via swarm-orchestrator.py for real. DEFAULT is dry-run.",
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,  # dry-run is the default; flag exists for clarity
    )
    parser.add_argument(
        "--swarm-tool",
        default=None,
        help="Override path to swarm-orchestrator.py (for tests)",
    )
    parser.add_argument(
        "--per-engagement",
        action="store_true",
        help="Kimi 20/10 Step 5: enable novelty-to-pattern promotion. "
             "On a `break` verdict, emit a candidate DSL pattern under "
             "reference/patterns.dsl/_novelty/ and append a record to "
             "tools/novelty_promotion_log.json. Used by engage.py close-out.",
    )
    parser.add_argument(
        "--use-llm-dispatch",
        action="store_true",
        help="Dispatch via tools/llm-dispatch.py (Kimi+Minimax) instead of "
             "the default swarm-orchestrator pathway. Honors "
             "AUDITOOOR_LLM_NETWORK_CONSENT (enforced inside llm-dispatch.py).",
    )
    parser.add_argument(
        "--llm-provider",
        choices=("kimi", "minimax", "auto"),
        default="kimi",
        help="Provider for --use-llm-dispatch. Defaults to kimi (line-level "
             "analysis); minimax is used for synthesis citations.",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Override repo root (for hermetic novelty-log tests).",
    )
    parser.add_argument(
        "--surface-duplicate-root",
        action="store_true",
        default=False,
        help=(
            "PR 9 (wave 8): print the hidden-duplicate-root status block "
            "for the workspace and exit 0. Reads back-filled rows from the "
            "central ledger at <repo>/reference/outcomes.jsonl. Used by "
            "adversarial-review reports to surface inherited parent-state "
            "context before contesting a verdict."
        ),
    )
    parser.add_argument(
        "--ledger-path",
        default=None,
        help=(
            "PR 9 override for the central outcome ledger path. Defaults to "
            "<repo>/reference/outcomes.jsonl."
        ),
    )
    args = parser.parse_args(argv)

    # PR 9 (wave 8) early-exit: surface dup-root status without dispatching
    # any agent verdicts.
    if getattr(args, "surface_duplicate_root", False):
        if not args.workspace:
            parser.error(
                "--surface-duplicate-root requires a workspace positional"
            )
            return 1  # unreachable
        ws_path = Path(args.workspace).expanduser().resolve()
        if not ws_path.is_dir():
            print(
                f"[adversarial-copilot] ERROR: workspace not found: {ws_path}",
                file=sys.stderr,
            )
            return 1
        ledger_override = (
            Path(args.ledger_path).expanduser().resolve()
            if getattr(args, "ledger_path", None)
            else None
        )
        rendered = render_duplicate_root_report(ws_path, ledger_override)
        if rendered:
            print(rendered, end="")
        else:
            print("(no duplicate-root rows for workspace)")
        return 0

    # Resolve workspace. When the caller only passes ``--agent-output``
    # without a workspace positional, we synthesise a scratch workspace in
    # /tmp so the guard / write paths still function.  Break/hold artifacts
    # in this implicit-workspace mode are written under that scratch dir,
    # never next to the source draft — keeps iter-v3-2 T1's "read-only over
    # the real draft corpus" invariant intact.
    if args.workspace:
        workspace = Path(args.workspace).expanduser().resolve()
        if not workspace.is_dir():
            print(f"[adversarial-copilot] ERROR: workspace not found: {workspace}",
                  file=sys.stderr)
            return 1
    elif args.input_override:
        import tempfile
        workspace = Path(tempfile.mkdtemp(prefix="advcopilot_ws_")).resolve()
        (workspace / "agent_outputs").mkdir(parents=True, exist_ok=True)
    else:
        parser.error("workspace or --agent-output/--input required")
        return 1  # unreachable

    swarm_tool = (
        Path(args.swarm_tool).resolve()
        if args.swarm_tool
        else (Path(__file__).resolve().parent / "swarm-orchestrator.py")
    )

    repo_root = (
        Path(args.repo_root).expanduser().resolve()
        if args.repo_root
        else DEFAULT_REPO_ROOT
    )

    # Per-engagement mode prints calibration cite lines so the operator
    # sees current Kimi+Minimax accuracy in the run log. Best-effort —
    # missing cites do not block.
    if args.per_engagement:
        for line in _cite_calibration_lines(repo_root):
            print(f"[adversarial-copilot] calibration: {line}")

    override = Path(args.input_override).resolve() if args.input_override else None
    sources = iter_agent_outputs(workspace, override)
    if not sources:
        print(f"[adversarial-copilot] {STATUS_SKIPPED}: no agent outputs found")
        return 0

    # Pick dispatcher. ``--use-llm-dispatch`` selects the Kimi+Minimax
    # pathway; otherwise fall back to the default (black-box swarm).
    if args.use_llm_dispatch:
        provider = args.llm_provider
        def _dispatch(workspace, brief, live, swarm_tool):
            return dispatch_via_llm_dispatch(
                workspace, brief, live, swarm_tool,
                repo_root=repo_root, provider=provider,
            )
        active_dispatcher = _dispatch
    else:
        active_dispatcher = dispatch_counter_brief

    counts = {s: 0 for s in ALLOWED_STATUSES}
    skipped_reasons: List[str] = []
    for src in sources:
        status, reason = process_one(
            workspace, src, args.live, swarm_tool,
            dispatcher=active_dispatcher,
            per_engagement=args.per_engagement,
            repo_root=repo_root,
        )
        counts[status] += 1
        if status == STATUS_SKIPPED and reason:
            skipped_reasons.append(reason)
        print(f"[adversarial-copilot] {status}: {src}")

    print(
        "[adversarial-copilot] summary: "
        + ", ".join(f"{k}={counts[k]}" for k in sorted(ALLOWED_STATUSES))
    )
    if counts[STATUS_SKIPPED] and skipped_reasons:
        for r in skipped_reasons:
            print(f"[adversarial-copilot]   skipped reason: {r}")

    # Exit 0 if no hard errors, regardless of break/hold/skipped mix.
    return 1 if counts[STATUS_ERROR] else 0


if __name__ == "__main__":
    sys.exit(main())
