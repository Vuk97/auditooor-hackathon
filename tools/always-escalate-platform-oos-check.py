#!/usr/bin/env python3
# r36-rebuttal: lane GAP-FIX-1-gap30 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Gap #30 always-escalate platform-OOS filter.

The ALWAYS-ESCALATE-BY-DEFAULT discipline (Rule 14 / triager-amend
asymmetry) is sound but doesn't know about platform-specific OOS clauses.
Hyperbridge SCOPE.md, for instance, lists ``Theoretical vulnerabilities
without any proof or demonstration`` as out-of-scope - escalating a
candidate whose framing matches that phrase wastes cycles.

This gate reads the workspace's ``SCOPE.md`` + ``SEVERITY.md``, builds a
per-workspace OOS-phrase list (default seed plus any phrases in env
override), and reports whether a candidate framing matches an OOS phrase.

When called from an orchestrator considering Rule-14 escalation, a
``fail-candidate-framing-matches-platform-oos`` verdict means: do NOT
escalate the candidate, file at the lower tier (or drop entirely).

Override marker:
  ``<!-- gap30-rebuttal: <reason up to 200 chars> -->``
  or the visible bounded line ``gap30-rebuttal: <reason>``.

Verdicts:
  - pass-no-scope-file: workspace has neither SCOPE.md nor SEVERITY.md (no
    OOS corpus to check against)
  - pass-candidate-framing-not-oos: framing does not match any platform
    OOS phrase
  - ok-rebuttal: bounded gap30-rebuttal accepted
  - fail-candidate-framing-matches-platform-oos: framing matches >=1 OOS
    phrase from SCOPE.md / SEVERITY.md
  - error: input / IO error

Exit codes:
  0 - pass / ok-rebuttal
  1 - fail-* verdict
  2 - error

Schema: ``auditooor.gap30_always_escalate_platform_oos.v1``.

Empirical anchor (2026-05-26): Hyperbridge SCOPE.md "Theoretical
vulnerabilities without any proof or demonstration" OOS clause - any
ALWAYS-ESCALATE candidate framed as "theoretical without demonstration"
will be triager-closed regardless of severity-tier elevation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.gap30_always_escalate_platform_oos.v1"
GATE = "GAP30-ALWAYS-ESCALATE-PLATFORM-OOS"
TOOL_REL_PATH = "tools/always-escalate-platform-oos-check.py"

# Default OOS-phrase seed list. Platform-agnostic phrasings that show up
# across HackenProof / Cantina / Immunefi / Sherlock / Code4rena
# SCOPE.md / SEVERITY.md / rules. Per-workspace lists ADD to this seed.
DEFAULT_OOS_PHRASES = [
    r"theoretical\s+vulnerabilit(?:y|ies)\s+without\s+(?:any\s+)?(?:proof|demonstration)",
    r"vulnerabilit(?:y|ies)\s+without\s+(?:any\s+)?(?:proof|demonstration)",
    r"speculative\s+(?:attack|vulnerability|finding)",
    r"hypothetical\s+(?:attack|exploit|vulnerability)\s+without\s+(?:a\s+)?proof",
    r"missing\s+(?:proof[\s-]?of[\s-]?concept|PoC)",
    r"design[\s-]?(?:choice|decision|by[\s-]design)",
    r"acknowledged[\s-]?(?:by[\s-]design|risk)",
    r"centralization\s+risk(?:s)?\s+(?:acknowledged|accepted)",
    r"(?:gas|griefing|denial[\s-]of[\s-]service|DoS)\s+attacks\s+(?:are\s+)?(?:OOS|out[\s-]of[\s-]scope|excluded)",
    r"informational(?:[\s-]only)?\s+(?:finding|issue|observation)",
    r"best[\s-]practice(?:s)?\s+only",
    r"gas\s+optimization(?:s)?\s+(?:only|excluded|OOS)",
    r"compromise\s+of\s+(?:off[\s-]chain|trusted)\s+infra\w*",
    r"validator[\s-]key\s+comprom\w*\s+(?:OOS|out[\s-]of[\s-]scope)",
    r"social\s+engineering",
    r"phishing\s+(?:attack|vulnerability)",
]

# Per-platform OOS overlay seeds (auto-applied based on directory hints).
PLATFORM_OOS_OVERLAY = {
    "hyperbridge": [
        r"theoretical\s+vulnerabilit",
    ],
    "polymarket": [
        r"restricted\s+to\s+deposit\s+wallets",
    ],
    "dydx": [
        r"non[\s-]core\s+module",
    ],
}

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*gap30[-_ ]rebuttal\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?gap30[-_ ]rebuttal\s*:\s*(.+?)\s*$",
)

MAX_REBUTTAL_LEN = 200

SCOPE_FILES = ("SCOPE.md", "scope.md", "SEVERITY.md", "severity.md")


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    payload.setdefault("schema", SCHEMA_VERSION)
    payload.setdefault("gate", GATE)
    payload.setdefault("tool", TOOL_REL_PATH)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        v = payload.get("verdict", "?")
        r = payload.get("reason", "")
        print(f"[{GATE}] verdict={v} reason={r}")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except OSError:
        return ""


def _load_platform_oos(workspace: Path) -> tuple[list[str], list[str]]:
    """Return (oos_phrases, source_paths) discovered for the workspace.

    The returned `oos_phrases` list is a literal-string list of OOS phrase
    rows extracted from SCOPE.md / SEVERITY.md - one phrase per row. They
    are matched literally (case-insensitive) against candidate framing.
    """
    discovered: list[str] = []
    sources: list[str] = []
    for name in SCOPE_FILES:
        p = workspace / name
        if p.exists():
            text = _read_text(p)
            if text.strip():
                discovered.append(text)
                sources.append(str(p))
    return discovered, sources


def _extract_oos_phrase_rows(text: str) -> list[str]:
    """Heuristic: a SCOPE.md / SEVERITY.md OOS row tends to be a list-item
    or table-row line containing one of: ``out of scope``, ``OOS``, ``not
    eligible``, ``excluded``, ``acknowledged``, ``known issue``.
    """
    out_keywords = re.compile(
        r"\b(out[\s-]of[\s-]scope|OOS|not\s+eligible|excluded|acknowledged|known\s+issue|won't[\s-]?fix|by[\s-]design)\b",
        re.IGNORECASE,
    )
    rows: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("-*|").strip()
        if not line:
            continue
        if out_keywords.search(line):
            # Trim trailing pipes/lists to a clean phrase.
            phrase = re.sub(r"\s+", " ", line)[:400]
            rows.append(phrase)
    return rows


def _detect_workspace_platform(workspace: Path) -> str | None:
    name = workspace.name.lower()
    for plat in PLATFORM_OOS_OVERLAY:
        if plat in name:
            return plat
    return None


def _extract_rebuttal(text: str) -> str | None:
    if not text:
        return None
    m = REBUTTAL_HTML_RE.search(text)
    if not m:
        m = REBUTTAL_LINE_RE.search(text)
    if not m:
        return None
    reason = (m.group(1) or "").strip()
    if not reason or len(reason) > MAX_REBUTTAL_LEN:
        return None
    return reason


def _build_phrase_set(
    workspace: Path,
    env_extra: str = "",
    platform_overlay: str | None = None,
) -> tuple[list[str], list[str]]:
    """Return (compiled regex source list, OOS row literal list).

    The compiled regex list comes from DEFAULT_OOS_PHRASES + the
    platform-overlay (if any) + env-extra patterns.
    The OOS row literal list comes from SCOPE.md / SEVERITY.md row parsing.
    Both are used to evaluate a candidate framing.
    """
    patterns = list(DEFAULT_OOS_PHRASES)
    if platform_overlay and platform_overlay in PLATFORM_OOS_OVERLAY:
        patterns.extend(PLATFORM_OOS_OVERLAY[platform_overlay])
    if env_extra:
        for raw in env_extra.splitlines():
            line = raw.strip()
            if line:
                patterns.append(line)

    docs, _src = _load_platform_oos(workspace)
    oos_row_literals: list[str] = []
    for text in docs:
        oos_row_literals.extend(_extract_oos_phrase_rows(text))

    return patterns, oos_row_literals


def _framing_matches_oos(
    framing: str,
    patterns: list[str],
    oos_row_literals: list[str],
) -> tuple[bool, list[str]]:
    """Return (matched_any, matched_evidence_list)."""
    if not framing:
        return (False, [])
    evidence: list[str] = []
    for pat in patterns:
        try:
            if re.search(pat, framing, re.IGNORECASE):
                evidence.append(f"pattern: {pat}")
        except re.error:
            continue
    # SCOPE.md row matching is substring-based on the lowercased framing.
    framing_low = framing.lower()
    for row in oos_row_literals:
        # Trim the OOS-keyword tail; if any 3+ word substring of the row
        # appears in the framing, count it.
        row_low = row.lower()
        tokens = re.findall(r"\w+", row_low)
        if len(tokens) >= 3:
            # Try 3- and 4-token windows.
            for window in (4, 3):
                if len(tokens) < window:
                    continue
                for i in range(len(tokens) - window + 1):
                    chunk = " ".join(tokens[i : i + window])
                    if chunk in framing_low:
                        evidence.append(f"scope-row: {row[:120]}")
                        break
                else:
                    continue
                break
    return (bool(evidence), evidence)


def check(
    workspace: Path,
    candidate_framing: str,
    rebuttal_text: str = "",
    env_extra_patterns: str = "",
) -> dict[str, Any]:
    if not workspace.exists():
        return {
            "verdict": "error",
            "reason": f"workspace path does not exist: {workspace}",
            "exit": 2,
        }

    platform = _detect_workspace_platform(workspace)
    patterns, oos_rows = _build_phrase_set(workspace, env_extra_patterns, platform)

    # If no SCOPE.md / SEVERITY.md AND no env-extra rows AND no platform
    # overlay, fall back to pass-no-scope-file. Default seeds still apply
    # if the framing matches one - that's the cross-platform default.
    has_corpus = bool(oos_rows or env_extra_patterns or (platform is not None))

    rebuttal = _extract_rebuttal(rebuttal_text)
    if rebuttal:
        return {
            "verdict": "ok-rebuttal",
            "reason": f"gap30-rebuttal accepted: {rebuttal}",
            "exit": 0,
            "platform": platform,
        }

    matched, evidence = _framing_matches_oos(candidate_framing, patterns, oos_rows)

    if matched:
        return {
            "verdict": "fail-candidate-framing-matches-platform-oos",
            "reason": (
                f"candidate framing matches {len(evidence)} platform-OOS "
                "phrase(s); always-escalate should be suppressed"
            ),
            "exit": 1,
            "platform": platform,
            "evidence": evidence[:8],
            "candidate_framing_snippet": candidate_framing[:240],
            "oos_phrase_count": len(patterns) + len(oos_rows),
            "remediation": (
                "Suppress always-escalate. File at the lower tier without "
                "Rule-14 amend, or drop the candidate entirely. Override: "
                "add `<!-- gap30-rebuttal: <reason up to 200 chars> -->`."
            ),
        }

    if not has_corpus:
        return {
            "verdict": "pass-no-scope-file",
            "reason": (
                "workspace has no SCOPE.md / SEVERITY.md and no env-extra "
                "or platform-overlay phrases; default seeds did not match"
            ),
            "exit": 0,
            "platform": platform,
        }

    return {
        "verdict": "pass-candidate-framing-not-oos",
        "reason": (
            f"candidate framing does not match any of "
            f"{len(patterns)} pattern(s) + {len(oos_rows)} SCOPE row(s)"
        ),
        "exit": 0,
        "platform": platform,
        "patterns_evaluated": len(patterns),
        "scope_rows_evaluated": len(oos_rows),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Gap #30 always-escalate platform-OOS filter. Cross-checks a "
            "candidate's framing against the workspace's SCOPE.md / "
            "SEVERITY.md OOS clauses and the cross-platform default seed."
        ),
    )
    p.add_argument("--workspace", required=True, help="Workspace path.")
    p.add_argument(
        "--candidate-framing",
        default="",
        help="Candidate framing text (one-liner from the finding draft).",
    )
    p.add_argument(
        "--framing-file",
        default=None,
        help="Optional path to a file whose contents are the candidate framing.",
    )
    p.add_argument(
        "--rebuttal-text",
        default="",
        help="Optional inline rebuttal text.",
    )
    p.add_argument(
        "--rebuttal-file",
        default=None,
        help="Optional rebuttal source file.",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    args = p.parse_args(argv)

    ws = Path(args.workspace).expanduser()

    framing = args.candidate_framing or ""
    if args.framing_file:
        try:
            framing = (framing + "\n" + Path(args.framing_file).expanduser().read_text(encoding="utf-8")).strip()
        except OSError:
            pass

    rebuttal_text = args.rebuttal_text or ""
    if args.rebuttal_file:
        try:
            rebuttal_text = (rebuttal_text + "\n" + Path(args.rebuttal_file).expanduser().read_text(encoding="utf-8")).strip()
        except OSError:
            pass

    env_extra = os.environ.get("AUDITOOOR_GAP30_OOS_PATTERNS", "")

    result = check(
        workspace=ws,
        candidate_framing=framing,
        rebuttal_text=rebuttal_text,
        env_extra_patterns=env_extra,
    )

    exit_code = int(result.pop("exit", 0))
    _emit(result, args.json)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
