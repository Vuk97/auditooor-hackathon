#!/usr/bin/env python3
"""scope-reasoner.py — capability-v3 iter-002 T5.

Regex-based scope reasoner. Reads a draft submission and the workspace
`SCOPE.md`, greps for known out-of-scope patterns, and emits a JSON
advisory indicating whether the draft is likely to be rejected on scope
grounds.

Design notes
------------
* Pattern-matching only. No ML, no LLM calls. Deterministic.
* Advisory output. The tool does NOT gate submissions — the operator
  integrates the flag signal into the drafting loop.
* Patterns live in `tools/scope_oos_patterns.json` so they can be
  extended without code changes. Each entry cites either a concrete
  triager rejection (e.g. SNOW R67-F001) or is marked "common".

Output schema (stable)
----------------------
    {
      "draft": "<path>",
      "scope_file": "<path>",
      "scope_oos_clauses": [<str>, ...],       # raw OOS lines from SCOPE.md
      "flags": [
        {
          "pattern_name": "<str>",
          "matches_found": ["<snippet>", ...],   # up to 5 lowercased snippets
          "severity": "likely-OOS | advisory | common-OOS | medium-OOS",
          "rationale": "<str>",
          "reference": "<str>",
          "scope_clause_hit": true | false
        },
        ...
      ],
      "suppressed_flags": [                     # PR #526 gap #1
        {
          "pattern_name": "<str>",
          "matches_found": ["<snippet>", ...],
          "exception_name": "<str>",
          "include_hits": ["<snippet>", ...],
          "exclude_hits": ["<snippet>", ...],
          "rationale": "<why suppressed>"
        },
        ...
      ],
      "risk_level": "none | advisory | likely-OOS"
    }

Risk ladder
-----------
* `likely-OOS`  — at least one pattern matched AND SCOPE.md has a
  corresponding OOS clause (keyword overlap).
* `advisory`    — at least one pattern matched but no SCOPE.md OOS
  clause mentions that territory. Soft nudge.
* `none`        — no pattern hits.

Exit code is always 0. Consumers read `risk_level` from the JSON.

Usage
-----
    python3 tools/scope-reasoner.py --draft path/to/source-draft.md
    python3 tools/scope-reasoner.py \
        --draft path/to/source-draft.md \
        --scope path/to/SCOPE.md \
        --oos-patterns path/to/patterns.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_PATTERNS = Path(__file__).resolve().parent / "scope_oos_patterns.json"

# OOS-clause header / inline markers we look for in SCOPE.md.
SCOPE_OOS_MARKERS = re.compile(
    r"(out[\s\-]?of[\s\-]?scope|\bOOS\b|excluded|not covered|excluded classes|"
    r"do not submit|will be marked invalid|will be considered out of scope|"
    r"not eligible)",
    re.IGNORECASE,
)

MACHINE_SCOPE_METADATA_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:oos_traps|oos checked|selected_impact|secondary_impact|"
    r"listed_impact_proven|severity_tier|impact\(s\)|asset|scope)\s*:",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Scope parsing
# ---------------------------------------------------------------------------


def derive_scope_path(draft_path: Path) -> Path | None:
    """Walk up from the draft looking for a SCOPE.md.

    We try ancestors up to 6 levels. That covers the usual layout:
      <ws>/submissions/packaged/<fid>/source-draft.md
      <ws>/SCOPE.md
    """
    for ancestor in [draft_path.parent, *draft_path.parents][:7]:
        candidate = ancestor / "SCOPE.md"
        if candidate.exists():
            return candidate
    return None


def parse_scope_oos_clauses(scope_path: Path) -> list[str]:
    """Return raw lines from SCOPE.md that look like OOS clauses.

    Strategy: (1) lines that directly match an OOS marker regex; (2) any
    line (non-blank) nested under a header whose title matches the
    marker regex, until the next `#` header.
    """
    if not scope_path or not scope_path.exists():
        return []

    lines = scope_path.read_text(errors="replace").splitlines()
    out: list[str] = []
    inside_oos_section = False

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        if stripped.startswith("#"):
            # heading — does it flip us in/out of an OOS section?
            inside_oos_section = bool(SCOPE_OOS_MARKERS.search(stripped))
            if inside_oos_section:
                out.append(stripped)
            continue

        if not stripped:
            continue

        if inside_oos_section:
            out.append(stripped)
        elif SCOPE_OOS_MARKERS.search(stripped):
            out.append(stripped)

    return out


# ---------------------------------------------------------------------------
# Pattern loading / scanning
# ---------------------------------------------------------------------------


def load_patterns(patterns_path: Path) -> dict[str, dict[str, Any]]:
    if not patterns_path.exists():
        raise SystemExit(f"[scope-reasoner] patterns file not found: {patterns_path}")
    try:
        data = json.loads(patterns_path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[scope-reasoner] bad JSON in {patterns_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"[scope-reasoner] patterns file must be a JSON object")
    return data


def scan_draft(draft_text: str, pattern_regex: str) -> list[str]:
    """Return up to 5 matching snippet lines (case-insensitive)."""
    try:
        compiled = re.compile(pattern_regex, re.IGNORECASE)
    except re.error as exc:
        raise SystemExit(
            f"[scope-reasoner] invalid regex {pattern_regex!r}: {exc}"
        ) from exc

    hits: list[str] = []
    for raw in draft_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if MACHINE_SCOPE_METADATA_RE.search(line):
            continue
        if compiled.search(line):
            # Trim very long lines for readability in the JSON output.
            hits.append(line.lower()[:240])
            if len(hits) >= 5:
                break
    return hits


def scope_clause_matches(scope_clauses: list[str], keywords: list[str]) -> bool:
    """Does any SCOPE.md OOS clause mention any of these keywords?"""
    if not scope_clauses or not keywords:
        return False
    joined = " ".join(scope_clauses).lower()
    return any(kw.lower() in joined for kw in keywords)


# ---------------------------------------------------------------------------
# Per-pattern exception classifier (PR #526 gap #1)
# ---------------------------------------------------------------------------
#
# Patterns originally written against Solidity dispute-game / proof-system
# rejection shapes (e.g. `unproven_bad_game_prereq`) misfire on Rust
# blockchain/DLT reports rooted in Engine API payload validation. The legacy
# regex matches phrases like "invalid game ... finalized" that also appear in
# Engine-API-payload prose ("invalid block / state / root ... resolved /
# finalized"), but the Rust DLT path has no Solidity dispute game whatsoever.
#
# Each pattern entry MAY declare:
#
#   "exceptions": [
#     {
#       "name": "dlt_engine_api",
#       "include_pattern": "(engine_newPayload...|OpEngineValidator|...)",
#       "exclude_pattern": "(dispute\\s+game|FaultDisputeGame|...)",
#       "rationale": "<why this draft is not the legacy class>"
#     },
#     ...
#   ]
#
# The flag is SUPPRESSED iff:
#   * the include_pattern matches (Rust DLT / Engine-API entrypoint cited), AND
#   * the exclude_pattern does NOT match (no Solidity dispute-game shape).
#
# When both DLT and dispute-game markers appear, the flag still fires — the
# draft is mixing classes and the conservative outcome is to surface the
# warning. This preserves the FN5/FN6 regression check.


def evaluate_exception(
    draft_text: str,
    exception: dict[str, Any],
) -> tuple[bool, list[str], list[str]]:
    """Return (suppress, include_hits, exclude_hits) for one exception entry.

    `suppress` is True iff include_pattern matches AND exclude_pattern does
    NOT match. Hits are returned for transparency in the JSON output.
    """
    include = exception.get("include_pattern")
    if not include:
        return False, [], []

    include_hits = scan_draft(draft_text, include)
    if not include_hits:
        return False, [], []

    exclude = exception.get("exclude_pattern")
    exclude_hits = scan_draft(draft_text, exclude) if exclude else []

    suppress = bool(include_hits) and not exclude_hits
    return suppress, include_hits, exclude_hits


def apply_exceptions(
    draft_text: str,
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    """Walk an entry's `exceptions` list. Return the first triggered
    exception's record (for the JSON output) or None when no exception
    suppresses the flag.

    Conservative semantics: if ANY exception declares both an include hit
    and a non-empty exclude hit, the flag still fires — the draft is
    mixing classes and we surface the warning.
    """
    raw_exceptions = entry.get("exceptions") or []
    if not isinstance(raw_exceptions, list):
        return None

    for exc in raw_exceptions:
        if not isinstance(exc, dict):
            continue
        suppress, include_hits, exclude_hits = evaluate_exception(draft_text, exc)
        if suppress:
            return {
                "exception_name": exc.get("name", "unnamed"),
                "include_hits": include_hits[:3],
                "exclude_hits": exclude_hits[:3],
                "rationale": exc.get("rationale", ""),
            }
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def reason(
    draft_path: Path,
    scope_path: Path | None,
    patterns_path: Path,
) -> dict[str, Any]:
    if not draft_path.exists():
        raise SystemExit(f"[scope-reasoner] draft not found: {draft_path}")

    draft_text = draft_path.read_text(errors="replace")
    patterns = load_patterns(patterns_path)

    scope_clauses = parse_scope_oos_clauses(scope_path) if scope_path else []

    flags: list[dict[str, Any]] = []
    risk_level = "none"

    suppressions: list[dict[str, Any]] = []

    for name, entry in patterns.items():
        regex = entry.get("pattern")
        if not regex:
            continue

        matches = scan_draft(draft_text, regex)
        if not matches:
            continue

        # Classifier exception: a pattern entry can declare include/exclude
        # regexes that suppress the flag when the draft cites a different
        # backend class than the one the legacy pattern was written for.
        # See PR #526 gap #1 (FN7-style Rust DLT vs legacy FN5/FN6 Solidity
        # dispute-game prerequisite class).
        exception_record = apply_exceptions(draft_text, entry)
        if exception_record is not None:
            suppressions.append(
                {
                    "pattern_name": name,
                    "matches_found": matches,
                    **exception_record,
                }
            )
            continue

        keywords = entry.get("scope_keywords") or []
        clause_hit = scope_clause_matches(scope_clauses, keywords)

        # Resolve per-flag severity.
        default_sev = entry.get("flag_severity", "advisory")
        if clause_hit:
            severity = "likely-OOS"
        else:
            severity = "advisory"

        flags.append(
            {
                "pattern_name": name,
                "matches_found": matches,
                "severity": severity,
                "declared_severity": default_sev,
                "rationale": entry.get("rationale", ""),
                "reference": entry.get("reference", ""),
                "scope_clause_hit": clause_hit,
            }
        )

        # Risk-level ladder: any likely-OOS wins; else advisory; else none.
        if severity == "likely-OOS":
            risk_level = "likely-OOS"
        elif risk_level == "none":
            risk_level = "advisory"

    return {
        "draft": str(draft_path),
        "scope_file": str(scope_path) if scope_path else "",
        "scope_oos_clauses": scope_clauses,
        "flags": flags,
        "suppressed_flags": suppressions,
        "risk_level": risk_level,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Regex-based scope reasoner. Advisory-only; flags likely-OOS "
            "drafts before submission."
        )
    )
    parser.add_argument(
        "--draft",
        required=True,
        type=Path,
        help="Path to the draft markdown file.",
    )
    parser.add_argument(
        "--scope",
        type=Path,
        default=None,
        help="Path to SCOPE.md. Default: walk up from --draft to find it.",
    )
    parser.add_argument(
        "--oos-patterns",
        type=Path,
        default=DEFAULT_PATTERNS,
        help=f"Path to patterns JSON. Default: {DEFAULT_PATTERNS}",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indent (default 2). Use 0 or negative for compact output.",
    )
    args = parser.parse_args(argv)

    scope_path = args.scope if args.scope is not None else derive_scope_path(args.draft)

    result = reason(args.draft, scope_path, args.oos_patterns)

    indent = args.indent if args.indent > 0 else None
    json.dump(result, sys.stdout, indent=indent, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
