#!/usr/bin/env python3
"""mcp-callable-count-check.py - assert MCP callable counts agree across docs.

Phase NEG Lane H (2026-05-23): callable count claims drifted across multiple
docs:
  - ~/.claude/CLAUDE.md ("Layer 1" anchor)
  - docs/MCP_LANE_SPECIFIC_CALLABLES.md ("22 callables")
  - docs/HACKERMAN_MCP_CALLABLE_REFERENCE_2026-05-16.md ("66")
  - Wave-8 / Wave-12 chatter ("39 total")
vs. the live `TOOL_SCHEMAS` list in `tools/vault-mcp-server.py` (102 entries
as of 2026-05-24).

This script is the canonical drift gate. It:
  1. Counts the live TOOL_SCHEMAS via `python3 tools/vault-mcp-server.py --help`
     (parses the `--call {...}` choices line; no module import required).
  2. Greps each tracked doc for the count claim it advertises.
  3. Compares claims to the live count and reports drift.
  4. Optionally asserts the live count against --expected-count.
  5. Exits 0 on agreement, 1 on drift or expected-count mismatch.

Usage:
  python3 tools/mcp-callable-count-check.py                       # strict mode
  python3 tools/mcp-callable-count-check.py --expected-count 102  # pin count
  python3 tools/mcp-callable-count-check.py --json                # JSON output

Schema: auditooor.mcp_callable_count_check.v1
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

SCHEMA = "auditooor.mcp_callable_count_check.v1"

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"
LANE_DOC = REPO_ROOT / "docs" / "MCP_LANE_SPECIFIC_CALLABLES.md"
HACKERMAN_DOC = REPO_ROOT / "docs" / "HACKERMAN_MCP_CALLABLE_REFERENCE_2026-05-16.md"
USER_CLAUDE_MD = pathlib.Path(os.path.expanduser("~/.claude/CLAUDE.md"))


def live_callable_count() -> tuple[int, list[str]]:
    """Return (count, sorted_callable_names) from the live server --help."""
    if not SERVER.exists():
        raise SystemExit(f"FATAL: server missing: {SERVER}")
    proc = subprocess.run(
        ["python3", str(SERVER), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(REPO_ROOT),
    )
    text = proc.stdout + proc.stderr
    match = re.search(r"--call\s*\{([^}]+)\}", text)
    if not match:
        raise SystemExit(
            "FATAL: could not parse --call choices from server --help. "
            f"stdout[:300]={proc.stdout[:300]!r}"
        )
    choices = sorted(c.strip() for c in match.group(1).split(",") if c.strip())
    return len(choices), choices


LAYER_TOTAL_RE = re.compile(
    r"\*\*(\d+)\*\*\s*callables?\s*total|"
    r"\*\*(\d+)\s*callables?\s*total\*\*|"
    r"callable\s+count:?\s*\*\*(\d+)\*\*\s*total|"
    r"(\d+)\s*callables?\s*total",
    re.IGNORECASE,
)
SCHEMA_COUNT_RE = re.compile(
    r"Schema\s+count[^*\n]*\*\*(\d+)\*\*", re.IGNORECASE
)
TOTAL_CALLABLES_DOC_RE = re.compile(
    r"Total\s+callables?\s+documented[^*\n]*\*\*(\d+)\*\*", re.IGNORECASE
)
# Catch "N callable(s)" with leading numerals between 30-200; tighter window
# to avoid matching "Check #94" / "PR #94" / record counts.
COUNT_RE = re.compile(r"(?:\b|\*\*)(\d{2,3})(?:\*\*)?\s*callables?\b", re.IGNORECASE)
LAYER1_LIST_RE = re.compile(r"LAYER_1\s*\(([^)]*)\)", re.IGNORECASE)
CALLABLE_NAME_RE = re.compile(r"`?(vault_[a-z0-9_]+)`?")


def extract_claims(path: pathlib.Path) -> list[tuple[int, int, str]]:
    """Return list of (line_number, claimed_count, snippet) from a doc.

    Looks for these shapes (in priority order):
      - "**N callables total**" / "**N** callables total" / "callable count: **N** total"
      - "Total callables documented: **N**"   (hackerman doc top)
      - "Schema count: **N**"                 (hackerman appendix)
      - "N callable" / "N callables" / "N-callable" (catch-all, N in [30..200])
    Skips counts <30 (typically subset claims like "4 callable contexts" -
    these are historically valid Layer-1 subsets, not total-count claims).
    """
    if not path.exists():
        return []
    claims: list[tuple[int, int, str]] = []
    with path.open("r", encoding="utf-8") as fh:
        for ln, line in enumerate(fh, 1):
            for rx in (
                LAYER_TOTAL_RE,
                TOTAL_CALLABLES_DOC_RE,
                SCHEMA_COUNT_RE,
                COUNT_RE,
            ):
                hit = None
                for m in rx.finditer(line):
                    for g in m.groups():
                        if g is None:
                            continue
                        try:
                            count = int(g)
                        except ValueError:
                            continue
                        if not (30 <= count <= 200):
                            continue
                        hit = count
                        break
                    if hit is not None:
                        break
                if hit is not None:
                    snippet = line.strip()[:160]
                    claims.append((ln, hit, snippet))
                    break  # one claim per line is enough
    return claims


def check_doc(
    path: pathlib.Path, expected: int, label: str
) -> dict:
    """Return per-doc verdict."""
    if not path.exists():
        return {
            "doc": label,
            "path": str(path),
            "exists": False,
            "claims": [],
            "verdict": "skip-missing",
        }
    claims = extract_claims(path)
    if not claims:
        return {
            "doc": label,
            "path": str(path),
            "exists": True,
            "claims": [],
            "verdict": "skip-no-claim-found",
        }
    # The canonical claim should match expected. Any drift = fail.
    mismatches = [
        {"line": ln, "claimed": c, "snippet": s}
        for (ln, c, s) in claims
        if c != expected
    ]
    matches = [
        {"line": ln, "claimed": c, "snippet": s}
        for (ln, c, s) in claims
        if c == expected
    ]
    if mismatches:
        return {
            "doc": label,
            "path": str(path),
            "exists": True,
            "expected": expected,
            "matches": matches,
            "mismatches": mismatches,
            "verdict": "fail-drift",
        }
    return {
        "doc": label,
        "path": str(path),
        "exists": True,
        "expected": expected,
        "matches": matches,
        "verdict": "pass-all-claims-match",
    }


def extract_layer1_callables(path: pathlib.Path) -> list[tuple[int, str]]:
    """Return (line_number, callable_name) entries from the LAYER_1 doc list."""
    if not path.exists():
        return []
    callables: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8") as fh:
        for ln, line in enumerate(fh, 1):
            match = LAYER1_LIST_RE.search(line)
            if not match:
                continue
            for name in CALLABLE_NAME_RE.findall(match.group(1)):
                callables.append((ln, name))
    return callables


def check_layer1_schema_refs(path: pathlib.Path, live_names: list[str]) -> dict:
    """Assert every documented Layer-1 callable exists in live TOOL_SCHEMAS."""
    refs = extract_layer1_callables(path)
    live = set(live_names)
    missing = [
        {"line": ln, "callable": name}
        for (ln, name) in refs
        if name not in live
    ]
    if missing:
        verdict = "fail-missing-callable"
    elif refs:
        verdict = "pass-all-callables-live"
    else:
        verdict = "skip-no-layer1-list-found"
    return {
        "doc": "MCP_LANE_SPECIFIC_CALLABLES.md Layer-1 refs",
        "path": str(path),
        "refs": [{"line": ln, "callable": name} for (ln, name) in refs],
        "missing": missing,
        "verdict": verdict,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON verdict on stdout."
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Hard-fail unless the live TOOL_SCHEMAS count equals this value.",
    )
    parser.add_argument(
        "--include-user-claude-md",
        action="store_true",
        help="Also check ~/.claude/CLAUDE.md (off by default since it's user-scope).",
    )
    args = parser.parse_args()

    live_count, live_names = live_callable_count()
    live_count_matches_expected = (
        args.expected_count is None or live_count == args.expected_count
    )

    docs = [
        check_doc(LANE_DOC, live_count, "MCP_LANE_SPECIFIC_CALLABLES.md"),
        check_doc(HACKERMAN_DOC, live_count, "HACKERMAN_MCP_CALLABLE_REFERENCE_2026-05-16.md"),
    ]
    if args.include_user_claude_md:
        docs.append(check_doc(USER_CLAUDE_MD, live_count, "~/.claude/CLAUDE.md"))

    drift = [d for d in docs if d["verdict"] == "fail-drift"]
    skips = [d for d in docs if d["verdict"].startswith("skip")]
    layer1_refs = check_layer1_schema_refs(LANE_DOC, live_names)
    missing_layer1_refs = layer1_refs["verdict"] == "fail-missing-callable"
    overall = (
        "pass"
        if not drift and live_count_matches_expected and not missing_layer1_refs
        else "fail"
    )

    verdict = {
        "schema": SCHEMA,
        "live_count": live_count,
        "expected_count": args.expected_count,
        "live_count_matches_expected": live_count_matches_expected,
        "live_callables_first_10": live_names[:10],
        "docs": docs,
        "layer1_refs": layer1_refs,
        "drift_count": len(drift),
        "skip_count": len(skips),
        "overall": overall,
    }

    if args.json:
        print(json.dumps(verdict, indent=2, sort_keys=True))
    else:
        print(f"[mcp-callable-count-check] live TOOL_SCHEMAS count: {live_count}")
        if args.expected_count is not None:
            if live_count_matches_expected:
                print(
                    f"  PASS expected live count ({args.expected_count})"
                )
            else:
                print(
                    f"  FAIL expected live count: expected {args.expected_count}, "
                    f"got {live_count}"
                )
        for d in docs:
            v = d["verdict"]
            if v == "pass-all-claims-match":
                n = len(d.get("matches", []))
                print(f"  PASS {d['doc']} ({n} matching claim(s))")
            elif v == "fail-drift":
                n = len(d["mismatches"])
                print(f"  FAIL {d['doc']} ({n} drifted claim(s)):")
                for mm in d["mismatches"]:
                    print(
                        f"      line {mm['line']}: claimed {mm['claimed']} "
                        f"(expected {live_count}) | {mm['snippet']}"
                    )
            else:
                print(f"  SKIP {d['doc']} ({v})")
        if layer1_refs["verdict"] == "pass-all-callables-live":
            print(
                "  PASS MCP_LANE_SPECIFIC_CALLABLES.md Layer-1 refs "
                f"({len(layer1_refs['refs'])} live callable(s))"
            )
        elif layer1_refs["verdict"] == "fail-missing-callable":
            print("  FAIL MCP_LANE_SPECIFIC_CALLABLES.md Layer-1 refs:")
            for mm in layer1_refs["missing"]:
                print(f"      line {mm['line']}: missing {mm['callable']}")
        else:
            print(
                "  SKIP MCP_LANE_SPECIFIC_CALLABLES.md Layer-1 refs "
                f"({layer1_refs['verdict']})"
            )
        if drift:
            print(
                f"[mcp-callable-count-check] DRIFT: {len(drift)} doc(s) "
                f"disagree with live count {live_count}",
                file=sys.stderr,
            )
        if not live_count_matches_expected:
            print(
                "[mcp-callable-count-check] DRIFT: live count "
                f"{live_count} does not match expected count {args.expected_count}",
                file=sys.stderr,
            )
        if missing_layer1_refs:
            print(
                "[mcp-callable-count-check] DRIFT: Layer-1 docs reference "
                "callables missing from live TOOL_SCHEMAS",
                file=sys.stderr,
            )
        if not drift and live_count_matches_expected and not missing_layer1_refs:
            print("[mcp-callable-count-check] OK: all docs agree with live count")

    if drift or not live_count_matches_expected or missing_layer1_refs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
