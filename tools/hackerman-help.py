#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - navigable index of all
``hackerman-*`` make targets defined in the repo Makefile.

Scans the Makefile for any target whose name starts with ``hackerman-`` and
emits a deterministic, human-readable (or JSON-enveloped) index containing:

- Target name
- Purpose, extracted from the contiguous ``#`` comment block immediately
  preceding the target line (the canonical doc location in this repo's
  Makefile authoring convention).
- Companion ``-test`` target, if any (auto-detected by name).
- Common knobs: env vars referenced from the target body via
  ``$(NAME)`` / ``$$NAME`` / inline ``NAME=`` assignments. These are the
  same toggles operators flip from the command line.

The tool is a one-shot lookup, not deeply interactive. Default output is a
plain-text index sorted by target name. Pass ``--json`` for a machine
envelope (``auditooor.hackerman_help.v1``).

Determinism guarantees:

- Targets are listed in lexicographic order.
- Knob lists are sorted asc.
- Companion ``-test`` detection prefers the exact ``<target>-test`` form;
  ``-test`` companion targets are never indexed as top-level entries (they
  show up nested under the parent).

Wired into the Makefile as:

    make hackerman-help          # human index
    make hackerman-help-json     # JSON envelope
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAKEFILE = REPO_ROOT / "Makefile"

TARGET_RE = re.compile(r"^(hackerman-[A-Za-z0-9_.-]+)\s*:")
# Captures env-var references inside the recipe body:
#   $(NAME) / $${NAME} / inline NAME=<value>
KNOB_PAREN_RE = re.compile(r"\$\(([A-Z][A-Z0-9_]+)\)")
KNOB_BRACE_RE = re.compile(r"\$\$\{([A-Z][A-Z0-9_]+)\}")
KNOB_INLINE_RE = re.compile(r"\b([A-Z][A-Z0-9_]{2,})=")

# Make built-ins / phony noise we never want to surface as a "knob".
KNOB_BLACKLIST = {
    "MAKE", "MAKEFLAGS", "SHELL", "PWD", "PATH", "HOME", "USER",
    "CURDIR", "MAKEFILE_LIST", "VPATH", "SUFFIXES",
}


def _read_makefile(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Makefile not found: {path}")
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _leading_comment_block(lines: list[str], target_idx: int) -> str:
    """Walk upward from ``target_idx - 1`` collecting contiguous ``#`` lines.

    Stops at the first non-comment, non-blank line. Strips ``# `` prefix.
    Ignores ``.PHONY:`` lines so a target can have ``.PHONY`` between its
    comment block and its rule line.
    """
    out: list[str] = []
    idx = target_idx - 1
    while idx >= 0:
        raw = lines[idx]
        stripped = raw.strip()
        if not stripped:
            # Blank line: stop walking upward.
            break
        if stripped.startswith(".PHONY"):
            idx -= 1
            continue
        if stripped.startswith("#"):
            # Drop leading "# " or "#".
            text = stripped[1:]
            if text.startswith(" "):
                text = text[1:]
            out.append(text)
            idx -= 1
            continue
        break
    out.reverse()
    return "\n".join(out).strip()


def _recipe_body(lines: list[str], target_idx: int) -> str:
    """Collect contiguous recipe lines (start with TAB) following the target."""
    out: list[str] = []
    idx = target_idx + 1
    while idx < len(lines):
        raw = lines[idx]
        if raw.startswith("\t"):
            out.append(raw)
            idx += 1
            continue
        # Continuation via trailing backslash on the previous line is fine,
        # but a new non-tab line means recipe is done.
        if raw.strip() == "":
            # Blank lines do not terminate a recipe in GNU make per se, but
            # in this repo's authoring style they do. Stop here.
            break
        break
    return "\n".join(out)


def _extract_knobs(body: str) -> list[str]:
    found: set[str] = set()
    for regex in (KNOB_PAREN_RE, KNOB_BRACE_RE, KNOB_INLINE_RE):
        for match in regex.findall(body):
            if match in KNOB_BLACKLIST:
                continue
            found.add(match)
    return sorted(found)


def parse_makefile(path: Path) -> list[dict[str, Any]]:
    """Return one record per top-level (non ``-test``) ``hackerman-*`` target.

    Each record is::

        {
          "target": "hackerman-corpus-stats",
          "purpose": "...",
          "test_target": "hackerman-corpus-stats-test" | None,
          "knobs": ["JSON", "TAGS_DIR", ...],
          "lineno": 1234,
        }
    """
    lines = _read_makefile(path)

    # First pass: collect every hackerman-* target's line number + recipe.
    raw: list[tuple[str, int]] = []
    for idx, raw_line in enumerate(lines):
        match = TARGET_RE.match(raw_line)
        if not match:
            continue
        raw.append((match.group(1), idx))

    # Dedup: a target may have multiple "definitions" (rare; treat first only).
    seen_targets: set[str] = set()
    target_to_line: dict[str, int] = {}
    for name, idx in raw:
        if name in seen_targets:
            continue
        seen_targets.add(name)
        target_to_line[name] = idx

    # Companion -test detection.
    test_companion: dict[str, str] = {}
    for name in seen_targets:
        if name.endswith("-test"):
            parent = name[: -len("-test")]
            if parent in seen_targets:
                test_companion[parent] = name

    # Build records for top-level targets only (skip "-test" companions).
    records: list[dict[str, Any]] = []
    for name in sorted(seen_targets):
        if name.endswith("-test"):
            continue
        idx = target_to_line[name]
        purpose = _leading_comment_block(lines, idx)
        body = _recipe_body(lines, idx)
        knobs = _extract_knobs(body)
        records.append({
            "target": name,
            "purpose": purpose,
            "test_target": test_companion.get(name),
            "knobs": knobs,
            "lineno": idx + 1,
        })
    return records


def render_human(records: list[dict[str, Any]], makefile_path: Path) -> str:
    """Plain-text index sorted by target name."""
    lines: list[str] = []
    lines.append("hackerman-* make target index")
    lines.append(f"  Makefile: {makefile_path}")
    lines.append(f"  Targets:  {len(records)}")
    lines.append("")
    for rec in records:
        lines.append(f"=== {rec['target']}  (Makefile:{rec['lineno']})")
        purpose = rec["purpose"] or "(no purpose comment)"
        # Indent multi-line purpose for readability.
        for pline in purpose.splitlines():
            lines.append(f"    {pline}".rstrip())
        if rec["test_target"]:
            lines.append(f"    test:  {rec['test_target']}")
        if rec["knobs"]:
            lines.append(f"    knobs: {', '.join(rec['knobs'])}")
        else:
            lines.append("    knobs: (none detected)")
        lines.append("")
    lines.append("Tip: `make <target>-test` runs the unit-test companion when listed.")
    return "\n".join(lines).rstrip() + "\n"


def render_json(records: list[dict[str, Any]], makefile_path: Path) -> str:
    envelope = {
        "schema": "auditooor.hackerman_help.v1",
        "makefile": str(makefile_path),
        "target_count": len(records),
        "targets": records,
    }
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--makefile",
        type=Path,
        default=DEFAULT_MAKEFILE,
        help="Path to the Makefile to scan (default: repo-root Makefile).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine envelope (auditooor.hackerman_help.v1).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write output to this path instead of stdout.",
    )
    args = parser.parse_args(argv)

    records = parse_makefile(args.makefile)
    if args.json:
        text = render_json(records, args.makefile)
    else:
        text = render_human(records, args.makefile)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
