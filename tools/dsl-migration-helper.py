#!/usr/bin/env python3
"""
dsl-migration-helper.py — batch-apply safe freshness-hardening transforms to
DSL pattern YAMLs.

Phases 19-22 hardened 35 patterns by hand. The subset below is deterministic
enough to mechanize (placeholders only — the human tightens them later):

    H1 fix  append `function.not_source_matches_regex: '(?i)mock|test|fixture'`
            to the `match:` block when missing. FP-guard placeholder.

    H2 fix  prepend `contract.source_matches_regex: '.*'` under `preconditions:`
            with a `# TODO: narrow to contract shape` comment when missing.

    H4 flag name regex containing `\\w+` or `.*` inside `function.name_matches`
            is reported only — NEVER auto-edited. Needs human judgment.

H3 (severity/confidence), H5 (predicate count) are intentionally out-of-scope.

Subcommands:
    --audit                list patterns that would receive H1 / H2 fixes
    --apply                apply safe auto-fixes to all candidates
    --apply --pattern NAME apply to a single pattern (basename, no .yaml)
    --apply --dry-run      preview planned edits without writing

Rules:
  * only touches reference/patterns.dsl/*.yaml
  * atomic writes (tempfile + os.replace)
  * prepends a header comment to each modified YAML:
      # Auto-migrated by tools/dsl-migration-helper.py <date>
  * re-runs `make freshness` after a non-dry --apply
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"

H1_LINE = "  - function.not_source_matches_regex: '(?i)mock|test|fixture'"
H2_PRE_KEY = "preconditions:"
H2_LINE_COMMENT = "  # TODO: narrow to contract shape (auto-migration placeholder)"
H2_LINE = "  - contract.source_matches_regex: '.*'"

HEADER_FMT = "# Auto-migrated by tools/dsl-migration-helper.py {date}\n"
NAME_REGEX_FLAG = re.compile(r"function\.name_matches[^\n]*(\\w\+|\.\*)")


class Diag(NamedTuple):
    path: Path
    needs_h1: bool
    needs_h2: bool
    flag_h4: bool


def scan(path: Path) -> Diag:
    text = path.read_text(encoding="utf-8", errors="replace")
    needs_h1 = "function.not_source_matches_regex" not in text
    needs_h2 = "contract.source_matches_regex" not in text
    flag_h4 = bool(NAME_REGEX_FLAG.search(text))
    return Diag(path, needs_h1, needs_h2, flag_h4)


def audit_all() -> list[Diag]:
    return [scan(p) for p in sorted(PATTERNS_DIR.glob("*.yaml"))]


def _inject_h2(text: str) -> str:
    """Add preconditions block or append to existing one."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    injected = False
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        if not injected and line.rstrip() == H2_PRE_KEY:
            # existing preconditions block — insert our line at the top of it
            out.append(H2_LINE_COMMENT + "\n")
            out.append(H2_LINE + "\n")
            injected = True
        i += 1

    if injected:
        return "".join(out)

    # No preconditions block exists — insert one before `match:` (or at top).
    new_lines: list[str] = []
    inserted = False
    for line in lines:
        if not inserted and line.rstrip() == "match:":
            new_lines.append(H2_PRE_KEY + "\n")
            new_lines.append(H2_LINE_COMMENT + "\n")
            new_lines.append(H2_LINE + "\n")
            new_lines.append("\n")
            inserted = True
        new_lines.append(line)
    if not inserted:
        # no match: block either — append at end
        new_lines.append("\n" + H2_PRE_KEY + "\n")
        new_lines.append(H2_LINE_COMMENT + "\n")
        new_lines.append(H2_LINE + "\n")
    return "".join(new_lines)


def _inject_h1(text: str) -> str:
    """Append function.not_source_matches_regex inside the match: block.

    We append after the last `- function.` or `- contract.` bullet that
    follows the `match:` line.
    """
    lines = text.splitlines(keepends=True)
    match_idx = None
    for i, line in enumerate(lines):
        if line.rstrip() == "match:":
            match_idx = i
            break
    if match_idx is None:
        return text + "\nmatch:\n" + H1_LINE + "\n"

    # Find the END of the last bullet inside match block. Bullets can have
    # nested-object continuation lines (more-indented YAML mappings), and we
    # MUST insert H1 after the ENTIRE bullet — not in the middle of its nested
    # object. Track the last line that is part of any bullet's value.
    last_bullet = match_idx
    last_bullet_end = match_idx  # end line (inclusive) of the last bullet
    bullet_indent = None
    for i in range(match_idx + 1, len(lines)):
        stripped = lines[i].lstrip()
        if lines[i].strip() == "":
            continue
        if stripped.startswith("- "):
            # new bullet
            last_bullet = i
            last_bullet_end = i
            # bullet_indent = leading whitespace count (spaces up to `-`)
            bullet_indent = len(lines[i]) - len(lines[i].lstrip())
        elif not lines[i].startswith(" "):
            # dedented back to a top-level key — end of block
            break
        else:
            # continuation line — check if it's more-indented than the bullet
            # (i.e., part of a nested object under `- key:`)
            indent = len(lines[i]) - len(lines[i].lstrip())
            if bullet_indent is not None and indent > bullet_indent:
                # still inside the current bullet's nested object
                last_bullet_end = i
            else:
                # same indent as bullet but not `- `; probably a trailing
                # scalar on the previous key — treat as part of last bullet
                last_bullet_end = i
    # Use last_bullet_end to avoid splitting nested objects.
    last_bullet = last_bullet_end
    out = lines[: last_bullet + 1] + [H1_LINE + "\n"] + lines[last_bullet + 1 :]
    return "".join(out)


def _add_header(text: str) -> str:
    header = HEADER_FMT.format(date=dt.date.today().isoformat())
    if text.startswith("# Auto-migrated"):
        # replace existing header line
        nl = text.find("\n")
        return header + text[nl + 1 :]
    return header + text


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def apply_fixes(diags: list[Diag], dry_run: bool) -> tuple[int, int]:
    h1_count = h2_count = 0
    for d in diags:
        if not (d.needs_h1 or d.needs_h2):
            continue
        text = d.path.read_text(encoding="utf-8", errors="replace")
        new_text = text
        if d.needs_h2:
            new_text = _inject_h2(new_text)
            h2_count += 1
        if d.needs_h1:
            new_text = _inject_h1(new_text)
            h1_count += 1
        new_text = _add_header(new_text)
        if dry_run:
            print(f"[dry-run] would migrate {d.path.name} "
                  f"(H1={d.needs_h1} H2={d.needs_h2})")
        else:
            _atomic_write(d.path, new_text)
            print(f"migrated  {d.path.name} (H1={d.needs_h1} H2={d.needs_h2})")
    return h1_count, h2_count


def cmd_audit() -> int:
    diags = audit_all()
    h1 = [d for d in diags if d.needs_h1]
    h2 = [d for d in diags if d.needs_h2]
    h4 = [d for d in diags if d.flag_h4]
    print(f"scanned {len(diags)} patterns in {PATTERNS_DIR.relative_to(ROOT)}")
    print(f"  H1 (missing FP-guard):       {len(h1)} patterns")
    print(f"  H2 (missing contract anchor):{len(h2)} patterns")
    print(f"  H4 (broad name regex, flag): {len(h4)} patterns (manual review)")
    if h4:
        print("\nH4 candidates (not auto-editable):")
        for d in h4[:15]:
            print(f"  - {d.path.name}")
        if len(h4) > 15:
            print(f"  ... and {len(h4) - 15} more")
    return 0


def cmd_apply(pattern: str | None, dry_run: bool) -> int:
    diags = audit_all()
    if pattern:
        diags = [d for d in diags if d.path.stem == pattern]
        if not diags:
            print(f"pattern not found: {pattern}", file=sys.stderr)
            return 2
    h1, h2 = apply_fixes(diags, dry_run)
    print(f"\nsummary: H1 fixes={h1}  H2 fixes={h2}  (dry-run={dry_run})")
    if not dry_run and (h1 or h2):
        print("\nre-running `make freshness`...")
        subprocess.run(["make", "freshness"], cwd=ROOT, check=False)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--pattern", help="single pattern basename (no .yaml)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.audit and args.apply:
        print("choose one of --audit or --apply", file=sys.stderr)
        return 2
    if args.audit:
        return cmd_audit()
    if args.apply:
        return cmd_apply(args.pattern, args.dry_run)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
