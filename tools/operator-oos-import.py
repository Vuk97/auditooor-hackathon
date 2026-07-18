#!/usr/bin/env python3
"""operator-oos-import.py — persist operator-pasted OOS text per workspace.

Wave-2 capability uplift (I24, closes #346). The operator pastes a project's
out-of-scope (OOS) list verbatim from Cantina/Code4rena/Immunefi. Today the
OOS check happens implicitly via heuristic ``scope-review-inline.sh``, which
can miss explicit clauses. This tool persists that pasted list as a
machine-readable artifact (``<workspace>/OOS_PASTED.md``) so a per-finding
checker (``per-finding-oos-check.py``) can iterate every clause × finding
before pre-submit-check Check #29 will flip green.

Why a separate file from ``OOS_CHECKLIST.md``?
----------------------------------------------
``OOS_CHECKLIST.md`` is hand-written by the operator, often before the bounty
page is fully read. ``OOS_PASTED.md`` is the *verbatim* paste from the bounty
program — it is the externally-authoritative list and should not be edited
once persisted. The two files coexist; pre-submit gates both.

Usage
-----
    # paste from stdin
    pbpaste | python3 tools/operator-oos-import.py --workspace ~/audits/foo

    # or read from file
    python3 tools/operator-oos-import.py --workspace ~/audits/foo \\
        --from-file ./oos_pasted.txt

    # source URL is recorded in frontmatter
    python3 tools/operator-oos-import.py --workspace ~/audits/foo \\
        --source-url https://cantina.xyz/competitions/foo \\
        --from-file ./oos.txt

    # legacy positional form (for tests and ergonomic shell use)
    python3 tools/operator-oos-import.py ~/audits/foo < paste.txt

Idempotency
-----------
- Re-running with byte-identical clause text is a no-op (returns rc=0,
  prints ``[operator-oos-import] no-op (content unchanged)``).
- Re-running with new clause text rotates the prior file to
  ``OOS_PASTED.<UTC-iso-stamp>.md`` and writes fresh.
- Source URL / date / project alone do NOT trigger rotation; the parsed
  clause text is the rotation trigger.

Clause parsing
--------------
Bullet lines that start with ``-``/``*``/``+`` (with optional checkbox)
become one clause. Numbered lines (``1.`` / ``1)`` / ``(1)``) likewise.
Indented continuation lines append to the prior clause. All other lines are
discarded (headers, blank lines, narrative). Each clause gets a stable id
``C1, C2, ...`` in input order.

Output format
-------------
The output file is operator-friendly Markdown. Embedded in it is a fenced
JSON manifest block (``<!-- OOS_PASTED_MANIFEST_BEGIN``/``OOS_PASTED_MANIFEST_END -->``)
that ``per-finding-oos-check.py`` reads. Only the JSON manifest is treated
as authoritative.

The body also lists clauses as ``- **C1**: ...`` and ``- OOS-1: ...`` so
the legacy ``CLAUSE_RE`` in older ``per-finding-oos-check.py`` versions and
``scope-review-inline.sh``'s ``OOS-N`` regex both keep working.

Exit codes
----------
    0 — wrote the file (or no-op on identical content)
    1 — workspace missing or not a directory
    2 — usage / argument error
    3 — empty / unparseable input (no clauses recognized)

The script is stdlib-only; no third-party deps.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.oos_pasted.v1"
MANIFEST_FENCE_OPEN = "<!-- OOS_PASTED_MANIFEST_BEGIN"
MANIFEST_FENCE_CLOSE = "OOS_PASTED_MANIFEST_END -->"


_BULLET_RE = re.compile(r"^\s*[-*+]\s+(?:\[[ xX]\]\s*)?(.*)$")
_NUMBERED_RE = re.compile(r"^\s*(?:\(?\d+[.)])\s+(.*)$")
_CONTINUATION_RE = re.compile(r"^\s{2,}(\S.*)$")


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_filestamp() -> str:
    # Filename-safe: no colons.
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_clauses(raw: str) -> list[dict[str, str]]:
    """Convert pasted OOS text into a list of ``{"id": "C1", "text": "..."}``.

    Accepts ``-``/``*``/``+`` bullets and ``1.``/``1)``/``(1)`` numbered
    lists. Indented continuation lines are appended (joined with a single
    space) to the previous clause. Markdown ``**Label:**`` prefixes are
    preserved as part of the clause text.
    """
    clauses: list[str] = []
    current: list[str] | None = None

    def _flush() -> None:
        nonlocal current
        if current is not None:
            joined = " ".join(current).strip()
            if joined:
                clauses.append(joined)
            current = None

    for raw_line in raw.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            _flush()
            continue

        m_bullet = _BULLET_RE.match(line)
        m_number = _NUMBERED_RE.match(line)
        m_cont = _CONTINUATION_RE.match(line)

        if m_bullet or m_number:
            _flush()
            body = (m_bullet or m_number).group(1).strip()
            if body:
                current = [body]
            continue

        if m_cont and current is not None:
            cont = m_cont.group(1).strip()
            if cont:
                current.append(cont)
            continue

        # Plain non-bullet, non-continuation line ends the current clause.
        _flush()

    _flush()

    out: list[dict[str, str]] = []
    for i, text in enumerate(clauses, start=1):
        text = text.strip()
        if not text:
            continue
        out.append({"id": f"C{i}", "text": text})
    return out


def _hash_clauses(clauses: list[dict[str, str]]) -> str:
    payload = "\n".join(f"{c['id']}\t{c['text']}" for c in clauses)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_existing_manifest(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if MANIFEST_FENCE_OPEN not in text or MANIFEST_FENCE_CLOSE not in text:
        return None
    try:
        block = text.split(MANIFEST_FENCE_OPEN, 1)[1].split(
            MANIFEST_FENCE_CLOSE, 1
        )[0]
    except IndexError:
        return None
    block = block.strip()
    try:
        return json.loads(block)
    except json.JSONDecodeError:
        return None


def render_oos_pasted(
    *,
    clauses: list[dict[str, str]],
    source_url: str,
    project: str,
    note: str,
    raw_text: str,
) -> str:
    manifest: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "date": _utc_now_iso(),
        "source_url": source_url,
        "project": project,
        "note": note,
        "clauses_hash": _hash_clauses(clauses),
        "clauses": clauses,
    }
    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)

    lines: list[str] = []
    lines.append("# Operator-Pasted OOS")
    lines.append("")
    lines.append(
        "This file is the canonical persisted copy of out-of-scope text the "
        "operator pasted during an engagement. If it exists, every filing "
        "candidate must have a per-finding OOS check artifact before "
        "`pre-submit-check.sh` Check #29 can pass."
    )
    lines.append("")
    lines.append(f"- **Captured (UTC):** {manifest['date']}")
    lines.append(
        f"- **Project:** {project or 'unspecified'}"
    )
    lines.append(
        f"- **Source URL:** {source_url or 'operator-paste'}"
    )
    if note:
        lines.append(f"- **Operator note:** {note}")
    lines.append(f"- **Clauses:** {len(clauses)}")
    lines.append(f"- **Schema:** `{SCHEMA_VERSION}`")
    lines.append("")
    lines.append("## Clauses")
    lines.append("")
    if not clauses:
        lines.append("_(no clauses parsed — see raw paste below)_")
    else:
        for c in clauses:
            # Emit BOTH a Cn id and an OOS-N legacy id so older readers
            # (scope-review-inline.sh, the v0 per-finding-oos-check) keep
            # matching. The Cn id is authoritative; OOS-N mirrors it.
            n = c["id"][1:]
            lines.append(f"- **{c['id']}** / OOS-{n}: {c['text']}")
    lines.append("")
    lines.append("## Manifest (machine-readable)")
    lines.append("")
    lines.append(MANIFEST_FENCE_OPEN)
    lines.append(manifest_json)
    lines.append(MANIFEST_FENCE_CLOSE)
    lines.append("")
    lines.append("## Raw paste")
    lines.append("")
    lines.append("```text")
    lines.append(raw_text.rstrip())
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="operator-oos-import.py",
        description=(
            "Persist operator-pasted OOS text as <workspace>/OOS_PASTED.md."
        ),
    )
    # Both --workspace and a positional are accepted. Positional matches the
    # legacy test contract; the flag matches the issue spec.
    parser.add_argument(
        "workspace_pos",
        nargs="?",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--workspace",
        dest="workspace",
        default=None,
        help="Workspace root (must already exist). Required.",
    )
    src_group = parser.add_mutually_exclusive_group()
    src_group.add_argument(
        "--from-file",
        dest="from_file",
        help="Read OOS text from this file. If omitted, read from stdin.",
    )
    src_group.add_argument(
        "--file",
        dest="from_file_legacy",
        help=argparse.SUPPRESS,  # legacy alias kept for back-compat
    )
    parser.add_argument(
        "--source-url",
        default="",
        help="Bounty/contest URL where this OOS list was copied from.",
    )
    parser.add_argument(
        "--project",
        default="",
        help="Project / program name recorded in frontmatter.",
    )
    parser.add_argument(
        "--note",
        default="",
        help="Optional operator note recorded in frontmatter.",
    )
    parser.add_argument(
        "--print-path",
        action="store_true",
        help="Print the absolute path to the persisted file on stdout.",
    )

    args = parser.parse_args(argv)

    workspace = args.workspace or args.workspace_pos
    if not workspace:
        _eprint(
            "[operator-oos-import] missing workspace (--workspace <ws> or "
            "positional)"
        )
        return 2

    ws_path = Path(workspace).expanduser()
    # Spec: "missing-workspace fails."
    if not ws_path.exists() or not ws_path.is_dir():
        _eprint(f"[operator-oos-import] workspace not found: {ws_path}")
        return 1

    src_file = args.from_file or args.from_file_legacy
    if src_file:
        src = Path(src_file).expanduser()
        if not src.is_file():
            _eprint(f"[operator-oos-import] --from-file not found: {src}")
            return 2
        try:
            raw = src.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            _eprint(f"[operator-oos-import] cannot read {src}: {e}")
            return 2
    else:
        raw = sys.stdin.read()

    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    if not raw.strip():
        _eprint("[operator-oos-import] empty input — nothing to persist")
        return 3

    clauses = parse_clauses(raw)
    if not clauses:
        _eprint(
            "[operator-oos-import] no clauses recognized "
            "(expected `- ` bullets or `1.` numbered lines)"
        )
        return 3

    out_path = ws_path / "OOS_PASTED.md"
    new_hash = _hash_clauses(clauses)
    existing = _read_existing_manifest(out_path)
    if existing and existing.get("clauses_hash") == new_hash:
        if args.print_path:
            print(str(out_path))
        print(
            "[operator-oos-import] no-op (content unchanged) → "
            f"{out_path}"
        )
        return 0

    if existing is not None:
        # Rotate before writing fresh content.
        ts = _utc_filestamp()
        rotated = ws_path / f"OOS_PASTED.{ts}.md"
        suffix_idx = 1
        while rotated.exists():
            rotated = ws_path / f"OOS_PASTED.{ts}.{suffix_idx}.md"
            suffix_idx += 1
        try:
            os.replace(out_path, rotated)
        except OSError as e:
            _eprint(f"[operator-oos-import] cannot rotate prior file: {e}")
            return 1
        _eprint(f"[operator-oos-import] rotated prior → {rotated.name}")

    rendered = render_oos_pasted(
        clauses=clauses,
        source_url=args.source_url,
        project=args.project,
        note=args.note,
        raw_text=raw,
    )

    try:
        out_path.write_text(rendered, encoding="utf-8")
    except OSError as e:
        _eprint(f"[operator-oos-import] cannot write {out_path}: {e}")
        return 1

    if args.print_path:
        print(str(out_path))
    print(
        f"[operator-oos-import] wrote {len(clauses)} clauses → {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
