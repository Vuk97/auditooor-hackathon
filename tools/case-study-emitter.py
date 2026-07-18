#!/usr/bin/env python3
"""case-study-emitter.py — PR #658 Tier-B #12: emit L2 case-study notes from
engagement retrospectives.

Given a workspace path, read ``<workspace>/retrospective.json`` (preferred) or
fall back to ``<workspace>/RETROSPECTIVE.md``, then emit a structured note at::

    <vault>/case_study/<engagement>-r<round>.md

with frontmatter ``layer: L2`` and the lessons/anti-patterns body extracted
from the retrospective.

The vault is auto-resolved (same DEFAULT_VAULTS priority order as
``tools/vault-frame-extractor.py``):
  1. /Users/wolf/Documents/Codex/auditooor/obsidian-vault
  2. <repo>/obsidian-vault

CLI::

    tools/case-study-emitter.py --workspace ~/audits/<project>
    tools/case-study-emitter.py --workspace ~/audits/<project> --round 2
    tools/case-study-emitter.py --workspace ~/audits/<project> --vault-dir /path/to/vault
    tools/case-study-emitter.py --workspace ~/audits/<project> --dry-run
    tools/case-study-emitter.py --workspace ~/audits/<project> --force

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

DEFAULT_VAULTS = [
    Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault"),
    REPO / "obsidian-vault",
]

# ── helpers ──────────────────────────────────────────────────────────────────


def _resolve_vault(override: str | None = None) -> Path | None:
    if override:
        p = Path(override).expanduser().resolve()
        return p if p.is_dir() else None
    for v in DEFAULT_VAULTS:
        if v.is_dir():
            return v
    return None


def _slug_from_workspace(ws: Path) -> str:
    """Derive engagement slug from workspace basename, stripping common suffixes."""
    name = ws.name
    # strip trailing -main, -v2, -r<N>, etc.
    name = re.sub(r"[-_](main|v\d+|r\d+)$", "", name, flags=re.IGNORECASE)
    return name or ws.name


def _load_retro_json(ws: Path) -> dict[str, Any] | None:
    """Load retrospective.json if present, else return None."""
    p = ws / "retrospective.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _load_retro_md(ws: Path) -> str | None:
    """Load RETROSPECTIVE.md if present, else return None."""
    p = ws / "RETROSPECTIVE.md"
    if not p.exists():
        return None
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return None


# ── extraction helpers ────────────────────────────────────────────────────────


def _extract_lessons_from_json(data: dict[str, Any]) -> list[str]:
    """Pull lessons list from retrospective.json ``lessons`` array."""
    raw = data.get("lessons", [])
    lines: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            text = item.get("text") or item.get("body") or item.get("lesson") or ""
            tag = item.get("extraction_method", "")
            if text:
                advisory = " *(advisory; regex-fallback)*" if "regex" in tag else ""
                lines.append(f"- {text.strip()}{advisory}")
        elif isinstance(item, str) and item.strip():
            lines.append(f"- {item.strip()}")
    return lines


def _extract_lessons_from_md(md: str) -> list[str]:
    """Extract lessons section from RETROSPECTIVE.md."""
    section_re = re.compile(
        r"^##\s+(Lessons|Retrospective|What worked|What didn'?t|Anti-patterns?)\b",
        re.IGNORECASE | re.MULTILINE,
    )
    next_section_re = re.compile(r"^##\s+", re.MULTILINE)

    m = section_re.search(md)
    if not m:
        return []

    start = m.end()
    tail = md[start:]
    # cut at next ## heading
    nm = next_section_re.search(tail)
    body = tail[: nm.start()] if nm else tail

    lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith(("-", "*", "+")):
            lines.append(stripped)
        elif re.match(r"^\d+\.\s+", stripped):
            lines.append(f"- {stripped.split(maxsplit=1)[-1]}")
    return lines


def _get_metric_value(metric: Any) -> Any:
    """Unwrap a {value, provenance, ...} metric object or return raw."""
    if isinstance(metric, dict):
        return metric.get("value", "unknown")
    return metric


def _extract_counts(
    data: dict[str, Any] | None,
) -> tuple[int | str, int | str]:
    """Return (submissions_count, accepted_count) from JSON or 'unknown'."""
    if data is None:
        return "unknown", "unknown"
    metrics = data.get("metrics", {})
    sc = _get_metric_value(metrics.get("submissions_count", "unknown"))
    ac = _get_metric_value(metrics.get("accepted_count", "unknown"))
    return sc, ac


# ── frontmatter + body builders ───────────────────────────────────────────────


def _build_frontmatter(
    slug: str,
    round_n: int,
    workspace: Path,
    submissions_count: int | str,
    accepted_count: int | str,
) -> str:
    now = datetime.now(tz=timezone.utc).isoformat()
    lines = [
        "---",
        "layer: L2",
        f"engagement: {slug}",
        f"round: {round_n}",
        f"emitted_at: {now}",
        f"source_workspace: {workspace}",
        f"submissions_count: {submissions_count}",
        f"accepted_count: {accepted_count}",
        "---",
    ]
    return "\n".join(lines) + "\n"


def _build_body(
    slug: str,
    round_n: int,
    lessons: list[str],
    data: dict[str, Any] | None,
    md_source: str | None,
) -> str:
    """Build the markdown body for the case-study note."""
    parts: list[str] = []

    parts.append(f"# Case Study: {slug} (round {round_n})\n")

    if lessons:
        parts.append("## Lessons / Anti-patterns\n")
        parts.extend(lessons)
        parts.append("")
    else:
        parts.append(
            "_No structured lessons section found in retrospective. "
            "Populate `RETROSPECTIVE.md` with a `## Lessons` heading._\n"
        )

    # Optionally surface exit-criteria summary from JSON
    if data:
        exit_rows = data.get("exit_criteria", [])
        if exit_rows:
            passes = sum(1 for r in exit_rows if r.get("status") == "PASS")
            fails = sum(1 for r in exit_rows if r.get("status") == "FAIL")
            unknowns = sum(1 for r in exit_rows if r.get("status") == "UNKNOWN")
            parts.append(
                f"\n## Exit-Criteria Snapshot\n\n"
                f"PASS: {passes} | FAIL: {fails} | UNKNOWN: {unknowns}\n"
            )

    parts.append(
        "\n---\n_Emitted by `tools/case-study-emitter.py`. "
        "Do not hand-edit frontmatter — re-run emitter to refresh._\n"
    )
    return "\n".join(parts)


# ── main ──────────────────────────────────────────────────────────────────────


def emit(
    workspace: Path,
    vault_dir: Path,
    round_n: int,
    dry_run: bool,
    force: bool,
    require_retrospective: bool = False,
) -> int:
    """Core logic. Returns 0 on success / skip, 1 on error.

    A missing retrospective is a graceful advisory skip (rc=0) by default: the
    case-study note is an optional L2 learning artifact, so its absence must NOT
    abort an otherwise-successful ``audit-closeout`` (the common honest-0 case
    where no retrospective was hand-authored). Pass ``require_retrospective`` to
    restore the hard-fail (rc=1) for callers that genuinely require the note.
    """
    # ── load retrospective ────────────────────────────────────────────────────
    data = _load_retro_json(workspace)
    md_source = _load_retro_md(workspace)

    if data is None and md_source is None:
        if require_retrospective:
            print(
                f"[case-study-emitter] ERROR: neither retrospective.json nor "
                f"RETROSPECTIVE.md found in {workspace}",
                file=sys.stderr,
            )
            return 1
        print(
            f"[case-study-emitter] SKIP: no retrospective.json / RETROSPECTIVE.md "
            f"in {workspace}; case-study note is optional (advisory). "
            f"Pass --require-retrospective to make this a hard failure."
        )
        return 0

    # ── derive fields ─────────────────────────────────────────────────────────
    slug = _slug_from_workspace(workspace)
    submissions_count, accepted_count = _extract_counts(data)

    if data is not None:
        lessons = _extract_lessons_from_json(data)
    else:
        assert md_source is not None
        lessons = _extract_lessons_from_md(md_source)

    # ── destination path ──────────────────────────────────────────────────────
    dest_dir = vault_dir / "case_study"
    dest = dest_dir / f"{slug}-r{round_n}.md"

    print(f"[case-study-emitter] destination: {dest}")

    if dry_run:
        # Print frontmatter preview and exit
        fm = _build_frontmatter(slug, round_n, workspace, submissions_count, accepted_count)
        print(fm)
        print(f"[case-study-emitter] dry-run: not writing")
        return 0

    if dest.exists() and not force:
        print(
            f"[case-study-emitter] SKIP: {dest} already exists "
            f"(use --force to overwrite)"
        )
        return 0

    # ── write ─────────────────────────────────────────────────────────────────
    dest_dir.mkdir(parents=True, exist_ok=True)

    fm = _build_frontmatter(slug, round_n, workspace, submissions_count, accepted_count)
    body = _build_body(slug, round_n, lessons, data, md_source)
    content = fm + "\n" + body

    dest.write_text(content, encoding="utf-8")
    print(f"[case-study-emitter] wrote {dest} ({len(content)} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit L2 case-study note from engagement retrospective."
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="Workspace directory (e.g. ~/audits/spark)",
    )
    parser.add_argument(
        "--vault-dir",
        default=None,
        help="Override vault directory (default: auto-resolve)",
    )
    parser.add_argument(
        "--round",
        type=int,
        default=1,
        help="Engagement round number (default: 1)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print destination path + frontmatter preview, do not write",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing case-study note",
    )
    parser.add_argument(
        "--require-retrospective",
        action="store_true",
        help="Hard-fail (rc=1) when no retrospective.json / RETROSPECTIVE.md is "
        "present (default: graceful advisory skip so audit-closeout is not aborted)",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(
            f"[case-study-emitter] ERROR: workspace not found: {workspace}",
            file=sys.stderr,
        )
        return 2

    vault = _resolve_vault(args.vault_dir)
    if vault is None:
        print(
            "[case-study-emitter] ERROR: no vault directory found. "
            "Pass --vault-dir or ensure obsidian-vault exists.",
            file=sys.stderr,
        )
        return 2

    return emit(
        workspace=workspace,
        vault_dir=vault,
        round_n=args.round,
        dry_run=args.dry_run,
        force=args.force,
        require_retrospective=args.require_retrospective,
    )


if __name__ == "__main__":
    sys.exit(main())
