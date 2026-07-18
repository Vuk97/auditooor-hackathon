#!/usr/bin/env python3
"""verdict-seed-extractor — A2 + A8 of PR #675 (KLBQ-015).

Walks engagement-verdict / closeout / HOLD_NOTE markdowns indexed under
``tools/obsidian-vault-sync.py`` ``SECTION_SOURCES['engagement-verdicts']``
and extracts detector seeds.

A2 extracts seeds from these section markers:
  - ## Engineering Yield / ## Engineering yield
  - ## Detector seed / ## Detector Seeds
  - ## Recommendation / ## Recommended
  - ## Backlog flagged / ## Backlog
  - ## Future work

A8 adds three regex-based seed extractors (parity-precedent, but-for,
synthetic-driver) that run alongside the section-marker scan.

Output YAML stubs land under ``detectors/from_verdicts/`` for downstream
detector authors to lift into real DSL / regex / AST rules.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob as _glob
import re
import sys
from pathlib import Path
from typing import Iterable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
AUDITS_ROOT = Path.home() / "audits"

# Mirrors tools/obsidian-vault-sync.py SECTION_SOURCES['engagement-verdicts'].
DEFAULT_GLOBS: list[str] = [
    str(AUDITS_ROOT / "*/agent_outputs/**/*.md"),
    str(AUDITS_ROOT / "*/submissions/held/HOLD_NOTE_*.md"),
    str(AUDITS_ROOT / "*/mining_rounds/**/*.md"),
]

SECTION_MARKERS: list[tuple[str, str]] = [
    ("engineering-yield", r"^##\s+Engineering\s+[Yy]ield\s*$"),
    ("detector-seed", r"^##\s+Detector\s+[Ss]eeds?\s*$"),
    ("recommendation", r"^##\s+Recommend(?:ation|ed)\s*$"),
    ("backlog", r"^##\s+Backlog(?:\s+flagged)?\s*$"),
    ("future-work", r"^##\s+Future\s+work\s*$"),
]
SECTION_MARKER_RES = [(slug, re.compile(pat, re.MULTILINE)) for slug, pat in SECTION_MARKERS]
NEXT_SECTION_RE = re.compile(r"^##\s+", re.MULTILINE)

LANG_HINTS: list[tuple[str, str]] = [
    ("go", r"\.go\b"),
    ("rust", r"\.rs\b"),
    ("solidity", r"\.sol\b"),
    ("python", r"\.py\b"),
    ("sql", r"\.sql\b"),
]
LANG_HINT_RES = [(lang, re.compile(pat)) for lang, pat in LANG_HINTS]

CLASS_HINTS: list[tuple[str, str]] = [
    ("ast", r"\bAST\b|\bast\b"),
    ("regex", r"\bregex\b|\bRegex\b"),
    ("runtime", r"\bruntime\b|\bRuntime\b|\bdynamic\b|\bDynamic\b"),
    ("static", r"\bstatic\b|\bStatic\b"),
]
CLASS_HINT_RES = [(cls, re.compile(pat)) for cls, pat in CLASS_HINTS]

# A8 extractors.
PARITY_PRECEDENT_RE = re.compile(
    r"parity[- ]precedent|precedent:\s*cantina-\d+",
    re.IGNORECASE,
)
BUT_FOR_RE = re.compile(
    r"but[- ]for\s+(?:causal|causation|analysis)|"
    r"would\s+the\s+bug\s+cause\s+.{1,200}\bif\b",
    re.IGNORECASE | re.DOTALL,
)
SYNTHETIC_DRIVER_RE = re.compile(
    r"synthetic[- ](?:bankruptcy|driver)|seeded\s+portfolio|oracle[- ]drift\s+driver",
    re.IGNORECASE,
)

A8_EXTRACTORS: list[tuple[str, re.Pattern[str], str]] = [
    ("parity-precedent", PARITY_PRECEDENT_RE, "parity_precedent"),
    ("but-for", BUT_FOR_RE, "but_for"),
    ("synthetic-driver", SYNTHETIC_DRIVER_RE, "synthetic_driver"),
]
# (file_prefix is just the third element; no separate function needed.)


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slugify(text: str, max_len: int = 60) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    if len(text) > max_len:
        text = text[:max_len].rstrip("-")
    return text or "seed"


def _verdict_slug(path: Path) -> str:
    return _slugify(path.stem)


def _detect_language(body: str) -> str:
    for lang, rex in LANG_HINT_RES:
        if rex.search(body):
            return lang
    return "unknown"


def _detect_class(body: str) -> str:
    for cls, rex in CLASS_HINT_RES:
        if rex.search(body):
            return cls
    return "unknown"


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _summarize(body: str) -> str:
    """Extract a 1-sentence implementation_todo from the seed body."""
    # Prefer the first non-empty bullet or first sentence under 200 chars.
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("-", "*", "+")):
            cand = stripped.lstrip("-*+ ").strip()
            if 10 < len(cand) <= 200:
                return cand
    # Fallback: first sentence-ish chunk.
    chunk = body.strip().split("\n", 1)[0].strip()
    if not chunk:
        return ""
    # Cut at first period if reasonable.
    m = re.search(r"^(.{20,200}?[.!?])\s", chunk + " ")
    if m:
        return m.group(1).strip()
    return chunk[:200].strip()


def _extract_sections(text: str) -> list[tuple[str, str, str, int]]:
    """Return list of (section-slug, section-title, body, start-line)."""
    out: list[tuple[str, str, str, int]] = []
    for slug, rex in SECTION_MARKER_RES:
        for match in rex.finditer(text):
            start = match.end()
            # Find next ## heading after this.
            nxt = NEXT_SECTION_RE.search(text, start)
            end = nxt.start() if nxt else len(text)
            body = text[start:end].strip()
            title = match.group(0).strip().lstrip("# ").strip()
            line_no = _line_of_offset(text, match.start())
            out.append((slug, title, body, line_no))
    return out


def _resolve_globs(globs: Iterable[str]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for pattern in globs:
        for match in _glob.glob(pattern, recursive=True):
            p = Path(match)
            if not p.is_file():
                continue
            if p.suffix.lower() != ".md":
                continue
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            out.append(p)
    return sorted(out)


def _relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.home()))
    except ValueError:
        return str(path.resolve())


def emit_seed(
    *,
    out_dir: Path,
    verdict_path: Path,
    section_slug: str,
    section_title: str,
    body: str,
    line_no: int,
    dry_run: bool,
) -> Path:
    lang = _detect_language(body)
    cls = _detect_class(body)
    verdict_slug = _verdict_slug(verdict_path)
    section_slug_clean = _slugify(section_slug)
    fname = f"{verdict_slug}_{section_slug_clean}_seed.yaml"
    target_dir = out_dir / lang
    target = target_dir / fname

    payload = {
        "origin_verdict": _relpath(verdict_path),
        "section": section_title,
        "language_hint": lang,
        "detector_class_hint": cls,
        "triage_notes": body[:500],
        "implementation_todo": _summarize(body),
        "empirical_anchor": f"{_relpath(verdict_path)}:{line_no}",
        "extracted_at": _now_iso(),
    }
    if not dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return target


def emit_a8_seed(
    *,
    out_dir: Path,
    verdict_path: Path,
    extractor_id: str,
    file_prefix: str,
    excerpt: str,
    line_no: int,
    dry_run: bool,
) -> Path:
    verdict_slug = _verdict_slug(verdict_path)
    fname = f"{file_prefix}_{verdict_slug}.yaml"
    target = out_dir / fname
    payload = {
        "origin_verdict": _relpath(verdict_path),
        "section": f"<{extractor_id}-regex-hit>",
        "language_hint": _detect_language(excerpt),
        "detector_class_hint": "regex",
        "triage_notes": excerpt[:500],
        "implementation_todo": _summarize(excerpt),
        "empirical_anchor": f"{_relpath(verdict_path)}:{line_no}",
        "extracted_at": _now_iso(),
        "extractor_id": extractor_id,
    }
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return target


def run(
    *,
    globs: list[str],
    out_dir: Path,
    dry_run: bool,
) -> dict:
    verdict_files = _resolve_globs(globs)
    seeds_emitted = 0
    a8_counts: dict[str, int] = {name: 0 for name, _, _ in A8_EXTRACTORS}
    emitted_paths: list[Path] = []

    for verdict_path in verdict_files:
        try:
            text = verdict_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # A2 section-marker scan.
        for slug, title, body, line_no in _extract_sections(text):
            if not body:
                continue
            target = emit_seed(
                out_dir=out_dir,
                verdict_path=verdict_path,
                section_slug=slug,
                section_title=title,
                body=body,
                line_no=line_no,
                dry_run=dry_run,
            )
            emitted_paths.append(target)
            seeds_emitted += 1

        # A8 regex extractors.
        for name, rex, file_prefix in A8_EXTRACTORS:
            match = rex.search(text)
            if match is None:
                continue
            start = match.start()
            window_start = max(0, start - 120)
            window_end = min(len(text), match.end() + 200)
            excerpt = text[window_start:window_end].strip()
            line_no = _line_of_offset(text, start)
            target = emit_a8_seed(
                out_dir=out_dir,
                verdict_path=verdict_path,
                extractor_id=name,
                file_prefix=file_prefix,
                excerpt=excerpt,
                line_no=line_no,
                dry_run=dry_run,
            )
            emitted_paths.append(target)
            a8_counts[name] += 1
            seeds_emitted += 1

    return {
        "verdicts_scanned": len(verdict_files),
        "seeds_emitted": seeds_emitted,
        "parity_precedent": a8_counts["parity-precedent"],
        "but_for": a8_counts["but-for"],
        "synthetic_driver": a8_counts["synthetic-driver"],
        "emitted_paths": [str(p) for p in emitted_paths],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Optional workspace dir; if set, restrict glob walk to that workspace's agent_outputs/submissions/mining_rounds.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT / "detectors" / "from_verdicts",
        help="Where to write seed YAML stubs.",
    )
    parser.add_argument(
        "--glob",
        action="append",
        default=None,
        help="Override glob(s) (may be repeated).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary without writing files.",
    )
    args = parser.parse_args(argv)

    if args.glob:
        globs = list(args.glob)
    elif args.workspace:
        ws = args.workspace.resolve()
        globs = [
            str(ws / "agent_outputs/**/*.md"),
            str(ws / "submissions/held/HOLD_NOTE_*.md"),
            str(ws / "mining_rounds/**/*.md"),
        ]
    else:
        globs = list(DEFAULT_GLOBS)

    summary = run(globs=globs, out_dir=args.out_dir, dry_run=args.dry_run)

    print(
        f"verdicts_scanned={summary['verdicts_scanned']} "
        f"seeds_emitted={summary['seeds_emitted']} "
        f"parity_precedent={summary['parity_precedent']} "
        f"but_for={summary['but_for']} "
        f"synthetic_driver={summary['synthetic_driver']} "
        f"dry_run={args.dry_run} "
        f"out_dir={args.out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
