#!/usr/bin/env python3
"""memory-anti-pattern-emitter.py — PLAN-MEM Tier-1 Tool #3.

Reads every feedback_*.md from canonical sources and emits one structured
Obsidian note per foot-gun into obsidian-vault/anti-patterns/<id>.md.

Sources (read-only):
  - ~/.claude/projects/.../memory/feedback_*.md
  - ~/.claude/projects/.../memory/MEMORY.md        (index — used for validation timestamp)
  - docs/feedback_*.md                             (repo-checked feedback files)
  - docs/feedback_recurring_agent_mistakes_addendum.md  (ACT-15 additions)

Output layout:
  obsidian-vault/anti-patterns/
    INDEX.md
    <slug>.md      (one per foot-gun)

Frontmatter keys (Dataview-compatible):
  id, title, trigger_class, trigger, mitigation, sample_size,
  recommendation, last_validated_at, confidence, counter_examples,
  last_referenced_at, harness_check, discovered_in, source_file

Trigger classes:
  LLM-dispatch | PR-hygiene | severity-scoping | operating-contract |
  smoke-test | worktree-isolation | fixture-discipline | memory-architecture

Self-test (--self-test): asserts >=18 anti-pattern notes emitted.

Usage:
    python3 tools/memory-anti-pattern-emitter.py [--vault-dir <path>] [--dry-run] [--self-test]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
CLAUDE_MEMORY_DIR = (
    Path.home()
    / ".claude"
    / "projects"
    / "-Users-wolf-Downloads-GTO-WEBSITE-proper-installation-polymarket-clob2"
    / "memory"
)
DOCS_DIR = REPO_ROOT / "docs"

NOW_ISO = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
TODAY = _dt.date.today().isoformat()

# Vault byte cap (5 MB for this section)
BYTE_CAP = 5 * 1024 * 1024

# ---------------------------------------------------------------------------
# Trigger class classifier — keyword → class mapping
# ---------------------------------------------------------------------------
TRIGGER_CLASS_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"fixture|smoke.test|AUDITOOOR_FIXTURE|tier.registry|pattern.compil", re.I), "fixture-discipline"),
    (re.compile(r"worktree|parallel.agent|concurrent|stale.base|cherry.pick", re.I), "worktree-isolation"),
    (re.compile(r"severity|critical|medium|high|rubric|OOM|over.claim|snappy", re.I), "severity-scoping"),
    (re.compile(r"PR.hygiene|pr.*stale|merge.*base|deletion|phantom", re.I), "PR-hygiene"),
    (re.compile(r"operating.contract|commit|push|merge|read.only|AGENTS\.md|takeover", re.I), "operating-contract"),
    (re.compile(r"LLM|kimi|minimax|codex|hallucin|false.positive|n=1|single.sample", re.I), "LLM-dispatch"),
    (re.compile(r"scope|OOS|out.of.scope|fileab|path.*not.*exist|upstream.*equiv", re.I), "severity-scoping"),
    (re.compile(r"memory|vault|M14|recommendation|sample.size|anti.pattern", re.I), "memory-architecture"),
    (re.compile(r"smoke|smoke.test|rescan|long.*rescan|rerun|truncat", re.I), "smoke-test"),
]

def _classify_trigger(text: str) -> str:
    """Classify trigger class from text content."""
    for pat, cls in TRIGGER_CLASS_RULES:
        if pat.search(text):
            return cls
    return "LLM-dispatch"


# ---------------------------------------------------------------------------
# Harness check mapping — trigger class → tool wikilink
# ---------------------------------------------------------------------------
HARNESS_CHECKS: dict[str, str] = {
    "fixture-discipline": "[[tools-api/agent-preflight-check]]",
    "worktree-isolation": "[[tools-api/agent-worktree-dispatch]]",
    "severity-scoping": "[[tools-api/agent-preflight-check]]",
    "PR-hygiene": "[[tools-api/agent-preflight-check]]",
    "operating-contract": "[[tools-api/agent-preflight-check]]",
    "LLM-dispatch": "[[tools-api/agent-dispatch-prompt-lint]]",
    "smoke-test": "[[tools-api/anchor-detector-runner]]",
    "memory-architecture": "[[tools-api/memory-privacy-audit]]",
}


# ---------------------------------------------------------------------------
# Slug helpers
# ---------------------------------------------------------------------------
def _slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    return text[:80]


def _safe_write(path: Path, content: str, byte_counter: list[int]) -> bool:
    encoded = content.encode("utf-8")
    if byte_counter[0] + len(encoded) > BYTE_CAP:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    byte_counter[0] += len(encoded)
    return True


# ---------------------------------------------------------------------------
# Parser — extract individual foot-guns from a feedback file
# ---------------------------------------------------------------------------
def _extract_footguns(src_path: Path) -> list[dict[str, Any]]:
    """Parse a feedback_*.md and return list of footgun dicts."""
    text = src_path.read_text(encoding="utf-8", errors="replace")
    footguns: list[dict[str, Any]] = []

    # Strategy 1: Files with numbered sections like "## 1. Title" or "## Foot-gun #N"
    section_pat = re.compile(
        r"^##\s+(?:Foot-gun\s+#?(\d+)\s*[—–-]+\s*(.+?)|(\d+)\.\s+(.+?))$",
        re.MULTILINE,
    )
    matches = list(section_pat.finditer(text))

    if matches:
        for i, m in enumerate(matches):
            # Extract number and title from either capture group style
            num = m.group(1) or m.group(3)
            title = (m.group(2) or m.group(4) or "").strip()
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[start:end].strip()

            # Extract subfields
            trigger = _extract_field(body, r"(?:Trigger|Symptom|Problem)[:\s]+(.+?)(?=\n#|\n\n[A-Z]|$)", body[:200])
            mitigation = _extract_field(body, r"(?:Fix|Mitigation|Rule|Recovery)[:\s]+(.+?)(?=\n#|\n\n[A-Z]|$)", "")
            discovered = _extract_field(body, r"(?:Discovered|Source|Origin)[:\s]+(.+?)(?=\n|$)", "")

            footguns.append({
                "num": num,
                "title": title,
                "body": body,
                "trigger": trigger,
                "mitigation": mitigation,
                "discovered_in": discovered,
                "source_file": str(src_path),
            })
        return footguns

    # Strategy 2: YAML frontmatter + single-block doc (e.g. feedback_no_long_rescans.md)
    fm_match = re.match(r"^---\n(.*?)\n---\n(.+)", text, re.DOTALL)
    if fm_match:
        body = fm_match.group(2).strip()
        # Pull title from frontmatter name field or first heading
        name_m = re.search(r"^name:\s*(.+)$", fm_match.group(1), re.MULTILINE)
        h1_m = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
        title = (name_m.group(1) if name_m else None) or (h1_m.group(1) if h1_m else src_path.stem)
        trigger = _extract_field(body, r"(?:Trigger|Problem|Issue)[:\s]+(.+?)(?=\n#|\n\n|$)", body[:200])
        mitigation = _extract_field(body, r"(?:Fix|Rule|Mitigation)[:\s]+(.+?)(?=\n#|\n\n|$)", "")
        footguns.append({
            "num": "1",
            "title": title.strip(),
            "body": body,
            "trigger": trigger,
            "mitigation": mitigation,
            "discovered_in": "",
            "source_file": str(src_path),
        })
        return footguns

    # Strategy 3: Plain markdown — treat whole file as one footgun
    h1_m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = h1_m.group(1).strip() if h1_m else src_path.stem.replace("feedback_", "").replace("_", " ").title()
    footguns.append({
        "num": "1",
        "title": title,
        "body": text.strip(),
        "trigger": text[:300].strip(),
        "mitigation": "",
        "discovered_in": "",
        "source_file": str(src_path),
    })
    return footguns


def _extract_field(text: str, pattern: str, fallback: str) -> str:
    """Extract a field using regex, falling back to provided string."""
    m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if m:
        val = m.group(1).strip()
        # Truncate multi-line to first 2 lines
        lines = [l.strip() for l in val.splitlines() if l.strip()]
        return " ".join(lines[:2])[:500]
    return (fallback[:300] if fallback else "").strip()


# ---------------------------------------------------------------------------
# Note renderer
# ---------------------------------------------------------------------------
def _render_note(fg: dict[str, Any], slug: str, trigger_class: str) -> str:
    harness = HARNESS_CHECKS.get(trigger_class, "")
    title = fg["title"]
    trigger = fg["trigger"] or "See body"
    mitigation = fg["mitigation"] or "See body"
    discovered = fg["discovered_in"] or "unknown"
    src_stem = Path(fg["source_file"]).stem
    num = fg.get("num", "1")

    # Build frontmatter
    fm_lines = [
        "---",
        f'id: "{slug}"',
        f'title: "{title[:120].replace(chr(34), chr(39))}"',
        f"trigger_class: {trigger_class}",
        f'trigger: "{trigger[:200].replace(chr(34), chr(39))}"',
        f'mitigation: "{mitigation[:200].replace(chr(34), chr(39))}"',
        f"sample_size: 1",
        f"recommendation: true",
        f"last_validated_at: {TODAY}",
        f"confidence: medium",
        f"counter_examples: 0",
        f"last_referenced_at: {TODAY}",
        f'harness_check: "{harness}"',
        f'discovered_in: "{discovered}"',
        f'source_file: "{src_stem}"',
        f"emitted_at: {NOW_ISO}",
        "---",
    ]
    fm = "\n".join(fm_lines)

    # Body
    body_lines = [
        fm,
        "",
        f"# Anti-Pattern: {title}",
        "",
        "## Trigger",
        "",
        trigger,
        "",
        "## Mitigation",
        "",
        mitigation if mitigation != "See body" else "_See full text below._",
        "",
    ]

    if harness:
        body_lines += [
            "## Enforcement",
            "",
            f"Harness check: {harness}",
            "",
        ]

    body_lines += [
        "## Source",
        "",
        f"Extracted from `{src_stem}` (foot-gun #{num}).",
        "",
        "## Full Text",
        "",
        fg["body"][:3000],  # cap at 3KB
        "",
        "---",
        f"_Emitted by `memory-anti-pattern-emitter.py` at {NOW_ISO}_",
    ]

    return "\n".join(body_lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def collect_feedback_files() -> list[Path]:
    """Collect all feedback_*.md from canonical sources."""
    files: list[Path] = []

    # Source 1: ~/.claude/.../memory/feedback_*.md
    if CLAUDE_MEMORY_DIR.exists():
        files.extend(sorted(CLAUDE_MEMORY_DIR.glob("feedback_*.md")))

    # Source 2: docs/feedback_*.md
    if DOCS_DIR.exists():
        files.extend(sorted(DOCS_DIR.glob("feedback_*.md")))

    # Source 3: docs/feedback_recurring_agent_mistakes_addendum.md
    addendum = DOCS_DIR / "feedback_recurring_agent_mistakes_addendum.md"
    if addendum.exists() and addendum not in files:
        files.append(addendum)

    # Deduplicate by stem (prefer claude memory over docs if same stem)
    seen: dict[str, Path] = {}
    for f in files:
        stem = f.stem
        if stem not in seen:
            seen[stem] = f
        elif "memory" in str(f):
            seen[stem] = f  # claude memory takes priority

    return list(seen.values())


def run(vault_dir: Path, dry_run: bool, self_test: bool) -> int:
    out_dir = vault_dir / "anti-patterns"
    out_dir.mkdir(parents=True, exist_ok=True)

    files = collect_feedback_files()
    if not files:
        print("[anti-pattern-emitter] WARNING: no feedback_*.md files found", file=sys.stderr)

    byte_counter = [0]
    emitted: list[dict[str, Any]] = []
    skipped: list[str] = []
    used_slugs: set[str] = set()

    for src_path in files:
        try:
            footguns = _extract_footguns(src_path)
        except Exception as exc:
            print(f"[anti-pattern-emitter] SKIP {src_path.name}: {exc}", file=sys.stderr)
            skipped.append(src_path.name)
            continue

        for fg in footguns:
            title = fg["title"]
            num = fg.get("num", "1")
            base_slug = _slugify(f"{src_path.stem}-{num}-{title[:30]}")
            # Ensure uniqueness
            slug = base_slug
            suffix = 2
            while slug in used_slugs:
                slug = f"{base_slug}-{suffix}"
                suffix += 1
            used_slugs.add(slug)

            body_text = fg["body"] + " " + title
            trigger_class = _classify_trigger(body_text)
            content = _render_note(fg, slug, trigger_class)

            note_path = out_dir / f"{slug}.md"
            if dry_run:
                print(f"[DRY-RUN] would write {note_path.name} ({trigger_class})")
            else:
                ok = _safe_write(note_path, content, byte_counter)
                if not ok:
                    print(f"[anti-pattern-emitter] Byte cap hit — stopping after {len(emitted)} notes", file=sys.stderr)
                    break

            emitted.append({"slug": slug, "title": title, "trigger_class": trigger_class, "source": src_path.name})

    # Emit INDEX
    index_lines = [
        "---",
        "category: anti-patterns",
        f"note_count: {len(emitted)}",
        f"emitted_at: {NOW_ISO}",
        "---",
        "",
        "# Anti-Pattern Catalog",
        "",
        f"_{len(emitted)} foot-guns extracted from feedback files._",
        "",
        "| ID | Title | Trigger Class | Source |",
        "|----|-------|---------------|--------|",
    ]
    for e in sorted(emitted, key=lambda x: x["trigger_class"]):
        slug = e["slug"]
        title = e["title"][:60].replace("|", "\\|")
        cls = e["trigger_class"]
        src = e["source"]
        index_lines.append(f"| [[{slug}]] | {title} | {cls} | {src} |")

    index_lines += [
        "",
        "## By Trigger Class",
        "",
    ]
    by_class: dict[str, list[dict]] = {}
    for e in emitted:
        by_class.setdefault(e["trigger_class"], []).append(e)
    for cls in sorted(by_class):
        index_lines.append(f"### {cls} ({len(by_class[cls])})")
        index_lines.append("")
        for e in by_class[cls]:
            index_lines.append(f"- [[{e['slug']}]] — {e['title'][:80]}")
        index_lines.append("")

    index_lines += [
        "---",
        f"_Emitted by `memory-anti-pattern-emitter.py` at {NOW_ISO}_",
    ]
    index_content = "\n".join(index_lines)
    index_path = out_dir / "INDEX.md"
    if dry_run:
        print(f"[DRY-RUN] would write {index_path.name}")
    else:
        _safe_write(index_path, index_content, byte_counter)

    # Summary
    print(f"[anti-pattern-emitter] Emitted {len(emitted)} anti-pattern notes + INDEX")
    if skipped:
        print(f"[anti-pattern-emitter] Skipped {len(skipped)}: {', '.join(skipped)}")

    # Self-test
    if self_test:
        min_required = 18
        if len(emitted) < min_required:
            print(f"SELF-TEST FAIL: expected >={min_required} notes, got {len(emitted)}", file=sys.stderr)
            return 1
        print(f"SELF-TEST PASS: {len(emitted)} >= {min_required}")

    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vault-dir", default=str(VAULT_DEFAULT), help="Obsidian vault root")
    ap.add_argument("--dry-run", action="store_true", help="Print actions without writing")
    ap.add_argument("--self-test", action="store_true", help="Assert >=18 notes emitted")
    args = ap.parse_args()

    vault_dir = Path(args.vault_dir)
    sys.exit(run(vault_dir, args.dry_run, args.self_test))


if __name__ == "__main__":
    main()
