#!/usr/bin/env python3
"""Map a candidate idea against already-submitted workspace findings.

The goal is to stop PoC work before it re-discovers an already-filed Cantina
submission. The tool prefers the canonical workspace submission ledger, then
adds ready/staging drafts, status docs, notes, and local PoC/test files as
supporting corpus evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from submission_ledger import load_submission_entries_from_text
from submission_paths import find_submission_file


STOPWORDS = {
    "about",
    "after",
    "again",
    "against",
    "allows",
    "already",
    "also",
    "before",
    "being",
    "between",
    "caller",
    "contract",
    "contracts",
    "during",
    "every",
    "finding",
    "from",
    "have",
    "into",
    "itself",
    "lacks",
    "market",
    "markets",
    "missing",
    "only",
    "path",
    "permanently",
    "question",
    "questions",
    "same",
    "sent",
    "state",
    "that",
    "their",
    "there",
    "this",
    "through",
    "when",
    "where",
    "with",
    "without",
}

SKIP_SUFFIXES = (".bak", ".block.md", ".notes.md")
TEXT_SUFFIXES = {".md", ".sol", ".t.sol", ".txt"}
CORPUS_GLOBS = (
    "submissions/ready/**/*.md",
    "submissions/staging/**/*.md",
    "submissions/clean/**/*.md",
    "pocs/test/**/*.sol",
    "pocs/test/**/*.t.sol",
    "lib/*/src/test/**/*.sol",
    "lib/*/src/test/**/*.t.sol",
    "notes/**/*.md",
    "STATUS.md",
    "FINAL_REPORT.md",
)


@dataclass
class CorpusItem:
    kind: str
    title: str
    text: str
    source: str
    cantina_id: str = ""
    status: str = ""
    severity: str = ""


@dataclass
class Match:
    label: str
    score: float
    token_overlap: float
    phrase_hits: list[str]
    item: CorpusItem


def split_identifier(value: str) -> str:
    """Expose camel-case identifiers to the tokenizer without losing originals."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return f"{value} {spaced}"


def tokenize(text: str) -> set[str]:
    expanded = split_identifier(text)
    raw_tokens = re.findall(r"[A-Za-z0-9_]{2,}", expanded.lower())
    tokens = {tok for tok in raw_tokens if tok not in STOPWORDS and len(tok) > 2}
    tokens.update(tok for tok in raw_tokens if tok.isdigit())
    return tokens


def important_phrases(text: str) -> set[str]:
    phrases: set[str] = set()
    for phrase in re.findall(r"`([^`]{3,80})`", text):
        phrases.add(phrase.lower())
    for match in re.findall(r"\b[A-Z][A-Za-z0-9_]{2,}\.[A-Za-z_][A-Za-z0-9_]*\b", text):
        phrases.add(match.lower())
    for match in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\(|\))", text):
        phrases.add(match.strip("()").lower())
    return {p for p in phrases if len(p) >= 3}


def read_text(path: Path, limit: int = 180_000) -> str:
    try:
        return path.read_text(errors="ignore")[:limit]
    except OSError:
        return ""


def title_from_text(path: Path, text: str) -> str:
    for line in text.splitlines()[:40]:
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
    return path.stem.replace("_", " ").replace("-", " ")


def load_ledger_items(ws: Path) -> tuple[list[CorpusItem], str]:
    tracker = find_submission_file(ws)
    if not tracker:
        return [], "missing"
    text = read_text(tracker)
    items: list[CorpusItem] = []
    for entry in load_submission_entries_from_text(text):
        title = entry.get("title", "")
        body = entry.get("text", "") or title
        source = f"{tracker}#{entry.get('id', '')}".rstrip("#")
        items.append(
            CorpusItem(
                kind="submitted-ledger",
                title=title,
                text=f"{title}\n{body}",
                source=source,
                cantina_id=entry.get("id", ""),
                status=entry.get("status", ""),
                severity=entry.get("severity", ""),
            )
        )
    return items, str(tracker)


def iter_corpus_paths(ws: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    for pattern in CORPUS_GLOBS:
        for path in ws.glob(pattern):
            if path in seen or not path.is_file():
                continue
            if path.suffix not in TEXT_SUFFIXES and not path.name.endswith(".t.sol"):
                continue
            if any(path.name.endswith(suffix) for suffix in SKIP_SUFFIXES):
                continue
            seen.add(path)
            yield path


def load_artifact_items(ws: Path) -> list[CorpusItem]:
    items: list[CorpusItem] = []
    for path in iter_corpus_paths(ws):
        text = read_text(path)
        if not text.strip():
            continue
        rel = path.relative_to(ws)
        kind = "artifact"
        if str(rel).startswith("submissions/"):
            kind = "submission-artifact"
        elif str(rel).startswith("pocs/") or "/src/test/" in str(rel):
            kind = "poc-test"
        elif rel.name in {"STATUS.md", "FINAL_REPORT.md"}:
            kind = "status-doc"
        elif str(rel).startswith("notes/"):
            kind = "note"
        items.append(CorpusItem(kind=kind, title=title_from_text(path, text), text=text, source=str(path)))
    return items


def classify_item(item: CorpusItem, score: float, phrase_hits: list[str]) -> str:
    status = item.status.lower()
    text = f"{item.title}\n{item.text}".lower()
    submitted = item.kind == "submitted-ledger"
    known_low = item.severity.lower() in {"low", "info", "informational"} or " event-only " in f" {text} "
    known_negative = any(token in text for token in ("not submitted", "out of scope", " oos", "false positive", "cleared"))

    if submitted and (score >= 0.60 or len(phrase_hits) >= 2):
        return "already-submitted"
    if submitted and (score >= 0.40 or ("duplicate" in status and score >= 0.25)):
        return "dupe-risk"
    if known_negative and score >= 0.35:
        return "known-fp-or-oos"
    if known_low and score >= 0.45:
        return "known-low-or-info"
    if score >= 0.20 or phrase_hits:
        return "needs-human-novelty-review"
    return "fresh-or-weak-match"


def score_item(query: str, item: CorpusItem) -> Match:
    query_tokens = tokenize(query)
    item_tokens = tokenize(f"{item.title}\n{item.text}")
    overlap = query_tokens & item_tokens
    union = query_tokens | item_tokens
    token_overlap = len(overlap) / len(union) if union else 0.0

    query_phrases = important_phrases(query)
    item_text_lower = f"{item.title}\n{item.text}".lower()
    phrase_hits = sorted(p for p in query_phrases if p in item_text_lower)

    id_bonus = 0.0
    if item.cantina_id and re.search(rf"(?:#|\b){re.escape(item.cantina_id)}\b", query):
        id_bonus = 0.45

    phrase_bonus = min(0.35, 0.11 * len(phrase_hits))
    score = min(1.0, token_overlap + phrase_bonus + id_bonus)
    label = classify_item(item, score, phrase_hits)
    return Match(label=label, score=round(score, 4), token_overlap=round(token_overlap, 4), phrase_hits=phrase_hits, item=item)


def top_matches(query: str, items: list[CorpusItem], limit: int) -> list[Match]:
    matches = [score_item(query, item) for item in items]
    matches = [m for m in matches if m.score > 0 or m.phrase_hits]
    priority = {
        "already-submitted": 0,
        "dupe-risk": 1,
        "known-low-or-info": 2,
        "known-fp-or-oos": 3,
        "needs-human-novelty-review": 4,
        "fresh-or-weak-match": 5,
    }
    matches.sort(key=lambda m: (priority.get(m.label, 9), -m.score, m.item.kind, m.item.title))
    return matches[:limit]


def overall_label(matches: list[Match]) -> str:
    if not matches:
        return "fresh-or-weak-match"
    order = (
        "already-submitted",
        "dupe-risk",
        "known-low-or-info",
        "known-fp-or-oos",
        "needs-human-novelty-review",
        "fresh-or-weak-match",
    )
    labels = {m.label for m in matches[:5]}
    return next(label for label in order if label in labels)


def emit_markdown(ws: Path, ledger_source: str, items: list[CorpusItem], matches: list[Match], query: str) -> str:
    lines = [
        "# Submission Corpus Map",
        "",
        f"- Workspace: `{ws}`",
        f"- Ledger: `{ledger_source}`",
        f"- Corpus items: {len(items)}",
    ]
    if query:
        lines.extend(["", f"## Query", "", query, "", f"Overall label: **{overall_label(matches)}**", ""])
        if matches:
            lines.append("## Top Matches")
            lines.append("")
            for idx, match in enumerate(matches, 1):
                item = match.item
                cid = f"#{item.cantina_id} " if item.cantina_id else ""
                meta = " · ".join(part for part in (item.severity, item.status, item.kind) if part)
                lines.append(f"{idx}. **{match.label}** `{match.score:.2f}` — {cid}{item.title}")
                lines.append(f"   Source: `{item.source}`")
                if meta:
                    lines.append(f"   Meta: {meta}")
                if match.phrase_hits:
                    lines.append(f"   Phrase hits: {', '.join(match.phrase_hits[:6])}")
        else:
            lines.append("No meaningful submitted-corpus overlap found.")
    else:
        lines.extend(["", "## Submitted Ledger Items", ""])
        for item in items:
            if item.kind != "submitted-ledger":
                continue
            cid = f"#{item.cantina_id} " if item.cantina_id else ""
            meta = " · ".join(part for part in (item.severity, item.status) if part)
            lines.append(f"- {cid}{item.title} ({meta})")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Map a candidate idea against submitted findings, PoCs, and status docs before new PoC work."
    )
    parser.add_argument("workspace", help="Audit workspace directory")
    parser.add_argument("--query", help="Candidate title/idea/function path to check")
    parser.add_argument("--query-file", help="Read candidate text from a file")
    parser.add_argument("--top", type=int, default=8, help="Number of matches to show")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--out", help="Write Markdown or JSON output to a file")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[corpus-map] Workspace not found: {ws}", file=sys.stderr)
        sys.exit(1)

    query = args.query or ""
    if args.query_file:
        query = read_text(Path(args.query_file).expanduser().resolve())

    ledger_items, ledger_source = load_ledger_items(ws)
    items = ledger_items + load_artifact_items(ws)
    matches = top_matches(query, items, args.top) if query else []

    if args.json:
        output: str | dict[str, object] = {
            "workspace": str(ws),
            "ledger_source": ledger_source,
            "corpus_items": len(items),
            "submitted_ledger_items": len(ledger_items),
            "query": query,
            "overall_label": overall_label(matches),
            "matches": [asdict(match) for match in matches],
        }
        rendered = json.dumps(output, indent=2)
    else:
        rendered = emit_markdown(ws, ledger_source, items, matches, query)

    if args.out:
        Path(args.out).expanduser().resolve().write_text(rendered)
    else:
        print(rendered, end="")

    if query and matches and overall_label(matches) in {"already-submitted", "dupe-risk"}:
        sys.exit(2)
    if query and matches and overall_label(matches) != "fresh-or-weak-match":
        sys.exit(1)


if __name__ == "__main__":
    main()
