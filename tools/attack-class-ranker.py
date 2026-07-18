#!/usr/bin/env python3
"""Rank local attack-class hypotheses from detector and function context.

This is a bounded, stdlib-only prototype. It reads local corpus metadata from:

  - reference/patterns.dsl/*.yaml
  - defihacklabs/catalog.yaml, when present
  - bounded external analogue corpora under reference/ and .audit_logs/

The output is advisory JSON for hunt prioritization. It does not claim that a
target is exploitable or submit-ready.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
DEFAULT_DEFIHACK_CATALOG = REPO_ROOT / "defihacklabs" / "catalog.yaml"
DEFAULT_EXTERNAL_CORPUS_LIMIT = 120
EXTERNAL_CORPUS_PATHS: tuple[tuple[str, str], ...] = (
    ("rust", "reference/patterns.dsl.r94_solodit_rust"),
    ("contest", "reference/contest_cache"),
    ("case-study", "case_study"),
    ("go", "reference/findings_go_external_advisories.jsonl"),
    ("go", "reference/findings_go_existing_corpus.jsonl"),
    ("zkbugs", ".audit_logs/zkbugs_farming"),
    ("rust", ".audit_logs/rust_corpus_mining"),
)

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "do",
    "does",
    "for",
    "from",
    "has",
    "have",
    "in",
    "into",
    "is",
    "it",
    "its",
    "no",
    "not",
    "of",
    "on",
    "or",
    "sol",
    "solidity",
    "src",
    "that",
    "the",
    "this",
    "to",
    "token",
    "tokens",
    "uses",
    "via",
    "with",
    "without",
}

SEVERITY_WEIGHT = {
    "CRITICAL": 1.35,
    "HIGH": 1.2,
    "MEDIUM": 1.0,
    "LOW": 0.8,
    "INFO": 0.65,
    "INFORMATIONAL": 0.65,
}
CONFIDENCE_WEIGHT = {"HIGH": 1.15, "MEDIUM": 1.0, "LOW": 0.85}

ATTACK_CLASS_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("access-control-bypass", ("access", "auth", "authorization", "onlyowner", "owner", "role", "admin", "manager", "permission")),
    ("arbitrary-call", ("arbitrary", "target", "calldata", "delegatecall", "call", "adapter", "router")),
    ("bridge-message-validation", ("bridge", "cross", "chain", "ccip", "layerzero", "message", "settlement", "withdrawal", "mint")),
    ("flashloan-manipulation", ("flashloan", "flash", "callback", "initiator", "executeoperation", "uniswapv2call")),
    ("governance-bypass", ("governance", "governor", "proposal", "vote", "quorum", "timelock", "veto")),
    ("initialization-upgrade", ("initializer", "initialize", "proxy", "upgrade", "implementation", "disableinitializers")),
    ("liquidation-solvency", ("liquidation", "liquidate", "collateral", "debt", "solvency", "health", "borrow", "lending")),
    ("oracle-manipulation", ("oracle", "price", "chainlink", "twap", "spot", "slot0", "reserves", "getreserves", "latestrounddata")),
    ("precision-rounding-accounting", ("round", "rounding", "precision", "decimal", "share", "shares", "accounting", "donation", "inflation", "dust")),
    ("reentrancy", ("reentrancy", "reentrant", "callback", "onerc", "hook", "external", "post", "cei")),
    ("signature-replay", ("signature", "permit", "nonce", "replay", "ecrecover", "eip712", "erc1271")),
    ("slippage-mev", ("slippage", "amountoutmin", "deadline", "sandwich", "mev", "swap", "uniswap")),
    ("zk-proof-validation", ("zk", "proof", "merkle", "fiat", "shamir", "circuit", "constraint", "halo", "circom")),
)


@dataclass
class CorpusItem:
    source_kind: str
    source_ref: str
    item_id: str
    attack_class: str
    text: str
    pattern_id: str | None = None
    severity: str = ""
    corpus_confidence: str = ""
    detector_status: str = ""
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    out: list[str] = []
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def _top_scalar(text: str, key: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}:\s*(.+?)\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return ""
    value = _strip_comment(match.group(1))
    return _strip_quotes(value.strip())


def _top_list(text: str, key: str, *, max_items: int = 6) -> list[str]:
    """Parse a small top-level YAML-ish scalar/list field without a YAML dep."""
    lines = text.splitlines()
    key_re = re.compile(rf"^{re.escape(key)}:\s*(.*?)\s*$")
    for idx, raw in enumerate(lines):
        line = _strip_comment(raw.rstrip())
        match = key_re.match(line)
        if not match:
            continue
        inline = _strip_quotes(match.group(1).strip())
        if inline and inline not in {"|", ">", "|-", ">-"}:
            if inline.startswith("[") and inline.endswith("]"):
                return [
                    _strip_quotes(part.strip())
                    for part in inline[1:-1].split(",")
                    if part.strip()
                ][:max_items]
            return [inline][:max_items]

        out: list[str] = []
        for child in lines[idx + 1:]:
            child_line = _strip_comment(child.rstrip())
            if not child_line.strip():
                continue
            indent = len(child_line) - len(child_line.lstrip(" "))
            stripped = child_line.strip()
            if indent == 0 and re.match(r"^[A-Za-z0-9_]+:\s*", stripped):
                break
            if stripped.startswith("- "):
                out.append(_strip_quotes(stripped[2:].strip()))
            if len(out) >= max_items:
                break
        return out
    return []


def _yaml_text_surface(text: str) -> str:
    """Return a search surface from a YAML-ish document without full parsing."""
    parts: list[str] = []
    in_block = False
    block_indent = 0
    for raw in text.splitlines():
        line = _strip_comment(raw.rstrip())
        if not line.strip() or line.lstrip().startswith("---"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if in_block and indent > block_indent:
            parts.append(stripped)
            continue
        in_block = False
        if stripped.endswith(": >") or stripped.endswith(": |") or stripped.endswith(": >-") or stripped.endswith(": |-"):
            key = stripped.split(":", 1)[0]
            parts.append(key)
            in_block = True
            block_indent = indent
            continue
        if stripped.startswith("- "):
            parts.append(stripped[2:])
            continue
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            parts.append(key)
            if value.strip():
                parts.append(value.strip())
            continue
        parts.append(stripped)
    return " ".join(parts)


def _parse_defihack_catalog(text: str) -> list[dict[str, Any]]:
    """Parse the checked-in defihacklabs catalog YAML subset."""
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_rows = False
    list_key: str | None = None
    block_key: str | None = None
    block_lines: list[str] = []

    def flush_block() -> None:
        nonlocal block_key, block_lines
        if block_key and current is not None:
            current[block_key] = " ".join(line.strip() for line in block_lines if line.strip())
        block_key = None
        block_lines = []

    for raw in text.splitlines():
        line = _strip_comment(raw.rstrip())
        stripped = line.strip()
        if not stripped or stripped == "---":
            continue
        if stripped == "rows:":
            in_rows = True
            continue
        if not in_rows:
            continue

        if block_key is not None:
            indent = len(line) - len(line.lstrip(" "))
            if indent >= 6:
                block_lines.append(stripped)
                continue
            flush_block()

        if re.match(r"^\s*-\s+id:\s*", line):
            if current is not None:
                rows.append(current)
            current = {"id": _strip_quotes(line.split("id:", 1)[1].strip())}
            list_key = None
            continue

        if current is None:
            continue

        if list_key and re.match(r"^\s*-\s+", line):
            current.setdefault(list_key, []).append(_strip_quotes(re.sub(r"^\s*-\s+", "", line).strip()))
            continue

        match_block = re.match(r"^\s{4}([A-Za-z0-9_]+):\s*[>|]", line)
        if match_block:
            flush_block()
            block_key = match_block.group(1)
            block_lines = []
            list_key = None
            continue

        match_kv = re.match(r"^\s{4}([A-Za-z0-9_]+):\s*(.*)$", line)
        if match_kv:
            key = match_kv.group(1)
            value = match_kv.group(2).strip()
            if value:
                current[key] = _strip_quotes(value)
                list_key = None
            else:
                current[key] = []
                list_key = key

    flush_block()
    if current is not None:
        rows.append(current)
    return rows


def _split_camel(token: str) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", token)


def tokenize(text: str) -> set[str]:
    text = re.sub(r"(?i)amount\s*out\s*min|amountOutMin", " amountoutmin ", text)
    text = re.sub(r"(?i)get\s*reserves|getReserves", " getreserves ", text)
    text = re.sub(r"(?i)latest\s*round\s*data|latestRoundData", " latestrounddata ", text)
    normalized = _split_camel(text.replace("_", " ").replace("-", " "))
    raw = re.findall(r"[A-Za-z0-9]{3,}", normalized.lower())
    tokens = {tok for tok in raw if tok not in STOPWORDS}
    aliases: set[str] = set()
    for tok in tokens:
        if tok.endswith("ing") and len(tok) > 6:
            aliases.add(tok[:-3])
        if tok.endswith("ed") and len(tok) > 5:
            aliases.add(tok[:-2])
        if tok.endswith("s") and len(tok) > 4:
            aliases.add(tok[:-1])
    return tokens | aliases


def infer_attack_class(text: str, fallback: str) -> str:
    tokens = tokenize(text)
    best_class = ""
    best_score = 0
    for attack_class, hints in ATTACK_CLASS_HINTS:
        score = sum(1 for hint in hints if hint in tokens or hint in text.lower())
        if score > best_score:
            best_class = attack_class
            best_score = score
    return best_class or fallback


def load_patterns(patterns_dir: Path, repo_root: Path) -> list[CorpusItem]:
    if not patterns_dir.is_dir():
        return []
    items: list[CorpusItem] = []
    for path in sorted(patterns_dir.glob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        pattern_id = _top_scalar(text, "pattern") or path.stem
        severity = _top_scalar(text, "severity").upper()
        confidence = _top_scalar(text, "confidence").upper()
        source = _top_scalar(text, "source")
        surface = " ".join(
            part
            for part in (
                pattern_id,
                source,
                _top_scalar(text, "help"),
                _top_scalar(text, "wiki_title"),
                _top_scalar(text, "wiki_description"),
                _top_scalar(text, "wiki_exploit_scenario"),
                _top_scalar(text, "wiki_recommendation"),
                _yaml_text_surface(text),
            )
            if part
        )
        attack_class = infer_attack_class(surface, pattern_id)
        items.append(
            CorpusItem(
                source_kind="patterns.dsl",
                source_ref=_safe_evidence_ref(path, repo_root),
                item_id=pattern_id,
                pattern_id=pattern_id,
                attack_class=attack_class,
                text=surface,
                severity=severity,
                corpus_confidence=confidence,
                source=source,
            )
        )
    return items


def load_defihack(catalog_path: Path, repo_root: Path) -> list[CorpusItem]:
    if not catalog_path.is_file():
        return []
    try:
        rows = _parse_defihack_catalog(catalog_path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
    items: list[CorpusItem] = []
    for row in rows:
        row_id = str(row.get("id") or "defihack")
        attack_class = str(row.get("attack_class") or row_id)
        predicates = row.get("grep_predicates") or []
        if not isinstance(predicates, list):
            predicates = []
        surface = " ".join(
            str(part)
            for part in (
                row_id,
                attack_class,
                row.get("mechanism", ""),
                " ".join(str(p) for p in predicates),
                row.get("detector_status", ""),
                row.get("wave_candidate", ""),
                row.get("wave_ref", ""),
                row.get("notes", ""),
                row.get("example_poc", ""),
            )
            if part
        )
        items.append(
            CorpusItem(
                source_kind="defihacklabs",
                source_ref=f"{_safe_source_path(catalog_path, repo_root)}#{row_id}",
                item_id=row_id,
                attack_class=attack_class,
                text=surface,
                detector_status=str(row.get("detector_status") or ""),
                metadata={
                    "grep_predicates": predicates[:5],
                    "example_poc": row.get("example_poc", ""),
                    "dollar_lost": row.get("dollar_lost", ""),
                },
            )
        )
    return items


def _json_surface(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} {_json_surface(val)}" for key, val in value.items())
    if isinstance(value, list):
        return " ".join(_json_surface(item) for item in value)
    return str(value or "")


def _external_item_from_mapping(
    row: dict[str, Any],
    *,
    source_kind: str,
    source_ref: str,
    fallback_id: str,
) -> CorpusItem:
    item_id = str(
        row.get("finding_id")
        or row.get("id")
        or row.get("pattern")
        or row.get("pattern_id")
        or row.get("title")
        or fallback_id
    )
    title = str(row.get("title") or "")
    bug_class = str(row.get("bug_class") or row.get("attack_class") or row.get("category") or row.get("class") or "")
    severity = str(row.get("severity") or row.get("impact_tier") or "").upper()
    source = str(row.get("source") or row.get("protocol") or row.get("firm") or "")
    surface = " ".join(
        part
        for part in (
            item_id,
            title,
            bug_class,
            str(row.get("summary") or ""),
            str(row.get("real_world_example") or ""),
            str(row.get("suggested_remediation") or ""),
            _json_surface(row),
        )
        if part
    )
    attack_class = infer_attack_class(surface, bug_class or item_id)
    return CorpusItem(
        source_kind=source_kind,
        source_ref=source_ref,
        item_id=item_id,
        attack_class=attack_class,
        text=surface,
        severity=severity,
        source=source,
        metadata={
            "title": title,
            "bug_class": bug_class,
            "language": row.get("language", ""),
            "mechanism": row.get("mechanism", ""),
            "grep_predicates": (row.get("grep_predicates") or [])[:6] if isinstance(row.get("grep_predicates"), list) else [],
            "runtime_predicates": (row.get("runtime_predicates") or [])[:6] if isinstance(row.get("runtime_predicates"), list) else [],
        },
    )


def _load_external_json(path: Path, source_kind: str, repo_root: Path, limit: int) -> list[CorpusItem]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    rows: list[dict[str, Any]]
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        rows = [row for row in payload["findings"] if isinstance(row, dict)]
    elif isinstance(payload, dict):
        rows = [payload]
    elif isinstance(payload, list):
        rows = [row for row in payload if isinstance(row, dict)]
    else:
        rows = []
    out: list[CorpusItem] = []
    for idx, row in enumerate(rows[:limit], start=1):
        item_id = str(row.get("finding_id") or row.get("id") or row.get("title") or f"{path.stem}-{idx}")
        out.append(
            _external_item_from_mapping(
                row,
                source_kind=source_kind,
                source_ref=f"{_safe_evidence_ref(path, repo_root)}#{item_id}",
                fallback_id=f"{path.stem}-{idx}",
            )
        )
    return out


def _load_external_jsonl(path: Path, source_kind: str, repo_root: Path, limit: int) -> list[CorpusItem]:
    out: list[CorpusItem] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for idx, line in enumerate(lines, start=1):
        if len(out) >= limit:
            break
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        item_id = str(row.get("finding_id") or row.get("id") or f"{path.stem}-{idx}")
        out.append(
            _external_item_from_mapping(
                row,
                source_kind=source_kind,
                source_ref=f"{_safe_evidence_ref(path, repo_root)}#{item_id}",
                fallback_id=f"{path.stem}-{idx}",
            )
        )
    return out


def _load_external_yaml_or_md(path: Path, source_kind: str, repo_root: Path) -> CorpusItem | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    item_id = _top_scalar(text, "case_id") or _top_scalar(text, "id") or _top_scalar(text, "pattern") or path.stem
    title = _top_scalar(text, "title")
    bug_class = (
        _top_scalar(text, "bug_class")
        or _top_scalar(text, "attack_class")
        or _top_scalar(text, "category")
        or _top_scalar(text, "class")
    )
    severity = (_top_scalar(text, "severity") or _top_scalar(text, "severity_class")).upper()
    source = _top_scalar(text, "source")
    grep_predicates = _top_list(text, "grep_predicates")
    runtime_predicates = _top_list(text, "runtime_predicates")
    surface = " ".join(
        part
        for part in (
            item_id,
            title,
            bug_class,
            source,
            _top_scalar(text, "mechanism"),
            " ".join(grep_predicates),
            " ".join(runtime_predicates),
            _top_scalar(text, "extracted_lesson"),
            _top_scalar(text, "stop_criterion"),
            _top_scalar(text, "real_world_example"),
            _top_scalar(text, "summary"),
            _top_scalar(text, "suggested_remediation"),
            _yaml_text_surface(text),
        )
        if part
    )
    return CorpusItem(
        source_kind=source_kind,
        source_ref=_safe_evidence_ref(path, repo_root),
        item_id=item_id,
        attack_class=infer_attack_class(surface, bug_class or item_id),
        text=surface,
        severity=severity,
        source=source,
        metadata={
            "title": title,
            "bug_class": bug_class,
            "case_id": _top_scalar(text, "case_id"),
            "mechanism": _top_scalar(text, "mechanism"),
            "grep_predicates": grep_predicates,
            "runtime_predicates": runtime_predicates,
            "extracted_lesson": _top_scalar(text, "extracted_lesson"),
            "stop_criterion": _top_scalar(text, "stop_criterion"),
        },
    )


def load_external_corpus(repo_root: Path, *, max_items: int = DEFAULT_EXTERNAL_CORPUS_LIMIT) -> list[CorpusItem]:
    """Load bounded local analogue corpora for detector-to-hacker questions.

    This deliberately avoids large raw PDF/text corpora. It only reads curated
    JSON/JSONL/YAML/MD rows that already live in local reference/audit-log
    indexes, and returns advisory corpus items for ranking context.
    """
    if max_items <= 0:
        return []
    items: list[CorpusItem] = []
    for label, rel in EXTERNAL_CORPUS_PATHS:
        if len(items) >= max_items:
            break
        path = repo_root / rel
        source_kind = f"external_corpus:{label}"
        remaining = max_items - len(items)
        if path.is_file():
            if path.suffix == ".jsonl":
                items.extend(_load_external_jsonl(path, source_kind, repo_root, remaining))
            elif path.suffix == ".json":
                items.extend(_load_external_json(path, source_kind, repo_root, remaining))
            elif path.suffix in {".yaml", ".yml", ".md"}:
                item = _load_external_yaml_or_md(path, source_kind, repo_root)
                if item is not None:
                    items.append(item)
            continue
        if not path.is_dir():
            continue
        for ext in ("*.yaml", "*.yml", "*.json", "*.jsonl", "*.md"):
            for child in sorted(path.rglob(ext)):
                if len(items) >= max_items:
                    break
                if child.suffix == ".jsonl":
                    items.extend(_load_external_jsonl(child, source_kind, repo_root, max_items - len(items)))
                elif child.suffix == ".json":
                    items.extend(_load_external_json(child, source_kind, repo_root, max_items - len(items)))
                else:
                    item = _load_external_yaml_or_md(child, source_kind, repo_root)
                    if item is not None:
                        items.append(item)
            if len(items) >= max_items:
                break
    return items[:max_items]


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return ""


def _safe_source_path(path: Path, root: Path) -> str:
    rel = _safe_rel(path, root)
    return rel or "<external-input>"


def _safe_evidence_ref(path: Path, root: Path) -> str:
    rel = _safe_rel(path, root)
    if rel:
        return rel
    return "<external-input>"


def _query_text(args: argparse.Namespace) -> str:
    parts = [
        args.detector_slug or "",
        args.file_path or "",
        args.language or "",
        args.function_signature or "",
        args.function_name or "",
        args.context or "",
    ]
    return " ".join(part for part in parts if part)


def _score_item(item: CorpusItem, query_tokens: set[str], query_text: str) -> tuple[float, list[str]]:
    item_tokens = tokenize(item.text)
    overlap = sorted(query_tokens & item_tokens)
    if not overlap:
        return 0.0, []

    score = float(len(overlap))
    score += min(4.0, len(overlap) * 0.4)

    item_id_low = item.item_id.lower()
    detectorish = tokenize(item.item_id)
    if detectorish & query_tokens:
        score += 2.5
    if item.pattern_id and (item.pattern_id.lower() in query_text.lower() or item_id_low in query_text.lower()):
        score += 4.0

    attack_tokens = tokenize(item.attack_class)
    score += min(3.0, len(attack_tokens & query_tokens) * 1.25)

    score *= SEVERITY_WEIGHT.get(item.severity.upper(), 1.0)
    score *= CONFIDENCE_WEIGHT.get(item.corpus_confidence.upper(), 1.0)

    if item.source_kind == "defihacklabs":
        status = item.detector_status.lower()
        if status == "gap":
            score += 0.75
        elif status == "covered":
            score += 0.35

    return round(score, 4), overlap[:12]


def _confidence(score: float, evidence_count: int, source_kind_count: int) -> str:
    if score >= 12 and evidence_count >= 2 and source_kind_count >= 2:
        return "medium-high"
    if score >= 8 and evidence_count >= 2:
        return "medium"
    if score >= 4:
        return "low-medium"
    return "low"


def rank_attack_classes(
    *,
    query_text: str,
    items: list[CorpusItem],
    top_n: int,
) -> list[dict[str, Any]]:
    query_tokens = tokenize(query_text)
    grouped: dict[str, dict[str, Any]] = {}

    for item in items:
        score, matched_terms = _score_item(item, query_tokens, query_text)
        if score <= 0:
            continue
        bucket = grouped.setdefault(
            item.attack_class,
            {
                "attack_class": item.attack_class,
                "score": 0.0,
                "pattern_ids": [],
                "evidence_refs": [],
                "matched_terms": set(),
                "source_kinds": set(),
                "item_scores": [],
            },
        )
        bucket["item_scores"].append(score)
        if item.pattern_id and item.pattern_id not in bucket["pattern_ids"]:
            bucket["pattern_ids"].append(item.pattern_id)
        bucket["matched_terms"].update(matched_terms)
        bucket["source_kinds"].add(item.source_kind)
        evidence_ref: dict[str, Any] = {
            "source_kind": item.source_kind,
            "source_ref": item.source_ref,
            "item_id": item.item_id,
            "pattern_id": item.pattern_id,
            "matched_terms": matched_terms[:8],
            "score": score,
        }
        for meta_key in (
            "title",
            "bug_class",
            "mechanism",
            "grep_predicates",
            "runtime_predicates",
            "extracted_lesson",
            "stop_criterion",
        ):
            meta_value = item.metadata.get(meta_key)
            if meta_value:
                evidence_ref[meta_key] = meta_value
        bucket["evidence_refs"].append(evidence_ref)

    ranked: list[dict[str, Any]] = []
    for bucket in grouped.values():
        # r36-rebuttal: bugfix-inventory-claude-20260610
        all_evidence_refs = sorted(bucket["evidence_refs"], key=lambda row: (row.get("source_kind") == "patterns.dsl", -row["score"], row["source_ref"]))
        evidence_refs = all_evidence_refs[:5]
        top_scores = sorted(bucket["item_scores"], reverse=True)[:3]
        score = sum(top_scores)
        if len(bucket["source_kinds"]) > 1:
            score += 1.0
        score += math.log1p(max(0, len(bucket["evidence_refs"]) - len(top_scores))) * 0.25
        score = round(float(score), 4)
        top_pattern_ids = [
            ref["pattern_id"]
            for ref in evidence_refs
            if ref.get("pattern_id")
        ]
        analogue_refs = [
            ref
            for ref in all_evidence_refs
            if ref.get("source_kind") != "patterns.dsl"
        ][:5]
        ranked.append(
            {
                "rank": 0,
                "attack_class": bucket["attack_class"],
                "score": score,
                "confidence": _confidence(score, len(evidence_refs), len(bucket["source_kinds"])),
                "confidence_basis": "uncalibrated_corpus_similarity",
                "advisory_only": True,
                "claim_scope": "hypothesis_prioritization_only",
                "pattern_ids": top_pattern_ids[:8],
                "matched_terms": sorted(bucket["matched_terms"])[:16],
                "evidence_refs": evidence_refs,
                "analogue_refs": analogue_refs,
                "rationale": (
                    "Ranked by local corpus token overlap and corpus metadata; "
                    "manual source review and proof are still required."
                ),
            }
        )

    ranked.sort(key=lambda row: (-row["score"], row["attack_class"]))
    for idx, row in enumerate(ranked[:top_n], start=1):
        row["rank"] = idx
        row["score"] = round(row["score"], 4)
    return ranked[:top_n]


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = Path(args.repo_root).resolve()
    patterns_dir = Path(args.patterns_dir).resolve() if args.patterns_dir else repo_root / "reference" / "patterns.dsl"
    defihack_catalog = (
        Path(args.defihack_catalog).resolve()
        if args.defihack_catalog
        else repo_root / "defihacklabs" / "catalog.yaml"
    )

    query = _query_text(args)
    external_limit = max(0, int(args.external_corpus_limit or 0))
    items = (
        load_patterns(patterns_dir, repo_root)
        + load_defihack(defihack_catalog, repo_root)
        + load_external_corpus(repo_root, max_items=external_limit)
    )
    ranked = rank_attack_classes(query_text=query, items=items, top_n=max(1, args.top_n))

    source_counts: dict[str, int] = {}
    for item in items:
        source_counts[item.source_kind] = source_counts.get(item.source_kind, 0) + 1

    payload: dict[str, Any] = {
        "schema": "auditooor.attack_class_ranker.v1",
        "advisory_only": True,
        "claim_scope": "hypothesis_prioritization_only",
        "inputs": {
            "detector_slug": args.detector_slug or "",
            "file_path": args.file_path or "",
            "language": args.language or "",
            "function_signature": args.function_signature or "",
            "function_name": args.function_name or "",
            "context_present": bool(args.context),
        },
        "sources": {
            "patterns_dir": _safe_source_path(patterns_dir, repo_root),
            "defihack_catalog": _safe_source_path(defihack_catalog, repo_root),
            "external_corpus_limit": external_limit,
            "items_loaded": len(items),
            "source_counts": source_counts,
        },
        "ranked_attack_classes": ranked,
        "summary": {
            "ranked_count": len(ranked),
            "query_token_count": len(tokenize(query)),
            "score_model": "local_token_overlap_with_metadata_weights",
        },
        "limitations": [
            "Advisory ranking only; not an exploitability verdict.",
            "Evidence refs point to local corpus rows, not confirmed target findings.",
            "Confidence reflects corpus/context similarity, not proof strength.",
        ],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload["context_pack_hash"] = digest
    payload["context_pack_id"] = f"{payload['schema']}:attack_class_ranker:{digest[:16]}"
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="Repository root containing reference/ and defihacklabs/")
    parser.add_argument("--patterns-dir", default="", help="Override patterns DSL directory")
    parser.add_argument("--defihack-catalog", default="", help="Override defihacklabs catalog path")
    parser.add_argument(
        "--external-corpus-limit",
        type=int,
        default=DEFAULT_EXTERNAL_CORPUS_LIMIT,
        help="Max curated external analogue rows to load from local reference/.audit_logs indexes (0 disables)",
    )
    parser.add_argument("--detector-slug", default="", help="Detector slug or pattern name")
    parser.add_argument("--file-path", default="", help="Target file path or module path")
    parser.add_argument("--language", default="", help="Language hint, e.g. solidity/go/rust")
    parser.add_argument("--function-signature", default="", help="Function signature under review")
    parser.add_argument("--function-name", default="", help="Function name under review")
    parser.add_argument("--context", default="", help="Free-text detector/function/file context")
    parser.add_argument("--top-n", type=int, default=8, help="Maximum ranked hypotheses to emit")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    return parser


def run(argv: list[str] | None = None) -> dict[str, Any]:
    parser = build_parser()
    args = parser.parse_args(argv)
    return build_payload(args)


def main(argv: list[str] | None = None) -> int:
    payload = run(argv)
    indent = 2 if (argv and "--pretty" in argv) else None
    print(json.dumps(payload, indent=indent, sort_keys=bool(indent)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
