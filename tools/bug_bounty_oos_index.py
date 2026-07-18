#!/usr/bin/env python3
"""Parse BUG_BOUNTY.md OOS catalogs and match live-target candidates.

The index is intentionally heuristic and conservative. It is not a filing
verdict. It marks candidates that need an extension-distinct argument before
they consume HIGH-PRIORITY-HUNT drill budget.
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
from typing import Any, Iterable


SCHEMA = "auditooor.bug_bounty_oos_index.v1"
DEFAULT_INDEX_REL = Path(".auditooor") / "bug_bounty_oos_index.json"
HIGH_CONFIDENCE_THRESHOLD = 0.7

SECTION_OUT_OF_SCOPE = "out_of_scope"
SECTION_AI_FP = "ai_false_positive"
SECTION_KNOWN = "known_issue"
SECTION_TRUST = "trust_assumption"

SECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (SECTION_OUT_OF_SCOPE, re.compile(r"\bout[- ]?of[- ]?scope\b|\boos\b", re.I)),
    (SECTION_AI_FP, re.compile(r"\bAI[- ]?(?:Tool\s+)?False[- ]Positive\b|\bAI[- ]FP\b", re.I)),
    (SECTION_KNOWN, re.compile(r"\bKnown Issues?\b|\bAcknowledged Design Decisions?\b", re.I)),
    (SECTION_TRUST, re.compile(r"\bTrust Assumptions?\b", re.I)),
)

GENERIC_TAGS = {
    "ai-fp",
    "known-issue",
    "out-of-scope",
    "trust-assumption",
}

TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)+\|?\s*$")
HEADING_RE = re.compile(r"^(?P<marks>#{1,6})\s+(?P<title>.+?)\s*#*\s*$")
BULLET_RE = re.compile(r"^\s*[-*+]\s+(?:\[[ xX]\]\s*)?(?P<body>.+?)\s*$")
NUMBERED_RE = re.compile(r"^\s*(?:\(?\d+[.)])\s+(?P<body>.+?)\s*$")
KNOWN_ID_RE = re.compile(r"\b(?:SE-P|SUA|SSA|SA2|SRL|AI-FP|OOS|HP|C|R)\s*-?\s*[A-Za-z0-9_.-]+\b", re.I)


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_text(text: str) -> str:
    text = str(text or "")
    text = text.replace("\u2014", "-").replace("\u2013", "-")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("`", "").replace("**", "").replace("__", "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _slug(text: str) -> str:
    raw = _normalize_text(text).lower()
    raw = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return raw[:80] or "row"


def _section_for_heading(title: str) -> str | None:
    clean = _normalize_text(title)
    for section, pattern in SECTION_PATTERNS:
        if pattern.search(clean):
            return section
    return None


def discover_bug_bounty_files(workspace: Path) -> list[Path]:
    """Return BUG_BOUNTY.md paths in root and src/*, with env overrides."""
    workspace = workspace.resolve()
    env_value = os.environ.get("AUDITOOOR_BUG_BOUNTY_MD_PATHS", "").strip()
    paths: list[Path] = []
    if env_value:
        parts = re.split(r"[\n,:]", env_value)
        for part in parts:
            raw = part.strip()
            if not raw:
                continue
            candidate = Path(raw)
            if not candidate.is_absolute():
                candidate = workspace / candidate
            if candidate.is_file():
                paths.append(candidate.resolve())
    default_candidates: list[Path] = [workspace / "BUG_BOUNTY.md"]
    src = workspace / "src"
    if src.is_dir():
        default_candidates.extend(sorted(src.glob("*/BUG_BOUNTY.md")))
    seen: set[Path] = set()
    for candidate in default_candidates:
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        paths.append(resolved)
    out: list[Path] = []
    seen.clear()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def _table_cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or "|" not in stripped[1:]:
        return None
    if TABLE_SEPARATOR_RE.match(stripped):
        return []
    cells = [_normalize_text(cell) for cell in stripped.strip("|").split("|")]
    cells = [cell for cell in cells if cell]
    if not cells:
        return []
    header_tokens = {"row", "id", "#", "pattern", "description", "issue", "status"}
    if all(cell.lower() in header_tokens for cell in cells[: min(len(cells), 3)]):
        return []
    if cells[0].lower() in {"row", "id", "#", "number"}:
        return []
    return cells


def _clause_id(section: str, cells_or_text: list[str] | str, line_no: int) -> str:
    if isinstance(cells_or_text, list):
        first = cells_or_text[0] if cells_or_text else ""
        known = KNOWN_ID_RE.search(first)
        if known:
            return re.sub(r"\s+", "", known.group(0)).upper()
        if section == SECTION_AI_FP and re.fullmatch(r"\d+", first):
            return f"AI-FP-row-{first}"
        if section == SECTION_OUT_OF_SCOPE and re.fullmatch(r"\d+", first):
            return f"OOS-row-{first}"
        if section == SECTION_KNOWN and first:
            known_any = KNOWN_ID_RE.search(" ".join(cells_or_text))
            if known_any:
                return re.sub(r"\s+", "", known_any.group(0)).upper()
    else:
        known = KNOWN_ID_RE.search(cells_or_text)
        if known:
            return re.sub(r"\s+", "", known.group(0)).upper()
    prefix = {
        SECTION_OUT_OF_SCOPE: "OOS",
        SECTION_AI_FP: "AI-FP",
        SECTION_KNOWN: "KNOWN",
        SECTION_TRUST: "TRUST",
    }.get(section, "BUG-BOUNTY")
    return f"{prefix}-L{line_no}"


def _phrase_from_cells(section: str, cells: list[str]) -> str:
    if not cells:
        return ""
    drop_first = False
    first = cells[0]
    if re.fullmatch(r"\d+", first):
        drop_first = True
    if KNOWN_ID_RE.fullmatch(first):
        drop_first = True
    phrase_cells = cells[1:] if drop_first and len(cells) > 1 else cells
    return _normalize_text(" | ".join(phrase_cells))


def semantic_tags_for_text(text: str, *, section: str | None = None) -> list[str]:
    low = _normalize_text(text).lower()
    tags: set[str] = set()
    if section == SECTION_OUT_OF_SCOPE:
        tags.add("out-of-scope")
    elif section == SECTION_AI_FP:
        tags.add("ai-fp")
    elif section == SECTION_KNOWN:
        tags.add("known-issue")
    elif section == SECTION_TRUST:
        tags.add("trust-assumption")

    if re.search(r"\b(front[- ]?running|frontrunning|sandwich|mev)\b", low):
        tags.add("front-running")
    if "public mempool" in low:
        tags.add("public-mempool")
    if {"front-running", "public-mempool"} <= tags or (
        "sandwich" in low and "mempool" in low
    ):
        tags.add("front-running-public-mempool")
    if re.search(r"\b(slippage|minout|min[-_ ]?out|no[-_ ]?slippage)\b", low):
        tags.add("slippage")
    if re.search(r"\b(request|claim|cooldown|redeem|withdraw)\b", low) and re.search(
        r"\b(two[- ]step|2[- ]step|async)\b", low
    ):
        tags.add("two-step-request-claim")
    if re.search(r"\bfee[- ]?on[- ]?transfer\b|\btransfer fee\b|\bfee[-_]?on[-_]?transfer\b", low):
        tags.add("fee-on-transfer")
    if re.search(r"\bstable\s*coin\b|\bstablecoin\b|\busdc\b|\busdt\b|\busdok\b|\busd0\b", low):
        tags.add("stablecoin")
    if re.search(r"\bissuer|blacklist|kyc|freeze|depeg|de-peg\b", low):
        tags.add("issuer-risk")
    if "stablecoin" in tags and re.search(r"\btrusted|trust assumption|trusts?\b", low):
        tags.add("stablecoin-trust")
        tags.add("trusted-issuer")
    if "stablecoin" in tags and "issuer-risk" in tags:
        tags.add("stablecoin-issuer-risk")
    if re.search(r"\boracle\b|\bprice feed\b", low):
        tags.add("oracle")
    if "oracle" in tags and re.search(r"\btrusted|trust assumption|trusts?\b", low):
        tags.add("trusted-oracle")
    if re.search(r"\bdecimal[- ]?mismatch\b|\bdecimals?\b", low):
        tags.add("decimal-model")
    if re.search(r"\bprivileged|admin|owner|governance|trusted role\b", low):
        tags.add("privileged-actor")
    if re.search(r"\btestnet|staging|mock|fixture\b", low):
        tags.add("test-or-mock-only")
    if re.search(r"\berc[- ]?4626\b|\berc4626\b", low):
        tags.add("erc4626")
    return sorted(tags)


def _row_from_phrase(
    *,
    workspace: Path,
    source_path: Path,
    section: str,
    line_no: int,
    clause_id: str,
    phrase: str,
) -> dict[str, Any] | None:
    phrase = _normalize_text(phrase)
    if not phrase:
        return None
    try:
        rel_source = source_path.relative_to(workspace).as_posix()
    except ValueError:
        rel_source = source_path.as_posix()
    tags = semantic_tags_for_text(phrase, section=section)
    return {
        "id": clause_id,
        "clause_id": clause_id,
        "section": section,
        "phrase": phrase,
        "semantic_tags": tags,
        "source_path": rel_source,
        "line_start": line_no,
    }


def parse_bug_bounty_file(path: Path, workspace: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    current_section: str | None = None
    current_heading_level: int | None = None
    paragraph: list[tuple[int, str]] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if not paragraph or current_section != SECTION_TRUST:
            paragraph = []
            return
        line_no = paragraph[0][0]
        phrase = _normalize_text(" ".join(part for _line_no, part in paragraph))
        row = _row_from_phrase(
            workspace=workspace,
            source_path=path,
            section=current_section,
            line_no=line_no,
            clause_id=_clause_id(current_section, phrase, line_no),
            phrase=phrase,
        )
        if row is not None:
            rows.append(row)
        paragraph = []

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip()
        heading = HEADING_RE.match(line)
        if heading:
            flush_paragraph()
            level = len(heading.group("marks"))
            section = _section_for_heading(heading.group("title"))
            if section:
                current_section = section
                current_heading_level = level
                continue
            if current_heading_level is not None and level <= current_heading_level:
                current_section = None
                current_heading_level = None
            continue

        if current_section is None:
            continue
        if not line.strip():
            flush_paragraph()
            continue

        cells = _table_cells(line)
        if cells is not None:
            flush_paragraph()
            if not cells:
                continue
            phrase = _phrase_from_cells(current_section, cells)
            row = _row_from_phrase(
                workspace=workspace,
                source_path=path,
                section=current_section,
                line_no=idx,
                clause_id=_clause_id(current_section, cells, idx),
                phrase=phrase,
            )
            if row is not None:
                rows.append(row)
            continue

        bullet = BULLET_RE.match(line) or NUMBERED_RE.match(line)
        if bullet:
            flush_paragraph()
            phrase = bullet.group("body")
            row = _row_from_phrase(
                workspace=workspace,
                source_path=path,
                section=current_section,
                line_no=idx,
                clause_id=_clause_id(current_section, phrase, idx),
                phrase=phrase,
            )
            if row is not None:
                rows.append(row)
            continue

        if current_section == SECTION_TRUST:
            paragraph.append((idx, line.strip()))

    flush_paragraph()
    return rows


def build_index(workspace: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    source_paths = discover_bug_bounty_files(workspace)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for source_path in source_paths:
        for row in parse_bug_bounty_file(source_path, workspace):
            key = (row["source_path"], row["clause_id"], row["phrase"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now_iso(),
        "workspace": str(workspace),
        "source_paths": [
            path.relative_to(workspace).as_posix()
            if not path.is_absolute() or str(path).startswith(str(workspace))
            else path.as_posix()
            for path in source_paths
        ],
        "row_count": len(rows),
        "rows": rows,
        "index_hash": digest,
        "high_confidence_threshold": HIGH_CONFIDENCE_THRESHOLD,
    }


def write_index(workspace: Path, index: dict[str, Any], output_path: Path | None = None) -> Path | None:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        return None
    out = output_path or (workspace / DEFAULT_INDEX_REL)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
    return out


def build_and_write_index(workspace: Path, output_path: Path | None = None) -> dict[str, Any]:
    workspace = workspace.resolve()
    index = build_index(workspace)
    written = write_index(workspace, index, output_path)
    index["index_path"] = str(written) if written is not None else ""
    return index


def _candidate_text(candidate: dict[str, Any]) -> str:
    parts: list[str] = []
    scalar_keys = (
        "cluster_id",
        "file_line",
        "snippet",
        "p1_match_tier",
        "source_context_excerpt",
    )
    for key in scalar_keys:
        value = candidate.get(key)
        if value:
            parts.append(str(value))
    list_keys = (
        "matched_p1_invariants",
        "p1_invariant_hits",
        "semantic_p1_invariants",
        "topical_p1_invariants",
        "matched_anti_patterns",
    )
    for key in list_keys:
        value = candidate.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
    gaps = candidate.get("p1_semantic_invariant_gaps")
    if gaps:
        try:
            parts.append(json.dumps(gaps, sort_keys=True))
        except TypeError:
            parts.append(str(gaps))
    return _normalize_text(" ".join(parts))


def candidate_semantic_tags(candidate: dict[str, Any]) -> list[str]:
    text = _candidate_text(candidate)
    tags = set(semantic_tags_for_text(text))
    cluster = str(candidate.get("cluster_id") or "").lower()
    if "no-slippage" in cluster or "functions-no-slippage" in cluster:
        tags.add("slippage")
    if "fee-on-transfer" in cluster or "fot" in cluster:
        tags.add("fee-on-transfer")
    if "oracle-stale" in cluster or "stale-price" in cluster:
        tags.add("oracle")
    if "decimal-mismatch" in cluster:
        tags.add("decimal-model")
    if "erc4626" in cluster:
        tags.add("erc4626")
    return sorted(tags)


def _token_overlap_score(phrase: str, candidate_text: str) -> float:
    phrase_tokens = {
        tok for tok in re.findall(r"[a-z0-9]{4,}", phrase.lower())
        if tok not in {"this", "that", "with", "from", "against", "contracts", "using"}
    }
    if not phrase_tokens:
        return 0.0
    candidate_tokens = set(re.findall(r"[a-z0-9]{4,}", candidate_text.lower()))
    overlap = phrase_tokens & candidate_tokens
    if not overlap:
        return 0.0
    return min(0.3, len(overlap) / max(len(phrase_tokens), 1) * 0.5)


def match_candidate(candidate: dict[str, Any], index: dict[str, Any]) -> dict[str, Any] | None:
    rows = index.get("rows") if isinstance(index, dict) else []
    if not isinstance(rows, list) or not rows:
        return None
    candidate_text = _candidate_text(candidate)
    cand_tags = set(candidate_semantic_tags(candidate))
    best: dict[str, Any] | None = None
    best_score = 0.0
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_tags = set(str(tag) for tag in row.get("semantic_tags") or [])
        meaningful_overlap = sorted((row_tags & cand_tags) - GENERIC_TAGS)
        score = 0.0
        if meaningful_overlap:
            score = max(score, 0.42 + min(0.36, 0.12 * len(meaningful_overlap)))
        phrase = str(row.get("phrase") or "")
        score = max(score, _token_overlap_score(phrase, candidate_text))

        if "front-running-public-mempool" in row_tags and (
            "slippage" in cand_tags or "erc4626" in cand_tags
        ):
            score = max(score, 0.86)
        if "slippage" in row_tags and "slippage" in cand_tags and (
            "ai-fp" in row_tags or "out-of-scope" in row_tags or "known-issue" in row_tags
        ):
            score = max(score, 0.74)
        if "stablecoin-trust" in row_tags and "fee-on-transfer" in cand_tags:
            score = max(score, 0.9 if "stablecoin" in cand_tags else 0.76)
        if "stablecoin-issuer-risk" in row_tags and {"fee-on-transfer", "stablecoin"} <= cand_tags:
            score = max(score, 0.78)
        if "fee-on-transfer" in row_tags and "fee-on-transfer" in cand_tags:
            score = max(score, 0.84)
        if "trusted-oracle" in row_tags and "oracle" in cand_tags:
            score = max(score, 0.82)
        if "decimal-model" in row_tags and "decimal-model" in cand_tags:
            score = max(score, 0.82)

        if score <= best_score:
            continue
        best_score = score
        best = {
            "clause_id": row.get("clause_id") or row.get("id"),
            "section": row.get("section"),
            "phrase": phrase,
            "confidence": round(score, 3),
            "semantic_tags": sorted(row_tags),
            "candidate_semantic_tags": sorted(cand_tags),
            "semantic_tags_overlap": meaningful_overlap,
            "source_path": row.get("source_path"),
            "line_start": row.get("line_start"),
            "requires_extension_distinct_argument": score >= HIGH_CONFIDENCE_THRESHOLD,
        }
    if best is None:
        return None
    if best["confidence"] < 0.4:
        return None
    return best


def annotate_candidates(candidates: Iterable[dict[str, Any]], index: dict[str, Any]) -> dict[str, Any]:
    matched = 0
    high_confidence = 0
    for candidate in candidates:
        match = match_candidate(candidate, index)
        candidate["bug_bounty_oos_match"] = match
        if match is None:
            continue
        matched += 1
        if float(match.get("confidence") or 0.0) >= HIGH_CONFIDENCE_THRESHOLD:
            high_confidence += 1
    return {
        "entries_matched": matched,
        "high_confidence_matches": high_confidence,
        "high_confidence_threshold": HIGH_CONFIDENCE_THRESHOLD,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build BUG_BOUNTY.md OOS index")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--output", default=None)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = Path(args.workspace).resolve()
    output = Path(args.output).resolve() if args.output else None
    index = build_and_write_index(workspace, output)
    if args.json:
        sys.stdout.write(json.dumps(index, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(
            "[bug-bounty-oos-index] "
            f"rows={index.get('row_count', 0)} path={index.get('index_path', '')}\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
