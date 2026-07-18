#!/usr/bin/env python3
"""Rule 59 anti-pattern attribution preflight.

High/Critical finding drafts that declare a cluster/category matching the P3
anti-pattern catalog must cite a recognized catalog ``pattern_id`` or carry a
bounded R59 rebuttal/no-binding reason.

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 59 violation
  2 - input/catalog error
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.r59_antipattern_attribution.v1"
GATE = "R59-ANTIPATTERN-ATTRIBUTION"
TOOL_REL_PATH = "tools/antipattern-attribution-check.py"

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG_ROOT = REPO_ROOT / "obsidian-vault" / "anti-patterns" / "v2"
CATALOG_TOOL = REPO_ROOT / "tools" / "antipattern-catalog-build.py"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
REBUTTAL_RE = re.compile(
    r"<!--\s*(?:r59-rebuttal|r59-no-binding|r59-no-antipattern-binding|no-antipattern-binding)\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:"
    r"r59[-_ ]rebuttal|"
    r"r59[-_ ]no[-_ ]binding|"
    r"r59[-_ ]no[-_ ]antipattern[-_ ]binding|"
    r"no[-_ ]antipattern[-_ ]binding|"
    r"no\s+anti[- ]pattern\s+binding"
    r")\s*[:=]\s*[\"'`]?(.*?)[\"'`]?\s*,?\s*$"
)

FIELD_PATTERNS = [
    re.compile(r"(?im)^\s*[\"']?(?:cluster|category|attack_class|bug_class|antipattern_category|anti_pattern_category)[\"']?\s*:\s*[\"']?([^\"'\n,]+)"),
    re.compile(r"(?im)^\s*\**\s*(?:Cluster|Category|Attack[ _]Class|Bug[ _]Class|Anti[- ]Pattern Category)\s*:\**\s*[\"']?([^\"'\n,]+)"),
    re.compile(r"(?im)\b(?:cluster|category|attack_class|bug_class)\s*=\s*[\"']?([^\"'\s,]+)"),
]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _visible_text(text: str) -> str:
    return HTML_COMMENT_RE.sub("", text)


def _normalize(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")


def _severity_from_text(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    patterns = [
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*[\"'`*]*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*[\"']severity_claim[\"']\s*:\s*[\"']?(Critical|High|Medium|Low)[\"']?\s*,?\s*$", "proof-packet-severity"),
        (r"(?im)^\s*[\"']?selected_severity[\"']?\s*:\s*[\"']?(Critical|High|Medium|Low)[\"']?\s*,?\s*$", "selected-severity"),
    ]
    for pattern, source in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text) or REBUTTAL_LINE_RE.search(text)
    if not match:
        return None
    value = " ".join(match.group(1).split())
    if not value or value.lower() in {"<reason>", "reason", "tbd", "todo", "n/a", "na", "none"}:
        return None
    return value


def _extract_binding_terms(text: str) -> list[str]:
    terms: list[str] = []
    for pattern in FIELD_PATTERNS:
        for match in pattern.finditer(text):
            value = " ".join(match.group(1).strip().split())
            if value and value not in terms:
                terms.append(value)
    return terms


def _catalog_mod() -> Any:
    spec = importlib.util.spec_from_file_location("antipattern_catalog_build", CATALOG_TOOL)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import catalog tool at {CATALOG_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _load_catalog(catalog_root: Path) -> list[dict[str, Any]]:
    mod = _catalog_mod()
    return mod.load_catalog(catalog_root)


def _record_haystacks(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("pattern_id", "category", "description", "language"):
        value = record.get(key)
        if isinstance(value, str):
            values.append(value)
    for key in ("known_bug_class_from_corpus", "source_finding_ids", "empirical_anchors", "target_invariants"):
        value = record.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value if str(item).strip())
    return values


def _term_matches_record(term: str, record: dict[str, Any]) -> bool:
    term_norm = _normalize(term)
    if not term_norm:
        return False
    for haystack in _record_haystacks(record):
        hay_norm = _normalize(haystack)
        if term_norm == hay_norm or term_norm in hay_norm or hay_norm in term_norm:
            return True
    return False


def _line_hits(text: str, pattern_ids: set[str], *, limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern_id in sorted(pattern_ids, key=len, reverse=True):
            if pattern_id in line:
                hits.append({"line": line_no, "pattern_id": pattern_id, "text": line.strip()[:240]})
                break
        if len(hits) >= limit:
            break
    return hits


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    catalog_root: Path = DEFAULT_CATALOG_ROOT,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema": SCHEMA_VERSION,
            "schema_version": SCHEMA_VERSION,
            "tool": TOOL_REL_PATH,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "reason": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity_from_text(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_REL_PATH,
        "gate": GATE,
        "file": str(draft),
        "severity_observed": severity,
        "severity_source": severity_source,
        "strict": strict,
        "rebuttal": None,
        "catalog_root": str(catalog_root),
        "evidence": {},
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload
    if rebuttal:
        payload["rebuttal_oversize"] = True
        payload["rebuttal_observed_length"] = len(rebuttal)

    try:
        records = _load_catalog(catalog_root)
    except Exception as exc:
        payload["verdict"] = "error"
        payload["reason"] = f"anti-pattern catalog load failed: {exc}"
        return 2, payload

    visible = _visible_text(text)
    pattern_ids = {str(row.get("pattern_id")) for row in records if row.get("pattern_id")}
    cited_pattern_ids = sorted(pattern_id for pattern_id in pattern_ids if pattern_id in visible)
    binding_terms = _extract_binding_terms(visible)
    matched_records = [
        row
        for row in records
        if any(_term_matches_record(term, row) for term in binding_terms)
    ]
    matched_ids = sorted({str(row.get("pattern_id")) for row in matched_records if row.get("pattern_id")})

    payload["binding_terms_observed"] = binding_terms
    payload["cited_antipattern_ids"] = cited_pattern_ids
    payload["known_antipattern_count"] = len(pattern_ids)
    payload["evidence"] = {
        "matched_catalog_pattern_ids": matched_ids[:32],
        "citation_hits": _line_hits(visible, pattern_ids),
    }

    if matched_ids:
        cited_matched = sorted(set(cited_pattern_ids).intersection(matched_ids))
        payload["cited_matched_antipattern_ids"] = cited_matched
        if cited_matched:
            payload["verdict"] = "pass-antipattern-cited-and-recognized"
            payload["reason"] = "draft cites recognized P3 anti-pattern ID(s) for the bound cluster/category"
            return 0, payload
        if cited_pattern_ids:
            payload["verdict"] = "fail-antipattern-id-does-not-match-bound-category"
            payload["reason"] = "draft cites recognized P3 anti-pattern ID(s), but none match the bound cluster/category"
            payload["remediation"] = [
                "Cite a P3 anti-pattern pattern_id that matches the declared cluster/category.",
                "If no catalog row binds, add <!-- r59-no-binding: <source-backed reason> --> (<=200 chars).",
            ]
            return 1, payload
        payload["verdict"] = "fail-no-antipattern-id-cited-for-bound-category"
        payload["reason"] = "draft cluster/category maps to P3 anti-pattern catalog entries but cites no recognized pattern_id"
        payload["remediation"] = [
            "Cite the relevant P3 anti-pattern pattern_id from obsidian-vault/anti-patterns/v2.",
            "If no catalog row binds, add <!-- r59-no-binding: <source-backed reason> --> (<=200 chars).",
        ]
        return 1, payload

    if cited_pattern_ids:
        payload["verdict"] = "pass-antipattern-cited-and-recognized"
        payload["reason"] = "draft cites recognized P3 anti-pattern ID(s)"
        return 0, payload

    payload["verdict"] = "pass-no-catalog-binding"
    payload["reason"] = "no declared cluster/category mapped to a P3 anti-pattern catalog entry"
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low", "auto"])
    parser.add_argument("--workspace", type=Path, help="Accepted for pre-submit parity.")
    parser.add_argument("--catalog-root", type=Path, default=DEFAULT_CATALOG_ROOT)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    severity_override = None if args.severity in (None, "auto") else args.severity
    rc, payload = run(
        args.draft,
        severity_override=severity_override,
        catalog_root=args.catalog_root,
        strict=args.strict,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
