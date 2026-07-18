#!/usr/bin/env python3
"""Rule 27 adjacent-finding disclosure preflight.

HIGH/CRITICAL drafts must not leak adjacent unfixed findings, sibling
variants, extra exploit paths, or "separate follow-up" evidence unless the
draft also states the filing boundary: integrated into this report, bounded as
out of scope, blocked by a defense, already duplicate-known, or intentionally
deferred with a source-backed reason.

Exit codes:
  0 - pass, out-of-scope, bounded disclosure, or accepted rebuttal
  1 - Rule 27 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.adjacent_finding_disclosure_check.v1"
GATE = "R27-ADJACENT-FINDING-DISCLOSURE"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

ADJACENT_TRIGGER_RE = re.compile(
    r"\b(?:"
    r"adjacent\s+(?:finding|vector|path|surface|call\s*site|variant|report)|"
    r"adjacent\s+[^\n]{0,80}\b(?:finding|vector|path|surface|call\s*site|variant|report)s?|"
    r"sibling\s+(?:finding|vector|path|surface|call\s*site|variant|report)|"
    r"sibling\s+[^\n]{0,80}\b(?:finding|vector|path|surface|call\s*site|variant|report)s?|"
    r"related\s+(?:finding|submission|report|vector|path|surface)|"
    r"same\s+(?:root\s+cause|bug\s+class|invariant|fix|remediation|pattern)|"
    r"structurally\s+(?:similar|adjacent|related)|"
    r"(?:another|other|additional)\s+(?:vulnerable\s+)?(?:path|surface|call\s*site|variant|exploit)|"
    r"(?:also|still)\s+(?:vulnerable|affected|exploitable)|"
    r"(?:separate|future|follow[- ]?up)\s+(?:report|submission|finding|filing)|"
    r"(?:not|outside|out\s+of)\s+(?:covered\s+)?(?:this\s+)?report|"
    r"left\s+for\s+(?:a\s+)?(?:follow[- ]?up|separate\s+report)|"
    r"do\s+not\s+include\s+(?:in|with)\s+this\s+report"
    r")\b",
    re.IGNORECASE,
)

SAFE_SECTION_RE = re.compile(
    r"(?im)^[^\S\n]{0,3}#{1,6}\s+(?:"
    r"Adjacent\s+(?:Finding\s+)?Disclosure|"
    r"Adjacent\s+Scope|"
    r"Related\s+Findings?(?:\s+and\s+Filing\s+Boundary)?|"
    r"Filing\s+Boundary|"
    r"Variant\s+Boundary|"
    r"Enumerated\s+Call\s+Sites"
    r")\b"
)

BOUNDARY_RE = re.compile(
    r"\b(?:"
    r"filing\s+boundary|this\s+report\s+covers|included\s+in\s+this\s+report|"
    r"integrated\s+into\s+this\s+report|one\s+report\s+with\s+all|"
    r"out\s+of\s+scope|not\s+reachable|structurally\s+blocked|defense\s+blocks|"
    r"duplicate|already\s+(?:filed|reported|known)|same\s+fix\s+would\s+close|"
    r"intentional\s+non[- ]coverage|different\s+guard\s+covers|"
    r"deferred\s+because|not\s+fileable|not\s+in\s+scope|"
    r"status\s*:\s*(?:covered|blocked|out[- ]of[- ]scope|duplicate|not\s+exposed|intentional)"
    r")\b",
    re.IGNORECASE,
)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:"
    r"no\s+adjacent\s+(?:finding|path|surface|variant)|"
    r"not\s+an\s+adjacent\s+(?:finding|path|surface|variant)|"
    r"adjacent\s+(?:finding|path|surface|variant)\s+(?:not\s+claimed|not\s+present|absent)|"
    r"not[_ -]?proven|not\s+claimed|not\s+alleged|no\s+claim"
    r")\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r27-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r27[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)

CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy", ".md", ".txt", ".log"}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
    return draft.resolve().parent


def _clean_ref(raw: str) -> str:
    return raw.strip().strip("`'\"").rstrip(").,;:")


def _resolve_poc_paths(draft: Path, text: str, explicit: list[str]) -> list[Path]:
    root = _workspace_root(draft)
    refs = list(explicit)
    refs.extend(match.group(1) for match in re.finditer(r"<!--\s*poc-dir:\s*([^>]+?)\s*-->", text, re.IGNORECASE))
    refs.extend(
        match.group(1)
        for match in re.finditer(r"(?im)^\s*(?:poc[_ -]?dir|poc[_ -]?path|PoC directory|PoC)\s*:\s*(.+?)\s*$", text)
    )
    refs.extend(match.group(0) for match in re.finditer(r"\bpoc-tests/[A-Za-z0-9_.\-/]+", text))

    resolved: list[Path] = []
    for raw in refs:
        ref = _clean_ref(raw)
        if not ref or "<" in ref or ">" in ref:
            continue
        path = Path(ref).expanduser()
        candidates = [path] if path.is_absolute() else [root / path, draft.parent / path, Path.cwd() / path]
        for candidate in candidates:
            if candidate.exists() and candidate not in resolved:
                resolved.append(candidate)
                break
    return resolved


def _source_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix in CODE_SUFFIXES:
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in CODE_SUFFIXES))
    return files


def _line_hits(source: str, text: str, pattern: re.Pattern[str], *, ignore_negative: bool = False, limit: int = 24) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if ignore_negative and NEGATIVE_SCOPE_RE.search(line):
            continue
        match = pattern.search(line)
        if not match:
            continue
        hits.append({"source": source, "line": idx, "token": match.group(0), "text": line.strip()[:240]})
        if len(hits) >= limit:
            break
    return hits


def _collect_trigger_hits(draft: Path, draft_text: str, poc_paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    hits = _line_hits(str(draft), draft_text, ADJACENT_TRIGGER_RE, ignore_negative=True)
    scanned: list[str] = []
    for path in _source_files(poc_paths):
        try:
            text = _read_text(path)
        except Exception:
            continue
        scanned.append(str(path))
        hits.extend(_line_hits(str(path), text, ADJACENT_TRIGGER_RE, ignore_negative=True))
        if len(hits) >= 48:
            hits = hits[:48]
            break
    return hits, scanned


def _safe_section(text: str) -> tuple[bool, int | None, list[dict[str, Any]]]:
    match = SAFE_SECTION_RE.search(text)
    if not match:
        return False, None, []
    start = match.start()
    section = text[start : start + 4000]
    after_first_line = section.find("\n")
    if after_first_line != -1:
        next_heading = re.search(r"(?m)^\s{0,3}#{1,6}\s+\S", section[after_first_line + 1 :])
        if next_heading:
            section = section[: after_first_line + 1 + next_heading.start()]
    boundary_hits = _line_hits("adjacent-disclosure-section", section, BOUNDARY_RE)
    return bool(boundary_hits), text[:start].count("\n") + 1, boundary_hits


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        match = REBUTTAL_LINE_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    poc_dir: list[str] | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Merge adjacent variants into the same report when they share the root cause and impact.",
            "Add an Adjacent Finding Disclosure or Filing Boundary section that bounds each variant.",
            "Mark adjacent paths as covered, blocked, out-of-scope, duplicate-known, or intentionally non-exposed.",
            "Use <!-- r27-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 240:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    trigger_hits, scanned = _collect_trigger_hits(draft, text, poc_paths)
    has_safe_section, safe_line, boundary_hits = _safe_section(text)
    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "trigger_hits": trigger_hits,
        "safe_section_line": safe_line,
        "boundary_hits": boundary_hits,
        "scanned_files": scanned,
    }

    if not trigger_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no adjacent-finding disclosure trigger"
        return 0, payload
    if has_safe_section:
        payload["verdict"] = "pass-adjacent-disclosure-bounded"
        payload["reason"] = "adjacent variants are bounded in an explicit disclosure section"
        return 0, payload
    if strict or trigger_hits:
        payload["verdict"] = "fail-adjacent-disclosure-missing"
        payload["reason"] = "HIGH/CRITICAL draft leaks adjacent finding surface without a filing boundary"
        return 1, payload

    payload["verdict"] = "pass-advisory"
    payload["reason"] = "adjacent trigger present but strict mode disabled"
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", default="auto")
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rc, payload = run(
        args.draft,
        severity_override=args.severity,
        poc_dir=args.poc_dir,
        strict=args.strict,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
