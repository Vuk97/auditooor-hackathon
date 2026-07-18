#!/usr/bin/env python3
"""Panic-context audit for live halt / liveness claims.

HIGH/CRITICAL reports that use a panic/fatal transcript to claim live halt,
validator halt, chain halt, or liveness impact must distinguish a stable
runtime failure from teardown contamination. Panic evidence that also contains
cleanup signals such as closed DB, context cancellation, EOF, signal
termination, or test cleanup must include a stable pre-teardown transcript
before it can support a live liveness claim.

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - panic-context violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.panic_context_audit.v1"
GATE = "PANIC-CONTEXT-AUDIT"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

LIVE_CLAIM_RE = re.compile(
    r"\b(?:"
    r"live halt|liveness|network[- ]level|consensus halt|chain halt|"
    r"validator halt|block production halt|halt(?:s|ed|ing)? block production|"
    r"FinalizeBlock|Commit|multi[- ]validator|4[- ]validator|validator set|"
    r"AppHash divergence|node[- ]level|production path"
    r")\b",
    re.IGNORECASE,
)

PANIC_RE = re.compile(
    r"\b(?:panic:|fatal error:|SIG(?:ABRT|SEGV|TERM|KILL)|stack trace|goroutine \d+|"
    r"unlock of unlocked mutex|concurrent map writes|nil pointer dereference|"
    r"fatal|panicked|panic)\b",
    re.IGNORECASE,
)

TEARDOWN_RE = re.compile(
    r"\b(?:"
    r"context canceled|context cancelled|context deadline exceeded|"
    r"closed DB|database closed|db closed|closed database|closed channel|"
    r"use of closed|already closed|EOF|broken pipe|connection reset|"
    r"signal: terminated|received signal|SIGTERM|SIGKILL|"
    r"cleanup|tear[- ]?down|test cleanup|t\.Cleanup|defer cancel|"
    r"defer .*Close\(\)|\.Close\(\)|cancel\(\)|after test completion|"
    r"shutting down|shutdown|stop node|stop validator|kill process"
    r")\b",
    re.IGNORECASE,
)

STABLE_EVIDENCE_RE = re.compile(
    r"\b(?:"
    r"goroutine dump|stable goroutine dump|non[- ]progressing goroutine|"
    r"no progress for|no forward progress for|timed out after|timeout after|"
    r"before teardown|pre[- ]teardown|before cleanup|pre[- ]cleanup|"
    r"captured before cleanup|captured before shutdown|"
    r"production path transcript|FinalizeBlock transcript|Commit transcript|"
    r"multi[- ]validator transcript|4[- ]validator transcript|"
    r"same stack for|unchanged stack|stable stack|exact stack trace"
    r")\b",
    re.IGNORECASE,
)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:not[_ -]?claimed|no claim|does not claim|not alleged|not demonstrated|"
    r"not a live halt|not a liveness claim|panic is not used as impact proof)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*panic-context-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)

CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy", ".log", ".txt"}


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
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
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
        for match in re.finditer(r"(?im)^\s*(?:poc[_ -]?dir|poc[_ -]?path|PoC directory|PoC|log[_ -]?path|transcript)\s*:\s*(.+?)\s*$", text)
    )
    refs.extend(match.group(0) for match in re.finditer(r"\bpoc-tests/[A-Za-z0-9_.\-/]+", text))
    refs.extend(match.group(0) for match in re.finditer(r"\b(?:logs?|transcripts?)/[A-Za-z0-9_.\-/]+", text))

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


def _line_hits(
    source: str,
    text: str,
    pattern: re.Pattern[str],
    *,
    ignore_negative: bool = False,
    limit: int = 16,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if ignore_negative and NEGATIVE_SCOPE_RE.search(line):
            continue
        match = pattern.search(line)
        if match:
            hits.append({"source": source, "line": idx, "token": match.group(0), "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def _combined_sources(draft: Path, draft_text: str, poc_paths: list[Path]) -> list[tuple[str, str]]:
    chunks = [(str(draft), draft_text)]
    for path in _source_files(poc_paths):
        try:
            chunks.append((str(path), _read_text(path)))
        except Exception:
            continue
    return chunks


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
            "Capture the panic/fatal transcript before teardown, cleanup, cancellation, or DB close.",
            "Add a stable goroutine dump showing no forward progress before test cleanup.",
            "Add production-path or multi-validator transcript evidence for live liveness claims.",
            "Walk back the live halt/liveness claim if the panic only occurs during teardown.",
            "Use <!-- panic-context-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    chunks = _combined_sources(draft, text, poc_paths)

    live_hits: list[dict[str, Any]] = []
    panic_hits: list[dict[str, Any]] = []
    teardown_hits: list[dict[str, Any]] = []
    stable_hits: list[dict[str, Any]] = []
    for source, chunk in chunks:
        live_hits.extend(_line_hits(source, chunk, LIVE_CLAIM_RE, ignore_negative=True, limit=8))
        panic_hits.extend(_line_hits(source, chunk, PANIC_RE, ignore_negative=True, limit=8))
        teardown_hits.extend(_line_hits(source, chunk, TEARDOWN_RE, limit=8))
        stable_hits.extend(_line_hits(source, chunk, STABLE_EVIDENCE_RE, limit=8))

    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "live_claim_hits": live_hits[:24],
        "panic_hits": panic_hits[:24],
        "teardown_hits": teardown_hits[:24],
        "stable_evidence_hits": stable_hits[:24],
        "scanned_files": [source for source, _ in chunks[1:]],
    }

    if not live_hits or not panic_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no HIGH/CRITICAL live-liveness panic claim"
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 240:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    if stable_hits:
        payload["verdict"] = "pass-stable-panic-evidence"
        payload["reason"] = "stable pre-teardown panic/liveness evidence found"
        return 0, payload

    if teardown_hits:
        payload["verdict"] = "fail-teardown-contaminated-panic"
        payload["reason"] = "panic/fatal liveness evidence includes teardown contamination without stable pre-teardown proof"
        return 1, payload

    payload["verdict"] = "pass-no-teardown-contamination"
    payload["reason"] = "panic/liveness claim has no teardown contamination signals"
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--severity", default="auto")
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
