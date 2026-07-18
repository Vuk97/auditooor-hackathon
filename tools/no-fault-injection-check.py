#!/usr/bin/env python3
"""Rule 20 no-fault-injection preflight.

HIGH/CRITICAL claims must demonstrate impact under unmodified runtime
conditions. Synthetic error/panic/fault wrappers cannot be used to lift the
claimed impact unless the draft explicitly rebuts or walks the wrapper out.

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 20 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.no_fault_injection_check.v1"
GATE = "R20-NO-FAULT-INJECTION"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

FAULT_RE = re.compile(
    r"\b(?:faultyDB|faultyBatch|panicMock|errorMock|mockDB|fakeDB|"
    r"simulatedDB|injectError|injectFault|FaultyKV|armFail|forceError|"
    r"forceFail|failOnNext|panicAfter)\b|"
    r"//\s*(?:inject .*fault|simulate failure|force error)",
    re.IGNORECASE,
)

LATENCY_ONLY_RE = re.compile(r"\b(?:slow|latency|delay)\w*(?:DB|Batch|Wrapper)?\b", re.IGNORECASE)

SAFETY_PHRASE_RE = re.compile(
    r"no fault injection|unmodified runtime|real disk latency|"
    r"hardware-latency modeling|hardware-realism modeling|"
    r"latency-only wrapper|wrapper removed|wrapper stripped|"
    r"with the wrapper (?:removed|stripped)",
    re.IGNORECASE,
)

REMOVED_LINE_RE = re.compile(
    r"removed|stripped|deleted|replaced|swapped|no longer|not present|~~",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r20-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)

CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy"}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
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


def _scan_hits(draft: Path, draft_text: str, poc_paths: list[Path]) -> list[dict[str, Any]]:
    chunks = [(str(draft), draft_text)]
    for path in _source_files(poc_paths):
        try:
            chunks.append((str(path), _read_text(path)))
        except Exception:
            continue

    hits: list[dict[str, Any]] = []
    for source, text in chunks:
        for line_no, line in enumerate(text.splitlines(), start=1):
            match = FAULT_RE.search(line)
            if not match:
                continue
            token = match.group(0)
            latency_only = bool(LATENCY_ONLY_RE.search(token)) and not re.search(
                r"fault|panic|error|fail|mock|fake|simulat|inject", token, re.IGNORECASE
            )
            removed = bool(REMOVED_LINE_RE.search(line))
            hits.append(
                {
                    "source": source,
                    "line": line_no,
                    "token": token,
                    "text": line.strip()[:240],
                    "latency_only": latency_only,
                    "removed_or_walked_back": removed,
                }
            )
    return hits


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
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
            "Remove synthetic error/panic/fault wrappers from the proof path.",
            "Rebuild the PoC under unmodified runtime conditions.",
            "Walk severity below HIGH if the impact only appears with injected failures.",
            "Use <!-- r20-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    hits = _scan_hits(draft, text, poc_paths)
    actionable = [hit for hit in hits if not hit["latency_only"] and not hit["removed_or_walked_back"]]
    safety_phrase = bool(SAFETY_PHRASE_RE.search(text))

    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "fault_hits": hits[:24],
        "actionable_fault_hits": actionable[:24],
        "safety_phrase_present": safety_phrase,
    }

    if not actionable:
        payload["verdict"] = "pass-no-fault-injection"
        payload["reason"] = "no actionable fault-injection signal found"
        return 0, payload
    if safety_phrase and not strict:
        payload["verdict"] = "pass-safety-disclosure"
        payload["reason"] = "fault tokens present but explicit no-fault/unmodified-runtime disclosure found"
        return 0, payload

    payload["verdict"] = "fail-fault-injection"
    payload["reason"] = "HIGH/CRITICAL claim contains synthetic fault-injection signals"
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--severity", choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low"])
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
