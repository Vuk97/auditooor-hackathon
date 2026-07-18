#!/usr/bin/env python3
"""Rule 34 control-test / alternative-cause preflight.

HIGH/CRITICAL claims that rely on a precise root-cause mechanism should
pre-empt the strongest alternative explanation. The preferred proof is a
negative/control/baseline test showing adjacent conditions do not trigger the
bug. A clear alternative-cause rebuttal section is acceptable when a control
test is not practical.

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 34 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.control_test_discipline_check.v1"
GATE = "R34-CONTROL-TEST-DISCIPLINE"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

TRIGGER_RE = re.compile(
    r"\b(?:"
    r"alternative cause|root cause|zero[- ]share|first[- ]deposit|residual|"
    r"asymmetry|missing guard|guard missing|panic|fatal|halt|liveness|"
    r"direct keeper|keeper[- ]level|synthetic setup|synthetic state|"
    r"state seeding|private state|cache ordering|stale cache|"
    r"only fires|fires when|does not fire|precise condition"
    r")\b",
    re.IGNORECASE,
)

CONTROL_RE = re.compile(
    r"\b(?:"
    r"control test|negative control|positive control|baseline test|"
    r"comparative control|comparator|same[- ]workload baseline|"
    r"adjacent condition|non[- ]triggering condition|does not trigger|"
    r"does not fire|doesn't fire|no longer fires|without the bug|"
    r"Test\w*(?:Control|Baseline|Comparator|NoBug|DoesNotFire|NoTrigger)\w*|"
    r"test_\w*(?:control|baseline|comparator|no_bug|does_not_fire|no_trigger)\w*"
    r")\b",
    re.IGNORECASE,
)

SECTION_RE = re.compile(
    r"(?im)^#{1,4}\s*(?:"
    r"Alternative Cause Rebuttal|Why This Is Not|Why the Bug Is Not|"
    r"Alternative Mechanism|Counter-Argument|Control Test|Negative Control|"
    r"Baseline Control|What The Tests Prove"
    r")\b"
)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:not[_ -]?claimed|no claim|does not claim|not alleged|not demonstrated|"
    r"not relying on|not a liveness claim|no halt claim|not part of this report)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r34-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)

CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy", ".log", ".txt"}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    severity_value = r"\**\s*(Critical|High|Medium|Low)\b\**"
    for pattern, source in (
        (rf"(?im)^\s*\**\s*Severity\s*:\**\s*{severity_value}", "severity-header"),
        (rf"(?im)^\s*severity_implied\s*:\s*{severity_value}", "program-impact-mapping"),
        (rf"(?im)^\s*severity_tier\s*:\s*{severity_value}", "impact-contract"),
        (rf"(?im)^\s*selected_severity\s*:\s*{severity_value}", "selected-severity"),
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
            "Add a negative/control/baseline test showing an adjacent condition does not trigger the bug.",
            "Add an explicit Alternative Cause Rebuttal / Why This Is Not X section.",
            "Move HIGH/CRITICAL claims to NOT_SUBMIT_READY until the proof isolates the root-cause mechanism.",
            "Use <!-- r34-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    chunks = _combined_sources(draft, text, poc_paths)
    trigger_hits: list[dict[str, Any]] = []
    control_hits: list[dict[str, Any]] = []
    section_hits: list[dict[str, Any]] = []
    for source, chunk in chunks:
        trigger_hits.extend(_line_hits(source, chunk, TRIGGER_RE, ignore_negative=True, limit=8))
        control_hits.extend(_line_hits(source, chunk, CONTROL_RE, limit=8))
        section_hits.extend(_line_hits(source, chunk, SECTION_RE, limit=8))

    if not trigger_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no R34 mechanism-isolation trigger"
        payload["poc_paths"] = [str(path) for path in poc_paths]
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 240:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        payload["evidence"] = {"trigger_hits": trigger_hits[:24]}
        payload["poc_paths"] = [str(path) for path in poc_paths]
        return 0, payload

    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "trigger_hits": trigger_hits[:24],
        "control_hits": control_hits[:24],
        "alternative_rebuttal_section_hits": section_hits[:24],
        "scanned_files": [source for source, _ in chunks[1:]],
    }

    if control_hits or section_hits:
        payload["verdict"] = "pass-control-or-rebuttal-present"
        payload["reason"] = "control test or alternative-cause rebuttal found"
        return 0, payload

    payload["verdict"] = "fail-missing-control-test"
    payload["reason"] = "HIGH/CRITICAL mechanism claim lacks control test or alternative-cause rebuttal"
    return 1, payload


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
