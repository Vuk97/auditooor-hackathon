#!/usr/bin/env python3
"""Rule 26 Cosmos SDK ante-handler traversal preflight.

HIGH/CRITICAL Cosmos Msg findings must show the message traverses the real
ante chain or explicitly disclose why the harness bypass is safe. Direct
keeper/msg-server calls are not enough.

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 26 violation
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


SCHEMA_VERSION = "auditooor.ante_handler_traversal_check.v1"
GATE = "R26-ANTE-HANDLER-TRAVERSAL"
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

COSMOS_MSG_RE = re.compile(
    r"\bMsg[A-Z][A-Za-z0-9_]*\b|"
    r"(?i:cosmos-sdk|cosmossdk\.io|sdk\.Msg|x/[a-z0-9_-]+/keeper|"
    r"ValidateBasicDecorator|ValidateNestedMsg|AnteHandler|ante decorator)"
)
ANTE_TRAVERSAL_RE = re.compile(
    r"BroadcastTxSync|BaseApp\.CheckTx|BaseApp\.DeliverTx|app\.RunTx\(|DeliverTx|"
    r"real ante chain|AnteHandler|ValidateBasicDecorator|ValidateNestedMsg|"
    r"RejectExtensionOptions|SetUpContextDecorator|SigVerificationDecorator|"
    r"DeductFeeDecorator|CircuitBreakerDecorator|TxExtension\.SelectedAuthenticators",
    re.IGNORECASE,
)
ANTE_BYPASS_RE = re.compile(
    r"direct keeper|keeper-level|directly calls? .*Keeper|keeper\.[A-Za-z0-9_]+\(|"
    r"msg_server_[A-Za-z0-9_]+|HandleMsg[A-Za-z0-9_]*\(|bypasses? ante|"
    r"without ante|not through ante",
    re.IGNORECASE,
)
WALKBACK_RE = re.compile(
    r"structurally rejected at ante|ValidateNestedMsg|Invalid nested msg|"
    r"ante rejects|never reaches block|downgraded from HIGH to MEDIUM|walk(?:ed)? back to Medium|"
    r"intentionally bypass(?:es|ed) ante.*rationale",
    re.IGNORECASE,
)
NEGATIVE_SCOPE_RE = re.compile(r"\b(?:not[_ -]?proven|not claimed|no claim|not alleged|not demonstrated)\b", re.IGNORECASE)
REBUTTAL_RE = re.compile(r"<!--\s*r26-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
CODE_SUFFIXES = {".go", ".rs", ".ts", ".tsx", ".js", ".mjs", ".py", ".log", ".txt"}


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
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
    return draft.resolve().parent


def _resolve_poc_paths(draft: Path, text: str, explicit: list[str]) -> list[Path]:
    root = _workspace_root(draft)
    refs = list(explicit)
    refs.extend(match.group(1) for match in re.finditer(r"<!--\s*poc-dir:\s*([^>]+?)\s*-->", text, re.IGNORECASE))
    refs.extend(match.group(0) for match in re.finditer(r"\b(?:poc-tests|external)/[A-Za-z0-9_.\-/]+", text))
    resolved: list[Path] = []
    for raw in refs:
        ref = raw.strip().strip("`'\"").rstrip(").,;:")
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


def _combined_text(draft: Path, draft_text: str, poc_paths: list[Path]) -> tuple[str, list[str]]:
    chunks = [draft_text]
    scanned: list[str] = []
    for path in _source_files(poc_paths):
        try:
            chunks.append(_read_text(path))
            scanned.append(str(path))
        except Exception:
            continue
    return "\n".join(chunks), scanned


def _line_hits(text: str, pattern: re.Pattern[str], *, ignore_negative: bool = False, limit: int = 16) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if ignore_negative and NEGATIVE_SCOPE_RE.search(line):
            continue
        match = pattern.search(line)
        if match:
            hits.append({"line": idx, "token": match.group(0), "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
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
        return 2, {"schema_version": SCHEMA_VERSION, "gate": GATE, "file": str(draft), "verdict": "error", "error": str(exc)}

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
            "Drive the Cosmos Msg through BroadcastTxSync, BaseApp.CheckTx, app.RunTx, or DeliverTx.",
            "Cite the project ante chain and decorators traversed.",
            "Walk severity back if ante decorators categorically reject the payload.",
            "Use <!-- r26-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    combined, scanned = _combined_text(draft, text, poc_paths)
    msg_hits = _line_hits(combined, COSMOS_MSG_RE, ignore_negative=True)
    if not msg_hits:
        payload["verdict"] = "pass-not-cosmos-msg"
        payload["reason"] = "no Cosmos SDK Msg signal"
        return 0, payload

    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload

    traversal_hits = _line_hits(combined, ANTE_TRAVERSAL_RE)
    bypass_hits = _line_hits(combined, ANTE_BYPASS_RE)
    walkback_hits = _line_hits(text, WALKBACK_RE)
    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "cosmos_msg_hits": msg_hits,
        "ante_traversal_hits": traversal_hits,
        "ante_bypass_hits": bypass_hits,
        "walkback_hits": walkback_hits,
        "scanned_files": scanned,
    }

    if traversal_hits:
        payload["verdict"] = "pass-ante-traversal"
        payload["reason"] = "ante traversal evidence found"
        return 0, payload
    if walkback_hits:
        payload["verdict"] = "pass-honest-walkback"
        payload["reason"] = "draft discloses ante rejection or walk-back"
        return 0, payload

    payload["verdict"] = "fail-ante-bypass"
    payload["reason"] = "Cosmos Msg claim lacks ante traversal evidence"
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--severity", choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low"])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rc, payload = run(args.draft, severity_override=args.severity, poc_dir=args.poc_dir, strict=args.strict)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
