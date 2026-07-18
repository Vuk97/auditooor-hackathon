#!/usr/bin/env python3
"""Rule 25 defense-in-depth traversal preflight.

HIGH/CRITICAL downstream-impact claims must show that the attack payload
survives the defense layers between the bug-local check and the claimed impact
surface. Function-local or keeper-only evidence is not enough without traversal
evidence or an honest walk-back disclosure.

Exit codes:
  0 - pass, out-of-scope, honest walk-back, or accepted rebuttal
  1 - Rule 25 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.defense_in_depth_traversal_check.v1"
GATE = "R25-DEFENSE-IN-DEPTH-TRAVERSAL"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _compile(patterns: list[str], env_name: str | None = None, *, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    """Compile an alternation regex, appending newline-separated env-var patterns.

    Mirrors tools/in-process-vs-node-level-check.py so callers can extend the
    built-in DEFAULTS for non-cosmos targets (EVM, Substrate) without code edits.
    """
    merged = list(patterns)
    if env_name and os.environ.get(env_name):
        merged.extend(line.strip() for line in os.environ[env_name].splitlines() if line.strip())
    return re.compile("|".join(f"(?:{pattern})" for pattern in merged), flags)

DOWNSTREAM_RE = re.compile(
    r"matching-engine (?:SLO|degradation|stall|halt)|consensus|liveness failure|"
    r"network-level|fund loss|loss of funds|direct theft|permanent freezing|"
    r"chain halt|validator halt|block production|settlement degradation|"
    r"AppHash divergence|state-machine write path|downstream impact",
    re.IGNORECASE,
)

# Traversal evidence: the attack payload demonstrably survives the defense
# layers between the bug-local check and the claimed impact surface.
# Built-in DEFAULTS cover cosmos-sdk, EVM/Solidity, and Substrate; extend via
# AUDITOOOR_R25_TRAVERSAL_PATTERNS (newline-separated regex) for other targets.
TRAVERSAL_DEFAULTS = [
    # cosmos-sdk
    r"mempool admission",
    r"ante decorators?",
    r"ProcessProposal",
    r"PrepareProposal",
    r"DeliverTx",
    r"FinalizeBlock",
    r"BroadcastTxSync",
    r"BaseApp\.CheckTx",
    r"BaseApp\.FinalizeBlock",
    r"\bapp\.RunTx\(",
    r"AdvanceToBlock\(",
    r"network\.New\(",
    r"multi-validator",
    r"RequestFinalizeBlock",
    r"ResponseFinalizeBlock",
    r"real ante chain",
    r"real block execution",
    r"attack tx .* reaches",
    r"reaches (?:matching engine|FinalizeBlock|DeliverTx|block)",
    # EVM / Solidity
    r"passes the `?require`?(?:/`?modifier`?)? checks?",
    r"passes the `?modifier`? checks?",
    r"reaches the external call",
    r"survives `?nonReentrant`?",
    r"through the proxy(?: / `?fallback`?)?",
    r"`?fallback`? (?:dispatch|delegatecall)",
    r"fork-test end-to-end",
    r"`?vm\.prank`? as a non-privileged caller",
    r"access-control modifier traversed",
    r"passes `?onlyOwner`?(?:/`?onlyRole`?)?",
    r"passes `?onlyRole`?",
    # Substrate
    r"passes `?ensure_signed`?(?:/`?ensure_root`?)?",
    r"passes `?ensure_root`?",
    r"validated by `?validate_unsigned`?",
    r"survives the `?SignedExtension`?(?:/`?TransactionExtension`?)?",
    r"survives the `?TransactionExtension`?",
    r"`?construct_runtime`? dispatch",
    r"reaches `?on_initialize`?(?:/`?on_finalize`?)?",
    r"reaches `?on_finalize`?",
    r"the extrinsic is dispatched",
    # generic
    r"the payload reaches the impact surface",
    r"end-to-end",
    r"full request path traversed",
]

# Function-local / unit-test-only smells: evidence that the PoC never exercised
# the defense layers it would need to traverse. Cosmos + EVM + Substrate.
LOCAL_ONLY_DEFAULTS = [
    # cosmos-sdk
    r"function-local",
    r"microbenchmark",
    r"direct keeper",
    r"keeper-level",
    r"directly calls? .*Keeper",
    r"\bkeeper\.[A-Za-z0-9_]+\(",
    r"ProcessSingleMatch\(",
    r"PlacePerpetualLiquidation\(",
    r"CheckTx-internal",
    r"hand-rolled branchedCtx",
    # EVM / Solidity
    r"`?internal`? function called directly",
    r"unit test with no access-control caller",
    r"`?vm\.store`? slot-seeded",
    r"\bno fork\b",
    # Substrate
    r"pallet function called directly",
    r"`?Pallet::<T>::`? direct call bypassing dispatch",
    r"`?new_test_ext\(\)`? only",
]

# Defense-in-depth CEILING signals: an honest walk-back disclosing that a
# defense layer categorically rejects the attack payload. Cosmos + EVM + Substrate.
WALKBACK_DEFAULTS = [
    # cosmos-sdk + generic
    r"defense-in-depth ceiling",
    r"structurally rejected at ante",
    r"never reaches block",
    r"categorically rejected",
    r"downgraded from HIGH to MEDIUM",
    r"downgraded from Critical to Medium",
    r"walk(?:ed)? back to Medium",
    r"MaxTxBytes",
    r"ValidateNestedMsg",
    r"Invalid nested msg",
    # EVM / Solidity
    r"reverts in the modifier",
    r"blocked by the access-control gate",
    r"caps at `?maxApproval`?",
    # Substrate
    r"rejected by `?validate_unsigned`?",
    r"blocked by the `?SignedExtension`?",
]

TRAVERSAL_RE = _compile(TRAVERSAL_DEFAULTS, "AUDITOOOR_R25_TRAVERSAL_PATTERNS")
LOCAL_ONLY_RE = _compile(LOCAL_ONLY_DEFAULTS)
WALKBACK_RE = _compile(WALKBACK_DEFAULTS)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:not[_ -]?proven|not claimed|does not claim|no claim|not alleged|not demonstrated)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r25-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r25[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)

CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy", ".log", ".txt"}


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
            "Show the attack payload traverses mempool/ante/proposal/block execution to the claimed impact surface.",
            "Walk severity back if a defense layer categorically rejects the payload.",
            "Use <!-- r25-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    trigger_hits = _line_hits(text, DOWNSTREAM_RE, ignore_negative=True)
    if not trigger_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no downstream-impact trigger"
        return 0, payload

    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    combined, scanned = _combined_text(draft, text, poc_paths)
    traversal_hits = _line_hits(combined, TRAVERSAL_RE)
    local_hits = _line_hits(combined, LOCAL_ONLY_RE)
    walkback_hits = _line_hits(text, WALKBACK_RE)
    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "trigger_hits": trigger_hits,
        "traversal_hits": traversal_hits,
        "local_only_hits": local_hits,
        "walkback_hits": walkback_hits,
        "scanned_files": scanned,
    }

    if traversal_hits:
        payload["verdict"] = "pass-defense-traversal"
        payload["reason"] = "defense traversal evidence found"
        return 0, payload
    if walkback_hits:
        payload["verdict"] = "pass-honest-walkback"
        payload["reason"] = "draft discloses defense-in-depth ceiling or walk-back"
        return 0, payload

    payload["verdict"] = "fail-local-only-downstream-claim"
    payload["reason"] = "downstream-impact claim lacks defense traversal evidence"
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
