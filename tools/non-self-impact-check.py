#!/usr/bin/env python3
"""Rule 24 non-self-impact preflight.

HIGH/CRITICAL fund-loss or fund-freeze claims must demonstrate impact on
funds or state the attacker does not control. The gate accepts either explicit
submission prose or concrete victim/protocol balance/state assertions in the
inline PoC or cited PoC directory.

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 24 violation
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


SCHEMA_VERSION = "auditooor.non_self_impact_check.v1"
GATE = "R24-NON-SELF-IMPACT-REQUIRED"

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

TRIGGER_PATTERNS = [
    "loss of funds",
    "freezing of funds",
    "theft of funds",
    "permanent freezing",
    "direct loss",
    "funds lost",
    "fund drain",
    "direct theft",
    "unauthorized withdraw",
    "unauthorized transfer",
    "unauthorized debit",
    "significant loss or theft",
    "theft of user funds",
    "loss or theft of user funds",
]

EXPLICIT_NON_SELF_RE = re.compile(
    r"non-self impact demonstrated|protocol-custody funds|"
    r"fee_collector revenue impairment|funds the attacker does not control|"
    r"not in the attacker'?s wallet|not controlled by the attacker|"
    r"belong to a user who is not the attacker|non-attacker address|"
    r"victim funds|protocol funds|module-account funds",
    re.IGNORECASE,
)

SELF_HARM_DISCLOSURE_RE = re.compile(
    r"self-harm only|attacker burns (?:their|his|her|its) own funds|"
    r"attacker freezes (?:their|his|her|its) own funds|"
    r"only the attacker'?s funds|attacker-owned funds only",
    re.IGNORECASE,
)

WALKBACK_RE = re.compile(
    r"walk(?:ed)? back to (?:medium|low)|severity walks? back|"
    r"medium or below|not fileable as high|not fileable as critical|"
    r"not a high(?:/critical)? claim|severity below high",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r24-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)

ASSERTION_RE = re.compile(
    r"\b(?:assertEq|assertTrue|assertFalse|assert_eq!|assert_ne!|"
    r"require\.(?:Equal|NotEqual|True|False|NoError)|"
    r"assert\.(?:Equal|NotEqual|True|False|ok|strictEqual|deepEqual)|"
    r"expect\(|t\.Fatalf|t\.Errorf)(?=\s*\(|\b)",
    re.IGNORECASE,
)

STATE_WORD_RE = re.compile(
    r"\b(?:balance|balances|funds|shares|asset|assets|quantums|amount|"
    r"collateral|vault|pool|module|treasury|fee|insurance|account|"
    r"subaccount|owner|recipient|credited|debited|withdraw|transfer)\b",
    re.IGNORECASE,
)

DEFAULT_ATTACKER_PATTERNS = [
    r"\battacker\w*\b",
    r"\bmalicious\w*\b",
    r"\bAlice\w*\b",
    r"\battacker_sender\w*\b",
]

DEFAULT_NON_SELF_PATTERNS = [
    # Generic victim characters.
    r"\bvictim\w*\b",
    r"\botherUser\w*\b",
    r"\buserAddr\b",
    r"\brecipient\w*\b",
    r"\bBob\w*\b",
    r"\bCarl\w*\b",
    r"\bDave\w*\b",
    r"\bLPs?\b",
    r"\bdepositor\w*\b",
    # EVM + cosmos-sdk protocol-custody actors.
    r"\btreasury\w*\b",
    r"\bprotocol\w*\b",
    r"\bmoduleAccount\w*\b",
    r"\bmodule account\w*\b",
    r"\bcollateralPool\w*\b",
    r"\bvault\w*\b",
    r"\bpoolAddr\b",
    r"\bfeeCollector\w*\b",
    r"\bfee_collector\w*\b",
    r"\bdistrModule\w*\b",
    r"\bcommunityPool\w*\b",
    r"\binsuranceFund\w*\b",
    # Substrate / polkadot protocol-custody actors.
    r"\bTreasury\b",
    r"\bTreasury(?:Account|PalletId|Pallet)\w*\b",
    r"\bpallet_balances\b",
    r"\bpallet_treasury\b",
    r"\breserved\w*\b",
    r"\breserve(?:_balance|d_balance)?\b",
    r"\bpot\(\)",
    r"\bpot_account\w*\b",
    # Move (Aptos / Sui) protocol-custody actors.
    r"@treasury\w*\b",
    r"\bresource_account\w*\b",
    r"\bresource-account\b",
    r"0x1::\w+",
    r"\bframework\w*\b",
    r"\bSupplyConfig\w*\b",
    # Solana protocol-custody actors.
    r"\bPDA\b",
    r"\bpda_\w*\b",
    r"\bvault_pda\w*\b",
    r"\bvault\s+PDA\b",
    r"\bescrow_pda\w*\b",
    r"\bescrow\s+PDA\b",
    r"\bescrow\w*\b",
    r"\bprogram_derived_address\w*\b",
]

CODE_SUFFIXES = {
    ".go",
    ".rs",
    ".sol",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".py",
    ".move",
    ".cairo",
    ".vy",
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity_from_text(text: str, path: Path, override: str | None = None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    patterns = [
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ]
    for pattern, source in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _scope_keywords(text: str) -> list[str]:
    lower = text.lower()
    return [keyword for keyword in TRIGGER_PATTERNS if keyword in lower]


def _rebuttal_text(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


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
    refs: list[str] = list(explicit)
    for match in re.finditer(r"<!--\s*poc-dir:\s*([^>]+?)\s*-->", text, re.IGNORECASE):
        refs.append(match.group(1))
    for match in re.finditer(
        r"(?im)^\s*(?:poc[_ -]?dir|poc[_ -]?path|PoC directory|PoC)\s*:\s*(.+?)\s*$",
        text,
    ):
        refs.append(match.group(1))
    for match in re.finditer(r"\bpoc-tests/[A-Za-z0-9_.\-/]+", text):
        refs.append(match.group(0))

    resolved: list[Path] = []
    for raw in refs:
        ref = _clean_ref(raw)
        if not ref or "<" in ref or ">" in ref:
            continue
        path = Path(ref).expanduser()
        candidates = [path] if path.is_absolute() else [root / path, draft.parent / path, Path.cwd() / path]
        for candidate in candidates:
            if candidate.exists():
                if candidate not in resolved:
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


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in re.split(r"[,|]", raw) if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.IGNORECASE)


def _line_hits(text: str, pattern: re.Pattern[str], source: str, limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            hits.append({"source": source, "line": idx, "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _collect_scan_text(draft: Path, draft_text: str, poc_paths: list[Path]) -> tuple[str, list[dict[str, Any]]]:
    chunks = [("draft", draft_text)]
    scanned_files: list[dict[str, Any]] = []
    for path in _source_files(poc_paths):
        try:
            body = _read_text(path)
        except Exception:
            continue
        chunks.append((str(path), body))
        scanned_files.append({"path": str(path)})
    return "\n".join(body for _, body in chunks), scanned_files


def _assertion_context_hits(text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if not ASSERTION_RE.search(line):
            continue
        window = "\n".join(lines[max(0, idx - 4) : min(len(lines), idx + 3)])
        if STATE_WORD_RE.search(window):
            hits.append({"source": "combined", "line": idx, "text": line.strip()[:240]})
        if len(hits) >= 12:
            break
    return hits


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

    severity, severity_source = _severity_from_text(text, draft, severity_override)
    scope = _scope_keywords(text)
    base_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "scope_keywords": scope,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add explicit 'Non-self impact demonstrated' prose naming the victim/protocol funds.",
            "Add balance/state assertions for a non-attacker victim, protocol custody account, module account, fee collector, community pool, or insurance fund.",
            "Walk severity below HIGH if the proof only burns or freezes attacker-controlled funds.",
            "Use <!-- r24-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        base_payload["verdict"] = "pass-out-of-scope"
        base_payload["reason"] = "severity below HIGH or missing"
        return 0, base_payload
    if not scope:
        base_payload["verdict"] = "pass-out-of-scope"
        base_payload["reason"] = "no fund-loss/fund-freeze trigger keyword"
        return 0, base_payload

    rebuttal = _rebuttal_text(text)
    if apply_rebuttal_gate(base_payload, rebuttal):
        return 0, base_payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    combined, scanned_files = _collect_scan_text(draft, text, poc_paths)

    attacker_re = _compile_union(DEFAULT_ATTACKER_PATTERNS + _env_patterns("AUDITOOOR_R24_ATTACKER_PATTERNS"))
    non_self_re = _compile_union(DEFAULT_NON_SELF_PATTERNS + _env_patterns("AUDITOOOR_R24_VICTIM_PATTERNS"))

    explicit_hits = _line_hits(text, EXPLICIT_NON_SELF_RE, "draft")
    non_self_hits = _line_hits(combined, non_self_re, "combined")
    attacker_hits = _line_hits(combined, attacker_re, "combined")
    assertion_hits = _assertion_context_hits(combined)
    self_harm_hits = _line_hits(text, SELF_HARM_DISCLOSURE_RE, "draft")

    base_payload["poc_paths"] = [str(path) for path in poc_paths]
    base_payload["evidence"] = {
        "explicit_non_self_hits": explicit_hits,
        "non_self_character_hits": non_self_hits,
        "attacker_character_hits": attacker_hits,
        "assertion_hits": assertion_hits,
        "self_harm_disclosure_hits": self_harm_hits,
        "scanned_files": scanned_files,
    }

    if explicit_hits:
        base_payload["verdict"] = "pass-non-self-impact"
        base_payload["reason"] = "explicit non-self-impact prose present"
        return 0, base_payload

    if non_self_hits and assertion_hits:
        base_payload["verdict"] = "pass-non-self-impact"
        base_payload["reason"] = "non-attacker victim/protocol character plus balance/state assertion present"
        return 0, base_payload

    if self_harm_hits and not non_self_hits:
        if WALKBACK_RE.search(text):
            base_payload["verdict"] = "pass-self-harm-disclosed"
            base_payload["reason"] = "draft explicitly discloses self-harm only and walks severity below HIGH"
            return 0, base_payload
        base_payload["verdict"] = "fail-self-harm-only"
        base_payload["reason"] = "draft discloses self-harm only but still claims HIGH+"
        return 1, base_payload

    if non_self_hits and strict:
        base_payload["verdict"] = "fail-strict-no-assertion"
        base_payload["reason"] = "non-attacker character mentioned but no balance/state assertion or explicit non-self prose found"
        return 1, base_payload

    if attacker_hits and not non_self_hits:
        base_payload["verdict"] = "fail-self-harm-only"
        base_payload["reason"] = "fund-loss claim names attacker-side impact but no victim/protocol funds"
        return 1, base_payload

    base_payload["verdict"] = "fail-strict-no-assertion" if strict else "fail-self-harm-only"
    base_payload["reason"] = "no explicit non-self impact proof found"
    return 1, base_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low"])
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
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
