#!/usr/bin/env python3
"""Rule 40 V3-grade-PoC preflight.

For any Medium+ loss-of-funds / state-corruption / finalization / DoS claim,
mocks may only replace EXTERNAL dependencies. The vulnerable protocol-owned
path must be real. A PoC is V3-grade only if it proves all six points:

  1. Real entrypoint -> real vulnerable code -> real impact surface.
  2. Every protocol-owned defense/rescue/refund/race/finalizer that could
     stop the path is executed or explicitly ruled out with source evidence.
  3. Mocked components are only external dependencies, and each mock
     assumption is stated.
  4. There is a negative control: patched code, canonical upstream behavior,
     or a clean path where the impact does not occur.
  5. The exact victim/asset/attacker balances or state transitions are
     asserted before and after.
  6. If the report names multiple variants, each variant has an executed PoC
     OR the report narrows the claim.

Honest walk-back / narrowed-claim disclosures PASS: a draft that says
"downstream loss is reasoned not executed; claim narrowed to the source-level
gap" is acceptable because the rule allows narrowing.

Exit codes:
  0 - pass, out-of-scope, claim-narrowed, or accepted rebuttal
  1 - Rule 40 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r40_v3_grade_poc_check.v1"
GATE = "R40-V3-GRADE-POC-REQUIRED"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Point 0: trigger - the rule only fires on Medium+ loss-of-funds /
# state-corruption / finalization / DoS claims.
TRIGGER_RE = re.compile(
    r"loss of funds|loss of user funds|theft of funds|direct theft|"
    r"fund drain|fund loss|funds lost|drain|stealing or loss of funds|"
    r"permanent freezing|freezing of funds|frozen funds|"
    r"state corruption|state-corruption|corrupt(?:ed|s)? (?:the )?state|"
    r"storage corruption|finaliz(?:e|ation|ing)|finalis(?:e|ation|ing)|"
    r"unfinalized|forged (?:state )?root|forged commitment|"
    r"denial of service|\bDoS\b|liveness failure|chain halt|"
    r"unauthorized withdraw|unauthorized transfer|insolvency",
    re.IGNORECASE,
)

# Point 1: real entrypoint -> real vulnerable code -> real impact surface.
REAL_ENTRYPOINT_RE = re.compile(
    r"real entrypoint|real (?:vulnerable )?(?:code|function|verifier|path)|"
    r"unmodified [A-Za-z0-9_.:]+|real, unmodified|drives the real|"
    r"production call (?:graph|path)|live production code|"
    r"real impact surface|in-scope [A-Za-z0-9_.\-]+ crate by local path|"
    r"imports the in-scope|exercises the real|through the REAL|"
    r"real protocol-owned path",
    re.IGNORECASE,
)

# Point 2: defenses executed or ruled out with source evidence.
DEFENSE_TRAVERSED_RE = re.compile(
    r"opposed-trace|opposed trace|every guard|all_defenses_enumerated|"
    r"all defenses enumerated|defense-in-depth traversal|guard traversal|"
    r"each (?:protocol-owned )?defense|ruled out with source|"
    r"no (?:downstream )?(?:layer|defense layer) rechecks|"
    r"no (?:independent )?guard|every protocol-owned (?:defense|guard)|"
    r"defense.{0,30}executed|finalizer.{0,30}(?:executed|ruled out)|"
    r"refund.{0,30}(?:executed|ruled out)|rescue.{0,30}(?:executed|ruled out)",
    re.IGNORECASE,
)

# Point 3: mock assumptions stated.
MOCK_ASSUMPTION_RE = re.compile(
    r"mock assumption|mocked? (?:component|dependenc|deps?)|"
    r"mock(?:s|ed)? only (?:replace|external)|"
    r"only external dependenc|external dependenc(?:y|ies) (?:are|is) mock|"
    r"mock(?:s)? (?:replace|stand in for) external|"
    r"each mock (?:assumption )?is stated|assumption.{0,40}mock|"
    r"mock deps?\b|with mock helpers|uses real .* \+ mock|"
    r"no fork needed.*mock|mock helpers",
    re.IGNORECASE,
)

# Point 4: negative control.
NEGATIVE_CONTROL_RE = re.compile(
    r"negative control|negative-control|patched code|patched (?:variant|path)|"
    r"canonical upstream behavio(?:u)?r|clean path|control test|"
    r"reference path that DOES|correct reference|intentionally-correct|"
    r"contrast (?:case|path)|sibling .* (?:correct|enforces)|"
    r"impact does not occur|baseline (?:without|where the impact)",
    re.IGNORECASE,
)

# Point 5: before/after balance/state assertions.
BEFORE_AFTER_RE = re.compile(
    r"before(?:/|\s+and\s+)after|balBefore|balAfter|"
    r"\bBefore\b.{0,40}\bAfter\b|"
    r"balances? .* (?:before|after)|state transition(?:s)? .* asserted|"
    r"asserts? .* (?:balance|state) (?:before|after)|"
    r"exact .* balances? .* asserted",
    re.IGNORECASE,
)

ASSERTION_RE = re.compile(
    r"\b(?:assertEq|assertTrue|assertFalse|assert_eq!|assert_ne!|assert!|"
    r"require\.(?:Equal|NotEqual|True|False|NoError)|"
    r"assert\.(?:Equal|NotEqual|True|False|ok|strictEqual|deepEqual)|"
    r"expect\(|t\.Fatalf|t\.Errorf)\b",
)

BALANCE_STATE_WORD_RE = re.compile(
    r"\b(?:balance|balances|funds|escrow|shares|asset|assets|amount|"
    r"surplus|refund|commitment|root|state|account)\b",
    re.IGNORECASE,
)

# Point 6: per-variant proof OR narrowed claim. Only counts "variant" when it
# is an attack / exploit / bug variant the report claims - NOT a Rust/Go enum
# `variant`, a proof-struct variant, or an error-enum variant (those are code
# nomenclature, not separate exploitable claims).
VARIANT_MENTION_RE = re.compile(
    r"(?:attack|exploit|bug|finding|impact|severity)[- ]variant(?:s)?|"
    r"variant(?:s)? of the (?:attack|exploit|bug|finding)|"
    r"(?:names?|claims?|reports?) (?:two|three|multiple|several) variants?|"
    r"multiple (?:attack|exploit|bug) variants?|"
    r"each (?:attack|exploit|bug) variant",
    re.IGNORECASE,
)

VARIANT_PROVEN_RE = re.compile(
    r"each variant has (?:an )?executed|each (?:attack|exploit|bug) variant "
    r".* (?:executed|proven|covered)|per-variant (?:proof|PoC)|"
    r"variant .* executed PoC|executed PoC .* (?:each|every|both) variant|"
    r"every variant .* (?:executed|proven)",
    re.IGNORECASE,
)

# Honest narrowing / walk-back: the rule explicitly allows narrowing in place
# of a full end-to-end PoC.
NARROWED_RE = re.compile(
    r"claim (?:is )?narrow(?:ed)?|narrows? the claim|reasoned not executed|"
    r"not executed; claim narrowed|reasoned .{0,40}not separately executed|"
    r"not separately executed|are reasoned .{0,30}not (?:separately )?executed|"
    r"downstream .{0,40}(?:is )?reasoned|source-level gap|"
    r"narrowed to the source|severity walks? back|"
    r"walk(?:ed)? back to (?:medium|low)|claim (?:is )?bounded to|"
    r"no over-framing|not (?:claimed|alleged|proven) (?:as|at) (?:high|critical)|"
    r"limited to the (?:source|logic) gap|honest scope of the PoC",
    re.IGNORECASE,
)

# Smell: a mock standing in for the protocol-owned vulnerable path itself.
# The built-in default is engagement-agnostic: it fires when simulate / mock /
# stub / re-implement language sits within a short window of a protocol-owned
# surface noun (vulnerable / protocol-owned / in-scope / entrypoint / verifier
# / finalizer / gateway / pool). Engagement-specific literals (e.g. the
# Hyperbridge `placeOrder` / `gateway-simulator` tokens) live in the env
# extension AUDITOOOR_R40_MOCK_PROTOCOL_PATTERNS, not hard-coded here.
MOCK_REPLACES_PROTOCOL_RE = re.compile(
    r"(?:simulat|mock|stub|re-?implement)\w*"
    r".{0,40}"
    r"(?:vulnerable|protocol-owned|in-scope|entrypoint|verifier|finaliz|"
    r"gateway|pool)|"
    r"mock(?:ed)? (?:the )?(?:vulnerable|protocol-owned|in-scope) "
    r"(?:path|code|function|verifier)|"
    r"stub(?:bed)? (?:out )?the (?:vulnerable|protocol|in-scope)|"
    r"re-?implement(?:ed|s)? the (?:vulnerable|protocol)",
    re.IGNORECASE,
)

# Engagement-specific mock-over-protocol literals previously hard-coded in
# MOCK_REPLACES_PROTOCOL_RE (Hyperbridge `placeOrder` / `gateway-simulator`).
# They are appended to the env-extension list so the built-in default stays
# generic; operators add target-specific literals via the env var directly.
_DEFAULT_MOCK_PROTOCOL_EXTENSIONS = (
    r"placeOrder simulator",
    r"gateway[- ]simulator",
    r"simulat(?:e|es|or|ing) (?:the )?placeOrder",
    r"re-?implement(?:ed|s)? (?:the )?placeOrder",
)

REBUTTAL_RE = re.compile(r"<!--\s*r40-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r40[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)

CODE_SUFFIXES = {
    ".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py",
    ".move", ".cairo", ".vy", ".log", ".txt",
}


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
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
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


def _combined_text(draft_text: str, poc_paths: list[Path]) -> tuple[str, list[str]]:
    chunks = [draft_text]
    scanned: list[str] = []
    for path in _source_files(poc_paths):
        try:
            chunks.append(_read_text(path))
            scanned.append(str(path))
        except Exception:
            continue
    return "\n".join(chunks), scanned


def _line_hits(text: str, pattern: re.Pattern[str], *, limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            hits.append({"line": idx, "token": match.group(0)[:80], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _balance_assertion_hits(text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if not ASSERTION_RE.search(line):
            continue
        window = "\n".join(lines[max(0, idx - 4): min(len(lines), idx + 3)])
        if BALANCE_STATE_WORD_RE.search(window):
            hits.append({"line": idx, "text": line.strip()[:240]})
        if len(hits) >= 12:
            break
    return hits


def _env_extra(name: str, defaults: tuple[str, ...] = ()) -> re.Pattern[str] | None:
    """Compile an env-supplied newline-separated regex list.

    `defaults` is unconditionally folded in so an engagement-specific literal
    (formerly hard-coded) is still matched even when the env var is unset. The
    env var EXTENDS the defaults; it does not replace them.
    """
    raw = os.environ.get(name, "")
    parts = [p.strip() for p in raw.splitlines() if p.strip()]
    parts = list(defaults) + parts
    if not parts:
        return None
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE)


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_LINE_RE.search(text)
    if not match:
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
            "Point 1: drive the real entrypoint -> real vulnerable code -> real impact surface; do not stub the protocol-owned path.",
            "Point 2: enumerate every protocol-owned defense/rescue/refund/race/finalizer and execute it or rule it out with source evidence (opposed-trace).",
            "Point 3: state each mock assumption; mocks may replace EXTERNAL dependencies only.",
            "Point 4: add a negative control - patched code, canonical upstream behavior, or a clean path where the impact does not occur.",
            "Point 5: assert exact victim/asset/attacker balances or state transitions before and after.",
            "Point 6: give each named variant an executed PoC, OR narrow the report's claim.",
            "Honest narrowing PASSES: state 'downstream loss is reasoned not executed; claim narrowed to the source-level gap'.",
            "Override: visible line 'r40-rebuttal: <reason>' (<=200 chars) or <!-- r40-rebuttal: <reason> -->.",
        ],
    }

    # Below Medium: out of scope.
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["medium"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below Medium or missing"
        return 0, payload

    trigger_hits = _line_hits(text, TRIGGER_RE)
    if not trigger_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no loss-of-funds / state-corruption / finalization / DoS trigger keyword"
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    combined, scanned = _combined_text(text, poc_paths)

    real_entrypoint_hits = _line_hits(combined, REAL_ENTRYPOINT_RE)
    defense_hits = _line_hits(combined, DEFENSE_TRAVERSED_RE)
    mock_assumption_hits = _line_hits(combined, MOCK_ASSUMPTION_RE)
    negative_control_hits = _line_hits(combined, NEGATIVE_CONTROL_RE)
    before_after_hits = _line_hits(combined, BEFORE_AFTER_RE)
    balance_assertion_hits = _balance_assertion_hits(combined)
    variant_mention_hits = _line_hits(combined, VARIANT_MENTION_RE)
    variant_proven_hits = _line_hits(combined, VARIANT_PROVEN_RE)
    narrowed_hits = _line_hits(text, NARROWED_RE)

    extra_mock_re = _env_extra(
        "AUDITOOOR_R40_MOCK_PROTOCOL_PATTERNS",
        _DEFAULT_MOCK_PROTOCOL_EXTENSIONS,
    )
    mock_protocol_hits = _line_hits(combined, MOCK_REPLACES_PROTOCOL_RE)
    if extra_mock_re is not None:
        mock_protocol_hits.extend(_line_hits(combined, extra_mock_re))

    has_real_entrypoint = bool(real_entrypoint_hits)
    has_defenses = bool(defense_hits)
    has_mock_statement = bool(mock_assumption_hits)
    has_negative_control = bool(negative_control_hits)
    has_before_after = bool(before_after_hits) or bool(balance_assertion_hits)
    narrowed = bool(narrowed_hits)
    variants_named = bool(variant_mention_hits)
    variants_proven = bool(variant_proven_hits)

    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "trigger_hits": trigger_hits,
        "real_entrypoint_hits": real_entrypoint_hits,
        "defense_traversed_hits": defense_hits,
        "mock_assumption_hits": mock_assumption_hits,
        "negative_control_hits": negative_control_hits,
        "before_after_hits": before_after_hits,
        "balance_assertion_hits": balance_assertion_hits,
        "variant_mention_hits": variant_mention_hits,
        "variant_proven_hits": variant_proven_hits,
        "narrowed_claim_hits": narrowed_hits,
        "mock_replaces_protocol_hits": mock_protocol_hits,
        "scanned_files": scanned,
    }
    payload["points"] = {
        "p1_real_entrypoint": has_real_entrypoint,
        "p2_defenses_traversed": has_defenses,
        "p3_mock_assumptions_stated": has_mock_statement,
        "p4_negative_control": has_negative_control,
        "p5_before_after_assertions": has_before_after,
        "p6_variants_covered": (not variants_named) or variants_proven or narrowed,
    }

    # An honest narrowed / walk-back claim is acceptable per the rule. But a
    # narrowed claim still cannot smuggle a mock over the protocol-owned path.
    if mock_protocol_hits and not narrowed:
        payload["verdict"] = "fail-mock-replaces-protocol-path"
        payload["reason"] = "a mock appears to replace the protocol-owned vulnerable path; mocks may only replace external dependencies"
        return 1, payload

    if narrowed:
        payload["verdict"] = "pass-claim-narrowed"
        payload["reason"] = "draft honestly narrows the claim (Rule 40 permits narrowing in place of a full end-to-end PoC)"
        return 0, payload

    # Full V3-grade path: all six points must be present.
    if variants_named and not variants_proven:
        payload["verdict"] = "fail-variant-unproven"
        payload["reason"] = "report names multiple variants but not every variant has an executed PoC and the claim is not narrowed"
        return 1, payload

    if not has_before_after:
        payload["verdict"] = "fail-no-before-after-assertions"
        payload["reason"] = "no before/after victim/asset/attacker balance or state-transition assertion found"
        return 1, payload

    if not has_negative_control:
        payload["verdict"] = "fail-no-negative-control"
        payload["reason"] = "no negative control (patched code, canonical upstream behavior, or clean no-impact path) found"
        return 1, payload

    if not has_defenses:
        payload["verdict"] = "fail-defense-not-traversed"
        payload["reason"] = "no evidence that protocol-owned defenses/rescue/refund/race/finalizers are executed or ruled out with source evidence"
        return 1, payload

    if strict and not has_real_entrypoint:
        payload["verdict"] = "fail-defense-not-traversed"
        payload["reason"] = "strict mode: no real-entrypoint marker found (cannot confirm the vulnerable protocol-owned path is exercised)"
        return 1, payload

    if strict and not has_mock_statement:
        payload["verdict"] = "fail-mock-replaces-protocol-path"
        payload["reason"] = "strict mode: no stated mock-assumptions list found; cannot confirm mocks are external-only"
        return 1, payload

    payload["verdict"] = "pass-v3-grade"
    payload["reason"] = "all six V3-grade-PoC points present (real entrypoint, defenses traversed, mock assumptions, negative control, before/after assertions, variant coverage)"
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument(
        "--severity",
        choices=["auto", "Critical", "High", "Medium", "Low",
                 "critical", "high", "medium", "low"],
        default="auto",
    )
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        severity_override=override,
        poc_dir=args.poc_dir,
        strict=args.strict,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
