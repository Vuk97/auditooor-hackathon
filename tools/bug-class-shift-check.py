#!/usr/bin/env python3
"""Rule 38 bug-class-shift preflight (Check #73).

HIGH/CRITICAL submissions whose ``attack_class`` does not match the rubric
phrase the draft cites must be corrected, or rebutted via
``<!-- r38-rebuttal: <reason> -->`` (<=200 chars). Also fails when the draft
cites a corpus ``record_id`` present in ``.auditooor/bug_class_shift.jsonl``
without acknowledging the drift category.

Source: docs/WAVE2_W29_NEW_GATES_SPEC_2026-05-16.md §1.

Exit codes:
  0 - pass / out-of-scope / accepted rebuttal
  1 - fail (rubric vs attack_class mismatch OR unacknowledged drift)
  2 - error (cannot read draft / cannot load drift index)
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


SCHEMA_VERSION = "auditooor.r38_bug_class_shift_check.v1"
GATE = "R38-BUG-CLASS-SHIFT"
TOOL_REL_PATH = "tools/bug-class-shift-check.py"

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Rubric phrase -> expected impact_class set. Per spec §1.2 step 2.
RUBRIC_TO_IMPACT: dict[str, set[str]] = {
    "direct loss of funds": {"theft"},
    "loss of funds": {"theft"},
    "theft of funds": {"theft"},
    "direct theft": {"theft"},
    "fund drain": {"theft"},
    "unauthorized withdraw": {"theft"},
    "permanent freezing": {"freeze"},
    "freezing of funds": {"freeze"},
    "frozen": {"freeze"},
    "governance takeover": {"governance-takeover"},
    "theft of governance": {"governance-takeover"},
    "rpc api crash": {"dos"},
    "denial of service": {"dos"},
    "dos": {"dos"},
    "griefing": {"griefing"},
    "yield redistribution": {"yield-redistribution"},
    "yield diversion": {"yield-redistribution"},
    "privilege escalation": {"privilege-escalation"},
    "precision loss": {"precision-loss"},
    "rounding error": {"precision-loss"},
}

# MECHANISM -> ACHIEVABLE IMPACT-CLASSES bridge (UNIVERSAL). SCOPE is defined by the
# IMPACT a finding achieves, NOT by its MECHANISM: the same in-scope impact (theft /
# freeze / governance-takeover / ...) is reachable through many mechanisms. R38's real
# job is NOT "does the mechanism LABEL equal the impact LABEL" (every real finding has a
# mechanism that DIFFERS from its impact); it is to catch IMPACT OVER-CLAIM - a draft
# whose attack_class names a mechanism that CANNOT plausibly produce the cited impact.
# So the gate PASSES when any impact a named mechanism can ACHIEVE intersects the
# expected impact bucket, and only FAILS the IMPOSSIBLE combos:
#   - halt / DoS -> theft / governance (a halt cannot directly move funds or seize gov)
#   - read-only / view reentrancy -> theft / freeze of in-scope funds (it corrupts a
#     view ANOTHER protocol reads; no direct in-scope fund impact - the classic drift)
#   - precision-loss -> governance-takeover / freeze
#   - griefing -> theft (value-destruction, not value-capture)
# The canonical table is SINGLE-SOURCED from audit/corpus_tags/impact_hunting_
# methodology.yaml (`mechanism_to_impacts:`), shared with the hunt brief, with the
# hardcoded dict below as a dependency-free fallback. Values use the RUBRIC_TO_IMPACT
# vocab. Override/extend via AUDITOOOR_R38_MECHANISM_IMPACTS.
# (NUVA 2026-06-30: started denial-family-only; generalised to universal per operator -
# the denial-only scope false-RED'd nothing but UNDER-claimed: it still rejected real
# overflow->freeze / access-control->theft / reentrancy->theft findings, which are the
# common case. Drift detection is preserved by the IMPOSSIBLE-combo exclusions above.)
MECHANISM_TO_ACHIEVABLE_IMPACTS: dict[str, set[str]] = {
    # denial / liveness family - locks funds (freeze) but cannot directly steal/seize.
    "halt": {"freeze", "dos", "griefing"},
    "chain-halt": {"freeze", "dos", "griefing"},
    "chainhalt": {"freeze", "dos", "griefing"},
    "dos": {"freeze", "dos", "griefing"},
    "denial-of-service": {"freeze", "dos", "griefing"},
    "liveness": {"freeze", "dos"},
    "gas-exhaustion": {"freeze", "dos"},
    "unbounded-loop": {"freeze", "dos"},
    "unbounded-gas": {"freeze", "dos"},
    "block-stuffing": {"freeze", "dos", "griefing"},
    # arithmetic family - mis-accounting drains (theft), locks (freeze), misprices.
    "overflow": {"theft", "freeze", "precision-loss", "yield-redistribution"},
    "underflow": {"theft", "freeze", "precision-loss", "yield-redistribution"},
    "arithmetic": {"theft", "freeze", "precision-loss", "yield-redistribution"},
    "rounding": {"precision-loss", "theft", "yield-redistribution"},
    "precision-loss": {"precision-loss", "theft", "yield-redistribution"},
    "division": {"precision-loss", "theft", "yield-redistribution"},
    # reentrancy family - drains (theft), bricks state (freeze), skews accounting.
    "reentrancy": {"theft", "freeze", "yield-redistribution", "governance-takeover"},
    "cross-function-reentrancy": {"theft", "freeze", "yield-redistribution"},
    "cross-contract-reentrancy": {"theft", "freeze", "yield-redistribution"},
    # access / auth family - missing auth can do almost anything.
    "access-control": {"theft", "freeze", "governance-takeover", "privilege-escalation", "yield-redistribution"},
    "auth-bypass": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "authorization": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "missing-modifier": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "unprotected": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    # oracle / price family.
    "oracle": {"theft", "freeze", "yield-redistribution"},
    "oracle-manipulation": {"theft", "freeze", "yield-redistribution"},
    "price-manipulation": {"theft", "freeze", "yield-redistribution"},
    "flashloan": {"theft", "freeze", "yield-redistribution"},
    # signature / init / upgrade / delegatecall family.
    "signature-replay": {"theft", "governance-takeover", "privilege-escalation"},
    "replay": {"theft", "governance-takeover", "privilege-escalation"},
    "uninitialized": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "initialization": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "delegatecall": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "storage-collision": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "upgrade": {"theft", "freeze", "governance-takeover", "privilege-escalation"},
    "governance": {"governance-takeover", "theft", "freeze", "yield-redistribution"},
    "liquidation": {"theft", "freeze", "yield-redistribution"},
    # MEV / ordering - extracts value (theft/yield) or griefs; cannot seize governance.
    "front-running": {"theft", "yield-redistribution", "griefing"},
    "mev": {"theft", "yield-redistribution", "griefing"},
    "sandwich": {"theft", "yield-redistribution", "griefing"},
    # griefing - value destruction, NOT capture; never bridges to theft.
    "griefing": {"griefing", "dos", "freeze"},
}

# RESTRICTED mechanism variants: substrings that name a mechanism whose direct in-scope
# impact is LESS than its parent family. These take PRECEDENCE over the generic family
# match so the genuine drift case (read-only-reentrancy claimed as direct theft) is
# still caught. A read-only/view reentrancy corrupts a view OTHER protocols read - it
# does NOT directly steal or freeze the in-scope protocol's funds.
RESTRICTED_REENTRANCY_IMPACTS: set[str] = {"griefing"}
RESTRICTED_REENTRANCY_MARKERS = ("read-only", "readonly", "read_only", "view-only", "view")


def _load_mechanism_impacts() -> dict[str, set[str]]:
    """Canonical mechanism->impact table. Single-sourced from
    audit/corpus_tags/impact_hunting_methodology.yaml (`mechanism_to_impacts:`) when
    readable, else the hardcoded MECHANISM_TO_ACHIEVABLE_IMPACTS fallback; then merged
    with AUDITOOOR_R38_MECHANISM_IMPACTS overrides (format 'mech=imp1|imp2,mech2=imp3').
    Mirrors the RUBRIC_TO_IMPACT override path; never raises (gate stays dependency-light)."""
    table = {k: set(v) for k, v in MECHANISM_TO_ACHIEVABLE_IMPACTS.items()}
    try:  # single-source from the corpus crosswalk shared with the hunt brief
        import yaml  # local import: gate must not hard-depend on PyYAML
        yml = Path(__file__).resolve().parent.parent / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
        if yml.is_file():
            data = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
            for mech, imps in (data.get("mechanism_to_impacts") or {}).items():
                buckets = {str(i).strip().lower() for i in (imps or []) if str(i).strip()}
                if mech and buckets:
                    table[str(mech).strip().lower()] = buckets
    except Exception:
        pass  # fallback to the hardcoded table
    raw = os.environ.get("AUDITOOOR_R38_MECHANISM_IMPACTS", "")
    for pair in raw.split(","):
        pair = pair.strip()
        if "=" in pair:
            mech, imps = pair.split("=", 1)
            mech = mech.strip().lower()
            buckets = {i.strip().lower() for i in imps.replace("|", " ").split() if i.strip()}
            if mech and buckets:
                table[mech] = buckets
    return table


def _mechanism_corpus_path() -> Path:
    """Resolve the canonical mechanism->impact corpus yaml path (single source for
    MECHANISM_TO_ACHIEVABLE_IMPACTS). Mirrors the path used in _load_mechanism_impacts."""
    return (
        Path(__file__).resolve().parent.parent
        / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
    )


def validate_mechanism_corpus(corpus_path: Path | None = None) -> tuple[int, dict[str, Any]]:
    """Validate EARLY that the MECHANISM_TO_ACHIEVABLE_IMPACTS corpus block is present +
    loadable + non-empty, so corpus drift surfaces at step-1/step-3 instead of only at the
    late R38 gate. The hardcoded MECHANISM_TO_ACHIEVABLE_IMPACTS dict remains the safety
    fallback for the gate itself; this check is purely a drift early-warning.

    Returns (rc, payload):
      0 - corpus yaml present, parseable, and its `mechanism_to_impacts:` block non-empty
      1 - typed DEFECT (corpus missing / empty / unparseable / PyYAML absent)
    The gate keeps working via the hardcoded fallback either way; rc=1 is a SMELL signal."""
    path = corpus_path or _mechanism_corpus_path()
    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "tool": TOOL_REL_PATH,
        "gate": GATE,
        "check": "mechanism-corpus-validation",
        "corpus_path": str(path),
        "fallback_keys": len(MECHANISM_TO_ACHIEVABLE_IMPACTS),
    }
    if not path.is_file():
        payload["verdict"] = "defect-corpus-missing"
        payload["defect"] = "mechanism_to_impacts corpus yaml not found"
        payload["reason"] = (
            f"{path} does not exist; gate runs on hardcoded fallback only - corpus drift "
            "would be invisible"
        )
        payload["mechanism_to_impacts_count"] = 0
        return 1, payload
    try:
        import yaml  # local import: validator must not hard-depend on PyYAML
    except Exception as exc:
        payload["verdict"] = "defect-pyyaml-unavailable"
        payload["defect"] = "PyYAML not importable; corpus cannot be validated"
        payload["reason"] = f"import yaml failed: {exc}"
        payload["mechanism_to_impacts_count"] = 0
        return 1, payload
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        payload["verdict"] = "defect-corpus-unparseable"
        payload["defect"] = "mechanism_to_impacts corpus yaml failed to parse"
        payload["reason"] = f"yaml.safe_load failed: {exc}"
        payload["mechanism_to_impacts_count"] = 0
        return 1, payload
    block = data.get("mechanism_to_impacts")
    # Count only entries that contribute a real mechanism -> non-empty impact bucket.
    valid = 0
    if isinstance(block, dict):
        for mech, imps in block.items():
            buckets = {str(i).strip().lower() for i in (imps or []) if str(i).strip()}
            if str(mech).strip() and buckets:
                valid += 1
    payload["mechanism_to_impacts_count"] = valid
    if valid == 0:
        payload["verdict"] = "defect-corpus-empty"
        payload["defect"] = "mechanism_to_impacts corpus block missing or empty"
        payload["reason"] = (
            "corpus yaml loaded but its `mechanism_to_impacts:` block has no usable "
            "mechanism->impact rows; gate runs on hardcoded fallback only"
        )
        return 1, payload
    payload["verdict"] = "ok-corpus-present"
    payload["reason"] = (
        f"mechanism_to_impacts corpus block has {valid} usable rows"
    )
    return 0, payload


def _achievable_impacts(observed_l: str, table: dict[str, set[str]]) -> set[str] | None:
    """The impact set a mechanism-labelled attack_class can ACHIEVE, or None when no
    known mechanism is recognised. RESTRICTED variants (read-only / view reentrancy)
    take precedence over the generic family; otherwise the MOST-SPECIFIC (longest)
    matching mechanism key wins so a specific label is not widened by a generic one."""
    # RESTRICTED: read-only / view reentrancy -> cannot directly steal/freeze in-scope.
    if "reentrancy" in observed_l and any(m in observed_l for m in RESTRICTED_REENTRANCY_MARKERS):
        return set(RESTRICTED_REENTRANCY_IMPACTS)
    best_key: str | None = None
    best_len = -1
    best_set: set[str] = set()
    for mech, achievable in table.items():
        mech_l = mech.lower()
        if (re.search(rf"(?:^|[-_/]){re.escape(mech_l)}(?:$|[-_/])", observed_l)
                or mech_l in observed_l):
            if len(mech_l) > best_len:
                best_key, best_len = mech_l, len(mech_l)
                best_set = achievable
    return set(best_set) if best_key is not None else None


REBUTTAL_RE = re.compile(
    r"<!--\s*r38-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r38[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)

# attack_class extraction patterns (front-matter, body header, Impact Contract).
ATTACK_CLASS_PATTERNS = [
    re.compile(r"(?im)^\s*attack_class\s*:\s*[\"']?([A-Za-z0-9_\-/.]+)[\"']?\s*$"),
    re.compile(r"(?im)^\s*\**\s*Attack[ _]Class\s*:\**\s*[\"']?([A-Za-z0-9_\-/.]+)"),
    re.compile(r"(?im)\battack_class\s*=\s*[\"']?([A-Za-z0-9_\-/.]+)"),
]

# Known bounty-platform prefixes for record_id citations. The drift index
# (.auditooor/bug_class_shift.jsonl) carries record_ids from every platform
# the corpus has mined, so the citation parser must cover all of them - not
# only the original four. Extend via AUDITOOOR_R38_RECORD_ID_PLATFORMS.
DEFAULT_RECORD_ID_PLATFORMS = [
    "code4rena",
    "sherlock",
    "immunefi",
    "cantina",
    "hackenproof",
    "hats",
    "secure3",
    "cyfrin",
    "spearbit",
]


def _env_record_id_platforms() -> list[str]:
    """Parse ``AUDITOOOR_R38_RECORD_ID_PLATFORMS`` env var.

    Format: newline-, comma-, or pipe-separated platform prefixes appended
    to ``DEFAULT_RECORD_ID_PLATFORMS``.
    """
    raw = os.environ.get("AUDITOOOR_R38_RECORD_ID_PLATFORMS", "")
    out: list[str] = []
    for item in re.split(r"[\n,|]", raw):
        item = item.strip().lower()
        if item and item not in out:
            out.append(item)
    return out


def _build_record_id_patterns() -> list[re.Pattern[str]]:
    """Compile the record_id citation patterns.

    Includes a literal ``record_id:`` front-matter pattern, one anchored
    pattern per known platform prefix, and a generic platform-prefix
    fallback so an unknown/new platform still parses.
    """
    platforms = list(DEFAULT_RECORD_ID_PLATFORMS)
    for extra in _env_record_id_platforms():
        if extra not in platforms:
            platforms.append(extra)
    patterns: list[re.Pattern[str]] = [
        re.compile(r"(?im)^\s*record_id\s*:\s*[\"']?([A-Za-z0-9_:\-./]+)[\"']?"),
    ]
    for platform in platforms:
        patterns.append(
            re.compile(
                rf"`({re.escape(platform)}:[a-z0-9_\-:.]+:[0-9a-f]{{8,16}})`",
                re.IGNORECASE,
            )
        )
    # Generic platform-prefix fallback: an unknown platform name followed by
    # a colon-delimited record_id ending in an 8-16 hex digest. Keeps the
    # gate from silently skipping a citation whose platform we have not yet
    # enumerated.
    patterns.append(
        re.compile(
            r"`([a-z][a-z0-9_-]+:[a-z0-9_\-:.]+:[0-9a-f]{8,16})`",
            re.IGNORECASE,
        )
    )
    return patterns


# record_id citation patterns (rebuilt per call to honour env overrides).
RECORD_ID_PATTERNS = _build_record_id_patterns()

DRIFT_ACKNOWLEDGEMENT_PATTERNS = [
    "bug-class-shift candidate",
    "prior_attack_class_drift",
    "drift category acknowledged",
    "r38-acknowledged-drift",
]

DEFAULT_DRIFT_INDEX = ".auditooor/bug_class_shift.jsonl"


def _env_rubric_overrides() -> dict[str, set[str]]:
    """Parse ``AUDITOOOR_R38_RUBRIC_TO_IMPACT_OVERRIDES`` env var.

    Format: newline-separated ``phrase=>class1,class2`` rows.
    """
    raw = os.environ.get("AUDITOOOR_R38_RUBRIC_TO_IMPACT_OVERRIDES", "")
    out: dict[str, set[str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=>" not in line:
            continue
        phrase, classes = line.split("=>", 1)
        phrase = phrase.strip().lower()
        bucket = {c.strip() for c in classes.split(",") if c.strip()}
        if phrase and bucket:
            out[phrase] = bucket
    return out


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity_from_text(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
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
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _extract_attack_class(text: str) -> str | None:
    for pattern in ATTACK_CLASS_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(1).strip().lower()
    return None


def _extract_rubric_phrases(text: str, table: dict[str, set[str]]) -> list[str]:
    lower = text.lower()
    return [phrase for phrase in table if phrase in lower]


def _attack_class_matches_expected(observed: str, expected: set[str]) -> bool:
    """Substring or prefix match between observed attack_class and the
    expected impact_class bucket. e.g. ``theft-via-reentrancy`` matches
    ``theft``; ``read-only-reentrancy`` does not match ``theft``."""
    observed_l = observed.lower()
    for cls in expected:
        cls_l = cls.lower()
        if observed_l == cls_l:
            return True
        # Substring on word boundaries: e.g. observed="theft-via-x"
        # contains "theft" segment.
        if re.search(rf"(?:^|[-_/]){re.escape(cls_l)}(?:$|[-_/])", observed_l):
            return True
        # Substring containment fallback (mirrors hackerman detector).
        if cls_l in observed_l:
            return True
    # MECHANISM -> IMPACT bridge (UNIVERSAL): the attack_class may name a MECHANISM
    # (chain-halt, overflow, reentrancy, access-control, ...) while the cited rubric row
    # is the IMPACT that mechanism achieves (freeze, theft, ...). Pass when any achievable
    # impact of the named mechanism intersects the expected impact bucket - never reject a
    # finding for being labelled by mechanism rather than impact. Drift detection survives
    # because IMPOSSIBLE combos resolve to a non-intersecting achievable set (e.g.
    # read-only-reentrancy -> {griefing} does NOT intersect {theft}; halt -> {freeze,dos,
    # griefing} does NOT intersect {theft}).
    achievable = _achievable_impacts(observed_l, _load_mechanism_impacts())
    if achievable is not None and (achievable & expected):
        return True
    return False


def _extract_record_ids(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    # Rebuild per call so AUDITOOOR_R38_RECORD_ID_PLATFORMS set after import
    # (e.g. in tests / per-invocation env) is honoured.
    for pat in _build_record_id_patterns():
        for m in pat.finditer(text):
            rid = m.group(1).strip()
            if rid and rid not in seen:
                seen.add(rid)
                out.append(rid)
    return out


def _load_drift_index(path: Path) -> tuple[set[str], dict[str, dict[str, Any]]]:
    """Return (set_of_record_ids, mapping_record_id_to_row).

    Skips the first ``schema_version`` envelope row.
    """
    record_ids: set[str] = set()
    rows: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "schema_version" in row and "record_id" not in row:
                continue
            rid = row.get("record_id")
            if rid:
                record_ids.add(rid)
                rows[rid] = row
    return record_ids, rows


def _rebuttal_text(text: str) -> str | None:
    m = REBUTTAL_RE.search(text)
    if not m:
        m = REBUTTAL_LINE_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _drift_acknowledged(text: str) -> bool:
    lower = text.lower()
    return any(token in lower for token in DRIFT_ACKNOWLEDGEMENT_PATTERNS)


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    drift_index_path: Path | None = None,
    strict: bool = False,
    allow_missing_index: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema": SCHEMA_VERSION,
            "tool": TOOL_REL_PATH,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity_from_text(text, draft, severity_override)

    rubric_table = dict(RUBRIC_TO_IMPACT)
    rubric_table.update(_env_rubric_overrides())

    base_payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "tool": TOOL_REL_PATH,
        "gate": GATE,
        "file": str(draft),
        "severity_observed": severity,
        "severity_source": severity_source,
        "strict": strict,
        "rebuttal": None,
        "drift_index_loaded": False,
        "drift_index_path": str(drift_index_path) if drift_index_path else None,
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        base_payload["verdict"] = "pass-out-of-scope"
        base_payload["reason"] = "severity below HIGH or missing"
        return 0, base_payload

    # Always honour rebuttal if present, BEFORE expensive checks.
    rebuttal = _rebuttal_text(text)
    if apply_rebuttal_gate(base_payload, rebuttal):
        return 0, base_payload
    if rebuttal:
        # Oversize rebuttal is ignored; gate may still fail.
        base_payload["rebuttal_oversize"] = True
        base_payload["rebuttal_observed_length"] = len(rebuttal)

    rubric_phrases = _extract_rubric_phrases(text, rubric_table)
    attack_class = _extract_attack_class(text)
    base_payload["rubric_phrases_observed"] = rubric_phrases
    base_payload["attack_class_observed"] = attack_class

    if not rubric_phrases:
        base_payload["verdict"] = "pass-no-rubric-phrase"
        base_payload["reason"] = "no known rubric phrase in draft"
        return 0, base_payload

    expected_set: set[str] = set()
    for phrase in rubric_phrases:
        expected_set |= rubric_table.get(phrase, set())
    base_payload["expected_impact_class"] = sorted(expected_set)

    rubric_mismatch = False
    if attack_class and expected_set:
        if not _attack_class_matches_expected(attack_class, expected_set):
            rubric_mismatch = True

    # If no attack_class declared at all in a HIGH+ draft, treat as mismatch
    # since the gate cannot verify alignment.
    if attack_class is None and expected_set:
        rubric_mismatch = True
        base_payload["attack_class_missing"] = True

    # Corpus citation drift check.
    drift_index_path = drift_index_path or Path(DEFAULT_DRIFT_INDEX)
    drift_failed = False
    drift_hits: list[str] = []
    if drift_index_path.exists():
        try:
            drift_ids, drift_rows = _load_drift_index(drift_index_path)
            base_payload["drift_index_loaded"] = True
            base_payload["drift_index_size"] = len(drift_ids)
            cited = _extract_record_ids(text)
            base_payload["record_ids_cited"] = cited
            drift_hits = [rid for rid in cited if rid in drift_ids]
            base_payload["record_ids_in_drift_index"] = drift_hits
            if drift_hits and not _drift_acknowledged(text):
                drift_failed = True
        except Exception as exc:
            base_payload["drift_index_error"] = str(exc)
            if not allow_missing_index:
                base_payload["verdict"] = "error"
                base_payload["reason"] = f"drift index load failed: {exc}"
                return 2, base_payload
    else:
        base_payload["drift_index_missing"] = True
        if not allow_missing_index and strict:
            base_payload["verdict"] = "error"
            base_payload["reason"] = f"drift index not found: {drift_index_path}"
            return 2, base_payload

    if rubric_mismatch:
        base_payload["verdict"] = "fail-rubric-attack-class-mismatch"
        base_payload["reason"] = (
            f"rubric phrase {rubric_phrases!r} expects {sorted(expected_set)!r} "
            f"but attack_class={attack_class!r}"
        )
        base_payload["remediation"] = [
            f"Correct attack_class to one of: {sorted(expected_set)}",
            "OR add <!-- r38-rebuttal: <reason> --> (<=200 chars)",
        ]
        return 1, base_payload

    if drift_failed:
        base_payload["verdict"] = "fail-corpus-citation-drift-unacknowledged"
        base_payload["reason"] = (
            f"cited record_ids {drift_hits!r} are bug-class-shift candidates; "
            "draft does not include the acknowledgement string"
        )
        base_payload["remediation"] = [
            "Add the phrase 'bug-class-shift candidate' or 'prior_attack_class_drift' near the citation",
            "OR remove the drift-candidate citation",
            "OR add <!-- r38-rebuttal: <reason> --> (<=200 chars)",
        ]
        return 1, base_payload

    if drift_hits:
        base_payload["verdict"] = "pass-corpus-citation-acknowledged"
        base_payload["reason"] = "drift-candidate cited but draft acknowledges drift"
        return 0, base_payload

    base_payload["verdict"] = "pass-attack-class-matches-rubric"
    base_payload["reason"] = "rubric phrase expected impact_class matches attack_class"
    return 0, base_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, nargs="?", default=None)
    parser.add_argument(
        "--validate-corpus",
        action="store_true",
        help="Validate the mechanism_to_impacts corpus yaml is present + non-empty "
        "(early drift check); does not require a draft. rc=1 on defect.",
    )
    parser.add_argument(
        "--corpus-path",
        type=Path,
        default=None,
        help="Override path to the mechanism_to_impacts corpus yaml (for --validate-corpus).",
    )
    parser.add_argument(
        "--severity",
        choices=["Critical", "High", "Medium", "Low", "critical", "high", "medium", "low", "auto"],
        default=None,
    )
    parser.add_argument(
        "--bug-class-shift-index",
        type=Path,
        default=Path(os.environ.get("AUDITOOOR_R38_INDEX_PATH", DEFAULT_DRIFT_INDEX)),
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--allow-missing-index", action="store_true")
    parser.add_argument("--json", action="store_true", default=True)
    args = parser.parse_args(argv)

    if args.validate_corpus:
        rc, payload = validate_mechanism_corpus(args.corpus_path)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return rc

    if args.draft is None:
        parser.error("draft is required unless --validate-corpus is given")

    sev_override = None if args.severity in (None, "auto") else args.severity
    rc, payload = run(
        args.draft,
        severity_override=sev_override,
        drift_index_path=args.bug_class_shift_index,
        strict=args.strict,
        allow_missing_index=args.allow_missing_index,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
