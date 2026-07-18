#!/usr/bin/env python3
"""Standalone Defender-Narrative Simulator.

This tool forecasts plausible protocol-team / defender objections for a draft
finding or evidence packet and emits rebuttal prompts before filing. It is a
deterministic local heuristic only: no provider is called, no triager verdict is
predicted, and the output is advisory hardening guidance rather than
submission clearance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.defender_narrative_simulator.v1"
MODE = "deterministic_local_rules"
DEFAULT_MAX_NARRATIVES = 7
MAX_NARRATIVES_LIMIT = 7
DEFAULT_MAX_INPUT_CHARS = 50_000
MAX_SOURCE_REFS = 8
MAX_SIGNALS = 8
MAX_CHECKLIST_ITEMS = 4

SEVERITY_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?\s*severity\s*(?:\*\*)?\s*:\s*(critical|high|medium|low)\b"
)
FILE_REF_RE = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_.-]+/)+(?:[A-Za-z0-9_.-]+)"
    r"\.(?:sol|rs|go|py|ts|tsx|js|jsx|md|move|vy|java|kt|c|cpp|h|hpp|toml|ya?ml|json))"
    r"(?:(?::|#L)(?P<line>\d+))?"
)


@dataclass(frozen=True)
class LoadedInput:
    text: str
    input_format: str
    input_label: str
    source_refs: list[str]
    truncated: bool


ARCHETYPES: tuple[dict[str, Any], ...] = (
    {
        "archetype": "intended-design",
        "likely_objection": (
            "Defenders may argue the behavior is documented, intentional, or an accepted design tradeoff."
        ),
        "evidence_gap": (
            "The packet needs the exact design boundary and proof that the exploit crosses it, rather than merely restating an omitted check."
        ),
        "rebuttal_strategy": (
            "Quote the protocol-owned design text, then show a non-privileged path with value movement or persistent state corruption outside that boundary."
        ),
        "kill_condition": (
            "Drop or downgrade if protocol-owned docs explicitly define the behavior as intended and the evidence shows no stronger boundary-crossing impact."
        ),
        "checklist": (
            "Quote the relevant design or scope clause.",
            "Name the intended behavior and the stronger behavior reached by the exploit.",
            "Show the exploit does not rely on a privileged/manual override.",
            "Attach the state or balance delta that the design text does not cover.",
        ),
        "trigger_terms": (
            "by design",
            "intended behavior",
            "expected behavior",
            "design choice",
            "design decision",
            "known limitation",
            "documented behavior",
            "architectural",
            "acknowledged",
            "defense in depth",
            "missing check",
            "omitted check",
            "does not validate",
            "fails to validate",
        ),
        "rebuttal_terms": (
            "strictly stronger",
            "crosses the intended boundary",
            "non-privileged exploit",
            "value extraction",
            "persistent corruption",
            "outside the documented design",
        ),
    },
    {
        "archetype": "user-error",
        "likely_objection": (
            "Defenders may argue the loss comes from user error, counterparty risk, or attacker self-harm rather than a protocol defect."
        ),
        "evidence_gap": (
            "The actor model must separate attacker, victim, payer, preventer, and asset owner, and show ordinary user verification cannot avoid the impact."
        ),
        "rebuttal_strategy": (
            "Add an actor table plus pre/post balances proving a non-self victim loses funds or control because of protocol logic."
        ),
        "kill_condition": (
            "Drop if the only harmed party is the actor who supplied the bad input or if normal user verification fully prevents the outcome."
        ),
        "checklist": (
            "Identify attacker, victim, preventer, payer, and asset owner.",
            "Show the victim cannot avoid the loss by ordinary verification.",
            "Prove the bug is the independent cause of loss.",
            "Include non-self pre/post balances or state ownership deltas.",
        ),
        "trigger_terms": (
            "user error",
            "user must verify",
            "victim should verify",
            "receiver must verify",
            "wrong recipient",
            "self-harm",
            "victim is the attacker",
            "counterparty risk",
            "misconfiguration",
            "phishing",
            "own funds",
            "attacker-provided",
            "caller supplied",
        ),
        "rebuttal_terms": (
            "non-self victim",
            "victim cannot avoid",
            "ordinary verification cannot prevent",
            "attacker controlled",
            "independent of user error",
            "balance delta",
        ),
    },
    {
        "archetype": "trusted-admin",
        "likely_objection": (
            "Defenders may argue the path requires a trusted admin, governance actor, operator, keeper, or team action that is out of scope."
        ),
        "evidence_gap": (
            "The packet needs a permissionless trigger path, or a scope citation proving the privileged role is explicitly in the threat model."
        ),
        "rebuttal_strategy": (
            "Trace the exploit from a public entrypoint and show no privileged actor must misbehave, pause, upgrade, whitelist, or withhold action."
        ),
        "kill_condition": (
            "Drop if impact requires trusted-role compromise, malicious governance/admin action, or project inaction excluded by the program scope."
        ),
        "checklist": (
            "Name every role touched by the exploit path.",
            "Show the attacker can trigger the path without a role grant.",
            "Separate remediation/admin response from exploit preconditions.",
            "Cite scope if the trusted role is intentionally in scope.",
        ),
        "trigger_terms": (
            "admin",
            "administrator",
            "owner",
            "onlyowner",
            "governance",
            "multisig",
            "operator",
            "keeper",
            "guardian",
            "whitelisted",
            "privileged",
            "permissioned",
            "team action",
            "team inaction",
            "pause",
            "upgrade",
            "security council",
            "council",
            "compromised admin",
        ),
        "rebuttal_terms": (
            "permissionless",
            "any user",
            "public entrypoint",
            "no admin action",
            "fresh account",
            "non-privileged",
            "without role grant",
        ),
    },
    {
        "archetype": "insufficient-impact",
        "likely_objection": (
            "Defenders may argue the draft shows no in-scope security impact, no non-self value movement, or only a low/informational issue."
        ),
        "evidence_gap": (
            "The packet needs concrete affected assets, affected users, persistence/recoverability, and a verbatim severity-rubric row."
        ),
        "rebuttal_strategy": (
            "Add pre/post balance or state deltas, quantify the affected population/value, and map the result to the exact severity rule."
        ),
        "kill_condition": (
            "Drop or downgrade if the outcome is cosmetic, event-only, fully recoverable, or lacks non-self asset/state impact."
        ),
        "checklist": (
            "Record concrete pre/post balances or state deltas.",
            "Tie the symptom to value movement, freeze, insolvency, or durable corruption.",
            "Explain recoverability and who can recover.",
            "Quote the exact claimed severity row.",
        ),
        "trigger_terms": (
            "no fund loss",
            "no user fund loss",
            "no direct loss",
            "no funds at risk",
            "informational",
            "cosmetic",
            "event only",
            "only affects event",
            "no functional impact",
            "impact unclear",
            "recoverable",
            "temporary",
            "low severity",
            "accounting mismatch",
        ),
        "rebuttal_terms": (
            "drain",
            "steal",
            "theft",
            "freeze",
            "insolvency",
            "non-self",
            "balance delta",
            "value movement",
            "persistent",
            "user funds",
        ),
    },
    {
        "archetype": "duplicate/prior-art",
        "likely_objection": (
            "Defenders may argue the issue is a duplicate, prior public art, acknowledged risk, or the same one-fix root cause as another report."
        ),
        "evidence_gap": (
            "The packet needs the nearest-prior comparison and a precise one-fix/root-cause distinction."
        ),
        "rebuttal_strategy": (
            "Cite the closest prior report or audit note, then distinguish vulnerable function, asset, victim, trigger, fix, and impact."
        ),
        "kill_condition": (
            "Drop if the same fix would remediate the same root cause and impact already disclosed or reported."
        ),
        "checklist": (
            "List closest prior reports, audit notes, and public issues.",
            "State whether one fix patches both issues.",
            "Distinguish trigger, vulnerable function, victim, and impact.",
            "Mark acknowledged/wont-fix status if present.",
        ),
        "trigger_terms": (
            "duplicate",
            "already reported",
            "prior art",
            "previous audit",
            "public disclosure",
            "known issue",
            "acknowledged",
            "wont-fix",
            "won't fix",
            "same root cause",
            "same issue",
            "same bug",
            "same fix",
            "one fix",
        ),
        "rebuttal_terms": (
            "distinct root cause",
            "different vulnerable function",
            "different victim",
            "different asset",
            "not same root cause",
            "one-fix distinction",
        ),
    },
    {
        "archetype": "external dependency",
        "likely_objection": (
            "Defenders may argue the failure belongs to an external oracle, relayer, sequencer, bridge, RPC, market, or third-party dependency."
        ),
        "evidence_gap": (
            "The packet needs the protocol trust boundary and proof that in-scope code mishandles dependency output or lacks required validation."
        ),
        "rebuttal_strategy": (
            "Show how production in-scope code consumes the dependency, what invariant it must enforce locally, and the resulting protocol-state impact."
        ),
        "kill_condition": (
            "Drop if the only failing component is external infrastructure and in-scope protocol code honors its documented assumptions."
        ),
        "checklist": (
            "Name the external component and the in-scope consumer.",
            "Quote the assumed trust boundary or integration invariant.",
            "Show the protocol-side missing validation or unsafe fallback.",
            "Prove the resulting on-chain/state-machine impact.",
        ),
        "trigger_terms": (
            "oracle",
            "price feed",
            "chainlink",
            "sequencer",
            "relayer",
            "bridge",
            "rpc",
            "api",
            "off-chain",
            "offchain",
            "third-party",
            "external dependency",
            "validator",
            "mempool",
            "market maker",
            "exchange",
            "keeper network",
        ),
        "rebuttal_terms": (
            "protocol-side validation",
            "in-scope consumer",
            "trust boundary",
            "unsafe fallback",
            "local invariant",
            "production code consumes",
        ),
    },
    {
        "archetype": "missing PoC",
        "likely_objection": (
            "Defenders may argue the claim is hypothetical because the packet lacks a reproducible PoC, trace, or concrete exploit transcript."
        ),
        "evidence_gap": (
            "The packet needs a minimal repro with exact commands, realistic setup, attacker transaction sequence, and pre/post state assertions."
        ),
        "rebuttal_strategy": (
            "Attach the smallest production-path PoC or transcript that starts from normal state and ends with the claimed asset/state delta."
        ),
        "kill_condition": (
            "Do not file as High/Critical if the exploit path remains theoretical, mock-only, synthetic, or unsupported by reproducible evidence."
        ),
        "checklist": (
            "Include exact command(s) to reproduce.",
            "Avoid mocks, synthetic storage, and impossible setup values unless scope allows them.",
            "Show attacker-controlled steps and victim impact assertions.",
            "Attach trace/log snippets with pre/post state.",
        ),
        "trigger_terms": (
            "no poc",
            "poc missing",
            "proof pending",
            "hypothetical",
            "theoretical",
            "cannot reproduce",
            "no concrete exploit",
            "mock",
            "synthetic",
            "test-only",
            "fixture-only",
            "todo",
            "assume",
            "assumed",
            "not implemented",
        ),
        "rebuttal_terms": (
            "poc",
            "repro",
            "reproduce",
            "forge test",
            "go test",
            "trace",
            "transaction",
            "fork test",
            "pre/post",
            "command output",
        ),
    },
)

PROOF_TERMS = (
    "poc",
    "repro",
    "reproduce",
    "forge test",
    "go test",
    "trace",
    "transaction",
    "fork test",
    "pre/post",
    "command output",
    "exploit script",
)
STRONG_IMPACT_TERMS = (
    "drain",
    "steal",
    "theft",
    "freeze",
    "insolvency",
    "liquidation",
    "bad debt",
    "balance delta",
    "value movement",
    "user funds",
    "principal",
    "permanent",
)
PRIOR_CHECK_TERMS = (
    "duplicate",
    "prior art",
    "previous audit",
    "originality",
    "public disclosure",
    "known issue",
    "one-fix",
    "same root cause",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _contains_term(text_norm: str, term: str) -> bool:
    term_norm = _normalize(term)
    return bool(term_norm) and f" {term_norm} " in f" {text_norm} "


def _trim(value: str, limit: int = 360) -> str:
    value = re.sub(r"\s+", " ", value.strip())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _dedupe(values: list[str], limit: int | None = None) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = _trim(str(value), 180)
        if not clean or clean in seen:
            continue
        seen.add(clean)
        result.append(clean)
        if limit is not None and len(result) >= limit:
            break
    return result


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _line_refs_for_terms(text: str, terms: tuple[str, ...], input_label: str) -> tuple[list[str], list[str]]:
    refs: list[str] = []
    signals: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line_norm = _normalize(line)
        if not line_norm:
            continue
        for term in terms:
            if _contains_term(line_norm, term):
                signals.append(term)
                refs.append(f"{input_label}:{line_no}")
    return _dedupe(signals, MAX_SIGNALS), _dedupe(refs, MAX_SOURCE_REFS)


def _extract_source_refs_from_text(text: str) -> list[str]:
    refs: list[str] = []
    for match in FILE_REF_RE.finditer(text):
        path = match.group("path")
        line = match.group("line")
        refs.append(f"{path}:{line}" if line else path)
    return _dedupe(refs, MAX_SOURCE_REFS)


def _extract_source_refs_from_json(value: Any) -> list[str]:
    refs: list[str] = []

    def walk(node: Any, key_hint: str = "") -> None:
        if len(refs) >= MAX_SOURCE_REFS * 3:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                key_l = str(key).lower()
                if key_l in {"source_refs", "sourcerefs", "source_ref", "references", "refs", "evidence_refs"}:
                    walk(child, key_l)
                else:
                    walk(child, key_l if key_l in {"path", "file", "line", "url"} else "")
            return
        if isinstance(node, list):
            for child in node:
                walk(child, key_hint)
            return
        if isinstance(node, str):
            if key_hint in {"source_refs", "sourcerefs", "source_ref", "references", "refs", "evidence_refs", "path", "file", "url"}:
                refs.append(node)
            refs.extend(_extract_source_refs_from_text(node))
            return
        if key_hint == "line" and isinstance(node, int):
            refs.append(str(node))

    walk(value)
    return _dedupe(refs, MAX_SOURCE_REFS)


def _json_to_text(value: Any) -> str:
    parts: list[str] = []

    def walk(node: Any, prefix: str = "") -> None:
        if len("\n".join(parts)) > DEFAULT_MAX_INPUT_CHARS:
            return
        if isinstance(node, dict):
            preferred = [
                "title",
                "severity",
                "summary",
                "description",
                "finding",
                "impact",
                "evidence",
                "poc",
                "proof",
                "rebuttal",
                "source_refs",
            ]
            keys = [key for key in preferred if key in node]
            keys.extend(key for key in node.keys() if key not in set(keys))
            for key in keys:
                child_prefix = f"{prefix}.{key}" if prefix else str(key)
                walk(node.get(key), child_prefix)
            return
        if isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{prefix}[{index}]")
            return
        if node is None:
            return
        if isinstance(node, (str, int, float, bool)):
            label = prefix or "value"
            parts.append(f"{label}: {node}")

    walk(value)
    return "\n".join(parts)


def _load_from_text(raw: str, input_label: str, max_input_chars: int, *, force_json: bool = False) -> LoadedInput:
    stripped = raw.lstrip()
    looks_json = stripped.startswith("{") or stripped.startswith("[")
    if force_json or looks_json:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            if force_json:
                raise SystemExit(f"could not parse JSON input {input_label}: {exc}") from exc
        else:
            text = _json_to_text(payload)
            refs = _extract_source_refs_from_json(payload)
            text_refs = _extract_source_refs_from_text(text)
            refs = _dedupe(refs + text_refs, MAX_SOURCE_REFS)
            truncated = len(text) > max_input_chars
            return LoadedInput(text[:max_input_chars], "json", input_label, refs, truncated)

    refs = _extract_source_refs_from_text(raw)
    truncated = len(raw) > max_input_chars
    return LoadedInput(raw[:max_input_chars], "text", input_label, refs, truncated)


def load_input(path: Path | None, inline_text: str | None, max_input_chars: int) -> LoadedInput:
    if inline_text is not None:
        return _load_from_text(inline_text, "<inline>", max_input_chars)
    if path is None:
        raw = sys.stdin.read()
        return _load_from_text(raw, "<stdin>", max_input_chars)
    if str(path) == "-":
        raw = sys.stdin.read()
        return _load_from_text(raw, "<stdin>", max_input_chars)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"could not read input {path}: {exc}") from exc
    return _load_from_text(raw, str(path), max_input_chars, force_json=path.suffix.lower() == ".json")


def _severity(text: str) -> str | None:
    match = SEVERITY_RE.search(text)
    return match.group(1).lower() if match else None


def _gap_boosts(archetype: str, text_norm: str, severity: str | None) -> tuple[int, list[str]]:
    boosts: list[str] = []
    score = 0
    high_plus = severity in {"high", "critical"}

    if archetype == "missing PoC" and not any(_contains_term(text_norm, term) for term in PROOF_TERMS):
        score += 3 if high_plus else 2
        boosts.append("no reproducible PoC/trace signal found")
    if archetype == "insufficient-impact" and high_plus and not any(
        _contains_term(text_norm, term) for term in STRONG_IMPACT_TERMS
    ):
        score += 2
        boosts.append("high-plus claim lacks strong impact signal")
    if archetype == "duplicate/prior-art" and high_plus and not any(
        _contains_term(text_norm, term) for term in PRIOR_CHECK_TERMS
    ):
        score += 1
        boosts.append("no prior-art/originality check signal found")
    if archetype == "trusted-admin" and any(
        _contains_term(text_norm, term) for term in ("pause", "upgrade", "governance", "admin")
    ) and not any(_contains_term(text_norm, term) for term in ("permissionless", "no admin action", "any user")):
        score += 2
        boosts.append("privileged-role term lacks permissionless rebuttal signal")
    if archetype == "intended-design" and any(
        _contains_term(text_norm, term) for term in ("missing check", "does not validate", "omitted check")
    ) and not any(_contains_term(text_norm, term) for term in ("outside the documented design", "strictly stronger")):
        score += 1
        boosts.append("omission claim lacks design-boundary rebuttal signal")
    return score, boosts


def _score_archetype(defn: dict[str, Any], text: str, severity: str | None) -> dict[str, Any]:
    text_norm = _normalize(text)
    trigger_terms: tuple[str, ...] = tuple(defn["trigger_terms"])
    rebuttal_terms: tuple[str, ...] = tuple(defn["rebuttal_terms"])
    matched = [term for term in trigger_terms if _contains_term(text_norm, term)]
    rebuttals = [term for term in rebuttal_terms if _contains_term(text_norm, term)]
    gap_score, gap_signals = _gap_boosts(str(defn["archetype"]), text_norm, severity)
    score = len(matched) * 3 + gap_score
    if rebuttals and score > 0:
        score = max(0, score - min(len(rebuttals), 3))
    confidence = 0.18 if score == 0 else min(0.95, round(0.34 + (score / 20.0), 2))
    return {
        "score": score,
        "confidence": confidence,
        "matched_signals": _dedupe(matched + gap_signals, MAX_SIGNALS),
        "rebuttal_signals": _dedupe(rebuttals, MAX_SIGNALS),
    }


def build_simulation(
    loaded: LoadedInput,
    *,
    max_narratives: int = DEFAULT_MAX_NARRATIVES,
    generated_at: str | None = None,
) -> dict[str, Any]:
    bounded_max = max(1, min(int(max_narratives), MAX_NARRATIVES_LIMIT))
    severity = _severity(loaded.text)
    scored: list[dict[str, Any]] = []

    for order, defn in enumerate(ARCHETYPES, start=1):
        scoring = _score_archetype(defn, loaded.text, severity)
        signals, signal_refs = _line_refs_for_terms(loaded.text, tuple(defn["trigger_terms"]), loaded.input_label)
        source_refs = _dedupe(loaded.source_refs + signal_refs + [loaded.input_label], MAX_SOURCE_REFS)
        row = {
            "archetype": defn["archetype"],
            "score": scoring["score"],
            "confidence": scoring["confidence"],
            "matched": scoring["score"] > 0,
            "likely_objection": _trim(defn["likely_objection"]),
            "evidence_gap": _trim(defn["evidence_gap"]),
            "rebuttal_strategy": _trim(defn["rebuttal_strategy"]),
            "rebuttal_checklist": list(defn["checklist"][:MAX_CHECKLIST_ITEMS]),
            "kill_condition": _trim(defn["kill_condition"]),
            "matched_signals": _dedupe(scoring["matched_signals"] + signals, MAX_SIGNALS),
            "rebuttal_signals_present": scoring["rebuttal_signals"],
            "source_refs": source_refs,
            "_order": order,
        }
        scored.append(row)

    scored.sort(key=lambda row: (-int(row["score"]), int(row["_order"]), str(row["archetype"])))
    narratives: list[dict[str, Any]] = []
    for rank, row in enumerate(scored[:bounded_max], start=1):
        row = dict(row)
        row.pop("_order", None)
        row["rank"] = rank
        narratives.append(row)

    all_refs: list[str] = []
    for row in narratives:
        all_refs.extend(row["source_refs"])

    return {
        "schema": SCHEMA_VERSION,
        "mode": MODE,
        "advisory_only": True,
        "provider_backed": False,
        "provider_call_made": False,
        "predicted_triager_verdict": None,
        "submission_clearance": False,
        "language_boundary": (
            "Advisory defender-objection forecast only; not a triager verdict, not approval, and not submission clearance."
        ),
        "generated_at": generated_at or _utc_now(),
        "input": {
            "format": loaded.input_format,
            "label": loaded.input_label,
            "sha256": _sha256_text(loaded.text),
            "chars_analyzed": len(loaded.text),
            "truncated": loaded.truncated,
            "claimed_severity": severity,
        },
        "bounds": {
            "max_narratives": bounded_max,
            "max_input_chars_default": DEFAULT_MAX_INPUT_CHARS,
            "max_source_refs_per_narrative": MAX_SOURCE_REFS,
            "max_signals_per_narrative": MAX_SIGNALS,
        },
        "defender_narratives": narratives,
        "source_refs": _dedupe(all_refs, MAX_SOURCE_REFS),
        "summary": (
            "Deterministic stdlib-only simulation of plausible defender objections. "
            "Use it to strengthen a draft before filing; it is advisory and not a verdict."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="finding/evidence packet path, JSON/text, or '-' for stdin")
    parser.add_argument("--text", help="inline finding/evidence text")
    parser.add_argument("--max-narratives", type=int, default=DEFAULT_MAX_NARRATIVES)
    parser.add_argument("--max-input-chars", type=int, default=DEFAULT_MAX_INPUT_CHARS)
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = parser.parse_args(argv)

    if args.text is not None and args.input is not None:
        parser.error("provide either --text or input path, not both")
    max_input_chars = max(1_000, min(int(args.max_input_chars), 200_000))
    loaded = load_input(args.input, args.text, max_input_chars)
    packet = build_simulation(loaded, max_narratives=args.max_narratives)
    print(json.dumps(packet, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
