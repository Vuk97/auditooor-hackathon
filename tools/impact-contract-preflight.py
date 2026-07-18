#!/usr/bin/env python3
"""impact-contract-preflight.py - strict route gate for impact evidence.

The gate blocks filing/promotion routes when an artifact is proof-grade but
does not carry an explicit impact contract. Planning artifacts may bypass the
gate advisory-only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional


SCHEMA_VERSION = "auditooor.impact_contract_preflight.v1"

ACTOR_KEYS = (
    "victim",
    "attacker",
    "protocol",
    "impacted-contract",
    "impacted-asset",
    "impacted-surface",
)

ANCHOR_KEYS = (
    "source-proof",
    "harness-scaffold",
    "exploit-memory",
    "fork-replay",
    "live-proof",
    "proof-anchor",
    "impact-proof",
)

L27_DIRECTIVE_KEYS = (
    "selected-impact",
    "severity-tier",
    "listed-impact-proven",
    "evidence-class",
    "oos-traps",
    "stop-condition",
)

PLACEHOLDER_TOKENS = {
    "",
    "?",
    "missing",
    "n/a",
    "na",
    "none",
    "not available",
    "tbd",
    "todo",
    "unknown",
    "unset",
}

LABEL_ALIASES = {
    "actor": "victim",
    "victim": "victim",
    "attacker": "attacker",
    "protocol": "protocol",
    "contract": "impacted-contract",
    "impacted contract": "impacted-contract",
    "impacted-contract": "impacted-contract",
    "asset": "impacted-asset",
    "impacted asset": "impacted-asset",
    "impacted-asset": "impacted-asset",
    "surface": "impacted-surface",
    "impacted surface": "impacted-surface",
    "impacted-surface": "impacted-surface",
    "source": "source-proof",
    "source proof": "source-proof",
    "source-proof": "source-proof",
    "harness": "harness-scaffold",
    "harness scaffold": "harness-scaffold",
    "harness-scaffold": "harness-scaffold",
    "exploit memory": "exploit-memory",
    "exploit-memory": "exploit-memory",
    "exploit path memory": "exploit-memory",
    "fork replay": "fork-replay",
    "fork-replay": "fork-replay",
    "live proof": "live-proof",
    "live-proof": "live-proof",
    "proof anchor": "proof-anchor",
    "proof-anchor": "proof-anchor",
    "impact proof": "impact-proof",
    "impact-proof": "impact-proof",
    "selected impact": "selected-impact",
    "selected-impact": "selected-impact",
    "listed impact": "selected-impact",
    "listed-impact": "selected-impact",
    "severity tier": "severity-tier",
    "severity-tier": "severity-tier",
    "severity": "severity-tier",
    "listed impact proven": "listed-impact-proven",
    "listed-impact-proven": "listed-impact-proven",
    "impact proven": "listed-impact-proven",
    "evidence class": "evidence-class",
    "evidence-class": "evidence-class",
    "oos traps": "oos-traps",
    "oos-traps": "oos-traps",
    "oos trap": "oos-traps",
    "forbidden assumptions": "oos-traps",
    "stop condition": "stop-condition",
    "stop-condition": "stop-condition",
    "stop conditions": "stop-condition",
    "artifact class": "artifact-class",
    "artifact-class": "artifact-class",
    "kind": "artifact-class",
}

PLANNING_KINDS = {
    "planning",
    "poc_plan",
    "candidate_plan",
    "capability_gap",
    "needs_verify",
}

PROOF_KINDS = {
    "candidate_finding",
    "finding",
    "paste_ready",
    "proof",
    "submission",
}


def _normalize_label(raw: str) -> str:
    cleaned = re.sub(r"[*`]+", "", raw).strip().lower()
    cleaned = cleaned.replace("_", " ")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return LABEL_ALIASES.get(cleaned, cleaned.replace(" ", "-"))


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower().strip(" .,:;`*_")
    return normalized in PLACEHOLDER_TOKENS


def _extract_markdown_section(text: str, heading: str) -> str:
    capture = False
    lines: list[str] = []
    for line in text.splitlines():
        # Tolerate a trailing bold close (`**`) and/or a parenthesised suffix
        # such as "(Rule 40)" after the heading text. Without this relaxation a
        # heading like "## Impact Contract (Rule 40)" or "## **Impact Contract**"
        # silently fails to match, dropping the whole section (43-fail cliff).
        if re.match(
            rf"^##+\s+\**\s*{re.escape(heading)}\s*\**\s*(?:\([^)]*\)\s*)?$",
            line,
            re.IGNORECASE,
        ):
            capture = True
            continue
        if capture and re.match(r"^##+\s+", line):
            break
        if capture:
            lines.append(line)
    return "\n".join(lines).strip()


def _parse_markdown_fields(section: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    raw_lines = section.splitlines()
    i = 0
    while i < len(raw_lines):
        raw_line = raw_lines[i]
        line = raw_line.strip()
        if not line:
            i += 1
            continue
        line = re.sub(r"^[-*]\s*", "", line)
        match = re.match(r"([^:]+):\s*(.*)$", line)
        if not match:
            i += 1
            continue
        label = _normalize_label(match.group(1))
        value = match.group(2).strip()
        if not value:
            collected: list[str] = []
            j = i + 1
            while j < len(raw_lines):
                next_line = raw_lines[j]
                next_stripped = next_line.strip()
                if not next_stripped:
                    j += 1
                    continue
                normalized_next = re.sub(r"^[-*]\s*", "", next_stripped)
                if re.match(r"[^:]+:\s*", normalized_next):
                    break
                if next_stripped.startswith(("-", "*")) or next_line.startswith((" ", "\t")):
                    collected.append(re.sub(r"^[-*]\s*", "", next_stripped))
                    j += 1
                    continue
                break
            value = "; ".join(collected)
        if label and value and label not in fields:
            fields[label] = value
        i += 1
    return fields


def _stringify_contract_value(value: Any) -> str:
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    if isinstance(value, list):
        parts = [
            str(item).strip()
            for item in value
            if isinstance(item, (str, int, float)) and str(item).strip()
        ]
        return ", ".join(parts)
    return ""


def _extract_json_contract(payload: dict[str, Any]) -> dict[str, str]:
    meta = payload.get("impact_contract")
    if not isinstance(meta, dict):
        return {}
    fields: dict[str, str] = {}
    for raw_key, value in meta.items():
        key = _normalize_label(str(raw_key))
        rendered = _stringify_contract_value(value)
        if rendered:
            fields[key] = rendered
    return fields


def _directive_present(key: str, fields: dict[str, str]) -> bool:
    value = fields.get(key, "")
    if _is_placeholder(value):
        return False
    if key == "listed-impact-proven":
        lowered = value.strip().lower()
        return lowered in {"true", "yes", "y", "1", "proven"} or lowered.startswith(
            ("true ", "true-", "true:", "true -")
        )
    if key == "severity-tier":
        return value.strip().lower().rstrip(".,:;") in {
            "critical",
            "high",
            "medium",
            "low",
        }
    return True


def _classify_artifact(*, payload: Optional[dict[str, Any]], text: str) -> str:
    if isinstance(payload, dict):
        kind = str(payload.get("kind") or payload.get("artifact_class") or "").strip().lower()
        if kind in PLANNING_KINDS:
            return "planning"
        if kind in PROOF_KINDS:
            return "proof"
        meta = payload.get("impact_contract")
        if isinstance(meta, dict):
            declared = str(meta.get("artifact_class") or "").strip().lower()
            if declared in PLANNING_KINDS:
                return "planning"
            if declared in PROOF_KINDS:
                return "proof"

    lower = text.lower()
    if (
        "proof-poor" in lower
        or "kind: poc_plan" in lower
        or "# swarm candidate plans" in lower
        or "recommended next step: execute live checks" in lower
    ):
        return "planning"
    return "proof"


def _load_json_payload(path: Path, text: str) -> Optional[dict[str, Any]]:
    if path.suffix.lower() != ".json":
        return None
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON artifact: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("JSON artifact root must be an object")
    return loaded


def build_packet(
    *,
    path: Optional[Path] = None,
    text: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
    route: str,
) -> dict[str, Any]:
    if text is None:
        if path is None:
            raise ValueError("either path or text must be provided")
        text = path.read_text(encoding="utf-8", errors="replace")

    if payload is None and path is not None:
        payload = _load_json_payload(path, text)

    artifact_class = _classify_artifact(payload=payload, text=text)
    fields = _extract_json_contract(payload) if isinstance(payload, dict) else {}
    if not fields:
        fields = _parse_markdown_fields(_extract_markdown_section(text, "Impact Contract"))

    actor_fields = sorted(
        key for key in ACTOR_KEYS if key in fields and not _is_placeholder(fields[key])
    )
    anchor_fields = sorted(
        key for key in ANCHOR_KEYS if key in fields and not _is_placeholder(fields[key])
    )
    directive_fields = sorted(
        key for key in L27_DIRECTIVE_KEYS if key in fields and _directive_present(key, fields)
    )
    missing_directives = sorted(set(L27_DIRECTIVE_KEYS) - set(directive_fields))
    explicit = bool(actor_fields and anchor_fields and not missing_directives)
    missing: list[str] = []
    if not actor_fields:
        missing.append("impacted actor/surface (victim/protocol/contract/asset)")
    if not anchor_fields:
        missing.append("evidence anchor (source-proof/harness-scaffold/exploit-memory)")
    if missing_directives:
        missing.append("L27 directives (" + ", ".join(missing_directives) + ")")

    if explicit:
        code = "impact-contract-explicit"
        blocked = False
        advisory_bypass = False
        summary = "explicit impact contract with L27 directives present"
    elif artifact_class == "planning":
        code = "planning-artifact-advisory-bypass"
        blocked = False
        advisory_bypass = True
        summary = "planning artifact bypassed; route remains advisory"
    else:
        code = "impact-contract-missing"
        blocked = True
        advisory_bypass = False
        summary = "missing explicit impact contract or L27 directive coverage"

    return {
        "schema_version": SCHEMA_VERSION,
        "route": route,
        "artifact_path": str(path) if path is not None else None,
        "artifact_class": artifact_class,
        "impact_contract": {
            "explicit": explicit,
            "fields": fields,
            "actor_fields_present": actor_fields,
            "anchor_fields_present": anchor_fields,
            "l27_directive_fields_present": directive_fields,
            "missing_l27_directives": missing_directives,
            "missing": missing,
        },
        "decision": {
            "code": code,
            "blocked": blocked,
            "advisory_bypass": advisory_bypass,
            "summary": summary,
        },
    }


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Gate filing/promotion on explicit impact-contract evidence."
    )
    parser.add_argument("artifact", type=Path, help="Markdown or JSON artifact to inspect")
    parser.add_argument(
        "--route",
        choices=("filing", "promotion"),
        default="filing",
        help="Route being guarded",
    )
    args = parser.parse_args(argv)

    try:
        packet = build_packet(path=args.artifact.resolve(), route=args.route)
    except OSError as exc:
        print(json.dumps({"error": f"unreadable artifact: {exc}"}), file=sys.stderr)
        return 1
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1

    print(json.dumps(packet, indent=2, sort_keys=True))
    return 2 if packet["decision"]["blocked"] else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
