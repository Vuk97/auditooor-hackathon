#!/usr/bin/env python3
"""HACKERMAN_V3 Lane L2 - system-model dispatch gate.

A High/Critical hunt worker packet must carry the relevant slice of the system
model (the components, defenses, and invariants its lane touches) - the same
way Lane J's worker packet must carry an MCP lesson-pack receipt. Without a
shared system model, agents dispatched at a queue of detector hits hunt blind
and re-derive "what does this component do" N times, and the architectural
Criticals (composition / trust-boundary / invariant-violation bugs) never get
looked for because no detector shape names them.

This is a standalone gate (it does NOT edit ``v3-worker-packet-builder.py``).
It mirrors that builder's lesson-pack-blocker pattern (``_lesson_pack_blockers``):

  - It only enforces for High/Critical severity. Medium/Low packets pass with a
    typed ``severity_not_high_critical`` verdict - never blocked.
  - A High/Critical packet PASSES if it carries EITHER:
      (a) a system-model slice - a ``system_model_slice`` object, or a
          ``system_model.json``-pointing entry in its source/context refs, with
          at least one of components / protocol_owned_defenses / invariants; OR
      (b) a typed ``no_system_model_reason`` starting with the
          ``NO_SYSTEM_MODEL_REASON:`` prefix and carrying a real reason.
  - Otherwise it FAILS with ``missing_system_model_slice``.

Acceptance (from the Lane L spec): a High/Critical hunt worker packet fails
dispatch lint if it claims a target surface with no system-model slice or a
typed ``NO_SYSTEM_MODEL_REASON``.

Usage:
    python3 tools/system-model-dispatch-gate.py --packet <packet.json> [--strict]
    python3 tools/system-model-dispatch-gate.py --packet <packet.json> --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.system_model_dispatch_gate.v1"

HIGH_CRITICAL_RE = re.compile(r"^\s*(high|critical|crit)\b", re.IGNORECASE)
NO_SYSTEM_MODEL_REASON_PREFIX = "NO_SYSTEM_MODEL_REASON:"

# Keys under which a packet may carry the system-model slice directly.
_SLICE_KEYS = ("system_model_slice", "system_model")
# Sub-fields that make a slice "real" (at least one must be present + non-empty).
_SLICE_CONTENT_KEYS = (
    "components",
    "protocol_owned_defenses",
    "claimed_invariants",
    "invariants",
    "trust_boundaries",
    "state_machines",
)


def _is_high_critical(severity: str) -> bool:
    return bool(HIGH_CRITICAL_RE.match(severity or ""))


def _nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, list, dict, tuple, set)):
        return len(value) > 0
    return True


def _has_inline_slice(packet: dict[str, Any]) -> tuple[bool, str]:
    """A directly-embedded system_model_slice object with real content."""
    for key in _SLICE_KEYS:
        slice_obj = packet.get(key)
        if isinstance(slice_obj, dict):
            for content_key in _SLICE_CONTENT_KEYS:
                if _nonempty(slice_obj.get(content_key)):
                    return True, f"inline `{key}.{content_key}`"
    return False, ""


def _has_slice_reference(packet: dict[str, Any]) -> tuple[bool, str]:
    """A source/context ref pointing at a system_model.json artifact."""
    haystacks: list[str] = []
    for key in ("source_files", "mcp_context_refs", "context_refs"):
        value = packet.get(key)
        if isinstance(value, list):
            for item in value:
                haystacks.append(json.dumps(item, sort_keys=True).lower())
        elif isinstance(value, str):
            haystacks.append(value.lower())
    for hay in haystacks:
        if "system_model.json" in hay or "system_model.md" in hay or "auditooor.system_model" in hay:
            return True, "reference to a system_model artifact in packet refs"
    return False, ""


def _typed_no_model_reason(packet: dict[str, Any]) -> tuple[bool, str]:
    reason = packet.get("no_system_model_reason") or packet.get("NO_SYSTEM_MODEL_REASON") or ""
    if not isinstance(reason, str):
        return False, ""
    reason = reason.strip()
    if reason.startswith(NO_SYSTEM_MODEL_REASON_PREFIX) and len(reason) > len(
        NO_SYSTEM_MODEL_REASON_PREFIX
    ):
        return True, reason
    return False, ""


def evaluate_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Return a structured gate verdict for one worker packet."""
    severity = str(packet.get("severity") or "")
    packet_id = str(packet.get("packet_id") or packet.get("title") or "<unnamed>")

    if not _is_high_critical(severity):
        return {
            "schema": SCHEMA,
            "packet_id": packet_id,
            "severity": severity,
            "verdict": "pass",
            "code": "severity_not_high_critical",
            "detail": "system-model slice not required below High/Critical severity",
            "blocked": False,
        }

    inline_ok, inline_detail = _has_inline_slice(packet)
    if inline_ok:
        return {
            "schema": SCHEMA,
            "packet_id": packet_id,
            "severity": severity,
            "verdict": "pass",
            "code": "system_model_slice_present",
            "detail": inline_detail,
            "blocked": False,
        }

    ref_ok, ref_detail = _has_slice_reference(packet)
    if ref_ok:
        return {
            "schema": SCHEMA,
            "packet_id": packet_id,
            "severity": severity,
            "verdict": "pass",
            "code": "system_model_slice_present",
            "detail": ref_detail,
            "blocked": False,
        }

    typed_ok, typed_reason = _typed_no_model_reason(packet)
    if typed_ok:
        return {
            "schema": SCHEMA,
            "packet_id": packet_id,
            "severity": severity,
            "verdict": "pass",
            "code": "typed_no_system_model_reason",
            "detail": typed_reason[:300],
            "blocked": False,
        }

    return {
        "schema": SCHEMA,
        "packet_id": packet_id,
        "severity": severity,
        "verdict": "fail",
        "code": "missing_system_model_slice",
        "detail": (
            "High/Critical worker packet must carry a system-model slice "
            "(`system_model_slice` with components/defenses/invariants, or a "
            "source/context ref to a `system_model.json` artifact) or a typed "
            f"`{NO_SYSTEM_MODEL_REASON_PREFIX}<reason>`."
        ),
        "blocked": True,
    }


def _load_packet(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("packet must be a JSON object")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="HACKERMAN_V3 Lane L2 - system-model dispatch gate."
    )
    parser.add_argument("--packet", required=True, help="Worker packet JSON path")
    parser.add_argument("--json", action="store_true", help="Print the verdict as JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when the gate verdict is fail (blocked)",
    )
    args = parser.parse_args(argv)

    packet_path = Path(args.packet).expanduser()
    if not packet_path.is_file():
        print(f"system-model-dispatch-gate: packet not found: {packet_path}", file=sys.stderr)
        return 2
    try:
        packet = _load_packet(packet_path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"system-model-dispatch-gate: bad packet: {exc}", file=sys.stderr)
        return 2

    verdict = evaluate_packet(packet)

    if args.json:
        print(json.dumps(verdict, indent=2, sort_keys=True))
    else:
        print(
            f"system-model-dispatch-gate: {verdict['verdict'].upper()} "
            f"[{verdict['code']}] {verdict['packet_id']} - {verdict['detail']}"
        )

    if args.strict and verdict["blocked"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
