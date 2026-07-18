"""
dos_cap_unbounded_or_sticky_state_fire9.py

Flags Rust intake paths that write caller-controlled entries into a global
pending collection while a collection length or cap gate can reject future
actions. This is the Fire9 Rust lift for the `dos-cap-weakening` shape where a
global queue/map slot can be filled by unrelated callers.

This intentionally does not reimplement Fire7 callback logic. It also leaves
deadline and simple global-flag cases to
`ineffective_deadline_or_global_flag_permanent_dos.py`.

Source-backed anchors:
- dsl_pattern/glider-state-array-unbounded-no-remove
- dsl_pattern/unbounded-user-array-dos-via-third-party-push
- corpus-mined:slice_af.md:L131:S73:0aff25870c26
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    source_nocomment,
)


DETECTOR_ID = "rust_wave1.dos_cap_unbounded_or_sticky_state_fire9"

_STATE_WORD = (
    r"(?:pending|queue|queued|request|requests|reservation|reservations|"
    r"claim|claims|withdrawal|withdrawals|order|orders|job|jobs|task|tasks|"
    r"message|messages|creation|creations|registration|registrations|"
    r"intake|intakes|work|work_items)"
)

_STATE_NAME_RE = re.compile(_STATE_WORD, re.IGNORECASE)

_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?P<target>[A-Za-z_][A-Za-z0-9_\.]*)\s*\.\s*"
    r"(?P<method>set|insert|push|push_back|append|enqueue)\s*\("
)

_LEN_GATE_RE = re.compile(
    rf"(?is)\bif\s+[^{{}};\n]{{0,220}}?"
    r"(?P<target>[A-Za-z_][A-Za-z0-9_\.]*)\s*\.\s*len\s*\(\s*\)"
    r"(?:\s+as\s+[A-Za-z_][A-Za-z0-9_:<>]*)?"
    r"[^{};\n]{0,160}?(?:>=|>|==)\s*[^{};\n]{0,160}?"
    r"(?:max|cap|limit|quota|MAX|CAP|LIMIT|QUOTA)"
    r"[^{};\n]*\{[^{}]{0,240}?"
    r"(?:return\s+Err|Err\s*\(|panic!|return\s+false|return\s+None)"
)

_SAFE_INTAKE_RE = re.compile(
    r"(?is)\b(?:"
    r"require_auth|has_auth|only_owner|only_admin|ensure_owner|ensure_admin|"
    r"assert_owner|assert_admin|trusted_factory|"
    r"pay_fee|charge_fee|require_fee|collect_fee|transfer_fee|"
    r"required_deposit|bond_required|stake_required|escrow_deposit|"
    r"rate_limit|cooldown|throttle|requests_per_block|"
    r"per_user|per_sender|per_caller|user_quota|caller_quota|"
    r"contains_key|already_pending|dedup|unique_request"
    r")\b"
)

_INTAKE_NAME_RE = re.compile(
    r"(?i)^(?:submit|request|create|register|schedule|enqueue|add|open|"
    r"deposit|mint|start|append|track|reserve|claim)"
)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _target_aliases(target: str) -> set[str]:
    aliases = {target}
    if "." in target:
        aliases.add(target.rsplit(".", 1)[-1])
    return {alias for alias in aliases if alias}


def _has_len_gate_for_target(text: str, target: str) -> bool:
    aliases = _target_aliases(target)
    for gate in _LEN_GATE_RE.finditer(text):
        gate_target = gate.group("target")
        if not _STATE_NAME_RE.search(gate_target):
            continue
        if gate_target in aliases or gate_target.rsplit(".", 1)[-1] in aliases:
            return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    src_nc = source_nocomment(source)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _INTAKE_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        raw_body = body_text_nocomment(body, source)
        if _SAFE_INTAKE_RE.search(raw_body):
            continue

        body_line, _ = line_col(body)

        for write in _STATE_WRITE_RE.finditer(raw_body):
            target = write.group("target")
            if not _STATE_NAME_RE.search(target):
                continue
            if not (
                _has_len_gate_for_target(raw_body, target)
                or _has_len_gate_for_target(src_nc, target)
            ):
                continue

            write_line = _line_for_offset(body_line, raw_body, write.start())
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "medium",
                    "line": write_line,
                    "col": 0,
                    "snippet": snippet_of(fn, source),
                    "message": (
                        f"fn `{name}` writes into global pending state "
                        f"`{target}` while a collection length or cap gate "
                        "can reject future actions. Without auth, fee, "
                        "rate-limit, or per-user bounding, one caller can "
                        "fill global slots and block unrelated users "
                        "(dos-cap-weakening; Fire9 unbounded-or-sticky-state)."
                    ),
                }
            )
            break

    return hits
