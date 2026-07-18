"""
ineffective_deadline_or_global_flag_permanent_dos.py

Flags Rust/Soroban code where a one-shot or user-controlled global flag,
deadline, or cap is written into persistent state and later used as a
global processing gate. A caller can permanently halt future processing,
expire it immediately, or force a zero cap.

Class: ineffective-deadline-or-global-flag-permanent-dos.
Attack-class suggestion: dos-cap-weakening.
"""

from __future__ import annotations

import re

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_GLOBAL_KEY_RE = re.compile(
    r"\b(paused|pause|halted|halt|stopped|disabled|frozen|closed|blocked|"
    r"initialized|deadline|expiry|expires_at|cap|limit|max_(?:items|requests|"
    r"orders|processing|pending)|processing_cap|global_cap|batch_cap)\b",
    re.IGNORECASE,
)

_ENTRY_FN_RE = re.compile(
    r"\b(?:pub\s+)?fn\s+"
    r"(initialize|init|configure|set_\w+|open|start|close|pause|halt|"
    r"disable|freeze|finalize|submit_\w+|schedule_\w+)\s*\(([^)]*)\)"
    r"\s*(?:->\s*[^{]+)?\{(?P<body>[\s\S]*?)\n\s*\}",
    re.IGNORECASE,
)

_PROCESS_FN_RE = re.compile(
    r"\b(?:pub\s+)?fn\s+"
    r"(process|execute|settle|finalize|claim|withdraw|dispatch|consume|"
    r"handle|run|drain|fill)(?:_\w+)?\s*\(([^)]*)\)"
    r"\s*(?:->\s*[^{]+)?\{(?P<body>[\s\S]*?)\n\s*\}",
    re.IGNORECASE,
)

_PERSISTENT_WRITE_RE = re.compile(
    r"(?:"
    r"(?:self\.)?(?P<field>paused|pause|halted|halt|stopped|disabled|frozen|"
    r"closed|blocked|initialized|deadline|expiry|expires_at|cap|limit|"
    r"max_\w+|processing_cap|global_cap|batch_cap|owner|admin)\s*=\s*(?P<value>[^;\n]+)"
    r"|"
    r"\.set\s*\([^;]*?(?P<key>paused|pause|halted|halt|stopped|disabled|frozen|"
    r"closed|blocked|initialized|deadline|expiry|expires_at|cap|limit|"
    r"max_\w+|processing_cap|global_cap|batch_cap|owner|admin)[^;]*?,\s*&?(?P<store_value>[^);\n]+)"
    r")",
    re.IGNORECASE,
)

_BLOCKING_GATE_RE = re.compile(
    r"(?:"
    r"if\s+[^{};\n]*(paused|pause|halted|halt|stopped|disabled|frozen|closed|"
    r"blocked|initialized)\b[^{};\n]*\{[^{}]{0,180}?"
    r"(return\s+Err|panic!|return\s+None|return\s+false)"
    r"|"
    r"if\s+[^{};\n]*(now|timestamp|ledger|block_time|current_time)[^{};\n]*"
    r"(>|>=)\s*[^{};\n]*(deadline|expiry|expires_at)\b[^{};\n]*\{"
    r"[^{}]{0,180}?(return\s+Err|panic!|return\s+None|return\s+false)"
    r"|"
    r"if\s+[^{};\n]*(requested|amount|items|orders|pending|count|batch|"
    r"queue_len|len\s*\(\s*\))[^{};\n]*(>|>=)\s*[^{};\n]*"
    r"(cap|limit|max_\w+|processing_cap|global_cap|batch_cap)\b[^{};\n]*"
    r"\{[^{}]{0,180}?(return\s+Err|panic!|return\s+None|return\s+false)"
    r")",
    re.IGNORECASE,
)

_SAFE_RE = re.compile(
    r"\b(require_auth|has_auth|only_owner|only_admin|admin\.require_auth|"
    r"owner\.require_auth|governance|access_control|ensure_owner|ensure_admin|"
    r"assert_owner|assert_admin|unpause|resume|reopen|extend_deadline|"
    r"increase_cap|reset_cap|clear_pause|clear_halt|can_unblock|reconfigure)"
    r"\b",
    re.IGNORECASE,
)

_AGGREGATE_DOS_RE = re.compile(
    r"\b(total_needed|total_required|aggregate_needed|aggregate_required|"
    r"aggregate_amount|total_pending|sum_(?:orders|items|requests|listings)|"
    r"total_for_\w+|pending_by_batch|request_reservations|reserved_for_request)\b",
    re.IGNORECASE,
)

_CALLER_VALUE_RE = re.compile(
    r"\b(admin|owner|caller|invoker|user_|_user|params\.|input|requested|amount|"
    r"deadline|expiry|expires_at|cap|limit|max_|block_timestamp|timestamp|now|"
    r"env\.ledger\(\)\.timestamp|ledger)\b",
    re.IGNORECASE,
)

_INEFFECTIVE_DEADLINE_RE = re.compile(
    r"\bfn\s+\w+\s*\([^)]*(?:user_deadline|caller_deadline|_user_deadline|"
    r"deadline)\s*:[^)]*\)\s*(?:->\s*[^{]+)?\{[\s\S]{0,900}?"
    r"(?:let\s+deadline\s*=\s*(?:block_timestamp|now\s*\(\s*\)|"
    r"self\.get_block_timestamp\s*\(\s*\)|env\.ledger\(\)\.timestamp\s*\(\s*\))|"
    r"\w+\s*\.[A-Za-z_]\w*\s*\([^;]*?(?:block_timestamp|now\s*\(\s*\)|"
    r"env\.ledger\(\)\.timestamp\s*\(\s*\)))[\s\S]{0,500}?"
    r"(?:if\s+deadline\s*<\s*(?:block_timestamp|now\s*\(\s*\)|"
    r"self\.get_block_timestamp\s*\(\s*\)|env\.ledger\(\)\.timestamp\s*\(\s*\))|"
    r"Ok\s*\()",
    re.IGNORECASE,
)

_ONE_SHOT_INIT_CONTROL_RE = re.compile(
    r"\bpub\s+fn\s+(?:initialize|init|setup)\s*\([^)]*(?:owner|admin)[^)]*\)"
    r"\s*(?:->\s*[^{]+)?\{[\s\S]{0,500}?"
    r"(?:\.set\s*\([^;]*?(?:owner|admin)[^;]*?,\s*&?(?:_?owner|_?admin|"
    r"owner|admin|caller|env\.invoker\s*\(\s*\))|"
    r"(?:owner|admin)\s*=\s*(?:_?owner|_?admin|caller|env\.invoker\s*\(\s*\)))",
    re.IGNORECASE,
)

_INIT_GUARD_RE = re.compile(
    r"\b(?:has\s*\(|contains_key|already_initialized|initialized|require_auth|"
    r"only_owner|only_admin|trusted_factory|expected_deployer)\b",
    re.IGNORECASE,
)


def _strip_comments(text: str) -> str:
    text = _LINE_COMMENT_RE.sub("", text)
    text = _BLOCK_COMMENT_RE.sub("", text)
    return text


def _line_for(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def _snippet(text: str, offset: int, length: int = 180) -> str:
    return " ".join(text[offset: offset + length].split())


def _has_user_controlled_global_write(body: str) -> re.Match[str] | None:
    for match in _PERSISTENT_WRITE_RE.finditer(body):
        value = match.group("value") or match.group("store_value") or ""
        field = match.group("field") or match.group("key") or ""
        if not _GLOBAL_KEY_RE.search(field):
            continue
        if _CALLER_VALUE_RE.search(value) or value.strip() in {"true", "false", "0", "0u64", "0u128"}:
            return match
    return None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_comments(text)

    if _AGGREGATE_DOS_RE.search(code):
        return hits

    ineffective_deadline = _INEFFECTIVE_DEADLINE_RE.search(code)
    if ineffective_deadline:
        line = _line_for(code, ineffective_deadline.start())
        hits.append({
            "severity": "high",
            "line": line,
            "col": 0,
            "snippet": _snippet(code, ineffective_deadline.start()),
            "message": (
                f"{filepath}: detected a user deadline path that substitutes "
                f"the current block or ledger timestamp, making the deadline "
                f"gate ineffective. Stale or caller-shaped work can bypass "
                f"the intended cap on execution lifetime "
                f"(ineffective-deadline-or-global-flag-permanent-dos). "
                f"Attack-class suggestion: dos-cap-weakening."
            ),
        })
        return hits

    one_shot_init = _ONE_SHOT_INIT_CONTROL_RE.search(code)
    if one_shot_init and not _INIT_GUARD_RE.search(code):
        line = _line_for(code, one_shot_init.start())
        hits.append({
            "severity": "high",
            "line": line,
            "col": 0,
            "snippet": _snippet(code, one_shot_init.start()),
            "message": (
                f"{filepath}: detected a one-shot initializer that persists "
                f"caller-controlled owner/admin state without an existing-"
                f"state guard. A frontrunner can permanently take the global "
                f"control slot and block legitimate future administration "
                f"(ineffective-deadline-or-global-flag-permanent-dos). "
                f"Attack-class suggestion: dos-cap-weakening."
            ),
        })
        return hits

    if _SAFE_RE.search(code):
        return hits

    has_blocking_gate = _BLOCKING_GATE_RE.search(code)
    if not has_blocking_gate:
        return hits

    for fn_match in _ENTRY_FN_RE.finditer(code):
        body = fn_match.group("body")
        write_match = _has_user_controlled_global_write(body)
        if not write_match:
            continue

        anchor = fn_match.start() + write_match.start()
        line = _line_for(code, anchor)
        hits.append({
            "severity": "high",
            "line": line,
            "col": 0,
            "snippet": _snippet(code, anchor),
            "message": (
                f"{filepath}: detected a one-shot or user-controlled global "
                f"flag, deadline, or cap that is persisted and later gates "
                f"processing. A caller can permanently halt future work, "
                f"expire it immediately, or force a zero cap "
                f"(ineffective-deadline-or-global-flag-permanent-dos). "
                f"Attack-class suggestion: dos-cap-weakening."
            ),
        })
        break

    return hits
