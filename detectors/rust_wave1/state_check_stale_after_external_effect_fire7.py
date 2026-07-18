"""
state_check_stale_after_external_effect_fire7.py

Flags Rust transaction/action dispatchers that validate every action against
current state before executing any action. This is the Penumbra-style TOCTOU
shape: `check_stateful` verifies that a key does not exist, but a sibling action
in the same batch can create that key before the checked action executes.

Source-backed analogue:
  audit/corpus_tags/tags/sibling_penumbra_toctou-parallel-check-stateful.yaml
  audit/corpus_tags/tags/sibling_penumbra_toctou-parallel-validator-def.yaml

The detector is intentionally narrower than generic callback/reentrancy scans.
It looks for a two-phase batch function where:
  1. A loop calls `check_stateful` / stateful validation on each action.
  2. A later loop calls `execute` / `apply` / `commit` on the actions.
  3. No reservation, deduplication, or pending-key insert appears between the
     check phase and the execute phase.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
    walk_no_nested_fn,
)


DETECTOR_ID = "rust_wave1.state_check_stale_after_external_effect_fire7"

_CHECK_CALL_RE = re.compile(
    r"(?is)\.(?:check_stateful|check[_a-z0-9]*(?:state|unique|valid|exists))"
    r"\s*\([^\)]{0,500}\)\s*\??\s*;"
)

_EXECUTE_CALL_RE = re.compile(
    r"(?is)\.(?:execute|apply|commit|perform|dispatch|run)"
    r"\s*\([^\)]{0,500}\)\s*\??\s*;"
)

_LOOP_RE = re.compile(r"(?is)\bfor\s+[^\{]{1,180}\{")

_BATCH_CONTEXT_RE = re.compile(
    r"(?i)\b(actions?|tx|transaction|batch|bundle|operation|ops|messages?)\b"
)

_STATE_CONTEXT_RE = re.compile(
    r"(?i)\b(state|store|storage|tree|position|positions|validator|"
    r"validators|consensus|key|keys|nullifier|anchor|commitment)\b"
)

_RESERVATION_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:reserved|reservation|pending|seen|dedup|unique|claimed|locked)"
    r"\b[^;\n]{0,160}(?:\.insert|\.set|=|push)\s*\(|"
    r"\b(?:HashSet|BTreeSet)\s*::\s*new\s*\(|"
    r"\bensure[_a-z0-9]*(?:unique|distinct|dedup|not_duplicate)\s*\(|"
    r"\b(?:reserve|claim|lock|mark_pending|mark_seen|dedup|insert_pending)"
    r"\s*\("
    r")"
)

_REVALIDATION_RE = re.compile(
    r"(?is)\b(?:revalidate|validate_after|check_after|reload|refresh|"
    r"ensure_current|check_current)\s*\("
)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _loop_start_before(text: str, offset: int) -> int | None:
    starts = [match.start() for match in _LOOP_RE.finditer(text, 0, offset)]
    return starts[-1] if starts else None


def _has_guard_between(text: str, start: int, end: int) -> bool:
    region = text[start:end]
    return bool(_RESERVATION_RE.search(region) or _REVALIDATION_RE.search(region))


def _same_loop(text: str, first: int, second: int) -> bool:
    first_loop = _loop_start_before(text, first)
    second_loop = _loop_start_before(text, second)
    return first_loop is not None and first_loop == second_loop


def _best_hit_node(body, source: bytes, execute_line: int):
    for node in walk_no_nested_fn(body):
        if node.type != "call_expression":
            continue
        line, _ = line_col(node)
        if line == execute_line and _EXECUTE_CALL_RE.search(text_of(node, source)):
            return node
    return body


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        raw_body = body_text_nocomment(body, source)
        if not _BATCH_CONTEXT_RE.search(raw_body):
            continue
        if not _STATE_CONTEXT_RE.search(raw_body):
            continue

        check_matches = list(_CHECK_CALL_RE.finditer(raw_body))
        if not check_matches:
            continue

        execute_matches = list(_EXECUTE_CALL_RE.finditer(raw_body))
        if not execute_matches:
            continue

        body_line, _ = line_col(body)
        name = fn_name(fn, source)
        emitted_for_fn = False

        for check in check_matches:
            for execute in execute_matches:
                if execute.start() <= check.end():
                    continue
                if _same_loop(raw_body, check.start(), execute.start()):
                    continue
                if _has_guard_between(raw_body, check.end(), execute.start()):
                    continue

                check_line = _line_for_offset(body_line, raw_body, check.start())
                execute_line = _line_for_offset(body_line, raw_body, execute.start())
                hit_node = _best_hit_node(body, source, execute_line)
                line, col = line_col(hit_node)
                hits.append(
                    {
                        "detector_id": DETECTOR_ID,
                        "severity": "high",
                        "line": line,
                        "col": col,
                        "snippet": snippet_of(hit_node, source),
                        "message": (
                            f"fn `{name}` runs a stateful check phase at line "
                            f"{check_line} before a later execute/effect phase at "
                            f"line {execute_line}. This two-phase batch shape can "
                            "leave check_stateful results stale when an earlier "
                            "action mutates the checked key before a later action "
                            "executes. Reserve or deduplicate checked keys during "
                            "validation, or validate and execute each action "
                            "sequentially. Source-backed analogue: Penumbra "
                            "parallel check_stateful TOCTOU."
                        ),
                    }
                )
                emitted_for_fn = True
                break
            if emitted_for_fn:
                break

    return hits
