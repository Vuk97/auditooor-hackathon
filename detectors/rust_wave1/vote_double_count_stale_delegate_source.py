"""
vote_double_count_stale_delegate_source

Flags Rust delegation or vote-source reassignment code that credits a new
delegate/source while retaining the old delegate/source edge. The detector is
intentionally shape-specific: a plain `delegate` identifier is not enough.

Seeds:
- reference/patterns.dsl/delegation-reassignment-stale-vote-source.yaml
- reference/patterns.dsl/voting-power-self-delegation-double-count.yaml
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
)


_DELEGATION_FN_RE = re.compile(
    r"(?i)(delegate|delegat|redelegate|representative|vote_source|votesource|"
    r"set_delegate|change_delegate|move_delegate|assign_delegate)"
)

_VOTE_FN_RE = re.compile(r"(?i)(cast_vote|castvote|submit_vote|record_vote|tally|vote)")

_VOTE_CONTEXT_RE = re.compile(
    r"(?i)(vote|voting|govern|proposal|ballot|quorum|checkpoint|delegate)"
)

_OLD_SOURCE_RE = re.compile(
    r"(?i)(old_delegate|olddelegate|current_delegate|currentdelegate|"
    r"previous_delegate|previousdelegate|prior_delegate|existing_delegate|"
    r"from_delegate|fromdelegate|old_source|oldsource|current_source|"
    r"previous_source|delegate_of\s*\.get|delegates\s*\.get|"
    r"representative_of\s*\.get|source_of\s*\.get)"
)

_NEW_SOURCE_NAME = (
    r"(?:new_delegate|newdelegate|new_source|newsource|delegatee|to_delegate|"
    r"todelegate|representative|new_rep|newrep|target_delegate|targetdelegate)"
)

_POWER_STORE = (
    r"(?:delegate|delegated|delegation|voting|vote|checkpoint)[\w\.]*"
    r"(?:power|votes|weight|source|sources|token_ids|tokenids|checkpoints)?"
)

_CREDIT_PATTERNS = [
    re.compile(
        rf"(?is){_POWER_STORE}\s*\.entry\s*\(\s*&?{_NEW_SOURCE_NAME}\b[^)]*\)"
        r"[\s\S]{0,220}(?:and_modify\s*\([^;]*(?:\+=|saturating_add|checked_add)|"
        r"or_insert\s*\([^;]*(?:vote|power|weight|amount|balance|source|token))"
    ),
    re.compile(
        rf"(?is){_POWER_STORE}\s*\.insert\s*\(\s*&?{_NEW_SOURCE_NAME}\b[^,]*,"
        r"[^;]*(?:\+|saturating_add|checked_add)[^;]*(?:vote|power|weight|amount|balance)"
    ),
    re.compile(
        rf"(?is){_POWER_STORE}\s*[\s\S]{{0,80}}{_NEW_SOURCE_NAME}"
        r"[\s\S]{0,160}\.push\s*\("
    ),
]

_DEBIT_BEFORE_RE = re.compile(
    r"(?is)(?:"
    r"(?:old_delegate|olddelegate|current_delegate|currentdelegate|"
    r"previous_delegate|previousdelegate|prior_delegate|existing_delegate|"
    r"from_delegate|fromdelegate|old_source|oldsource|current_source|"
    r"previous_source)[\s\S]{0,260}"
    r"(?:\-=|saturating_sub|checked_sub|remove\s*\(|retain\s*\(|swap_remove\s*\(|clear\s*\()"
    r"|(?:remove_delegation|clear_old_delegate|detach_delegate|delete_old_delegate|"
    r"debit_delegate|debit_source|move_delegate_votes|_move_delegate_votes)\s*\("
    r"|(?:delegate|delegated|delegation|voting|vote)[\w\.]*"
    r"(?:power|votes|weight|source|sources|token_ids|tokenids)?"
    r"[\s\S]{0,180}(?:remove\s*\([^)]*(?:old|current|previous|from)|"
    r"get_mut\s*\([^)]*(?:old|current|previous|from)[\s\S]{0,220}"
    r"(?:\-=|saturating_sub|checked_sub|retain\s*\(|remove\s*\(|swap_remove\s*\())"
    r")"
)

_DIRECT_PLUS_DELEGATED_RE = re.compile(
    r"(?is)(?:balance|base_vote|basevote|direct_vote|directvote|own_vote|ownvote)"
    r"[\s\S]{0,120}\+[\s\S]{0,120}"
    r"(?:delegate|delegated|checkpoint)[\w\.]*(?:power|votes|weight)"
)

_DELEGATE_READ_RE = re.compile(
    r"(?i)(delegate_of|delegates|representative_of|delegated_power|delegate_votes)\s*\.get"
)

_SELF_OR_REPEAT_GUARD_RE = re.compile(
    r"(?is)(has_voted|voted_by_proposal|proposal_voter|receipt\.has_voted|"
    r"delegatee\s*!=\s*voter|new_delegate\s*!=\s*voter|representative\s*!=\s*voter|"
    r"if\s+delegatee\s*==\s*voter[\s\S]{0,120}(?:return|0))"
)


def _first_credit(body_text: str) -> re.Match[str] | None:
    matches = [m for pattern in _CREDIT_PATTERNS for m in [pattern.search(body_text)] if m]
    if not matches:
        return None
    return min(matches, key=lambda match: match.start())


def _has_debit_before_credit(body_text: str, credit_start: int) -> bool:
    return bool(_DEBIT_BEFORE_RE.search(body_text[:credit_start]))


def _line_for_match(fn_node, source: bytes, body_text: str, match_start: int) -> tuple[int, int]:
    fn_line, fn_col = line_col(fn_node)
    return fn_line + body_text[:match_start].count("\n"), fn_col


def _hit(filepath: str, fn_node, source: bytes, body_text: str, match: re.Match[str], name: str):
    line, col = _line_for_match(fn_node, source, body_text, match.start())
    snippet = " ".join(match.group(0).split())
    if not snippet:
        snippet = snippet_of(fn_node, source)
    if len(snippet) > 180:
        snippet = snippet[:180] + "..."
    return {
        "severity": "high",
        "line": line,
        "col": col,
        "snippet": snippet,
        "message": (
            f"{filepath}: pub fn `{name}` credits a new vote delegate/source "
            "without first debiting or clearing the old source "
            "(vote-double-count-stale-delegate-source)."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if not is_pub(fn, source) or in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _VOTE_CONTEXT_RE.search(body_nc):
            continue

        if _DELEGATION_FN_RE.search(name) and _OLD_SOURCE_RE.search(body_nc):
            credit = _first_credit(body_nc)
            if credit and not _has_debit_before_credit(body_nc, credit.start()):
                hits.append(_hit(filepath, fn, source, body_nc, credit, name))
                continue

        if _VOTE_FN_RE.search(name):
            double_count = _DIRECT_PLUS_DELEGATED_RE.search(body_nc)
            if (
                double_count
                and _DELEGATE_READ_RE.search(body_nc)
                and not _SELF_OR_REPEAT_GUARD_RE.search(body_nc)
            ):
                hits.append(_hit(filepath, fn, source, body_nc, double_count, name))

    return hits
