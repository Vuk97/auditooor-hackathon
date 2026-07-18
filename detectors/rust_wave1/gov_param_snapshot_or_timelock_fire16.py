"""
gov_param_snapshot_or_timelock_fire16.py

Same-class Rust recall lift for gov-param-injection misses.

The detector targets three concrete governance mutation shapes from the
Fire15 Rust gap report:
- vote weight is read from current balances instead of proposal snapshots
- timelock execution forwards only the queued value and traps surplus value
- public governance-intended parameter mutation has no governance guard
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
    text_of,
)


DETECTOR_ID = "rust_wave1.gov_param_snapshot_or_timelock_fire16"

_VOTE_FN_RE = re.compile(r"(?i)(^|_)(cast_?vote|vote|vote_on|submit_?vote)($|_)")
_PROPOSAL_CONTEXT_RE = re.compile(
    r"(?i)\b(proposal|proposal_id|snapshot_block|snapshot_height|"
    r"start_block|start_time|voting_period|voting_power)\b"
)
_CURRENT_POWER_RE = re.compile(
    r"(?is)("
    r"\bget_current_(?:votes|balance|voting_power)\s*\(|"
    r"\bcurrent_(?:votes|balances|balance|voting_power)\b|"
    r"\b(?:balance_of|get_balance|get_votes|get_voting_power)\s*\(\s*"
    r"(?:voter|user|account|who|sender|caller)\s*\)"
    r")"
)
_SNAPSHOT_POWER_RE = re.compile(
    r"(?is)("
    r"\bget_(?:votes|balance|voting_power)_at\s*\([^;]*(?:snapshot|start)|"
    r"\bget_(?:past|prior)_(?:votes|balance|voting_power)\s*\(|"
    r"\b(?:snapshot|checkpoint)_(?:votes|balance|voting_power)\s*\(|"
    r"\b(?:proposal|prop)\s*\.\s*(?:snapshot_block|snapshot_height)"
    r"[^;]*(?:get_votes_at|get_balance_at|get_voting_power_at)"
    r")"
)

_TIMELOCK_FN_RE = re.compile(r"(?i)(^|_)(execute|execute_transaction|execute_tx)($|_)")
_TIMELOCK_CONTEXT_RE = re.compile(
    r"(?i)\b(timelock|queued_?transactions?|queued_?tx|eta|delay|"
    r"execute_?transaction|execute_?tx)\b"
)
_RECEIVED_VALUE_RE = re.compile(r"(?i)\b(received_value|msg_value|value_sent|sent_value)\b")
_REQUIRED_VALUE_RE = re.compile(
    r"(?is)("
    r"\blet\s+(?:required|required_value|value_required)\s*=\s*"
    r"(?:tx|queued|operation)\s*\.\s*value|"
    r"(?:received_value|msg_value|value_sent|sent_value)\s*<\s*"
    r"(?:required|required_value|value_required|(?:tx|queued|operation)\s*\.\s*value)"
    r")"
)
_NATIVE_TRANSFER_RE = re.compile(
    r"(?is)("
    r"\btransfer_(?:native|eth|balance|coin)\s*\([^;]*(?:required|tx\s*\.\s*value|"
    r"queued\s*\.\s*value)|"
    r"\.(?:transfer|send)\s*\([^;]*(?:required|tx\s*\.\s*value|queued\s*\.\s*value)"
    r")"
)
_REFUND_RE = re.compile(
    r"(?is)\b(refund|refund_stuck|surplus|excess|"
    r"saturating_sub\s*\(\s*(?:required|required_value|value_required)\s*\)|"
    r"checked_sub\s*\(\s*(?:required|required_value|value_required)\s*\))\b"
)

_PARAM_MUTATOR_NAME_RE = re.compile(
    r"(?i)("
    r"update_impact|"
    r"(?:set|update|change|configure)_(?:governance_)?"
    r"(?:param|params|quorum|threshold|proposal_threshold|voting_period|"
    r"timelock_delay|delay|reward|rewards|impact|fee|rate)|"
    r"(?:set|update)(?:Param|Params|Quorum|Threshold|VotingPeriod|"
    r"TimelockDelay|Impact|Fee|Rate)"
    r")"
)
_GOV_INTENT_RE = re.compile(
    r"(?is)("
    r"only\s+(?:callable\s+)?(?:through\s+)?governance|"
    r"governance\s+(?:proposal|execution|only|controlled|authorized)|"
    r"intended[^.\n]{0,100}governance|"
    r"authorized_proposal|"
    r"proposal\s+execution"
    r")"
)
_GOV_GUARD_RE = re.compile(
    r"(?is)("
    r"assert_governance|require_governance|check_governance|only_governance|"
    r"ensure_governance|governance_guard|is_governance|"
    r"GovernanceOrigin\s*::\s*ensure_origin|"
    r"T::GovernanceOrigin\s*::\s*ensure_origin|"
    r"ensure_root\s*\(|ensure_origin\s*\(|\.require_auth\s*\(|"
    r"has_role\s*\([^;]*(?:governance|governor|council|admin)|"
    r"Signer\s*<"
    r")"
)
_PARAM_WRITE_RE = re.compile(
    r"(?xs)"
    r"(?:self|ctx\s*\.\s*accounts\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\.\s*(?P<field>"
    r"governance_params|gov_params|params|config|impact_scores|"
    r"quorum|threshold|proposal_threshold|voting_period|timelock_delay|"
    r"rewards|reward_rate|fee_rate|rate"
    r")\s*(?:\.\s*(?P<method>insert|set|remove|push)\s*\(|=)"
    r"|"
    r"(?P<storage>"
    r"GovernanceParams|GovParams|Params|Config|ImpactScores|Quorum|"
    r"Threshold|ProposalThreshold|VotingPeriod|TimelockDelay|Rewards|"
    r"RewardRate|FeeRate"
    r")\s*::\s*(?P<storage_method>put|insert|mutate|try_mutate|set)\s*\("
)


def _signature_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _prefix_text(fn, source: bytes, window: int = 500) -> str:
    start = max(0, fn.start_byte - window)
    return source[start:fn.start_byte].decode("utf-8", errors="replace")


def _first_param_write(body_text: str) -> tuple[str, str] | None:
    match = _PARAM_WRITE_RE.search(body_text)
    if not match:
        return None
    target = match.group("field") or match.group("storage") or "governance parameter"
    method = match.group("method") or match.group("storage_method") or "assign"
    return target, method


def _snapshot_vote_gap(name: str, signature: str, body_text: str) -> str | None:
    joined = signature + "\n" + body_text
    if not _VOTE_FN_RE.search(name):
        return None
    if not _PROPOSAL_CONTEXT_RE.search(joined):
        return None
    if _SNAPSHOT_POWER_RE.search(body_text):
        return None
    if not _CURRENT_POWER_RE.search(body_text):
        return None
    return "vote power is read from current balances instead of proposal snapshot state"


def _timelock_value_gap(name: str, signature: str, body_text: str, file_text: str) -> str | None:
    joined = signature + "\n" + body_text
    if not _TIMELOCK_FN_RE.search(name):
        return None
    if not (_TIMELOCK_CONTEXT_RE.search(joined) or _TIMELOCK_CONTEXT_RE.search(file_text)):
        return None
    if _REFUND_RE.search(body_text):
        return None
    if not _RECEIVED_VALUE_RE.search(joined):
        return None
    if not _REQUIRED_VALUE_RE.search(body_text):
        return None
    if not _NATIVE_TRANSFER_RE.search(body_text):
        return None
    return "timelock execute path forwards the queued value without refunding surplus value"


def _public_governance_mutation_gap(
    name: str,
    signature: str,
    body_text: str,
    prefix_text: str,
    file_text: str,
) -> tuple[str, str, str] | None:
    if not _PARAM_MUTATOR_NAME_RE.search(name):
        return None
    write = _first_param_write(body_text)
    if write is None:
        return None
    if _GOV_GUARD_RE.search(signature + "\n" + body_text):
        return None
    intent_context = "\n".join([prefix_text, signature, file_text[:1200]])
    if not _GOV_INTENT_RE.search(intent_context):
        return None
    target, method = write
    return (
        "public governance-intended parameter mutation has no governance guard",
        target,
        method,
    )


def _build_hit(
    *,
    filepath: str,
    line: int,
    col: int,
    name: str,
    variant: str,
    detail: str,
    snippet: str,
    write_target: str | None = None,
    write_method: str | None = None,
) -> dict:
    hit = {
        "detector_id": DETECTOR_ID,
        "severity": "medium",
        "file": filepath,
        "line": line,
        "col": col,
        "fn_name": name,
        "variant": variant,
        "snippet": snippet,
        "message": (
            f"pub fn `{name}` matches gov-param-injection recall variant "
            f"`{variant}`: {detail}."
        ),
    }
    if write_target is not None:
        hit["write_target"] = write_target
    if write_method is not None:
        hit["write_method"] = write_method
    return hit


def run(tree, source: bytes, filepath: str):
    hits = []
    file_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        signature = _signature_text(fn, source)
        body_nc = body_text_nocomment(body, source)
        prefix = _prefix_text(fn, source)
        line, col = line_col(fn)

        snapshot_detail = _snapshot_vote_gap(name, signature, body_nc)
        if snapshot_detail is not None:
            hits.append(_build_hit(
                filepath=filepath,
                line=line,
                col=col,
                name=name,
                variant="snapshot-vote-power",
                detail=snapshot_detail,
                snippet=snippet_of(fn, source, 220),
            ))
            continue

        timelock_detail = _timelock_value_gap(name, signature, body_nc, file_text)
        if timelock_detail is not None:
            hits.append(_build_hit(
                filepath=filepath,
                line=line,
                col=col,
                name=name,
                variant="timelock-surplus-value-trap",
                detail=timelock_detail,
                snippet=snippet_of(fn, source, 220),
            ))
            continue

        mutation_gap = _public_governance_mutation_gap(
            name,
            signature,
            body_nc,
            prefix,
            file_text,
        )
        if mutation_gap is not None:
            detail, target, method = mutation_gap
            hits.append(_build_hit(
                filepath=filepath,
                line=line,
                col=col,
                name=name,
                variant="unguarded-governance-parameter-mutation",
                detail=detail,
                snippet=snippet_of(fn, source, 220),
                write_target=target,
                write_method=method,
            ))

    return hits
