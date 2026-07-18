"""
r94_loop_governance_only_state_fn_exposed_as_public.py

Flags state-mutating fns with names that imply governance-only
intent (update_impact, mint_service_nft, set_protocol_param,
adjust_emission, etc.) that are declared `pub` but contain no
auth guard (onlyOwner / onlyGovernance / require_auth). Any
caller can drive the mutation directly, cascading into
consensus / accounting errors.

Source: Solodit #61824 (Code4rena Virtuals Protocol ServiceNft).
Class: governance-only-state-fn-exposed-as-public (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(update_impact|updateImpact|"
    r"mint_service_nft|mintServiceNft|"
    r"set_protocol_param|setProtocolParam|"
    r"adjust_emission|adjustEmission|"
    r"update_consensus_score|updateConsensusScore|"
    r"set_governance_weight|setGovernanceWeight|"
    r"update_oracle_price|updateOraclePrice|"
    r"submit_impact_update)"
)
_AUTH_RE = re.compile(
    fr"(?i)(only_owner|onlyOwner|only_governance|onlyGovernance|"
    fr"only_gov|onlyGov|only_admin|onlyAdmin|"
    fr"require_auth\s*\(\s*&?\s*{IDENT}(admin|owner|gov|dao)|"
    fr"require\s*\(\s*msg\.sender\s*==\s*{IDENT}governance|"
    fr"require\s*\(\s*msg\.sender\s*==\s*{IDENT}governor|"
    fr"require\s*\(\s*msg\.sender\s*==\s*{IDENT}timelock|"
    fr"require\s*\(\s*msg\.sender\s*==\s*{IDENT}dao|"
    fr"hasRole\s*\(\s*{IDENT}(GOV|ADMIN|OWNER))"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if _AUTH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is named as a governance-only / "
                f"protocol-param mutation but lacks any onlyGovernance "
                f"/ onlyOwner / require_auth gate — any caller can "
                f"drive the mutation, cascading into consensus / "
                f"reward / oracle misaccounting "
                f"(governance-only-state-fn-exposed-as-public). "
                f"See Solodit #61824 (C4 Virtuals Protocol ServiceNft)."
            ),
        })
    return hits
