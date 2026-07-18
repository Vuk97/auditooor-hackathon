"""
go-cosmos-privileged-bypass-requires-all-msgs.py

Sibling Go/Cosmos detector for ante-handler privilege escalation where one
privileged Msg selects a whole-transaction bypass path. The invariant is that
all bundled Msgs must satisfy the privileged predicate before a no-gas,
no-fee, skip-auth, or alternate ante path is selected.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-cosmos-privileged-bypass-requires-all-msgs"

_ANTE_FN_RE = re.compile(
    r"(NewAnteHandler|AnteHandle|CheckTx|SelectAnte|RouteAnte|Decorate)"
)
_TX_MSGS_RE = re.compile(r"(GetMsgs\s*\(\s*\)|\.Msgs\s*\(\s*\)|for\s+[^{}]*range\s+msgs)")
_PRIVILEGED_MSG_RE = re.compile(
    r"(Msg[A-Za-z]*(?:Observer|Validator|Authority|Admin|Signer|Proposer|GasPriceVoter|Gov)[A-Za-z]*"
    r"|ObserverMsg|ValidatorMsg|AdminMsg|AuthorityMsg)"
)
_BYPASS_RE = re.compile(
    r"(NoGasLimit|InfiniteGas|NewInfiniteGasMeter|SkipFee|NoFee|FeeBypass|BypassFee|BypassAuth|SkipAuth|NoGas)"
)
_ALL_MSGS_GUARD_RE = re.compile(
    r"(all(?:Msgs|Messages)?(?:Are|Were)?(?:Observer|Validator|Admin|Authority|Privileged)"
    r"|every(?:Msg|Message)|AllMsgs|return\s+[^,\n]*newCosmosAnteHandler\s*\()"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _ANTE_FN_RE.search(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)
        if not _TX_MSGS_RE.search(body_text):
            continue
        if not _PRIVILEGED_MSG_RE.search(body_text):
            continue
        if not _BYPASS_RE.search(body_text):
            continue
        if _ALL_MSGS_GUARD_RE.search(body_text):
            continue
        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` appears to select a whole-transaction ante bypass "
                f"from a privileged Msg shape without proving every bundled "
                f"Msg is privileged. Require an all-Msg predicate before "
                f"selecting the bypass. (class: admin-bypass)"
            ),
        })
    return hits
