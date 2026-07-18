"""
go-ante-msg-auth-mixed-msg-privileged-bypass.py

Detects Cosmos ante-handler routing that grants a whole transaction a
privileged auth, fee, or gas bypass when any privileged Msg type is present.

The class invariant: if an ante handler routes a transaction to a special
path for validator, observer, authority, or admin messages, every message in
the transaction must satisfy that privileged predicate. Otherwise an attacker
can bundle one privileged-shaped message with ordinary expensive messages and
make the ordinary messages ride the same bypass.

Empirical anchor: ZetaChain C4 2023-11 finding where a transaction containing
one observer-only Msg selected the no-gas-limit ante path for all bundled
messages. This detector is recall-only and does not claim exploitability.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-ante-msg-auth-mixed-msg-privileged-bypass"

_ANTE_FN_RE = re.compile(
    r"(NewAnteHandler|AnteHandle|anteHandler|CheckTx|ProcessProposal|"
    r"PrepareProposal|SelectAnte|RouteAnte|Decorate)"
)

_TX_MSGS_RE = re.compile(
    r"(GetMsgs\s*\(\s*\)|\.Msgs\s*\(\s*\)|\[\]sdk\.Msg|for\s+[^{}]*range\s+msgs)"
)

_PRIVILEGED_MSG_RE = re.compile(
    r"(Msg[A-Za-z]*(?:Observer|Validator|Authority|Admin|Signer|Proposer|"
    r"GasPriceVoter|VoteOnObservedInboundTx|Gov)[A-Za-z]*"
    r"|ObserverMsg|ValidatorMsg|AdminMsg|AuthorityMsg)"
)

_WHOLE_TX_BYPASS_RE = re.compile(
    r"(NoGasLimit|InfiniteGas|NewInfiniteGasMeter|SkipFee|NoFee|FeeBypass|"
    r"BypassFee|BypassAuth|SkipAuth|new[A-Za-z]*AnteHandlerNoGas|"
    r"anteHandler\s*=|return\s+[A-Za-z_]\w*NoGas[A-Za-z_]\w*)"
)

_ANY_MSG_SHAPE_RE = re.compile(
    r"(for\s+[^{}]*range\s+[^{}]*(?:GetMsgs\s*\(\s*\)|msgs)\s*\{[\s\S]{0,900}"
    r"(?:case\s+\*?[A-Za-z0-9_.]*Msg|if\s+[^{}]*Msg)[\s\S]{0,900}"
    r"(?:NoGasLimit|SkipFee|NoFee|Bypass|anteHandler\s*=|return\s+)"
    r"|has(?:Observer|Validator|Admin|Authority|Privileged)Msg\s*:=\s*true)"
)

_ALL_MSGS_GUARD_RE = re.compile(
    r"(all(?:Msgs|Messages)?(?:Are|Were)?(?:Observer|Validator|Admin|Authority|Privileged)"
    r"|every(?:Msg|Message)"
    r"|AllMsgs"
    r"|all[^=\n]{0,60}:=\s*true[\s\S]{0,900}default\s*:[\s\S]{0,120}"
    r"(?:all[^=\n]{0,60}=\s*false|return\s+[^,\n]*newCosmosAnteHandler\s*\())"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        if not _ANTE_FN_RE.search(name):
            continue
        if not _TX_MSGS_RE.search(body_text):
            continue
        if not _PRIVILEGED_MSG_RE.search(body_text):
            continue
        if not _WHOLE_TX_BYPASS_RE.search(body_text):
            continue
        if _ALL_MSGS_GUARD_RE.search(body_text):
            continue
        if not _ANY_MSG_SHAPE_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"Cosmos ante handler `{name}` appears to grant a whole-tx "
                f"auth/fee/gas bypass when any privileged Msg type is present. "
                f"Require every bundled Msg to satisfy the privileged predicate "
                f"before selecting the bypass path. "
                f"(class: ante-msg-auth-bypass)"),
        })
    return hits
