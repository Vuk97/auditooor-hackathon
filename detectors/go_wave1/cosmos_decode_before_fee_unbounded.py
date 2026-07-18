"""
cosmos_decode_before_fee_unbounded.py

Detects ante-handler / CheckTx-side decoders that fully unmarshal an
attacker-supplied payload (Unmarshal / proto.Unmarshal / json.Unmarshal /
codec.Unmarshal of raw tx bytes or a nested Msg) WITHOUT a prior size /
depth / recursion bound.

A cosmos-sdk node decodes the transaction BEFORE the fee is deducted and
before signature verification completes. If a decoder accepts an
unbounded-size or unbounded-recursion-depth payload, an attacker submits a
crafted tx that costs CPU/memory to decode but pays no fee (the tx can be
rejected after decoding). Repeated cheaply, this exhausts validator CPU on
the CheckTx / mempool path -> matching-engine degradation and liveness
pressure.

The safe pattern bounds the payload before decoding: a `MaxTxBytes` /
`len(bz) > maxSize` check, a recursion-depth cap, or `MaxDecodeDepth` /
`MaxRecursionDepth` passed to the codec.

Bug class: HIGH (codec-recursion-amplification -> CheckTx CPU exhaustion).
Attack-class anchor: zero-coverage class `codec-recursion-amplification`
("Codec recursion cap exceeded by crafted transaction").
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_decode_before_fee_unbounded"

# Ante/CheckTx-side decoder function names (where decode-before-fee lives).
_DECODER_FN_RE = re.compile(
    r"(AnteHandle|DecodeTx|TxDecoder|CheckTx|decodeTx|unmarshalTx"
    r"|ProcessProposal|PrepareProposal|ValidateNestedMsg|decodeMsg)"
)

# An unbounded full unmarshal of attacker bytes.
_UNMARSHAL_RE = re.compile(
    r"(\bproto\.Unmarshal\s*\("
    r"|\bjson\.Unmarshal\s*\("
    r"|\.Unmarshal\s*\(\s*[A-Za-z_]"
    r"|codec\.Unmarshal\b"
    r"|cdc\.Unmarshal\b"
    r"|\.UnmarshalJSON\s*\()"
)

# Evidence the payload was size/depth-bounded before decoding.
_BOUND_RE = re.compile(
    r"(\bMaxTxBytes\b|\bmaxTxBytes\b|\bMaxBytes\b|\bmaxSize\b|\bMaxSize\b"
    r"|len\s*\(\s*[A-Za-z_]\w*\s*\)\s*>\s*[A-Za-z0-9_]+"
    r"|\bMaxDecodeDepth\b|\bMaxRecursionDepth\b|\bmaxDepth\b|\bMaxDepth\b"
    r"|\bdepth\s*>\s*[A-Za-z0-9_]+|\brecursion\b)"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _DECODER_FN_RE.search(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        if not _UNMARSHAL_RE.search(body_text):
            continue
        if _BOUND_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"ante/CheckTx-side decoder `{name}` fully unmarshals an "
                f"attacker-supplied payload with no size / recursion-depth "
                f"bound. Decoding happens before the fee is charged; a "
                f"crafted tx exhausts validator CPU for free -> CheckTx "
                f"liveness pressure. Bound payload size / decode depth "
                f"first. (class: codec-recursion-amplification)"),
        })
    return hits
