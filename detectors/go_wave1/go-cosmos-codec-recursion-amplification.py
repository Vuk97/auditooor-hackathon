"""
go-cosmos-codec-recursion-amplification.py

Sibling detector for Go/Cosmos codec-recursion-amplification recall.

Flags nested-message decode helpers in files that also expose an ante-side
decode entrypoint. The seed detector `cosmos_decode_before_fee_unbounded`
keys on the top-level unmarshal in `AnteHandle` / `DecodeTx`; this sibling
keys on helper-centric shapes such as `decodeMsg` / `unpackNestedMessages`
that unmarshal nested `Msg` / `Any` / `Children` payloads without a local
size or recursion-depth bound.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-cosmos-codec-recursion-amplification"


_ENTRY_RE = re.compile(
    r"(AnteHandle|DecodeTx|TxDecoder|CheckTx|decodeTx|unmarshalTx"
    r"|ProcessProposal|PrepareProposal|ValidateNestedMsg)"
)

_HELPER_RE = re.compile(
    r"(decode|unmarshal|unpack).*(msg|msgs|message|messages|nested|any|body)"
    r"|^(decodeMsg|unpackNestedMessages)$",
    re.IGNORECASE,
)

_UNMARSHAL_RE = re.compile(
    r"(\bproto\.Unmarshal\s*\("
    r"|\bjson\.Unmarshal\s*\("
    r"|\.Unmarshal\s*\(\s*[A-Za-z_]"
    r"|codec\.Unmarshal\b"
    r"|cdc\.Unmarshal\b"
    r"|\.UnmarshalJSON\s*\()"
)

_NESTED_PAYLOAD_RE = re.compile(
    r"(\bNested[A-Za-z0-9_]*\b"
    r"|\b[A-Za-z0-9_]*Children\b"
    r"|\b[A-Za-z0-9_]*Msgs\b"
    r"|\b[A-Za-z0-9_]*Messages\b"
    r"|\bAny\b"
    r"|\.Value\b)",
    re.IGNORECASE,
)

_BOUND_RE = re.compile(
    r"(\bMaxTxBytes\b|\bmaxTxBytes\b|\bMaxBytes\b|\bmaxSize\b|\bMaxSize\b"
    r"|len\s*\(\s*[A-Za-z_]\w*\s*\)\s*>\s*[A-Za-z0-9_]+"
    r"|\bMaxDecodeDepth\b|\bMaxRecursionDepth\b|\bmaxDepth\b|\bMaxDepth\b"
    r"|\bdepth\s*>\s*[A-Za-z0-9_]+|\bdepth\s*>=\s*[A-Za-z0-9_]+"
    r"|\brecursion\b|\btoo deep\b)"
)


def run(engine, filepath: str):
    hits = []
    functions = []
    file_has_entry = False

    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)
        functions.append((fn, name, body_text))
        if _ENTRY_RE.search(name):
            file_has_entry = True

    if not file_has_entry:
        return hits

    for fn, name, body_text in functions:
        if not _HELPER_RE.search(name):
            continue
        if not _UNMARSHAL_RE.search(body_text):
            continue
        if not _NESTED_PAYLOAD_RE.search(body_text):
            continue
        if _BOUND_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"nested-message decode helper `{name}` unmarshals attacker-"
                f"controlled payloads in an ante/CheckTx decode file with no "
                f"local size or recursion-depth bound. A crafted nested tx can "
                f"amplify codec work before fees are charged. Bound nested "
                f"payload size / decode depth first. "
                f"(class: codec-recursion-amplification)"
            ),
        })

    return hits
