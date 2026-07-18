#!/usr/bin/env python3
"""capv3-iter8-T3 — halmos counterexample → forge test scaffold (advisory).

Reads a halmos `--json-output` CE document and renders a human-review
scaffold from the CE's `call_sequence` and `values` against the
contract-under-test, seeding symbolic `values` as concrete literals.

The generated file is a *scaffold* — the actual `cut.<fn>(...)` calls
are rendered as commented-out lines for a reviewer to enable after
binding the interface; the tool does NOT produce an executable replay
by itself (out of scope for FIX-8C).

ADVISORY SCAFFOLD — this tool satisfies the *machinery* half of
`docs/SYMBOLIC_PROMOTION_GATE.md §S2` (CE-to-PoC fidelity). It activates
only when a real CE arrives. Today, 0 CEs have been produced across the
5 wired symbolic harnesses, so the tool's output is useful strictly as
infrastructure — it does NOT in itself satisfy S2, and it does NOT
contribute to the evidence-matrix pipeline. Every emitted file carries
an `ADVISORY` header comment making this classification explicit.

Hard-negative guarantees (mirrored in the hermetic tests):
  - This tool MUST NOT emit promotion-flagging tokens (the forbidden
    regex is checked externally; see the T3 acceptance grep).
  - This tool MUST NOT write into any packaged-submission directory
    (leaf names `submissions/packaged/`, `submissions/ready/`, or
    `submissions/staging/` are rejected with a structured `cannot-run`
    reason `output-path-in-submissions` and a non-zero exit).
  - On empty `counterexamples` array: honest-zero — `cannot-run` JSON to
    stderr, exit 0, NO output file written.
  - On a malformed CE shape (non-dict CE, non-dict `values`, non-list
    `call_sequence`): structured `cannot-run` JSON with reason
    `malformed-counterexample-schema` + non-zero exit, no traceback.

Dependencies: stdlib only (argparse / hashlib / json / pathlib / re / sys).
This is required by the acceptance spec of T3 and is checked by a
hermetic grep.

Usage:
    python3 tools/symbolic-ce-to-forge.py --input <halmos-ce.json>
        [--output <path>]
        [--contract-under-test <Name>]

If `--output` is omitted, the filename is derived as
`reproduce_<ce_hash>.t.sol` in the current working directory. If the
input contains multiple counterexamples, they all land in a single
output file as sibling `test_reproduces_ce_<hash>_<n>()` functions.

The CE hash is the first 8 chars of SHA256(canonical_json(values +
call_sequence)) — deterministic for a given CE, invariant across
halmos reruns that produce the same solver witness.

------------------------------------------------------------------------
W5-D2 — counterexample-to-executable-PoC concretizer
------------------------------------------------------------------------
The default mode above is the *advisory scaffold* (skipped-test,
commented-out calls). It is preserved byte-for-byte against the golden.

`--concretize` upgrades the tool from scaffold to a real PASS/FAIL
verdict. In concretize mode the tool:

  1. Reads the CE's concrete `values` + `call_sequence` (as before).
  2. Reads the extra concretization fields the CE may carry:
       - `contract_under_test` : the source `.sol` file (relative to a
         `--project-root` Foundry project, or absolute).
       - `setup`        : optional list of Solidity statements run in
         `setUp()` after the CUT is deployed (state concretization).
       - `assertions`   : list of Solidity boolean expressions that the
         symbolic engine proved violated. The generated test asserts
         each one; a PASS means the property is violated == exploit
         reproduced.
       - `expect_revert`: optional bool — if true the CE call is wrapped
         in `vm.expectRevert()` instead of an assertion block.
  3. Renders a *real, un-skipped* Foundry test that imports the CUT,
     deploys it, applies the concretized setup, pranks the attacker,
     calls the target function with the CE literals, and asserts the
     violated property.
  4. Writes the test into `<project-root>/test/` and invokes
     `forge test --match-test <name>` against the project.
  5. Records the outcome into an `auditooor.ce_replay_result.v1` JSON
     artifact: `status` in {reproduced, not-reproduced, skipped,
     error}, plus the forge exit code, matched-test count, and the
     CE hash for provenance.

forge-graceful: if the `forge` binary is not on PATH (or
`AUDITOOOR_DEEP_SKIP_FORGE=1` is set) the tool still renders the
executable test file, but the run step emits `status: skipped` with
`reason: forge-unavailable` and exits 0. CI never requires forge.

`reproduced`     == forge test PASSED  (the violated-property assert
                    held, i.e. the engine's counterexample is real).
`not-reproduced` == forge test FAILED  (the assert did not hold; the
                    CE could not be replayed on the real contract).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# CE hashing — deterministic, canonical JSON.
# ---------------------------------------------------------------------------


def _canonical(obj) -> str:
    """Canonical JSON: sorted keys, no whitespace, UTF-8 safe."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def ce_hash(ce: dict) -> str:
    """First 8 hex chars of SHA256 over the CE's values + call_sequence."""
    payload = {
        "values": ce.get("values", {}),
        "call_sequence": ce.get("call_sequence", []),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Value decoding — halmos prints symbolic bindings as typed hex literals.
# ---------------------------------------------------------------------------


_HEX_RX = re.compile(r"^0x[0-9a-fA-F]+$")

# Sentinel returned by `decode_value` when the raw value cannot be
# parsed into a Solidity literal. Callers MUST check for this sentinel
# and emit a commented-out scaffold line rather than interpolating the
# sentinel into a live Solidity declaration (which would produce a
# compile error like `uint256 x = "foo";`). See Bug 4 in
# `docs/FIX8C_CE_REPLAY_SAFETY.md`.
_UNRECOGNIZED = object()


def decode_value(raw, hint: str | None = None):
    """Decode a halmos value string into a Solidity literal, or sentinel.

    halmos JSON emits values as hex strings (`"0x…"`) most of the time;
    some variants print decimal integers. We accept both and pass the
    hint (if present) through unchanged — we emit the literal as-is
    wrapped for the target Solidity type. The reproducer is ADVISORY,
    so we deliberately do NOT widen narrow types or coerce addresses
    here: the caller must eyeball the output.

    On an unparseable value we return the sentinel `_UNRECOGNIZED`
    rather than a bogus quoted string — this keeps the generated file
    valid Solidity (the caller will emit a TODO comment instead of an
    invalid assignment).
    """
    if raw is None:
        return "0 /* null */"
    if isinstance(raw, int):
        return str(raw)
    s = str(raw).strip()
    if _HEX_RX.match(s):
        return s
    if s.lstrip("-").isdigit():
        return s
    # Unknown shape — return the sentinel so the caller can emit a
    # commented-out declaration + TODO instead of a bogus
    # `uint256 x = "foo";` line that would fail Solidity compile.
    return _UNRECOGNIZED


def _raw_repr(raw) -> str:
    """Shortened, comment-safe repr of a raw CE value (for TODO lines)."""
    s = "null" if raw is None else str(raw)
    # Strip characters that would break a `// …` comment or inject new
    # declarations. No newlines, carriage returns, or `*/` — the TODO
    # lives inside a single-line `//` comment, but belt-and-braces in
    # case a reviewer moves it into a `/* */` block later.
    s = s.replace("\r", " ").replace("\n", " ").replace("*/", "* /")
    if len(s) > 120:
        s = s[:117] + "..."
    return s


def eip55_checksum(addr: str) -> str:
    """Return the EIP-55 mixed-case checksummed form of a 20-byte address.

    Solidity >=0.8 rejects address literals that look like an address but
    are not correctly checksummed. The concretizer emits CE address values
    verbatim, so it must checksum them. Non-address-shaped input is
    returned unchanged.
    """
    s = addr.strip()
    if not _HEX_RX.match(s):
        return addr
    hexpart = s[2:]
    if len(hexpart) != 40:
        return addr
    lowered = hexpart.lower()
    try:
        # EIP-55 uses keccak-256, not SHA3-256. Python's hashlib does not
        # ship keccak; use the pure-python fallback.
        h = _keccak256(lowered.encode("ascii")).hex()
    except Exception:
        return addr
    out = []
    for i, ch in enumerate(lowered):
        if ch in "0123456789":
            out.append(ch)
        elif int(h[i], 16) >= 8:
            out.append(ch.upper())
        else:
            out.append(ch)
    return "0x" + "".join(out)


def _keccak256(data: bytes) -> bytes:
    """Pure-python keccak-256 (no third-party deps; EIP-55 needs keccak)."""
    # Keccak-f[1600] sponge, rate 1088 bits (136 bytes), capacity 512.
    RHO = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ]
    PI = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ]
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    MASK = (1 << 64) - 1

    def rol(x, n):
        return ((x << n) | (x >> (64 - n))) & MASK

    def keccak_f(st):
        for rnd in range(24):
            c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]
                 for x in range(5)]
            d = [c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(0, 25, 5):
                    st[x + y] ^= d[x]
            t = st[1]
            for i in range(24):
                j = PI[i]
                t2 = st[j]
                st[j] = rol(t, RHO[i])
                t = t2
            for y in range(0, 25, 5):
                row = st[y:y + 5]
                for x in range(5):
                    st[x + y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
            st[0] ^= RC[rnd]
        return st

    rate = 136
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i] ^= lane
        keccak_f(state)
    out = bytearray()
    for i in range(4):
        out += state[i].to_bytes(8, "little")
    return bytes(out)


def solidity_type_for(hint: str | None) -> str:
    """Map halmos type hints to forge-test local variable types."""
    if not hint:
        return "uint256"
    h = hint.strip().lower()
    if h.startswith("address"):
        return "address"
    if h.startswith("bool"):
        return "bool"
    if h.startswith("bytes32"):
        return "bytes32"
    if h.startswith("bytes"):
        return "bytes memory"
    if h.startswith("string"):
        return "string memory"
    if h.startswith("int"):
        return "int256"
    # default: uint256 (halmos's most-common symbolic width)
    return "uint256"


# ---------------------------------------------------------------------------
# Forge test rendering.
# ---------------------------------------------------------------------------


_HEADER_TEMPLATE = """// SPDX-License-Identifier: UNLICENSED
// ADVISORY — auto-generated from halmos CE; review before including in evidence_matrix.
// Source CE hash (SHA256 of values + call_sequence, 64 hex): {full_hash}
// Generated at (UTC, ISO-8601): {ts}
// Generator: tools/symbolic-ce-to-forge.py (capv3-iter8-T3)
//
// This file is an advisory scaffold. It does NOT contribute to evidence-matrix
// verdicts. It does NOT satisfy SYMBOLIC_PROMOTION_GATE.md §S2 by itself —
// fidelity requires human review + `forge test -vvv` confirming the same
// assertion violation halmos reported.
pragma solidity ^0.8.20;

import {{Test}} from "forge-std/Test.sol";

interface I{cut} {{}}

contract ReproduceHalmosCE is Test {{
    I{cut} internal cut;

    function setUp() public {{
        // TODO: deploy or bind `cut` to the contract-under-test instance
        // that halmos was configured against. The symbolic run assumed a
        // storage layout + constructor args the reviewer must replicate.
    }}
"""


_FUNCTION_TEMPLATE = """
    /// @notice Scaffold renders halmos CE #{idx} (hash {short_hash}) for human review.
    /// @dev ADVISORY — review each decoded literal; commented-out calls must be enabled by hand.
    function test_reproduces_ce_{short_hash}{suffix}() public {{
{value_decls}
{call_sequence}
        // NOTE: halmos asserted a violation here. The reviewer MUST add the
        // concrete `assertEq` / `vm.expectRevert` / invariant check that
        // mirrors the `check_*` assertion in the symbolic harness.
    }}
"""


_FOOTER = "}\n"


def render_value_decls(values: dict, indent: str = "        ") -> str:
    """Render the CE's symbolic bindings as typed local Solidity vars.

    Unparseable raw values are rendered as a TODO comment + a commented
    declaration rather than a bogus `= "foo"` assignment. This keeps
    the emitted file valid Solidity; the reviewer is nudged to supply
    a literal before trusting the scaffold.
    """
    if not values:
        return f"{indent}// no symbolic values in this CE\n"
    lines: list[str] = []
    # Sort for determinism — halmos's JSON key order can drift between
    # solver runs without changing the CE semantics.
    for name in sorted(values.keys()):
        entry = values[name]
        if isinstance(entry, dict):
            raw = entry.get("value")
            hint = entry.get("type")
        else:
            raw = entry
            hint = None
        lit = decode_value(raw, hint)
        sol_type = solidity_type_for(hint)
        safe_name = re.sub(r"[^A-Za-z0-9_]", "_", str(name))
        if lit is _UNRECOGNIZED:
            # Bug-4 safety: DO NOT emit `uint256 x = "foo";` (invalid
            # Solidity). Emit a TODO + commented-out declaration so the
            # file still compiles as a skeleton and the reviewer can
            # fill in the real literal.
            lines.append(
                f"{indent}// TODO: decode value for '{safe_name}' — raw: '{_raw_repr(raw)}'"
            )
            lines.append(f"{indent}// {sol_type} {safe_name}; // placeholder; see TODO above")
            continue
        if sol_type == "address" and _HEX_RX.match(str(lit)):
            lit = f"address({lit})"
        lines.append(f"{indent}{sol_type} {safe_name} = {lit};")
    return "\n".join(lines) + "\n"


def _decode_for_comment(raw, hint: str | None = None) -> str:
    """Decode a value for embedding in a `//` comment line.

    Returns a literal on recognized values, or a shortened raw repr
    tagged `<UNRECOGNIZED:…>` for unparseable values. Because the
    result only ever lives inside a comment, we never risk emitting
    invalid Solidity at this site.
    """
    lit = decode_value(raw, hint)
    if lit is _UNRECOGNIZED:
        return f"<UNRECOGNIZED:{_raw_repr(raw)}>"
    return str(lit)


def render_call_sequence(call_sequence: list, indent: str = "        ") -> str:
    """Render `call_sequence` as `vm.prank(...)` + commented `cut.fn(...)` scaffold."""
    if not call_sequence:
        return f"{indent}// no call_sequence in this CE\n"
    lines: list[str] = []
    for i, call in enumerate(call_sequence):
        if not isinstance(call, dict):
            lines.append(f"{indent}// step {i}: malformed entry, skipped")
            continue
        fn = call.get("fn") or call.get("function") or "unknown"
        caller = call.get("caller")
        args = call.get("args") or []
        if caller:
            decoded_caller = decode_value(caller)
            if decoded_caller is _UNRECOGNIZED:
                # Can't emit a safe `vm.prank(...)` literal. Degrade to
                # a TODO comment so the file still parses.
                lines.append(
                    f"{indent}// TODO: decode prank caller — raw: '{_raw_repr(caller)}'"
                )
                lines.append(f"{indent}// vm.prank(<UNRECOGNIZED>);")
            else:
                lines.append(f"{indent}vm.prank({decoded_caller});")
        rendered_args = ", ".join(
            _decode_for_comment(
                a.get("value") if isinstance(a, dict) else a,
                a.get("type") if isinstance(a, dict) else None,
            )
            for a in args
        )
        safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", str(fn))
        lines.append(f"{indent}// step {i}: {fn}({rendered_args})")
        lines.append(f"{indent}// cut.{safe_fn}({rendered_args});  // uncomment after binding interface")
    return "\n".join(lines) + "\n"


def render_forge_test(ce_document: dict, cut_name: str) -> str:
    """Render the full forge-test file body."""
    ces = ce_document.get("counterexamples") or []
    # Full-hash provenance uses the first CE's content (single-CE is the
    # common case; multi-CE is rare but supported).
    first = ces[0] if ces else {"values": {}, "call_sequence": []}
    full_payload = {
        "values": first.get("values", {}),
        "call_sequence": first.get("call_sequence", []),
    }
    full_hash = hashlib.sha256(_canonical(full_payload).encode("utf-8")).hexdigest()
    ts = "1970-01-01T00:00:00+00:00"  # deterministic for golden; overridden if caller passes a timestamp
    if ce_document.get("_generated_at"):
        ts = ce_document["_generated_at"]
    body = _HEADER_TEMPLATE.format(full_hash=full_hash, ts=ts, cut=cut_name)
    for i, ce in enumerate(ces):
        short = ce_hash(ce)
        suffix = f"_{i}" if len(ces) > 1 else ""
        value_decls = render_value_decls(ce.get("values") or {})
        call_seq = render_call_sequence(ce.get("call_sequence") or [])
        body += _FUNCTION_TEMPLATE.format(
            idx=i,
            short_hash=short,
            suffix=suffix,
            value_decls=value_decls.rstrip("\n"),
            call_sequence=call_seq.rstrip("\n"),
        )
    body += _FOOTER
    return body


# ---------------------------------------------------------------------------
# W5-D2 — concretizer: render an executable Foundry test + run forge.
# ---------------------------------------------------------------------------


CE_REPLAY_RESULT_SCHEMA = "auditooor.ce_replay_result.v1"


_CONCRETE_HEADER = """// SPDX-License-Identifier: UNLICENSED
// EXECUTABLE — auto-generated from a symbolic counterexample by
// tools/symbolic-ce-to-forge.py --concretize (W5-D2 CE-to-PoC concretizer).
// Source CE hash (SHA256 of values + call_sequence, 64 hex): {full_hash}
// Generated at (UTC, ISO-8601): {ts}
//
// A PASSING `forge test` for this file means the violated property the
// symbolic engine reported is REPRODUCED on the real contract == the
// counterexample is a genuine exploit. A FAILING run means the CE could
// not be replayed (spurious witness, stale source, or layout mismatch).
pragma solidity ^0.8.20;

import {{Test}} from "forge-std/Test.sol";
import {{{cut}}} from "{cut_import}";

contract ConcretizedCE_{short_hash} is Test {{
    {cut} internal cut;

    function setUp() public {{
        cut = new {cut}({ctor_args});
{setup_body}
    }}
"""


_CONCRETE_FN_ASSERT = """
    /// @notice Concretized halmos CE (hash {short_hash}) — PASS == property violated == exploit reproduced.
    function test_concretized_ce_{short_hash}() public {{
{value_decls}
{prank}        cut.{fn}({call_args});
{assertions}
    }}
"""


_CONCRETE_FN_REVERT = """
    /// @notice Concretized halmos CE (hash {short_hash}) — expects the CE call to revert.
    function test_concretized_ce_{short_hash}() public {{
{value_decls}
{prank}        vm.expectRevert();
        cut.{fn}({call_args});
    }}
"""


def render_concrete_value_decls(values: dict, indent: str = "        ") -> str:
    """Concretize-mode value declarations — like `render_value_decls` but
    EIP-55-checksums address literals so the emitted file compiles under
    Solidity >=0.8 (scaffold mode keeps the raw literal for the golden).
    """
    if not values:
        return f"{indent}// no symbolic values in this CE\n"
    lines: list[str] = []
    for name in sorted(values.keys()):
        entry = values[name]
        if isinstance(entry, dict):
            raw = entry.get("value")
            hint = entry.get("type")
        else:
            raw = entry
            hint = None
        lit = decode_value(raw, hint)
        sol_type = solidity_type_for(hint)
        safe_name = re.sub(r"[^A-Za-z0-9_]", "_", str(name))
        if lit is _UNRECOGNIZED:
            lines.append(
                f"{indent}// TODO: decode value for '{safe_name}' — raw: "
                f"'{_raw_repr(raw)}'"
            )
            lines.append(
                f"{indent}// {sol_type} {safe_name}; // placeholder; see TODO above"
            )
            continue
        if sol_type == "address" and _HEX_RX.match(str(lit)):
            lit = f"address({eip55_checksum(str(lit))})"
        lines.append(f"{indent}{sol_type} {safe_name} = {lit};")
    return "\n".join(lines) + "\n"


def _concrete_arg_list(args: list) -> str:
    """Render a CE call_sequence step's args as a comma-joined literal list.

    Unparseable args are rendered as `0 /* TODO */` so the file still
    compiles; the run step will surface a not-reproduced/error verdict.
    """
    out: list[str] = []
    for a in args:
        raw = a.get("value") if isinstance(a, dict) else a
        hint = a.get("type") if isinstance(a, dict) else None
        lit = decode_value(raw, hint)
        if lit is _UNRECOGNIZED:
            out.append("0 /* TODO: unparseable CE arg */")
            continue
        if solidity_type_for(hint) == "address" and _HEX_RX.match(str(lit)):
            lit = f"address({eip55_checksum(str(lit))})"
        out.append(str(lit))
    return ", ".join(out)


def render_concretized_test(ce_document: dict) -> tuple[str, str]:
    """Render a runnable Foundry test from the first CE of `ce_document`.

    Returns `(file_body, test_function_name)`. Raises ValueError if the
    CE lacks the fields concretize mode requires.
    """
    ces = ce_document.get("counterexamples") or []
    if not ces:
        raise ValueError("no counterexamples to concretize")
    ce = ces[0]
    cut_source = ce.get("contract_under_test") or ce_document.get(
        "contract_under_test"
    )
    if not cut_source:
        raise ValueError(
            "concretize mode requires a 'contract_under_test' source path "
            "in the CE document or counterexample"
        )
    cut_name = ce.get("cut_name") or ce_document.get("cut_name") or "CUT"
    short = ce_hash(ce)
    full_payload = {
        "values": ce.get("values", {}),
        "call_sequence": ce.get("call_sequence", []),
    }
    full_hash = hashlib.sha256(
        _canonical(full_payload).encode("utf-8")
    ).hexdigest()
    ts = ce_document.get("_generated_at") or "1970-01-01T00:00:00+00:00"

    # Constructor args (optional) — concretized literals for `new CUT(...)`.
    ctor = ce.get("constructor_args") or ce_document.get("constructor_args") or []
    ctor_args = _concrete_arg_list(ctor)

    # setUp() extra statements — verbatim Solidity, indented.
    setup_stmts = ce.get("setup") or []
    setup_body = "\n".join(f"        {s.rstrip(';')};" for s in setup_stmts)

    # The CE's symbolic value bindings as typed locals (checksummed).
    value_decls = render_concrete_value_decls(
        ce.get("values") or {}, indent="        "
    )

    # The single target call from call_sequence[0].
    call_seq = ce.get("call_sequence") or []
    if not call_seq or not isinstance(call_seq[0], dict):
        raise ValueError(
            "concretize mode requires a non-empty call_sequence with a "
            "target function in the first step"
        )
    step = call_seq[0]
    fn = step.get("fn") or step.get("function")
    if not fn:
        raise ValueError("call_sequence[0] is missing a 'fn' / 'function'")
    safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", str(fn))
    call_args = _concrete_arg_list(step.get("args") or [])
    caller = step.get("caller")
    prank = ""
    if caller:
        decoded = decode_value(caller)
        if decoded is not _UNRECOGNIZED:
            if _HEX_RX.match(str(decoded)):
                decoded = eip55_checksum(str(decoded))
            prank = f"        vm.prank({decoded});\n"

    cut_import = str(cut_source)

    expect_revert = bool(ce.get("expect_revert"))
    if expect_revert:
        body = _CONCRETE_HEADER.format(
            full_hash=full_hash,
            ts=ts,
            cut=cut_name,
            cut_import=cut_import,
            short_hash=short,
            ctor_args=ctor_args,
            setup_body=setup_body,
        )
        body += _CONCRETE_FN_REVERT.format(
            short_hash=short,
            value_decls=value_decls.rstrip("\n"),
            prank=prank,
            fn=safe_fn,
            call_args=call_args,
        )
    else:
        assertions = ce.get("assertions") or []
        if not assertions:
            raise ValueError(
                "concretize mode requires 'assertions' (violated-property "
                "Solidity expressions) unless 'expect_revert' is true"
            )
        assert_lines = "\n".join(
            f"        assertTrue({a.rstrip(';')}, "
            f'"CE property #{i} not violated");'
            for i, a in enumerate(assertions)
        )
        body = _CONCRETE_HEADER.format(
            full_hash=full_hash,
            ts=ts,
            cut=cut_name,
            cut_import=cut_import,
            short_hash=short,
            ctor_args=ctor_args,
            setup_body=setup_body,
        )
        body += _CONCRETE_FN_ASSERT.format(
            short_hash=short,
            value_decls=value_decls.rstrip("\n"),
            prank=prank,
            fn=safe_fn,
            call_args=call_args,
            assertions=assert_lines,
        )
    body += _FOOTER
    return body, f"test_concretized_ce_{short}"


def _forge_available() -> bool:
    """True if `forge` is on PATH and the skip env var is not set."""
    if os.environ.get("AUDITOOOR_DEEP_SKIP_FORGE", "").strip() in {"1", "true", "yes"}:
        return False
    return shutil.which("forge") is not None


def run_forge_replay(
    project_root: Path, test_name: str, ce_short_hash: str
) -> dict:
    """Invoke `forge test --match-test <test_name>`; classify the verdict.

    Returns an `auditooor.ce_replay_result.v1` dict. Never raises — every
    failure mode is mapped to a structured `status`.
    """
    result = {
        "schema_version": CE_REPLAY_RESULT_SCHEMA,
        "ce_hash": ce_short_hash,
        "test_name": test_name,
        "project_root": str(project_root),
        "_generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    }
    if not _forge_available():
        result["status"] = "skipped"
        result["reason"] = "forge-unavailable"
        return result
    try:
        proc = subprocess.run(
            [
                "forge",
                "test",
                "--match-test",
                test_name,
            ],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["reason"] = "forge-timeout"
        return result
    except OSError as exc:
        result["status"] = "error"
        result["reason"] = f"forge-spawn-failed: {exc}"
        return result
    result["forge_exit_code"] = proc.returncode
    combined = proc.stdout + "\n" + proc.stderr
    result["forge_stdout_tail"] = proc.stdout[-2000:]
    # A passing run reproduces the violated property; a failing run does not.
    if proc.returncode == 0:
        result["status"] = "reproduced"
    elif re.search(r"\[FAIL", combined) or "Test result: FAILED" in combined:
        result["status"] = "not-reproduced"
    else:
        # Compile error / dependency miss / no matching test.
        result["status"] = "error"
        if "No tests match" in combined or "0 tests" in combined:
            result["reason"] = "no-matching-test"
        else:
            result["reason"] = "forge-run-failed"
    return result


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _emit_cannot_run(reason: str) -> int:
    """Honest-zero on empty input: stderr JSON, exit 0, no file."""
    sys.stderr.write(_canonical({"status": "cannot-run", "reason": reason}))
    sys.stderr.write("\n")
    return 0


def _emit_cannot_run_nonzero(reason: str, message: str | None = None) -> int:
    """Structured cannot-run for validation failures: stderr JSON + non-zero exit.

    Used when we *can* identify a concrete failure (unsafe output path,
    malformed CE schema) and want a machine-readable reason plus a
    non-zero exit. Distinct from `_emit_cannot_run` which is the
    honest-zero exit 0 path for an empty but well-formed CE manifest.
    """
    if message:
        sys.stderr.write(f"error: {message}\n")
    sys.stderr.write(_canonical({"status": "cannot-run", "reason": reason}))
    sys.stderr.write("\n")
    return 2


_FORBIDDEN_SUBMISSION_LEAVES = {"packaged", "ready", "staging"}


def _is_forbidden_output_path(path: Path) -> bool:
    """Return True if `path` lands inside a reserved submissions subtree."""
    # Normalize before checking so traversal like
    # `submissions/tmp/../packaged/reproduce.t.sol` cannot bypass the guard.
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    parts = candidate.resolve(strict=False).parts
    for idx, part in enumerate(parts[:-1]):
        if (
            part == "submissions"
            and idx + 1 < len(parts)
            and parts[idx + 1] in _FORBIDDEN_SUBMISSION_LEAVES
        ):
            return True
    return False


def _validate_counterexamples(ces) -> str | None:
    """Schema-validate a list of counterexamples.

    Returns None on success, or a short human-readable error message on
    failure. Enforces:
      - each CE is a dict,
      - if `values` is present it is a dict,
      - if `call_sequence` is present it is a list.
    """
    for i, ce in enumerate(ces):
        if not isinstance(ce, dict):
            return (
                f"counterexamples[{i}] must be a JSON object, got "
                f"{type(ce).__name__}"
            )
        if "values" in ce and not isinstance(ce["values"], dict):
            return (
                f"counterexamples[{i}].values must be a JSON object, got "
                f"{type(ce['values']).__name__}"
            )
        if "call_sequence" in ce and not isinstance(ce["call_sequence"], list):
            return (
                f"counterexamples[{i}].call_sequence must be a JSON array, got "
                f"{type(ce['call_sequence']).__name__}"
            )
    return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="symbolic-ce-to-forge",
        description="Convert a halmos counterexample JSON into a forge-test scaffold (advisory).",
    )
    p.add_argument("--input", required=True, help="Path to halmos --json-output CE file.")
    p.add_argument("--output", default=None, help="Path to write the forge-test scaffold.")
    p.add_argument(
        "--contract-under-test",
        default="CUT",
        help="Name of the contract-under-test (used for the interface skeleton).",
    )
    p.add_argument(
        "--concretize",
        action="store_true",
        help="W5-D2: render a runnable Foundry test (not a scaffold) and "
        "invoke `forge test` to a PASS/FAIL verdict.",
    )
    p.add_argument(
        "--project-root",
        default=None,
        help="Foundry project root for --concretize mode. The executable "
        "test is written under <project-root>/test/ and `forge test` is "
        "run from there. Defaults to the --output file's grandparent.",
    )
    p.add_argument(
        "--result-json",
        default=None,
        help="Path to write the auditooor.ce_replay_result.v1 verdict JSON "
        "in --concretize mode (default: alongside the emitted test).",
    )
    args = p.parse_args(argv)

    # Bug-1 safety gate: reject any --output that lands in a reserved
    # submissions subtree (FM-016: no forced submissions). We check
    # this BEFORE opening the input or parsing JSON so the rejection
    # is cheap + no partial-work side-effects are possible.
    if args.output is not None:
        candidate = Path(args.output)
        if _is_forbidden_output_path(candidate):
            return _emit_cannot_run_nonzero(
                "output-path-in-submissions",
                f"refusing to write into reserved submissions subtree: {candidate}",
            )

    inp = Path(args.input)
    if not inp.exists():
        sys.stderr.write(f"error: input file not found: {inp}\n")
        return 2
    try:
        ce_document = json.loads(inp.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: failed to parse halmos CE JSON: {exc}\n")
        return 2

    if not isinstance(ce_document, dict):
        sys.stderr.write("error: halmos CE JSON must be an object at top level\n")
        return 2

    ces = ce_document.get("counterexamples")
    if ces is None:
        sys.stderr.write("error: halmos CE JSON missing 'counterexamples' key\n")
        return 2
    if not isinstance(ces, list):
        sys.stderr.write("error: 'counterexamples' must be a list\n")
        return 2
    if len(ces) == 0:
        return _emit_cannot_run("no-counterexample")

    # Bug-3 safety gate: validate each CE's shape before handing it to
    # the renderer. A malformed CE (string instead of dict, etc.) used
    # to crash with an AttributeError traceback — now we exit with a
    # controlled `cannot-run: malformed-counterexample-schema`.
    schema_err = _validate_counterexamples(ces)
    if schema_err is not None:
        return _emit_cannot_run_nonzero(
            "malformed-counterexample-schema",
            schema_err,
        )

    # -------------------------------------------------------------------
    # W5-D2 concretize mode: render an executable test + run forge.
    # -------------------------------------------------------------------
    if args.concretize:
        try:
            body, test_name = render_concretized_test(ce_document)
        except ValueError as exc:
            return _emit_cannot_run_nonzero(
                "concretize-input-incomplete", str(exc)
            )
        short = ce_hash(ces[0])
        if args.output:
            out_path = Path(args.output)
        else:
            out_path = Path.cwd() / "test" / f"ConcretizedCE_{short}.t.sol"
        if _is_forbidden_output_path(out_path):
            return _emit_cannot_run_nonzero(
                "output-path-in-submissions",
                f"refusing to write into reserved submissions subtree: {out_path}",
            )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(body)
        sys.stdout.write(f"wrote {out_path}\n")

        # Resolve the Foundry project root.
        if args.project_root:
            project_root = Path(args.project_root).expanduser().resolve()
        else:
            # Default: the test file's parent's parent (test/ -> project).
            project_root = out_path.resolve().parent.parent

        verdict = run_forge_replay(project_root, test_name, short)
        result_path = (
            Path(args.result_json)
            if args.result_json
            else out_path.with_suffix(".ce_replay_result.json")
        )
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n")
        sys.stdout.write(f"wrote {result_path} (status={verdict['status']})\n")
        # Exit 0 for reproduced / not-reproduced / skipped (all are
        # well-formed verdicts); non-zero only on a structural error.
        return 0 if verdict["status"] != "error" else 3

    body = render_forge_test(ce_document, args.contract_under_test)

    if args.output:
        out_path = Path(args.output)
    else:
        short = ce_hash(ces[0])
        out_path = Path.cwd() / f"reproduce_{short}.t.sol"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(body)
    sys.stdout.write(f"wrote {out_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
