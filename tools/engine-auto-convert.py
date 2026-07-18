#!/usr/bin/env python3
"""engine-auto-convert.py - the Rust/Go 0-day PROOF driver (closes the 0% gap).

The Rust author (`rust-engine-harness-author.py`) and Go author
(`go-engine-harness-author.py`) AUTHOR harnesses, but their predicates run over
a MODEL of the input domain - the Rust author explicitly notes its assertion
"runs over a MODEL ... not the protocol function's real types" and marks the
binding as the auditor's "last mile". The runners RUN whatever exists. Nobody
PICKS the grounding invariant, AUTHORS a harness that drives the REAL function,
RUNS it, AND adjudicates a run-backed verdict by requiring the invariant to
CATCH the bug (exploit FAILs on the buggy fn) AND a NEGATIVE CONTROL to pass
(the invariant holds on a fixed fn). That missing auto-pick + drive-real + run +
adjudicate step is why rust/go conversion is 0%. This tool is that step.

This is the Rust/Go twin of `evm-0day-proof-pipeline.py` (the EVM driver). It
mirrors that tool's adjudication contract verbatim:

    proof-backed             : exploit test FAILS-on-bug + negative control PASSES-on-fixed
    blocked-with-obligation  : the target cannot be lifted standalone / no engine
                               / the run did not produce a genuine catch + control
    refuted                  : the invariant did NOT catch the bug (exploit passed
                               even on the buggy fn -> the asserted invariant is
                               not the one the vuln violates)

THE HONESTY CONTRACT IS ABSOLUTE
================================
A proof counts ONLY if it actually compiles + runs + the exploit test PASSES
(i.e. the invariant assertion FAILS on the buggy variant, proving the invariant
catches the bug) + a negative-control test PASSES (the invariant holds on the
fixed variant). `assert(true)`, scaffold-only, a stub harness, or a test that
does not run = NOT a proof; this tool reports `blocked-with-obligation` and
states the obligation. A fabricated / non-running proof is the single worst
failure mode and this tool never emits a `proof-backed` verdict without a real
`cargo test` / `go test` transcript showing exploit-FAIL-on-bug +
control-PASS-on-fixed.

How a REAL run-backed proof is produced
=======================================
For a self-contained target function (one whose body references only types /
helpers defined in the same source snippet), the driver lifts the function into
a throwaway mini-crate (Rust) or module (Go) containing THREE things:

  1. the REAL buggy function, lifted verbatim;
  2. a FIXED variant derived by applying the vuln_class's canonical guard
     (e.g. freshness/uniqueness -> add a `used`-flag reject);
  3. an invariant-asserting harness that DRIVES the real function (both
     variants) and asserts the grounding invariant.

The harness emits two tests:
  * `test_exploit_*`            asserts the invariant HOLDS. Run against the
                               buggy fn it must FAIL (the invariant catches the
                               bug). A pass here -> `refuted`.
  * `test_negative_control_*`  asserts the same invariant against the FIXED fn.
                               It must PASS.

`cargo test` / `go test` is then invoked and the transcript parsed. Only the
exact PASS/FAIL shape above adjudicates `proof-backed`.

When the function is NOT self-contained (its body references types defined
elsewhere in the crate, external imports, protocol state we cannot synthesize),
the driver does NOT fabricate a lift. It returns `blocked-with-obligation` and
names the obligation: "drive the real fn inside its own crate's test target".

GENERIC, SIGNATURE-DRIVEN synthesis (NO hand-spec)
==================================================
Every convert family is driven by the target fn's SIGNATURE + the in-file struct
declarations - there are NO hardcoded target function names and NO per-target
exploit bodies. The synthesizer re-derives the harness from scratch for any
target whose shape matches one of the six mechanically-convertible families:

  1. freshness / consume-once  (guard = freshness-flag)
       a `&mut <T>` / `*<T>` consumable resource usable at most once. The harness
       calls the real fn twice on the SAME resource; the second call must reject.
       Anchor: FROST nonce-reuse `sign`.
  2. bounds / dos-resource     (guard = cap-check)
       a caller-controlled length param driving an allocation/loop + a configured
       cap (struct field or const). In-cap accepted, over-cap rejected. Anchor:
       merkle-proof unbounded-alloc `verify`.
  3. conservation / normalization (guard = sum-check)
       a `[]T` / `[]*T` slice param whose element struct carries a numeric
       weight/share-like field. A conserving collection (field sum == EXPECTED)
       is accepted; a non-conserving one is rejected. Anchor: Quicksilver
       MsgSignalIntent validator-weight gap `validateIntents`.
  4. freshness / staleness     (guard = staleness-gate)
       a `&<T>` ref whose struct carries a stored-timestamp field, plus a
       now/slot clock param and a max_delay/ttl bound param. A FRESH input is
       accepted; a STALE input (timestamp older than now - bound) is rejected.
       Anchor: Synthetify `calculate_debt` asset.last_update gate.
  5. integer-overflow / truncation (guard = cast-bound-check)
       a WIDE caller-controlled numeric param flows into a NARROWING cast
       (`u64 as u32` in Rust; `uint32(x)` in Go) with no prior bound check, so a
       value above the destination type's max silently truncates. An in-range
       value is accepted; an over-max value is rejected. The harness drives the
       real fn with an in-range and an over-destination-max value; the buggy fn
       (incorrectly) accepts+truncates the over-max value. Supports the
       `(T, error)` multi-value return shape (arity-aware reject/capture), not
       just bare `error`. Detection is signature-driven: the source param type
       must be strictly wider than the cast destination (a WIDENING cast such as
       `u32 as u64` is correctly NOT flagged).
  6. access-control-bypass        (guard = owner-guard)
       a `&mut <T>` / `*<T>` state struct carrying an owner/admin/authority-like
       identity field, plus a caller/sender param of the SAME type, mutated WITH
       NO `caller == state.owner` equality guard. An OWNER caller is accepted; an
       ATTACKER caller (!= the stored owner) is rejected. The harness drives the
       real fn twice on a fresh copy of the same state: once as the owner, once
       as a non-owner; the buggy fn (incorrectly) accepts the non-owner. A fn
       that ALREADY compares caller against the owner is correctly NOT flagged
       (the bug is not present). String- and integer-typed identities both
       convert; supports `(T, error)` multi-value returns.

Three further signature-driven families extend the six above (each documented
in full at its VULN_CLASS_MAP entry); they are GENERIC and dispatch purely on
guard + struct/signature shape, with NO target fn-name special-casing, and each
is proof-backed on BOTH Rust (`cargo test`) and Go (`go test`):

  7. reentrancy / CEI-violation (guard = cei-order-check)
       a `&mut <State>` / `*<State>` struct carrying a numeric balance-like field
       written AFTER a callback/hook param is invoked in the body (the external
       call precedes the state effect). The fixed variant moves the state write
       BEFORE the call (checks-effects-interactions). The harness drives the real
       fn with a hook that records the balance the external call OBSERVES; on the
       buggy fn the hook sees the PRE-effect balance -> invariant violated.
  8. oracle/price staleness-on-read (guard = valid-flag-check)
       a read/valuation fn taking a `&<T>` / `*<T>` ref whose struct stores a
       numeric value field AND a boolean validity/freshness flag, returning the
       value WITHOUT consulting the flag. Supports POSITIVE flags (valid/fresh,
       must be TRUE) and NEGATIVE flags (stale/invalid, must be FALSE). The fixed
       variant injects the flag gate. The harness drives a VALID datum (accept)
       and a STALE one (reject). This is the boolean-flag sibling of family 4's
       timestamp staleness-gate.
  9. double-mint / double-credit (guard = processed-flag-check)
       a fn crediting/minting a numeric amount onto a single `&mut <T>` / `*<T>`
       state struct WITHOUT a processed/claimed flag, so a replay double-credits.
       The fixed variant injects a `processed`-flag field + guard. The harness
       drives the real fn TWICE on the SAME state; the second (replay) call must
       be rejected for the uniqueness invariant to HOLD.

Three more signature-driven GENERIC families (codex95 single-owner wave) extend
the nine above. They are Go-proven (`go test`); on Rust they honestly
block-with-obligation (the Rust converter has no hand-author for these guards, so
it never fabricates a fix). NO target fn-name dispatch - each dispatches on
guard + struct/signature shape:

  10. signature-replay / missing-nonce (guard = used-nonce-check)
       a verify/authorize/execute fn consuming a signature/message-bearing param
       (sig/signature/digest/permit/voucher/...) AND a `*<State>` struct carrying
       a nonce/used field (a bool flag like `used`/`consumed`/`seen`, or a numeric
       counter like `nonce`/`seq`) that the body never consults - so the SAME
       signed payload replays. The fixed variant injects a flip-and-reject guard
       (`if st.used { reject }; st.used = true`); for a counter nonce with no bool
       flag, an auxiliary `UsedAUTO bool` is added. The harness drives the real fn
       TWICE with the SAME signature on the SAME state; the replay must be rejected.
  11. unchecked-external-call-return (guard = call-return-check)
       a fn invoking a callback/transfer param (call/transfer/send/remit/push/...)
       returning a `bool` success or `error`, but DISCARDING the result - so a
       FAILED external call is treated as success and the post-call effect runs.
       The fixed variant captures the result and rejects on failure. The harness
       drives the real fn with a FAILING call (must reject) and a SUCCEEDING call
       (must accept); the buggy fn accepts both.
  12. missing-deadline / slippage-bound (guard = deadline-bound-check)
       a swap/fill/exec fn taking a numeric realized/output param (out/received/
       exec_price/now/...) AND a caller-supplied bound param (min_out/deadline/
       limit/...) it never compares - so an adverse/stale execution runs. The
       bound polarity selects the guard direction (MIN: realized >= bound; MAX/
       DEADLINE: realized <= bound). The harness drives an in-bound case (accept)
       and an out-of-bound case (reject); the buggy fn accepts the adverse value.

The anchors above are the SHAPES the families recognize; the synthesizer does
NOT special-case any anchor's symbol names. A never-seen target with entirely
different field/param names (e.g. `distribute(payouts []Payout)` with a `Bps`
field, or `read_value(feed &PriceFeed)` with a `published_at` field, or Go
`disburse(pool *LiquidityPool, drain uint64, notify func(uint64))` with a
`Reserve` field) converts via the identical signature-driven path. A hand-spec
that only works on a known target would be the forbidden anti-pattern; this tool
has none.

The REAL Quicksilver/Synthetify functions are protocol-coupled (RefMut<AssetsList>,
cosmos Dec, package-qualified keeper calls) and therefore honestly
block-with-obligation at the self-containment gate - the drive-in-place fixtures
above lift the SAME bug shape standalone so the family is provable end-to-end
without fabricating a lift of an uncloneable protocol-coupled fn.

RELATED TOOLS (Rule: tool-duplication preflight)
=================================================
  * tools/evm-0day-proof-pipeline.py - the EVM/Solidity twin (forge). Disjoint
    target language + disjoint engine (forge, not cargo/go test). This tool is
    its Rust+Go counterpart and shares its verdict vocabulary verbatim. DO NOT
    EDIT that file (sibling lane A owns it).
  * tools/rust-engine-harness-author.py - AUTHORS model-based kani/proptest/
    bolero harnesses. It is the AUTHOR; this tool is the auto-CONVERTER that
    picks the invariant, authors a REAL-fn-driving harness, RUNS it, and
    adjudicates. The author has no pick+run+adjudicate step; this tool fills it.
  * tools/go-engine-harness-author.py - AUTHORS Go fuzz/property harnesses
    (real no-panic, model determinism/round-trip). Same author-vs-converter
    distinction.
  * tools/novel-vector-invariant-miner.py - DERIVES target-specific invariants.
    This tool CONSUMES the invariant FAMILY (category) for the picked vuln_class
    and grounds the harness in an indexed INV-* id when one matches.
  * tools/engine-harness-proof-gate.py - the credit GATE (catches stub/ghost/
    tautology harnesses). This tool's authored harness is designed to PASS that
    gate (non-tautological invariant assertion driving the real fn).

Usage
=====
  engine-auto-convert.py --target-file <path> --fn <name> --vuln-class <class> \
      --language {rust,go} [--out-dir <dir>] [--no-run] [--json]

  engine-auto-convert.py --candidate-json <path>   # {target_file,fn,vuln_class,language}

Exit codes
==========
  0  proof-backed
  1  blocked-with-obligation OR refuted
  2  input error
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.realfn_token_guard import (  # noqa: E402
    verify_realfn_tokens_or_downgrade,
)

SCHEMA_VERSION = "auditooor.engine_auto_convert.v1"

PROOF_BACKED = "proof-backed"
BLOCKED = "blocked-with-obligation"
REFUTED = "refuted"
ERROR = "error"

DEFAULT_INVARIANT_SOURCES = [
    "audit/corpus_tags/derived/invariants_extracted.jsonl",
    "audit/corpus_tags/derived/invariants_pilot.jsonl",
]

# vuln_class -> (invariant category, canonical guard kind the FIXED variant adds).
# Only classes for which we can mechanically derive BOTH a buggy lift and a
# fixed variant + a real invariant assertion are convertible. Everything else
# is honestly reported as blocked-with-obligation (no fabricated fix).
VULN_CLASS_MAP: Dict[str, Tuple[str, str]] = {
    # freshness/uniqueness family (guard = freshness-flag): a consumable resource
    # must be usable at most once.
    "nonce-reuse": ("uniqueness", "freshness-flag"),
    "nonce-reuse-risk": ("uniqueness", "freshness-flag"),
    "replay": ("uniqueness", "freshness-flag"),
    "replay-attack": ("uniqueness", "freshness-flag"),
    "missing-freshness-guard": ("freshness", "freshness-flag"),
    "missing-nonce-check": ("freshness", "freshness-flag"),
    "double-spend": ("uniqueness", "freshness-flag"),
    "missing-uniqueness-check": ("uniqueness", "freshness-flag"),
    "unscoped-secret": ("uniqueness", "freshness-flag"),
    # bounds / dos-resource-exhaustion family (guard = cap-check): a
    # caller-controlled allocation/iteration length must be capped to a
    # configured bound before the allocation; an over-cap request must be
    # rejected. Grounded by corpus INV-BND-009 / INV-BND-EX-0004 [bounds].
    "dos-resource-exhaustion": ("bounds", "cap-check"),
    "resource-exhaustion": ("bounds", "cap-check"),
    "allocation-amplification": ("bounds", "cap-check"),
    "unbounded-allocation": ("bounds", "cap-check"),
    "unbounded-alloc": ("bounds", "cap-check"),
    "missing-bounds-check": ("bounds", "cap-check"),
    "missing-cap-check": ("bounds", "cap-check"),
    "unbounded-loop": ("bounds", "cap-check"),
    "over-allocation": ("bounds", "cap-check"),
    # missing-input-validation family (iter12 BS-3): a caller-controlled
    # length/count input is consumed without a domain check. Mechanically this
    # is the same shape the cap-check guard fixes - an unchecked input that must
    # be rejected when it exceeds the configured bound. Mapping it to the bounds
    # family lets the existing length-param + cap detection drive the conversion
    # for the cap-checkable subset; non-cap-checkable input-validation shapes
    # honestly fall through to blocked-with-obligation (no length param / no
    # configured cap), never a fabricated fix.
    "missing-input-validation": ("bounds", "cap-check"),
    "missing-validation": ("bounds", "cap-check"),
    "unchecked-input": ("bounds", "cap-check"),
    "missing-length-check": ("bounds", "cap-check"),
    # conservation / normalization family (guard = sum-check): a caller-supplied
    # collection of weight/share/amount-bearing items must satisfy a conservation
    # invariant - the field SUM must equal a configured total (e.g. weights sum
    # to 1.0/100%) and each item must be positive. The buggy fn consumes the
    # collection WITHOUT the sum/positivity check; a non-conserving collection
    # (sum != EXPECTED) is silently accepted, corrupting the downstream
    # distribution. Mechanically convertible whenever a slice/Vec-of-struct param
    # carries a numeric weight-like field; non-convertible shapes (no collection
    # param, no numeric weight field) honestly fall through to
    # blocked-with-obligation (no fabricated fix). The conservation taxonomy is
    # grounded by the corpus INV-CON-* family (the corpus-hunt layer already
    # surfaces INV-CON-004 on the Cosmos validator-weight shape).
    "missing-conservation-check": ("conservation", "sum-check"),
    "missing-normalization-check": ("conservation", "sum-check"),
    "unchecked-weight-sum": ("conservation", "sum-check"),
    "weight-sum-not-validated": ("conservation", "sum-check"),
    "intent-weight-validation": ("conservation", "sum-check"),
    "missing-weight-validation": ("conservation", "sum-check"),
    "distribution-not-normalized": ("conservation", "sum-check"),
    "unnormalized-weights": ("conservation", "sum-check"),
    "share-sum-not-validated": ("conservation", "sum-check"),
    # integer-overflow / narrowing-truncation family (guard = cast-bound-check):
    # a caller-controlled WIDE numeric value flows into a NARROWING cast
    # (`u64 as u32` in Rust; `uint32(x)` in Go) without a prior bound check, so a
    # value above the narrow type's max silently truncates (wraps), corrupting the
    # returned/stored amount. The buggy fn performs the cast unconditionally; the
    # fixed variant rejects any input exceeding the narrow type's max BEFORE the
    # cast. Mechanically convertible whenever a wide numeric param is narrowed by
    # an `as <narrow>` cast (Rust) or `<narrow>(<param>)` conversion (Go) and the
    # fn signals rejection via Result/error; non-convertible shapes (no narrowing
    # cast / no wide-param source / no error-rejection channel) honestly fall
    # through to blocked-with-obligation (no fabricated fix). Grounded by the
    # corpus INV-INT-* / overflow-truncation family.
    "integer-overflow": ("int-truncation", "cast-bound-check"),
    "integer-truncation": ("int-truncation", "cast-bound-check"),
    "narrowing-cast": ("int-truncation", "cast-bound-check"),
    "unchecked-cast": ("int-truncation", "cast-bound-check"),
    "unchecked-narrowing": ("int-truncation", "cast-bound-check"),
    "truncation": ("int-truncation", "cast-bound-check"),
    "downcast-truncation": ("int-truncation", "cast-bound-check"),
    "silent-truncation": ("int-truncation", "cast-bound-check"),
    "missing-overflow-check": ("int-truncation", "cast-bound-check"),
    "unsafe-cast": ("int-truncation", "cast-bound-check"),
    # access-control-bypass family (guard = owner-guard): a state-mutating fn
    # takes a `&mut <T>` / `*<T>` state struct carrying an owner/admin/authority-
    # like identity field AND a caller/sender param, but consumes them WITHOUT
    # comparing caller against the stored owner - so any caller can mutate state
    # an owner-only operation should gate. The buggy fn omits the equality guard;
    # the fixed variant injects `if caller != state.owner { reject }` BEFORE the
    # mutation. Mechanically convertible whenever a mutable state param's struct
    # carries an identity field AND the signature carries a caller param of the
    # same type AND rejection is signalled via Result/error; non-convertible
    # shapes (no identity field / no caller param / type mismatch / no error
    # channel) honestly fall through to blocked-with-obligation (no fabricated
    # fix). Grounded by the corpus INV-AC-* access-control family.
    "access-control-bypass": ("access-control", "owner-guard"),
    "missing-access-control": ("access-control", "owner-guard"),
    "missing-owner-check": ("access-control", "owner-guard"),
    "missing-authorization": ("access-control", "owner-guard"),
    "missing-auth-check": ("access-control", "owner-guard"),
    "unauthorized-state-mutation": ("access-control", "owner-guard"),
    "missing-only-owner": ("access-control", "owner-guard"),
    "broken-access-control": ("access-control", "owner-guard"),
    "missing-caller-check": ("access-control", "owner-guard"),
    "privilege-escalation": ("access-control", "owner-guard"),
    # reentrancy / checks-effects-interactions (CEI) violation family (guard =
    # cei-order-check): a state-mutating fn performs an EXTERNAL CALL (modeled by
    # a caller-supplied callback / hook param) BEFORE writing the state effect, so
    # a re-entrant observer (the callback) sees the pre-effect state and can
    # double-act on it. The buggy fn orders the external call before the state
    # write; the fixed variant moves the state write BEFORE the external call
    # (checks-effects-interactions order). Mechanically convertible whenever a
    # `&mut <State>` (Rust) / `*<State>` (Go) state param carries a numeric
    # balance-like field that is written AFTER a callback/hook param is invoked in
    # the body; non-convertible shapes (no callback param / no post-call state
    # write / write already precedes the call) honestly fall through to
    # blocked-with-obligation (no fabricated fix). Grounded by the corpus INV-REE-*
    # reentrancy family.
    "reentrancy": ("reentrancy", "cei-order-check"),
    "reentrancy-vulnerability": ("reentrancy", "cei-order-check"),
    "reentrancy-risk": ("reentrancy", "cei-order-check"),
    "cei-violation": ("reentrancy", "cei-order-check"),
    "checks-effects-interactions": ("reentrancy", "cei-order-check"),
    "checks-effects-interactions-violation": ("reentrancy", "cei-order-check"),
    "state-update-after-external-call": ("reentrancy", "cei-order-check"),
    "external-call-before-state-update": ("reentrancy", "cei-order-check"),
    "missing-reentrancy-guard": ("reentrancy", "cei-order-check"),
    "read-only-reentrancy": ("reentrancy", "cei-order-check"),
    # valid-flag staleness-on-read family (guard = valid-flag-check): a read/
    # valuation fn returns a stored price/value from a struct that ALSO carries a
    # boolean freshness/validity flag (`valid` / `fresh` / `is_stale`), but (in the
    # buggy variant) returns the value WITHOUT consulting that flag - so a datum
    # the source already marked invalid/stale is read as a current one. This is the
    # boolean-flag sibling of the timestamp-based staleness-gate sub-shape (the
    # timestamp shape compares `ts < now - max_delay`; this shape consults a
    # pre-computed validity bool). The fixed variant injects a `if !<flag> {
    # reject }` (or `if <stale_flag> { reject }`) gate before the read.
    # Mechanically convertible whenever the read fn takes a `&<T>` / `*<T>` ref
    # whose struct carries a canonical validity/staleness bool field AND signals
    # rejection via Result/error; non-convertible shapes (no validity bool / no
    # error channel) honestly fall through to blocked-with-obligation. Grounded by
    # the corpus INV-FRE-* freshness family.
    "stale-price-on-read": ("freshness", "valid-flag-check"),
    "missing-validity-check": ("freshness", "valid-flag-check"),
    "unchecked-validity-flag": ("freshness", "valid-flag-check"),
    "ignored-freshness-flag": ("freshness", "valid-flag-check"),
    "ignored-validity-flag": ("freshness", "valid-flag-check"),
    "stale-oracle-read": ("freshness", "valid-flag-check"),
    "missing-staleness-flag-check": ("freshness", "valid-flag-check"),
    # double-mint / double-credit family (guard = processed-flag-check): a fn
    # credits / mints / settles an amount onto an id-bearing state struct WITHOUT a
    # `processed` / `claimed` / `settled` boolean flag, so a replayed call on the
    # SAME state double-credits. The buggy fn omits the flag guard; the fixed
    # variant injects a `processed`-flag field on the struct + a guard that rejects
    # a second call and sets the flag on the first. Mechanically convertible
    # whenever the fn takes a single `&mut <T>` / `*<T>` state param carrying a
    # numeric credited/amount/balance-like field AND signals rejection via
    # Result/error; non-convertible shapes (no state param / no creditable numeric
    # field / no error channel) honestly fall through to blocked-with-obligation.
    # Grounded by the corpus INV-UNQ-* uniqueness family (a credit must apply at
    # most once per id).
    "double-mint": ("uniqueness", "processed-flag-check"),
    "double-credit": ("uniqueness", "processed-flag-check"),
    "double-claim": ("uniqueness", "processed-flag-check"),
    "double-settlement": ("uniqueness", "processed-flag-check"),
    "missing-processed-flag": ("uniqueness", "processed-flag-check"),
    "missing-claimed-flag": ("uniqueness", "processed-flag-check"),
    "unprotected-claim": ("uniqueness", "processed-flag-check"),
    "replayable-credit": ("uniqueness", "processed-flag-check"),
    "replayable-mint": ("uniqueness", "processed-flag-check"),
    "missing-replay-protection": ("uniqueness", "processed-flag-check"),
    # signature-replay / missing-nonce family (guard = used-nonce-check): a
    # verify/authorize/execute fn consumes a signature/message-bearing param AND a
    # `*<State>` struct carrying a nonce/used-like field, but consumes them WITHOUT
    # marking the nonce consumed - so the SAME signed payload replays. This differs
    # from double-credit (keyed on a written *credit* field): signature-replay is
    # keyed on a SIGNATURE/MESSAGE param + an unconsulted nonce/used identity. The
    # buggy fn omits the used-nonce guard; the fixed variant injects a
    # `if state.<nonce-flag> { reject }; state.<nonce-flag> = true` guard BEFORE the
    # authorized effect. Mechanically convertible whenever the fn takes a
    # signature/message-bearing param AND a single `*<State>` param carrying a
    # canonical nonce/used field AND signals rejection via Result/error;
    # non-convertible shapes (no signature param / no nonce field / no error
    # channel / nonce already consulted) honestly fall through to
    # blocked-with-obligation. Grounded by the corpus INV-UNQ-* uniqueness family
    # (a signed authorization must be consumable at most once).
    "signature-replay": ("uniqueness", "used-nonce-check"),
    "signature-replay-attack": ("uniqueness", "used-nonce-check"),
    "missing-nonce": ("uniqueness", "used-nonce-check"),
    "missing-nonce-increment": ("uniqueness", "used-nonce-check"),
    "missing-used-flag": ("uniqueness", "used-nonce-check"),
    "replayable-signature": ("uniqueness", "used-nonce-check"),
    "replayable-authorization": ("uniqueness", "used-nonce-check"),
    "missing-sig-replay-protection": ("uniqueness", "used-nonce-check"),
    "unprotected-signature": ("uniqueness", "used-nonce-check"),
    "permit-replay": ("uniqueness", "used-nonce-check"),
    # unchecked-external-call-return family (guard = call-return-check): a fn makes
    # an external call/transfer (modeled by a caller-supplied callback returning a
    # `(bool)` success / `error`) and IGNORES the returned status - so a FAILED
    # external call is treated as success and the fn proceeds with its post-call
    # effect (e.g. marks a payout sent that never landed). The buggy fn discards
    # the call's return; the fixed variant checks it and rejects (returns the
    # error / reverts) when the call signals failure. Mechanically convertible
    # whenever the fn takes a callback/transfer param whose result type is `bool`
    # or `error` AND the body invokes it WITHOUT consuming the result AND the fn
    # signals rejection via Result/error; non-convertible shapes (no call param /
    # result already checked / no error channel) honestly fall through to
    # blocked-with-obligation. Grounded by the corpus INV-CALL-* / INV-EXT-*
    # external-call family (an external call's failure MUST propagate).
    "unchecked-external-call-return": ("external-call", "call-return-check"),
    "unchecked-call-return": ("external-call", "call-return-check"),
    "unchecked-return-value": ("external-call", "call-return-check"),
    "ignored-return-value": ("external-call", "call-return-check"),
    "unchecked-transfer-return": ("external-call", "call-return-check"),
    "unchecked-send": ("external-call", "call-return-check"),
    "ignored-call-failure": ("external-call", "call-return-check"),
    "swallowed-error": ("external-call", "call-return-check"),
    "unchecked-low-level-call": ("external-call", "call-return-check"),
    # missing-deadline / slippage-bound family (guard = deadline-bound-check): a
    # swap/fill/exec fn takes an amount/price/quote param but NO deadline/min-out
    # bound, so it executes under stale/adverse conditions (an execution price far
    # worse than the caller intended, or a long-expired order). The buggy fn omits
    # the bound check; the fixed variant rejects when the realized value violates a
    # caller-supplied `min_out` / `deadline` bound passed BEFORE the execution.
    # Mechanically convertible whenever the fn takes a numeric realized/output
    # amount param AND a caller-supplied bound param (min_out / deadline / max_in /
    # limit) of a numeric type AND the body does NOT compare them AND the fn signals
    # rejection via Result/error; non-convertible shapes (no realized param / no
    # bound param / bound already enforced / no error channel) honestly fall through
    # to blocked-with-obligation. Grounded by the corpus INV-BND-* / INV-SLIP-*
    # bound family (a realized execution value MUST satisfy the caller's bound).
    "missing-deadline": ("slippage-bound", "deadline-bound-check"),
    "missing-deadline-check": ("slippage-bound", "deadline-bound-check"),
    "missing-slippage-check": ("slippage-bound", "deadline-bound-check"),
    "missing-slippage-bound": ("slippage-bound", "deadline-bound-check"),
    "missing-min-out": ("slippage-bound", "deadline-bound-check"),
    "missing-minimum-output": ("slippage-bound", "deadline-bound-check"),
    "unbounded-slippage": ("slippage-bound", "deadline-bound-check"),
    "no-deadline-protection": ("slippage-bound", "deadline-bound-check"),
    "missing-price-bound": ("slippage-bound", "deadline-bound-check"),
}

# Numeric field names that mark a per-item weight/share/amount in a collection
# whose SUM is a conservation invariant. Used by both the Go and Rust
# conservation convert paths. GENERAL - no target symbol names; these are the
# canonical distribution-field names a weight-sum invariant ranges over.
_WEIGHT_FIELD_RE = re.compile(
    r"^(weight|share|ratio|fraction|portion|allocation|pct|percent|percentage|"
    r"proportion|amount|stake|power|bps)$",
    re.IGNORECASE)

# Numeric Go/Rust field types a weight may carry. We treat cosmos-sdk `Dec` /
# `LegacyDec` as a numeric weight type too (the dominant Cosmos shape), but for
# a SELF-CONTAINED drive-in-place fixture the weight field must be a primitive
# numeric (or an in-file numeric newtype) so the harness can construct literals
# without a protocol decimal library. A `Dec`/`Decimal` field on a NON-self-
# contained target blocks earlier at the self-containment gate, so here we only
# need the primitive-numeric recognizer.
_GO_NUMERIC_TYPES = {"uint", "uint8", "uint16", "uint32", "uint64",
                     "int", "int8", "int16", "int32", "int64",
                     "byte", "rune", "float32", "float64"}

# ---------------------------------------------------------------------------
# int-truncation family (guard = cast-bound-check).
# ---------------------------------------------------------------------------
# A NARROWING cast is a conversion from a wider integer type to a strictly
# narrower one (the destination holds fewer bits than the source). When the
# source value can exceed the destination's max, the cast silently truncates
# (Rust `as` wraps to the low bits; Go `uintN(x)` likewise), corrupting the
# value. The fixed variant rejects values above the destination max BEFORE the
# cast. The detection is signature-driven: a WIDE numeric param flows into a
# narrowing cast in the body. These maps are GENERAL - no target symbol names.

# bit-width per integer type name (unsigned + signed share the width set; the
# bound-check uses the *unsigned* max of the destination width, which is the
# value above which truncation occurs for the dominant unsigned-amount shape).
_RUST_INT_WIDTH = {
    "u8": 8, "u16": 16, "u32": 32, "u64": 64, "u128": 128, "usize": 64,
    "i8": 8, "i16": 16, "i32": 32, "i64": 64, "i128": 128, "isize": 64,
}
_GO_INT_WIDTH = {
    "uint8": 8, "uint16": 16, "uint32": 32, "uint64": 64, "uint": 64,
    "int8": 8, "int16": 16, "int32": 32, "int64": 64, "int": 64,
    "byte": 8, "rune": 32, "uintptr": 64,
}
# unsigned max for a given destination bit width (the threshold above which a
# value cannot be represented in the narrow type and is silently truncated).
_UNSIGNED_MAX = {8: "255", 16: "65535", 32: "4294967295", 64: "18446744073709551615"}

# ---------------------------------------------------------------------------
# access-control family (guard = owner-guard).
# ---------------------------------------------------------------------------
# An identity field on a state struct names the principal a privileged operation
# must be gated on; a caller param names the principal actually invoking the fn.
# When a state-mutating fn omits the `caller == state.<identity>` equality guard,
# any caller can perform the privileged mutation. The detection is signature-
# driven: a mutable state param whose struct carries an identity field, plus a
# caller param of the SAME type, with NO equality comparison between them in the
# body. These name sets are GENERAL - canonical identity / caller field names.
_IDENTITY_FIELD_RE = re.compile(
    r"^(owner|admin|authority|controller|governor|manager|operator|guardian|"
    r"creator|minter|root|superuser|super_admin|admin_key|owner_key|"
    r"authorized|authorized_key)$",
    re.IGNORECASE)
_CALLER_PARAM_RE = re.compile(
    r"^(caller|sender|msg_sender|signer|from|invoker|actor|origin|account|"
    r"who|principal|requester|user|tx_sender)$",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# reentrancy / CEI family (guard = cei-order-check).
# ---------------------------------------------------------------------------
# A callback/hook param models the external call the CEI ordering must precede.
# A numeric balance-like state field is the effect written either BEFORE (fixed)
# or AFTER (buggy) the external call. These name sets are GENERAL - canonical
# callback / balance field names, no target symbol names.
_HOOK_PARAM_RE = re.compile(
    r"^(hook|callback|cb|on_call|external|ext_call|notify|notifier|receiver|"
    r"recipient_hook|handler|sink|emit|observer|reentrant|call_back|after)$",
    re.IGNORECASE)
_BALANCE_FIELD_RE = re.compile(
    r"^(balance|bal|amount|credited|credit|debt|deposit|deposits|shares|funds|"
    r"reserve|reserves|holdings|owed|principal|collateral|escrow|locked|"
    r"available)$",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# valid-flag staleness-on-read family (guard = valid-flag-check).
# ---------------------------------------------------------------------------
# A boolean validity/freshness flag on the read struct names whether the stored
# value is current. A POSITIVE flag (`valid`/`fresh`) must be TRUE to accept; a
# NEGATIVE flag (`stale`/`invalid`/`expired`) must be FALSE to accept. The reader
# (buggy) returns the value WITHOUT consulting the flag. These name sets are
# GENERAL - canonical validity-flag field names, no target symbol names.
_VALID_FLAG_POSITIVE_RE = re.compile(
    r"^(valid|is_valid|fresh|is_fresh|active|is_active|live|is_live|ok|is_ok|"
    r"healthy|is_healthy|current|is_current|trusted|is_trusted)$",
    re.IGNORECASE)
_VALID_FLAG_NEGATIVE_RE = re.compile(
    r"^(stale|is_stale|invalid|is_invalid|expired|is_expired|outdated|"
    r"is_outdated|frozen|is_frozen|paused|is_paused|deprecated|is_deprecated)$",
    re.IGNORECASE)
_PRICE_FIELD_RE = re.compile(
    r"^(price|value|rate|amount|val|quote|reading|answer|data|measurement|"
    r"figure|level)$",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# double-mint / double-credit family (guard = processed-flag-check).
# ---------------------------------------------------------------------------
# A creditable numeric field is the per-id amount a double-call would apply
# twice; an id-like field marks the per-call identity. The fixed variant injects
# a `processed` flag the buggy fn lacks. These name sets are GENERAL - canonical
# credit / id field names, no target symbol names.
_CREDIT_FIELD_RE = re.compile(
    r"^(credited|credit|minted|mint|settled|settlement|paid|payout|balance|bal|"
    r"claimed_amount|distributed|redeemed|withdrawn|accrued|total|accumulated)$",
    re.IGNORECASE)
# canonical pre-existing processed/claimed flag names: if the struct already
# carries one of these, the bug is NOT mechanically present (the fn likely
# already guards on it) -> we still synthesize but with the existing flag rather
# than injecting a fresh one. The injected flag uses a NAME that cannot collide.
_PROCESSED_FLAG_RE = re.compile(
    r"^(processed|is_processed|claimed|is_claimed|settled|is_settled|done|"
    r"is_done|consumed|is_consumed|finalized|is_finalized|redeemed|"
    r"is_redeemed|spent|is_spent)$",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# signature-replay / missing-nonce family (guard = used-nonce-check).
# ---------------------------------------------------------------------------
# A signature/message-bearing param names the authorization the fn consumes; a
# nonce/used field on the `*State` struct names the per-authorization freshness
# the fn must consume. The buggy fn authorizes WITHOUT marking the nonce used, so
# the same signed payload replays. These name sets are GENERAL - canonical
# signature/message param names and nonce/used field names, no target symbols.
_SIG_PARAM_RE = re.compile(
    r"^(sig|signature|sigs|signatures|msg|message|msg_hash|digest|payload|"
    r"voucher|permit|authorization|auth|signed_msg|signed|proof|attestation|"
    r"witness|approval|claim_sig)$",
    re.IGNORECASE)
# nonce/used field that, when consumed, prevents replay. A FLAG nonce (`used`,
# `consumed`) is a bool the fn must flip true; a COUNTER nonce (`nonce`, `seq`)
# is a numeric the fn must increment/compare. We handle the bool-flag sub-shape
# mechanically (inject the flip-and-reject guard); a bare numeric nonce with no
# comparison is also a missing-guard (the buggy fn never reads it).
_NONCE_FLAG_RE = re.compile(
    r"^(used|is_used|consumed|is_consumed|spent|is_spent|replayed|seen|"
    r"is_seen|redeemed_sig|sig_used)$",
    re.IGNORECASE)
_NONCE_COUNTER_RE = re.compile(
    r"^(nonce|seq|sequence|seqno|seq_no|counter|nonce_counter|tx_nonce|"
    r"account_nonce|msg_nonce)$",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# unchecked-external-call-return family (guard = call-return-check).
# ---------------------------------------------------------------------------
# A call/transfer param models the external call whose return status the fn must
# consult. The buggy fn INVOKES it but discards the `(bool)` / `error` result, so
# a failed call is treated as success. These name sets are GENERAL - canonical
# external-call param names, no target symbols. (Distinct from the reentrancy
# _HOOK_PARAM_RE: that hook returns nothing and models CEI ordering; this call
# returns a success status the fn must check.)
_CALL_PARAM_RE = re.compile(
    r"^(call|transfer|send|do_call|external_call|ext_call|invoke|dispatch|"
    r"payout|remit|push|deliver|forward|low_level_call|raw_call|try_call|"
    r"do_transfer|do_send)$",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# missing-deadline / slippage-bound family (guard = deadline-bound-check).
# ---------------------------------------------------------------------------
# A realized-output numeric param names the value a swap/fill actually produces;
# a caller-supplied bound param names the floor/ceiling/deadline the realized
# value must satisfy. The buggy fn does NOT compare them, executing under adverse
# conditions. These name sets are GENERAL - canonical realized / bound param
# names, no target symbols.
_REALIZED_PARAM_RE = re.compile(
    r"^(out|output|out_amount|amount_out|realized|realized_out|received|"
    r"received_amount|exec_price|fill_price|quote|quoted|got|result_amount|"
    r"actual|actual_out|now|current_time|block_time|timestamp)$",
    re.IGNORECASE)
_BOUND_PARAM_RE = re.compile(
    r"^(min_out|minimum_out|min_amount_out|min_received|min_return|"
    r"slippage_bound|slippage|deadline|expiry|expiration|max_in|max_amount_in|"
    r"limit|price_limit|min_price|floor|threshold|valid_until|valid_to)$",
    re.IGNORECASE)
# Bound params split into two polarities: a MINIMUM bound (realized >= bound to
# accept; min_out / min_received / floor) and a DEADLINE/ceiling bound (realized
# <= bound to accept; deadline / expiry / valid_until / limit). The fixed-variant
# guard direction is chosen by which set the bound param name falls in.
_BOUND_MIN_RE = re.compile(
    r"^(min_out|minimum_out|min_amount_out|min_received|min_return|"
    r"min_price|floor|threshold|min_amount)$",
    re.IGNORECASE)
_BOUND_MAX_RE = re.compile(
    r"^(deadline|expiry|expiration|valid_until|valid_to|max_in|max_amount_in|"
    r"limit|price_limit|slippage_bound)$",
    re.IGNORECASE)


def normalize_vuln_class(raw: str) -> str:
    s = (raw or "").strip().lower().replace("_", "-").replace(" ", "-")
    return s


def map_vuln_class(vuln_class: str) -> Optional[Tuple[str, str]]:
    return VULN_CLASS_MAP.get(normalize_vuln_class(vuln_class))


# ---------------------------------------------------------------------------
# Invariant grounding (pick an INV-* from the corpus for the category).
# ---------------------------------------------------------------------------

def pick_invariant(repo_root: Path, category: str, language: str) -> Dict[str, Any]:
    """Return the lowest-id indexed invariant whose category matches and whose
    target_lang is the language or 'any'. Falls back to a synthetic id if the
    corpus has no matching record (so grounding is best-effort, never blocking)."""
    langs = (language, "any")
    best: Optional[Dict[str, Any]] = None
    for rel in DEFAULT_INVARIANT_SOURCES:
        path = repo_root / rel
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            content = d.get("content") if isinstance(d.get("content"), dict) else d
            inv_id = (content.get("invariant_id") or d.get("invariant_id")
                      or d.get("record_id"))
            cat = (content.get("category") or "").strip().lower()
            tl = (content.get("target_lang") or content.get("target_language")
                  or d.get("target_lang") or d.get("target_language") or "")
            if not inv_id or cat != category or tl not in langs:
                continue
            stmt = (content.get("statement") or content.get("invariant_text") or "").strip()
            cand = {"invariant_id": inv_id, "category": cat,
                    "statement": stmt, "grounded": True}
            if best is None or inv_id < best["invariant_id"]:
                best = cand
    if best is not None:
        return best
    return {"invariant_id": f"INV-SYNTH-{category.upper().replace('-', '')}",
            "category": category,
            "statement": _SYNTH_STATEMENT.get(
                category,
                "a category-bearing identifier MUST be consumable at most once; "
                "a replay MUST be rejected"),
            "grounded": False}


# Category-appropriate synthetic invariant statements used when the corpus has
# no indexed INV-* for the picked category (grounding is best-effort, never
# blocking). GENERAL - one statement per convert-family category.
_SYNTH_STATEMENT = {
    "uniqueness": ("a consumable resource MUST be usable at most once; a replay "
                   "MUST be rejected"),
    "freshness": ("a freshness-bearing input MUST be rejected when stale (its "
                  "stored timestamp is older than now - max_delay)"),
    "bounds": ("a caller-controlled allocation/iteration length MUST be bounded "
               "by the configured cap; an over-cap request MUST be rejected"),
    "conservation": ("a caller-supplied weight/share collection MUST conserve "
                     "(field sum == the configured total, all items positive)"),
    "int-truncation": ("a wide caller-controlled value MUST be rejected before a "
                       "narrowing cast when it exceeds the destination type max "
                       "(it would otherwise silently truncate)"),
    "access-control": ("a privileged state mutation MUST be gated on caller == "
                       "the stored owner; a non-owner caller MUST be rejected"),
    "reentrancy": ("a state effect MUST be written BEFORE the external call it "
                   "guards (checks-effects-interactions); a re-entrant observer "
                   "MUST see the post-effect state"),
    "external-call": ("an external call's failure status MUST be checked and "
                      "propagated; a failed call MUST NOT be treated as success"),
    "slippage-bound": ("a realized execution value MUST satisfy the caller-supplied "
                       "bound (realized >= min_out, or realized <= deadline); an "
                       "out-of-bound execution MUST be rejected"),
}


# ---------------------------------------------------------------------------
# Target-function lift (self-containment detection).
# ---------------------------------------------------------------------------

def read_target(target_file: Path) -> str:
    return target_file.read_text(encoding="utf-8", errors="replace")


def extract_rust_fn(src: str, fn: str) -> Optional[str]:
    """Extract the full `pub fn <fn>(...) {...}` body by brace-matching."""
    m = re.search(rf"\bpub\s+fn\s+{re.escape(fn)}\s*\(", src)
    if not m:
        m = re.search(rf"\bfn\s+{re.escape(fn)}\s*\(", src)
    if not m:
        return None
    # find the opening brace after the signature, then brace-match.
    i = src.find("{", m.start())
    if i < 0:
        return None
    depth = 0
    j = i
    while j < len(src):
        c = src[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():j + 1]
        j += 1
    return None


def extract_go_fn(src: str, fn: str) -> Optional[str]:
    # Match BOTH free functions (`func Name(...)`) AND method-receiver functions
    # (`func (k msgServer) Name(...)`). The optional `(<receiver>)` group between
    # `func` and the name is what Cosmos-SDK / Go-idiomatic method definitions
    # carry; without it the extractor silently missed every keeper/msgServer
    # method (the dominant shape in cosmos-sdk targets). The receiver group is
    # `\([^)]*\)` followed by required whitespace before the name.
    m = re.search(rf"\bfunc\s+(?:\([^)]*\)\s+)?{re.escape(fn)}\s*\(", src)
    if not m:
        return None
    i = src.find("{", m.start())
    if i < 0:
        return None
    depth = 0
    j = i
    while j < len(src):
        c = src[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():j + 1]
        j += 1
    return None


# Type names referenced by the target fn that must be defined in the same file
# for the lift to be self-contained. We collect the type names from struct/type
# decls and verify the fn signature + body refer only to those (plus primitives).
_RUST_PRIMITIVE = {
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
    "isize", "bool", "char", "str", "String", "Vec", "Result", "Option", "Box",
    "f32", "f64",
    # closure/fn-trait markers used by the reentrancy/CEI shape's external-call
    # stand-in param (`&mut dyn FnMut(...)`, `impl FnMut`, `F: FnMut`). These are
    # std fn-traits, not target-defined types, so they do not break self-containment.
    "Fn", "FnMut", "FnOnce",
}
_GO_PRIMITIVE = {
    "uint", "uint8", "uint16", "uint32", "uint64", "int", "int8", "int16",
    "int32", "int64", "byte", "rune", "bool", "string", "float32", "float64",
    "error", "uintptr",
}


def rust_defined_types(src: str) -> set:
    out = set()
    for m in re.finditer(r"\b(?:pub\s+)?struct\s+([A-Za-z_]\w*)", src):
        out.add(m.group(1))
    for m in re.finditer(r"\b(?:pub\s+)?enum\s+([A-Za-z_]\w*)", src):
        out.add(m.group(1))
    for m in re.finditer(r"\b(?:pub\s+)?type\s+([A-Za-z_]\w*)", src):
        out.add(m.group(1))
    return out


def go_defined_types(src: str) -> set:
    out = set()
    for m in re.finditer(r"\btype\s+([A-Za-z_]\w*)\s+(?:struct|interface|[A-Za-z\[\]*]+)", src):
        out.add(m.group(1))
    return out


def rust_sig_types(fn_src: str) -> set:
    """Collect capitalized identifiers from the signature (param + return
    portion, after the fn name's `(`), which are the candidate user-defined
    type references. Excludes the fn name itself."""
    paren = fn_src.find("(")
    sig = fn_src[paren: fn_src.find("{")] if paren >= 0 else ""
    return set(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", sig))


def go_sig_types(fn_src: str) -> set:
    # Scan only the param + return portion (after the fn NAME's `(`), so the
    # capitalized fn name itself is not mistaken for a type reference. For a
    # receiver method `func (r *Recv) Name(params) ret`, the FIRST `(` opens the
    # receiver group, not the param list - skip the receiver group so the param
    # `(` is the anchor (otherwise the fn name `Name` leaks in as a false type
    # ref and a self-contained receiver method spuriously blocks). The receiver
    # type itself is a real in-file dependency, so we DO include it in refs.
    m = re.match(r"\s*func\s+(\([^)]*\)\s+)?([A-Za-z_]\w*)\s*\(", fn_src)
    if m:
        recv_refs: set = set()
        if m.group(1):
            recv_refs = set(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", m.group(1)))
        # anchor at the param-list `(` (end of the matched prefix minus 1).
        paren = m.end() - 1
        sig = fn_src[paren: fn_src.find("{")] if paren >= 0 else ""
        return recv_refs | set(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", sig))
    # Free-function / fallback: original behavior (first `(` is the param list).
    paren = fn_src.find("(")
    sig = fn_src[paren: fn_src.find("{")] if paren >= 0 else ""
    return set(re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", sig))


def is_rust_self_contained(target_src: str, fn_src: str) -> Tuple[bool, List[str]]:
    defined = rust_defined_types(target_src)
    refs = rust_sig_types(fn_src)
    unresolved = sorted(r for r in refs
                        if r not in defined and r not in _RUST_PRIMITIVE)
    # An external import (`use foo::Bar`) or `::` path in the body also breaks
    # self-containment unless the path root is std/core.
    body = fn_src[fn_src.find("{"):]
    ext_path = bool(re.search(r"\b(?!std::|core::|Self::)[a-z_]\w*::[A-Za-z_]", body))
    return (not unresolved and not ext_path), unresolved


def is_go_self_contained(target_src: str, fn_src: str) -> Tuple[bool, List[str]]:
    defined = go_defined_types(target_src)
    refs = go_sig_types(fn_src)
    unresolved = sorted(r for r in refs
                        if r not in defined and r not in _GO_PRIMITIVE)
    body = fn_src[fn_src.find("{"):]
    # qualified call like `pkg.Func(` (a dot before an identifier-call) breaks
    # self-containment; method calls on locals are fine but conservatively we
    # only block on package-qualified Capitalized refs.
    ext_pkg = bool(re.search(r"\b[a-z_]\w*\.[A-Z]\w*\(", body))
    return (not unresolved and not ext_pkg), unresolved


# ---------------------------------------------------------------------------
# Fixed-variant derivation (canonical guard) + harness authoring.
# ---------------------------------------------------------------------------

def derive_rust_fixed(fn_src: str, fn: str, fixed_name: str, guard: str) -> Optional[str]:
    """Apply the canonical guard for the vuln class. For freshness-flag: rename
    to fixed_name, ensure the nonce-bearing &mut param gets a `used`-flag reject
    + set. We only handle the case where the fn takes a `&mut <T>` param whose
    type has (or we add) a `used: bool` field. Returns the fixed fn source, or
    None if the shape isn't mechanically fixable."""
    if guard != "freshness-flag":
        return None
    # Find a `&mut <ident>: &mut <Type>` parameter (the consumable resource).
    m = re.search(r"([A-Za-z_]\w*)\s*:\s*&\s*mut\s+([A-Za-z_]\w*)", fn_src)
    if not m:
        return None
    var = m.group(1)
    # Rename the fn.
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    # Inject a freshness guard at the top of the body.
    brace = fixed.find("{")
    guard_stmt = (
        f"\n    if {var}.used {{ return Err(\"freshness violation: resource already "
        f"consumed\".into()); }}\n    {var}.used = true;\n"
    )
    fixed = fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]
    return fixed


# --- bounds / dos-resource-exhaustion family (guard = cap-check) -------------

_RUST_INT_TYPES = {"u8", "u16", "u32", "u64", "u128", "usize",
                   "i8", "i16", "i32", "i64", "i128", "isize"}
_LEN_NAME_RE = re.compile(r"(?:^|_)(len|length|count|size|num|n|depth|amount|cap|qty|items?)(?:$|_)",
                          re.IGNORECASE)


def _rust_param_list(fn_src: str) -> str:
    """Return the EXACT inner text of the parameter list, paren-balanced. Robust
    to fns whose return type contains parens (e.g. `-> Result<(), E>` or a closure
    type `-> impl Fn(u64) -> bool`): we match the OPENING `(` of the param list to
    its balanced close instead of using `rfind(')')`, which would mis-stop inside
    the return type."""
    open_idx = fn_src.find("(")
    if open_idx < 0:
        return ""
    depth = 0
    for i in range(open_idx, len(fn_src)):
        c = fn_src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return fn_src[open_idx + 1: i]
    # unbalanced; fall back to the legacy slice.
    sig = fn_src[open_idx + 1: fn_src.find("{")]
    return sig[: sig.rfind(")")]


def _rust_named_params(fn_src: str) -> List[Tuple[str, str, bool]]:
    """Return [(name, type, is_ref)] for each parameter."""
    sig = _rust_param_list(fn_src)
    out: List[Tuple[str, str, bool]] = []
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw:
            continue
        m = re.match(r"([A-Za-z_]\w*)\s*:\s*(.+)$", raw)
        if not m:
            continue
        name, ty = m.group(1), m.group(2).strip()
        out.append((name, ty, ty.lstrip().startswith("&")))
    return out


def detect_rust_length_param(fn_src: str) -> Optional[str]:
    """Pick the caller-controlled numeric param that DRIVES an allocation /
    iteration in the body. Preference order:
      (1) a numeric param used in `with_capacity(<p>` / `reserve(<p>`;
      (2) a numeric param used as a loop bound (`< <p>` / `<= <p>` /
          `..<p>` / `..=<p>` / `0..<p>`);
      (3) a numeric param whose NAME matches a length-y pattern.
    Returns the param name or None when no caller-controlled length drives an
    allocation (the shape is not mechanically convertible)."""
    body = fn_src[fn_src.find("{"):]
    numeric = [n for (n, ty, is_ref) in _rust_named_params(fn_src)
               if ty.strip() in _RUST_INT_TYPES]
    if not numeric:
        return None
    # (1) allocation-driving param.
    for n in numeric:
        if re.search(rf"(?:with_capacity|reserve)\s*\(\s*{re.escape(n)}\b", body):
            return n
    # (2) loop-bound param.
    for n in numeric:
        if re.search(rf"(?:<=?|\.\.=?|\b0\s*\.\.)\s*{re.escape(n)}\b", body) or \
           re.search(rf"\b{re.escape(n)}\b", body) and re.search(
               rf"while\s+\w+\s*<\s*{re.escape(n)}\b", body):
            return n
    # (3) name-based.
    for n in numeric:
        if _LEN_NAME_RE.search(n):
            return n
    return None


def detect_rust_cap_expr(target_src: str, fn_src: str, len_param: str) -> Optional[str]:
    """Find the configured cap to bound `len_param` against. Preference order:
      (1) an existing comparison in the body already referencing a cap
          (`len_param > <cap>` / `<cap> < len_param` etc.) -- unlikely on a buggy
          fn but captured for completeness;
      (2) a `&<Cfg>` ref param with a cap-named numeric struct field
          (max_*, *_cap, *_limit, *_depth, *_max) -> `<refparam>.<field>`;
      (3) a module-level `const <CAP>: <int> = ...;` whose name is cap-named;
    Returns the cap EXPRESSION string, or None when no configured cap exists
    (then the shape is not mechanically convertible -> blocked-with-obligation)."""
    _CAP_FIELD_RE = re.compile(
        r"^(max_|min_)|(_cap|_limit|_max|_min|_depth|_bound|_size)$", re.IGNORECASE)
    # (2) ref param struct field.
    for (name, ty, is_ref) in _rust_named_params(fn_src):
        if not is_ref:
            continue
        bare = ty.lstrip("&").replace("mut", "").strip()
        sm = re.search(rf"struct\s+{re.escape(bare)}\s*\{{([^}}]*)\}}", target_src)
        if not sm:
            continue
        for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)",
                              sm.group(1)):
            fname, fty = fm.group(1), fm.group(2)
            if fty in _RUST_INT_TYPES and _CAP_FIELD_RE.search(fname):
                return f"{name}.{fname}"
    # (3) module-level cap const.
    for cm in re.finditer(r"\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*([A-Za-z_]\w*)\s*=",
                          target_src):
        cname, cty = cm.group(1), cm.group(2)
        if cty in _RUST_INT_TYPES and re.search(
                r"(MAX|CAP|LIMIT|BOUND|DEPTH)", cname):
            return cname
    return None


def derive_rust_fixed_capcheck(fn_src: str, fn: str, fixed_name: str,
                               len_param: str, cap_expr: str) -> str:
    """Inject the canonical cap-check guard at the top of the fn body and rename
    it to fixed_name. Rejects any request whose length exceeds the configured
    cap before the allocation runs."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    guard_stmt = (
        f"\n    if {len_param} > {cap_expr} {{ return Err(\"bounds violation: "
        f"allocation request exceeds the configured cap\".into()); }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def derive_go_fixed(fn_src: str, fn: str, fixed_name: str, guard: str) -> Optional[str]:
    if guard != "freshness-flag":
        return None
    # Find a `*<Type>` pointer parameter (the consumable resource).
    m = re.search(r"([A-Za-z_]\w*)\s+\*\s*([A-Za-z_]\w*)", fn_src)
    if not m:
        return None
    var = m.group(1)
    fixed = re.sub(rf"\bfunc\s+{re.escape(fn)}\b", f"func {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    # Determine the zero-return tuple shape from the signature return list.
    sig = fixed[: brace]
    rm = re.search(r"\)\s*\(([^)]*)\)\s*$", sig.strip())
    ret_list = rm.group(1) if rm else ""
    zeros = _go_zero_returns(ret_list)
    guard_stmt = (
        f"\n\tif {var}.Used {{ return {zeros} }}\n\t{var}.Used = true\n"
    )
    fixed = fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]
    return fixed


def _go_zero_returns(ret_list: str) -> str:
    parts = [p.strip() for p in ret_list.split(",") if p.strip()]
    zeros = []
    for p in parts:
        ty = p.split()[-1]
        if ty in ("bool",):
            zeros.append("false")
        elif ty == "string":
            zeros.append('""')
        elif ty == "error":
            zeros.append("nil")
        elif re.match(r"^u?int(8|16|32|64)?$", ty) or ty in ("byte", "rune"):
            zeros.append("0")
        elif re.match(r"^float(32|64)$", ty):
            zeros.append("0")
        elif ty.startswith("*") or ty.startswith("[]") or ty.startswith("map["):
            zeros.append("nil")
        else:
            zeros.append(f"*new({ty})")
    return ", ".join(zeros)


def ensure_rust_used_field(target_src: str, fn_src: str) -> str:
    """Ensure the &mut resource type has a `used: bool` field; if not, add one.
    Returns the (possibly amended) target source for the lift."""
    m = re.search(r":\s*&\s*mut\s+([A-Za-z_]\w*)", fn_src)
    if not m:
        return target_src
    ty = m.group(1)
    sm = re.search(rf"((?:pub\s+)?struct\s+{re.escape(ty)}\s*\{{)([^}}]*)(\}})",
                   target_src)
    if not sm:
        return target_src
    fields = sm.group(2)
    if re.search(r"\bused\s*:", fields):
        return target_src
    trimmed = fields.rstrip()
    # Rust struct fields are comma-separated; ensure the prior last field has a
    # trailing comma before we append `used`.
    sep = "" if trimmed.endswith(",") or not trimmed else ","
    new_struct = sm.group(1) + trimmed + sep + "\n    pub used: bool,\n" + sm.group(3)
    return target_src[: sm.start()] + new_struct + target_src[sm.end():]


def ensure_go_used_field(target_src: str, fn_src: str) -> str:
    m = re.search(r"\*\s*([A-Za-z_]\w*)", fn_src)
    if not m:
        return target_src
    ty = m.group(1)
    sm = re.search(rf"(type\s+{re.escape(ty)}\s+struct\s*\{{)([^}}]*)(\}})", target_src)
    if not sm:
        return target_src
    fields = sm.group(2)
    if re.search(r"\bUsed\b", fields):
        return target_src
    new_struct = sm.group(1) + fields.rstrip() + "\n\tUsed bool\n" + sm.group(3)
    return target_src[: sm.start()] + new_struct + target_src[sm.end():]


# ---------------------------------------------------------------------------
# Harness rendering (drives the REAL lifted fn; asserts the invariant).
# ---------------------------------------------------------------------------

def rust_resource_ctor(target_src: str, fn_src: str) -> Optional[Tuple[str, str]]:
    """Return (Type, constructor-expr) for the &mut resource, building a literal
    with every field zero-init and `used: false`."""
    m = re.search(r":\s*&\s*mut\s+([A-Za-z_]\w*)", fn_src)
    if not m:
        return None
    ty = m.group(1)
    sm = re.search(rf"struct\s+{re.escape(ty)}\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)", sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        fields.append(f"{name}: {_rust_zero(fty, name)}")
    return ty, f"{ty} {{ {', '.join(fields)} }}"


def _rust_zero(fty: str, name: str) -> str:
    if name == "used":
        return "false"
    if fty in ("u8", "u16", "u32", "u64", "u128", "usize",
               "i8", "i16", "i32", "i64", "i128", "isize"):
        return "0x1234"
    if fty == "bool":
        return "false"
    if fty.startswith("Vec"):
        return "vec![1, 2, 3]"
    if fty in ("String",):
        return 'String::from("x")'
    if fty in ("f32", "f64"):
        return "1.0"
    return "Default::default()"


def render_go_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                      pkg: str, resource_ty: str, resource_ctor: str,
                      call_buggy: str, call_fixed: str) -> str:
    tag = f"{inv['invariant_id']} [{inv['category']}] for {fn}"
    cat = inv["category"]
    cat_title = cat.title()
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving)
// Grounded invariant: {inv['invariant_id']} [{cat}]
//   {inv['statement']}
package {pkg}

import "testing"

// drive returns true iff the {cat} invariant HOLDS (replay rejected).
func driveInvariantBuggy_AUTO() bool {{
{call_buggy}
}}

func driveInvariantFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveInvariantBuggy_AUTO() {{
\t\tt.Errorf("{cat} invariant VIOLATED: {fn} accepted a replay (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveInvariantFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} should reject the replay: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Engine run + adjudication.
# ---------------------------------------------------------------------------

def parse_cargo_output(out: str) -> Dict[str, bool]:
    return {
        "exploit_pass": bool(re.search(r"test\s+test_exploit_\w+\s+\.\.\.\s+ok", out)),
        "exploit_fail": bool(re.search(r"test\s+test_exploit_\w+\s+\.\.\.\s+FAILED", out)),
        "control_pass": bool(re.search(r"test\s+test_negative_control_\w+\s+\.\.\.\s+ok", out)),
        "control_fail": bool(re.search(r"test\s+test_negative_control_\w+\s+\.\.\.\s+FAILED", out)),
        "compiled": "error[E" not in out and "error: could not compile" not in out,
    }


def parse_go_output(out: str) -> Dict[str, bool]:
    return {
        "exploit_pass": bool(re.search(r"---\s+PASS:\s+TestExploit", out)),
        "exploit_fail": bool(re.search(r"---\s+FAIL:\s+TestExploit", out)),
        "control_pass": bool(re.search(r"---\s+PASS:\s+TestNegativeControl", out)),
        "control_fail": bool(re.search(r"---\s+FAIL:\s+TestNegativeControl", out)),
        "compiled": "build failed" not in out and "cannot" not in out.split("FAIL")[0][-400:],
    }


def adjudicate(parsed: Dict[str, bool], compiled: bool) -> Tuple[str, str]:
    if not compiled:
        return BLOCKED, "the authored harness did not compile against the lifted target"
    # proof-backed: invariant catches the bug (exploit FAILS on buggy fn) AND
    # the negative control PASSES (invariant holds on the fixed fn).
    if parsed["exploit_fail"] and parsed["control_pass"]:
        return PROOF_BACKED, ("exploit FAILED-on-bug (invariant caught the vuln) + "
                              "negative control PASSED-on-fixed")
    if parsed["exploit_pass"] and parsed["control_pass"]:
        return REFUTED, ("the invariant did NOT catch the bug: exploit assertion held "
                         "even on the buggy fn -> wrong invariant for this vuln class")
    return BLOCKED, ("run did not produce the exploit-FAIL-on-bug + control-PASS-on-fixed "
                     "shape; no fabricated proof emitted")


# ---------------------------------------------------------------------------
# Rust convert path (self-contained lift + run).
# ---------------------------------------------------------------------------

def _convert_rust_bounds(target_file: Path, src: str, fn_src: str, fn: str,
                         vuln_class: str, category: str, inv: Dict[str, Any],
                         out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    """Bounds / dos-resource-exhaustion convert path. Picks the caller-controlled
    length param + the configured cap, derives the cap-check fixed variant, and
    drives the real fn with in-cap (accept) vs over-cap (reject) lengths."""
    len_param = detect_rust_length_param(fn_src)
    if len_param is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("no caller-controlled length param drives an allocation/"
                         "loop in this fn; obligation: hand-author the bounds "
                         "invariant + cap-check fixed variant"))
    cap_expr = detect_rust_cap_expr(src, fn_src, len_param)
    if cap_expr is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("no configured cap (cap-named struct field on a &ref "
                         "param, or a cap-named const) found to bound the length "
                         f"param {len_param!r}; obligation: hand-author the cap-check"))
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_capcheck(fn_src, fn, fixed_name, len_param, cap_expr)
    lib_rs = _rust_lib(src, fn_src, fixed_src)

    # Build in-cap + over-cap arg vectors. Every NON-length param gets a concrete
    # literal (struct types rendered field-by-field). The length param gets a
    # small in-cap value (16) and a far-over-cap value (1_000_000) so the buggy
    # fn accepts the over-cap request (invariant violation) while the fixed fn
    # rejects it. The over-cap value is intentionally large-but-allocatable so
    # the buggy fn returns Ok (the catch is "accepted", not "process aborted").
    named = _rust_named_params(fn_src)
    param_types = _rust_param_types(fn_src)
    in_cap_args: List[str] = []
    over_cap_args: List[str] = []
    len_idx = 0
    for idx, (name, ty, is_ref) in enumerate(named):
        if name == len_param:
            len_idx = idx
            in_cap_args.append("16")
            over_cap_args.append("1_000_000")
            continue
        lit = _rust_arg_literal(src, ty)
        in_cap_args.append(lit)
        over_cap_args.append(lit)
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    crate = "eac_target_auto"
    harness = _rust_bounds_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        len_param=len_param, len_idx=len_idx, param_types=param_types,
        in_cap_args=in_cap_args, over_cap_args=over_cap_args,
        ret_ty=ret_ty, err_ty=err_ty)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["length_param"] = len_param
    result["cap_expr"] = cap_expr
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


# --- freshness / staleness sub-shape (guard = staleness-gate) ----------------
#
# The staleness shape: a valuation/read fn takes a `&<T>` reference whose struct
# carries a stored timestamp field (last_update / updated_at / timestamp), plus
# a `now`/`slot` clock param and a `max_delay`/`ttl`/`max_age` bound param, and
# (in the buggy variant) consumes the struct WITHOUT rejecting when the stored
# timestamp is older than `now - bound`. This is the dominant oracle-pricing
# freshness shape (anchor: Synthetify calculate_debt asset.last_update gate at
# math.rs:26). The synthesis is signature-driven: no target symbol names.

_TS_FIELD_RE = re.compile(
    r"^(last_update|updated_at|update_slot|update_time|last_updated|timestamp|"
    r"last_seen|last_refresh|published_at|publish_time|last_price_update|"
    r"slot|time|ts)$",
    re.IGNORECASE)
_NOW_PARAM_RE = re.compile(r"^(slot|now|current_slot|current_time|clock|"
                           r"block_time|timestamp|current_timestamp|height)$",
                           re.IGNORECASE)
_DELAY_PARAM_RE = re.compile(r"^(max_delay|max_age|ttl|staleness|max_staleness|"
                             r"freshness_window|max_slot_delay|tolerance|"
                             r"max_lag|validity_window|max_price_age)$",
                             re.IGNORECASE)


def _detect_rust_staleness(target_src: str, fn_src: str):
    """Return (ref_param, ref_ty, ts_field, now_param, delay_param) when the fn
    matches the staleness shape, else None. Signature-driven: the ref param's
    struct must carry a numeric timestamp-like field, and the signature must
    carry a now-like and a delay-like numeric param."""
    named = _rust_named_params(fn_src)
    # now / delay params (numeric, name-matched).
    now_param = None
    delay_param = None
    for (name, ty, is_ref) in named:
        bare = ty.strip()
        if bare in _RUST_INT_TYPES:
            if now_param is None and _NOW_PARAM_RE.search(name):
                now_param = name
            elif delay_param is None and _DELAY_PARAM_RE.search(name):
                delay_param = name
    if now_param is None or delay_param is None:
        return None
    # ref param whose struct has a timestamp field.
    for (name, ty, is_ref) in named:
        bare = ty.lstrip("&").replace("mut", "").strip()
        sm = re.search(rf"struct\s+{re.escape(bare)}\s*\{{([^}}]*)\}}", target_src)
        if not sm:
            continue
        for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)",
                              sm.group(1)):
            fname, fty = fm.group(1), fm.group(2)
            if fty in _RUST_INT_TYPES and _TS_FIELD_RE.search(fname):
                return name, bare, fname, now_param, delay_param
    return None


def derive_rust_fixed_staleness(fn_src: str, fn: str, fixed_name: str,
                                ref_param: str, ts_field: str,
                                now_param: str, delay_param: str) -> str:
    """Inject the canonical staleness gate at the top of the body and rename to
    fixed_name. Rejects when the stored timestamp is older than now - delay."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    guard_stmt = (
        f"\n    if ({ref_param}.{ts_field} as u128) "
        f"< ({now_param} as u128).saturating_sub({delay_param} as u128) {{\n"
        f"        return Err(\"freshness violation: stored timestamp is older than "
        f"now - max_delay (stale)\".into());\n    }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _convert_rust_staleness(target_file: Path, src: str, fn_src: str, fn: str,
                            vuln_class: str, category: str, inv: Dict[str, Any],
                            stale, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    ref_param, ref_ty, ts_field, now_param, delay_param = stale
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_staleness(fn_src, fn, fixed_name, ref_param,
                                            ts_field, now_param, delay_param)
    # Build a FRESH and a STALE constructor for the ref struct. The clock and
    # delay literals are fixed (now=1_000_000, delay=100); FRESH sets ts within
    # window (=999_950), STALE sets ts far before window (=1). Other ref-struct
    # fields zero/seed-init.
    now_lit, delay_lit = "1_000_000", "100"
    fresh_ctor = _rust_staleness_ctor(src, ref_ty, ts_field, "999_950")
    stale_ctor = _rust_staleness_ctor(src, ref_ty, ts_field, "1")
    if fresh_ctor is None or stale_ctor is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        "could not synthesize a constructor for the staleness ref type")
    # Other (non-ref, non-now, non-delay) args as concrete literals.
    named = _rust_named_params(fn_src)
    other_pos = {}  # idx -> literal/now/delay/ref marker
    param_types = _rust_param_types(fn_src)
    arg_types = ", ".join(ty.strip() for ty, _ in param_types)
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    # Build the ordered arg lists for the FRESH and STALE drives.
    fresh_args: List[str] = []
    stale_args: List[str] = []
    for (name, ty, is_ref) in named:
        if name == ref_param:
            fresh_args.append(f"&__fresh")
            stale_args.append(f"&__stale")
        elif name == now_param:
            fresh_args.append(now_lit)
            stale_args.append(now_lit)
        elif name == delay_param:
            fresh_args.append(delay_lit)
            stale_args.append(delay_lit)
        else:
            lit = _rust_arg_literal(src, ty)
            fresh_args.append(lit)
            stale_args.append(lit)
    crate = "eac_target_auto"
    lib_rs = _rust_lib(src, fn_src, fixed_src)
    harness = _rust_staleness_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        ref_ty=ref_ty, fresh_ctor=fresh_ctor, stale_ctor=stale_ctor,
        fresh_args=fresh_args, stale_args=stale_args, arg_types=arg_types,
        ret_ty=ret_ty, err_ty=err_ty, ts_field=ts_field)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["freshness_shape"] = "staleness-gate"
    result["timestamp_field"] = f"{ref_ty}.{ts_field}"
    result["now_param"] = now_param
    result["delay_param"] = delay_param
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_staleness_ctor(target_src: str, ref_ty: str, ts_field: str,
                         ts_val: str) -> Optional[str]:
    sm = re.search(rf"struct\s+{re.escape(ref_ty)}\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                          sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        if name == ts_field:
            fields.append(f"{name}: {ts_val}")
        else:
            fields.append(f"{name}: {_rust_zero(fty, name)}")
    return f"{ref_ty} {{ {', '.join(fields)} }}"


def _rust_staleness_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                            crate: str, category: str, ref_ty: str,
                            fresh_ctor: str, stale_ctor: str,
                            fresh_args: List[str], stale_args: List[str],
                            arg_types: str, ret_ty: str, err_ty: str,
                            ts_field: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    fresh_call = ", ".join(fresh_args)
    stale_call = ", ".join(stale_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, staleness)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed). The stored
// timestamp field is `{ref_ty}.{ts_field}`; a STALE input (timestamp older than
// now - max_delay) must be REJECTED for the freshness invariant to HOLD.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the freshness invariant HOLDS: a FRESH input is accepted (Ok) AND
    // a STALE input is REJECTED (Err). On the buggy fn the stale input is
    // (incorrectly) accepted -> invariant violated -> exploit test FAILs.
    let __fresh: {ref_ty} = {fresh_ctor};
    let __stale: {ref_ty} = {stale_ctor};
    let fresh = f({fresh_call});
    let stale = f({stale_call});
    fresh.is_ok() && stale.is_err()
}}

#[test]
fn test_exploit_{category}_{fn}() {{
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} accepted a stale input (bug present): {tag}");
}}

#[test]
fn test_negative_control_{category}_{fn}() {{
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the stale input: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Rust int-truncation convert path (guard = cast-bound-check).
# ---------------------------------------------------------------------------

def _detect_rust_truncation(fn_src: str):
    """Return (param, src_ty, dst_ty) when a WIDE numeric param flows into a
    NARROWING `as <dst>` cast in the body, else None. Signature-driven: the
    param's declared type must be strictly wider than the cast destination."""
    named = _rust_named_params(fn_src)
    param_ty = {n: ty.strip() for (n, ty, _) in named}
    body = fn_src[fn_src.find("{"):]
    best = None
    for m in re.finditer(r"\b([a-z_]\w*)\s+as\s+([iu](?:8|16|32|64|128|size))\b", body):
        var, dst = m.group(1), m.group(2)
        src_ty = param_ty.get(var)
        if src_ty is None or src_ty not in _RUST_INT_WIDTH:
            continue
        if _RUST_INT_WIDTH[src_ty] <= _RUST_INT_WIDTH.get(dst, 0):
            continue  # not a narrowing cast (dst >= src)
        cand = (var, src_ty, dst)
        # prefer the widest source / narrowest dest (largest truncation gap).
        if best is None or (_RUST_INT_WIDTH[src_ty] - _RUST_INT_WIDTH[dst]) > \
                (_RUST_INT_WIDTH[best[1]] - _RUST_INT_WIDTH[best[2]]):
            best = cand
    return best


def derive_rust_fixed_castcheck(fn_src: str, fn: str, fixed_name: str,
                                param: str, dst_ty: str) -> str:
    """Inject the canonical cast-bound-check guard at the top of the body and
    rename to fixed_name. Rejects any value above the destination type's max
    BEFORE the narrowing cast runs."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    width = _RUST_INT_WIDTH[dst_ty]
    bound = _UNSIGNED_MAX.get(width, "0")
    guard_stmt = (
        f"\n    if ({param} as u128) > {bound}u128 {{ return Err(\"int-truncation "
        f"violation: value exceeds the {dst_ty} max and would silently truncate\""
        f".into()); }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _convert_rust_truncation(target_file: Path, src: str, fn_src: str, fn: str,
                             vuln_class: str, category: str, inv: Dict[str, Any],
                             trunc, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    param, src_ty, dst_ty = trunc
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if ret_ty == "()" and err_ty == "String" and "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no error-rejection channel for the "
                         "cast-bound-check); obligation: hand-author the bound check"))
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_castcheck(fn_src, fn, fixed_name, param, dst_ty)
    lib_rs = _rust_lib(src, fn_src, fixed_src)

    # in-range value (<= dst max) accepted; over-range value (> dst max) rejected.
    width = _RUST_INT_WIDTH[dst_ty]
    bound = int(_UNSIGNED_MAX.get(width, "0"))
    in_val = str(min(7, bound))
    over_val = str(bound + 1)
    named = _rust_named_params(fn_src)
    param_types = _rust_param_types(fn_src)
    in_args: List[str] = []
    over_args: List[str] = []
    for (name, ty, is_ref) in named:
        if name == param:
            in_args.append(in_val)
            over_args.append(over_val)
        else:
            lit = _rust_arg_literal(src, ty)
            in_args.append(lit)
            over_args.append(lit)
    crate = "eac_target_auto"
    harness = _rust_truncation_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        param=param, src_ty=src_ty, dst_ty=dst_ty, param_types=param_types,
        in_args=in_args, over_args=over_args, ret_ty=ret_ty, err_ty=err_ty)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["truncation_param"] = param
    result["narrowing_cast"] = f"{src_ty} -> {dst_ty}"
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_truncation_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                             crate: str, category: str, param: str,
                             src_ty: str, dst_ty: str,
                             param_types: List[Tuple[str, bool]],
                             in_args: List[str], over_args: List[str],
                             ret_ty: str, err_ty: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    # identifier-safe category slug for the test fn names (Rust identifiers
    # cannot contain `-`; the int-truncation/access-control categories carry one).
    cat_id = category.replace("-", "_")
    arg_types = ", ".join(ty.strip() for ty, _ in param_types)
    in_call = ", ".join(in_args)
    over_call = ", ".join(over_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, int-truncation)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed). The
// caller-controlled wide param `{param}` ({src_ty}) is narrowed by an `as {dst_ty}`
// cast; a value above the {dst_ty} max must be REJECTED for the invariant to HOLD.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the int-truncation invariant HOLDS: an in-range value is accepted
    // AND a value above the {dst_ty} max is REJECTED (would silently truncate). On
    // the buggy fn the over-max value is (incorrectly) accepted and truncated ->
    // invariant violated -> the exploit test FAILs (the invariant catches the bug).
    let within = f({in_call});
    let over   = f({over_call});
    within.is_ok() && over.is_err()
}}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} truncated an over-{dst_ty}-max value (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the over-max value: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Rust access-control convert path (guard = owner-guard).
# ---------------------------------------------------------------------------

def _detect_rust_access_control(target_src: str, fn_src: str):
    """Return (state_param, state_ty, identity_field, identity_fty, caller_param)
    when the fn mutates a `&mut <T>` state struct carrying an identity field AND
    takes a caller param of the SAME type AND does NOT compare them, else None.
    Signature-driven; the identity/caller name sets are canonical, not target-
    tuned."""
    named = _rust_named_params(fn_src)
    # find a &mut state param whose struct carries an identity field.
    state = None  # (param, ty, field, fty)
    for (name, ty, is_ref) in named:
        if "&" not in ty or "mut" not in ty:
            continue
        bare = ty.lstrip("&").replace("mut", "").strip()
        sm = re.search(rf"struct\s+{re.escape(bare)}\s*\{{([^}}]*)\}}", target_src)
        if not sm:
            continue
        for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                              sm.group(1)):
            fname, fty = fm.group(1), fm.group(2)
            if _IDENTITY_FIELD_RE.search(fname):
                state = (name, bare, fname, fty)
                break
        if state:
            break
    if state is None:
        return None
    state_param, state_ty, identity_field, identity_fty = state
    # find a caller param whose type matches the identity field's type.
    caller_param = None
    for (name, ty, is_ref) in named:
        bare = ty.lstrip("&").replace("mut", "").strip()
        if _CALLER_PARAM_RE.search(name) and bare == identity_fty:
            caller_param = name
            break
    if caller_param is None:
        return None
    # the buggy fn must NOT already compare caller against state.identity.
    body = fn_src[fn_src.find("{"):]
    already = (re.search(rf"{re.escape(caller_param)}\s*[!=]=\s*{re.escape(state_param)}\."
                         rf"{re.escape(identity_field)}", body)
               or re.search(rf"{re.escape(state_param)}\.{re.escape(identity_field)}\s*"
                            rf"[!=]=\s*{re.escape(caller_param)}", body))
    if already:
        return None
    return state_param, state_ty, identity_field, identity_fty, caller_param


def derive_rust_fixed_ownerguard(fn_src: str, fn: str, fixed_name: str,
                                 state_param: str, identity_field: str,
                                 caller_param: str) -> str:
    """Inject the canonical owner-guard at the top of the body and rename to
    fixed_name. Rejects when the caller is not the stored owner."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    guard_stmt = (
        f"\n    if {caller_param} != {state_param}.{identity_field} {{ return Err("
        f"\"access-control violation: caller is not the stored owner\".into()); }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _convert_rust_access_control(target_file: Path, src: str, fn_src: str, fn: str,
                                 vuln_class: str, category: str, inv: Dict[str, Any],
                                 ac, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, identity_field, identity_fty, caller_param = ac
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no error-rejection channel for the "
                         "owner-guard); obligation: hand-author the access-control check"))
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_ownerguard(fn_src, fn, fixed_name, state_param,
                                             identity_field, caller_param)
    lib_rs = _rust_lib(src, fn_src, fixed_src)

    # Build the state ctor with identity == OWNER_ID; an OWNER caller (== identity)
    # must be accepted, and an ATTACKER caller (!= identity) must be rejected.
    owner_lit = _rust_identity_literal(identity_fty)
    attacker_lit = _rust_identity_literal(identity_fty, attacker=True)
    state_ctor = _rust_ac_state_ctor(src, state_ty, identity_field, owner_lit)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        "could not synthesize a constructor for the state type")
    named = _rust_named_params(fn_src)
    param_types = _rust_param_types(fn_src)
    owner_args: List[str] = []
    attacker_args: List[str] = []
    for (name, ty, is_ref) in named:
        if name == state_param:
            owner_args.append("&mut __st_owner")
            attacker_args.append("&mut __st_attacker")
        elif name == caller_param:
            owner_args.append(owner_lit)
            attacker_args.append(attacker_lit)
        else:
            lit = _rust_arg_literal(src, ty)
            owner_args.append(lit)
            attacker_args.append(lit)
    crate = "eac_target_auto"
    harness = _rust_access_control_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        state_ty=state_ty, state_ctor=state_ctor, param_types=param_types,
        owner_args=owner_args, attacker_args=attacker_args,
        ret_ty=ret_ty, err_ty=err_ty, identity_field=identity_field,
        caller_param=caller_param)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["state_param"] = state_param
    result["identity_field"] = f"{state_ty}.{identity_field}"
    result["caller_param"] = caller_param
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_identity_literal(fty: str, attacker: bool = False) -> str:
    f = fty.strip()
    if f in _RUST_INT_WIDTH:
        return "0xBADBAD" if attacker else "0x0WNER".replace("0WNER", "1111")
    if f in ("String", "str"):
        return 'String::from("attacker")' if attacker else 'String::from("owner")'
    return "Default::default()"


def _rust_ac_state_ctor(target_src: str, state_ty: str, identity_field: str,
                        owner_lit: str) -> Optional[str]:
    sm = re.search(rf"struct\s+{re.escape(state_ty)}\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                          sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        if name == identity_field:
            fields.append(f"{name}: {owner_lit}")
        else:
            fields.append(f"{name}: {_rust_zero(fty, name)}")
    return f"{state_ty} {{ {', '.join(fields)} }}"


def _rust_access_control_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                                 crate: str, category: str, state_ty: str,
                                 state_ctor: str, param_types: List[Tuple[str, bool]],
                                 owner_args: List[str], attacker_args: List[str],
                                 ret_ty: str, err_ty: str, identity_field: str,
                                 caller_param: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    cat_id = category.replace("-", "_")
    arg_types = ", ".join(ty.strip() for ty, _ in param_types)
    owner_call = ", ".join(owner_args)
    attacker_call = ", ".join(attacker_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, access-control)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed). The state
// struct carries `{state_ty}.{identity_field}`; the privileged op must reject a
// `{caller_param}` that is NOT the stored owner for the invariant to HOLD.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the access-control invariant HOLDS: the OWNER caller is accepted
    // (Ok) AND an ATTACKER caller (!= stored owner) is REJECTED (Err). On the
    // buggy fn the attacker is (incorrectly) accepted -> invariant violated ->
    // the exploit test FAILs (the invariant catches the missing owner-guard).
    let mut __st_owner: {state_ty} = {state_ctor};
    let mut __st_attacker: {state_ty} = {state_ctor};
    let owner = f({owner_call});
    let attacker = f({attacker_call});
    owner.is_ok() && attacker.is_err()
}}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} accepted a non-owner caller (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the non-owner caller: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Rust reentrancy / CEI convert path (guard = cei-order-check).
# ---------------------------------------------------------------------------
#
# The CEI shape: a state-mutating fn takes a `&mut <State>` param carrying a
# numeric balance-like field AND a callback/hook param (a `&mut dyn FnMut(...)` /
# `impl FnMut` / `F: FnMut` external-call stand-in). In the BUGGY variant the
# body invokes the hook BEFORE the line that writes the balance field, so a
# re-entrant observer (the hook) sees the pre-effect balance. The FIXED variant
# moves the balance-write statement BEFORE the hook call (checks-effects-
# interactions). The synthesis is signature + body driven: no target symbol names.

def _detect_rust_reentrancy(target_src: str, fn_src: str):
    """Return (state_param, state_ty, balance_field, hook_param) when the fn
    matches the CEI shape (a &mut state struct w/ a balance field + a callback
    param, and the balance write occurs AFTER the hook call), else None."""
    named = _rust_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    # find a &mut state param whose struct carries a balance-like field.
    state = None  # (param, ty, field)
    for (name, ty, is_ref) in named:
        if "&" not in ty or "mut" not in ty:
            continue
        bare = ty.lstrip("&").replace("mut", "").strip()
        sm = re.search(rf"struct\s+{re.escape(bare)}\s*\{{([^}}]*)\}}", target_src)
        if not sm:
            continue
        for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                              sm.group(1)):
            fname, fty = fm.group(1), fm.group(2)
            if fty in _RUST_INT_TYPES and _BALANCE_FIELD_RE.search(fname):
                state = (name, bare, fname)
                break
        if state:
            break
    if state is None:
        return None
    state_param, state_ty, balance_field = state
    # find a hook/callback param: a name-matched param OR a param whose type
    # contains `FnMut` / `FnOnce` / `Fn(` (the external-call stand-in).
    hook_param = None
    for (name, ty, is_ref) in named:
        if _HOOK_PARAM_RE.search(name) or re.search(r"\bFn(Mut|Once)?\b", ty):
            hook_param = name
            break
    if hook_param is None:
        return None
    # the hook must be CALLED in the body, and the balance write must occur AFTER
    # the hook call (buggy ordering). If the write precedes the call, the fn is
    # already CEI-correct -> not a bug -> block.
    call_m = re.search(rf"\b{re.escape(hook_param)}\s*\(", body)
    write_m = re.search(rf"{re.escape(state_param)}\.{re.escape(balance_field)}\s*"
                        rf"(?:[-+*/]?=)", body)
    if not call_m or not write_m:
        return None
    if write_m.start() < call_m.start():
        return None  # already effects-before-interactions
    return state_param, state_ty, balance_field, hook_param


def derive_rust_fixed_cei(fn_src: str, fn: str, fixed_name: str,
                          state_param: str, balance_field: str,
                          hook_param: str) -> Optional[str]:
    """Move the balance-write statement BEFORE the hook-call statement (CEI
    order) and rename to fixed_name. Returns None if the statements cannot be
    isolated at the top statement level."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    head, body = fixed[: brace + 1], fixed[brace + 1:]
    # isolate the balance-write statement (a full `state.field <op>= ...;` stmt)
    # and the hook-call statement (the stmt containing `hook(...)`).
    write_stmt_re = re.compile(
        rf"[^\n;{{}}]*{re.escape(state_param)}\.{re.escape(balance_field)}\s*"
        rf"[-+*/]?=\s*[^;]*;")
    wm = write_stmt_re.search(body)
    if wm is None:
        return None
    write_stmt = wm.group(0).strip()
    # the hook-call statement: the stmt (line) that invokes the hook.
    hook_stmt_re = re.compile(rf"[^\n;{{}}]*\b{re.escape(hook_param)}\s*\([^;]*;")
    hm = hook_stmt_re.search(body)
    if hm is None:
        return None
    if wm.start() < hm.start():
        return None  # write already precedes the call (no reorder needed)
    # remove the write statement from its current position, then re-insert it
    # immediately BEFORE the hook-call statement.
    body_wo_write = body[: wm.start()] + body[wm.end():]
    # recompute the hook-call position in the write-removed body.
    hm2 = hook_stmt_re.search(body_wo_write)
    if hm2 is None:
        return None
    # find the start of the hook statement's line (to preserve indentation).
    line_start = body_wo_write.rfind("\n", 0, hm2.start()) + 1
    indent_m = re.match(r"[ \t]*", body_wo_write[line_start: hm2.start()])
    indent = indent_m.group(0) if indent_m else "    "
    reordered = (body_wo_write[: line_start]
                 + indent + write_stmt + "\n"
                 + body_wo_write[line_start:])
    return head + reordered


def _convert_rust_reentrancy(target_file: Path, src: str, fn_src: str, fn: str,
                             vuln_class: str, category: str, inv: Dict[str, Any],
                             ree, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, balance_field, hook_param = ree
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no channel to assert acceptance); "
                         "obligation: hand-author the CEI reorder + invariant"))
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_cei(fn_src, fn, fixed_name, state_param,
                                      balance_field, hook_param)
    if fixed_src is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("could not isolate the balance-write + hook-call statements "
                         "to reorder; obligation: hand-author the CEI fixed variant"))
    lib_rs = _rust_lib(src, fn_src, fixed_src)
    # Build the initial balance + withdraw amount. The state ctor sets the balance
    # field to INIT (100); the withdraw amount is AMT (40); the invariant asserts
    # that DURING the external call the observed balance is already INIT-AMT (=60).
    init_bal, amt = "100", "40"
    expected_during = "60"
    state_ctor = _rust_cei_state_ctor(src, state_ty, balance_field, init_bal)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        "could not synthesize a constructor for the state type")
    named = _rust_named_params(fn_src)
    param_types = _rust_param_types(fn_src)
    # ordered arg builders for the drive call: state -> &mut __st, hook -> &mut h,
    # the balance/amount param (a numeric non-state, non-hook param) -> AMT, others
    # -> concrete literals.
    amount_param = _rust_pick_amount_param(named, state_param, hook_param)
    arg_slots: List[str] = []
    for (name, ty, is_ref) in named:
        if name == state_param:
            arg_slots.append("STATE")
        elif name == hook_param:
            arg_slots.append("HOOK")
        elif name == amount_param:
            arg_slots.append(amt)
        else:
            arg_slots.append(_rust_arg_literal(src, ty))
    crate = "eac_target_auto"
    harness = _rust_reentrancy_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        state_ty=state_ty, state_ctor=state_ctor, balance_field=balance_field,
        param_types=param_types, arg_slots=arg_slots,
        expected_during=expected_during, ret_ty=ret_ty, err_ty=err_ty)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["reentrancy_shape"] = "cei-order-check"
    result["state_param"] = state_param
    result["balance_field"] = f"{state_ty}.{balance_field}"
    result["hook_param"] = hook_param
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_pick_amount_param(named, state_param, hook_param) -> Optional[str]:
    """Pick the numeric non-state, non-hook param to drive as the withdraw
    amount (the value deducted from the balance field). Prefers a name-matched
    amount-like param; falls back to the first plain numeric param."""
    fallback = None
    for (name, ty, is_ref) in named:
        if name in (state_param, hook_param):
            continue
        bare = ty.strip()
        if bare in _RUST_INT_TYPES:
            if re.search(r"(amount|amt|value|qty|sum|delta|withdraw|debit)", name, re.I):
                return name
            if fallback is None:
                fallback = name
    return fallback


def _rust_cei_state_ctor(target_src: str, state_ty: str, balance_field: str,
                         init_bal: str) -> Optional[str]:
    sm = re.search(rf"struct\s+{re.escape(state_ty)}\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                          sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        if name == balance_field:
            fields.append(f"{name}: {init_bal}")
        else:
            fields.append(f"{name}: {_rust_zero(fty, name)}")
    return f"{state_ty} {{ {', '.join(fields)} }}"


def _rust_reentrancy_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                             crate: str, category: str, state_ty: str,
                             state_ctor: str, balance_field: str,
                             param_types: List[Tuple[str, bool]],
                             arg_slots: List[str], expected_during: str,
                             ret_ty: str, err_ty: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    cat_id = category.replace("-", "_")
    # Build the fn-pointer arg-type annotation (the real signature). The hook
    # param's type is rendered as a `&mut dyn FnMut(u64) -> u64` standin; the
    # state as `&mut <state_ty>`; numerics as-is.
    arg_types = _rust_cei_fn_ptr_types(param_types, state_ty)
    # Build the concrete call arg list: STATE -> &mut __st, HOOK -> &mut hook,
    # everything else literal.
    call_args = []
    for slot in arg_slots:
        if slot == "STATE":
            call_args.append("&mut __st")
        elif slot == "HOOK":
            call_args.append("&mut hook")
        else:
            call_args.append(slot)
    call = ", ".join(call_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, reentrancy/CEI)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed). The state
// struct carries `{state_ty}.{balance_field}`; a re-entrant observer (the hook)
// invoked DURING the call must already see the post-effect balance for the CEI
// invariant to HOLD.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the CEI invariant HOLDS: the balance observed by the external hook
    // DURING the call already reflects the deduction ({expected_during}). On the
    // buggy fn the hook sees the PRE-effect balance (the external call precedes the
    // state write) -> invariant violated -> the exploit test FAILs (the invariant
    // catches the missing checks-effects-interactions ordering).
    let mut __st: {state_ty} = {state_ctor};
    let mut __observed: u128 = u128::MAX;
    {{
        let mut hook = |seen| {{ __observed = seen as u128; Default::default() }};
        let _ = f({call});
    }}
    __observed == {expected_during}
}}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} wrote state AFTER the external call (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must write the effect before the external call: {tag}");
}}
'''


def _rust_cei_fn_ptr_types(param_types: List[Tuple[str, bool]], state_ty: str) -> str:
    """Render the fn-pointer arg types for the CEI drive. The hook param's
    `impl FnMut` / `F: FnMut` / generic type is normalized to a concrete
    `&mut dyn FnMut(u64) -> u64` so the harness can pass a closure; the &mut state
    keeps its `&mut <state_ty>` type; numerics pass through."""
    out = []
    for (ty, is_res) in param_types:
        t = ty.strip()
        if re.search(r"\bFn(Mut|Once)?\b", t):
            out.append("&mut dyn FnMut(u64) -> u64")
        else:
            out.append(t)
    return ", ".join(out)


# ---------------------------------------------------------------------------
# Rust valid-flag staleness-on-read convert path (guard = valid-flag-check).
# ---------------------------------------------------------------------------
#
# The shape: a read/valuation fn takes a `&<T>` ref whose struct carries a numeric
# value field AND a boolean validity/freshness flag, and (buggy) returns the value
# WITHOUT consulting the flag. The fixed variant injects a `if !<flag> { reject }`
# (positive flag) or `if <flag> { reject }` (negative flag) gate. Signature-driven.

def _detect_rust_valid_flag(target_src: str, fn_src: str):
    """Return (ref_param, ref_ty, flag_field, flag_polarity) when the fn matches
    the validity-flag read shape, else None. flag_polarity is 'positive' (a
    valid/fresh flag that must be TRUE) or 'negative' (a stale/invalid flag that
    must be FALSE)."""
    named = _rust_named_params(fn_src)
    for (name, ty, is_ref) in named:
        bare = ty.lstrip("&").replace("mut", "").strip()
        sm = re.search(rf"struct\s+{re.escape(bare)}\s*\{{([^}}]*)\}}", target_src)
        if not sm:
            continue
        has_value = False
        flag = None  # (field, polarity)
        for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                              sm.group(1)):
            fname, fty = fm.group(1), fm.group(2)
            if fty in _RUST_INT_TYPES and _PRICE_FIELD_RE.search(fname):
                has_value = True
            if fty == "bool":
                if _VALID_FLAG_POSITIVE_RE.search(fname):
                    flag = (fname, "positive")
                elif _VALID_FLAG_NEGATIVE_RE.search(fname):
                    flag = (fname, "negative")
        if has_value and flag is not None:
            # the buggy fn must NOT already consult the flag.
            body = fn_src[fn_src.find("{"):]
            if re.search(rf"\.{re.escape(flag[0])}\b", body):
                continue
            return name, bare, flag[0], flag[1]
    return None


def derive_rust_fixed_validflag(fn_src: str, fn: str, fixed_name: str,
                                ref_param: str, flag_field: str,
                                polarity: str) -> str:
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    cond = (f"!{ref_param}.{flag_field}" if polarity == "positive"
            else f"{ref_param}.{flag_field}")
    guard_stmt = (
        f"\n    if {cond} {{ return Err(\"staleness violation: source datum is "
        f"flagged stale/invalid (the {flag_field} flag was not consulted)\""
        f".into()); }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _convert_rust_valid_flag(target_file: Path, src: str, fn_src: str, fn: str,
                             vuln_class: str, category: str, inv: Dict[str, Any],
                             vf, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    ref_param, ref_ty, flag_field, polarity = vf
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no error-rejection channel for the "
                         "valid-flag-check); obligation: hand-author the bound check"))
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_validflag(fn_src, fn, fixed_name, ref_param,
                                            flag_field, polarity)
    lib_rs = _rust_lib(src, fn_src, fixed_src)
    # VALID ctor (flag set so the datum is accepted) + STALE ctor (flag set so it
    # is rejected). positive flag: valid=true / stale flag=false=valid.
    valid_flag_lit = "true" if polarity == "positive" else "false"
    stale_flag_lit = "false" if polarity == "positive" else "true"
    valid_ctor = _rust_validflag_ctor(src, ref_ty, flag_field, valid_flag_lit)
    stale_ctor = _rust_validflag_ctor(src, ref_ty, flag_field, stale_flag_lit)
    if valid_ctor is None or stale_ctor is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        "could not synthesize a constructor for the read ref type")
    named = _rust_named_params(fn_src)
    param_types = _rust_param_types(fn_src)
    arg_types = ", ".join(ty.strip() for ty, _ in param_types)
    valid_args: List[str] = []
    stale_args: List[str] = []
    for (name, ty, is_ref) in named:
        if name == ref_param:
            valid_args.append("&__valid")
            stale_args.append("&__stale")
        else:
            lit = _rust_arg_literal(src, ty)
            valid_args.append(lit)
            stale_args.append(lit)
    crate = "eac_target_auto"
    harness = _rust_validflag_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        ref_ty=ref_ty, valid_ctor=valid_ctor, stale_ctor=stale_ctor,
        valid_args=valid_args, stale_args=stale_args, arg_types=arg_types,
        ret_ty=ret_ty, err_ty=err_ty, flag_field=flag_field)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["freshness_shape"] = "valid-flag-check"
    result["validity_flag"] = f"{ref_ty}.{flag_field}"
    result["flag_polarity"] = polarity
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_validflag_ctor(target_src: str, ref_ty: str, flag_field: str,
                         flag_lit: str) -> Optional[str]:
    sm = re.search(rf"struct\s+{re.escape(ref_ty)}\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                          sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        if name == flag_field:
            fields.append(f"{name}: {flag_lit}")
        else:
            fields.append(f"{name}: {_rust_zero(fty, name)}")
    return f"{ref_ty} {{ {', '.join(fields)} }}"


def _rust_validflag_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                            crate: str, category: str, ref_ty: str,
                            valid_ctor: str, stale_ctor: str,
                            valid_args: List[str], stale_args: List[str],
                            arg_types: str, ret_ty: str, err_ty: str,
                            flag_field: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    cat_id = category.replace("-", "_")
    valid_call = ", ".join(valid_args)
    stale_call = ", ".join(stale_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, valid-flag staleness)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed). The read
// struct carries a `{flag_field}` validity flag; a datum flagged stale/invalid
// must be REJECTED for the invariant to HOLD.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the validity invariant HOLDS: a VALID datum is accepted (Ok) AND a
    // STALE/INVALID datum is REJECTED (Err). On the buggy fn the stale datum is
    // (incorrectly) accepted (the flag is never consulted) -> invariant violated
    // -> the exploit test FAILs (the invariant catches the ignored validity flag).
    let __valid: {ref_ty} = {valid_ctor};
    let __stale: {ref_ty} = {stale_ctor};
    f({valid_call}).is_ok() && f({stale_call}).is_err()
}}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} read a stale/invalid datum (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the stale/invalid datum: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Rust double-mint / double-credit convert path (guard = processed-flag-check).
# ---------------------------------------------------------------------------
#
# The shape: a fn credits/mints/settles a numeric amount onto a `&mut <T>` state
# struct WITHOUT a processed/claimed flag, so a replayed call double-credits. The
# fixed variant injects a `processed_AUTO: bool` field on the struct + a guard
# that rejects the second call and sets the flag on the first. Signature-driven.

def _detect_rust_double_credit(target_src: str, fn_src: str):
    """Return (state_param, state_ty, credit_field) when the fn matches the
    double-credit shape (a single &mut state struct carrying a creditable numeric
    field that the body WRITES, no pre-existing processed flag consulted), else
    None."""
    named = _rust_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    for (name, ty, is_ref) in named:
        if "&" not in ty or "mut" not in ty:
            continue
        bare = ty.lstrip("&").replace("mut", "").strip()
        sm = re.search(rf"struct\s+{re.escape(bare)}\s*\{{([^}}]*)\}}", target_src)
        if not sm:
            continue
        credit_field = None
        already_flag = None
        for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                              sm.group(1)):
            fname, fty = fm.group(1), fm.group(2)
            if fty in _RUST_INT_TYPES and _CREDIT_FIELD_RE.search(fname):
                # require the body to WRITE this field (the credit effect).
                if re.search(rf"{re.escape(name)}\.{re.escape(fname)}\s*[-+*]?=", body):
                    credit_field = fname
            if fty == "bool" and _PROCESSED_FLAG_RE.search(fname):
                already_flag = fname
        if credit_field is None:
            continue
        # if the body already consults a processed flag, the bug is not present.
        if already_flag and re.search(rf"\.{re.escape(already_flag)}\b", body):
            continue
        return name, bare, credit_field
    return None


def derive_rust_fixed_processedflag(fn_src: str, fn: str, fixed_name: str,
                                    state_param: str) -> str:
    """Inject the processed-flag guard (using the injected `processed_AUTO` field)
    at the top of the body and rename to fixed_name."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    guard_stmt = (
        f"\n    if {state_param}.processed_AUTO {{ return Err(\"double-credit "
        f"violation: this id was already processed (replay)\".into()); }}\n"
        f"    {state_param}.processed_AUTO = true;\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _ensure_rust_processed_field(target_src: str, state_ty: str) -> str:
    """Add a `pub processed_AUTO: bool` field to the state struct decl if absent."""
    sm = re.search(rf"(struct\s+{re.escape(state_ty)}\s*\{{)([^}}]*)(\}})", target_src)
    if not sm:
        return target_src
    if "processed_AUTO" in sm.group(2):
        return target_src
    inner = sm.group(2).rstrip()
    sep = "" if inner.strip().endswith(",") or not inner.strip() else ","
    new_inner = f"{inner}{sep} pub processed_AUTO: bool "
    return target_src[: sm.start(2)] + new_inner + target_src[sm.end(2):]


def _convert_rust_double_credit(target_file: Path, src: str, fn_src: str, fn: str,
                                vuln_class: str, category: str, inv: Dict[str, Any],
                                dc, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, credit_field = dc
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no error-rejection channel for the "
                         "processed-flag-check); obligation: hand-author the guard"))
    fixed_name = f"{fn}_fixed_AUTO"
    # amend the struct with the processed_AUTO flag so both buggy + fixed compile.
    amended = _ensure_rust_processed_field(src, state_ty)
    fixed_src = derive_rust_fixed_processedflag(fn_src, fn, fixed_name, state_param)
    lib_rs = _rust_lib(amended, fn_src, fixed_src)
    state_ctor = _rust_struct_literal(amended, state_ty)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        "could not synthesize a constructor for the state type")
    named = _rust_named_params(fn_src)
    param_types = _rust_param_types(fn_src)
    arg_types = _rust_fn_ptr_types(param_types, state_ty)
    other_pre: List[str] = []
    for (name, ty, is_ref) in named:
        if name == state_param:
            continue
        other_pre.append(_rust_arg_literal(amended, ty))
    # ordered call args: state -> &mut __st, others -> concrete per-type literals.
    call_args: List[str] = []
    for (name, ty, is_ref) in named:
        if name == state_param:
            call_args.append("&mut __st")
        else:
            call_args.append(_rust_arg_literal(amended, ty))
    crate = "eac_target_auto"
    harness = _rust_double_credit_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        state_ty=state_ty, state_ctor=state_ctor, arg_types=arg_types,
        call_args=call_args, ret_ty=ret_ty, err_ty=err_ty,
        credit_field=credit_field)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["uniqueness_shape"] = "processed-flag-check"
    result["state_param"] = state_param
    result["credit_field"] = f"{state_ty}.{credit_field}"
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_double_credit_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                                crate: str, category: str, state_ty: str,
                                state_ctor: str, arg_types: str,
                                call_args: List[str], ret_ty: str, err_ty: str,
                                credit_field: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    cat_id = category.replace("-", "_")
    call = ", ".join(call_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, double-credit)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed) TWICE on the
// SAME state. The second call (a replay) must be REJECTED for the uniqueness
// invariant to HOLD (a credit applies at most once per id).
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the uniqueness invariant HOLDS: the first call is accepted (Ok) AND
    // a replay on the SAME state is REJECTED (Err). On the buggy fn the replay is
    // (incorrectly) accepted and double-credits -> invariant violated -> the
    // exploit test FAILs (the invariant catches the missing processed-flag guard).
    let mut __st: {state_ty} = {state_ctor};
    let first = f({call});
    let second = f({call});
    first.is_ok() && second.is_err()
}}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} double-credited a replay (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the replay: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Rust signature-replay / missing-nonce convert path (guard = used-nonce-check).
# ---------------------------------------------------------------------------
#
# The shape: an authorization fn takes a value-typed signature/message param AND a
# `&mut <State>` param whose struct carries an UNCONSULTED nonce field (a bool
# `used`/`consumed` flag, or a numeric `nonce`/`seq` counter). The buggy fn
# authorizes without flipping/incrementing the nonce, so the SAME signed payload
# replays on the SAME state. The fixed variant injects a flip-and-reject guard
# (for the counter sub-shape we add a `used_AUTO: bool` sentinel, mirroring Go).
# Signature-driven: param/field NAMES are matched, not target symbols.

def _rust_struct_field_matching(target_src: str, ty: str, name_re,
                                type_pred) -> Optional[Tuple[str, str]]:
    """Return (field_name, field_type) of the FIRST field on struct `ty` whose
    name matches `name_re` AND whose type satisfies `type_pred(field_type)`.
    The Rust sibling of `_go_struct_field_matching`."""
    sm = re.search(rf"struct\s+{re.escape(ty)}\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                          sm.group(1)):
        fname, fty = fm.group(1), fm.group(2)
        if name_re.search(fname) and type_pred(fty):
            return fname, fty
    return None


def _detect_rust_signature_replay(target_src: str, fn_src: str):
    """Return (state_param, state_ty, sig_param, nonce_field, nonce_kind) when the
    fn matches the signature-replay shape, else None. nonce_kind is 'flag' (bool,
    flip-and-reject) or 'counter' (numeric, sentinel-flag injected). The Rust
    sibling of `_detect_go_signature_replay`."""
    named = _rust_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    # require a value-typed signature/message param (NOT a `&mut <T>` state ref,
    # so a state ref whose name happens to match the sig vocabulary is excluded).
    sig_param = None
    for (name, ty, is_ref) in named:
        if "&" in ty:
            continue
        if _SIG_PARAM_RE.search(name):
            sig_param = name
            break
    if sig_param is None:
        return None
    for (name, ty, is_ref) in named:
        if "&" not in ty or "mut" not in ty:
            continue
        if name == sig_param:
            continue
        bare = ty.lstrip("&").replace("mut", "").strip()
        # prefer a bool flag nonce.
        flag = _rust_struct_field_matching(
            target_src, bare, _NONCE_FLAG_RE, lambda t: t == "bool")
        if flag is not None:
            # buggy fn must NOT already consult the flag.
            if re.search(rf"\.{re.escape(flag[0])}\b", body):
                continue
            return name, bare, sig_param, flag[0], "flag"
        # else a numeric counter nonce that the buggy fn never reads/increments.
        ctr = _rust_struct_field_matching(
            target_src, bare, _NONCE_COUNTER_RE, lambda t: t in _RUST_INT_TYPES)
        if ctr is not None:
            if re.search(rf"\.{re.escape(ctr[0])}\b", body):
                continue
            return name, bare, sig_param, ctr[0], "counter"
    return None


def derive_rust_fixed_usednonce(fn_src: str, fn: str, fixed_name: str,
                                state_param: str, nonce_field: str,
                                nonce_kind: str) -> str:
    """Inject the used-nonce guard at the top of the body and rename to fixed_name.
    For a bool flag: `if st.<flag> { reject }; st.<flag> = true`. For a numeric
    counter: flip-and-reject on the injected `used_AUTO: bool` sentinel (the counter
    is unconsulted by the buggy fn, so the mechanical fix is the bool used-flag
    sibling the converter adds via _ensure_rust_usednonce_field)."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    if nonce_kind == "flag":
        guard_stmt = (
            f"\n    if {state_param}.{nonce_field} {{ return Err(\"signature-replay "
            f"violation: this signed authorization was already consumed (nonce not "
            f"marked used)\".into()); }}\n"
            f"    {state_param}.{nonce_field} = true;\n"
        )
    else:
        guard_stmt = (
            f"\n    if {state_param}.used_AUTO {{ return Err(\"signature-replay "
            f"violation: this signed authorization was already consumed (nonce not "
            f"marked used)\".into()); }}\n"
            f"    {state_param}.used_AUTO = true;\n"
        )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _ensure_rust_usednonce_field(target_src: str, state_ty: str) -> str:
    """Add a `pub used_AUTO: bool` field to the state struct (for the counter
    sub-shape where no bool nonce flag exists)."""
    sm = re.search(rf"(struct\s+{re.escape(state_ty)}\s*\{{)([^}}]*)(\}})", target_src)
    if not sm:
        return target_src
    if "used_AUTO" in sm.group(2):
        return target_src
    inner = sm.group(2).rstrip()
    sep = "" if inner.strip().endswith(",") or not inner.strip() else ","
    new_inner = f"{inner}{sep} pub used_AUTO: bool "
    return target_src[: sm.start(2)] + new_inner + target_src[sm.end(2):]


def _convert_rust_signature_replay(target_file: Path, src: str, fn_src: str, fn: str,
                                   vuln_class: str, category: str, inv: Dict[str, Any],
                                   sr, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, sig_param, nonce_field, nonce_kind = sr
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no error-rejection channel for the "
                         "used-nonce-check); obligation: hand-author the nonce guard"))
    fixed_name = f"{fn}_fixed_AUTO"
    amended = src if nonce_kind == "flag" else _ensure_rust_usednonce_field(src, state_ty)
    fixed_src = derive_rust_fixed_usednonce(fn_src, fn, fixed_name, state_param,
                                            nonce_field, nonce_kind)
    lib_rs = _rust_lib(amended, fn_src, fixed_src)
    state_ctor = _rust_struct_literal(amended, state_ty)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        "could not synthesize a constructor for the state type")
    named = _rust_named_params(fn_src)
    param_types = _rust_param_types(fn_src)
    arg_types = _rust_fn_ptr_types(param_types, state_ty)
    # ordered call args: state -> &mut __st (replayed on the SAME state), others ->
    # concrete per-type literals (the SAME signed payload each call).
    call_args: List[str] = []
    for (name, ty, is_ref) in named:
        if name == state_param:
            call_args.append("&mut __st")
        else:
            call_args.append(_rust_arg_literal(amended, ty))
    crate = "eac_target_auto"
    harness = _rust_signature_replay_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        state_ty=state_ty, state_ctor=state_ctor, arg_types=arg_types,
        call_args=call_args, ret_ty=ret_ty, err_ty=err_ty, sig_param=sig_param,
        nonce_field=nonce_field if nonce_kind == "flag" else "used_AUTO")

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["uniqueness_shape"] = "used-nonce-check"
    result["sig_param"] = sig_param
    result["nonce_field"] = f"{state_ty}.{nonce_field}"
    result["nonce_kind"] = nonce_kind
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_signature_replay_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                                   crate: str, category: str, state_ty: str,
                                   state_ctor: str, arg_types: str,
                                   call_args: List[str], ret_ty: str, err_ty: str,
                                   sig_param: str, nonce_field: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    cat_id = category.replace("-", "_")
    call = ", ".join(call_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, signature-replay)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed) TWICE with the
// SAME signed payload (`{sig_param}`) on the SAME state. The second call (a replay)
// must be REJECTED for the uniqueness invariant to HOLD (a signed authorization is
// consumable at most once). The fixed variant gates on `{state_ty}.{nonce_field}`.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the uniqueness invariant HOLDS: the first authorization is accepted
    // (Ok) AND a replay on the SAME state with the SAME signed payload is REJECTED
    // (Err). On the buggy fn the replay is (incorrectly) accepted (the nonce is
    // never marked used) -> invariant violated -> the exploit test FAILs.
    let mut __st: {state_ty} = {state_ctor};
    let first = f({call});
    let second = f({call});
    first.is_ok() && second.is_err()
}}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} accepted a replayed signature (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the replayed signature: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Rust unchecked-external-call-return convert path (guard = call-return-check).
# ---------------------------------------------------------------------------
#
# The shape: a fn takes a callback/transfer param (a closure-typed param `impl
# Fn(..) -> bool` / `F: Fn(..) -> bool` / `&dyn Fn(..) -> bool`, also `-> Result`)
# that it INVOKES but whose result it DISCARDS (a bare `name(args);` statement),
# so a failed external call is treated as success. The fixed variant captures the
# result and rejects on failure. Signature-driven: no `transfer`/`send` symbol is
# hardcoded. The drive normalises the callback param to a `&dyn Fn(u64) -> bool`
# (or `-> Result<(), <Err>>`) so a failing closure and a succeeding closure can be
# passed.

def _rust_callback_return_kind(ty: str) -> Optional[str]:
    """For a callback param type whose closure-return is `bool` / `Result<...>`,
    return 'bool' or 'result', else None. Accepts `impl Fn(..) -> bool`,
    `F: Fn(..) -> bool`, `&dyn Fn(..) -> Result<(), E>`, `Box<dyn Fn(..) -> bool>`
    etc. - we only inspect the `-> <ret>` suffix."""
    m = re.search(r"->\s*([A-Za-z_][\w:<>, ()]*?)\s*$", ty.strip())
    if not m:
        return None
    r = m.group(1).strip()
    if r == "bool":
        return "bool"
    if r.startswith("Result"):
        return "result"
    return None


def _rust_callback_param(fn_src: str) -> Optional[Tuple[str, str, str]]:
    """Return (param_name, param_type, return_kind) for a closure-typed callback
    param whose name matches the external-call vocabulary AND whose type is an
    `Fn`-trait closure returning bool/Result. Uses MULTI-TOKEN type capture so the
    closure type (which spans `->`) is preserved."""
    for (name, ty) in _rust_named_params_full(fn_src):
        if not _CALL_PARAM_RE.search(name):
            continue
        if not re.search(r"\bFn(Mut|Once)?\b", ty):
            continue
        kind = _rust_callback_return_kind(ty)
        if kind is not None:
            return name, ty, kind
    return None


def _rust_named_params_full(fn_src: str) -> List[Tuple[str, str]]:
    """Like _rust_named_params but preserves MULTI-TOKEN types (a closure param
    `remit: impl Fn(u64) -> bool` -> ('remit', 'impl Fn(u64) -> bool')). Needed by
    the unchecked-external-call detector where the callback type spans `->`."""
    sig = _rust_param_list(fn_src)
    out: List[Tuple[str, str]] = []
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw:
            continue
        m = re.match(r"([A-Za-z_]\w*)\s*:\s*(.+)$", raw)
        if not m:
            continue
        out.append((m.group(1), m.group(2).strip()))
    return out


def _detect_rust_unchecked_call(fn_src: str):
    """Return (call_param, result_kind) when a closure-typed callback param
    returning bool/Result is INVOKED in the body but its result is DISCARDED, else
    None. The Rust sibling of `_detect_go_unchecked_call`."""
    cb = _rust_callback_param(fn_src)
    if cb is None:
        return None
    name, ty, kind = cb
    body = fn_src[fn_src.find("{"):]
    # the body must INVOKE the param: a bare `name(` call.
    if not re.search(rf"(^|[^.\w]){re.escape(name)}\s*\(", body):
        return None
    # the result must be DISCARDED: a bare `name(args);` statement whose value is
    # not bound (`let x = name(`), tested (`if name(`), returned (`return name(`),
    # `?`-propagated, or negated (`!name(`). We scan each invocation and check the
    # line prefix does NOT capture/consult the value.
    for cm in re.finditer(rf"(^|[^.\w])({re.escape(name)}\s*\([^\n;]*\))", body):
        before = body[max(0, cm.start() - 60): cm.start(2)]
        line_start = before.rfind("\n")
        prefix = before[line_start + 1:]
        if re.search(r"(=|\bif\b|\breturn\b|\blet\b|!|==|&&|\|\|)\s*$", prefix):
            continue
        # also a trailing `?` immediately after the call consults the result.
        after = body[cm.end(2): cm.end(2) + 2]
        if after.lstrip().startswith("?"):
            continue
        return name, kind
    return None


def derive_rust_fixed_callcheck(fn_src: str, fn: str, fixed_name: str,
                                call_param: str, result_kind: str) -> str:
    """Replace the FIRST discarded `<call_param>(...)` statement with a checked
    form that captures the result and rejects on failure, and rename to fixed_name.
    bool: `if !<call>(..) { return Err(..) }`. result: `if <call>(..).is_err() {
    return Err(..) }`."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    reject = ("return Err(\"unchecked-external-call violation: the external call "
              "failed but its return status was ignored\".into());")
    if result_kind == "bool":
        check = (lambda call: f"if !({call}) {{ {reject} }}")
    else:
        check = (lambda call: f"if ({call}).is_err() {{ {reject} }}")

    def _repl(m):
        # m.group(1) is the leading non-call char (preserve it); m.group(2) is the
        # `call(args)` text; an optional trailing `;` is dropped (the check carries
        # its own braces/semicolons).
        return m.group(1) + check(m.group(2))
    return re.sub(rf"(^|[^.\w])({re.escape(call_param)}\s*\([^\n;]*\))\s*;",
                  _repl, fixed, count=1)


def _convert_rust_unchecked_call(target_file: Path, src: str, fn_src: str, fn: str,
                                 vuln_class: str, category: str, inv: Dict[str, Any],
                                 uc, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    call_param, result_kind = uc
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no error-rejection channel for the "
                         "call-return-check); obligation: hand-author the return check"))
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_callcheck(fn_src, fn, fixed_name, call_param, result_kind)
    lib_rs = _rust_lib(src, fn_src, fixed_src)
    named = _rust_named_params(fn_src)
    # Build the per-call arg slots. The callback param is the FAIL/OK closure; a
    # `&mut <T>` state ref is bound to a fresh `let mut __stN` local (each call gets
    # its OWN state so the FAIL/OK runs are independent); other params are concrete
    # literals. We drive the fns by NAME directly (no `fn`-pointer) so a generic
    # `impl Fn` callback param coerces cleanly.
    pre_lines: List[str] = []
    fail_args: List[str] = []
    ok_args: List[str] = []
    st_i = 0
    for (name, ty, is_ref) in named:
        if name == call_param:
            fail_args.append("&__failCB")
            ok_args.append("&__okCB")
            continue
        t = ty.strip()
        if t.startswith("&") and "mut" in t:
            bare = t.lstrip("&").replace("mut", "").strip()
            lit = _rust_owned_literal(src, bare)
            pre_lines.append(f"    let mut __stF{st_i}: {bare} = {lit};")
            pre_lines.append(f"    let mut __stO{st_i}: {bare} = {lit};")
            fail_args.append(f"&mut __stF{st_i}")
            ok_args.append(f"&mut __stO{st_i}")
            st_i += 1
        elif t.startswith("&"):
            bare = t.lstrip("&").strip()
            lit = _rust_owned_literal(src, bare)
            pre_lines.append(f"    let __stF{st_i}: {bare} = {lit};")
            pre_lines.append(f"    let __stO{st_i}: {bare} = {lit};")
            fail_args.append(f"&__stF{st_i}")
            ok_args.append(f"&__stO{st_i}")
            st_i += 1
        else:
            lit = _rust_arg_literal(src, ty)
            fail_args.append(lit)
            ok_args.append(lit)
    if result_kind == "bool":
        fail_cb = "|_: u64| false"
        ok_cb = "|_: u64| true"
    else:
        fail_cb = '|_: u64| Err::<(), String>("call failed".into())'
        ok_cb = "|_: u64| Ok::<(), String>(())"
    crate = "eac_target_auto"
    harness = _rust_uncheckedcall_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        pre_lines=pre_lines, fail_args=fail_args, ok_args=ok_args,
        fail_cb=fail_cb, ok_cb=ok_cb, call_param=call_param, result_kind=result_kind)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["external_call_shape"] = "call-return-check"
    result["call_param"] = call_param
    result["result_kind"] = result_kind
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_uncheckedcall_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                                crate: str, category: str, pre_lines: List[str],
                                fail_args: List[str], ok_args: List[str],
                                fail_cb: str, ok_cb: str, call_param: str,
                                result_kind: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    cat_id = category.replace("-", "_")
    pre = ("\n".join(pre_lines) + "\n") if pre_lines else ""
    fail_call = ", ".join(fail_args)
    ok_call = ", ".join(ok_args)
    # one drive body per fn (buggy + fixed); named-direct calls so a generic
    # `impl Fn` callback param coerces. We re-build the state locals inside each
    # drive so the buggy/fixed runs are fully independent.
    def body(target: str) -> str:
        return (f"{{\n{pre}"
                f"    let __failCB = {fail_cb};\n"
                f"    let __okCB = {ok_cb};\n"
                f"    let failed = {target}({fail_call});\n"
                f"    let ok = {target}({ok_call});\n"
                f"    failed.is_err() && ok.is_ok()\n}}")
    buggy_body = body(fn)
    fixed_body = body(fixed_name)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, unchecked-external-call-return)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed) with a FAILING
// external call (`{call_param}` returns {result_kind} failure) and a SUCCEEDING
// one. When the call FAILS the fn must REJECT (Err) for the external-call invariant
// to HOLD; the buggy fn ignores the call return and accepts both.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive_buggy_AUTO() -> bool {buggy_body}

fn drive_fixed_AUTO() -> bool {fixed_body}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    // TRUE iff the external-call invariant HOLDS: a FAILING call is REJECTED (Err)
    // AND a SUCCEEDING call is ACCEPTED (Ok). On the buggy fn the failing call's
    // status is discarded so BOTH are accepted -> invariant violated -> this FAILs.
    assert!(drive_buggy_AUTO(),
        "{category} invariant VIOLATED: {fn} treated a failed external call as success (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive_fixed_AUTO(),
        "negative control failed: {fixed_name} must reject when the external call fails: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Rust missing-deadline / slippage-bound convert path (guard = deadline-bound-check)
# ---------------------------------------------------------------------------
#
# The shape: a swap/fill/exec fn takes a realized numeric param AND a caller-
# supplied bound param (min_out / deadline), but does NOT compare them - executing
# under adverse conditions. The fixed variant injects the polarity-aware bound
# comparison (MIN: reject realized < bound; MAX/DEADLINE: reject realized > bound).
# Signature-driven: no `swap`/`minOut` symbol is hardcoded.

def _detect_rust_missing_deadline(fn_src: str):
    """Return (realized_param, bound_param, polarity) when the fn carries a numeric
    realized param + a numeric bound param NOT compared in the body, else None. The
    Rust sibling of `_detect_go_missing_deadline`."""
    named = _rust_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    realized = None
    for (name, ty, is_ref) in named:
        if _REALIZED_PARAM_RE.search(name) and ty.strip() in _RUST_INT_TYPES:
            realized = name
            break
    if realized is None:
        return None
    for (name, ty, is_ref) in named:
        if name == realized or ty.strip() not in _RUST_INT_TYPES:
            continue
        if not _BOUND_PARAM_RE.search(name):
            continue
        polarity = "min" if _BOUND_MIN_RE.search(name) else (
            "max" if _BOUND_MAX_RE.search(name) else "min")
        # the buggy fn must NOT already compare realized against the bound.
        cmp_re = (rf"\b{re.escape(realized)}\b\s*[<>]=?\s*\b{re.escape(name)}\b|"
                  rf"\b{re.escape(name)}\b\s*[<>]=?\s*\b{re.escape(realized)}\b")
        if re.search(cmp_re, body):
            continue
        return realized, name, polarity
    return None


def derive_rust_fixed_deadlinecheck(fn_src: str, fn: str, fixed_name: str,
                                    realized: str, bound: str, polarity: str) -> str:
    """Inject the bound check at the top of the body and rename to fixed_name.
    MIN polarity: reject when realized < bound. MAX/DEADLINE: reject when realized
    > bound."""
    fixed = re.sub(rf"\bfn\s+{re.escape(fn)}\b", f"fn {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    cond = (f"{realized} < {bound}" if polarity == "min" else f"{realized} > {bound}")
    guard_stmt = (
        f"\n    if {cond} {{ return Err(\"slippage-bound violation: the realized "
        f"execution value violates the caller-supplied min_out/deadline bound\""
        f".into()); }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _convert_rust_missing_deadline(target_file: Path, src: str, fn_src: str, fn: str,
                                   vuln_class: str, category: str, inv: Dict[str, Any],
                                   md, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    realized, bound, polarity = md
    ret_ty, err_ty = _rust_return_error_types(fn_src)
    if "Result" not in fn_src[: fn_src.find("{")]:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("fn does not return Result (no error-rejection channel for the "
                         "deadline-bound-check); obligation: hand-author the bound check"))
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed_deadlinecheck(fn_src, fn, fixed_name, realized,
                                                bound, polarity)
    lib_rs = _rust_lib(src, fn_src, fixed_src)
    # in-bound case (must accept) + out-of-bound case (must reject). MIN: in-bound =
    # realized(100) >= bound(50); out = realized(10) < 50. MAX/DEADLINE: in-bound =
    # realized(10) <= bound(50); out = realized(100) > 50.
    bound_val = "50"
    if polarity == "min":
        in_realized, out_realized = "100", "10"
    else:
        in_realized, out_realized = "10", "100"
    named = _rust_named_params(fn_src)
    # Build per-call arg slots. realized/bound -> the numeric in/out test values;
    # a `&mut <T>` / `&<T>` ref -> a fresh `let mut __stN` local bound per call;
    # other params -> concrete literals. We drive the fns by NAME directly so any
    # `&mut` ref param binds cleanly (a `fn`-pointer drive would mis-pass `&mut`).
    pre_lines: List[str] = []
    in_args: List[str] = []
    out_args: List[str] = []
    st_i = 0
    for (name, ty, is_ref) in named:
        if name == realized:
            in_args.append(in_realized)
            out_args.append(out_realized)
        elif name == bound:
            in_args.append(bound_val)
            out_args.append(bound_val)
        else:
            t = ty.strip()
            if t.startswith("&") and "mut" in t:
                bare = t.lstrip("&").replace("mut", "").strip()
                lit = _rust_owned_literal(src, bare)
                pre_lines.append(f"    let mut __stI{st_i}: {bare} = {lit};")
                pre_lines.append(f"    let mut __stO{st_i}: {bare} = {lit};")
                in_args.append(f"&mut __stI{st_i}")
                out_args.append(f"&mut __stO{st_i}")
                st_i += 1
            elif t.startswith("&"):
                bare = t.lstrip("&").strip()
                lit = _rust_owned_literal(src, bare)
                pre_lines.append(f"    let __stI{st_i}: {bare} = {lit};")
                pre_lines.append(f"    let __stO{st_i}: {bare} = {lit};")
                in_args.append(f"&__stI{st_i}")
                out_args.append(f"&__stO{st_i}")
                st_i += 1
            else:
                lit = _rust_arg_literal(src, ty)
                in_args.append(lit)
                out_args.append(lit)
    crate = "eac_target_auto"
    harness = _rust_deadline_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, crate=crate, category=category,
        pre_lines=pre_lines, in_args=in_args, out_args=out_args,
        realized=realized, bound=bound, polarity=polarity)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    result["slippage_shape"] = "deadline-bound-check"
    result["realized_param"] = realized
    result["bound_param"] = bound
    result["bound_polarity"] = polarity
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _rust_deadline_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                           crate: str, category: str, pre_lines: List[str],
                           in_args: List[str], out_args: List[str],
                           realized: str, bound: str, polarity: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    cat_id = category.replace("-", "_")
    rel = ">=" if polarity == "min" else "<="
    pre = ("\n".join(pre_lines) + "\n") if pre_lines else ""
    in_call = ", ".join(in_args)
    out_call = ", ".join(out_args)

    def body(target: str) -> str:
        return (f"{{\n{pre}"
                f"    let within = {target}({in_call});\n"
                f"    let over = {target}({out_call});\n"
                f"    within.is_ok() && over.is_err()\n}}")
    buggy_body = body(fn)
    fixed_body = body(fixed_name)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, missing-deadline/slippage-bound)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed) with an IN-BOUND
// case (realized {rel} bound, must be ACCEPTED) and an OUT-OF-BOUND case (must be
// REJECTED). The bound is `{bound}` ({polarity}); the realized value is `{realized}`.
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive_buggy_AUTO() -> bool {buggy_body}

fn drive_fixed_AUTO() -> bool {fixed_body}

#[test]
fn test_exploit_{cat_id}_{fn}() {{
    // TRUE iff the slippage-bound invariant HOLDS: an IN-BOUND realized value is
    // accepted (Ok) AND an OUT-OF-BOUND value is REJECTED (Err). On the buggy fn the
    // bound is never compared so the adverse value is (incorrectly) accepted -> this FAILs.
    assert!(drive_buggy_AUTO(),
        "{category} invariant VIOLATED: {fn} executed an out-of-bound (adverse) value (bug present): {tag}");
}}

#[test]
fn test_negative_control_{cat_id}_{fn}() {{
    assert!(drive_fixed_AUTO(),
        "negative control failed: {fixed_name} must reject the out-of-bound value: {tag}");
}}
'''


def convert_rust(target_file: Path, fn: str, vuln_class: str, category: str,
                 guard: str, inv: Dict[str, Any], out_dir: Optional[Path],
                 run: bool) -> Dict[str, Any]:
    src = read_target(target_file)
    fn_src = extract_rust_fn(src, fn)
    if fn_src is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        f"function {fn!r} not found in {target_file.name}")
    ok, unresolved = is_rust_self_contained(src, fn_src)
    if not ok:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("target fn is not self-contained (references "
                         f"{unresolved or 'external paths'}); obligation: drive the "
                         "real fn inside its own crate's `tests/` target"))
    if guard == "cap-check":
        return _convert_rust_bounds(target_file, src, fn_src, fn, vuln_class,
                                    category, inv, out_dir, run)
    if guard == "cast-bound-check":
        trunc = _detect_rust_truncation(fn_src)
        if trunc is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no wide numeric param flows into a narrowing `as <T>` "
                             "cast in this fn; obligation: hand-author the int-"
                             "truncation invariant + cast-bound-check fixed variant"))
        return _convert_rust_truncation(target_file, src, fn_src, fn, vuln_class,
                                        category, inv, trunc, out_dir, run)
    if guard == "owner-guard":
        ac = _detect_rust_access_control(src, fn_src)
        if ac is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no mutable state param with an identity field + a "
                             "matching caller param (and no existing owner check) "
                             "found; obligation: hand-author the access-control "
                             "invariant + owner-guard fixed variant"))
        return _convert_rust_access_control(target_file, src, fn_src, fn, vuln_class,
                                            category, inv, ac, out_dir, run)
    if guard == "cei-order-check":
        ree = _detect_rust_reentrancy(src, fn_src)
        if ree is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no callback/hook param invoked BEFORE a state balance-"
                             "field write found (no CEI-ordering bug); obligation: "
                             "hand-author the reentrancy invariant + CEI reorder"))
        return _convert_rust_reentrancy(target_file, src, fn_src, fn, vuln_class,
                                        category, inv, ree, out_dir, run)
    if guard == "valid-flag-check":
        vf = _detect_rust_valid_flag(src, fn_src)
        if vf is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no read ref whose struct carries a value field + an "
                             "unconsulted validity/staleness bool flag found; "
                             "obligation: hand-author the valid-flag invariant + gate"))
        return _convert_rust_valid_flag(target_file, src, fn_src, fn, vuln_class,
                                        category, inv, vf, out_dir, run)
    if guard == "processed-flag-check":
        dc = _detect_rust_double_credit(src, fn_src)
        if dc is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no single &mut state param with a written creditable "
                             "numeric field (and no consulted processed flag) found; "
                             "obligation: hand-author the processed-flag invariant"))
        return _convert_rust_double_credit(target_file, src, fn_src, fn, vuln_class,
                                           category, inv, dc, out_dir, run)
    if guard == "used-nonce-check":
        sr = _detect_rust_signature_replay(src, fn_src)
        if sr is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no signature/message value param + `&mut <State>` "
                             "nonce/used field (unconsulted) found; obligation: hand-"
                             "author the signature-replay invariant + used-nonce guard"))
        return _convert_rust_signature_replay(target_file, src, fn_src, fn, vuln_class,
                                              category, inv, sr, out_dir, run)
    if guard == "call-return-check":
        uc = _detect_rust_unchecked_call(fn_src)
        if uc is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no closure-typed callback/transfer param returning "
                             "bool/Result that is INVOKED with its result DISCARDED "
                             "found; obligation: hand-author the external-call-return "
                             "invariant + check"))
        return _convert_rust_unchecked_call(target_file, src, fn_src, fn, vuln_class,
                                            category, inv, uc, out_dir, run)
    if guard == "deadline-bound-check":
        md = _detect_rust_missing_deadline(fn_src)
        if md is None:
            return _blocked(target_file, fn, vuln_class, "rust", inv,
                            ("no numeric realized param + numeric bound param "
                             "(min_out/deadline) that are NOT compared in the body "
                             "found; obligation: hand-author the slippage-bound "
                             "invariant + bound check"))
        return _convert_rust_missing_deadline(target_file, src, fn_src, fn, vuln_class,
                                              category, inv, md, out_dir, run)
    # Freshness family has TWO mechanically-convertible sub-shapes:
    #  (a) consume-once: a `&mut <T>` resource that must be usable at most once
    #      (the freshness-flag guard);
    #  (b) staleness: a `&<T>` ref whose struct carries a stored timestamp field
    #      compared against a `now`/`slot` param minus a `max_delay`/`ttl` bound
    #      (the staleness-gate guard - the dominant oracle-pricing shape, anchor:
    #      Synthetify calculate_debt asset.last_update gate).
    # Try the staleness shape FIRST (it is signature-detectable and disjoint from
    # the consume-once shape); fall back to consume-once; block honestly if
    # neither shape is present (no fabricated fix).
    if guard == "freshness-flag":
        stale = _detect_rust_staleness(src, fn_src)
        if stale is not None:
            return _convert_rust_staleness(target_file, src, fn_src, fn, vuln_class,
                                           category, inv, stale, out_dir, run)
    fixed_name = f"{fn}_fixed_AUTO"
    fixed_src = derive_rust_fixed(fn_src, fn, fixed_name, guard)
    if fixed_src is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        ("could not mechanically derive a fixed variant for this fn "
                         "shape (no `&mut <T>` consume-once resource param and no "
                         "stored-timestamp staleness shape); obligation: "
                         "hand-author the fixed variant + invariant assertion"))
    amended = ensure_rust_used_field(src, fn_src)
    ctor = rust_resource_ctor(amended, fn_src)
    if ctor is None:
        return _blocked(target_file, fn, vuln_class, "rust", inv,
                        "could not synthesize a constructor for the resource type")
    resource_ty, resource_ctor = ctor

    # Build the other (non-&mut-resource) call args as concrete literals so the
    # harness can drive the real fn signature. param_types preserves the REAL
    # signature types for the fn-pointer annotation.
    other_args = _rust_other_args(amended, fn_src)
    param_types = _rust_param_types(fn_src)
    crate = "eac_target_auto"
    lib_rs = _rust_lib(amended, fn_src, fixed_src)
    harness = _rust_real_harness(fn=fn, fixed_name=fixed_name, inv=inv,
                                 resource_ty=resource_ty, resource_ctor=resource_ctor,
                                 other_args=other_args, param_types=param_types,
                                 crate=crate, category=category)

    work = _mk_workdir(out_dir, f"rust_{fn}")
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n', encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_convert.rs").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "rust", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_convert.rs"
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = "cargo not installed; obligation: run `cargo test` on the scaffold"
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc,
                   "transcript_tail": _tail(out)})
    return result


def _rust_param_types(fn_src: str) -> List[Tuple[str, bool]]:
    """Return [(type_string, is_resource)] for each param, where is_resource is
    True for the `&mut <T>` consumable resource (bound separately in the harness)."""
    sig = _rust_param_list(fn_src)
    out: List[Tuple[str, bool]] = []
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw:
            continue
        m = re.match(r"[A-Za-z_]\w*\s*:\s*(.+)$", raw)
        ty = (m.group(1).strip() if m else raw)
        out.append((ty, bool(re.search(r"&\s*mut\s+", ty))))
    return out


def _rust_other_args(target_src: str, fn_src: str) -> List[str]:
    """Render a CONCRETE literal for every param EXCEPT the &mut resource.
    Struct types get a full field-literal (zero/seed-init every field) so the
    harness never relies on `Default`."""
    args: List[str] = []
    for ty, is_res in _rust_param_types(fn_src):
        if is_res:
            continue
        args.append(_rust_arg_literal(target_src, ty))
    return args


def _rust_arg_literal(target_src: str, ty: str) -> str:
    t = ty.strip()
    if t.startswith("&"):
        inner = t.lstrip("&").replace("mut", "").strip()
        return "&" + _rust_owned_literal(target_src, inner)
    return _rust_owned_literal(target_src, t)


def _rust_owned_literal(target_src: str, t: str) -> str:
    t = t.strip()
    if re.match(r"^[iu](8|16|32|64|128|size)$", t):
        return "7"
    if t == "bool":
        return "false"
    if t.startswith("Vec"):
        return "vec![1u8, 2, 3]"
    if t == "String" or t == "str":
        return 'String::from("x")'
    if t in ("f32", "f64"):
        return "1.0"
    # struct / named type: build a full field-literal from its declaration so we
    # never depend on a Default impl the target may not have.
    lit = _rust_struct_literal(target_src, t)
    if lit is not None:
        return lit
    return f"{t}::default()"


def _rust_struct_literal(target_src: str, ty: str) -> Optional[str]:
    sm = re.search(rf"struct\s+{re.escape(ty)}\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w:<>]*)",
                          sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        fields.append(f"{name}: {_rust_zero(fty, name)}")
    return f"{ty} {{ {', '.join(fields)} }}"


def _split_top_commas(s: str) -> List[str]:
    out, depth, cur = [], 0, ""
    for c in s:
        if c in "<([{":
            depth += 1
        elif c in ">)]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur)
    return out


def _rust_lib(target_src: str, buggy_fn_src: str, fixed_fn_src: str) -> str:
    """Assemble lib.rs: the amended target source (types + buggy fn) + the fixed
    variant + aliases the harness references (SignatureShare_AUTO / Error_AUTO).
    We rename the real return + error types to stable aliases for the harness."""
    body = target_src
    if fixed_fn_src not in body:
        body = body.rstrip() + "\n\n" + fixed_fn_src + "\n"
    # Provide stable aliases the harness uses regardless of the real type names.
    ret_ty, err_ty = _rust_return_error_types(buggy_fn_src)
    alias = (f"\npub type SignatureShare_AUTO = {ret_ty};\n"
             f"pub type Error_AUTO = {err_ty};\n")
    return "#![allow(unused, non_camel_case_types, clippy::all)]\n" + body + alias


def _rust_return_error_types(fn_src: str) -> Tuple[str, str]:
    # Slice the RETURN-type text only (everything AFTER the balanced param-list
    # close paren, up to the body brace). Without this, a callback param whose own
    # type contains `-> Result<...>` (e.g. `payout: impl Fn(u64) -> Result<(), E>`)
    # would shadow the fn's real return type and yield a garbage Error_AUTO alias.
    open_idx = fn_src.find("(")
    ret = fn_src[: fn_src.find("{")]
    if open_idx >= 0:
        depth = 0
        for i in range(open_idx, len(fn_src)):
            c = fn_src[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    ret = fn_src[i + 1: fn_src.find("{")]
                    break
    m = re.search(r"->\s*Result\s*<\s*(.+)\s*>\s*$", ret.strip())
    if m:
        inner = m.group(1).strip()
        # split Ok / Err at the TOP-LEVEL comma (Ok types may themselves carry
        # commas, e.g. `Result<(A, B), E>`).
        parts = _split_top_commas(inner)
        if len(parts) >= 2:
            return parts[0].strip(), ",".join(parts[1:]).strip()
        return inner, "String"
    return "()", "String"


def _rust_real_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                       resource_ty: str, resource_ctor: str, other_args: List[str],
                       param_types: List[Tuple[str, bool]],
                       crate: str, category: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    pre = (", ".join(other_args) + ", ") if other_args else ""
    arg_types = _rust_fn_ptr_types(param_types, resource_ty)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed).
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(sign: fn({arg_types}) -> Result<SignatureShare_AUTO, Error_AUTO>) -> bool {{
    // TRUE iff the {category} invariant HOLDS: the consumable resource is usable
    // at most once. We call the real fn twice on the SAME resource; the second
    // call must be rejected (Err) for the invariant to hold.
    let mut n: {resource_ty} = {resource_ctor};
    let first = sign({pre}&mut n);
    let second = sign({pre}&mut n);
    first.is_ok() && second.is_err()
}}

#[test]
fn test_exploit_{category}_{fn}() {{
    // Expected to FAIL on the buggy fn: the invariant catches the vuln.
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} accepted a replay (bug present): {tag}");
}}

#[test]
fn test_negative_control_{category}_{fn}() {{
    // Expected to PASS on the fixed fn: the invariant holds.
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the replay: {tag}");
}}
'''


def _rust_bounds_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                         crate: str, category: str, len_param: str,
                         len_idx: int, param_types: List[Tuple[str, bool]],
                         in_cap_args: List[str], over_cap_args: List[str],
                         ret_ty: str, err_ty: str) -> str:
    """Render a bounds-family harness. It drives the REAL fn twice on the SAME
    config: once with an IN-CAP length (must be accepted -> Ok) and once with an
    OVER-CAP length (must be rejected -> Err) for the invariant to HOLD."""
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    stmt = inv["statement"].replace('"', "'")
    arg_types = ", ".join(ty.strip() for ty, _ in param_types)
    in_call = ", ".join(in_cap_args)
    over_call = ", ".join(over_cap_args)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, bounds)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {stmt}
// Drives the REAL lifted `{fn}` (buggy) and `{fixed_name}` (fixed). The
// caller-controlled length param is `{len_param}` (arg #{len_idx}).
#![allow(unused, non_snake_case)]
use {crate}::*;

fn drive(f: fn({arg_types}) -> Result<{ret_ty}, {err_ty}>) -> bool {{
    // TRUE iff the bounds invariant HOLDS: an in-cap allocation request is
    // accepted AND an over-cap allocation request is REJECTED. The over-cap
    // length is chosen far above any plausible configured bound; on the buggy
    // fn it is (incorrectly) accepted -> invariant violated -> this returns
    // false -> the exploit test FAILs (the invariant catches the DoS).
    let within = f({in_call});
    let over   = f({over_call});
    within.is_ok() && over.is_err()
}}

#[test]
fn test_exploit_{category}_{fn}() {{
    // Expected to FAIL on the buggy fn: the over-cap request is accepted.
    assert!(drive({fn}),
        "{category} invariant VIOLATED: {fn} accepted an over-cap allocation (bug present): {tag}");
}}

#[test]
fn test_negative_control_{category}_{fn}() {{
    // Expected to PASS on the fixed fn: the over-cap request is rejected.
    assert!(drive({fixed_name}),
        "negative control failed: {fixed_name} must reject the over-cap allocation: {tag}");
}}
'''


def _rust_fn_ptr_types(param_types: List[Tuple[str, bool]], resource_ty: str) -> str:
    """Build the fn-pointer parameter type list from the REAL signature types so
    the harness's `fn(...)` annotation matches the lifted fn exactly. The &mut
    resource param keeps its concrete `&mut <T>` type."""
    out: List[str] = []
    for ty, is_res in param_types:
        out.append(ty.strip())
    return ", ".join(out)


# ---------------------------------------------------------------------------
# Go convert path.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Go int-truncation convert path (guard = cast-bound-check).
# ---------------------------------------------------------------------------

def _go_named_params(fn_src: str) -> List[Tuple[str, str]]:
    """Return [(name, type)] for each parameter (Go `name type` syntax)."""
    sig = _go_param_list(fn_src)
    out: List[Tuple[str, str]] = []
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split()
        if len(parts) < 2:
            continue
        out.append((parts[0], parts[-1]))
    return out


def _detect_go_truncation(fn_src: str):
    """Return (param, src_ty, dst_ty) when a WIDE numeric param flows into a
    NARROWING `<dst>(param)` conversion in the body, else None."""
    param_ty = {n: ty for (n, ty) in _go_named_params(fn_src)}
    body = fn_src[fn_src.find("{"):]
    best = None
    dst_alt = "|".join(t for t in _GO_INT_WIDTH if t not in ("uint", "int", "uintptr"))
    for m in re.finditer(rf"\b({dst_alt})\s*\(\s*([a-z_]\w*)\s*\)", body):
        dst, var = m.group(1), m.group(2)
        src_ty = param_ty.get(var)
        if src_ty is None or src_ty not in _GO_INT_WIDTH:
            continue
        if _GO_INT_WIDTH[src_ty] <= _GO_INT_WIDTH.get(dst, 0):
            continue  # not a narrowing conversion
        cand = (var, src_ty, dst)
        if best is None or (_GO_INT_WIDTH[src_ty] - _GO_INT_WIDTH[dst]) > \
                (_GO_INT_WIDTH[best[1]] - _GO_INT_WIDTH[best[2]]):
            best = cand
    return best


def derive_go_fixed_castcheck(fn_src: str, fn: str, fixed_name: str,
                              param: str, dst_ty: str, reject_sentinel: str) -> str:
    """Inject the canonical cast-bound-check guard + rename to fixed_name."""
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    width = _GO_INT_WIDTH[dst_ty]
    bound = _UNSIGNED_MAX.get(width, "0")
    reject_stmt = _go_reject_return(fn_src, reject_sentinel)
    guard_stmt = (
        f"\n\tif uint64({param}) > {bound} {{ {reject_stmt} }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _go_return_list(fn_src: str) -> str:
    """Return the inner text of the fn's return-type list. Handles both the
    parenthesised `) (A, error)` shape and the bare `) error` single-return."""
    brace = fn_src.find("{")
    sig = fn_src[: brace].rstrip()
    # parenthesised return list: the LAST balanced (...) before the brace.
    m = re.search(r"\)\s*\(([^)]*)\)\s*$", sig)
    if m:
        return m.group(1)
    # bare single return: everything after the LAST top-level `)` (the close of
    # the parameter list).
    last = sig.rfind(")")
    return sig[last + 1:].strip()


def _go_reject_return(fn_src: str, reject_sentinel: str) -> str:
    """Build the reject `return ...` statement matching the fn's return arity.
    The LAST return slot is `error`; it gets the non-nil sentinel. Every leading
    slot gets its zero value so the reject path type-checks for `(T, error)` as
    well as the bare `error` shape."""
    ret = _go_return_list(fn_src).strip()
    if not ret:
        return "return"
    parts = [p.strip() for p in _split_top_commas(ret) if p.strip()]
    # If the list is a single `error` slot, return just the sentinel.
    if len(parts) == 1 and parts[0].split()[-1] == "error":
        return f"return {reject_sentinel}"
    # Multi-slot: zero every leading slot, sentinel for the trailing error.
    zeros = _go_zero_returns(", ".join(parts[:-1]))
    if parts[-1].split()[-1] == "error":
        return f"return {zeros}, {reject_sentinel}" if zeros else f"return {reject_sentinel}"
    # No trailing error slot (should not happen - _go_returns_error gates it).
    return f"return {_go_zero_returns(ret)}"


def _go_returns_error(fn_src: str) -> bool:
    brace = fn_src.find("{")
    sig = fn_src[: brace]
    return bool(re.search(r"\berror\s*\)?\s*$", sig.strip()))


def _convert_go_truncation(target_file: Path, src: str, fn_src: str, fn: str,
                           vuln_class: str, category: str, inv: Dict[str, Any],
                           trunc, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    param, src_ty, dst_ty = trunc
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "int-truncation cast-bound-check converter only supports the "
                         "`func(...) error` rejection shape; obligation: hand-author"))
    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed_castcheck(fn_src, fn, fixed_name, param, dst_ty,
                                          "errTruncationAUTO")
    sentinel = ('\n\ntype _truncErrAUTO struct{}\n'
                'func (_truncErrAUTO) Error() string { return "int-truncation '
                'violation: value exceeds the destination type max and would '
                'silently truncate" }\n'
                'var errTruncationAUTO error = _truncErrAUTO{}\n')
    lib = _go_lib(src, fixed_src) + sentinel
    pkg = _go_package(src)
    crate = pkg

    width = _GO_INT_WIDTH[dst_ty]
    bound = int(_UNSIGNED_MAX.get(width, "0"))
    in_val = str(min(7, bound))
    over_val = str(bound + 1)
    in_args: List[str] = []
    over_args: List[str] = []
    for (name, ty) in _go_named_params(fn_src):
        if name == param:
            in_args.append(in_val)
            over_args.append(over_val)
        else:
            in_args.append(_go_arg_literal(ty))
            over_args.append(_go_arg_literal(ty))
    n_rets = _go_return_arity(fn_src)
    call_buggy = _go_truncation_drive_body(fn, in_args, over_args, n_rets)
    call_fixed = _go_truncation_drive_body(fixed_name, in_args, over_args, n_rets)
    harness = _render_go_truncation_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=pkg, category=category,
        call_buggy=call_buggy, call_fixed=call_fixed, param=param,
        src_ty=src_ty, dst_ty=dst_ty)

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["truncation_param"] = param
    result["narrowing_cast"] = f"{src_ty} -> {dst_ty}"
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_return_arity(fn_src: str) -> int:
    ret = _go_return_list(fn_src).strip()
    if not ret:
        return 0
    return len([p for p in _split_top_commas(ret) if p.strip()])


def _go_err_capture(n_rets: int, var: str) -> str:
    """Capture the trailing `error` return into `var`, discarding leading slots.
    For a single-return `error` shape: `var := fn(...)`. For `(T, error)`:
    `_, var := fn(...)`. For `(A, B, error)`: `_, _, var := fn(...)`."""
    if n_rets <= 1:
        return var
    return ", ".join(["_"] * (n_rets - 1) + [var])


def _go_truncation_drive_body(fn: str, in_args: List[str],
                              over_args: List[str], n_rets: int) -> str:
    in_call = ", ".join(in_args)
    over_call = ", ".join(over_args)
    cap_w = _go_err_capture(n_rets, "within")
    cap_o = _go_err_capture(n_rets, "over")
    return (f"\t{cap_w} := {fn}({in_call})\n"
            f"\t{cap_o} := {fn}({over_call})\n"
            f"\treturn within == nil && over != nil")


def _render_go_truncation_harness(*, fn: str, fixed_name: str,
                                  inv: Dict[str, Any], pkg: str, category: str,
                                  call_buggy: str, call_fixed: str, param: str,
                                  src_ty: str, dst_ty: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, int-truncation)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed). The wide param
// `{param}` ({src_ty}) is narrowed by a `{dst_ty}(...)` conversion; a value above
// the {dst_ty} max must be REJECTED for the invariant to HOLD.
package {pkg}

import "testing"

func driveTruncationBuggy_AUTO() bool {{
{call_buggy}
}}

func driveTruncationFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveTruncationBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} truncated an over-{dst_ty}-max value (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveTruncationFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject the over-max value: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Go access-control convert path (guard = owner-guard).
# ---------------------------------------------------------------------------

def _go_struct_identity_field(target_src: str, ty: str):
    """Return (field_name, field_type) of the identity field on struct `ty`."""
    sm = re.search(rf"type\s+{re.escape(ty)}\s+struct\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        fname, fty = fm.group(1), fm.group(2)
        if _IDENTITY_FIELD_RE.search(fname):
            return fname, fty
    return None


def _detect_go_access_control(target_src: str, fn_src: str):
    """Return (state_param, state_ty, identity_field, identity_fty, caller_param)
    when the fn mutates a `*<T>` state struct carrying an identity field AND
    takes a caller param of the SAME type AND does NOT compare them, else None."""
    named = _go_named_params(fn_src)
    state = None
    for (name, ty) in named:
        if not ty.startswith("*"):
            continue
        bare = ty.lstrip("*")
        idf = _go_struct_identity_field(target_src, bare)
        if idf:
            state = (name, bare, idf[0], idf[1])
            break
    if state is None:
        return None
    state_param, state_ty, identity_field, identity_fty = state
    caller_param = None
    for (name, ty) in named:
        if _CALLER_PARAM_RE.search(name) and ty == identity_fty:
            caller_param = name
            break
    if caller_param is None:
        return None
    body = fn_src[fn_src.find("{"):]
    already = (re.search(rf"{re.escape(caller_param)}\s*[!=]=\s*{re.escape(state_param)}\."
                         rf"{re.escape(identity_field)}", body)
               or re.search(rf"{re.escape(state_param)}\.{re.escape(identity_field)}\s*"
                            rf"[!=]=\s*{re.escape(caller_param)}", body))
    if already:
        return None
    return state_param, state_ty, identity_field, identity_fty, caller_param


def derive_go_fixed_ownerguard(fn_src: str, fn: str, fixed_name: str,
                               state_param: str, identity_field: str,
                               caller_param: str) -> str:
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    reject_stmt = _go_reject_return(fn_src, "errAccessControlAUTO")
    guard_stmt = (
        f"\n\tif {caller_param} != {state_param}.{identity_field} {{ "
        f"{reject_stmt} }}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _go_identity_literal(fty: str, attacker: bool = False) -> str:
    if re.match(r"^u?int(8|16|32|64)?$", fty) or fty in ("byte", "rune"):
        return "0xBADBAD" if attacker else "0x111111"
    if fty == "string":
        return '"attacker"' if attacker else '"owner"'
    return f"{fty}{{}}"


def _go_ac_state_ctor(target_src: str, state_ty: str, identity_field: str,
                      owner_lit: str) -> Optional[str]:
    sm = re.search(rf"type\s+{re.escape(state_ty)}\s+struct\s*\{{([^}}]*)\}}",
                   target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        if name == identity_field:
            fields.append(f"{name}: {owner_lit}")
        else:
            fields.append(f"{name}: {_go_field_init(fty, name)}")
    return f"{state_ty}{{{', '.join(fields)}}}"


def _convert_go_access_control(target_file: Path, src: str, fn_src: str, fn: str,
                               vuln_class: str, category: str, inv: Dict[str, Any],
                               ac, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, identity_field, identity_fty, caller_param = ac
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "access-control owner-guard converter only supports the "
                         "`func(...) error` rejection shape; obligation: hand-author"))
    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed_ownerguard(fn_src, fn, fixed_name, state_param,
                                           identity_field, caller_param)
    sentinel = ('\n\ntype _acErrAUTO struct{}\n'
                'func (_acErrAUTO) Error() string { return "access-control violation: '
                'caller is not the stored owner" }\n'
                'var errAccessControlAUTO error = _acErrAUTO{}\n')
    lib = _go_lib(src, fixed_src) + sentinel
    pkg = _go_package(src)
    crate = pkg

    owner_lit = _go_identity_literal(identity_fty)
    attacker_lit = _go_identity_literal(identity_fty, attacker=True)
    state_ctor = _go_ac_state_ctor(src, state_ty, identity_field, owner_lit)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        "could not synthesize a constructor for the state type")
    owner_args: List[str] = []
    attacker_args: List[str] = []
    for (name, ty) in _go_named_params(fn_src):
        if name == state_param:
            owner_args.append("&__stOwner")
            attacker_args.append("&__stAttacker")
        elif name == caller_param:
            owner_args.append(owner_lit)
            attacker_args.append(attacker_lit)
        else:
            owner_args.append(_go_arg_literal(ty))
            attacker_args.append(_go_arg_literal(ty))
    n_rets = _go_return_arity(fn_src)
    call_buggy = _go_access_control_drive_body(fn, state_ty, state_ctor,
                                               owner_args, attacker_args, n_rets)
    call_fixed = _go_access_control_drive_body(fixed_name, state_ty, state_ctor,
                                               owner_args, attacker_args, n_rets)
    harness = _render_go_access_control_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=pkg, category=category,
        call_buggy=call_buggy, call_fixed=call_fixed, state_ty=state_ty,
        identity_field=identity_field, caller_param=caller_param)

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["state_param"] = state_param
    result["identity_field"] = f"{state_ty}.{identity_field}"
    result["caller_param"] = caller_param
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_access_control_drive_body(fn: str, state_ty: str, state_ctor: str,
                                  owner_args: List[str],
                                  attacker_args: List[str], n_rets: int) -> str:
    owner_call = ", ".join(owner_args)
    attacker_call = ", ".join(attacker_args)
    cap_o = _go_err_capture(n_rets, "owner")
    cap_a = _go_err_capture(n_rets, "attacker")
    return (f"\t__stOwner := {state_ctor}\n"
            f"\t__stAttacker := {state_ctor}\n"
            f"\t{cap_o} := {fn}({owner_call})\n"
            f"\t{cap_a} := {fn}({attacker_call})\n"
            f"\treturn owner == nil && attacker != nil")


def _render_go_access_control_harness(*, fn: str, fixed_name: str,
                                      inv: Dict[str, Any], pkg: str, category: str,
                                      call_buggy: str, call_fixed: str,
                                      state_ty: str, identity_field: str,
                                      caller_param: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, access-control)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed). The state struct
// carries `{state_ty}.{identity_field}`; the privileged op must reject a
// `{caller_param}` that is NOT the stored owner for the invariant to HOLD.
package {pkg}

import "testing"

func driveAccessControlBuggy_AUTO() bool {{
{call_buggy}
}}

func driveAccessControlFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveAccessControlBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} accepted a non-owner caller (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveAccessControlFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject the non-owner caller: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Go struct-field helpers shared by the reentrancy / valid-flag / double-credit
# families (canonical-field-name driven; NO target symbol names).
# ---------------------------------------------------------------------------

def _go_struct_field_matching(target_src: str, ty: str, name_re,
                              type_pred) -> Optional[Tuple[str, str]]:
    """Return (field_name, field_type) of the FIRST field on struct `ty` whose
    name matches `name_re` AND whose type satisfies `type_pred(field_type)`."""
    sm = re.search(rf"type\s+{re.escape(ty)}\s+struct\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        fname, fty = fm.group(1), fm.group(2)
        if name_re.search(fname) and type_pred(fty):
            return fname, fty
    return None


# ---------------------------------------------------------------------------
# Go reentrancy / CEI convert path (guard = cei-order-check).
# ---------------------------------------------------------------------------
#
# The shape: a state-mutating fn takes a `*<State>` param carrying a numeric
# balance-like field AND a callback/hook param (a `func(...)`-typed external-call
# stand-in), and (buggy) WRITES the balance field AFTER invoking the hook - so a
# re-entrant observer (the hook) sees the PRE-effect state. The fixed variant
# moves the balance write BEFORE the hook call (checks-effects-interactions).
# Signature-driven: no `Vault` / `withdraw` / `Balance` symbol is hardcoded.

def _go_hook_param(fn_src: str):
    """Return (param_name, param_type) of the callback/hook param: a name-matched
    param OR a param whose type is a `func(...)` signature, else None."""
    for (name, ty) in _go_named_params(fn_src):
        if _HOOK_PARAM_RE.search(name) or ty.startswith("func"):
            return name, ty
    return None


def _detect_go_reentrancy(target_src: str, fn_src: str):
    """Return (state_param, state_ty, balance_field, hook_param) when the fn
    matches the CEI shape (a `*State` struct w/ a balance field + a callback
    param, and the balance write occurs AFTER the hook call), else None."""
    named = _go_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    state = None  # (param, ty, field)
    for (name, ty) in named:
        if not ty.startswith("*"):
            continue
        bare = ty.lstrip("*")
        bf = _go_struct_field_matching(target_src, bare, _BALANCE_FIELD_RE,
                                       lambda t: t in _GO_NUMERIC_TYPES)
        if bf:
            state = (name, bare, bf[0])
            break
    if state is None:
        return None
    state_param, state_ty, balance_field = state
    hp = _go_hook_param(fn_src)
    if hp is None:
        return None
    hook_param = hp[0]
    if hook_param == state_param:
        return None
    call_m = re.search(rf"\b{re.escape(hook_param)}\s*\(", body)
    write_m = re.search(rf"{re.escape(state_param)}\.{re.escape(balance_field)}\s*"
                        rf"[-+*/]?=", body)
    if not call_m or not write_m:
        return None
    if write_m.start() < call_m.start():
        return None  # already effects-before-interactions (CEI-correct)
    return state_param, state_ty, balance_field, hook_param


def derive_go_fixed_cei(fn_src: str, fn: str, fixed_name: str, state_param: str,
                        balance_field: str, hook_param: str) -> Optional[str]:
    """Move the balance-write statement BEFORE the hook-call statement (CEI
    order) and rename to fixed_name."""
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    head, body = fixed[: brace + 1], fixed[brace + 1:]
    write_stmt_re = re.compile(
        rf"[^\n;{{}}]*{re.escape(state_param)}\.{re.escape(balance_field)}\s*"
        rf"[-+*/]?=\s*[^\n;]*")
    wm = write_stmt_re.search(body)
    if wm is None:
        return None
    write_stmt = wm.group(0).strip()
    hook_stmt_re = re.compile(rf"[^\n;{{}}]*\b{re.escape(hook_param)}\s*\([^\n]*")
    hm = hook_stmt_re.search(body)
    if hm is None:
        return None
    if wm.start() < hm.start():
        return None  # write already precedes the call
    body_wo_write = body[: wm.start()] + body[wm.end():]
    hm2 = hook_stmt_re.search(body_wo_write)
    if hm2 is None:
        return None
    line_start = body_wo_write.rfind("\n", 0, hm2.start()) + 1
    indent_m = re.match(r"[ \t]*", body_wo_write[line_start: hm2.start()])
    indent = indent_m.group(0) if indent_m else "\t"
    reordered = (body_wo_write[: line_start]
                 + indent + write_stmt + "\n"
                 + body_wo_write[line_start:])
    return head + reordered


def _go_pick_amount_param(named, state_param, hook_param) -> Optional[str]:
    """Pick the numeric non-state, non-hook param to drive as the withdraw amount
    (the value deducted from the balance field)."""
    fallback = None
    for (name, ty) in named:
        if name in (state_param, hook_param):
            continue
        if ty in _GO_NUMERIC_TYPES:
            if re.search(r"(amount|amt|value|qty|sum|delta|withdraw|debit)", name, re.I):
                return name
            if fallback is None:
                fallback = name
    return fallback


def _go_cei_state_ctor(target_src: str, state_ty: str, balance_field: str,
                       init_bal: str) -> Optional[str]:
    sm = re.search(rf"type\s+{re.escape(state_ty)}\s+struct\s*\{{([^}}]*)\}}",
                   target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        if name == balance_field:
            fields.append(f"{name}: {init_bal}")
        else:
            fields.append(f"{name}: {_go_field_init(fty, name)}")
    return f"{state_ty}{{{', '.join(fields)}}}"


def _go_hook_func_type(fn_src: str, hook_param: str) -> str:
    """Return the concrete `func(...)` type the hook param carries so the harness
    can build a matching closure literal. Normalizes a name-matched-but-untyped
    hook to `func(uint64)`."""
    for (name, ty) in _go_named_params(fn_src):
        if name == hook_param:
            if ty.startswith("func"):
                return ty
    return "func(uint64)"


def _convert_go_reentrancy(target_file: Path, src: str, fn_src: str, fn: str,
                           vuln_class: str, category: str, inv: Dict[str, Any],
                           ree, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, balance_field, hook_param = ree
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal acceptance/rejection via a returned "
                         "`error`; the reentrancy CEI converter only supports the "
                         "`func(...) error` shape; obligation: hand-author"))
    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed_cei(fn_src, fn, fixed_name, state_param,
                                    balance_field, hook_param)
    if fixed_src is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("could not isolate the balance-write + hook-call statements "
                         "to reorder; obligation: hand-author the CEI fixed variant"))
    pkg = _go_package(src)
    crate = pkg
    init_bal, amt, expected_during = "100", "40", "60"
    state_ctor = _go_cei_state_ctor(src, state_ty, balance_field, init_bal)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        "could not synthesize a constructor for the state type")
    named = _go_named_params(fn_src)
    amount_param = _go_pick_amount_param(named, state_param, hook_param)
    hook_ty = _go_hook_func_type(fn_src, hook_param)
    # Build the ordered drive-call args: state -> &__st, hook -> __hook closure,
    # amount -> AMT, others -> concrete literals.
    arg_slots: List[str] = []
    for (name, ty) in named:
        if name == state_param:
            arg_slots.append("&__st")
        elif name == hook_param:
            arg_slots.append("__hook")
        elif name == amount_param:
            arg_slots.append(amt)
        else:
            arg_slots.append(_go_arg_literal(ty))
    n_rets = _go_return_arity(fn_src)
    call_buggy = _go_reentrancy_drive_body(fn, state_ctor, arg_slots, hook_ty,
                                           balance_field, n_rets)
    call_fixed = _go_reentrancy_drive_body(fixed_name, state_ctor, arg_slots,
                                           hook_ty, balance_field, n_rets)
    harness = _render_go_reentrancy_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=pkg, category=category,
        call_buggy=call_buggy, call_fixed=call_fixed, state_ty=state_ty,
        balance_field=balance_field, expected_during=expected_during)
    sentinel = ('\n\ntype _reeErrAUTO struct{}\n'
                'func (_reeErrAUTO) Error() string { return "reentrancy/CEI '
                'violation: state effect written after the external call" }\n'
                'var errReentrancyAUTO error = _reeErrAUTO{}\n')
    lib = _go_lib(src, fixed_src) + sentinel

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["reentrancy_shape"] = "cei-order-check"
    result["state_param"] = state_param
    result["balance_field"] = f"{state_ty}.{balance_field}"
    result["hook_param"] = hook_param
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_reentrancy_drive_body(fn: str, state_ctor: str, arg_slots: List[str],
                              hook_ty: str, balance_field: str,
                              n_rets: int) -> str:
    """Drive the real fn once; the hook closure records the balance the external
    call OBSERVES. TRUE iff the observed balance already reflects the deduction
    (CEI: effect-before-interaction). On the buggy fn the hook sees the PRE-effect
    balance -> invariant violated -> exploit test FAILs."""
    call = ", ".join(arg_slots)
    cap = _go_err_capture(n_rets, "_")
    return (f"\t__st := {state_ctor}\n"
            f"\tvar __observed int64 = -1\n"
            f"\t__hook := func(seen uint64) {{ __observed = int64(seen) }}\n"
            f"\t{cap} = {fn}({call})\n"
            f"\treturn __observed == {{EXPECTED}}")


def _render_go_reentrancy_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                                  pkg: str, category: str, call_buggy: str,
                                  call_fixed: str, state_ty: str,
                                  balance_field: str, expected_during: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    # the drive-body template leaves {EXPECTED} as a placeholder so the same
    # builder serves both buggy + fixed; fill it here.
    cb = call_buggy.replace("{EXPECTED}", expected_during)
    cf = call_fixed.replace("{EXPECTED}", expected_during)
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, reentrancy/CEI)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed). The state struct
// carries `{state_ty}.{balance_field}`; a re-entrant observer (the hook) invoked
// DURING the call must already see the post-effect balance ({expected_during})
// for the CEI invariant to HOLD.
package {pkg}

import "testing"

func driveReentrancyBuggy_AUTO() bool {{
{cb}
}}

func driveReentrancyFixed_AUTO() bool {{
{cf}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveReentrancyBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} wrote state AFTER the external call (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveReentrancyFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must write the effect before the external call: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Go valid-flag staleness-on-read convert path (guard = valid-flag-check).
# ---------------------------------------------------------------------------
#
# The shape: a read/valuation fn takes a `*<T>` / `<T>` ref whose struct carries a
# numeric value field AND a boolean validity/freshness flag, and (buggy) returns
# the value WITHOUT consulting the flag. The fixed variant injects a `if !<flag>
# { reject }` (positive flag) or `if <flag> { reject }` (negative flag) gate.
# Signature-driven: no `PriceFeed` / `readValue` / `valid` symbol is hardcoded.

def _detect_go_valid_flag(target_src: str, fn_src: str):
    """Return (ref_param, ref_ty, is_ptr, flag_field, flag_polarity) when the fn
    matches the validity-flag read shape, else None."""
    named = _go_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    for (name, ty) in named:
        is_ptr = ty.startswith("*")
        bare = ty.lstrip("*")
        has_value = _go_struct_field_matching(
            target_src, bare, _PRICE_FIELD_RE,
            lambda t: t in _GO_NUMERIC_TYPES)
        if not has_value:
            continue
        flag = _go_struct_field_matching(
            target_src, bare, _VALID_FLAG_POSITIVE_RE, lambda t: t == "bool")
        polarity = "positive"
        if flag is None:
            flag = _go_struct_field_matching(
                target_src, bare, _VALID_FLAG_NEGATIVE_RE, lambda t: t == "bool")
            polarity = "negative"
        if flag is None:
            continue
        # the buggy fn must NOT already consult the flag.
        if re.search(rf"\.{re.escape(flag[0])}\b", body):
            continue
        return name, bare, is_ptr, flag[0], polarity
    return None


def derive_go_fixed_validflag(fn_src: str, fn: str, fixed_name: str,
                              ref_param: str, flag_field: str,
                              polarity: str) -> str:
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    cond = (f"!{ref_param}.{flag_field}" if polarity == "positive"
            else f"{ref_param}.{flag_field}")
    reject_stmt = _go_reject_return(fn_src, "errStalenessAUTO")
    guard_stmt = f"\n\tif {cond} {{ {reject_stmt} }}\n"
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _go_validflag_ctor(target_src: str, ref_ty: str, flag_field: str,
                       flag_lit: str, is_ptr: bool) -> Optional[str]:
    sm = re.search(rf"type\s+{re.escape(ref_ty)}\s+struct\s*\{{([^}}]*)\}}",
                   target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        if name == flag_field:
            fields.append(f"{name}: {flag_lit}")
        else:
            # value fields get a non-zero seed so a returned value is meaningful.
            if _PRICE_FIELD_RE.search(name) and fty in _GO_NUMERIC_TYPES:
                fields.append(f"{name}: 42")
            else:
                fields.append(f"{name}: {_go_field_init(fty, name)}")
    amp = "&" if is_ptr else ""
    return f"{amp}{ref_ty}{{{', '.join(fields)}}}"


def _convert_go_valid_flag(target_file: Path, src: str, fn_src: str, fn: str,
                           vuln_class: str, category: str, inv: Dict[str, Any],
                           vf, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    ref_param, ref_ty, is_ptr, flag_field, polarity = vf
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "valid-flag-check converter only supports the `func(...) "
                         "error` shape; obligation: hand-author the bound check"))
    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed_validflag(fn_src, fn, fixed_name, ref_param,
                                          flag_field, polarity)
    valid_flag_lit = "true" if polarity == "positive" else "false"
    stale_flag_lit = "false" if polarity == "positive" else "true"
    valid_ctor = _go_validflag_ctor(src, ref_ty, flag_field, valid_flag_lit, is_ptr)
    stale_ctor = _go_validflag_ctor(src, ref_ty, flag_field, stale_flag_lit, is_ptr)
    if valid_ctor is None or stale_ctor is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        "could not synthesize a constructor for the read ref type")
    valid_args: List[str] = []
    stale_args: List[str] = []
    for (name, ty) in _go_named_params(fn_src):
        if name == ref_param:
            valid_args.append("__valid")
            stale_args.append("__stale")
        else:
            lit = _go_arg_literal(ty)
            valid_args.append(lit)
            stale_args.append(lit)
    n_rets = _go_return_arity(fn_src)
    call_buggy = _go_validflag_drive_body(fn, valid_ctor, stale_ctor,
                                          valid_args, stale_args, n_rets)
    call_fixed = _go_validflag_drive_body(fixed_name, valid_ctor, stale_ctor,
                                          valid_args, stale_args, n_rets)
    harness = _render_go_validflag_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=_go_package(src),
        category=category, call_buggy=call_buggy, call_fixed=call_fixed,
        ref_ty=ref_ty, flag_field=flag_field)
    sentinel = ('\n\ntype _staleErrAUTO struct{}\n'
                'func (_staleErrAUTO) Error() string { return "staleness violation: '
                'source datum is flagged stale/invalid (the validity flag was not '
                'consulted)" }\n'
                'var errStalenessAUTO error = _staleErrAUTO{}\n')
    lib = _go_lib(src, fixed_src) + sentinel
    pkg = _go_package(src)
    crate = pkg

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["freshness_shape"] = "valid-flag-check"
    result["validity_flag"] = f"{ref_ty}.{flag_field}"
    result["flag_polarity"] = polarity
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_validflag_drive_body(fn: str, valid_ctor: str, stale_ctor: str,
                             valid_args: List[str], stale_args: List[str],
                             n_rets: int) -> str:
    valid_call = ", ".join(valid_args)
    stale_call = ", ".join(stale_args)
    cap_v = _go_err_capture(n_rets, "vErr")
    cap_s = _go_err_capture(n_rets, "sErr")
    return (f"\t__valid := {valid_ctor}\n"
            f"\t__stale := {stale_ctor}\n"
            f"\t{cap_v} := {fn}({valid_call})\n"
            f"\t{cap_s} := {fn}({stale_call})\n"
            f"\treturn vErr == nil && sErr != nil")


def _render_go_validflag_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                                 pkg: str, category: str, call_buggy: str,
                                 call_fixed: str, ref_ty: str,
                                 flag_field: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, valid-flag staleness)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed). The read struct
// carries a `{ref_ty}.{flag_field}` validity flag; a datum flagged stale/invalid
// must be REJECTED for the invariant to HOLD.
package {pkg}

import "testing"

func driveValidFlagBuggy_AUTO() bool {{
{call_buggy}
}}

func driveValidFlagFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveValidFlagBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} read a stale/invalid datum (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveValidFlagFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject the stale/invalid datum: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Go double-mint / double-credit convert path (guard = processed-flag-check).
# ---------------------------------------------------------------------------
#
# The shape: a fn credits/mints/settles a numeric amount onto a `*<State>` struct
# WITHOUT a processed/claimed flag, so a replayed call double-credits. The fixed
# variant injects a `ProcessedAUTO bool` field on the struct + a guard that
# rejects the second call and sets the flag on the first. Signature-driven: no
# `Claim` / `processClaim` / `Credited` symbol is hardcoded.

def _detect_go_double_credit(target_src: str, fn_src: str):
    """Return (state_param, state_ty, credit_field) when the fn matches the
    double-credit shape (a single `*State` struct carrying a creditable numeric
    field that the body WRITES, no pre-existing processed flag consulted)."""
    named = _go_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    for (name, ty) in named:
        if not ty.startswith("*"):
            continue
        bare = ty.lstrip("*")
        credit_field = None
        for (fname, fty) in _go_struct_all_fields(target_src, bare):
            if fty in _GO_NUMERIC_TYPES and _CREDIT_FIELD_RE.search(fname):
                if re.search(rf"{re.escape(name)}\.{re.escape(fname)}\s*[-+*]?=", body):
                    credit_field = fname
                    break
        if credit_field is None:
            continue
        already = _go_struct_field_matching(
            target_src, bare, _PROCESSED_FLAG_RE, lambda t: t == "bool")
        if already and re.search(rf"\.{re.escape(already[0])}\b", body):
            continue
        return name, bare, credit_field
    return None


def derive_go_fixed_processedflag(fn_src: str, fn: str, fixed_name: str,
                                  state_param: str) -> str:
    """Inject the processed-flag guard (using the injected `ProcessedAUTO` field)
    at the top of the body and rename to fixed_name."""
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    reject_stmt = _go_reject_return(fn_src, "errDoubleCreditAUTO")
    guard_stmt = (
        f"\n\tif {state_param}.ProcessedAUTO {{ {reject_stmt} }}\n"
        f"\t{state_param}.ProcessedAUTO = true\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _ensure_go_processed_field(target_src: str, state_ty: str) -> str:
    """Add a `ProcessedAUTO bool` field to the state struct decl if absent."""
    sm = re.search(rf"(type\s+{re.escape(state_ty)}\s+struct\s*\{{)([^}}]*)(\}})",
                   target_src)
    if not sm:
        return target_src
    if "ProcessedAUTO" in sm.group(2):
        return target_src
    inner = sm.group(2).rstrip()
    new_inner = f"{inner}\n\tProcessedAUTO bool\n"
    return target_src[: sm.start(2)] + new_inner + target_src[sm.end(2):]


def _go_double_credit_state_ctor(target_src: str, state_ty: str) -> Optional[str]:
    sm = re.search(rf"type\s+{re.escape(state_ty)}\s+struct\s*\{{([^}}]*)\}}",
                   target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        fields.append(f"{name}: {_go_field_init(fty, name)}")
    return f"&{state_ty}{{{', '.join(fields)}}}"


def _convert_go_double_credit(target_file: Path, src: str, fn_src: str, fn: str,
                              vuln_class: str, category: str, inv: Dict[str, Any],
                              dc, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, credit_field = dc
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "processed-flag-check converter only supports the `func(...) "
                         "error` shape; obligation: hand-author the guard"))
    fixed_name = f"{fn}FixedAUTO"
    amended = _ensure_go_processed_field(src, state_ty)
    fixed_src = derive_go_fixed_processedflag(fn_src, fn, fixed_name, state_param)
    state_ctor = _go_double_credit_state_ctor(amended, state_ty)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        "could not synthesize a constructor for the state type")
    call_args: List[str] = []
    for (name, ty) in _go_named_params(fn_src):
        if name == state_param:
            call_args.append("__st")
        elif ty.startswith("*"):
            call_args.append(f"&{ty.lstrip('*')}{{}}")
        else:
            call_args.append(_go_arg_literal(ty))
    n_rets = _go_return_arity(fn_src)
    call_buggy = _go_double_credit_drive_body(fn, state_ctor, call_args, n_rets)
    call_fixed = _go_double_credit_drive_body(fixed_name, state_ctor, call_args, n_rets)
    harness = _render_go_double_credit_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=_go_package(amended),
        category=category, call_buggy=call_buggy, call_fixed=call_fixed,
        state_ty=state_ty, credit_field=credit_field)
    sentinel = ('\n\ntype _dcErrAUTO struct{}\n'
                'func (_dcErrAUTO) Error() string { return "double-credit violation: '
                'this id was already processed (replay)" }\n'
                'var errDoubleCreditAUTO error = _dcErrAUTO{}\n')
    lib = _go_lib(amended, fixed_src) + sentinel
    pkg = _go_package(amended)
    crate = pkg

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["uniqueness_shape"] = "processed-flag-check"
    result["state_param"] = state_param
    result["credit_field"] = f"{state_ty}.{credit_field}"
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_double_credit_drive_body(fn: str, state_ctor: str,
                                 call_args: List[str], n_rets: int) -> str:
    call = ", ".join(call_args)
    cap1 = _go_err_capture(n_rets, "first")
    cap2 = _go_err_capture(n_rets, "second")
    return (f"\t__st := {state_ctor}\n"
            f"\t{cap1} := {fn}({call})\n"
            f"\t{cap2} := {fn}({call})\n"
            f"\treturn first == nil && second != nil")


def _render_go_double_credit_harness(*, fn: str, fixed_name: str,
                                     inv: Dict[str, Any], pkg: str, category: str,
                                     call_buggy: str, call_fixed: str,
                                     state_ty: str, credit_field: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, double-credit)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed) TWICE on the SAME
// state. The second call (a replay) must be REJECTED for the uniqueness
// invariant to HOLD (a credit applies at most once per id). The fixed variant
// gates on an injected `{state_ty}.ProcessedAUTO` flag; the credit field is
// `{state_ty}.{credit_field}`.
package {pkg}

import "testing"

func driveDoubleCreditBuggy_AUTO() bool {{
{call_buggy}
}}

func driveDoubleCreditFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveDoubleCreditBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} double-credited a replay (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveDoubleCreditFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject the replay: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Go signature-replay / missing-nonce convert path (guard = used-nonce-check).
# ---------------------------------------------------------------------------
#
# The shape: a verify/authorize/execute fn consumes a signature/message param AND
# a `*<State>` struct carrying a nonce/used field, but authorizes WITHOUT marking
# the nonce consumed - so the SAME signed payload replays. The fixed variant
# injects a `if state.<flag> { reject }; state.<flag> = true` guard (bool-flag
# nonce) at the top of the body. Signature-driven: no `verifyPermit` / `Used`
# symbol is hardcoded.

def _detect_go_signature_replay(target_src: str, fn_src: str):
    """Return (state_param, state_ty, sig_param, nonce_field, nonce_kind) when the
    fn matches the signature-replay shape, else None. nonce_kind is 'flag' (bool,
    mechanically convertible: flip-and-reject) or 'counter' (numeric: still a
    missing-guard, we inject a bool sentinel flag alongside)."""
    named = _go_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    # require a signature/message-bearing param. A signature is a value/bytes
    # payload, NOT a `*State` pointer - exclude pointer params so a state pointer
    # whose name happens to match the sig vocabulary (e.g. `ticket`) is not
    # mistaken for the signature.
    sig_param = None
    for (name, ty) in named:
        if ty.startswith("*"):
            continue
        if _SIG_PARAM_RE.search(name):
            sig_param = name
            break
    if sig_param is None:
        return None
    for (name, ty) in named:
        if not ty.startswith("*"):
            continue
        if name == sig_param:
            continue
        bare = ty.lstrip("*")
        # prefer a bool flag nonce.
        flag = _go_struct_field_matching(
            target_src, bare, _NONCE_FLAG_RE, lambda t: t == "bool")
        if flag is not None:
            # buggy fn must NOT already consult the flag.
            if re.search(rf"\.{re.escape(flag[0])}\b", body):
                continue
            return name, bare, sig_param, flag[0], "flag"
        # else a numeric counter nonce that the buggy fn never reads/increments.
        ctr = _go_struct_field_matching(
            target_src, bare, _NONCE_COUNTER_RE, lambda t: t in _GO_NUMERIC_TYPES)
        if ctr is not None:
            if re.search(rf"\.{re.escape(ctr[0])}\b", body):
                continue
            return name, bare, sig_param, ctr[0], "counter"
    return None


def derive_go_fixed_usednonce(fn_src: str, fn: str, fixed_name: str,
                              state_param: str, nonce_field: str,
                              nonce_kind: str) -> str:
    """Inject the used-nonce guard at the top of the body and rename to fixed_name.
    For a bool flag: `if st.<flag> { reject }; st.<flag> = true`. For a numeric
    counter: inject an auxiliary `UsedAUTO bool` flip-and-reject (the counter is
    not consulted by the buggy fn, so the mechanical fix is the boolean used-flag
    sibling the converter adds via _ensure_go_usednonce_field)."""
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    reject_stmt = _go_reject_return(fn_src, "errSigReplayAUTO")
    if nonce_kind == "flag":
        guard_stmt = (
            f"\n\tif {state_param}.{nonce_field} {{ {reject_stmt} }}\n"
            f"\t{state_param}.{nonce_field} = true\n"
        )
    else:
        guard_stmt = (
            f"\n\tif {state_param}.UsedAUTO {{ {reject_stmt} }}\n"
            f"\t{state_param}.UsedAUTO = true\n"
        )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _ensure_go_usednonce_field(target_src: str, state_ty: str) -> str:
    """Add a `UsedAUTO bool` field to the state struct (for the counter sub-shape
    where no bool nonce flag exists)."""
    sm = re.search(rf"(type\s+{re.escape(state_ty)}\s+struct\s*\{{)([^}}]*)(\}})",
                   target_src)
    if not sm:
        return target_src
    if "UsedAUTO" in sm.group(2):
        return target_src
    inner = sm.group(2).rstrip()
    return target_src[: sm.start(2)] + f"{inner}\n\tUsedAUTO bool\n" + target_src[sm.end(2):]


def _go_sigreplay_state_ctor(target_src: str, state_ty: str) -> Optional[str]:
    sm = re.search(rf"type\s+{re.escape(state_ty)}\s+struct\s*\{{([^}}]*)\}}",
                   target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        fields.append(f"{name}: {_go_field_init(fty, name)}")
    return f"&{state_ty}{{{', '.join(fields)}}}"


def _convert_go_signature_replay(target_file: Path, src: str, fn_src: str, fn: str,
                                 vuln_class: str, category: str, inv: Dict[str, Any],
                                 sr, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    state_param, state_ty, sig_param, nonce_field, nonce_kind = sr
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "used-nonce-check converter only supports the `func(...) "
                         "error` shape; obligation: hand-author the nonce guard"))
    fixed_name = f"{fn}FixedAUTO"
    amended = src if nonce_kind == "flag" else _ensure_go_usednonce_field(src, state_ty)
    fixed_src = derive_go_fixed_usednonce(fn_src, fn, fixed_name, state_param,
                                          nonce_field, nonce_kind)
    state_ctor = _go_sigreplay_state_ctor(amended, state_ty)
    if state_ctor is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        "could not synthesize a constructor for the state type")
    call_args: List[str] = []
    for (name, ty) in _go_named_params(fn_src):
        if name == state_param:
            call_args.append("__st")
        elif ty.startswith("*"):
            call_args.append(f"&{ty.lstrip('*')}{{}}")
        else:
            call_args.append(_go_arg_literal(ty))
    n_rets = _go_return_arity(fn_src)
    # same signature/payload replayed: the SAME state, the SAME args -> second call
    # must be rejected for the uniqueness invariant to hold.
    call_buggy = _go_double_credit_drive_body(fn, state_ctor, call_args, n_rets)
    call_fixed = _go_double_credit_drive_body(fixed_name, state_ctor, call_args, n_rets)
    harness = _render_go_signature_replay_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=_go_package(amended),
        category=category, call_buggy=call_buggy, call_fixed=call_fixed,
        state_ty=state_ty, nonce_field=nonce_field if nonce_kind == "flag" else "UsedAUTO",
        sig_param=sig_param)
    sentinel = ('\n\ntype _sigReplayErrAUTO struct{}\n'
                'func (_sigReplayErrAUTO) Error() string { return "signature-replay '
                'violation: this signed authorization was already consumed (nonce not '
                'marked used)" }\n'
                'var errSigReplayAUTO error = _sigReplayErrAUTO{}\n')
    lib = _go_lib(amended, fixed_src) + sentinel
    pkg = _go_package(amended)
    crate = pkg

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["uniqueness_shape"] = "used-nonce-check"
    result["sig_param"] = sig_param
    result["nonce_field"] = f"{state_ty}.{nonce_field}"
    result["nonce_kind"] = nonce_kind
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _render_go_signature_replay_harness(*, fn: str, fixed_name: str,
                                        inv: Dict[str, Any], pkg: str, category: str,
                                        call_buggy: str, call_fixed: str,
                                        state_ty: str, nonce_field: str,
                                        sig_param: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, signature-replay)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed) TWICE with the SAME
// signed payload (`{sig_param}`) on the SAME state. The second call (a replay)
// must be REJECTED for the uniqueness invariant to HOLD (a signed authorization
// is consumable at most once). The fixed variant gates on `{state_ty}.{nonce_field}`.
package {pkg}

import "testing"

func driveSigReplayBuggy_AUTO() bool {{
{call_buggy}
}}

func driveSigReplayFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveSigReplayBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} accepted a replayed signature (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveSigReplayFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject the replayed signature: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Go unchecked-external-call-return convert path (guard = call-return-check).
# ---------------------------------------------------------------------------
#
# The shape: a fn invokes a callback/transfer param returning `bool` (success) or
# `error`, but DISCARDS the result - so a failed external call is treated as
# success. The fixed variant captures the result and rejects when the call signals
# failure. Signature-driven: no `transfer` / `send` symbol is hardcoded.

def _go_param_return_kind(ty: str) -> Optional[str]:
    """For a callback param type `func(...) bool` / `func(...) error`, return
    'bool' or 'error' (the result kind the fn must consult), else None."""
    m = re.search(r"func\s*\([^)]*\)\s*([A-Za-z_]\w*)\s*$", ty)
    if not m:
        # also accept a parenthesised single return `func(...) (bool)`.
        m = re.search(r"func\s*\([^)]*\)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*$", ty)
    if not m:
        return None
    r = m.group(1)
    if r in ("bool", "error"):
        return r
    return None


def _go_named_params_full(fn_src: str) -> List[Tuple[str, str]]:
    """Like _go_named_params but preserves MULTI-TOKEN types (e.g. a func-typed
    param `remit func(uint64) bool` -> ('remit', 'func(uint64) bool')). The
    name is the FIRST top-level token; the type is everything after it. Needed by
    the unchecked-external-call detector where the callback type spans tokens."""
    sig = _go_param_list(fn_src)
    out: List[Tuple[str, str]] = []
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw:
            continue
        m = re.match(r"([A-Za-z_]\w*)\s+(.+)$", raw)
        if not m:
            continue
        out.append((m.group(1), m.group(2).strip()))
    return out


def _detect_go_unchecked_call(fn_src: str):
    """Return (call_param, result_kind) when a callback/transfer param returning
    bool/error is INVOKED in the body but its result is DISCARDED, else None."""
    named = _go_named_params_full(fn_src)
    body = fn_src[fn_src.find("{"):]
    for (name, ty) in named:
        if not (_CALL_PARAM_RE.search(name) and ty.startswith("func")):
            continue
        kind = _go_param_return_kind(ty)
        if kind is None:
            continue
        # the body must INVOKE the param: a bare `name(` call.
        invoke = re.search(rf"(^|[^.\w]){re.escape(name)}\s*\(", body)
        if not invoke:
            continue
        # the result must be DISCARDED: there must be NO assignment-capture of the
        # invocation (`x := name(`, `x = name(`, `if name(`, `return name(`, `_ =
        # name(` all count as a consult of the result; a bare `name(args)` stmt on
        # its own line discards it). We detect the discard by checking the call is
        # NOT preceded on its line by `:=`/`=`/`if `/`return `/`!`/`==`.
        discarded = False
        for cm in re.finditer(rf"(^|[^.\w])({re.escape(name)}\s*\([^\n]*\))", body):
            before = body[max(0, cm.start() - 40): cm.start(2)]
            line_start = before.rfind("\n")
            prefix = before[line_start + 1:]
            if re.search(r"(:=|[^=!<>]=[^=]|\bif\b|\breturn\b|!|==|&&|\|\|)\s*$", prefix):
                continue
            discarded = True
            break
        if discarded:
            return name, kind
    return None


def derive_go_fixed_callcheck(fn_src: str, fn: str, fixed_name: str,
                              call_param: str, result_kind: str) -> str:
    """Replace the FIRST discarded `<call_param>(...)` statement with a checked
    form that captures the result and rejects on failure, and rename to fixed_name."""
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    reject_stmt = _go_reject_return(fn_src, "errCallFailedAUTO")
    if result_kind == "bool":
        check = (lambda call: f"if okAUTO := {call}; !okAUTO {{ {reject_stmt} }}")
    else:
        check = (lambda call: f"if errAUTO := {call}; errAUTO != nil {{ {reject_stmt} }}")
    # replace the first bare invocation statement.
    def _repl(m):
        return m.group(1) + check(m.group(2))
    return re.sub(rf"(^|[^.\w])({re.escape(call_param)}\s*\([^\n]*\))",
                  _repl, fixed, count=1)


def _convert_go_unchecked_call(target_file: Path, src: str, fn_src: str, fn: str,
                               vuln_class: str, category: str, inv: Dict[str, Any],
                               uc, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    call_param, result_kind = uc
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "call-return-check converter only supports the `func(...) "
                         "error` shape; obligation: hand-author the return check"))
    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed_callcheck(fn_src, fn, fixed_name, call_param, result_kind)
    # build a FAILING-call callback literal and a SUCCEEDING-call callback literal.
    fail_cb = ("func() bool { return false }" if result_kind == "bool"
               else "func() error { return errCallFailedAUTO }")
    # the callback param signature may take args; rebuild a closure matching its
    # arity (params ignored). Derive arity from the func type.
    fail_cb = _go_make_cb_literal(fn_src, call_param, result_kind, success=False)
    ok_cb = _go_make_cb_literal(fn_src, call_param, result_kind, success=True)
    fail_args: List[str] = []
    ok_args: List[str] = []
    for (name, ty) in _go_named_params(fn_src):
        if name == call_param:
            fail_args.append("__failCB")
            ok_args.append("__okCB")
        elif ty.startswith("*"):
            fail_args.append(f"&{ty.lstrip('*')}{{}}")
            ok_args.append(f"&{ty.lstrip('*')}{{}}")
        else:
            lit = _go_arg_literal(ty)
            fail_args.append(lit)
            ok_args.append(lit)
    n_rets = _go_return_arity(fn_src)
    call_buggy = _go_uncheckedcall_drive_body(fn, fail_cb, ok_cb, fail_args, ok_args, n_rets)
    call_fixed = _go_uncheckedcall_drive_body(fixed_name, fail_cb, ok_cb, fail_args, ok_args, n_rets)
    harness = _render_go_uncheckedcall_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=_go_package(src),
        category=category, call_buggy=call_buggy, call_fixed=call_fixed,
        call_param=call_param, result_kind=result_kind)
    sentinel = ('\n\ntype _callFailedErrAUTO struct{}\n'
                'func (_callFailedErrAUTO) Error() string { return "unchecked-external-'
                'call violation: the external call failed but its return status was '
                'ignored" }\n'
                'var errCallFailedAUTO error = _callFailedErrAUTO{}\n')
    lib = _go_lib(src, fixed_src) + sentinel
    pkg = _go_package(src)
    crate = pkg

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["external_call_shape"] = "call-return-check"
    result["call_param"] = call_param
    result["result_kind"] = result_kind
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_make_cb_literal(fn_src: str, call_param: str, result_kind: str,
                        success: bool) -> str:
    """Build a closure literal matching the callback param's `func(<params>) <ret>`
    type, returning success/failure. Params are accepted but ignored."""
    ty = dict(_go_named_params_full(fn_src)).get(call_param, "")
    m = re.search(r"func\s*\(([^)]*)\)", ty)
    params_inner = m.group(1).strip() if m else ""
    # name each param `_` to avoid unused-var; preserve types.
    sig_params = ""
    if params_inner:
        parts = [p.strip() for p in _split_top_commas(params_inner) if p.strip()]
        # if params are bare types (`uint64, string`) keep them as-is (valid in a
        # closure literal signature without names).
        sig_params = ", ".join(parts)
    if result_kind == "bool":
        ret_lit = "true" if success else "false"
        return f"func({sig_params}) bool {{ return {ret_lit} }}"
    ret_lit = "nil" if success else "errCallFailedAUTO"
    return f"func({sig_params}) error {{ return {ret_lit} }}"


def _go_uncheckedcall_drive_body(fn: str, fail_cb: str, ok_cb: str,
                                 fail_args: List[str], ok_args: List[str],
                                 n_rets: int) -> str:
    fail_call = ", ".join(fail_args)
    ok_call = ", ".join(ok_args)
    cap_f = _go_err_capture(n_rets, "fErr")
    cap_o = _go_err_capture(n_rets, "oErr")
    return (f"\t__failCB := {fail_cb}\n"
            f"\t__okCB := {ok_cb}\n"
            f"\t{cap_f} := {fn}({fail_call})\n"
            f"\t{cap_o} := {fn}({ok_call})\n"
            f"\treturn oErr == nil && fErr != nil")


def _render_go_uncheckedcall_harness(*, fn: str, fixed_name: str,
                                     inv: Dict[str, Any], pkg: str, category: str,
                                     call_buggy: str, call_fixed: str,
                                     call_param: str, result_kind: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, unchecked-external-call-return)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed) with a FAILING external
// call (`{call_param}` returns {result_kind} failure) and a SUCCEEDING one. When
// the call FAILS the fn must REJECT (return a non-nil error) for the external-call
// invariant to HOLD; the buggy fn ignores the call return and accepts both.
package {pkg}

import "testing"

func driveUncheckedCallBuggy_AUTO() bool {{
{call_buggy}
}}

func driveUncheckedCallFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveUncheckedCallBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} treated a failed external call as success (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveUncheckedCallFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject when the external call fails: {tag}")
\t}}
}}
'''


# ---------------------------------------------------------------------------
# Go missing-deadline / slippage-bound convert path (guard = deadline-bound-check)
# ---------------------------------------------------------------------------
#
# The shape: a swap/fill/exec fn takes a realized numeric param AND a caller-
# supplied bound param (min_out / deadline), but does NOT compare them - executing
# under adverse conditions. The fixed variant injects the bound comparison. The
# guard direction depends on the bound polarity (MIN: realized >= bound; MAX/
# DEADLINE: realized <= bound). Signature-driven: no `swap` / `minOut` symbol is
# hardcoded.

def _detect_go_missing_deadline(fn_src: str):
    """Return (realized_param, bound_param, polarity) when the fn carries a numeric
    realized param + a numeric bound param NOT compared in the body, else None."""
    named = _go_named_params(fn_src)
    body = fn_src[fn_src.find("{"):]
    realized = None
    for (name, ty) in named:
        if _REALIZED_PARAM_RE.search(name) and ty in _GO_NUMERIC_TYPES:
            realized = name
            break
    if realized is None:
        return None
    for (name, ty) in named:
        if name == realized or ty not in _GO_NUMERIC_TYPES:
            continue
        if not _BOUND_PARAM_RE.search(name):
            continue
        polarity = "min" if _BOUND_MIN_RE.search(name) else (
            "max" if _BOUND_MAX_RE.search(name) else "min")
        # the buggy fn must NOT already compare realized against the bound.
        cmp_re = (rf"\b{re.escape(realized)}\b\s*[<>]=?\s*\b{re.escape(name)}\b|"
                  rf"\b{re.escape(name)}\b\s*[<>]=?\s*\b{re.escape(realized)}\b")
        if re.search(cmp_re, body):
            continue
        return realized, name, polarity
    return None


def derive_go_fixed_deadlinecheck(fn_src: str, fn: str, fixed_name: str,
                                  realized: str, bound: str, polarity: str) -> str:
    """Inject the bound check at the top of the body and rename to fixed_name.
    MIN polarity: reject when realized < bound. MAX/DEADLINE: reject when realized
    > bound."""
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    reject_stmt = _go_reject_return(fn_src, "errBoundAUTO")
    cond = (f"{realized} < {bound}" if polarity == "min" else f"{realized} > {bound}")
    guard_stmt = f"\n\tif {cond} {{ {reject_stmt} }}\n"
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _convert_go_missing_deadline(target_file: Path, src: str, fn_src: str, fn: str,
                                 vuln_class: str, category: str, inv: Dict[str, Any],
                                 md, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    realized, bound, polarity = md
    if not _go_returns_error(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "deadline-bound-check converter only supports the `func(...) "
                         "error` shape; obligation: hand-author the bound check"))
    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed_deadlinecheck(fn_src, fn, fixed_name, realized,
                                              bound, polarity)
    # in-bound case (must accept) and out-of-bound case (must reject). For MIN:
    # in-bound = realized(100) >= bound(50); out = realized(10) < bound(50). For
    # MAX/DEADLINE: in-bound = realized(10) <= bound(50); out = realized(100) > 50.
    bound_val = "50"
    if polarity == "min":
        in_realized, out_realized = "100", "10"
    else:
        in_realized, out_realized = "10", "100"
    in_args: List[str] = []
    out_args: List[str] = []
    for (name, ty) in _go_named_params(fn_src):
        if name == realized:
            in_args.append(in_realized)
            out_args.append(out_realized)
        elif name == bound:
            in_args.append(bound_val)
            out_args.append(bound_val)
        elif ty.startswith("*"):
            in_args.append(f"&{ty.lstrip('*')}{{}}")
            out_args.append(f"&{ty.lstrip('*')}{{}}")
        else:
            lit = _go_arg_literal(ty)
            in_args.append(lit)
            out_args.append(lit)
    n_rets = _go_return_arity(fn_src)
    call_buggy = _go_deadline_drive_body(fn, in_args, out_args, n_rets)
    call_fixed = _go_deadline_drive_body(fixed_name, in_args, out_args, n_rets)
    harness = _render_go_deadline_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=_go_package(src),
        category=category, call_buggy=call_buggy, call_fixed=call_fixed,
        realized=realized, bound=bound, polarity=polarity)
    sentinel = ('\n\ntype _boundErrAUTO struct{}\n'
                'func (_boundErrAUTO) Error() string { return "slippage-bound '
                'violation: the realized execution value violates the caller-supplied '
                'min_out/deadline bound" }\n'
                'var errBoundAUTO error = _boundErrAUTO{}\n')
    lib = _go_lib(src, fixed_src) + sentinel
    pkg = _go_package(src)
    crate = pkg

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["slippage_shape"] = "deadline-bound-check"
    result["realized_param"] = realized
    result["bound_param"] = bound
    result["bound_polarity"] = polarity
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_deadline_drive_body(fn: str, in_args: List[str], out_args: List[str],
                            n_rets: int) -> str:
    in_call = ", ".join(in_args)
    out_call = ", ".join(out_args)
    cap_i = _go_err_capture(n_rets, "inErr")
    cap_o = _go_err_capture(n_rets, "outErr")
    return (f"\t{cap_i} := {fn}({in_call})\n"
            f"\t{cap_o} := {fn}({out_call})\n"
            f"\treturn inErr == nil && outErr != nil")


def _render_go_deadline_harness(*, fn: str, fixed_name: str, inv: Dict[str, Any],
                                pkg: str, category: str, call_buggy: str,
                                call_fixed: str, realized: str, bound: str,
                                polarity: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title().replace("-", "")
    rel = ">=" if polarity == "min" else "<="
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, missing-deadline/slippage-bound)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed) with an IN-BOUND case
// (realized {rel} `{bound}` -> must accept) and an OUT-OF-BOUND case (realized
// violates `{bound}` -> must reject). The buggy fn never compares `{realized}`
// against `{bound}`, accepting the adverse execution.
package {pkg}

import "testing"

func driveDeadlineBuggy_AUTO() bool {{
{call_buggy}
}}

func driveDeadlineFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveDeadlineBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} executed an out-of-bound (adverse) value (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveDeadlineFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject the out-of-bound value: {tag}")
\t}}
}}
'''


def convert_go(target_file: Path, fn: str, vuln_class: str, category: str,
               guard: str, inv: Dict[str, Any], out_dir: Optional[Path],
               run: bool) -> Dict[str, Any]:
    src = read_target(target_file)
    fn_src = extract_go_fn(src, fn)
    if fn_src is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        f"function {fn!r} not found in {target_file.name}")
    ok, unresolved = is_go_self_contained(src, fn_src)
    if not ok:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("target fn is not self-contained (references "
                         f"{unresolved or 'external packages'}); obligation: drive the "
                         "real fn inside its own package's `_test.go`"))
    if guard == "sum-check":
        return _convert_go_conservation(target_file, src, fn_src, fn, vuln_class,
                                        category, inv, out_dir, run)
    if guard == "cast-bound-check":
        trunc = _detect_go_truncation(fn_src)
        if trunc is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no wide numeric param flows into a narrowing "
                             "`<T>(param)` conversion in this fn; obligation: "
                             "hand-author the int-truncation invariant + cast-bound-"
                             "check fixed variant"))
        return _convert_go_truncation(target_file, src, fn_src, fn, vuln_class,
                                      category, inv, trunc, out_dir, run)
    if guard == "owner-guard":
        ac = _detect_go_access_control(src, fn_src)
        if ac is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no `*<T>` state param with an identity field + a "
                             "matching caller param (and no existing owner check) "
                             "found; obligation: hand-author the access-control "
                             "invariant + owner-guard fixed variant"))
        return _convert_go_access_control(target_file, src, fn_src, fn, vuln_class,
                                          category, inv, ac, out_dir, run)
    if guard == "cei-order-check":
        ree = _detect_go_reentrancy(src, fn_src)
        if ree is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no callback/hook param invoked BEFORE a `*<State>` "
                             "balance-field write found (no CEI-ordering bug); "
                             "obligation: hand-author the reentrancy invariant + "
                             "CEI reorder"))
        return _convert_go_reentrancy(target_file, src, fn_src, fn, vuln_class,
                                      category, inv, ree, out_dir, run)
    if guard == "valid-flag-check":
        vf = _detect_go_valid_flag(src, fn_src)
        if vf is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no read ref whose struct carries a value field + an "
                             "unconsulted validity/staleness bool flag found; "
                             "obligation: hand-author the valid-flag invariant + gate"))
        return _convert_go_valid_flag(target_file, src, fn_src, fn, vuln_class,
                                      category, inv, vf, out_dir, run)
    if guard == "processed-flag-check":
        dc = _detect_go_double_credit(src, fn_src)
        if dc is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no single `*<State>` param with a written creditable "
                             "numeric field (and no consulted processed flag) found; "
                             "obligation: hand-author the processed-flag invariant"))
        return _convert_go_double_credit(target_file, src, fn_src, fn, vuln_class,
                                         category, inv, dc, out_dir, run)
    if guard == "used-nonce-check":
        sr = _detect_go_signature_replay(src, fn_src)
        if sr is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no signature/message param + `*<State>` nonce/used "
                             "field (unconsulted) found; obligation: hand-author the "
                             "signature-replay invariant + used-nonce guard"))
        return _convert_go_signature_replay(target_file, src, fn_src, fn, vuln_class,
                                            category, inv, sr, out_dir, run)
    if guard == "call-return-check":
        uc = _detect_go_unchecked_call(fn_src)
        if uc is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no callback/transfer param returning bool/error that is "
                             "INVOKED with its result DISCARDED found; obligation: "
                             "hand-author the external-call-return invariant + check"))
        return _convert_go_unchecked_call(target_file, src, fn_src, fn, vuln_class,
                                          category, inv, uc, out_dir, run)
    if guard == "deadline-bound-check":
        md = _detect_go_missing_deadline(fn_src)
        if md is None:
            return _blocked(target_file, fn, vuln_class, "go", inv,
                            ("no numeric realized param + numeric bound param "
                             "(min_out/deadline) that are NOT compared in the body "
                             "found; obligation: hand-author the slippage-bound "
                             "invariant + bound check"))
        return _convert_go_missing_deadline(target_file, src, fn_src, fn, vuln_class,
                                            category, inv, md, out_dir, run)
    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed(fn_src, fn, fixed_name, guard)
    if fixed_src is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("could not mechanically derive a fixed variant (no `*<T>` "
                         "consumable resource param); obligation: hand-author the fix"))
    amended = ensure_go_used_field(src, fn_src)
    pkg = _go_package(amended)
    ctor = _go_resource_ctor(amended, fn_src)
    if ctor is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        "could not synthesize a constructor for the resource type")
    resource_ty, resource_ctor = ctor
    other = _go_other_args(fn_src)
    crate = pkg
    call_buggy = _go_drive_body(fn, resource_ty, resource_ctor, other)
    call_fixed = _go_drive_body(fixed_name, resource_ty, resource_ctor, other)
    harness = render_go_harness(fn=fn, fixed_name=fixed_name, inv=inv, pkg=pkg,
                                resource_ty=resource_ty, resource_ctor=resource_ctor,
                                call_buggy=call_buggy, call_fixed=call_fixed)
    lib = _go_lib(amended, fixed_src)

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


# ---------------------------------------------------------------------------
# Go conservation / normalization convert path (guard = sum-check).
# ---------------------------------------------------------------------------
#
# The conservation family is the dominant Cosmos-SDK economic-validation-omission
# shape (anchor: Quicksilver MsgSignalIntent validator-weight gap). A handler
# takes a slice of weight-bearing structs and consumes it WITHOUT asserting the
# weights conserve (sum == EXPECTED) + positivity. The buggy fn silently accepts
# a non-conserving collection; the fixed variant injects the canonical sum-check.
#
# The synthesis is DRIVEN BY THE SIGNATURE: we find the `[]*T` / `[]T` parameter
# whose element struct carries a numeric weight-like field, then drive the real
# fn with a CONSERVING collection (sum == 100, accepted) and a NON-CONSERVING one
# (sum == 1, rejected). No target symbol names are hardcoded - the weight field
# is matched by the canonical distribution-field-name regex and the element type
# is read from the in-file struct decl.

def _go_slice_param(fn_src: str) -> Optional[Tuple[str, str, bool]]:
    """Return (param_name, element_type, is_ptr_elem) for the FIRST `[]*T` / `[]T`
    parameter, or None. is_ptr_elem True for `[]*T`."""
    sig = _go_param_list(fn_src)
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw:
            continue
        m = re.match(r"([A-Za-z_]\w*)\s+\[\]\s*(\*?)\s*([A-Za-z_]\w*)\s*$", raw)
        if m:
            return m.group(1), m.group(3), bool(m.group(2))
    return None


def _go_struct_weight_field(target_src: str, ty: str) -> Optional[Tuple[str, str]]:
    """Return (field_name, field_type) of the numeric weight-like field on the
    element struct `ty`, or None when no such field exists (the shape is not a
    conservation target -> blocked-with-obligation, never a fabricated fix)."""
    sm = re.search(rf"type\s+{re.escape(ty)}\s+struct\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        fname, fty = fm.group(1), fm.group(2)
        if fty in _GO_NUMERIC_TYPES and _WEIGHT_FIELD_RE.search(fname):
            return fname, fty
    return None


def _go_struct_all_fields(target_src: str, ty: str) -> List[Tuple[str, str]]:
    sm = re.search(rf"type\s+{re.escape(ty)}\s+struct\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return []
    out: List[Tuple[str, str]] = []
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        out.append((fm.group(1), fm.group(2)))
    return out


def _go_elem_literal(target_src: str, ty: str, weight_field: str,
                     weight_val: str, is_ptr: bool) -> str:
    """Build a struct literal for one collection element, setting the weight
    field to weight_val and every other field to a concrete zero/seed value."""
    parts: List[str] = []
    for (fname, fty) in _go_struct_all_fields(target_src, ty):
        if fname == weight_field:
            parts.append(f"{fname}: {weight_val}")
        else:
            parts.append(f"{fname}: {_go_field_init(fty, fname)}")
    amp = "&" if is_ptr else ""
    return f"{amp}{ty}{{{', '.join(parts)}}}"


def derive_go_fixed_sumcheck(fn_src: str, fn: str, fixed_name: str,
                             slice_param: str, weight_field: str,
                             expected_total: str) -> str:
    """Inject the canonical conservation sum-check guard at the top of the body
    and rename to fixed_name. Rejects any collection whose weight field does not
    sum to expected_total, or whose any weight is non-positive."""
    fixed = re.sub(rf"\bfunc(\s+\([^)]*\))?\s+{re.escape(fn)}\b",
                   lambda m: f"func{m.group(1) or ''} {fixed_name}", fn_src, count=1)
    brace = fixed.find("{")
    # The conservation converter is only entered when the fn rejects via a
    # returned `error` (guaranteed by _go_fixed_returns_error_on_reject). The
    # REJECT value must therefore be a NON-nil error sentinel - returning the
    # zero value (`nil`) would mean ACCEPT, inverting the guard. We use a package
    # sentinel `errConservationAUTO` appended to the lib so the reject path is a
    # genuine non-nil error.
    reject_stmt = "return errConservationAUTO"
    guard_stmt = (
        f"\n\t{{\n"
        f"\t\tvar _sum_AUTO int64\n"
        f"\t\tfor _, _it_AUTO := range {slice_param} {{\n"
        f"\t\t\tif int64(_it_AUTO.{weight_field}) <= 0 {{ {reject_stmt} }}\n"
        f"\t\t\t_sum_AUTO += int64(_it_AUTO.{weight_field})\n"
        f"\t\t}}\n"
        f"\t\tif _sum_AUTO != {expected_total} {{ {reject_stmt} }}\n"
        f"\t}}\n"
    )
    return fixed[: brace + 1] + guard_stmt + fixed[brace + 1:]


def _go_fixed_returns_error_on_reject(fn_src: str) -> bool:
    """True iff the fn's return list ends in an `error` - the sum-check fixed
    variant returns a non-nil error sentinel on reject. We only support the
    conservation convert when the fn signals rejection via a returned `error`
    (the dominant Cosmos handler shape `func ... (...) error`); other return
    shapes block-with-obligation."""
    brace = fn_src.find("{")
    sig = fn_src[: brace]
    return bool(re.search(r"\berror\s*\)?\s*$", sig.strip()))


def _go_conservation_drive_body(fn: str, slice_param_ctor_ok: str,
                                slice_param_ctor_bad: str, other: List[str],
                                slice_first: bool) -> str:
    """Drive the real fn with a CONSERVING collection (must be accepted -> nil
    error) and a NON-CONSERVING collection (must be rejected -> non-nil error).
    Returns the body of a `func() bool` that is TRUE iff the conservation
    invariant HOLDS (good accepted AND bad rejected)."""
    pre = (", ".join(other) + ", ") if (other and not slice_first) else ""
    post = (", " + ", ".join(other)) if (other and slice_first) else ""
    if slice_first:
        good_call = f"{fn}({slice_param_ctor_ok}{post})"
        bad_call = f"{fn}({slice_param_ctor_bad}{post})"
    else:
        good_call = f"{fn}({pre}{slice_param_ctor_ok})"
        bad_call = f"{fn}({pre}{slice_param_ctor_bad})"
    return (f"\tgood := {good_call}\n"
            f"\tbad := {bad_call}\n"
            f"\treturn good == nil && bad != nil")


def _convert_go_conservation(target_file: Path, src: str, fn_src: str, fn: str,
                             vuln_class: str, category: str, inv: Dict[str, Any],
                             out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    sp = _go_slice_param(fn_src)
    if sp is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("no `[]T` / `[]*T` collection param found to range a "
                         "conservation invariant over; obligation: hand-author the "
                         "conservation invariant + sum-check fixed variant"))
    slice_param, elem_ty, is_ptr = sp
    wf = _go_struct_weight_field(src, elem_ty)
    if wf is None:
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        (f"element type {elem_ty!r} has no numeric weight/share-like "
                         "field to ground a conservation sum; obligation: hand-author "
                         "the conservation invariant"))
    weight_field, weight_fty = wf
    if not _go_fixed_returns_error_on_reject(fn_src):
        return _blocked(target_file, fn, vuln_class, "go", inv,
                        ("fn does not signal rejection via a returned `error`; the "
                         "conservation sum-check converter only supports the "
                         "`func(...) error` rejection shape; obligation: hand-author"))
    # Determine whether the slice param leads the arg list (slice_first).
    sig = _go_param_list(fn_src)
    first_tok = ""
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if raw:
            first_tok = raw.split()[0]
            break
    slice_first = (first_tok == slice_param)

    expected_total = "100"
    # CONSERVING collection: two items summing to 100, both positive.
    ok_elems = [
        _go_elem_literal(src, elem_ty, weight_field, "60", is_ptr),
        _go_elem_literal(src, elem_ty, weight_field, "40", is_ptr),
    ]
    # NON-CONSERVING collection: sums to 1 (!= 100). On the buggy fn this is
    # accepted (invariant violated); on the fixed fn it is rejected.
    bad_elems = [
        _go_elem_literal(src, elem_ty, weight_field, "1", is_ptr),
    ]
    elem_decl = f"*{elem_ty}" if is_ptr else elem_ty
    ok_ctor = f"[]{elem_decl}{{{', '.join(ok_elems)}}}"
    bad_ctor = f"[]{elem_decl}{{{', '.join(bad_elems)}}}"

    fixed_name = f"{fn}FixedAUTO"
    fixed_src = derive_go_fixed_sumcheck(fn_src, fn, fixed_name, slice_param,
                                         weight_field, expected_total)
    # Other (non-slice) args as concrete literals.
    other = _go_other_args_excluding_slice(fn_src, slice_param)
    pkg = _go_package(src)
    crate = pkg
    call_buggy = _go_conservation_drive_body(fn, ok_ctor, bad_ctor, other, slice_first)
    call_fixed = _go_conservation_drive_body(fixed_name, ok_ctor, bad_ctor, other, slice_first)
    harness = _render_go_conservation_harness(
        fn=fn, fixed_name=fixed_name, inv=inv, pkg=pkg,
        call_buggy=call_buggy, call_fixed=call_fixed, category=category,
        weight_field=weight_field, elem_ty=elem_ty)
    # The fixed variant rejects via a non-nil error sentinel; declare it in the
    # lib (a fresh package-level error value, distinct from any target symbol).
    sentinel = ('\n\ntype _convErrAUTO struct{}\n'
                'func (_convErrAUTO) Error() string { return "conservation violation: '
                'weights do not sum to the configured total or are non-positive" }\n'
                'var errConservationAUTO error = _convErrAUTO{}\n')
    lib = _go_lib(src, fixed_src) + sentinel

    work = _mk_workdir(out_dir, f"go_{fn}")
    (work / "go.mod").write_text(f"module {crate}\n\ngo 1.21\n", encoding="utf-8")
    (work / "target.go").write_text(lib, encoding="utf-8")
    (work / "auditooor_convert_test.go").write_text(harness, encoding="utf-8")

    result = _base_result(target_file, fn, vuln_class, "go", inv)
    result["workdir"] = str(work)
    result["harness_file"] = "auditooor_convert_test.go"
    result["slice_param"] = slice_param
    result["weight_field"] = f"{elem_ty}.{weight_field}"
    result["expected_total"] = expected_total
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    go_bin = shutil.which("go")
    if go_bin is None:
        result["verdict"] = BLOCKED
        result["reason"] = "go not installed; obligation: run `go test` on the scaffold"
        return result
    out, rc = _run([go_bin, "test", "-v", "./..."], work, timeout=300)
    parsed = parse_go_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "go test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    return result


def _go_other_args_excluding_slice(fn_src: str, slice_param: str) -> List[str]:
    """Concrete literals for every NON-slice param (the slice param is supplied
    separately by the conservation driver)."""
    sig = _go_param_list(fn_src)
    args: List[str] = []
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split()
        if len(parts) < 2:
            continue
        name, ty = parts[0], parts[-1]
        if name == slice_param or ty.startswith("[]") or "[]" in raw:
            continue
        if ty.startswith("*"):
            # pointer non-slice param: build a pointed-to zero literal.
            args.append(f"&{ty.lstrip('*')}{{}}")
            continue
        args.append(_go_arg_literal(ty))
    return args


def _render_go_conservation_harness(*, fn: str, fixed_name: str,
                                    inv: Dict[str, Any], pkg: str,
                                    call_buggy: str, call_fixed: str,
                                    category: str, weight_field: str,
                                    elem_ty: str) -> str:
    tag = f"{inv['invariant_id']} [{category}] for {fn}"
    cat_title = category.title()
    return f'''// auditooor-generated engine-auto-convert harness (REAL-fn-driving, conservation)
// Grounded invariant: {inv['invariant_id']} [{category}]
//   {inv['statement']}
// Drives the REAL `{fn}` (buggy) and `{fixed_name}` (fixed). The conservation
// invariant ranges over `{elem_ty}.{weight_field}` (the per-item weight); the
// non-conserving collection (sum != EXPECTED) must be REJECTED for it to HOLD.
package {pkg}

import "testing"

func driveConservationBuggy_AUTO() bool {{
{call_buggy}
}}

func driveConservationFixed_AUTO() bool {{
{call_fixed}
}}

func TestExploit{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveConservationBuggy_AUTO() {{
\t\tt.Errorf("{category} invariant VIOLATED: {fn} accepted a non-conserving collection (bug present): {tag}")
\t}}
}}

func TestNegativeControl{cat_title}{fn}_AUTO(t *testing.T) {{
\tif !driveConservationFixed_AUTO() {{
\t\tt.Errorf("negative control failed: {fixed_name} must reject the non-conserving collection: {tag}")
\t}}
}}
'''


def _go_package(src: str) -> str:
    m = re.search(r"^\s*package\s+([A-Za-z_]\w*)", src, re.MULTILINE)
    return m.group(1) if m else "target"


def _go_lib(target_src: str, fixed_src: str) -> str:
    body = target_src
    if fixed_src not in body:
        body = body.rstrip() + "\n\n" + fixed_src + "\n"
    return body


def _go_resource_ctor(target_src: str, fn_src: str) -> Optional[Tuple[str, str]]:
    m = re.search(r"\*\s*([A-Za-z_]\w*)", fn_src)
    if not m:
        return None
    ty = m.group(1)
    sm = re.search(rf"type\s+{re.escape(ty)}\s+struct\s*\{{([^}}]*)\}}", target_src)
    if not sm:
        return None
    fields = []
    for fm in re.finditer(r"([A-Za-z_]\w*)\s+([A-Za-z_][\w\[\]*]*)", sm.group(1)):
        name, fty = fm.group(1), fm.group(2)
        fields.append(f"{name}: {_go_field_init(fty, name)}")
    return ty, f"&{ty}{{{', '.join(fields)}}}"


def _go_field_init(fty: str, name: str) -> str:
    if name == "Used":
        return "false"
    if re.match(r"^u?int(8|16|32|64)?$", fty) or fty in ("byte", "rune"):
        return "0x1234"
    if fty == "bool":
        return "false"
    if fty == "string":
        return '"x"'
    if fty.startswith("[]"):
        return f"{fty}{{1, 2, 3}}"
    if re.match(r"^float(32|64)$", fty):
        return "1.0"
    return f"{fty}{{}}"


def _go_param_list(fn_src: str) -> str:
    """Return the inner text of the FIRST balanced `(...)` group (the parameter
    list), ignoring the return-type parens that may follow."""
    start = fn_src.find("(")
    if start < 0:
        return ""
    depth = 0
    for j in range(start, len(fn_src)):
        c = fn_src[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return fn_src[start + 1: j]
    return ""


def _go_other_args(fn_src: str) -> List[str]:
    sig = _go_param_list(fn_src)
    args: List[str] = []
    for raw in _split_top_commas(sig):
        raw = raw.strip()
        if not raw or "*" in raw:
            continue
        parts = raw.split()
        if len(parts) < 2:
            continue
        ty = parts[-1]
        args.append(_go_arg_literal(ty))
    return args


def _go_arg_literal(ty: str) -> str:
    if re.match(r"^u?int(8|16|32|64)?$", ty) or ty in ("byte", "rune"):
        return "7"
    if ty == "bool":
        return "false"
    if ty == "string":
        return '"x"'
    if ty.startswith("[]"):
        return f"{ty}{{1, 2, 3}}"
    if re.match(r"^float(32|64)$", ty):
        return "1.0"
    return f"{ty}{{}}"


def _go_drive_body(fn: str, resource_ty: str, resource_ctor: str,
                   other: List[str]) -> str:
    # The resource pointer is the FIRST param in the freshness-flag shape
    # (func Sign(n *Nonce, msg uint64)), so it leads the call; the other args
    # (concrete literals) follow it. Drives the real fn twice on the SAME
    # resource; the second call must be rejected (ok2==false) for the invariant.
    suffix = (", " + ", ".join(other)) if other else ""
    return (f"\tn := {resource_ctor}\n"
            f"\t_, ok1 := {fn}(n{suffix})\n"
            f"\t_, ok2 := {fn}(n{suffix})\n"
            f"\treturn ok1 && !ok2")


# ---------------------------------------------------------------------------
# Result + IO helpers.
# ---------------------------------------------------------------------------

def _base_result(target_file: Path, fn: str, vuln_class: str, language: str,
                 inv: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "target_file": str(target_file),
        "fn": fn,
        "vuln_class": vuln_class,
        "language": language,
        "grounded_invariant": inv["invariant_id"],
        "invariant_category": inv["category"],
        "invariant_grounded_in_corpus": inv["grounded"],
    }


def _blocked(target_file: Path, fn: str, vuln_class: str, language: str,
             inv: Dict[str, Any], obligation: str) -> Dict[str, Any]:
    r = _base_result(target_file, fn, vuln_class, language, inv)
    r["verdict"] = BLOCKED
    r["reason"] = obligation
    r["obligation"] = obligation
    return r


def _mk_workdir(out_dir: Optional[Path], slug: str) -> Path:
    if out_dir is not None:
        d = out_dir / slug
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
        return d
    return Path(tempfile.mkdtemp(prefix=f"eac_{slug}_"))


def _run(cmd: List[str], cwd: Path, timeout: int) -> Tuple[str, int]:
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                           timeout=timeout)
        return (p.stdout + "\n" + p.stderr), p.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", 124
    except Exception as e:  # noqa: BLE001
        return f"RUN-ERROR: {e}", 1


def _tail(out: str, n: int = 60) -> str:
    return "\n".join(out.splitlines()[-n:])


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------

def convert(target_file: Path, fn: str, vuln_class: str, language: str, *,
            repo_root: Path, out_dir: Optional[Path], run: bool) -> Dict[str, Any]:
    mapping = map_vuln_class(vuln_class)
    if mapping is None:
        inv = {"invariant_id": "INV-NONE", "category": "unknown",
               "statement": "", "grounded": False}
        return _blocked(target_file, fn, vuln_class, language, inv,
                        (f"vuln_class {vuln_class!r} is not in the auto-convertible map "
                         f"({sorted(set(VULN_CLASS_MAP))}); obligation: extend the map or "
                         "hand-author the invariant + fixed variant"))
    category, guard = mapping
    inv = pick_invariant(repo_root, category, language)
    if language == "rust":
        result = convert_rust(target_file, fn, vuln_class, category, guard, inv,
                              out_dir, run)
    elif language == "go":
        result = convert_go(target_file, fn, vuln_class, category, guard, inv,
                            out_dir, run)
    else:
        return _blocked(target_file, fn, vuln_class, language, inv,
                        f"language {language!r} not supported (rust|go only)")

    # Anti-fabrication guard (GRSWEEP-2): a proof-backed verdict on a CITED REAL
    # external source must DRIVE THE REAL fn. The rust/go lifters embed the real
    # source via _rust_lib/_go_lib, so a genuine convert passes; but if a future
    # path (or a synthetic-template lift) emits proof-backed without the real fn
    # tokens in the authored lib.rs/target.go, downgrade it. Self-contained
    # fixtures stay proof-backed (the fixture IS the real program).
    if result.get("verdict") in ("proof-backed", "proven", "converted",
                                 "real-fn-convert"):
        fn_src = None
        try:
            src = read_target(target_file)
            fn_src = (extract_rust_fn(src, fn) if language == "rust"
                      else extract_go_fn(src, fn))
        except OSError:
            fn_src = None
        workdir = Path(result["workdir"]) if result.get("workdir") else None
        result = verify_realfn_tokens_or_downgrade(
            result, target_file=target_file, fn=fn, fn_src=fn_src,
            workdir=workdir)
    return result


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--target-file")
    p.add_argument("--fn")
    p.add_argument("--vuln-class")
    p.add_argument("--language", choices=["rust", "go"])
    p.add_argument("--candidate-json")
    p.add_argument("--out-dir")
    p.add_argument("--no-run", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if args.candidate_json:
        cand = json.loads(Path(args.candidate_json).read_text(encoding="utf-8"))
        target_file = cand.get("target_file")
        fn = cand.get("fn")
        vuln_class = cand.get("vuln_class")
        language = cand.get("language")
    else:
        target_file, fn, vuln_class, language = (
            args.target_file, args.fn, args.vuln_class, args.language)

    if not (target_file and fn and vuln_class and language):
        print("need --target-file --fn --vuln-class --language (or --candidate-json)",
              file=sys.stderr)
        return 2
    tf = Path(target_file).expanduser().resolve()
    if not tf.is_file():
        print(f"not a file: {tf}", file=sys.stderr)
        return 2
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else None
    result = convert(tf, fn, vuln_class, language, repo_root=repo_root,
                     out_dir=out_dir, run=not args.no_run)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[engine-auto-convert] {result['verdict']}: {result.get('reason','')}")
        print(f"  target: {result['fn']} ({result['language']}) "
              f"vuln_class={result['vuln_class']}")
        print(f"  grounded-invariant: {result['grounded_invariant']} "
              f"[{result['invariant_category']}] "
              f"(corpus={result['invariant_grounded_in_corpus']})")
        if result.get("workdir"):
            print(f"  workdir: {result['workdir']}")
        if result.get("parsed"):
            pr = result["parsed"]
            print(f"  run: exploit_fail={pr['exploit_fail']} "
                  f"control_pass={pr['control_pass']} compiled={pr['compiled']}")
    return 0 if result["verdict"] == PROOF_BACKED else 1


if __name__ == "__main__":
    raise SystemExit(main())
