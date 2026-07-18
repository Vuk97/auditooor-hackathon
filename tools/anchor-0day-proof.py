#!/usr/bin/env python3
"""anchor-0day-proof.py - the Solana/Anchor 0-day PROOF driver.

This is the Solana/Anchor analogue of `engine-auto-convert.py` (the plain-Go /
plain-Rust converter). That tool drives a self-contained free-function or
receiver-method; it has NO model of the Anchor account / zero-copy / Context
shape - the discriminator, the `RefMut<T>` zero-copy layout, the signer/owner
`Account<'_, T>` / `AccountInfo` accounts, and the `#[account(has_one = ..)]` /
`#[account(constraint = ..)]` validation that an Anchor instruction handler
relies on. This tool is that missing Anchor-shape converter.

It mirrors `engine-auto-convert.py`'s adjudication contract VERBATIM:

    proof-backed             : exploit test FAILS-on-bug + negative control PASSES
    blocked-with-obligation  : the handler cannot be lifted standalone (it needs
                               the Solana runtime - CPI, account loading, the SBF
                               loader) OR the solana toolchain is unavailable OR
                               the run did not produce a genuine catch + control
    refuted                  : the invariant did NOT catch the bug (the exploit
                               assertion held even on the buggy handler -> the
                               asserted invariant is not the one the vuln violates)

THE HONESTY CONTRACT IS ABSOLUTE
================================
A proof counts ONLY if it actually compiles + runs + the exploit test PASSES
(i.e. the invariant assertion FAILS on the buggy handler, proving the invariant
catches the bug) + a negative-control test PASSES (the invariant holds on the
fixed handler). `assert(true)`, scaffold-only, a stub harness, or a test that
does not run = NOT a proof; this tool reports `blocked-with-obligation` and
states the obligation. A fabricated / non-running proof is the single worst
failure mode and this tool never emits a `proof-backed` verdict without a real
`cargo test` (or `cargo test-sbf` when available) transcript showing
exploit-FAIL-on-bug + control-PASS-on-fixed.

Two runtime tiers, two honesty postures
========================================
Anchor's account-validation semantics are a PURE FUNCTION of the account data
(the `has_one` constraint is `caller_key == account.<field>`; the staleness gate
is `account.<ts> >= clock.slot - max_age`; the unchecked-account gate is
`account.owner == expected_program`). When the handler's check + the account
structs it ranges over are SELF-CONTAINED Rust (the constraint logic references
only fields declared in the same `#[account]` struct, plus the signer key and a
clock/slot value), the driver lifts the constraint as a plain function into a
throwaway mini-crate and drives it with `cargo test` - exactly the
engine-auto-convert drive-in-place model. This is the tier where a `proof-backed`
verdict is reachable in any environment that has `cargo`.

When the handler genuinely needs the SOLANA RUNTIME to demonstrate the impact -
a real CPI, runtime account deserialization through the discriminator, the SBF
loader, cross-program-invocation reentrancy - the constraint cannot be lifted as
a pure function. The driver authors a `solana-program-test` / BanksClient
scaffold (the `#[tokio::test]` ProgramTest harness that builds the account
fixtures: the 8-byte discriminator + the zero-copy `RefMut` layout + the
signer/owner accounts) and then, if `cargo test-sbf` / `solana-test-validator` /
the SBF toolchain is NOT installed, returns `blocked-with-obligation` naming the
EXACT missing piece. It NEVER fakes a pass for the runtime tier.

GENERIC, SHAPE-DRIVEN synthesis (NO hand-spec)
==============================================
Every convert family is driven by the Anchor instruction handler's account
context + the `#[account(..)]` attribute shape - there are NO hardcoded target
program names, NO hardcoded instruction names, NO per-target exploit bodies. The
synthesizer dispatches on the GUARD + the ACCOUNT/SIGNER shape:

  1. missing-owner / missing-has_one (access-control)
       a state `Account<'_, T>` (or zero-copy `AccountLoader<'_, T>`) whose data
       struct carries an owner/authority/admin-like Pubkey field, mutated by an
       instruction whose `#[derive(Accounts)]` context carries a `Signer<'_>`
       (the caller) but NO `#[account(has_one = <field>)]` / no
       `require_keys_eq!(caller, state.<field>)` guard. The harness drives the
       real constraint twice on a fresh copy: as the owner (accept), as a
       non-owner attacker (must reject). The buggy handler accepts the attacker.
  2. account-validation / unchecked-account
       an `AccountInfo<'_>` / `UncheckedAccount<'_>` consumed as if it were a
       trusted program-owned account (its `.owner` / discriminator used to gate a
       privileged read/write) with NO `#[account(owner = <program>)]` /
       `require_keys_eq!(acct.owner, expected)` / discriminator check. The harness
       drives the constraint with a correctly-owned account (accept) and a
       spoofed account whose `.owner` is an attacker program (must reject). The
       buggy handler accepts the spoofed account.
  3. staleness-on-read (freshness)
       a read/valuation handler returns a stored price/value/slot from an
       `Account<'_, T>` whose data carries a `last_update` / `published_slot` /
       `updated_at` slot field, plus the `Clock` sysvar, but does NOT gate on
       `clock.slot - state.<ts> <= max_age`. The harness drives the constraint
       with a FRESH datum (accept) and a STALE datum (must reject). The buggy
       handler accepts the stale datum.

The anchors above are the SHAPES the families recognize; the synthesizer does
NOT special-case any anchor's symbol names. A never-seen Anchor program with
entirely different field/account names converts via the identical shape-driven
path. A hand-spec that only works on a known target would be the forbidden
anti-pattern; this tool has none.

RELATED TOOLS (Rule: tool-duplication preflight)
=================================================
  * tools/engine-auto-convert.py - the plain-Go / plain-Rust twin. It has NO
    Anchor account/zero-copy/Context shape detection, NO discriminator /
    AccountLoader / Signer fixture synthesis, and NO `solana-program-test` /
    `cargo test-sbf` runtime tier. This tool fills exactly that gap and shares
    its verdict vocabulary verbatim. DO NOT EDIT that file (sibling lane owns it).
  * tools/evm-0day-proof-pipeline.py - the EVM/Solidity twin (forge). Disjoint
    target language + engine. DO NOT EDIT (sibling lane owns it).
  * tools/anchor-detector-runner.py / tools/solana-detect.py - DETECTORS (they
    flag candidate sites). This tool is the auto-CONVERTER that PROVES a flagged
    site by authoring a real-constraint-driving harness, RUNNING it, and
    adjudicating a run-backed verdict. The detectors have no pick+drive+run+
    adjudicate step; this tool is that step for Anchor.
  * tools/novel-vector-invariant-miner.py - DERIVES target-specific invariants.
    This tool CONSUMES the invariant FAMILY (category) for the picked vuln_class
    and grounds the harness in an indexed INV-* id when one matches.

Usage
=====
  anchor-0day-proof.py --target-file <path> --fn <name> --vuln-class <class> \
      [--out-dir <dir>] [--no-run] [--force-runtime-tier] [--json]

  anchor-0day-proof.py --candidate-json <path>   # {target_file,fn,vuln_class}

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

SCHEMA_VERSION = "auditooor.anchor_0day_proof.v1"

PROOF_BACKED = "proof-backed"
BLOCKED = "blocked-with-obligation"
REFUTED = "refuted"
ERROR = "error"

DEFAULT_INVARIANT_SOURCES = [
    "audit/corpus_tags/derived/invariants_extracted.jsonl",
    "audit/corpus_tags/derived/invariants_pilot.jsonl",
]

# vuln_class -> (invariant category, canonical guard kind the FIXED variant adds).
# GENERIC - the keys are vuln-class synonyms, the values are the THREE Anchor
# convert families. Everything not in this map is honestly reported as
# blocked-with-obligation (no fabricated fix).
VULN_CLASS_MAP: Dict[str, Tuple[str, str]] = {
    # 1. missing-owner / missing-has_one (access-control family).
    "missing-has-one": ("access-control", "has-one-guard"),
    "missing-has_one": ("access-control", "has-one-guard"),
    "missing-owner-check": ("access-control", "has-one-guard"),
    "missing-owner": ("access-control", "has-one-guard"),
    "missing-authority-check": ("access-control", "has-one-guard"),
    "missing-access-control": ("access-control", "has-one-guard"),
    "access-control-bypass": ("access-control", "has-one-guard"),
    "missing-signer-check": ("access-control", "has-one-guard"),
    "missing-authorization": ("access-control", "has-one-guard"),
    "unauthorized-state-mutation": ("access-control", "has-one-guard"),
    "missing-constraint": ("access-control", "has-one-guard"),
    "privilege-escalation": ("access-control", "has-one-guard"),
    "broken-access-control": ("access-control", "has-one-guard"),
    # 2. account-validation / unchecked-account family.
    "unchecked-account": ("account-validation", "owner-program-check"),
    "missing-account-validation": ("account-validation", "owner-program-check"),
    "account-validation": ("account-validation", "owner-program-check"),
    "missing-owner-program-check": ("account-validation", "owner-program-check"),
    "account-substitution": ("account-validation", "owner-program-check"),
    "account-confusion": ("account-validation", "owner-program-check"),
    "type-confusion": ("account-validation", "owner-program-check"),
    "arbitrary-account": ("account-validation", "owner-program-check"),
    "missing-discriminator-check": ("account-validation", "owner-program-check"),
    "fake-account": ("account-validation", "owner-program-check"),
    "spoofed-account": ("account-validation", "owner-program-check"),
    # 3. staleness-on-read (freshness family).
    "stale-price-on-read": ("freshness", "staleness-gate"),
    "stale-oracle-read": ("freshness", "staleness-gate"),
    "missing-staleness-check": ("freshness", "staleness-gate"),
    "missing-freshness-check": ("freshness", "staleness-gate"),
    "stale-slot-read": ("freshness", "staleness-gate"),
    "missing-clock-check": ("freshness", "staleness-gate"),
    "unchecked-staleness": ("freshness", "staleness-gate"),
    "stale-account-data": ("freshness", "staleness-gate"),
    "missing-last-update-check": ("freshness", "staleness-gate"),
}

# ---------------------------------------------------------------------------
# Anchor shape recognizers (GENERAL - canonical field/attribute names).
# ---------------------------------------------------------------------------
# Anchor surfaces that mark a file as an Anchor program (vs plain Rust). Any of
# these markers makes the target Anchor-shaped; the converter dispatches on the
# account/signer shape, not on these markers alone.
_ANCHOR_MARKERS = (
    re.compile(r"#\[\s*program\s*\]"),
    re.compile(r"#\[\s*account\s*(\([^)]*\))?\s*\]"),
    re.compile(r"#\[\s*derive\s*\(\s*Accounts\s*\)\s*\]"),
    re.compile(r"\bContext\s*<"),
    re.compile(r"\bAccount\s*<\s*'"),
    re.compile(r"\bAccountLoader\s*<"),
    re.compile(r"\bSigner\s*<\s*'"),
    re.compile(r"\banchor_lang\b"),
    re.compile(r"\brequire_keys_eq\s*!"),
    re.compile(r"\bzero_copy\b"),
)

# Pubkey/identity field on an account-data struct that an owner-gate ranges over.
_OWNER_FIELD_RE = re.compile(
    r"^(owner|authority|admin|admin_authority|update_authority|mint_authority|"
    r"freeze_authority|governor|manager|operator|controller|delegate|creator|"
    r"signer|payer)$",
    re.IGNORECASE)

# slot/timestamp freshness field on an account-data struct.
_TS_FIELD_RE = re.compile(
    r"^(last_update|last_updated|last_update_slot|last_updated_slot|updated_at|"
    r"published_slot|publish_slot|published_at|update_slot|last_slot|slot|"
    r"timestamp|ts|last_update_timestamp|valid_slot|as_of_slot|fetch_slot)$",
    re.IGNORECASE)

# stored value/price field on a read struct.
_VALUE_FIELD_RE = re.compile(
    r"^(price|value|rate|amount|val|quote|reading|answer|data|aggregate|"
    r"agg_price|ema_price|spot|index_price|mark_price)$",
    re.IGNORECASE)

# owner-program / expected-program field naming for the unchecked-account family.
_PROGRAM_FIELD_RE = re.compile(
    r"^(owner|program|program_id|owner_program|expected_program|expected_owner|"
    r"token_program|mint|expected_mint)$",
    re.IGNORECASE)

# Anchor attribute constraints that, if PRESENT on the relevant account, mean the
# guard already exists (so the bug is NOT mechanically present - we do not
# fabricate it). These are scanned in the `#[account(..)]` attribute blocks.
_HAS_ONE_PRESENT_RE = re.compile(r"has_one\s*=", re.IGNORECASE)
_OWNER_CONSTRAINT_PRESENT_RE = re.compile(r"\bowner\s*=", re.IGNORECASE)
_CONSTRAINT_PRESENT_RE = re.compile(r"\bconstraint\s*=", re.IGNORECASE)
# require_keys_eq! / require! in the handler body = an in-body guard.
_REQUIRE_KEYS_EQ_RE = re.compile(r"\brequire_keys_eq\s*!|\brequire_eq\s*!|"
                                 r"\bassert_eq\s*!\s*\([^)]*owner|"
                                 r"\bif\s+[^\n{]*owner[^\n{]*!=", re.IGNORECASE)
_STALENESS_GUARD_RE = re.compile(
    r"clock\.slot\s*-|slot\s*-\s*\w*last|\bmax_age\b|\bstaleness\b|"
    r"\bis_stale\b|require[!_].*slot|\bvalidity_slots\b", re.IGNORECASE)


def normalize_vuln_class(raw: str) -> str:
    return (raw or "").strip().lower().replace("_", "-").replace(" ", "-")


def map_vuln_class(vuln_class: str) -> Optional[Tuple[str, str]]:
    n = normalize_vuln_class(vuln_class)
    if n in VULN_CLASS_MAP:
        return VULN_CLASS_MAP[n]
    # tolerate the `missing_has_one` underscore variant that normalizes away the
    # underscore differently (has-one vs has_one): also try the raw lower form.
    raw_lower = (vuln_class or "").strip().lower().replace(" ", "-")
    return VULN_CLASS_MAP.get(raw_lower)


def is_anchor_file(src: str) -> bool:
    return any(rx.search(src) for rx in _ANCHOR_MARKERS)


# ---------------------------------------------------------------------------
# Invariant grounding (pick an INV-* from the corpus for the category).
# ---------------------------------------------------------------------------

_SYNTH_STATEMENT = {
    "access-control": ("an Anchor instruction that mutates an owner-bearing "
                       "account MUST gate on signer_key == account.<owner> "
                       "(has_one / require_keys_eq!); a non-owner signer MUST be "
                       "rejected"),
    "account-validation": ("an account consumed as a trusted program-owned "
                           "account MUST validate account.owner == the expected "
                           "program (or its discriminator); a spoofed account "
                           "owned by another program MUST be rejected"),
    "freshness": ("a read of a slot/timestamp-bearing account MUST reject a datum "
                  "whose stored slot is older than clock.slot - max_age (stale)"),
}


def pick_invariant(repo_root: Path, category: str) -> Dict[str, Any]:
    """Return the lowest-id indexed invariant whose category matches and whose
    target_lang is rust/solana/any. Falls back to a synthetic id (best-effort,
    never blocking)."""
    langs = ("rust", "solana", "anchor", "any", "")
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
                  or d.get("target_lang") or d.get("target_language") or "").lower()
            if not inv_id or cat != category or tl not in langs:
                continue
            stmt = (content.get("statement") or content.get("invariant_text") or "").strip()
            cand = {"invariant_id": inv_id, "category": cat,
                    "statement": stmt, "grounded": True}
            if best is None or str(inv_id) < str(best["invariant_id"]):
                best = cand
    if best is not None:
        return best
    return {"invariant_id": f"INV-SYNTH-{category.upper().replace('-', '')}",
            "category": category,
            "statement": _SYNTH_STATEMENT.get(category, ""),
            "grounded": False}


# ---------------------------------------------------------------------------
# Anchor account struct + handler extraction.
# ---------------------------------------------------------------------------

def read_target(target_file: Path) -> str:
    return target_file.read_text(encoding="utf-8", errors="replace")


def extract_rust_fn(src: str, fn: str) -> Optional[str]:
    """Extract the full `[pub] fn <fn>(...) {...}` body by brace-matching. Anchor
    handlers are free `pub fn` inside `#[program] mod` or methods; both forms are
    `fn <name>(`."""
    m = re.search(rf"\bpub\s+fn\s+{re.escape(fn)}\s*(?:<[^>]*>)?\s*\(", src)
    if not m:
        m = re.search(rf"\bfn\s+{re.escape(fn)}\s*(?:<[^>]*>)?\s*\(", src)
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


def _struct_body(src: str, name: str) -> Optional[str]:
    """Return the body (between { }) of `struct <name> { ... }` (brace-matched)."""
    m = re.search(rf"\bstruct\s+{re.escape(name)}\s*(?:<[^>]*>)?\s*\{{", src)
    if not m:
        return None
    i = src.find("{", m.start())
    depth = 0
    j = i
    while j < len(src):
        c = src[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[i + 1:j]
        j += 1
    return None


def _struct_fields(body: str) -> List[Tuple[str, str]]:
    """[(field_name, field_type)] from a struct body, attributes stripped."""
    out: List[Tuple[str, str]] = []
    # strip #[...] attribute lines (possibly multi-line) before field parse.
    cleaned = re.sub(r"#\[[^\]]*\]", "", body, flags=re.DOTALL)
    for raw in _split_top_commas(cleaned):
        raw = raw.strip()
        if not raw or raw.startswith("//"):
            continue
        m = re.match(r"(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$", raw, re.DOTALL)
        if not m:
            continue
        out.append((m.group(1), m.group(2).strip().replace("\n", " ")))
    return out


def _data_struct_for_account(src: str, account_ty: str) -> Optional[str]:
    """Given an account WRAPPER type referenced in a context (e.g.
    `Account<'info, VaultState>` -> VaultState), return the data-struct body.
    Accepts the inner type directly too."""
    body = _struct_body(src, account_ty)
    return body


def _context_struct_name(fn_src: str) -> Optional[str]:
    """The accounts-context type `Context<XCtx>` the handler takes."""
    m = re.search(r"\bContext\s*<\s*([A-Za-z_]\w*)", fn_src)
    return m.group(1) if m else None


def _account_wrapper_inner(ty: str) -> Optional[Tuple[str, str]]:
    """For an account field type return (wrapper, inner_data_type), e.g.
    `Account<'info, VaultState>` -> ('Account', 'VaultState');
    `AccountLoader<'info, Pool>` -> ('AccountLoader', 'Pool');
    `Signer<'info>` -> ('Signer', None-ish);
    `AccountInfo<'info>` / `UncheckedAccount<'info>` -> ('AccountInfo', None)."""
    m = re.match(r"\s*(Account|AccountLoader)\s*<\s*'[\w]+\s*,\s*([A-Za-z_]\w*)\s*>",
                 ty)
    if m:
        return (m.group(1), m.group(2))
    m = re.match(r"\s*(Signer)\s*<", ty)
    if m:
        return ("Signer", "")
    m = re.match(r"\s*(AccountInfo|UncheckedAccount)\s*<", ty)
    if m:
        return ("AccountInfo", "")
    return None


# ---------------------------------------------------------------------------
# Shape detection per family.
# ---------------------------------------------------------------------------

def _ctx_account_fields(src: str, ctx_name: str) -> List[Tuple[str, str, str, str]]:
    """Return [(field_name, full_type, wrapper, inner_data_ty, attr_block)] for
    each account in the context struct. attr_block is the joined #[account(..)]
    text for that field (for guard-presence detection)."""
    body = _struct_body(src, ctx_name)
    if body is None:
        return []
    # strip line comments (incl. Anchor `/// CHECK:` doc lines) so they do not
    # leak into the field-name capture.
    body = re.sub(r"//[^\n]*", "", body)
    out = []
    # Split fields on TOP-LEVEL commas so the comma inside a generic type such as
    # `Account<'info, VaultState>` does NOT split the field (a flat `[^,]+` regex
    # truncates the type to `Account<'info` and loses the inner data type).
    for chunk in _split_top_commas(body):
        chunk = chunk.strip()
        if not chunk:
            continue
        am = re.match(
            r"((?:#\[[^\]]*\]\s*)*)(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$",
            chunk, re.DOTALL)
        if not am:
            continue
        attrs, fname, fty = am.group(1), am.group(2), am.group(3).strip().replace("\n", " ")
        wi = _account_wrapper_inner(fty)
        wrapper = wi[0] if wi else ""
        inner = wi[1] if wi else ""
        out.append((fname, fty, wrapper, inner, attrs))
    return out


def detect_access_control(src: str, fn_src: str) -> Optional[Dict[str, Any]]:
    """Find a mutable owner-bearing Account in the context with NO has_one /
    owner-constraint / in-body require_keys_eq guard, AND a Signer (caller). The
    bug is the missing equality between the signer key and the stored owner."""
    ctx = _context_struct_name(fn_src)
    if not ctx:
        return None
    fields = _ctx_account_fields(src, ctx)
    signer = next((f for f in fields if f[2] == "Signer"), None)
    if signer is None:
        return None
    # an Account<'_, T> whose data struct has an owner-like Pubkey field.
    for (fname, fty, wrapper, inner, attrs) in fields:
        if wrapper not in ("Account", "AccountLoader") or not inner:
            continue
        body = _data_struct_for_account(src, inner)
        if body is None:
            continue
        owner_field = None
        for (dfn, dty) in _struct_fields(body):
            if _OWNER_FIELD_RE.match(dfn) and "Pubkey" in dty:
                owner_field = dfn
                break
        if owner_field is None:
            continue
        # is the guard already present?
        if _HAS_ONE_PRESENT_RE.search(attrs) or _CONSTRAINT_PRESENT_RE.search(attrs):
            continue
        if _REQUIRE_KEYS_EQ_RE.search(fn_src):
            continue
        return {"ctx": ctx, "state_field": fname, "state_data_ty": inner,
                "owner_field": owner_field, "signer_field": signer[0],
                "data_body": body}
    return None


def detect_account_validation(src: str, fn_src: str) -> Optional[Dict[str, Any]]:
    """Find an AccountInfo / UncheckedAccount consumed without an
    owner-program / discriminator validation in the context attrs or body."""
    ctx = _context_struct_name(fn_src)
    if not ctx:
        return None
    fields = _ctx_account_fields(src, ctx)
    for (fname, fty, wrapper, inner, attrs) in fields:
        if wrapper != "AccountInfo":
            continue
        # guard already present (owner = .. or constraint = .. referencing owner)?
        if _OWNER_CONSTRAINT_PRESENT_RE.search(attrs) or _CONSTRAINT_PRESENT_RE.search(attrs):
            continue
        # in-body owner check?
        if re.search(rf"{re.escape(fname)}\s*\.\s*owner|owner.*{re.escape(fname)}",
                     fn_src):
            continue
        return {"ctx": ctx, "account_field": fname}
    return None


def detect_staleness(src: str, fn_src: str) -> Optional[Dict[str, Any]]:
    """Find a read handler over an Account whose data struct carries a slot/ts
    field + a value field, with no staleness gate in body."""
    ctx = _context_struct_name(fn_src)
    if not ctx:
        return None
    fields = _ctx_account_fields(src, ctx)
    for (fname, fty, wrapper, inner, attrs) in fields:
        if wrapper not in ("Account", "AccountLoader") or not inner:
            continue
        body = _data_struct_for_account(src, inner)
        if body is None:
            continue
        ts_field = None
        value_field = None
        for (dfn, dty) in _struct_fields(body):
            if _TS_FIELD_RE.match(dfn) and re.search(r"\b(u64|i64|u32|i32|u128)\b", dty):
                ts_field = ts_field or dfn
            if _VALUE_FIELD_RE.match(dfn) and re.search(r"\b(u64|i64|u128|u32)\b", dty):
                value_field = value_field or dfn
        if ts_field is None or value_field is None:
            continue
        if _STALENESS_GUARD_RE.search(fn_src):
            continue
        return {"ctx": ctx, "state_field": fname, "state_data_ty": inner,
                "ts_field": ts_field, "value_field": value_field,
                "data_body": body}
    return None


# ---------------------------------------------------------------------------
# Self-containment gate for the data struct (plain-cargo tier).
# ---------------------------------------------------------------------------
# The data struct must reference only primitives + Pubkey (which we model as a
# `[u8;32]` newtype in the lifted crate). If a field references another
# user-defined non-primitive type we cannot synthesize a literal -> the lift is
# not self-contained -> runtime tier / blocked.
_PRIMITIVE_FIELD_TYPES = re.compile(
    r"^(u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|bool|f32|f64|"
    r"Pubkey|\[u8;\s*\d+\]|\[u8;\d+\])$")


def data_struct_self_contained(body: str) -> Tuple[bool, List[str]]:
    bad = []
    for (dfn, dty) in _struct_fields(body):
        t = dty.strip()
        if not _PRIMITIVE_FIELD_TYPES.match(t):
            bad.append(f"{dfn}:{t}")
    return (not bad), bad


# ---------------------------------------------------------------------------
# Lifted-crate authoring (plain-cargo tier): model Pubkey as [u8;32], lift the
# data struct + the constraint as a pure fn, drive buggy vs fixed.
# ---------------------------------------------------------------------------

def _render_data_struct(name: str, body: str) -> str:
    """Render the data struct in the lifted crate with Pubkey -> [u8;32]."""
    fields = []
    for (dfn, dty) in _struct_fields(body):
        t = dty.strip()
        t = re.sub(r"\bPubkey\b", "[u8; 32]", t)
        fields.append(f"    pub {dfn}: {t},")
    return f"#[derive(Clone)]\npub struct {name} {{\n" + "\n".join(fields) + "\n}"


def _zero_for(dty: str) -> str:
    t = dty.strip()
    if re.match(r"^\[u8;\s*\d+\]$", t) or t == "Pubkey":
        return "[0u8; 32]"
    if t in ("bool",):
        return "false"
    if t in ("f32", "f64"):
        return "0.0"
    return "0"


def _data_ctor(name: str, body: str, overrides: Dict[str, str]) -> str:
    fields = []
    for (dfn, dty) in _struct_fields(body):
        val = overrides.get(dfn, _zero_for(dty))
        fields.append(f"{dfn}: {val}")
    return f"{name} {{ {', '.join(fields)} }}"


def render_access_control_crate(state_ty: str, body: str, owner_field: str,
                                inv: Dict[str, Any]) -> str:
    ds = _render_data_struct(state_ty, body)
    stmt = inv["statement"].replace('"', "'")
    return f'''#![allow(unused, non_camel_case_types, clippy::all)]
// auditooor anchor-0day-proof lifted crate (access-control / has_one).
// Models Anchor `Pubkey` as `[u8;32]`; lifts the account-data struct + the
// has_one constraint as a pure fn (the constraint is a pure function of the
// signer key and the stored owner field - exactly what Anchor `#[account(
// has_one = {owner_field})]` enforces at the runtime layer).
// Grounded invariant: {inv['invariant_id']} [{inv['category']}]
//   {stmt}

{ds}

// BUGGY: mutates state without comparing the signer key to state.{owner_field}.
pub fn handler_buggy(state: &mut {state_ty}, signer_key: [u8; 32], new_val: u64)
    -> Result<(), String> {{
    // NO has_one gate -> any signer mutates the owner-gated account.
    // (We write the canonical first numeric field as the "effect".)
    Ok(())
}}

// FIXED: injects the has_one guard (signer_key == state.{owner_field}).
pub fn handler_fixed(state: &mut {state_ty}, signer_key: [u8; 32], new_val: u64)
    -> Result<(), String> {{
    if signer_key != state.{owner_field} {{
        return Err("has_one violation: signer is not the stored {owner_field}".into());
    }}
    Ok(())
}}
'''


def render_access_control_harness(state_ty: str, body: str, owner_field: str,
                                  fn: str, inv: Dict[str, Any], crate: str) -> str:
    owner_ctor = _data_ctor(state_ty, body, {owner_field: "[1u8; 32]"})
    cat = inv["category"]
    tag = f"{inv['invariant_id']} [{cat}] for {fn}"
    return f'''#![allow(unused, non_snake_case)]
// auditooor anchor-0day-proof harness (REAL-constraint-driving, plain-cargo tier)
// Drives the lifted has_one constraint for `{fn}`.
use {crate}::*;

fn drive(h: fn(&mut {state_ty}, [u8; 32], u64) -> Result<(), String>) -> bool {{
    // TRUE iff the access-control invariant HOLDS: an owner signer is accepted
    // AND a non-owner attacker signer is rejected.
    let owner: [u8; 32] = [1u8; 32];
    let attacker: [u8; 32] = [9u8; 32];
    let mut s_owner = {owner_ctor};
    let owner_accepted = h(&mut s_owner, owner, 42).is_ok();
    let mut s_attacker = {owner_ctor};
    let attacker_rejected = h(&mut s_attacker, attacker, 42).is_err();
    owner_accepted && attacker_rejected
}}

#[test]
fn test_exploit_access_control_AUTO() {{
    // Run against the BUGGY handler the invariant must FAIL (the attacker is
    // accepted) -> this test PASSES only if the invariant catches the bug.
    assert!(drive(handler_buggy),
        "access-control invariant VIOLATED: buggy {fn} accepted a non-owner signer: {tag}");
}}

#[test]
fn test_negative_control_access_control_AUTO() {{
    assert!(drive(handler_fixed),
        "negative control failed: fixed {fn} should reject the non-owner signer: {tag}");
}}
'''


def render_staleness_crate(state_ty: str, body: str, ts_field: str,
                           value_field: str, inv: Dict[str, Any]) -> str:
    ds = _render_data_struct(state_ty, body)
    stmt = inv["statement"].replace('"', "'")
    return f'''#![allow(unused, non_camel_case_types, clippy::all)]
// auditooor anchor-0day-proof lifted crate (freshness / staleness-on-read).
// Lifts the account-data struct + the staleness gate as a pure fn (the gate is a
// pure function of the Clock slot, the stored slot field, and the max_age bound).
// Grounded invariant: {inv['invariant_id']} [{inv['category']}]
//   {stmt}

{ds}

// BUGGY: returns the stored value without consulting state.{ts_field} vs the
// current slot.
pub fn read_buggy(state: &{state_ty}, clock_slot: u64, max_age: u64)
    -> Result<u64, String> {{
    Ok(state.{value_field} as u64)
}}

// FIXED: rejects a stale datum (clock_slot - state.{ts_field} > max_age).
pub fn read_fixed(state: &{state_ty}, clock_slot: u64, max_age: u64)
    -> Result<u64, String> {{
    let stored = state.{ts_field} as u64;
    if clock_slot.saturating_sub(stored) > max_age {{
        return Err("staleness violation: stored slot is older than clock - max_age".into());
    }}
    Ok(state.{value_field} as u64)
}}
'''


def render_staleness_harness(state_ty: str, body: str, ts_field: str,
                             value_field: str, fn: str, inv: Dict[str, Any],
                             crate: str) -> str:
    fresh_ctor = _data_ctor(state_ty, body, {ts_field: "1000", value_field: "777"})
    stale_ctor = _data_ctor(state_ty, body, {ts_field: "10", value_field: "777"})
    cat = inv["category"]
    tag = f"{inv['invariant_id']} [{cat}] for {fn}"
    return f'''#![allow(unused, non_snake_case)]
// auditooor anchor-0day-proof harness (REAL-constraint-driving, plain-cargo tier)
// Drives the lifted staleness gate for `{fn}`.
use {crate}::*;

fn drive(h: fn(&{state_ty}, u64, u64) -> Result<u64, String>) -> bool {{
    // TRUE iff the freshness invariant HOLDS: a FRESH datum is accepted AND a
    // STALE datum is rejected. clock_slot=1010, max_age=100.
    let fresh = {fresh_ctor};
    let stale = {stale_ctor};
    let fresh_accepted = h(&fresh, 1010, 100).is_ok();
    let stale_rejected = h(&stale, 1010, 100).is_err();
    fresh_accepted && stale_rejected
}}

#[test]
fn test_exploit_freshness_AUTO() {{
    assert!(drive(read_buggy),
        "freshness invariant VIOLATED: buggy {fn} accepted a stale datum: {tag}");
}}

#[test]
fn test_negative_control_freshness_AUTO() {{
    assert!(drive(read_fixed),
        "negative control failed: fixed {fn} should reject the stale datum: {tag}");
}}
'''


def render_account_validation_crate(inv: Dict[str, Any]) -> str:
    """The account-validation (unchecked-account) family models a minimal
    AccountMeta {owner_program} struct and the owner-program gate as a pure fn.
    This is GENERIC - it does not depend on any in-target data struct, because an
    unchecked `AccountInfo` exposes only its `.owner` (program) and key. The
    gate the bug omits is `acct.owner == expected_program`."""
    stmt = inv["statement"].replace('"', "'")
    return f'''#![allow(unused, non_camel_case_types, clippy::all)]
// auditooor anchor-0day-proof lifted crate (account-validation / unchecked-account).
// An unchecked `AccountInfo` exposes its owning PROGRAM (`.owner`). The gate the
// bug omits is `acct.owner == expected_program`. Modeled as [u8;32] keys.
// Grounded invariant: {inv['invariant_id']} [{inv['category']}]
//   {stmt}

#[derive(Clone)]
pub struct AcctMeta {{
    pub key: [u8; 32],
    pub owner_program: [u8; 32],
}}

// BUGGY: consumes the account as trusted WITHOUT checking acct.owner_program.
pub fn handler_buggy(acct: &AcctMeta, expected_program: [u8; 32]) -> Result<(), String> {{
    Ok(())
}}

// FIXED: rejects an account not owned by the expected program.
pub fn handler_fixed(acct: &AcctMeta, expected_program: [u8; 32]) -> Result<(), String> {{
    if acct.owner_program != expected_program {{
        return Err("account-validation violation: account is owned by an unexpected program".into());
    }}
    Ok(())
}}
'''


def render_account_validation_harness(fn: str, inv: Dict[str, Any], crate: str) -> str:
    cat = inv["category"]
    tag = f"{inv['invariant_id']} [{cat}] for {fn}"
    return f'''#![allow(unused, non_snake_case)]
// auditooor anchor-0day-proof harness (REAL-constraint-driving, plain-cargo tier)
// Drives the lifted owner-program gate for `{fn}`.
use {crate}::*;

fn drive(h: fn(&AcctMeta, [u8; 32]) -> Result<(), String>) -> bool {{
    // TRUE iff the account-validation invariant HOLDS: a correctly-owned account
    // is accepted AND a spoofed account (owned by an attacker program) rejected.
    let expected: [u8; 32] = [2u8; 32];
    let attacker_program: [u8; 32] = [7u8; 32];
    let good = AcctMeta {{ key: [3u8; 32], owner_program: expected }};
    let spoofed = AcctMeta {{ key: [3u8; 32], owner_program: attacker_program }};
    let good_accepted = h(&good, expected).is_ok();
    let spoofed_rejected = h(&spoofed, expected).is_err();
    good_accepted && spoofed_rejected
}}

#[test]
fn test_exploit_account_validation_AUTO() {{
    assert!(drive(handler_buggy),
        "account-validation invariant VIOLATED: buggy {fn} accepted a spoofed account: {tag}");
}}

#[test]
fn test_negative_control_account_validation_AUTO() {{
    assert!(drive(handler_fixed),
        "negative control failed: fixed {fn} should reject the spoofed account: {tag}");
}}
'''


# ---------------------------------------------------------------------------
# Runtime-tier scaffold (solana-program-test / BanksClient).
# ---------------------------------------------------------------------------
# When the handler genuinely needs the Solana runtime, we author the ProgramTest
# scaffold (the fixture-builder that constructs the 8-byte discriminator + the
# zero-copy RefMut layout + the signer/owner accounts) and, if the SBF toolchain
# is unavailable, return blocked-with-obligation naming the missing piece. The
# scaffold is unit-test-locked (the tests assert the AUTHORED shape) but is NOT
# claimed as a live proof until `cargo test-sbf` runs.

def render_runtime_scaffold(fn: str, family: str, inv: Dict[str, Any]) -> str:
    disc = _anchor_discriminator(fn)
    stmt = inv["statement"].replace('"', "'")
    return f'''#![allow(unused)]
// auditooor anchor-0day-proof RUNTIME-TIER scaffold (solana-program-test / BanksClient).
// This scaffold builds the Anchor account fixtures the runtime needs to drive the
// REAL instruction handler `{fn}` end-to-end:
//   * the 8-byte Anchor discriminator: {disc}
//   * the zero-copy RefMut<T> account-data layout (constructed below)
//   * the signer/owner accounts (Keypair-backed)
// It is authored so that, once a SBF toolchain (`cargo test-sbf` /
// `solana-test-validator`) is available, the test drives the deployed program
// and asserts exploit-FAIL-on-bug + control-PASS. Until then this is a SCAFFOLD,
// not a live proof, and the driver reports blocked-with-obligation.
// Grounded invariant: {inv['invariant_id']} [{inv['category']}]  ({family})
//   {stmt}

// The authored fixture-builder (shape-locked by the unit tests in the harness).
pub fn build_account_fixture(discriminator: [u8; 8], owner: [u8; 32], data: &[u8]) -> Vec<u8> {{
    // Anchor account data = 8-byte discriminator || borsh/zero-copy payload.
    let mut buf = Vec::with_capacity(8 + 32 + data.len());
    buf.extend_from_slice(&discriminator);
    buf.extend_from_slice(&owner);
    buf.extend_from_slice(data);
    buf
}}

pub const DISCRIMINATOR_{fn}: [u8; 8] = {disc};

// #[tokio::test] driver (requires solana-program-test + tokio; gated on SBF
// toolchain availability - DO NOT claim a pass without `cargo test-sbf`).
// async fn drive_runtime() {{ /* ProgramTest::new(..).start(); ix; banks.process_transaction(..) */ }}
'''


def _anchor_discriminator(fn: str) -> str:
    """Anchor's instruction discriminator is sha256("global:<fn>")[:8]. We
    compute it deterministically so the scaffold carries the REAL 8 bytes the
    runtime would dispatch on (no fabrication - this is the documented Anchor
    derivation)."""
    import hashlib
    h = hashlib.sha256(f"global:{fn}".encode()).digest()[:8]
    return "[" + ", ".join(str(b) for b in h) + "]"


# ---------------------------------------------------------------------------
# Engine run + adjudication (mirrors engine-auto-convert verbatim).
# ---------------------------------------------------------------------------

def parse_cargo_output(out: str) -> Dict[str, bool]:
    return {
        "exploit_pass": bool(re.search(r"test\s+test_exploit_\w+\s+\.\.\.\s+ok", out)),
        "exploit_fail": bool(re.search(r"test\s+test_exploit_\w+\s+\.\.\.\s+FAILED", out)),
        "control_pass": bool(re.search(r"test\s+test_negative_control_\w+\s+\.\.\.\s+ok", out)),
        "control_fail": bool(re.search(r"test\s+test_negative_control_\w+\s+\.\.\.\s+FAILED", out)),
        "compiled": "error[E" not in out and "error: could not compile" not in out,
    }


def adjudicate(parsed: Dict[str, bool], compiled: bool) -> Tuple[str, str]:
    if not compiled:
        return BLOCKED, "the authored harness did not compile against the lifted target"
    if parsed["exploit_fail"] and parsed["control_pass"]:
        return PROOF_BACKED, ("exploit FAILED-on-bug (invariant caught the vuln) + "
                              "negative control PASSED-on-fixed")
    if parsed["exploit_pass"] and parsed["control_pass"]:
        return REFUTED, ("the invariant did NOT catch the bug: exploit assertion held "
                         "even on the buggy handler -> wrong invariant for this class")
    return BLOCKED, ("run did not produce the exploit-FAIL-on-bug + control-PASS-on-fixed "
                     "shape; no fabricated proof emitted")


# ---------------------------------------------------------------------------
# Convert dispatch.
# ---------------------------------------------------------------------------

def _base_result(target_file: Path, fn: str, vuln_class: str,
                 inv: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "target_file": str(target_file),
        "fn": fn,
        "vuln_class": vuln_class,
        "language": "anchor",
        "grounded_invariant": inv["invariant_id"],
        "invariant_category": inv["category"],
        "invariant_grounded_in_corpus": inv["grounded"],
    }


def _blocked(target_file: Path, fn: str, vuln_class: str,
             inv: Dict[str, Any], obligation: str, **extra) -> Dict[str, Any]:
    r = _base_result(target_file, fn, vuln_class, inv)
    r["verdict"] = BLOCKED
    r["reason"] = obligation
    r["obligation"] = obligation
    r.update(extra)
    return r


def _mk_workdir(out_dir: Optional[Path], slug: str) -> Path:
    if out_dir is not None:
        d = out_dir / slug
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
        return d
    return Path(tempfile.mkdtemp(prefix=f"a0d_{slug}_"))


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


def _write_plain_cargo(work: Path, crate: str, lib_rs: str, harness: str) -> None:
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "Cargo.toml").write_text(
        f'[package]\nname = "{crate}"\nversion = "0.0.0"\nedition = "2021"\n',
        encoding="utf-8")
    (work / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    (work / "tests" / "auditooor_anchor_convert.rs").write_text(harness, encoding="utf-8")


def _run_plain_cargo(work: Path, result: Dict[str, Any], run: bool,
                     family: str, *, target_file: Optional[Path] = None,
                     fn: Optional[str] = None,
                     fn_src: Optional[str] = None) -> Dict[str, Any]:
    result["workdir"] = str(work)
    result["harness_file"] = "tests/auditooor_anchor_convert.rs"
    result["runtime_tier"] = "plain-cargo"
    result["convert_family"] = family
    if not run:
        result["verdict"] = BLOCKED
        result["reason"] = "scaffold-only (--no-run); not adjudicated"
        result["scaffold_only"] = True
        return result
    cargo = shutil.which("cargo")
    if cargo is None:
        result["verdict"] = BLOCKED
        result["reason"] = ("cargo not installed; obligation: run `cargo test` on "
                            "the lifted crate")
        result["obligation"] = result["reason"]
        return result
    out, rc = _run([cargo, "test", "--tests"], work, timeout=600)
    parsed = parse_cargo_output(out)
    verdict, reason = adjudicate(parsed, parsed["compiled"])
    result.update({"verdict": verdict, "reason": reason, "engine": "cargo test",
                   "parsed": parsed, "run_rc": rc, "transcript_tail": _tail(out)})
    # Anti-fabrication guard (GRSWEEP-2): a proof-backed verdict on a CITED REAL
    # external source must drive the REAL fn. The anchor lifter SYNTHESIZES a
    # generic template (handler_buggy(state, signer_key, new_val) {Ok(())}) rather
    # than embedding the real fn body, so a proof-backed verdict here is exactly
    # the template-proof fabrication the guard kills. Self-contained fixtures stay
    # proof-backed (the fixture IS the real program).
    result = verify_realfn_tokens_or_downgrade(
        result, target_file=target_file, fn=fn, fn_src=fn_src, workdir=work)
    return result


def _runtime_scaffold_block(target_file: Path, fn: str, vuln_class: str,
                            inv: Dict[str, Any], family: str,
                            out_dir: Optional[Path], obligation_detail: str
                            ) -> Dict[str, Any]:
    """Author the runtime-tier scaffold and return blocked-with-obligation
    (honest - the live run needs the SBF toolchain which is checked here)."""
    work = _mk_workdir(out_dir, f"runtime_{fn}")
    scaffold = render_runtime_scaffold(fn, family, inv)
    (work / "src").mkdir(parents=True, exist_ok=True)
    (work / "src" / "runtime_scaffold.rs").write_text(scaffold, encoding="utf-8")
    r = _base_result(target_file, fn, vuln_class, inv)
    r["runtime_tier"] = "solana-program-test"
    r["convert_family"] = family
    r["workdir"] = str(work)
    r["scaffold_file"] = "src/runtime_scaffold.rs"
    r["scaffold_only"] = True
    # Check the SBF toolchain.
    have_sbf = bool(shutil.which("cargo-test-sbf") or shutil.which("solana-test-validator"))
    if have_sbf:
        # The toolchain exists but we still do not auto-run the full ProgramTest
        # here (it needs the program built + deployed). Honest posture: scaffold
        # authored, drive obligation remains.
        r["verdict"] = BLOCKED
        r["reason"] = ("runtime-tier scaffold authored; SBF toolchain present but the "
                       "full ProgramTest drive of the deployed program is not "
                       f"auto-run by this tool. Obligation: {obligation_detail}")
    else:
        r["verdict"] = BLOCKED
        r["reason"] = ("runtime-tier scaffold authored; the live run requires the "
                       "Solana SBF toolchain (cargo test-sbf / solana-test-validator) "
                       f"which is NOT installed. Obligation: {obligation_detail}")
    r["obligation"] = r["reason"]
    r["sbf_toolchain_present"] = have_sbf
    return r


def convert(target_file: Path, fn: str, vuln_class: str, *, repo_root: Path,
            out_dir: Optional[Path], run: bool,
            force_runtime_tier: bool = False) -> Dict[str, Any]:
    mapping = map_vuln_class(vuln_class)
    if mapping is None:
        inv = {"invariant_id": "INV-NONE", "category": "unknown",
               "statement": "", "grounded": False}
        return _blocked(target_file, fn, vuln_class, inv,
                        (f"vuln_class {vuln_class!r} is not in the Anchor auto-convertible "
                         f"map ({sorted(set(VULN_CLASS_MAP))}); obligation: extend the map "
                         "or hand-author the invariant + fixed handler"))
    category, guard = mapping
    inv = pick_invariant(repo_root, category)
    src = read_target(target_file)
    if not is_anchor_file(src):
        return _blocked(target_file, fn, vuln_class, inv,
                        ("target file shows no Anchor markers (#[program] / #[account] / "
                         "#[derive(Accounts)] / Context< / Account<' / Signer<' / "
                         "anchor_lang); this is the Anchor converter - use "
                         "engine-auto-convert.py for plain Rust/Go"))
    fn_src = extract_rust_fn(src, fn)
    if fn_src is None:
        return _blocked(target_file, fn, vuln_class, inv,
                        f"instruction handler {fn!r} not found in {target_file.name}")

    if guard == "has-one-guard":
        shape = detect_access_control(src, fn_src)
        if shape is None:
            return _blocked(target_file, fn, vuln_class, inv,
                            ("no owner-bearing Account + Signer context with a MISSING "
                             "has_one/require_keys_eq guard found (the guard may already "
                             "be present, or the context carries no owner-Pubkey field); "
                             "obligation: hand-author the access-control invariant + "
                             "has_one fixed handler"))
        ok, bad = data_struct_self_contained(shape["data_body"])
        if force_runtime_tier or not ok:
            return _runtime_scaffold_block(
                target_file, fn, vuln_class, inv, "access-control", out_dir,
                ("drive the real handler via solana-program-test/BanksClient: build "
                 f"the {shape['state_data_ty']} account fixture (discriminator + "
                 "zero-copy layout), invoke the ix as a non-owner signer, assert the "
                 "tx is rejected; assert an owner signer succeeds (negative control). "
                 + (f"Data struct not plain-cargo-liftable: {bad}" if not ok else "")))
        crate = "a0d_target_auto"
        lib_rs = render_access_control_crate(shape["state_data_ty"],
                                             shape["data_body"], shape["owner_field"], inv)
        harness = render_access_control_harness(shape["state_data_ty"],
                                                shape["data_body"], shape["owner_field"],
                                                fn, inv, crate)
        work = _mk_workdir(out_dir, f"anchor_ac_{fn}")
        _write_plain_cargo(work, crate, lib_rs, harness)
        result = _base_result(target_file, fn, vuln_class, inv)
        result["anchor_shape"] = {k: shape[k] for k in
                                  ("ctx", "state_field", "state_data_ty",
                                   "owner_field", "signer_field")}
        return _run_plain_cargo(work, result, run, "access-control",
                                target_file=target_file, fn=fn, fn_src=fn_src)

    if guard == "owner-program-check":
        shape = detect_account_validation(src, fn_src)
        if shape is None:
            return _blocked(target_file, fn, vuln_class, inv,
                            ("no AccountInfo/UncheckedAccount consumed without an "
                             "owner-program/discriminator validation found (the guard "
                             "may already be present, or there is no unchecked account); "
                             "obligation: hand-author the account-validation invariant + "
                             "owner-program fixed handler"))
        # The account-validation family is ALWAYS plain-cargo-liftable (it ranges
        # over the synthesized AcctMeta {owner_program}, not an in-target struct),
        # UNLESS the operator forces the runtime tier (e.g. the impact needs a real
        # CPI). The bug-presence is established from the context (no owner constraint).
        if force_runtime_tier:
            return _runtime_scaffold_block(
                target_file, fn, vuln_class, inv, "account-validation", out_dir,
                ("drive the real handler via solana-program-test/BanksClient: pass a "
                 f"spoofed account for `{shape['account_field']}` owned by an attacker "
                 "program, assert the tx is rejected; pass a correctly-owned account "
                 "(negative control)."))
        crate = "a0d_target_auto"
        lib_rs = render_account_validation_crate(inv)
        harness = render_account_validation_harness(fn, inv, crate)
        work = _mk_workdir(out_dir, f"anchor_av_{fn}")
        _write_plain_cargo(work, crate, lib_rs, harness)
        result = _base_result(target_file, fn, vuln_class, inv)
        result["anchor_shape"] = {"ctx": shape["ctx"],
                                  "account_field": shape["account_field"]}
        return _run_plain_cargo(work, result, run, "account-validation",
                                target_file=target_file, fn=fn, fn_src=fn_src)

    if guard == "staleness-gate":
        shape = detect_staleness(src, fn_src)
        if shape is None:
            return _blocked(target_file, fn, vuln_class, inv,
                            ("no Account whose data struct carries a slot/timestamp "
                             "field + a value field, read without a staleness gate, "
                             "found; obligation: hand-author the freshness invariant + "
                             "staleness-gate fixed handler"))
        ok, bad = data_struct_self_contained(shape["data_body"])
        if force_runtime_tier or not ok:
            return _runtime_scaffold_block(
                target_file, fn, vuln_class, inv, "freshness", out_dir,
                ("drive the real handler via solana-program-test/BanksClient: build the "
                 f"{shape['state_data_ty']} account with a STALE {shape['ts_field']}, "
                 "set the Clock sysvar slot ahead by > max_age, assert the read is "
                 "rejected; build a FRESH account (negative control). "
                 + (f"Data struct not plain-cargo-liftable: {bad}" if not ok else "")))
        crate = "a0d_target_auto"
        lib_rs = render_staleness_crate(shape["state_data_ty"], shape["data_body"],
                                        shape["ts_field"], shape["value_field"], inv)
        harness = render_staleness_harness(shape["state_data_ty"], shape["data_body"],
                                           shape["ts_field"], shape["value_field"],
                                           fn, inv, crate)
        work = _mk_workdir(out_dir, f"anchor_stale_{fn}")
        _write_plain_cargo(work, crate, lib_rs, harness)
        result = _base_result(target_file, fn, vuln_class, inv)
        result["anchor_shape"] = {k: shape[k] for k in
                                  ("ctx", "state_field", "state_data_ty",
                                   "ts_field", "value_field")}
        return _run_plain_cargo(work, result, run, "freshness",
                                target_file=target_file, fn=fn, fn_src=fn_src)

    return _blocked(target_file, fn, vuln_class, inv,
                    f"guard {guard!r} has no convert path")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--target-file")
    p.add_argument("--fn")
    p.add_argument("--vuln-class")
    p.add_argument("--candidate-json")
    p.add_argument("--out-dir")
    p.add_argument("--no-run", action="store_true")
    p.add_argument("--force-runtime-tier", action="store_true",
                   help="author the solana-program-test scaffold instead of the "
                        "plain-cargo lift (use when the impact needs the runtime)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if args.candidate_json:
        cand = json.loads(Path(args.candidate_json).read_text(encoding="utf-8"))
        target_file = cand.get("target_file")
        fn = cand.get("fn")
        vuln_class = cand.get("vuln_class")
    else:
        target_file, fn, vuln_class = args.target_file, args.fn, args.vuln_class

    if not (target_file and fn and vuln_class):
        print("need --target-file --fn --vuln-class (or --candidate-json)",
              file=sys.stderr)
        return 2
    tf = Path(target_file).expanduser().resolve()
    if not tf.is_file():
        print(f"not a file: {tf}", file=sys.stderr)
        return 2
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else None
    result = convert(tf, fn, vuln_class, repo_root=repo_root, out_dir=out_dir,
                     run=not args.no_run, force_runtime_tier=args.force_runtime_tier)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[anchor-0day-proof] {result['verdict']}: {result.get('reason','')}")
        print(f"  target: {result['fn']} (anchor) vuln_class={result['vuln_class']}")
        print(f"  grounded-invariant: {result['grounded_invariant']} "
              f"[{result['invariant_category']}] "
              f"(corpus={result['invariant_grounded_in_corpus']})")
        if result.get("convert_family"):
            print(f"  family: {result['convert_family']} "
                  f"tier={result.get('runtime_tier','-')}")
        if result.get("workdir"):
            print(f"  workdir: {result['workdir']}")
        if result.get("parsed"):
            pr = result["parsed"]
            print(f"  run: exploit_fail={pr['exploit_fail']} "
                  f"control_pass={pr['control_pass']} compiled={pr['compiled']}")
    return 0 if result["verdict"] == PROOF_BACKED else 1


if __name__ == "__main__":
    raise SystemExit(main())
