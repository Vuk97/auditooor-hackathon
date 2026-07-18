#!/usr/bin/env python3
"""tools/lib/dataflow_attack_class.py - map a DefUsePath sink.kind to a CANONICAL
attack class string (bidirectional wiring 49c, edge 9, R38).

Single source of truth for the sink-kind -> attack-class SUGGESTION shared by the
dataflow consumers (per-function-hacker-questions flow-seeded questions today; any
future consumer that assigns a path-derived attack class). The suggestion is
ADDITIVE and PROVENANCE-TAGGED ``dataflow_sink_kind`` by the caller.

R38 contract (the crux): the suggested attack class MUST verbatim-match a canonical
class string from the attack-class taxonomy
(``audit/corpus_tags/derived/attack_class_taxonomy.json``). We do NOT invent a class
name. For each sink-kind we hold a PRIORITY list of conceptually-faithful canonical
candidate strings; ``suggest_attack_class`` returns the FIRST candidate that exists
verbatim in the taxonomy, and ``None`` when none of them do. So:

  - the mapping is honest TODAY (a concept with no verbatim taxonomy class yields no
    suggestion - never a fabricated class), AND
  - it auto-lights-up if/when the corpus later adds the general class name (e.g. a
    future ``fund-transfer`` / ``supply-manipulation`` class makes the transfer /
    mint-burn sinks start suggesting it with no code change).

Concept map (task-named -> candidate priority, most-general first):
  transfer / transferFrom / send / safeTransfer / safeTransferFrom / call /
  low_level_call / delegatecall / sendValue / staticcall
        -> fund-transfer / theft               (value leaves the contract)
  mint / burn / _mint / _burn
        -> supply-manipulation                 (token supply moves)
  storage-value (economic state-write)
        -> accounting / balance-corruption      (protocol accounting moves)
  authority (role / owner / access write)
        -> access-control                       (authorization moves)

Dependency-free (stdlib + a small JSON read); offline-safe; never executes target
code. The taxonomy path defaults to the in-repo derived file and degrades to an
empty class-set (=> every suggestion omitted) when the file is absent/unreadable,
so a consumer in a tree without the corpus never fabricates a class.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

# Default taxonomy location relative to the repo root (this file is tools/lib/).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_TAXONOMY = _REPO_ROOT / "audit" / "corpus_tags" / "derived" / "attack_class_taxonomy.json"

# Concept buckets keyed by sink.kind / callee. Each value is a PRIORITY-ORDERED
# list of canonical candidate strings (most general first). The FIRST candidate
# that is present verbatim in the taxonomy wins; if none are present, no class is
# suggested for that sink-kind. The lists deliberately contain only genuinely-
# GENERAL class names that faithfully describe the concept - never an over-narrow
# corpus-provenance class - so a hit is always a faithful, not an over-claimed,
# attack class.
_FUND_TRANSFER = ["fund-transfer", "theft", "fund-loss", "asset-theft"]
_SUPPLY_MANIPULATION = [
    "supply-manipulation",
    "unauthorized-mint",
    "token-supply-manipulation",
]
_ACCOUNTING = [
    "accounting-balance-corruption",
    "accounting-corruption",
    "balance-corruption",
    "accounting",
    "accounting-conservation",
]
_ACCESS_CONTROL = [
    "access-control",
    "access-control-bypass",
    "access-control-missing",
]
# Guard-correctness boundary (off-by-one / strict-vs-non-strict cap). PRIORITY-
# ORDERED canonical candidates, most-general first. R38: returned only when the
# string exists VERBATIM in the taxonomy; today no general `off-by-one`/`boundary`
# class is in the corpus, so this yields None (no fabricated class) and auto-
# lights-up if/when the corpus adds the general class name.
_BOUNDARY = [
    "off-by-one",
    "boundary-condition",
    "boundary-error",
    "rounding",
    "integer-boundary",
]
# Type-convertibility / UNSAFE-DOWNCAST (silent uintN truncation / int<->uint
# sign-flip on a value-moving operand). PRIORITY-ORDERED canonical candidates,
# most-faithful first. R38: returned only when present VERBATIM in the taxonomy.
# Truncation-specific names come first (omitted if absent); `integer-overflow`
# is the most-general faithful candidate that DOES exist in the corpus today (a
# silent narrowing cast wraps == the integer-overflow family), so it is the live
# fallback. Auto-lights-up if/when the corpus adds a dedicated truncation class.
_DOWNCAST = [
    "integer-truncation",
    "downcast-truncation",
    "truncation",
    "unsafe-downcast",
    "integer-overflow",
]
# Inline-assembly / Yul delegatecall (proxy / upgrade backdoor). PRIORITY-ORDERED
# canonical candidates, most-general first. R38: returned only when present
# VERBATIM in the taxonomy. `delegatecall-to-untrusted-target` IS in the corpus
# today and faithfully describes a Yul delegatecall whose target the attacker can
# influence; the more-general `proxy`/`upgradeability` names are listed first so
# the suggestion auto-promotes if/when the corpus adds them.
_ASM_DELEGATECALL = [
    "proxy-upgradeability",
    "upgradeability",
    "uninitialized-proxy",
    "delegatecall-to-untrusted-target",
]
# Inline-assembly / Yul literal-slot sstore (storage-slot collision). PRIORITY-
# ORDERED canonical candidates, most-general first. R38: returned only when present
# VERBATIM in the taxonomy; today no GENERAL `storage-collision` class is in the
# corpus (the only match is an over-narrow corpus-provenance string, deliberately
# EXCLUDED), so this yields None (no fabricated class) and auto-lights-up if/when
# the corpus adds the general class name.
_ASM_STORAGE_COLLISION = [
    "storage-collision",
    "storage-slot-collision",
    "storage-layout-collision",
    "uninitialized-storage-pointer",
]
# Inline-assembly / Yul raw value-moving call. Reuses the fund-transfer concept.
_ASM_RAW_CALL = list(_FUND_TRANSFER)
# Same-fn CEI violation (Glider gap #5): a state-write AFTER an external call in
# one function with no reentrancy guard - the intra-procedural reentrancy class.
# PRIORITY-ORDERED canonical candidates, most-general first. R38: returned only
# when present VERBATIM in the taxonomy. `reentrancy` IS in the corpus today and
# faithfully describes a same-fn CEI violation; the more-specific
# `external-call-reentrancy` is listed first so the suggestion auto-promotes if/
# when the corpus prefers it.
_INTRA_CEI = [
    "external-call-reentrancy",
    "reentrancy",
    "hook-reentrancy",
]
# Unbounded-loop gas griefing (Glider gap #5): a loop bounded by an attacker-
# growable `.length` with an effect inside - a denial-of-service / gas-griefing
# class. PRIORITY-ORDERED canonical candidates, most-general first. R38: returned
# only when present VERBATIM in the taxonomy. `dos` IS in the corpus today and
# faithfully describes the gas-griefing impact; the more-specific
# `unbounded-loop`/`gas-griefing` names are listed first so the suggestion auto-
# promotes if/when the corpus adds them.
_UNBOUNDED_LOOP = [
    "unbounded-loop",
    "gas-griefing",
    "denial-of-service",
    "dos",
]
# EnumerableSet at()-in-remove iteration-skip (Glider gap W5): a FORWARD loop that
# reads `set.at(i)` AND `set.remove(...)` on the same collection skips the element
# swapped into slot `i` - elements are silently NEVER processed (incomplete
# iteration / a partial clear-all / unhandled state). This is a FUNCTIONAL
# correctness break (a protocol invariant like "every member purged" is violated),
# NOT a gas-exhaustion DoS, so it deliberately does NOT reuse `_UNBOUNDED_LOOP`.
# PRIORITY-ORDERED canonical candidates, most-specific first. R38: returned ONLY
# when present VERBATIM in the taxonomy. The iteration-specific names
# (`iteration-skip`/`incomplete-iteration`) are tried first (omitted if absent
# today, so the suggestion auto-promotes if/when the corpus adds them);
# `protocol-invariant-bypass` IS in the corpus today and faithfully describes the
# silently-skipped-element invariant break, so it is the live fallback. No `dos`
# fallback - that would mis-class a functional skip as a griefing DoS.
_ENUMSET_REMOVE_IN_LOOP = [
    "iteration-skip",
    "incomplete-iteration",
    "protocol-invariant-bypass",
]
# Override-dropped-guard dispatch (Glider gap W1): a child override DROPPED the
# caller-identity access-control guard its base version enforced, so the leaf
# dispatch target runs unguarded - an access-control class. PRIORITY-ORDERED
# canonical candidates, most-specific first. R38: returned only when present
# VERBATIM in the taxonomy. The general `access-control` IS in the corpus today
# and faithfully describes the dropped-guard authorization gap; the more-specific
# `access-control-bypass`/`access-control-missing` names are listed first so the
# suggestion auto-promotes if/when the corpus adds them.
_OVERRIDE_DROPPED_GUARD = [
    "access-control-bypass",
    "access-control-missing",
    "access-control",
]
# Divide-before-multiply precision loss (Glider gap W3): an integer DIVISION whose
# result is then MULTIPLIED (`(a / b) * c`) truncates before scaling - the classic
# precision-loss / rounding bug. PRIORITY-ORDERED canonical candidates, most-faithful
# first. R38: returned only when present VERBATIM in the taxonomy. The precision-
# specific names come first (omitted if absent); `rounding` IS in the corpus today and
# faithfully describes the truncation-on-divide impact, so it is the live fallback. The
# over-narrow corpus-provenance string `shares-rounding-favors-attacker` is deliberately
# EXCLUDED. Auto-lights-up if/when the corpus adds a dedicated precision-loss class.
_PRECISION = [
    "precision-loss",
    "rounding-error",
    "decimal-precision-loss",
    "division-before-multiplication",
    "rounding",
]

# Oracle try/catch-swallow (Glider gap W2): a try-wrapped oracle/price read whose
# catch SWALLOWS the failure, so execution proceeds on a stale/zero/default price -
# the stale-oracle / oracle-manipulation class. PRIORITY-ORDERED canonical
# candidates, most-faithful first. R38: returned only when present VERBATIM in the
# taxonomy. `stale-price` is the most-faithful name (omitted if absent today);
# `stale-or-manipulated-oracle` IS in the corpus today and faithfully describes a
# stale-price-used-on-swallow bug; `oracle-manipulation` is the more-general live
# fallback. Auto-promotes if/when the corpus adds a dedicated stale-price class.
_ORACLE_SWALLOW = [
    "stale-price",
    "stale-or-manipulated-oracle",
    "oracle-manipulation",
]
# Unchecked return-value (Glider gap W6 P1): a transfer / transferFrom / .call /
# .send / delegatecall whose boolean success RETURN value is never consumed by a
# require/assert/if-revert/return, so a failed call silently continues - the
# silent-failure / swallowed-revert class. PRIORITY-ORDERED canonical candidates,
# most-specific first. R38: returned ONLY when present VERBATIM in the taxonomy.
# NONE of these four candidates exists in the corpus today, so this list yields
# None (no fabricated class) - the I1 question + the slice annotation still fire
# (so this is NOT an orphan), and the class auto-lights-up if/when the corpus adds
# one. No generic `dos` fallback - a silently-swallowed failure is a CORRECTNESS /
# fund-safety break, not a gas-exhaustion DoS, so a `dos` fallback would mis-class.
_UNCHECKED_RETURN = [
    "unchecked-low-level-return",
    "unchecked-return-value",
    "unchecked-call-return",
    "silent-transfer-failure",
]
# Logic-tautology / dead-comparison (Glider gap W6 P2): a guard whose BOOLEAN
# LOGIC is broken - an always-true OR tautology (msg.sender != A || msg.sender
# != B) or a dead comparison whose result is discarded. The access-control check
# is nullified or never applied. PRIORITY-ORDERED canonical candidates, most-
# specific first. R38: returned ONLY when present VERBATIM in the taxonomy.
# `access-control-bypass` and `access-control-missing` are tried first (omitted
# if absent today); `access-control` IS in the corpus today and faithfully
# describes an authorization gap caused by a broken guard logic - so it is the
# live fallback. No generic `dos`/`validation` fallback - a logic-broken guard
# is an authorization gap, not a gas or DoS issue.
_LOGIC_TAUTOLOGY = [
    "access-control-bypass",
    "access-control-missing",
    "access-control",
]

# asm sink kind -> concept candidate list.
_ASM_KIND_CANDIDATES: dict[str, List[str]] = {
    "delegatecall": _ASM_DELEGATECALL,
    "sstore-literal": _ASM_STORAGE_COLLISION,
    "asm-call": _ASM_RAW_CALL,
}

# sink.kind (or callee) -> concept candidate list.
SINK_KIND_CANDIDATES: dict[str, List[str]] = {
    # value leaves the contract (token transfer / raw call / native send)
    "transfer": _FUND_TRANSFER,
    "transferFrom": _FUND_TRANSFER,
    "send": _FUND_TRANSFER,
    "sendValue": _FUND_TRANSFER,
    "safeTransfer": _FUND_TRANSFER,
    "safeTransferFrom": _FUND_TRANSFER,
    "call": _FUND_TRANSFER,
    "low_level_call": _FUND_TRANSFER,
    "delegatecall": _FUND_TRANSFER,
    "staticcall": _FUND_TRANSFER,
    # token supply moves
    "mint": _SUPPLY_MANIPULATION,
    "burn": _SUPPLY_MANIPULATION,
    "_mint": _SUPPLY_MANIPULATION,
    "_burn": _SUPPLY_MANIPULATION,
    # economic protocol accounting moves
    "storage-value": _ACCOUNTING,
    # authorization moves
    "authority": _ACCESS_CONTROL,
}


def _read_canonical_classes(taxonomy_path: Optional[str]) -> frozenset:
    p = Path(taxonomy_path).expanduser() if taxonomy_path else _DEFAULT_TAXONOMY
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    classes = data.get("classes") if isinstance(data, dict) else None
    if not isinstance(classes, list):
        return frozenset()
    out = set()
    for c in classes:
        if isinstance(c, dict):
            name = c.get("attack_class")
            if isinstance(name, str) and name.strip():
                out.add(name.strip())
    return frozenset(out)


@lru_cache(maxsize=8)
def canonical_classes(taxonomy_path: Optional[str] = None) -> frozenset:
    """The set of canonical attack-class strings from the taxonomy (cached).

    Returns an empty frozenset when the taxonomy file is absent/unreadable, so a
    consumer in a tree without the corpus simply suggests nothing (never invents).
    The ``AUDITOOOR_ATTACK_CLASS_TAXONOMY`` env override is honored when
    taxonomy_path is None.
    """
    if taxonomy_path is None:
        taxonomy_path = os.environ.get("AUDITOOOR_ATTACK_CLASS_TAXONOMY")
    return _read_canonical_classes(taxonomy_path)


def candidate_classes_for_sink_kind(sink_kind: str) -> List[str]:
    """The priority-ordered candidate canonical-class list for a sink.kind.

    Returns [] for an unknown / non-value-moving sink kind (e.g. state_var_read).
    """
    return list(SINK_KIND_CANDIDATES.get((sink_kind or "").strip(), []))


def suggest_boundary_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a BOUNDARY-SUSPECT path to a canonical off-by-one/boundary attack class.

    Returns the FIRST `_BOUNDARY` candidate present verbatim in the taxonomy, or
    None when none exist (R38: never invent - omit). The sink_kind/callee are
    accepted for signature symmetry with ``suggest_attack_class`` and to allow a
    future kind-specific boundary class without a caller change.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _BOUNDARY:
        if cand in classes:
            return cand
    return None


def suggest_downcast_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map an UNSAFE-DOWNCAST path to a canonical truncation/overflow attack class.

    Returns the FIRST `_DOWNCAST` candidate present verbatim in the taxonomy, or
    None when none exist (R38: never invent - omit). The sink_kind/callee are
    accepted for signature symmetry with ``suggest_attack_class`` and to allow a
    future kind-specific truncation class without a caller change.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _DOWNCAST:
        if cand in classes:
            return cand
    return None


def suggest_asm_attack_class(
    asm_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map an INLINE-ASSEMBLY / YUL suspect sink (`asm_kind` one of
    "delegatecall" / "sstore-literal" / "asm-call") to a canonical proxy/
    upgradeability, storage-collision, or fund-transfer attack class.

    Returns the FIRST candidate (for that asm_kind) present verbatim in the
    taxonomy, or None when none exist (R38: never invent - omit). The candidate
    lists are most-general first, so a Yul delegatecall resolves to the live
    `delegatecall-to-untrusted-target` today and auto-promotes to a future
    `proxy-upgradeability` class with no caller change; a literal-slot sstore
    yields None today (no general storage-collision class in the corpus yet)."""
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    candidates = _ASM_KIND_CANDIDATES.get((asm_kind or "").strip(), [])
    for cand in candidates:
        if cand in classes:
            return cand
    return None


def suggest_intra_cei_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a SAME-FN CEI-violation path (Glider gap #5) to a canonical reentrancy
    attack class.

    Returns the FIRST `_INTRA_CEI` candidate present verbatim in the taxonomy, or
    None when none exist (R38: never invent - omit). `external-call-reentrancy` is
    tried first, then the live `reentrancy` corpus class. The sink_kind/callee are
    accepted for signature symmetry with ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _INTRA_CEI:
        if cand in classes:
            return cand
    return None


def suggest_unbounded_loop_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map an UNBOUNDED-LOOP path (Glider gap #5) to a canonical DoS / gas-griefing
    attack class.

    Returns the FIRST `_UNBOUNDED_LOOP` candidate present verbatim in the taxonomy,
    or None when none exist (R38: never invent - omit). The general
    `unbounded-loop`/`gas-griefing` names are tried first, then the live `dos`
    corpus class. The sink_kind/callee are accepted for signature symmetry.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _UNBOUNDED_LOOP:
        if cand in classes:
            return cand
    return None


def suggest_enumset_remove_in_loop_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map an ENUMERABLESET REMOVE-IN-LOOP iteration-skip path (Glider gap W5) to a
    canonical functional-correctness attack class.

    Returns the FIRST `_ENUMSET_REMOVE_IN_LOOP` candidate present verbatim in the
    taxonomy, or None when none exist (R38: never invent - omit). The iteration-
    specific `iteration-skip`/`incomplete-iteration` names are tried first (omitted
    if absent today), then the live `protocol-invariant-bypass` corpus class. There
    is deliberately NO `dos` fallback - an iteration-skip is a FUNCTIONAL break, not
    a gas-exhaustion DoS. The sink_kind/callee are accepted for signature symmetry
    with ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _ENUMSET_REMOVE_IN_LOOP:
        if cand in classes:
            return cand
    return None


def suggest_override_dropped_guard_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map an OVERRIDE-DROPPED-GUARD path (Glider gap W1) to a canonical
    access-control attack class.

    Returns the FIRST `_OVERRIDE_DROPPED_GUARD` candidate present verbatim in the
    taxonomy, or None when none exist (R38: never invent - omit). The specific
    `access-control-bypass`/`access-control-missing` names are tried first, then
    the live `access-control` corpus class. The sink_kind/callee are accepted for
    signature symmetry with ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _OVERRIDE_DROPPED_GUARD:
        if cand in classes:
            return cand
    return None


def suggest_div_before_mul_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a DIVIDE-BEFORE-MULTIPLY path (Glider gap W3) to a canonical precision-loss
    / rounding attack class.

    Returns the FIRST `_PRECISION` candidate present verbatim in the taxonomy, or None
    when none exist (R38: never invent - omit). The precision-specific names
    (precision-loss / rounding-error / decimal-precision-loss /
    division-before-multiplication) are tried first, then the live `rounding` corpus
    class. The sink_kind/callee are accepted for signature symmetry with
    ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _PRECISION:
        if cand in classes:
            return cand
    return None


def suggest_oracle_swallow_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map an ORACLE TRY/CATCH-SWALLOW path (Glider gap W2) to a canonical
    stale-oracle / oracle-manipulation attack class.

    Returns the FIRST `_ORACLE_SWALLOW` candidate present verbatim in the taxonomy,
    or None when none exist (R38: never invent - omit). The most-faithful
    `stale-price` is tried first (omitted if absent), then the live
    `stale-or-manipulated-oracle` corpus class, then `oracle-manipulation`. The
    sink_kind/callee are accepted for signature symmetry with ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _ORACLE_SWALLOW:
        if cand in classes:
            return cand
    return None


def suggest_unchecked_return_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map an UNCHECKED-RETURN-VALUE path (Glider gap W6 P1) to a canonical
    silent-failure attack class.

    Returns the FIRST `_UNCHECKED_RETURN` candidate present verbatim in the
    taxonomy, or None when none exist (R38: never invent - omit). NOTE: none of the
    four candidates (`unchecked-low-level-return`, `unchecked-return-value`,
    `unchecked-call-return`, `silent-transfer-failure`) exists in the corpus today,
    so this returns None right now - HONEST, no fabrication. The I1 question + the
    slice annotation still fire (so this is NOT an orphan), and the class
    auto-lights-up if/when the corpus adds one of the candidates. There is
    deliberately NO `dos` fallback - a swallowed failure is a correctness / fund-
    safety break, not a gas-exhaustion DoS. The sink_kind/callee are accepted for
    signature symmetry with ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _UNCHECKED_RETURN:
        if cand in classes:
            return cand
    return None


# Signature-replay precondition (Glider gap W6 P3): a verifying function calls
# ecrecover but lacks a per-signer/per-message nonce write (same-chain replay) OR
# does not include block.chainid in the digest (cross-chain replay). PRIORITY-
# ORDERED canonical candidates, most-specific first. R38: returned ONLY when
# present VERBATIM in the taxonomy. `signer-authorization-bypass` is tried first
# (omitted if absent - it is in the corpus but is slightly broader);
# `permit-signature-replay` IS in the corpus today and faithfully describes a
# missing-nonce / missing-chainid permit/signature replay, so it is the live
# fallback after the more-specific names. There is deliberately NO `access-control`
# fallback - a replay gap requires a cryptographic-verification precondition miss,
# not merely a missing guard, so mis-classing it as `access-control` would lose
# the distinctive nature of the finding. Auto-promotes if/when the corpus adds
# more-specific names.
_SIGNATURE_REPLAY = [
    "signer-authorization-bypass",
    "permit-signature-replay",
    "signature-malleability",
]

# Memory-copy-of-storage-never-written-back (Glider gap W6 P8): a storage STATE
# variable is read into a MEMORY local, the local is mutated, but the mutation is
# NEVER written back to the state var - the state update is silently lost. This is
# a FUNCTIONAL CORRECTNESS break (the protocol's invariant that "this function
# updates this state" is violated), NOT an access-control or precision issue.
# PRIORITY-ORDERED canonical candidates, most-specific first. R38: returned ONLY
# when present VERBATIM in the taxonomy. The most-faithful names are tried first
# (omitted if absent today, so the suggestion auto-promotes if/when the corpus adds
# them); `protocol-invariant-bypass` IS in the corpus today and faithfully describes
# a silently-lost state update (the invariant "the state var is updated by this
# function" is bypassed/violated). There is deliberately NO generic `dos` or
# `access-control` fallback - a lost write is a CORRECTNESS break.
_MEMORY_COPY_NO_WRITEBACK = [
    "lost-state-update",
    "incorrect-state-update",
    "state-update-lost",
    "protocol-invariant-bypass",
]


def suggest_logic_tautology_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a LOGIC-TAUTOLOGY / DEAD-COMPARISON path (Glider gap W6 P2) to a
    canonical access-control attack class.

    Returns the FIRST `_LOGIC_TAUTOLOGY` candidate present verbatim in the
    taxonomy, or None when none exist (R38: never invent - omit). The specific
    `access-control-bypass`/`access-control-missing` names are tried first, then
    the live `access-control` corpus class. The `access-control` class IS in the
    corpus today and faithfully describes a guard whose boolean logic is broken
    (always-true OR tautology or dead comparison), nullifying the access check.
    The sink_kind/callee are accepted for signature symmetry with
    ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _LOGIC_TAUTOLOGY:
        if cand in classes:
            return cand
    return None


def suggest_signature_replay_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a SIGNATURE-REPLAY path (Glider gap W6 P3) to a canonical replay
    attack class.

    Returns the FIRST `_SIGNATURE_REPLAY` candidate present verbatim in the
    taxonomy, or None when none exist (R38: never invent - omit).
    `permit-signature-replay` IS in the corpus today and faithfully describes
    a signed message replayable due to a missing nonce or missing chainid.
    The more-specific `signer-authorization-bypass` is listed first (omitted if
    absent), then the live `permit-signature-replay` corpus class. There is
    deliberately NO `access-control` fallback - a signature-replay bug requires
    a genuine cryptographic-verification precondition gap, not merely a missing
    guard. The sink_kind/callee are accepted for signature symmetry with
    ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _SIGNATURE_REPLAY:
        if cand in classes:
            return cand
    return None


def suggest_memory_copy_no_writeback_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a MEMORY-COPY-OF-STORAGE-NEVER-WRITTEN-BACK path (Glider gap W6 P8) to
    a canonical lost-state-update / functional-correctness attack class.

    Returns the FIRST `_MEMORY_COPY_NO_WRITEBACK` candidate present verbatim in the
    taxonomy, or None when none exist (R38: never invent - omit). The most-specific
    names (`lost-state-update`, `incorrect-state-update`, `state-update-lost`) are
    tried first (omitted if absent today); `protocol-invariant-bypass` IS in the
    corpus today and faithfully describes the silently-lost state update, so it is
    the live fallback. There is deliberately NO `dos` or `access-control` fallback.
    The sink_kind/callee are accepted for signature symmetry with
    ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _MEMORY_COPY_NO_WRITEBACK:
        if cand in classes:
            return cand
    return None


# Two-step-ownership-accept WRONG-GUARD (Glider gap W6 P5): an accept/claim-
# ownership function is gated by onlyOwner (the CURRENT owner) instead of
# checking msg.sender == pendingOwner (the PENDING owner). This is an access-
# control class: the authorization check is PRESENT but targets the WRONG role.
# PRIORITY-ORDERED canonical candidates, most-specific first. R38: returned ONLY
# when present VERBATIM in the taxonomy. The specific `access-control-bypass` /
# `access-control-missing` names are tried first (omitted if absent today);
# `access-control` IS in the corpus today and faithfully describes the wrong-guard
# authorization gap, so it is the live fallback. No `dos` or `precision` fallback -
# a wrong guard is an authorization break, not a gas or math issue.
_TWO_STEP_ACCEPT_WRONG_GUARD = [
    "access-control-bypass",
    "access-control-missing",
    "access-control",
]


def suggest_two_step_accept_wrong_guard_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a TWO-STEP-OWNERSHIP-ACCEPT WRONG-GUARD path (Glider gap W6 P5) to a
    canonical access-control attack class.

    Returns the FIRST `_TWO_STEP_ACCEPT_WRONG_GUARD` candidate present verbatim in
    the taxonomy, or None when none exist (R38: never invent - omit). The specific
    `access-control-bypass` / `access-control-missing` names are tried first, then
    the live `access-control` corpus class. The `access-control` class IS in the
    corpus today and faithfully describes the authorization gap where the guard
    targets the CURRENT owner instead of the PENDING owner. There is deliberately NO
    `dos` or `precision` fallback. The sink_kind/callee are accepted for signature
    symmetry with ``suggest_attack_class``.
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    for cand in _TWO_STEP_ACCEPT_WRONG_GUARD:
        if cand in classes:
            return cand
    return None


def suggest_attack_class(
    sink_kind: str,
    *,
    callee: str | None = None,
    taxonomy_path: Optional[str] = None,
) -> Optional[str]:
    """Map a sink.kind (with optional callee fallback) to a CANONICAL attack class.

    Returns the FIRST candidate that verbatim-matches a taxonomy class, or None
    when the sink kind has no concept bucket, or no candidate exists in the
    taxonomy (R38: never invent a class - omit instead).
    """
    classes = canonical_classes(taxonomy_path)
    if not classes:
        return None
    candidates = candidate_classes_for_sink_kind(sink_kind)
    if not candidates and callee:
        # A generic `call`/`HighLevelCall` sink may carry the real mover in its
        # callee name (e.g. callee="transferFrom" with kind="call"). Fall back to
        # the callee's concept bucket so a named mover is still classified.
        candidates = candidate_classes_for_sink_kind(callee)
    for cand in candidates:
        if cand in classes:
            return cand
    return None
