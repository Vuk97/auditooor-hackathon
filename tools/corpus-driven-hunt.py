#!/usr/bin/env python3
"""corpus-driven-hunt.py - turn the invariant/detector corpus into a ranked,
target-grounded live-hypothesis list for one workspace.

WHAT IT DOES (the unique gap):
  1. Resolve the target source root for <workspace> and detect its
     language(s) + bug-family fingerprint (crypto/signing, bridge/replay,
     reentrancy, accounting/conservation, access-control, etc.).
  2. Select corpus invariants whose target_lang matches the target
     (detected-lang OR "any") AND whose family is relevant to the target
     fingerprint.
  3. For EACH selected invariant, MATERIALIZE a concrete live hypothesis:
     grep/AST the target's own functions for the invariant's
     commit_point_pattern / defense_layer / attack_signature tokens, locate
     candidate functions, and score the hypothesis by (corpus weight x
     family-fit x in-target evidence). A hypothesis with zero in-target
     evidence is still emitted but ranked low and flagged need_more_evidence.
  4. Emit a ranked corpus-sourced hypothesis list (JSON + markdown).
  5. Optionally (--mimo) emit a MIMO fanout task batch (one task per top-N
     hypotheses, capped to --mimo-concurrency, default 4) compatible with
     llm-fanout-dispatcher.py for the reasoning step. This tool does NOT
     block on a synchronous model call - MIMO in this repo is a batch fanout.

PR7a - MANDATORY PROOF QUEUE (not advisory):
  --emit-proof-queue UPSERTs every TRUSTED-corpus hypothesis into the
  workspace's canonical ``<ws>/.auditooor/exploit_queue.json`` as a
  proof-status=open row (source="corpus-hunt-fuel"). Each relevant corpus
  invariant becomes a LIVE PROOF OBLIGATION, not just an advisory line in a
  side JSON. Existing non-fuel queue rows are never destroyed; fuel rows are
  deduped by (contract.function | invariant_id) and re-written idempotently.
  The exploit-queue is the queue ``audit-completeness-check.py`` already
  certifies, so corpus invariants now flow into the same proof pipeline as
  preflight fuel and source-mined leads.

ADD-D - brain-prime seed gate + hacker-question fold-in:
  - At hunt entry the tool REQUIRES ``<ws>/.auditooor/brain_prime_receipt.json``
    (schema auditooor.brain_prime_receipt.v1, the receipt
    ``vault_brain_prime_context`` reads). The receipt's ``top_phase_f_lanes``
    attack-classes SEED the hypothesis ranking: a hypothesis whose family /
    category matches a brain-prime lane gets a ranking boost so the corpus
    hunt is aligned with the priming step instead of running blind. Without
    the receipt the run fails closed (verdict gate=fail) unless
    ``--no-brain-prime-gate`` is passed (override is audit-logged in output).
  - ``vault_hacker_questions`` per in-scope function: the tool reads the
    hacker-questions library
    (``audit/corpus_tags/derived/hacker_questions_library.jsonl``), matches
    each question's grep/function patterns against the target functions, and
    emits the matched questions as ADDITIONAL proof-queue rows
    (source="corpus-hunt-hacker-q") so per-fn hunting questions flow into the
    SAME mandatory proof queue as the invariant hypotheses.

RELATED TOOLS (read these first - this tool fills a distinct gap):
  - tools/novel-hypothesis-probe.py: generates NEGATIVE-SPACE hypotheses
    (mechanisms NOT in the corpus). This tool is the inverse: it drives
    hypotheses FROM the corpus invariants/detectors that ARE present.
  - tools/adversarial-hypothesis-differential-hunter.py: emits per-function
    adversarial differential ideas with NO corpus grounding (pure shape
    heuristics on Solidity). This tool grounds every hypothesis in a cited
    INV-* corpus record and is language-agnostic.
  - tools/mimo-corpus-miner.py / tools/mimo-harness-batch-gen.py: mine MIMO
    sidecars into corpus / build question-driven MIMO batches. This tool is
    invariant-driven (not question-driven) and produces the ranked hypothesis
    list as its primary product; the MIMO batch is an optional side-output.

Deterministic, stdlib-only. Advisory: it does not prove exploitability and a
backtest MISS is reported as a miss.

Schema: auditooor.corpus_driven_hunt.v1

USAGE:
  python3 tools/corpus-driven-hunt.py <workspace> [--source <dir>]
      [--invariant-corpus <jsonl>[,<jsonl>...]] [--top N] [--max-functions N]
      [--mimo] [--mimo-out <path>] [--mimo-concurrency 4]
      [--emit-proof-queue] [--proof-queue-path <json>]
      [--brain-prime-receipt <json>] [--no-brain-prime-gate]
      [--hacker-questions <jsonl>] [--no-hacker-questions]
      [--out <json>] [--md-out <md>] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA = "auditooor.corpus_driven_hunt.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools" / "lib"))
import zero_day_fuel_identity as zero_day_identity


AWARENESS_LEDGER_SCHEMA = "auditooor.awareness_ledger.v1"
AWARENESS_LOGICAL_FIELDS = (
    "target_unit",
    "asset_invariant",
    "violation_relation",
    "actor_model",
    "impact_class",
)


class AwarenessFilterError(ValueError):
    """Raised when reviewed-awareness exclusions cannot be applied exactly."""

# PR2b: route corpus consumption through the shared trusted-corpus resolver so
# hunt output always states the trust_scope it was produced under (active vs
# raw-fallback). Resilient import: if the helper is missing we degrade silently.
sys.path.insert(0, str(REPO_ROOT / "tools" / "lib"))
try:
    import trusted_corpus_resolver as _tcr  # noqa: E402
except Exception:  # pragma: no cover - defensive
    _tcr = None


def _corpus_trust_annotation():
    if _tcr is None:
        return {"trust_scope": "raw-fallback", "is_fallback": True,
                "reason": "trusted_corpus_resolver unavailable"}
    inc = os.environ.get("INCLUDE_ADVISORY") == "1"
    return _tcr.resolve_active_corpus(repo_root_path=REPO_ROOT,
                                      include_advisory=inc).as_dict()
# REPOINTED (corpus-driven-hunt-fuel-repoint): the default fuel is the FRESH
# audited library the brain serves, NOT the 2026-05-24 pre-harvest snapshot. The
# old default ({extracted, pilot, extracted_llm_v1}) yielded 523 invariants (rust
# 49, circom 0, no cross-language transfer set); the audited default yields ~1314
# (rust 201, circom 70, cairo 102) and loads invariants_cross_lang_lifted.jsonl so
# A->B cross-workspace transfer fires. trusted_corpus_resolver is the SINGLE source
# of truth (hunt + brain repoint atomically); the literal list is a defensive
# fallback when the resolver is unavailable. Ordering = pilot_audited FIRST so the
# load_invariants first-wins dedup keeps the incident-audited row over the raw
# extracted snapshot's same-id-different-content collision
# (lane-invariant-audit-ext.py:355).
_DEFAULT_INVARIANT_CORPORA_FALLBACK = [
    "audit/corpus_tags/derived/invariants_pilot_audited.jsonl",
    "audit/corpus_tags/derived/invariants_full_library_llm_v1.jsonl",
    "audit/corpus_tags/derived/invariants_cross_lang_lifted.jsonl",
    "audit/corpus_tags/derived/invariants_extracted.jsonl",
]


def _resolve_default_invariant_corpora():
    """Active invariant-corpus relpaths (resolver-first, existence-filtered)."""
    if _tcr is not None and hasattr(_tcr, "resolve_active_invariant_corpora"):
        try:
            relpaths = _tcr.resolve_active_invariant_corpora(
                repo_root_path=REPO_ROOT, relative=True)
            if relpaths:
                return list(relpaths)
        except Exception:  # pragma: no cover - defensive
            pass
    # Fallback: filter the literal list to files that exist on disk.
    return [c for c in _DEFAULT_INVARIANT_CORPORA_FALLBACK
            if (REPO_ROOT / c).is_file()] or list(_DEFAULT_INVARIANT_CORPORA_FALLBACK)


DEFAULT_INVARIANT_CORPORA = _resolve_default_invariant_corpora()

# ADD-D: the hacker-questions library vault_hacker_questions reads. Matched
# per-function questions are folded into the SAME mandatory proof queue.
DEFAULT_HACKER_QUESTIONS = "audit/corpus_tags/derived/hacker_questions_library.jsonl"

# ADD-D: the brain-prime receipt vault_brain_prime_context reads. Required at
# hunt entry to seed the hypothesis ranking (unless --no-brain-prime-gate).
DEFAULT_BRAIN_PRIME_RECEIPT = ".auditooor/brain_prime_receipt.json"
BRAIN_PRIME_RECEIPT_SCHEMA = "auditooor.brain_prime_receipt.v1"

# PR7a: canonical exploit-queue path (the queue audit-completeness-check.py
# certifies). Corpus hypotheses are UPSERTed here as proof obligations.
EXPLOIT_QUEUE_REL = ".auditooor/exploit_queue.json"
CORPUS_HUNT_FUEL_SOURCE = "corpus-hunt-fuel"
CORPUS_HUNT_HACKER_Q_SOURCE = "corpus-hunt-hacker-q"

LANG_BY_EXT = {
    ".sol": "solidity",
    ".rs": "rust",
    ".go": "go",
    ".move": "move",
    ".cairo": "cairo",
    # F1 per-language UNION: circuit/zk source files were never enumerated even
    # though 70 circom + 25 noir INV records exist (scope_exclusion already lists
    # these exts). Mapping them here is load-bearing: without it circom/noir
    # functions are never indexed and no INV anchors to them.
    ".circom": "circom",
    ".nr": "noir",
    ".zok": "zokrates",
}

SKIP_DIRS = {
    ".git", "node_modules", "lib", "out", "cache", "artifacts", "broadcast",
    "target", "vendor", "third_party", "deps", ".auditooor", "__pycache__",
    "test", "tests", "mock", "mocks", "fixtures",
}


@dataclass(frozen=True)
class Family:
    name: str
    source_tokens: tuple
    corpus_categories: tuple
    corpus_signature_tokens: tuple


FAMILIES = (
    Family(
        "crypto_signing",
        ("sign", "nonce", "verify", "schnorr", "ecdsa", "frost", "keygen",
         "secret_share", "signature", "challenge", "commitment", "rng",
         "random", "ristretto", "scalar", "keypair"),
        ("determinism", "uniqueness", "soundness", "freshness"),
        ("nonce", "replay", "deterministic", "randomness", "signature",
         "malleab", "threshold", "share"),
    ),
    Family(
        "bridge_replay",
        ("bridge", "relay", "message", "vaa", "merkle", "proof", "crosschain",
         "cross_chain", "domain", "chainid", "chain_id", "ism", "ismp",
         "consumed", "processed"),
        ("uniqueness", "freshness", "ordering"),
        ("replay", "cross-chain", "cross-domain", "message", "consumed",
         "sequence", "nonce", "domain"),
    ),
    Family(
        "reentrancy_atomicity",
        ("call", "delegatecall", "transfer", "send", "external", "callback",
         "hook", "afterswap", "onerc"),
        ("atomicity", "ordering"),
        ("reentrancy", "callback", "checks-effects", "atomic", "interaction"),
    ),
    Family(
        "accounting_conservation",
        ("balance", "totalsupply", "total_supply", "shares", "assets",
         "deposit", "withdraw", "mint", "burn", "redeem", "fee", "reserve",
         "liquidity", "collateral", "debt",
         # F1 cosmos-bank value-flow tokens (Go/Cosmos accounting)
         "sendcoins", "spendablecoins", "sdk.coins",
         # F1 Solana value-flow tokens (lamport / SPL transfer paths)
         "lamports", "try_borrow_mut_lamports", "invoke", "invoke_signed",
         "spl_token", "token::transfer", "transfer_checked"),
        ("conservation", "monotonicity", "bounds"),
        ("conservation", "rounding", "inflation", "underflow", "overflow",
         "share", "supply", "balance", "fee"),
    ),
    Family(
        "access_control",
        ("owner", "admin", "onlyowner", "role", "auth", "require_keys_eq",
         "signer", "governance", "guardian", "operator", "ensure_signed",
         "ensure_root", "permission", "access"),
        ("authorization", "custody"),
        ("access", "authorization", "privilege", "owner", "admin",
         "permission", "custody", "unauthorized"),
    ),
    Family(
        "state_freshness",
        ("price", "oracle", "stale", "timestamp", "deadline", "expiry",
         "snapshot", "epoch", "round", "update"),
        ("freshness", "monotonicity"),
        ("stale", "freshness", "oracle", "price", "timestamp", "expiry"),
    ),
    # F1 Go/Cosmos: the existing FAMILIES vocab is Solidity-shaped, so 397 'go'
    # INVs (determinism/ordering/authorization) never family-fit a real cosmos
    # module. This family carries the cosmos-SDK state-machine surface so a
    # keeper / msgServer / ABCI handler matches.
    Family(
        "consensus_state_machine",
        ("keeper", "ctx", "msgserver", "validatebasic", "abci", "checktx",
         "delivertx", "processproposal", "prepareproposal", "beginblock",
         "endblock", "epoch", "validator", "staking", "gas", "store",
         "iterate"),
        ("determinism", "ordering", "atomicity", "bounds"),
        ("determinism", "ordering", "non-determinism", "map-range", "gas",
         "consensus", "halt", "proposal", "validator"),
    ),
    # F1 Move (Aptos/Sui): resource-model value-flow sinks. The existing
    # accounting family is balance/share-shaped (Solidity/EVM); Move moves value
    # through global-storage and coin module ops, which need their own sink set.
    Family(
        "move_resource_model",
        ("move_to", "move_from", "borrow_global_mut", "coin::transfer",
         "coin::withdraw", "coin::deposit", "object::transfer"),
        ("custody", "conservation", "authorization", "atomicity"),
        ("resource", "coin", "conservation", "custody", "global", "acquires",
         "withdraw", "deposit"),
    ),
    # F1 Solana/Anchor: account-model surface (zero such INVs exist today; this
    # family lets a Solana handler family-fit so an INV-SOL-* can anchor once the
    # corpus is built). Tokens are the Anchor/sealevel account-validation set.
    Family(
        "account_model",
        ("seeds", "bump", "pda", "find_program_address", "has_one",
         "is_signer", "owner", "close", "realloc", "init_if_needed",
         "accountinfo", "uncheckedaccount"),
        ("authorization", "custody", "determinism"),
        ("signer", "owner", "pda", "seed", "account-substitution",
         "type-cosplay", "close", "reinit", "cpi", "discriminator"),
    ),
)

CATEGORY_TO_FAMILY = {}
for _f in FAMILIES:
    for _c in _f.corpus_categories:
        CATEGORY_TO_FAMILY.setdefault(_c, _f.name)

FAMILY_BY_NAME = {_f.name: _f for _f in FAMILIES}


def _family_name_tokens(family: str) -> frozenset:
    """Return the CLASS-FAMILY name vocabulary for a hypothesis's family.

    iter14: this is the general fix for the INV-CON-004 mislanding. The
    byte-position nearest-fn scan anchors a class-matched hypothesis to whatever
    function precedes the FIRST byte-hit of one of the invariant's literal corpus
    keywords - which is frequently an unrelated handler in a dense file (the real
    anchor: INV-CON-004 landed on ``ibc_packet_handlers.go:handlePacket`` instead
    of the validator/distribution function whose OWN NAME carries the class
    signal). A conservation/normalization invariant's literal grep keywords
    ({conservation, shares, supply, ...}) often do NOT appear as a substring of
    the real bug function's name (``ApplyValidatorDistribution``,
    ``validateIntents``, ``settleEpochRewards``), so that function is never
    surfaced as a candidate.

    The family vocabulary returned here is the SAME class-signal token set the
    tool already uses to FINGERPRINT the target (``Family.source_tokens``). Using
    it to also NAME-ANCHOR candidate functions is general and class-keyed: a
    function whose name carries a distribution/validator/weight/epoch/reward/
    share token is the structurally-correct anchor for an accounting-conservation
    hypothesis, regardless of which specific symbol name the target chose. No
    target-specific symbol names (validateIntents / intents / Quicksilver /
    Synthetify) are hard-coded - only the open class vocabulary.

    To keep the anchor on-class for conservation/normalization (the family the
    INV-CON-004 mislanding was in), accounting hypotheses ALSO reach the
    distribution/weight/epoch/reward computation tokens that frequently name the
    real conserved-quantity function but are not in the accounting family's own
    source_tokens. This widening is additive and class-gated.
    """
    fam = FAMILY_BY_NAME.get(family)
    toks = set(fam.source_tokens) if fam else set()
    # Conservation/normalization functions are very often named for the quantity
    # being distributed/accrued (validator set distribution, epoch reward accrual,
    # weight normalization) rather than for the literal corpus keyword. Reach
    # those class-of-symbol names for the accounting family.
    if family == "accounting_conservation":
        toks |= {
            "distribution", "distribute", "validator", "weight", "weights",
            "normalize", "normalise", "epoch", "reward", "rewards", "accrue",
            "accrual", "allocate", "allocation", "settle", "settlement",
            "intent", "intents", "stake", "delegation", "commission",
        }
    return frozenset(t for t in toks if len(t) >= 4)


# iter10-B: READ-class invariant families. A hypothesis whose invariant
# category/family belongs to this set is about a quantity that a pure-READ
# (view) helper computes - epoch boundaries, conserved totals, monotone
# counters, bounded values, rounded results, freshness windows. For these,
# candidate enumeration ALSO surfaces internal/private VIEW helpers whose name
# matches a class keyword (iter9-B only enumerated internal mutating helpers).
# GENERAL: keyed on invariant CLASS (category/family), never on symbol names.
READ_CLASS_CATEGORIES = frozenset({
    "conservation", "monotonicity", "bounds", "rounding", "freshness",
    "epoch-boundary", "epoch_boundary", "boundary", "off-by-one", "off_by_one",
})
READ_CLASS_FAMILIES = frozenset({
    "accounting_conservation", "state_freshness",
})

# iter11-B: generic READ-class computation-token vocabulary. A read-class
# invariant constrains a numeric quantity that a pure-READ (view) helper
# COMPUTES - a price, rate, share, balance, epoch boundary, rounded value,
# accrued reward, etc. The iter10 fresh-target measurement proved that anchoring
# read-class hypotheses to view helpers by the INVARIANT's corpus keywords alone
# is too narrow: a corpus conservation invariant carries keywords like
# {shares, inflation, erc4626, deposit}, none of which is a substring of a view
# helper named `getSqrtPrice` (unbiased Predy datapoint) even though that helper
# computes exactly the contested read-class quantity. So for read-class
# hypotheses Pass 2 ALSO matches a view helper whose name contains one of these
# generic computation tokens. This is GENERAL and class-keyed (only fires for
# read-class invariants, only on VIEW helpers, name-level) - no symbol names are
# hard-coded. It is additive: a view helper that already matches the invariant's
# own keywords still matches; this only WIDENS the read-class view net.
READ_CLASS_VIEW_NAME_TOKENS = frozenset({
    # price / rate / value family
    "price", "rate", "value", "amount", "sqrt", "convert", "quote", "preview",
    "exchange", "index", "oracle",
    # accounting / conservation family
    "share", "shares", "asset", "assets", "balance", "supply", "total",
    "reserve", "collateral", "debt", "fee", "redeem", "deposit", "withdraw",
    "yield", "accru", "reward",
    # boundary / time / epoch family
    "epoch", "round", "boundary", "timestamp", "deadline", "expiry", "window",
    "start", "end",
    # generic numeric-compute verbs (intentionally excludes a bare "get" - too
    # broad; it would match every getter and defeat the read-class targeting).
    "calc", "compute", "bound",
})


def _matches_read_class_view_name(name_low: str) -> str:
    """Return the generic read-class computation token contained in a view
    helper's (lowercased) name, or None. Name-level + class-keyed; no symbol
    names hard-coded. Used by Pass 2 of ``_internal_fn_candidates`` so a
    read-class hypothesis anchors the actual numeric-computing view helper even
    when the invariant's own corpus keywords do not appear in the helper name.
    """
    return next((t for t in READ_CLASS_VIEW_NAME_TOKENS if t in name_low), None)


def _is_read_class(category: str, family: str) -> bool:
    cat = (category or "").strip().lower()
    fam = (family or "").strip().lower()
    if cat in READ_CLASS_CATEGORIES or fam in READ_CLASS_FAMILIES:
        return True
    # Token-level fallback so compound categories (e.g. "epoch-boundary-rounding")
    # still classify read-class without an exact frozenset entry.
    blob = cat + " " + fam
    return any(tok in blob for tok in (
        "conservation", "monoton", "bounds", "boundary", "round",
        "freshness", "epoch", "off-by-one", "off_by_one"))


FUNC_RE = {
    "solidity": re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE),
    "rust": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]", re.MULTILINE),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", re.MULTILINE),
    "move": re.compile(r"\b(?:public\s+|entry\s+|native\s+)*fun\s+([A-Za-z_]\w*)", re.MULTILINE),
    "cairo": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]", re.MULTILINE),
    # F1 zk: circom declares circuit logic with `template` (and helper
    # `function`); noir uses `fn`. zokrates uses `def` for functions.
    "circom": re.compile(r"\b(?:template|function)\s+([A-Za-z_]\w*)", re.MULTILINE),
    "noir": re.compile(r"\bfn\s+([A-Za-z_]\w*)", re.MULTILINE),
    "zokrates": re.compile(r"\bdef\s+([A-Za-z_]\w*)", re.MULTILINE),
}


@dataclass
class TargetFunction:
    name: str
    file: str
    line: int
    body_window: str
    # visibility: "internal" for private/internal helpers (Solidity
    # internal/private, Rust/Go/Move/Cairo unexported fns), "external" for
    # public/external/exported entrypoints. Defaults to "external" when the
    # language regex cannot disambiguate (conservative: only ADD internal
    # candidates, never drop external ones).
    visibility: str = "external"
    # is_view: True for pure-read helpers (Solidity view/pure, Rust fns that
    # take no `&mut`, Move fns that neither take `&mut` nor `acquires`). Used by
    # iter10-B so READ-class invariant families (conservation/monotonicity/
    # bounds/epoch-boundary/rounding/freshness) ALSO anchor to internal VIEW
    # helpers - the byte-position scan tends to land on the mutating entrypoint
    # and skip the view helper that actually computes the contested quantity.
    # Conservative default False: only ADD view candidates, never drop others.
    is_view: bool = False


# Per-language detection of an INTERNAL/private function declaration. The
# enumeration of internal functions is GENERAL: any function the language marks
# as internal/private/unexported counts, regardless of name. No symbol names are
# hard-coded - the fix is "internal functions were being skipped as anchor
# targets; now they are enumerated class-level".
#   solidity: a fn carrying the `internal` or `private` visibility specifier.
#   rust/cairo: a fn NOT preceded by `pub` (module-private).
#   go: an unexported fn (name begins with a lowercase letter).
#   move: a fn NOT marked `public`/`entry` (module-internal).
_SOL_INTERNAL_RE = re.compile(r"\b(internal|private)\b")
_RUST_PUB_RE = re.compile(r"\bpub\b")
_MOVE_PUBLIC_RE = re.compile(r"\b(public|entry)\b")


def _detect_visibility(lang: str, name: str, decl_prefix: str,
                       sig_window: str) -> str:
    """Classify a function as 'internal' or 'external' from its declaration.

    decl_prefix is the small slice of source immediately BEFORE the function
    keyword (where Rust/Move place `pub`/`public`); sig_window is the slice
    immediately AFTER the name (where Solidity places `internal`/`private`).
    Conservative default is 'external' so the new internal-fn enumeration only
    ADDS candidates and never removes the existing nearest-fn behavior.
    """
    if lang == "solidity":
        # Solidity visibility sits between the param list and the body, e.g.
        # `function _f(uint x) internal returns (...)`. Look in the signature
        # window up to the opening brace.
        head = sig_window.split("{", 1)[0]
        return "internal" if _SOL_INTERNAL_RE.search(head) else "external"
    if lang in ("rust", "cairo"):
        return "external" if _RUST_PUB_RE.search(decl_prefix) else "internal"
    if lang == "go":
        # Exported Go identifiers start with an uppercase letter.
        first = name[:1]
        return "external" if first.isupper() else "internal"
    if lang == "move":
        return "external" if _MOVE_PUBLIC_RE.search(decl_prefix) else "internal"
    return "external"


# Per-language detection of a pure-READ (view) function. GENERAL and class-free:
# no symbol names hard-coded - a fn is "view" iff the language's read-only marker
# is present in its signature window. Conservative: returns False whenever the
# read-only marker is absent or undetectable, so the iter10-B view-anchoring only
# ADDS candidates and never reclassifies a mutating fn as view.
#   solidity: `view` or `pure` between the param list and the body.
#   rust/cairo: signature takes no `&mut` receiver/arg (no `&mut` before `{`).
#   move: signature neither takes `&mut` nor declares `acquires` (no write path).
#   go: a keeper fn taking sdk.Context whose name reads as a getter/query/iter
#       (^Get|Has|Query|List|Iterate|Calc|Compute|View) and whose body has no
#       store write (store.Set/store.Delete) is a view-class helper. Otherwise
#       conservative False (no reliable marker).
_SOL_VIEW_RE = re.compile(r"\b(view|pure)\b")
_MUT_REF_RE = re.compile(r"&mut\b")
_MOVE_ACQUIRES_RE = re.compile(r"\bacquires\b")
_GO_VIEW_NAME_RE = re.compile(r"^(Get|Has|Query|List|Iterate|Calc|Compute|View)")
_GO_CONTEXT_RE = re.compile(r"sdk\.Context")
_GO_STORE_WRITE_RE = re.compile(r"\bstore\.(Set|Delete)\b")


def _detect_view(lang: str, sig_window: str, name: str = "") -> bool:
    head = sig_window.split("{", 1)[0]
    if lang == "solidity":
        return bool(_SOL_VIEW_RE.search(head))
    if lang in ("rust", "cairo"):
        return not _MUT_REF_RE.search(head)
    if lang == "move":
        return not (_MUT_REF_RE.search(head) or _MOVE_ACQUIRES_RE.search(head))
    if lang == "go":
        # name must read as a getter/query/iterate AND the fn must take an
        # sdk.Context AND its (windowed) body must not write to the store.
        if not _GO_VIEW_NAME_RE.match(name or ""):
            return False
        if not _GO_CONTEXT_RE.search(head):
            return False
        return not _GO_STORE_WRITE_RE.search(sig_window)
    return False


@dataclass
class TargetModel:
    source_root: str
    languages: list
    file_count: int
    function_count: int
    families_active: list
    functions: list = field(default_factory=list)
    corpus_blob_files: dict = field(default_factory=dict)


def _iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            ext = Path(fn).suffix.lower()
            if ext in LANG_BY_EXT:
                yield Path(dirpath) / fn


def build_target_model(source_root: Path, max_functions: int) -> TargetModel:
    # UNBOUNDED-QUEUE: max_functions <= 0 (or None) means "no cap - index every
    # in-scope function". Callers default to a positive int (12/200/2000) so the
    # bounded path is byte-for-byte unchanged; only the explicit opt-in
    # (--unbounded-queue / MAX_FUNCTIONS=all) routes a non-positive sentinel here.
    if max_functions is None or max_functions <= 0:
        max_functions = float("inf")
    langs = {}
    functions = []
    family_hits = {}
    file_count = 0
    blob_by_file = {}

    files = sorted(_iter_source_files(source_root))
    for fp in files:
        ext = fp.suffix.lower()
        lang = LANG_BY_EXT.get(ext)
        if not lang:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > 2_000_000:
            text = text[:2_000_000]
        file_count += 1
        langs[lang] = langs.get(lang, 0) + 1
        rel = str(fp.relative_to(source_root)) if _is_relative(fp, source_root) else str(fp)
        low = text.lower()
        blob_by_file[rel] = low

        for fam in FAMILIES:
            if any(tok in low for tok in fam.source_tokens):
                family_hits[fam.name] = family_hits.get(fam.name, 0) + 1

        fre = FUNC_RE.get(lang)
        if fre and len(functions) < max_functions:
            for m in fre.finditer(text):
                if len(functions) >= max_functions:
                    break
                start = m.start()
                line = text.count("\n", 0, start) + 1
                window = text[m.end(): m.end() + 600]
                # decl_prefix spans the modifiers a language can place before
                # AND on the function declaration: a small slice before the
                # match (Rust/Cairo `pub`) PLUS the matched declaration text
                # itself (Move `public`/`entry`/`native`, which FUNC_RE
                # captures as part of m.group(0)).
                decl_prefix = text[max(0, start - 24): start] + m.group(0)
                visibility = _detect_visibility(
                    lang, m.group(1), decl_prefix, window)
                is_view = _detect_view(lang, window, m.group(1))
                functions.append(TargetFunction(
                    name=m.group(1), file=rel, line=line, body_window=window,
                    visibility=visibility, is_view=is_view,
                ))

    languages = [l for l, _ in sorted(langs.items(), key=lambda kv: -kv[1])]
    families_active = [f for f, _ in sorted(family_hits.items(), key=lambda kv: -kv[1])]
    return TargetModel(
        source_root=str(source_root),
        languages=languages,
        file_count=file_count,
        function_count=len(functions),
        families_active=families_active,
        functions=functions,
        corpus_blob_files=blob_by_file,
    )


def _is_relative(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass
class Invariant:
    invariant_id: str
    category: str
    statement: str
    target_lang: str
    attack_signature: str
    commit_point_pattern: str
    defense_layer: str
    source_finding_ids: list
    source_file: str


def load_invariants(paths: list) -> list:
    out = []
    seen = set()
    for p in paths:
        if not p.exists():
            continue
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                continue
            iid = str(r.get("invariant_id") or "")
            if not iid or iid in seen:
                continue
            seen.add(iid)
            out.append(Invariant(
                invariant_id=iid,
                category=str(r.get("category") or "").lower(),
                statement=str(r.get("statement") or ""),
                target_lang=str(r.get("target_lang") or "any").lower(),
                attack_signature=str(r.get("attack_signature") or ""),
                commit_point_pattern=str(r.get("commit_point_pattern") or ""),
                defense_layer=str(r.get("defense_layer") or ""),
                source_finding_ids=list(r.get("source_finding_ids") or []),
                source_file=p.name,
            ))
    return out


def _warn_stale_corpus(corpus_paths: list) -> None:
    """Emit a stderr freshness-warn when the loaded corpus is stale.

    Stale = the newest loaded corpus file predates the audited freshness anchor
    (invariants_pilot_audited.jsonl). A miss means a re-harvest landed but the
    hunt is still reading a pre-harvest snapshot (the exact failure this lane
    fixes). Also warns once per relpath that was requested but is absent on disk.
    Best-effort: any I/O error is swallowed so the warn never blocks the hunt.
    """
    try:
        present = [p for p in corpus_paths if p.is_file()]
        for p in corpus_paths:
            if not p.is_file():
                sys.stderr.write(
                    "[corpus-fuel] WARN: requested corpus not found, skipped: "
                    + str(p) + "\n")
        if not present:
            return
        if _tcr is None or not hasattr(_tcr, "freshness_anchor_path"):
            return
        anchor = _tcr.freshness_anchor_path(repo_root_path=REPO_ROOT)
        if not anchor.is_file():
            return
        anchor_mtime = anchor.stat().st_mtime
        newest = max(p.stat().st_mtime for p in present)
        if newest < anchor_mtime:
            sys.stderr.write(
                "[corpus-fuel] WARN: loaded invariant corpus is STALE - newest "
                "loaded file predates the audited library "
                + anchor.name + " (newest_loaded_mtime=" + str(int(newest))
                + " < anchor_mtime=" + str(int(anchor_mtime)) + "); a re-harvest "
                "may have landed - repoint via "
                "trusted_corpus_resolver.resolve_active_invariant_corpora\n")
    except OSError:  # pragma: no cover - defensive
        pass


def _evidence_keywords(inv: Invariant) -> list:
    raw = " ".join([inv.commit_point_pattern, inv.defense_layer, inv.attack_signature])
    kws = set()
    for part in re.split(r"[\s/|,;]+", raw.lower()):
        part = part.strip("()[]{}.")
        if len(part) >= 4 and not part.isdigit():
            kws.add(part)
        # Also split compound hyphen/underscore tokens into atomic grep terms
        # (e.g. "verify-then-mark-consumed" -> consumed; "consumed_set" -> consumed).
        for atom in re.split(r"[-_]+", part):
            if len(atom) >= 4 and not atom.isdigit():
                kws.add(atom)
    stop = {"before", "after", "must", "that", "with", "from", "then", "have",
            "been", "into", "this", "same", "more", "than", "only", "each",
            "state", "mutation", "value", "values", "check", "checks"}
    return sorted(k for k in kws if k not in stop)


@dataclass
class Hypothesis:
    rank: int
    score: float
    invariant_id: str
    category: str
    family: str
    target_lang: str
    statement: str
    hypothesis: str
    evidence_keywords: list
    in_target_evidence: list
    candidate_functions: list
    corpus_source_ids: list
    need_more_evidence: bool
    differential_test_idea: str
    brain_prime_boost: float = 0.0


def _lang_match(inv: Invariant, target_langs: list) -> bool:
    if inv.target_lang in ("any", "", "*"):
        return True
    return inv.target_lang in target_langs


def _family_for_invariant(inv: Invariant) -> str:
    if inv.category in CATEGORY_TO_FAMILY:
        return CATEGORY_TO_FAMILY[inv.category]
    blob = (inv.attack_signature + " " + inv.statement).lower()
    # Score every family by signature-token match count; pick the strongest.
    # Ties broken by FAMILIES declaration order (stable).
    best_name, best_score = "general", 0
    for fam in FAMILIES:
        n = sum(1 for tok in fam.corpus_signature_tokens if tok in blob)
        if n > best_score:
            best_name, best_score = fam.name, n
    return best_name


def _family_fit(fam: str, families_active: list) -> float:
    if not families_active:
        return 0.3
    if fam in families_active:
        idx = families_active.index(fam)
        return 1.0 - min(idx, 4) * 0.12
    return 0.15


def _scan_evidence(keywords, target, per_kw_cap=3, total_cap=12,
                   read_class=False, family=None):
    hits = []
    cand_fns = {}
    fn_index = _function_index(target)
    for kw in keywords:
        if len(hits) >= total_cap:
            break
        kw_hits = 0
        for rel, blob in target.corpus_blob_files.items():
            if kw_hits >= per_kw_cap or len(hits) >= total_cap:
                break
            pos = blob.find(kw)
            if pos < 0:
                continue
            line = blob.count("\n", 0, pos) + 1
            fn = _nearest_fn(fn_index.get(rel, []), line)
            hits.append({"keyword": kw, "file": rel, "line": line, "fn": fn})
            kw_hits += 1
            if fn:
                key = (rel, fn[0])
                cand_fns.setdefault(key, {"fn": fn[0], "file": rel, "line": fn[1]})

    # iter9-B fix: ALSO anchor class-matched hypotheses to INTERNAL/private
    # functions whose OWN NAME matches the invariant's class keywords. The
    # nearest-preceding-fn loop above tends to land on the large external
    # entrypoint where a keyword first appears, skipping the internal helper
    # (e.g. an internal validating/settling fn) that actually carries the bug.
    # This is GENERAL: it enumerates ANY internal fn whose name contains a class
    # keyword, no symbol names hard-coded. Internal candidates are appended so
    # the existing external-anchor behavior is preserved and never reduced.
    # iter11-B: pass the set of files where this hypothesis already has byte-hit
    # evidence so the read-class view pass can PREFER view helpers in those same
    # files (the hypothesis is already localized there). This keeps the exact
    # bug helper from being crowded out on dense trees with many same-class view
    # getters elsewhere. General: a file-set, not a symbol list.
    evidence_files = {h["file"] for h in hits if h.get("file")}
    name_cands = _internal_fn_candidates(
        keywords, target, read_class=read_class,
        evidence_files=evidence_files)

    # iter14: CLASS-FAMILY NAME ANCHORING (the INV-CON-004 mislanding fix).
    # The two passes above anchor by (a) the byte-position nearest-fn of an
    # invariant LITERAL keyword and (b) internal/view helpers whose name matches
    # a literal keyword. Both miss the very common case where the real bug
    # function is an EXTERNAL function whose OWN NAME carries the CLASS signal
    # (validator/distribution/weight/epoch/reward/normalize) but NOT one of the
    # invariant's literal grep keywords - so the conservation hypothesis's only
    # byte-hit lands on an unrelated handler in a dense file
    # (ibc_packet_handlers.go) and the real distribution/validator function is
    # never enumerated. This pass enumerates ANY function (any visibility) whose
    # name carries a token from the hypothesis's CLASS-FAMILY vocabulary
    # (Family.source_tokens, widened for the accounting family). GENERAL and
    # class-keyed: the vocabulary is the open class-signal token set the tool
    # already uses to fingerprint the target; no target symbol names are
    # hard-coded. Additive: it only ADDS candidates.
    family_name_cands = _family_name_fn_candidates(
        family, target, evidence_files=evidence_files)

    # Build the final candidate list with a priority order that keeps the
    # structurally-correct, on-class anchor inside the 8-candidate cap:
    #   1. family-name anchors that sit IN an evidence file (most localized).
    #   2. read-class VIEW helpers in an evidence file (iter11-B).
    #   3. family-name anchors anywhere (on-class even without a same-file hit).
    #   4. byte-position nearest-fn anchors (the original behavior).
    #   5. remaining internal/view name candidates.
    # GENERAL: every tier is gated on a class/family signal or a file-set, never
    # on a symbol name. The non-class path (family=None) skips tiers 1 and 3 and
    # is byte-for-byte unchanged from prior behavior.
    fam_priority = []     # tier 1
    view_priority = []    # tier 2
    fam_rest = []         # tier 3
    name_rest = []        # tier 5
    for fc in family_name_cands:
        key = (fc["file"], fc["fn"])
        if key in cand_fns:
            continue
        if fc.get("file") in evidence_files:
            fam_priority.append((key, fc))
        else:
            fam_rest.append((key, fc))
    fam_keys = {k for k, _ in fam_priority} | {k for k, _ in fam_rest}
    for ic in name_cands:
        key = (ic["file"], ic["fn"])
        if key in cand_fns or key in fam_keys:
            continue
        if (read_class and ic.get("view")
                and ic.get("file") in evidence_files):
            view_priority.append((key, ic))
        else:
            name_rest.append((key, ic))

    final = {}
    for key, ic in fam_priority:    # tier 1
        final.setdefault(key, ic)
    for key, ic in view_priority:   # tier 2
        final.setdefault(key, ic)
    for key, ic in fam_rest:        # tier 3
        final.setdefault(key, ic)
    for key, ic in cand_fns.items():  # tier 4 (byte-position)
        final.setdefault(key, ic)
    for key, ic in name_rest:       # tier 5
        final.setdefault(key, ic)
    return hits, list(final.values())[:8]


def _family_name_fn_candidates(family, target, cap=6, evidence_files=None):
    """Enumerate functions whose OWN NAME carries a CLASS-FAMILY token for the
    hypothesis's family, at ANY visibility. Returns candidate-function dicts
    flagged ``family_anchor=True`` and ``matched_keyword=<token>``.

    This is the iter14 general fix for the INV-CON-004 mislanding: the real bug
    function for a conservation/normalization hypothesis is frequently named for
    the conserved quantity (a validator-set distribution, an epoch reward
    accrual, a weight normalization, an intents settlement) rather than for the
    invariant's literal grep keyword, so neither the byte-position scan nor the
    literal-keyword name pass surfaces it. Matching the function NAME against the
    open class-family vocabulary anchors the structurally-correct function.

    GENERAL and class-keyed: ``_family_name_tokens`` returns the same open
    class-signal vocabulary the tool already uses to fingerprint the target -
    no target-specific symbol names are hard-coded. Deterministic: functions are
    scanned in source order; same-evidence-file matches are kept first so the
    localized anchor is never crowded out, then the rest in source order, capped.
    """
    if not family:
        return []
    fam_tokens = _family_name_tokens(family)
    if not fam_tokens:
        return []
    ev_files = evidence_files or set()
    same_file = []
    other = []
    for f in target.functions:
        low = f.name.lower()
        matched = next((t for t in fam_tokens if t in low), None)
        if matched is None:
            continue
        rec = {"fn": f.name, "file": f.file, "line": f.line,
               "internal": getattr(f, "visibility", "external") == "internal",
               "view": bool(getattr(f, "is_view", False)),
               "family_anchor": True, "matched_keyword": matched}
        if f.file in ev_files:
            same_file.append(rec)
        else:
            other.append(rec)
    return (same_file + other)[:cap]


def _internal_fn_candidates(keywords, target, cap=4, read_class=False,
                            view_cap=6, evidence_files=None):
    """Enumerate internal/private functions whose own name matches a class
    keyword. Returns candidate-function dicts flagged ``internal=True``.

    The match is name-level: the function's lowercased name must contain one of
    the class keywords. This surfaces internal helpers (validators, settlers,
    finalizers) the byte-position nearest-fn scan would otherwise skip in favor
    of the external entrypoint. Deterministic: scanned in source order, capped.

    iter10-B: when ``read_class`` is True the hypothesis is a READ-class
    invariant (conservation/monotonicity/bounds/epoch-boundary/rounding/
    freshness). iter9-B's pass already enumerates internal helpers regardless of
    view/mutating, but it is name-capped at ``cap`` and a mutating internal
    helper can crowd out the VIEW helper that actually computes the contested
    quantity (an epoch-boundary timestamp, a conserved total, a rounded share).
    So for read-class hypotheses we run a SECOND, independent pass that
    enumerates VIEW (pure-read) helpers whose name matches a class keyword and
    tags them ``view=True``. GENERAL and class-level: the read-class gate is
    keyed on the invariant CLASS, and the per-fn match is name-level - no symbol
    names are hard-coded.

    iter11-B: Pass 2 now enumerates VIEW helpers at ANY visibility (internal/
    private AND public/external), not internal-only. A pure-READ helper that
    COMPUTES the contested quantity is the correct read-class anchor whether it
    is marked ``internal view`` or ``public view`` - the visibility of a getter
    does not change that it is the function whose computed result the invariant
    constrains. The iter10 fresh-target measurement proved the internal-only
    gate missed exactly this case: the M-02 anchor ``totalBondedBalanceAtEpochEnd``
    (public view) and the unbiased Predy ``getSqrtPrice`` (external view) both
    compute the contested read-class quantity yet were skipped because Pass 2
    required ``visibility == "internal"``. This pass stays VIEW-only and additive
    (it only ADDS view candidates, never drops or reclassifies a mutating fn or
    an existing external anchor), so the change cannot reduce prior behavior.
    """
    kw_set = {k for k in keywords if len(k) >= 4}
    if not kw_set:
        return []
    out = []
    # Pass 1 (iter9-B): internal helpers by name, view or mutating.
    for f in target.functions:
        if getattr(f, "visibility", "external") != "internal":
            continue
        low = f.name.lower()
        matched = next((k for k in kw_set if k in low), None)
        if matched is None:
            continue
        out.append({"fn": f.name, "file": f.file, "line": f.line,
                    "internal": True, "view": bool(getattr(f, "is_view", False)),
                    "matched_keyword": matched})
        if len(out) >= cap:
            break

    if not read_class:
        return out

    # Pass 2 (iter10-B + iter11-B): for READ-class hypotheses, ensure VIEW
    # helpers are enumerated even if Pass 1's name cap was filled by mutating
    # helpers. iter11-B widens this pass from internal-only to ANY visibility
    # (internal/private AND public/external) view helper, because a public-view
    # getter that computes the contested quantity is just as much the read-class
    # anchor as an internal one. Dedup against Pass 1 by (file, fn). Independent
    # view_cap so a view helper is never crowded out by the mutating cap.
    #
    # iter11-B relevance ranking: when a dense target carries many view helpers
    # sharing one class token (the Intuition emissions tree has 37 epoch-named
    # view fns; the Predy tree has many *SqrtPrice* getters), a flat source-order
    # scan capped at ``view_cap`` lets unrelated same-class getters crowd out the
    # specific helper that computes the contested quantity. So we COLLECT every
    # matching view candidate with a deterministic relevance score and keep the
    # top ``view_cap``. Score, highest factor first:
    #   (1) SAME-FILE-AS-EVIDENCE: the hypothesis already has a byte-hit in this
    #       file, so a view helper there is the localized read-class anchor. This
    #       dominates - it is what keeps `getSqrtPrice` (PriceFeed.sol, the only
    #       evidence file) from being outranked by `getSqrtIndexPrice` getters in
    #       other files.
    #   (2) invariant-keyword match (stronger than a generic token).
    #   (3) number of DISTINCT generic compute tokens in the name (a richer name
    #       like `_calculateEpochTimestampEnd` = epoch+timestamp+end+calc is a
    #       stronger anchor than `getBalance`).
    # GENERAL: scored on a file-set + token COUNT, no symbol names hard-coded.
    # Ties broken by source order (stable).
    ev_files = evidence_files or set()
    seen = {(c["file"], c["fn"]) for c in out}
    scored = []
    for order, f in enumerate(target.functions):
        # iter11-B: no visibility gate here - view helpers at any visibility are
        # eligible read-class anchors. (Pass 1 stays internal-only for mutating
        # helpers; an external MUTATING entrypoint is already the byte-scan's
        # natural anchor and does not need this pass.)
        if not getattr(f, "is_view", False):
            continue
        if (f.file, f.name) in seen:
            continue
        low = f.name.lower()
        # iter11-B: match EITHER the invariant's own corpus keywords OR a generic
        # read-class computation token. The generic-token arm is what surfaces a
        # numeric-computing view helper (getSqrtPrice, totalBondedBalanceAtEpochEnd)
        # whose name does not contain the corpus keyword but which computes the
        # exact contested read-class quantity.
        kw_match = next((k for k in kw_set if k in low), None)
        generic_tokens = [t for t in READ_CLASS_VIEW_NAME_TOKENS if t in low]
        if kw_match is None and not generic_tokens:
            continue
        same_file = 1 if f.file in ev_files else 0
        relevance = (10000 * same_file
                     + (100 if kw_match is not None else 0)
                     + len(generic_tokens))
        matched = kw_match if kw_match is not None else generic_tokens[0]
        scored.append((relevance, order, f, matched))

    # Highest relevance first; stable on source order for ties.
    scored.sort(key=lambda t: (-t[0], t[1]))
    for _rel, _order, f, matched in scored[:view_cap]:
        vis_internal = getattr(f, "visibility", "external") == "internal"
        out.append({"fn": f.name, "file": f.file, "line": f.line,
                    "internal": vis_internal, "view": True,
                    "matched_keyword": matched})
        seen.add((f.file, f.name))
    return out


def _function_index(target):
    idx = {}
    for f in target.functions:
        idx.setdefault(f.file, []).append((f.name, f.line))
    for v in idx.values():
        v.sort(key=lambda t: t[1])
    return idx


def _nearest_fn(fns, line):
    best = None
    for name, fline in fns:
        if fline <= line:
            best = (name, fline)
        else:
            break
    return best


def materialize(invariants, target, top, brain_prime_seed=None):
    scored = []
    for inv in invariants:
        if not _lang_match(inv, target.languages):
            continue
        fam = _family_for_invariant(inv)
        fit = _family_fit(fam, target.families_active)
        kws = _evidence_keywords(inv)
        read_class = _is_read_class(inv.category, fam)
        hits, cand_fns = _scan_evidence(kws, target, read_class=read_class,
                                        family=fam)
        corpus_w = min(len(inv.source_finding_ids), 6) / 6.0
        ev_w = min(len(hits), 6) / 6.0
        lang_exact = 0.0 if inv.target_lang in ("any", "", "*") else 0.25
        base_score = round(
            0.40 * fit + 0.30 * ev_w + 0.20 * corpus_w
            + lang_exact * (1.0 if ev_w > 0 else 0.4),
            4,
        )
        need_more = len(hits) == 0
        h = Hypothesis(
            rank=0,
            score=base_score,
            invariant_id=inv.invariant_id,
            category=inv.category,
            family=fam,
            target_lang=inv.target_lang,
            statement=inv.statement,
            hypothesis=_phrase_hypothesis(inv, target, hits, cand_fns),
            evidence_keywords=kws[:12],
            in_target_evidence=hits,
            candidate_functions=cand_fns,
            corpus_source_ids=inv.source_finding_ids[:6],
            need_more_evidence=need_more,
            differential_test_idea=_phrase_differential(inv),
        )
        # ADD-D: brain-prime seed boost aligns the corpus hunt with the
        # priming step's prioritized attack-class lanes.
        if brain_prime_seed is not None:
            boost = _brain_prime_boost(h, brain_prime_seed)
            if boost:
                h.brain_prime_boost = boost
                h.score = round(h.score + boost, 4)
        scored.append(h)

    scored.sort(key=lambda h: (-h.score, h.need_more_evidence, h.invariant_id))
    # top=None -> UNBOUNDED-QUEUE: keep every materialized hypothesis. A positive
    # int caps to the top-N as before (bounded default unchanged).
    kept = scored if top is None else scored[:top]
    for i, h in enumerate(kept, start=1):
        h.rank = i
    return kept


def _phrase_hypothesis(inv, target, hits, cand_fns):
    where = ""
    if cand_fns:
        where = " e.g. `{fn}` ({file}:{line})".format(**cand_fns[0])
    elif hits:
        where = " near {file}:{line}".format(**hits[0])
    stmt = inv.statement.rstrip(".")
    if hits:
        return ("Verify in " + target.source_root + ": " + stmt + ". "
                "Corpus invariant " + inv.invariant_id + " fires here" + where + "; "
                "check the " + (inv.defense_layer or "defense") + " actually holds on this path.")
    return ("Verify in " + target.source_root + ": " + stmt + ". "
            "Corpus invariant " + inv.invariant_id + " (" + inv.category + ") is family-relevant "
            "but no in-target token evidence was found - manual confirmation needed.")


def _phrase_differential(inv):
    cp = inv.commit_point_pattern or "the protected operation"
    dl = inv.defense_layer or "the guard"
    return ("Differential: run the normal path (where " + dl + " is present) vs a path "
            "that reaches " + cp + " with " + dl + " absent/bypassed; assert the invariant "
            "'" + inv.statement.rstrip(".") + "' still holds.")


def build_mimo_batch(hyps, target, workspace_name, concurrency, unbounded=False):
    # DEFAULT (unbounded=False): byte-for-byte unchanged - clamp concurrency to
    # 4 and emit only the top-`concurrency` hypotheses as tasks.
    #
    # UNBOUNDED-QUEUE (unbounded=True, opt-in): emit ONE task per hypothesis (no
    # hyps[:concurrency] truncation) so the full in-scope hypothesis set reaches
    # the expensive per-fn layer. Throttling is NOT this generator's job in
    # unbounded mode - the downstream dispatcher
    # (tools/llm-fanout-dispatcher.py) is the rate-limiter via its
    # --concurrency / --budget-cap-usd / --per-task-timeout-s knobs, and
    # tools/hunt-resume-planner.py is the checkpoint/resume layer. `concurrency`
    # is still recorded in the batch so the operator can pass it straight to the
    # dispatcher as the inter-batch concurrency cap.
    selected = hyps if unbounded else hyps[:max(1, min(concurrency, 4))]
    if not unbounded:
        concurrency = max(1, min(concurrency, 4))
    tasks = []
    for h in selected:
        ev_lines = "\n".join(
            "- " + e["keyword"] + " @ " + e["file"] + ":" + str(e["line"])
            + ((" (fn " + e["fn"][0] + ")") if e.get("fn") else "")
            for e in h.in_target_evidence[:6]
        ) or "(no in-target token evidence; confirm or refute presence)"
        prompt = "\n".join([
            "You are auditing a real codebase. Confirm or REFUTE one corpus-sourced hypothesis.",
            "Return STRICT JSON: {verdict, confidence, file_line, code_excerpt, reasoning}.",
            "verdict in {CONFIRMED, REFUTED, NEEDS_MANUAL}. A miss is a miss - do not invent code.",
            "",
            "Target source root: " + target.source_root,
            "Target languages: " + (", ".join(target.languages) or "unknown"),
            "Corpus invariant: " + h.invariant_id + " (" + h.category + " / family=" + h.family + ")",
            "Invariant statement: " + h.statement,
            "Hypothesis: " + h.hypothesis,
            "Differential test idea: " + h.differential_test_idea,
            "In-target evidence already found (grep):",
            ev_lines,
            "",
            "Read the cited file:line. If the code_excerpt you cite is not actually",
            "present in the target tree, set verdict=NEEDS_MANUAL and say so.",
        ])
        tasks.append({
            "task_id": "corpus_hunt_" + workspace_name + "_" + ("%03d" % h.rank),
            "task_type": "corpus_driven_hypothesis_verify",
            "workspace": workspace_name,
            "workspace_path": target.source_root,
            "source_question_id": h.invariant_id,
            "attack_class": h.family,
            "prompt": prompt,
            "max_tokens": 1200,
        })
    out = {
        "schema": "auditooor.corpus_driven_hunt_mimo_batch.v1",
        "workspace": workspace_name,
        "concurrency": concurrency,
        "task_count": len(tasks),
        "note": ("MIMO is a batch fanout in this repo (llm-fanout-dispatcher.py); "
                 "dispatch these tasks, do not block on a synchronous model call."),
        "tasks": tasks,
    }
    if unbounded:
        # NO-SILENT-CAPS: in unbounded mode every hypothesis is queued, so
        # surface the full denominator. `mimo_pending` is the count not yet
        # dispatched/verified (== task_count at generation time); a downstream
        # resume run drives it toward 0. `hypotheses_total` is the honest
        # denominator the operator compares coverage against.
        out["unbounded"] = True
        out["hypotheses_total"] = len(hyps)
        out["mimo_pending"] = len(tasks)
        out["throttle_note"] = (
            "Throttle/resume/budget are NOT applied here. Dispatch via "
            "llm-fanout-dispatcher.py --concurrency N --budget-cap-usd C "
            "--per-task-timeout-s T; on rate-limit/budget-halt, replan with "
            "hunt-resume-planner.py --record-dir <out> --original-batch <batch>."
        )
    return out


# --------------------------------------------------------------------------
# ADD-D: brain-prime seed gate
# --------------------------------------------------------------------------

@dataclass
class BrainPrimeSeed:
    present: bool
    path: str
    schema_valid: bool
    lane_attack_classes: list = field(default_factory=list)
    seed_tokens: list = field(default_factory=list)
    gate: str = "fail"            # pass | pass-override | fail
    reason: str = ""


def load_brain_prime_seed(workspace: Path, explicit, gate_enabled: bool) -> BrainPrimeSeed:
    """Load the brain-prime receipt and extract attack-class seed tokens.

    The seed gate REQUIRES the receipt vault_brain_prime_context reads. Its
    top_phase_f_lanes attack-classes seed the hypothesis ranking. When the
    receipt is missing and the gate is enabled, gate=fail (the caller treats
    this as a hard stop). With --no-brain-prime-gate, gate=pass-override and
    the run proceeds with an empty seed (audit-logged).
    """
    if explicit:
        p = Path(explicit)
        if not p.is_absolute():
            p = (workspace / p).resolve()
    else:
        p = workspace / DEFAULT_BRAIN_PRIME_RECEIPT

    if not p.exists():
        if not gate_enabled:
            return BrainPrimeSeed(
                present=False, path=str(p), schema_valid=False,
                gate="pass-override",
                reason="brain-prime receipt missing; --no-brain-prime-gate override active",
            )
        return BrainPrimeSeed(
            present=False, path=str(p), schema_valid=False, gate="fail",
            reason=("brain-prime receipt not found at " + str(p)
                    + "; run brain-prime.py / vault_brain_prime_context first "
                    "or pass --no-brain-prime-gate"),
        )

    try:
        raw = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        if not gate_enabled:
            return BrainPrimeSeed(
                present=True, path=str(p), schema_valid=False,
                gate="pass-override",
                reason="brain-prime receipt unreadable (" + str(exc) + "); override active",
            )
        return BrainPrimeSeed(
            present=True, path=str(p), schema_valid=False, gate="fail",
            reason="brain-prime receipt unreadable: " + str(exc),
        )

    schema_valid = raw.get("schema") == BRAIN_PRIME_RECEIPT_SCHEMA
    lanes = raw.get("top_phase_f_lanes") or []
    attack_classes = []
    tokens = set()
    for lane in lanes:
        if not isinstance(lane, dict):
            continue
        ac = str(lane.get("attack_class") or "")
        if ac:
            attack_classes.append(ac)
            for atom in re.split(r"[\s/_\-:.]+", ac.lower()):
                if len(atom) >= 4 and not atom.isdigit():
                    tokens.add(atom)
    return BrainPrimeSeed(
        present=True, path=str(p), schema_valid=schema_valid,
        lane_attack_classes=attack_classes[:24],
        seed_tokens=sorted(tokens)[:48],
        gate="pass",
        reason=("brain-prime receipt loaded; " + str(len(attack_classes))
                + " seed lane(s)"),
    )


def _brain_prime_boost(h: "Hypothesis", seed: BrainPrimeSeed) -> float:
    """Ranking boost when a hypothesis aligns with a brain-prime seed lane.

    Match on family-name tokens, category tokens, or evidence keywords vs the
    seed tokens lifted from top_phase_f_lanes. Bounded to +0.15.
    """
    if not seed.seed_tokens:
        return 0.0
    seed_set = set(seed.seed_tokens)
    hay = set()
    for piece in (h.family, h.category):
        for atom in re.split(r"[\s/_\-:.]+", (piece or "").lower()):
            if len(atom) >= 4:
                hay.add(atom)
    for kw in h.evidence_keywords:
        if len(kw) >= 4:
            hay.add(kw.lower())
    overlap = len(hay & seed_set)
    if overlap <= 0:
        return 0.0
    return round(min(0.15, 0.05 * overlap), 4)


# --------------------------------------------------------------------------
# ADD-D: per-function hacker-questions fold-in (vault_hacker_questions)
# --------------------------------------------------------------------------

@dataclass
class HackerQuestionHit:
    question_id: str
    question_text: str
    attack_class: str
    matched_functions: list
    grep_patterns: list
    linked_invariant_ids: list
    source: str
    binding_invariant_id: str = ""


def load_hacker_questions(path: Path) -> list:
    out = []
    if not path.exists():
        return out
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            r = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        out.append(r)
    return out


def _compile_safe(patterns):
    compiled = []
    for pat in patterns:
        if not isinstance(pat, str) or not pat:
            continue
        try:
            compiled.append(re.compile(pat))
        except re.error:
            # treat as a plain substring needle
            compiled.append(re.compile(re.escape(pat)))
    return compiled


def match_hacker_questions(questions, target, lang_set, per_q_fn_cap=6,
                           max_questions=40) -> list:
    """Match each library question's function/grep patterns against the target
    functions. Emit only questions with >=1 matched in-scope function so the
    proof queue carries real per-fn obligations, not the whole library.
    """
    hits = []
    fn_records = [(f.name, f.file, f.line, (f.name + "\n" + f.body_window).lower())
                  for f in target.functions]
    for q in questions:
        if len(hits) >= max_questions:
            break
        qlang = str(q.get("target_language") or "any").lower()
        if qlang not in ("any", "", "*") and lang_set and qlang not in lang_set:
            continue
        fn_pats = q.get("target_function_patterns") or []
        grep_pats = q.get("grep_patterns") or []
        needles = _compile_safe(list(fn_pats) + list(grep_pats))
        if not needles:
            continue
        matched = []
        for (name, fpath, line, blob) in fn_records:
            if len(matched) >= per_q_fn_cap:
                break
            if any(rx.search(name) or rx.search(blob) for rx in needles):
                matched.append({"fn": name, "file": fpath, "line": line})
        if not matched:
            continue
        linked = list(dict.fromkeys(
            str(i).strip() for i in (q.get("linked_invariant_ids") or [])
            if isinstance(i, str) and i.strip()
        ))[:8]
        common = {
            "question_id": str(q.get("question_id") or ""),
            "question_text": str(q.get("question_text") or ""),
            "attack_class": str(q.get("attack_class_anchor")
                                or q.get("attack_class") or "unknown"),
            "matched_functions": matched,
            "grep_patterns": [str(g) for g in grep_pats][:8],
            "source": str(q.get("source_case_study") or q.get("source_incident_id") or ""),
        }
        # Every linked invariant becomes a separate proof obligation. This is
        # an explicit corpus relation, not a similarity expansion. Keep an
        # unlinked question visible so strict mode fails before output instead
        # of silently dropping a question with no reasoner parent.
        if not linked:
            hits.append(HackerQuestionHit(linked_invariant_ids=[], **common))
        for invariant_id in linked:
            hits.append(HackerQuestionHit(
                linked_invariant_ids=[invariant_id],
                binding_invariant_id=invariant_id,
                **common,
            ))
    return hits


# --------------------------------------------------------------------------
# PR7a: MANDATORY proof-queue emission (UPSERT into exploit_queue.json)
# --------------------------------------------------------------------------

def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _empty_exploit_queue(workspace_name: str) -> dict:
    return {
        "schema": "auditooor.exploit_queue.v1",
        "generated_at_utc": _utc_now(),
        "workspace": workspace_name,
        "top_n": 0,
        "total_candidates": 0,
        "context_pack_hash": "",
        "context_pack_id": "",
        "benchmark": {},
        "source_artifacts_consumed": [],
        "queue": [],
    }


def _load_exploit_queue(queue_path: Path, workspace_name: str) -> dict:
    if not queue_path.exists():
        return _empty_exploit_queue(workspace_name)
    try:
        return json.loads(queue_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return _empty_exploit_queue(workspace_name)


# Cross-wire #14: map the corpus invariant FAMILY to a canonical impact class +
# a severity HINT, so a corpus-hunt lead carries a structured impact instead of a
# hardcoded "unknown" that the severity oracle (cross-wire #5) cannot key on. The
# vocab matches tools/hacker_question_renderer + exploit-queue impact_class (#4).
# Conservative: an unmapped family stays ("unknown","unknown") = legacy behavior.
_FAMILY_TO_IMPACT = {
    "accounting_conservation": ("direct-theft-funds", "high"),
    "reentrancy_atomicity": ("direct-theft-funds", "high"),
    "bridge_replay": ("direct-theft-funds", "high"),
    "move_resource_model": ("direct-theft-funds", "high"),
    "account_model": ("direct-theft-funds", "high"),
    "access_control": ("access-control-bypass", "high"),
    "crypto_signing": ("access-control-bypass", "high"),
    "state_freshness": ("protocol-insolvency", "medium"),
    "consensus_state_machine": ("griefing-dos", "medium"),
}


def _family_to_impact(family: str) -> tuple[str, str]:
    """(impact_class, likely_severity_hint) for a corpus family; unmapped -> unknown."""
    return _FAMILY_TO_IMPACT.get((family or "").strip().lower(), ("unknown", "unknown"))


def _proof_row_base(lead_id, title, attack_class, impact_path, root_cause,
                    source_refs, source, impact_class="unknown",
                    likely_severity="unknown") -> dict:
    """Build a proof-status=open exploit_queue row mirroring the canonical
    schema used by preflight-to-exploit-queue.py. impact_class/likely_severity
    default to the legacy "unknown" so callers that do not classify are unchanged."""
    return {
        "lead_id": lead_id,
        "title": title,
        "attack_class": attack_class,
        "likely_severity": likely_severity,
        "severity_confidence": "low",
        "proof_status": "open",
        "proof_shell": "unknown",
        "proof_path": "unknown",
        "required_proof_path": "unknown",
        "quality_gate_status": "open",
        "impact_path": impact_path,
        "impact_class": impact_class,
        "root_cause_hypothesis": root_cause,
        "learning_route": source,
        "attacker_role": "unknown",
        "attacker_control": "unknown",
        "victim_role": "unknown",
        "asset_at_risk": "unknown",
        "dupe_risk": "unknown",
        "blockers": [],
        "falsification_requirements": [],
        "impact_contract_gaps": [],
        "impact_contract_status": "missing",
        "likely_triager_objection": "",
        "mcp_context_ids": [],
        "metric_integrity_refs": [],
        "multi_validator_requirement": "",
        "negative_control": "",
        "next_command": "",
        "priority_score": 0.0,
        "production_path_requirement": "",
        "proof_artifact_precedent_refs": [],
        "provider_tasks_run": [],
        "restart_requirement": "",
        "source_artifact_gaps": [],
        "source_artifact_path": "",
        "source_artifacts_complete": False,
        "source_mined_proof_status": "open",
        "source_refs": list(source_refs),
        "synthetic_state_risk": "",
        "truth_table_complete": False,
        "truth_table_summary": {},
        "broken_invariant_ids": [],
        "chain_template_ids": [],
        "source": source,
        "contract": "",
        "function": "",
    }


def _hypothesis_to_row(h: "Hypothesis", workspace_name: str) -> dict:
    cf = h.candidate_functions[0] if h.candidate_functions else {}
    contract = str(cf.get("file") or "")
    function = str(cf.get("fn") or "")
    slug = (h.invariant_id + "-" + (function or h.family)).replace(".", "-")[:48]
    lead_id = "F-CORPUS-" + slug
    impact_path = ((contract + "." + function) if (contract and function)
                   else (h.invariant_id))
    title = ("corpus-hunt-fuel: " + h.invariant_id + " (" + h.family + ") "
             + ("@ " + function if function else "no in-target fn"))
    _imp_cls, _imp_sev = _family_to_impact(h.family)
    row = _proof_row_base(
        lead_id=lead_id,
        title=title,
        attack_class=h.family,
        impact_path=impact_path,
        root_cause=("corpus invariant " + h.invariant_id + ": " + h.statement.rstrip(".")),
        source_refs=h.corpus_source_ids[:6],
        source=CORPUS_HUNT_FUEL_SOURCE,
        impact_class=_imp_cls,
        likely_severity=_imp_sev,
    )
    row["broken_invariant_ids"] = [h.invariant_id]
    row["contract"] = contract
    row["function"] = function
    row["priority_score"] = round(float(h.score), 4)
    row["negative_control"] = h.differential_test_idea
    # need_more_evidence hypotheses are still MANDATORY proof obligations;
    # they carry a manual-confirm flag rather than being dropped.
    row["source_artifacts_complete"] = not h.need_more_evidence
    return row


def _hacker_q_to_row(hit: HackerQuestionHit, workspace_name: str) -> dict:
    mf = hit.matched_functions[0] if hit.matched_functions else {}
    contract = str(mf.get("file") or "")
    function = str(mf.get("fn") or "")
    qid = hit.question_id or "HQ"
    binding = hit.binding_invariant_id or "unbound"
    slug = (qid + "-" + binding + "-" + (function or hit.attack_class)).replace(".", "-")[:48]
    lead_id = "F-CORPUS-HQ-" + slug
    impact_path = ((contract + "." + function) if (contract and function) else qid)
    title = ("corpus-hunt-hacker-q: " + qid + " (" + hit.attack_class + ") "
             + ("@ " + function if function else ""))
    refs = [binding] if hit.binding_invariant_id else list(hit.linked_invariant_ids)
    if hit.source:
        refs = refs + [hit.source]
    _imp_cls, _imp_sev = _family_to_impact(hit.attack_class)
    row = _proof_row_base(
        lead_id=lead_id,
        title=title,
        attack_class=hit.attack_class,
        impact_path=impact_path,
        root_cause=("hacker-question " + qid + ": " + hit.question_text),
        source_refs=refs[:6],
        source=CORPUS_HUNT_HACKER_Q_SOURCE,
        impact_class=_imp_cls,
        likely_severity=_imp_sev,
    )
    row["broken_invariant_ids"] = [binding] if hit.binding_invariant_id else []
    row["binding_invariant_id"] = hit.binding_invariant_id
    row["contract"] = contract
    row["function"] = function
    row["next_command"] = ("grep -rn '" + "|".join(hit.grep_patterns[:4]) + "' "
                           if hit.grep_patterns else "")
    return row


def _dedup_key(row: dict) -> str:
    src = row.get("source", "")
    # corpus-hunt rows dedup by lead_id (invariant/question + fn), so the same
    # invariant on the same function never duplicates across reruns.
    if src in (CORPUS_HUNT_FUEL_SOURCE, CORPUS_HUNT_HACKER_Q_SOURCE):
        return src + "::" + row.get("lead_id", "")
    c, fn = row.get("contract", ""), row.get("function", "")
    if c and fn:
        return c + "." + fn
    return row.get("lead_id", row.get("title", ""))


def _atomic_write_json(path: Path, data: dict) -> None:
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=str(path.parent), suffix=".tmp", delete=False
    ) as tf:
        json.dump(data, tf, indent=2)
        tmp = tf.name
    os.replace(tmp, str(path))


def emit_proof_queue(queue_path: Path, workspace_name: str, hyps, hacker_hits,
                     dry_run=False) -> dict:
    """UPSERT corpus hypotheses + matched hacker-questions into the canonical
    exploit_queue.json. Existing non-fuel rows are preserved; corpus-hunt rows
    are deduped and idempotently re-written.
    """
    queue_data = _load_exploit_queue(queue_path, workspace_name)
    existing_rows = list(queue_data.get("queue", []))
    existing_index = {_dedup_key(r): i for i, r in enumerate(existing_rows)}

    new_rows = [_hypothesis_to_row(h, workspace_name) for h in hyps]
    new_rows += [_hacker_q_to_row(hit, workspace_name) for hit in hacker_hits]

    written = 0
    updated = 0
    for row in new_rows:
        key = _dedup_key(row)
        if key in existing_index:
            idx = existing_index[key]
            prev = existing_rows[idx]
            # never clobber a non-corpus row; only refresh our own fuel rows
            if prev.get("source") in (CORPUS_HUNT_FUEL_SOURCE, CORPUS_HUNT_HACKER_Q_SOURCE):
                existing_rows[idx] = row
                updated += 1
            else:
                # augment a real hunt row with our invariant ids if missing
                if not prev.get("broken_invariant_ids") and row.get("broken_invariant_ids"):
                    prev["broken_invariant_ids"] = row["broken_invariant_ids"]
        else:
            existing_rows.append(row)
            existing_index[key] = len(existing_rows) - 1
            written += 1

    queue_data["queue"] = existing_rows
    queue_data["total_candidates"] = len(existing_rows)
    queue_data["generated_at_utc"] = _utc_now()
    consumed = queue_data.get("source_artifacts_consumed") or []
    if CORPUS_HUNT_FUEL_SOURCE not in consumed:
        consumed.append(CORPUS_HUNT_FUEL_SOURCE)
    queue_data["source_artifacts_consumed"] = consumed

    if not dry_run:
        _atomic_write_json(queue_path, queue_data)

    # F1/E1.4 non-vacuity gate: a corpus hunt where EVERY hypothesis is
    # need_more_evidence (zero real source anchors across the CUT) has grounded
    # nothing real - it must NOT read as a successful grounding. Flag it so the
    # caller can fail-closed under STRICT instead of greening a hollow run. A
    # run that emitted >=1 hypothesis with real in-target evidence is non-vacuous.
    non_vacuous = sum(1 for h in hyps if not getattr(h, "need_more_evidence", True))
    vacuous = bool(hyps) and non_vacuous == 0

    return {
        "queue_path": str(queue_path),
        "rows_written": written,
        "rows_updated": updated,
        "queue_total": len(existing_rows),
        "fuel_rows_from_hypotheses": len(hyps),
        "fuel_rows_from_hacker_questions": len(hacker_hits),
        "non_vacuous_hypotheses": non_vacuous,
        "vacuous_corpus_hunt": vacuous,
        "dry_run": dry_run,
    }


def _field(row: Any, name: str, default: Any = "") -> Any:
    if isinstance(row, Mapping):
        return row.get(name, default)
    return getattr(row, name, default)


def _candidate_function(row: Any) -> str:
    for field in ("candidate_functions", "matched_functions"):
        functions = _field(row, field, [])
        if isinstance(functions, list) and functions:
            first = functions[0]
            if isinstance(first, Mapping):
                value = first.get("fn")
                if isinstance(value, str) and value.strip():
                    return value.strip()
    value = _field(row, "function", "")
    return value.strip() if isinstance(value, str) else ""


def _fuel_identity_key(kind: str, row: Any) -> str:
    identifier = _field(row, "invariant_id", "")
    if kind == "corpus_hacker_question":
        identifier = _field(row, "binding_invariant_id", "")
        linked = _field(row, "linked_invariant_ids", [])
        if not identifier and isinstance(linked, list) and len(linked) == 1:
            identifier = linked[0]
        if not isinstance(identifier, str) or not identifier.strip():
            return f"{kind}:unbound:{_candidate_function(row)}"
    try:
        return zero_day_identity.corpus_binding_key(
            fuel_kind=kind,
            invariant_id=str(identifier or ""),
            function=_candidate_function(row),
        )
    except zero_day_identity.FuelIdentityError:
        return f"{kind}:unbound:{_candidate_function(row)}"


def _load_awareness_exclusions(
    path: Path | None,
    identity_index: Mapping[str, Mapping[str, Any]],
    strict: bool,
) -> tuple[set[str], list[dict[str, Any]]]:
    """Return exact blocked obligation IDs from a completed semantic review.

    This deliberately accepts no title, path, keyword, or generated-ID match.
    A reviewer has to supply the full immutable logical identity, and that
    identity must already exist in the current reasoner map.
    """
    if path is None:
        if strict:
            raise AwarenessFilterError("missing_awareness_ledger_for_strict_hunt")
        return set(), []
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if strict:
            raise AwarenessFilterError(f"malformed_awareness_ledger:{path}") from exc
        return set(), []
    if not isinstance(ledger, Mapping) or ledger.get("schema") != AWARENESS_LEDGER_SCHEMA:
        raise AwarenessFilterError("invalid_awareness_ledger_schema")
    if ledger.get("fail_closed") is not False or ledger.get("validation_errors"):
        raise AwarenessFilterError("awareness_ledger_not_complete")
    candidates = ledger.get("candidates")
    if not isinstance(candidates, list):
        raise AwarenessFilterError("awareness_ledger_candidates_malformed")

    current_ids = {str(link["obligation_id"]) for link in identity_index.values()}
    blocked: set[str] = set()
    rows: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping) or candidate.get("terminal") is not True:
            raise AwarenessFilterError(f"awareness_ledger_unresolved_candidate:{index}")
        if candidate.get("novelty_blocked") is not True:
            continue
        candidate_id = candidate.get("candidate_id")
        source_ids = candidate.get("source_ids")
        logical = candidate.get("obligation_logical")
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise AwarenessFilterError(f"awareness_candidate_id_missing:{index}")
        if not isinstance(source_ids, list) or not source_ids or any(
            not isinstance(item, str) or not item.strip() for item in source_ids
        ):
            raise AwarenessFilterError(f"awareness_candidate_source_ids_missing:{candidate_id}")
        if not isinstance(logical, Mapping):
            raise AwarenessFilterError(f"awareness_obligation_binding_missing:{candidate_id}")
        normalized = {field: logical.get(field) for field in AWARENESS_LOGICAL_FIELDS}
        if any(not isinstance(value, str) or not value.strip() for value in normalized.values()):
            raise AwarenessFilterError(f"awareness_obligation_binding_invalid:{candidate_id}")
        obligation_id = "zdo_" + zero_day_identity.digest(normalized)
        if obligation_id not in current_ids:
            raise AwarenessFilterError(f"awareness_binding_no_current_obligation:{candidate_id}")
        blocked.add(obligation_id)
        rows.append({
            "candidate_id": candidate_id,
            "awareness_state": candidate.get("state"),
            "source_ids": sorted(source_ids),
            "obligation_id": obligation_id,
        })
    rows.sort(key=lambda row: (row["obligation_id"], row["candidate_id"]))
    return blocked, rows


def filter_reviewed_awareness(
    hypotheses: list[Any],
    hacker_questions: list[Any],
    identity_map_path: Path | None,
    awareness_ledger_path: Path | None,
    strict: bool,
) -> tuple[list[Any], list[Any], dict[str, Any]]:
    """Exclude only exact, reviewed known obligations before Step 4c outputs.

    Strict mode also makes identity linking a pre-output gate. This prevents an
    unlinked candidate from reaching the proof queue or MIMO and failing only
    later during fuel emission.
    """
    all_rows = [("corpus_hypothesis", row) for row in hypotheses]
    all_rows += [("corpus_hacker_question", row) for row in hacker_questions]
    if not all_rows and not strict:
        return hypotheses, hacker_questions, {"excluded": 0, "bindings": []}
    if identity_map_path is None:
        if strict:
            raise AwarenessFilterError("missing_identity_map_for_awareness_filter")
        return hypotheses, hacker_questions, {"excluded": 0, "bindings": []}
    identity_index = zero_day_identity.load_identity_map(identity_map_path)
    blocked_ids, bindings = _load_awareness_exclusions(
        awareness_ledger_path, identity_index, strict
    )
    kept_hypotheses: list[Any] = []
    kept_questions: list[Any] = []
    excluded: list[dict[str, str]] = []
    for kind, row in all_rows:
        identity_key = _fuel_identity_key(kind, row)
        link = identity_index.get(identity_key)
        if link is None:
            if strict:
                raise AwarenessFilterError(f"unlinked_applicable_fuel:{identity_key}")
            target = kept_hypotheses if kind == "corpus_hypothesis" else kept_questions
            target.append(row)
            continue
        if link["obligation_id"] in blocked_ids:
            excluded.append({
                "identity_key": identity_key,
                "obligation_id": str(link["obligation_id"]),
                "revision_id": str(link["revision_id"]),
                "fuel_kind": kind,
            })
            continue
        target = kept_hypotheses if kind == "corpus_hypothesis" else kept_questions
        target.append(row)
    return kept_hypotheses, kept_questions, {
        "excluded": len(excluded),
        "excluded_rows": excluded,
        "bindings": bindings,
    }


def emit_zero_day_fuel(result: dict, identity_map_path: Path | None, strict: bool) -> list[dict]:
    """Emit only explicitly mapped Step 4c fuel; never infer reasoner links."""
    hypotheses = result.get("hypotheses", [])
    questions = result.get("hacker_questions", [])
    applicable = [("corpus_hypothesis", row) for row in hypotheses]
    applicable += [("corpus_hacker_question", row) for row in questions]
    if not applicable:
        return []
    if identity_map_path is None:
        if strict:
            raise zero_day_identity.FuelIdentityError("missing_identity_map_for_applicable_fuel")
        return []
    identity_index = zero_day_identity.load_identity_map(identity_map_path)
    fuel: list[dict] = []
    for kind, row in applicable:
        key = _fuel_identity_key(kind, row)
        payload = {
            "question": str(row.get("question_text") or row.get("hypothesis") or row.get("statement") or "").strip(),
            "title": str(row.get("question_id") or row.get("invariant_id") or "").strip(),
            "identity_key": key,
        }
        try:
            fuel.append(zero_day_identity.fuel_row(
                producer_step_id="step-4c", fuel_kind=kind, identity_key=key,
                identity_index=identity_index, payload=payload,
            ))
        except zero_day_identity.FuelIdentityError:
            if strict:
                raise
    return fuel


def resolve_source_root(workspace, explicit):
    if explicit:
        p = Path(explicit)
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        return (p, "explicit") if p.exists() else (None, "explicit-missing")

    for ptr in (".auditooor/source_root", ".auditooor/source_path", "SOURCE_ROOT"):
        f = workspace / ptr
        if f.exists():
            try:
                cand = Path(f.read_text(encoding="utf-8").strip())
                if not cand.is_absolute():
                    cand = (workspace / cand).resolve()
                if cand.exists():
                    return cand, "workspace-pointer:" + ptr
            except OSError:
                pass

    if any(True for _ in _iter_source_files(workspace)):
        return workspace, "workspace-tree"

    name = workspace.name
    for cand in (REPO_ROOT / "external" / name,
                 workspace / "source",
                 workspace / "src",
                 workspace / "repo"):
        if cand.exists() and any(True for _ in _iter_source_files(cand)):
            return cand, "convention"

    return None, "unresolved"


def render_md(result):
    t = result["target"]
    bp = result.get("brain_prime", {})
    lines = [
        "# Corpus-driven hunt: " + result["workspace"],
        "",
        "- Source root: `" + t["source_root"] + "` (resolution: " + result["source_resolution"] + ")",
        "- Languages: " + (", ".join(t["languages"]) or "unknown"),
        "- Files scanned: " + str(t["file_count"]) + " | functions indexed: " + str(t["function_count"]),
        "- Active families: " + (", ".join(t["families_active"]) or "none detected"),
        "- Brain-prime seed gate: " + str(bp.get("gate", "n/a"))
        + " (" + str(bp.get("reason", "")) + ")",
        "- Corpus invariants loaded: " + str(result["corpus_loaded"]) + " | "
        "lang+family eligible: " + str(result["eligible"]) + " | hypotheses emitted: " + str(len(result["hypotheses"])),
    ]
    pq = result.get("proof_queue")
    if pq:
        lines.append("- Proof queue: +" + str(pq["rows_written"]) + " new / "
                     + str(pq["rows_updated"]) + " updated (total "
                     + str(pq["queue_total"]) + ") -> `" + pq["queue_path"] + "`")
    if "error" in result:
        lines += ["", "**ERROR**: " + str(result["error"]), ""]
        return "\n".join(lines)
    lines += [
        "",
        "## Ranked corpus-sourced hypotheses",
        "",
    ]
    for h in result["hypotheses"]:
        flag = " [NEED-MORE-EVIDENCE]" if h["need_more_evidence"] else ""
        lines.append("### " + str(h["rank"]) + ". " + h["invariant_id"]
                     + " (" + h["category"] + "/" + h["family"] + ", score " + str(h["score"]) + ")" + flag)
        lines.append("- Statement: " + h["statement"])
        lines.append("- Hypothesis: " + h["hypothesis"])
        if h["candidate_functions"]:
            cf = ", ".join("`" + c["fn"] + "` (" + c["file"] + ":" + str(c["line"]) + ")"
                           for c in h["candidate_functions"][:4])
            lines.append("- Candidate functions: " + cf)
        if h["in_target_evidence"]:
            ev = ", ".join(e["keyword"] + "@" + e["file"] + ":" + str(e["line"])
                           for e in h["in_target_evidence"][:5])
            lines.append("- In-target evidence: " + ev)
        if h.get("brain_prime_boost"):
            lines.append("- Brain-prime seed boost: +" + str(h["brain_prime_boost"]))
        lines.append("- " + h["differential_test_idea"])
        if h["corpus_source_ids"]:
            lines.append("- Corpus provenance: " + ", ".join(h["corpus_source_ids"][:3]))
        lines.append("")

    hq = result.get("hacker_questions") or []
    if hq:
        lines += ["## Per-function hacker-questions (folded into proof queue)", ""]
        for q in hq:
            mf = ", ".join("`" + m["fn"] + "` (" + m["file"] + ":" + str(m["line"]) + ")"
                           for m in q.get("matched_functions", [])[:4])
            lines.append("- **" + q["question_id"] + "** (" + q["attack_class"] + "): "
                         + q["question_text"])
            if mf:
                lines.append("  - Matched: " + mf)
            if q.get("linked_invariant_ids"):
                lines.append("  - Linked invariants: " + ", ".join(q["linked_invariant_ids"][:4]))
        lines.append("")
    return "\n".join(lines)


def run(workspace_arg, source, corpora, top, max_functions,
        brain_prime_receipt=None, brain_prime_gate=True,
        hacker_questions_path=None, hacker_questions_enabled=True,
        unbounded_queue=False):
    # UNBOUNDED-QUEUE opt-in: when enabled, drop BOTH expensive-layer caps -
    # the per-function index cap (build_target_model) and the top-`top`
    # hypothesis cap (materialize). The bounded default leaves both intact.
    if unbounded_queue:
        max_functions = 0  # sentinel -> build_target_model indexes all fns
        top = None         # sentinel -> materialize keeps all hypotheses
    workspace = Path(workspace_arg)
    if not workspace.is_absolute():
        workspace = (Path.cwd() / workspace).resolve()
    workspace_name = workspace.name

    # ADD-D: brain-prime seed gate runs at hunt entry, BEFORE materialization,
    # so the receipt's attack-class lanes can seed the ranking.
    seed = load_brain_prime_seed(workspace, brain_prime_receipt, brain_prime_gate)
    brain_prime_block = {
        "gate": seed.gate,
        "present": seed.present,
        "schema_valid": seed.schema_valid,
        "path": seed.path,
        "lane_attack_classes": seed.lane_attack_classes,
        "seed_tokens": seed.seed_tokens,
        "reason": seed.reason,
    }

    src_root, resolution = resolve_source_root(workspace, source)

    corpus_paths = []
    for c in corpora:
        p = Path(c)
        if not p.is_absolute():
            p = REPO_ROOT / c
        corpus_paths.append(p)
    invariants = load_invariants(corpus_paths)
    _warn_stale_corpus(corpus_paths)

    # If the brain-prime gate failed, return a fail-closed result. The hunt
    # still reports the loaded corpus so the operator sees what was skipped.
    if seed.gate == "fail":
        return {
            "schema": SCHEMA,
            "workspace": workspace_name,
            "workspace_path": str(workspace),
            "source_resolution": resolution,
            "error": ("brain-prime seed gate failed: " + seed.reason),
            "brain_prime": brain_prime_block,
            "corpus_loaded": len(invariants),
            "corpus_trust": _corpus_trust_annotation(),
            "eligible": 0,
            "hypotheses": [],
            "hacker_questions": [],
            "target": {
                "source_root": "", "languages": [], "file_count": 0,
                "function_count": 0, "families_active": [],
            },
        }

    if src_root is None:
        return {
            "schema": SCHEMA,
            "workspace": workspace_name,
            "workspace_path": str(workspace),
            "source_resolution": resolution,
            "error": "could not resolve a target source root; pass --source <dir>",
            "brain_prime": brain_prime_block,
            "corpus_loaded": len(invariants),
            "corpus_trust": _corpus_trust_annotation(),
            "eligible": 0,
            "hypotheses": [],
            "hacker_questions": [],
            "target": {
                "source_root": "", "languages": [], "file_count": 0,
                "function_count": 0, "families_active": [],
            },
        }

    target = build_target_model(src_root, max_functions)
    eligible = [iv for iv in invariants if _lang_match(iv, target.languages)]
    hyps = materialize(invariants, target, top, brain_prime_seed=seed)

    # ADD-D: fold per-function hacker-questions into the same hypothesis set
    # (they become proof-queue rows alongside the invariant hypotheses).
    hacker_hits = []
    if hacker_questions_enabled:
        hq_path = Path(hacker_questions_path) if hacker_questions_path else (
            REPO_ROOT / DEFAULT_HACKER_QUESTIONS)
        if not hq_path.is_absolute():
            hq_path = REPO_ROOT / hq_path
        questions = load_hacker_questions(hq_path)
        lang_set = set(target.languages)
        hacker_hits = match_hacker_questions(questions, target, lang_set)

    return {
        "schema": SCHEMA,
        "workspace": workspace_name,
        "workspace_path": str(workspace),
        "source_resolution": resolution,
        "brain_prime": brain_prime_block,
        "corpus_loaded": len(invariants),
        "corpus_trust": _corpus_trust_annotation(),
        "eligible": len(eligible),
        "target": {
            "source_root": target.source_root,
            "languages": target.languages,
            "file_count": target.file_count,
            "function_count": target.function_count,
            "families_active": target.families_active,
        },
        "hypotheses": [asdict(h) for h in hyps],
        "hacker_questions": [asdict(h) for h in hacker_hits],
        "_target_model": target,
        "_hypothesis_objs": hyps,
        "_hacker_hit_objs": hacker_hits,
    }


def main(argv):
    ap = argparse.ArgumentParser(description="Corpus-driven live-hypothesis hunt.")
    ap.add_argument("workspace", help="workspace dir (or any path; --source overrides source root)")
    ap.add_argument("--source", help="explicit target source root")
    ap.add_argument("--invariant-corpus", default=",".join(DEFAULT_INVARIANT_CORPORA),
                    help="comma-separated invariant JSONL paths")
    ap.add_argument("--top", type=int, default=40)
    # --max-functions accepts an int OR the literal "all" (UNBOUNDED-QUEUE opt-in
    # that mirrors MAX_FUNCTIONS=all from the Makefile). Parsed as str then
    # normalized below so the bounded int default path is unchanged.
    ap.add_argument("--max-functions", default="2000")
    ap.add_argument("--unbounded-queue", action="store_true",
                    help="UNBOUNDED-QUEUE opt-in: index EVERY in-scope function "
                         "and emit ONE MIMO task per hypothesis (no top-N / "
                         "concurrency truncation). Throttle/resume/budget are "
                         "delegated to llm-fanout-dispatcher.py "
                         "(--concurrency/--budget-cap-usd) + hunt-resume-planner.py. "
                         "Default behavior (flag absent) is byte-for-byte unchanged. "
                         "Also enabled via UNBOUNDED_QUEUE=1 env or --max-functions all.")
    ap.add_argument("--mimo", action="store_true",
                    help="also emit a MIMO fanout task batch for the top hypotheses")
    ap.add_argument("--mimo-out", help="path to write the MIMO batch JSON")
    ap.add_argument("--mimo-concurrency", type=int, default=4)
    ap.add_argument("--emit-proof-queue", action="store_true",
                    help="UPSERT every hypothesis + matched hacker-question into "
                         "the canonical <ws>/.auditooor/exploit_queue.json as a "
                         "MANDATORY proof obligation (not advisory)")
    ap.add_argument("--proof-queue-path",
                    help="override the exploit_queue.json path "
                         "(default <ws>/.auditooor/exploit_queue.json)")
    ap.add_argument("--proof-queue-dry-run", action="store_true",
                    help="compute the proof-queue UPSERT but do not write")
    ap.add_argument("--strict", action="store_true",
                    help="F1/E1.4 non-vacuity gate: exit non-zero (rc=3) when the "
                         "corpus hunt grounded NOTHING real (every hypothesis is "
                         "need_more_evidence) - prevents a green pipeline over a "
                         "corpus that anchors to no real source in the CUT")
    ap.add_argument("--zero-day-fuel-out",
                    help="write explicitly linked auditooor.zero_day_fuel.v1 JSONL")
    ap.add_argument("--zero-day-identity-map",
                    help="JSONL map of exact current reasoner obligation/revision identities")
    ap.add_argument("--awareness-ledger",
                    help="completed semantic-awareness ledger used to exclude exact known obligations")
    ap.add_argument("--brain-prime-receipt",
                    help="explicit path to the brain_prime_receipt.json "
                         "(default <ws>/.auditooor/brain_prime_receipt.json)")
    ap.add_argument("--no-brain-prime-gate", action="store_true",
                    help="ADD-D override: proceed without the brain-prime "
                         "receipt (audit-logged)")
    ap.add_argument("--hacker-questions",
                    help="explicit path to the hacker_questions_library.jsonl")
    ap.add_argument("--no-hacker-questions", action="store_true",
                    help="skip the per-function hacker-question fold-in")
    ap.add_argument("--out", help="path to write the ranked-hypothesis JSON")
    ap.add_argument("--md-out", help="path to write the markdown report")
    ap.add_argument("--json", action="store_true", help="print JSON to stdout")
    args = ap.parse_args(argv)

    # Resolve UNBOUNDED-QUEUE opt-in from any of three signals (all opt-in;
    # none changes the default path): explicit --unbounded-queue, env
    # UNBOUNDED_QUEUE=1, or --max-functions all.
    mf_raw = str(args.max_functions).strip().lower()
    unbounded_queue = bool(
        args.unbounded_queue
        or os.environ.get("UNBOUNDED_QUEUE", "").strip() in ("1", "true", "yes")
        or mf_raw in ("all", "0", "-1")
    )
    if mf_raw in ("all", "0", "-1"):
        max_functions = 0  # sentinel; run() also forces this when unbounded
    else:
        try:
            max_functions = int(mf_raw)
        except ValueError:
            max_functions = 2000

    corpora = [c.strip() for c in args.invariant_corpus.split(",") if c.strip()]
    result = run(
        args.workspace, args.source, corpora, args.top, max_functions,
        brain_prime_receipt=args.brain_prime_receipt,
        brain_prime_gate=not args.no_brain_prime_gate,
        hacker_questions_path=args.hacker_questions,
        hacker_questions_enabled=not args.no_hacker_questions,
        unbounded_queue=unbounded_queue,
    )
    target_model = result.pop("_target_model", None)
    hypothesis_objs = result.pop("_hypothesis_objs", None)
    hacker_hit_objs = result.pop("_hacker_hit_objs", None)

    workspace = Path(args.workspace)
    if not workspace.is_absolute():
        workspace = (Path.cwd() / workspace).resolve()
    awareness_path = Path(args.awareness_ledger) if args.awareness_ledger else (
        workspace / ".auditooor" / "awareness_ledger.json"
    )
    try:
        filtered_hypotheses, filtered_questions, awareness_summary = filter_reviewed_awareness(
            result.get("hypotheses", []), result.get("hacker_questions", []),
            Path(args.zero_day_identity_map) if args.zero_day_identity_map else None,
            awareness_path, args.strict,
        )
    except (AwarenessFilterError, zero_day_identity.FuelIdentityError) as exc:
        print(f"corpus-driven-hunt: FAIL awareness filter {exc}", file=sys.stderr)
        return 4
    result["hypotheses"] = filtered_hypotheses
    result["hacker_questions"] = filtered_questions
    result["awareness_exclusions"] = awareness_summary

    # The serialized and object forms are both Step 4c consumers. Filter the
    # object forms through the same identity path before proof-queue emission.
    try:
        hypothesis_objs, hacker_hit_objs, object_awareness_summary = filter_reviewed_awareness(
            hypothesis_objs or [], hacker_hit_objs or [],
            Path(args.zero_day_identity_map) if args.zero_day_identity_map else None,
            awareness_path, args.strict,
        )
    except (AwarenessFilterError, zero_day_identity.FuelIdentityError) as exc:
        print(f"corpus-driven-hunt: FAIL awareness object filter {exc}", file=sys.stderr)
        return 4
    if object_awareness_summary["excluded"] != awareness_summary["excluded"]:
        print("corpus-driven-hunt: FAIL awareness filter representation mismatch", file=sys.stderr)
        return 4

    # PR7a: MANDATORY proof-queue emission.
    if args.emit_proof_queue and "error" not in result:
        if args.proof_queue_path:
            queue_path = Path(args.proof_queue_path)
            if not queue_path.is_absolute():
                queue_path = (Path.cwd() / queue_path).resolve()
        else:
            queue_path = workspace / EXPLOIT_QUEUE_REL
        emit_summary = emit_proof_queue(
            queue_path, result["workspace"],
            hypothesis_objs or [], hacker_hit_objs or [],
            dry_run=args.proof_queue_dry_run,
        )
        result["proof_queue"] = emit_summary

    if args.mimo and target_model is not None and result.get("hypotheses"):
        hyp_objs = [Hypothesis(**h) for h in result["hypotheses"]]
        batch = build_mimo_batch(hyp_objs, target_model, result["workspace"],
                                 args.mimo_concurrency, unbounded=unbounded_queue)
        result["mimo_batch_task_count"] = batch["task_count"]
        if unbounded_queue:
            # NO-SILENT-CAPS coverage report: how many functions were indexed
            # vs the cap, and how many MIMO tasks are queued-not-yet-done.
            result["unbounded_queue"] = True
            result["coverage"] = {
                "functions_indexed": target_model.function_count,
                "hypotheses_total": batch.get("hypotheses_total", batch["task_count"]),
                "mimo_tasks_queued": batch["task_count"],
                "mimo_pending": batch.get("mimo_pending", batch["task_count"]),
                "note": ("unbounded: every in-scope function indexed + one task "
                         "per hypothesis. mimo_pending drives toward 0 via "
                         "hunt-resume-planner.py re-dispatch."),
            }
        if args.mimo_out:
            Path(args.mimo_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.mimo_out).write_text(json.dumps(batch, indent=2), encoding="utf-8")

    if args.zero_day_fuel_out:
        try:
            fuel = emit_zero_day_fuel(
                result,
                Path(args.zero_day_identity_map) if args.zero_day_identity_map else None,
                args.strict,
            )
        except zero_day_identity.FuelIdentityError as exc:
            print(f"corpus-driven-hunt: FAIL zero-day fuel {exc}", file=sys.stderr)
            return 4
        fuel_path = Path(args.zero_day_fuel_out)
        fuel_path.parent.mkdir(parents=True, exist_ok=True)
        fuel_path.write_text(
            "".join(json.dumps(row, separators=(",", ":"), ensure_ascii=True) + "\n" for row in fuel),
            encoding="utf-8",
        )
        result["zero_day_fuel"] = {"path": str(fuel_path), "rows": len(fuel)}

    # The report is a separate receipt-bound artifact from typed fuel. Write it
    # only after fuel emission so its row count and path attest the exact file
    # consumed by the freeze compiler.
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.md_out:
        Path(args.md_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md_out).write_text(render_md(result), encoding="utf-8")

    if args.json or not (args.out or args.md_out):
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print("corpus-driven-hunt: ERROR (" + result["workspace"] + "): "
                  + str(result["error"]))
        else:
            line = ("corpus-driven-hunt: " + str(len(result["hypotheses"])) + " hypotheses "
                    "(" + str(result["eligible"]) + " eligible / "
                    + str(result["corpus_loaded"]) + " loaded) "
                    "for " + result["workspace"] + " -> " + result["target"]["source_root"])
            bp = result.get("brain_prime", {})
            line += " | brain-prime gate=" + str(bp.get("gate", "?"))
            hq = result.get("hacker_questions", [])
            line += " | hacker-q matched=" + str(len(hq))
            pq = result.get("proof_queue")
            if pq:
                line += (" | proof-queue +" + str(pq["rows_written"])
                         + " new / " + str(pq["rows_updated"]) + " updated -> "
                         + pq["queue_path"])
            print(line)

    # F1/E1.4 non-vacuity gate. A corpus hunt that grounded zero real anchors
    # (every hypothesis need_more_evidence) must not read as success. Emit a typed
    # verdict and, under --strict, exit rc=3 so STEP 3.5 / audit-complete can
    # fail-closed instead of greening a hollow grounding.
    pq = result.get("proof_queue") or {}
    if pq.get("vacuous_corpus_hunt"):
        import sys as _sys
        print('{"schema":"auditooor.corpus_hunt_verdict.v1","verdict":'
              '"vacuous-corpus-hunt","workspace":"' + str(result.get("workspace", "?"))
              + '","reason":"every hypothesis is need_more_evidence; corpus anchored '
              'to no real source in the CUT","non_vacuous_hypotheses":0}',
              file=_sys.stderr)
        if args.strict:
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
