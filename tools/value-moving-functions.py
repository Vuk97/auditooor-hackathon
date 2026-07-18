#!/usr/bin/env python3
"""value-moving-functions.py - enumerate VALUE-MOVING functions of a workspace.

WHAT IS A VALUE-MOVING FUNCTION?
=================================
A function is value-moving when it satisfies AT LEAST ONE of two criteria
(union, not intersection - either alone is sufficient):

  A. TRANSFER-CALL: the function body contains a token-transfer call-site -
     language-generic patterns for direct ERC-20/native/Cosmos/bank moves:
       Solidity : safeTransfer / safeTransferFrom / transfer( / transferFrom(
                  call{value: / .send( / SafeTransferLib / ERC20.transfer
       Go/Cosmos : bank.SendCoins / bank.Send / bankKeeper.Send* / BankMsg.Send
                  sdk.NewCoin / SendCoinsFromModuleToAccount / etc.
       Rust/CosmwWasm : BankMsg::Send / bank::send / transfer{} / coins!
       Move       : coin::transfer / coin::withdraw / aptos_account::transfer
       Cairo      : transfer / transfer_from / IERC20.transfer

  B. LEDGER-WRITE: the function body writes a balance / credit / debt / share /
     units / amount field of a shared ledger mapping - the same per-language
     WRITE patterns already used by cross-function-invariant-coverage.py (reused
     verbatim from that module so there is a single source of truth).

     Additionally, field-name filtering: the written token must contain at least
     one value-related root word (balance, credit, debt, share, unit, amount,
     asset, vault, escrow, collateral, reserve, stake, supply, borrow, lend,
     deposit, withdraw, liquidity, fund, pool, holding, position, fee, reward,
     token, coin, mint, burn). This suppresses spurious hits on fields like
     `nonce`, `timestamp`, `owner`, etc.

DESIGN
======
- GENERIC: zero workspace literals. Language is inferred from file extension.
- REUSE, NOT REBUILD: transfer patterns + ledger write patterns coexist in this
  file (they have no build-time dependency on the sister tool at import time),
  but they are IDENTICAL copies of the patterns cross-function-invariant-coverage
  uses. When cross-function-invariant-coverage._WRITE_RES is updated, mirror it
  here and vice versa.
- OOS: scope_exclusion.is_oos() is called on every relative path before any
  pattern is applied. Test / vendored / generated files are skipped.
- OUTPUT: <ws>/.auditooor/value_moving_functions.json
    {
      "workspace": "<abs-path>",
      "generated_at": "<iso-timestamp>",
      "function_count": N,
      "functions": [
        {
          "file": "<rel-path>",
          "function": "<name>",
          "language": "sol|go|rs|move|cairo",
          "transfer_hit": true|false,
          "ledger_write_hit": true|false,
          "transfer_evidence": ["<snippet>", ...],
          "ledger_write_evidence": ["<field>", ...],
          "guarded_callee_hit": true|false,     # present iff EXTENDED is ON
          "guarded_callee_caller": "<name>"|null,  # present iff EXTENDED is ON
          "authz_write_hit": true|false,        # present iff EXTENDED is ON
          "authz_write_evidence": ["<field>", ...]  # present iff EXTENDED is ON
        },
        ...
      ]
    }

  C. GUARDED-BRANCH CALLEE (extended, default ON): a function with NO direct
     transfer/ledger hit that is called (by name) from within a conditional
     branch (if/else guarded by a comparison) inside a function that IS
     already value-moving, IN THE SAME FILE. This is a simple same-file,
     name-match call-graph check (not interprocedural / cross-file) so it
     stays cheap and language-portable. Rationale: a private/internal helper
     inlined only under a guarded branch of a value-moving caller (e.g. a
     loss-allocation math helper invoked only when a valuation check fails)
     does no transfer/ledger write itself, yet is exactly where the
     interesting math for the value-moving path lives.

  D. AUTHZ-WRITE (extended, default ON): a function that assigns/mutates a
     mapping or map-shaped storage variable whose KEY or NAME is role/
     permission/access-shaped (grantRole-style calls, or a mapping literally
     named role/permission/access/operator/allow(ed)/whitelist-shaped, or a
     mapping keyed by a role/selector-shaped identifier). These mappings
     store permission BITS, not token amounts, so the token/balance-tuned
     _is_value_field() filter never recognizes them - yet they gate every
     OTHER value-moving function in the contract. Detected via a SEPARATE
     regex tier (_is_authz_field) so the existing value-field tuning is
     never weakened.

  Categories C and D are ADDITIVE to the A/B union (OR-chain) and never
  remove or narrow the A/B criteria. They are gated behind the environment
  variable AUDITOOOR_VALUE_MOVING_EXTENDED, default ON (only a literal "0"
  disables them) since they only ever ADD candidates to the enumerated set -
  never removes any - so there is no fail-closed regression risk to gate
  behind STRICT. Set AUDITOOOR_VALUE_MOVING_EXTENDED=0 to reproduce the
  pre-extension A/B-only behavior exactly (e.g. if a downstream consumer is
  not yet updated to tolerate the new "guarded_callee_hit"/"authz_write_hit"
  record fields, though all existing keys are unchanged/still present).

CLI
===
  python3 tools/value-moving-functions.py <workspace-path> [--out <path>]

Returns rc=0 on success, rc=1 on error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Compose with scope_exclusion (single-source-of-truth OOS filter).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos, is_in_scope, is_generated, resolve_source_roots  # type: ignore
except Exception:
    _HERE = Path(__file__).resolve().parent
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos, is_in_scope, is_generated, resolve_source_roots  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            """Fallback: mark vendored / test dirs conservatively."""
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
            ):
                if marker in n:
                    return True
            return False

        def is_in_scope(rel: str, *, workspace=None) -> bool:  # type: ignore[misc]
            """Fallback: in-scope iff not OOS (no manifest authority available)."""
            return not is_oos(rel)

        def is_generated(rel: str, *, head: str | None = None) -> bool:  # type: ignore[misc]
            """Fallback: detect the abigen / protoc generated-code header."""
            if head and ("DO NOT EDIT" in head and "Code generated" in head):
                return True
            return rel.endswith((".pb.go", ".gen.go"))

        def resolve_source_roots(ws) -> list:  # type: ignore[misc]
            return [Path(ws)]

# ---------------------------------------------------------------------------
# Canonical source-extension registry (single source of truth). Used ONLY to
# recognize DECLARATIVE / LLM-hunt-only languages (Obyte Oscript AAs et al) that
# have NO function-start regex here and are therefore seeded from the in-scope
# manifest instead of the source walk. The regex-walked engine languages keep
# coming from _EXT_TO_LANG below, byte-identically.
# ---------------------------------------------------------------------------
try:
    from lib.source_extensions import (  # type: ignore
        EXT_TO_LANG as _REG_EXT_TO_LANG,
        lang_of as _reg_lang_of,
        is_llm_hunt_only as _reg_is_llm_hunt_only,
    )
except Exception:  # pragma: no cover - fallback when run as a bare script
    _T = Path(__file__).resolve().parent
    if str(_T) not in sys.path:
        sys.path.insert(0, str(_T))
    try:
        from lib.source_extensions import (  # type: ignore
            EXT_TO_LANG as _REG_EXT_TO_LANG,
            lang_of as _reg_lang_of,
            is_llm_hunt_only as _reg_is_llm_hunt_only,
        )
    except Exception:  # pragma: no cover
        _REG_EXT_TO_LANG = {}

        def _reg_lang_of(_p: str):  # type: ignore[misc]
            return None

        def _reg_is_llm_hunt_only(_p: str) -> bool:  # type: ignore[misc]
            return False

# ---------------------------------------------------------------------------
# Extended-detection gate (categories C/D). Default ON: this env var only ever
# ADDS candidates to the enumerated set, it never removes any, so there is no
# fail-closed risk in defaulting it on. Set AUDITOOOR_VALUE_MOVING_EXTENDED=0
# to reproduce the pre-extension A/B-only behavior exactly (e.g. a downstream
# consumer not yet updated to tolerate the new record fields).
# ---------------------------------------------------------------------------
def _extended_enabled() -> bool:
    return os.environ.get("AUDITOOOR_VALUE_MOVING_EXTENDED", "1") != "0"


# ---------------------------------------------------------------------------
# Language detection.
# ---------------------------------------------------------------------------
_EXT_TO_LANG: dict[str, str] = {
    ".sol": "sol",
    ".vy": "sol",   # Vyper - Solidity-adjacent transfer patterns apply
    ".go": "go",
    ".rs": "rs",
    ".move": "move",
    ".cairo": "cairo",
    ".nr": "cairo",  # Noir - Cairo-adjacent
    # JavaScript (Obyte ocore + counterstake-bridge + AA off-chain glue). Node
    # CommonJS: `function NAME(` and `exports.NAME = function` are the dominant
    # forms (see _FN_RES["js"]). Adding ".js" here promotes JavaScript from the
    # file-level js_oscript classifier (denominator gate, unchanged below) to a
    # PER-FUNCTION transfer_hit/ledger_write_hit walk, exactly like the other
    # engine languages. Registry side-effect (intended): "javascript" now enters
    # _WALKED_CANON_LANGS and so leaves _MANIFEST_SEED_LANGS - JS is source-walked
    # here instead of manifest-seeded (obyte manifest js rows carry function=None
    # + no value_movers, so seeding already emitted zero js rows; no regression).
    # Oscript (.oscript/.aa) stays manifest-seeded (declarative, no fn regex).
    ".js": "js",
}


def _lang(path: Path) -> str | None:
    return _EXT_TO_LANG.get(path.suffix.lower())


# Canonical languages the REGEX walker above already handles (mapped in
# _EXT_TO_LANG). move/cairo/noir are is_llm_hunt_only in the registry but ARE
# walked here, so they must be EXCLUDED from the manifest-seed set below to avoid
# double-counting a unit from both the source walk and the manifest.
_WALKED_CANON_LANGS: frozenset[str] = frozenset(
    l for l in (_reg_lang_of(e) for e in _EXT_TO_LANG) if l
)
# DECLARATIVE / LLM-hunt-only languages with NO function-start regex here (Obyte
# Oscript AAs .oscript/.aa, and any future no-engine DSL): seeded from the
# in-scope manifest's value_movers/state_writes fields instead of a source scan.
# = registry LLM-hunt-only langs MINUS the langs the walker already covers.
_MANIFEST_SEED_LANGS: frozenset[str] = frozenset(
    l for l in set(_REG_EXT_TO_LANG.values())
    if _reg_is_llm_hunt_only(l) and l not in _WALKED_CANON_LANGS
)


def _manifest_seed_enabled() -> bool:
    """Default-ON manifest-seeding of DECLARATIVE (LLM-hunt-only) value-movers.
    Disabled only by a literal 0/false/no. An engine-language workspace produces
    no manifest-seed rows regardless, so disabling it is a no-op there."""
    return os.environ.get(
        "AUDITOOOR_OSCRIPT_VALUE_MOVING", "1"
    ).strip().lower() not in ("0", "false", "no")


# Oscript value_movers tokens that denote an actual OUTBOUND value transfer (a
# `payment` message sends the AA's funds; `asset` issues/moves an asset) versus a
# pure ledger/state write (`state`/`definition`, plus any state_writes token).
_DECL_TRANSFER_TOKENS = frozenset({"payment", "asset"})
_DECL_LEDGER_TOKENS = frozenset({"state", "definition"})


# ===========================================================================
# JS / Oscript FILE-LEVEL value-moving CLASSIFIER (denominator integrity).
# ---------------------------------------------------------------------------
# The Solidity value-moving enumerator above is per-FUNCTION. A JS/Oscript
# workspace (Obyte: obyte-core `ocore/*.js`, bridge `evm/*.js`, AA `.oscript`)
# is enumerated in the coverage denominator at FILE granularity (one file-level
# unit per module, ``function=''``), so the same idea needs a FILE-level shape:
# decide whether a JS/Oscript module is value-moving (KEEP in the denominator)
# or genuinely non-value-moving infrastructure (EXEMPT, the JS/Oscript analog of
# the bodyless-interface denominator exemption in hunt-coverage-gate.py).
#
# The consumers (hunt-coverage-gate.py denom exemption, workspace-coverage-
# heatmap.py advisory disclosure) import ``js_oscript_unit_value_moving_verdict``
# from HERE so there is a single source of truth (no new silo) - exactly as
# value-moving-functions.py is the single source for the Solidity value-mover
# set and go_entrypoint_surface.py for the Go entry-point set.
#
# FAIL-OPEN, ALWAYS: a unit is treated as value-moving unless it is POSITIVELY
# matched as a non-value-moving category AND its source shows no value signal.
# Exempting a value-moving unit would HIDE attack surface - the opposite of the
# denominator-integrity goal - so every uncertain case keeps the unit.
# ===========================================================================

# Extensions this classifier speaks. Oscript (.oscript/.aa) is fail-open
# value-moving here (its value_movers are already classified by the Oscript AA
# enumerator + the manifest-declarative seeding above); the file-level EXEMPTION
# path only narrows JavaScript, which is where the infra/config/CLI noise lives.
_JS_EXTS = frozenset({".js"})
_OSCRIPT_EXTS = frozenset({".oscript", ".aa"})

# CONFIG (never value-moving): eslint config, *.config.js build config, truffle
# config, hardhat/webpack style *.config.js, migration scripts, per-AA conf.js.
_JS_CONFIG_RE = re.compile(
    r"(?:^|/)\.eslintrc(?:\.\w+)?\.js$"
    r"|(?:^|/)[^/]*\.config\.js$"
    r"|(?:^|/)truffle-config\.js$"
    r"|(?:^|/)hardhat\.config\.js$"
    r"|(?:^|/)migrations/"
    r"|(?:^|/)conf\.js$",
    re.IGNORECASE,
)

# TEST / CLI / DEPLOY / MAINTENANCE tooling (never on the value path in prod):
# unit tests, one-off deploy + admin + oracle-poking scripts, nonce-finders,
# replication/renounce maintenance CLIs.
_JS_TEST_CLI_RE = re.compile(
    r"\.(?:test|spec)\.[jt]s$"
    r"|(?:^|/)(?:"
    r"find-nonce|find_longest_state_var|replicate|renounce|check-replication"
    r"|check_daemon|check_stability|update_stability|compare_vote_balances"
    r"|deploy-[\w.]+|deploy_[\w.]+|deploy-contracts[\w.\-]*|deploy-aas"
    r"|migrate_to_kv|db_import|setup_bridges|get_oracle|get_gas_price"
    r"|post_oracle_price|sign_message|provider|run|remove_support_from_token"
    r")\.js$",
    re.IGNORECASE,
)

# PURE STRING / INT / FORMAT UTILITIES (no value or consensus role): exactly the
# helpers called out as non-value-moving (int2str/uint2str/toAsciiString/
# errorToString/errorFormatter/opRender), plus uri formatting.
_JS_PURE_UTIL_BASENAMES = frozenset({
    "int2str.js", "uint2str.js", "toasciistring.js",
    "errortostring.js", "errorformatter.js", "oprender.js",
    "uri.js",
})

# PURE INFRA (IO / messaging / telemetry plumbing with no value or consensus
# role): exactly the modules called out (bots/breadcrumbs/profiler/event_bus/
# mail/desktop_app), plus adjacent mail/telemetry/DB-pool/HTTP plumbing of the
# same class. Consensus/storage/validation/writer/composer modules are NOT here
# (they carry the real obligation) and are additionally protected by the
# consensus-signal veto below.
_JS_PURE_INFRA_BASENAMES = frozenset({
    "bots.js", "breadcrumbs.js", "profiler.js", "event_bus.js",
    "mail.js", "mailerlite.js", "desktop_app.js", "notifications.js",
    "mysql_pool.js", "sqlite_pool.js", "webserver.js",
})

# VALUE-SIGNAL veto (anti-rubber-stamp): if a module's SOURCE contains any of
# these strong value/ledger/asset tokens it is KEPT as value-moving even if its
# name matched an exempt category above. This is the mechanical guarantee that a
# value-mover can never be exempted by a mis-curated name list.
_JS_VALUE_SIGNAL_RE = re.compile(
    r"\bbalances?\b"
    r"|\bpayment"
    r"|\bissueasset\b|\bissue_asset\b"
    r"|\bdivisible_asset\b|\bindivisible_asset\b"
    r"|\bpaytoaddress\b|\bsendallbytes\b|\bsendpayment\b"
    r"|\bwithdraw_fees\b|\bcommission"
    r"|\bmint\b|\bburn\b"
    r"|\boutputs\b",
    re.IGNORECASE,
)

# CONSENSUS / STORAGE-CRITICAL veto: ocore modules that write the DAG / main
# chain / validation / composition surface must always stay value-moving even if
# a name somehow matched. Keyed on the ROLE word appearing in the basename so it
# is cheap and needs no source read; the value-signal veto (source-based) is the
# stronger of the two.
_JS_CONSENSUS_BASENAME_RE = re.compile(
    r"valid|writer|storage|main_chain|graph|joint|catchup|network|composer"
    r"|witness|headers_commission|paid_witnessing|mc_outputs|proof",
    re.IGNORECASE,
)


def _js_nonvaluemoving_category(unit_rel: str) -> str | None:
    """Return the non-value-moving CATEGORY name for a JS unit path, or None if
    the unit is not positively in any exempt category (-> keep as value-moving).
    Accepts a workspace-relative path OR a bare basename (both occur as coverage
    unit ids)."""
    p = str(unit_rel or "").replace("\\", "/").strip()
    if not p:
        return None
    base = p.rsplit("/", 1)[-1].lower()
    if not base.endswith(".js"):
        return None
    # Consensus/storage-critical modules are NEVER exempt (belt-and-suspenders
    # with the source value-signal veto in the verdict fn).
    if _JS_CONSENSUS_BASENAME_RE.search(base):
        return None
    if _JS_CONFIG_RE.search(p):
        return "config"
    if _JS_TEST_CLI_RE.search(p):
        return "test-cli-tooling"
    if base in _JS_PURE_UTIL_BASENAMES:
        return "pure-util"
    if base in _JS_PURE_INFRA_BASENAMES:
        return "pure-infra"
    return None


def js_oscript_unit_value_moving_verdict(
    unit_rel: str, text: str | None = None
) -> tuple[str, str]:
    """Classify a JS/Oscript coverage unit for denominator integrity.

    Returns ``(verdict, reason)`` where ``verdict`` is one of:
      * ``"value-moving"``     - KEEP in the coverage denominator.
      * ``"non-value-moving"`` - EXEMPT from the denominator (infra/config/CLI/
                                 pure-util) - only ever returned for JavaScript.
      * ``"not-applicable"``   - not a JS/Oscript unit (the classifier only
                                 narrows JS/Oscript; every other language is left
                                 byte-identical).

    ``text`` is the module SOURCE (may be None/'' when unresolvable). FAIL-OPEN:
    with no source and a matched category the name-based verdict stands, but a
    matched category is OVERRIDDEN back to value-moving whenever the source shows
    a value/ledger/asset signal (anti-rubber-stamp - a value-mover is never
    hidden by a mis-curated name list)."""
    p = str(unit_rel or "").replace("\\", "/").strip()
    base = p.rsplit("/", 1)[-1].lower()
    _, ext = os.path.splitext(base)
    ext = ext.lower()
    if ext in _OSCRIPT_EXTS:
        # Oscript AAs are value-moving by construction (deployed on-chain value
        # logic); their value_movers are classified by the Oscript AA enumerator
        # and seeded into the value-mover set above. Fail-open: never exempted.
        return ("value-moving", "oscript-fail-open")
    if ext not in _JS_EXTS:
        return ("not-applicable", "non-js-oscript")
    cat = _js_nonvaluemoving_category(p)
    if cat is None:
        return ("value-moving", "js-default-fail-open")
    if text and _JS_VALUE_SIGNAL_RE.search(text):
        return ("value-moving", f"js-{cat}-vetoed-by-value-signal")
    return ("non-value-moving", f"js-{cat}")


# ---------------------------------------------------------------------------
# Per-language function-start detectors (name-capture in group 1).
# Identical to the _FN_RES table in cross-function-invariant-coverage.py.
# ---------------------------------------------------------------------------
_FN_RES: dict[str, re.Pattern] = {
    # Solidity: word-boundary match so single-line test fixtures and real
    # multi-line source both work. The simpler \bfunction form is identical
    # to the one in cross-function-invariant-coverage.py.
    "sol": re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\("),
    "rs": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[<(]"),
    "move": re.compile(r"\bfun\s+([A-Za-z_]\w*)\s*[<(]"),
    "cairo": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
    # JavaScript (Node CommonJS - Obyte ocore + counterstake-bridge). The name is
    # ALWAYS captured in group 1 so the generic `m.group(1)` walker is unchanged:
    #   * branch 1 `function\s+` consumes the keyword, group 1 = the declared name
    #     (`function composePaymentJoint(...)` -> composePaymentJoint). An anonymous
    #     `function(` has no `\s+name` and is intentionally NOT matched.
    #   * branch 2 is a ZERO-WIDTH lookahead `(?=NAME [:=] function)` that consumes
    #     nothing, then group 1 captures the leading identifier of an assignment/
    #     property function expression (`exports.setGenesis = function(){...}` ->
    #     setGenesis; `sendPayment: function(){...}` -> sendPayment). The `exports.`
    #     prefix is skipped because the engine only matches the lookahead at the
    #     identifier that is directly `= function` / `: function`.
    # Only `function`-keyword forms are matched (both always brace-bodied), so
    # _extract_body finds the correct body brace; brace-less one-line arrow bodies
    # are deliberately excluded to avoid absorbing a following function's block.
    "js": re.compile(
        r"(?:function\s+|(?=[A-Za-z_$][\w$]*\s*[:=]\s*(?:async\s+)?function\b))"
        r"([A-Za-z_$][\w$]*)"
    ),
}

# Solidity state-mutability keyword that proves a function cannot write storage
# or transfer value. Matched only in the header (signature ")" -> body "{"),
# lowercase + word-boundary so a `View`/`Pure` type or identifier is not hit.
_SOL_NONMUTATING_RE: re.Pattern = re.compile(r"\b(?:view|pure)\b")

# ---------------------------------------------------------------------------
# Per-language TRANSFER-CALL patterns (part A of the union).
# Each pattern fires when a token-transfer call-site is in the function body.
# Patterns deliberately broad: false-positives at the BODY level are suppressed
# by function-body isolation (we only search within the extracted body text).
# ---------------------------------------------------------------------------
_TRANSFER_RES: dict[str, list[re.Pattern]] = {
    "sol": [
        # SafeTransferLib / OZ SafeERC20 calls
        re.compile(r"\bsafeTransfer\s*\(", re.I),
        re.compile(r"\bsafeTransferFrom\s*\(", re.I),
        # Bare ERC-20 transfer / transferFrom
        re.compile(r"\btransfer\s*\("),
        re.compile(r"\btransferFrom\s*\("),
        # Native ETH: call{value:} / .send(
        re.compile(r"\.\s*call\s*\{[^}]*value\s*:"),
        re.compile(r"\bsend\s*\("),
        # IERC20 interface pattern
        re.compile(r"IERC20\([^)]*\)\.transfer\s*\(", re.I),
    ],
    "go": [
        # Cosmos bank keeper methods
        re.compile(r"\bbank(?:Keeper)?\.Send\w*\s*\(", re.I),
        re.compile(r"\bk\.bankKeeper\.Send\w*\s*\(", re.I),
        re.compile(r"\bBankMsg\s*\.\s*Send\b"),
        re.compile(r"\bSendCoinsFromModuleTo\w+\s*\(", re.I),
        re.compile(r"\bSendCoins\s*\("),
        re.compile(r"\bMintCoins\s*\("),
        re.compile(r"\bBurnCoins\s*\("),
        # NOTE: `sdk.NewCoin(` was previously here but it is a CONSTRUCTOR, not a
        # custody move - it builds a Coin VALUE (fee calc, event/struct init,
        # zero-balance account construction). A function that actually MOVES the
        # constructed coin still matches SendCoins / SendCoinsFromModuleTo* / bank.Send*
        # / MintCoins / BurnCoins above, so real transfers keep transfer_hit=True.
        # Matching bare `sdk.NewCoin` false-flagged every Cosmos coin-constructing fn
        # (extremely common) as a custody mover, which blocked legitimate non-economic
        # dispositions (a pure constructor could never be dropped). Removed 2026-07-03.
    ],
    "rs": [
        # CosmWasm / Substrate / SPL token
        re.compile(r"\bBankMsg\s*::\s*Send\b"),
        re.compile(r"\bbank\s*::\s*send\b"),
        re.compile(r"\btransfer\s*\{", re.I),
        re.compile(r"\bcoins!\s*\(", re.I),
        re.compile(r"\bspl_token\s*::\s*transfer\b", re.I),
        re.compile(r"\btransfer_checked\s*\(", re.I),
        re.compile(r"\bmint_to\s*\(", re.I),
        re.compile(r"\bburn_from\s*\(", re.I),
        # Substrate pallet_balances / orml_tokens
        re.compile(r"\bT\s*::\s*Currency\s*::\s*transfer\b"),
        re.compile(r"\bCurrency\s*::\s*transfer\b"),
        re.compile(r"\bpallet_balances\s*::\s*Pallet\s*::", re.I),
        # Generic Rust value moves: send / withdraw / deposit / transfer method calls
        re.compile(r"\.send\s*\(", re.I),
        re.compile(r"\.withdraw\s*\(", re.I),
        re.compile(r"\.deposit\s*\(", re.I),
        re.compile(r"\.transfer\s*\(", re.I),
        # CosmWasm Response / SubMsg with funds
        re.compile(r"\bCosmosMsg\s*::\s*Bank\b"),
        re.compile(r"\bsubmessage\s*::\s*send\b", re.I),
        re.compile(r"\bfunds\s*:\s*vec!\[", re.I),
        re.compile(r"\bfunds\s*:\s*coins\s*\(", re.I),
        # near-sdk / anchor / solana program transfer shapes
        re.compile(r"\bPromise\s*::\s*new\b"),
        re.compile(r"\benv::promise_batch_action_transfer\b"),
        re.compile(r"\bsystem_instruction\s*::\s*transfer\b"),
        re.compile(r"\binvoke\s*\(", re.I),
        re.compile(r"\binvoke_signed\s*\(", re.I),
        # amount/balance compound-assignment (value ledger mutations without self.)
        re.compile(r"\b\w+_amount\s*[+\-]?="),
        re.compile(r"\b\w+_balance\s*[+\-]?="),
        re.compile(r"\bbalance\s*[+\-]?="),
        re.compile(r"\bamount\s*[+\-]?="),
    ],
    "move": [
        re.compile(r"\bcoin\s*::\s*transfer\s*\(", re.I),
        re.compile(r"\bcoin\s*::\s*withdraw\s*\(", re.I),
        re.compile(r"\bcoin\s*::\s*deposit\s*\(", re.I),
        re.compile(r"\baptos_account\s*::\s*transfer\s*\(", re.I),
        re.compile(r"\bprimary_fungible_store\s*::\s*transfer\s*\(", re.I),
        re.compile(r"\bfungible_asset\s*::\s*transfer\s*\(", re.I),
    ],
    "cairo": [
        re.compile(r"\btransfer\s*\(", re.I),
        re.compile(r"\btransfer_from\s*\(", re.I),
        re.compile(r"\bIERC20\w*\s*::\s*transfer\b", re.I),
        re.compile(r"\bERC20\s*::\s*transfer\b", re.I),
    ],
    "js": [
        # EVM-bridge token move (counterstake-bridge evm-chain.js): erc20.transfer(
        re.compile(r"\.transfer\s*\(", re.I),
        # Obyte `payment` app message = an on-chain value transfer of the AA/wallet
        # funds. Word-boundary token so it fires on `app: 'payment'` / a `payment`
        # message object, but NOT inside camelCase names like `sendPayment` (those
        # are matched by the explicit call patterns below).
        re.compile(r"\bpayment\b", re.I),
        # High-level wallet/DAG send APIs that actually move bytes/assets.
        re.compile(r"\bsendPayment\w*\s*\(", re.I),
        re.compile(r"\bsendMultiPayment\s*\(", re.I),
        # Writer/composer commit paths that persist a value-bearing joint/tx.
        re.compile(r"\baddTransaction\s*\(", re.I),
        re.compile(r"\bcomposeAndSaveJoint\s*\(", re.I),
        # Balance-mutating output construction: outputs.push / arrOutputs.push /
        # payload.outputs.push (each appends a {address, amount} value output).
        re.compile(r"\b\w*outputs\s*\.\s*push\s*\(", re.I),
    ],
}

# ---------------------------------------------------------------------------
# Go bare-assignment write. The optional `(?:k\.|s\.|app\.)?` prefix means this
# ALSO matches an UNQUALIFIED assignment `vaults = append(vaults, v)` /
# `vaults[a] = true` on a LOCAL variable in a read-only query / pure constructor /
# validator. In Go there is no bare package-level mutable storage the way Solidity
# has storage fields - real ledger state is written through a keeper/store receiver
# (`k.`/`s.`/`app.`) or a store method (`.Set(`), so an unqualified bare assignment
# is a LOCAL variable, never a ledger write. `_go_bare_assign_is_local` gates it in
# the Part B loop (Go-scoped) so a local slice/map build stops inflating the
# per-language value-moving floor. nuva 2026-07-12 FPs: query_server.go::Vaults
# (`vaults := []types.VaultAccount{}` + `vaults = append(...)`), events.go
# (`metadataDenomUnits = append(...)`), genesis.go::Validate (local `vaults` dedup
# map). A qualified write (`k.balances[addr] = x`) keeps the prefix and still counts.
# ---------------------------------------------------------------------------
_GO_BARE_ASSIGN_RE: re.Pattern = re.compile(
    r"(?<![.\w])(?:k\.|s\.|app\.)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>:])[-+*/|&^%]?=(?!=)"
)


def _go_bare_assign_is_local(m: re.Match) -> bool:
    """True iff a Go `_GO_BARE_ASSIGN_RE` hit is an UNQUALIFIED local variable
    assignment (no `k.`/`s.`/`app.` store/keeper receiver). Such a hit is a local
    slice/map/scalar build in a read-only query, pure constructor, or validator -
    it moves no value and must NOT count as a ledger write. Conservative + Go-scoped:
    a qualified keeper/store write (`k.field = x`) keeps its prefix and still counts,
    and a struct-field write (`vault.TotalShares = x`) is matched by the separate
    member-assignment regex, not this one."""
    g0 = m.group(0)
    return not (
        g0.startswith("k.") or g0.startswith("s.") or g0.startswith("app.")
    )


# ---------------------------------------------------------------------------
# Go FILE/PACKAGE-SHAPE false-positive narrowing (axelar-dlt 2026-07-13).
# ---------------------------------------------------------------------------
# The classifier over-flags three Go FILE/PACKAGE shapes that can NEVER move the
# on-chain ledger. They are keyed on FILE/PACKAGE SHAPE (not on a blanket
# qualified-receiver-write suppression, which would introduce false-negatives - a
# receiver-field write in a KEEPER that is then persisted IS a real value-mover):
#
#   (1) READ-ONLY gRPC QUERY SERVER - a Cosmos `grpc_query.go` whose exported
#       methods all take a `*...Request` and return `(*...Response, error)`, or
#       whose receiver type is a `Querier`/`queryServer`/`QueryServer`. By the
#       gRPC query-server contract these cannot persist state (msg writes live in
#       the sibling `msg_server.go`, never here), so drop the whole file.
#   (2) PURE TYPE-DEFINITION package file (`.../types/types.go`,
#       `.../exported/types.go`) whose flagged function only mutates the method's
#       OWN RECEIVER struct field (`m.X = ...` / `append(m.X, ...)`) with NO
#       keeper/store handle in the body - an in-memory proto mutation, not a
#       persisted ledger write. Per-FUNCTION drop (a real bank Send / store write
#       in such a file keeps the function).
#   (3) CLIENT CLI file (`.../client/cli/...`) - builds messages client-side and
#       never executes on-chain state; drop the whole file.
#
# A file/function with a real keeper/store write, bank Send/Mint/Burn, or escrow
# op is NOT matched by any of these shapes and STAYS value-moving.

# gRPC method: `func (recv Type) Name(ctx, req *pkg.XRequest) (*pkg.XResponse, error)`
_GO_METHOD_DECL_RE = re.compile(
    r"func\s*\(\s*\w+\s+\*?([A-Za-z_][\w.]*)\s*\)\s*([A-Za-z_]\w*)\s*"
    r"\(([^)]*)\)\s*(?:\(([^)]*)\)|(\*?[\w.]+))",
)
# Receiver type that is a query server by NAME (Querier / *queryServer / QueryServer).
_GO_QUERY_RECEIVER_RE = re.compile(r"(?i)(?:^|\b)(?:querier|query[_]?server)$")
# keeper/store persistence handle in a body: proves a write reaches the ledger.
_GO_STORE_HANDLE_RE = re.compile(
    r"(?<![.\w])(?:k|s|app)\.|\.Set\s*\(|\.Store\s*\(|ctx\.KVStore|\.Append\s*\("
    r"|SendCoins|MintCoins|BurnCoins|\.Send\w*\s*\(",
)


def _go_is_readonly_query_server(text: str, rel: str) -> bool:
    """True iff a Go file is a read-only gRPC query server (shape (1)).

    Positive only when EITHER the receiver type is a Querier/queryServer/
    QueryServer, OR the basename is the Cosmos-canonical ``grpc_query.go`` AND
    every exported method has the read-only ``*...Request -> (*...Response, error)``
    shape. Requiring the request/response shape (never violated by a writing
    method) is the belt-and-suspenders guard against dropping a file that somehow
    persists state. Msg servers (``msg_server.go``) are never matched - their
    writes live in a different file."""
    base = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
    receiver_querier = False
    all_exported_request_response = True
    saw_exported = False
    for mm in _GO_METHOD_DECL_RE.finditer(text):
        recv_type, name, params = mm.group(1), mm.group(2), mm.group(3)
        rets = mm.group(4) or mm.group(5) or ""
        if _GO_QUERY_RECEIVER_RE.search(recv_type):
            receiver_querier = True
        if name and name[0].isupper():
            saw_exported = True
            if not ("Request" in params and "Response" in rets):
                all_exported_request_response = False
    if receiver_querier:
        return True
    if base == "grpc_query.go" and saw_exported and all_exported_request_response:
        return True
    return False


def _go_is_client_cli(rel: str) -> bool:
    """True iff a Go file is a client-side CLI tx/query builder (shape (3))."""
    n = rel.replace("\\", "/")
    return "/client/cli/" in n or n.startswith("client/cli/")


def _go_is_pure_typedef_file(rel: str) -> bool:
    """True iff a Go file is a pure type-definition package file (shape (2)):
    ``.../types/types.go`` or ``.../exported/types.go``. Narrow by design - only
    the canonical proto/type-def file, never an arbitrary keeper .go."""
    n = rel.replace("\\", "/")
    return n.endswith("/types/types.go") or n.endswith("/exported/types.go") \
        or n == "types/types.go" or n == "exported/types.go"


_GO_MIGRATE_CTXONLY_RE = re.compile(
    r"\bMigrate\w*\s*\(\s*\w+\s+(?:sdk\.Context|context\.Context)\s*\)")


def _go_fn_is_lifecycle(name: str, signature: str) -> bool:
    """True iff a Go function is a Cosmos-SDK MODULE LIFECYCLE hook that is NOT
    externally-attacker-reachable, so it is not a fuzzable value-moving asset:

      * ``InitGenesis`` / ``ExportGenesis`` - run ONCE at chain genesis by the module
        manager (InitGenesis writes the KVStore, so the ledger-write shape flags it);
        an attacker cannot re-invoke them with adversarial input. A malformed-genesis
        concern is a ``ValidateGenesis`` / read audit axis, not a >=1M-call invariant
        target. These are RESERVED Cosmos module method names, never user msg handlers.
      * a ``Migrate*`` STORE-MIGRATION handler whose signature is ctx-ONLY
        (``func (m Migrator) MigrateX(ctx sdk.Context) error``) - registered via
        ``cfg.RegisterMigration`` and run ONCE under a gov-gated upgrade.

    This is the value-moving analog of the genesis/migration SCAFFOLDING the
    go_entrypoint_surface classifier already excludes from the coverage denominator
    (2026-07-14 nuva: genesis.go::InitGenesis + migrations.go::Migrate... were the
    only two "value-moving asset-gap" files, both lifecycle-only).

    FALSE-NEGATIVE GUARD: the ``Migrate*`` arm requires a ctx-only signature. A
    user-facing migration msg handler (``MigratePosition(goCtx, *types.MsgMigrate...)``)
    takes a second msg/request param, so the ctx-only regex does NOT match it and it
    stays value-moving. ``InitGenesis``/``ExportGenesis`` are exact-name reserved."""
    if name in ("InitGenesis", "ExportGenesis"):
        return True
    if name.startswith("Migrate"):
        return bool(_GO_MIGRATE_CTXONLY_RE.search(signature))
    return False


def _go_typedef_fn_is_inmemory(body: str, has_transfer: bool) -> bool:
    """True iff a flagged function in a pure type-def file only mutates its own
    receiver struct field in memory - NO keeper/store persistence handle and NO
    token transfer in the body (shape (2), per-function). Such a hit is an
    in-memory proto mutation (`m.Assets = append(m.Assets, ...)`), not a ledger
    write, so it is dropped. A body with a real store handle or a bank transfer
    is NOT in-memory and stays value-moving (guards the false-negative)."""
    if has_transfer:
        return False
    return not bool(_GO_STORE_HANDLE_RE.search(body))


# ---------------------------------------------------------------------------
# Per-language LEDGER-WRITE patterns (part B of the union).
# Mirrors _WRITE_RES in cross-function-invariant-coverage.py - KEEP IN SYNC. As of
# the sibling's mirror commit the two Go tables are CONSISTENT AGAIN: both name the
# bare-assignment regex `_GO_BARE_ASSIGN_RE`, gate it via `_go_bare_assign_is_local`
# in their write-scan loop so an unqualified local `vaults = append(...)` is not a
# write, and both carry the cosmos collections `.Set/.Remove/.Append` store-write
# pattern. Other languages are byte-identical to the sibling table.
# ---------------------------------------------------------------------------
_WRITE_RES: dict[str, list[re.Pattern]] = {
    "sol": [
        # bare storage field assignment (not via member access)
        re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
        re.compile(r"\bthis\.([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
    ],
    "rs": [
        re.compile(r"\bself\.([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
        re.compile(r"\b([A-Z][A-Za-z0-9_]*)::(?:<[^>]*>::)?(?:put|set|insert|mutate|kill|take|remove)\s*\("),
        # Vec/container push on a value-named field: self.amounts.push(...) etc.
        re.compile(r"\bself\.([A-Za-z_]\w*)\.push\s*\("),
        # HashMap/BTreeMap insert on a value-named field: self.balances.insert(...)
        re.compile(r"\bself\.([A-Za-z_]\w*)\.insert\s*\("),
        # entry().or_insert / entry().and_modify with compound assignment on the result
        # Capture the field name from the entry call: self.FIELD.entry(
        re.compile(r"\bself\.([A-Za-z_]\w*)\.entry\s*\("),
    ],
    "go": [
        _GO_BARE_ASSIGN_RE,
        re.compile(r"\.Set([A-Z]\w*)\s*\("),
        # Cosmos collections / keeper STORE write: `k.Vaults.Set(ctx, addr, v)`,
        # `k.Balances.Remove(...)`, `seq.Append(...)`. The bare `.Set(`/`.Remove(`/
        # `.Append(` method (no capital suffix) was invisible to the `.Set([A-Z]...)`
        # pattern above, so a genuine collections store write went uncredited. Capture
        # the RECEIVER name and value-filter it via `_is_value_field` so a non-ledger
        # receiver (`params.Set(`, `header.Set(`, `flags.Set(`) is dropped while a
        # value-named store (`vaults`/`balances`/`Vaults`) counts. Go-scoped.
        re.compile(r"\b([A-Za-z_]\w*)\.(?:Set|Remove|Append)\s*\("),
        # STRUCT-FIELD assignment on ANY receiver: `vault.TotalShares = ...`,
        # `vault.OutstandingAumFee += ...`. The cosmos pattern is: fetch a struct from
        # a collection into a LOCAL (`vault, _ := k.VaultAccounts.Get(...)`), mutate a
        # SUBSET of its coupled fields, then `.Set(...)` it back. The coupled obligation
        # is between those STRUCT FIELDS (TotalShares<->Principal<->OutstandingAumFee) -
        # the must-move-together / partial-flush surface. The prior go regexes only
        # captured `k.Field=`/bare `field=` (the `(?<![.\w])` lookbehind BLOCKS a member
        # field), so a local-struct field write was invisible and the conserved-with lane
        # never saw the coupled fields (NUVA: Go VMF evidence held collection/local names
        # `VaultAccount`/`vault`/`fee`, never `TotalShares`/`Principal`). Value-filtered by
        # _is_value_field so a non-value member (`x.owner=`) is dropped.
        re.compile(r"\.([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>:])[-+*/|&^%]?=(?!=)"),
    ],
    "move": [
        re.compile(r"\bmove_to\b[^;]*<\s*([A-Za-z_]\w*)"),
        re.compile(r"\bborrow_global_mut\b[^;]*<\s*([A-Za-z_]\w*)"),
    ],
    "cairo": [
        re.compile(r"\bself\.([A-Za-z_]\w*)\.write\s*\("),
        re.compile(r"\b([A-Za-z_]\w*)::write\s*\("),
    ],
    "js": [
        # Obyte in-memory balance ledger write, indexed form:
        #   `assocBalances[asset] = {...}` / `balances[addr] = x` /
        #   `trigger_opts.assocBalances[address] = {}`. Group 1 is the balance-named
        #   token (assocBalances / balances / newBalances) and is value-filtered by
        #   _is_value_field via its `balance` root.
        re.compile(r"\b(\w*[Bb]alances?)\s*\[[^\]]*\]\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
        # Whole-map / member balance assignment: `assocBalances = {}` /
        #   `objValidationState.assocBalances = {}`. Same value-named group-1 gate.
        re.compile(r"\b(\w*[Bb]alances?)\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
        # Persistent KV/store setter (`storage.setBalance(...)` and kin): capture
        #   the setter METHOD name and value-filter it, so `storage.setBalance` /
        #   `.setAssetInfo` count while `storage.setUnitIsKnown` / `.setTimestamp`
        #   are dropped by _is_value_field. Same shape as the Go `.Set([A-Z]...)`
        #   pattern, lowercased for JS camelCase setters.
        re.compile(r"\.(set[A-Za-z_]\w*)\s*\("),
    ],
}

# ---------------------------------------------------------------------------
# Value-field name filter: a written token must contain at least one of these
# roots (case-insensitive) to count as a ledger-field write. This eliminates
# noise from locals like `nonce`, `timestamp`, `owner`, `paused`, etc.
# ---------------------------------------------------------------------------
_VALUE_ROOTS = re.compile(
    r"balance|credit|debt|share|unit|amount|asset|vault|escrow"
    r"|collateral|reserve|stake|supply|borrow|lend|deposit|withdraw"
    r"|liquidity|fund|pool|holding|position|fee|reward|token|coin"
    r"|mint|burn|principal|nav|yield|interest|payout|redemption",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Stopwords: field names that are never shared ledger state (same set as
# cross-function-invariant-coverage._FIELD_STOPWORDS, extended with common
# non-value names).
# ---------------------------------------------------------------------------
_FIELD_STOPWORDS: frozenset[str] = frozenset({
    "return", "let", "var", "const", "if", "for", "while", "uint", "int",
    "bool", "address", "bytes", "string", "memory", "storage", "mut", "self",
    "this", "result", "ok", "err", "true", "false", "i", "j", "k", "n", "x",
    "y", "z", "tmp", "temp", "_", "out", "data", "value", "amount", "msg",
    "require", "assert", "emit", "new", "type",
    "name", "symbol", "href", "imageuri", "ibyte",
    "msb", "shift", "exponent", "xexponent", "yexponent",
    "capexponent", "resultexponent", "downcasted",
    "rx", "ss", "ep", "ds",
    # common non-value identifiers
    "nonce", "timestamp", "owner", "admin", "paused", "initialized",
    "version", "slot", "idx", "index", "count", "num", "flag", "lock",
})


def _is_value_field(tok: str) -> bool:
    """True iff ``tok`` looks like a ledger/value field (not a local variable)."""
    tl = tok.lower()
    if tl in _FIELD_STOPWORDS:
        return False
    if len(tok) <= 1:
        return False
    return bool(_VALUE_ROOTS.search(tok))


# ---------------------------------------------------------------------------
# Category D: AUTHZ-WRITE field filter (extended, gated).
# A SEPARATE tier from _is_value_field - deliberately NOT merged into
# _VALUE_ROOTS, which is correctly tuned for token/balance amounts. A
# role/permission mapping stores authorization BITS, not amounts, but gates
# every OTHER value-moving function in the contract (e.g. onlyRole checks),
# so it is a value-moving write in the sense that matters for audit coverage.
# ---------------------------------------------------------------------------
_AUTHZ_ROOTS = re.compile(
    r"role|permission|access|operator|allow(?:ed)?|whitelist|blacklist"
    r"|grant|revoke|admin|authoriz|capability|entitle",
    re.IGNORECASE,
)

# Direct grantRole/revokeRole/setRole-shaped call sites (OZ AccessControl and
# custom equivalents) - a strong signal even without a bare field-name write,
# since these often go through an internal library call rather than a bare
# `field[key] = value` assignment that the generic _WRITE_RES table catches.
_AUTHZ_CALL_RES: dict[str, list[re.Pattern]] = {
    "sol": [
        re.compile(r"\bgrantRole\s*\(", re.I),
        re.compile(r"\brevokeRole\s*\(", re.I),
        re.compile(r"\b_setupRole\s*\(", re.I),
        re.compile(r"\b_grantRole\s*\(", re.I),
        re.compile(r"\b_revokeRole\s*\(", re.I),
    ],
    "go": [
        re.compile(r"\bGrantRole\s*\(", re.I),
        re.compile(r"\bRevokeRole\s*\(", re.I),
        re.compile(r"\bSetPermission\w*\s*\(", re.I),
    ],
    "rs": [
        re.compile(r"\bgrant_role\s*\(", re.I),
        re.compile(r"\brevoke_role\s*\(", re.I),
        re.compile(r"\bset_permission\w*\s*\(", re.I),
    ],
}


def _is_authz_field(tok: str) -> bool:
    """True iff ``tok`` looks like a role/permission/access-control field.

    Deliberately a SEPARATE check from ``_is_value_field`` - a role mapping
    (e.g. ``role[addr] = true`` or ``permissions[selector] = mask``) stores
    authorization bits, not token amounts, so it must never be folded into
    the token-tuned ``_VALUE_ROOTS`` regex (that would weaken/broaden A/B).
    """
    tl = tok.lower()
    if tl in _FIELD_STOPWORDS:
        return False
    if len(tok) <= 1:
        return False
    return bool(_AUTHZ_ROOTS.search(tok))


# ---------------------------------------------------------------------------
# Test-attribute detection for Rust (per-function, not per-file).
# A Rust fn preceded within ~3 lines by #[test] or #[tokio::test] is a
# test fn that lives in a non-test file (e.g. inline #[cfg(test)] block).
# We skip it regardless of the file path.
# ---------------------------------------------------------------------------
_RUST_TEST_ATTR_RE = re.compile(
    r"#\[\s*(?:tokio\s*::\s*)?test\b",
)


def _rust_fn_is_test(source: str, sig_start: int) -> bool:
    """Return True if the fn at sig_start is annotated with a test attribute.

    Scans backward from sig_start through up to ~5 lines to find a
    ``#[test]`` or ``#[tokio::test]`` attribute line.  Stops early when it
    encounters the closing brace of the previous function ('}' at column 0
    or after only whitespace), a ``pub``/``fn`` keyword indicating a
    non-attribute line, or any line that is clearly not an attribute.
    """
    # Grab the text before the fn keyword (up to 300 chars backward).
    prefix = source[max(0, sig_start - 300): sig_start]
    # Walk backward line-by-line.
    lines = prefix.splitlines()
    for line in reversed(lines[-6:]):
        stripped = line.strip()
        if not stripped:
            continue
        if _RUST_TEST_ATTR_RE.search(stripped):
            return True
        # If we hit a closing brace or another fn/pub statement, stop.
        if stripped.startswith("}") or stripped.startswith("pub ") or stripped.startswith("fn "):
            break
        # Allow attribute lines (#[...]) and doc comments to pass through.
        if stripped.startswith("#[") or stripped.startswith("///") or stripped.startswith("//"):
            continue
        # Any other non-empty, non-attribute line: stop scanning backward.
        break
    return False


# ---------------------------------------------------------------------------
# Body extraction: find the opening brace after the function signature and
# extract everything up to the matching closing brace.
# Returns the body text (empty string if no body / abstract fn).
# ---------------------------------------------------------------------------
def _extract_body(source: str, sig_end: int) -> str:
    """Extract the brace-delimited body starting at or after ``sig_end``."""
    i = source.find("{", sig_end)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(source)):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[i + 1: j]
    return source[i + 1:]


# ---------------------------------------------------------------------------
# Category C: GUARDED-BRANCH CALLEE detection (extended, gated).
# Same-file, name-match call-graph check: a callee with no direct A/B hit that
# is invoked from within a conditional branch of an already value-moving
# caller (in the SAME file) is flagged. Deliberately simple/cheap - no
# cross-file resolution, no full CFG - to stay generic and language-portable.
# ---------------------------------------------------------------------------

# A conditional-branch header: "if (...)" / "} else if (...)" / "elif" etc,
# with a comparison-shaped operator inside the parens (a bare `if (flag)`
# guard with no comparison is intentionally NOT matched - we want the
# "guarded by a comparison" shape called out in the spec, e.g. valuation/
# price/threshold checks, not every boolean flag branch).
_GUARD_BRANCH_RE = re.compile(
    r"\b(?:if|else\s+if|elif)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)",
    re.IGNORECASE,
)
_COMPARISON_OP_RE = re.compile(r"[<>]=?|==|!=")


def _guarded_branch_spans(body: str) -> list[tuple[int, int]]:
    """Return (start, end) char spans of the body that lie inside a
    comparison-guarded conditional branch's own block (the '{ ... }' that
    immediately follows the guarded 'if (...)' header, or - for a
    brace-less single-statement branch - up to the next ';').

    Best-effort / regex-based: intentionally simple (same trade-off as the
    rest of this module) rather than a full parser.
    """
    spans: list[tuple[int, int]] = []
    for gm in _GUARD_BRANCH_RE.finditer(body):
        cond = gm.group(1)
        if not _COMPARISON_OP_RE.search(cond):
            continue
        after = gm.end()
        # Skip whitespace to find the branch body start.
        k = after
        while k < len(body) and body[k] in " \t\r\n":
            k += 1
        if k < len(body) and body[k] == "{":
            depth = 0
            for j in range(k, len(body)):
                c = body[j]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        spans.append((k + 1, j))
                        break
        else:
            # brace-less single statement: up to the next ';'
            semi = body.find(";", k)
            if semi != -1:
                spans.append((k, semi + 1))
    return spans


def _find_guarded_callee_names(body: str) -> set[str]:
    """Names that appear called (``name(``) inside a comparison-guarded
    conditional branch of ``body``."""
    names: set[str] = set()
    call_re = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    for start, end in _guarded_branch_spans(body):
        seg = body[start:end]
        for cm in call_re.finditer(seg):
            names.add(cm.group(1))
    return names


# ---------------------------------------------------------------------------
# Core analysis: scan one source file -> list of value-moving function dicts.
# ---------------------------------------------------------------------------
def _analyze_file(
    path: Path, rel: str, lang: str
) -> list[dict[str, Any]]:
    """Scan ``path`` and return one record per value-moving function."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    fn_re = _FN_RES.get(lang)
    if fn_re is None:
        return []

    # A Go `package main` file is a build-time tool (a //go:generate codegen
    # generator like contractsgen/generate.go, or the node/cmd entrypoint) - NOT
    # the value-moving PROTOCOL surface, which by Cosmos convention lives in
    # library packages (keeper / msg_server / module). Its shape-matched "writes"
    # (a generator emitting Go source, a cmd main wiring the app) are not
    # fund/share-conservation obligations. axelar-dlt 2026-07-12:
    # parseContracts@x/evm/types/contractsgen/generate.go (a `package main`
    # go:generate binary) was shape-flagged ledger_write_hit and inflated the
    # per-language value-moving floor. Scoped to Go so other languages are
    # byte-identical.
    if lang == "go" and re.search(r"(?m)^package\s+main\b", text):
        return []

    # FILE/PACKAGE-SHAPE narrowing (axelar-dlt 2026-07-13): drop whole-file for a
    # read-only gRPC query server (shape 1) or a client CLI builder (shape 3);
    # neither can persist on-chain value. The pure-type-def file (shape 2) is
    # narrowed PER-FUNCTION in the Part-B loop below, since a real bank Send /
    # store write in such a file must still be kept.
    if lang == "go" and (
        _go_is_readonly_query_server(text, rel) or _go_is_client_cli(rel)
    ):
        return []
    go_typedef_file = lang == "go" and _go_is_pure_typedef_file(rel)

    transfer_res = _TRANSFER_RES.get(lang, [])
    write_res = _WRITE_RES.get(lang, [])
    authz_call_res = _AUTHZ_CALL_RES.get(lang, [])
    extended = _extended_enabled()

    # First pass: base (A/B) candidates, keyed by function name, plus every
    # candidate function's body (even non-value-moving ones) so category C
    # can check callee names against value-moving callers' guarded branches.
    # NOTE: same-file only - callers in another file are out of scope for
    # this cheap, name-match-based call-graph check (per spec).
    base_records: list[dict[str, Any]] = []
    # name -> list of (body, is_value_moving) - a name can repeat (overloads).
    fn_bodies: dict[str, list[tuple[str, bool]]] = {}

    for m in fn_re.finditer(text):
        fn_name = m.group(1)
        sig_end = m.end()
        # Skip Rust inline test fns (e.g. #[test] fn ...) that live in non-test
        # files. Per-file OOS filtering already handles *_test.rs / tests/ dirs;
        # this guard handles #[test]/#[tokio::test] fns in production .rs files.
        if lang == "rs" and _rust_fn_is_test(text, m.start()):
            continue
        body = _extract_body(text, sig_end)
        if not body:
            continue

        # Solidity bodiless declaration guard: a function whose signature is
        # terminated by ';' before the opening '{' is an interface method or
        # abstract/external declaration with no implementation body.  The
        # _extract_body call above finds the NEXT '{' in the file - which may
        # belong to the following contract or function - and incorrectly returns
        # that block as the body.  Concretely, IWETH.withdraw/balanceOf
        # (interface declarations with ';') absorb UnwrapAndSendETH's body,
        # which contains call{value:}, and are mis-flagged as value-movers.
        # Fix: for Solidity, if the first ';' after sig_end precedes the first
        # '{' after sig_end, the declaration is bodiless - skip it.
        if lang == "sol":
            next_semi_bld = text.find(";", sig_end)
            next_brace_bld = text.find("{", sig_end)
            if next_brace_bld < 0 or (
                next_semi_bld >= 0 and next_semi_bld < next_brace_bld
            ):
                continue

        # Solidity view/pure functions are compiler-guaranteed to neither write
        # storage nor transfer value, so they can never be value-moving. The
        # write-detector otherwise mis-credits storage-field *reads* (e.g. a
        # getter that returns balances/totalSupply) as ledger writes, flooding
        # every downstream lane with view/getter false-positives. The state-
        # mutability keyword lives in the header between the signature ")" and
        # the body "{"; word-boundary, lowercase-only (Solidity keywords are
        # lowercase) so a type named `View`/`Pure` is not matched.
        if lang == "sol":
            brace_pos = text.find("{", sig_end)
            if brace_pos != -1:
                header_tail = text[sig_end:brace_pos]
                if _SOL_NONMUTATING_RE.search(header_tail):
                    continue

        # Part A: transfer-call detection
        transfer_evidence: list[str] = []
        for rx in transfer_res:
            hit = rx.search(body)
            if hit:
                # collect a short snippet (up to 80 chars) around the match
                start = max(0, hit.start() - 10)
                snippet = body[start: hit.end() + 20].strip().replace("\n", " ")
                transfer_evidence.append(snippet[:80])
                break  # one hit is enough; we don't need to exhaust all patterns

        # Part B: ledger-write detection
        ledger_fields: list[str] = []
        for rx in write_res:
            for wm in rx.finditer(body):
                # Go: an UNQUALIFIED bare assignment is a local variable, not a
                # ledger write (e.g. `vaults = append(vaults, v)` in a read-only
                # query). Drop it; a qualified keeper/store write still counts.
                if (
                    lang == "go"
                    and rx is _GO_BARE_ASSIGN_RE
                    and _go_bare_assign_is_local(wm)
                ):
                    continue
                tok = wm.group(1) if wm.lastindex else ""
                if tok and _is_value_field(tok):
                    if tok not in ledger_fields:
                        ledger_fields.append(tok)

        is_value_moving_ab = bool(transfer_evidence) or bool(ledger_fields)

        # Shape (2): in a pure type-def file, a function that only mutates its own
        # receiver struct field in memory (no store handle, no transfer) is NOT a
        # ledger write - drop it. A real store write / bank transfer in the same
        # file keeps the function (guards the false-negative).
        if (
            go_typedef_file
            and is_value_moving_ab
            and _go_typedef_fn_is_inmemory(body, bool(transfer_evidence))
        ):
            is_value_moving_ab = False
            ledger_fields = []

        # Track every candidate fn body (value-moving or not) for the
        # category-C same-file guarded-callee pass below, regardless of the
        # extended gate - the gate only controls whether category C/D fields
        # are ever EMITTED, not this cheap bookkeeping.
        fn_bodies.setdefault(fn_name, []).append((body, is_value_moving_ab))

        if not is_value_moving_ab:
            continue

        # Cosmos-SDK lifecycle hook (InitGenesis / ExportGenesis / ctx-only
        # Migrate* store-migration): writes the KVStore but is NOT attacker-
        # reachable, so it is not a fuzzable value-moving asset (2026-07-14).
        # fn_re stops at the opening '(' of the param list, so extend the slice to
        # the param-list close-paren so the ctx-only Migrate* signature check sees
        # the params (a msg-handler's second param keeps it value-moving).
        if lang == "go":
            _close = text.find(")", sig_end)
            _sig_region = text[m.start():_close + 1] if _close != -1 else text[m.start():sig_end]
            if _go_fn_is_lifecycle(fn_name, _sig_region):
                continue

        rec: dict[str, Any] = {
            "file": rel,
            "function": fn_name,
            "language": lang,
            "transfer_hit": bool(transfer_evidence),
            "ledger_write_hit": bool(ledger_fields),
            "transfer_evidence": transfer_evidence,
            "ledger_write_evidence": ledger_fields,
        }

        # Part D: authz-write detection (extended, gated). ADDITIVE only -
        # this function is already value-moving via A/B; authz_write_hit is
        # an extra evidence tag, never a reason to include/exclude a record.
        if extended:
            authz_fields: list[str] = []
            for rx in write_res:
                for wm in rx.finditer(body):
                    if (
                        lang == "go"
                        and rx is _GO_BARE_ASSIGN_RE
                        and _go_bare_assign_is_local(wm)
                    ):
                        continue
                    tok = wm.group(1) if wm.lastindex else ""
                    if tok and _is_authz_field(tok):
                        if tok not in authz_fields:
                            authz_fields.append(tok)
            if any(rx.search(body) for rx in authz_call_res):
                if "<authz-call>" not in authz_fields:
                    authz_fields.append("<authz-call>")
            rec["authz_write_hit"] = bool(authz_fields)
            rec["authz_write_evidence"] = authz_fields
            rec["guarded_callee_hit"] = False
            rec["guarded_callee_caller"] = None

        base_records.append(rec)

    results: list[dict[str, Any]] = list(base_records)

    # Category D (standalone): a function that is ONLY an authz-write (no
    # A/B hit at all) must still be captured - e.g. a pure role-grant setter
    # with no token/balance field write. Re-scan every candidate NOT already
    # counted via A/B.
    if extended:
        for m in fn_re.finditer(text):
            fn_name = m.group(1)
            sig_end = m.end()
            if lang == "rs" and _rust_fn_is_test(text, m.start()):
                continue
            body = _extract_body(text, sig_end)
            if not body:
                continue
            if lang == "sol":
                next_semi_bld = text.find(";", sig_end)
                next_brace_bld = text.find("{", sig_end)
                if next_brace_bld < 0 or (
                    next_semi_bld >= 0 and next_semi_bld < next_brace_bld
                ):
                    continue
                brace_pos = text.find("{", sig_end)
                if brace_pos != -1:
                    header_tail = text[sig_end:brace_pos]
                    if _SOL_NONMUTATING_RE.search(header_tail):
                        continue
            # Skip if this exact (name, body) combination was already
            # recorded as an A/B hit above (avoid double-counting overloads).
            if any(b == body and vm for (b, vm) in fn_bodies.get(fn_name, [])):
                continue

            authz_fields = []
            for rx in write_res:
                for wm in rx.finditer(body):
                    tok = wm.group(1) if wm.lastindex else ""
                    if tok and _is_authz_field(tok):
                        if tok not in authz_fields:
                            authz_fields.append(tok)
            has_authz_call = any(rx.search(body) for rx in authz_call_res)
            if has_authz_call and "<authz-call>" not in authz_fields:
                authz_fields.append("<authz-call>")

            if not authz_fields:
                continue

            results.append({
                "file": rel,
                "function": fn_name,
                "language": lang,
                "transfer_hit": False,
                "ledger_write_hit": False,
                "transfer_evidence": [],
                "ledger_write_evidence": [],
                "authz_write_hit": True,
                "authz_write_evidence": authz_fields,
                "guarded_callee_hit": False,
                "guarded_callee_caller": None,
            })

    # Category C (extended, gated): a callee with NO direct A/B hit that is
    # invoked from within a comparison-guarded branch of an already
    # value-moving (A/B) caller, in the SAME file. Simple name-match call
    # graph - not interprocedural, not cross-file.
    if extended:
        value_moving_names = {r["function"] for r in base_records}
        guarded_callee_names: dict[str, str] = {}  # callee -> caller name
        for caller_name in value_moving_names:
            for (caller_body, is_vm) in fn_bodies.get(caller_name, []):
                if not is_vm:
                    continue
                for callee in _find_guarded_callee_names(caller_body):
                    if callee == caller_name:
                        continue  # skip self-recursive guarded calls
                    if callee not in guarded_callee_names:
                        guarded_callee_names[callee] = caller_name

        already_flagged = {r["function"] for r in results}
        for callee_name, caller_name in guarded_callee_names.items():
            if callee_name in already_flagged:
                continue
            bodies = fn_bodies.get(callee_name)
            if not bodies:
                continue  # callee not defined in this file (out of scope)
            # Use the first recorded (non-value-moving-via-A/B) body.
            callee_body, callee_is_vm_ab = bodies[0]
            if callee_is_vm_ab:
                continue  # already an A/B hit, would have been in base_records
            results.append({
                "file": rel,
                "function": callee_name,
                "language": lang,
                "transfer_hit": False,
                "ledger_write_hit": False,
                "transfer_evidence": [],
                "ledger_write_evidence": [],
                "guarded_callee_hit": True,
                "guarded_callee_caller": caller_name,
                "authz_write_hit": False,
                "authz_write_evidence": [],
            })
            already_flagged.add(callee_name)

    return results


# ---------------------------------------------------------------------------
# DECLARATIVE-language value-movers (manifest-seeded).
# A language with no function-start regex (is_llm_hunt_only + not walked here) -
# e.g. Obyte Oscript AAs - cannot be source-scanned for transfer/ledger call
# sites. Its own in-scope enumerator ALREADY classified each unit's value_movers
# (payment / asset / state / definition) and state_writes into the inscope_units
# manifest, so those rows ARE the authoritative value-mover list: seed one record
# per unit that carries a value_movers or state_writes signal. Purely ADDITIVE to
# the source-walk records; produces nothing for an engine-language workspace (no
# manifest-seed-lang rows), so Solidity/Go/Rust output is byte-identical.
# ---------------------------------------------------------------------------
def _manifest_declarative_value_moving_records(ws: Path) -> list[dict[str, Any]]:
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file() or not _MANIFEST_SEED_LANGS or not _manifest_seed_enabled():
        return []
    try:
        lines = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    extended = _extended_enabled()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            row = json.loads(ln)
        except (ValueError, TypeError):
            continue
        if not isinstance(row, dict):
            continue
        rel = str(row.get("file") or "").replace("\\", "/").strip()
        if not rel:
            continue
        # canonical language: prefer the manifest lang, fall back to the extension.
        lang = str(row.get("lang") or row.get("language") or "").strip().lower()
        if lang not in _MANIFEST_SEED_LANGS:
            lang = _reg_lang_of(rel) or ""
        if lang not in _MANIFEST_SEED_LANGS:
            continue  # engine lang (walked) or unrecognized -> not manifest-seeded
        fn_name = str(row.get("function") or row.get("fn") or "").strip()
        if not fn_name:
            continue
        value_movers = [str(t) for t in (row.get("value_movers") or []) if str(t).strip()]
        state_writes = [str(t) for t in (row.get("state_writes") or []) if str(t).strip()]
        vm_low = {t.strip().lower() for t in value_movers}
        transfer_hit = bool(vm_low & _DECL_TRANSFER_TOKENS)
        ledger_write_hit = bool(state_writes) or bool(vm_low & _DECL_LEDGER_TOKENS)
        if not (transfer_hit or ledger_write_hit):
            continue  # a pure getter / read-only unit is NOT value-moving
        key = (rel, fn_name)
        if key in seen:
            continue
        seen.add(key)
        transfer_evidence = sorted(t for t in value_movers if t.strip().lower() in _DECL_TRANSFER_TOKENS)
        ledger_evidence = (list(state_writes)
                           or sorted(t for t in value_movers if t.strip().lower() in _DECL_LEDGER_TOKENS))
        rec: dict[str, Any] = {
            "file": rel,
            "function": fn_name,
            "language": lang,
            "transfer_hit": transfer_hit,
            "ledger_write_hit": ledger_write_hit,
            "transfer_evidence": transfer_evidence[:8],
            "ledger_write_evidence": ledger_evidence[:8],
        }
        if extended:
            rec["authz_write_hit"] = False
            rec["authz_write_evidence"] = []
            rec["guarded_callee_hit"] = False
            rec["guarded_callee_caller"] = None
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Workspace walker.
# ---------------------------------------------------------------------------
def enumerate_value_moving(workspace: str | Path) -> list[dict[str, Any]]:
    """Walk ``workspace`` and return all value-moving function records."""
    ws = Path(workspace).resolve()
    all_records: list[dict[str, Any]] = []

    # Walk the entire workspace tree. Scope membership is MANIFEST-AUTHORITATIVE
    # via is_in_scope(rel, workspace=ws): when <ws>/.auditooor/inscope_units.jsonl
    # is present and non-empty, only its rows count as in-scope (is_oos still
    # excludes test/vendored/generated). Falls back to ``not is_oos(rel)`` when no
    # manifest exists. Prior code filtered with is_oos alone, which is blind to the
    # workspace's curated scope and leaked OOS modules (e.g. optimism op-e2e /
    # op-chain-ops / op-batcher / cannon) into the value-moving core set, polluting
    # the core-coverage gate's "uncovered core" enumeration.
    for path in sorted(ws.rglob("*")):
        if not path.is_file():
            continue
        lang = _lang(path)
        if lang is None:
            continue
        try:
            rel = str(path.relative_to(ws))
        except ValueError:
            rel = str(path)
        if not is_in_scope(rel, workspace=ws):
            continue
        # GENERATED-CODE EXCLUSION: abigen/protoc bindings (e.g. op-node/bindings/
        # optimismportal.go) carry a "// Code generated ... DO NOT EDIT." header but
        # no generated FILENAME suffix, so is_in_scope (manifest) admits them and
        # is_oos(rel) (no head text) misses them. They are auto-generated ABI
        # wrappers, NEVER an auditable value-moving CORE contract - the real logic
        # lives in the Solidity source / keeper. Counting them polluted the
        # core-coverage denominator (3 of optimism's 63) and would demand invariant
        # harnesses for generated wrappers. Read a cheap head + drop if generated.
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:600]
        except OSError:
            head = ""
        if is_generated(rel, head=head):
            continue
        records = _analyze_file(path, rel, lang)
        all_records.extend(records)

    # DECLARATIVE / LLM-hunt-only languages (e.g. Obyte Oscript AAs) have no
    # function-start regex here; seed their value-movers from the in-scope
    # manifest. Additive; a no-op for an engine-language workspace.
    all_records.extend(_manifest_declarative_value_moving_records(ws))

    return all_records


def run(workspace: str | Path, out_path: str | Path | None = None) -> Path:
    """Enumerate value-moving functions and write JSON output.

    Returns the path of the written JSON file.
    """
    ws = Path(workspace).resolve()
    records = enumerate_value_moving(ws)

    out = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "value_moving_functions.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "workspace": str(ws),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "function_count": len(records),
        "functions": records,
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# CLI entry-point.
# ---------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enumerate value-moving functions in a workspace."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override output path")
    args = parser.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    out = run(ws, args.out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    print(f"value-moving-functions: {payload['function_count']} functions -> {out}")
    for rec in payload["functions"]:
        parts = []
        if rec["transfer_hit"]:
            parts.append("transfer")
        if rec["ledger_write_hit"]:
            parts.append(f"ledger({','.join(rec['ledger_write_evidence'][:3])})")
        if rec.get("guarded_callee_hit"):
            parts.append(f"guarded-callee(of {rec.get('guarded_callee_caller')})")
        if rec.get("authz_write_hit"):
            evid = rec.get("authz_write_evidence") or []
            parts.append(f"authz({','.join(evid[:3])})")
        print(f"  {rec['file']}::{rec['function']}  [{' + '.join(parts)}]")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
