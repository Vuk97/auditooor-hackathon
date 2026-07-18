#!/usr/bin/env python3
"""share-inflation-lane.py  (SIDL) - Share-Inflation / Donation Lane.

WHAT THIS TOOL DOES
===================
For every value-moving function in <ws>/.auditooor/value_moving_functions.json,
SIDL checks whether the function is a SHARE-MINTING function - one that mints or
credits a share/LP/units token from a ratio of deposited assets to total supply.
The class is the well-known ERC-4626-style share-inflation / first-depositor attack:

  * DONATION path: an adversary calls token.transfer(vault, X) WITHOUT going
    through the vault's deposit() entrypoint. This inflates totalAssets while
    totalSupply stays fixed, so a subsequent depositor receives fewer shares than
    expected (rounds down to 0 in the extreme case). The solvency-floor invariant
    (balanceOf >= liabilities) is SATISFIED by the donation because balanceOf
    only goes up - so VCIS structurally misses this class.

  * FIRST-DEPOSITOR path: the first depositor mints 1 wei of LP/shares, then
    donates a large amount directly (bypassing tracked deposit), so any later
    depositor's shares round to ~0 and their assets are effectively stolen.

WHY VCIS MISSES THIS
====================
The VCIS solvency-floor invariant (balanceOf >= sum(credit fields)) is SATISFIED
by a donation because the balance only rises. This is NOT a bug in VCIS - it is
a structural blind-spot. SIDL is the dedicated lane.

DETECTION SHAPE (language-generic)
===================================
A function is a SIDL candidate when ALL three gates pass:

GATE 1 - SHARE-MINTING: the function body contains a call to _mint(recipient, X)
or an additive write to a shares/lp/units/credit mapping (language-specific patterns).

GATE 2 - RATIO FROM SUPPLY: the minted amount is computed using totalSupply (or an
equivalent running supply counter) combined with totalAssets / totalReserves /
balanceOf(address(this)) - or via a well-function-style call whose inputs include
both the current reserve vector and a supply. Concretely one of:
  - Solidity: mulDiv / * supply / totalSupply / totalAssets / calcLpTokenSupply /
    _calcLpTokenSupply / balanceOf(address(this))
  - Go: MulDiv / totalSupply / TotalShares / TotalAssets / totalAssets
  - Rust: mul_div / checked_mul / total_supply / total_assets / total_shares

GATE 3 - MITIGATIONS ABSENT: none of the known safe-guards are present in the
function body:
  - virtualShares / _decimalsOffset (OZ ERC-4626 virtual share offset)
  - DEAD_SHARES / dead_shares / MIN_LIQUIDITY (burn on first mint)
  - initialDeposit / initial_deposit minimum
  - _totalAssets (tracked internal variable, written only on deposit/withdraw)

NO FALSE-GREEN RULE
===================
SIDL NEVER auto-credits a confirmed finding. Every emitted record carries
verdict="needs-fuzz". The invariant spec is emitted for the fuzzer oracle;
the hypotheses are emitted for the LLM hunt layer.

EMITS (per share-minting function)
===================================
(a) A SHARE-PRICE-INTEGRITY invariant spec in the standard invariant schema:
    {
      "workspace", "file", "function", "language",
      "invariant_id":     "SIDL-<N>",
      "invariant_class":  "share-price-integrity",
      "invariant_text":   "<two-form text: DONATION-ISOLATION + FIRST-DEPOSIT-SAFE>",
      "fuzz_property":    "<suggested medusa/echidna property>",
      "mitigations_absent": [<list of known absent mitigations>],
      "source":           "SIDL",
      "verdict":          "needs-fuzz"
    }

(b) Two hypothesis records in <ws>/.auditooor/share_inflation_hypotheses.jsonl:
    - DONATION hypothesis (attack_class=share-inflation-donation)
    - FIRST-DEPOSITOR hypothesis (attack_class=share-inflation-first-depositor)

OUTPUT FILES
============
1. <ws>/.auditooor/share_inflation_hypotheses.jsonl  - hypothesis records
2. <ws>/.auditooor/share_inflation_invariants.jsonl  - invariant specs

CLI
===
  python3 tools/share-inflation-lane.py <workspace> [--out <path>] [--out-inv <path>]
  --vmf-json:   override value_moving_functions.json path
  --regen-vmf:  re-run value-moving-functions.py even if JSON exists

Returns rc=0 on success (even if 0 hypotheses emitted), rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Compose with scope_exclusion (single source of truth OOS guard).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _HERE = Path(__file__).resolve().parent
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
            ):
                if marker in n:
                    return True
            return False

# ---------------------------------------------------------------------------
# Lazy-load value-moving-functions module (hyphen in filename requires spec).
# ---------------------------------------------------------------------------
_VMF_MOD_NAME = "value_moving_functions_sidl_import"
_VMF_PATH = Path(__file__).resolve().parent / "value-moving-functions.py"


def _load_vmf_module():
    spec = importlib.util.spec_from_file_location(_VMF_MOD_NAME, _VMF_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_VMF_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_VMF: Any = None


def _vmf() -> Any:
    global _VMF
    if _VMF is None:
        _VMF = _load_vmf_module()
    return _VMF


# ---------------------------------------------------------------------------
# GATE 1 - SHARE-MINTING patterns (per language).
#
# A function scores GATE 1 when its body contains a call that mints or
# additively writes a share / LP / units / credit token.
# ---------------------------------------------------------------------------

# Solidity: _mint(recipient, amount) or shares[...] += ...  or lpToken.mint(...)
_SOL_MINT_RES: list[re.Pattern] = [
    re.compile(r"\b_mint\s*\(", re.I),
    re.compile(r"\bmint\s*\(", re.I),
    # additive write to a share/lp/units mapping
    re.compile(r"\b\w*(?:share|lp|units|liquidity|credit)\w*\s*(?:\[[^\]]*\])*\s*\+="),
    # internal _mint that takes an address + amount
    re.compile(r"\bERC20\._mint\s*\(", re.I),
    re.compile(r"\bERC4626\._mint\s*\(", re.I),
    re.compile(r"\bSupply\._mint\s*\(", re.I),
]

# Go/Cosmos: MintCoins / bankKeeper.MintCoins / supply.MintCoins / share += ...
_GO_MINT_RES: list[re.Pattern] = [
    re.compile(r"\bMintCoins\s*\(", re.I),
    re.compile(r"\b\w*Keeper\b.*\bMint\w*\s*\(", re.I),
    # additive write to a share/lp/units field
    re.compile(r"\b\w*(?:share|lp|units|liquidity|credit)\w*\s*\+="),
    re.compile(r"\bmint\w*\s*\(", re.I),
    re.compile(r"\bTotalShares\b.*\+="),
    re.compile(r"\btotalSupply\b.*\+="),
]

# Rust/CosmWasm: mint_to / spl_token::mint_to / state.shares += / .mint(
_RS_MINT_RES: list[re.Pattern] = [
    re.compile(r"\bmint_to\s*\(", re.I),
    re.compile(r"\bspl_token\s*::\s*mint_to\b", re.I),
    re.compile(r"\.mint\s*\(", re.I),
    re.compile(r"\b\w*(?:share|lp|units|liquidity|credit)\w*\s*\+="),
    re.compile(r"\bself\.\w*(?:share|lp|units|supply)\w*\s*\+=", re.I),
    re.compile(r"\btotal_supply\b.*\+="),
    re.compile(r"\btotal_shares\b.*\+="),
]

# Move: coin::mint / fungible_asset::mint
_MOVE_MINT_RES: list[re.Pattern] = [
    re.compile(r"\bcoin\s*::\s*mint\b", re.I),
    re.compile(r"\bfungible_asset\s*::\s*mint\b", re.I),
    re.compile(r"\bmint_capability\b", re.I),
]

# Cairo/Noir: ERC20._mint / _mint(
_CAIRO_MINT_RES: list[re.Pattern] = [
    re.compile(r"\b_mint\s*\(", re.I),
    re.compile(r"\bmint\s*\(", re.I),
]

_MINT_RES: dict[str, list[re.Pattern]] = {
    "sol":   _SOL_MINT_RES,
    "go":    _GO_MINT_RES,
    "rs":    _RS_MINT_RES,
    "move":  _MOVE_MINT_RES,
    "cairo": _CAIRO_MINT_RES,
}

# ---------------------------------------------------------------------------
# GATE 2 - RATIO FROM SUPPLY patterns (per language).
#
# The minted amount must be computed from a ratio involving totalSupply and
# totalAssets/totalReserves/balanceOf(address(this)), OR via a well-function
# style call whose inputs include both the reserve vector and the supply.
# ---------------------------------------------------------------------------

# Solidity
_SOL_RATIO_RES: list[re.Pattern] = [
    # explicit mulDiv / muldiv patterns
    re.compile(r"\bmulDiv\s*\(", re.I),
    re.compile(r"\bmulDivDown\s*\(", re.I),
    re.compile(r"\bmulDivUp\s*\(", re.I),
    # totalSupply in arithmetic context (e.g. * totalSupply() or * totalSupply)
    re.compile(r"\*\s*totalSupply\b", re.I),
    re.compile(r"\btotalSupply\s*\(\s*\)\s*[*/]", re.I),
    re.compile(r"\btotalSupply\b.*[*/]"),
    # totalAssets in arithmetic context
    re.compile(r"\btotalAssets\s*\(\s*\)", re.I),
    re.compile(r"\btotalAssets\b.*[*/]"),
    # calcLpTokenSupply / _calcLpTokenSupply (beanstalk well pattern)
    re.compile(r"\b_?calcLpTokenSupply\s*\(", re.I),
    # balanceOf(address(this)) used as reserve
    re.compile(r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)", re.I),
    # reserves[] vector
    re.compile(r"\breserves\b.*[*/]"),
    re.compile(r"\b_reserves\b.*[*/]"),
]

# Go/Cosmos
_GO_RATIO_RES: list[re.Pattern] = [
    re.compile(r"\bMulDiv\b", re.I),
    re.compile(r"\btotalSupply\b.*[*/]", re.I),
    re.compile(r"\bTotalShares\b.*[*/]", re.I),
    re.compile(r"\btotalAssets\b.*[*/]", re.I),
    re.compile(r"\bTotalAssets\b.*[*/]", re.I),
    re.compile(r"\bGetTotalShares\s*\(", re.I),
    re.compile(r"\bGetTotalSupply\s*\(", re.I),
    re.compile(r"\bPoolSupply\b.*[*/]", re.I),
    re.compile(r"\bLpTokenSupply\b", re.I),
]

# Rust
_RS_RATIO_RES: list[re.Pattern] = [
    re.compile(r"\bmul_div\b", re.I),
    re.compile(r"\bchecked_mul\b", re.I),
    re.compile(r"\btotal_supply\b.*[*/]", re.I),
    re.compile(r"\btotal_assets\b.*[*/]", re.I),
    re.compile(r"\btotal_shares\b.*[*/]", re.I),
    re.compile(r"\bself\.total_supply\b", re.I),
    re.compile(r"\bself\.total_shares\b", re.I),
    # integer arithmetic with supply-like variables
    re.compile(r"\*\s*total_supply\b", re.I),
    re.compile(r"\*\s*total_shares\b", re.I),
    re.compile(r"\*\s*supply\b", re.I),
    re.compile(r"\bsupply\b.*[*/]"),
]

# Move
_MOVE_RATIO_RES: list[re.Pattern] = [
    re.compile(r"\btotal_supply\b", re.I),
    re.compile(r"\bpool_supply\b", re.I),
    re.compile(r"\bcoin::supply\b", re.I),
]

# Cairo
_CAIRO_RATIO_RES: list[re.Pattern] = [
    re.compile(r"\btotal_supply\b", re.I),
    re.compile(r"\btotalSupply\b", re.I),
    re.compile(r"\btotal_assets\b", re.I),
]

_RATIO_RES: dict[str, list[re.Pattern]] = {
    "sol":   _SOL_RATIO_RES,
    "go":    _GO_RATIO_RES,
    "rs":    _RS_RATIO_RES,
    "move":  _MOVE_RATIO_RES,
    "cairo": _CAIRO_RATIO_RES,
}

# ---------------------------------------------------------------------------
# GATE 3 - MITIGATION patterns (presence of ANY negates the SIDL signal).
# These are the known safe-guards that defeat the inflation attack.
# Language-generic (match across all).
# ---------------------------------------------------------------------------
_MITIGATION_RES: list[tuple[str, re.Pattern]] = [
    # OZ ERC-4626 virtual share offset
    ("virtualShares",    re.compile(r"\bvirtualShares\b", re.I)),
    ("_decimalsOffset",  re.compile(r"\b_decimalsOffset\b", re.I)),
    ("decimalsOffset",   re.compile(r"\bdecimalsOffset\b", re.I)),
    # Burn on first mint (Uniswap-style DEAD_SHARES)
    ("DEAD_SHARES",      re.compile(r"\bDEAD_SHARES\b", re.I)),
    ("dead_shares",      re.compile(r"\bdead_shares\b", re.I)),
    ("MINIMUM_LIQUIDITY",re.compile(r"\bMINIMUM_LIQUIDITY\b", re.I)),
    ("MIN_LIQUIDITY",    re.compile(r"\bMIN_LIQUIDITY\b", re.I)),
    ("min_liquidity",    re.compile(r"\bmin_liquidity\b", re.I)),
    # initialDeposit / initialMint guard
    ("initialDeposit",   re.compile(r"\binitialDeposit\b", re.I)),
    ("initial_deposit",  re.compile(r"\binitial_deposit\b", re.I)),
    ("initialMint",      re.compile(r"\binitialMint\b", re.I)),
    # internally tracked _totalAssets (not raw balanceOf)
    ("_totalAssets",     re.compile(r"\b_totalAssets\b")),
    ("stored_total_assets", re.compile(r"\bstored_total_assets\b", re.I)),
]


# ---------------------------------------------------------------------------
# Invariant text templates.
# ---------------------------------------------------------------------------
_INVARIANT_TEXT_TEMPLATE = (
    "SHARE-PRICE-INTEGRITY invariant for {fn} ({file}):\n"
    "  Form A - DONATION-ISOLATION: for any state S, if an external actor calls\n"
    "    token.transfer(vault, X) WITHOUT going through {fn}, the assets-per-share\n"
    "    ratio MUST NOT change adversely (a subsequent depositor must receive shares\n"
    "    proportional to their deposit, not fewer due to the untracked balance increase).\n"
    "    Fuzz predicate: deposit(assets) after donation(X) -> shares_received >=\n"
    "      assets * totalSupply_before / (totalAssets_before + X) - 1.\n"
    "  Form B - FIRST-DEPOSIT-SAFE: if totalSupply == 0 when {fn} is first called,\n"
    "    a subsequent depositor MUST receive shares proportional to their deposit.\n"
    "    No single-wei first-deposit followed by a donation must allow the first\n"
    "    depositor to steal a later depositor's assets via rounding.\n"
    "    Fuzz predicate: after first_deposit(1 wei) + donation(large), deposit(assets)\n"
    "      -> shares_received > 0 OR assets_refunded == deposited_assets."
)

_FUZZ_PROPERTY_TEMPLATE = (
    "invariant sharesNotInflatable() {{\n"
    "    // Before: record totalSupply and totalAssets\n"
    "    // Action: donate X tokens to vault WITHOUT calling {fn}\n"
    "    // Then:   call {fn}(assets, recipient)\n"
    "    // Assert: shares_minted >= assets * supply_before / (assets_before + X) - 1\n"
    "    // Also assert: if supply_before == 0, shares_minted > 0 for any assets > 0\n"
    "}}"
)

_DONATION_HYPOTHESIS_NOTE = (
    "Donation attack on {fn}: an attacker calls token.transfer(vault, X) directly "
    "(not via {fn}), inflating totalAssets without touching totalSupply. A subsequent "
    "legitimate depositor receives fewer shares than their assets merit - at extreme X "
    "this rounds to 0 shares, effectively stealing their deposit. "
    "VCIS misses this because the donation increases balanceOf (solvency-floor satisfied)."
)

_FIRST_DEPOSITOR_NOTE = (
    "First-depositor attack on {fn}: the attacker is the first depositor, mints 1 wei "
    "of shares, then donates a large amount directly to the vault. Any subsequent "
    "depositor receives 0 shares (rounds down) and the attacker redeems the vault. "
    "Requires: totalSupply == 0 at the time of the first deposit."
)


# ---------------------------------------------------------------------------
# Core detection: classify one function.
# Returns (gate1_evidence, gate2_evidence, mitigations_present).
# ---------------------------------------------------------------------------
def _detect_share_minting(
    body: str,
    lang: str,
) -> tuple[list[str], list[str], list[str]]:
    """Return (mint_evidence, ratio_evidence, mitigations_found).

    mint_evidence   - non-empty iff GATE 1 passes
    ratio_evidence  - non-empty iff GATE 2 passes
    mitigations_found - names of mitigations present in body (GATE 3 negation)
    """
    mint_evidence: list[str] = []
    for rx in _MINT_RES.get(lang, []):
        m = rx.search(body)
        if m:
            start = max(0, m.start() - 10)
            snippet = body[start: m.end() + 20].strip().replace("\n", " ")
            mint_evidence.append(snippet[:80])
            break  # one hit is sufficient

    ratio_evidence: list[str] = []
    for rx in _RATIO_RES.get(lang, []):
        m = rx.search(body)
        if m:
            start = max(0, m.start() - 10)
            snippet = body[start: m.end() + 30].strip().replace("\n", " ")
            ratio_evidence.append(snippet[:80])
            break

    mitigations_found: list[str] = []
    for mit_name, rx in _MITIGATION_RES:
        if rx.search(body):
            mitigations_found.append(mit_name)

    return mint_evidence, ratio_evidence, mitigations_found


# ---------------------------------------------------------------------------
# Hypothesis + invariant record builders.
# ---------------------------------------------------------------------------
def _build_donation_hypothesis(
    ws_abs: str,
    fn_rec: dict[str, Any],
    mint_evidence: list[str],
    ratio_evidence: list[str],
) -> dict[str, Any]:
    fn = fn_rec["function"]
    file_ = fn_rec["file"]
    return {
        "workspace":       ws_abs,
        "file":            file_,
        "function":        fn,
        "language":        fn_rec["language"],
        "attack_class":    "share-inflation-donation",
        "source":          "SIDL",
        "verdict":         "needs-fuzz",
        "note":            _DONATION_HYPOTHESIS_NOTE.format(fn=fn),
        "mint_evidence":   mint_evidence,
        "ratio_evidence":  ratio_evidence,
        "vcis_miss_reason": (
            "VCIS solvency-floor is SATISFIED by the donation (balanceOf rises); "
            "SIDL is the dedicated lane for this class."
        ),
        "suggested_invariant": (
            "after donate(X): deposit(A) -> shares >= A * totalSupply / (totalAssets + X) - 1"
        ),
    }


def _build_first_depositor_hypothesis(
    ws_abs: str,
    fn_rec: dict[str, Any],
    mint_evidence: list[str],
    ratio_evidence: list[str],
) -> dict[str, Any]:
    fn = fn_rec["function"]
    file_ = fn_rec["file"]
    return {
        "workspace":       ws_abs,
        "file":            file_,
        "function":        fn,
        "language":        fn_rec["language"],
        "attack_class":    "share-inflation-first-depositor",
        "source":          "SIDL",
        "verdict":         "needs-fuzz",
        "note":            _FIRST_DEPOSITOR_NOTE.format(fn=fn),
        "mint_evidence":   mint_evidence,
        "ratio_evidence":  ratio_evidence,
        "vcis_miss_reason": (
            "VCIS solvency-floor is SATISFIED by the inflation (donated balance raises floor); "
            "SIDL is the dedicated lane for this class."
        ),
        "suggested_invariant": (
            "totalSupply == 0 -> deposit(1 wei) -> donate(large) -> deposit(A) -> "
            "shares_for_second_depositor > 0 OR assets_refunded == A"
        ),
    }


def _build_invariant_spec(
    ws_abs: str,
    fn_rec: dict[str, Any],
    inv_id: str,
    mitigations_absent: list[str],
) -> dict[str, Any]:
    fn = fn_rec["function"]
    file_ = fn_rec["file"]
    return {
        "workspace":         ws_abs,
        "file":              file_,
        "function":          fn,
        "language":          fn_rec["language"],
        "invariant_id":      inv_id,
        "invariant_class":   "share-price-integrity",
        "invariant_text":    _INVARIANT_TEXT_TEMPLATE.format(fn=fn, file=file_),
        "fuzz_property":     _FUZZ_PROPERTY_TEMPLATE.format(fn=fn),
        "mitigations_absent": mitigations_absent,
        "source":            "SIDL",
        "verdict":           "needs-fuzz",
    }


# ---------------------------------------------------------------------------
# Per-function public API (used by tests without a workspace).
# ---------------------------------------------------------------------------
def hypotheses_from_source(
    source: str,
    language: str,
    fn_name: str,
    file_rel: str = "fixture.sol",
    ws_abs: str = "/tmp/sidl_fixture_ws",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (hypotheses, invariant_specs) for a single function in ``source``.

    Convenience wrapper for unit tests: no workspace directory required.
    ``source`` must contain the full function definition (signature + body).

    Returns a tuple:
      - hypotheses: list of DONATION + FIRST-DEPOSITOR hypothesis records
      - invariants: list of SHARE-PRICE-INTEGRITY invariant specs
    """
    fn_re = _vmf()._FN_RES.get(language)
    if fn_re is None:
        return [], []

    fn_match = None
    for m in fn_re.finditer(source):
        if m.group(1) == fn_name:
            fn_match = m
            break
    if fn_match is None:
        return [], []

    body = _vmf()._extract_body(source, fn_match.end())
    if not body:
        return [], []

    mint_ev, ratio_ev, mits_present = _detect_share_minting(body, language)

    # All three gates must pass: MINT present, RATIO present, no mitigations.
    if not mint_ev or not ratio_ev or mits_present:
        return [], []

    fn_rec: dict[str, Any] = {
        "file":     file_rel,
        "function": fn_name,
        "language": language,
        "transfer_hit": True,
        "ledger_write_hit": False,
        "transfer_evidence": [],
        "ledger_write_evidence": [],
    }
    ws_abs_str = ws_abs

    hyps = [
        _build_donation_hypothesis(ws_abs_str, fn_rec, mint_ev, ratio_ev),
        _build_first_depositor_hypothesis(ws_abs_str, fn_rec, mint_ev, ratio_ev),
    ]

    # Mitigations absent = all known mitigations NOT found in body
    mit_names = [n for n, _ in _MITIGATION_RES]
    absent = [n for n in mit_names if n not in mits_present]

    inv = _build_invariant_spec(ws_abs_str, fn_rec, "SIDL-1", absent)

    return hyps, [inv]


# ---------------------------------------------------------------------------
# Workspace-level runner.
# ---------------------------------------------------------------------------
def run_sidl(
    workspace: str | Path,
    vmf_json_path: str | Path | None = None,
    out_path: str | Path | None = None,
    out_inv_path: str | Path | None = None,
    regen_vmf: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run SIDL over ``workspace`` and return (hypotheses, invariants).

    Also writes the .jsonl sidecars.
    """
    ws = Path(workspace).resolve()
    ws_abs = str(ws)

    vmf_json = (
        Path(vmf_json_path)
        if vmf_json_path is not None
        else ws / ".auditooor" / "value_moving_functions.json"
    )

    if regen_vmf or not vmf_json.exists():
        vmf_mod = _vmf()
        out_vmf = vmf_mod.run(ws, vmf_json)
        vmf_json = out_vmf

    if not vmf_json.exists():
        print(
            f"ERROR: value_moving_functions.json not found at {vmf_json}",
            file=sys.stderr,
        )
        return [], []

    payload = json.loads(vmf_json.read_text(encoding="utf-8"))
    fn_records: list[dict[str, Any]] = payload.get("functions", [])

    # Group by file for efficient source reads.
    by_file: dict[str, list[dict[str, Any]]] = {}
    for rec in fn_records:
        by_file.setdefault(rec["file"], []).append(rec)

    all_hypotheses: list[dict[str, Any]] = []
    all_invariants: list[dict[str, Any]] = []
    inv_counter = 0

    for rel_path, recs in by_file.items():
        abs_path = ws / rel_path
        if not abs_path.exists():
            continue
        if is_oos(rel_path):
            continue
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        fn_re = _vmf()._FN_RES.get(recs[0]["language"])
        if fn_re is None:
            continue

        # Build a name->match index for the file once.
        match_by_name: dict[str, re.Match] = {}
        for m in fn_re.finditer(source):
            name = m.group(1)
            if name not in match_by_name:
                match_by_name[name] = m

        for fn_rec in recs:
            fn_name = fn_rec["function"]
            lang = fn_rec["language"]
            fn_match = match_by_name.get(fn_name)
            if fn_match is None:
                continue

            body = _vmf()._extract_body(source, fn_match.end())
            if not body:
                continue

            mint_ev, ratio_ev, mits_present = _detect_share_minting(body, lang)
            if not mint_ev or not ratio_ev or mits_present:
                continue

            inv_counter += 1
            inv_id = f"SIDL-{inv_counter}"

            mit_names = [n for n, _ in _MITIGATION_RES]
            absent = [n for n in mit_names if n not in mits_present]

            hyp1 = _build_donation_hypothesis(ws_abs, fn_rec, mint_ev, ratio_ev)
            hyp2 = _build_first_depositor_hypothesis(ws_abs, fn_rec, mint_ev, ratio_ev)
            inv = _build_invariant_spec(ws_abs, fn_rec, inv_id, absent)

            all_hypotheses.extend([hyp1, hyp2])
            all_invariants.append(inv)

    # Write hypotheses .jsonl
    out_jsonl = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "share_inflation_hypotheses.jsonl"
    )
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for h in all_hypotheses:
            fh.write(json.dumps(h) + "\n")

    # Write invariants .jsonl
    out_inv = (
        Path(out_inv_path)
        if out_inv_path is not None
        else ws / ".auditooor" / "share_inflation_invariants.jsonl"
    )
    with out_inv.open("w", encoding="utf-8") as fh:
        for inv in all_invariants:
            fh.write(json.dumps(inv) + "\n")

    return all_hypotheses, all_invariants


# ---------------------------------------------------------------------------
# CLI entry-point.
# ---------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SIDL: share-inflation / donation lane hypothesis emitter."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override hypotheses .jsonl path")
    parser.add_argument("--out-inv", default=None, help="Override invariants .jsonl path")
    parser.add_argument("--vmf-json", default=None, help="Override value_moving_functions.json path")
    parser.add_argument(
        "--regen-vmf", action="store_true",
        help="Re-run value-moving-functions.py even if JSON exists",
    )
    args = parser.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    hyps, invs = run_sidl(
        workspace=ws,
        vmf_json_path=args.vmf_json,
        out_path=args.out,
        out_inv_path=args.out_inv,
        regen_vmf=args.regen_vmf,
    )

    out_hyp = (
        Path(args.out)
        if args.out
        else ws / ".auditooor" / "share_inflation_hypotheses.jsonl"
    )
    out_inv = (
        Path(args.out_inv)
        if args.out_inv
        else ws / ".auditooor" / "share_inflation_invariants.jsonl"
    )

    print(f"SIDL: {len(hyps)} hypotheses -> {out_hyp}")
    print(f"SIDL: {len(invs)} invariant specs -> {out_inv}")

    by_fn: dict[str, list[dict[str, Any]]] = {}
    for h in hyps:
        key = f"{h['file']}::{h['function']}"
        by_fn.setdefault(key, []).append(h)
    for fn_key, fn_hyps in sorted(by_fn.items()):
        print(f"  {fn_key}:")
        for h in fn_hyps:
            print(f"    [{h['verdict']}] {h['attack_class']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
