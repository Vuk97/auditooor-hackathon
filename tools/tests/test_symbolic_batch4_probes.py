"""capv3-iter9-T1 — non-vacuity probes for the symbolic batch-4 harnesses.

Four probe tests, one per new batch-4 ``.sym.t.sol`` file. Same shape as
``test_symbolic_batch3_probes.py`` (iter-v3-8 T1) and
``test_symbolic_batch2_probes.py`` (iter-v3-7 T2), but scoped to the 4
new harnesses shipped by iter-v3-9 T1 (the final wave, closing the
symbolic matrix at 12/12):

  - vault_Holdings_RedemptionBounds.sym.t.sol (analogue)
  - governance_MultiAdapter_ProposalIdMonotonicity.sym.t.sol (analogue)
  - bridge_MessageProcessor_LockMintBalanceConservation.sym.t.sol (analogue)
  - lending_Accounting_OraclePriceDelta.sym.t.sol (analogue)

Per harness, the single probe test checks TWO non-vacuity properties:

  1. setUp() actually mutates state (contains load-bearing deployment
     and init lines). A silently-empty setUp would let every check_*
     pass trivially under halmos.

  2. Every check_* function declares >= 2 symbolic inputs (plan
     requirement) AND every declared symbolic parameter is *consumed*
     by at least one expression in the function body. A dangling
     symbolic param is silent vacuity — halmos treats it as symbolic
     but nothing in the invariant binds it.

These tests run against the static harness sources in
``projects/centrifuge-v3/symbolic/``. They do NOT require halmos to be
installed — they lock the non-vacuity property of the *harness source*
itself, so halmos outcomes (``pass``, ``no-counterexample``,
``counterexample``, ``timeout``) remain attributable to protocol
logic or to harness property-design, never to a silent probe gap.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SYM_DIR = _REPO_ROOT / "projects" / "centrifuge-v3" / "symbolic"

_VAULT_HARNESS = _SYM_DIR / "vault_Holdings_RedemptionBounds.sym.t.sol"
_GOVERNANCE_HARNESS = _SYM_DIR / "governance_MultiAdapter_ProposalIdMonotonicity.sym.t.sol"
_BRIDGE_HARNESS = _SYM_DIR / "bridge_MessageProcessor_LockMintBalanceConservation.sym.t.sol"
_LENDING_HARNESS = _SYM_DIR / "lending_Accounting_OraclePriceDelta.sym.t.sol"

# Per-harness must-contain lines for the setUp() body. These are the load-
# bearing state mutations that the check_* functions assume. If any one is
# missing, the check_* would either trivially pass (nothing to evaluate) or
# trivially revert (unreachable path) — in both cases halmos's advisory is
# vacuous.
_SETUP_STATE_MUTATIONS: dict[Path, list[str]] = {
    _VAULT_HARNESS: [
        "new _RBRegistryMockSym()",
        "new _RBIdentityValuationSym()",
        "new Holdings(IHubRegistry(address(registry)), address(this))",
        "registry.__markPool(poolId, 18)",
        "registry.__markAsset(assetA, 18)",
        "registry.__markAsset(assetB, 18)",
        "vault.initialize(poolId, scId, assetA, IValuation(address(valuation)), false, accs)",
        "vault.initialize(poolId, scId, assetB, IValuation(address(valuation)), false, accs)",
    ],
    _GOVERNANCE_HARNESS: [
        "new _PIMGatewayMockSym()",
        "new MultiAdapter(uint16(1), IMessageHandler(address(gatewayMock)), address(this))",
        "new _PIMAdapterMockSym()",
    ],
    _BRIDGE_HARNESS: [
        "new MessageProcessor(IScheduleAuth(address(0xDEAD)), address(this))",
        'makeAddr("symBridgeUser")',
        'makeAddr("symSrcLockVault")',
        'new _LMBERC20MockSym("SRC")',
        'new _LMBERC20MockSym("DST")',
        "new _LMBModelBridgeSym(srcTokenImpl, dstTokenImpl, srcLockVault)",
    ],
    _LENDING_HARNESS: [
        "new Accounting(address(this))",
        "pool.createAccount(poolId, priceAcct,  false)",
        "pool.createAccount(poolId, offsetAcct, true)",
    ],
}


def _extract_setup_body(source: str) -> str:
    """Return the text of setUp() from a Solidity source string."""
    m = re.search(r"function\s+setUp\s*\([^)]*\)\s*public[^{]*\{", source)
    assert m is not None, "setUp() signature not found"
    start = m.end()
    depth = 1
    i = start
    while i < len(source) and depth > 0:
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    assert depth == 0, "setUp() body did not close cleanly"
    return source[start:i - 1]


def _extract_check_functions(source: str) -> dict[str, tuple[list[tuple[str, str]], str]]:
    """Return {function_name: ([(type, name), ...], body_source)} for every
    ``check_*(...)`` function declared in the Solidity source.
    """
    out: dict[str, tuple[list[tuple[str, str]], str]] = {}
    pattern = re.compile(
        r"function\s+(check_[A-Za-z0-9_]+)\s*\(([^)]*)\)\s*public[^{]*\{"
    )
    for m in pattern.finditer(source):
        name = m.group(1)
        params_raw = m.group(2).strip()
        params: list[tuple[str, str]] = []
        if params_raw:
            for piece in [p.strip() for p in params_raw.split(",")]:
                toks = piece.split()
                assert len(toks) >= 2, f"malformed param: {piece!r}"
                ptype = toks[0]
                pname = toks[-1]
                params.append((ptype, pname))
        body_start = m.end()
        depth = 1
        i = body_start
        while i < len(source) and depth > 0:
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = source[body_start:i - 1]
        out[name] = (params, body)
    return out


def _assert_harness_non_vacuous(harness_path: Path, must_contain: list[str]) -> None:
    """Shared core: assert setUp is non-vacuous AND every check_* has >=2
    consumed symbolic params.
    """
    assert harness_path.exists(), f"harness missing: {harness_path}"
    source = harness_path.read_text()

    # Probe 1: setUp must contain load-bearing state mutations.
    body = _extract_setup_body(source)
    missing = [needle for needle in must_contain if needle not in body]
    assert not missing, (
        f"{harness_path.name} setUp() is missing load-bearing state-"
        f"mutation lines: {missing}. Probe exists to prevent a "
        f"silently-empty setUp that would let every check_* pass "
        f"trivially under halmos."
    )

    # Probe 2: every check_* has >=2 symbolic params and each is consumed
    # in the body.
    checks = _extract_check_functions(source)
    assert checks, f"{harness_path.name} has no check_* functions"
    for name, (params, body_src) in checks.items():
        assert len(params) >= 2, (
            f"{harness_path.name}::{name} has {len(params)} symbolic "
            f"inputs; plan requires >=2 to avoid a trivially-small "
            f"state space."
        )
        dangling: list[str] = []
        for _ptype, pname in params:
            # Whole-word match of the param name inside the body.
            if re.search(rf"\b{re.escape(pname)}\b", body_src) is None:
                dangling.append(pname)
        assert not dangling, (
            f"{harness_path.name}::{name} declares symbolic param(s) "
            f"{dangling} that are not consumed in the function body. "
            f"halmos would treat them as symbolic but nothing in the "
            f"invariant binds them — silent vacuity."
        )


def test_probe_vault_redemption_bounds_non_vacuous() -> None:
    """Probe: vault_Holdings_RedemptionBounds.sym.t.sol setUp is
    non-vacuous AND every check_* has >=2 consumed symbolic inputs.

    setUp must deploy Holdings + _RBRegistryMockSym + _RBIdentityValuationSym,
    mark the pool + both assets (A and B) as registered with 18 decimals,
    and initialize the two holdings. Without the two initialize() calls the
    check_* functions would hit HoldingNotFound() on the first increase/decrease
    and trivially revert — halmos would observe the revert path and the
    redemption-bound properties would be unreachable.
    """
    _assert_harness_non_vacuous(
        _VAULT_HARNESS,
        _SETUP_STATE_MUTATIONS[_VAULT_HARNESS],
    )


def test_probe_governance_proposal_id_monotonicity_non_vacuous() -> None:
    """Probe: governance_MultiAdapter_ProposalIdMonotonicity.sym.t.sol
    setUp is non-vacuous AND every check_* has >=2 consumed symbolic
    inputs.

    setUp must deploy _PIMGatewayMockSym and MultiAdapter wiring the
    gateway mock into the inner handler slot, plus at least one
    _PIMAdapterMockSym (the pool of 3 concrete adapters used by both
    check_* functions to avoid the iter-v3-8 T1 halmos NotConcreteError
    on symbolic indexing of the adapters mapping-backed array). Without
    those, setAdapters() would hit the zero-adapter-address revert path
    on every symbolic call and activeSessionId would always return 0.
    """
    _assert_harness_non_vacuous(
        _GOVERNANCE_HARNESS,
        _SETUP_STATE_MUTATIONS[_GOVERNANCE_HARNESS],
    )


def test_probe_bridge_lock_mint_balance_conservation_non_vacuous() -> None:
    """Probe: bridge_MessageProcessor_LockMintBalanceConservation.sym.t.sol
    setUp is non-vacuous AND every check_* has >=2 consumed symbolic
    inputs.

    setUp must deploy MessageProcessor (banner compliance), create the
    symbolic user + srcLockVault addresses, deploy both _LMBERC20MockSym
    instances (SRC and DST), and wire the compact _LMBModelBridgeSym over
    them. Without the model bridge, the lock/unlock calls in check_*
    would target address(0) and all conservation assertions would
    trivially revert.
    """
    _assert_harness_non_vacuous(
        _BRIDGE_HARNESS,
        _SETUP_STATE_MUTATIONS[_BRIDGE_HARNESS],
    )


def test_probe_lending_oracle_price_delta_non_vacuous() -> None:
    """Probe: lending_Accounting_OraclePriceDelta.sym.t.sol setUp is
    non-vacuous AND every check_* has >=2 consumed symbolic inputs.

    setUp must deploy Accounting with the harness as deployer/auth, then
    createAccount for BOTH the credit-normal price account AND the
    debit-normal offset account. Without both accounts, the balanced
    journals (addCredit(price, t) + addDebit(offset, t)) would hit the
    UnrecognizedAccount revert path on lock() and the price-delta
    invariant would be unreachable.
    """
    _assert_harness_non_vacuous(
        _LENDING_HARNESS,
        _SETUP_STATE_MUTATIONS[_LENDING_HARNESS],
    )


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            suite.addTest(unittest.FunctionTestCase(value, description=name))
    return suite
