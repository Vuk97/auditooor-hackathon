"""capv3-iter7-T2 — non-vacuity probes for the symbolic batch-2 harnesses.

Three probe tests, one per new batch-2 `.sym.t.sol` file. Same shape as
the iter-v3-6 T2 probes (`test_symbolic_first_wave_probes.py`), but
scoped to the 3 new harnesses shipped by iter-v3-7 T2:

  - bridge_MessageProcessor_MessageReplayResistance.sym.t.sol (strong)
  - vault_Holdings_SharePriceMonotonicity.sym.t.sol (analogue)
  - lending_Accounting_DebtCollateralSolvency.sym.t.sol (strong)

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
`projects/centrifuge-v3/symbolic/`. They do NOT require halmos to be
installed — they lock the non-vacuity property of the *harness source*
itself, so halmos outcomes (pass, no-counterexample, counterexample,
timeout) are always attributable to protocol logic, not probe gaps.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SYM_DIR = _REPO_ROOT / "projects" / "centrifuge-v3" / "symbolic"

_BRIDGE_HARNESS = _SYM_DIR / "bridge_MessageProcessor_MessageReplayResistance.sym.t.sol"
_VAULT_HARNESS = _SYM_DIR / "vault_Holdings_SharePriceMonotonicity.sym.t.sol"
_LENDING_HARNESS = _SYM_DIR / "lending_Accounting_DebtCollateralSolvency.sym.t.sol"

# Per-harness must-contain lines for the setUp() body. These are the load-
# bearing state mutations that the check_* functions assume. If any one is
# missing, the check_* would either trivially pass (nothing to evaluate) or
# trivially revert (unreachable path) — in both cases halmos's advisory is
# vacuous.
_SETUP_STATE_MUTATIONS: dict[Path, list[str]] = {
    _BRIDGE_HARNESS: [
        "new Gateway(LOCAL_CENT_ID, pauser, address(this))",
        "new _ToggleProcessorSym()",
        "new _PauserMockSym()",
        "new _MessagePropsMockSym()",
        'gateway.file("processor", address(processor))',
        'gateway.file("messageProperties", address(props))',
    ],
    _VAULT_HARNESS: [
        "new Holdings(IHubRegistry(address(registry)), address(this))",
        "new _RegistryMockSym()",
        "new _IdentityValuationSym()",
        "vault.initialize(poolId, scId, assetId, IValuation(address(valuation)), false, accs)",
        "vault.increase(poolId, scId, assetId, d18(1e18), SEED_AMOUNT)",
    ],
    _LENDING_HARNESS: [
        "new Accounting(address(this))",
        "pool.createAccount(poolId, debitAccount,  true)",
        "pool.createAccount(poolId, creditAccount, false)",
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
    `check_*(...)` function declared in the Solidity source.
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


def test_probe_bridge_message_replay_resistance_non_vacuous() -> None:
    """Probe: bridge_MessageProcessor_MessageReplayResistance.sym.t.sol
    setUp is non-vacuous AND every check_* has >=2 consumed symbolic
    inputs.

    setUp must deploy Gateway + _ToggleProcessorSym + _PauserMockSym +
    _MessagePropsMockSym and file the processor + messageProperties
    slots — without these the check_* calls to gateway.handle /
    gateway.retry hit address(0) immediately. Probe locks the setUp
    against silent regression.
    """
    _assert_harness_non_vacuous(
        _BRIDGE_HARNESS,
        _SETUP_STATE_MUTATIONS[_BRIDGE_HARNESS],
    )


def test_probe_vault_share_price_monotonicity_non_vacuous() -> None:
    """Probe: vault_Holdings_SharePriceMonotonicity.sym.t.sol setUp is
    non-vacuous AND every check_* has >=2 consumed symbolic inputs.

    setUp must deploy Holdings + _RegistryMockSym + _IdentityValuationSym,
    initialize the single holding, and prime a seed increase so
    value/amount is defined before the first check_*. Without the seed,
    _assetsPerShare() returns 0 and every check_* passes trivially on
    the early-return path.
    """
    _assert_harness_non_vacuous(
        _VAULT_HARNESS,
        _SETUP_STATE_MUTATIONS[_VAULT_HARNESS],
    )


def test_probe_lending_debt_collateral_solvency_non_vacuous() -> None:
    """Probe: lending_Accounting_DebtCollateralSolvency.sym.t.sol setUp
    is non-vacuous AND every check_* has >=2 consumed symbolic inputs.

    setUp must deploy Accounting and createAccount both sides (debit-
    normal + credit-normal); without either account, the addDebit /
    addCredit call inside check_* reverts on AccountDoesNotExist
    before the invariant can evaluate.
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
