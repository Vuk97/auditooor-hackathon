"""capv3-iter8-T1 — non-vacuity probes for the symbolic batch-3 harnesses.

Three probe tests, one per new batch-3 `.sym.t.sol` file. Same shape as
`test_symbolic_batch2_probes.py` (iter-v3-7 T2) and
`test_symbolic_first_wave_probes.py` (iter-v3-6 T2), but scoped to the 3
new harnesses shipped by iter-v3-8 T1:

  - bridge_MessageProcessor_FinalityBeforeWithdraw.sym.t.sol (analogue)
  - vault_Holdings_TotalAssetsMonotonicity.sym.t.sol (analogue)
  - governance_MultiAdapter_QuorumEnforced.sym.t.sol (analogue)

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

_BRIDGE_HARNESS = _SYM_DIR / "bridge_MessageProcessor_FinalityBeforeWithdraw.sym.t.sol"
_VAULT_HARNESS = _SYM_DIR / "vault_Holdings_TotalAssetsMonotonicity.sym.t.sol"
_GOVERNANCE_HARNESS = _SYM_DIR / "governance_MultiAdapter_QuorumEnforced.sym.t.sol"

# Per-harness must-contain lines for the setUp() body. These are the load-
# bearing state mutations that the check_* functions assume. If any one is
# missing, the check_* would either trivially pass (nothing to evaluate) or
# trivially revert (unreachable path) — in both cases halmos's advisory is
# vacuous.
_SETUP_STATE_MUTATIONS: dict[Path, list[str]] = {
    _BRIDGE_HARNESS: [
        "new Gateway(LOCAL_CENT_ID, pauser, address(this))",
        "new _FinalityNoopProcessorSym()",
        "new _FinalityPauserMockSym()",
        "new _FinalityMessagePropsMockSym()",
        'gateway.file("processor", address(processor))',
        'gateway.file("messageProperties", address(props))',
    ],
    _VAULT_HARNESS: [
        "new Holdings(IHubRegistry(address(registry)), address(this))",
        "new _TAMRegistryMockSym()",
        "new _TAMIdentityValuationSym()",
        "vault.initialize(poolId, scId, assetId, IValuation(address(valuation)), false, accs)",
        "vault.increase(poolId, scId, assetId, d18(1e18), SEED_AMOUNT)",
    ],
    _GOVERNANCE_HARNESS: [
        "new MultiAdapter(uint16(1), IMessageHandler(address(spy)), address(this))",
        "new _QEnfSpyGatewaySym()",
        "new _QEnfPropsMockSym()",
        "new _QEnfAdapterMockSym()",
        'governor.file("messageProperties", address(props))',
        "governor.setAdapters(REMOTE_CID, PoolId.wrap(0), addrs, THRESHOLD, QUORUM)",
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


def test_probe_bridge_finality_before_withdraw_non_vacuous() -> None:
    """Probe: bridge_MessageProcessor_FinalityBeforeWithdraw.sym.t.sol
    setUp is non-vacuous AND every check_* has >=2 consumed symbolic
    inputs.

    setUp must deploy Gateway + _FinalityNoopProcessorSym +
    _FinalityPauserMockSym + _FinalityMessagePropsMockSym and file the
    processor + messageProperties slots — without these the check_*
    calls to gateway.handle / gateway.retry hit address(0) immediately.
    Probe locks setUp against silent regression.
    """
    _assert_harness_non_vacuous(
        _BRIDGE_HARNESS,
        _SETUP_STATE_MUTATIONS[_BRIDGE_HARNESS],
    )


def test_probe_vault_total_assets_monotonicity_non_vacuous() -> None:
    """Probe: vault_Holdings_TotalAssetsMonotonicity.sym.t.sol setUp is
    non-vacuous AND every check_* has >=2 consumed symbolic inputs.

    setUp must deploy Holdings + _TAMRegistryMockSym +
    _TAMIdentityValuationSym, initialize the single holding, and prime
    a seed increase so value() > 0 before the first check_*. Without
    the seed, the analytic floor in the fuzz invariant is degenerate
    and the exact-drop assertion in
    check_decrease_drops_value_by_exact_amount trivially holds on a
    zero-valued holding.
    """
    _assert_harness_non_vacuous(
        _VAULT_HARNESS,
        _SETUP_STATE_MUTATIONS[_VAULT_HARNESS],
    )


def test_probe_governance_quorum_enforced_non_vacuous() -> None:
    """Probe: governance_MultiAdapter_QuorumEnforced.sym.t.sol setUp is
    non-vacuous AND every check_* has >=2 consumed symbolic inputs.

    setUp must deploy MultiAdapter + _QEnfSpyGatewaySym +
    _QEnfPropsMockSym + at least one _QEnfAdapterMockSym, file the
    messageProperties slot, and call setAdapters with THRESHOLD=2 /
    QUORUM=3 against REMOTE_CID so the configured adapter set actually
    binds to the payload route. Without setAdapters, handle() reverts
    with NotAuthorizedAdapter on every path and both check_*s trivially
    observe totalForwards==0 via a revert, not via the real
    vote-counting branch.
    """
    _assert_harness_non_vacuous(
        _GOVERNANCE_HARNESS,
        _SETUP_STATE_MUTATIONS[_GOVERNANCE_HARNESS],
    )


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            suite.addTest(unittest.FunctionTestCase(value, description=name))
    return suite
