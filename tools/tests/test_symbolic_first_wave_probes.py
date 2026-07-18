"""capv3-iter6-T2 — non-vacuity probes for the symbolic first-wave harnesses.

Two probe tests, mirroring the iter-v3-2 T2 / iter-v3-5 T2 `test_probe_*`
pattern used for the concrete fuzz harnesses:

  Probe 1: setUp of each `.sym.t.sol` mutates expected state. Confirms the
           symbolic setUp is not a no-op that would let any check_* pass
           trivially. Verified statically across both harnesses.

  Probe 2: every symbolic variable declared on each check_* function is
           actually *consumed* by at least one assertion / vm.assume / or
           expression in the body. A dangling symbolic parameter would make
           halmos explore a larger state space but never bind it to the
           invariant — a silent vacuity. Also enforces the plan's
           ">=2 symbolic inputs per check_*" requirement.

These tests run against the static harness sources in
`projects/centrifuge-v3/symbolic/`. They do NOT require halmos to be
installed — they lock the non-vacuity property of the *harness source*.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SYM_DIR = _REPO_ROOT / "projects" / "centrifuge-v3" / "symbolic"

_GOV_HARNESS = _SYM_DIR / "governance_MultiAdapter_TimelockRespected.sym.t.sol"
_LEND_HARNESS = _SYM_DIR / "lending_Accounting_LiquidationIncentive.sym.t.sol"

# Per-harness must-contain lines for the setUp() body. These are the load-
# bearing state mutations that the check_* functions assume. If any one is
# missing, the check_* would either trivially pass (nothing to evaluate) or
# trivially revert (unreachable path) — in both cases the halmos advisory
# is vacuous.
_SETUP_STATE_MUTATIONS: dict[Path, list[str]] = {
    _GOV_HARNESS: [
        "new Root(INITIAL_DELAY, address(this))",
        "new MultiAdapter(",
        "new _MultiAdapterGatewayMockSym()",
    ],
    _LEND_HARNESS: [
        "new Accounting(address(this))",
        "pool.createAccount(poolId, borrowerDebt,   true)",
        "pool.createAccount(poolId, liquidatorGain, false)",
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


def test_probe_setup_non_vacuous_for_both_symbolic_harnesses() -> None:
    """Probe 1: setUp() of each .sym.t.sol must actually build the state
    the check_* functions rely on.

    A missing deployment or missing createAccount would silently make
    every check_* in that harness a no-op from halmos's perspective —
    either the invariant has no surface to drive, or the first external
    call in the check reverts on a precondition that the setUp was
    supposed to establish. Both cases produce green halmos runs that
    prove nothing.
    """
    for harness_path, must_contain in _SETUP_STATE_MUTATIONS.items():
        assert harness_path.exists(), f"harness missing: {harness_path}"
        source = harness_path.read_text()
        body = _extract_setup_body(source)
        missing = [needle for needle in must_contain if needle not in body]
        assert not missing, (
            f"{harness_path.name} setUp() is missing load-bearing state-"
            f"mutation lines: {missing}. Probe exists to prevent a "
            f"silently-empty setUp that would let every check_* pass "
            f"trivially."
        )


def test_probe_every_symbolic_param_consumed_for_both_harnesses() -> None:
    """Probe 2: every symbolic parameter on every check_* function in each
    harness must appear at least once in the function body, and each
    check_* must declare >=2 symbolic inputs (plan requirement).

    A dangling symbolic param is a silent vacuity: halmos treats the
    param as symbolic, explores paths, but the invariant assertion
    never binds it — so a "pass" says nothing about that dimension
    of the state space. A <2-input check_* collapses the symbolic
    exploration to a trivially-small space, which defeats the purpose
    of mirroring the fuzz harness.
    """
    harnesses = [_GOV_HARNESS, _LEND_HARNESS]
    for harness_path in harnesses:
        assert harness_path.exists(), f"harness missing: {harness_path}"
        source = harness_path.read_text()
        checks = _extract_check_functions(source)

        assert checks, f"{harness_path.name} has no check_* functions"

        for name, (params, body) in checks.items():
            assert len(params) >= 2, (
                f"{harness_path.name}::{name} has {len(params)} symbolic "
                f"inputs; plan requires >=2 to avoid a trivially-small "
                f"state space."
            )
            dangling: list[str] = []
            for _ptype, pname in params:
                # Whole-word match of the param name inside the body.
                if re.search(rf"\b{re.escape(pname)}\b", body) is None:
                    dangling.append(pname)
            assert not dangling, (
                f"{harness_path.name}::{name} declares symbolic param(s) "
                f"{dangling} that are not consumed in the function body. "
                f"halmos would treat them as symbolic but nothing in the "
                f"invariant binds them — silent vacuity."
            )


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            suite.addTest(unittest.FunctionTestCase(value, description=name))
    return suite
