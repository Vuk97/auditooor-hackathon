#!/usr/bin/env python3
"""Tests for tools/transitive-crosscontract-cei.py (TCCEI).

Covers: a genuine cross-contract survivor, the entrypoint filter, the honest
cited-empty vs substrate_vacuous distinction, schema conformance, and a
NON-VACUOUS mutation pair (add a dominating lock -> survivor disappears;
retarget the reentry write to a local -> survivor disappears).
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "transitive-crosscontract-cei.py"
_spec = importlib.util.spec_from_file_location("tccei", _TOOL)
tccei = importlib.util.module_from_spec(_spec)  # type: ignore
assert _spec and _spec.loader
_spec.loader.exec_module(tccei)  # type: ignore


# ---------------------------------------------------------------------------
# Fixture builders. A Vault reads `totalShares`, hands control to an external
# `receiver` hook, then USES `totalShares` again. A sibling Router (related by
# type-ref) writes `totalShares` in an unguarded public function -> the
# attacker re-enters Router.sync during the hook and invalidates the cached
# read. Neither module's own body is CEI-wrong; the violation is transitive.
# ---------------------------------------------------------------------------
def _vault(guard: str = "") -> str:
    return f"""
pragma solidity ^0.8.0;

interface IReceiver {{ function onFlashLoan(uint256 v) external; }}

contract Router {{
    uint256 public totalShares;
    address public receiver;
    // unguarded sibling writer reached transitively during the hook.
    function sync(uint256 delta) public {{
        totalShares = totalShares + delta;
    }}
}}

contract Vault {{
    uint256 public totalShares;
    Router public router;
    IReceiver public receiver;

    function distribute(uint256 amount) external {guard} {{
        uint256 cached = totalShares;          // READ(S)
        receiver.onFlashLoan(amount);                 // EXTERNAL CALL (hook window)
        uint256 payout = totalShares * amount / cached; // USE(S) stale
        router.sync(payout);
    }}
}}
"""


def _vault_local_write() -> str:
    """Mutation B: the reentry writer mutates a LOCAL, not the tracked state,
    so the transitive-write-reachable predicate must go false."""
    return """
pragma solidity ^0.8.0;

interface IReceiver { function onFlashLoan(uint256 v) external; }

contract Router {
    uint256 public totalShares;
    address public receiver;
    function sync(uint256 delta) public {
        uint256 tmpShares = delta;   // writes a LOCAL, not totalShares
        tmpShares = tmpShares + 1;
    }
}

contract Vault {
    uint256 public totalShares;
    Router public router;
    IReceiver public receiver;

    function distribute(uint256 amount) external {
        uint256 cached = totalShares;
        receiver.onFlashLoan(amount);
        uint256 payout = totalShares * amount / cached;
        router.sync(payout);
    }
}
"""


def _internal_only_nonentry() -> str:
    """An internal helper that is never reachable from any entrypoint should be
    filtered out (entrypoint-reachable predicate)."""
    return """
pragma solidity ^0.8.0;
interface IReceiver { function onFlashLoan(uint256 v) external; }
contract Router {
    uint256 public totalShares;
    function sync(uint256 d) public { totalShares = totalShares + d; }
}
contract Orphan {
    uint256 public totalShares;
    Router public router;
    IReceiver public receiver;
    // internal, and NO public caller anywhere -> not entrypoint-reachable.
    function _dead(uint256 amount) internal {
        uint256 cached = totalShares;
        receiver.onFlashLoan(amount);
        uint256 x = totalShares + cached;
        router.sync(x);
    }
}
"""


def _write(root: Path, name: str, body: str) -> None:
    (root / name).write_text(body, encoding="utf-8")


class TestTCCEI(unittest.TestCase):
    def _run(self, files: dict[str, str]) -> dict:
        d = Path(tempfile.mkdtemp())
        for n, b in files.items():
            _write(d, n, b)
        return tccei.produce_survivors(d, d)

    # 1. genuine cross-contract survivor is emitted.
    def test_survivor_emitted(self) -> None:
        res = self._run({"Vault.sol": _vault()})
        survs = res["survivors"]
        self.assertTrue(survs, "expected at least one survivor")
        s = next(x for x in survs if x["function"] == "distribute")
        self.assertEqual(s["state_var"], "totalShares")
        self.assertEqual(s["writer_function"], "sync")
        self.assertTrue(s["cross_contract"])
        self.assertFalse(res["substrate_vacuous"])

    # 2. schema conformance + required fields + source_refs shape.
    def test_schema_conformance(self) -> None:
        res = self._run({"Vault.sol": _vault()})
        s = res["survivors"][0]
        self.assertEqual(s["schema"], "auditooor.transitive_crosscontract_cei.v1")
        for k in ("state_var", "function", "contract", "file", "line",
                  "writer_function", "writer_contract", "reentry_path",
                  "source_refs", "attack_class", "verdict", "sub_class"):
            self.assertIn(k, s)
        self.assertEqual(s["verdict"], "needs-fuzz")
        self.assertTrue(all(":" in r for r in s["source_refs"]))
        self.assertIn("reads totalShares", s["reentry_path"])

    # 3. MUTATION A: adding a dominating shared/global lock removes the survivor.
    #    A per-instance nonReentrant on the CROSS-contract writer must NOT
    #    dominate (still a survivor); a shared global lock MUST.
    def test_mutation_lock_dominates(self) -> None:
        base = self._run({"Vault.sol": _vault()})
        base_n = len([s for s in base["survivors"]
                      if s["function"] == "distribute"])
        self.assertGreater(base_n, 0)

        # inject a shared/global lock token referenced by BOTH F and writer.
        locked = _vault().replace(
            "function sync(uint256 delta) public {",
            "function sync(uint256 delta) public { globalSharedReentrancyLock = 1;"
        ).replace(
            "uint256 cached = totalShares;",
            "globalSharedReentrancyLock = 1; uint256 cached = totalShares;"
        ).replace(
            "uint256 public totalShares;\n    Router public router;",
            "uint256 public totalShares;\n    uint256 public globalSharedReentrancyLock;\n    Router public router;"
        ).replace(
            "uint256 public totalShares;\n    address public receiver;",
            "uint256 public totalShares;\n    uint256 public globalSharedReentrancyLock;\n    address public receiver;"
        )
        mut = self._run({"Vault.sol": locked})
        mut_n = len([s for s in mut["survivors"]
                     if s["function"] == "distribute"])
        self.assertEqual(mut_n, 0,
                         "shared global lock must dominate the window")
        self.assertGreater(mut["counts"]["guard_dominated"], 0)

    # 4. MUTATION B: retargeting the reentry write to a LOCAL removes the
    #    survivor (transitive-write-reachable goes false).
    def test_mutation_write_local(self) -> None:
        base = self._run({"Vault.sol": _vault()})
        self.assertGreater(len(base["survivors"]), 0)
        mut = self._run({"Vault.sol": _vault_local_write()})
        distrib = [s for s in mut["survivors"] if s["function"] == "distribute"]
        self.assertEqual(distrib, [],
                         "writer touching a local, not state, must not survive")

    # 5. entrypoint-reachable filter: an internal, unreferenced helper drops.
    def test_entrypoint_filter(self) -> None:
        res = self._run({"Orphan.sol": _internal_only_nonentry()})
        self.assertEqual(
            [s for s in res["survivors"] if s["function"] == "_dead"], [],
            "non-entrypoint-reachable helper must be filtered out")

    # 6. substrate vacuity: a workspace with no owned Solidity is vacuous, not
    #    a false clean 0 (honest cited-empty vs substrate_vacuous).
    def test_substrate_vacuous_vs_cited_empty(self) -> None:
        # vacuous: no .sol at all.
        d = Path(tempfile.mkdtemp())
        (d / "README.md").write_text("no solidity here", encoding="utf-8")
        vac = tccei.produce_survivors(d, d)
        self.assertTrue(vac["substrate_vacuous"])
        self.assertEqual(vac["counts"]["survivors"], 0)

        # cited-empty: real solidity, but CEI-clean (guarded same-contract).
        clean = """
pragma solidity ^0.8.0;
contract Safe {
    uint256 public totalShares;
    function poke() external { totalShares = totalShares + 1; }
}
"""
        ce = self._run({"Safe.sol": clean})
        self.assertFalse(ce["substrate_vacuous"])
        self.assertEqual(ce["counts"]["survivors"], 0)

    # 7. evaluate() advisory wrapper reports needs-fuzz + status.
    def test_evaluate_status(self) -> None:
        d = Path(tempfile.mkdtemp())
        _write(d, "Vault.sol", _vault())
        out = tccei.evaluate(d, d, emit=False)["transitive_crosscontract_cei"]
        self.assertEqual(out["verdict"], "needs-fuzz")
        self.assertEqual(out["status"], "survivors")
        self.assertIn("read_extcall_use_windows", out["counts"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
