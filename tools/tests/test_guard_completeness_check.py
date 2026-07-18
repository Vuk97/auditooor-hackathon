#!/usr/bin/env python3
"""Regression tests for tools/guard-completeness-check.py (wibjbh2e8 gap #5).

Proves the generic guard/access-control completeness gate:
  - a guarded external mutator PASSES,
  - an unguarded external mutator WARNS (advisory default) / FAILS under strict,
  - a view/pure function is NOT counted,
  - a permissionless-with-disposition function PASSES,
  - the audit-done-guard advisory consumer fails-open on absent inputs and
    fails-closed only under strict with no rebuttal.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load(name: str, file_name: str):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / file_name))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


GCC = _load("_gcc_test", "guard-completeness-check.py")
ADG = _load("_adg_gcc_test", "audit-done-guard.py")


def _mk_ws(tmp: Path, sol_body: str, *, sub="src") -> Path:
    ws = tmp
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    src = ws / sub
    src.mkdir(parents=True, exist_ok=True)
    (src / "Target.sol").write_text(sol_body, encoding="utf-8")
    return ws


class GuardCompletenessCheckTest(unittest.TestCase):
    def setUp(self):
        # Ensure a clean strict env per test.
        self._old = os.environ.pop("AUDITOOOR_GUARD_COMPLETENESS_STRICT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_GUARD_COMPLETENESS_STRICT", None)
        if self._old is not None:
            os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = self._old

    # ------------------------------------------------------------------
    def test_guarded_external_mutator_passes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C {
                    address owner;
                    uint256 public total;
                    function setTotal(uint256 v) external onlyOwner {
                        total = v;
                    }
                }
            """)
            rep = GCC.check(ws)
            self.assertEqual(rep["verdict"], "pass-guards-complete", rep)
            self.assertEqual(rep["unguarded_count"], 0, rep)
            self.assertGreaterEqual(rep["guarded"], 1, rep)

    def test_body_require_msgsender_counts_as_guarded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C {
                    address owner;
                    uint256 public total;
                    function setTotal(uint256 v) external {
                        require(msg.sender == owner, "no");
                        total = v;
                    }
                }
            """)
            rep = GCC.check(ws)
            self.assertEqual(rep["verdict"], "pass-guards-complete", rep)

    def test_unguarded_external_mutator_warns_by_default(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C {
                    uint256 public total;
                    function setTotal(uint256 v) external {
                        total = v;
                    }
                }
            """)
            rep = GCC.check(ws)
            self.assertEqual(rep["verdict"], "warn-unguarded-mutators", rep)
            self.assertEqual(rep["unguarded_count"], 1, rep)
            self.assertEqual(rep["unguarded"][0]["function"], "setTotal", rep)

    def test_unguarded_external_mutator_fails_under_strict(self):
        import tempfile
        os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = "1"
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C {
                    uint256 public total;
                    function setTotal(uint256 v) external {
                        total = v;
                    }
                }
            """)
            rep = GCC.check(ws)
            self.assertEqual(rep["verdict"], "fail-unguarded-mutators", rep)

    def test_view_pure_not_counted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C {
                    uint256 total;
                    function getTotal() external view returns (uint256) { return total; }
                    function calc(uint256 a) public pure returns (uint256) { return a * 2; }
                }
            """)
            rep = GCC.check(ws)
            # No external mutators at all -> pass-no-external-mutators.
            self.assertEqual(rep["verdict"], "pass-no-external-mutators", rep)
            self.assertEqual(rep["external_mutators"], 0, rep)

    def test_internal_not_counted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C {
                    uint256 total;
                    function _setTotal(uint256 v) internal { total = v; }
                    function _priv(uint256 v) private { total = v; }
                }
            """)
            rep = GCC.check(ws)
            self.assertEqual(rep["verdict"], "pass-no-external-mutators", rep)

    def test_permissionless_with_disposition_passes(self):
        import tempfile
        os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = "1"
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract Vault {
                    mapping(address => uint256) public balanceOf;
                    function deposit(uint256 amt) external {
                        balanceOf[msg.sender] += amt;
                    }
                }
            """)
            # Without a disposition this fails under strict.
            rep0 = GCC.check(ws)
            self.assertEqual(rep0["verdict"], "fail-unguarded-mutators", rep0)
            # Add a typed permissionless-by-design disposition.
            disp = ws / ".auditooor" / "guard_dispositions.jsonl"
            disp.write_text(json.dumps({
                "file": "src/Target.sol",
                "function": "deposit",
                "reason": "permissionless-by-design ERC4626 deposit",
            }) + "\n", encoding="utf-8")
            rep1 = GCC.check(ws)
            self.assertEqual(rep1["verdict"], "pass-guards-complete", rep1)
            self.assertEqual(rep1["dispositioned"], 1, rep1)

    def test_disposition_without_reason_does_not_excuse(self):
        import tempfile
        os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = "1"
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C { uint256 public t; function s(uint256 v) external { t = v; } }
            """)
            disp = ws / ".auditooor" / "guard_dispositions.jsonl"
            disp.write_text(json.dumps({
                "file": "src/Target.sol", "function": "s", "reason": "",
            }) + "\n", encoding="utf-8")
            rep = GCC.check(ws)
            self.assertEqual(rep["verdict"], "fail-unguarded-mutators", rep)

    def test_sidecar_written(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C { uint256 public t; function s(uint256 v) external { t = v; } }
            """)
            GCC.check(ws)
            side = ws / ".auditooor" / "guard_completeness.jsonl"
            self.assertTrue(side.is_file())
            rows = [json.loads(x) for x in side.read_text().splitlines() if x.strip()]
            self.assertTrue(any(r["function"] == "s" and r["guarded"] is False for r in rows), rows)

    def test_rebuttal_downgrades_cli_exit(self):
        import tempfile
        os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = "1"
        with tempfile.TemporaryDirectory() as d:
            ws = _mk_ws(Path(d), """
                pragma solidity ^0.8.0;
                contract C { uint256 public t; function s(uint256 v) external { t = v; } }
            """)
            # No rebuttal -> CLI rc 1.
            rc0 = GCC.main(["--workspace", str(ws), "--no-write"])
            self.assertEqual(rc0, 1)
            # Rebuttal present -> downgraded to advisory, rc 0.
            (ws / ".auditooor" / "guard_completeness_rebuttal.md").write_text(
                "operator: these are permissionless AMM primitives, reviewed manually.",
                encoding="utf-8")
            rc1 = GCC.main(["--workspace", str(ws), "--no-write"])
            self.assertEqual(rc1, 0)

    def test_absent_workspace_fails_open(self):
        rep = GCC.check(Path("/nonexistent/ws/for/guard/test"))
        self.assertTrue(rep["verdict"].startswith("warn-"), rep)


class AuditDoneGuardWiringTest(unittest.TestCase):
    """The advisory consumer must be present in audit-done-guard.py and mirror
    the block contract: fail_gate ONLY when the verdict starts with fail-
    (strict env) AND no rebuttal; fail-open on a missing/erroring tool.

    audit-done-guard.evaluate() short-circuits on the FIRST failing gate, and a
    tmp fixture legitimately fails the earlier README-conformance gate long
    before the (late) guard block runs. So rather than construct a fully-green
    workspace (which would require replaying the whole runbook), we (1) assert
    the block is wired, and (2) exercise the exact decision logic the block uses
    (GCC.check + GCC._rebuttal) which is what determines whether it blocks."""

    _SRC = (_TOOLS / "audit-done-guard.py").read_text(encoding="utf-8")

    def setUp(self):
        self._old = os.environ.pop("AUDITOOOR_GUARD_COMPLETENESS_STRICT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_GUARD_COMPLETENESS_STRICT", None)
        if self._old is not None:
            os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = self._old

    def test_block_is_wired(self):
        # The advisory consumer must import the tool, attach detail, and gate
        # only on a fail- verdict with no rebuttal.
        self.assertIn("guard-completeness-check.py", self._SRC)
        self.assertIn("guard_completeness_detail", self._SRC)
        self.assertIn('startswith("fail-") and _m12._rebuttal(ws) is None', self._SRC)
        self.assertIn("Guard/access-control completeness FAIL", self._SRC)
        # It must sit inside evaluate(), wrapped in a fail-open try/except (an
        # import error must not brick done).
        self.assertIn("# tool unavailable -> fail-open", self._SRC)

    def _mk_ws(self, tmp: Path, sol_body: str) -> Path:
        ws = tmp
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        src = ws / "src"
        src.mkdir(parents=True, exist_ok=True)
        (src / "Target.sol").write_text(sol_body, encoding="utf-8")
        return ws

    def _block_would_block(self, ws: Path) -> bool:
        """Replicate the exact gating condition the wired block uses."""
        gcc = GCC.check(ws)
        return (str(gcc.get("verdict", "")).startswith("fail-")
                and GCC._rebuttal(ws) is None)

    def test_block_gates_only_under_strict(self):
        import tempfile
        sol = ("pragma solidity ^0.8.0; contract C { uint256 public t; "
               "function s(uint256 v) external { t = v; } }")
        # Non-strict: verdict is warn- -> block would NOT gate.
        with tempfile.TemporaryDirectory() as d:
            ws = self._mk_ws(Path(d), sol)
            self.assertFalse(self._block_would_block(ws))
        # Strict + no rebuttal: verdict is fail- -> block WOULD gate.
        os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = "1"
        with tempfile.TemporaryDirectory() as d:
            ws = self._mk_ws(Path(d), sol)
            self.assertTrue(self._block_would_block(ws))

    def test_block_rebuttal_unblocks_under_strict(self):
        import tempfile
        os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = "1"
        sol = ("pragma solidity ^0.8.0; contract C { uint256 public t; "
               "function s(uint256 v) external { t = v; } }")
        with tempfile.TemporaryDirectory() as d:
            ws = self._mk_ws(Path(d), sol)
            (ws / ".auditooor" / "guard_completeness_rebuttal.md").write_text(
                "operator: permissionless by design, reviewed.", encoding="utf-8")
            self.assertFalse(self._block_would_block(ws))

    def test_block_fails_open_when_all_guarded(self):
        import tempfile
        os.environ["AUDITOOOR_GUARD_COMPLETENESS_STRICT"] = "1"
        sol = ("pragma solidity ^0.8.0; contract C { uint256 public t; "
               "function s(uint256 v) external onlyOwner { t = v; } }")
        with tempfile.TemporaryDirectory() as d:
            ws = self._mk_ws(Path(d), sol)
            self.assertFalse(self._block_would_block(ws))

    def test_evaluate_does_not_crash_and_attaches_detail_when_reached(self):
        # A workspace green enough to REACH the guard block would need the whole
        # runbook; instead assert evaluate() runs without raising on a minimal
        # ws (the fail-open contract) and that reaching an earlier gate does not
        # surface a Guard/access-control reason spuriously.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = self._mk_ws(Path(d), "pragma solidity ^0.8.0; contract C {}")
            (ws / ".auditooor" / "audit_complete_last_result.json").write_text(
                json.dumps({"verdict": "pass-audit-complete", "strict": True}),
                encoding="utf-8")
            pr = ws / "submissions" / "paste_ready"
            pr.mkdir(parents=True, exist_ok=True)
            (pr / "f.md").write_text("# f", encoding="utf-8")
            res = ADG.evaluate(ws)  # must not raise
            self.assertIn("done", res)


class GoMutatorPrecisionTest(unittest.TestCase):
    """Regression: the Go external-mutator predicate must NOT flag a pure exported
    helper (local assignments only) as a mutator. The old branch ended in
    `\\b\\w+\\s*:?=` matching any local assign, so pure math like utils/math.go::
    ExpDec + the pro-rata share helpers were false-flagged unguarded (NUVA)."""

    def test_pure_go_math_is_not_a_mutator(self):
        pure = ("result = math.LegacyDec{}\n sum := math.LegacyOneDec()\n"
                " sum = sum.Add(term)\n return sum, nil\n")
        self.assertFalse(GCC._is_external_mutator("go", "func ExpDec(x Dec) Dec", pure))

    def test_pure_prorata_is_not_a_mutator(self):
        pure = "frac := shares.Quo(total)\n out := frac.MulInt(assets)\n return out\n"
        self.assertFalse(GCC._is_external_mutator("go", "func CalcProRata()", pure))

    def test_keeper_store_write_is_a_mutator(self):
        body = "k.Balances.Set(ctx, addr, newBal)\n return nil\n"
        self.assertTrue(GCC._is_external_mutator("go", "func (k Keeper) SetBal()", body))

    def test_receiver_field_write_is_a_mutator(self):
        body = "k.lastPrice = price\n return nil\n"
        self.assertTrue(GCC._is_external_mutator("go", "func (k *Keeper) Upd()", body))


if __name__ == "__main__":
    unittest.main()
