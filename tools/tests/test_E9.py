#!/usr/bin/env python3
"""
Tests for tools/ordering-dependent-invariant-tagger.py (E9).
Schema: auditooor.ordering_dependent_invariant.v1

Non-vacuity contract (all three must hold):
  * a planted positive FIRES,
  * a guarded negative stays SILENT,
  * neutralizing the CORE ordering predicate makes the positive test FAIL.

Plus real-fleet mutation-verify: silent on the guarded Morpho.sol, and FIRES on a
TEMP COPY whose borrow() loses its _accrueInterest domination (the ws file is never
mutated). Fleet tests self-skip when the corpus is absent (offline/CI safe).

Run: python3 -m unittest tools.tests.test_E9 -v
"""
from __future__ import annotations

import importlib.util
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

TOOL_PATH = Path(__file__).resolve().parents[1] / "ordering-dependent-invariant-tagger.py"
MORPHO = Path("/Users/wolf/audits/morpho/src/morpho-blue/src/Morpho.sol")


def _load():
    import sys
    spec = importlib.util.spec_from_file_location("odi_tagger", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclass field resolution needs this
    spec.loader.exec_module(mod)
    return mod


ODI = _load()

# --------------------------------------------------------------------------- #
# Synthetic fixtures (Morpho-shaped, all languages)
# --------------------------------------------------------------------------- #
SOL_POSITIVE = """\
contract C {
    struct M { uint128 totalBorrowAssets; uint128 lastUpdate; }
    mapping(bytes32 => M) market;

    function _accrueInterest(bytes32 id) internal {
        market[id].totalBorrowAssets += 1;
        market[id].lastUpdate = uint128(block.timestamp);
    }

    function borrow(bytes32 id, uint256 assets) external {
        require(market[id].lastUpdate != 0);
        uint256 debt = market[id].totalBorrowAssets + assets;
        market[id].totalBorrowAssets += assets;
    }
}
"""

SOL_GUARDED = """\
contract C {
    struct M { uint128 totalBorrowAssets; uint128 lastUpdate; }
    mapping(bytes32 => M) market;

    function _accrueInterest(bytes32 id) internal {
        market[id].totalBorrowAssets += 1;
        market[id].lastUpdate = uint128(block.timestamp);
    }

    function borrow(bytes32 id, uint256 assets) external {
        require(market[id].lastUpdate != 0);
        _accrueInterest(id);
        uint256 debt = market[id].totalBorrowAssets + assets;
        market[id].totalBorrowAssets += assets;
    }
}
"""

# supplyCollateral analog: reads only the plain-assignment flag lastUpdate, never
# the drifting accumulator -> must stay silent even with NO accrue call.
SOL_LASTUPDATE_ONLY = """\
contract C {
    struct M { uint128 totalBorrowAssets; uint128 lastUpdate; }
    mapping(bytes32 => M) market;

    function _accrueInterest(bytes32 id) internal {
        market[id].totalBorrowAssets += 1;
        market[id].lastUpdate = uint128(block.timestamp);
    }

    function supplyCollateral(bytes32 id, uint256 amt) external {
        require(market[id].lastUpdate != 0);
        position[id].collateral += amt; // touches non-accumulator, no accrue needed
    }
}
"""

RUST_POSITIVE = """\
struct Market { total_assets: u128, debt: u128 }
impl Market {
    fn accrue(&mut self) { self.total_assets += 1; }
    fn borrow(&mut self, x: u128) {
        let d = self.total_assets + x;
        self.debt += d;
    }
}
"""

RUST_GUARDED = """\
struct Market { total_assets: u128, debt: u128 }
impl Market {
    fn accrue(&mut self) { self.total_assets += 1; }
    fn borrow(&mut self, x: u128) {
        self.accrue();
        let d = self.total_assets + x;
        self.debt += d;
    }
}
"""

GO_POSITIVE = """\
package m
type Market struct { TotalBorrow uint64; Debt uint64 }
func (m *Market) update() { m.TotalBorrow += 1 }
func (m *Market) Borrow(x uint64) {
    d := m.TotalBorrow + x
    m.Debt += d
}
"""

GO_GUARDED = """\
package m
type Market struct { TotalBorrow uint64; Debt uint64 }
func (m *Market) update() { m.TotalBorrow += 1 }
func (m *Market) Borrow(x uint64) {
    m.update()
    d := m.TotalBorrow + x
    m.Debt += d
}
"""


class TestPositiveNegative(unittest.TestCase):
    def test_sol_positive_fires(self):
        rows = ODI.analyze_source(SOL_POSITIVE, "sol")
        self.assertTrue(rows, "planted positive must fire")
        r = rows[0]
        self.assertEqual(r.function, "borrow")
        self.assertEqual(r.subject_field, "totalBorrowAssets")
        self.assertEqual(r.verdict, "needs-fuzz")
        self.assertTrue(r.advisory)
        self.assertIn("_accrueInterest", r.refresher_candidates)

    def test_sol_guarded_silent(self):
        rows = ODI.analyze_source(SOL_GUARDED, "sol")
        self.assertEqual(rows, [], "guarded (accrue-before-read) must be silent")

    def test_lastupdate_flag_excluded(self):
        # reading the plain-assignment bookkeeping flag is not a drift hazard
        rows = ODI.analyze_source(SOL_LASTUPDATE_ONLY, "sol")
        self.assertEqual(rows, [], "plain-assignment flag read must not fire")

    def test_rust_generality(self):
        self.assertTrue(ODI.analyze_source(RUST_POSITIVE, "rust"), "rust positive must fire")
        self.assertEqual(ODI.analyze_source(RUST_GUARDED, "rust"), [], "rust guarded silent")

    def test_go_generality(self):
        self.assertTrue(ODI.analyze_source(GO_POSITIVE, "go"), "go positive must fire")
        self.assertEqual(ODI.analyze_source(GO_GUARDED, "go"), [], "go guarded silent")


# Lido ExitLimitUtils.setExitLimits analog: the accumulator `prevTimestamp` is
# compound-assigned inside the refresher updatePrevExitLimit, but in setExitLimits
# it is only PLAIN-overwritten (`_data.prevTimestamp = uint32(timestamp)`) with an
# RHS that does not reference `.prevTimestamp` -> a pure overwrite, not a stale
# read, must stay silent. (Fleet FP: src/core/contracts/0.8.9/lib/ExitLimitUtils.sol:116)
# NB: signatures are multi-line with `internal ... returns (...) {` on the brace
# line, mirroring the real Lido source so these funcs are actually analyzed (a
# single-line `... pure ... {` header would be dropped by the view/pure filter and
# the fixture would pass vacuously).
SOL_PLAIN_OVERWRITE = """\
library L {
    struct D { uint32 prevTimestamp; uint32 prevLimit; uint32 maxLimit; }

    function updatePrevExitLimit(
        D memory _data,
        uint256 t
    ) internal returns (D memory) {
        _data.prevTimestamp += uint32(t);
        return _data;
    }

    function setExitLimits(
        D memory _data,
        uint256 timestamp
    ) internal returns (D memory) {
        _data.prevLimit = uint32(0);
        _data.prevTimestamp = uint32(timestamp);
        return _data;
    }
}
"""

# Self-referential plain assign (`.fld = .fld + x`) reads the stale value and MUST
# keep firing -- guards the fix against over-suppression.
SOL_SELF_REF_ASSIGN = """\
library L {
    struct D { uint32 prevTimestamp; }

    function updatePrevExitLimit(
        D memory _data,
        uint256 t
    ) internal returns (D memory) {
        _data.prevTimestamp += uint32(t);
        return _data;
    }

    function setExitLimits(
        D memory _data,
        uint256 timestamp
    ) internal returns (D memory) {
        _data.prevTimestamp = _data.prevTimestamp + uint32(timestamp);
        return _data;
    }
}
"""


class TestPlainOverwriteNotStaleRead(unittest.TestCase):
    def test_plain_overwrite_silent(self):
        # pure overwrite of the accumulator is not a stale read -> 0 FP (Lido)
        rows = ODI.analyze_source(SOL_PLAIN_OVERWRITE, "sol")
        self.assertEqual(
            rows, [],
            "a plain `.fld = <expr w/o .fld>` overwrite must not fire (Lido FP)",
        )

    def test_self_referential_plain_assign_still_fires(self):
        # read-modify via plain `=` reads the stale value -> must keep firing
        rows = ODI.analyze_source(SOL_SELF_REF_ASSIGN, "sol")
        self.assertTrue(
            rows, "self-referential plain assign (`.fld = .fld + x`) must still fire"
        )
        self.assertEqual(rows[0].subject_field, "prevTimestamp")
        self.assertEqual(rows[0].function, "setExitLimits")

    def test_helper_predicate_direct(self):
        self.assertTrue(
            ODI._is_plain_overwrite_no_self_read(
                "_data.prevTimestamp = uint32(timestamp);", "prevTimestamp"
            )
        )
        # compound assign is never a pure overwrite
        self.assertFalse(
            ODI._is_plain_overwrite_no_self_read(
                "_data.prevTimestamp += uint32(t);", "prevTimestamp"
            )
        )
        # self-referential RHS is not a pure overwrite
        self.assertFalse(
            ODI._is_plain_overwrite_no_self_read(
                "_data.prevTimestamp = _data.prevTimestamp + 1;", "prevTimestamp"
            )
        )

    def test_lido_fleet_file_zero_fp(self):
        lido = Path(
            "/Users/wolf/audits/lido/src/core/contracts/0.8.9/lib/ExitLimitUtils.sol"
        )
        if not lido.exists():
            self.skipTest("lido fleet file not present")
        rows = ODI.analyze_file(lido)
        self.assertEqual(
            rows, [], "the real Lido ExitLimitUtils.sol must be silent (0 FP)"
        )


class TestNonVacuity(unittest.TestCase):
    def test_neutralizing_ordering_predicate_kills_the_fire(self):
        # sanity: positive fires normally
        self.assertTrue(ODI.analyze_source(SOL_POSITIVE, "sol"))
        # neutralize the CORE predicate: pretend a refresher call precedes every
        # line -> the ordering-domination obligation can never be unmet.
        orig = ODI._line_has_refresher_call
        try:
            ODI._line_has_refresher_call = lambda code, r_names: True
            rows = ODI.analyze_source(SOL_POSITIVE, "sol")
            self.assertEqual(
                rows, [],
                "with the ordering predicate neutralized the positive MUST stop "
                "firing -- proves the fire is produced by the domination check, "
                "not by an unconditional tag",
            )
        finally:
            ODI._line_has_refresher_call = orig
        # and it fires again once restored
        self.assertTrue(ODI.analyze_source(SOL_POSITIVE, "sol"))

    def test_no_accumulator_means_no_rows(self):
        # a file with a refresher that never compound-assigns a member has no
        # tracked accumulator -> zero obligations (drift is undefined).
        src = SOL_POSITIVE.replace("market[id].totalBorrowAssets += 1;", "uint256 z = 1;")
        self.assertEqual(ODI.analyze_source(src, "sol"), [])


class TestAdvisoryContract(unittest.TestCase):
    def test_main_never_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "Pos.sol"
            f.write_text(SOL_POSITIVE)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = ODI.main([str(f)])
            self.assertEqual(rc, 0, "advisory tool must exit 0 even when rows fire")
            self.assertIn('"needs-fuzz"', out.getvalue())

    def test_json_out(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "Pos.sol"
            f.write_text(SOL_POSITIVE)
            jout = Path(d) / "rows.json"
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                ODI.main([str(f), "--json", str(jout)])
            data = json.loads(jout.read_text())
            self.assertTrue(data and data[0]["schema"] == ODI.SCHEMA)


@unittest.skipUnless(MORPHO.exists(), "fleet corpus (Morpho.sol) not present")
class TestRealFleetMutation(unittest.TestCase):
    def test_guarded_fleet_silent(self):
        rows = ODI.analyze_file(MORPHO)
        self.assertEqual(rows, [], "the guarded, real Morpho.sol must be silent (0 FP)")

    def test_weakened_borrow_fires_on_temp_copy(self):
        src = MORPHO.read_text()
        lines = src.splitlines()
        # drop the first _accrueInterest call inside borrow() on a TEMP COPY only
        out, in_borrow, dropped = [], False, False
        for ln in lines:
            if re.search(r"\bfunction\s+borrow\s*\(", ln):
                in_borrow = True
            if in_borrow and not dropped and "_accrueInterest(marketParams, id);" in ln:
                dropped = True
                continue  # remove the domination guard
            out.append(ln)
        self.assertTrue(dropped, "fixture precondition: borrow accrue call located")
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d) / "Morpho.sol"
            tmp.write_text("\n".join(out) + "\n")
            rows = ODI.analyze_file(tmp)
        fired = [r for r in rows if r.function == "borrow"]
        self.assertTrue(fired, "weakened borrow() must fire the ordering obligation")
        self.assertTrue(
            all(r.verdict == "needs-fuzz" and r.advisory for r in rows),
            "every fleet row must remain advisory needs-fuzz",
        )
        # precision: firing is confined to the mutated path, not the whole file
        self.assertEqual({r.function for r in rows}, {"borrow"})


if __name__ == "__main__":
    unittest.main()
