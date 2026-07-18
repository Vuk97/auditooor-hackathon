#!/usr/bin/env python3
"""Tests for tools/guard-negative-space-analyzer.py (schema auditooor.guard_negative_space.v1)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "guard-negative-space-analyzer.py"
_spec = importlib.util.spec_from_file_location("guard_negative_space_analyzer", _TOOL)
gns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gns)


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _mk_ws(tmp: Path) -> Path:
    """Build a fixture workspace: two in-scope .sol files, one with guards, plus a
    vendored file that must be ignored."""
    ws = tmp / "ws"
    (ws / ".auditooor").mkdir(parents=True)

    # in-scope source with two guards (a require + a modifier-use)
    _write(ws / "src" / "Vault.sol", """\
pragma solidity ^0.8.0;
contract Vault {
    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= balance, "insufficient balance");
        balance -= amount;
    }
}
""")
    # in-scope source with NO guards
    _write(ws / "src" / "View.sol", """\
pragma solidity ^0.8.0;
contract View {
    function peek() external view returns (uint256) { return x; }
}
""")
    # vendored file with a guard - must be skipped
    _write(ws / "lib" / "Dep.sol", """\
contract Dep { function f() external { require(true, "x"); } }
""")

    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    rows = [
        {"file": "src/Vault.sol", "function": "withdraw", "file_line": "src/Vault.sol:3"},
        {"file": "src/View.sol", "function": "peek", "file_line": "src/View.sol:3"},
        # vendored unit - should be filtered out of the denominator
        {"file": "lib/Dep.sol", "function": "f", "file_line": "lib/Dep.sol:1"},
    ]
    inscope.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return ws


class EmitWorklistTests(unittest.TestCase):
    def test_case1_emits_worklist_for_inscope_guards_only(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            res = gns.emit_worklist(ws)
            self.assertEqual(res["schema"], gns.SCHEMA)
            # Vault.sol contributes >=2 guards (require + onlyOwner); View.sol none;
            # Dep.sol vendored and excluded.
            self.assertGreaterEqual(res["guards_enumerated"], 2)
            wl = (ws / ".auditooor" / "negative_space_worklist.jsonl").read_text()
            self.assertIn("src/Vault.sol", wl)
            self.assertNotIn("lib/Dep.sol", wl, "vendored guard must not appear")

    def test_case2_worklist_row_shape(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            gns.emit_worklist(ws)
            rows = gns._load_worklist(ws)
            self.assertTrue(rows)
            r = rows[0]
            for field in ("guard_id", "file_line", "kinds", "checks",
                          "invariant_hint", "question"):
                self.assertIn(field, r)
            self.assertIn("NOT check", r["question"])
            self.assertTrue(r["guard_id"].startswith("NS-"))

    def test_case3_invariant_hint_picks_up_balance_token(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            gns.emit_worklist(ws)
            rows = gns._load_worklist(ws)
            hints = " ".join(r["invariant_hint"] for r in rows).lower()
            self.assertIn("balance", hints)


class CheckTests(unittest.TestCase):
    def test_case4_check_fails_when_no_worklist(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            res = gns.check(ws)
            self.assertEqual(res["verdict"], "fail-no-worklist")
            self.assertEqual(res["total_guards"], 0)

    def test_case5_check_needs_probing_after_emit_no_ingest(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            gns.emit_worklist(ws)
            res = gns.check(ws)
            self.assertEqual(res["verdict"], "needs-probing")
            self.assertGreater(res["blindspot_no_exploitation_attempt"], 0)

    def test_case6_complete_path_one_guard_with_artifact_one_without(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            gns.emit_worklist(ws)
            wl = gns._load_worklist(ws)
            gids = [r["guard_id"] for r in wl]

            # Verdict ALL guards: first with an exploitation artifact, rest ruled out.
            verdicts = ws / "verdicts.jsonl"
            lines = []
            for i, gid in enumerate(gids):
                if i == 0:
                    lines.append(json.dumps({
                        "guard_id": gid,
                        "gap_found": True,
                        "kind": "missing-bound",
                        "passing_but_malicious_input": "amount=0 underflow",
                        "exploitation_attempt_artifact": "poc/withdraw_underflow_test.sol",
                    }))
                else:
                    lines.append(json.dumps({
                        "guard_id": gid,
                        "gap_found": False,
                        "kind": "complete",
                        "ruled_out": "covered by onlyOwner; src/Vault.sol:3",
                    }))
            verdicts.write_text("\n".join(lines) + "\n", encoding="utf-8")

            ing = gns.ingest(ws, verdicts)
            self.assertEqual(ing["ingested"], len(gids))
            self.assertEqual(ing["gaps_found"], 1)

            res = gns.check(ws)
            self.assertEqual(res["verdict"], "pass-negative-space-complete")
            self.assertEqual(res["blindspot_no_exploitation_attempt"], 0)

    def test_case7_coverage_below_when_one_guard_lacks_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            gns.emit_worklist(ws)
            wl = gns._load_worklist(ws)
            gids = [r["guard_id"] for r in wl]
            # Verdict every guard but ONE carries no artifact / ruled_out -> blindspot.
            verdicts = ws / "verdicts.jsonl"
            lines = []
            for i, gid in enumerate(gids):
                rec = {"guard_id": gid, "gap_found": False, "kind": "x"}
                if i != 0:
                    rec["ruled_out"] = "n/a; src/Vault.sol:3"
                lines.append(json.dumps(rec))
            verdicts.write_text("\n".join(lines) + "\n", encoding="utf-8")
            gns.ingest(ws, verdicts)
            res = gns.check(ws)
            self.assertEqual(res["verdict"], "coverage-below")
            self.assertEqual(res["blindspot_no_exploitation_attempt"], 1)


class IngestEdgeTests(unittest.TestCase):
    def test_case8_unknown_guard_id_flagged_not_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            gns.emit_worklist(ws)
            verdicts = ws / "v.jsonl"
            verdicts.write_text(json.dumps({
                "guard_id": "NS-deadbeef0000",
                "gap_found": True,
                "exploitation_attempt_artifact": "poc/x.sol",
            }) + "\n", encoding="utf-8")
            res = gns.ingest(ws, verdicts)
            self.assertEqual(res["ingested"], 1)
            gaps = gns._load_gaps(ws)
            self.assertTrue(any(g.get("unknown_guard") for g in gaps.values()))

    def test_case9_ingest_missing_file_errors_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            res = gns.ingest(ws, ws / "nope.jsonl")
            self.assertIn("error", res)
            self.assertEqual(res["ingested"], 0)


def _mk_scope_ws(tmp: Path) -> Path:
    """Fixture exercising the shared scope_exclusion wiring.

    Three guard-bearing Go files, all listed in the manifest:
      * ``x/keeper/msg_server.go``  - in-scope protocol source (KEPT)
      * ``x/keeper/latest_state.go``- in-scope; name CONTAINS the substring
        ``latest`` / would be false-dropped by a naive ``interchaintest``
        substring match. Must be KEPT (no false-red).
      * ``x/keeper/msg_server_test.go`` - a Go test file. The OLD ad-hoc
        segment table only excluded a ``test``/``tests`` *directory* segment, so
        a ``_test.go`` *file* in a real dir slipped through. The shared
        scope_exclusion.is_oos catches it. Must be EXCLUDED (no OOS-guard
        packet, no false-green of probing test infra).
    """
    ws = tmp / "ws"
    (ws / ".auditooor").mkdir(parents=True)

    _write(ws / "x" / "keeper" / "msg_server.go", """\
package keeper
func (k Keeper) Withdraw(amount uint64) error {
    if amount == 0 {
        return ErrZeroAmount
    }
    require(amount <= balance, "insufficient")
    return nil
}
""")
    # latest_state.go carries one REAL security guard (an authorization check)
    # plus idiomatic Go err-propagation boilerplate. The scope-exclusion test
    # below asserts the FILE is in scope (not false-dropped by the substring
    # ``latest``); the per-language LG3 filter prunes the ``if err != nil``
    # plumbing but keeps the auth guard, so the file still contributes a row.
    _write(ws / "x" / "keeper" / "latest_state.go", """\
package keeper
func (k Keeper) LatestState(id uint64, caller string) (State, error) {
    if err := k.validateOwner(caller); err != nil {
        return State{}, err
    }
    s, err := k.fetch(id)
    if err != nil {
        return State{}, err
    }
    return s, nil
}
""")
    _write(ws / "x" / "keeper" / "msg_server_test.go", """\
package keeper
func TestWithdraw(t *testing.T) {
    require(setupAmount == 0, "guard in a TEST file - must not be probed")
}
""")

    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    rows = [
        {"file": "x/keeper/msg_server.go", "function": "Withdraw",
         "file_line": "x/keeper/msg_server.go:2"},
        {"file": "x/keeper/latest_state.go", "function": "LatestState",
         "file_line": "x/keeper/latest_state.go:2"},
        # A test file erroneously present in the manifest - the OOS filter must
        # refuse to emit a guard packet for it even though it is listed.
        {"file": "x/keeper/msg_server_test.go", "function": "TestWithdraw",
         "file_line": "x/keeper/msg_server_test.go:2"},
    ]
    inscope.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return ws


class SharedScopeExclusionTests(unittest.TestCase):
    """Step-5 guard: OOS surface excluded AND in-scope surface still present."""

    def test_case11_test_file_guard_excluded_inscope_guard_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_scope_ws(Path(td))
            res = gns.emit_worklist(ws)
            wl = (ws / ".auditooor" / "negative_space_worklist.jsonl").read_text()

            # in-scope protocol guard IS present
            self.assertIn("x/keeper/msg_server.go", wl,
                          "in-scope guard must be enumerated")
            # the OOS _test.go guard is NOT emitted (no OOS-guard packet)
            self.assertNotIn("msg_server_test.go", wl,
                             "guard in a _test.go file must be excluded by is_oos")
            # denominator counted only the 2 in-scope files, not the test file
            self.assertEqual(res["inscope_files"], 2)

    def test_case12_substring_named_inscope_file_not_false_dropped(self):
        # ``latest_state.go`` contains the substring ``latest`` (and a naive
        # ``interchaintest`` substring matcher would wrongly drop it). The
        # shared helper does whole-segment matching, so it stays IN scope.
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_scope_ws(Path(td))
            gns.emit_worklist(ws)
            wl = (ws / ".auditooor" / "negative_space_worklist.jsonl").read_text()
            self.assertIn("x/keeper/latest_state.go", wl,
                          "in-scope file whose name contains a marker substring "
                          "must NOT be false-dropped (no false-red)")

    def test_case13_is_vendored_delegates_to_shared_is_oos(self):
        # Direct unit check that the renamed-but-retained _is_vendored now uses
        # the shared scope_exclusion.is_oos verdict (broader than the old table).
        self.assertTrue(gns._is_vendored("x/keeper/foo_test.go"))   # test file
        self.assertTrue(gns._is_vendored("gen/types/tx.pb.go"))     # generated
        self.assertTrue(gns._is_vendored("lib/Dep.sol"))           # vendored dir
        self.assertFalse(gns._is_vendored("x/keeper/latest_state.go"))  # in-scope
        self.assertFalse(gns._is_vendored("src/Vault.sol"))        # in-scope


class CliTests(unittest.TestCase):
    def test_case10_cli_check_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td))
            # check before emit -> non-zero
            rc = gns.main(["--workspace", str(ws), "--check", "--json"])
            self.assertEqual(rc, 1)
            # emit -> zero
            rc = gns.main(["--workspace", str(ws), "--emit-worklist", "--json"])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
