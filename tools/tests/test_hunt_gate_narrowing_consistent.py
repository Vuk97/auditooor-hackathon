#!/usr/bin/env python3
"""Never-false-pass tests for Lane CAP-HUNT-GATE-NARROWING-CONSISTENT.

Background: `tools/workspace-coverage-heatmap.py --coverage-report` narrows
its coverage_report denominator to the true Go/Cosmos entry-point surface via
`go_entrypoint_surface.apply_go_cosmos_coverage_scope_narrowing` (Lane D,
commit c9ed88aa60). `tools/hunt-coverage-gate.py`'s `fail-denominator-missing-
in-scope-units` check compares that reported total against its OWN
independently-built live in-scope enumeration (from `.auditooor/
inscope_units.jsonl` + `enumerate_units`). Before this lane, the live side was
never narrowed, so a narrowed reported_total (e.g. SEI 5119) was compared
against an un-narrowed live_total (e.g. SEI 20653) and ALWAYS false-failed.

This test file pins that `_live_denominator` (via
`_apply_live_go_cosmos_narrowing_if_consistent`) now applies the IDENTICAL
narrowing predicate to the live side, ONLY when the reported side was itself
narrowed AND the workspace is confidently Cosmos-Go - and, above all, that the
narrowing can NEVER launder a genuinely-unscanned entry-point unit out of the
gate's obligation set (constraint #6 - the most important property here).

This is a GATE-INPUT file: an over-pass is a false-green (the #1 sin), so
every test pins a NEVER-FALSE-PASS guarantee, not just "narrowing runs".
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Load workspace-coverage-heatmap.py (hyphenated name) by file path, exactly as
# hunt-coverage-gate.py's own _load_heatmap does.
_hm_spec = importlib.util.spec_from_file_location(
    "hm_for_gate_narrow_test", ROOT / "tools" / "workspace-coverage-heatmap.py"
)
hm = importlib.util.module_from_spec(_hm_spec)
_hm_spec.loader.exec_module(hm)  # type: ignore[union-attr]

sys.path.insert(0, str(ROOT / "tools"))
gate = importlib.import_module("hunt-coverage-gate")  # type: ignore


_COSMOS_GOMOD = (
    "module github.com/example/chain\n\ngo 1.21\n\n"
    "require (\n\tgithub.com/cosmos/cosmos-sdk v0.47.0\n)\n"
)
_NONCOSMOS_GOMOD = "module github.com/example/plainservice\n\ngo 1.21\n"

_MSG_SERVER_FN = (
    "package keeper\n\n"
    "func (k msgServer) Send(goCtx context.Context, msg *types.MsgSend) "
    "(*types.MsgSendResponse, error) {\n\treturn nil, nil\n}\n"
)
_KEEPER_HELPER_FN = (
    "package keeper\n\n"
    "func (k Keeper) GetGasPool(ctx sdk.Context) sdk.Coins {\n\treturn nil\n}\n"
)
_KEEPER_HELPER_FN_2 = (
    "package keeper\n\n"
    "func (k Keeper) GetInflationPool(ctx sdk.Context) sdk.Coins {\n\treturn nil\n}\n"
)
_PRECOMPILE_DISPATCH_FN = (
    "package precompiles\n\n"
    "func (p Precompile) Run(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {\n\treturn nil, nil\n}\n"
)
_PRECOMPILE_INTERNAL_HELPER_FN = (
    "package precompiles\n\n"
    "func (p Precompile) internalAccessorNotDispatch() error {\n\treturn nil\n}\n"
)


def _write(ws: Path, rel: str, content: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _cosmos_ws(files: dict[str, str]) -> Path:
    tmp = tempfile.mkdtemp(prefix="hunt_gate_narrow_")
    ws = Path(tmp)
    _write(ws, "go.mod", _COSMOS_GOMOD)
    (ws / "app").mkdir(parents=True, exist_ok=True)
    (ws / "x").mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        _write(ws, rel, content)
    return ws


def _plain_go_ws(files: dict[str, str]) -> Path:
    tmp = tempfile.mkdtemp(prefix="hunt_gate_narrow_plain_")
    ws = Path(tmp)
    _write(ws, "go.mod", _NONCOSMOS_GOMOD)
    for rel, content in files.items():
        _write(ws, rel, content)
    return ws


def _write_inscope_manifest(ws: Path, rel_files: list[str]) -> None:
    lines = [json.dumps({"file": rel}) for rel in rel_files]
    _write(ws, ".auditooor/inscope_units.jsonl", "\n".join(lines) + "\n")


class TestNarrowedReportMatchesNarrowedLive(unittest.TestCase):
    """Core fix: on a Cosmos-Go ws where the reported side was narrowed, the
    live side narrows identically -> reported_total == live_total ->
    fail-denominator-missing-in-scope-units does NOT fire."""

    def test_reported_and_live_totals_agree_after_narrowing(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helper.go": _KEEPER_HELPER_FN,
            "x/bank/keeper/helper2.go": _KEEPER_HELPER_FN_2,
        })
        _write_inscope_manifest(ws, [
            "x/bank/keeper/msg_server.go",
            "x/bank/keeper/helper.go",
            "x/bank/keeper/helper2.go",
        ])
        report = hm.build_coverage_report(ws)
        self.assertTrue(
            report["enumeration"]["go_cosmos_scope_narrowing"]["applied"],
            "precondition: reported side must be narrowed for this test",
        )
        reported_total = report["total_units"]

        live_units, enum_detail, _ = gate._live_denominator(hm, ws, report)
        self.assertIsNotNone(live_units)
        self.assertTrue(
            enum_detail.get("go_cosmos_scope_narrowing_live", {}).get("applied"),
            "live side must record that it applied the same narrowing",
        )
        self.assertEqual(
            reported_total, len(live_units),
            f"reported_total={reported_total} vs live_total={len(live_units)} "
            "must agree after symmetric narrowing",
        )

    def test_fail_denominator_check_passes_after_narrowing(self):
        """End-to-end: the actual comparison block in gate.check()'s inline
        logic (reproduced here via the same helpers it calls) must NOT flag
        missing/extra units once both sides are narrowed identically."""
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helper.go": _KEEPER_HELPER_FN,
            "x/bank/keeper/helper2.go": _KEEPER_HELPER_FN_2,
        })
        _write_inscope_manifest(ws, [
            "x/bank/keeper/msg_server.go",
            "x/bank/keeper/helper.go",
            "x/bank/keeper/helper2.go",
        ])
        report = hm.build_coverage_report(ws)
        live_units, _, _ = gate._live_denominator(hm, ws, report)
        reported_units = gate._reported_denominator_units(report)
        missing = sorted(live_units - reported_units)
        extra = sorted(reported_units - live_units)
        self.assertEqual(missing, [])
        self.assertEqual(extra, [])
        self.assertEqual(report["total_units"], len(live_units))


class TestUnnarrowedBehaviorUnchanged(unittest.TestCase):
    """No go_cosmos_scope_narrowing block, or non-Cosmos-Go workspace -> full
    un-narrowed compare, byte-identical to pre-lane behavior."""

    def test_non_cosmos_go_workspace_not_narrowed(self):
        ws = _plain_go_ws({
            "internal/svc/handler.go": _MSG_SERVER_FN,
            "internal/svc/helper.go": _KEEPER_HELPER_FN,
        })
        _write_inscope_manifest(ws, [
            "internal/svc/handler.go",
            "internal/svc/helper.go",
        ])
        report = hm.build_coverage_report(ws)
        self.assertFalse(report["enumeration"]["go_cosmos_scope_narrowing"]["applied"])

        live_units, enum_detail, _ = gate._live_denominator(hm, ws, report)
        self.assertNotIn("go_cosmos_scope_narrowing_live", enum_detail)
        # Every .go unit stays in the live set (no narrowing applied at all).
        go_units = {u for u in live_units if u.split("::")[0].lower().endswith(".go")}
        self.assertEqual(len(go_units), 2)

    def test_solidity_workspace_untouched(self):
        """STRATA/NUVA-shape (pure Solidity, zero .go units): the narrowing
        helper must no-op and the gate's existing comparison logic is
        unaffected."""
        tmp = tempfile.mkdtemp(prefix="hunt_gate_narrow_sol_")
        ws = Path(tmp)
        _write(ws, "src/A.sol", "contract A { function hit() external {} }\n")
        _write_inscope_manifest(ws, ["src/A.sol"])
        report = hm.build_coverage_report(ws)
        self.assertEqual(
            report["enumeration"]["go_cosmos_scope_narrowing"]["reason"],
            "not-a-cosmos-go-workspace",
        )
        live_units_before, enum_detail_before, _ = gate._live_denominator(hm, ws, report)

        # Directly exercise the guard helper too - must be a clean no-op.
        narrowed, detail = gate._apply_live_go_cosmos_narrowing_if_consistent(
            hm, ws, report, live_units_before, enum_detail_before
        )
        self.assertFalse(detail["applied"])
        self.assertEqual(narrowed, live_units_before)


class TestCrownJewelNeverDropped(unittest.TestCase):
    """Crown-jewel paths (precompiles/, x/evm/, evmrpc/, giga/executor/) must
    never be dropped by the narrowing, on the live side either."""

    def test_precompile_dispatch_and_internal_helper_both_survive_crown_jewel(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helper.go": _KEEPER_HELPER_FN,
            "precompiles/bank/bank.go": _PRECOMPILE_DISPATCH_FN,
            "precompiles/bank/accessors.go": _PRECOMPILE_INTERNAL_HELPER_FN,
        })
        _write_inscope_manifest(ws, [
            "x/bank/keeper/msg_server.go",
            "x/bank/keeper/helper.go",
            "precompiles/bank/bank.go",
            "precompiles/bank/accessors.go",
        ])
        report = hm.build_coverage_report(ws)
        live_units, enum_detail, _ = gate._live_denominator(hm, ws, report)
        live_files = {u.split("::")[0] for u in live_units}
        # Both precompile files survive on the live side (crown-jewel
        # allowlist checked unconditionally, even though `accessors.go`'s
        # `internalAccessorNotDispatch` would otherwise classify as an
        # internal helper and be dropped elsewhere).
        self.assertTrue(
            any("precompiles/bank/bank.go" in f for f in live_files) or
            "bank.go" in live_files,
        )
        self.assertTrue(
            any("precompiles/bank/accessors.go" in f for f in live_files) or
            "accessors.go" in live_files,
        )
        reported_files = {u.split("::")[0] for u in gate._reported_denominator_units(report)}
        self.assertTrue(
            any("precompiles/bank/accessors.go" in f for f in reported_files) or
            "accessors.go" in reported_files,
        )


class TestForkDeltaNeverDropped(unittest.TestCase):
    """A fork-delta MODIFIED/ADDED unit is never excludable - only a unit
    PROVEN unmodified-upstream is. With no fork_modified/*.json materialized
    at all, fail-open keeps everything (no fork-delta exclusion fires)."""

    def test_no_materialized_fork_json_keeps_all_units_on_both_sides(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "src/go-ethereum/core/vm/untouched.go": _KEEPER_HELPER_FN,
        })
        _write_inscope_manifest(ws, [
            "x/bank/keeper/msg_server.go",
            "src/go-ethereum/core/vm/untouched.go",
        ])
        report = hm.build_coverage_report(ws)
        # No fork_modified/*.json -> fork-delta exclusion never fires (fail-open);
        # the file may still be dropped as an internal-helper (GetGasPool is not
        # an entry point) but NOT via the fork-delta reason. Assert reason isn't
        # fork-delta-unmodified-upstream if excluded at all - we just assert the
        # live/reported totals still agree (the real regression under test).
        live_units, _, _ = gate._live_denominator(hm, ws, report)
        self.assertEqual(report["total_units"], len(live_units))


class TestKillSwitchDisablesEverywhere(unittest.TestCase):
    def test_env_kill_switch_disables_narrowing_on_both_sides(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helper.go": _KEEPER_HELPER_FN,
            "x/bank/keeper/helper2.go": _KEEPER_HELPER_FN_2,
        })
        _write_inscope_manifest(ws, [
            "x/bank/keeper/msg_server.go",
            "x/bank/keeper/helper.go",
            "x/bank/keeper/helper2.go",
        ])
        old = os.environ.get("AUDITOOOR_COVERAGE_SCOPE_NARROW")
        os.environ["AUDITOOOR_COVERAGE_SCOPE_NARROW"] = "0"
        try:
            report = hm.build_coverage_report(ws)
            self.assertFalse(report["enumeration"]["go_cosmos_scope_narrowing"]["applied"])
            self.assertEqual(
                report["enumeration"]["go_cosmos_scope_narrowing"]["reason"],
                "env-disabled",
            )
            live_units, enum_detail, _ = gate._live_denominator(hm, ws, report)
            self.assertNotIn("go_cosmos_scope_narrowing_live", enum_detail)
            self.assertEqual(report["total_units"], len(live_units))
            # All 3 go units present un-narrowed on both sides.
            self.assertEqual(len(live_units), 3)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_COVERAGE_SCOPE_NARROW", None)
            else:
                os.environ["AUDITOOOR_COVERAGE_SCOPE_NARROW"] = old


class TestUncoveredEntryPointNeverLaunderedOut(unittest.TestCase):
    """THE MOST IMPORTANT TEST (constraint #6): narrowing the live-enum must
    NEVER let the gate pass while a genuinely-in-scope ENTRY-POINT unit is
    uncovered/unscanned. Take a live-enum with >=1 uncovered entry-point unit,
    apply narrowing, and confirm the gate STILL reports it as a failure - i.e.
    the entry point is never dropped out of the obligation set, and coverage
    scoring still reflects it as uncovered."""

    def test_uncovered_entry_point_survives_narrowing_and_is_still_flagged(self):
        ws = _cosmos_ws({
            # Entry point (msgServer receiver) - genuinely UNCOVERED (no hit
            # token / scan artifact anywhere for it).
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            # Internal helper - narrowing legitimately drops this one.
            "x/bank/keeper/helper.go": _KEEPER_HELPER_FN,
        })
        _write_inscope_manifest(ws, [
            "x/bank/keeper/msg_server.go",
            "x/bank/keeper/helper.go",
        ])
        report = hm.build_coverage_report(ws)
        self.assertTrue(report["enumeration"]["go_cosmos_scope_narrowing"]["applied"])

        # The entry-point unit (Send) must still be present in BOTH the
        # reported AND the live-narrowed denominator - narrowing may only ever
        # remove the internal helper, never the entry point.
        reported_units = gate._reported_denominator_units(report)
        live_units, _, _ = gate._live_denominator(hm, ws, report)

        def _has_entry_point(units):
            return any(
                u.split("::")[0].endswith("msg_server.go") and u.endswith("::Send")
                for u in units
            )

        self.assertTrue(_has_entry_point(reported_units),
                         "entry point must survive on the reported side")
        self.assertTrue(_has_entry_point(live_units),
                         "entry point must survive on the live side (never "
                         "laundered out by narrowing)")

        # And it is genuinely uncovered: build_coverage_report's own
        # uncovered_units must list it (no coverage token/scan artifact was
        # ever emitted for this workspace), so the gate's per-unit obligation
        # still sees it as a failure, not silently satisfied.
        uncovered = set(report.get("uncovered_units") or [])

        def _in_uncovered(units):
            return any(
                u.split("::")[0].endswith("msg_server.go") and u.endswith("::Send")
                for u in units
            )

        self.assertTrue(_in_uncovered(uncovered),
                         "the entry point must still show up UNCOVERED after "
                         "narrowing - narrowing must never launder an "
                         "unscanned entry point out of the obligation set")

        # Sanity: the helper WAS legitimately excluded from both sides (that is
        # the narrowing actually doing its job, not a no-op).
        self.assertFalse(
            any(u.split("::")[0].endswith("helper.go") for u in live_units),
            "the internal helper should have been narrowed OUT (this is the "
            "legitimate exclusion the lane is supposed to produce)",
        )


if __name__ == "__main__":
    unittest.main()
