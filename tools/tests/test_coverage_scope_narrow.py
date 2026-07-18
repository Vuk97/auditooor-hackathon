#!/usr/bin/env python3
"""Never-false-pass tests for the Go/Cosmos coverage_report scope narrowing
(Lane CAP-HUNT-COVERAGE-SCOPE-NARROW).

`tools/workspace-coverage-heatmap.py --coverage-report` writes the coverage
denominator consumed by `tools/hunt-coverage-gate.py`. On a Cosmos/Go-L1 it
must apply the SAME Go entry-point + fork-delta-unmodified-upstream + SCOPE.md
documented-carve-out narrowing that `tools/function-coverage-completeness.py`
already applies via `tools/go_entrypoint_surface.py` - otherwise the two gates
disagree on the same workspace's true attack surface.

This is a GATE-INPUT file: over-exclusion is a false-green (the #1 sin), so
every test here pins a NEVER-FALSE-PASS guarantee, not just "narrowing works".
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "hm_scope_narrow", ROOT / "tools" / "workspace-coverage-heatmap.py"
)
hm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hm)  # type: ignore[union-attr]


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
_XEVM_HELPER_FN = (
    "package evm\n\n"
    "func (k Keeper) internalHelperNotAnEntryPoint() error {\n\treturn nil\n}\n"
)
_GIGA_EXECUTOR_HELPER_FN = (
    "package executor\n\n"
    "func (e Executor) internalSchedulerHelper() error {\n\treturn nil\n}\n"
)
_LOADTEST_FN = (
    "package loadtest\n\n"
    "func RunLoadTest() error {\n\treturn nil\n}\n"
)


def _write(ws: Path, rel: str, content: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _kept_real_paths(ws: Path, kept: list[str]) -> set[str]:
    """Resolve each kept unit's file_key to its REAL ws-relative path (unit
    keys collapse to a bare basename when unique workspace-wide, so a
    directory-segment assertion must check the real path, not the raw key)."""
    go_units = [u for u in kept if u.rpartition("::")[0].lower().endswith(".go")]
    real_by_key = hm._resolve_go_unit_file_paths(ws, go_units)
    out = set()
    for u in kept:
        fk = u.rpartition("::")[0]
        out.add(real_by_key.get(fk, fk))
    return out


def _cosmos_ws(extra_files: dict[str, str], with_layout: bool = False) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="cov_scope_narrow_"))
    _write(ws, "go.mod", _COSMOS_GOMOD)
    if with_layout:
        _write(ws, "x/bank/keeper/keeper.go", "package keeper\n")
        _write(ws, "app/app.go", "package app\n")
    for rel, content in extra_files.items():
        _write(ws, rel, content)
    return ws


def _noncosmos_ws(extra_files: dict[str, str]) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="cov_scope_narrow_noncosmos_"))
    _write(ws, "go.mod", _NONCOSMOS_GOMOD)
    for rel, content in extra_files.items():
        _write(ws, rel, content)
    return ws


class TestGuardedFailOpen(unittest.TestCase):
    def test_non_cosmos_go_workspace_is_a_no_op(self):
        ws = _noncosmos_ws({
            "internal/svc.go": _KEEPER_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        self.assertFalse(detail["applied"])
        self.assertEqual(detail["reason"], "not-a-cosmos-go-workspace")
        self.assertEqual(sorted(kept), sorted(units))

    def test_env_kill_switch_disables_narrowing(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helpers.go": _KEEPER_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        old = os.environ.get("AUDITOOOR_COVERAGE_SCOPE_NARROW")
        os.environ["AUDITOOOR_COVERAGE_SCOPE_NARROW"] = "0"
        try:
            kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_COVERAGE_SCOPE_NARROW", None)
            else:
                os.environ["AUDITOOOR_COVERAGE_SCOPE_NARROW"] = old
        self.assertFalse(detail["applied"])
        self.assertEqual(detail["reason"], "env-disabled")
        self.assertEqual(sorted(kept), sorted(units))

    def test_empty_exclusion_set_is_a_no_op(self):
        # Every fn here IS a true entry point (msgServer receiver) -> nothing
        # to exclude -> narrowing must fail-open (not narrow-to-same-set as a
        # false "applied").
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        self.assertFalse(detail["applied"])
        self.assertEqual(detail["reason"], "empty-exclusion-set")
        self.assertEqual(sorted(kept), sorted(units))


class TestMixedInScopeAndOOS(unittest.TestCase):
    def test_only_internal_helper_is_excluded_entry_point_survives(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helpers.go": _KEEPER_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        self.assertTrue(detail["applied"])
        kept_names = {u.rpartition("::")[2] for u in kept}
        self.assertIn("Send", kept_names)  # true entry point kept
        self.assertNotIn("GetGasPool", kept_names)  # internal helper excluded
        # never-false-pass: the excluded unit really was in the input set.
        in_names = {u.rpartition("::")[2] for u in units}
        self.assertIn("GetGasPool", in_names)

    def test_documented_scope_md_oos_path_excluded_sibling_survives(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "contracts/src/MockToken.go": _KEEPER_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        self.assertTrue(detail["applied"])
        kept_files = {u.rpartition("::")[0] for u in kept}
        self.assertFalse(any("contracts/src/" in f for f in kept_files))
        self.assertTrue(any(f.endswith("msg_server.go") for f in kept_files))

    def test_loadtest_path_excluded(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "loadtest/runner.go": _LOADTEST_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        self.assertTrue(detail["applied"])
        kept_files = {u.rpartition("::")[0] for u in kept}
        self.assertFalse(any("/loadtest/" in ("/" + f) for f in kept_files))


class TestCrownJewelHardAllowlist(unittest.TestCase):
    def test_precompiles_never_excluded_even_if_internal_shaped(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            # A precompiles/ file whose only fn is a Keeper-receiver internal
            # helper is entry surface via the boundary-package family (family
            # 7: anything under precompiles/ is surface, receiver-agnostic).
            "precompiles/bank/helpers.go": _KEEPER_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_files = _kept_real_paths(ws, kept)
        self.assertTrue(any("precompiles/" in f for f in kept_files))

    def test_crown_jewel_allowlist_overrides_documented_oos_path_match(self):
        # A crown-jewel path that ALSO happens to sit under a documented-OOS
        # segment (loadtest/) must still be kept - the allowlist unconditionally
        # overrides any other exclusion reason (constraint 2).
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "loadtest/precompiles/bench/helper.go": _KEEPER_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_files = _kept_real_paths(ws, kept)
        self.assertTrue(any("loadtest/precompiles/" in f for f in kept_files))
        self.assertGreaterEqual(detail.get("crown_jewel_protected", 0), 1)

    def test_x_evm_never_excluded(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/evm/keeper/internal.go": _XEVM_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_files = _kept_real_paths(ws, kept)
        self.assertTrue(any("x/evm/" in f for f in kept_files))

    def test_evmrpc_never_excluded(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "evmrpc/internal.go": _XEVM_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_files = _kept_real_paths(ws, kept)
        self.assertTrue(any("evmrpc/" in f for f in kept_files))

    def test_giga_executor_never_excluded(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "giga/executor/internal.go": _GIGA_EXECUTOR_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_files = _kept_real_paths(ws, kept)
        self.assertTrue(any("giga/executor/" in f for f in kept_files))


class TestForkDeltaNeverExcludesModifiedOrAdded(unittest.TestCase):
    def _fork_ws(self) -> Path:
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            # precompiles/ dispatch surface (true entry point) in the MODIFIED
            # fork file - proves a modified file's entry fn is never dropped by
            # the fork-delta lever even though it also happens to classify as
            # true surface independently.
            "src/go-ethereum/core/vm/evm.go": _PRECOMPILE_DISPATCH_FN,  # modified
            "src/go-ethereum/core/vm/untouched.go": _KEEPER_HELPER_FN_2,  # unmodified, non-entry
        })
        fm_dir = ws / ".auditooor" / "fork_modified"
        fm_dir.mkdir(parents=True, exist_ok=True)
        (fm_dir / "go-ethereum.json").write_text(json.dumps({
            "schema": "auditooor.fork_modified.v1",
            "local_name": "go-ethereum",
            "modified_count": 1,
            "added_count": 0,
            "sei_modified_files": ["core/vm/evm.go"],
            "sei_added_files": [],
        }), encoding="utf-8")
        return ws

    def test_unmodified_upstream_excluded_modified_kept(self):
        ws = self._fork_ws()
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_files = _kept_real_paths(ws, kept)
        self.assertTrue(any(f.endswith("core/vm/evm.go") for f in kept_files))
        self.assertFalse(any(f.endswith("core/vm/untouched.go") for f in kept_files))
        self.assertIn("fork-delta-unmodified-upstream", detail["excluded_by_reason"])

    def test_unresolved_fork_json_keeps_all_fork_units(self):
        # No fork_modified/*.json materialized at all -> keep-all for any
        # src/<name>/ prefixed unit (fail-open).
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "src/go-ethereum/core/vm/untouched.go": _KEEPER_HELPER_FN,
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_files = _kept_real_paths(ws, kept)
        self.assertTrue(any(f.endswith("core/vm/untouched.go") for f in kept_files))


class TestNonGoUnitsUntouched(unittest.TestCase):
    def test_solidity_units_pass_through_unchanged(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helpers.go": _KEEPER_HELPER_FN,
            "contracts/Token.sol": (
                "// SPDX\npragma solidity ^0.8;\n"
                "contract Token { function transfer() public {} }\n"
            ),
        })
        units, _ = hm.enumerate_units(ws)
        kept, detail = hm.apply_go_cosmos_coverage_scope_narrowing(ws, units)
        kept_names = {u.rpartition("::")[2] for u in kept}
        self.assertIn("transfer", kept_names)


class TestBuildCoverageReportIntegration(unittest.TestCase):
    def test_strata_like_non_cosmos_solidity_ws_byte_identical(self):
        """STRATA (non-Cosmos Solidity) must be unaffected: build_coverage_report
        with narrowing enabled vs explicitly disabled must produce an identical
        denominator_units set."""
        ws = Path(tempfile.mkdtemp(prefix="cov_scope_narrow_strata_like_"))
        _write(ws, "contracts/Vault.sol",
               "// SPDX\npragma solidity ^0.8;\n"
               "contract Vault { function deposit() public {} }\n")
        report_on = hm.build_coverage_report(ws)
        old = os.environ.get("AUDITOOOR_COVERAGE_SCOPE_NARROW")
        os.environ["AUDITOOOR_COVERAGE_SCOPE_NARROW"] = "0"
        try:
            report_off = hm.build_coverage_report(ws)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_COVERAGE_SCOPE_NARROW", None)
            else:
                os.environ["AUDITOOOR_COVERAGE_SCOPE_NARROW"] = old
        self.assertEqual(
            sorted(report_on["denominator_units"]),
            sorted(report_off["denominator_units"]),
        )
        self.assertEqual(report_on["total_units"], report_off["total_units"])

    def test_coverage_report_carries_narrowing_detail(self):
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helpers.go": _KEEPER_HELPER_FN,
        })
        report = hm.build_coverage_report(ws)
        narrow_detail = report["enumeration"].get("go_cosmos_scope_narrowing")
        self.assertIsNotNone(narrow_detail)
        self.assertTrue(narrow_detail["applied"])
        self.assertGreaterEqual(narrow_detail["excluded_total"], 1)
        names = {u.rpartition("::")[2] for u in report["denominator_units"]}
        self.assertIn("Send", names)
        self.assertNotIn("GetGasPool", names)

    def test_source_freshness_recompute_matches_report_narrowing(self):
        """COVERAGE-MAP L37 REGRESSION (narrowing-consistency): the coverage-map
        signal recomputes the denominator fingerprint via build_source_freshness(ws)
        with units=None, while the stored report is built by build_coverage_report
        (which narrows units first). Before the fix build_source_freshness did NOT
        apply the Go/Cosmos entry-point narrowing, so on a narrowed Cosmos-Go-L1 the
        stored (narrowed) vs recomputed (every-exported) source_units_count could
        never match -> coverage-map FAILed forever. They must now agree."""
        ws = _cosmos_ws({
            "x/bank/keeper/msg_server.go": _MSG_SERVER_FN,
            "x/bank/keeper/helpers.go": _KEEPER_HELPER_FN,
            "x/bank/keeper/helpers2.go": _KEEPER_HELPER_FN_2,
        })
        report = hm.build_coverage_report(ws)
        stored = report["source_freshness"]
        recomputed = hm.build_source_freshness(ws)  # units=None -> L37 signal path
        self.assertEqual(
            stored["source_units_count"], recomputed["source_units_count"],
            "stored report denominator must equal the L37 recompute (both narrowed)",
        )
        self.assertEqual(
            stored["source_units_sha256"], recomputed["source_units_sha256"])
        self.assertEqual(
            stored["denominator_sha256"], recomputed["denominator_sha256"])
        # sanity: narrowing genuinely dropped the non-entry keeper helpers
        self.assertLessEqual(recomputed["source_units_count"], 2)


if __name__ == "__main__":
    unittest.main()
