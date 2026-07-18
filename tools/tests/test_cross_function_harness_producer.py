#!/usr/bin/env python3
"""Tests for tools/cross-function-harness-producer.py.

Covers:
  - per-function aggregation from genuine_coverage_manifest.json -> canonical
    per_function records with BOTH contract + legacy fields.
  - the canonical file is written in the SHARED-CONTRACT schema AND is parseable
    by BOTH consumer gates (cross-function-invariant-coverage +
    function-coverage-completeness _records_from_payload).
  - cross-function harness discovery + the dispatch-brief emission when no
    cross-function harness exists.
  - offline-safe behavior (no toolchain => recorded skip, never silent PASS).
  - error verdict on a non-existent workspace.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(filename: str, modname: str):
    spec = importlib.util.spec_from_file_location(modname, str(_TOOLS / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


PROD = _load("cross-function-harness-producer.py", "_t_xfhp")
XFI = _load("cross-function-invariant-coverage.py", "_t_xfi_consumer")
FCC = _load("function-coverage-completeness.py", "_t_fcc_consumer")


def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TestPerFunctionAggregation(unittest.TestCase):
    def test_aggregate_carries_contract_and_legacy_fields(self):
        manifest = {
            "verdicts": [
                {"function": "deposit", "source": "src/Vault.sol:5",
                 "harness_contract": "Halmos_Vault_deposit", "verdict": "non-vacuous"},
                {"function": "withdraw", "source": "src/Vault.sol:9",
                 "harness_contract": "Halmos_Vault_withdraw", "verdict": "vacuous"},
            ]
        }
        rows = PROD._aggregate_per_function(manifest)
        self.assertEqual(len(rows), 2)
        d = {r["function"]: r for r in rows}
        # contract fields
        self.assertTrue(d["deposit"]["mutation_verified"])
        self.assertFalse(d["withdraw"]["mutation_verified"])
        self.assertIn("file_line", d["deposit"])
        self.assertIn("clean_result", d["deposit"])
        # legacy fields the consumers parse: verdict is mapped to the consumer's
        # canonical token set (killed/vacuous) to avoid the "non-vacuous"-
        # contains-"vacuous" normalizer trap; the raw genuine verdict is kept.
        self.assertEqual(d["deposit"]["verdict"], "killed")
        self.assertEqual(d["deposit"]["genuine_verdict"], "non-vacuous")
        self.assertEqual(d["withdraw"]["verdict"], "vacuous")
        self.assertEqual(d["withdraw"]["genuine_verdict"], "vacuous")
        self.assertEqual(d["deposit"]["harness"], "Halmos_Vault_deposit")
        self.assertTrue(d["deposit"]["killed"])
        self.assertFalse(d["withdraw"]["killed"])

    def test_no_manifest_returns_empty(self):
        self.assertEqual(PROD._aggregate_per_function(None), [])
        self.assertEqual(PROD._aggregate_per_function({}), [])

    def test_mvc_sidecar_kills_credited(self):
        """The durable mvc_sidecar/ mutation-kills (genuine baseline-pass + killed
        mutant) must be aggregated as mutation_verified per-function records; they
        were orphaned (near-intents 2026-06-26: 14 real kills, 0 credit)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            scd = ws / ".auditooor" / "mvc_sidecar"
            scd.mkdir(parents=True)
            # genuine kill (verdict + baseline pass + killed)
            (scd / "ts_verify_mutation_killed.json").write_text(json.dumps({
                "verdict": "killed", "function": "verify",
                "source_file": "src/x/signature.rs", "file_line": "src/x/signature.rs:36",
                "killed": True, "mutant_count": 1, "baseline": {"status": "pass"}}))
            # non-vacuous with killed_count (omnibridge form)
            (scd / "mvc-omnibridge-fintransfer.json").write_text(json.dumps({
                "verdict": "non-vacuous", "function": "finTransfer",
                "source_file": "src/y/OmniBridge.sol", "killed_count": 6,
                "baseline": {"status": "pass"}}))
            # vacuous (must NOT credit)
            (scd / "vac.json").write_text(json.dumps({
                "verdict": "vacuous", "function": "f", "source_file": "src/z.rs",
                "killed": False, "baseline": {"status": "pass"}}))
            # no-baseline (must NOT credit)
            (scd / "nb.json").write_text(json.dumps({
                "verdict": "killed", "function": "g", "source_file": "src/w.rs",
                "killed": True, "baseline": {"status": "fail"}}))
            recs = PROD._aggregate_mvc_sidecars(ws)
            fns = {r["function"] for r in recs}
            self.assertEqual(fns, {"verify", "finTransfer"})
            self.assertTrue(all(r["mutation_verified"] for r in recs))


class TestCanonicalFileShape(unittest.TestCase):
    def test_canonical_file_consumed_by_both_gates(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # a genuine manifest with a verified + a vacuous per-function row
            _write(
                ws / ".auditooor" / "genuine_coverage_manifest.json",
                json.dumps({
                    "status": "ok",
                    "verdicts": [
                        {"function": "deposit", "source": "src/Vault.sol:5",
                         "harness_contract": "Halmos_Vault_deposit", "verdict": "non-vacuous"},
                    ],
                }),
            )
            payload = PROD.produce(ws, emit_brief_only=True)
            out = PROD._write_canonical(ws, payload)
            self.assertTrue(out.is_file())

            disk = json.loads(out.read_text(encoding="utf-8"))
            # SHARED-CONTRACT top-level keys
            self.assertEqual(disk["schema"], "auditooor.mutation_verify_coverage.v1")
            self.assertIn("per_function", disk)
            self.assertIn("cross_function", disk)
            self.assertIn("generated_at", disk)
            self.assertIn("run_id", disk)

            # BOTH consumers' _records_from_payload must find the flattened list.
            xfi_records = XFI._records_from_payload(disk)
            fcc_records = FCC._records_from_payload(disk)
            self.assertTrue(any(r.get("function") == "deposit" for r in xfi_records))
            self.assertTrue(any(r.get("function") == "deposit" for r in fcc_records))

            # FCC must classify the deposit record as a kill (mutation-verified).
            dep = next(r for r in fcc_records if r.get("function") == "deposit")
            self.assertEqual(FCC._record_verdict(dep), "killed")

    def test_emit_brief_only_writes_dispatch_brief(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "Vault.sol",
                   "pragma solidity ^0.8.0; contract V { function deposit() external {} "
                   "function withdraw() external {} }")
            payload = PROD.produce(ws, emit_brief_only=True)
            self.assertEqual(payload["cross_function_status"], "brief-only")
            brief = payload.get("cross_function_dispatch_brief")
            self.assertIsNotNone(brief)
            self.assertTrue(Path(brief).is_file())
            bd = json.loads(Path(brief).read_text(encoding="utf-8"))
            self.assertEqual(bd["schema"], "auditooor.cross_function_harness_dispatch_brief.v1")


class TestOfflineSafe(unittest.TestCase):
    def test_no_cross_function_harness_emits_brief_not_pass(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "Vault.sol",
                   "pragma solidity ^0.8.0; contract V { function deposit() external {} }")
            payload = PROD.produce(ws)
            # No cross-function harness file -> brief emitted, zero verified
            # (REACHABLE when the real harness lands; never vacuously green).
            self.assertEqual(payload["cross_function_status"], "no-harnesses-brief-emitted")
            self.assertEqual(payload["counts"]["cross_function_verified"], 0)
            self.assertIsNotNone(payload.get("cross_function_dispatch_brief"))

    def test_existing_non_vacuous_sidecar_is_imported(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "lib.rs", "pub fn first() {}\npub fn second() {}\n")
            _write(
                ws / ".auditooor" / "cross-function-coverage" / "mutation_first.json",
                json.dumps({
                    "schema": "auditooor.mutation_verify_coverage.v1",
                    "source_file": str(ws / "src" / "lib.rs"),
                    "function": "first",
                    "function_span": {"start_line": 1, "end_line": 1},
                    "harness": "cargo test first_second_invariant",
                    "baseline": {"status": "pass"},
                    "mutant_count": 1,
                    "killed_count": 1,
                    "verdict": "non-vacuous",
                    "reason": "harness FAILED on 1/1 mutants",
                }),
            )
            _write(
                ws / ".auditooor" / "cross-function-coverage" / "mutation_second.json",
                json.dumps({
                    "source_file": str(ws / "src" / "lib.rs"),
                    "function": "second",
                    "function_span": {"start_line": 2, "end_line": 2},
                    "harness": "cargo test first_second_invariant",
                    "baseline": {"status": "pass"},
                    "mutant_count": 1,
                    "killed_count": 0,
                    "verdict": "vacuous",
                }),
            )
            payload = PROD.produce(ws, language="rust")
            self.assertEqual(payload["cross_function_status"], "sidecar-evidence-imported")
            self.assertEqual(payload["counts"]["cross_function_total"], 1)
            self.assertEqual(payload["counts"]["cross_function_verified"], 1)
            rec = payload["cross_function"][0]
            self.assertEqual(rec["function"], "first")
            self.assertEqual(rec["verdict"], "killed")
            self.assertTrue(rec["mutation_verified"])
            self.assertIn("sidecar", rec)

    def test_generated_per_function_invariants_do_not_count_as_harnesses(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "lib.rs", "pub fn deposit() {}\npub fn withdraw() {}\n")
            _write(
                ws / ".auditooor" / "per_function_invariants" / "RustInv_test_roundtrip.rs",
                "#[test]\nfn test_roundtrip() { assert!(true); }\n",
            )
            payload = PROD.produce(ws, language="rust")
            self.assertEqual(payload["cross_function_status"], "no-harnesses-brief-emitted")
            self.assertEqual(payload["counts"]["cross_function_total"], 0)
            self.assertIsNotNone(payload.get("cross_function_dispatch_brief"))

    def test_rust_run_ignores_solidity_placeholder_harness(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "lib.rs", "pub fn deposit() {}\npub fn withdraw() {}\n")
            _write(
                ws / "economic_fuzz" / "EconomicInvariantFuzz.t.sol",
                "contract EconomicInvariantFuzz { function invariant_econ() public { assert(true); } }\n",
            )
            payload = PROD.produce(ws, language="rust")
            self.assertEqual(payload["cross_function_status"], "no-harnesses-brief-emitted")
            self.assertEqual(payload["counts"]["cross_function_total"], 0)

    def test_toolchain_absent_records_skip(self):
        # When a cross-function harness exists but the toolchain is absent, the
        # record is a skip (mutation_verified False), not a silent pass.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "Vault.sol",
                   "pragma solidity ^0.8.0; contract V { function deposit() external { uint x = 1; } }")
            _write(ws / "test" / "Vault_roundtrip_invariant.t.sol",
                   "contract T { function test_roundtrip() public {} }")
            # Force the solidity toolchain to look absent.
            orig = PROD._toolchain_present_for
            PROD._toolchain_present_for = lambda lang: False
            try:
                payload = PROD.produce(ws)
            finally:
                PROD._toolchain_present_for = orig
            self.assertTrue(payload["cross_function"])
            rec = payload["cross_function"][0]
            self.assertFalse(rec["mutation_verified"])
            self.assertEqual(rec["verdict"], "skipped")


# r36-rebuttal: bugfix-inventory-claude-20260610
class TestMutationTargetSourceFor(unittest.TestCase):
    """_mutation_target_source_for must not select certora/lib/mock files as
    any_concrete fallback - same exclusion as _harness_driven_target."""

    def test_certora_helper_not_selected_as_any_concrete(self):
        """When the only .sol file in src/ is under src/certora/, the legacy
        resolver must return None (not select the certora helper).  Before the
        fix, the file passes the _is_test_path + _SKIP_DIRS filter and lands as
        any_concrete, producing a false-green mutation target."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Only non-test .sol is a certora helper.
            certora_file = ws / "src" / "certora" / "helpers" / "MorphoHarness.sol"
            certora_file.parent.mkdir(parents=True)
            certora_file.write_text(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "contract MorphoHarness { function transfer(address to, uint256 amt) external {} }\n",
                encoding="utf-8",
            )
            # Harness body has only cheatcode/assertion calls - no instance.fn() pattern.
            harness = ws / "test" / "MorphoRoundtrip.t.sol"
            harness.parent.mkdir(parents=True)
            harness.write_text(
                "contract MorphoRoundtrip {\n"
                "  function test_roundtrip() public {\n"
                "    vm.prank(address(1));\n"
                "    vm.deal(address(1), 1 ether);\n"
                "    assertEq(x, y);\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            result = PROD._mutation_target_source_for(harness, ws)
            # Must NOT select the certora helper; must return None.
            self.assertIsNone(
                result,
                f"Expected None but got {result} - certora file selected as fallback",
            )

    def test_certora_excluded_but_real_contract_selected(self):
        """When both a certora helper and a real production contract exist in
        src/, the resolver must pick the production contract and never the
        certora file."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            certora_file = ws / "src" / "certora" / "helpers" / "MorphoHarness.sol"
            certora_file.parent.mkdir(parents=True)
            certora_file.write_text(
                "pragma solidity ^0.8.0; contract MorphoHarness { function foo() external {} }\n",
                encoding="utf-8",
            )
            real_contract = ws / "src" / "Morpho.sol"
            real_contract.write_text(
                "pragma solidity ^0.8.0; contract Morpho { function supply() external {} }\n",
                encoding="utf-8",
            )
            harness = ws / "test" / "MorphoRoundtrip.t.sol"
            harness.parent.mkdir(parents=True)
            harness.write_text(
                "contract T { function invariant_x() public { vm.prank(address(1)); } }\n",
                encoding="utf-8",
            )
            result = PROD._mutation_target_source_for(harness, ws)
            self.assertIsNotNone(result, "Expected a production contract to be selected")
            self.assertNotIn("/certora/", str(result).replace("\\", "/"),
                             f"Certora file selected instead of real contract: {result}")
            self.assertEqual(result, real_contract)

    def test_mock_and_lib_not_selected_as_fallback(self):
        """Files under /mock and /lib/ directories must also be excluded from the
        any_concrete fallback - mirrors _harness_driven_target exclusions."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            mock_file = ws / "src" / "mocks" / "MockToken.sol"
            mock_file.parent.mkdir(parents=True)
            mock_file.write_text(
                "pragma solidity ^0.8.0; contract MockToken { function transfer() external {} }\n",
                encoding="utf-8",
            )
            harness = ws / "test" / "Token_roundtrip.t.sol"
            harness.parent.mkdir(parents=True)
            harness.write_text(
                "contract T { function invariant_x() public { vm.prank(address(1)); } }\n",
                encoding="utf-8",
            )
            result = PROD._mutation_target_source_for(harness, ws)
            # /mocks/ matches /mock prefix filter - must be excluded.
            self.assertIsNone(
                result,
                f"Expected None but mock file was selected as fallback: {result}",
            )


class TestErrors(unittest.TestCase):
    def test_missing_workspace_error(self):
        payload = PROD.produce("/nonexistent/ws/xyzzy")
        self.assertEqual(payload.get("verdict"), "error")


class TestCliCompatibility(unittest.TestCase):
    def test_makefile_wrapper_flags_write_requested_output(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            out = Path(td) / "coverage.json"
            rc = PROD.main([
                "--workspace", str(ws),
                "--lang", "rust",
                "--out", str(out),
                "--project-root", str(ws),
                "--strict",
                "--json",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(out.is_file())
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.mutation_verify_coverage.v1")
            self.assertEqual(payload["language"], "rust")
            self.assertEqual(payload["counts"]["cross_function_verified"], 0)


if __name__ == "__main__":
    unittest.main()
