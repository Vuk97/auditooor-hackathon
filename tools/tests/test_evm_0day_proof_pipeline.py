#!/usr/bin/env python3
"""Tests for tools/evm-0day-proof-pipeline.py."""

import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "evm_0day_proof_pipeline", TOOLS / "evm-0day-proof-pipeline.py"
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class TestVulnClassNormalization(unittest.TestCase):
    def test_aliases_map_to_canonical(self):
        self.assertEqual(mod.normalize_vuln_class("reent"), "reentrancy")
        self.assertEqual(mod.normalize_vuln_class("read-only-reentrancy"), "reentrancy")
        self.assertEqual(mod.normalize_vuln_class("unprotected-initialize"), "access-control")
        self.assertEqual(mod.normalize_vuln_class("stale-oracle"), "oracle-manipulation")
        self.assertEqual(mod.normalize_vuln_class("first-depositor"), "share-inflation")
        self.assertEqual(mod.normalize_vuln_class("nonce-reuse"), "signature-replay")

    def test_underscore_and_case(self):
        self.assertEqual(mod.normalize_vuln_class("Access_Control_Bypass"), "access-control")

    def test_unknown_falls_through(self):
        self.assertEqual(mod.normalize_vuln_class("brand-new-class"), "brand-new-class")

    def test_empty_is_generic(self):
        self.assertEqual(mod.normalize_vuln_class(""), "generic")


class TestParseFileLine(unittest.TestCase):
    def test_with_line(self):
        self.assertEqual(mod.parse_file_line("src/Foo.sol:142"), ("src/Foo.sol", 142))

    def test_without_line(self):
        self.assertEqual(mod.parse_file_line("src/Foo.sol"), ("src/Foo.sol", None))

    def test_empty(self):
        self.assertEqual(mod.parse_file_line(""), ("", None))


class TestTemplateSelection(unittest.TestCase):
    def test_known_class_has_template(self):
        for cls in ["reentrancy", "access-control", "oracle-manipulation",
                    "arithmetic-overflow", "unchecked-call", "share-inflation",
                    "signature-replay"]:
            tpl = mod.get_template(cls)
            self.assertIn("exploit_body", tpl)
            self.assertIn("control_body", tpl)

    def test_unknown_uses_generic(self):
        self.assertIs(mod.get_template("zzz-unknown"), mod.GENERIC_TEMPLATE)


class TestScaffoldV3Shape(unittest.TestCase):
    def _scaffold(self, vuln_class, in_tree=True):
        cand = {
            "contract": "VaultManager", "fn": "withdraw",
            "vuln_class": vuln_class, "file_line": "src/VaultManager.sol:142",
            "rel_path": "src/VaultManager.sol",
        }
        return mod.build_scaffold(cand, in_tree=in_tree)

    def test_has_real_entrypoint_and_target(self):
        s = self._scaffold("reentrancy")
        self.assertIn("VaultManager target;", s)
        self.assertIn("test_exploit_withdraw", s)

    def test_has_negative_control(self):
        s = self._scaffold("reentrancy")
        self.assertIn("test_negative_control_withdraw", s)
        self.assertIn("NEGATIVE CONTROL", s)

    def test_has_before_after_assertions(self):
        s = self._scaffold("reentrancy")
        self.assertIn("Before", s)
        self.assertIn("After", s)
        self.assertIn("assert", s.lower())

    def test_v3_grade_banner_present(self):
        s = self._scaffold("oracle-manipulation")
        self.assertIn("V3-GRADE", s)
        self.assertIn("Rule 40", s)

    def test_out_of_tree_warning(self):
        s = self._scaffold("access-control", in_tree=False)
        self.assertIn("NOT resolved in workspace tree", s)

    def test_fn_substituted_in_body(self):
        s = self._scaffold("access-control")
        self.assertIn("target.withdraw(", s)


class TestResolveInTree(unittest.TestCase):
    def test_resolves_by_rel_path(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}")
            self.assertTrue(mod.resolve_in_tree(ws, "src/Vault.sol", "Vault"))

    def test_resolves_by_contract_definition(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.sol").write_text("// header\ncontract MyVault {\n}\n")
            self.assertTrue(mod.resolve_in_tree(ws, "elsewhere/MyVault.sol", "MyVault"))

    def test_not_in_tree(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "x.sol").write_text("contract Other {}")
            self.assertFalse(mod.resolve_in_tree(ws, "lib/Dep.sol", "ExternalDep"))

    def test_none_workspace(self):
        self.assertFalse(mod.resolve_in_tree(None, "src/Foo.sol", "Foo"))


class TestParseForgeOutput(unittest.TestCase):
    def test_both_pass(self):
        out = "[PASS] test_exploit_withdraw() (gas: 1)\n[PASS] test_negative_control_withdraw() (gas: 2)"
        r = mod.parse_forge_output(out)
        self.assertTrue(r["exploit_pass"])
        self.assertTrue(r["control_pass"])

    def test_exploit_fail(self):
        out = "[FAIL: assertion] test_exploit_withdraw() (gas: 1)\n[PASS] test_negative_control_withdraw()"
        r = mod.parse_forge_output(out)
        self.assertFalse(r["exploit_pass"])
        self.assertTrue(r["exploit_fail"])

    def test_compile_fail(self):
        out = "Compiler run failed:\nError (1234): something"
        r = mod.parse_forge_output(out)
        self.assertTrue(r["compile_fail"])


class TestAdjudicate(unittest.TestCase):
    def test_out_of_tree(self):
        v, _ = mod.adjudicate(in_tree=False, run=None)
        self.assertEqual(v, "claim-narrowed-out-of-tree")

    def test_no_run(self):
        v, _ = mod.adjudicate(in_tree=True, run=None)
        self.assertEqual(v, "scaffold-only-not-run")

    def test_proof_backed(self):
        run = {"ran": True, "exploit_pass": True, "control_pass": True}
        v, _ = mod.adjudicate(in_tree=True, run=run)
        self.assertEqual(v, "proof-backed")

    def test_refuted(self):
        run = {"ran": True, "exploit_pass": False, "control_pass": True}
        v, _ = mod.adjudicate(in_tree=True, run=run)
        self.assertEqual(v, "refuted")

    def test_exploit_pass_control_fail_not_proof(self):
        run = {"ran": True, "exploit_pass": True, "control_pass": False}
        v, _ = mod.adjudicate(in_tree=True, run=run)
        self.assertEqual(v, "scaffold-only-not-run")

    def test_compile_fail(self):
        run = {"ran": True, "compile_fail": True, "exploit_pass": False, "control_pass": False}
        v, _ = mod.adjudicate(in_tree=True, run=run)
        self.assertEqual(v, "compile-blocked-with-obligation")

    def test_timeout(self):
        run = {"ran": True, "timeout": True, "exploit_pass": False, "control_pass": False}
        v, _ = mod.adjudicate(in_tree=True, run=run)
        self.assertEqual(v, "scaffold-only-not-run")


class TestRunPipelineEndToEnd(unittest.TestCase):
    def test_in_tree_no_run_emits_scaffold(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault { function withdraw() public {} }")
            out = ws / "poc"
            cand = {"contract": "Vault", "fn": "withdraw",
                    "vuln_class": "reentrancy", "file_line": "src/Vault.sol:10",
                    "rel_path": "src/Vault.sol", "line": 10}
            res = mod.run_pipeline(cand, ws, out, do_run=False)
            self.assertTrue(res["in_tree"])
            self.assertEqual(res["verdict"], "scaffold-only-not-run")
            self.assertTrue(Path(res["scaffold_path"]).exists())
            self.assertIn("test_exploit_withdraw", Path(res["scaffold_path"]).read_text())

    def test_out_of_tree_narrows(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "other.sol").write_text("contract Other {}")
            cand = {"contract": "ExternalDep", "fn": "claim",
                    "vuln_class": "access-control", "file_line": "lib/Dep.sol:5",
                    "rel_path": "lib/Dep.sol", "line": 5}
            res = mod.run_pipeline(cand, ws, None, do_run=True)
            self.assertFalse(res["in_tree"])
            self.assertEqual(res["verdict"], "claim-narrowed-out-of-tree")


class TestLoadCandidate(unittest.TestCase):
    def test_from_json_blob(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps({
                "contract": "Foo", "function": "bar",
                "attack_class": "reent", "file_lines": "src/Foo.sol:1"}))
            ns = type("NS", (), {
                "candidate_json": str(p), "contract": None, "fn": None,
                "vuln_class": None, "file_line": ""})()
            cand = mod.load_candidate(ns)
            self.assertEqual(cand["contract"], "Foo")
            self.assertEqual(cand["fn"], "bar")
            self.assertEqual(cand["vuln_class"], "reentrancy")

    def test_source_ref_parser_strips_engage_report_prefix(self):
        self.assertEqual(
            mod._first_source_file_line("engage_report.json:src/Vault.sol:12"),
            "src/Vault.sol:12",
        )

    def test_source_ref_parser_accepts_hash_line(self):
        self.assertEqual(
            mod._first_source_file_line("src/Vault.sol#L12"),
            "src/Vault.sol:12",
        )

    def test_from_exploit_queue_row_derives_contract_fn(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Vault {\n"
                "    function withdraw() external {}\n"
                "}\n"
            )
            row = {
                "lead_id": "EQ-001",
                "title": "Vault conservation",
                "source_refs": ["engage_report.json:src/Vault.sol:3"],
                "attack_class": "reent",
                "likely_severity": "high",
                "obligation_id": "zdo-1",
                "revision_id": "zdr-1",
                "zero_day_proof_envelope": {
                    "envelope_id": "zdpe-1",
                    "parent_ids": ["zdo-1", "zdr-1"],
                },
            }
            cand = mod.load_candidate_from_queue_row(row, ws)
            self.assertEqual(cand["contract"], "Vault")
            self.assertEqual(cand["fn"], "withdraw")
            self.assertEqual(cand["vuln_class"], "reentrancy")
            self.assertEqual(cand["lead_id"], "EQ-001")
            self.assertEqual(cand["zero_day_proof_envelope"]["envelope_id"], "zdpe-1")

    def test_queue_row_missing_source_ref_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                mod.load_candidate_from_queue_row({"attack_class": "reent"}, Path(d))

    def test_queue_json_selects_by_lead_id(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "A.sol").write_text(
                "contract A {\n"
                "    function a() external {}\n"
                "}\n"
            )
            (ws / "src" / "B.sol").write_text(
                "contract B {\n"
                "    function b() external {}\n"
                "}\n"
            )
            q = ws / "queue.json"
            q.write_text(json.dumps({
                "queue": [
                    {"lead_id": "EQ-001", "source_refs": ["src/A.sol:2"], "attack_class": "reent"},
                    {"lead_id": "EQ-002", "source_refs": ["src/B.sol:2"], "attack_class": "access-control"},
                ]
            }))
            cand = mod.load_candidate_from_queue_json(str(q), ws, lead_id="EQ-002")
            self.assertEqual(cand["contract"], "B")
            self.assertEqual(cand["lead_id"], "EQ-002")

    def test_queue_json_multiple_rows_requires_selector(self):
        payload = {"queue": [
            {"lead_id": "A", "source_refs": ["src/A.sol:1"], "attack_class": "reent"},
            {"lead_id": "B", "source_refs": ["src/B.sol:1"], "attack_class": "reent"},
        ]}
        with self.assertRaises(ValueError):
            mod.select_queue_row(payload)

    def test_cli_queue_json_no_run_emits_candidate_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(
                "contract Vault {\n"
                "    function withdraw() external {}\n"
                "}\n"
            )
            q = ws / "queue.json"
            q.write_text(json.dumps({
                "queue": [
                    {"lead_id": "EQ-001", "source_refs": ["src/Vault.sol:2"], "attack_class": "reent"}
                ]
            }))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = mod.main([
                    "--queue-json", str(q),
                    "--lead-id", "EQ-001",
                    "--workspace", str(ws),
                    "--no-run",
                    "--json",
                ])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["candidate"]["lead_id"], "EQ-001")
            self.assertEqual(out["candidate"]["contract"], "Vault")

    def test_missing_required_raises(self):
        ns = type("NS", (), {
            "candidate_json": None, "contract": "Foo", "fn": None,
            "vuln_class": "reent", "file_line": "",
            "lead_id": None, "queue_index": None})()
        with self.assertRaises(ValueError):
            mod.load_candidate(ns)


class TestSchema(unittest.TestCase):
    def test_schema_constant(self):
        self.assertEqual(mod.SCHEMA, "auditooor.evm_0day_proof_pipeline.v1")

    def test_verdict_exit_map_complete(self):
        for v in ["proof-backed", "claim-narrowed-out-of-tree",
                  "scaffold-only-not-run", "blocked-with-obligation",
                  "compile-blocked-with-obligation",
                  "refuted", "error"]:
            self.assertIn(v, mod.VERDICT_EXIT)


# ===========================================================================
# iter6-A: real run-backed proof machinery (source introspection + adjudication
# + honesty contract). The forge-dependent end-to-end runs are exercised by
# tools/tests/test_evm_0day_real_proof_e2e.py (gated on forge + corpus presence).
# ===========================================================================

class TestSourceIntrospection(unittest.TestCase):
    LIB_SRC = (
        "pragma solidity ^0.8.20;\n"
        "library Bytes {\n"
        "    function isEmpty(bytes memory item) internal pure returns (bool) {\n"
        "        return item.length > 0 && (item[0] == 0xc0 || item[0] == 0x80);\n"
        "    }\n"
        "}\n"
    )

    def test_read_pragma(self):
        self.assertEqual(mod._read_pragma(self.LIB_SRC), "^0.8.20")

    def test_enclosing_unit_library(self):
        name, kind, abstract = mod._enclosing_unit(self.LIB_SRC, 4)
        self.assertEqual(name, "Bytes")
        self.assertEqual(kind, "library")
        self.assertFalse(abstract)

    def test_enclosing_unit_abstract(self):
        src = "pragma solidity ^0.8.20;\nabstract contract Amp is Base {\n  uint x;\n}\n"
        name, kind, abstract = mod._enclosing_unit(src, 3)
        self.assertEqual(name, "Amp")
        self.assertTrue(abstract)

    def test_fn_at_line(self):
        fn = mod._fn_at_line(self.LIB_SRC, 4)
        self.assertEqual(fn["name"], "isEmpty")
        self.assertEqual(fn["visibility"], "internal")
        self.assertEqual(fn["mutability"], "pure")
        self.assertIn("bool", fn["returns"])

    def test_synthesize_ctor_args_value_types(self):
        self.assertEqual(mod._synthesize_ctor_args("address deployer"), "address(0xBEEF)")
        self.assertEqual(mod._synthesize_ctor_args(""), "")
        self.assertEqual(mod._synthesize_ctor_args("uint256 a, bool b"), "1, false")

    def test_synthesize_ctor_args_rejects_struct(self):
        self.assertIsNone(mod._synthesize_ctor_args("IPoolManager pm, address o"))

    def test_fwd_args(self):
        self.assertEqual(mod._fwd_args("bytes memory item"), "item")
        self.assertEqual(mod._fwd_args("bytes memory a, uint256 b"), "a, b")
        self.assertEqual(mod._fwd_args(""), "")


class TestDecodeMismatchAuthor(unittest.TestCase):
    def test_isempty_template_present(self):
        fn = {"name": "isEmpty", "params": "bytes memory item",
              "visibility": "internal", "mutability": "pure", "returns": "bool"}
        out = mod._author_decode_mismatch("EthereumTrieDB", fn, "X.sol:144")
        self.assertIsNotNone(out)
        self.assertIn("real.isEmpty(legit_c0)", out["exploit"])
        self.assertIn("patched.isEmpty(legit_c0)", out["control"])
        self.assertIn("item.length == 0", out["patched_fn"])

    def test_remove_ending_zero_template_present(self):
        fn = {"name": "removeEndingZero", "params": "bytes memory data",
              "visibility": "internal", "mutability": "pure", "returns": "bytes memory"}
        out = mod._author_decode_mismatch("Bytes", fn, "Bytes.sol:204")
        self.assertIsNotNone(out)
        self.assertIn("vm.expectRevert()", out["exploit"])

    def test_unknown_fn_shape_returns_none(self):
        fn = {"name": "someOtherFn", "params": "uint256 x",
              "visibility": "internal", "mutability": "pure", "returns": "uint256"}
        self.assertIsNone(mod._author_decode_mismatch("Lib", fn, "X.sol:1"))


class TestAdjudicateRealRun(unittest.TestCase):
    """The HONESTY CONTRACT: proof-backed ONLY on exploit PASS + control PASS."""
    def _run(self, **kw):
        return mod._adjudicate_real_run(kw, Path("/tmp/proj"), None, "U", "f", "pure-library")

    def test_proof_backed_requires_both_pass(self):
        r = self._run(ran=True, compile_fail=False, timeout=False,
                      exploit_pass=True, control_pass=True)
        self.assertEqual(r["verdict"], "proof-backed")

    def test_exploit_pass_control_fail_is_not_proof(self):
        r = self._run(ran=True, compile_fail=False, timeout=False,
                      exploit_pass=True, control_pass=False)
        self.assertNotEqual(r["verdict"], "proof-backed")
        self.assertEqual(r["verdict"], "blocked-with-obligation")

    def test_compile_fail_outside_tail_is_detected(self):
        out = "Error: Compiler run failed\n" + "\n".join(f"noise {i}" for i in range(80))
        r = mod.parse_forge_output(out, return_code=1)
        self.assertTrue(r["compile_fail"])
        self.assertEqual(r["return_code"], 1)
        self.assertIn("Compiler run failed", r["raw_output"])
        self.assertNotIn("Compiler run failed", r["raw_tail"])

    def test_exploit_fail_is_refuted(self):
        r = self._run(ran=True, compile_fail=False, timeout=False,
                      exploit_pass=False, control_pass=True)
        self.assertEqual(r["verdict"], "refuted")

    def test_compile_fail_is_blocked_not_proof(self):
        r = self._run(ran=True, compile_fail=True, exploit_pass=False, control_pass=False,
                      raw_tail="Error (1234)")
        self.assertEqual(r["verdict"], "compile-blocked-with-obligation")

    def test_not_run_is_blocked(self):
        r = self._run(ran=False, error="forge missing")
        self.assertEqual(r["verdict"], "blocked-with-obligation")

    def test_timeout_is_blocked(self):
        r = self._run(ran=True, compile_fail=False, timeout=True,
                      exploit_pass=False, control_pass=False)
        self.assertEqual(r["verdict"], "blocked-with-obligation")


class TestForgeStdDiscovery(unittest.TestCase):
    def test_env_override_respected(self):
        with tempfile.TemporaryDirectory() as d:
            fs = Path(d) / "forge-std"
            (fs / "src").mkdir(parents=True)
            (fs / "src" / "Test.sol").write_text("// test")
            import os as _os
            old = _os.environ.get("AUDITOOOR_FORGE_STD")
            _os.environ["AUDITOOOR_FORGE_STD"] = str(fs)
            try:
                self.assertEqual(mod.find_forge_std(), fs)
            finally:
                if old is None:
                    _os.environ.pop("AUDITOOOR_FORGE_STD", None)
                else:
                    _os.environ["AUDITOOOR_FORGE_STD"] = old


class TestCorpusLoading(unittest.TestCase):
    def test_load_corpus_rows_skips_comments(self):
        rows = mod.load_corpus_rows()
        for r in rows:
            self.assertIsInstance(r, dict)

    def test_rel_import_from(self):
        rel = mod._rel_import_from(Path("/a/b/test/_evm0day"), Path("/a/b/src/Foo.sol"))
        self.assertTrue(rel.startswith("../"))
        self.assertTrue(rel.endswith("src/Foo.sol"))


class TestFactoryFeeGapShape(unittest.TestCase):
    """iter7-A: factory-fee-domain-validation-gap deploy author (the shape that
    converts the dynamic-fee-sentinel business-logic case to a real proof)."""

    FACTORY_SRC = (
        "pragma solidity 0.8.30;\n"
        'import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";\n'
        "contract StableSwapHooksFactory {\n"
        "    error InvalidCreationCode();\n"
        "    IPoolManager public immutable poolManager;\n"
        "    bytes32 public immutable creationCodeHash;\n"
        "    constructor(IPoolManager _pm, address _owner, address _a, address _b, bytes32 _h) {\n"
        "        poolManager = _pm; creationCodeHash = _h;\n"
        "    }\n"
        "    function deploy(uint256 _lpFeePercentage, bytes calldata _creationCode)\n"
        "        external returns (address) {\n"
        "        if (keccak256(_creationCode) != creationCodeHash) revert InvalidCreationCode();\n"
        "        return address(0);\n"
        "    }\n"
        "}\n"
    )

    def _fn(self):
        return mod._fn_at_line(self.FACTORY_SRC, 11)

    def test_synthesize_ctor_args_factory_interface_ok(self):
        # interface-type ctor arg is cast from a dummy address (factory stores it)
        out = mod._synthesize_ctor_args_factory(
            "IPoolManager _pm, address _owner, address _a, address _b, bytes32 _h")
        self.assertIsNotNone(out)
        self.assertIn("IPoolManager(address(0xBEEF))", out)
        self.assertIn("address(0xBEEF)", out)

    def test_synthesize_ctor_args_factory_rejects_arrays(self):
        self.assertIsNone(mod._synthesize_ctor_args_factory("uint256[] _x"))

    def test_collect_symbol_imports_resolves(self):
        imp = mod._collect_symbol_imports(self.FACTORY_SRC, ["IPoolManager"])
        self.assertIsNotNone(imp)
        self.assertIn("IPoolManager", imp)
        self.assertIn("from", imp)

    def test_collect_symbol_imports_missing_returns_none(self):
        self.assertIsNone(mod._collect_symbol_imports(self.FACTORY_SRC, ["INope"]))

    def test_author_factory_fee_gap_fires_on_unguarded_deploy(self):
        fn = self._fn()
        self.assertEqual(fn["name"], "deploy")
        cand = {"vuln_class": "business-logic", "file_line": "x:11"}
        out = mod._author_factory_fee_gap(
            cand, self.FACTORY_SRC, "StableSwapHooksFactory", fn,
            "src/StableSwapHooksFactory.sol")
        self.assertIsNotNone(out)
        self.assertIn("test_exploit_deploy", out["test_src"])
        self.assertIn("InvalidCreationCode.selector", out["test_src"])
        self.assertIn("0x800000", out["test_src"])  # dynamic-fee sentinel
        self.assertIn("FeeOutOfDomain", out["test_src"])  # negative control

    def test_author_factory_fee_gap_skips_when_fee_is_guarded(self):
        guarded = self.FACTORY_SRC.replace(
            "if (keccak256(_creationCode) != creationCodeHash) revert InvalidCreationCode();",
            "if (_lpFeePercentage > FEE_PRECISION) revert();\n"
            "        if (keccak256(_creationCode) != creationCodeHash) revert InvalidCreationCode();")
        fn = mod._fn_at_line(guarded, 11)
        cand = {"vuln_class": "business-logic", "file_line": "x:11"}
        out = mod._author_factory_fee_gap(
            cand, guarded, "StableSwapHooksFactory", fn,
            "src/StableSwapHooksFactory.sol")
        self.assertIsNone(out, "must NOT fire when deploy already guards the fee")

    def test_author_factory_fee_gap_skips_non_deploy_fn(self):
        fn = dict(self._fn())
        fn["name"] = "pause"
        out = mod._author_factory_fee_gap(
            dict(vuln_class="business-logic", file_line="x:11"),
            self.FACTORY_SRC, "StableSwapHooksFactory", fn, "x.sol")
        self.assertIsNone(out)


class TestVaultConservationShape(unittest.TestCase):
    """iter11-A: vault-accounting-conservation auto-conversion. The shape is a
    tracked accumulator decremented by a yield-INFLATED amount (the pUSDeVault
    ._withdraw `depositedBase -= (assets + previewYield(...))` shape)."""

    # Faithful slice of the real pUSDeVault._withdraw conservation shape.
    VAULT_SRC = (
        "pragma solidity ^0.8.28;\n"
        "contract pUSDeVault {\n"
        "    uint256 public depositedBase;\n"
        "    function previewYield(address c, uint256 s) public view returns (uint256) { return 0; }\n"
        "    function _withdraw(address caller, address r, address o, uint256 assets, uint256 shares) internal {\n"
        "        assets += previewYield(caller, shares);\n"
        "        require(assets <= depositedBase, \"INSUFFICIENT_ASSETS\");\n"
        "        depositedBase -= assets;\n"
        "    }\n"
        "}\n"
    )

    def _fn(self, src=None):
        return mod._fn_at_line(src or self.VAULT_SRC, 5)

    def test_detect_fires_on_inflated_decrement(self):
        shape = mod.detect_vault_conservation_shape(self.VAULT_SRC, self._fn())
        self.assertIsNotNone(shape)
        self.assertEqual(shape["accumulator"], "depositedBase")
        self.assertEqual(shape["inflated_var"], "assets")
        self.assertEqual(shape["yield_term"], "previewYield")

    def test_detect_skips_when_decrement_var_differs(self):
        # Conservation HOLDS: accumulator decremented by a clean `base` var, not
        # the yield-inflated `assets` var -> not the bug.
        safe = self.VAULT_SRC.replace("depositedBase -= assets;",
                                      "uint256 base = assets - previewYield(caller, shares);\n"
                                      "        depositedBase -= base;")
        shape = mod.detect_vault_conservation_shape(safe, self._fn(safe))
        self.assertIsNone(shape, "must NOT fire when accumulator decremented by clean base var")

    def test_detect_skips_non_vault_fn(self):
        fn = dict(self._fn())
        fn["name"] = "rebase"  # not a recognized vault mutation fn
        self.assertIsNone(mod.detect_vault_conservation_shape(self.VAULT_SRC, fn))

    def test_detect_requires_accumulator_and_inflation_and_decrement(self):
        # No inflation site -> no shape.
        no_inflation = self.VAULT_SRC.replace("assets += previewYield(caller, shares);", "")
        self.assertIsNone(mod.detect_vault_conservation_shape(no_inflation, self._fn(no_inflation)))

    def test_author_emits_v3_grade_shape(self):
        fn = self._fn()
        shape = mod.detect_vault_conservation_shape(self.VAULT_SRC, fn)
        cand = {"vuln_class": "vault-conservation",
                "file_line": "contracts/predeposit/pUSDeVault.sol:144"}
        out = mod.author_vault_conservation_proof(cand, self.VAULT_SRC, "pUSDeVault", fn, shape)
        src = out["test_src"]
        self.assertIn("test_exploit__withdraw", src)
        self.assertIn("test_negative_control__withdraw", src)
        self.assertIn("ReproVault", src)
        self.assertIn("ReproVaultPatched", src)
        self.assertIn("conservation NOT violated", src)
        self.assertIn("depositedBase", src)
        self.assertIn("V3-GRADE", src)
        self.assertIn("FAITHFUL SELF-CONTAINED REPRODUCTION", src)

    def test_normalize_vault_aliases(self):
        for a in ("erc4626", "vault-accounting", "yield-inflation", "conservation-violation"):
            self.assertEqual(mod.normalize_vuln_class(a), "vault-conservation")


class TestVaultConservationRealRun(unittest.TestCase):
    """End-to-end: run the authored faithful reproduction under forge and assert
    proof-backed. Gated on forge availability (skip cleanly otherwise)."""

    def setUp(self):
        self.forge = mod.resolve_forge()
        self.forge_std = mod.find_forge_std()
        if not self.forge or not self.forge_std:
            self.skipTest("forge or forge-std unavailable")

    def test_standalone_repro_runs_proof_backed(self):
        src = TestVaultConservationShape.VAULT_SRC
        fn = mod._fn_at_line(src, 5)
        shape = mod.detect_vault_conservation_shape(src, fn)
        cand = {"vuln_class": "vault-conservation", "file_line": "pUSDeVault.sol:144"}
        authored = mod.author_vault_conservation_proof(cand, src, "pUSDeVault", fn, shape)
        proj = mod.build_standalone_runner(self.forge_std, authored["test_src"], "^0.8.28")
        self.assertIsNotNone(proj)
        run = mod.run_forge(self.forge, proj, authored["test_match"])
        res = mod._adjudicate_real_run(run, proj, None, "pUSDeVault", "_withdraw",
                                       "vault-conservation-repro")
        self.assertEqual(res["verdict"], "proof-backed", run.get("raw_tail"))
        self.assertIn("faithful self-contained reproduction", res["reason"])


class TestSynthesizedRemappings(unittest.TestCase):
    """iter14-A: non-destructive synthesized remappings.txt context manager."""

    def test_creates_then_removes_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            mapping = {"@openzeppelin/contracts/": Path("/x/oz/contracts"),
                       "forge-std/": Path("/x/fstd/src")}
            rm = proj / "remappings.txt"
            self.assertFalse(rm.exists())
            with mod._SynthesizedRemappings(proj, mapping):
                self.assertTrue(rm.exists())
                body = rm.read_text()
                self.assertIn("@openzeppelin/contracts/=/x/oz/contracts/", body)
                self.assertIn("forge-std/=/x/fstd/src/", body)
            self.assertFalse(rm.exists(), "must remove a remappings.txt it created")

    def test_backs_up_and_restores_existing(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            rm = proj / "remappings.txt"
            rm.write_text("original/=lib/original/\n")
            with mod._SynthesizedRemappings(proj, {"a/": Path("/y")}):
                self.assertIn("a/=/y/", rm.read_text())
            self.assertEqual(rm.read_text(), "original/=lib/original/\n",
                             "must restore the original remappings.txt verbatim")


class TestInplaceVaultDeployShape(unittest.TestCase):
    """iter15-A: GENERIC source-inferred deploy-shape detector. The fixture uses
    a TYPED ERC4626 initializer + ERC20/ERC4626 source mocks (the realistic
    shape) and NO target literal - the detector infers the recipe from source,
    so it works for any vault with this conservation shape, not just one target.
    """

    DEPLOY_SRC = (
        "pragma solidity 0.8.28;\n"
        "import \"@openzeppelin/contracts/token/ERC20/IERC20.sol\";\n"
        "import \"@openzeppelin/contracts/interfaces/IERC4626.sol\";\n"
        "contract SomeVault {\n"
        "    address public sink;\n"
        "    function initialize(address o, IERC20 base, IERC4626 stake) external {}\n"
        "    function deposit(uint256 a, address r) external returns (uint256) {}\n"
        "    function withdraw(uint256 a, address r, address o) external returns (uint256) {}\n"
        "    function setDepositsEnabled(bool v) external {}\n"
        "    function setWithdrawalsEnabled(bool v) external {}\n"
        "    function previewYield(address caller, uint256 shares) public view returns (uint256) {\n"
        "        if (caller == address(sink)) return 1; return 0; }\n"
        "    function startYieldPhase() external {}\n"
        "    function updateSink(address a) external { sink = a; }\n"
        "}\n"
    )

    def _project_with_mocks(self, d):
        proj = Path(d)
        (proj / "foundry.toml").write_text("[profile.default]\nsrc='contracts'\n")
        src_mock = proj / "contracts" / "test"
        src_mock.mkdir(parents=True)
        # realistic typed source mocks (ERC20 base + ERC4626 stake).
        (src_mock / "MockBase.sol").write_text(
            "import \"@openzeppelin/contracts/token/ERC20/ERC20.sol\";\n"
            "contract MockBase is ERC20 {\n"
            "    constructor() ERC20(\"b\",\"b\") {}\n"
            "    function mint(address to, uint256 amt) external { _mint(to, amt); }\n"
            "}\n")
        (src_mock / "MockStake.sol").write_text(
            "import \"@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol\";\n"
            "contract MockStake is ERC4626 {}\n")
        return proj

    def test_detects_when_mocks_present(self):
        with tempfile.TemporaryDirectory() as d:
            proj = self._project_with_mocks(d)
            shape = mod.detect_inplace_vault_deploy_shape(self.DEPLOY_SRC, proj, "SomeVault")
            self.assertIsNotNone(shape)
            self.assertTrue(shape["mock_usde"].endswith("contracts/test/MockBase.sol"))
            # the recipe is inferred, not hardcoded.
            self.assertEqual(shape["phase_entry_fn"], "startYieldPhase")
            self.assertEqual(shape["deposit_fn"], "deposit")
            self.assertEqual(shape["withdraw_fn"], "withdraw")
            self.assertIn("setDepositsEnabled(true)", shape["enable_toggles"])
            self.assertEqual(shape["caller_gate"]["gate_var"], "sink")
            self.assertEqual(shape["caller_gate"]["setter"], "updateSink")

    def test_excludes_build_artifact_dirs(self):
        # A forge `out/MockBase.sol/` artifact DIRECTORY must be ignored; only
        # the real source mock counts.
        with tempfile.TemporaryDirectory() as d:
            proj = self._project_with_mocks(d)
            art = proj / "out" / "MockBase.sol"
            art.mkdir(parents=True)
            (art / "MockBase.json").write_text("{}")
            shape = mod.detect_inplace_vault_deploy_shape(self.DEPLOY_SRC, proj, "SomeVault")
            self.assertIsNotNone(shape)
            self.assertNotIn("/out/", shape["mock_usde"])

    def test_returns_none_without_phase_api(self):
        no_phase = self.DEPLOY_SRC.replace("function startYieldPhase() external {}", "")
        with tempfile.TemporaryDirectory() as d:
            proj = self._project_with_mocks(d)
            self.assertIsNone(mod.detect_inplace_vault_deploy_shape(no_phase, proj, "SomeVault"))

    def test_marks_for_synthesis_without_source_mocks(self):
        # iter16: when NO project source mock exists for an external dependency
        # arg, the detector no longer blocks - it marks the arg for SYNTHESIS
        # from the target's interface usage. The deploy shape is still returned.
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            shape = mod.detect_inplace_vault_deploy_shape(
                self.DEPLOY_SRC, proj, "SomeVault")
            self.assertIsNotNone(shape)
            erc20 = next(m for m in shape["arg_mocks"] if m["is_erc20"])
            self.assertTrue(erc20["synthesize"])
            self.assertIsNone(erc20["mock"])
            # back-compat truthiness sentinel for synthesized args.
            self.assertEqual(shape["mock_usde"], "<synthesized>")

    def test_generic_no_target_literals_in_tool(self):
        # GUARD: the de-contaminated tool must not hardcode any Strata-IDENTITY
        # literal as MATCH LOGIC (regex / string-equality used to recognize or
        # drive a target). Strata-identity literals are names unique to that one
        # target. Generic / ERC-standard terms (previewRedeem, previewWithdraw,
        # the `\\w*yield\\w*` family) are allowed - they are not one target's
        # identity. The literals may still appear in human-readable docstrings /
        # comments / explanatory message prose as anchors.
        path = TOOLS / "evm-0day-proof-pipeline.py"
        text = path.read_text()
        # strip comments + triple-quoted docstrings: only code-level literals
        # (regex bodies, equality checks, drive statements) are under test.
        import re as _re
        code = _re.sub(r'"""(?:.|\n)*?"""', "", text)
        code = _re.sub(r"#[^\n]*", "", code)
        # Strata-IDENTITY literals that DRIVE behavior (mock names, fn names,
        # phase names, gate setters) - these are the contamination the iter15-A
        # de-contamination removed. (`depositedBase` remains as ONE accumulator-
        # name alternative in the generic accumulator regex alongside totalDebt /
        # principal / trackedAssets etc.; it is a descriptive name in a list of
        # alternatives, not a single-target drive literal, so it is allowed.)
        for lit in ("yUSDe", "startYieldPhase", "updateYUSDeVault",
                    "MockUSDe", "MockStakedUSDe", "setDepositsEnabled",
                    "setWithdrawalsEnabled", "pUSDeVault",
                    # GAP A / GAP B forward-test target identities: none may leak
                    # into drive logic (docstrings/comments/fixtures are stripped
                    # above, so any hit here is a real contamination).
                    "scLiquity", "sandclock", "sc4626", "stabilityPool",
                    "usd2eth", "Pods", "Maple", "Punk", "DeepConstDepVault"):
            self.assertNotIn(
                lit, code,
                f"target-identity literal '{lit}' is hardcoded as drive logic")


class TestInplaceVaultAuthor(unittest.TestCase):
    """iter15-A: the GENERIC in-place real-deploy author emits a real-deploy V3
    shape whose deploy recipe is INFERRED from source (initializer args, mocks,
    phase-entry, toggles, caller gate, yield lever) - no target literal."""

    # A realistic accumulator-over-decrement vault with TYPED ERC4626 args, an
    # ERC4626-donation yield lever, a caller gate, and enable toggles. Names are
    # generic (trackedAssets / rewardSink / activateEpoch / base / stake).
    VAULT_SRC = (
        "pragma solidity 0.8.28;\n"
        "import \"@openzeppelin/contracts/token/ERC20/IERC20.sol\";\n"
        "import \"@openzeppelin/contracts/interfaces/IERC4626.sol\";\n"
        "contract GVault {\n"
        "    uint256 public trackedAssets;\n"
        "    IERC4626 public stake;\n"
        "    address public rewardSink;\n"
        "    function initialize(address o, IERC20 base, IERC4626 stake_) external {}\n"
        "    function deposit(uint256 a, address r) external returns (uint256) {}\n"
        "    function withdraw(uint256 a, address r, address o) external returns (uint256) {}\n"
        "    function setDepositsEnabled(bool v) external {}\n"
        "    function setWithdrawalsEnabled(bool v) external {}\n"
        "    function activateEpoch() external {}\n"
        "    function setRewardSink(address s) external { rewardSink = s; }\n"
        "    function accruedYield(address caller, uint256 shares) public view returns (uint256) {\n"
        "        if (caller == address(rewardSink)) return stake.previewRedeem(1); return 0; }\n"
        "    function _withdraw(address caller, address r, address o, uint256 assets, uint256 shares) internal {\n"
        "        assets += accruedYield(caller, shares);\n"
        "        trackedAssets -= assets;\n"
        "    }\n"
        "}\n"
    )

    def test_author_emits_real_deploy_shape(self):
        src = self.VAULT_SRC
        # locate _withdraw dynamically (robust to fixture line shifts).
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        self.assertEqual(fn["name"], "_withdraw")
        shape = mod.detect_vault_conservation_shape(src, fn)
        self.assertIsNotNone(shape)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            tdir = proj / "test"
            tdir.mkdir()
            (proj / "src").mkdir(parents=True)
            (proj / "src" / "GVault.sol").write_text(src)
            mb = proj / "src" / "MockBase.sol"
            mb.write_text("import \"@openzeppelin/contracts/token/ERC20/ERC20.sol\";\n"
                          "contract MockBase is ERC20 { constructor() ERC20(\"b\",\"b\"){}\n"
                          "  function mint(address t,uint256 a) external { _mint(t,a);} }\n")
            ms = proj / "src" / "MockStake.sol"
            ms.write_text("import \"@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol\";\n"
                          "contract MockStake is ERC4626 {}\n")
            cand = {"vuln_class": "vault-conservation",
                    "file_line": "src/GVault.sol:18",
                    "rel_path": "src/GVault.sol"}
            deploy_shape = mod.detect_inplace_vault_deploy_shape(src, proj, "GVault")
            self.assertIsNotNone(deploy_shape, "generic detector must fire")
            out = mod.author_vault_conservation_inplace(
                cand, src, "GVault", fn, shape, tdir, proj, deploy_shape)
            self.assertIsNotNone(out)
            body = out["test_src"]
            self.assertIn("ERC1967Proxy", body)
            self.assertIn("MockBase", body)          # inferred ERC20 base mock
            self.assertIn("MockStake", body)         # inferred ERC4626 stake mock
            self.assertIn("activateEpoch", body)     # inferred phase entry
            self.assertIn("setRewardSink(actor)", body)  # inferred caller-gate reg
            self.assertIn("vault.withdraw(", body)   # drives the REAL entrypoint
            self.assertIn("conservation violated", body)
            self.assertIn("test_exploit__withdraw", body)
            self.assertIn("test_negative_control__withdraw", body)
            # NO target literal leaked into the authored test.
            for lit in ("pUSDeVault", "previewYield", "yUSDe", "USDe", "MockUSDe"):
                self.assertNotIn(lit, body, f"target literal '{lit}' leaked")


class TestInplaceRealDeployE2E(unittest.TestCase):
    """iter14-A: full in-place real-deploy run against the strata workspace.
    Gated on forge + the strata-iter10 workspace + a vendorable OZ-5.x sibling."""

    def setUp(self):
        self.forge = mod.resolve_forge()
        self.ws = Path.home() / "audits" / "strata-iter10"
        vault = self.ws / "contracts" / "predeposit" / "pUSDeVault.sol"
        if not self.forge or not vault.exists():
            self.skipTest("forge or strata-iter10 workspace unavailable")
        if mod._find_sibling_oz_and_forge_std(Path.home() / "audits") is None:
            self.skipTest("no vendorable OZ-5.x + forge-std sibling checkout")

    def test_strata_pusdevault_inplace_proof_backed(self):
        cand = mod.load_candidate(_ns(
            contract="pUSDeVault", fn="_withdraw", vuln_class="vault-conservation",
            file_line="contracts/predeposit/pUSDeVault.sol:144"))
        res = mod.run_pipeline(cand, self.ws, None, do_run=True)
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "vault-conservation-inplace-real-deploy")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        # workspace must be left clean (no leftover authored test / remappings).
        self.assertFalse((self.ws / "remappings.txt").exists(),
                         "synthesized remappings.txt must be removed")
        leftovers = list((self.ws / "test").rglob("_evm0day_autoproof"))
        self.assertEqual(leftovers, [], "authored in-place test dir must be cleaned")


class TestUnseenTargetGenerality(unittest.TestCase):
    """iter15-A GENERALITY PROOF: the generic in-place author must autonomously
    convert a PREVIOUSLY-UNSEEN vault target (escrowvault-blind: zero Strata
    literals, not in any corpus, deliberately different identifiers throughout)
    to a REAL in-place forge-PASS proof-backed verdict WITHOUT any target-
    specific code path. This is the load-bearing test: a hand-spec that only
    works on a known target would FAIL here.

    Gated on forge + the escrowvault-blind workspace + a vendorable OZ-5.x
    upgradeable sibling checkout (the blind workspace ships no deps)."""

    def setUp(self):
        self.forge = mod.resolve_forge()
        self.ws = Path.home() / "audits" / "escrowvault-blind"
        vault = self.ws / "src" / "RewardEscrowVault.sol"
        if not self.forge or not vault.exists():
            self.skipTest("forge or escrowvault-blind workspace unavailable")
        mapping = mod._find_sibling_oz_and_forge_std(Path.home() / "audits")
        if mapping is None or "@openzeppelin/contracts-upgradeable/" not in mapping:
            self.skipTest("no vendorable OZ-5.x upgradeable + forge-std sibling")

    def test_unseen_escrowvault_inplace_proof_backed(self):
        cand = mod.load_candidate(_ns(
            contract="RewardEscrowVault", fn="_withdraw",
            vuln_class="vault-conservation",
            file_line="src/RewardEscrowVault.sol:72"))
        res = mod.run_pipeline(cand, self.ws, None, do_run=True)
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        # MUST be the in-place real-deploy path, not the self-contained fallback:
        # that is what proves the generic synth drove the REAL unseen contract.
        self.assertEqual(res["real_proof_mode"],
                         "vault-conservation-inplace-real-deploy")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])
        # workspace left clean.
        self.assertFalse((self.ws / "remappings.txt").exists())
        leftovers = list((self.ws).rglob("_evm0day_autoproof"))
        self.assertEqual(leftovers, [], "authored in-place test dir must be cleaned")


class TestDepMockSynthesis(unittest.TestCase):
    """iter16: dependency-mock SYNTHESIS from the target's interface usage. When
    no project source mock exists, the in-place author synthesizes a minimal
    compliant ERC20/ERC4626 mock from the methods the target actually invokes."""

    def test_dep_methods_called_parses_usage(self):
        src = ("function f() external { uint b = base.balanceOf(msg.sender);\n"
               "  base_.transfer(to, b); stake.previewRedeem(1); }\n")
        m20 = mod._dep_methods_called(src, "base_")
        self.assertIn("balanceOf", m20)
        self.assertIn("transfer", m20)
        m4626 = mod._dep_methods_called(src, "stake")
        self.assertIn("previewRedeem", m4626)

    def test_synthesize_erc20_mock_emits_mintable(self):
        with tempfile.TemporaryDirectory() as d:
            out = mod._synthesize_dep_mock(
                "IERC20", ["balanceOf", "transfer"], Path(d), "0.8.28")
            self.assertIsNotNone(out)
            self.assertTrue(out["is_erc20"])
            self.assertEqual(out["name"], "_SynthErc20Dep")
            body = Path(out["path"]).read_text()
            self.assertIn("is ERC20", body)
            self.assertIn("function mint(", body)       # funder for actors
            self.assertIn("balanceOf, transfer", body)  # honesty: usage recorded

    def test_synthesize_erc4626_mock_takes_asset(self):
        with tempfile.TemporaryDirectory() as d:
            out = mod._synthesize_dep_mock(
                "IERC4626", ["previewRedeem"], Path(d), "0.8.28")
            self.assertIsNotNone(out)
            self.assertFalse(out["is_erc20"])
            self.assertEqual(out["name"], "_SynthErc4626Dep")
            body = Path(out["path"]).read_text()
            self.assertIn("is ERC4626", body)
            self.assertIn("ERC4626(asset_)", body)      # standard asset ctor

    def test_synthesize_rejects_non_token_type(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(
                mod._synthesize_dep_mock("IPoolManager", [], Path(d), "0.8.28"))

    def test_author_drives_synthesis_when_no_source_mock(self):
        # The realistic conservation vault from TestInplaceVaultAuthor, but the
        # project ships NO source mock. The author must synthesize the ERC20 +
        # ERC4626 deps from the target's usage and reference them in the test.
        src = TestInplaceVaultAuthor.VAULT_SRC
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            tdir = proj / "test"
            tdir.mkdir()
            (proj / "src").mkdir(parents=True)
            (proj / "src" / "GVault.sol").write_text(src)
            # NO MockBase / MockStake on disk -> synthesis path.
            cand = {"vuln_class": "vault-conservation",
                    "file_line": "src/GVault.sol:18", "rel_path": "src/GVault.sol"}
            deploy_shape = mod.detect_inplace_vault_deploy_shape(src, proj, "GVault")
            self.assertIsNotNone(deploy_shape)
            erc20 = next(m for m in deploy_shape["arg_mocks"] if m["is_erc20"])
            self.assertTrue(erc20["synthesize"])
            out = mod.author_vault_conservation_inplace(
                cand, src, "GVault", fn, shape, tdir, proj, deploy_shape)
            self.assertIsNotNone(out)
            body = out["test_src"]
            # the authored test references the SYNTHESIZED mocks, not source mocks.
            self.assertIn("_SynthErc20Dep", body)
            self.assertIn("_SynthErc4626Dep", body)
            self.assertIn("ERC1967Proxy", body)
            self.assertIn("vault.withdraw(", body)
            # the synth mock files were written to gen_dir and are tracked for
            # cleanup; confirm they exist on disk where the author put them.
            self.assertTrue(out["synth_mocks"])
            for sm in out["synth_mocks"]:
                self.assertTrue(Path(sm["path"]).exists())
            # NO target literal leaked.
            for lit in ("pUSDeVault", "yUSDe", "MockUSDe"):
                self.assertNotIn(lit, body)


class TestSynthesizedMockRealRun(unittest.TestCase):
    """iter16 LOAD-BEARING PROOF: the dependency-mock SYNTHESIS path must drive a
    real OZ-upgradeable yield-phase conservation vault to a forge-PASS
    proof-backed verdict with ZERO hand-placed mocks on disk. The vault ships
    NO mock; the pipeline synthesizes the ERC20 + ERC4626 deps from the target's
    interface usage, deploys the REAL vault via ERC1967Proxy, and proves the
    conservation over-decrement. Gated on forge + a vendorable OZ-5.x upgradeable
    sibling (the synthesized mocks import the OZ ERC20/ERC4626/ERC4626Upgradeable
    bases, which the synthesized remappings resolve)."""

    VAULT = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.28;\n"
        "import {IERC20} from \"@openzeppelin/contracts/token/ERC20/IERC20.sol\";\n"
        "import {IERC4626} from \"@openzeppelin/contracts/interfaces/IERC4626.sol\";\n"
        "import {ERC4626Upgradeable} from "
        "\"@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol\";\n"
        "contract YieldPhaseVault is ERC4626Upgradeable {\n"
        "    uint256 public trackedAssets;\n"
        "    IERC4626 public stakeVault;\n"
        "    address public yieldSink;\n"
        "    bool public yieldPhase;\n"
        "    function initialize(address owner_, IERC20 base_, IERC4626 stake_) external initializer {\n"
        "        __ERC4626_init(base_); __ERC20_init(\"yp\", \"YP\");\n"
        "        stakeVault = stake_; yieldSink = owner_;\n"
        "    }\n"
        "    function startYieldPhase() external { yieldPhase = true; }\n"
        "    function setYieldSink(address s) external { yieldSink = s; }\n"
        "    function accruedYield(address caller) public view returns (uint256) {\n"
        "        if (yieldPhase && caller == address(yieldSink)) {\n"
        "            return stakeVault.previewRedeem(1e18); }\n"
        "        return 0;\n"
        "    }\n"
        "    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {\n"
        "        super._deposit(caller, receiver, assets, shares); trackedAssets += assets;\n"
        "    }\n"
        "    function _withdraw(address caller, address receiver, address ownr, uint256 assets, uint256 shares) internal override {\n"
        "        assets += accruedYield(caller); trackedAssets -= assets;\n"
        "        super._withdraw(caller, receiver, ownr, assets, shares);\n"
        "    }\n"
        "}\n"
    )

    def setUp(self):
        self.forge = mod.resolve_forge()
        if not self.forge:
            self.skipTest("forge unavailable")
        mapping = mod._find_sibling_oz_and_forge_std(Path.home() / "audits")
        if mapping is None or "@openzeppelin/contracts-upgradeable/" not in mapping:
            self.skipTest("no vendorable OZ-5.x upgradeable + forge-std sibling")

    def test_synthesized_deps_drive_real_vault_proof_backed(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "YieldPhaseVault.sol").write_text(self.VAULT)
            (ws / "foundry.toml").write_text("[profile.default]\nsrc='src'\n")
            # HARD honesty assertion: there is NO mock anywhere on disk.
            pre = [p for p in ws.rglob("*.sol")
                   if "Mock" in p.name or "mock" in p.read_text().lower()]
            self.assertEqual(pre, [], "no hand-placed mock may exist pre-run")
            wline = next(i for i, l in enumerate(self.VAULT.split("\n"), 1)
                         if "function _withdraw(" in l)
            cand = mod.load_candidate(_ns(
                contract="YieldPhaseVault", fn="_withdraw",
                vuln_class="vault-conservation",
                file_line=f"src/YieldPhaseVault.sol:{wline}"))
            out = ws / "_evidence"
            res = mod.run_pipeline(cand, ws, out, do_run=True)
            self.assertEqual(res["verdict"], "proof-backed",
                             (res.get("forge_run") or {}).get("raw_tail"))
            self.assertEqual(res["real_proof_mode"],
                             "vault-conservation-inplace-real-deploy")
            self.assertTrue(res["forge_run"]["exploit_pass"])
            self.assertTrue(res["forge_run"]["control_pass"])
            self.assertFalse(res["forge_run"]["compile_fail"])
            # the evidence bundle carries the SYNTHESIZED mocks (proof they were
            # generated, not hand-placed).
            names = {p.name for p in out.rglob("*") if p.is_file()}
            self.assertIn("_SynthErc20Dep.sol", names)
            self.assertIn("_SynthErc4626Dep.sol", names)
            # workspace left clean: no synth mock / authored test leaked back.
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])
            post = [p for p in (ws / "src").rglob("*.sol")]
            self.assertEqual([p.name for p in post], ["YieldPhaseVault.sol"],
                             "synthesized mocks must not persist in the src tree")


# ---------------------------------------------------------------------------
# iter17: GENERAL dep-routing for the three deploy SHAPES the iter16 typed-arg
# detector missed - (a) CONSTRUCTOR-injected, (b) ADDRESS-TYPED cast, and
# (c) HARDCODED-CONSTANT vm.etch'd deps. Each is a deploy PATTERN, never a target
# name; the fixtures below carry zero target-identity literals and deliberately
# different identifiers so a hand-spec keyed on a known target would FAIL here.
# ---------------------------------------------------------------------------

# Canonical conservation shape shared by the three fixtures: an internal
# `_withdraw` whose `assets += accruedYield(...)` inflation site over-decrements
# `trackedAssets`, with an external-ERC4626 `previewRedeem` yield lever. Only the
# DEP-INJECTION shape differs between fixtures (ctor / address-cast / constant).
def _iter17_vault(unit, base_decl, init_or_ctor, base_use_in_withdraw=""):
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.28;\n"
        'import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
        'import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";\n'
        f"contract {unit} {{\n"
        "    uint256 public trackedAssets;\n"
        f"    {base_decl}\n"
        "    IERC4626 public stake;\n"
        "    address public rewardSink;\n"
        f"    {init_or_ctor}\n"
        "    function deposit(uint256 a, address r) external returns (uint256) {\n"
        "        trackedAssets += a; return a; }\n"
        "    function activateEpoch() external {}\n"
        "    function setRewardSink(address s) external { rewardSink = s; }\n"
        "    function accruedYield(address caller, uint256) public view returns (uint256) {\n"
        "        if (caller == address(rewardSink)) return stake.previewRedeem(1e18);\n"
        "        return 0; }\n"
        "    function withdraw(uint256 a, address r, address o) external returns (uint256) {\n"
        "        _withdraw(msg.sender, r, o, a, a); return a; }\n"
        "    function _withdraw(address caller, address r, address o, uint256 assets, uint256 shares) internal {\n"
        f"        {base_use_in_withdraw}\n"
        "        assets += accruedYield(caller, shares);\n"
        "        trackedAssets -= assets; }\n"
        "}\n"
    )


# (a) CONSTRUCTOR-injected deps -> non-upgradeable `new Vault(...)` deploy.
_ITER17_CTOR_SRC = _iter17_vault(
    "OrbitVault", "IERC20 public base;",
    "constructor(address o, IERC20 base_, IERC4626 stake_) "
    "{ base = base_; stake = stake_; }")

# (b) ADDRESS-TYPED deps cast in-body to IERC20/IERC4626 -> pass address(mock).
_ITER17_ADDR_SRC = _iter17_vault(
    "CometVault", "IERC20 public base;",
    "function initialize(address o, address base_, address stake_) external "
    "{ base = IERC20(base_); stake = IERC4626(stake_); }")

# (c) HARDCODED-CONSTANT base ERC20 read from a fixed address -> vm.etch.
_ITER17_CONST_SRC = _iter17_vault(
    "PulsarVault",
    "IERC20 public constant base = IERC20(0x2222222222222222222222222222222222222222);",
    "function initialize(address o, IERC4626 stake_) external { stake = stake_; }",
    "uint256 _b = base.balanceOf(address(this)); _b;")


class TestIter17ConstructorDepRouting(unittest.TestCase):
    """iter17 (a): a non-upgradeable vault whose CONSTRUCTOR takes the token deps
    must be routed to a `new Vault(...)` deploy (deploy_mode=constructor), with the
    deps synthesized from the constructor signature."""

    def test_detects_constructor_deploy_mode(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            (proj / "src").mkdir()
            (proj / "src" / "OrbitVault.sol").write_text(_ITER17_CTOR_SRC)
            shape = mod.detect_inplace_vault_deploy_shape(
                _ITER17_CTOR_SRC, proj, "OrbitVault")
            self.assertIsNotNone(shape, "ctor-dep detector must fire")
            self.assertEqual(shape["deploy_mode"], "constructor")
            erc20 = next(m for m in shape["arg_mocks"] if m["is_erc20"])
            self.assertTrue(erc20["synthesize"])
            self.assertEqual(erc20["pass_as"], "instance")

    def test_author_emits_new_vault_not_proxy(self):
        src = _ITER17_CTOR_SRC
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape_c = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            (proj / "src").mkdir()
            (proj / "src" / "OrbitVault.sol").write_text(src)
            tdir = proj / "test"
            tdir.mkdir()
            cand = {"vuln_class": "vault-conservation",
                    "file_line": "src/OrbitVault.sol:18",
                    "rel_path": "src/OrbitVault.sol"}
            shape = mod.detect_inplace_vault_deploy_shape(src, proj, "OrbitVault")
            out = mod.author_vault_conservation_inplace(
                cand, src, "OrbitVault", fn, shape_c, tdir, proj, shape)
            self.assertIsNotNone(out)
            body = out["test_src"]
            self.assertIn("new OrbitVault(", body)       # direct ctor deploy
            self.assertNotIn("ERC1967Proxy", body)       # NOT the proxy path
            self.assertIn("_SynthErc20Dep", body)
            self.assertIn("_SynthErc4626Dep", body)
            self.assertIn("vault.withdraw(", body)       # drives REAL entrypoint
            for sm in out.get("synth_mocks", []):
                Path(sm["path"]).unlink(missing_ok=True)


class TestIter17AddressTypedDepRouting(unittest.TestCase):
    """iter17 (b): an `address X` arg the body casts to IERC20(X)/IERC4626(X) must
    be routed as a token dep and passed to deploy as `address(mock)`, not the
    instance."""

    def test_detects_address_cast_dep(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            (proj / "src").mkdir()
            (proj / "src" / "CometVault.sol").write_text(_ITER17_ADDR_SRC)
            shape = mod.detect_inplace_vault_deploy_shape(
                _ITER17_ADDR_SRC, proj, "CometVault")
            self.assertIsNotNone(shape, "address-typed detector must fire")
            self.assertEqual(shape["deploy_mode"], "initialize")
            erc20 = next(m for m in shape["arg_mocks"] if m["is_erc20"])
            erc4626 = next(m for m in shape["arg_mocks"] if not m["is_erc20"])
            self.assertEqual(erc20["pass_as"], "address")
            self.assertEqual(erc20["type"], "IERC20")
            self.assertEqual(erc4626["type"], "IERC4626")

    def test_author_passes_address_of_mock(self):
        src = _ITER17_ADDR_SRC
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape_c = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            (proj / "src").mkdir()
            (proj / "src" / "CometVault.sol").write_text(src)
            tdir = proj / "test"
            tdir.mkdir()
            cand = {"vuln_class": "vault-conservation",
                    "file_line": "src/CometVault.sol:18",
                    "rel_path": "src/CometVault.sol"}
            shape = mod.detect_inplace_vault_deploy_shape(src, proj, "CometVault")
            out = mod.author_vault_conservation_inplace(
                cand, src, "CometVault", fn, shape_c, tdir, proj, shape)
            self.assertIsNotNone(out)
            body = out["test_src"]
            self.assertIn("address(base)", body)   # address-typed arg passed as addr
            self.assertIn("address(stake)", body)
            self.assertIn("ERC1967Proxy", body)    # upgradeable initialize path
            for sm in out.get("synth_mocks", []):
                Path(sm["path"]).unlink(missing_ok=True)

    def test_non_token_cast_does_not_route(self):
        # HONESTY: an `address` arg cast to a NON-token interface (IPoolManager)
        # must NOT be synthesized as a token dep. With no base ERC20 anywhere the
        # detector returns None -> honest fallback, never a fake mock.
        non_tok = (
            "pragma solidity 0.8.28;\n"
            "contract HVault {\n"
            "    uint256 public trackedAssets; address public mgr;\n"
            "    function initialize(address o, address mgr_) external "
            "{ mgr = mgr_; IPoolManager(mgr_).foo(); }\n"
            "    function deposit(uint256 a, address r) external returns (uint256) {}\n"
            "    function withdraw(uint256 a, address r, address o) external returns (uint256) {}\n"
            "    function activateEpoch() external {}\n"
            "    function _withdraw(uint256 a) internal { trackedAssets -= a; }\n"
            "}\n"
            "interface IPoolManager { function foo() external; }\n"
        )
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            (proj / "src").mkdir()
            (proj / "src" / "HVault.sol").write_text(non_tok)
            self.assertIsNone(
                mod.detect_inplace_vault_deploy_shape(non_tok, proj, "HVault"),
                "non-token cast must not be routed as a synthesizable token dep")
        # the cast classifier itself is honest:
        self.assertIsNone(mod._addr_cast_dep_type(
            "mgr = mgr_; IPoolManager(mgr_).foo();", "mgr_"))
        self.assertEqual(mod._addr_cast_dep_type(
            "base = IERC20(base_);", "base_"), "IERC20")
        self.assertEqual(mod._addr_cast_dep_type(
            "v = IERC4626(s_);", "s_"), "IERC4626")


class TestIter17HardcodedConstantDepRouting(unittest.TestCase):
    """iter17 (c): a token dep the vault reads from a hardcoded constant /
    immutable address must be backed by a synthesized mock vm.etch'd at that
    address, with a typed contract-field handle bound for funding."""

    def test_detects_hardcoded_constant_dep(self):
        deps = mod._hardcoded_constant_deps(_ITER17_CONST_SRC)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["name"], "base")
        self.assertEqual(deps[0]["dep_type"], "IERC20")
        self.assertEqual(deps[0]["addr"],
                         "0x2222222222222222222222222222222222222222")

    def test_immutable_literal_constant_routes(self):
        src = (
            "pragma solidity 0.8.28;\n"
            "contract IVault {\n"
            "    IERC20 immutable base;\n"
            "    constructor() { base = IERC20(0x3333333333333333333333333333333333333333); }\n"
            "    function f() external { base.balanceOf(address(this)); }\n"
            "}\n"
        )
        deps = mod._hardcoded_constant_deps(src)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["addr"],
                         "0x3333333333333333333333333333333333333333")
        self.assertTrue(deps[0]["is_erc20"])

    def test_author_emits_vm_etch_with_field_handle(self):
        src = _ITER17_CONST_SRC
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape_c = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            (proj / "src").mkdir()
            (proj / "src" / "PulsarVault.sol").write_text(src)
            tdir = proj / "test"
            tdir.mkdir()
            cand = {"vuln_class": "vault-conservation",
                    "file_line": "src/PulsarVault.sol:18",
                    "rel_path": "src/PulsarVault.sol"}
            shape = mod.detect_inplace_vault_deploy_shape(src, proj, "PulsarVault")
            self.assertTrue(shape["etch_deps"])
            out = mod.author_vault_conservation_inplace(
                cand, src, "PulsarVault", fn, shape_c, tdir, proj, shape)
            self.assertIsNotNone(out)
            body = out["test_src"]
            self.assertIn(
                "vm.etch(0x2222222222222222222222222222222222222222", body)
            # the etch handle is a CONTRACT FIELD (visible in test fns), assigned
            # in setUp - not a setUp-local that would not compile in test_exploit.
            self.assertIn("_SynthErc20Dep _etch_base_at;", body)
            self.assertIn("_etch_base_at = _SynthErc20Dep(", body)
            self.assertIn("_etch_base_at.mint(", body)   # funds via the handle
            for sm in out.get("synth_mocks", []):
                Path(sm["path"]).unlink(missing_ok=True)


@unittest.skipUnless(
    mod.resolve_forge()
    and mod._find_sibling_oz_and_forge_std(Path.home() / "audits")
    and "@openzeppelin/contracts-upgradeable/" in (
        mod._find_sibling_oz_and_forge_std(Path.home() / "audits") or {}),
    "forge / vendorable OZ-5.x upgradeable sibling unavailable")
class TestIter17RealDeployE2E(unittest.TestCase):
    """iter17 LOAD-BEARING PROOF: each of the three new dep-routing patterns must
    drive the REAL deployed vault to a forge-PASS proof-backed verdict with ZERO
    hand-placed mocks. The deps are synthesized + (b) address-passed + (c) vm.etch'd
    entirely by the pipeline. A fake / hand-placed-mock proof would not reach here
    because the workspaces ship NO mock and the pipeline drives the REAL withdraw."""

    def _prove(self, unit, src):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / f"{unit}.sol").write_text(src)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            # HONESTY: no mock exists on disk pre-run.
            pre = [p for p in ws.rglob("*.sol")
                   if "Mock" in p.name or "mock" in p.read_text().lower()]
            self.assertEqual(pre, [], "no hand-placed mock may exist pre-run")
            wline = next(i for i, l in enumerate(src.split("\n"), 1)
                         if "function _withdraw(" in l)
            cand = mod.load_candidate(_ns(
                contract=unit, fn="_withdraw", vuln_class="vault-conservation",
                file_line=f"src/{unit}.sol:{wline}"))
            res = mod.run_pipeline(cand, ws, None, do_run=True)
            self.assertEqual(res["verdict"], "proof-backed",
                             (res.get("forge_run") or {}).get("raw_tail"))
            self.assertEqual(res["real_proof_mode"],
                             "vault-conservation-inplace-real-deploy")
            self.assertTrue(res["forge_run"]["exploit_pass"])
            self.assertTrue(res["forge_run"]["control_pass"])
            self.assertFalse(res["forge_run"]["compile_fail"])
            # workspace left clean.
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])

    def test_a_constructor_injected_dep_proof_backed(self):
        self._prove("OrbitVault", _ITER17_CTOR_SRC)

    def test_b_address_typed_dep_proof_backed(self):
        self._prove("CometVault", _ITER17_ADDR_SRC)

    def test_c_hardcoded_constant_dep_proof_backed(self):
        self._prove("PulsarVault", _ITER17_CONST_SRC)


class TestProjectSolcPinPrecedence(unittest.TestCase):
    """GAP-B+1 (sandclock-closest +1): the project foundry.toml `solc` pin is
    AUTHORITATIVE for the authored test pragma. It must win over BOTH the cited
    source pragma AND the highest-installed svm minor, because forge run in-place
    compiles the authored test under the project-pinned solc. Empirical anchor:
    sandclock scLiquity source pragma -> highest installed `=0.8.35` while the
    project pins `solc = '0.8.21'` -> forge `No solc version exists that matches
    =0.8.35`. These unit-level assertions are deterministic (no forge needed)."""

    PIN_SRC = "pragma solidity ^0.8.0;\ncontract V {}\n"

    def test_project_pin_beats_source_pragma_and_svm_highest(self):
        installed = mod._installed_solc_minors()
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsolc = '0.8.21'\n")
            picked = mod._derive_test_pragma(self.PIN_SRC, proj)
            # project pin wins over the open source pragma AND svm highest.
            self.assertEqual(picked, "0.8.21",
                             "project foundry.toml solc pin must be authoritative")
            if installed and installed[-1] != 21:
                self.assertNotEqual(
                    picked, f"0.8.{installed[-1]}",
                    "pin must NOT fall back to the svm-highest minor")

    def test_project_pin_beats_conflicting_hard_source_pragma(self):
        # even a CONFLICTING hard source pin loses to the project pin (forge uses
        # the project solc; authoring against the project pin is the only
        # compilable choice).
        src = "pragma solidity =0.8.30;\ncontract V {}\n"
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsolc = '0.8.21'\n")
            self.assertEqual(mod._derive_test_pragma(src, proj), "0.8.21")

    def test_no_project_pin_keeps_source_pragma(self):
        # regression: a project with NO solc pin keeps the existing behavior
        # (source pragma authoritative).
        src = "pragma solidity =0.8.19;\ncontract V {}\n"
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text("[profile.default]\nsrc='src'\n")
            self.assertEqual(mod._derive_test_pragma(src, proj), "0.8.19")

    def test_open_range_project_pin_is_not_authoritative(self):
        # an OPEN-range pin in foundry.toml (`^0.8.X`) is NOT a hard pin; the
        # source pragma still governs.
        src = "pragma solidity =0.8.19;\ncontract V {}\n"
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsolc = '^0.8.0'\n")
            self.assertIsNone(mod._read_project_solc_pin(proj))
            self.assertEqual(mod._derive_test_pragma(src, proj), "0.8.19")

    def test_uninstalled_pin_blocks_with_obligation_naming_solc(self):
        # the run-time preflight: a project pinning a solc that is NOT installed
        # and cannot be bounded-installed must emit a PRECISE
        # compile-blocked-with-obligation naming the missing solc - NEVER a silent
        # fall-back to a different solc the project rejects.
        miss = "0.8.99"  # not a real release; guaranteed absent from svm.
        self.assertFalse(mod._solc_version_installed(miss))
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text(
                f"[profile.default]\nsolc = '{miss}'\n")
            old = os.environ.get("AUDITOOOR_EVM0DAY_NO_SVM_INSTALL")
            os.environ["AUDITOOOR_EVM0DAY_NO_SVM_INSTALL"] = "1"
            try:
                block = mod._preflight_project_solc(proj)
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_EVM0DAY_NO_SVM_INSTALL", None)
                else:
                    os.environ["AUDITOOOR_EVM0DAY_NO_SVM_INSTALL"] = old
            self.assertIsNotNone(block)
            self.assertEqual(block["verdict"], "compile-blocked-with-obligation")
            self.assertIn(miss, block["reason"])
            self.assertIn(miss, block["obligation"])

    def test_installed_pin_passes_preflight(self):
        # a project pin that IS installed passes the preflight (None == proceed).
        installed = mod._installed_solc_minors()
        if not installed:
            self.skipTest("no installed solc store visible")
        ver = f"0.8.{installed[-1]}"
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text(
                f"[profile.default]\nsolc = '{ver}'\n")
            self.assertIsNone(mod._preflight_project_solc(proj))


@unittest.skipUnless(
    mod.resolve_forge()
    and mod._find_sibling_oz_and_forge_std(Path.home() / "audits")
    and "21" in {str(m) for m in mod._installed_solc_minors()},
    "forge / vendorable OZ-5.x sibling / solc 0.8.21 unavailable")
class TestProjectSolcPinE2E(unittest.TestCase):
    """GAP-B+1 LOAD-BEARING PROOF: a vault whose source pragma is OPEN (`^0.8.0`,
    which would derive the svm-highest minor) but whose foundry.toml pins
    `solc = '0.8.21'` must drive a REAL in-place forge-PASS under 0.8.21 -
    exploit-PASS + control-PASS - proving the authored test pragma honors the
    project pin (and does NOT fail `No solc version exists that matches =0.8.35`).
    Gated on forge + a vendorable OZ-5.x sibling + solc 0.8.21 installed; skips
    cleanly otherwise (HONESTY: a missing 0.8.21 would be a blocked-with-obligation
    in production, never a wrong-solc run)."""

    def test_open_pragma_with_project_pin_proof_backed_under_pinned_solc(self):
        src = _read_fixture("project_solc_pin_conservation/MeridianVault.sol")
        toml = _read_fixture("project_solc_pin_conservation/foundry.toml")
        # confirm the fixture really pins a solc that differs from svm highest.
        installed = mod._installed_solc_minors()
        self.assertIn("solc = '0.8.21'", toml)
        if installed and installed[-1] != 21:
            self.assertNotEqual(installed[-1], 21,
                                "test only load-bearing when svm-highest != 21")
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "MeridianVault.sol").write_text(src)
            (ws / "foundry.toml").write_text(toml)
            # HONESTY: no mock exists on disk pre-run.
            pre = [p for p in ws.rglob("*.sol")
                   if "Mock" in p.name or "mock" in p.read_text().lower()]
            self.assertEqual(pre, [], "no hand-placed mock may exist pre-run")
            wline = next(i for i, l in enumerate(src.split("\n"), 1)
                         if "function _withdraw(" in l)
            cand = mod.load_candidate(_ns(
                contract="MeridianVault", fn="_withdraw",
                vuln_class="vault-conservation",
                file_line=f"src/MeridianVault.sol:{wline}"))
            res = mod.run_pipeline(cand, ws, None, do_run=True)
            self.assertEqual(res["verdict"], "proof-backed",
                             (res.get("forge_run") or {}).get("raw_tail"))
            self.assertTrue(res["forge_run"]["exploit_pass"])
            self.assertTrue(res["forge_run"]["control_pass"])
            self.assertFalse(res["forge_run"]["compile_fail"])
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])


# ===========================================================================
# Step 2: EXTERNAL ENTRYPOINT BINDER. An internal/private/library-only cited fn
# is bound to a REAL external/public wrapper that reaches it, so the bug is
# proven THROUGH the public entrypoint. When no public caller reaches the
# internal fn, a SPECIFIC entrypoint obligation is emitted (never a fake proof).
# ===========================================================================

_WRAP_SRC = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.19;\n"
    "contract Wrap {\n"
    "    function deposit(uint256 a, address r) external returns (uint256) {\n"
    "        return _deposit(a, r); }\n"
    "    function _deposit(uint256 a, address r) internal returns (uint256) {\n"
    "        return _credit(a, r); }\n"
    "    function _credit(uint256 a, address r) private returns (uint256) {\n"
    "        return a; }\n"
    "}\n"
)


class TestAllFunctionsAndBodySlice(unittest.TestCase):
    def test_all_functions_lists_every_fn(self):
        names = {f["name"] for f in mod._all_functions(_WRAP_SRC)}
        self.assertEqual(names, {"deposit", "_deposit", "_credit"})

    def test_visibility_parsed(self):
        fns = {f["name"]: f for f in mod._all_functions(_WRAP_SRC)}
        self.assertEqual(fns["deposit"]["visibility"], "external")
        self.assertEqual(fns["_deposit"]["visibility"], "internal")
        self.assertEqual(fns["_credit"]["visibility"], "private")

    def test_body_slice_is_balanced(self):
        fns = {f["name"]: f for f in mod._all_functions(_WRAP_SRC)}
        body = mod._fn_body_slice(_WRAP_SRC, fns["deposit"])
        self.assertIn("_deposit(a, r)", body)
        self.assertTrue(body.strip().startswith("{"))
        self.assertTrue(body.strip().endswith("}"))


class TestExternalEntrypointBinder(unittest.TestCase):
    def test_direct_public_caller_bound(self):
        fns = {f["name"]: f for f in mod._all_functions(_WRAP_SRC)}
        w = mod.find_public_wrapper_for_internal_fn(_WRAP_SRC, fns["_deposit"])
        self.assertIsNotNone(w)
        self.assertEqual(w["wrapper"]["name"], "deposit")
        self.assertEqual(w["via"], "same-unit")

    def test_transitive_public_caller_bound(self):
        # _credit is reached only via deposit -> _deposit -> _credit.
        fns = {f["name"]: f for f in mod._all_functions(_WRAP_SRC)}
        w = mod.find_public_wrapper_for_internal_fn(_WRAP_SRC, fns["_credit"])
        self.assertIsNotNone(w)
        self.assertEqual(w["wrapper"]["name"], "deposit")
        self.assertEqual(w["via"], "same-unit-transitive")

    def test_no_public_caller_returns_none(self):
        src = ("pragma solidity ^0.8.19;\n"
               "contract X {\n"
               "    function _vuln(uint256 a) internal { uint256 b = a; b; }\n"
               "}\n")
        v = next(f for f in mod._all_functions(src) if f["name"] == "_vuln")
        self.assertIsNone(mod.find_public_wrapper_for_internal_fn(src, v))

    def test_descendant_public_caller_bound(self):
        # An abstract base's internal fn is exposed by a concrete child's public fn.
        base = ("pragma solidity ^0.8.19;\n"
                "abstract contract Base {\n"
                "    function _vuln(uint256 a) internal returns (uint256) { return a; }\n"
                "}\n")
        child = ("pragma solidity ^0.8.19;\n"
                 "contract Child is Base {\n"
                 "    function run(uint256 a) external returns (uint256) {\n"
                 "        return _vuln(a); }\n"
                 "}\n")
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "Base.sol").write_text(base)
            (proj / "Child.sol").write_text(child)
            v = next(f for f in mod._all_functions(base) if f["name"] == "_vuln")
            w = mod.find_public_wrapper_for_internal_fn(base, v, proj, "Base")
            self.assertIsNotNone(w)
            self.assertEqual(w["via"], "descendant")
            self.assertEqual(w["descendant_unit"], "Child")
            self.assertEqual(w["wrapper"]["name"], "run")


# ===========================================================================
# Step 3: ERC4626 donation / share-price-inflation FAMILY (share-price
# manipulation CLASS). GENERIC + target-literal-free: routes on the SHAPE.
# ===========================================================================

_FIX_DIR = TOOLS / "tests" / "fixtures" / "evm_zero_day_pipeline"


def _read_fixture(rel):
    return (_FIX_DIR / rel).read_text()


class TestShareInflationDetector(unittest.TestCase):
    def test_fires_on_donation_inflatable_vuln(self):
        src = _read_fixture("erc4626_share_price_vuln/MiniVault.sol")
        shape = mod.detect_share_inflation_shape(src, None)
        self.assertIsNotNone(shape)
        self.assertEqual(shape["deposit_fn"], "deposit")

    def test_skips_virtual_offset_mitigation(self):
        # The clean sibling applies a virtual-shares/assets offset -> NOT the bug.
        src = _read_fixture("erc4626_share_price_clean/MiniVault.sol")
        self.assertIsNone(mod.detect_share_inflation_shape(src, None))

    def test_requires_rounding_down_convert(self):
        # A vault with the donation denominator but NO convertToShares fn / no
        # integer-division convert is not the share-inflation shape.
        src = ("pragma solidity ^0.8.19;\n"
               "contract V {\n"
               "    function totalAssets() public view returns (uint256) {\n"
               "        return token.balanceOf(address(this)); }\n"
               "    function deposit(uint256 a, address r) external returns (uint256) {}\n"
               "}\n")
        self.assertIsNone(mod.detect_share_inflation_shape(src, None))

    def test_requires_deposit_entrypoint(self):
        src = ("pragma solidity ^0.8.19;\n"
               "contract V {\n"
               "    function convertToShares(uint256 a) public view returns (uint256) {\n"
               "        return (a * s) / token.balanceOf(address(this)); }\n"
               "}\n")
        self.assertIsNone(mod.detect_share_inflation_shape(src, None))

    def test_share_inflation_alias(self):
        for a in ("erc4626-inflation", "share-inflation", "first-depositor"):
            self.assertEqual(mod.normalize_vuln_class(a), "share-inflation")


class TestInheritedErc4626ShareInflation(unittest.TestCase):
    """codex95 OBL3: the INHERITED-ERC4626 sub-shape - the vault inherits an
    ERC4626 base (deposit/mint + share math in the base) and overrides ONLY
    `totalAssets()` to a raw `balanceOf(address(this))` read with no guard. The
    in-contract `convertToShares`-fn detector missed this because the math lives
    in the base; the inherited detector binds the surface from the inheritance +
    raw-balance totalAssets override + absence of a first-deposit guard."""

    def _src(self):
        return _read_fixture(
            "inherited_erc4626_share_inflation/InheritedVault.sol")

    def test_fires_on_inherited_erc4626_raw_total_assets(self):
        shape = mod.detect_share_inflation_shape(self._src(), None)
        self.assertIsNotNone(shape)
        self.assertTrue(shape.get("inherited_erc4626"))
        self.assertEqual(shape["deposit_fn"], "deposit")

    def test_natspec_no_dead_shares_prose_does_not_veto(self):
        # GUARD: the fixture's docstring says "no dead shares" / "no virtual
        # offset" in PROSE; comment-stripping must keep the shape detected (the
        # absence of an in-CODE guard is what matters).
        shape = mod.detect_share_inflation_shape(self._src(), None)
        self.assertIsNotNone(shape)

    def test_inherited_guard_present_rejects(self):
        # When the inherited surface DOES carry a built-in guard (virtual offset /
        # dead shares / min first deposit) the donation cannot grief to zero. We
        # inject a `_decimalsOffset` marker as CODE (not prose) into the base.
        base = self._src()
        self.assertIn("function totalAssets() public view virtual", base)
        guarded = base.replace(
            "    function totalAssets() public view virtual returns (uint256);",
            "    function totalAssets() public view virtual returns (uint256);\n"
            "    function _decimalsOffset() internal pure returns (uint8) "
            "{ return 6; }")
        # sanity: the un-guarded original IS detected, the guarded variant is not.
        self.assertIsNotNone(mod.detect_share_inflation_shape(base, None))
        self.assertIsNone(mod.detect_share_inflation_shape(guarded, None))

    def test_obl4_round_down_bookkeeping_does_not_falsely_veto(self):
        # codex95 OBL4(2a): a round-DOWN price-accounting mulDiv (the inflation-
        # PERMITTING direction) is bookkeeping, NOT a first-depositor guard, so it
        # must NOT veto the inherited share-inflation shape. The Pods-class shape
        # was previously false-vetoed by the broad `mulDiv\([^)]*Rounding`
        # alternative.
        base = self._src()
        # inject a round-DOWN bookkeeping mulDiv into the base body (as CODE).
        with_down = base.replace(
            "    function totalAssets() public view virtual returns (uint256);",
            "    function totalAssets() public view virtual returns (uint256);\n"
            "    function _price(uint256 a, uint256 s, uint256 t) internal pure "
            "returns (uint256) { return a.mulDiv(s, t, Math.Rounding.Down); }")
        # the round-DOWN bookkeeping must NOT veto -> shape still detected.
        self.assertIsNotNone(
            mod.detect_share_inflation_shape(with_down, None),
            "round-DOWN bookkeeping mulDiv must not veto the inflation shape")
        # but a real round-UP convert guard MUST still veto.
        with_up = base.replace(
            "    function totalAssets() public view virtual returns (uint256);",
            "    function totalAssets() public view virtual returns (uint256);\n"
            "    function _convUp(uint256 a, uint256 s, uint256 t) internal pure "
            "returns (uint256) { return a.mulDiv(s, t, Math.Rounding.Up); }")
        self.assertIsNone(
            mod.detect_share_inflation_shape(with_up, None),
            "a round-UP convert guard must still veto the inflation shape")

    def test_obl4_inherited_guard_regex_directionality(self):
        # direct guard-regex directionality: round-DOWN/Floor pass (no veto);
        # round-UP + virtual-offset + dead-shares + min-floor veto.
        g = mod._INHERITED_GUARD_RE
        for permitting in ("x.mulDiv(a, b, Math.Rounding.Down)",
                           "x.mulDiv(a, b, Rounding.Floor)",
                           "(a * supply) / totalAssets()"):
            self.assertIsNone(g.search(permitting), permitting)
        for guard in ("x.mulDiv(a, b, Math.Rounding.Up)",
                      "convertToShares(x, Rounding.Up)",
                      "uint8 _decimalsOffset = 6;",
                      "_mint(address(0), 1000);",
                      "require(shares >= MIN_DEPOSIT);"):
            self.assertIsNotNone(g.search(guard), guard)

    def test_in_contract_fixtures_not_misrouted_as_inherited(self):
        # The original in-contract fixtures (no ERC4626 inheritance) must NOT be
        # tagged inherited; their `shares(addr)` accessor still applies.
        for rel in ("erc4626_share_price_vuln/MiniVault.sol",
                    "share_inflation_ctor_constant_dep/PoolVault.sol",
                    "internal_share_inflation_via_wrapper/WrappedVault.sol",
                    "share_inflation_blocked_obligation/DeepGraphVault.sol"):
            shape = mod.detect_share_inflation_shape(_read_fixture(rel), None)
            self.assertIsNotNone(shape, rel)
            self.assertFalse(shape.get("inherited_erc4626"), rel)

    def test_author_emits_inherited_shape_balanceOf_and_decimals_mock(self):
        src = self._src()
        shape = mod.detect_share_inflation_shape(src, None)
        out = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "InheritedVault", {"name": "totalAssets"},
            "./InheritedVault.sol", shape)
        self.assertIsNotNone(out)
        body = out["test_src"]
        # share balance read via the inherited ERC20 balanceOf, not shares().
        self.assertIn("vault.balanceOf(victim)", body)
        self.assertIn("clean.balanceOf(victim)", body)
        self.assertNotIn("vault.shares(", body)
        # asset mock exposes decimals()/name()/symbol() for the base ctor.
        self.assertIn("function decimals()", body)
        self.assertIn("function name()", body)
        # the project-local ctor asset interface is co-imported + the cast typed.
        self.assertIn("import {InheritedVault, IERC20Like}", body)
        self.assertIn("IERC20Like(address(token))", body)
        # the REAL inherited deposit() entrypoint is driven.
        self.assertIn("vault.deposit(", body)
        self.assertIn("test_exploit_totalAssets", body)
        self.assertIn("test_negative_control_totalAssets", body)
        # needs_mocks records the inherited-base asset surface honestly.
        self.assertIn("inherited ERC4626 base", out["needs_mocks"])

    def test_author_no_target_literal_leak(self):
        src = self._src()
        shape = mod.detect_share_inflation_shape(src, None)
        body = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "InheritedVault", {"name": "totalAssets"},
            "./InheritedVault.sol", shape)["test_src"]
        for lit in ("scLiquity", "solmate", "sandclock", "stabilityPool",
                    "MiniVault", "PoolVault", "DeepGraphVault", "pUSDeVault"):
            self.assertNotIn(lit, body)


class TestShareInflationAuthor(unittest.TestCase):
    def test_author_emits_v3_shape_for_single_asset_ctor(self):
        src = _read_fixture("erc4626_share_price_vuln/MiniVault.sol")
        shape = mod.detect_share_inflation_shape(src, None)
        cand = {"vuln_class": "share-inflation", "file_line": "MiniVault.sol:50"}
        out = mod.author_share_inflation_proof(
            cand, src, "MiniVault", {"name": "deposit"},
            "./src/MiniVault.sol", shape)
        self.assertIsNotNone(out)
        body = out["test_src"]
        self.assertIn("test_exploit_deposit", body)
        self.assertIn("test_negative_control_deposit", body)
        self.assertIn("function setUp()", body)        # token deployed in setUp
        self.assertIn("token.transfer(address(vault), DONATION)", body)  # donation
        self.assertIn("vault.deposit(", body)          # real entrypoint driven
        self.assertIn("rounded to 0 shares", body)     # impact asserted
        self.assertIn("V3-GRADE", body)
        self.assertIn("Rule 40", body)
        self.assertIn("new MiniVault(address(token))", body)

    def test_author_rejects_multi_arg_ctor(self):
        # A deep-graph multi-dep ctor whose extra args are CONTRACT DEPENDENCIES
        # (oracle / registry cast to a non-token interface and CALLED in deposit)
        # is still not synthesizable -> None. codex95 OBL4(1) only fills plain
        # role/config address args (admin/keeper - stored / role-granted) with EOAs;
        # a contract-dep address filled with an EOA would revert, so the classifier
        # blocks honestly here (distinct from the multiarg_role_ctor fixture whose
        # extra args are pure role EOAs).
        src = _read_fixture("share_inflation_blocked_obligation/DeepGraphVault.sol")
        shape = mod.detect_share_inflation_shape(src, None)
        self.assertIsNotNone(shape)
        out = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "DeepGraphVault", {"name": "deposit"}, "x", shape)
        self.assertIsNone(out)

    def test_no_target_literal_in_author(self):
        # The authored test for one vault must not leak another vault's identity.
        src = _read_fixture("erc4626_share_price_vuln/MiniVault.sol")
        shape = mod.detect_share_inflation_shape(src, None)
        body = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "MiniVault", {"name": "deposit"}, "./MiniVault.sol", shape)["test_src"]
        for lit in ("pUSDeVault", "yUSDe", "previewYield", "DeepGraphVault",
                    "WrappedVault"):
            self.assertNotIn(lit, body)

    def test_author_co_imports_imported_erc20_typed_ctor(self):
        # FIX 1 approach (b): a ctor asset arg declared with an IMPORTED ERC20
        # type (solmate `ERC20`) is cast to THAT type and the type is co-imported
        # from the cited file so the cast resolves (no hardcoded `IERC20` cast,
        # no Undeclared-identifier).
        src = _read_fixture(
            "solmate_erc20_typed_ctor_share_inflation/TypedAssetVault.sol")
        shape = mod.detect_share_inflation_shape(src, None)
        self.assertIsNotNone(shape)
        body = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "TypedAssetVault", {"name": "deposit"},
            "../src/TypedAssetVault.sol", shape)["test_src"]
        # the cast is to the REAL ctor type, and that type is co-imported.
        self.assertIn("new TypedAssetVault(ERC20(address(token)))", body)
        self.assertIn("import {TypedAssetVault, ERC20}", body)
        # the wrong hardcoded cast must NOT appear, and no orphan interface decl.
        self.assertNotIn("IERC20(address(token))", body)
        self.assertNotIn("interface IERC20", body)

    def test_author_co_emits_interface_decl_for_bare_unimported_iface_ctor(self):
        # FIX 1 approach (a): a ctor asset arg declared with a bare ERC20-shaped
        # interface the cited file does NOT declare or import (`IERC20`) is cast
        # to that type and a MINIMAL `interface IERC20 {...}` is co-emitted so the
        # cast identifier resolves without inventing a target dependency.
        src = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.19;\n"
            "interface IHandle { function balanceOf(address) external view "
            "returns (uint256); }\n"
            "contract BareIfaceVault {\n"
            "    IHandle public asset;\n"
            "    mapping(address=>uint256) public shares;\n"
            "    uint256 public totalSupply;\n"
            "    constructor(IERC20 _asset) { asset = IHandle(address(_asset)); }\n"
            "    function totalAssets() public view returns (uint256) {\n"
            "        return asset.balanceOf(address(this)); }\n"
            "    function convertToShares(uint256 a) public view returns "
            "(uint256) { uint256 s = totalSupply; return s == 0 ? a : "
            "(a * s) / totalAssets(); }\n"
            "    function deposit(uint256 a, address r) external returns "
            "(uint256 x) { x = convertToShares(a); shares[r] += x; "
            "totalSupply += x; }\n"
            "}\n")
        shape = mod.detect_share_inflation_shape(src, None)
        self.assertIsNotNone(shape)
        body = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "BareIfaceVault", {"name": "deposit"}, "../src/X.sol",
            shape)["test_src"]
        # cast to the declared bare type + a co-emitted minimal interface decl.
        self.assertIn("new BareIfaceVault(IERC20(address(token)))", body)
        self.assertIn("interface IERC20 {", body)
        self.assertIn("function balanceOf(address account)", body)
        # the cited file did NOT export IERC20, so it must NOT be co-imported.
        self.assertNotIn("import {BareIfaceVault, IERC20}", body)


class TestShareInflationCtorConstantDep(unittest.TestCase):
    """codex95 OBL2: the scLiquity convert-gap shape - a single-asset-ctor
    donation/inflation vault that references HARDCODED-CONSTANT external deps and
    CALLS METHODS ON THEM IN THE CONSTRUCTOR. A naive `new Vault(asset)` deploy
    reverts because the constant address has no code; the author must synthesize a
    mock per constant dep and vm.etch it at the constant address BEFORE deploy."""

    def _src(self):
        return _read_fixture("share_inflation_ctor_constant_dep/PoolVault.sol")

    def test_constructor_body_extraction(self):
        body = mod._constructor_body(self._src(), "PoolVault")
        self.assertIn("asset = IERC20(_asset)", body)
        self.assertIn("yieldPool.register", body)
        # the convertToShares body must NOT bleed into the ctor body.
        self.assertNotIn("convertToShares", body)

    def test_const_addr_decls_finds_non_token_iface(self):
        decls = mod._const_addr_decls(self._src())
        names = {d["name"] for d in decls}
        self.assertIn("yieldPool", names)
        yp = next(d for d in decls if d["name"] == "yieldPool")
        self.assertEqual(yp["type"], "IYieldPool")
        self.assertEqual(yp["addr"],
                         "0x9999999999999999999999999999999999999999")

    def test_ctor_const_deps_detects_ctor_relevant_dep(self):
        deps = mod._share_inflation_ctor_const_deps(
            self._src(), "PoolVault", "_asset")
        self.assertEqual(len(deps), 1)
        d = deps[0]
        self.assertEqual(d["name"], "yieldPool")
        self.assertEqual(d["addr"],
                         "0x9999999999999999999999999999999999999999")
        # the method the ctor invokes on the dep is recorded for the mock banner.
        self.assertIn("register", d["methods"])

    def test_plain_single_asset_has_no_ctor_const_deps(self):
        # The plain MiniVault (no constant deps) yields an EMPTY list -> the
        # author emits the original template with no etch (no behavior change).
        src = _read_fixture("erc4626_share_price_vuln/MiniVault.sol")
        deps = mod._share_inflation_ctor_const_deps(src, "MiniVault", "_asset")
        self.assertEqual(deps, [])

    def test_author_emits_etch_before_deploy(self):
        src = self._src()
        shape = mod.detect_share_inflation_shape(src, None)
        self.assertIsNotNone(shape)
        out = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "PoolVault", {"name": "deposit"}, "./PoolVault.sol", shape)
        self.assertIsNotNone(out)
        body = out["test_src"]
        # a synthesized constant-dep mock contract is emitted.
        self.assertIn("contract _SynthConstDep0", body)
        # it is vm.etch'd at the EXACT constant address the vault reads.
        self.assertIn(
            "vm.etch(0x9999999999999999999999999999999999999999", body)
        # the etch is staged in setUp (BEFORE _deploy, which runs in the test fns).
        setup_idx = body.index("function setUp()")
        etch_idx = body.index("vm.etch(0x9999")
        deploy_fn_idx = body.index("function _deploy()")
        self.assertLess(setup_idx, etch_idx)
        self.assertLess(etch_idx, deploy_fn_idx)
        # the real entrypoint is still driven + the impact + control are present.
        self.assertIn("vault.deposit(", body)
        self.assertIn("test_exploit_deposit", body)
        self.assertIn("test_negative_control_deposit", body)
        # needs_mocks records the etch'd constant-dep honestly.
        self.assertIn("vm.etch'd constant-dep mock", out["needs_mocks"])

    def test_author_no_target_literal_leak(self):
        # The synthesized mock + etch must not leak any other target's identity.
        src = self._src()
        shape = mod.detect_share_inflation_shape(src, None)
        body = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "PoolVault", {"name": "deposit"}, "./PoolVault.sol", shape)["test_src"]
        for lit in ("scLiquity", "stabilityPool", "usd2eth", "lqty",
                    "pUSDeVault", "yUSDe", "DeepGraphVault"):
            self.assertNotIn(lit, body)


@unittest.skipUnless(
    mod.resolve_forge()
    and mod._find_sibling_oz_and_forge_std(Path.home() / "audits"),
    "forge / vendorable forge-std sibling unavailable")
class TestShareInflationRealRun(unittest.TestCase):
    """Step-3 LOAD-BEARING PROOF: the donation/inflation family must drive the
    REAL deployed vault to a forge-PASS proof-backed verdict with ONLY a
    synthesized inline ERC20 asset mock (external dependency) and a before/after
    share-price assert + no-donation negative control."""

    def _run_fixture(self, fixture_rel, contract, fn):
        src = _read_fixture(fixture_rel)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / Path(fixture_rel).name).write_text(src)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            # HONESTY: no hand-placed mock CONTRACT may exist pre-run. (The
            # check matches mock contract DECLARATIONS, not the word "mock" in a
            # NatSpec docstring - the DeepGraphVault fixture mentions "mocks" in
            # prose while shipping no mock contract.)
            import re as _re
            pre = [p for p in ws.rglob("*.sol")
                   if "Mock" in p.name
                   or _re.search(r"\bcontract\s+\w*[Mm]ock", p.read_text())]
            self.assertEqual(pre, [], "no hand-placed mock contract may exist pre-run")
            wline = next(i for i, l in enumerate(src.split("\n"), 1)
                         if f"function {fn}(" in l)
            cand = mod.load_candidate(_ns(
                contract=contract, fn=fn, vuln_class="share-inflation",
                file_line=f"src/{Path(fixture_rel).name}:{wline}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            # workspace left clean.
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])
            return res

    def test_deployable_donation_inflation_proof_backed(self):
        res = self._run_fixture(
            "erc4626_share_price_vuln/MiniVault.sol", "MiniVault", "deposit")
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_internal_bug_through_public_wrapper_proof_backed(self):
        # Step 2 + Step 3 together: cite the INTERNAL _deposit; the binder routes
        # it to the public deposit wrapper and the donation/inflation author
        # proves the bug THROUGH the real public entrypoint.
        res = self._run_fixture(
            "internal_share_inflation_via_wrapper/WrappedVault.sol",
            "WrappedVault", "_deposit")
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])

    def test_clean_mitigated_fixture_not_proof_backed(self):
        # The mitigated (virtual-offset) sibling must NOT yield a fake proof.
        res = self._run_fixture(
            "erc4626_share_price_clean/MiniVault.sol", "MiniVault", "deposit")
        self.assertNotEqual(res["verdict"], "proof-backed")

    def test_deep_graph_ctor_blocked_with_obligation(self):
        # A donation/inflation shape whose multi-dep ctor is not single-asset
        # synthesizable must block honestly with a PRECISE next action.
        res = self._run_fixture(
            "share_inflation_blocked_obligation/DeepGraphVault.sol",
            "DeepGraphVault", "deposit")
        self.assertEqual(res["verdict"], "blocked-with-obligation")
        self.assertIn("donation/share-price-inflation shape", res["reason"])
        self.assertIn("1-wei-seed", res["obligation"])
        self.assertIn("negative control", res["obligation"])

    def test_inherited_erc4626_share_inflation_proof_backed(self):
        # codex95 OBL3: the INHERITED-ERC4626 sub-shape. The vault inherits an
        # ERC4626 base (deposit/mint + share math in the base) and overrides ONLY
        # totalAssets() to a raw balanceOf(this) read with no guard. The REAL
        # inherited deposit() entrypoint is driven via the 1-wei-seed + donation +
        # victim-deposit sequence; the victim is griefed to 0 shares (read via the
        # inherited ERC20 balanceOf) and the no-donation negative control mints
        # non-zero shares. Real deploy + real inherited entrypoint + synthesized
        # external-dependency asset mock + before/after + negative control.
        # cite the OVERRIDE in the concrete vault (not the abstract base's
        # `totalAssets() ... virtual;` declaration which appears first textually).
        fixture_rel = "inherited_erc4626_share_inflation/InheritedVault.sol"
        src = _read_fixture(fixture_rel)
        override_line = next(
            i for i, l in enumerate(src.split("\n"), 1)
            if "function totalAssets(" in l and "override" in l)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / Path(fixture_rel).name).write_text(src)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            cand = mod.load_candidate(_ns(
                contract="InheritedVault", fn="totalAssets",
                vuln_class="share-inflation",
                file_line=f"src/{Path(fixture_rel).name}:{override_line}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_ctor_constant_dep_etch_proof_backed(self):
        # codex95 OBL2: a single-asset-ctor donation/inflation vault that calls a
        # method on a HARDCODED-CONSTANT dep IN THE CONSTRUCTOR. Without the
        # vm.etch'd constant-dep mock the REAL deploy reverts; WITH it the REAL
        # deposit() entrypoint drives the donation/inflation impact to a forge
        # PASS (real deploy + real entrypoint + synthesized etched mock +
        # before/after + no-donation negative control).
        res = self._run_fixture(
            "share_inflation_ctor_constant_dep/PoolVault.sol",
            "PoolVault", "deposit")
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_obl4_multiarg_role_ctor_inherited_proof_backed(self):
        # codex95 OBL4(1): a MULTI-ARG role+asset ctor on an inherited-ERC4626
        # inflation vault. The ctor is
        #   (address admin, address keeper, IERC20Like asset, string, string).
        # The previous author blocked any ctor with len(params) != 1; the
        # multi-arg classifier now fills admin/keeper with distinct vm.addr() EOAs
        # and the asset slot with the synthesized token, deploys the REAL vault,
        # and drives the inherited deposit() to a forge PASS (real deploy + real
        # inherited entrypoint + synthesized asset mock + before/after + control).
        fixture_rel = ("multiarg_role_ctor_inherited_inflation/"
                       "RoleGatedVault.sol")
        src = _read_fixture(fixture_rel)
        override_line = next(
            i for i, l in enumerate(src.split("\n"), 1)
            if "function totalAssets(" in l and "override" in l)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / Path(fixture_rel).name).write_text(src)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            cand = mod.load_candidate(_ns(
                contract="RoleGatedVault", fn="totalAssets",
                vuln_class="share-inflation",
                file_line=f"src/{Path(fixture_rel).name}:{override_line}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_obl4_oz_override_indirected_proof_backed(self):
        # codex95 OBL4(2b): the cited internal `_deposit` OVERRIDE is reached only
        # through the OZ ERC4626 base's public deposit() (in a SEPARATE imported
        # file, NOT the cited file). No in-cited-file public body literally calls
        # `_deposit(`, so the textual-call binder misses it; the OZ-override-
        # indirected binder step binds the canonical inherited public deposit().
        # The whole multi-file tree is copied so the base compiles; the cited
        # candidate is the vault file only.
        fxdir = (_FIX_DIR / "oz_override_indirected_inflation")
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            shutil.copytree(fxdir, ws / "src" / "oz", dirs_exist_ok=True)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            vault = (ws / "src" / "oz" / "HookOverrideVault.sol").read_text()
            override_line = [
                i for i, l in enumerate(vault.split("\n"), 1)
                if re.search(r"function\s+_deposit\s*\(", l)][-1]
            cand = mod.load_candidate(_ns(
                contract="HookOverrideVault", fn="_deposit",
                vuln_class="share-inflation",
                file_line=f"src/oz/HookOverrideVault.sol:{override_line}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])


class TestInternalBugThroughWrapperBinding(unittest.TestCase):
    """Step 2 binding at the pipeline level (no forge required): citing the
    internal _deposit must NOT block on visibility - the binder re-targets it to
    the public deposit wrapper before authoring."""

    def test_internal_fn_no_public_caller_blocks_with_entrypoint_obligation(self):
        src = ("// SPDX-License-Identifier: MIT\n"
               "pragma solidity ^0.8.19;\n"
               "contract Orphan {\n"
               "    uint256 public totalShares;\n"
               "    function _vuln(uint256 a) internal returns (uint256) {\n"
               "        totalShares += a; return a; }\n"
               "}\n")
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / "Orphan.sol").write_text(src)
            (ws / "foundry.toml").write_text("[profile.default]\nsrc='src'\n")
            wline = next(i for i, l in enumerate(src.split("\n"), 1)
                         if "function _vuln(" in l)
            cand = mod.load_candidate(_ns(
                contract="Orphan", fn="_vuln", vuln_class="business-logic",
                file_line=f"src/Orphan.sol:{wline}"))
            res = mod.run_pipeline(cand, ws, None, do_run=True)
            self.assertEqual(res["verdict"], "blocked-with-obligation")
            self.assertIn("internal-only", res["reason"])
            self.assertIn("external/public", res["obligation"])


class TestObl4MultiArgRoleCtorClassifier(unittest.TestCase):
    """codex95 OBL4(1): the multi-arg role+asset ctor classifier (no forge)."""

    def _params(self, raw):
        return mod._split_params(raw)

    def test_multiarg_role_asset_string_classified(self):
        src = ("contract V is ERC4626 {\n"
               "  constructor(address admin_, address keeper_, IERC20Like asset_,"
               " string memory n_, string memory s_) ERC4626(asset_, n_, s_) {}\n"
               "  function totalAssets() public view override returns (uint256) {\n"
               "    return asset_.balanceOf(address(this)); }\n"
               "}\n")
        params = self._params(
            "address admin_, address keeper_, IERC20Like asset_, "
            "string memory n_, string memory s_")
        cls = mod._classify_share_inflation_ctor(src, "V", params, True)
        self.assertIsNotNone(cls)
        self.assertEqual(cls["asset_name"], "asset_")
        self.assertEqual(cls["asset_type"], "IERC20Like")
        # admin/keeper -> distinct vm.addr() EOAs; strings -> literal; asset slot.
        self.assertEqual(
            cls["args"],
            ["vm.addr(1)", "vm.addr(2)", "<<ASSET>>", '"PoC"', '"PoC"'])
        # the two role EOAs are distinct.
        self.assertEqual(len(set(e for _, e in cls["roles"])), 2)

    def test_two_token_args_block_honestly(self):
        # two ERC20-typed args -> ambiguous asset -> not synthesizable.
        src = "contract V is ERC4626 { }"
        params = self._params("IERC20 a, IERC20 b")
        self.assertIsNone(
            mod._classify_share_inflation_ctor(src, "V", params, True))

    def test_nonsynthesizable_struct_arg_blocks(self):
        # a struct/custom arg that is not the asset -> block honestly.
        src = ("contract V is ERC4626 {\n"
               "  function totalAssets() public view override returns (uint256)"
               " { return asset_.balanceOf(address(this)); }\n}\n")
        params = self._params("IERC20 asset_, Config cfg")
        # asset_ is found, but Config is not a fillable value/role/string type.
        self.assertIsNone(
            mod._classify_share_inflation_ctor(src, "V", params, True))

    def test_value_type_args_filled_with_defaults(self):
        src = ("contract V is ERC4626 {\n"
               "  function totalAssets() public view override returns (uint256)"
               " { return asset_.balanceOf(address(this)); }\n}\n")
        params = self._params(
            "address owner_, IERC20 asset_, uint256 cap_, bool live_")
        cls = mod._classify_share_inflation_ctor(src, "V", params, True)
        self.assertIsNotNone(cls)
        self.assertEqual(cls["args"], ["vm.addr(1)", "<<ASSET>>", "1", "false"])


class TestObl4OzOverrideIndirectedBinder(unittest.TestCase):
    """codex95 OBL4(2b): the OZ-override-indirected entrypoint binder (no forge).
    When the cited internal `_deposit` override is reachable only through an
    out-of-cited-file OZ ERC4626 base, the binder must bind the canonical public
    deposit() rather than miss it."""

    VAULT = (
        "pragma solidity ^0.8.19;\n"
        'import {ERC4626} from "./base.sol";\n'
        "contract V is ERC4626 {\n"
        "  function totalAssets() public view override returns (uint256)"
        " { return asset.balanceOf(address(this)); }\n"
        "  function _deposit(address c, address r, uint256 a, uint256 s)"
        " internal override { _mint(r, s); }\n"
        "}\n")

    def test_oz_indirected_binds_public_deposit(self):
        fns = mod._all_functions(self.VAULT)
        dep = [f for f in fns if f["name"] == "_deposit"][-1]
        self.assertEqual(dep["visibility"], "internal")
        w = mod.find_public_wrapper_for_internal_fn(
            self.VAULT, dep, project=None, unit_name="V")
        self.assertIsNotNone(w)
        self.assertEqual(w["via"], "oz-override-indirected")
        self.assertEqual(w["wrapper"]["name"], "deposit")
        self.assertTrue(w["wrapper"].get("oz_indirected"))

    def test_oz_hook_to_entrypoint_map(self):
        for hook, entry in (("_deposit", "deposit"), ("_mint", "mint"),
                            ("_withdraw", "withdraw"), ("_redeem", "redeem")):
            src = (f"contract V is ERC4626 {{\n"
                   f"  function {hook}(uint256 a) internal override {{}}\n}}\n")
            fn = {"name": hook, "start_line": 2, "body_start": 0}
            res = mod._oz_override_indirected_entrypoint(src, fn)
            self.assertIsNotNone(res, hook)
            self.assertEqual(res["name"], entry)

    def test_non_override_hook_not_indirected(self):
        # a plain (non-override) `_deposit` is handled by the textual binder, not
        # the OZ-indirected step.
        src = ("contract V is ERC4626 {\n"
               "  function _deposit(uint256 a) internal { }\n}\n")
        fn = {"name": "_deposit", "start_line": 2, "body_start": 0}
        self.assertIsNone(mod._oz_override_indirected_entrypoint(src, fn))

    def test_non_erc4626_not_indirected(self):
        # a `_deposit` override in a contract that does NOT inherit ERC4626 is not
        # OZ-indirected.
        src = ("contract V is SomethingElse {\n"
               "  function _deposit(uint256 a) internal override { }\n}\n")
        fn = {"name": "_deposit", "start_line": 2, "body_start": 0}
        self.assertIsNone(mod._oz_override_indirected_entrypoint(src, fn))


class TestGapAFoundryProjectResolution(unittest.TestCase):
    """GAP A: when fresh-target-forward-test.py provisions a workspace IN-TREE,
    it clones the real repo (with its foundry.toml) into <ws>/repo and MIRRORS
    the in-scope src/ into <ws>/src. The cited file then lives under the MIRROR
    (<ws>/src/...), whose ancestors contain NO foundry.toml - the real one is in
    a SIBLING subtree (<ws>/repo). find_enclosing_foundry_project must resolve
    the provisioned repo's foundry project instead of short-circuiting to
    blocked-with-obligation."""

    def _provisioned_ws(self, d):
        """Build a provisioned-layout tmp ws: <ws>/repo (real foundry project)
        + <ws>/src (mirror) + AUDIT_PIN.txt + targets.tsv."""
        ws = Path(d)
        # the real foundry project the provisioner cloned to <ws>/repo.
        repo = ws / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.19;\ncontract Vault {}\n")
        (repo / "foundry.toml").write_text(
            "[profile.default]\nsrc='src'\ntest='test'\n")
        # the MIRROR the engage scan / proof pipeline reads.
        (ws / "src").mkdir()
        (ws / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.19;\ncontract Vault {}\n")
        # provisioning markers.
        (ws / "AUDIT_PIN.txt").write_text("audit-pin: deadbeef\ntarget: o/n\n")
        (ws / "targets.tsv").write_text("# repo\tref\trole\no/n\tdeadbeef\tprimary\n")
        return ws, repo

    def test_resolves_sibling_repo_foundry_project_for_mirror_path(self):
        with tempfile.TemporaryDirectory() as d:
            ws, repo = self._provisioned_ws(d)
            mirror_file = ws / "src" / "Vault.sol"
            # the ANCESTOR walk alone returns None (no foundry.toml above the
            # mirror); the GAP A fallback must resolve the provisioned repo.
            proj = mod.find_enclosing_foundry_project(mirror_file, ws)
            self.assertEqual(proj.resolve(), repo.resolve(),
                             "must resolve the provisioned <ws>/repo foundry project")

    def test_ancestor_walk_still_wins_for_normal_in_project_layout(self):
        # Normal case: the cited file lives INSIDE the foundry project (foundry.toml
        # is an ancestor). The ancestor walk must win and the fallback is not used.
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Vault.sol").write_text("pragma solidity ^0.8.19;\n")
            (ws / "foundry.toml").write_text("[profile.default]\nsrc='src'\n")
            proj = mod.find_enclosing_foundry_project(ws / "src" / "Vault.sol", ws)
            self.assertEqual(proj, ws)

    def test_unprovisioned_source_only_ws_still_blocks_honestly(self):
        # An ordinary source-only ws with NO provisioning marker and NO ancestor
        # foundry.toml must STILL resolve to None (the honest blocked path) - the
        # GAP A fallback must not fabricate a project for an unprovisioned tree.
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Vault.sol").write_text("pragma solidity ^0.8.19;\n")
            self.assertIsNone(
                mod.find_enclosing_foundry_project(ws / "src" / "Vault.sol", ws))

    def test_skips_foundry_toml_inside_dependency_dirs(self):
        # A foundry.toml shipped inside lib/ (a vendored dependency) must NOT be
        # picked as the project root for the mirror; the real <ws>/repo wins.
        with tempfile.TemporaryDirectory() as d:
            ws, repo = self._provisioned_ws(d)
            dep = ws / "src" / "lib" / "somedep"
            dep.mkdir(parents=True)
            (dep / "foundry.toml").write_text("[profile.default]\n")
            proj = mod.find_enclosing_foundry_project(ws / "src" / "Vault.sol", ws)
            self.assertEqual(proj.resolve(), repo.resolve())

    def test_resolve_src_file_in_project_picks_project_copy(self):
        # The mirror file must be re-resolved to the PROJECT's own copy so the
        # authored import stays inside the project tree (no `../../..` escape).
        with tempfile.TemporaryDirectory() as d:
            ws, repo = self._provisioned_ws(d)
            mirror_file = ws / "src" / "Vault.sol"
            resolved = mod._resolve_src_file_in_project(mirror_file, repo)
            self.assertEqual(resolved.resolve(),
                             (repo / "src" / "Vault.sol").resolve())

    def test_resolve_src_file_in_project_noop_when_already_inside(self):
        with tempfile.TemporaryDirectory() as d:
            ws, repo = self._provisioned_ws(d)
            inside = repo / "src" / "Vault.sol"
            self.assertEqual(
                mod._resolve_src_file_in_project(inside, repo).resolve(),
                inside.resolve())


@unittest.skipUnless(mod.resolve_forge(), "forge unavailable")
class TestGapAProvisionedSiblingRealRun(unittest.TestCase):
    """GAP A LOAD-BEARING PROOF: a workspace in the provisioned layout (real repo
    with foundry.toml at <ws>/repo, in-scope src mirrored to <ws>/src) must run
    forge IN-PLACE against the resolved sibling repo project and reach a real
    proof-backed verdict - NOT short-circuit to blocked-with-obligation before
    forge runs (the GAP A bug)."""

    def test_provisioned_sibling_subtree_proof_backed(self):
        src = _read_fixture(
            "share_inflation_view_fn_constant_dep/YieldVault.sol")
        dline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function deposit(" in l)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            # provisioned layout: real foundry project at <ws>/repo + mirror src.
            repo = ws / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "YieldVault.sol").write_text(src)
            (repo / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            (ws / "src").mkdir()
            (ws / "src" / "YieldVault.sol").write_text(src)
            (ws / "AUDIT_PIN.txt").write_text("audit-pin: deadbeef\n")
            (ws / "targets.tsv").write_text(
                "# repo\tref\trole\no/n\tx\tprimary\n")
            # cite the MIRROR path (what the proof pipeline sees post-provision).
            cand = mod.load_candidate(_ns(
                contract="YieldVault", fn="deposit",
                vuln_class="share-inflation",
                file_line=f"src/YieldVault.sol:{dline}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            # the provisioned repo tree is left clean.
            self.assertEqual(list(repo.rglob("_evm0day_autoproof")), [])
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])


class TestGapBPragmaDerive(unittest.TestCase):
    """GAP B (pragma derive): the authored test pragma must DERIVE from the cited
    source / repo solc and resolve to an INSTALLED version, not a hardcoded
    0.8.28 (which fails `No solc version exists that matches =0.8.28` when the
    repo pins a different minor)."""

    def test_pinned_pragma_is_preserved_exactly(self):
        # a pinned `=0.8.X` must NOT silently become 0.8.28.
        self.assertEqual(mod._pick_solc("=0.8.21"), "0.8.21")
        self.assertEqual(mod._pick_solc("0.8.17"), "0.8.17")

    def test_open_range_picks_installed_minor_at_or_above_floor(self):
        installed = mod._installed_solc_minors()
        if not installed:
            self.skipTest("no installed solc store visible")
        picked = mod._pick_solc("^0.8.19")
        m = re.fullmatch(r"0\.8\.(\d+)", picked)
        self.assertIsNotNone(m)
        minor = int(m.group(1))
        self.assertGreaterEqual(minor, 19)
        self.assertIn(minor, installed,
                      "open-range pick must be an INSTALLED minor")

    def test_derive_test_pragma_reads_source_pragma(self):
        src = "pragma solidity =0.8.21;\ncontract V {}\n"
        self.assertEqual(mod._derive_test_pragma(src), "0.8.21")

    def test_derive_test_pragma_falls_back_to_foundry_toml(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsolc = '0.8.23'\n")
            # source has no pragma -> derive from the foundry.toml pin.
            self.assertEqual(
                mod._derive_test_pragma("contract V {}\n", proj), "0.8.23")

    def test_authored_share_inflation_pragma_is_not_hardcoded_28(self):
        # A vault pinned to a non-28 minor must produce a test pragma matching the
        # source, not the old hardcoded 0.8.28.
        src = _read_fixture(
            "share_inflation_view_fn_constant_dep/YieldVault.sol")
        # force a pinned non-28 pragma to prove the derive is source-driven.
        src_pinned = re.sub(r"pragma solidity[^;]+;",
                            "pragma solidity =0.8.21;", src, count=1)
        shape = mod.detect_share_inflation_shape(src_pinned, None)
        out = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src_pinned,
            "YieldVault", {"name": "deposit"}, "./YieldVault.sol", shape)
        body = out["test_src"]
        self.assertIn("pragma solidity 0.8.21;", body)
        self.assertNotIn("pragma solidity 0.8.28;", body)


class TestGapBViewFnConstantDep(unittest.TestCase):
    """GAP B (const-dep-read-in-view-fn): a hardcoded-constant dependency READ
    inside the exploited share-price view fn (totalAssets/convertToShares/...),
    NOT a ctor arg and NOT touched in the constructor, must be detected + etch'd
    so the exploit does not revert reading the un-etched constant address."""

    def _src(self):
        return _read_fixture(
            "share_inflation_view_fn_constant_dep/YieldVault.sol")

    def test_view_fn_const_dep_detected_even_though_not_ctor_relevant(self):
        src = self._src()
        # the const dep is NOT referenced in the ctor body -> obl2 ctor-relevance
        # alone would have SKIPPED it (the GAP this fix closes).
        ctor_body = mod._constructor_body(src, "YieldVault")
        self.assertNotIn("stabilityPool", ctor_body)
        # GAP B: the dep is detected via the share-price VIEW fns it is read in
        # (totalAssets/convertToShares), with OR without the cited exploited fn.
        dline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function deposit(" in l)
        fn = mod._fn_at_line(src, dline)
        deps = mod._share_inflation_ctor_const_deps(
            src, "YieldVault", "_asset", fn)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["name"], "stabilityPool")
        self.assertEqual(deps[0]["addr"],
                         "0x7777777777777777777777777777777777777777")
        self.assertIn("deposited", deps[0]["methods"])

    def test_const_dep_read_only_in_cited_exploited_fn_body_detected(self):
        # Tighten the GAP B contract: a const dep read ONLY in the cited exploited
        # fn body (not in any of the standard share-price view fns) is still
        # detected via the exploited_fn body scan. A dep in NO traversed body and
        # NOT ctor-relevant is NOT detected (no spurious etch).
        src = (
            "pragma solidity ^0.8.19;\n"
            "contract V {\n"
            "  IDep public constant onlyInExploit ="
            " IDep(0x1111111111111111111111111111111111111111);\n"
            "  IDep public constant unused ="
            " IDep(0x2222222222222222222222222222222222222222);\n"
            "  constructor(address a) {}\n"
            "  function pull(uint256 x) external returns (uint256) {\n"
            "    return onlyInExploit.value();\n"  # read ONLY in the cited fn
            "  }\n"
            "}\n"
            "interface IDep { function value() external view returns (uint256); }\n")
        pline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function pull(" in l)
        fn = mod._fn_at_line(src, pline)
        deps = mod._share_inflation_ctor_const_deps(src, "V", "a", fn)
        names = {d["name"] for d in deps}
        self.assertIn("onlyInExploit", names,
                      "dep read in the cited exploited fn must be detected")
        self.assertNotIn("unused", names,
                         "a dep read nowhere must NOT be etch'd")

    def test_author_etches_view_fn_const_dep_before_deploy(self):
        src = self._src()
        shape = mod.detect_share_inflation_shape(src, None)
        out = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "YieldVault", {"name": "deposit"}, "./YieldVault.sol", shape)
        self.assertIsNotNone(out)
        body = out["test_src"]
        self.assertIn("contract _SynthConstDep0", body)
        self.assertIn(
            "vm.etch(0x7777777777777777777777777777777777777777", body)
        setup_idx = body.index("function setUp()")
        etch_idx = body.index("vm.etch(0x7777")
        deploy_fn_idx = body.index("function _deploy()")
        self.assertLess(setup_idx, etch_idx)
        self.assertLess(etch_idx, deploy_fn_idx)
        self.assertIn("vm.etch'd constant-dep mock", out["needs_mocks"])

    def test_no_target_literal_leak(self):
        src = self._src()
        shape = mod.detect_share_inflation_shape(src, None)
        body = mod.author_share_inflation_proof(
            {"vuln_class": "share-inflation", "file_line": "x:1"}, src,
            "YieldVault", {"name": "deposit"}, "./YieldVault.sol",
            shape)["test_src"]
        for lit in ("scLiquity", "sandclock", "stabilityPool", "usd2eth",
                    "Pods", "Maple", "Cap", "Punk", "PoolVault"):
            self.assertNotIn(lit, body)


@unittest.skipUnless(
    mod.resolve_forge()
    and mod._find_sibling_oz_and_forge_std(Path.home() / "audits"),
    "forge / vendorable forge-std sibling unavailable")
class TestGapBViewFnConstDepRealRun(unittest.TestCase):
    """GAP B LOAD-BEARING PROOF: the view-fn const-dep vault must drive the REAL
    deployed vault to a forge-PASS proof-backed verdict (the etch reaches the
    un-ctor const dep read inside totalAssets()); the too-deep sibling must block
    HONESTLY with a precise next action."""

    def _run_fixture(self, fixture_rel, contract, fn):
        src = _read_fixture(fixture_rel)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / Path(fixture_rel).name).write_text(src)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            # HONESTY: no hand-placed mock contract may exist pre-run.
            import re as _re
            pre = [p for p in ws.rglob("*.sol")
                   if "Mock" in p.name
                   or _re.search(r"\bcontract\s+\w*[Mm]ock", p.read_text())]
            self.assertEqual(pre, [], "no hand-placed mock contract pre-run")
            wline = next(i for i, l in enumerate(src.split("\n"), 1)
                         if f"function {fn}(" in l)
            cand = mod.load_candidate(_ns(
                contract=contract, fn=fn, vuln_class="share-inflation",
                file_line=f"src/{Path(fixture_rel).name}:{wline}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])
            return res

    def test_view_fn_const_dep_etch_proof_backed(self):
        res = self._run_fixture(
            "share_inflation_view_fn_constant_dep/YieldVault.sol",
            "YieldVault", "deposit")
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_view_fn_const_dep_too_deep_blocked_with_obligation(self):
        res = self._run_fixture(
            "share_inflation_view_fn_const_dep_blocked/DeepConstDepVault.sol",
            "DeepConstDepVault", "deposit")
        self.assertEqual(res["verdict"], "blocked-with-obligation")
        # the obligation is precise (deploy + drive + assert + negative control).
        self.assertIn("1-wei-seed", res["obligation"])
        self.assertIn("negative control", res["obligation"])


class TestCommonLibraryVendoring(unittest.TestCase):
    """Common-library (solmate / OpenZeppelin) vendoring - the generalization of
    the forge-std vendoring/remapping mechanism. These are pure-logic unit tests
    (no forge required): they assert the import classifier, the sibling-solmate
    discovery, the augmented OZ+solmate mapping, the synthesized standalone
    remappings, and the env disable hook."""

    def test_common_lib_import_classifier(self):
        # solmate + bare-OZ + scoped-OZ + forge-std prefixes are recognized; an
        # application/protocol-coupled import is NOT classified as a common lib.
        blob = ('import {ERC20} from "solmate/tokens/ERC20.sol";\n'
                'import {Address} from "openzeppelin-contracts/utils/Address.sol";\n'
                'import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
                'import {Test} from "forge-std/Test.sol";\n'
                'import {IConfigurationManager} from "../interfaces/IConfig.sol";\n')
        c = mod._common_lib_imports(blob)
        self.assertTrue(c["solmate"])
        self.assertTrue(c["oz"])
        self.assertTrue(c["forge_std"])
        # only solmate/OZ/forge-std are classified - the protocol-coupled
        # application dep is deliberately NOT a recognized common-library prefix.
        self.assertEqual(set(c.keys()), {"solmate", "oz", "forge_std"})

    def test_common_lib_classifier_negative(self):
        c = mod._common_lib_imports('import {Foo} from "../local/Foo.sol";\n')
        self.assertFalse(c["solmate"])
        self.assertFalse(c["oz"])
        self.assertFalse(c["forge_std"])

    def test_synthesize_remappings_skips_when_no_common_lib(self):
        # a test importing ONLY forge-std needs no solmate/OZ synthesis -> None
        # (caller keeps its forge-std baseline).
        fstd = mod.find_forge_std()
        if fstd is None:
            self.skipTest("no forge-std checkout to anchor the test")
        m = mod._synthesize_common_lib_remappings(
            'import {Test} from "forge-std/Test.sol";\n', fstd)
        self.assertIsNone(m)

    def test_env_disable_hook_suppresses_vendoring(self):
        fstd = mod.find_forge_std()
        if fstd is None:
            self.skipTest("no forge-std checkout to anchor the test")
        blob = 'import {ERC20} from "solmate/tokens/ERC20.sol";\n'
        prev = os.environ.get(mod._NO_COMMON_LIB_VENDOR_ENV)
        try:
            os.environ[mod._NO_COMMON_LIB_VENDOR_ENV] = "1"
            self.assertTrue(mod._common_lib_vendor_disabled())
            # with the hook set, no solmate is discovered and no mapping built.
            self.assertIsNone(mod._find_sibling_solmate(fstd.parent))
            self.assertIsNone(mod._synthesize_common_lib_remappings(blob, fstd))
        finally:
            if prev is None:
                os.environ.pop(mod._NO_COMMON_LIB_VENDOR_ENV, None)
            else:
                os.environ[mod._NO_COMMON_LIB_VENDOR_ENV] = prev

    @unittest.skipUnless(
        mod._find_sibling_solmate(Path.home() / "audits" / "_nonexistent")
        or list((Path.home() / "audits").rglob("solmate/src/mixins/ERC4626.sol"))
        if (Path.home() / "audits").exists() else False,
        "no vendorable solmate checkout under ~/audits")
    def test_sibling_solmate_discovered_and_valid(self):
        solmate = mod._find_sibling_solmate(Path.home() / "audits" / "_nope")
        self.assertIsNotNone(solmate)
        self.assertTrue(mod._solmate_src_is_valid(solmate))
        self.assertTrue(solmate.as_posix().endswith("/src"))

    @unittest.skipUnless(
        mod._find_sibling_oz_and_forge_std(Path.home() / "audits"),
        "no vendorable OZ+forge-std sibling under ~/audits")
    def test_oz_mapping_carries_bare_prefix_and_solmate(self):
        m = mod._find_sibling_oz_and_forge_std(Path.home() / "audits")
        # the bare `openzeppelin-contracts/` prefix maps to the SAME contracts
        # root as the scoped `@openzeppelin/contracts/` prefix (foundry-default).
        self.assertIn("openzeppelin-contracts/", m)
        self.assertEqual(m["openzeppelin-contracts/"], m["@openzeppelin/contracts/"])
        # solmate is added to the mapping when a vendorable checkout exists.
        if (Path.home() / "audits").exists() and list(
                (Path.home() / "audits").rglob("solmate/src/mixins/ERC4626.sol")):
            self.assertIn("solmate/", m)
            self.assertTrue(mod._solmate_src_is_valid(m["solmate/"]))

    @unittest.skipUnless(
        mod.find_forge_std()
        and ((Path.home() / "audits").exists() and list(
            (Path.home() / "audits").rglob("solmate/src/mixins/ERC4626.sol"))),
        "no forge-std + solmate to anchor the standalone-runner remap test")
    def test_standalone_runner_writes_common_lib_remappings(self):
        fstd = mod.find_forge_std()
        test_src = ('// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\n'
                    'import {ERC20} from "solmate/tokens/ERC20.sol";\n'
                    'import {Test} from "forge-std/Test.sol";\n'
                    'contract T is Test {}\n')
        proj = mod.build_standalone_runner(fstd, test_src, "^0.8.19")
        try:
            toml = (proj / "foundry.toml").read_text()
            # the synthesized remappings include solmate (vendored from a sibling).
            self.assertIn("solmate/=", toml)
            self.assertIn("forge-std/=", toml)
        finally:
            shutil.rmtree(proj, ignore_errors=True)


@unittest.skipUnless(
    mod.resolve_forge()
    and ((Path.home() / "audits").exists() and list(
        (Path.home() / "audits").rglob("solmate/src/mixins/ERC4626.sol")))
    and mod._find_sibling_oz_and_forge_std(Path.home() / "audits"),
    "forge / vendorable solmate / vendorable OZ sibling unavailable")
class TestCommonLibVendoringRealRun(unittest.TestCase):
    """LOAD-BEARING PROOF for the common-library vendoring lift: an UNSEEN vault
    that imports the real solmate (ERC20 / SafeTransferLib / FixedPointMathLib)
    AND OpenZeppelin (bare `openzeppelin-contracts/Address`) common libraries
    must drive the converter to author a harness that COMPILES (solmate + OZ
    resolved via the synthesized remappings, mirroring the forge-std mechanism)
    and reaches a real forge exploit-PASS + control-PASS. Without the vendoring
    the project would compile-block on the unresolved solmate/OZ imports."""

    def _run_fixture(self, fixture_rel, contract, fn):
        src = _read_fixture(fixture_rel)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / Path(fixture_rel).name).write_text(src)
            # ship NO installed deps + NO remappings.txt -> the converter must
            # synthesize the solmate/OZ remappings itself (the lift under test).
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            # HONESTY: no hand-placed mock contract may exist pre-run.
            import re as _re
            pre = [p for p in ws.rglob("*.sol")
                   if "Mock" in p.name
                   or _re.search(r"\bcontract\s+\w*[Mm]ock", p.read_text())]
            self.assertEqual(pre, [], "no hand-placed mock contract pre-run")
            wline = next(i for i, l in enumerate(src.split("\n"), 1)
                         if f"function {fn}(" in l)
            cand = mod.load_candidate(_ns(
                contract=contract, fn=fn, vuln_class="share-inflation",
                file_line=f"src/{Path(fixture_rel).name}:{wline}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [],
                             "workspace must be left clean")
            return res

    def test_solmate_oz_importing_vault_proof_backed(self):
        res = self._run_fixture(
            "solmate_oz_common_lib_share_inflation/LibVault.sol",
            "LibVault", "deposit")
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_erc20_typed_ctor_asset_arg_proof_backed(self):
        # FIX 1 (approach (b), the sandclock scLiquity blocker): a vault whose
        # constructor declares the asset arg with the solmate `ERC20` type forces
        # the converter to cast the synthesized token to that ctor type AND emit
        # the matching `ERC20` import. Before the fix the converter emitted a
        # hardcoded `IERC20(address(token))` cast with no import -> solc Error 7576
        # Undeclared identifier. This proves the authored harness now COMPILES and
        # reaches a real exploit-PASS + control-PASS on the interface-cast-ctor
        # shape.
        res = self._run_fixture(
            "solmate_erc20_typed_ctor_share_inflation/TypedAssetVault.sol",
            "TypedAssetVault", "deposit")
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"], "deployable-in-place")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_disable_hook_blocks_with_obligation_not_refuted(self):
        # HONESTY: with common-lib vendoring DISABLED the solmate/OZ imports
        # cannot resolve, so the verdict must be an honest blocked-with-obligation
        # (compile-blocked), NEVER refuted.
        prev = os.environ.get(mod._NO_COMMON_LIB_VENDOR_ENV)
        try:
            os.environ[mod._NO_COMMON_LIB_VENDOR_ENV] = "1"
            res = self._run_fixture(
                "solmate_oz_common_lib_share_inflation/LibVault.sol",
                "LibVault", "deposit")
        finally:
            if prev is None:
                os.environ.pop(mod._NO_COMMON_LIB_VENDOR_ENV, None)
            else:
                os.environ[mod._NO_COMMON_LIB_VENDOR_ENV] = prev
        self.assertNotEqual(res["verdict"], "refuted",
                            "an unresolved common-lib import must never refute")
        self.assertNotEqual(res["verdict"], "proof-backed",
                            "vendoring disabled -> imports cannot resolve")


class TestObl9AppDepIfaceCtorWiring(unittest.TestCase):
    """obl9-prep CAPABILITY 1 (no forge): the in-place vault-conservation author
    wires the committed protocol-dep mock synthesizer for an APPLICATION-LEVEL
    interface initializer param (a config-manager-style `IYieldConfig` with a
    settable cap getter), and keeps the honest block-with-obligation when the
    app-dep is un-synthesizable (its only called member returns a struct)."""

    SYNTH_FIX = ("conservation_app_dep_iface_ctor/AppDepVault.sol")
    BLOCK_FIX = ("conservation_app_dep_unsynth_block/UnsynthAppDepVault.sol")

    def _author(self, fixture_rel, contract):
        src = _read_fixture(fixture_rel)
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape_c = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "src").mkdir()
            (proj / "src" / Path(fixture_rel).name).write_text(src)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            tdir = proj / "test"
            tdir.mkdir()
            shape = mod.detect_inplace_vault_deploy_shape(src, proj, contract)
            self.assertIsNotNone(shape, "deploy detector must fire")
            cand = {"vuln_class": "vault-conservation",
                    "file_line": f"src/{Path(fixture_rel).name}:18",
                    "rel_path": f"src/{Path(fixture_rel).name}"}
            out = mod.author_vault_conservation_inplace(
                cand, src, contract, fn, shape_c, tdir, proj, shape)
            # capture synthesized mock SOURCES while the temp dir is still alive
            # (the gen-dir files live under the tempdir and vanish on exit).
            if out is not None:
                out["_mock_sources"] = {
                    sm["name"]: Path(sm["path"]).read_text()
                    for sm in out.get("synth_mocks", [])
                    if Path(sm["path"]).exists()}
            return out, shape

    def test_app_dep_iface_param_present_in_shape(self):
        # the app-dep interface param stays in initializer_params even though the
        # token-only arg_mocks router does not pick it up.
        _out, shape = self._author(self.SYNTH_FIX, "AppDepVault")
        types = [t for (t, _n) in shape["initializer_params"]]
        self.assertIn("IYieldConfig", types)

    def test_author_synthesizes_app_dep_mock(self):
        out, _shape = self._author(self.SYNTH_FIX, "AppDepVault")
        self.assertIsNotNone(out, "app-dep wiring must author a real-deploy test")
        body = out["test_src"]
        # the synthesized protocol-dep mock is referenced + constructed + passed.
        self.assertIn("_SynthProtoDep", body)
        self.assertRegex(body, r"_SynthProtoDep\d+ config;")
        self.assertRegex(body, r"config = new _SynthProtoDep\d+\(\);")
        self.assertIn("AppDepVault.initialize.selector", body)
        # the mock file was written to gen_dir and is tracked for cleanup.
        proto = [sm for sm in out["synth_mocks"]
                 if "_SynthProtoDep" in sm["name"]]
        self.assertEqual(len(proto), 1)
        mock_src = out["_mock_sources"][proto[0]["name"]]
        # settable getter the exploit could drive + the obl7 banner.
        self.assertIn("maxYieldBps", mock_src)
        self.assertIn("setMaxYieldBps", mock_src)
        self.assertIn("protocol-coupled dependency mock", mock_src)

    def test_no_target_literal_leak(self):
        out, _shape = self._author(self.SYNTH_FIX, "AppDepVault")
        body = out["test_src"]
        for lit in ("scLiquity", "sandclock", "stabilityPool", "Liquity",
                    "pUSDeVault", "PoolVault", "yUSDe"):
            self.assertNotIn(lit, body, f"target literal '{lit}' leaked")

    def test_unsynthesizable_app_dep_blocks_honestly(self):
        # the app-dep's only called member returns a struct -> the structured
        # report is non-ready -> the in-place author keeps the honest block
        # (returns None), NEVER a fabricated non-compiling mock.
        out, _shape = self._author(self.BLOCK_FIX, "UnsynthAppDepVault")
        self.assertIsNone(out, "un-synthesizable app-dep must block, not fabricate")

    def test_app_dep_synth_helper_success_with_evidence(self):
        iface = ("interface IGate { function canCall(address who, bytes32 tag) "
                 "external view returns (bool); }")
        with tempfile.TemporaryDirectory() as d:
            out = mod._synthesize_app_dep_mock(
                "IGate", ["canCall"], iface, Path(d), "0.8.28", 0,
                return_values={"canCall(address,bytes32)": ["true"]},
                negative_control_behavior={
                    "canCall(address,bytes32)": "clean path covers gate behavior"
                })
            self.assertTrue(out["ready"])
            self.assertEqual(out["name"], "_SynthProtoDep0")
            body = Path(out["path"]).read_text()
            self.assertIn("function canCall", body)
            self.assertIn("return true", body)

    def test_app_dep_synth_helper_missing_negative_control(self):
        iface = ("interface IYieldConfig { function maxYieldBps() external "
                 "view returns (uint256); }")
        with tempfile.TemporaryDirectory() as d:
            out = mod._synthesize_app_dep_mock(
                "IYieldConfig", ["maxYieldBps"], iface, Path(d), "0.8.28", 1)
            self.assertFalse(out["ready"])
            self.assertIsNone(out["path"])
            self.assertTrue(any("missing-negative-control-behavior" in o
                                for o in out["obligations"]))

    def test_app_dep_synth_helper_missing_return_value(self):
        iface = ("interface IGate { function canCall(address who, bytes32 tag) "
                 "external view returns (bool); }")
        with tempfile.TemporaryDirectory() as d:
            out = mod._synthesize_app_dep_mock(
                "IGate", ["canCall"], iface, Path(d), "0.8.28", 2,
                negative_control_behavior={
                    "canCall(address,bytes32)": "clean path covers gate behavior"
                })
            self.assertFalse(out["ready"])
            self.assertTrue(any("missing-return-values" in o
                                for o in out["obligations"]))

    def test_app_dep_synth_helper_struct_return_is_non_ready(self):
        # direct helper check: a struct-returning member is un-defaultable.
        iface = ("interface IRegistryView { function getConfig() external view "
                 "returns (ConfigData memory); }")
        with tempfile.TemporaryDirectory() as d:
            out = mod._synthesize_app_dep_mock(
                "IRegistryView", ["getConfig"], iface, Path(d), "0.8.28", 3,
                negative_control_behavior={
                    "getConfig()": "clean path covers registry behavior"
                })
            self.assertFalse(out["ready"])
            self.assertTrue(any("missing-return-values" in o
                                for o in out["obligations"]))

    def test_app_dep_obligations_propagate_to_blocked_verdict(self):
        src = _read_fixture(self.BLOCK_FIX)
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape_c = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "src").mkdir()
            src_file = proj / "src" / Path(self.BLOCK_FIX).name
            src_file.write_text(src)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            cand = {"vuln_class": "vault-conservation",
                    "file_line": f"src/{src_file.name}:{wline}",
                    "rel_path": f"src/{src_file.name}"}
            res = mod._attempt_inplace_vault_conservation(
                cand, src, "UnsynthAppDepVault", fn, shape_c, src_file,
                proj, None)
        self.assertIsNotNone(res)
        self.assertEqual(res["verdict"], "blocked-with-obligation")
        self.assertFalse(res["mock_synthesis_ready"])
        self.assertTrue(any("missing-return-values" in o
                            for o in res["mock_synthesis_obligations"]))
        self.assertIn("missing-return-values", res["obligation"])

    def test_is_app_dep_iface_type_excludes_tokens(self):
        self.assertTrue(mod._is_app_dep_iface_type("IYieldConfig"))
        self.assertTrue(mod._is_app_dep_iface_type("IPoolManager"))
        self.assertFalse(mod._is_app_dep_iface_type("IERC20"))
        self.assertFalse(mod._is_app_dep_iface_type("IERC4626"))
        self.assertFalse(mod._is_app_dep_iface_type("address"))
        self.assertFalse(mod._is_app_dep_iface_type("uint256"))


@unittest.skipUnless(
    mod.resolve_forge()
    and mod._find_sibling_oz_and_forge_std(Path.home() / "audits")
    and "@openzeppelin/contracts-upgradeable/" in (
        mod._find_sibling_oz_and_forge_std(Path.home() / "audits") or {}),
    "forge / vendorable OZ-5.x upgradeable sibling unavailable")
class TestObl9AppDepIfaceCtorRealRun(unittest.TestCase):
    """obl9-prep CAPABILITY 1 LOAD-BEARING PROOF: the app-dep synth must drive the
    REAL deployed conservation vault (whose initializer calls into an app-level
    interface dep) to a forge-PASS proof-backed verdict. Without the synthesized
    deployable app-dep mock the REAL initializer's external call on a code-less
    address reverts; WITH it the real withdraw entrypoint reaches the cited
    accumulator-over-decrement (exploit-PASS) and the no-yield negative control
    conserves exactly (control-PASS)."""

    def test_app_dep_conservation_proof_backed(self):
        fixture_rel = "conservation_app_dep_iface_ctor/AppDepVault.sol"
        src = _read_fixture(fixture_rel)
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / Path(fixture_rel).name).write_text(src)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            cand = mod.load_candidate(_ns(
                contract="AppDepVault", fn="_withdraw",
                vuln_class="vault-conservation",
                file_line=f"src/{Path(fixture_rel).name}:{wline}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
            self.assertEqual(list(ws.rglob("_evm0day_autoproof")), [])
        self.assertEqual(res["verdict"], "proof-backed",
                         (res.get("forge_run") or {}).get("raw_tail"))
        self.assertEqual(res["real_proof_mode"],
                         "vault-conservation-inplace-real-deploy")
        self.assertTrue(res["forge_run"]["exploit_pass"])
        self.assertTrue(res["forge_run"]["control_pass"])
        self.assertFalse(res["forge_run"]["compile_fail"])

    def test_unsynthesizable_app_dep_pipeline_not_refuted(self):
        # the honest-block half must NOT refute the candidate end-to-end.
        fixture_rel = "conservation_app_dep_unsynth_block/UnsynthAppDepVault.sol"
        src = _read_fixture(fixture_rel)
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src").mkdir()
            (ws / "src" / Path(fixture_rel).name).write_text(src)
            (ws / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            cand = mod.load_candidate(_ns(
                contract="UnsynthAppDepVault", fn="_withdraw",
                vuln_class="vault-conservation",
                file_line=f"src/{Path(fixture_rel).name}:{wline}"))
            res = mod.run_pipeline(cand, ws, ws / "_ev", do_run=True)
        # the app-dep in-place author blocks honestly; the pipeline must never
        # report `refuted` for a real (if un-deployable-in-place) conservation bug.
        self.assertNotEqual(res["verdict"], "refuted")


class TestObl9ForkModeEmission(unittest.TestCase):
    """obl9-prep CAPABILITY 2 (no forge): the authored harness EMITS
    `vm.createSelectFork(...)` in setUp when a fork RPC is configured (per-run
    field OR env var) and does NOT when no fork config is present. A real forked
    run is OPT-IN and fork-gated (see TestObl9ForkModeRealRun)."""

    FIX = "conservation_app_dep_iface_ctor/AppDepVault.sol"

    def _author(self, deploy_shape_extra):
        src = _read_fixture(self.FIX)
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape_c = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "src").mkdir()
            (proj / "src" / Path(self.FIX).name).write_text(src)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            tdir = proj / "test"
            tdir.mkdir()
            shape = mod.detect_inplace_vault_deploy_shape(
                src, proj, "AppDepVault")
            shape.update(deploy_shape_extra)
            out = mod.author_vault_conservation_inplace(
                {"vuln_class": "vault-conservation",
                 "file_line": f"src/{Path(self.FIX).name}:18",
                 "rel_path": f"src/{Path(self.FIX).name}"},
                src, "AppDepVault", fn, shape_c, tdir, proj, shape)
            for sm in (out or {}).get("synth_mocks", []):
                Path(sm["path"]).unlink(missing_ok=True)
            return out["test_src"]

    def test_no_fork_config_does_not_emit(self):
        body = self._author({})
        self.assertNotIn("createSelectFork", body)

    def test_per_run_fork_field_emits(self):
        body = self._author({"fork_rpc": "mainnet", "fork_block": 19000000})
        self.assertIn('vm.createSelectFork("mainnet", 19000000);', body)
        # the fork line precedes the deploy in setUp.
        self.assertLess(body.index("createSelectFork"),
                        body.index("vault = _deploy();"))

    def test_per_run_fork_field_without_block_emits_single_arg(self):
        body = self._author({"fork_rpc": "https://eth.example/rpc"})
        self.assertIn('vm.createSelectFork("https://eth.example/rpc");', body)

    def test_env_fork_rpc_emits(self):
        prev = os.environ.get("AUDITOOOR_EVM0DAY_FORK_RPC")
        os.environ["AUDITOOOR_EVM0DAY_FORK_RPC"] = "wss://node/ws"
        try:
            body = self._author({})
        finally:
            if prev is None:
                os.environ.pop("AUDITOOOR_EVM0DAY_FORK_RPC", None)
            else:
                os.environ["AUDITOOOR_EVM0DAY_FORK_RPC"] = prev
        self.assertIn('vm.createSelectFork("wss://node/ws");', body)

    def test_resolve_fork_config_helper(self):
        self.assertIsNone(mod._resolve_fork_config({}))
        cfg = mod._resolve_fork_config({"fork_rpc": "mainnet", "fork_block": 5})
        self.assertEqual(cfg, {"rpc": "mainnet", "block": 5})
        # non-int block is dropped, not crashed.
        cfg2 = mod._resolve_fork_config({"fork_rpc": "x", "fork_block": "abc"})
        self.assertEqual(cfg2, {"rpc": "x", "block": None})

    def test_fork_select_stmt_helper(self):
        self.assertEqual(mod._fork_select_stmt({"rpc": "mainnet", "block": None}),
                         '        vm.createSelectFork("mainnet");')
        self.assertEqual(mod._fork_select_stmt({"rpc": "u", "block": 7}),
                         '        vm.createSelectFork("u", 7);')


@unittest.skipUnless(
    os.environ.get("AUDITOOOR_EVM0DAY_FORK_RPC")
    and mod.resolve_forge()
    and mod._find_sibling_oz_and_forge_std(Path.home() / "audits"),
    "fork RPC (AUDITOOOR_EVM0DAY_FORK_RPC) / forge / OZ sibling unavailable")
class TestObl9ForkModeRealRun(unittest.TestCase):
    """obl9-prep CAPABILITY 2 OPTIONAL real-fork proof: gated on an actual fork
    RPC so it SKIPS cleanly in CI without a provider. The real fork run is driven
    in the separate forward phase; here we only assert the authored harness runs
    against forked state when an RPC is configured."""

    def test_fork_run_executes_against_forked_state(self):
        fixture_rel = "conservation_app_dep_iface_ctor/AppDepVault.sol"
        src = _read_fixture(fixture_rel)
        wline = next(i for i, l in enumerate(src.split("\n"), 1)
                     if "function _withdraw(" in l)
        fn = mod._fn_at_line(src, wline)
        shape_c = mod.detect_vault_conservation_shape(src, fn)
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            (proj / "src").mkdir()
            (proj / "src" / Path(fixture_rel).name).write_text(src)
            (proj / "foundry.toml").write_text("[profile.default]\n")
            tdir = proj / "test"
            tdir.mkdir()
            shape = mod.detect_inplace_vault_deploy_shape(
                src, proj, "AppDepVault")
            out = mod.author_vault_conservation_inplace(
                {"vuln_class": "vault-conservation",
                 "file_line": f"src/{Path(fixture_rel).name}:{wline}",
                 "rel_path": f"src/{Path(fixture_rel).name}"},
                src, "AppDepVault", fn, shape_c, tdir, proj, shape)
            self.assertIsNotNone(out)
            self.assertIn("createSelectFork", out["test_src"])
            for sm in out.get("synth_mocks", []):
                Path(sm["path"]).unlink(missing_ok=True)


def _ns(**kw):
    import argparse
    ns = argparse.Namespace(candidate_json=None, contract=None, fn=None,
                            vuln_class=None, file_line="")
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


if __name__ == "__main__":
    unittest.main()
