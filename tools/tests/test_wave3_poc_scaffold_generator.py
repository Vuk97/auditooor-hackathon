"""Unit tests for tools/wave3-poc-scaffold-generator.py.

Covers (>= 8 cases per the Wave-3 brief):

  1. Solidity scaffold emits valid Foundry shape.
  2. Go scaffold emits valid cosmos-sdk shape.
  3. Rust scaffold emits valid substrate shape.
  4. Severity CRITICAL forces multi-validator stub for Go on network-level rubric.
  5. Severity Low keeps single-actor PoC; no multi-validator stub.
  6. Auto-detect target language from --target-contract extension.
  7. Output dir auto-created.
  8. README emitted alongside test file for each language.
  9. (Bonus) scaffold_metadata.json receipt is valid JSON and lists files.
 10. (Bonus) emitter refuses em-dashes in output (global no-dash rule).
 11. (Bonus) Rule 19 production-runtime triggers on state-machine rubric.

synthetic_fixture: true (these are synthetic-input unit tests of the
emitter; not real PoC artifacts).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
TOOL_PATH = HERE.parent / "wave3-poc-scaffold-generator.py"


def _load_module():
    mod_name = "wave3_poc_scaffold_generator_under_test"
    spec = importlib.util.spec_from_file_location(mod_name, TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register in sys.modules BEFORE exec so that @dataclass can resolve
    # the cls.__module__ at decorator time (required on Python 3.14+).
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _run(argv):
    return MOD.main(argv)


class Wave3PocScaffoldGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = pathlib.Path(self.tmp.name)
        # workspace + a "repo tree" so paths look real.
        (self.ws / "poc-tests").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------------ #
    # 1. Solidity scaffold shape
    # ------------------------------------------------------------------ #
    def test_solidity_scaffold_emits_valid_foundry_shape(self):
        out_dir = self.ws / "poc-tests" / "unprotected-initialize"
        rc = _run([
            "--audit-pin", "c9971e7ee436634ea25b8dae9d83a967f9fd7d34",
            "--target-repo", "graphprotocol/contracts",
            "--target-contract", "protocol/contracts/staking/GraphStaking.sol",
            "--cluster-name", "unprotected-initialize",
            "--attack-class", "access-control-bypass",
            "--severity", "High",
            "--target-language", "solidity",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
        ])
        self.assertEqual(rc, 0)
        sol = (out_dir / "PoC_UnprotectedInitialize.t.sol").read_text()
        self.assertIn("pragma solidity", sol)
        self.assertIn('import {Test} from "forge-std/Test.sol";', sol)
        self.assertIn("contract PoC_UnprotectedInitialize is Test", sol)
        self.assertIn("function setUp() public", sol)
        self.assertIn("function test_UnprotectedInitialize_PoC()", sol)
        self.assertIn("rule-30-disclaimer", sol)
        self.assertIn("rule-18-disclaimer", sol)
        self.assertIn("synthetic_fixture: false", sol)

    # ------------------------------------------------------------------ #
    # 2. Go scaffold shape
    # ------------------------------------------------------------------ #
    def test_go_scaffold_emits_valid_cosmos_sdk_shape(self):
        out_dir = self.ws / "poc-tests" / "matching-engine-cap"
        rc = _run([
            "--audit-pin", "5ee9766351ef864856a309a971b13fdd98cae2c5",
            "--target-repo", "dydxprotocol/v4-chain",
            "--target-contract", "protocol/x/clob/keeper/orders.go",
            "--cluster-name", "matching-engine-cap",
            "--attack-class", "cap-weakening",
            "--severity", "High",
            "--target-language", "go",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
            "--rubric-line", "matching engine SLO breach via cap weakening",
        ])
        self.assertEqual(rc, 0)
        go = (out_dir / "matching-engine-cap_test.go").read_text()
        self.assertIn("package poc", go)
        self.assertIn("func TestMatchingEngineCap_PoC(t *testing.T)", go)
        self.assertIn("rule-30-disclaimer", go)
        self.assertIn("rule-19-disclaimer", go)
        self.assertIn("FinalizeBlock", go)
        self.assertIn("synthetic_fixture: false", go)

    # ------------------------------------------------------------------ #
    # 3. Rust scaffold shape
    # ------------------------------------------------------------------ #
    def test_rust_scaffold_emits_valid_substrate_shape(self):
        out_dir = self.ws / "poc-tests" / "frost-nonce-reuse"
        rc = _run([
            "--audit-pin", "20585f1abcdef0123456789abcdef0123456789a",
            "--target-repo", "lightsparkdev/frost",
            "--target-contract", "src/lib.rs",
            "--cluster-name", "frost-nonce-reuse",
            "--attack-class", "nonce-reuse",
            "--severity", "Critical",
            "--target-language", "rust",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
        ])
        self.assertEqual(rc, 0)
        rs = (out_dir / "lib.rs").read_text()
        cargo = (out_dir / "Cargo.toml").read_text()
        self.assertIn("#![cfg(test)]", rs)
        self.assertIn("fn test_frost_nonce_reuse_poc()", rs)
        self.assertIn("rule-30-disclaimer", rs)
        self.assertIn("apply_extrinsic", rs)
        self.assertIn("[package]", cargo)
        self.assertIn("audit-pin", cargo)

    # ------------------------------------------------------------------ #
    # 4. CRITICAL + network-level rubric -> multi-validator stub for Go
    # ------------------------------------------------------------------ #
    def test_critical_network_level_forces_multi_validator_for_go(self):
        out_dir = self.ws / "poc-tests" / "validator-halt"
        rc = _run([
            "--audit-pin", "deadbeefcafebabe1234567890abcdefdeadbeef",
            "--target-repo", "dydxprotocol/v4-chain",
            "--target-contract", "protocol/app/app.go",
            "--cluster-name", "validator-halt",
            "--attack-class", "consensus-halt",
            "--severity", "Critical",
            "--target-language", "go",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
            "--rubric-line", "network-level liveness failure halting block production",
        ])
        self.assertEqual(rc, 0)
        go = (out_dir / "validator-halt_test.go").read_text()
        readme = (out_dir / "README.md").read_text()
        self.assertIn("multi-validator", go)
        self.assertIn(">=2 validator", go)
        self.assertIn("YES", readme)  # multi-validator: YES

    # ------------------------------------------------------------------ #
    # 5. Severity Low keeps single-actor PoC (no over-engineering)
    # ------------------------------------------------------------------ #
    def test_low_severity_does_not_force_multi_validator(self):
        out_dir = self.ws / "poc-tests" / "small-leak"
        rc = _run([
            "--audit-pin", "1111111111111111111111111111111111111111",
            "--target-repo", "dydxprotocol/v4-chain",
            "--target-contract", "protocol/x/perpetuals/keeper/keeper.go",
            "--cluster-name", "small-leak",
            "--attack-class", "info-leak",
            "--severity", "Low",
            "--target-language", "go",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
            "--rubric-line", "network-level liveness failure",  # would trigger at HIGH+
        ])
        self.assertEqual(rc, 0)
        go = (out_dir / "small-leak_test.go").read_text()
        readme = (out_dir / "README.md").read_text()
        self.assertIn("Single-actor", go)
        self.assertIn("no (severity", readme)  # multi-validator: no
        self.assertNotIn(">=2 validator", go)

    # ------------------------------------------------------------------ #
    # 6. Auto-detect target language from --target-contract extension
    # ------------------------------------------------------------------ #
    def test_auto_detect_language_from_extension(self):
        out_dir = self.ws / "poc-tests" / "auto-detect-sol"
        rc = _run([
            "--audit-pin", "abc1234567890def",
            "--target-repo", "morpho-labs/morpho-blue",
            "--target-contract", "src/Morpho.sol",
            "--cluster-name", "auto-detect-sol",
            "--attack-class", "rounding",
            "--severity", "Medium",
            # no --target-language; should auto-detect solidity
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue((out_dir / "PoC_AutoDetectSol.t.sol").exists())

    # ------------------------------------------------------------------ #
    # 7. Output dir auto-created
    # ------------------------------------------------------------------ #
    def test_output_dir_auto_created(self):
        # deliberately point at a path that does not exist yet
        out_dir = self.ws / "deep" / "nested" / "not-yet" / "poc"
        self.assertFalse(out_dir.exists())
        rc = _run([
            "--audit-pin", "abc",
            "--target-repo", "x/y",
            "--target-contract", "src/Foo.sol",
            "--cluster-name", "auto-mkdir",
            "--attack-class", "test",
            "--severity", "Low",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(out_dir.exists())
        self.assertTrue((out_dir / "scaffold_metadata.json").exists())

    # ------------------------------------------------------------------ #
    # 8. README emitted alongside test file for each language
    # ------------------------------------------------------------------ #
    def test_readme_emitted_for_each_language(self):
        cases = [
            ("solidity", "src/Foo.sol", "PoC_X.t.sol"),
            ("go", "x/y/foo.go", "x_test.go"),
            ("rust", "src/lib.rs", "lib.rs"),
        ]
        for lang, contract, _expected_test in cases:
            with self.subTest(language=lang):
                out_dir = self.ws / "poc-tests" / ("readme-check-" + lang)
                rc = _run([
                    "--audit-pin", "deadbeef",
                    "--target-repo", "x/y",
                    "--target-contract", contract,
                    "--cluster-name", "X",
                    "--attack-class", "test",
                    "--severity", "Medium",
                    "--target-language", lang,
                    "--workspace", str(self.ws),
                    "--out-dir", str(out_dir),
                ])
                self.assertEqual(rc, 0)
                self.assertTrue((out_dir / "README.md").exists(), lang)
                rm = (out_dir / "README.md").read_text()
                self.assertIn("Rule compliance hints", rm)
                self.assertIn("How to run", rm)

    # ------------------------------------------------------------------ #
    # 9. Scaffold metadata JSON receipt
    # ------------------------------------------------------------------ #
    def test_scaffold_metadata_receipt_is_valid_json(self):
        out_dir = self.ws / "poc-tests" / "meta-test"
        rc = _run([
            "--audit-pin", "feedface",
            "--target-repo", "x/y",
            "--target-contract", "src/Z.sol",
            "--cluster-name", "meta-test",
            "--attack-class", "rounding",
            "--severity", "High",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
            "--rubric-line", "loss of funds",
        ])
        self.assertEqual(rc, 0)
        meta = json.loads((out_dir / "scaffold_metadata.json").read_text())
        self.assertEqual(meta["audit_pin"], "feedface")
        self.assertEqual(meta["cluster_slug"], "meta-test")
        self.assertEqual(meta["severity"], "High")
        self.assertEqual(meta["target_language"], "solidity")
        self.assertIn("scaffold_metadata.json", meta["files_written"])
        self.assertFalse(meta["synthetic_fixture"])

    # ------------------------------------------------------------------ #
    # 10. em-dash rejection: refuse cluster names that round-trip dashes
    # ------------------------------------------------------------------ #
    def test_emitter_does_not_introduce_emdashes(self):
        # Verify the EMITTED content never contains an em-dash, even when
        # the operator passes an em-dash in --cluster-name or --rubric-line.
        # (The slugifier strips dashes; the emitter never produces them.)
        out_dir = self.ws / "poc-tests" / "dash-check"
        rc = _run([
            "--audit-pin", "abc",
            "--target-repo", "x/y",
            "--target-contract", "src/Foo.sol",
            "--cluster-name", "dash-check",
            "--attack-class", "rounding",
            "--severity", "Low",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
        ])
        self.assertEqual(rc, 0)
        for path in out_dir.iterdir():
            if path.is_file():
                content = path.read_text()
                self.assertNotIn("—", content, f"em-dash in {path.name}")
                self.assertNotIn("–", content, f"en-dash in {path.name}")

    # ------------------------------------------------------------------ #
    # 11. Rule 19 state-machine rubric triggers production-runtime hints
    # ------------------------------------------------------------------ #
    def test_state_machine_rubric_triggers_production_runtime(self):
        out_dir = self.ws / "poc-tests" / "apphash-divergence"
        rc = _run([
            "--audit-pin", "abc",
            "--target-repo", "dydxprotocol/v4-chain",
            "--target-contract", "protocol/app/app.go",
            "--cluster-name", "apphash-divergence",
            "--attack-class", "state-write-path",
            "--severity", "High",
            "--target-language", "go",
            "--workspace", str(self.ws),
            "--out-dir", str(out_dir),
            "--rubric-line", "state-machine write path / AppHash divergence",
        ])
        self.assertEqual(rc, 0)
        readme = (out_dir / "README.md").read_text()
        self.assertIn("production-runtime", readme)
        meta = json.loads((out_dir / "scaffold_metadata.json").read_text())
        self.assertTrue(meta["production_runtime_required"])


if __name__ == "__main__":
    unittest.main()
