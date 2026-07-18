"""Regression tests for tools/spark-poi-scope-verifier.py (S1)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "spark-poi-scope-verifier.py"
FIXTURES = REPO / "tools" / "detectors" / "fixtures" / "s1_poi_scope"


def _load_module():
    """Import the hyphenated CLI script as a module."""
    spec = importlib.util.spec_from_file_location("spark_poi_scope_verifier", TOOL)
    assert spec and spec.loader, "could not build spec for tool"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SparkPoiScopeVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    # --- per-path classification ----------------------------------------
    def test_classify_path_listed_asset(self) -> None:
        r = self.mod.classify_path("buildonspark/spark/coordinator/lib.rs")
        self.assertEqual(r["classification"], "listed-asset")

    def test_classify_path_btkn_listed_asset(self) -> None:
        r = self.mod.classify_path("buildonspark/BTKN/contracts/token.sol")
        self.assertEqual(r["classification"], "listed-asset")

    def test_classify_path_frost_is_poi_placeholder(self) -> None:
        r = self.mod.classify_path("lightsparkdev/frost/src/keys.rs")
        self.assertEqual(r["classification"], "PoI-placeholder")

    def test_classify_path_btcsuite_is_poi_placeholder(self) -> None:
        r = self.mod.classify_path("btcsuite/btcd/wire/msgblock.go")
        self.assertEqual(r["classification"], "PoI-placeholder")

    def test_classify_path_lightspark_rs_is_redirect(self) -> None:
        r = self.mod.classify_path("lightsparkdev/lightspark-rs/src/client.rs")
        self.assertEqual(r["classification"], "REDIRECT")

    def test_classify_path_lightspark_go_sdk_is_redirect(self) -> None:
        r = self.mod.classify_path("lightsparkdev/go-sdk/client.go")
        self.assertEqual(r["classification"], "REDIRECT")

    def test_classify_path_unknown_lightspark_repo_redirects_by_default(self) -> None:
        # SCOPE.md:71 excludes all lightsparkdev/* programs except frost.
        r = self.mod.classify_path("lightsparkdev/some-future-product/src/main.rs")
        self.assertEqual(r["classification"], "REDIRECT")

    def test_classify_path_testnet_drops(self) -> None:
        r = self.mod.classify_path("buildonspark/spark/testnet/mock_signer.go")
        self.assertEqual(r["classification"], "DROP")

    def test_classify_path_mocks_dir_drops(self) -> None:
        r = self.mod.classify_path("buildonspark/spark/coordinator/mocks/fake_db.go")
        self.assertEqual(r["classification"], "DROP")

    def test_classify_path_unknown(self) -> None:
        r = self.mod.classify_path("some/random/unknown-repo/file.go")
        self.assertEqual(r["classification"], "UNKNOWN")

    # --- draft-level aggregation ---------------------------------------
    def test_draft_pos_listed_asset(self) -> None:
        text = (FIXTURES / "pos_listed_asset.md").read_text(encoding="utf-8")
        result = self.mod.classify_draft(text)
        self.assertEqual(result["recommended_selector"], "listed-asset")
        self.assertGreater(len(result["paths"]), 0)
        self.assertEqual(result["confidence"], "high")

    def test_draft_pos_poi_placeholder(self) -> None:
        text = (FIXTURES / "pos_poi_placeholder.md").read_text(encoding="utf-8")
        result = self.mod.classify_draft(text)
        self.assertEqual(result["recommended_selector"], "PoI-placeholder")
        self.assertEqual(result["confidence"], "high")

    def test_draft_pos_redirect(self) -> None:
        text = (FIXTURES / "pos_redirect.md").read_text(encoding="utf-8")
        result = self.mod.classify_draft(text)
        self.assertEqual(result["recommended_selector"], "REDIRECT")

    def test_draft_pos_drop_testnet(self) -> None:
        text = (FIXTURES / "pos_drop_testnet.md").read_text(encoding="utf-8")
        result = self.mod.classify_draft(text)
        self.assertEqual(result["recommended_selector"], "DROP")

    # --- CLI round-trips ----------------------------------------------
    def test_cli_classify_path_json(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--classify-path",
             "buildonspark/spark/coordinator/lib.rs", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["recommended_selector"], "listed-asset")

    def test_cli_draft_json(self) -> None:
        draft = FIXTURES / "pos_redirect.md"
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(draft), "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["recommended_selector"], "REDIRECT")


if __name__ == "__main__":
    unittest.main()
