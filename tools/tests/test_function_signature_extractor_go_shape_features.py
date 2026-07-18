"""Wave-14 tests: Go body-shape features for tools/function-signature-extractor.py.

The body features break the file-level shape_hash collapse FP. See
audit/postmortems/wave14-ranker-file-level-fp-2026-05-11.md.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "function-signature-extractor.py"
SHAPE_PATH = REPO_ROOT / "tools" / "shape-hash.py"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "fn_sig_extractor_go"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class GoBodyFeaturesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fse = _load("_fse_w14", TOOL_PATH)
        self.sh = _load("_sh_w14", SHAPE_PATH)
        sample_text = (FIXTURE_DIR / "sample.go").read_text()
        self.recs = self.fse.extract_go_functions(sample_text, "sample.go")
        self.by_name = {r["function_name"]: r for r in self.recs}

    def test_body_features_present(self) -> None:
        for name, rec in self.by_name.items():
            self.assertIn("body_features", rec, f"missing body_features on {name}")
            bf = rec["body_features"]
            for k in ("line_bucket", "call_bucket", "returns_error", "return_count"):
                self.assertIn(k, bf, f"{name} body_features missing {k}")

    def test_returns_error_flag(self) -> None:
        ra = self.by_name["RegisterAffiliate"]
        self.assertEqual(ra["body_features"]["returns_error"], 1)
        helper = self.by_name["unexportedHelper"]
        # unexportedHelper returns only int - no error
        self.assertEqual(helper["body_features"]["returns_error"], 0)

    def test_line_bucket_categorisation(self) -> None:
        # unexportedHelper has a 1-line body → xs bucket
        helper = self.by_name["unexportedHelper"]
        self.assertEqual(helper["body_features"]["line_bucket"], "xs")

    def test_call_bucket_categorisation(self) -> None:
        # RegisterAffiliate has > 0 calls, helper has 0
        ra = self.by_name["RegisterAffiliate"]
        self.assertNotEqual(ra["body_features"]["call_bucket"], "0")
        helper = self.by_name["unexportedHelper"]
        self.assertEqual(helper["body_features"]["call_bucket"], "0")

    def test_shape_hash_fine_consumes_body_features(self) -> None:
        # Construct two records with identical param/return signature but
        # different bodies; their shape_hash_fine MUST differ now.
        rec_a = dict(self.by_name["RegisterAffiliate"])
        rec_b = dict(rec_a)
        rec_b["body_features"] = dict(rec_a["body_features"])
        rec_b["body_features"]["line_bucket"] = "xl"
        rec_b["body_features"]["call_bucket"] = "11+"
        h_a = self.sh.compute_shape_hash(
            language="go",
            params=rec_a.get("params"),
            return_types=rec_a.get("return_types"),
            visibility=rec_a.get("visibility"),
            guards_detected=rec_a.get("guards_detected"),
            receiver_type=rec_a.get("receiver_type"),
            fine=True,
            body_features=rec_a.get("body_features"),
        )
        h_b = self.sh.compute_shape_hash(
            language="go",
            params=rec_b.get("params"),
            return_types=rec_b.get("return_types"),
            visibility=rec_b.get("visibility"),
            guards_detected=rec_b.get("guards_detected"),
            receiver_type=rec_b.get("receiver_type"),
            fine=True,
            body_features=rec_b.get("body_features"),
        )
        self.assertNotEqual(h_a, h_b, "body_features did not differentiate shape_hash_fine")

    def test_legacy_coarse_hash_unchanged(self) -> None:
        # The coarse shape_hash MUST NOT be affected by body_features.
        rec = self.by_name["RegisterAffiliate"]
        h_no_body = self.sh.compute_shape_hash(
            language="go",
            params=rec.get("params"),
            return_types=rec.get("return_types"),
            visibility=rec.get("visibility"),
            guards_detected=rec.get("guards_detected"),
            receiver_type=rec.get("receiver_type"),
            fine=False,
        )
        h_with_body = self.sh.compute_shape_hash(
            language="go",
            params=rec.get("params"),
            return_types=rec.get("return_types"),
            visibility=rec.get("visibility"),
            guards_detected=rec.get("guards_detected"),
            receiver_type=rec.get("receiver_type"),
            fine=False,
            body_features=rec.get("body_features"),
        )
        self.assertEqual(h_no_body, h_with_body)


if __name__ == "__main__":
    unittest.main()
