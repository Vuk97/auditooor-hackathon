"""Tests for the shared trusted-corpus resolver (PR2b)."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "trusted_corpus_resolver", ROOT / "tools" / "lib" / "trusted_corpus_resolver.py"
)
tcr = importlib.util.module_from_spec(_spec)
# Register in sys.modules before exec so dataclass module resolution works on 3.14.
sys.modules["trusted_corpus_resolver"] = tcr
_spec.loader.exec_module(tcr)


class TestTrustedCorpusResolver(unittest.TestCase):
    def setUp(self) -> None:
        # Clear env that could leak between tests.
        for k in ("AUDITOOOR_TRUSTED_CORPUS_INDEX", "AUDITOOOR_CORPUS_TRUST_DIR",
                  "INCLUDE_ADVISORY"):
            os.environ.pop(k, None)

    def test_raw_fallback_when_index_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_raw:
            tmp = Path(tmp_raw)
            res = tcr.resolve_active_corpus(repo_root_path=tmp)
            self.assertEqual(res.trust_scope, "raw-fallback")
            self.assertTrue(res.is_fallback)
            self.assertIn("audit/corpus_tags", res.primary_path)
            self.assertFalse(tcr.trusted_index_available(tmp))

    def test_active_when_index_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_raw:
            tmp = Path(tmp_raw)
            idx = tmp / "reference" / "corpus_trust" / "TRUSTED_CORPUS_INDEX.jsonl"
            idx.parent.mkdir(parents=True)
            idx.write_text('{"id":"x","trust_state":"active"}\n', encoding="utf-8")
            res = tcr.resolve_active_corpus(repo_root_path=tmp)
            self.assertEqual(res.trust_scope, "active")
            self.assertFalse(res.is_fallback)
            self.assertEqual(res.primary_path, str(idx))
            self.assertTrue(tcr.trusted_index_available(tmp))

    def test_advisory_added_with_include_advisory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_raw:
            tmp = Path(tmp_raw)
            ct = tmp / "reference" / "corpus_trust"
            ct.mkdir(parents=True)
            (ct / "TRUSTED_CORPUS_INDEX.jsonl").write_text('{"id":"x"}\n', encoding="utf-8")
            (ct / "CORPUS_TRUST_LEDGER.jsonl").write_text('{"id":"adv"}\n', encoding="utf-8")
            res = tcr.resolve_active_corpus(repo_root_path=tmp, include_advisory=True)
            self.assertEqual(res.trust_scope, "advisory")
            self.assertEqual(len(res.extra_paths), 1)

    def test_empty_index_is_not_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_raw:
            tmp = Path(tmp_raw)
            idx = tmp / "reference" / "corpus_trust" / "TRUSTED_CORPUS_INDEX.jsonl"
            idx.parent.mkdir(parents=True)
            idx.write_text("", encoding="utf-8")  # empty
            res = tcr.resolve_active_corpus(repo_root_path=tmp)
            self.assertEqual(res.trust_scope, "raw-fallback")

    def test_env_override_index_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_raw:
            tmp = Path(tmp_raw)
            alt = tmp / "alt_index.jsonl"
            alt.write_text('{"id":"x"}\n', encoding="utf-8")
            os.environ["AUDITOOOR_TRUSTED_CORPUS_INDEX"] = str(alt)
            try:
                res = tcr.resolve_active_corpus(repo_root_path=tmp)
                self.assertEqual(res.trust_scope, "active")
                self.assertEqual(res.primary_path, str(alt))
            finally:
                os.environ.pop("AUDITOOOR_TRUSTED_CORPUS_INDEX", None)

    def test_annotate_stamps_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_raw:
            res = tcr.resolve_active_corpus(repo_root_path=Path(tmp_raw))
            payload: dict = {"foo": 1}
            tcr.annotate(payload, res)
            self.assertIn("corpus_trust", payload)
            self.assertEqual(payload["corpus_trust"]["trust_scope"], "raw-fallback")


if __name__ == "__main__":
    unittest.main()
