"""Tests for tools/wave2-w26-cosmos-dedup-verify.py.

The verifier is loaded by module path because the filename uses
hyphens. Synthetic manifests are written to a temp workspace tree and
explicitly tagged with ``synthetic_fixture: true`` so they cannot be
mistaken for real corpus state.
"""
from __future__ import annotations

import json
import importlib.util
import tempfile
import unittest
from pathlib import Path


TOOL_PATH = Path(__file__).resolve().parents[1] / "wave2-w26-cosmos-dedup-verify.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "wave2_w26_cosmos_dedup_verify", str(TOOL_PATH)
    )
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f"could not load tool spec from {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()


def _write_manifest(workspace: Path, data) -> Path:
    """Write a synthetic manifest under the canonical relative path.

    ``data`` may be a dict (will be json.dumped) or a raw string (will
    be written verbatim, useful for malformed-JSON cases).
    """
    manifest_dir = workspace / "audit" / "corpus_tags" / "tags" / "_deprecated"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    p = manifest_dir / "REDIRECT_MANIFEST.json"
    if isinstance(data, str):
        p.write_text(data, encoding="utf-8")
    else:
        # mark synthetic fixture for hygiene (top-level only; tool ignores)
        if isinstance(data, dict):
            data = dict(data)
            data.setdefault("synthetic_fixture", True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


def _baseline_manifest() -> dict:
    """A fully-valid manifest that should yield overall_status=PASS."""
    return {
        "schema_version": "v1",
        "audit_doc": "synthetic-test",
        "redirects": [
            {
                "deprecated_record_id": "findings-go:cosmos-sdk-ghsa-aaaa-bbbb-cccc:111",
                "deprecated_path": "audit/corpus_tags/tags/_deprecated/cosmos_sdk_flat_dupes/x.yaml",
                "canonical_record_id": "cosmos-sdk-ibc:foo:ghsa-aaaa-bbbb-cccc:222",
                "canonical_path": "audit/corpus_tags/tags/cosmos_sdk_ibc/foo-ghsa-aaaa-bbbb-cccc/record.json",
                "reason": "synthetic redirect",
            }
        ],
        "verdict_artefacts": [
            {
                "record_id": "verdict_tag:dydx-hunt-iter-2/DYDX-ASA-2024-0012-CAP-verdict.md",
                "path": "audit/corpus_tags/tags/dydx-hunt-iter-2_DYDX-ASA-2024-0012-CAP-verdict.md.yaml",
                "verdict_id": "dydx-hunt-iter-2/DYDX-ASA-2024-0012-CAP-verdict.md",
                "marker_field": "verdict_artefact",
                "marker_value": True,
                "reason": "workspace verdict output",
                "marked_at": "2026-05-16",
            }
        ],
        "wave2_w26_execution_ledger": {
            "wave_id": "W2.6",
            "executed_at": "2026-05-16",
            "spec_doc": "docs/WAVE2_W26_DUPE_CANONICALIZATION_EXECUTION_PLAN_2026-05-16.md",
            "verdict_artefacts_marked": 1,
            "dupe_finder_group_count_pre": 33,
            "dupe_finder_group_count_post": 32,
        },
    }


def _place_canonical_record(workspace: Path, rel_path: str) -> None:
    """Materialise an empty canonical record file so integrity checks pass."""
    p = workspace / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"synthetic_fixture": True}), encoding="utf-8")


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #


class Wave2W26VerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_pass_synthetic_baseline(self) -> None:
        """Synthetic manifest with all required fields & ASA-2024-0012 cited
        and a real on-disk canonical_path target should produce PASS."""
        data = _baseline_manifest()
        _write_manifest(self.ws, data)
        _place_canonical_record(
            self.ws,
            "audit/corpus_tags/tags/cosmos_sdk_ibc/foo-ghsa-aaaa-bbbb-cccc/record.json",
        )
        pack = TOOL.run_verification(self.ws)
        self.assertEqual(pack["manifest_parse_status"], "ok")
        self.assertTrue(pack["ledger_present"])
        self.assertTrue(pack["ledger_fields_ok"])
        self.assertEqual(pack["verdict_artefact_count"], 1)
        self.assertTrue(pack["asa_2024_0012_referenced"])
        self.assertEqual(
            pack["redirect_target_integrity"]["redirects_with_missing_canonical"], 0
        )
        self.assertEqual(pack["overall_status"], "PASS", msg=pack["failures"])

    def test_fail_malformed_json(self) -> None:
        """Manifest with JSON parse error should FAIL with parse-error status."""
        _write_manifest(self.ws, "{ this is :: not valid json,, }")
        pack = TOOL.run_verification(self.ws)
        self.assertEqual(pack["manifest_parse_status"], "parse-error")
        self.assertFalse(pack["ledger_present"])
        self.assertEqual(pack["overall_status"], "FAIL")
        self.assertTrue(
            any("parse error" in f for f in pack["failures"]),
            msg=pack["failures"],
        )

    def test_fail_missing_ledger(self) -> None:
        """Manifest exists but no wave2_w26_execution_ledger block -> FAIL."""
        data = _baseline_manifest()
        del data["wave2_w26_execution_ledger"]
        _write_manifest(self.ws, data)
        pack = TOOL.run_verification(self.ws)
        self.assertEqual(pack["manifest_parse_status"], "ok")
        self.assertFalse(pack["ledger_present"])
        self.assertFalse(pack["ledger_fields_ok"])
        self.assertEqual(pack["overall_status"], "FAIL")
        self.assertTrue(
            any("execution_ledger" in f for f in pack["failures"]),
            msg=pack["failures"],
        )

    def test_fail_asa_not_referenced(self) -> None:
        """Ledger present but verdict_artefacts doesn't cite ASA-2024-0012 -> FAIL."""
        data = _baseline_manifest()
        # Replace verdict_artefacts with one that doesn't mention ASA
        data["verdict_artefacts"] = [
            {
                "record_id": "verdict_tag:unrelated/some-other-verdict.md",
                "path": "audit/corpus_tags/tags/unrelated_some-other-verdict.md.yaml",
                "verdict_id": "unrelated/some-other-verdict.md",
                "marker_field": "verdict_artefact",
                "marker_value": True,
                "reason": "unrelated synthetic",
                "marked_at": "2026-05-16",
            }
        ]
        _write_manifest(self.ws, data)
        _place_canonical_record(
            self.ws,
            "audit/corpus_tags/tags/cosmos_sdk_ibc/foo-ghsa-aaaa-bbbb-cccc/record.json",
        )
        pack = TOOL.run_verification(self.ws)
        self.assertEqual(pack["manifest_parse_status"], "ok")
        self.assertTrue(pack["ledger_present"])
        self.assertFalse(pack["asa_2024_0012_referenced"])
        self.assertEqual(pack["overall_status"], "FAIL")
        self.assertTrue(
            any("ASA-2024-0012" in f for f in pack["failures"]),
            msg=pack["failures"],
        )

    def test_warning_dangling_redirect_target(self) -> None:
        """A redirect pointing at a canonical_path that doesn't exist on disk
        should produce a WARNING (not FAIL)."""
        data = _baseline_manifest()
        # canonical_path is set but we deliberately do NOT create the file
        _write_manifest(self.ws, data)
        pack = TOOL.run_verification(self.ws)
        self.assertEqual(pack["manifest_parse_status"], "ok")
        self.assertEqual(
            pack["redirect_target_integrity"]["redirects_with_missing_canonical"], 1
        )
        self.assertEqual(pack["overall_status"], "WARNING", msg=pack)
        self.assertTrue(
            any("canonical_path" in w for w in pack["warnings"]),
            msg=pack["warnings"],
        )

    def test_fail_manifest_missing(self) -> None:
        """No manifest file at all -> FAIL with missing status."""
        # Don't write anything
        pack = TOOL.run_verification(self.ws)
        self.assertEqual(pack["manifest_parse_status"], "missing")
        self.assertEqual(pack["overall_status"], "FAIL")

    def test_fail_malformed_verdict_artefact_entry(self) -> None:
        """A verdict_artefacts[] entry missing required fields -> FAIL."""
        data = _baseline_manifest()
        # entry missing 'marker_field' and 'marked_at'
        data["verdict_artefacts"] = [
            {
                "record_id": "verdict_tag:dydx-hunt-iter-2/DYDX-ASA-2024-0012-CAP-verdict.md",
                "path": "x.yaml",
                "verdict_id": "dydx-hunt-iter-2/DYDX-ASA-2024-0012-CAP-verdict.md",
                "marker_value": True,
                "reason": "missing required fields",
            }
        ]
        _write_manifest(self.ws, data)
        _place_canonical_record(
            self.ws,
            "audit/corpus_tags/tags/cosmos_sdk_ibc/foo-ghsa-aaaa-bbbb-cccc/record.json",
        )
        pack = TOOL.run_verification(self.ws)
        self.assertEqual(pack["overall_status"], "FAIL")
        self.assertTrue(
            any("missing required fields" in f for f in pack["failures"]),
            msg=pack["failures"],
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
