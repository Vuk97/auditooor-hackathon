#!/usr/bin/env python3
"""Tests for tools/mining-manifest.py — V5 Gap-26 (V5-P0-18).

Stdlib-only, hermetic. Loads the tool via ``importlib`` because the
filename has a hyphen.

Coverage:
  1. Mining manifest is written for a source-mining dry run.
  2. Schema validation: required fields present, prompt_hash deterministic.
  3. Validation rejects bad provider, bad prompt_hash, candidate < rej+prom,
     bad sampled_coverage, bad date.
  4. ``estimate_context_size`` is monotone in input length.
  5. CLI ``write`` round-trips through ``validate``.
  6. Schema version stability: bumping requires explicit acknowledgement.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "mining-manifest.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "mining_manifest", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mining_manifest"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _good_payload(**overrides) -> dict:
    base = {
        "source_packet": "/tmp/packet.md",
        "provider": "kimi",
        "prompt_hash": MOD.compute_prompt_hash("hello world"),
        "context_size": 8,
        "sampled_coverage": {"shown": 5, "total": 50},
        "candidate_count": 10,
        "rejection_count": 7,
        "promotion_count": 2,
        "workspace": "morpho",
        "campaign_date": "2026-04-26",
        "campaign_label": "oracle-pricing",
    }
    base.update(overrides)
    return MOD.build_manifest(base)


class TestPromptHash(unittest.TestCase):

    def test_deterministic(self):
        a = MOD.compute_prompt_hash("foo bar baz")
        b = MOD.compute_prompt_hash("foo bar baz")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_different_inputs_diverge(self):
        self.assertNotEqual(
            MOD.compute_prompt_hash("foo"),
            MOD.compute_prompt_hash("bar"),
        )

    def test_rejects_bytes(self):
        with self.assertRaises(TypeError):
            MOD.compute_prompt_hash(b"bytes-not-allowed")

    def test_known_vector(self):
        # Stable test vector for "hello world" SHA-256.
        self.assertEqual(
            MOD.compute_prompt_hash("hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )


class TestValidate(unittest.TestCase):

    def test_good_payload_passes(self):
        MOD.validate_manifest(_good_payload())

    def test_missing_required_field(self):
        p = _good_payload()
        del p["candidate_count"]
        with self.assertRaisesRegex(MOD.ManifestError, "missing"):
            MOD.validate_manifest(p)

    def test_bad_provider(self):
        p = _good_payload(provider="claude")
        with self.assertRaisesRegex(MOD.ManifestError, "provider"):
            MOD.validate_manifest(p)

    def test_bad_prompt_hash(self):
        p = _good_payload(prompt_hash="not-a-hex")
        with self.assertRaisesRegex(MOD.ManifestError, "prompt_hash"):
            MOD.validate_manifest(p)

    def test_tally_inconsistent(self):
        p = _good_payload(candidate_count=5, rejection_count=4,
                          promotion_count=4)
        with self.assertRaisesRegex(MOD.ManifestError, "tally"):
            MOD.validate_manifest(p)

    def test_sampled_coverage_shown_gt_total(self):
        p = _good_payload(sampled_coverage={"shown": 100, "total": 5})
        with self.assertRaisesRegex(MOD.ManifestError, "shown"):
            MOD.validate_manifest(p)

    def test_bad_date(self):
        p = _good_payload(campaign_date="04/26/2026")
        with self.assertRaisesRegex(MOD.ManifestError, "campaign_date"):
            MOD.validate_manifest(p)

    def test_negative_context_size(self):
        p = _good_payload(context_size=0)
        with self.assertRaisesRegex(MOD.ManifestError, "context_size"):
            MOD.validate_manifest(p)


class TestContextSize(unittest.TestCase):

    def test_empty_zero(self):
        self.assertEqual(MOD.estimate_context_size(""), 0)

    def test_monotone(self):
        a = MOD.estimate_context_size("x" * 100)
        b = MOD.estimate_context_size("x" * 1000)
        self.assertLess(a, b)

    def test_ceil(self):
        self.assertEqual(MOD.estimate_context_size("x"), 1)
        self.assertEqual(MOD.estimate_context_size("xxxx"), 1)
        self.assertEqual(MOD.estimate_context_size("xxxxx"), 2)


class TestWriteAndValidate(unittest.TestCase):

    def test_dry_run_write_and_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = tmp_path / "audits" / "morpho"
            ws.mkdir(parents=True)
            # Write a fake truth packet so source_packet path resolves
            packet = ws / "source_mining" / "2026-04-26" / "truth_packet.md"
            packet.parent.mkdir(parents=True)
            packet.write_text("# Truth packet\nscope: ...\n")
            prompt_path = tmp_path / "prompt.md"
            prompt_path.write_text("Read the truth packet ...\n" * 50)

            argv = [
                "write",
                "--workspace", str(ws),
                "--date", "2026-04-26",
                "--campaign-label", "oracle-pricing",
                "--source-packet", str(packet),
                "--provider", "kimi",
                "--prompt-file", str(prompt_path),
                "--candidate-count", "10",
                "--rejection-count", "7",
                "--promotion-count", "2",
                "--sampled-shown", "5",
                "--sampled-total", "50",
            ]
            from contextlib import redirect_stdout, redirect_stderr
            import io
            so, se = io.StringIO(), io.StringIO()
            with redirect_stdout(so), redirect_stderr(se):
                rc = MOD.main(argv)
            self.assertEqual(rc, 0, f"write failed: {se.getvalue()}")
            manifest = packet.parent / "mining_manifest.json"
            self.assertTrue(manifest.exists())
            payload = json.loads(manifest.read_text())
            self.assertEqual(payload["provider"], "kimi")
            self.assertEqual(payload["candidate_count"], 10)
            self.assertEqual(len(payload["prompt_hash"]), 64)
            self.assertEqual(payload["workspace"], "morpho")
            # Validate via subcommand
            so2, se2 = io.StringIO(), io.StringIO()
            with redirect_stdout(so2), redirect_stderr(se2):
                rc2 = MOD.main(["validate", str(manifest)])
            self.assertEqual(rc2, 0,
                             f"validate failed: {se2.getvalue()}")

    def test_validate_rejects_corrupt_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            # Corrupt manifest: missing provider
            bad.write_text(json.dumps({
                "source_packet": "/x", "prompt_hash": "f" * 64,
                "context_size": 1, "candidate_count": 1,
                "rejection_count": 0, "promotion_count": 0,
                "workspace": "x", "campaign_date": "2026-04-26",
                "campaign_label": "x", "tool_version": "1",
                "generated_at_utc": "2026-04-26T00:00:00+00:00",
            }))
            from contextlib import redirect_stderr
            import io
            se = io.StringIO()
            with redirect_stderr(se):
                rc = MOD.main(["validate", str(bad)])
            self.assertEqual(rc, 1)
            self.assertIn("missing", se.getvalue())


class TestSchemaVersion(unittest.TestCase):
    """Schema version stability — adding fields is fine, but the
    constant must match what's persisted."""

    def test_constant_matches(self):
        self.assertEqual(MOD.SCHEMA_VERSION, "1")

    def test_validation_rejects_other_version(self):
        p = _good_payload()
        p["tool_version"] = "999"
        with self.assertRaisesRegex(MOD.ManifestError, "tool_version"):
            MOD.validate_manifest(p)


if __name__ == "__main__":
    unittest.main()
