#!/usr/bin/env python3
"""Tests for tools/fp-calibration-manifest.py — the FP calibration manifest tool.

P1-4 burn-down. Stdlib-only, hermetic via ``tempfile.TemporaryDirectory``.

Cases covered:

  1. ``--read`` on an absent file emits an empty schema-stamped manifest.
  2. ``--update`` writes a row, ``--validate`` passes, ``--read`` round-trips.
  3. ``--validate`` rejects a row missing required fields, with bad tier,
     unparseable ISO, out-of-range precision, malformed corpus hash.
  4. ``--required-for-tier-sa`` with no manifest + Tier-S/A entries in the
     registry exits 1 (fail-closed) and lists every pattern as missing.
  5. ``--required-for-tier-sa`` with one fresh Tier-S row passes.
  6. ``--required-for-tier-sa`` with one stale (> 90d) Tier-S row fails.
  7. ``corpus_hash_for`` is deterministic across slug ordering.
  8. The tier-registry parser tolerates a registry with no ``tiers:`` block.
"""
from __future__ import annotations

import datetime
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "fp-calibration-manifest.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "fp_calibration_manifest_under_test", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fp_calibration_manifest_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_registry(path: Path, rows: dict[str, str]) -> None:
    """Write a minimal _tier_registry.yaml — same two-space block format
    the real parser handles."""
    out: list[str] = ["version: 1", "tiers:"]
    for name, tier in rows.items():
        out.append(f"  {name}:")
        out.append(f"    tier: {tier}")
        out.append("    reason: test row")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def _good_row(
    name: str = "demo-pattern",
    *,
    tier: str = "S",
    iso: str = "2026-04-29T00:00:00Z",
    precision: float = 100.0,
    corpus: str = "deadbeefcafef00d",
    clean: int = 3,
) -> dict:
    return {
        "pattern": name,
        "tier": tier,
        "last_calibrated_iso": iso,
        "clean_codebases_count": clean,
        "clean_corpus_hash": corpus,
        "precision_pct": precision,
    }


class ReadAndUpdateTest(unittest.TestCase):
    def test_read_empty(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(["--read", "--manifest", str(manifest)])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(
                payload["schema_version"], MOD.SCHEMA_VERSION
            )
            self.assertEqual(payload["patterns"], {})

    def test_update_round_trip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            registry = Path(tmp) / "_tier_registry.yaml"
            _write_registry(registry, {"role-grant-divergence": "S"})
            argv = [
                "--update", "role-grant-divergence",
                "--manifest", str(manifest),
                "--tier-registry", str(registry),
                "--precision", "97.5",
                "--corpus", "1234567890abcdef",
                "--clean-codebases", "3",
                "--iso", "2026-04-29T00:00:00Z",
                "--notes", "smoke",
            ]
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(argv)
            self.assertEqual(rc, 0)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            row = data["patterns"]["role-grant-divergence"]
            self.assertEqual(row["tier"], "S")
            self.assertEqual(row["clean_corpus_hash"], "1234567890abcdef")
            self.assertEqual(row["clean_codebases_count"], 3)
            self.assertAlmostEqual(row["precision_pct"], 97.5)
            self.assertEqual(row["notes"], "smoke")

    def test_update_uses_registry_tier_when_absent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            registry = Path(tmp) / "_tier_registry.yaml"
            _write_registry(registry, {"some-pattern": "A"})
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "--update", "some-pattern",
                    "--manifest", str(manifest),
                    "--tier-registry", str(registry),
                    "--precision", "100",
                    "--corpus", "abc1234567",
                ])
            self.assertEqual(rc, 0)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(data["patterns"]["some-pattern"]["tier"], "A")


class ValidateTest(unittest.TestCase):
    def test_validate_empty_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(["--validate", "--manifest", str(manifest)])
            self.assertEqual(rc, 0)

    def test_validate_rejects_bad_tier(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            row = _good_row(tier="Z")
            payload = {
                "schema_version": MOD.SCHEMA_VERSION,
                "patterns": {row["pattern"]: row},
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = MOD.main(["--validate", "--manifest", str(manifest)])
            self.assertEqual(rc, 1)
            self.assertIn("tier='Z'", err.getvalue())

    def test_validate_rejects_out_of_range_precision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            row = _good_row(precision=120.0)
            payload = {
                "schema_version": MOD.SCHEMA_VERSION,
                "patterns": {row["pattern"]: row},
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = MOD.main(["--validate", "--manifest", str(manifest)])
            self.assertEqual(rc, 1)
            self.assertIn("precision_pct=120", err.getvalue())

    def test_validate_rejects_malformed_iso(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            row = _good_row(iso="yesterday")
            payload = {
                "schema_version": MOD.SCHEMA_VERSION,
                "patterns": {row["pattern"]: row},
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = MOD.main(["--validate", "--manifest", str(manifest)])
            self.assertEqual(rc, 1)
            self.assertIn("last_calibrated_iso='yesterday'", err.getvalue())

    def test_validate_rejects_missing_required_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            row = _good_row()
            row.pop("clean_corpus_hash")
            payload = {
                "schema_version": MOD.SCHEMA_VERSION,
                "patterns": {row["pattern"]: row},
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = MOD.main(["--validate", "--manifest", str(manifest)])
            self.assertEqual(rc, 1)
            self.assertIn("clean_corpus_hash", err.getvalue())


class RequiredForTierSaTest(unittest.TestCase):
    def test_empty_manifest_lists_every_tier_sa_as_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            registry = Path(tmp) / "_tier_registry.yaml"
            _write_registry(
                registry,
                {"alpha": "S", "beta": "A", "gamma": "D", "delta": "B"},
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "--required-for-tier-sa",
                    "--manifest", str(manifest),
                    "--tier-registry", str(registry),
                    "--json",
                ])
            self.assertEqual(rc, 1)
            report = json.loads(buf.getvalue())
            self.assertFalse(report["ok"])
            self.assertEqual(
                sorted(report["tier_sa_patterns"]), ["alpha", "beta"]
            )
            self.assertEqual(sorted(report["missing"]), ["alpha", "beta"])
            self.assertEqual(report["stale"], [])
            self.assertEqual(report["fresh"], [])

    def test_one_fresh_tier_s_row_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            registry = Path(tmp) / "_tier_registry.yaml"
            _write_registry(registry, {"alpha": "S"})
            now = datetime.datetime.now(datetime.timezone.utc)
            iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            payload = {
                "schema_version": MOD.SCHEMA_VERSION,
                "patterns": {"alpha": _good_row("alpha", iso=iso)},
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "--required-for-tier-sa",
                    "--manifest", str(manifest),
                    "--tier-registry", str(registry),
                    "--json",
                ])
            self.assertEqual(rc, 0)
            report = json.loads(buf.getvalue())
            self.assertTrue(report["ok"])
            self.assertEqual(report["fresh"], ["alpha"])
            self.assertEqual(report["missing"], [])
            self.assertEqual(report["stale"], [])

    def test_stale_tier_s_row_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            manifest = Path(tmp) / "fp_calibration_manifest.json"
            registry = Path(tmp) / "_tier_registry.yaml"
            _write_registry(registry, {"alpha": "S"})
            now = datetime.datetime.now(datetime.timezone.utc)
            stale = now - datetime.timedelta(days=200)
            iso = stale.strftime("%Y-%m-%dT%H:%M:%SZ")
            payload = {
                "schema_version": MOD.SCHEMA_VERSION,
                "patterns": {"alpha": _good_row("alpha", iso=iso)},
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "--required-for-tier-sa",
                    "--manifest", str(manifest),
                    "--tier-registry", str(registry),
                    "--max-age-days", "90",
                    "--json",
                ])
            self.assertEqual(rc, 1)
            report = json.loads(buf.getvalue())
            self.assertFalse(report["ok"])
            self.assertEqual(report["missing"], [])
            self.assertEqual(len(report["stale"]), 1)
            self.assertEqual(report["stale"][0]["pattern"], "alpha")
            self.assertGreaterEqual(report["stale"][0]["age_days"], 90)


class TierRegistryParseTest(unittest.TestCase):
    def test_parser_handles_no_tiers_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            registry = Path(tmp) / "_tier_registry.yaml"
            registry.write_text("version: 1\n", encoding="utf-8")
            self.assertEqual(MOD.parse_tier_registry(registry), {})

    def test_parser_extracts_tier_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fpcal-") as tmp:
            registry = Path(tmp) / "_tier_registry.yaml"
            _write_registry(
                registry,
                {"alpha": "S", "beta": "A", "gamma": "D"},
            )
            self.assertEqual(
                MOD.parse_tier_registry(registry),
                {"alpha": "S", "beta": "A", "gamma": "D"},
            )


class CorpusHashTest(unittest.TestCase):
    def test_corpus_hash_is_order_independent(self) -> None:
        h1 = MOD.corpus_hash_for(
            [("oz", "v5.1.0"), ("solady", "v0.0.287"), ("solmate", "v7")]
        )
        h2 = MOD.corpus_hash_for(
            [("solmate", "v7"), ("oz", "v5.1.0"), ("solady", "v0.0.287")]
        )
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 16)

    def test_corpus_hash_changes_when_version_changes(self) -> None:
        h1 = MOD.corpus_hash_for([("oz", "v5.1.0")])
        h2 = MOD.corpus_hash_for([("oz", "v5.2.0")])
        self.assertNotEqual(h1, h2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
