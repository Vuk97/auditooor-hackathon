"""Hermetic tests for tools/llm-calibration-log.py.

Coverage:

- schema validation (required fields, valid enums, ts shape)
- append-only writer round-trips (load_entries reads what append wrote)
- append rejects malformed entries before touching disk
- stats math: TRUE/(TRUE+FALSE), excludes PARTIAL/INDETERMINATE
- filter_entries by provider / task_type / since
- dedupe-by-hash: same (provider, task_ref, prompt_hash) -> later wins
- entries with prompt_hash=None are NEVER deduped
- cite_calibration formats expected 1-line string
- cite_calibration falls back when no decided rows
- validate command flags malformed rows

Test fixtures use neutral inputs (Foo / Bar / Baz / generic PR refs) —
NOT real session content — so this file is comment-leak-safe.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "llm-calibration-log.py"


def _load_module():
    cache_key = "_test_llm_calibration_log"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    spec = importlib.util.spec_from_file_location(cache_key, TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


def _entry(**overrides):
    """Build a neutral, schema-valid entry. Override any field by kwargs."""
    base = {
        "ts": "2026-04-25T10:00:00Z",
        "provider": "kimi",
        "task_type": "pr-review",
        "task_ref": "PR #999 foo",
        "verdict": "TRUE",
    }
    base.update(overrides)
    return base


class TestSchemaValidation(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()

    def test_valid_entry_passes(self):
        # Neutral fixture — no real PR content.
        self.mod.validate_entry(_entry())

    def test_missing_required_field_rejected(self):
        e = _entry()
        del e["verdict"]
        with self.assertRaisesRegex(ValueError, "missing required field: verdict"):
            self.mod.validate_entry(e)

    def test_invalid_provider_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid provider"):
            self.mod.validate_entry(_entry(provider="gpt5"))

    def test_invalid_verdict_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid verdict"):
            self.mod.validate_entry(_entry(verdict="MAYBE"))

    def test_invalid_task_type_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid task_type"):
            self.mod.validate_entry(_entry(task_type="vibes"))

    def test_model_field_passes_validation(self):
        self.mod.validate_entry(_entry(model="kimi-for-coding"))

    def test_blank_model_field_rejected(self):
        with self.assertRaisesRegex(ValueError, "model must be a non-empty string"):
            self.mod.validate_entry(_entry(model=""))

    def test_v4_p5_task_types_accepted(self):
        # V4 P5 added six task-type presets to the schema (sliced
        # separately from the canonical pr-review aggregate so per-task
        # accuracy can be measured). Each must validate end-to-end.
        for tt in (
            "detector-tier-b",
            "gate-hardening",
            "docs-plan",
            "submission-critical",
            "crypto-review",
            "econ-review",
        ):
            self.mod.validate_entry(_entry(task_type=tt))

    def test_p0_3_routing_task_types_accepted(self):
        for tt in (
            "source-extraction",
            "adversarial-kill",
            "poc-wiring",
            "docs-integration",
            "factory-config-liveness-extraction",
            "factory-config-liveness-kill",
            "severity-downgrade",
            "severity-escalation",
        ):
            self.mod.validate_entry(_entry(task_type=tt))

    def test_severity_labels_are_not_calibration_verdicts(self):
        for verdict in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            with self.subTest(verdict=verdict):
                with self.assertRaisesRegex(ValueError, "invalid verdict"):
                    self.mod.validate_entry(
                        _entry(
                            task_type="severity-downgrade",
                            verdict=verdict,
                        )
                    )

    def test_factory_config_liveness_outcome_rows_accept_verified_and_fp_results(self):
        samples = (
            ("kimi", "factory-config-liveness-extraction", "TRUE"),
            ("kimi", "factory-config-liveness-extraction", "FALSE"),
            ("minimax", "factory-config-liveness-kill", "TRUE"),
            ("minimax", "factory-config-liveness-kill", "FALSE"),
            ("minimax", "factory-config-liveness-kill", "PARTIAL"),
        )
        for provider, task_type, verdict in samples:
            with self.subTest(provider=provider, task_type=task_type, verdict=verdict):
                self.mod.validate_entry(
                    _entry(
                        provider=provider,
                        task_type=task_type,
                        task_ref=f"FCL calibration {provider} {verdict}",
                        verdict=verdict,
                        evidence="local validation recorded verified/false-positive outcome",
                    )
                )

    def test_unknown_field_rejected(self):
        e = _entry()
        e["mystery"] = 1
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            self.mod.validate_entry(e)

    def test_bad_ts_rejected(self):
        with self.assertRaisesRegex(ValueError, "ts not parseable"):
            self.mod.validate_entry(_entry(ts="not-a-date"))


class TestAppendAndLoad(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.jsonl"

    def test_append_then_load_roundtrip(self):
        e1 = _entry(task_ref="PR #1 foo", verdict="TRUE")
        e2 = _entry(task_ref="PR #2 bar", verdict="FALSE")
        self.mod.append_entry(e1, path=self.path)
        self.mod.append_entry(e2, path=self.path)
        rows = self.mod.load_entries(self.path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["task_ref"], "PR #1 foo")
        self.assertEqual(rows[1]["verdict"], "FALSE")

    def test_append_rejects_malformed_before_writing(self):
        # First write an OK row to seed the file.
        self.mod.append_entry(_entry(task_ref="PR #1 foo"), path=self.path)
        bad = _entry(verdict="MAYBE")
        with self.assertRaises(ValueError):
            self.mod.append_entry(bad, path=self.path)
        # File should still contain only the original good row.
        rows = self.mod.load_entries(self.path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["task_ref"], "PR #1 foo")

    def test_load_missing_file_returns_empty(self):
        missing = Path(self.tmp.name) / "nope.jsonl"
        self.assertEqual(self.mod.load_entries(missing), [])


class TestStatsAndFilters(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.rows = [
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #A", verdict="TRUE",
                   ts="2026-04-20T10:00:00Z"),
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #B", verdict="TRUE",
                   ts="2026-04-21T10:00:00Z"),
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #C", verdict="FALSE",
                   ts="2026-04-22T10:00:00Z"),
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #D", verdict="PARTIAL",
                   ts="2026-04-23T10:00:00Z"),
            _entry(provider="minimax", task_type="synthesis",
                   task_ref="Synth #1", verdict="TRUE",
                   ts="2026-04-23T10:00:00Z"),
        ]

    def test_stats_excludes_partial_from_denominator(self):
        rows = self.mod.filter_entries(self.rows, provider="kimi",
                                       task_type="pr-review")
        s = self.mod.compute_stats(rows)
        self.assertEqual(s["true"], 2)
        self.assertEqual(s["false"], 1)
        self.assertEqual(s["partial"], 1)
        # 2 / (2+1) = 0.6667 — PARTIAL not in denom
        self.assertAlmostEqual(s["accuracy"], 2 / 3, places=6)
        self.assertEqual(s["n"], 4)

    def test_filter_by_provider(self):
        rows = self.mod.filter_entries(self.rows, provider="minimax")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["task_ref"], "Synth #1")

    def test_filter_by_task_type(self):
        rows = self.mod.filter_entries(self.rows, task_type="synthesis")
        self.assertEqual(len(rows), 1)

    def test_filter_by_since_date(self):
        rows = self.mod.filter_entries(self.rows, since="2026-04-22")
        # Drops the 04-20 and 04-21 entries.
        self.assertEqual(len(rows), 3)


class TestDedupeByHash(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()

    def test_same_hash_provider_taskref_later_wins(self):
        rows = [
            _entry(task_ref="PR #1 foo", prompt_hash="sha256:abc",
                   verdict="TRUE",  ts="2026-04-20T10:00:00Z",
                   evidence="initial verdict"),
            _entry(task_ref="PR #1 foo", prompt_hash="sha256:abc",
                   verdict="FALSE", ts="2026-04-21T10:00:00Z",
                   evidence="amended after smoke test"),
        ]
        deduped = self.mod._dedupe_keep_latest(rows)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["verdict"], "FALSE")
        self.assertEqual(deduped[0]["evidence"], "amended after smoke test")

    def test_no_hash_means_no_dedupe(self):
        # Two distinct observations with no prompt_hash must both survive.
        rows = [
            _entry(task_ref="PR #1 foo", verdict="TRUE",
                   ts="2026-04-20T10:00:00Z"),
            _entry(task_ref="PR #1 foo", verdict="FALSE",
                   ts="2026-04-21T10:00:00Z"),
        ]
        deduped = self.mod._dedupe_keep_latest(rows)
        self.assertEqual(len(deduped), 2)

    def test_different_hashes_coexist(self):
        rows = [
            _entry(task_ref="PR #1 foo", prompt_hash="sha256:aaa",
                   verdict="TRUE"),
            _entry(task_ref="PR #1 foo", prompt_hash="sha256:bbb",
                   verdict="FALSE"),
        ]
        deduped = self.mod._dedupe_keep_latest(rows)
        self.assertEqual(len(deduped), 2)


class TestCiteCalibration(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.jsonl"
        seed = [
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #A", verdict="TRUE",
                   ts="2026-04-20T10:00:00Z"),
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #B", verdict="TRUE",
                   ts="2026-04-21T10:00:00Z"),
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #C", verdict="FALSE",
                   ts="2026-04-22T10:00:00Z"),
        ]
        for row in seed:
            self.mod.append_entry(row, path=self.path)

    def test_cite_format(self):
        line = self.mod.cite_calibration(
            "kimi", "pr-review", path=self.path,
        )
        # Expected: "kimi pr-review accuracy: 2/3 = 67% (n=3, since 2026-04-20)"
        self.assertIn("kimi pr-review accuracy:", line)
        self.assertIn("2/3", line)
        self.assertIn("67%", line)
        self.assertIn("n=3", line)
        self.assertIn("2026-04-20", line)

    def test_cite_fallback_when_no_data(self):
        empty = Path(self.tmp.name) / "empty.jsonl"
        line = self.mod.cite_calibration(
            "kimi", "pr-review", path=empty, fallback="FALLBACK",
        )
        self.assertEqual(line, "FALLBACK")

    def test_cite_uses_dedup_winner(self):
        # Amend the FALSE on PR #C to TRUE via a same-hash later entry.
        # Original PR #C entry had no prompt_hash -> need to seed a fresh
        # set with hashes so dedupe applies.
        path = Path(self.tmp.name) / "dedupe.jsonl"
        rows = [
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #X", prompt_hash="sha256:xxx",
                   verdict="FALSE", ts="2026-04-20T10:00:00Z"),
            _entry(provider="kimi", task_type="pr-review",
                   task_ref="PR #X", prompt_hash="sha256:xxx",
                   verdict="TRUE", ts="2026-04-21T10:00:00Z",
                   evidence="amended"),
        ]
        for row in rows:
            self.mod.append_entry(row, path=path)
        line = self.mod.cite_calibration("kimi", "pr-review", path=path)
        # Should be 1/1 = 100%, not 0/1 or 1/2.
        self.assertIn("1/1", line)
        self.assertIn("100%", line)


class TestFactoryConfigLivenessCalibrationRows(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.jsonl"

    def test_extraction_stats_record_verified_and_false_positive_outcomes(self):
        rows = [
            _entry(provider="kimi", task_type="factory-config-liveness-extraction",
                   task_ref="FCL extraction sample 1", verdict="TRUE",
                   evidence="local grep confirmed line-cited config edge"),
            _entry(provider="kimi", task_type="factory-config-liveness-extraction",
                   task_ref="FCL extraction sample 2", verdict="FALSE",
                   evidence="local review showed admin-only self-config"),
            _entry(provider="kimi", task_type="factory-config-liveness-extraction",
                   task_ref="FCL extraction sample 3", verdict="PARTIAL",
                   evidence="candidate useful but required live-state was missing"),
        ]
        for row in rows:
            self.mod.append_entry(row, path=self.path)
        stats = self.mod.compute_stats(
            self.mod.filter_entries(
                self.mod.load_entries(self.path),
                provider="kimi",
                task_type="factory-config-liveness-extraction",
            )
        )
        self.assertEqual(stats["true"], 1)
        self.assertEqual(stats["false"], 1)
        self.assertEqual(stats["partial"], 1)
        self.assertEqual(stats["decided"], 2)
        self.assertAlmostEqual(stats["accuracy"], 0.5)

    def test_kill_stats_record_minimax_keep_and_bad_kill_outcomes(self):
        rows = [
            _entry(provider="minimax", task_type="factory-config-liveness-kill",
                   task_ref="FCL kill sample 1", verdict="TRUE",
                   evidence="local proof agreed with REJECT_SELF_CONFIG"),
            _entry(provider="minimax", task_type="factory-config-liveness-kill",
                   task_ref="FCL kill sample 2", verdict="FALSE",
                   evidence="local proof contradicted REJECT_MISSING_LIVE_PROOF"),
        ]
        for row in rows:
            self.mod.append_entry(row, path=self.path)
        cite = self.mod.cite_calibration(
            "minimax",
            "factory-config-liveness-kill",
            path=self.path,
        )
        self.assertIn("minimax factory-config-liveness-kill accuracy:", cite)
        self.assertIn("1/2", cite)
        self.assertIn("50%", cite)


class TestFactoryConfigLivenessRecordingLoop(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"
        self.samples = Path(self.tmp.name) / "samples"
        self.seed = Path(self.tmp.name) / "seed.json"
        self.seed.write_text(
            json.dumps({
                "_schema_version": 1,
                "_default_min_samples": 20,
                "_min_precision_pct": 70,
                "rows": [
                    {
                        "provider": "kimi",
                        "task_type": "factory-config-liveness-extraction",
                        "sample_count": 0,
                        "precision_pct": "insufficient-data",
                        "last_updated_iso": "2026-05-02T00:00:00Z",
                        "notes": "test row",
                    },
                    {
                        "provider": "minimax",
                        "task_type": "factory-config-liveness-kill",
                        "sample_count": 0,
                        "precision_pct": "insufficient-data",
                        "last_updated_iso": "2026-05-02T00:00:00Z",
                        "notes": "test row",
                    },
                ],
            }),
            encoding="utf-8",
        )

    def test_record_fcl_writes_manifest_and_ledger_entry(self):
        result = self.mod.record_fcl_sample(
            "kimi",
            "FCL packet demo",
            "verified-true",
            evidence="local source proof confirmed factory-created instance edge",
            candidate_id="FCL-demo",
            packet_path="reference/dispatch-packets/factory-config-liveness-extraction.example.md",
            local_proof="rg -n 'createPool' external/demo/contracts/Factory.sol",
            ledger_path=self.ledger,
            samples_dir=self.samples,
            seed_path=self.seed,
        )
        rows = self.mod.load_entries(self.ledger)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["task_type"], "factory-config-liveness-extraction")
        self.assertEqual(rows[0]["verdict"], "TRUE")
        manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], self.mod.FCL_SAMPLE_SCHEMA)
        self.assertEqual(manifest["candidate_id"], "FCL-demo")
        self.assertEqual(
            result["summary"]["routing_reason"],
            "cannot-route: insufficient-data",
        )

    def test_sync_seed_stays_fail_closed_below_min_samples(self):
        for i in range(3):
            self.mod.record_fcl_sample(
                "minimax",
                f"FCL kill sample {i}",
                "verified-true" if i < 2 else "verified-false-positive",
                evidence="local adjudication completed",
                ledger_path=self.ledger,
                samples_dir=self.samples,
                seed_path=self.seed,
            )
        summary = self.mod.sync_seed_row_from_ledger(
            "minimax",
            "factory-config-liveness-kill",
            path=self.ledger,
            seed_path=self.seed,
        )
        self.assertEqual(summary["seed_sample_count"], 3)
        self.assertEqual(summary["seed_precision_pct"], "insufficient-data")
        self.assertEqual(summary["routing_reason"], "cannot-route: insufficient-data")

    def test_sync_seed_promotes_numeric_precision_only_after_threshold(self):
        for i in range(20):
            verdict = "verified-true" if i < 15 else "verified-false-positive"
            self.mod.record_fcl_sample(
                "kimi",
                f"FCL extraction sample {i}",
                verdict,
                evidence="local adjudication completed",
                ledger_path=self.ledger,
                samples_dir=self.samples,
                seed_path=self.seed,
            )
        summary = self.mod.sync_seed_row_from_ledger(
            "kimi",
            "factory-config-liveness-extraction",
            path=self.ledger,
            seed_path=self.seed,
        )
        self.assertEqual(summary["seed_sample_count"], 20)
        self.assertEqual(summary["seed_precision_pct"], 75)
        self.assertTrue(summary["primary_allowed"])
        self.assertEqual(summary["routing_reason"], "primary-allowed-by-seed")

    def test_fcl_summary_reports_both_lanes(self):
        self.mod.record_fcl_sample(
            "kimi",
            "FCL extraction sample",
            "verified-partial",
            evidence="useful packet but live-state still unresolved",
            ledger_path=self.ledger,
            samples_dir=self.samples,
            seed_path=self.seed,
        )
        rows = [
            self.mod.summarize_lane(
                provider,
                self.mod.FCL_PROVIDER_TASK_TYPES[provider],
                path=self.ledger,
                seed_path=self.seed,
            )
            for provider in sorted(self.mod.FCL_PROVIDER_TASK_TYPES)
        ]
        by_provider = {row["provider"]: row for row in rows}
        self.assertEqual(by_provider["kimi"]["partial"], 1)
        self.assertEqual(by_provider["minimax"]["decided"], 0)


class TestRoutingStatus(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.jsonl"
        # Routing tests that exercise the legacy JSONL-only path must
        # point seed_path at a non-existent file; otherwise the real
        # repo-shipped seed at reference/llm_calibration_seed.json
        # (insufficient-data for every lane) would override the JSONL
        # decision under test. Tests that exercise the seed precedence
        # path explicitly set their own seed_path.
        self.no_seed = Path(self.tmp.name) / "no-such-seed.json"

    def test_missing_precision_data_is_advisory_only(self):
        status = self.mod.routing_status(
            "kimi", "source-extraction",
            path=self.path, seed_path=self.no_seed,
        )
        self.assertFalse(status["primary_allowed"])
        self.assertTrue(status["advisory_only"])
        self.assertEqual(status["reason"], "missing-precision-data")

    def test_low_precision_is_advisory_only(self):
        rows = [
            _entry(provider="kimi", task_type="source-extraction",
                   task_ref=f"case-{i}", verdict=("TRUE" if i < 3 else "FALSE"))
            for i in range(5)
        ]
        for row in rows:
            self.mod.append_entry(row, path=self.path)
        status = self.mod.routing_status(
            "kimi", "source-extraction",
            path=self.path, seed_path=self.no_seed,
        )
        self.assertFalse(status["primary_allowed"])
        self.assertEqual(status["reason"], "precision-below-threshold")
        self.assertEqual(status["decided"], 5)

    def test_enough_high_precision_allows_primary(self):
        rows = [
            _entry(provider="minimax", task_type="adversarial-kill",
                   task_ref=f"case-{i}", verdict=("TRUE" if i < 4 else "FALSE"))
            for i in range(5)
        ]
        for row in rows:
            self.mod.append_entry(row, path=self.path)
        status = self.mod.routing_status(
            "minimax", "adversarial-kill",
            path=self.path, seed_path=self.no_seed,
        )
        self.assertTrue(status["primary_allowed"])
        self.assertFalse(status["advisory_only"])
        self.assertEqual(status["reason"], "primary-allowed")


class TestSeedRoutingPrecedence(unittest.TestCase):
    """P0-3 burn-down: seed file is the first-class refusal source.

    Cases (mirrors the requirements in the PR plan):
      - synthetic seed with 1 row at 70% / 30 samples passes
      - 1 row at 65% / 50 samples fails (precision below floor)
      - 1 row at 80% / 5 samples fails with cannot-route: insufficient-data
      - missing row fails with cannot-route: no-calibration
      - insufficient-data sentinel fails with cannot-route: insufficient-data
    """

    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"

    def _write_seed(self, rows):
        path = Path(self.tmp.name) / "seed.json"
        path.write_text(
            json.dumps({"_schema_version": 1, "rows": rows}),
            encoding="utf-8",
        )
        return path

    def test_seed_70pct_30samples_passes(self):
        seed = self._write_seed([
            {
                "provider": "kimi", "task_type": "source-extraction",
                "sample_count": 30, "precision_pct": 70,
                "last_updated_iso": "2026-04-29T00:00:00Z",
                "notes": "synthetic test row",
            },
        ])
        status = self.mod.routing_status(
            "kimi", "source-extraction",
            path=self.ledger, seed_path=seed,
        )
        self.assertTrue(status["primary_allowed"])
        self.assertEqual(status["reason"], "primary-allowed-by-seed")
        self.assertEqual(status["sample_count"], 30)

    def test_seed_65pct_50samples_fails_below_floor(self):
        seed = self._write_seed([
            {
                "provider": "minimax", "task_type": "adversarial-kill",
                "sample_count": 50, "precision_pct": 65,
                "last_updated_iso": "2026-04-29T00:00:00Z",
                "notes": "synthetic test row",
            },
        ])
        status = self.mod.routing_status(
            "minimax", "adversarial-kill",
            path=self.ledger, seed_path=seed,
        )
        self.assertFalse(status["primary_allowed"])
        self.assertEqual(
            status["reason"], "cannot-route: precision-below-threshold"
        )
        self.assertEqual(status["sample_count"], 50)
        self.assertEqual(status["precision_pct"], 65)

    def test_seed_80pct_5samples_fails_insufficient_data(self):
        seed = self._write_seed([
            {
                "provider": "claude", "task_type": "harness-implementation",
                "sample_count": 5, "precision_pct": 80,
                "last_updated_iso": "2026-04-29T00:00:00Z",
                "notes": "synthetic test row",
            },
        ])
        status = self.mod.routing_status(
            "claude", "harness-implementation",
            path=self.ledger, seed_path=seed,
        )
        self.assertFalse(status["primary_allowed"])
        self.assertEqual(
            status["reason"], "cannot-route: insufficient-data"
        )
        self.assertEqual(status["sample_count"], 5)

    def test_missing_seed_row_fails_no_calibration(self):
        seed = self._write_seed([
            {
                "provider": "kimi", "task_type": "source-extraction",
                "sample_count": 0, "precision_pct": "insufficient-data",
                "last_updated_iso": "2026-04-29T00:00:00Z",
                "notes": "different row, not the one queried",
            },
        ])
        status = self.mod.routing_status(
            "minimax", "contradiction-search",
            path=self.ledger, seed_path=seed,
        )
        self.assertFalse(status["primary_allowed"])
        self.assertEqual(
            status["reason"], "cannot-route: no-calibration"
        )

    def test_seed_insufficient_data_sentinel_fails(self):
        seed = self._write_seed([
            {
                "provider": "claude", "task_type": "fixture-wiring",
                "sample_count": 100, "precision_pct": "insufficient-data",
                "last_updated_iso": "2026-04-29T00:00:00Z",
                "notes": "explicit sentinel even with high sample_count",
            },
        ])
        status = self.mod.routing_status(
            "claude", "fixture-wiring",
            path=self.ledger, seed_path=seed,
        )
        self.assertFalse(status["primary_allowed"])
        self.assertEqual(
            status["reason"], "cannot-route: insufficient-data"
        )

    def test_seed_severity_lanes_remain_advisory_only(self):
        seed = self._write_seed([
            {
                "provider": "claude", "task_type": "severity-downgrade",
                "sample_count": 0, "precision_pct": "insufficient-data",
                "advisory_only_explicit": True,
                "last_updated_iso": "2026-05-12T00:00:00Z",
                "notes": "synthetic severity downgrade row",
            },
            {
                "provider": "claude", "task_type": "severity-escalation",
                "sample_count": 0, "precision_pct": "insufficient-data",
                "advisory_only_explicit": True,
                "last_updated_iso": "2026-05-12T00:00:00Z",
                "notes": "synthetic severity escalation row",
            },
        ])
        for provider, task_type in (
            ("claude", "severity-downgrade"),
            ("claude", "severity-escalation"),
        ):
            with self.subTest(provider=provider, task_type=task_type):
                status = self.mod.routing_status(
                    provider, task_type,
                    path=self.ledger, seed_path=seed,
                )
                self.assertFalse(status["primary_allowed"])
                self.assertEqual(status["reason"], "advisory-only-by-explicit-policy")

    def test_repo_seed_routes_default_rows_by_seed_evidence(self):
        # Sanity: the seed shipped at reference/llm_calibration_seed.json
        # is authoritative. Evidence-backed lanes may route primary, while
        # rows still marked insufficient-data must continue to refuse.
        repo_seed = (Path(__file__).resolve().parents[2]
                     / "reference" / "llm_calibration_seed.json")
        if not repo_seed.is_file():
            self.skipTest("repo seed not present")
        seed = json.loads(repo_seed.read_text(encoding="utf-8"))
        for row in seed["rows"]:
            with self.subTest(provider=row["provider"],
                              task_type=row["task_type"]):
                status = self.mod.routing_status(
                    row["provider"], row["task_type"],
                    path=self.ledger, seed_path=repo_seed,
                )
                if row["precision_pct"] == "insufficient-data":
                    self.assertFalse(status["primary_allowed"])
                    # P0-3 closure (2026-05-04): rows that are still seeded
                    # at insufficient-data may carry an explicit
                    # advisory-only policy marker. Both refusal classes
                    # are valid; the test asserts the refusal happens, not
                    # which of the two reason strings it produces.
                    if row.get("advisory_only_explicit"):
                        self.assertEqual(
                            status["reason"],
                            "advisory-only-by-explicit-policy",
                        )
                    else:
                        self.assertEqual(
                            status["reason"],
                            "cannot-route: insufficient-data",
                        )
                else:
                    self.assertTrue(status["primary_allowed"])
                    self.assertEqual(status["reason"], "primary-allowed-by-seed")


class TestValidateCommand(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_validate_all_clean(self):
        path = Path(self.tmp.name) / "ledger.jsonl"
        self.mod.append_entry(_entry(task_ref="PR #1"), path=path)
        self.mod.append_entry(_entry(task_ref="PR #2", verdict="FALSE"),
                              path=path)
        rows = self.mod.load_entries(path)
        self.assertEqual(self.mod.validate_all(rows), [])

    def test_validate_flags_bad_row(self):
        path = Path(self.tmp.name) / "ledger.jsonl"
        # Hand-write a bad row directly to bypass append_entry's guard,
        # because the invariant we care about is "validate catches what
        # was somehow already on disk" (e.g. manual edit).
        with path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": "2026-04-25T10:00:00Z",
                "provider": "kimi",
                "task_type": "pr-review",
                "task_ref": "PR #1",
                # missing verdict
            }) + "\n")
        rows = self.mod.load_entries(path)
        errs = self.mod.validate_all(rows)
        self.assertEqual(len(errs), 1)
        self.assertIn("missing required field: verdict", errs[0])


class TestProviderAssistSummary(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"
        self.budget = Path(self.tmp.name) / "llm_budget.json"
        self.budget.write_text(
            json.dumps({
                "providers": {
                    "kimi": {
                        "window_minutes": 60,
                        "max_calls": 180,
                        "max_tokens": 1800000,
                        "soft_ratio": 0.9,
                    },
                    "minimax": {
                        "window_minutes": 60,
                        "max_calls": 240,
                        "max_tokens": 2400000,
                        "soft_ratio": 0.9,
                    },
                },
            }),
            encoding="utf-8",
        )
        rows = [
            _entry(provider="kimi", task_type="source-extraction",
                   task_ref="case-k", verdict="TRUE"),
            _entry(provider="minimax", task_type="adversarial-kill",
                   task_ref="case-m", verdict="FALSE"),
        ]
        for row in rows:
            self.mod.append_entry(row, path=self.ledger)

    def test_provider_assist_uses_active_paid_tier_budget(self):
        summary = self.mod.provider_assist_summary(
            ledger_path=self.ledger,
            budget_path=self.budget,
        )
        self.assertEqual(
            summary["providers"]["kimi"]["active_budget"]["max_calls"],
            180,
        )
        self.assertEqual(
            summary["providers"]["minimax"]["active_budget"]["max_tokens"],
            2400000,
        )
        self.assertEqual(
            summary["providers"]["kimi"]["paid_tier_mode"],
            "active-aggressive-audited",
        )
        self.assertIn(
            "no_paste_ready_from_provider_output",
            summary["hard_guards"],
        )
        self.assertIn("legacy history", summary["legacy_budget_note"])

    def test_provider_assist_profiles_keep_outputs_advisory(self):
        summary = self.mod.provider_assist_summary(
            ledger_path=self.ledger,
            budget_path=self.budget,
        )
        guards = set(summary["hard_guards"])
        self.assertIn("provider_output_advisory_only", guards)
        self.assertIn("no_severity_authority_from_provider_output", guards)
        self.assertEqual(
            summary["providers"]["minimax"]["profile"]["recommended_loop_role"],
            "candidate_killer",
        )


class TestLocalVerificationAccepted(unittest.TestCase):
    """Lane-7 GAP-1: local_verification_accepted field on calibration rows."""

    def setUp(self):
        self.mod = _load_module()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.jsonl"

    # ------------------------------------------------------------------
    # Schema validation
    # ------------------------------------------------------------------
    def test_new_row_with_true_passes_validation(self):
        e = _entry(local_verification_accepted="true")
        self.mod.validate_entry(e)  # must not raise

    def test_new_row_with_false_passes_validation(self):
        e = _entry(local_verification_accepted="false")
        self.mod.validate_entry(e)

    def test_new_row_with_unknown_passes_validation(self):
        e = _entry(local_verification_accepted="unknown")
        self.mod.validate_entry(e)

    def test_invalid_value_rejected(self):
        e = _entry(local_verification_accepted="yes")
        with self.assertRaisesRegex(ValueError, "invalid local_verification_accepted"):
            self.mod.validate_entry(e)

    def test_absent_field_passes_validation(self):
        # Legacy rows without the field must still validate (forward-fill only).
        e = _entry()
        self.assertNotIn("local_verification_accepted", e)
        self.mod.validate_entry(e)  # must not raise

    # ------------------------------------------------------------------
    # Append + read-back
    # ------------------------------------------------------------------
    def test_new_row_carries_local_verification_accepted(self):
        e = _entry(local_verification_accepted="true")
        self.mod.append_entry(e, path=self.path)
        rows = self.mod.load_entries(self.path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("local_verification_accepted"), "true")

    def test_absent_field_reads_back_as_missing_then_treated_as_unknown(self):
        # Write a legacy row without the field directly (bypassing append_entry
        # schema check by hand-writing JSON so we simulate a pre-Lane-7 row).
        with self.path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": "2026-04-25T10:00:00Z",
                "provider": "kimi",
                "task_type": "pr-review",
                "task_ref": "PR #legacy",
                "verdict": "TRUE",
            }) + "\n")
        rows = self.mod.load_entries(self.path)
        self.assertEqual(len(rows), 1)
        # Field absent on legacy row; caller treats None/.get() default as "unknown".
        lva = rows[0].get("local_verification_accepted", "unknown")
        self.assertEqual(lva, "unknown")

    # ------------------------------------------------------------------
    # CLI subcommand: log writes the field; default is "unknown"
    # ------------------------------------------------------------------
    def test_cmd_log_writes_unknown_by_default(self):
        rc = self.mod.main([
            "--ledger", str(self.path),
            "log", "kimi", "pr-review", "PR #cli-test", "TRUE",
        ])
        self.assertEqual(rc, 0)
        rows = self.mod.load_entries(self.path)
        self.assertEqual(rows[0].get("local_verification_accepted"), "unknown")
        self.assertEqual(rows[0].get("model"), "kimi-for-coding")

    def test_cmd_log_writes_model_when_flag_set(self):
        rc = self.mod.main([
            "--ledger", str(self.path),
            "log", "minimax", "adversarial-kill", "model-test-1", "TRUE",
            "--model", "MiniMax-M2.7",
        ])
        self.assertEqual(rc, 0)
        rows = self.mod.load_entries(self.path)
        self.assertEqual(rows[0].get("model"), "MiniMax-M2.7")

    def test_cmd_log_writes_true_when_flag_set(self):
        rc = self.mod.main([
            "--ledger", str(self.path),
            "log", "kimi", "pr-review", "PR #cli-test-true", "TRUE",
            "--local-verification-accepted", "true",
        ])
        self.assertEqual(rc, 0)
        rows = self.mod.load_entries(self.path)
        self.assertEqual(rows[0].get("local_verification_accepted"), "true")

    def test_cmd_log_writes_false_when_flag_set(self):
        rc = self.mod.main([
            "--ledger", str(self.path),
            "log", "minimax", "adversarial-kill", "kill-test-1", "FALSE",
            "--local-verification-accepted", "false",
        ])
        self.assertEqual(rc, 0)
        rows = self.mod.load_entries(self.path)
        self.assertEqual(rows[0].get("local_verification_accepted"), "false")


if __name__ == "__main__":
    unittest.main()
