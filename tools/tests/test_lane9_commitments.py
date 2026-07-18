"""Tests for Lane 9 corpus-mining commitments (PR #658 Tier-B #15).

Covers:
  (a) defimon-staleness-check.py  — fresh / stale / missing cases + --json
  (b) big-loss-template-registry-emit.py — compose + writes row, idempotent
  (c) reference/audit_pdf_mining_targets.json — schema, 15 entries, required fields
  (d) reference/corpus_registry.json — still validates after edits (extended_corpora row present)

At least 8 tests as required.
"""
from __future__ import annotations

import datetime
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
_TOOLS = _HERE.parent
_REPO_ROOT = _TOOLS.parent


# ---------------------------------------------------------------------------
# Module loaders
# ---------------------------------------------------------------------------

def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_staleness_mod = _load(
    "defimon_staleness_check",
    _TOOLS / "defimon-staleness-check.py",
)
_emit_mod = _load(
    "big_loss_template_registry_emit",
    _TOOLS / "big-loss-template-registry-emit.py",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_registry(extended_corpora: list | None = None) -> dict:
    """Return a minimal registry dict."""
    base: dict = {
        "schema": "auditooor.corpus_registry.v1",
        "generated_at": "2026-05-10T00:00:00Z",
        "corpora": [],
    }
    if extended_corpora is not None:
        base["extended_corpora"] = extended_corpora
    return base


def _write_registry(path: pathlib.Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _defimon_entry(last_mined: str | None = None, ttl_days: int = 30) -> dict:
    entry: dict = {
        "slug": "defimon",
        "source": "https://de.fi/rekt-database",
        "produces": "reference/patterns.dsl.r97_defimon_mine/",
        "staleness": {"ttl_days": ttl_days, "status": "stale"},
    }
    if last_mined is not None:
        entry["staleness"]["last_mined"] = last_mined
    return entry


# ---------------------------------------------------------------------------
# (a) defimon-staleness-check tests
# ---------------------------------------------------------------------------

class TestDefimonStalenessCheck(unittest.TestCase):

    def _run(self, registry: dict, extra_args: list | None = None) -> tuple[int, dict | None]:
        """Write registry to tmp, run staleness check, return (exit_code, report|None)."""
        with tempfile.TemporaryDirectory() as td:
            reg_path = pathlib.Path(td) / "corpus_registry.json"
            _write_registry(reg_path, registry)
            args = ["--registry", str(reg_path), "--slug", "defimon", "--json"]
            if extra_args:
                args += extra_args
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            rc = 0
            try:
                with redirect_stdout(buf):
                    rc = _staleness_mod.run(args)
            except SystemExit as exc:
                rc = int(exc.code or 0)
            out = buf.getvalue().strip()
            parsed = json.loads(out) if out else None
            return rc, parsed

    def test_fresh_entry_returns_0(self):
        """Entry mined today should be fresh (exit 0)."""
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = _defimon_entry(last_mined=today, ttl_days=30)
        reg = _make_registry(extended_corpora=[entry])
        rc, report = self._run(reg)
        self.assertEqual(rc, 0)
        self.assertIsNotNone(report)
        self.assertFalse(report["is_stale"])
        self.assertEqual(report["status"], "fresh")

    def test_stale_entry_returns_1(self):
        """Entry mined 60 days ago with ttl=30 should be stale (exit 1)."""
        old = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=60)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = _defimon_entry(last_mined=old, ttl_days=30)
        reg = _make_registry(extended_corpora=[entry])
        rc, report = self._run(reg)
        self.assertEqual(rc, 1)
        self.assertTrue(report["is_stale"])
        self.assertEqual(report["status"], "stale")

    def test_never_mined_is_stale(self):
        """Entry with no last_mined should be treated as never_mined (stale)."""
        entry = _defimon_entry(last_mined=None)
        reg = _make_registry(extended_corpora=[entry])
        rc, report = self._run(reg)
        self.assertEqual(rc, 1)
        self.assertTrue(report["is_stale"])
        self.assertEqual(report["status"], "never_mined")

    def test_missing_slug_exits_2(self):
        """Missing slug in registry should exit 2."""
        reg = _make_registry(extended_corpora=[])
        with tempfile.TemporaryDirectory() as td:
            reg_path = pathlib.Path(td) / "corpus_registry.json"
            _write_registry(reg_path, reg)
            with self.assertRaises(SystemExit) as ctx:
                _staleness_mod.run(["--registry", str(reg_path), "--slug", "defimon", "--json"])
            self.assertEqual(ctx.exception.code, 2)

    def test_json_output_is_parseable(self):
        """--json mode must produce valid JSON with all required keys."""
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = _defimon_entry(last_mined=today)
        reg = _make_registry(extended_corpora=[entry])
        _rc, report = self._run(reg)
        required_keys = {"slug", "last_mined", "age_days", "ttl_days", "is_stale", "status"}
        self.assertTrue(required_keys.issubset(report.keys()))

    def test_ttl_override(self):
        """--ttl-days should override the registry entry's ttl_days."""
        # mined 3 days ago; with ttl=30 it's fresh, with ttl=2 it's stale
        three_days_ago = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = _defimon_entry(last_mined=three_days_ago, ttl_days=30)
        reg = _make_registry(extended_corpora=[entry])
        # With default ttl=30 -> fresh
        rc_fresh, report_fresh = self._run(reg)
        self.assertFalse(report_fresh["is_stale"])
        # With --ttl-days 2 -> stale
        rc_stale, report_stale = self._run(reg, extra_args=["--ttl-days", "2"])
        self.assertTrue(report_stale["is_stale"])

    def test_remine_dry_run_updates_nothing(self):
        """--remine --dry-run should not modify registry last_mined."""
        old = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=60)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = _defimon_entry(last_mined=old, ttl_days=30)
        reg = _make_registry(extended_corpora=[entry])
        with tempfile.TemporaryDirectory() as td:
            reg_path = pathlib.Path(td) / "corpus_registry.json"
            _write_registry(reg_path, reg)
            _staleness_mod.run([
                "--registry", str(reg_path),
                "--slug", "defimon",
                "--remine", "--dry-run",
            ])
            # Registry should still have the old last_mined
            after = json.loads(reg_path.read_text())
            ext_entry = next(
                (e for e in after.get("extended_corpora", []) if e.get("slug") == "defimon"),
                None,
            )
            self.assertIsNotNone(ext_entry)
            self.assertEqual(ext_entry["staleness"].get("last_mined"), old)


# ---------------------------------------------------------------------------
# (b) big-loss-template-registry-emit tests
# ---------------------------------------------------------------------------

class TestBigLossTemplateRegistryEmit(unittest.TestCase):

    def _make_workspace(self) -> tempfile.TemporaryDirectory:
        """Create a minimal workspace (empty ledger — compose will return 0 rows)."""
        td = tempfile.TemporaryDirectory()
        root = pathlib.Path(td.name)
        (root / ".auditooor").mkdir()
        ledger = {
            "schema_version": "auditooor.invariant_ledger.v1",
            "workspace": str(root),
            "rows": [],
        }
        (root / ".auditooor" / "invariant_ledger.json").write_text(json.dumps(ledger))
        return td

    def _make_registry_with_blt(self) -> dict:
        return _make_registry(extended_corpora=[{
            "slug": "big_loss_templates",
            "source": "tools/big-loss-template-compose.py",
            "produces": "auditooor.big_loss_template_composed.v1",
            "staleness": {"last_emitted": None, "ttl_days": 7, "status": "fresh"},
        }])

    def test_apply_writes_last_emitted(self):
        """--apply should write a last_emitted timestamp to the registry row."""
        ws_td = self._make_workspace()
        try:
            reg = self._make_registry_with_blt()
            with tempfile.TemporaryDirectory() as td:
                reg_path = pathlib.Path(td) / "corpus_registry.json"
                _write_registry(reg_path, reg)
                _emit_mod.run(["--workspace", ws_td.name, "--registry", str(reg_path), "--apply"])
                after = json.loads(reg_path.read_text())
                ext_entry = next(
                    (e for e in after.get("extended_corpora", []) if e.get("slug") == "big_loss_templates"),
                    None,
                )
                self.assertIsNotNone(ext_entry)
                self.assertIsNotNone(ext_entry["staleness"].get("last_emitted"))
                self.assertEqual(ext_entry["staleness"]["status"], "fresh")
        finally:
            ws_td.cleanup()

    def test_idempotent_apply(self):
        """Running --apply twice should produce the same registry slug, not duplicate it."""
        ws_td = self._make_workspace()
        try:
            reg = self._make_registry_with_blt()
            with tempfile.TemporaryDirectory() as td:
                reg_path = pathlib.Path(td) / "corpus_registry.json"
                _write_registry(reg_path, reg)
                _emit_mod.run(["--workspace", ws_td.name, "--registry", str(reg_path), "--apply"])
                _emit_mod.run(["--workspace", ws_td.name, "--registry", str(reg_path), "--apply"])
                after = json.loads(reg_path.read_text())
                slugs = [e["slug"] for e in after.get("extended_corpora", [])]
                count = slugs.count("big_loss_templates")
                self.assertEqual(count, 1, "big_loss_templates should appear exactly once")
        finally:
            ws_td.cleanup()

    def test_write_manifest_creates_file(self):
        """--write-manifest should create .auditooor/big_loss_template_composed.json."""
        ws_td = self._make_workspace()
        try:
            reg = self._make_registry_with_blt()
            with tempfile.TemporaryDirectory() as td:
                reg_path = pathlib.Path(td) / "corpus_registry.json"
                _write_registry(reg_path, reg)
                _emit_mod.run([
                    "--workspace", ws_td.name,
                    "--registry", str(reg_path),
                    "--apply",
                    "--write-manifest",
                ])
                manifest_path = pathlib.Path(ws_td.name) / ".auditooor" / "big_loss_template_composed.json"
                self.assertTrue(manifest_path.exists())
                data = json.loads(manifest_path.read_text())
                self.assertIn("schema_version", data)
        finally:
            ws_td.cleanup()


# ---------------------------------------------------------------------------
# (c) audit_pdf_mining_targets.json schema tests
# ---------------------------------------------------------------------------

class TestAuditPdfMiningTargets(unittest.TestCase):

    _TARGETS_PATH = _REPO_ROOT / "reference" / "audit_pdf_mining_targets.json"
    _REQUIRED_FIELDS = {"slug", "title", "source_path", "source_url", "workspace",
                        "protocol_class", "status", "target_loop"}
    _VALID_STATUSES = {"planned", "extracted", "mined"}

    def setUp(self):
        if not self._TARGETS_PATH.exists():
            self.skipTest(f"audit_pdf_mining_targets.json not found at {self._TARGETS_PATH}")
        with self._TARGETS_PATH.open() as fh:
            self._data = json.load(fh)

    def test_schema_field_present(self):
        self.assertIn("schema", self._data)
        self.assertEqual(self._data["schema"], "auditooor.audit_pdf_mining_targets.v1")

    def test_at_least_15_entries(self):
        targets = self._data.get("targets", [])
        self.assertGreaterEqual(len(targets), 15, "Expected at least 15 audit PDF targets")

    def test_all_required_fields_present(self):
        for i, entry in enumerate(self._data.get("targets", [])):
            for field in self._REQUIRED_FIELDS:
                self.assertIn(field, entry, f"Entry #{i} (slug={entry.get('slug')}) missing field '{field}'")

    def test_all_statuses_valid(self):
        for entry in self._data.get("targets", []):
            self.assertIn(
                entry.get("status"),
                self._valid_statuses() if hasattr(self, "_valid_statuses") else self._VALID_STATUSES,
                f"Invalid status '{entry.get('status')}' for slug '{entry.get('slug')}'",
            )

    def _valid_statuses(self):
        return self._VALID_STATUSES

    def test_slugs_unique(self):
        slugs = [e.get("slug") for e in self._data.get("targets", [])]
        self.assertEqual(len(slugs), len(set(slugs)), "Slugs must be unique")


# ---------------------------------------------------------------------------
# (d) corpus_registry.json extended_corpora rows present
# ---------------------------------------------------------------------------

class TestCorpusRegistryExtended(unittest.TestCase):

    _REGISTRY_PATH = _REPO_ROOT / "reference" / "corpus_registry.json"

    def setUp(self):
        if not self._REGISTRY_PATH.exists():
            self.skipTest(f"corpus_registry.json not found at {self._REGISTRY_PATH}")
        with self._REGISTRY_PATH.open() as fh:
            self._data = json.load(fh)

    def test_schema_unchanged(self):
        self.assertEqual(self._data.get("schema"), "auditooor.corpus_registry.v1")

    def test_defimon_extended_row_present(self):
        slugs = [e.get("slug") for e in self._data.get("extended_corpora", [])]
        self.assertIn("defimon", slugs)

    def test_defimon_staleness_fields(self):
        entry = next(
            (e for e in self._data.get("extended_corpora", []) if e.get("slug") == "defimon"),
            None,
        )
        self.assertIsNotNone(entry)
        staleness = entry.get("staleness", {})
        self.assertIn("last_mined", staleness)
        self.assertIn("ttl_days", staleness)
        self.assertIn("status", staleness)

    def test_big_loss_templates_extended_row_present(self):
        slugs = [e.get("slug") for e in self._data.get("extended_corpora", [])]
        self.assertIn("big_loss_templates", slugs)

    def test_big_loss_templates_has_source_and_produces(self):
        entry = next(
            (e for e in self._data.get("extended_corpora", []) if e.get("slug") == "big_loss_templates"),
            None,
        )
        self.assertIsNotNone(entry)
        self.assertIn("source", entry)
        self.assertIn("produces", entry)

    def test_original_corpora_list_preserved(self):
        """The original 'corpora' list must still exist and be non-empty."""
        self.assertIn("corpora", self._data)
        self.assertGreater(len(self._data["corpora"]), 0)


if __name__ == "__main__":
    unittest.main()
