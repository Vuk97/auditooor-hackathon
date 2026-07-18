"""Tests for tools/sidecar-staleness-gate.py (J3b).

Covers:
  1. All sidecars fresh -> gate pass, exit 0
  2. Stale sidecar with no reason -> warn (non-strict) / fail (strict)
  3. Stale sidecar with SIDECAR_STALE_REASON -> gate pass
  4. Strict mode exits non-zero when stale+no-reason
  5. Failing-subdir classification output
  6. Missing derived dir -> graceful missing rows, no crash
  7. JSON schema field presence
  8. Sidecar file absent -> status=missing, gate=pass
  9. JSONL sidecar with no corpus_fingerprint field -> unknown, gate=pass
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

# Make the tools package importable when running from repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

# Import via load to avoid dashes-in-module-name issue
import importlib.util

_GATE_PATH = REPO_ROOT / "tools" / "sidecar-staleness-gate.py"
spec = importlib.util.spec_from_file_location("sidecar_staleness_gate", _GATE_PATH)
gate_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(gate_mod)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_args(
    derived_dir: str,
    tag_dir: str,
    reasons_file: str,
    strict: bool = False,
    json_out: bool = False,
) -> "gate_mod.argparse.Namespace":  # type: ignore[name-defined]
    import argparse
    ns = argparse.Namespace(
        derived_dir=derived_dir,
        tag_dir=tag_dir,
        reasons_file=reasons_file,
        strict=strict,
        json=json_out,
    )
    return ns


def _write_jsonl_sidecar(path: Path, fingerprint: str) -> None:
    """Write a minimal JSONL sidecar with the given fingerprint as first-line meta."""
    meta = {
        "corpus_fingerprint": fingerprint,
        "corpus_file_count": 42,
        "schema_version": "auditooor.test.v1",
        "sidecar_schema": "auditooor.test.sidecar.v1",
    }
    with path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(meta) + "\n")
        # one dummy record line
        fh.write(json.dumps({"record_id": "test-001"}) + "\n")


def _write_json_meta_sidecar(path: Path, fingerprint: str) -> None:
    """Write a minimal JSON sidecar whose meta subkey holds the fingerprint."""
    data = {
        "schema_version": "auditooor.test.v1",
        "meta": {
            "corpus_fingerprint": fingerprint,
            "generated_at_utc": "2026-05-20T00:00:00Z",
        },
        "payload": [],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_no_fp_jsonl(path: Path) -> None:
    """Write a JSONL sidecar with no corpus_fingerprint in metadata."""
    meta = {"schema_version": "auditooor.test.v1", "records_loaded": 0}
    with path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(meta) + "\n")


def _make_corpus_fingerprint(tag_dir: Path) -> str:
    """Compute the same fingerprint the gate would compute for the given tag_dir."""
    entries: list[tuple[str, int, int]] = []
    yaml_extensions = {".yaml", ".yml"}
    paths = [p for p in tag_dir.rglob("*") if p.is_file() and p.suffix.lower() in yaml_extensions]
    for path in sorted(set(paths)):
        try:
            stat = path.stat()
        except OSError:
            continue
        try:
            name = str(path.relative_to(tag_dir))
        except ValueError:
            name = path.name
        entries.append((name, stat.st_size, stat.st_mtime_ns))
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestAllFreshSidecars(unittest.TestCase):
    """Case 1: all sidecars have current fingerprint -> pass, exit 0."""

    def test_all_fresh_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()
            reasons_file = Path(tmp) / "sidecar_stale_reasons.json"

            # Create one dummy yaml so fingerprint is non-trivial
            (tag_dir / "dummy.yaml").write_text("record_id: test\n", encoding="utf-8")
            current_fp = _make_corpus_fingerprint(tag_dir)

            # Write all four known sidecars with current fingerprint
            _write_jsonl_sidecar(derived_dir / "detector_relationship_records.jsonl", current_fp)
            _write_jsonl_sidecar(derived_dir / "chain_candidates.jsonl", current_fp)
            _write_json_meta_sidecar(derived_dir / "chain_unify_payload.json", current_fp)
            # attack_class_taxonomy has no fp field; handled as 'none'
            (derived_dir / "attack_class_taxonomy.json").write_text(
                json.dumps({"schema": "auditooor.test.v1", "classes": []}), encoding="utf-8"
            )

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file))
            rc, payload = gate_mod.run_gate(args)

        self.assertEqual(rc, 0)
        self.assertEqual(payload["gate"], "pass")
        # detector_relationship_records and chain_candidates should be fresh
        statuses = {r["sidecar"]: r["status"] for r in payload["sidecars"]}
        self.assertEqual(statuses["detector_relationship_records.jsonl"], "fresh")
        self.assertEqual(statuses["chain_candidates.jsonl"], "fresh")


class TestStaleSidecarNoReason(unittest.TestCase):
    """Case 2: stale sidecar + no reason -> warn (non-strict) or fail (strict)."""

    def _setup(self, tmp: str) -> tuple[Path, Path, Path]:
        tag_dir = Path(tmp) / "tags"
        tag_dir.mkdir()
        derived_dir = Path(tmp) / "derived"
        derived_dir.mkdir()
        reasons_file = Path(tmp) / "reasons.json"
        (tag_dir / "dummy.yaml").write_text("record_id: test\n", encoding="utf-8")
        # Write sidecar with a STALE (old) fingerprint
        _write_jsonl_sidecar(derived_dir / "detector_relationship_records.jsonl", "deadbeef" * 8)
        # Other sidecars absent (treated as missing=pass)
        return tag_dir, derived_dir, reasons_file

    def test_stale_no_reason_non_strict_is_warn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir, derived_dir, reasons_file = self._setup(tmp)
            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file), strict=False)
            rc, payload = gate_mod.run_gate(args)

        # non-strict: warn, exit 0
        self.assertEqual(rc, 0)
        self.assertEqual(payload["gate"], "warn")
        stale_rows = [r for r in payload["sidecars"] if r["status"] == "stale"]
        self.assertTrue(len(stale_rows) >= 1)
        self.assertEqual(stale_rows[0]["gate"], "warn")
        self.assertIn("SIDECAR_STALE_REASON_MISSING", stale_rows[0].get("note", ""))

    def test_stale_no_reason_strict_is_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir, derived_dir, reasons_file = self._setup(tmp)
            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file), strict=True)
            rc, payload = gate_mod.run_gate(args)

        # strict: fail, exit 1
        self.assertEqual(rc, 1)
        self.assertEqual(payload["gate"], "fail")


class TestStaleSidecarWithReason(unittest.TestCase):
    """Case 3: stale sidecar but SIDECAR_STALE_REASON present -> gate pass."""

    def test_stale_with_reason_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()
            reasons_file = Path(tmp) / "reasons.json"
            (tag_dir / "dummy.yaml").write_text("record_id: test\n", encoding="utf-8")

            # Stale fingerprint
            _write_jsonl_sidecar(derived_dir / "chain_candidates.jsonl", "stale_fp_" + "0" * 55)

            # Provide a reason for this sidecar
            reasons_file.write_text(
                json.dumps({"chain_candidates.jsonl": "DarkNavy batch run pending; will refresh after ETL"}),
                encoding="utf-8",
            )

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file), strict=True)
            rc, payload = gate_mod.run_gate(args)

        self.assertEqual(rc, 0)
        self.assertEqual(payload["gate"], "pass")
        stale_rows = [r for r in payload["sidecars"] if r["status"] == "stale"]
        self.assertEqual(len(stale_rows), 1)
        self.assertEqual(stale_rows[0]["gate"], "pass")
        self.assertIn("stale_with_reason", stale_rows[0].get("note", ""))


class TestStrictModeExitCode(unittest.TestCase):
    """Case 4: strict mode exits non-zero on stale+no-reason."""

    def test_strict_exit_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()
            reasons_file = Path(tmp) / "reasons.json"
            (tag_dir / "a.yaml").write_text("record_id: x\n", encoding="utf-8")

            # Two stale sidecars, no reasons
            _write_jsonl_sidecar(derived_dir / "detector_relationship_records.jsonl", "old_fp_" + "a" * 57)
            _write_jsonl_sidecar(derived_dir / "chain_candidates.jsonl", "old_fp_" + "b" * 57)

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file), strict=True)
            rc, payload = gate_mod.run_gate(args)

        self.assertNotEqual(rc, 0, "strict mode must exit non-zero when stale+no-reason")
        self.assertEqual(payload["gate"], "fail")
        self.assertEqual(payload["gate_fail_count"], 2)


class TestSubdirClassification(unittest.TestCase):
    """Case 5: failing-subdir acceptance classification."""

    def test_known_subdirs_classified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()
            reasons_file = Path(tmp) / "reasons.json"

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file))
            _, payload = gate_mod.run_gate(args)

        acceptance = {r["subdir"]: r for r in payload["subdir_acceptance"]}

        # corpus_mined must be fanout_fixture_corpus (high confidence synthetic)
        self.assertEqual(acceptance["corpus_mined"]["classification"], "fanout_fixture_corpus")

        # bridge_attacks must be real_anchor
        self.assertEqual(acceptance["bridge_attacks"]["classification"], "real_anchor")

        # pattern_docs must be explicitly_exempted
        self.assertEqual(acceptance["pattern_docs"]["classification"], "explicitly_exempted")

        # vyper_cve must be real_anchor
        self.assertEqual(acceptance["vyper_cve"]["classification"], "real_anchor")

        # near_ink must be real_anchor
        self.assertEqual(acceptance["near_ink"]["classification"], "real_anchor")

        # all entries have required fields
        for row in payload["subdir_acceptance"]:
            self.assertIn("subdir", row)
            self.assertIn("classification", row)
            self.assertIn("confidence", row)
            self.assertIn("reason", row)
            self.assertIn(row["classification"], {"real_anchor", "fanout_fixture_corpus", "explicitly_exempted"})


class TestMissingDerivedDir(unittest.TestCase):
    """Case 6: derived dir absent -> graceful missing rows, no crash."""

    def test_missing_derived_dir_no_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "nonexistent_derived"
            reasons_file = Path(tmp) / "reasons.json"

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file))
            rc, payload = gate_mod.run_gate(args)

        # should not crash; exit 0 (missing dir is not a hard fail - new workspace)
        self.assertEqual(rc, 0)
        # all known sidecars should appear as missing
        statuses = {r["sidecar"]: r["status"] for r in payload["sidecars"]}
        for sidecar_name, _ in gate_mod.KNOWN_SIDECARS:
            self.assertEqual(statuses[sidecar_name], "missing", f"expected missing for {sidecar_name}")


class TestJsonSchemaFieldPresence(unittest.TestCase):
    """Case 7: JSON output has required schema fields."""

    REQUIRED_FIELDS = {
        "schema",
        "gate",
        "strict",
        "current_corpus_fingerprint",
        "corpus_file_count",
        "tag_dir",
        "derived_dir",
        "reasons_file",
        "sidecars_checked",
        "fresh_count",
        "stale_count",
        "stale_no_reason_count",
        "gate_fail_count",
        "gate_warn_count",
        "sidecars",
        "subdir_acceptance",
    }

    def test_schema_fields_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()
            reasons_file = Path(tmp) / "reasons.json"

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file))
            _, payload = gate_mod.run_gate(args)

        for field in self.REQUIRED_FIELDS:
            self.assertIn(field, payload, f"required field '{field}' missing from payload")

        self.assertEqual(payload["schema"], gate_mod.SCHEMA)
        # schema id should match declared constant
        self.assertEqual(payload["schema"], "auditooor.sidecar_staleness_gate.v1")


class TestSidecarFileAbsent(unittest.TestCase):
    """Case 8: sidecar file absent -> status=missing, gate=pass."""

    def test_absent_sidecar_is_missing_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()
            reasons_file = Path(tmp) / "reasons.json"
            (tag_dir / "x.yaml").write_text("record_id: x\n", encoding="utf-8")
            # No sidecar files written at all

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file), strict=True)
            rc, payload = gate_mod.run_gate(args)

        self.assertEqual(rc, 0)
        # All known sidecars should be missing, not stale
        for row in payload["sidecars"]:
            if row["sidecar"] in {name for name, _ in gate_mod.KNOWN_SIDECARS}:
                self.assertEqual(row["status"], "missing", f"{row['sidecar']} should be missing")
                self.assertEqual(row["gate"], "pass", f"missing sidecar should not fail gate")


class TestJsonlNoFingerprintField(unittest.TestCase):
    """Case 9: JSONL sidecar with no corpus_fingerprint -> unknown, gate=pass."""

    def test_no_fp_field_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "tags"
            tag_dir.mkdir()
            derived_dir = Path(tmp) / "derived"
            derived_dir.mkdir()
            reasons_file = Path(tmp) / "reasons.json"
            (tag_dir / "y.yaml").write_text("record_id: y\n", encoding="utf-8")

            _write_no_fp_jsonl(derived_dir / "detector_relationship_records.jsonl")

            args = _make_args(str(derived_dir), str(tag_dir), str(reasons_file), strict=True)
            rc, payload = gate_mod.run_gate(args)

        self.assertEqual(rc, 0)
        row = next(r for r in payload["sidecars"] if r["sidecar"] == "detector_relationship_records.jsonl")
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["gate"], "pass")


if __name__ == "__main__":
    unittest.main()
