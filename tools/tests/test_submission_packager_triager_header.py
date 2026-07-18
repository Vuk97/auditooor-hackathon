#!/usr/bin/env python3
"""capv3 iter-v3-8 T4 — Row-7 factory-header consumer tests.

These three hermetic tests lock the behavior of the Row-7
("Triager-risk rules") notes string when the packager's
``build_evidence_matrix`` is called against a bundle that may or may
not contain a factory-rendered ``cantina_ready.md`` (iter-v3-7 T1 /
FIX-7 producer).

Precedence contract (mirrors docstring in ``_read_factory_triager_header``):

  +------------------+------------------+-----------------------------------------------------+
  | pre-submit #20   | factory header   | Row-7 `notes`                                       |
  +==================+==================+=====================================================+
  | present          | markers present  | "pre-submit #20 executed; factory header            |
  |                  |                  |  confirms markers present"                          |
  +------------------+------------------+-----------------------------------------------------+
  | present          | no-known-class   | "pre-submit #20 executed; factory header            |
  |                  |                  |  confirms no-known-class"                           |
  +------------------+------------------+-----------------------------------------------------+
  | present          | missing          | "pre-submit check #20 executed"    [regression-lock]|
  +------------------+------------------+-----------------------------------------------------+
  | absent           | markers present  | "factory header only: markers present (advisory)"   |
  +------------------+------------------+-----------------------------------------------------+
  | absent           | no-known-class   | "factory header only: no-known-class (advisory)"    |
  +------------------+------------------+-----------------------------------------------------+
  | absent           | missing          | "pre-submit output did not include check #20 line"  |
  |                  |                  |                                    [regression-lock]|
  +------------------+------------------+-----------------------------------------------------+

The producer (``tools/submission-factory.py``) is NOT modified by T4;
these tests assert only the consumer wiring.

All tests are fully hermetic (``tempfile`` bundle + no subprocess, no
network). The only imports touched are the in-repo
``tools/submission-packager.py`` via ``importlib``.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGER_PATH = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    """Load ``tools/submission-packager.py`` by file path (the dash in
    the filename blocks direct ``import``)."""
    spec = importlib.util.spec_from_file_location(
        "submission_packager_for_t4", PACKAGER_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _minimal_bundle(tmp: Path, *, severity: str = "Medium") -> Path:
    """Write the minimum set of files ``build_evidence_matrix`` reads.

    Only ``source-draft.md`` is strictly needed for severity extraction —
    the other matrix rows fall through to their N/A / MISSING defaults
    when ``results`` is empty, which is exactly what Row-7 tests want.
    """
    bundle = tmp / "packaged" / "r00-t4"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "source-draft.md").write_text(
        "## Test finding\n"
        f"**Severity**: {severity}\n\n"
        "Target: some contract.\n"
    )
    (bundle / "manifest.json").write_text(json.dumps({"workspace": "t4"}))
    return bundle


def _row7(matrix: dict) -> dict:
    """Return the ``triager_risk`` row from an evidence-matrix dict."""
    for row in matrix.get("rows", []):
        if row.get("key") == "triager_risk":
            return row
    raise AssertionError("triager_risk row missing from matrix")


class FactoryHeaderConsumerTest(unittest.TestCase):
    """Lock the Row-7 notes variants introduced by capv3 iter-v3-8 T4."""

    # ------------------------------------------------------------------
    # 1. Both sources agree: pre-submit #20 present + factory "markers present".
    # ------------------------------------------------------------------
    def test_both_sources_agree_markers_present(self) -> None:
        pkg = _load_packager_module()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = _minimal_bundle(tmp_path)
            # Factory header — iter-v3-7 T1 vocabulary.
            (bundle / "cantina_ready.md").write_text(
                "<!-- triager-risk: markers present -->\n"
                "---\n"
                "title: irrelevant\n"
                "---\n"
            )
            results = {
                "gates": {
                    "variant": {"risk_level": "LOW"},
                    "pre_submit": {
                        "rc": 0,
                        # The glyph + "20." is what Row-7's regex matches.
                        "output": "  ✅ 20. Triager-risk rules — ok\n",
                    },
                },
            }
            matrix = pkg.build_evidence_matrix(
                results,
                draft_path=bundle / "source-draft.md",
                ws=tmp_path,
                poc_found=False,
                bundle_dir=bundle,
            )
            row = _row7(matrix)
            # Status still derives from pre-submit #20 (factory header is
            # notes-only, never promotes PRESENT/MISSING).
            self.assertEqual(row["status"], "PRESENT")
            self.assertEqual(
                row["notes"],
                "pre-submit #20 executed; factory header confirms markers present",
            )

    # ------------------------------------------------------------------
    # 2. Factory header only (no pre-submit #20 output) → advisory notes.
    # ------------------------------------------------------------------
    def test_factory_header_only_no_known_class(self) -> None:
        pkg = _load_packager_module()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = _minimal_bundle(tmp_path)
            (bundle / "cantina_ready.md").write_text(
                "<!-- triager-risk: no-known-class -->\n"
                "---\n"
                "title: irrelevant\n"
                "---\n"
            )
            results = {
                # No pre_submit key at all — simulates packager invocation
                # where Check #20 has not been executed for this bundle.
                "gates": {"variant": {"risk_level": "LOW"}},
            }
            matrix = pkg.build_evidence_matrix(
                results,
                draft_path=bundle / "source-draft.md",
                ws=tmp_path,
                poc_found=False,
                bundle_dir=bundle,
            )
            row = _row7(matrix)
            # Pre-submit absent → status stays MISSING (factory header does
            # not promote).
            self.assertEqual(row["status"], "MISSING")
            self.assertEqual(
                row["notes"],
                "factory header only: no-known-class (advisory)",
            )

    # ------------------------------------------------------------------
    # 3. Factory header missing → existing pre-submit-only notes preserved.
    # ------------------------------------------------------------------
    def test_factory_header_missing_preserves_existing_notes(self) -> None:
        """Regression-lock: bundles that have NOT been run through the
        submission-factory have no ``cantina_ready.md`` yet. Row-7 must
        behave exactly as it did before iter-v3-8 T4 — the notes string
        must be preserved byte-for-byte.
        """
        pkg = _load_packager_module()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = _minimal_bundle(tmp_path)
            # No cantina_ready.md written — this is the existing path.
            self.assertFalse((bundle / "cantina_ready.md").exists())
            results = {
                "gates": {
                    "variant": {"risk_level": "LOW"},
                    "pre_submit": {
                        "rc": 0,
                        "output": "  ✅ 20. Triager-risk rules — ok\n",
                    },
                },
            }
            matrix = pkg.build_evidence_matrix(
                results,
                draft_path=bundle / "source-draft.md",
                ws=tmp_path,
                poc_found=False,
                bundle_dir=bundle,
            )
            row = _row7(matrix)
            self.assertEqual(row["status"], "PRESENT")
            # Byte-for-byte preservation of the pre-iter-v3-8-T4 string.
            self.assertEqual(row["notes"], "pre-submit check #20 executed")


if __name__ == "__main__":
    unittest.main()
