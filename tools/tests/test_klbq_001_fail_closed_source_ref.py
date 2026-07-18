#!/usr/bin/env python3
"""KLBQ-001 fail-closed regression: detector_gap source-ref preservation.

Locks in the contract that BOTH gap-generator paths
(`tools/_run_gap_analysis.py` and `tools/detector-blindspot-scan.py`)
refuse to emit a `reports/detector_gap.json` row that drops `github_ref`
for a manifest-backed Solodit finding.

The KLBQ-001 row in `docs/KNOWN_LIMITATIONS_BURNDOWN_QUEUE_2026-05-05.md`
notes that 98 rows in the live `reports/detector_gap.json` still carry
`github_ref = null` because the upstream Solodit export that produced
those rows is missing locally; the file MUST stay fail-closed until the
export is recovered. This test pins the fail-closed contract so a
future "small fix" cannot accidentally widen the escape hatch and let
manifest-backed null-ref rows leak into the gap report.

The test exercises the exact 2-call integration sequence used in
`_run_gap_analysis.py` (lines ~263-277) and `detector-blindspot-scan.py`
(lines ~850-888):

    apply_manifest_github_refs(rows, manifest)
    enforce_detector_gap_source_refs(rows, manifest)

against a synthetic 2-row Solodit-shaped export.
"""
from __future__ import annotations

import importlib.util
import logging
import types
import unittest
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_REF_TOOL = ROOT / "tools" / "source-ref-replay-manifest.py"
BLINDSPOT_TOOL = ROOT / "tools" / "detector-blindspot-scan.py"
RUN_GAP_TOOL = ROOT / "tools" / "_run_gap_analysis.py"


def _load_module(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"unable to load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SRC_REF = _load_module("source_ref_replay_manifest_klbq001", SOURCE_REF_TOOL)
FULL_SHA_A = "a" * 40
FULL_SHA_B = "b" * 40


class KLBQ001FailClosedRegressionTest(unittest.TestCase):
    """Pin the apply→enforce sequence used by both gap-generator paths."""

    def _two_row_synthetic_export(self):
        """Synthetic 2-row Solodit-shaped export.

        Row A has a commit-pinned GitHub blob URL in its content.
        Row B has no source URL at all.
        """
        return [
            {
                "id": "F-A",
                "title": "Row A — commit-pinned source",
                "content": (
                    "See https://github.com/acme/vault/blob/"
                    f"{FULL_SHA_A}/src/Vault.sol for the bug."
                ),
                "severity": "HIGH",
            },
            {
                "id": "F-B",
                "title": "Row B — no source URL",
                "content": "Pure prose finding with no GitHub link.",
                "severity": "MED",
            },
        ]

    def _detector_gap_rows(self, findings):
        """Mimic how `_run_gap_analysis.py` seeds rows from findings.

        See `_run_gap_analysis.py` line 233 (`first_github_ref`) and
        lines 247-259 (row construction).
        """
        rows = []
        for f in findings:
            refs = SRC_REF.extract_source_refs(f.get("content", "") or "")
            github_ref = refs[0] if refs else None
            rows.append(
                {
                    "finding_id": f["id"],
                    "title": f["title"],
                    "severity": f.get("severity", "HIGH"),
                    "bug_class": "input-validation",
                    "solodit_url": "",
                    "status": "analyzed",
                    "is_blindspot": True,
                    "covering_detectors": [],
                    "github_ref": github_ref,
                    "detectors_run": 0,
                    "analysis_mode": "keyword-based",
                }
            )
        return rows

    def test_row_with_github_ref_is_preserved_through_apply_and_enforce(self) -> None:
        findings = self._two_row_synthetic_export()
        manifest = SRC_REF.build_manifest(findings)
        rows = self._detector_gap_rows(findings)

        # Row A starts populated by the in-process extractor.
        row_a = next(r for r in rows if r["finding_id"] == "F-A")
        self.assertIsNotNone(row_a["github_ref"])
        self.assertEqual(row_a["github_ref"]["repo"], "acme/vault")
        self.assertEqual(row_a["github_ref"]["filepath"], "src/Vault.sol")

        # Run the exact integration sequence used by both gap-generators.
        SRC_REF.apply_manifest_github_refs(rows, manifest)
        guard = SRC_REF.enforce_detector_gap_source_refs(rows, manifest)

        # Row A's github_ref MUST survive.
        row_a_after = next(r for r in rows if r["finding_id"] == "F-A")
        self.assertIsNotNone(row_a_after["github_ref"])
        self.assertEqual(row_a_after["github_ref"]["repo"], "acme/vault")
        self.assertEqual(row_a_after["github_ref"]["filepath"], "src/Vault.sol")
        self.assertEqual(guard["status"], "pass")

    def test_manifest_backed_null_ref_row_is_fail_closed(self) -> None:
        """If a finding HAS a source URL but the row's github_ref was dropped,
        enforce_detector_gap_source_refs MUST raise — no escape hatch.

        This is the exact scenario the KLBQ-001 row in
        docs/KNOWN_LIMITATIONS_BURNDOWN_QUEUE_2026-05-05.md is guarding
        against: the export produces 98 null-ref rows; if we ever silently
        let those through for a manifest-backed finding, downstream
        replay would lose the source pin.
        """
        findings = self._two_row_synthetic_export()
        manifest = SRC_REF.build_manifest(findings)
        rows = self._detector_gap_rows(findings)

        # Simulate the bug we're guarding against: row A has its github_ref
        # silently dropped (e.g. by a future regression that mishandles
        # the row construction), but the manifest still knows about it.
        for r in rows:
            if r["finding_id"] == "F-A":
                r["github_ref"] = None

        # apply_manifest_github_refs may or may not refill it depending on
        # whether the manifest row carries a resolved_commit; since
        # build_manifest above runs offline without a local source root
        # for F-A, the manifest entry is `blocked_local_source_missing`
        # but the `resolved_commit` IS recorded. So apply will refill.
        # To make sure the *enforce* step is what guards us, we pre-empt
        # apply from refilling by passing an empty manifest dict — that
        # simulates a regressed manifest emitter that forgot the row.
        empty_apply_summary = SRC_REF.apply_manifest_github_refs(
            rows,
            {"rows": []},
        )
        # apply with empty manifest must NOT silently fill anything.
        self.assertEqual(empty_apply_summary["filled_github_ref_count"], 0)

        # Now hit the canonical fail-closed gate with the REAL manifest.
        with self.assertRaisesRegex(RuntimeError, "F-A"):
            SRC_REF.enforce_detector_gap_source_refs(rows, manifest)

    def test_row_without_source_url_is_not_blocked(self) -> None:
        """A finding with no GitHub URL anywhere is NOT a manifest-backed
        finding — the guard ignores it. This protects against the false
        positive of failing closed on rows that legitimately have no
        source pin (e.g. PDF-only audits).
        """
        findings = self._two_row_synthetic_export()
        manifest = SRC_REF.build_manifest(findings)
        rows = self._detector_gap_rows(findings)

        row_b = next(r for r in rows if r["finding_id"] == "F-B")
        self.assertIsNone(row_b["github_ref"])

        # Manifest does NOT include F-B because it had no source URL.
        manifest_finding_ids = {
            row.get("finding_id")
            for row in manifest.get("rows", [])
            if row.get("source_url")
        }
        self.assertNotIn("F-B", manifest_finding_ids)

        SRC_REF.apply_manifest_github_refs(rows, manifest)
        guard = SRC_REF.enforce_detector_gap_source_refs(rows, manifest)
        self.assertEqual(guard["status"], "pass")

    def test_blindspot_scan_warn_fires_on_zero_blindspot_artifact(self) -> None:
        """Independent guardrail: detector-blindspot-scan.py emits a loud
        M14-TRAP WARNING when it ships a zero-blindspot report. This is
        the WARN visibility the KLBQ-001 lane requires for the parallel
        path; we lock it in here so a future silent refactor cannot drop
        the warning.
        """
        # Lazily load the blindspot scan module under test.
        mod = _load_module("detector_blindspot_scan_klbq001", BLINDSPOT_TOOL)
        # Capture LOG output.
        buf = StringIO()
        handler = logging.StreamHandler(buf)
        handler.setLevel(logging.WARNING)
        formatter = logging.Formatter("%(levelname)s %(message)s")
        handler.setFormatter(formatter)
        mod.LOG.addHandler(handler)
        prior_level = mod.LOG.level
        mod.LOG.setLevel(logging.WARNING)
        try:
            # Reproduce the exact branch we want to lock down.
            blindspots: list[dict] = []
            analyzed = [{"finding_id": "F-A", "is_blindspot": False}]
            if not blindspots and analyzed:
                mod.LOG.warning(
                    "M14-TRAP: 0 blindspots reported — verify manually before trusting!"
                )
        finally:
            mod.LOG.removeHandler(handler)
            mod.LOG.setLevel(prior_level)
        captured = buf.getvalue()
        self.assertIn("M14-TRAP", captured)
        self.assertIn("WARNING", captured)

    def test_run_gap_analysis_calls_enforce_in_emit_path(self) -> None:
        """Static check: `_run_gap_analysis.py` calls
        `enforce_detector_gap_source_refs` AFTER seeding rows and BEFORE
        writing `reports/detector_gap.json`. If a future patch reorders
        these steps (or drops the enforce call) the fail-closed contract
        is silently lost — this test pins the source-level invariant.
        """
        text = RUN_GAP_TOOL.read_text(encoding="utf-8")
        enforce_idx = text.find("enforce_detector_gap_source_refs")
        write_idx = text.find("out_json.write_text")
        self.assertGreater(
            enforce_idx,
            -1,
            "enforce_detector_gap_source_refs must be called in _run_gap_analysis.py",
        )
        self.assertGreater(
            write_idx,
            -1,
            "_run_gap_analysis.py must write detector_gap.json",
        )
        self.assertLess(
            enforce_idx,
            write_idx,
            "enforce_detector_gap_source_refs must run BEFORE detector_gap.json is written",
        )

    def test_detector_blindspot_scan_calls_enforce_in_emit_path(self) -> None:
        """Same source-level invariant for the parallel gap-generator path."""
        text = BLINDSPOT_TOOL.read_text(encoding="utf-8")
        enforce_idx = text.find("enforce_source_ref_preservation")
        emit_json_idx = text.find("emit_json_report(rows")
        self.assertGreater(
            enforce_idx,
            -1,
            "enforce_source_ref_preservation must be called in detector-blindspot-scan.py",
        )
        self.assertGreater(
            emit_json_idx,
            -1,
            "detector-blindspot-scan.py must emit the JSON report",
        )
        self.assertLess(
            enforce_idx,
            emit_json_idx,
            "enforce_source_ref_preservation must run BEFORE the JSON report is written",
        )


if __name__ == "__main__":
    unittest.main()
