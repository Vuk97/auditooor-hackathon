"""Hermetic smoke coverage for tools/gap-analyzer.py.

The smoke mode proves parser/scoring/report mechanics without claiming real
Solodit or audit-corpus parity.

P2-2 burn-down expansion:
  * The fixture covers four buckets: covered-keyword, covered-semantic,
    negative-clean, gap-novel.
  * Each fixture finding carries a `fixture_kind` annotation; the
    invariants are checked here so the fixture cannot regress.
  * The CLI emits a JSON manifest at
    `<repo>/.auditooor/gap_analysis_smoke.json` whose schema is asserted
    in `test_smoke_manifest_schema_valid`.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "gap-analyzer.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("gap_analyzer", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class GapAnalyzerSmokeTest(unittest.TestCase):
    def test_smoke_corpus_has_covered_negative_and_gap_rows(self) -> None:
        tool = _load_tool()
        classes = tool.load_bug_classes()
        findings = tool.load_smoke_corpus()

        report = tool.render_report(
            corpus_path=tool.SMOKE_CORPUS_LABEL,
            findings=findings,
            classes=classes,
            threshold=5,
            top_n=3,
        )

        # Header references the smoke label, not a real corpus.
        self.assertIn("hermetic-smoke-fixture", report)

        # Five fixtures: 3 covered, 2 gaps (1 negative-clean + 1 gap-novel).
        self.assertIn("Findings scanned: **5**", report)
        self.assertIn(
            "Covered (top score >= 5): **3**",
            report.replace("≥", ">="),
        )
        self.assertIn("Gaps (top score < 5 or no match): **2**", report)

        # All four fixture kinds are reachable from the report body.
        self.assertIn("SMOKE-COVERED-REGEX-LIQUIDATION", report)
        self.assertIn("SMOKE-COVERED-REENTRANCY", report)
        self.assertIn("SMOKE-COVERED-SEMANTIC-ORACLE", report)
        self.assertIn("SMOKE-NEGATIVE-CLEAN", report)
        self.assertIn("SMOKE-GAP-NOVEL", report)

    def test_fixture_kind_invariants(self) -> None:
        """Each fixture finding lands in the bucket its kind promises."""
        tool = _load_tool()
        classes = tool.load_bug_classes()
        threshold = tool.SMOKE_EXPECTATIONS["threshold"]

        kinds = {f["id"]: f.get("fixture_kind") for f in tool.load_smoke_corpus()}
        scores = {}
        for f in tool.load_smoke_corpus():
            ranked = tool.analyse_finding(f, classes)
            scores[f["id"]] = ranked[0][0] if ranked else 0

        # Sanity — every fixture has a declared kind.
        self.assertNotIn(None, kinds.values())

        # At least 2 covered hits (a + b in the task spec).
        covered = [fid for fid, k in kinds.items()
                   if k in ("covered-keyword", "covered-semantic")
                   and scores[fid] >= threshold]
        self.assertGreaterEqual(
            len(covered), 2,
            f"expected >= 2 covered fixtures, got {covered} (scores={scores})",
        )

        # Negative-clean fixtures must score 0 — not just below threshold.
        # If they crept above zero we would fail to demonstrate "no detector
        # fires on clean input".
        for fid, k in kinds.items():
            if k == "negative-clean":
                self.assertEqual(
                    scores[fid], 0,
                    f"negative-clean fixture {fid} scored {scores[fid]}; "
                    f"expected 0",
                )

        # Gap-novel fixtures must stay below threshold (else they are not
        # exercising the gap branch).
        for fid, k in kinds.items():
            if k == "gap-novel":
                self.assertLess(
                    scores[fid], threshold,
                    f"gap-novel fixture {fid} scored {scores[fid]} >= "
                    f"threshold {threshold}",
                )

    def test_semantic_predicate_path_actually_contributes(self) -> None:
        """The covered-semantic fixture must score via the description-bigram
        path, not only via keyword matches.

        Without this assertion, the fixture could regress to a pure regex
        hit and the smoke would still claim "semantic" coverage.
        """
        tool = _load_tool()
        classes = tool.load_bug_classes()
        f = next(x for x in tool.load_smoke_corpus()
                 if x["fixture_kind"] == "covered-semantic")
        pinned = f["expected_class_fires"]
        bd = tool.analyse_finding_for_class(f, classes, pinned)
        self.assertIsNotNone(
            bd, f"expected_class_fires={pinned!r} not in registry",
        )
        self.assertGreater(
            bd["desc_bigram"], 0,
            f"covered-semantic fixture {f['id']} scored desc_bigram="
            f"{bd['desc_bigram']} against {pinned!r}; semantic-predicate "
            f"path did not contribute",
        )

    def test_cli_smoke_writes_report_without_corpus_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "gap-smoke.md"
            manifest = Path(tmp) / "gap-smoke.json"
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--smoke",
                 "--out", str(out),
                 "--manifest", str(manifest)],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("mode: smoke", proc.stderr)
            self.assertTrue(out.exists())
            self.assertIn("hermetic-smoke-fixture",
                          out.read_text(encoding="utf-8"))
            # Manifest written, PASS line on stdout.
            self.assertTrue(manifest.exists())
            self.assertIn("[gap-analyzer:smoke] PASS", proc.stdout)

    def test_cli_requires_corpus_without_smoke(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--out", "/tmp/unused-gap-report.md"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(proc.returncode, 2)
        self.assertIn("corpus path required unless --smoke", proc.stderr)

    def test_smoke_manifest_schema_valid(self) -> None:
        """Run the CLI and validate the JSON manifest against the v1 schema."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "gap-smoke.md"
            manifest_path = Path(tmp) / "gap-smoke.json"
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--smoke",
                 "--out", str(out),
                 "--manifest", str(manifest_path)],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        # Top-level schema keys.
        self.assertEqual(manifest["schema_version"], tool.SMOKE_MANIFEST_SCHEMA)
        self.assertEqual(manifest["mode"], "smoke")
        self.assertFalse(manifest["is_real_corpus"])
        self.assertIn("real_corpus_disclaimer", manifest)
        self.assertIn(
            "DOES NOT measure real-corpus parity",
            manifest["real_corpus_disclaimer"],
        )
        self.assertEqual(manifest["corpus_label"], tool.SMOKE_CORPUS_LABEL)
        self.assertTrue(manifest["pass"])
        self.assertEqual(manifest["expected_violations"], [])

        # Counts add up to total findings.
        self.assertEqual(manifest["findings_total"], len(manifest["rows"]))
        self.assertEqual(
            manifest["findings_total"],
            (manifest["covered_total"]
             + manifest["negative_clean_total"]
             + manifest["gap_novel_total"]),
        )
        # Smoke contract minimums.
        self.assertGreaterEqual(manifest["covered_total"], 2)
        self.assertGreaterEqual(manifest["negative_clean_total"], 1)
        self.assertGreaterEqual(manifest["gap_novel_total"], 1)

        # Row-level schema.
        required_row_keys = {
            "id", "title", "fixture_kind", "top_score", "top_class",
            "bucket", "nonzero_match_count", "near_misses",
            "expected_class_fires", "pinned_breakdown",
        }
        ids_seen = set()
        for row in manifest["rows"]:
            self.assertTrue(
                required_row_keys.issubset(row),
                f"row missing keys: {required_row_keys - row.keys()}",
            )
            self.assertIn(row["bucket"],
                          {"covered", "below-threshold", "no-match"})
            self.assertIn(row["fixture_kind"],
                          {"covered-keyword", "covered-semantic",
                           "negative-clean", "gap-novel"})
            ids_seen.add(row["id"])

        # Required IDs present.
        self.assertIn("SMOKE-COVERED-REENTRANCY", ids_seen)
        self.assertIn("SMOKE-COVERED-SEMANTIC-ORACLE", ids_seen)
        self.assertIn("SMOKE-NEGATIVE-CLEAN", ids_seen)

    def test_smoke_default_manifest_under_dot_auditooor(self) -> None:
        """Without --manifest, --smoke writes to <repo>/.auditooor/gap_analysis_smoke.json."""
        tool = _load_tool()
        default_path = REPO / tool.SMOKE_DEFAULT_MANIFEST_REL
        # Clean any stale file so the test is honest about what was written.
        if default_path.exists():
            default_path.unlink()
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--smoke",
                 "--out", str(Path(tmp) / "gap-smoke.md")],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(
                default_path.exists(),
                f"default manifest not written to {default_path}",
            )
            payload = json.loads(default_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"],
                             tool.SMOKE_MANIFEST_SCHEMA)

    def test_makefile_exposes_separate_real_and_smoke_targets(self) -> None:
        text = (REPO / "Makefile").read_text(encoding="utf-8")

        self.assertIn("gaps-smoke:", text)
        self.assertIn("tools/gap-analyzer.py --smoke", text)
        self.assertIn("make gaps CORPUS=/path/to/findings.json", text)
        self.assertIn("does not measure real corpus parity", text)
        # Smoke target writes the manifest to the canonical location.
        self.assertIn(".auditooor/gap_analysis_smoke.json", text)


if __name__ == "__main__":
    unittest.main()
