"""Tests for tools/audit/external-recall-manifest-quality.py."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "audit" / "external-recall-manifest-quality.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(TOOL), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


class ExternalRecallManifestQualityTest(unittest.TestCase):
    def _write_manifest(self, root: Path, samples: list[dict[str, object]]) -> Path:
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "auditooor.external_recall_samples.v1",
                    "samples": samples,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest

    def test_unvalidated_external_rows_block_gap_prioritization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "prod-current",
                        "path": "Verification.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "severity": "HIGH",
                        "source": "external_repo:snowbridge:production",
                    }
                ],
            )

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.external_recall_manifest_quality.v1")
            self.assertEqual(payload["summary"]["needs_source_state_validation"], 1)
            row = payload["rows"][0]
            self.assertFalse(row["gap_prioritization_eligible"])
            self.assertEqual(row["quality_state"], "needs_source_state_validation")

    def test_fixed_or_out_of_class_rows_are_disqualified_not_gaps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "fixed-current",
                        "path": "Verification.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "source_state": "fixed",
                        "finding_ref": "Snowbridge v2 digest-tag fix review",
                    },
                    {
                        "id": "helper",
                        "path": "MMRProof.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "source_state": "out-of-class",
                        "finding_ref": "generic proof helper, no bridge domain dispatch",
                    },
                ],
            )

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["disqualified_source_state"], 2)
            self.assertTrue(
                all(row["quality_state"] == "disqualified_source_state" for row in payload["rows"])
            )
            self.assertFalse(any(row["gap_prioritization_eligible"] for row in payload["rows"]))

    def test_vulnerable_rows_with_evidence_are_gap_eligible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "prefix",
                        "path": "BridgeVerifier.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "source_state": "pre_fix",
                        "vulnerable_commit": "abc123",
                        "finding_ref": "audit report M-01",
                    }
                ],
            )

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["gap_eligible"], 1)
            self.assertEqual(payload["summary"]["blockers"], 0)
            self.assertTrue(payload["rows"][0]["gap_prioritization_eligible"])

    def test_vulnerable_rows_without_evidence_need_validation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "claimed-vulnerable-no-evidence",
                        "path": "BridgeVerifier.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "source_state": "vulnerable",
                    }
                ],
            )

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["needs_source_state_validation"], 1)
            self.assertFalse(payload["rows"][0]["gap_prioritization_eligible"])
            self.assertIn("no source-state evidence", payload["rows"][0]["reasons"][0])

    def test_empty_manifest_has_no_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(root, [])

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["sample_count"], 0)
            self.assertEqual(payload["summary"]["blockers"], 0)

    def test_writes_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "unknown",
                        "path": "Current.sol",
                        "attack_class": "access-control",
                    }
                ],
            )
            report = root / "quality.md"

            proc = _run(str(manifest), "--out-md", str(report), "--warn-only")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            text = report.read_text(encoding="utf-8")
            self.assertIn("External Recall Manifest Quality Gate", text)
            self.assertIn("needs source-state validation", text)
            self.assertIn("unknown", text)

    # -----------------------------------------------------------------------
    # Lane 2 integration: quality report feeds source-completeness gate in
    # the work-queue builder.  These tests confirm that quality-report rows
    # carry the ``source_state`` and ``quality_state`` fields consumed by
    # _source_completeness_envelope.
    # -----------------------------------------------------------------------

    def test_lane2_quality_json_carries_source_state_field(self) -> None:
        """Quality rows for unvalidated samples must carry source_state so the
        work-queue builder can derive row-level source_state."""
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "unvalidated-sample",
                        "path": "BridgeVerifier.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "source": "external_repo:snowbridge:production",
                    }
                ],
            )

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            row = payload["rows"][0]
            # quality_state present and set to the canonical value.
            self.assertEqual(row["quality_state"], "needs_source_state_validation")
            # gap_prioritization_eligible must be False so the work-queue gate
            # routes the row to mine-source / provider_allowed=False.
            self.assertFalse(row["gap_prioritization_eligible"])

    def test_lane2_gap_eligible_quality_row_has_source_state(self) -> None:
        """A gap-eligible quality row must carry source_state='pre_fix' (or
        equivalent) so the work-queue builder can confirm source completeness."""
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "pre-fix-sample",
                        "path": "BridgeVerifier.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "source_state": "pre_fix",
                        "vulnerable_commit": "deadbeef",
                        "finding_ref": "audit-M-01",
                    }
                ],
            )

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            row = payload["rows"][0]
            # Must be gap-eligible so the work-queue can set provider_allowed=True.
            self.assertTrue(row["gap_prioritization_eligible"])
            self.assertEqual(row["quality_state"], "gap_eligible")
            # source_state echoed through so the work-queue row-level field can
            # be derived accurately.
            self.assertIn("source_state", row)

    def test_lane2_disqualified_quality_rows_set_disqualified_source_state(self) -> None:
        """Disqualified (fixed/out-of-class) rows must produce quality_state=
        'disqualified_source_state', which the work-queue gate uses to block
        provider dispatch and route to mine-source."""
        with tempfile.TemporaryDirectory(prefix="external-recall-quality-") as td:
            root = Path(td)
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "fixed-sample",
                        "path": "BridgeVerifier.sol",
                        "attack_class": "bridge-proof-domain-bypass",
                        "source_state": "fixed",
                        "finding_ref": "Snowbridge v2 fix review",
                    }
                ],
            )

            proc = _run(str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            row = payload["rows"][0]
            self.assertEqual(row["quality_state"], "disqualified_source_state")
            self.assertFalse(row["gap_prioritization_eligible"])


if __name__ == "__main__":
    unittest.main()
