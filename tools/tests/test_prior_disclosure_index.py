from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "prior-disclosure-index.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("prior_disclosure_index", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["prior_disclosure_index"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class PriorDisclosureIndexTests(unittest.TestCase):
    def _workspace(self, root: Path) -> Path:
        ws = root / "morpho"
        (ws / "prior_audits").mkdir(parents=True)
        (ws / "submissions").mkdir()
        (ws / "prior_audits" / ".ingested_findings.tsv").write_text(
            "id\ttitle\tseverity\tstatus\n"
            "L-01\tMorphoChainlinkOracleV2Factory constructor can create broken oracle\tHigh\tpublic-prior\n",
            encoding="utf-8",
        )
        (ws / "prior_audits" / "DIGEST_oracles.md").write_text(
            "# Oracle prior audit digest\n\n"
            "## L-01 Broken oracle through constructor scale factor\n\n"
            "Same contract constructor produces a broken oracle.\n",
            encoding="utf-8",
        )
        (ws / "submissions" / "SUBMISSIONS.md").write_text(
            "# Submissions\n\n"
            "### #I2.A - MorphoChainlinkOracleV2 SCALE_FACTOR=0\n\n"
            "Status: submitted then declined.\n",
            encoding="utf-8",
        )
        return ws

    def _sibling_spark_workspace(self, root: Path) -> Path:
        ws = root / "spark"
        (ws / "submissions").mkdir(parents=True)
        (ws / "submissions" / "SUBMISSIONS.md").write_text(
            "# Spark submissions\n\n"
            "### LEAD H-D - duplicate same root cause as LEAD F-N\n\n"
            "Status: Duplicate / same fix refs.\n\n"
            "### LEAD F-N - duplicate same root cause family as LEAD H-D\n\n"
            "Status: Duplicate / same root cause family.\n",
            encoding="utf-8",
        )
        return ws

    def _reference_files(self, root: Path) -> tuple[Path, Path]:
        outcomes = root / "outcomes.jsonl"
        outcomes.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "workspace": "polymarket",
                            "submission_id": "polymarket-14",
                            "outcome_class": "dupe",
                            "severity_claimed": "High",
                            "status": "Rejected duplicate",
                            "title": "CollateralOfframp.unwrap permanently reverts: Offramp missing WRAPPER_ROLE",
                        }
                    ),
                    json.dumps(
                        {
                            "workspace": "polymarket",
                            "submission_id": "polymarket-129",
                            "outcome_class": "dupe",
                            "severity_claimed": "Medium",
                            "status": "Duplicate, 5 finders",
                            "title": "Trading._settleTakerOrder refund flushes exchange collateral to taker",
                        }
                    ),
                    json.dumps(
                        {
                            "workspace": "morpho",
                            "submission_id": "morpho-I2.A",
                            "outcome_class": "rejected",
                            "severity_claimed": "Critical",
                            "status": "DECLINED",
                            "title": "#I2.A",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        dupes = root / "DUPE_CAUSES.md"
        dupes.write_text(
            "# DUPE_CAUSES\n\n"
            "### morpho/I2.A - DUPE\n"
            "- **Contract:** MorphoChainlinkOracleV2Factory\n"
            "- **Function:** constructor\n"
            "- **Outcome class:** broken-oracle\n"
            "- **Prior finding that dedup'd:** Cantina Oracle audit L-01\n\n"
            "### spark/LEAD H-D - DUPE\n"
            "- **Contract:** Spark SO chain watcher\n"
            "- **Outcome class:** same fix refs as LEAD F-N\n\n"
            "### spark/LEAD F-N - DUPE\n"
            "- **Contract:** Spark SO chain watcher\n"
            "- **Outcome class:** same root cause family as LEAD H-D\n",
            encoding="utf-8",
        )
        return outcomes, dupes

    def test_build_payload_indexes_outcomes_dupes_and_workspace_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = self._workspace(root)
            outcomes, dupes = self._reference_files(root)

            payload = tool.build_payload(
                workspace=ws,
                repo_root=root,
                outcomes_path=outcomes,
                dupe_causes_path=dupes,
                audits_root=root,
                target="morpho",
            )

            self.assertEqual(payload["schema_version"], "auditooor.prior_disclosure_index.v1")
            self.assertGreaterEqual(payload["summary"]["total_rows"], 7)
            self.assertGreaterEqual(payload["summary"]["high_dupe_risk_rows"], 4)
            self.assertIn("duplicate", payload["class_index"]["by_outcome"])
            self.assertIn("oracle-price", payload["class_index"]["by_attack_class"])

    def test_acceptance_examples_are_query_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = self._workspace(root)
            self._sibling_spark_workspace(root)
            outcomes, dupes = self._reference_files(root)
            payload = tool.build_payload(
                workspace=ws,
                repo_root=root,
                outcomes_path=outcomes,
                dupe_causes_path=dupes,
                audits_root=root,
                target="morpho",
            )

            morpho = tool.query_index(payload, "MorphoChainlinkOracleV2Factory constructor broken oracle I2.A")
            poly14 = tool.query_index(payload, "CollateralOfframp unwrap missing WRAPPER_ROLE")
            poly129 = tool.query_index(payload, "Trading settleTakerOrder refund flushes collateral")
            spark = tool.query_index(payload, "Spark LEAD H-D F-N same root cause")

            self.assertTrue(any("morpho" in r["workspace"] and r["dupe_risk_weight"] >= 75 for r in morpho))
            self.assertTrue(any(r["finding_id"] == "polymarket-14" for r in poly14))
            self.assertTrue(any(r["finding_id"] == "polymarket-129" for r in poly129))
            self.assertTrue(any(r["workspace"] == "spark" for r in spark))
            self.assertEqual(spark[0]["workspace"], "spark")
            self.assertGreaterEqual(
                sum(1 for r in spark[:2] if r["workspace"] == "spark"),
                2,
                spark,
            )

    def test_cli_writes_prior_disclosure_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = self._workspace(root)
            outcomes, dupes = self._reference_files(root)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--repo-root",
                    str(root),
                    "--outcomes",
                    str(outcomes),
                    "--dupe-causes",
                    str(dupes),
                    "--audits-root",
                    str(root),
                    "--query",
                    "MorphoChainlinkOracleV2Factory constructor",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            out = ws / ".auditooor" / "prior_disclosure_index.json"
            self.assertTrue(out.is_file())
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("query_results", payload)
            self.assertTrue(payload["query_results"]["MorphoChainlinkOracleV2Factory constructor"])


if __name__ == "__main__":
    unittest.main()
