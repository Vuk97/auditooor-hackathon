from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-corpus-mined.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "corpus_mined_etl"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromCorpusMinedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_corpus_mined")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_corpus_etl")

    def test_segments_bullets_and_novel_headings(self) -> None:
        solodit = self.tool.segment_file(FIXTURE_DIR / "solodit_slice.md")
        code4arena = self.tool.segment_file(FIXTURE_DIR / "code4arena_slice.md")
        defihacklabs = self.tool.segment_file(FIXTURE_DIR / "defihacklabs_catalog.md")

        self.assertEqual([item.title for item in solodit], ["missing-slippage", "fee-uncapped-in-constructor"])
        self.assertEqual(
            [item.title for item in code4arena],
            ["WellUpgradeable-upgradeable-by-anyone", "calcLpTokenSupply-non-convergence-DoS"],
        )
        self.assertEqual(
            [item.title for item in defihacklabs],
            ["2025-11 - Balancer V2 StableMath - $120M lost"],
        )

    def test_extract_records_infers_core_fields(self) -> None:
        records, counters = self.tool.extract_records(FIXTURE_DIR)
        self.assertEqual(counters["documents_scanned"], 3)
        self.assertEqual(len(records), 5)

        by_component = {record["target_component"]: record for record in records}
        slippage = by_component["bridgeFunds()"]
        self.assertEqual(slippage["severity_at_finding"], "high")
        self.assertEqual(slippage["target_domain"], "bridge")
        self.assertEqual(slippage["bug_class"], "missing-slippage")

        balancer = [record for record in records if "Balancer V2" in record["target_component"]][0]
        self.assertEqual(balancer["severity_at_finding"], "critical")
        self.assertEqual(balancer["target_language"], "solidity")
        self.assertEqual(balancer["target_domain"], "dex")
        self.assertEqual(balancer["bug_class"], "precision-loss")
        self.assertEqual(balancer["impact_dollar_class"], ">=$1M")

    def test_cli_writes_schema_valid_yaml_with_deterministic_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--corpus-dir",
                        str(FIXTURE_DIR),
                        "--out-dir",
                        str(out_dir),
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertEqual(len(files), 5)
            self.assertEqual([path.name for path in files], sorted(path.name for path in files))

            schema = self.validator.load_schema()
            for path in files:
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", (path, errors))

    def test_dry_run_and_limit_do_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--corpus-dir",
                        str(FIXTURE_DIR),
                        "--out-dir",
                        str(out_dir),
                        "--limit",
                        "2",
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists())
            records, _ = self.tool.extract_records(FIXTURE_DIR, limit=2)
            self.assertEqual(len(records), 2)

    def test_json_summary_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            records, counters = self.tool.extract_records(FIXTURE_DIR, limit=1)
            paths = self.tool.write_records(records, out_dir, dry_run=True)
            summary = {
                "documents_scanned": counters["documents_scanned"],
                "records_emitted": len(records),
                "files": [str(path) for path in paths],
            }
            encoded = json.dumps(summary, sort_keys=True)
            self.assertIn('"records_emitted": 1', encoded)


if __name__ == "__main__":
    unittest.main()
