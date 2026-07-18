from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-platforms.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


SAMPLE_CYFRIN_REPORT = """# Cyfrin Audit — Example Vault

Repository: example/cyfrin-vault

## H-01 First depositor can inflate ERC4626 shares

Severity: High

An attacker who is the first depositor donates tokens to skew share pricing.
Subsequent depositors round to zero shares. The attacker can then withdraw
nearly all funds.

Recommendation
Seed virtual shares at construction and base share math on internal accounting
rather than raw token balance.

Status: Fixed in commit abc123.

## M-02 Oracle price stale during liquidation

Severity: Medium

The liquidation flow consumes an oracle price that may be stale, causing
incorrect collateral assessments. Recommendation: enforce a freshness bound.

Status: Acknowledged.
"""

SAMPLE_PASHOV_REPORT = """# Pashov Audit Group — Bridge

Repository: github.com/example/bridge

## C-01 Missing input validation in bridge intake permits theft

Severity: Critical

An attacker can submit a cross-chain message with malformed identifiers, and
the bridge intake routes funds without validating recipient. Loss of funds.

Recommendation
Validate every externally supplied recipient, amount and chain id at intake.

Status: Disclosed and patched in PR #42.
"""

SAMPLE_HATS_REPORT = """# Hats Finance — Lending Market

Repository: example/lending

## H-03 Reentrancy in borrow flow

Severity: High

A reentrant callback during borrow lets an attacker drain collateral before
state updates.

Recommendation: move state updates before external calls and add a targeted
reentrancy guard.
"""


SAMPLE_CANTINA_REPORT = """# Cantina Competition — DEX

Repository: example/dex

## M-01 Precision loss in swap rounding

Severity: Medium

Rounding direction favors the actor in certain edge cases of swap math.

Recommendation: use full-precision math and define rounding direction per actor.
"""


def _write_mirror(tmp: Path, platform: str, fname: str, body: str) -> Path:
    mirror = tmp / platform
    mirror.mkdir(parents=True, exist_ok=True)
    (mirror / fname).write_text(body, encoding="utf-8")
    return mirror


class HackermanEtlFromPlatformsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_platforms")

    def test_segments_markdown_findings(self) -> None:
        segments = self.tool.segment_findings(SAMPLE_CYFRIN_REPORT)
        titles = [seg.title for seg in segments]
        self.assertEqual(
            titles,
            [
                "H-01 First depositor can inflate ERC4626 shares",
                "M-02 Oracle price stale during liquidation",
            ],
        )

    def test_parse_mirror_arg_rejects_bad_platform(self) -> None:
        import argparse

        with self.assertRaises(argparse.ArgumentTypeError):
            self.tool.parse_mirror_arg("solodit=/tmp/nope")

    def test_parse_mirror_arg_accepts_known_platform(self) -> None:
        platform, path = self.tool.parse_mirror_arg("Cyfrin=/tmp/foo")
        self.assertEqual(platform, "cyfrin")
        self.assertEqual(path, Path("/tmp/foo"))

    def test_severity_high_critical_medium_info_inferred(self) -> None:
        self.assertEqual(self.tool.infer_severity("Severity: Critical"), "critical")
        self.assertEqual(self.tool.infer_severity("Severity: High"), "high")
        self.assertEqual(self.tool.infer_severity("Severity: Medium"), "medium")
        self.assertEqual(self.tool.infer_severity("Severity: Informational"), "info")
        self.assertEqual(self.tool.infer_severity("Severity: Gas"), "info")

    def test_detect_mitigation_states_three_slots(self) -> None:
        states = self.tool.detect_mitigation_states(
            "Disclosed in 2024. Acknowledged by team. Fixed in commit deadbeef."
        )
        self.assertEqual(set(states.keys()), {"disclosed", "acknowledged", "fixed"})
        self.assertEqual(states["disclosed"], "observed")
        self.assertEqual(states["acknowledged"], "observed")
        self.assertEqual(states["fixed"], "observed")

    def test_detect_mitigation_states_unknown_when_no_signal(self) -> None:
        states = self.tool.detect_mitigation_states("nothing notable here at all")
        self.assertEqual(states["disclosed"], "unknown")
        self.assertEqual(states["acknowledged"], "unknown")
        self.assertEqual(states["fixed"], "unknown")

    def test_extract_records_from_cyfrin_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirror = _write_mirror(tmp_path, "cyfrin", "report.md", SAMPLE_CYFRIN_REPORT)
            records, sidecars, counters = self.tool.extract_records([("cyfrin", mirror)])

        self.assertEqual(counters["documents_scanned"], 1)
        self.assertEqual(counters["documents_with_text"], 1)
        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first["schema_version"], "auditooor.hackerman_record.v1")
        self.assertEqual(first["severity_at_finding"], "high")
        self.assertEqual(first["target_language"], "solidity")
        self.assertEqual(first["target_repo"], "example/cyfrin-vault")
        self.assertTrue(first["source_audit_ref"].startswith("cyfrin:"))
        self.assertEqual(len(sidecars), 2)
        self.assertEqual(sidecars[0]["platform"], "cyfrin")
        self.assertEqual(sidecars[0]["original_severity"], "high")
        # Cyfrin report carries both "Fixed in commit" and an explicit Status
        # field; mitigation_states should reflect that.
        self.assertEqual(sidecars[0]["mitigation_states"]["fixed"], "observed")

    def test_extract_records_multi_platform(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirrors = [
                ("cyfrin", _write_mirror(tmp_path, "cyfrin", "vault.md", SAMPLE_CYFRIN_REPORT)),
                ("pashov", _write_mirror(tmp_path, "pashov", "bridge.md", SAMPLE_PASHOV_REPORT)),
                ("hats", _write_mirror(tmp_path, "hats", "lending.md", SAMPLE_HATS_REPORT)),
                ("cantina", _write_mirror(tmp_path, "cantina", "dex.md", SAMPLE_CANTINA_REPORT)),
            ]
            records, sidecars, counters = self.tool.extract_records(mirrors)

        platforms = sorted({sc["platform"] for sc in sidecars})
        self.assertEqual(platforms, ["cantina", "cyfrin", "hats", "pashov"])
        self.assertEqual(counters["per_platform_counts"]["cyfrin"], 2)
        self.assertEqual(counters["per_platform_counts"]["pashov"], 1)
        self.assertEqual(counters["per_platform_counts"]["hats"], 1)
        self.assertEqual(counters["per_platform_counts"]["cantina"], 1)
        # Critical severity should map to >=$1M
        crit = next(r for r in records if r["severity_at_finding"] == "critical")
        self.assertEqual(crit["impact_dollar_class"], ">=$1M")

    def test_existing_index_dedup_skips_known_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirror = _write_mirror(tmp_path, "cyfrin", "report.md", SAMPLE_CYFRIN_REPORT)
            # Build a one-shot index that already contains the source-ref the
            # ETL will emit; the dedup should drop both findings.
            index_path = tmp_path / "index.jsonl"
            # Reconstruct the deterministic source-ref the ETL would produce.
            mirror_rel = "report.md"
            for ordinal, line in [(1, 3), (2, 16)]:
                # Best-effort: just match by target_repo and known prefix.
                pass
            # Simpler: write index rows with the exact (repo, source_audit_ref)
            # pairs that the ETL emits, by running the ETL once first.
            records, _, _ = self.tool.extract_records([("cyfrin", mirror)])
            with index_path.open("w", encoding="utf-8") as h:
                for record in records:
                    h.write(
                        json.dumps(
                            {
                                "target_repo": record["target_repo"],
                                "source_audit_ref": record["source_audit_ref"],
                            }
                        )
                        + "\n"
                    )
            existing = self.tool.load_existing_repo_title_pairs(index_path)
            self.assertEqual(len(existing), 2)
            records2, sidecars2, counters2 = self.tool.extract_records(
                [("cyfrin", mirror)],
                existing_pairs=existing,
            )

        self.assertEqual(len(records2), 0)
        self.assertEqual(len(sidecars2), 0)
        self.assertEqual(counters2["skipped_as_duplicate"], 2)

    def test_write_records_dry_run_does_not_create_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirror = _write_mirror(tmp_path, "cyfrin", "r.md", SAMPLE_CYFRIN_REPORT)
            records, _, _ = self.tool.extract_records([("cyfrin", mirror)])
            out_dir = tmp_path / "out"
            paths = self.tool.write_records(records, out_dir, dry_run=True)

            self.assertEqual(len(paths), len(records))
            self.assertFalse(out_dir.exists())

    def test_write_records_real_emits_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirror = _write_mirror(tmp_path, "pashov", "b.md", SAMPLE_PASHOV_REPORT)
            records, _, _ = self.tool.extract_records([("pashov", mirror)])
            out_dir = tmp_path / "out"
            paths = self.tool.write_records(records, out_dir, dry_run=False)
            self.assertTrue(out_dir.exists())
            self.assertEqual(len(paths), 1)
            yaml_text = paths[0].read_text(encoding="utf-8")
            self.assertIn("schema_version: auditooor.hackerman_record.v1", yaml_text)
            self.assertIn("severity_at_finding: critical", yaml_text)
            self.assertIn("target_repo:", yaml_text)

    def test_records_pass_canonical_validator(self) -> None:
        """Every emitted record must validate against hackerman_record v1."""
        validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_platforms_test")
        schema = json.loads(
            (REPO_ROOT / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.schema.json")
            .read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirrors = [
                ("cyfrin", _write_mirror(tmp_path, "cyfrin", "vault.md", SAMPLE_CYFRIN_REPORT)),
                ("pashov", _write_mirror(tmp_path, "pashov", "bridge.md", SAMPLE_PASHOV_REPORT)),
                ("hats", _write_mirror(tmp_path, "hats", "lending.md", SAMPLE_HATS_REPORT)),
                ("cantina", _write_mirror(tmp_path, "cantina", "dex.md", SAMPLE_CANTINA_REPORT)),
            ]
            records, _, _ = self.tool.extract_records(mirrors)
            out_dir = tmp_path / "out"
            paths = self.tool.write_records(records, out_dir, dry_run=False)
            for path in paths:
                status, errs = validator.validate_file(path, schema, strict_all=True)
                self.assertEqual(status, "valid", msg=f"{path.name}: {errs}")

    def test_cli_dry_run_writes_stage_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirror = _write_mirror(tmp_path, "cyfrin", "r.md", SAMPLE_CYFRIN_REPORT)
            stage_path = tmp_path / "stage.json"
            out_dir = tmp_path / "out"
            rc = self.tool.main(
                [
                    "--platform-mirror",
                    f"cyfrin={mirror}",
                    "--out-dir",
                    str(out_dir),
                    "--stage-artifact-out",
                    str(stage_path),
                    "--dry-run",
                    "--json-summary",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(stage_path.exists())
            payload = json.loads(stage_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "auditooor.hackerman_platform_stage.v1")
            self.assertGreaterEqual(len(payload["sidecars"]), 1)
            sidecar0 = payload["sidecars"][0]
            self.assertIn("mitigation_states", sidecar0)
            self.assertEqual(set(sidecar0["mitigation_states"].keys()), {"disclosed", "acknowledged", "fixed"})

    def test_cli_rejects_missing_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            rc = self.tool.main(["--out-dir", str(out_dir)])
            self.assertEqual(rc, 2)

    def test_cli_rejects_negative_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirror = _write_mirror(tmp_path, "cyfrin", "r.md", SAMPLE_CYFRIN_REPORT)
            rc = self.tool.main(
                [
                    "--platform-mirror",
                    f"cyfrin={mirror}",
                    "--out-dir",
                    str(tmp_path / "out"),
                    "--limit",
                    "-1",
                ]
            )
            self.assertEqual(rc, 2)

    def test_repo_inference_rejects_pathlike_candidates(self) -> None:
        repo = self.tool.infer_repo("contracts/foo.sol", file_rel_path="report.md")
        self.assertEqual(repo, "unknown")
        repo2 = self.tool.infer_repo("see github.com/example/realrepo for details")
        self.assertEqual(repo2, "example/realrepo")


if __name__ == "__main__":
    unittest.main()
