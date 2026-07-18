from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-github-advisory.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE = (
    REPO_ROOT
    / "tools"
    / "tests"
    / "fixtures"
    / "hackerman_etl_from_github_advisory"
    / "sample_advisories.json"
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromGithubAdvisoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_github_advisory")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_ghsa_test")
        self.assertTrue(FIXTURE.exists(), f"fixture missing: {FIXTURE}")

    # -----------------------------------------------------------------
    # Schema validation: every emitted record must validate.
    # -----------------------------------------------------------------
    def test_cache_driven_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ghsa-dry-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out", dry_run=True, cache_file=FIXTURE
            )
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)
        self.assertEqual(summary["records_emitted"], summary["records_attempted"])

    def test_all_emitted_records_validate_against_v1_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ghsa-write-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir, cache_file=FIXTURE)
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["file_count"], 0)
            schema = self.validator.load_schema()
            seen = 0
            for path in out_dir.glob("*.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])

    # -----------------------------------------------------------------
    # Real-source-driven: zero advisories means honest zero.
    # -----------------------------------------------------------------
    def test_honest_zero_for_zero_advisory_repo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ghsa-zero-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                cache_file=FIXTURE,
                filter_repo="paradigmxyz/reth",
            )
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["records_attempted"], 0)
        self.assertEqual(summary["errors"], [])
        self.assertIn("paradigmxyz/reth", summary["repos_with_zero_advisories"])

    def test_zero_repo_does_not_invent_records(self) -> None:
        """Even when the fixture has the repo key present, the value [] must
        produce zero records (no synthesis)."""
        with tempfile.TemporaryDirectory(prefix="ghsa-noinvent-") as tmp:
            payload_path = Path(tmp) / "empty.json"
            payload_path.write_text(json.dumps({}))
            summary = self.tool.convert(
                Path(tmp) / "out", dry_run=True, cache_file=payload_path
            )
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["errors"], [])

    # -----------------------------------------------------------------
    # Repo coverage + language fan-out.
    # -----------------------------------------------------------------
    def test_top_repo_list_has_minimum_breadth(self) -> None:
        """The static repo list must span Solidity / Go / Rust and be >= 20."""
        repos = list(self.tool.TOP_REPOS)
        self.assertGreaterEqual(len(repos), 20)
        langs = {lang for _r, lang, _d in repos}
        for required in ("solidity", "go", "rust"):
            self.assertIn(required, langs)

    def test_known_repos_present_in_top_list(self) -> None:
        repo_names = {r for r, _l, _d in self.tool.TOP_REPOS}
        for required in (
            "OpenZeppelin/openzeppelin-contracts",
            "Uniswap/v3-core",
            "aave/aave-v3-core",
            "dydxprotocol/v4-chain",
            "cosmos/cosmos-sdk",
            "cometbft/cometbft",
            "paradigmxyz/reth",
            "vyperlang/vyper",
            "ethereum/solidity",
            "OffchainLabs/nitro",
            "ethereum-optimism/optimism",
            "foundry-rs/foundry",
            "ProjectOpenSea/seaport",
        ):
            self.assertIn(required, repo_names, f"missing repo {required}")

    # -----------------------------------------------------------------
    # Per-advisory field mapping.
    # -----------------------------------------------------------------
    def test_severity_mapping_normalises_moderate(self) -> None:
        self.assertEqual(self.tool._normalize_severity("moderate"), "medium")
        self.assertEqual(self.tool._normalize_severity("Critical"), "critical")
        self.assertEqual(self.tool._normalize_severity(None), "info")

    def test_dollar_class_tracks_severity(self) -> None:
        self.assertEqual(self.tool._dollar_class("critical"), ">=$1M")
        self.assertEqual(self.tool._dollar_class("high"), "$100K-$1M")
        self.assertEqual(self.tool._dollar_class("medium"), "$10K-$100K")
        self.assertEqual(self.tool._dollar_class("low"), "<$10K")
        self.assertEqual(self.tool._dollar_class("info"), "non-financial")

    def test_mitigation_state_mitigated_when_patched_versions(self) -> None:
        advisory = {
            "vulnerabilities": [
                {"package": {"name": "x"}, "patched_versions": "5.4.0"}
            ]
        }
        self.assertEqual(self.tool._mitigation_state(advisory), "mitigated")

    def test_mitigation_state_proposed_when_no_patched_versions(self) -> None:
        advisory = {
            "vulnerabilities": [
                {"package": {"name": "x"}, "patched_versions": ""}
            ]
        }
        self.assertEqual(self.tool._mitigation_state(advisory), "proposed")

    def test_mitigation_marker_always_present_in_action_sequence(self) -> None:
        """Even a very long description must not strip the mitigation marker."""
        long_desc = "x" * 9000
        advisory = {
            "summary": "Long descr stress test",
            "description": long_desc,
            "vulnerabilities": [
                {"package": {"name": "p"}, "patched_versions": "1.0"}
            ],
        }
        seq = self.tool._attacker_action_sequence(advisory, "go", "mitigated")
        self.assertLessEqual(len(seq), 4900)
        self.assertIn("[mitigation-state=mitigated;", seq)

    # -----------------------------------------------------------------
    # Single-advisory -> record contract.
    # -----------------------------------------------------------------
    def test_advisory_to_record_uses_real_ghsa_id(self) -> None:
        payload = json.loads(FIXTURE.read_text())
        repo, advisories = next(iter(payload.items()))
        self.assertGreater(len(advisories), 0)
        lang_domain = next(
            (lang, domain) for r, lang, domain in self.tool.TOP_REPOS if r == repo
        )
        record = self.tool.advisory_to_record(repo, lang_domain[0], lang_domain[1], advisories[0])
        self.assertEqual(record["schema_version"], self.tool.SCHEMA_VERSION)
        self.assertEqual(record["target_repo"], repo)
        self.assertEqual(record["record_tier"], "public-corpus")
        self.assertEqual(record["source_extraction_method"], "corpus-etl")
        self.assertIn(advisories[0]["ghsa_id"].lower(), record["record_id"])
        # source_audit_ref should be the html_url -> real GitHub link.
        self.assertTrue(
            record["source_audit_ref"].startswith(("https://github.com", "http://github.com"))
            or record["source_audit_ref"].startswith("github.com/"),
            f"source_audit_ref not a github link: {record['source_audit_ref']}",
        )

    def test_record_ids_are_unique_for_full_run(self) -> None:
        records = self.tool.build_records(
            self.tool.fetch_all_advisories(self.tool.TOP_REPOS, cache_file=FIXTURE),
            self.tool.TOP_REPOS,
        )
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)))

    # -----------------------------------------------------------------
    # CLI surface.
    # -----------------------------------------------------------------
    def test_cli_dry_run_with_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ghsa-cli-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--cache-file",
                        str(FIXTURE),
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertGreater(payload["records_emitted"], 0)
            self.assertFalse(out_dir.exists())  # dry-run must not create dir

    def test_cli_limit_rejects_negative(self) -> None:
        rc = self.tool.main(
            ["--out-dir", "/tmp/should-not-be-created-ghsa", "--limit", "-1"]
        )
        self.assertEqual(rc, 2)

    def test_cli_filter_repo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ghsa-cli-filter-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--cache-file",
                        str(FIXTURE),
                        "--filter-repo",
                        "vyperlang/vyper",
                    ]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            for repo in payload["by_repo"]:
                self.assertEqual(repo, "vyperlang/vyper")

    # -----------------------------------------------------------------
    # YAML rendering.
    # -----------------------------------------------------------------
    def test_yaml_scalar_emits_float_as_number(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(4.0), "4.0")

    def test_yaml_scalar_emits_bool_as_unquoted_bool(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(True), "true")
        self.assertEqual(self.tool.yaml_scalar(False), "false")


if __name__ == "__main__":
    unittest.main()
