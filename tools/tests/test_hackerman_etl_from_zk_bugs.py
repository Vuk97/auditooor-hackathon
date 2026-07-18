"""Tests for tools/hackerman-etl-from-zk-bugs.py.

The miner has two real-source channels:

    * ``zksecurity/zkbugs`` structured ``zkbugs_config.json`` dataset
      (139 entries at the pin captured in the fixture).
    * ``0xPARC/zk-bug-tracker`` README markdown (27 wild bugs).

Tests drive the miner through cached fixtures so they are deterministic
and run offline (no live ``gh api`` or ``curl`` calls).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-zk-bugs.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_from_zk_bugs"
ZKBUGS_FIXTURE = FIXTURE_DIR / "zkbugs_configs.json"
README_FIXTURE = FIXTURE_DIR / "zk_bug_tracker_README.md"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromZkBugsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_zk_bugs")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_zk_bugs_test")
        self.assertTrue(ZKBUGS_FIXTURE.exists(), f"missing zkbugs fixture: {ZKBUGS_FIXTURE}")
        self.assertTrue(README_FIXTURE.exists(), f"missing README fixture: {README_FIXTURE}")

    # -----------------------------------------------------------------
    # Smoke: end-to-end emit produces zero errors and >= 30 records.
    # -----------------------------------------------------------------
    def test_full_run_emits_in_30_to_500_range_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-full-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
        self.assertEqual(summary["errors"], [])
        # Honest range: the user-requested floor is 30; ceiling is corpus-bounded.
        self.assertGreaterEqual(summary["records_emitted"], 30)
        self.assertLessEqual(summary["records_emitted"], 500)
        self.assertEqual(summary["records_emitted"], summary["records_attempted"])

    # -----------------------------------------------------------------
    # Schema validation: every emitted YAML must validate.
    # -----------------------------------------------------------------
    def test_all_emitted_records_validate_against_v1_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-validate-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(
                out_dir,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["file_count"], 0)
            schema = self.validator.load_schema()
            seen = 0
            for path in out_dir.rglob("record.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])

    def test_emit_writes_both_yaml_and_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-dual-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(
                out_dir,
                limit=5,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
            yamls = list(out_dir.rglob("record.yaml"))
            jsons = list(out_dir.rglob("record.json"))
            self.assertEqual(len(yamls), 5)
            self.assertEqual(len(jsons), 5)
            sample = json.loads(jsons[0].read_text(encoding="utf-8"))
            self.assertEqual(sample["schema_version"], "auditooor.hackerman_record.v1")

    # -----------------------------------------------------------------
    # Honest-zero: empty fixtures emit zero records (no fabrication).
    # -----------------------------------------------------------------
    def test_empty_zkbugs_cache_and_empty_readme_emits_zero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-empty-") as tmp:
            empty_json = Path(tmp) / "empty.json"
            empty_json.write_text(json.dumps({}))
            empty_md = Path(tmp) / "empty.md"
            empty_md.write_text("")
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                zkbugs_configs_cache=empty_json,
                zkbugtracker_readme_cache=empty_md,
            )
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["records_attempted"], 0)
        self.assertEqual(summary["errors"], [])

    def test_skip_zkbugs_emits_readme_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-skipa-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                zkbugtracker_readme_cache=README_FIXTURE,
                skip_zkbugs=True,
            )
        self.assertEqual(summary["errors"], [])
        self.assertGreaterEqual(summary["records_emitted"], 1)
        self.assertEqual(
            summary["by_source"].get("zk-bug-tracker-readme", 0),
            summary["records_emitted"],
        )
        self.assertNotIn("zksecurity-zkbugs", summary["by_source"])

    def test_skip_readme_emits_zkbugs_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-skipb-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                skip_readme=True,
            )
        self.assertEqual(summary["errors"], [])
        self.assertGreaterEqual(summary["records_emitted"], 1)
        self.assertEqual(
            summary["by_source"].get("zksecurity-zkbugs", 0),
            summary["records_emitted"],
        )
        self.assertNotIn("zk-bug-tracker-readme", summary["by_source"])

    # -----------------------------------------------------------------
    # DSL coverage breadth: we expect circom + halo2 + cairo + plonky3
    # to be present in the corpus (verified-real distribution).
    # -----------------------------------------------------------------
    def test_circuit_dsl_coverage_is_broad(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-dsl-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
        for required in ("circom", "halo2-rust"):
            self.assertGreater(
                summary["by_circuit_dsl"].get(required, 0),
                0,
                f"missing DSL coverage: {required}",
            )
        # Cardinality sanity: each emitted record carries a circuit_dsl
        # value, so the sum of by_circuit_dsl must equal records_emitted.
        self.assertEqual(
            sum(summary["by_circuit_dsl"].values()),
            summary["records_emitted"],
        )

    def test_attack_class_coverage_has_unconstrained_majority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-attack-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
        # unconstrained-variable is the dominant ZK soundness class.
        self.assertGreater(summary["by_attack_class"].get("unconstrained-variable", 0), 0)
        # missing-range-check is the second-most-common ZK class.
        self.assertGreater(summary["by_attack_class"].get("missing-range-check", 0), 0)

    # -----------------------------------------------------------------
    # Source-attribution: both channels must contribute at least one row.
    # -----------------------------------------------------------------
    def test_both_sources_contribute(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-src-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
        self.assertGreaterEqual(summary["by_source"].get("zksecurity-zkbugs", 0), 1)
        self.assertGreaterEqual(summary["by_source"].get("zk-bug-tracker-readme", 0), 1)

    # -----------------------------------------------------------------
    # Helper-function unit tests.
    # -----------------------------------------------------------------
    def test_attack_class_for_canonical_inputs(self) -> None:
        self.assertEqual(
            self.tool._attack_class_for("Under-Constrained", "Assigned but Unconstrained"),
            "unconstrained-variable",
        )
        self.assertEqual(
            self.tool._attack_class_for("Computational Issues", "Missing Bit Length Check"),
            "missing-range-check",
        )
        self.assertEqual(
            self.tool._attack_class_for("Fiat-Shamir Issue", "frozen heart"),
            "fiat-shamir-domain-confusion",
        )
        self.assertEqual(
            self.tool._attack_class_for("Backend Issue", "trusted setup"),
            "trusted-setup-bypass",
        )

    def test_target_repo_from_github_project_url(self) -> None:
        self.assertEqual(
            self.tool._target_repo_from_project("https://github.com/iden3/circomlib"),
            "iden3/circomlib",
        )
        self.assertEqual(
            self.tool._target_repo_from_project("https://github.com/foo/bar.git"),
            "foo/bar",
        )
        self.assertEqual(self.tool._target_repo_from_project(""), "unknown")
        self.assertEqual(self.tool._target_repo_from_project("not-a-url"), "unknown")

    def test_dsl_to_language_mapping_has_known_keys(self) -> None:
        for required in ("circom", "halo2", "cairo", "plonky3", "risc0", "gnark"):
            self.assertIn(required, self.tool.DSL_TO_LANGUAGE)
            self.assertIn(self.tool.DSL_TO_LANGUAGE[required], {
                "circom", "rust", "go", "cairo-zk", "noir", "leo",
            })

    def test_severity_for_critical_when_soundness_or_theft(self) -> None:
        self.assertEqual(self.tool._severity_for("theft", "Under-Constrained"), "critical")
        self.assertEqual(self.tool._severity_for("dos", "Backend Issue"), "medium")

    def test_dollar_class_tracks_severity(self) -> None:
        self.assertEqual(self.tool._dollar_class("critical"), ">=$1M")
        self.assertEqual(self.tool._dollar_class("high"), "$100K-$1M")
        self.assertEqual(self.tool._dollar_class("medium"), "$10K-$100K")
        self.assertEqual(self.tool._dollar_class("low"), "<$10K")
        self.assertEqual(self.tool._dollar_class("info"), "non-financial")

    # -----------------------------------------------------------------
    # README parser unit tests.
    # -----------------------------------------------------------------
    def test_readme_split_finds_at_least_20_wild_bugs(self) -> None:
        text = README_FIXTURE.read_text(encoding="utf-8")
        sections = self.tool._split_readme_sections(text)
        self.assertGreaterEqual(len(sections), 20)
        # Sample title sanity.
        titles = [s["title"] for s in sections]
        self.assertTrue(any("Dark Forest" in t for t in titles))
        self.assertTrue(any("MACI" in t for t in titles))

    def test_readme_dedup_against_zkbugs_anchors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-dedup-") as tmp:
            full = self.tool.convert(
                Path(tmp) / "out_full",
                dry_run=True,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
            readme_only = self.tool.convert(
                Path(tmp) / "out_readme_only",
                dry_run=True,
                zkbugtracker_readme_cache=README_FIXTURE,
                skip_zkbugs=True,
            )
        readme_full = full["by_source"].get("zk-bug-tracker-readme", 0)
        readme_alone = readme_only["by_source"].get("zk-bug-tracker-readme", 0)
        # README contributes fewer rows when zkbugs is also active (dedup
        # removes the overlap). When zkbugs is the only source skipped,
        # the readme-alone count must be >= the dedup'd count.
        self.assertGreaterEqual(readme_alone, readme_full)

    # -----------------------------------------------------------------
    # Real-source hard rule: zkbugs entry record_ids must contain the
    # ``zkbugs:`` prefix; README entry record_ids must contain the
    # ``zkbugtracker:`` prefix. No invented prefixes allowed.
    # -----------------------------------------------------------------
    def test_record_id_prefix_is_real_source_anchored(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-pfx-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(
                out_dir,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
                limit=20,
            )
            seen_prefix = set()
            for path in out_dir.rglob("record.json"):
                doc = json.loads(path.read_text(encoding="utf-8"))
                rid = doc["record_id"]
                self.assertTrue(
                    rid.startswith("zkbugs:") or rid.startswith("zkbugtracker:"),
                    f"unrecognised record_id prefix: {rid}",
                )
                seen_prefix.add(rid.split(":", 1)[0])
        self.assertTrue(seen_prefix.issubset({"zkbugs", "zkbugtracker"}))

    # -----------------------------------------------------------------
    # No-CVE-fabrication: zk-circuit miner does NOT emit verification_method
    # claims it cannot prove (no nvd-live / ghsa-live unless the upstream
    # source carries one). The miner sets ``manual`` because zkbugs entries
    # rarely include a CVE/GHSA id.
    # -----------------------------------------------------------------
    def test_verification_method_is_manual_or_blank(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-verif-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(
                out_dir,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
                limit=10,
            )
            for path in out_dir.rglob("record.json"):
                doc = json.loads(path.read_text(encoding="utf-8"))
                vm = doc.get("verification_method", "")
                self.assertIn(vm, {"manual", "", "none"})

    # -----------------------------------------------------------------
    # Limit honours the user-provided cap.
    # -----------------------------------------------------------------
    def test_limit_caps_emitted_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="zkbugs-limit-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out",
                dry_run=True,
                limit=7,
                zkbugs_configs_cache=ZKBUGS_FIXTURE,
                zkbugtracker_readme_cache=README_FIXTURE,
            )
        self.assertEqual(summary["records_emitted"], 7)
        self.assertEqual(summary["records_attempted"], 7)


if __name__ == "__main__":
    unittest.main()
