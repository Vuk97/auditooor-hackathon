#!/usr/bin/env python3
"""Tests for tools/engagement-prescreen.py - corpus-fit prescreen.

Each test builds an isolated fake auditooor repo root under a temp dir so
no real workspace is touched. The fake root ships:

    <root>/reference/patterns.dsl/                      (solidity, no category)
    <root>/reference/patterns.dsl.r94_solodit_go/       (go, no category)
    <root>/reference/patterns.dsl.r94_solodit_oracle/   (solidity, oracle)
    <root>/reference/patterns.dsl.r94_solodit_bridge/   (solidity, bridge)
    <root>/CLAUDE.md                                    (R-rule registry)

Each pattern dir contains a small number of .yaml stubs so the path-based
counter has work to do.

Offline. Stdlib only. No network. No writes outside the tempdir.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


# Load the tool module by file path (script name has a hyphen).
_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "engagement-prescreen.py"
_spec = importlib.util.spec_from_file_location("engagement_prescreen", _TOOL_PATH)
prescreen_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(prescreen_mod)


def _seed_fake_repo(
    root: Path,
    *,
    solidity_count: int = 100,
    go_count: int = 20,
    rust_count: int = 50,
    oracle_count: int = 30,
    bridge_count: int = 25,
    n_rules: int = 30,
) -> None:
    """Seed a fake auditooor repo under `root`."""
    (root / "reference" / "patterns.dsl").mkdir(parents=True)
    (root / "reference" / "patterns.dsl.r94_solodit_go").mkdir(parents=True)
    (root / "reference" / "patterns.dsl.r94_solodit_rust").mkdir(parents=True)
    (root / "reference" / "patterns.dsl.r94_solodit_oracle").mkdir(parents=True)
    (root / "reference" / "patterns.dsl.r94_solodit_bridge").mkdir(parents=True)

    def _spam(directory: Path, n: int) -> None:
        for i in range(n):
            (directory / f"pattern-{i}.yaml").write_text(f"pattern: stub-{i}\n")

    _spam(root / "reference" / "patterns.dsl", solidity_count)
    _spam(root / "reference" / "patterns.dsl.r94_solodit_go", go_count)
    _spam(root / "reference" / "patterns.dsl.r94_solodit_rust", rust_count)
    _spam(root / "reference" / "patterns.dsl.r94_solodit_oracle", oracle_count)
    _spam(root / "reference" / "patterns.dsl.r94_solodit_bridge", bridge_count)

    # CLAUDE.md with N hard-rule headers
    lines = ["# Stub CLAUDE.md\n\n"]
    for i in range(1, n_rules + 1):
        lines.append(f"### Rule {i} - stub-rule-{i}\n\n")
    (root / "CLAUDE.md").write_text("".join(lines))


class TestClassifyPatternDir(unittest.TestCase):
    def test_solidity_default_for_un_suffixed(self):
        # The un-suffixed `patterns.dsl` dir is the corpus-wide solidity
        # bucket; the classifier returns "solidity" by convention.
        lang, fam = prescreen_mod._classify_pattern_dir("patterns.dsl")
        self.assertEqual(lang, "solidity")
        self.assertIsNone(fam)

    def test_solodit_default_solidity(self):
        lang, fam = prescreen_mod._classify_pattern_dir(
            "patterns.dsl.r94_solodit_misc"
        )
        self.assertEqual(lang, "solidity")
        self.assertIsNone(fam)

    def test_go_suffix(self):
        lang, fam = prescreen_mod._classify_pattern_dir(
            "patterns.dsl.r94_solodit_go"
        )
        self.assertEqual(lang, "go")

    def test_rust_suffix(self):
        lang, _ = prescreen_mod._classify_pattern_dir(
            "patterns.dsl.r94_solodit_rust"
        )
        self.assertEqual(lang, "rust")

    def test_oracle_category(self):
        lang, fam = prescreen_mod._classify_pattern_dir(
            "patterns.dsl.r94_solodit_oracle"
        )
        self.assertEqual(lang, "solidity")
        self.assertEqual(fam, "oracle-staleness")

    def test_bridge_category(self):
        _, fam = prescreen_mod._classify_pattern_dir(
            "patterns.dsl.r94_solodit_bridge"
        )
        self.assertEqual(fam, "cross-chain-auth")


class TestScanPatternCorpus(unittest.TestCase):
    def test_basic_counts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root)
            corpus = prescreen_mod._scan_pattern_corpus(root)
            # solidity = unclassified (100) + oracle (30) + bridge (25) = 155
            self.assertEqual(corpus["language_summary"]["solidity"], 155)
            self.assertEqual(corpus["language_summary"]["go"], 20)
            self.assertEqual(corpus["language_summary"]["rust"], 50)
            self.assertEqual(corpus["total_patterns"], 225)
            self.assertEqual(corpus["bug_family_counts"]["oracle-staleness"], 30)
            self.assertEqual(corpus["bug_family_counts"]["cross-chain-auth"], 25)


class TestCountRRules(unittest.TestCase):
    def test_counts_from_in_tree_claudemd(self):
        # Disable HOME so the global CLAUDE.md isn't consulted (point HOME at tmpdir).
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root, n_rules=42)
            with tempfile.TemporaryDirectory() as home_td:
                old_home = os.environ.get("HOME")
                os.environ["HOME"] = home_td
                try:
                    result = prescreen_mod._count_r_rules(root)
                finally:
                    if old_home is not None:
                        os.environ["HOME"] = old_home
            self.assertEqual(result["r_rule_count"], 42)
            self.assertEqual(result["r_rule_ids"][0], 1)
            self.assertEqual(result["r_rule_ids"][-1], 42)


class TestScoreLanguageCoverage(unittest.TestCase):
    def test_unknown_language_zero(self):
        out = prescreen_mod._score_language_coverage(["cairo"], {"solidity": 1000})
        self.assertEqual(out["score"], 0)

    def test_well_covered_language_saturates(self):
        out = prescreen_mod._score_language_coverage(["solidity"], {"solidity": 2000})
        self.assertEqual(out["score"], 100.0)

    def test_two_languages_averaged(self):
        out = prescreen_mod._score_language_coverage(
            ["solidity", "go"], {"solidity": 2000, "go": 10}
        )
        # solidity = 100, go = 40 -> avg 70.0
        self.assertAlmostEqual(out["score"], 70.0)


class TestScoreDetectorDensity(unittest.TestCase):
    def test_density_with_code_loc(self):
        # 100 patterns over 50 kloc = 2 patterns/kloc, saturates -> 100
        out = prescreen_mod._score_detector_density(
            ["solidity"], {"solidity": 100}, 50000
        )
        self.assertEqual(out["score"], 100.0)

    def test_density_no_code_loc(self):
        # Falls back to count bucket: 100 -> 80
        out = prescreen_mod._score_detector_density(
            ["solidity"], {"solidity": 100}, None
        )
        self.assertEqual(out["score"], 80.0)

    def test_density_zero_patterns(self):
        out = prescreen_mod._score_detector_density(
            ["move"], {"solidity": 1000, "move": 0}, 20000
        )
        self.assertEqual(out["score"], 0.0)


class TestPriorAuditSimilarity(unittest.TestCase):
    def test_no_workspace(self):
        out = prescreen_mod._measure_prior_audit_similarity(None)
        self.assertEqual(out["score"], 0)

    def test_workspace_no_prior_audits(self):
        with tempfile.TemporaryDirectory() as td:
            out = prescreen_mod._measure_prior_audit_similarity(Path(td))
            self.assertEqual(out["score"], 0)

    def test_workspace_with_three_files(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            pa = ws / "prior_audits"
            pa.mkdir()
            for i in range(3):
                (pa / f"audit-{i}.txt").write_text("foo bar\n")
            out = prescreen_mod._measure_prior_audit_similarity(ws)
            # 3 files -> base 60, no familiar family hit -> 60
            self.assertEqual(out["score"], 60)
            self.assertEqual(out["n_files"], 3)

    def test_familiar_family_boost(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            pa = ws / "prior_audits"
            pa.mkdir()
            (pa / "report.md").write_text(
                "Issue: reentrancy in vault deposit path\n"
            )
            out = prescreen_mod._measure_prior_audit_similarity(ws)
            # 1 file = 30 + 20 familiar boost = 50
            self.assertEqual(out["score"], 50)
            self.assertIn("reentrancy", out["familiar_family_hits"])


class TestPrescreenComposite(unittest.TestCase):
    def test_high_fit_verdict_solidity_classic(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root, solidity_count=2000, n_rules=40)
            # isolate HOME so global CLAUDE.md does not pollute
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                result = prescreen_mod.prescreen(
                    {
                        "languages": ["solidity"],
                        "categories": ["dex", "vault"],
                        "code_loc": 15000,
                    },
                    repo_root=root,
                )
            self.assertEqual(result["verdict"], "HIGH-FIT")
            self.assertGreaterEqual(result["corpus_fit_score"], 70)

    def test_low_fit_verdict_niche_language(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root, n_rules=5)  # few rules
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                result = prescreen_mod.prescreen(
                    {
                        "languages": ["move"],
                        "categories": ["dex"],
                        "code_loc": 200000,
                    },
                    repo_root=root,
                )
            self.assertEqual(result["verdict"], "LOW-FIT")
            self.assertLess(result["corpus_fit_score"], 40)

    def test_medium_fit_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root, n_rules=15)
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                result = prescreen_mod.prescreen(
                    {
                        "languages": ["rust"],
                        "categories": ["bridge"],
                        "code_loc": 30000,
                    },
                    repo_root=root,
                )
            self.assertIn(result["verdict"], ("MEDIUM-FIT", "HIGH-FIT"))
            self.assertGreaterEqual(result["corpus_fit_score"], 40)

    def test_missing_target_meta_infers_from_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root, n_rules=20)
            ws = root / "fake_ws"
            ws.mkdir()
            (ws / "SCOPE.md").write_text(
                "# Stub scope\nSolidity smart contracts in scope.\n"
            )
            (ws / "INTAKE_BASELINE.md").write_text(
                "Files indexed: 40\nbridge target with merkle proofs\n"
            )
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                result = prescreen_mod.prescreen(
                    {},  # empty meta -> infer
                    workspace_path=ws,
                    repo_root=root,
                )
            self.assertIn(
                "solidity", result["target_meta_used"]["languages"]
            )
            self.assertIn(
                "languages",
                result["target_meta_used"]["inferred_from_workspace_fields"],
            )

    def test_prior_audit_boost_changes_score(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root, n_rules=20)
            ws = root / "fake_ws"
            ws.mkdir()
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                result_no_pa = prescreen_mod.prescreen(
                    {
                        "languages": ["solidity"],
                        "categories": ["dex"],
                        "code_loc": 10000,
                    },
                    workspace_path=ws,
                    repo_root=root,
                )
            pa = ws / "prior_audits"
            pa.mkdir()
            for i in range(7):
                (pa / f"audit-{i}.txt").write_text("reentrancy bug class\n")
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                result_with_pa = prescreen_mod.prescreen(
                    {
                        "languages": ["solidity"],
                        "categories": ["dex"],
                        "code_loc": 10000,
                    },
                    workspace_path=ws,
                    repo_root=root,
                )
            self.assertGreater(
                result_with_pa["corpus_fit_score"],
                result_no_pa["corpus_fit_score"],
            )


class TestCategoryCoverage(unittest.TestCase):
    def test_category_coverage_dex(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root)
            corpus = prescreen_mod._scan_pattern_corpus(root)
            out = prescreen_mod._score_category_coverage(
                ["dex"], corpus["bug_family_counts"]
            )
            # dex bug families = {reentrancy, rounding-asymmetry, decimals-mismatch,
            # hook-bypass, state-machine-race, approval-abuse}
            # corpus only has oracle-staleness + cross-chain-auth -> all uncovered
            self.assertEqual(out["dex"]["covered_in_corpus"], [])
            self.assertGreater(len(out["dex"]["uncovered_in_corpus"]), 0)


class TestSchemaAndJsonOutput(unittest.TestCase):
    def test_schema_field_present(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root)
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                result = prescreen_mod.prescreen(
                    {
                        "languages": ["solidity"],
                        "categories": ["dex"],
                        "code_loc": 10000,
                    },
                    repo_root=root,
                )
            self.assertEqual(result["schema"], "auditooor.engagement_prescreen.v1")
            for key in (
                "engagement_name",
                "target_meta_used",
                "corpus_fit_score",
                "verdict",
                "score_breakdown",
                "category_coverage",
                "setup_time_estimate",
                "corpus_totals",
                "thresholds",
            ):
                self.assertIn(key, result)

    def test_json_subprocess_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(_TOOL_PATH),
                    "--target-meta",
                    '{"languages":["solidity"],"categories":["dex"],"code_loc":10000}',
                    "--repo-root",
                    str(root),
                    "--workspace-name",
                    "fake-ws",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["engagement_name"], "fake-ws")
            self.assertEqual(payload["schema"], "auditooor.engagement_prescreen.v1")


class TestVerdictThresholdEnv(unittest.TestCase):
    def test_env_override_raises_high_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_fake_repo(root, solidity_count=2000, n_rules=40)
            with tempfile.TemporaryDirectory() as home_td:
                os.environ["HOME"] = home_td
                os.environ["AUDITOOOR_PRESCREEN_HIGH_THRESHOLD"] = "99"
                try:
                    result = prescreen_mod.prescreen(
                        {
                            "languages": ["solidity"],
                            "categories": ["dex"],
                            "code_loc": 15000,
                        },
                        repo_root=root,
                    )
                finally:
                    del os.environ["AUDITOOOR_PRESCREEN_HIGH_THRESHOLD"]
            self.assertIn(result["verdict"], ("MEDIUM-FIT", "LOW-FIT"))


class TestInferTargetMetaFromWorkspace(unittest.TestCase):
    def test_infer_solidity_from_scope(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "SCOPE.md").write_text(
                "## In-scope assets\n\nSolidity smart contracts.\n"
            )
            inferred = prescreen_mod._infer_target_meta_from_workspace(ws)
            self.assertIn("solidity", inferred["languages"])

    def test_infer_audit_pin(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "SCOPE.md").write_text(
                "Audit pin: abc1234567890def\n"
            )
            inferred = prescreen_mod._infer_target_meta_from_workspace(ws)
            self.assertTrue(inferred["audit_pin"] is not None)
            self.assertIn("abc1234567890def", inferred["audit_pin"])

    def test_infer_loc_estimate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "INTAKE_BASELINE.md").write_text(
                "Files indexed: 100\n"
            )
            inferred = prescreen_mod._infer_target_meta_from_workspace(ws)
            self.assertEqual(inferred["code_loc"], 25000)  # 100 * 250


class TestSetupTimeEstimate(unittest.TestCase):
    def test_high_fit_short_setup(self):
        self.assertEqual(prescreen_mod._compute_setup_time_estimate(85)["hours_estimated"], 8)

    def test_medium_fit_medium_setup(self):
        self.assertEqual(prescreen_mod._compute_setup_time_estimate(55)["hours_estimated"], 20)

    def test_low_fit_full_setup(self):
        self.assertEqual(prescreen_mod._compute_setup_time_estimate(20)["hours_estimated"], 40)


if __name__ == "__main__":
    unittest.main()
