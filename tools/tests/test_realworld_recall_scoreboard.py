#!/usr/bin/env python3
"""Tests for tools/audit/realworld-recall-scoreboard.py.

Stdlib-only. Does NOT require slither (the slither-dependent run path is
exercised by actually running the scoreboard). These tests cover the
held-out discovery, aggregation math, markdown/stdout rendering, and the
own-detector-exclusion logic - the pure-logic surface that must stay correct.
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit" / "realworld-recall-scoreboard.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "realworld_recall_scoreboard", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


class TestSchema(unittest.TestCase):
    def test_schema_constant(self):
        self.assertEqual(M.SCHEMA, "auditooor.realworld_recall_scoreboard.v1")

    def test_limitations_block_present(self):
        # honest discipline: limitations must be enumerated, not hidden
        self.assertGreaterEqual(len(M.LIMITATIONS), 3)
        joined = " ".join(M.LIMITATIONS).lower()
        self.assertIn("lower bound", joined)
        self.assertIn("synthesised", joined)

    def test_solc_version_normalization(self):
        self.assertEqual(M._normalize_solc_version(None), "")
        self.assertEqual(M._normalize_solc_version(""), "")
        self.assertEqual(M._normalize_solc_version("v0.8.28"), "0.8.28")
        self.assertEqual(
            M._normalize_solc_version("0.8.28+commit.7893614a"),
            "0.8.28",
        )

    def test_language_inference(self):
        self.assertEqual(M.infer_target_language("x.sol", {}), "solidity")
        self.assertEqual(M.infer_target_language("x.go", {}), "go")
        self.assertEqual(M.infer_target_language("x.rs", {}), "rust")
        self.assertEqual(
            M.infer_target_language("x.sol", {"target_language": "golang"}),
            "go",
        )
        self.assertEqual(M.infer_target_language("pkg", {"backend": "cosmos"}), "go")
        self.assertEqual(M._sample_engine_for_language("go", {}), "go_wave1")
        self.assertEqual(M._sample_engine_for_language("rust", {}), "rust_wave1")
        self.assertEqual(
            M._sample_engine_for_language("go", {"backend": "cosmos"}),
            "cosmos_dsl",
        )

    def test_attack_class_filter_accepts_repeated_and_comma_values(self):
        self.assertEqual(
            M.parse_attack_class_filter([
                "initializer-front-run,state-change-between-check-and-use",
                "dos-cap-weakening",
            ]),
            [
                "dos-cap-weakening",
                "initializer-front-run",
                "state-change-between-check-and-use",
            ],
        )

    def test_attack_class_filter_matches_primary_or_alias(self):
        rows = [
            {
                "slug": "primary",
                "attack_class": "initializer-front-run",
                "attack_classes": [],
            },
            {
                "slug": "alias",
                "attack_class": "timestamp-manipulation",
                "attack_classes": ["signature-replay-cross-domain"],
            },
            {
                "slug": "other",
                "attack_class": "admin-bypass",
                "attack_classes": [],
            },
        ]
        filtered = M.filter_by_attack_class(
            rows,
            ["initializer-front-run", "signature-replay-cross-domain"],
        )
        self.assertEqual([row["slug"] for row in filtered], ["primary", "alias"])


class TestAggregation(unittest.TestCase):
    def _rec(self, cls, own, indep_any, indep_same, compile_error=None, language="solidity"):
        return {
            "slug": "p", "attack_class": cls, "severity": "HIGH",
            "source": "test", "sample_origin": "internal_fixture",
            "target_language": language,
            "compile_error": compile_error,
            "own_detector_fired": own,
            "independent_any_fired": indep_any,
            "independent_same_class_fired": indep_same,
            "independent_firing_detectors": [],
        }

    def test_self_test_vs_realworld_gap(self):
        # own fires on all 4; independent fires on only 2
        results = [
            self._rec("reentrancy", True, True, True),
            self._rec("reentrancy", True, True, False),
            self._rec("oracle", True, False, False),
            self._rec("oracle", True, False, False),
        ]
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["self_test_own_detector_recall"], 1.0)
        self.assertEqual(overall["realworld_recall_any_independent"], 0.5)
        self.assertEqual(overall["realworld_recall_same_class"], 0.25)
        self.assertEqual(overall["self_test_catches"], 4)
        self.assertEqual(overall["realworld_any_catches"], 2)
        self.assertEqual(overall["by_origin"]["internal_fixture"]["held_out_scorable"], 4)
        self.assertEqual(overall["by_language"]["solidity"]["held_out_scorable"], 4)

    def test_language_breakdown_includes_compile_failures(self):
        results = [
            self._rec("msg-auth", True, True, True, language="go"),
            self._rec(
                "state-root",
                False,
                False,
                False,
                compile_error="compile-error: unsupported language",
                language="rust",
            ),
            self._rec("access-control", True, False, False, language="solidity"),
        ]
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["by_language"]["go"]["held_out_scorable"], 1)
        self.assertEqual(overall["by_language"]["go"]["realworld_recall_same_class"], 1.0)
        self.assertEqual(overall["by_language"]["rust"]["held_out_samples_total"], 1)
        self.assertEqual(overall["by_language"]["rust"]["held_out_scorable"], 0)
        self.assertEqual(overall["by_language"]["rust"]["held_out_compile_failed"], 1)
        self.assertEqual(overall["by_language"]["solidity"]["realworld_recall_same_class"], 0.0)

    def test_external_origin_breakdown(self):
        results = [
            {
                "slug": "external-a",
                "attack_class": "access-control",
                "severity": "HIGH",
                "source": "external_repo:test",
                "sample_origin": "external_repo",
                "compile_error": None,
                "target_language": "solidity",
                "own_detector_fired": False,
                "independent_any_fired": True,
                "independent_same_class_fired": True,
                "independent_firing_detectors": ["det-a"],
            },
            self._rec("access-control", True, False, False),
        ]
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["by_origin"]["external_repo"]["held_out_scorable"], 1)
        self.assertEqual(overall["by_origin"]["external_repo"]["realworld_recall_same_class"], 1.0)
        self.assertEqual(overall["by_origin"]["internal_fixture"]["realworld_recall_same_class"], 0.0)

    def test_same_class_alias_match_metadata(self):
        results = [
            {
                "slug": "glider-ecrecover-no-deadline",
                "attack_class": "timestamp-manipulation",
                "attack_classes": ["signature-replay-cross-domain", "timestamp-manipulation"],
                "severity": "MEDIUM",
                "source": "test",
                "sample_origin": "internal_fixture",
                "compile_error": None,
                "target_language": "solidity",
                "own_detector_fired": True,
                "independent_any_fired": True,
                "independent_same_class_fired": True,
                "independent_firing_detectors": ["sig-signed-action-missing-deadline"],
                "same_class_matching_detectors": [
                    {
                        "detector": "sig-signed-action-missing-deadline",
                        "matched_classes": ["timestamp-manipulation"],
                        "match_mode": "explicit-alias",
                    }
                ],
            }
        ]
        overall, rows = M.aggregate(results)
        self.assertEqual(overall["realworld_recall_same_class"], 1.0)
        self.assertEqual(rows[0]["realworld_recall_same_class"], 1.0)

    def test_compile_failure_excluded_from_scorable(self):
        results = [
            self._rec("x", True, True, True),
            self._rec("x", False, False, False,
                      compile_error="compile-error: boom"),
        ]
        overall, _ = M.aggregate(results)
        self.assertEqual(overall["held_out_scorable"], 1)
        self.assertEqual(overall["held_out_compile_failed"], 1)
        self.assertEqual(overall["realworld_recall_any_independent"], 1.0)

    def test_empty_results(self):
        overall, rows = M.aggregate([])
        self.assertEqual(overall["held_out_scorable"], 0)
        self.assertEqual(overall["realworld_recall_any_independent"], 0.0)
        self.assertEqual(rows, [])

    def test_per_class_ranked_weakest_first(self):
        results = [
            self._rec("strong", True, True, True),
            self._rec("strong", True, True, True),
            self._rec("weak", True, False, False),
            self._rec("weak", True, True, False),
        ]
        _, rows = M.aggregate(results)
        self.assertEqual(rows[0]["attack_class"], "weak")
        self.assertEqual(rows[0]["realworld_recall_same_class"], 0.0)
        self.assertEqual(rows[-1]["attack_class"], "strong")
        self.assertEqual(rows[-1]["realworld_recall_same_class"], 1.0)


class TestReportRendering(unittest.TestCase):
    def test_markdown_contains_headline_metrics(self):
        results = [
            {"slug": "p1", "attack_class": "reentrancy", "severity": "HIGH",
            "source": "Solodit #1", "sample_origin": "external_repo",
             "target_language": "solidity",
             "compile_error": None,
             "own_detector_fired": True, "independent_any_fired": True,
             "independent_same_class_fired": False,
             "independent_firing_detectors": []},
        ]
        overall, rows = M.aggregate(results)
        md = M.build_markdown(overall, rows, 5, "2026-05-17T00:00:00Z")
        self.assertIn("Real-world recall", md)
        self.assertIn("Self-test recall", md)
        self.assertIn("Honest limitations", md)
        self.assertIn("External-only run", md)
        self.assertIn("Origin breakdown", md)
        self.assertIn("Language breakdown", md)
        self.assertIn("external_repo", md)

    def test_external_only_markdown_uses_external_limitations(self):
        results = [
            {"slug": "p1", "attack_class": "reentrancy", "severity": "HIGH",
            "source": "external_repo:test", "sample_origin": "external_repo",
             "target_language": "solidity",
             "compile_error": None,
             "own_detector_fired": False, "independent_any_fired": True,
             "independent_same_class_fired": False,
             "independent_firing_detectors": []},
        ]
        overall, rows = M.aggregate(results)
        md = M.build_markdown(overall, rows, 0, "2026-05-17T00:00:00Z")
        txt = M.build_stdout(overall, 0)
        self.assertIn("External-only run", md)
        self.assertIn("production-source samples", md)
        self.assertNotIn("auditooor-internal synthesised fixtures", md)
        self.assertIn("self-test gap is not applicable", txt)

    def test_stdout_contains_gap_line(self):
        results = [
            {"slug": "p1", "attack_class": "x", "severity": "HIGH",
             "source": "s", "sample_origin": "internal_fixture",
             "target_language": "solidity",
             "compile_error": None,
             "own_detector_fired": True, "independent_any_fired": False,
             "independent_same_class_fired": False,
             "independent_firing_detectors": []},
        ]
        overall, _ = M.aggregate(results)
        txt = M.build_stdout(overall, 0)
        self.assertIn("OVERSTATES real", txt)
        self.assertIn("REAL-WORLD recall", txt)
        # the honest metric must be flagged; the 'any' metric flagged as noise
        self.assertIn("same-class", txt)
        self.assertIn("UPPER BOUND", txt)


class TestHeldOutDiscovery(unittest.TestCase):
    def test_skips_patterns_without_fixtures(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "no-fixture.yaml").write_text(
                "pattern: no-fixture\nseverity: HIGH\nmatch: []\n")
            samples, skipped = M.discover_held_out(d)
            self.assertEqual(len(samples), 0)
            self.assertEqual(skipped, 0)

    def test_counts_missing_fixture_file_as_skipped(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "ghost.yaml").write_text(
                "pattern: ghost\nseverity: HIGH\nmatch: []\n"
                "fixtures:\n  vuln: /nonexistent/vuln.sol\n")
            samples, skipped = M.discover_held_out(d)
            self.assertEqual(len(samples), 0)
            self.assertEqual(skipped, 1)

    def test_library_load_carries_slug_and_predicates(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "det.yaml").write_text(
                "pattern: det\nseverity: HIGH\n"
                "preconditions: []\nmatch:\n  - function.name_matches: '.*'\n")
            library = M.load_detector_library(d)
            self.assertEqual(len(library), 1)
            self.assertEqual(library[0]["slug"], "det")
            self.assertEqual(len(library[0]["match"]), 1)
            self.assertIn("attack_classes", library[0])

    def test_library_load_carries_explicit_attack_class_aliases(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("pyyaml not available")
        library = M.load_detector_library(_REPO / "reference" / "patterns.dsl")
        sig = next(
            row for row in library
            if row["slug"] == "sig-signed-action-missing-deadline"
        )
        self.assertEqual(sig["attack_class"], "signature-replay-cross-domain")
        self.assertIn("timestamp-manipulation", sig["attack_classes"])

    def test_go_wave1_discovery_excludes_proof_of_life(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixtures = root / "test_fixtures"
            fixtures.mkdir()
            (root / "go-demo.py").write_text("def run(engine, filepath): return []\n")
            (root / "proof_of_life.py").write_text("def run(engine, filepath): return []\n")
            (fixtures / "go-demo_positive.go").write_text("package demo\n")
            (fixtures / "go-demo_negative.go").write_text("package demo\n")
            (fixtures / "proof_of_life_positive.go").write_text("package demo\n")
            (fixtures / "proof_of_life_negative.go").write_text("package demo\n")

            samples, skipped = M.discover_go_wave1_held_out(root)

            self.assertEqual(skipped, 0)
            self.assertEqual([sample["exclude_detector_slug"] for sample in samples], ["go-demo"])
            self.assertEqual(samples[0]["target_language"], "go")
            self.assertEqual(samples[0]["engine"], "go_wave1")

    def test_rust_wave1_discovery_requires_matching_detector(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixtures = root / "test_fixtures"
            fixtures.mkdir()
            (root / "rust-demo.py").write_text(
                "def run(tree, source, filepath): return []\n"
            )
            (fixtures / "rust-demo_positive.rs").write_text("fn demo() {}\n")
            (fixtures / "rust-demo_negative.rs").write_text("fn demo() {}\n")
            (fixtures / "missing-detector_positive.rs").write_text("fn demo() {}\n")
            (fixtures / "missing-detector_negative.rs").write_text("fn demo() {}\n")

            samples, skipped = M.discover_rust_wave1_held_out(root)

            self.assertEqual(skipped, 1)
            self.assertEqual([sample["exclude_detector_slug"] for sample in samples], ["rust-demo"])
            self.assertEqual(samples[0]["target_language"], "rust")
            self.assertEqual(samples[0]["engine"], "rust_wave1")

    def test_native_run_uses_language_engine_and_excludes_own_detector(self):
        original = M._run_go_detectors
        try:
            def fake_go_runner(path, detectors, ast_engine_mod):
                return {det["slug"]: det["slug"] in {"own-go", "sibling-go"} for det in detectors}, None

            M._run_go_detectors = fake_go_runner
            samples = [{
                "slug": "native-sample",
                "exclude_detector_slug": "own-go",
                "engine": "go_wave1",
                "vuln_path": Path("sample.go"),
                "target_language": "go",
                "severity": "HIGH",
                "attack_class": "admin-bypass",
                "attack_classes": ["admin-bypass"],
                "source": "test",
                "sample_origin": "internal_fixture",
            }]
            library = [
                {
                    "slug": "own-go",
                    "engine": "go_wave1",
                    "attack_class": "admin-bypass",
                    "attack_classes": ["admin-bypass"],
                },
                {
                    "slug": "sibling-go",
                    "engine": "go_wave1",
                    "attack_class": "admin-bypass",
                    "attack_classes": ["admin-bypass"],
                },
                {
                    "slug": "solidity-detector",
                    "engine": "slither_dsl",
                    "attack_class": "admin-bypass",
                    "attack_classes": ["admin-bypass"],
                },
            ]

            results = M.run_scoreboard(
                samples,
                library,
                {"slither_engine": None, "ast_engine": object(), "cosmos_runner": object()},
                quiet=True,
            )

            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]["own_detector_fired"])
            self.assertTrue(results[0]["independent_same_class_fired"])
            self.assertEqual(results[0]["independent_firing_detectors"], ["sibling-go"])
            self.assertEqual(results[0]["engine"], "go_wave1")
        finally:
            M._run_go_detectors = original

    def test_external_manifest_loads_relative_samples(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "External.sol"
            sample.write_text("contract External { function pwn() external {} }\n")
            manifest = root / "external_samples.json"
            manifest.write_text(
                """{
                  "schema": "auditooor.external_recall_samples.v1",
                  "repo_root": ".",
                  "solc_version": "0.8.28",
                  "samples": [
                    {
                      "id": "ext-1",
                      "path": "External.sol",
                      "attack_class": "access-control",
                      "severity": "HIGH",
                      "source": "external_repo:test"
                    }
                  ]
                }""",
                encoding="utf-8",
            )

            samples, errors = M.discover_external_manifest(manifest)

            self.assertEqual(errors, [])
            self.assertEqual(len(samples), 1)
            self.assertEqual(samples[0]["sample_origin"], "external_repo")
            self.assertEqual(samples[0]["vuln_path"], sample.resolve())
        self.assertEqual(samples[0]["compile_cwd"], str(root.resolve()))
        self.assertEqual(samples[0]["solc_version"], "0.8.28")
        self.assertEqual(samples[0]["target_language"], "solidity")
        self.assertEqual(samples[0]["attack_class"], "admin-bypass")
        self.assertEqual(samples[0]["attack_classes"], ["admin-bypass"])

    def test_external_manifest_row_solc_version_overrides_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "External.sol"
            sample.write_text("contract External { function pwn() external {} }\n")
            manifest = root / "external_samples.json"
            manifest.write_text(
                """{
                  "schema": "auditooor.external_recall_samples.v1",
                  "repo_root": ".",
                  "solc_version": "0.8.24",
                  "samples": [
                    {
                      "id": "ext-1",
                      "path": "External.sol",
                      "attack_class": "access-control",
                      "severity": "HIGH",
                      "source": "external_repo:test",
                      "solc_version": "0.8.28"
                    }
                  ]
                }""",
                encoding="utf-8",
            )

            samples, errors = M.discover_external_manifest(manifest)

            self.assertEqual(errors, [])
            self.assertEqual(samples[0]["solc_version"], "0.8.28")

    def test_external_manifest_target_language_overrides_suffix(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "External.sol"
            sample.write_text("contract External { function pwn() external {} }\n")
            manifest = root / "external_samples.json"
            manifest.write_text(
                """{
                  "schema": "auditooor.external_recall_samples.v1",
                  "repo_root": ".",
                  "samples": [
                    {
                      "id": "ext-1",
                      "path": "External.sol",
                      "target_language": "go",
                      "attack_class": "access-control",
                      "severity": "HIGH",
                      "source": "external_repo:test"
                    }
                  ]
                }""",
                encoding="utf-8",
            )

            samples, errors = M.discover_external_manifest(manifest)

            self.assertEqual(errors, [])
            self.assertEqual(samples[0]["target_language"], "go")

    def test_external_manifest_compiler_version_alias_normalized(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "External.sol"
            sample.write_text("contract External { function pwn() external {} }\n")
            manifest = root / "external_samples.json"
            manifest.write_text(
                """{
                  "schema": "auditooor.external_recall_samples.v1",
                  "repo_root": ".",
                  "compiler_version": "v0.8.28+commit.7893614a",
                  "samples": [
                    {
                      "id": "ext-1",
                      "path": "External.sol",
                      "attack_class": "access-control",
                      "severity": "HIGH",
                      "source": "external_repo:test"
                    }
                  ]
                }""",
                encoding="utf-8",
            )

            samples, errors = M.discover_external_manifest(manifest)

            self.assertEqual(errors, [])
            self.assertEqual(samples[0]["solc_version"], "0.8.28")


if __name__ == "__main__":
    unittest.main()
