#!/usr/bin/env python3
"""Tests for tools/wave4-cross-workspace-all-pairs-fp-matrix.py (Wave-4 W4.3).

Stdlib + PyYAML. All fixtures are synthetic in-tempdir.

Coverage matrix:
  1. classify_attack_class maps known slugs to expected FP buckets.
  2. classify_attack_class returns FP-XX for unrecognized slug.
  3. load_seeds_from_derived_detectors round-trips a synthetic
     derived_detectors YAML and SKIPS synthetic_fixture:true records.
  4. derive_fp_set_for_source groups seeds by FP-XX.
  5. detect_workspace_language correctly tags a Solidity-only and
     Go-only synthetic workspace.
  6. End-to-end dry-run: 3 synthetic workspaces (1 sol-source-seeded,
     1 go-source-seeded, 1 empty) emit a valid matrix JSON envelope
     with candidate-new-universal aggregation.
  7. End-to-end real invocation (no --dry-run): pair-runner subprocess
     fires on a sol target with FP-01 strategy and surfaces hits.
  8. --skip-cross-language drops sol-source -> go-only-target pairs.
  9. --skip-pairs regex filter drops the named pair.
 10. --strict + no candidates -> rc=1.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "wave4-cross-workspace-all-pairs-fp-matrix.py"
RUNNER = ROOT / "tools" / "audit" / "universal_fp_runner.py"


def _run(args, expect_rc=None):
    proc = subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if expect_rc is not None:
        assert proc.returncode == expect_rc, (
            "rc=%d stdout=%s stderr=%s"
            % (proc.returncode, proc.stdout[-400:], proc.stderr[-400:])
        )
    return proc


# Import the tool as a module for white-box tests.
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "wave4_all_pairs_fp_matrix", TOOL
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _write_derived_detector_yaml(target_dir: Path, slug: str, attack_class: str,
                                  target_language: str = "solidity",
                                  synthetic_fixture: bool = False) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / (slug + ".yaml")
    body = textwrap.dedent(
        """\
        record_id: {slug}
        schema_version: auditooor.dsl_pattern.synthetic
        verdict_id: {slug}
        pattern_shape: |
          Synthetic pattern for test of {slug}
        attack_class: {ac}
        target_repo: synthetic/test
        target_language: {lang}
        mitigation_commit_sha: deadbeef
        synthetic_fixture: {synth}
        """
    ).format(
        slug=slug,
        ac=attack_class,
        lang=target_language,
        synth=("true" if synthetic_fixture else "false"),
    )
    path.write_text(body, encoding="utf-8")
    return path


def _write_synth_fp_yaml(target_dir: Path, fp_id: str, lang: str, bug_class: str) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    slug = "%s_synth" % fp_id.lower().replace("-", "_")
    path = target_dir / ("dsl_pattern_universal_fp_%s_%s.yaml" % (fp_id.split("-")[1], slug))
    body = textwrap.dedent(
        """\
        schema_version: auditooor.hackerman_record.v1
        record_id: {slug}
        target_language: {lang}
        bug_class: {bc}
        attack_class: {bc}
        function_shape:
          raw_signature: "synthetic FP {fp_id}"
          shape_tags:
            - {bc}
            - universal-fingerprint
            - fingerprint_id:{fp_id}
            - universality:synthetic-test
            - workspace:test
            - seed:SYN-PAT-001
            - synthetic_fixture:true
        attacker_action_sequence: |-
          Synthetic pattern shape for test of {fp_id}
        """
    ).format(slug=slug, lang=lang, bc=bug_class, fp_id=fp_id)
    path.write_text(body, encoding="utf-8")
    return path


class Wave4AllPairsMatrixTest(unittest.TestCase):
    def test_01_classify_attack_class_known_slugs(self):
        cases = [
            ("missing-validation-on-state-mutation", "FP-01"),
            ("missing-blockedaddr-on-fee-transfer", "FP-01"),
            ("silent-skip-on-missing-map-entry", "FP-01"),
            ("counter-underflow-on-epoch-decrement", "FP-01"),
            ("atomic-multi-write-ordering", "FP-02"),
            ("bank-send-ordering-vs-subaccount-update", "FP-02"),
            ("state-desync-on-config-update", "FP-03"),
            ("memclob-desync-on-clob-pair-update", "FP-03"),
            ("initializer-chain-mismatch-Hardhat3", "FP-03"),
            ("loosened-guard-via-revert-or-refactor", "FP-04"),
            ("commission-cap-enforcement-regression", "FP-04"),
            ("reverted-emergency-disable-without-root-cause", "FP-04"),
            ("enum-rename-stale-reference", "FP-05"),
            ("interface-arity-drift", "FP-06"),
            ("administration-interface-drift", "FP-06"),
        ]
        for slug, expected in cases:
            got = _mod.classify_attack_class(slug)
            self.assertEqual(got, expected, "slug=%s" % slug)

    def test_02_classify_attack_class_unknown_returns_fp_xx(self):
        self.assertEqual(_mod.classify_attack_class(""), "FP-XX")
        self.assertEqual(
            _mod.classify_attack_class("totally-novel-shape-xyz"), "FP-XX"
        )

    def test_03_load_seeds_from_derived_detectors_skips_synthetic(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            dd = ws / "derived_detectors"
            _write_derived_detector_yaml(dd, "p1_missing-validation",
                                         "missing-validation-on-state-mutation",
                                         synthetic_fixture=False)
            _write_derived_detector_yaml(dd, "p2_synthetic",
                                         "atomic-multi-write-ordering",
                                         synthetic_fixture=True)
            seeds = _mod.load_seeds_from_derived_detectors(ws)
            self.assertEqual(len(seeds), 1)
            self.assertEqual(seeds[0]["attack_class"],
                             "missing-validation-on-state-mutation")

    def test_04_derive_fp_set_for_source_groups_by_fp(self):
        seeds = [
            {"attack_class": "missing-validation-on-state-mutation",
             "record_id": "a", "target_language": "solidity"},
            {"attack_class": "interface-arity-drift",
             "record_id": "b", "target_language": "solidity"},
            {"attack_class": "missing-blockedaddr-on-fee-transfer",
             "record_id": "c", "target_language": "go"},
        ]
        by_fp = _mod.derive_fp_set_for_source(seeds)
        self.assertIn("FP-01", by_fp)
        self.assertIn("FP-06", by_fp)
        self.assertEqual(len(by_fp["FP-01"]), 2)
        self.assertEqual(len(by_fp["FP-06"]), 1)

    def test_05_detect_workspace_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws_sol = Path(tmp) / "ws_sol"
            ws_sol.mkdir()
            for i in range(5):
                (ws_sol / ("f%d.sol" % i)).write_text(
                    "contract C {}\n", encoding="utf-8"
                )
            ws_go = Path(tmp) / "ws_go"
            ws_go.mkdir()
            for i in range(5):
                (ws_go / ("f%d.go" % i)).write_text(
                    "package main\nfunc f() {}\n", encoding="utf-8"
                )
            ws_none = Path(tmp) / "ws_none"
            ws_none.mkdir()
            (ws_none / "readme.txt").write_text("text\n", encoding="utf-8")
            self.assertEqual(
                _mod.detect_workspace_language(ws_sol), "solidity"
            )
            self.assertEqual(_mod.detect_workspace_language(ws_go), "go")
            self.assertEqual(_mod.detect_workspace_language(ws_none), "none")

    def test_06_end_to_end_dry_run_emits_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            audits = base / "audits"
            audits.mkdir()
            # 3 synthetic workspaces
            ws_a = audits / "ws_a"  # solidity source-seeded for FP-01
            ws_b = audits / "ws_b"  # go source-seeded for FP-02
            ws_c = audits / "ws_c"  # empty
            for ws, ac, lang in [
                (ws_a, "missing-validation-on-state-mutation", "solidity"),
                (ws_b, "atomic-multi-write-ordering", "go"),
            ]:
                dd = ws / "derived_detectors"
                _write_derived_detector_yaml(dd, "p1_" + ws.name, ac,
                                             target_language=lang)
            ws_c.mkdir()
            # Source files so the workspaces are "target-walkable"
            (ws_a / "C.sol").write_text(
                "contract C { function f() public { x = 1; } }\n",
                encoding="utf-8",
            )
            (ws_b / "m.go").write_text(
                "package main\nfunc f(){\n  k.SetX()\n  k.SetY()\n}\n",
                encoding="utf-8",
            )
            (ws_c / "z.sol").write_text(
                "contract Z { function g() public {} }\n",
                encoding="utf-8",
            )

            fp_dir = base / "tags"
            _write_synth_fp_yaml(fp_dir, "FP-01", "solidity",
                                 "missing-validation-on-state-mutation")
            _write_synth_fp_yaml(fp_dir, "FP-02", "go",
                                 "atomic-multi-write-ordering")

            out_json = base / "matrix.json"
            out_md = base / "matrix.md"
            proc = _run(
                [
                    "--workspaces-glob", str(audits / "*"),
                    "--fp-dir", str(fp_dir),
                    "--seed-source", "derived_detectors",
                    "--out-json", str(out_json),
                    "--out-markdown", str(out_md),
                    "--dry-run",
                    "--workers", "1",
                    "--runner-path", str(RUNNER),
                ],
                expect_rc=0,
            )
            self.assertTrue(out_json.exists(), msg=proc.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"],
                             "auditooor.wave4_all_pairs_fp_matrix.v1")
            self.assertIn("ws_a", payload["source_workspaces"])
            self.assertIn("ws_b", payload["source_workspaces"])
            self.assertNotIn("ws_c", payload["source_workspaces"])
            self.assertIn("ws_c", payload["target_workspaces"])
            transfers = payload["matrix"]["transfers"]
            self.assertIn("ws_a", transfers)
            self.assertIn("ws_b", transfers["ws_a"])

    def test_07_real_invocation_solidity_fp01_hit(self):
        # Verify real runner subprocess fires and matrix carries non-zero hits.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            audits = base / "audits"
            audits.mkdir()
            ws_src = audits / "ws_src"
            ws_tgt = audits / "ws_tgt"
            ws_src.mkdir()
            ws_tgt.mkdir()
            # Source workspace seeded with FP-01 attack-class
            _write_derived_detector_yaml(
                ws_src / "derived_detectors",
                "p1_missing-validation",
                "missing-validation-on-state-mutation",
                target_language="solidity",
            )
            (ws_src / "src.sol").write_text("contract X {}\n",
                                            encoding="utf-8")
            # Target workspace has a real Sol fn with state assignment + no guard
            # so the universal FP runner's FP-01 strategy fires.
            (ws_tgt / "T.sol").write_text(
                textwrap.dedent(
                    """\
                    contract T {
                        uint256 public x;
                        function bad() public {
                            x = 42;
                        }
                    }
                    """
                ),
                encoding="utf-8",
            )

            fp_dir = base / "tags"
            _write_synth_fp_yaml(fp_dir, "FP-01", "solidity",
                                 "missing-validation-on-state-mutation")

            out_json = base / "matrix.json"
            out_md = base / "matrix.md"
            _run(
                [
                    "--workspaces-glob", str(audits / "*"),
                    "--fp-dir", str(fp_dir),
                    "--seed-source", "derived_detectors",
                    "--out-json", str(out_json),
                    "--out-markdown", str(out_md),
                    "--workers", "1",
                    "--runner-path", str(RUNNER),
                ],
                expect_rc=0,
            )
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            transfers = payload["matrix"]["transfers"]
            r = transfers["ws_src"]["ws_tgt"]
            self.assertFalse(r["skipped"], msg=str(r))
            # FP-01 should fire on T.sol bad() (state write, no guard).
            self.assertGreaterEqual(r.get("total_hits", 0), 1,
                                    msg=str(r))

    def test_08_skip_cross_language_filters_sol_to_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            audits = base / "audits"
            audits.mkdir()
            ws_sol_src = audits / "ws_sol_src"
            ws_go_tgt = audits / "ws_go_tgt"
            _write_derived_detector_yaml(
                ws_sol_src / "derived_detectors", "p1",
                "missing-validation-on-state-mutation",
                target_language="solidity",
            )
            (ws_sol_src / "A.sol").write_text("contract A {}\n",
                                              encoding="utf-8")
            ws_go_tgt.mkdir(parents=True, exist_ok=True)
            for i in range(3):
                (ws_go_tgt / ("f%d.go" % i)).write_text(
                    "package main\nfunc x(){}\n", encoding="utf-8"
                )
            fp_dir = base / "tags"
            _write_synth_fp_yaml(fp_dir, "FP-01", "solidity",
                                 "missing-validation-on-state-mutation")
            out_json = base / "matrix.json"
            _run(
                [
                    "--workspaces-glob", str(audits / "*"),
                    "--fp-dir", str(fp_dir),
                    "--seed-source", "derived_detectors",
                    "--out-json", str(out_json),
                    "--out-markdown", str(base / "out.md"),
                    "--skip-cross-language",
                    "--workers", "1",
                    "--runner-path", str(RUNNER),
                ],
                expect_rc=0,
            )
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            r = payload["matrix"]["transfers"]["ws_sol_src"]["ws_go_tgt"]
            self.assertTrue(r.get("skipped"))
            self.assertEqual(r.get("skip_reason"), "skip-cross-language")

    def test_09_skip_pairs_regex_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            audits = base / "audits"
            audits.mkdir()
            ws_a = audits / "ws_a"
            ws_b = audits / "ws_b"
            _write_derived_detector_yaml(
                ws_a / "derived_detectors", "p1",
                "missing-validation-on-state-mutation",
                target_language="solidity",
            )
            (ws_a / "x.sol").write_text("contract X {}\n",
                                        encoding="utf-8")
            ws_b.mkdir(parents=True, exist_ok=True)
            (ws_b / "y.sol").write_text("contract Y {}\n",
                                        encoding="utf-8")
            fp_dir = base / "tags"
            _write_synth_fp_yaml(fp_dir, "FP-01", "solidity",
                                 "missing-validation-on-state-mutation")
            out_json = base / "matrix.json"
            _run(
                [
                    "--workspaces-glob", str(audits / "*"),
                    "--fp-dir", str(fp_dir),
                    "--seed-source", "derived_detectors",
                    "--out-json", str(out_json),
                    "--out-markdown", str(base / "out.md"),
                    "--skip-pairs", r"ws_a:ws_b",
                    "--workers", "1",
                    "--runner-path", str(RUNNER),
                ],
                expect_rc=0,
            )
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            r = payload["matrix"]["transfers"]["ws_a"]["ws_b"]
            self.assertTrue(r.get("skipped"))
            self.assertEqual(r.get("skip_reason"), "skip-pattern")

    def test_10_strict_no_candidates_returns_rc1(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            audits = base / "audits"
            audits.mkdir()
            ws_a = audits / "ws_a"
            _write_derived_detector_yaml(
                ws_a / "derived_detectors", "p1",
                "missing-validation-on-state-mutation",
                target_language="solidity",
            )
            (ws_a / "x.sol").write_text("contract X {}\n",
                                        encoding="utf-8")
            fp_dir = base / "tags"
            _write_synth_fp_yaml(fp_dir, "FP-01", "solidity",
                                 "missing-validation-on-state-mutation")
            out_json = base / "matrix.json"
            proc = _run(
                [
                    "--workspaces-glob", str(audits / "*"),
                    "--fp-dir", str(fp_dir),
                    "--seed-source", "derived_detectors",
                    "--out-json", str(out_json),
                    "--out-markdown", str(base / "out.md"),
                    "--workers", "1",
                    "--runner-path", str(RUNNER),
                    "--strict",
                ],
            )
            self.assertEqual(proc.returncode, 1,
                             msg="stderr=%s" % proc.stderr[-400:])


if __name__ == "__main__":
    unittest.main()
