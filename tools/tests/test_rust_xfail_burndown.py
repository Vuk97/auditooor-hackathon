from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-xfail-burndown.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_xfail_burndown", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_xfail_burndown"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


class RustXfailBurndownTests(unittest.TestCase):
    def test_parse_now_correct_helper_summary(self) -> None:
        summary = MOD.parse_helper_summary("detectors=500\nresidual_skips=13\n")

        self.assertEqual(summary.detectors, 500)
        self.assertEqual(summary.residual_skips, 13)

    def test_parse_full_harness_generated_xfails(self) -> None:
        summary = MOD.parse_harness_summary(
            """
            =========================================
             Rust wave1 regression:  921/1000 passed
             Generated fixture residual xfail: 79
            =========================================
            Generated residual xfails:
              - generated_a positive: expected >=1 hit, got 0
              - generated_b negative: expected 0 hits, got 2
            """
        )

        self.assertEqual(summary.passed, 921)
        self.assertEqual(summary.total, 1000)
        self.assertEqual(summary.generated_residual_xfail, 79)
        self.assertEqual(summary.xfails[0].detector_id, "generated_a")
        self.assertEqual(summary.xfails[1].mode, "negative")

    def test_build_report_accepts_pass_with_generated_xfail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            coverage = repo / "reports" / "rust_detector_coverage_2026-05-05.json"
            _write(
                coverage,
                json.dumps(
                    {
                        "per_detector": [
                            {
                                "detector_id": "draft_gap",
                                "detector_path": "detectors/rust_wave1/draft_gap.py",
                                "fixture_pair_present": False,
                                "nested_detector": False,
                                "detector_group": "rust_wave1",
                            }
                        ]
                    }
                ),
            )

            payload = MOD.build_report(
                repo,
                helper_result=MOD.CommandResult(
                    command=["helper"],
                    returncode=0,
                    stdout="detectors=2\nresidual_skips=1\n",
                    stderr="",
                ),
                harness_result=MOD.CommandResult(
                    command=["harness"],
                    returncode=0,
                    stdout="""
                    =========================================
                     Rust wave1 regression:  3/4 passed
                     Generated fixture residual xfail: 1
                    =========================================
                    Generated residual xfails:
                      - generated_a positive: expected >=1 hit, got 0
                    """,
                    stderr="",
                ),
                coverage_report=coverage,
            )

            self.assertEqual(payload["status"], "pass_with_generated_xfail")
            self.assertTrue(payload["consistency"]["harness_total_matches_helper_detector_pairs"])
            self.assertEqual(payload["burndown"]["generated_residual_xfail_remaining"], 1)
            self.assertEqual(payload["residual_skip_detectors"][0]["detector_id"], "draft_gap")

    def test_static_nested_detector_is_not_residual_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write(
                repo / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh",
                """
                DETECTORS=(
                  static_nested
                )
                """,
            )
            coverage = repo / "reports" / "rust_detector_coverage_2026-05-05.json"
            _write(
                coverage,
                json.dumps(
                    {
                        "per_detector": [
                            {
                                "detector_id": "static_nested",
                                "detector_path": "detectors/rust_wave1/nested/static_nested.py",
                                "fixture_pair_present": True,
                                "nested_detector": True,
                                "detector_group": "nested",
                            }
                        ]
                    }
                ),
            )

            payload = MOD.build_report(
                repo,
                helper_result=MOD.CommandResult(
                    command=["helper"],
                    returncode=0,
                    stdout="detectors=1\nresidual_skips=0\n",
                    stderr="",
                ),
                harness_result=MOD.CommandResult(
                    command=["harness"],
                    returncode=0,
                    stdout="Rust wave1 regression:  2/2 passed\n",
                    stderr="",
                ),
                coverage_report=coverage,
            )

            self.assertEqual(payload["status"], "pass_no_generated_xfail")
            self.assertEqual(payload["residual_skip_detectors"], [])

    def test_build_report_flags_total_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            payload = MOD.build_report(
                repo,
                helper_result=MOD.CommandResult(
                    command=["helper"],
                    returncode=0,
                    stdout="detectors=2\nresidual_skips=0\n",
                    stderr="",
                ),
                harness_result=MOD.CommandResult(
                    command=["harness"],
                    returncode=0,
                    stdout="Rust wave1 regression:  3/6 passed\nGenerated fixture residual xfail: 3\n",
                    stderr="",
                ),
                coverage_report=repo / "missing.json",
            )

            self.assertEqual(payload["status"], "needs_attention")
            self.assertIn("harness total 6 != helper detector pairs 4", payload["notes"])

    def test_cli_writes_json_and_markdown_from_output_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            helper = repo / "helper.out"
            harness = repo / "harness.out"
            json_out = repo / "out" / "burndown.json"
            md_out = repo / "out" / "burndown.md"
            _write(helper, "detectors=500\nresidual_skips=13\n")
            _write(
                harness,
                """
                =========================================
                 Rust wave1 regression:  921/1000 passed
                 Generated fixture residual xfail: 79
                =========================================
                """,
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(repo),
                    "--helper-output",
                    str(helper),
                    "--harness-output",
                    str(harness),
                    "--json-out",
                    str(json_out),
                    "--md-out",
                    str(md_out),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.rust_xfail_burndown.v1")
            self.assertEqual(payload["status"], "pass_with_generated_xfail")
            self.assertIn("harness=921/1000 passed xfail=79", proc.stdout)
            markdown = md_out.read_text(encoding="utf-8")
            self.assertIn("**921/1000** passed", markdown)
            self.assertIn("**13** residual skipped detector rows", markdown)


if __name__ == "__main__":
    unittest.main()
