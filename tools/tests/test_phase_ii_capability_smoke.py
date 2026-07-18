from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "phase-ii-capability-smoke.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("phase_ii_capability_smoke", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


smoke = load_tool()


def write_script(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


class PhaseIICapabilitySmokeTests(unittest.TestCase):
    def test_default_smiv_spec_has_live_target_alias_and_sample_probe(self) -> None:
        spec = next(row for row in smoke.DEFAULT_CAPABILITIES if row.capability_id == "SMIV")
        self.assertIn("tools/live-target-intelligence-report.py", spec.tool_candidates)
        self.assertEqual(
            spec.sample_arg_template,
            (
                "--workspace",
                "{sample_path}",
                "--json",
                "--top-n",
                "3",
                "--triager-precheck-budget",
                "0",
            ),
        )
        self.assertEqual(
            spec.sample_path_candidates[0],
            "reports/v3_iter_2026-05-23/lane_HB_P1_HYPERBRIDGE_DOGFOOD",
        )

    def test_default_smiv_spec_runs_live_target_sample_probe(self) -> None:
        spec = next(row for row in smoke.DEFAULT_CAPABILITIES if row.capability_id == "SMIV")
        report = smoke.build_report(
            smoke.REPO_ROOT,
            specs=(spec,),
            timeout_seconds=2.5,
            max_excerpt_chars=120,
        )
        row = report["capabilities"][0]
        self.assertEqual(row["status"], "present-pass")
        self.assertEqual([probe["probe_id"] for probe in row["probes"]], ["help", "sample-1"])
        self.assertIn("--workspace", row["command"])
        sample_probe = next(p for p in row["probes"] if p["probe_id"] == "sample-1")
        self.assertEqual(sample_probe["status"], "pass")
        self.assertIn("--workspace", sample_probe["command"])
        self.assertIn(
            "--top-n 3",
            sample_probe["command"],
        )

    def test_pass_fail_and_pending_statuses_use_stable_row_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phase-ii-smoke-") as tmp:
            root = Path(tmp)
            passing = write_script(
                root / "passing.py",
                "import sys\nprint('pass ' + ' '.join(sys.argv[1:]))\n",
            )
            failing = write_script(
                root / "failing.py",
                (
                    "import sys\n"
                    "print('fail stdout')\n"
                    "print('fail stderr', file=sys.stderr)\n"
                    "raise SystemExit(7)\n"
                ),
            )
            missing = root / "missing.py"

            specs = (
                smoke.CapabilitySpec("DNS", (str(passing),), ("fixture:pass",)),
                smoke.CapabilitySpec("FDASR", (str(failing),), ("fixture:fail",)),
                smoke.CapabilitySpec("AHDH", (str(missing),), ("fixture:pending",)),
            )
            report = smoke.build_report(
                root,
                specs=specs,
                timeout_seconds=1.0,
                max_excerpt_chars=120,
            )

        self.assertEqual(
            list(report.keys()),
            ["schema", "tool", "summary", "bounds", "capabilities", "assumptions"],
        )
        self.assertEqual(report["schema"], "auditooor.phase_ii_capability_smoke.v1")
        self.assertEqual(report["summary"]["present_pass"], 1)
        self.assertEqual(report["summary"]["present_fail"], 1)
        self.assertEqual(report["summary"]["pending"], 1)

        rows = {row["capability_id"]: row for row in report["capabilities"]}
        required_row_keys = {
            "capability_id",
            "tool_path",
            "status",
            "command",
            "exit_code",
            "stdout_excerpt",
            "stderr_excerpt",
            "source_refs",
            "probes",
        }
        for row in rows.values():
            self.assertTrue(required_row_keys.issubset(row))

        self.assertEqual(rows["DNS"]["status"], "present-pass")
        self.assertEqual(rows["DNS"]["exit_code"], 0)
        self.assertEqual(rows["FDASR"]["status"], "present-fail")
        self.assertEqual(rows["FDASR"]["exit_code"], 7)
        self.assertIn("fail stderr", rows["FDASR"]["stderr_excerpt"])
        self.assertEqual(rows["AHDH"]["status"], "pending")
        self.assertIsNone(rows["AHDH"]["exit_code"])
        self.assertEqual(rows["AHDH"]["probes"], [])

    def test_sample_json_path_probe_runs_when_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phase-ii-smoke-sample-") as tmp:
            root = Path(tmp)
            sample = root / "sample.json"
            sample.write_text(json.dumps({"title": "sample"}), encoding="utf-8")
            script = write_script(
                root / "sample_tool.py",
                (
                    "import pathlib, sys\n"
                    "if '--help' in sys.argv:\n"
                    "    print('usage: sample_tool')\n"
                    "    raise SystemExit(0)\n"
                    "idx = sys.argv.index('--payload') + 1\n"
                    "print(pathlib.Path(sys.argv[idx]).read_text(encoding='utf-8'))\n"
                ),
            )
            spec = smoke.CapabilitySpec(
                "PFORPD",
                (str(script),),
                ("fixture:sample",),
                sample_path_candidates=(str(sample),),
                sample_arg_template=("--payload", "{sample_path}"),
            )

            report = smoke.build_report(root, specs=(spec,), timeout_seconds=1.0, max_excerpt_chars=120)

        row = report["capabilities"][0]
        self.assertEqual(row["status"], "present-pass")
        self.assertEqual([probe["probe_id"] for probe in row["probes"]], ["help", "sample-1"])
        self.assertIn("--payload", row["command"])
        self.assertIn("sample:sample.json", row["source_refs"])
        self.assertIn('"title": "sample"', row["stdout_excerpt"])

    def test_cli_tool_override_emits_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phase-ii-smoke-cli-") as tmp:
            root = Path(tmp)
            passing = write_script(root / "passing.py", "print('ok')\n")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--only",
                    "DNS",
                    "--tool",
                    f"DNS={passing}",
                    "--timeout",
                    "1",
                ],
                check=True,
                text=True,
                capture_output=True,
            )

        payload = json.loads(proc.stdout)
        self.assertEqual(payload["summary"]["capabilities"], 1)
        self.assertEqual(payload["capabilities"][0]["capability_id"], "DNS")
        self.assertEqual(payload["capabilities"][0]["status"], "present-pass")


if __name__ == "__main__":
    unittest.main()
