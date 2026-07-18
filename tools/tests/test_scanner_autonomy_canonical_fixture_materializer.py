import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "scanner-autonomy-canonical-fixture-materializer.py"
spec = importlib.util.spec_from_file_location("scanner_autonomy_canonical_fixture_materializer", MODULE_PATH)
materializer = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(materializer)


class CanonicalFixtureMaterializerTests(unittest.TestCase):
    def test_safe_copy_blocks_different_existing_fixture_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src.sol"
            dst = root / "dst.sol"
            src.write_text("contract A {}\n", encoding="utf-8")
            dst.write_text("contract B {}\n", encoding="utf-8")

            ok, status = materializer._safe_copy(src, dst, overwrite=False)

            self.assertFalse(ok)
            self.assertEqual(status, "canonical_fixture_exists_with_different_content")
            self.assertEqual(dst.read_text(encoding="utf-8"), "contract B {}\n")

    def test_materialize_blocks_non_ready_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            manifest_dir = ws / ".auditooor" / "scanner_autonomy_semantic_repair_manifests"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "ssi-fix-001_demo.json").write_text(
                json.dumps({
                    "source_id": "SSI-FIX-001",
                    "pattern": "demo-pattern",
                    "materialization_ready": False,
                }),
                encoding="utf-8",
            )

            payload = materializer.materialize(ws, limit=None, overwrite=False, runner_python="python3")

            self.assertEqual(payload["selected_count"], 1)
            self.assertEqual(payload["blocked_count"], 1)
            self.assertEqual(payload["rows"][0]["status"], "blocked_manifest_not_materialization_ready")

    def test_run_smoke_sets_fixture_smoke_environment(self):
        completed = materializer.subprocess.CompletedProcess(
            args=["python3"],
            returncode=0,
            stdout="total hits: 1\n",
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            materializer.subprocess,
            "run",
            return_value=completed,
        ) as run:
            ws = Path(tmp)
            fixture = ws / "detectors" / "fixtures" / "demo" / "positive.sol"
            result = materializer._run_smoke(ws, "python3", fixture, "demo-pattern")

        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"]["AUDITOOOR_FIXTURE_SMOKE_MODE"], "1")
        self.assertEqual(kwargs["env"]["AUDITOOOR_SLITHER_NOCACHE"], "1")
        self.assertEqual(result["total_hits"], 1)
        self.assertIn("AUDITOOOR_FIXTURE_SMOKE_MODE=1", result["command"])


if __name__ == "__main__":
    unittest.main()
