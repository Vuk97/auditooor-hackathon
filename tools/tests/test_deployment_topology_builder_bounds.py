from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "deployment-topology-builder.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("deployment_topology_builder_under_test", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class DeploymentTopologyBuilderBoundsTests(unittest.TestCase):
    def test_build_topology_artifact_caps_contracts_and_marks_truncated(self) -> None:
        builder = _load_builder()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)

            angles = [
                {"id": "A-AUTH", "contracts": [f"Contract{i}"], "title": f"angle {i}"}
                for i in range(5)
            ]

            def fake_lookup(workspace: Path, contract: str, timeout_seconds: int = 5):
                return {"contract": contract, "matches": {}}

            with mock.patch.object(builder, "load_ccia", return_value=({}, angles)), \
                    mock.patch.object(builder, "load_workspace_env", return_value={}), \
                    mock.patch.object(builder, "run_lookup", side_effect=fake_lookup) as lookup:
                artifact = builder.build_topology_artifact(ws, max_contracts=2, lookup_timeout_seconds=3)

            self.assertTrue(artifact["truncated"])
            self.assertEqual(artifact["contracts"], ["Contract0", "Contract1"])
            self.assertEqual(artifact["contracts_available"], 5)
            self.assertEqual(artifact["contracts_skipped"], ["Contract2", "Contract3", "Contract4"])
            self.assertEqual(artifact["lookup_timeout_seconds"], 3)
            self.assertEqual(artifact["summary"]["contracts_total"], 2)
            self.assertEqual(lookup.call_count, 2)

            rendered = builder.render_markdown(ws, artifact)
            self.assertIn("- Truncated: yes", rendered)
            self.assertIn("Partial artifact", rendered)
            self.assertIn("Skipped contracts: 3", rendered)

    def test_run_lookup_timeout_returns_error_payload(self) -> None:
        builder = _load_builder()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            lookup = ws / "deploy-state-lookup.sh"
            lookup.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            with mock.patch.object(builder, "DEPLOY_STATE_LOOKUP", lookup), \
                    mock.patch.object(
                        builder.subprocess,
                        "run",
                        side_effect=subprocess.TimeoutExpired(cmd=["lookup"], timeout=1),
                    ):
                payload = builder.run_lookup(ws, "SlowContract", timeout_seconds=1)

        self.assertEqual(payload["contract"], "SlowContract")
        self.assertIn("timed out after 1s", payload["error"])


if __name__ == "__main__":
    unittest.main()
