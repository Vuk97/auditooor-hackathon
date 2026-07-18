from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "agent-calibration-vault-emit.py"


def load_module():
    spec = importlib.util.spec_from_file_location("agent_calibration_vault_emit", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


emitter = load_module()


class AgentCalibrationVaultEmitTest(unittest.TestCase):
    def test_display_path_keeps_repo_relative_paths_compact(self):
        path = REPO_ROOT / "obsidian-vault" / "calibration" / "INDEX.md"

        self.assertEqual(emitter.display_path(path), "obsidian-vault/calibration/INDEX.md")

    def test_display_path_accepts_external_vault_paths(self):
        with tempfile.TemporaryDirectory(prefix="auditooor-external-vault-") as tmp:
            path = Path(tmp) / "obsidian-vault" / "calibration" / "INDEX.md"

            self.assertEqual(emitter.display_path(path), str(path.resolve()))


if __name__ == "__main__":
    unittest.main()
