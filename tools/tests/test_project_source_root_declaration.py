from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "project-source-root-declaration.py"


def _import():
    spec = importlib.util.spec_from_file_location("project_source_root_declaration_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ProjectSourceRootDeclarationTests(unittest.TestCase):
    def test_writes_workspace_neutral_manifest_entries(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / ".auditooor" / "project_source_roots.json"
            payload = mod.build_payload(manifest, ["contracts=target_project/contracts"], merge_existing=False)

        self.assertEqual(payload["schema"], "auditooor.project_source_roots.v1")
        self.assertEqual(payload["roots"][0]["label"], "contracts")
        self.assertEqual(payload["roots"][0]["path"], "target_project/contracts")
        self.assertEqual(payload["roots"][0]["kind"], "target_project_source")
        self.assertFalse(mod.validate_manifest(payload))
        self.assertIn("make project-source-root-readiness WS=<workspace>", payload["next_commands"])

    def test_check_rejects_missing_path_and_wrong_kind(self) -> None:
        mod = _import()
        payload = {
            "schema": "auditooor.project_source_roots.v1",
            "roots": [
                {"label": "missing", "path": "", "kind": "target_project_source"},
                {"label": "fixture", "path": "detectors/fixtures", "kind": "generated_fixture"},
            ],
        }

        errors = mod.validate_manifest(payload)

        self.assertIn("root_0_missing_path", errors)
        self.assertIn("root_1_invalid_kind", errors)

    def test_cli_round_trip_check(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rc = mod.main(["--workspace", str(ws), "--entry", "src=target_project/src"])
            self.assertEqual(rc, 0)
            payload = json.loads((ws / ".auditooor" / "project_source_roots.json").read_text())
            self.assertEqual(payload["roots"][0]["path"], "target_project/src")
            self.assertEqual(mod.main(["--workspace", str(ws), "--check"]), 0)


if __name__ == "__main__":
    unittest.main()
