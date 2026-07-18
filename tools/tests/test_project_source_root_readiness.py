from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "project-source-root-readiness.py"


def _import():
    spec = importlib.util.spec_from_file_location("project_source_root_readiness_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class ProjectSourceRootReadinessTests(unittest.TestCase):
    def test_accepts_declared_target_project_root_and_rejects_generated_roots(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "target_project" / "src").mkdir(parents=True)
            (ws / "target_project" / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            (ws / "detectors" / "fixtures").mkdir(parents=True)
            (ws / "detectors" / "fixtures" / "Fake.sol").write_text("contract Fake {}\n", encoding="utf-8")
            manifest = ws / ".auditooor" / "project_source_roots.json"
            _write_json(
                manifest,
                {
                    "roots": [
                        {"label": "target", "path": "target_project/src"},
                        {"label": "generated", "path": "detectors/fixtures"},
                    ]
                },
            )

            payload = mod.build_payload(ws, manifest_path=manifest)

        self.assertEqual(payload["declared_root_count"], 2)
        self.assertEqual(payload["ready_root_count"], 1)
        self.assertEqual(payload["source_file_count"], 1)
        statuses = {root["label"]: root["status"] for root in payload["roots"]}
        self.assertEqual(statuses["target"], "ready")
        self.assertIn("excluded_generated_or_non_project_path", statuses["generated"])
        self.assertFalse(payload["promotion_allowed"])

    def test_cli_root_is_workspace_neutral_and_missing_root_is_terminal(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "contracts").mkdir()
            (ws / "contracts" / "Oracle.rs").write_text("pub fn settle() {}\n", encoding="utf-8")

            payload = mod.build_payload(ws, cli_roots=["contracts", "missing"])

        self.assertEqual(payload["declared_root_count"], 2)
        self.assertEqual(payload["ready_root_count"], 1)
        self.assertEqual(payload["summary"]["suffix_counts"], {".rs": 1})
        self.assertEqual(payload["summary"]["ready_language_counts"]["rust"], 1)
        self.assertEqual(payload["summary"]["rejection_reason_counts"], {"path_missing": 1})

    def test_records_per_root_language_counts_for_base_split_readiness(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "external" / "base-contracts" / "src").mkdir(parents=True)
            (ws / "external" / "base-reth" / "crates" / "node" / "src").mkdir(parents=True)
            (ws / "external" / "base-contracts" / "src" / "Bridge.sol").write_text("contract Bridge {}\n", encoding="utf-8")
            (ws / "external" / "base-reth" / "crates" / "node" / "src" / "lib.rs").write_text("pub fn run() {}\n", encoding="utf-8")
            manifest = ws / ".auditooor" / "project_source_roots.json"
            _write_json(
                manifest,
                {
                    "roots": [
                        {
                            "label": "base-contracts",
                            "path": "external/base-contracts",
                            "expected_languages": ["solidity"],
                        },
                        {
                            "label": "base-reth",
                            "path": "external/base-reth",
                            "expected_languages": ["rust"],
                        },
                    ]
                },
            )

            payload = mod.build_payload(ws, manifest_path=manifest)

        roots = {root["label"]: root for root in payload["roots"]}
        self.assertEqual(roots["base-contracts"]["language_presence"]["solidity"], 1)
        self.assertEqual(roots["base-reth"]["language_presence"]["rust"], 1)
        self.assertEqual(payload["summary"]["ready_language_counts"]["solidity"], 1)
        self.assertEqual(payload["summary"]["ready_language_counts"]["rust"], 1)

    def test_rejects_external_roots_by_default(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ext = Path(td) / "external"
            ws.mkdir()
            ext.mkdir()
            (ext / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")

            payload = mod.build_payload(ws, cli_roots=[str(ext)])

        self.assertEqual(payload["ready_root_count"], 0)
        self.assertEqual(payload["summary"]["rejection_reason_counts"], {"outside_workspace": 1})


if __name__ == "__main__":
    unittest.main()
