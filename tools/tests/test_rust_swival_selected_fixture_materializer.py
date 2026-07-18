from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-swival-selected-fixture-materializer.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_swival_selected_fixture_materializer", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_swival_selected_fixture_materializer"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _index_records() -> list[dict[str, object]]:
    records = []
    for item_id in MOD.TEMPLATE_IDS:
        records.append(
            {
                "item_id": item_id,
                "title": item_id.replace("-", " "),
                "corpus_severity": "High" if not item_id.startswith("045-") else "Medium",
                "family": "rust_decode_or_parser_boundary" if item_id.startswith("045-") else "rust_unsafe_memory_boundary",
                "source_pointers": [f"{item_id}.md"],
                "patch_pointers": [f"{item_id}.patch"],
                "poc_pointers": [f"PoCs/{item_id}.rs"],
            }
        )
    return records


class RustSwivalSelectedFixtureMaterializerTests(unittest.TestCase):
    def test_materializer_writes_advisory_artifacts_without_proof_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "index.json"
            index.write_text(json.dumps({"records": _index_records()}), encoding="utf-8")

            payload = MOD.materialize(ws, index_path=index, run_smoke=False)

            self.assertEqual(payload["created_count"], len(MOD.TEMPLATE_IDS))
            self.assertEqual(payload["skipped_count"], 0)
            self.assertEqual(payload["proof_claims"], 0)
            self.assertEqual(payload["smoke_status_counts"], {"not_run": len(MOD.TEMPLATE_IDS)})
            first = payload["rows"][0]
            self.assertTrue(Path(first["cargo_toml"]).is_file())
            self.assertTrue(Path(first["lib_rs"]).is_file())
            self.assertIn("NOT_SUBMIT_READY", Path(first["manifest"]).read_text(encoding="utf-8"))

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "index.json"
            index.write_text(json.dumps({"records": _index_records()}), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--index",
                    str(index),
                    "--no-smoke",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["created_count"], len(MOD.TEMPLATE_IDS))
            self.assertTrue((ws / ".audit_logs" / "rust_corpus_mining" / "swival_selected_fixture_materialization.json").is_file())
            self.assertTrue((ws / ".audit_logs" / "rust_corpus_mining" / "swival_selected_fixture_materialization.md").is_file())


if __name__ == "__main__":
    unittest.main()
