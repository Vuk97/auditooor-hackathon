from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "pipeline-applicability.py"
SPEC = importlib.util.spec_from_file_location("pipeline_applicability", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
applicability = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = applicability
SPEC.loader.exec_module(applicability)


def manifest(*probes: dict) -> dict:
    return {"applicability_probes": list(probes)}


def write_inventory(workspace: Path, rows: list[dict]) -> None:
    auditooor = workspace / ".auditooor"
    auditooor.mkdir(exist_ok=True)
    content = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    (auditooor / "inscope_units.jsonl").write_text(content, encoding="utf-8")


class PipelineApplicabilityTests(unittest.TestCase):
    def test_language_aliases_use_canonical_names_and_preserve_unknowns(self) -> None:
        expected = {
            "Solidity": "solidity",
            "EVM": "solidity",
            "GoLang": "go",
            "RS": "rust",
            "JS": "javascript",
            "TS": "typescript",
            "AA": "oscript",
            "Vyper": "vyper",
            "Move": "move",
            "Cairo": "cairo",
            "Circom": "circom",
            "Noir": "noir",
            "Python": "python",
            "C": "c",
            "C++": "cpp",
            "C/C++": "cpp",
            "Java": "java",
            "Clarity": "clarity",
            "ZoKrates": "zokrates",
            "Novel DSL": "novel dsl",
        }
        self.assertEqual({value: applicability.normalize_language(value) for value in expected}, expected)

    def test_large_inventory_reads_every_row_and_detects_language_aliases(self) -> None:
        graph = manifest({"id": "mixed", "kind": "language_any", "languages": ["javascript", "oscript", "solidity"]})
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            for name in ("many.js", "contract.sol", "agent.aa"):
                (workspace / name).write_text("source\n", encoding="utf-8")
            rows = [{"file": "many.js", "lang": "js"} for _ in range(2001)]
            rows.extend([
                {"file": "contract.sol", "lang": "EVM"},
                {"file": "agent.aa", "lang": "AA"},
            ])
            write_inventory(workspace, rows)
            result = applicability.evaluate_probe(graph, "mixed", workspace)
            self.assertTrue(result["result"])
            self.assertEqual(result["canonical_inputs"]["inventory"]["row_count"], 2003)
            self.assertEqual(result["canonical_inputs"]["normalized_languages"], ["javascript", "oscript", "solidity"])
            self.assertEqual(result["canonical_inputs"]["requested_languages"], ["javascript", "oscript", "solidity"])

    def test_unrelated_language_is_not_applicable(self) -> None:
        graph = manifest({"id": "rust-only", "kind": "language_any", "languages": ["rust"]})
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "app.js").write_text("source\n", encoding="utf-8")
            write_inventory(workspace, [{"file": "app.js", "lang": "javascript"}])
            self.assertFalse(applicability.evaluate_probe(graph, "rust-only", workspace)["result"])

    def test_invalid_inventory_never_becomes_false_na(self) -> None:
        graph = manifest({"id": "go-only", "kind": "language_any", "languages": ["go"]})
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            def assert_error(code: str) -> None:
                with self.assertRaises(applicability.ApplicabilityError) as raised:
                    applicability.evaluate_probe(graph, "go-only", workspace)
                self.assertIn(code, raised.exception.diagnostics)

            assert_error("applicability_inventory_missing")
            (workspace / ".auditooor").mkdir()
            (workspace / ".auditooor" / "inscope_units.jsonl").write_text("\n", encoding="utf-8")
            assert_error("applicability_inventory_empty")
            (workspace / ".auditooor" / "inscope_units.jsonl").write_text("not-json\n", encoding="utf-8")
            assert_error("applicability_inventory_malformed_row:1")
            (workspace / ".auditooor" / "inscope_units.jsonl").write_text("[]\n", encoding="utf-8")
            assert_error("applicability_inventory_non_object_row:1")
            write_inventory(workspace, [{"lang": "go"}])
            assert_error("applicability_inventory_missing_file:1")
            write_inventory(workspace, [{"file": "missing.go", "lang": "go"}])
            assert_error("applicability_inventory_source_missing:1")
            (workspace / "same.go").write_text("source\n", encoding="utf-8")
            write_inventory(workspace, [{"file": "same.go", "lang": "go"}, {"file": "same.go", "lang": "rust"}])
            assert_error("applicability_inventory_contradictory_row:2")

    def test_inputs_bind_complete_inventory_and_definition(self) -> None:
        graph = manifest({"id": "js", "kind": "language_any", "languages": ["javascript"]})
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "app.js").write_text("source\n", encoding="utf-8")
            write_inventory(workspace, [{"file": "app.js", "lang": "js"}])
            first = applicability.evaluate_probe(graph, "js", workspace)
            self.assertEqual(first["canonical_inputs"]["probe_definition"], {"id": "js", "kind": "language_any", "languages": ["javascript"]})
            self.assertEqual(first["canonical_inputs"]["workspace_root"], str(workspace.resolve()))
            self.assertEqual(first["canonical_inputs"]["inventory"]["size"], len((workspace / ".auditooor" / "inscope_units.jsonl").read_bytes()))
            write_inventory(workspace, [{"file": "app.js", "lang": "js"}, {"file": "app.js", "lang": "javascript"}])
            second = applicability.evaluate_probe(graph, "js", workspace)
            self.assertNotEqual(first["canonical_inputs"]["inventory"]["sha256"], second["canonical_inputs"]["inventory"]["sha256"])
            self.assertNotEqual(first["hash"], second["hash"])


if __name__ == "__main__":
    unittest.main()
