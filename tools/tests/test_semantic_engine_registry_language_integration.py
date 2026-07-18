from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PHASE_TEST = ROOT / "tools" / "tests" / "test_audit_deep_phase_runner.py"
spec = importlib.util.spec_from_file_location("audit_deep_phase_runner_test", PHASE_TEST)
phase_tests = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(phase_tests)


class SemanticEngineRegistryLanguageIntegrationTest(unittest.TestCase):
    setUp = phase_tests.StrictPhaseRunnerTest.setUp
    tearDown = phase_tests.StrictPhaseRunnerTest.tearDown
    _set_language = phase_tests.StrictPhaseRunnerTest._set_language
    _write = phase_tests.StrictPhaseRunnerTest._write
    _receipt = phase_tests.StrictPhaseRunnerTest._receipt

    def test_default_registry_accepts_strict_semantic_receipts_for_all_supported_languages(self) -> None:
        engine = phase_tests.runner._load_repo_module(
            "semantic_engine_registry_language_test", "tools/semantic-engine-substrate.py"
        )
        expected = {
            "solidity": ("solidity-semantic-engine", "slither"),
            "go": ("go-semantic-engine", "go-ssa"),
            "rust": ("rust-semantic-engine", "rustc-mir"),
        }

        for language, (route_id, backend) in expected.items():
            with self.subTest(language=language):
                self._set_language(language)
                files, source_set_sha256 = engine._inventory(self.ws, language)
                record = engine.DATAFLOW.new_path(
                    f"semantic-{language}", language, "backward", backend,
                    {"kind": "param", "fn": "deposit", "var": "amount", "file": self._source_file(language), "line": 1},
                    {"kind": "transfer", "callee": "send", "arg_pos": 0, "fn": "deposit", "file": self._source_file(language), "line": 1}, [],
                )
                self._write(
                    ".auditooor/language_backend_receipts/dataflow.jsonl",
                    json.dumps({"receipt_schema": "auditooor.language_backend_receipt.v1", "language": language, "backend": backend, "confidence": "semantic-ssa", "status": "pass", "degraded": False, "source_set_sha256": source_set_sha256, "inventory_unit_count": len(files), "examined_empty": False, "execution": {"argv": ["backend"], "executable": "backend", "returncode": 0, "command_sha256": "a" * 64, "stdout_sha256": "b" * 64, "stderr_sha256": "c" * 64, "artifact_kind": f"{backend.replace('rustc-', '')}-semantic-rows", "artifact_sha256": engine._record_digest([record])}}) + "\n",
                )
                self._write(".auditooor/dataflow_paths.jsonl", json.dumps(record) + "\n")
                self.assertEqual(0, phase_tests.runner.run_phase(self.ws, "engine-substrates"))
                phase_receipt = self._receipt("engine-substrates")
                self.assertEqual("passed", phase_receipt["status"])
                command = next(row for row in phase_receipt["commands"] if row["id"] == route_id)
                self.assertEqual(route_id, command["id"])
                artifact = self.ws / f".auditooor/strict_audit_deep/engine-substrates/{language}.json"
                substrate = json.loads(artifact.read_text(encoding="utf-8"))
                self.assertEqual(language, substrate["language"])
                self.assertEqual(backend, substrate["backend"])
                self.assertEqual("semantic/compiler-backed", substrate["evidence_tier"])

    @staticmethod
    def _source_file(language: str) -> str:
        return {"solidity": "src/Vault.sol", "go": "src/vault.go", "rust": "src/lib.rs"}[language]


if __name__ == "__main__":
    unittest.main()
