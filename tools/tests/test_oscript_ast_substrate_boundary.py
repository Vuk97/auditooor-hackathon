from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


substrate = load_module("oscript_ast_substrate_boundary", ROOT / "tools" / "oscript-ast-substrate.py")
phase_runner = load_module("audit_deep_phase_runner_boundary", ROOT / "tools" / "audit-deep-phase-runner.py")


class OscriptAstSubstrateBoundaryTests(unittest.TestCase):
    def test_parser_backed_output_is_pinned_but_has_no_semantic_credit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "aa" / "agent.oscript"
            source.parent.mkdir()
            raw = b"{ messages: {} }\n"
            source.write_bytes(raw)
            record = substrate._record(
                workspace, source, {"messages": [{"app": "data", "guard_ast": {"type": "formula"}}]}
            )
        self.assertEqual(record["evidence_tier"], "ast-backed/syntactic")
        self.assertEqual(record["parser_execution"]["status"], "passed")
        self.assertEqual(record["source"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(record["source"]["size"], len(raw))
        self.assertFalse(record["credit"]["compiler_backed"])
        self.assertFalse(record["credit"]["semantic_engine"])

    def test_ast_tier_cannot_be_registered_as_a_semantic_engine(self) -> None:
        registry = phase_runner._default_registry()
        registry["engine-substrates"] = [{
            "id": "oscript-ast", "role": "semantic-engine", "evidence_tier": "ast-backed/syntactic",
            "languages": ["oscript"], "argv": ["python3", "tools/oscript-ast-substrate.py"],
            "outputs": [{"path": ".auditooor/oscript.json", "contract": "semantic-engine-substrate"}],
        }]
        with tempfile.TemporaryDirectory() as directory:
            registry_path = Path(directory) / "registry.json"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            with self.assertRaises(phase_runner.PhaseError) as raised:
                phase_runner.load_registry(registry_path)
        self.assertIn("invalid engine evidence tier", str(raised.exception))

    def test_semantic_engine_substrate_contract_rejects_oscript(self) -> None:
        engine = load_module("semantic_engine_substrate_boundary", ROOT / "tools" / "semantic-engine-substrate.py")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with self.assertRaisesRegex(engine.SubstrateError, "unsupported_semantic_engine_language:oscript"):
                engine.build(workspace, "oscript", workspace / "out.json", workspace / "paths.jsonl")


if __name__ == "__main__":
    unittest.main()
