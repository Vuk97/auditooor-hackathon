from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oscript_ast_substrate", ROOT / "tools" / "oscript-ast-substrate.py")
assert SPEC is not None and SPEC.loader is not None
substrate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(substrate)


class OscriptAstSubstrateTests(unittest.TestCase):
    def test_parser_backed_record_is_pinned_and_cannot_claim_semantic_credit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "aa" / "agent.oscript"
            source.parent.mkdir()
            raw = b"{ messages: {} }\n"
            source.write_bytes(raw)
            adapter = mock.Mock()
            adapter._ocore_root.return_value = workspace / "ocore"
            adapter.shutil.which.return_value = "node"
            adapter.run_parser.return_value = {
                "messages": [{"app": "data", "guard_ast": {"type": "formula"}}, {"app": "payment", "guard_ast": None}],
            }
            with mock.patch.object(substrate, "_load_parser_adapter", return_value=adapter):
                records = substrate.run(workspace)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["source"], {"path": "aa/agent.oscript", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        self.assertEqual(record["parser_execution"], {"status": "passed", "backend": "ocore-nearley-ast", "message_count": 2})
        self.assertEqual(record["ast_summary"], {"message_apps": ["data", "payment"], "guarded_message_count": 1})
        self.assertEqual(record["credit"], {"compiler_backed": False, "semantic_engine": False, "depth": False, "fuzz": False})

    def test_source_outside_workspace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            outside = Path(directory) / "outside.oscript"
            outside.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source is outside workspace"):
                substrate._source_files(workspace, outside)
