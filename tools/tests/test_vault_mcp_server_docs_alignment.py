"""Docs alignment test for vault MCP callables.

Guards against drift where docs mark registered callables as planned/unregistered
or omit registered `vault_*` names entirely.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
DOC_PATH = REPO_ROOT / "docs" / "VAULT_MCP_SERVER.md"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_docs_alignment", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


class TestVaultMcpServerDocsAlignment(unittest.TestCase):
    def test_registered_vault_tools_are_documented_and_not_marked_unregistered(self) -> None:
        doc_text = DOC_PATH.read_text(encoding="utf-8")
        doc_lower = doc_text.lower()
        registered = sorted(
            {
                tool["name"]
                for tool in vault_mcp_server.TOOL_SCHEMAS
                if isinstance(tool, dict)
                and isinstance(tool.get("name"), str)
                and tool["name"].startswith("vault_")
            }
        )
        self.assertGreater(len(registered), 0)

        missing = [name for name in registered if name not in doc_text]
        self.assertEqual(missing, [], f"Registered vault tools missing from docs: {missing}")

        bad_context_re = re.compile(
            r"(planned|not registered|unregistered|not yet registered|todo|tbd)",
            re.IGNORECASE,
        )
        offenders: list[str] = []
        for name in registered:
            for line in doc_lower.splitlines():
                if name in line and bad_context_re.search(line):
                    offenders.append(f"{name}: {line.strip()}")
                    break

        self.assertEqual(
            offenders,
            [],
            "Registered vault tools must not be described as planned/unregistered in docs: "
            + "; ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
