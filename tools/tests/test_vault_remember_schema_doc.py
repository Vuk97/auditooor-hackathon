"""Tests for vault_remember TOOL_SCHEMAS doc (FIX-PASS Gap 1).

Verifies:
  1. The TOOL_SCHEMAS["vault_remember"] inputSchema documents the 3 required
     frontmatter fields (name, description, type) in the content.description.
  2. A "frontmatter_template" field is present at the inputSchema level.
  3. The top-level tool description mentions "type" alongside "name" and
     "description" so callers see the full requirement.
"""

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _vault_remember_schema():
    for entry in vault_mcp_server.TOOL_SCHEMAS:
        if entry.get("name") == "vault_remember":
            return entry
    raise AssertionError("vault_remember not found in TOOL_SCHEMAS")


class TestVaultRememberSchemaDoc(unittest.TestCase):

    def test_content_description_documents_required_fields(self):
        entry = _vault_remember_schema()
        content_desc = (
            entry["inputSchema"]["properties"]["content"]["description"].lower()
        )
        # All four required tokens must appear so the agent reading the
        # MCP tools/list output knows what to put into the frontmatter.
        for token in ("frontmatter", "name", "description", "type"):
            self.assertIn(
                token,
                content_desc,
                f"content.description missing token {token!r}: {content_desc!r}",
            )

    def test_frontmatter_template_present(self):
        entry = _vault_remember_schema()
        self.assertIn("frontmatter_template", entry["inputSchema"])
        template = entry["inputSchema"]["frontmatter_template"]
        self.assertIn("name:", template)
        self.assertIn("description:", template)
        self.assertIn("type:", template)

    def test_top_level_description_mentions_type(self):
        entry = _vault_remember_schema()
        desc = entry["description"].lower()
        # Tool-level description must also mention type (not just name+description).
        self.assertIn("type", desc)
        self.assertIn("name", desc)
        self.assertIn("description", desc)


if __name__ == "__main__":
    unittest.main()
