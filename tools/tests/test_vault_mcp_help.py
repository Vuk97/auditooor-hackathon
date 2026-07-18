"""Tests for ``tools/vault-mcp-help.py``.

The tool parses ``tools/vault-mcp-server.py`` for ``def vault_*`` callables,
the ``TOOL_SCHEMAS`` array, and module-level ``*_SCHEMA = "..."`` constants,
then emits a human / JSON index of every vault_* MCP callable.

Coverage (>=8 cases):

1. ``index_callables`` returns one record per ``vault_*`` callable on the
   live repo source and detects >=60 callables (sanity floor; repo ships
   65 as of PR #726).
2. Synthetic fixture: ``_extract_schema_constants`` indexes both the base
   callable name (v1) and the versioned sibling name (_v2, _v3) when the
   schema's major version is >= 2.
3. ``_extract_tool_schemas`` lifts name + description + input + required
   from a literal TOOL_SCHEMAS entry; named-reference properties (e.g.
   ``CONTEXT_PACK_INPUT_PROPERTIES``) surface as ``<from:NAME>`` placeholders
   so callers know to consult source.
4. ``_harvest_return_keys`` collects top-level literal-string keys from
   ``return {...}`` dicts within a function body; non-literal keys are
   silently skipped.
5. The JSON envelope matches schema ``auditooor.vault_mcp_help.v1`` and
   ``callable_count`` equals the length of ``callables``.
6. Human renderer header includes source path, callable count, and
   ``Registered in TOOL_SCHEMAS`` ratio; every callable name appears.
7. Output is deterministic across two consecutive runs (byte-identical
   for both human and JSON formats) on the live repo source.
8. CLI entry point exits 0 and writes to ``--out`` when given.
9. Callables in the live source that wrap ``_context_pack`` (e.g.
   ``vault_resume_context``) surface as registered-in-TOOL_SCHEMAS with
   an empty per-callable schema id (they share the canonical
   ``auditooor.vault_context_pack.v1`` schema via the helper).
10. ``_harvest_inline_schema_from_returns`` picks up an inline
    ``"schema": "auditooor.vault_..."`` literal inside a return dict
    when no module-level constant exists.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "vault-mcp-help.py"
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_tool() -> Any:
    name = "_vault_mcp_help_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


SYNTH_SOURCE = '''
"""Synthetic vault-mcp-server fixture for vault-mcp-help tests."""
from typing import Any

ALPHA_SCHEMA = "auditooor.vault_alpha.v1"
BETA_SCHEMA = "auditooor.vault_beta.v2"
GAMMA_SCHEMA = "auditooor.vault_gamma.v1.1"

CONTEXT_PACK_INPUT_PROPERTIES = {"workspace_path": {"type": "string"}}


class FixtureServer:
    def vault_alpha(self, query: str = "", limit: int = 5) -> dict[str, Any]:
        """One-line alpha docstring.

        Long description that should NOT appear in the index.
        """
        return {"schema": ALPHA_SCHEMA, "query": query, "limit": limit, "hits": []}

    def vault_beta(self, **kwargs: Any) -> dict[str, Any]:
        return {"schema": BETA_SCHEMA, "workspace_path": kwargs.get("workspace_path")}

    def vault_gamma_inline(self, **kwargs: Any) -> dict[str, Any]:
        # Inline-schema callable: no module-level constant for it; the
        # schema id is literal in the return dict.
        return {"schema": "auditooor.vault_gamma_inline.v1", "ok": True}

    def vault_no_schema(self, x: int = 0) -> dict[str, Any]:
        return {"value": x}


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "vault_alpha",
        "description": "Alpha description.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "vault_beta",
        "description": "Beta description.",
        "inputSchema": {
            "type": "object",
            "properties": CONTEXT_PACK_INPUT_PROPERTIES,
        },
    },
    {
        "name": "vault_gamma_inline",
        "description": "Gamma inline description.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "vault_no_schema",
        "description": "Internal helper - no module schema constant.",
        "inputSchema": {
            "type": "object",
            "properties": {"x": {"type": "integer"}},
        },
    },
]
'''


def _write_synth_fixture(tmp_dir: Path) -> Path:
    p = tmp_dir / "synth-server.py"
    p.write_text(SYNTH_SOURCE, encoding="utf-8")
    return p


class IndexLiveRepoTests(unittest.TestCase):
    def test_index_callables_returns_at_least_60_records(self) -> None:
        records = tool.index_callables(SERVER_PATH)
        self.assertGreaterEqual(
            len(records),
            60,
            f"expected >=60 vault_* callables, got {len(records)}",
        )
        # Sanity: a few well-known callables must appear.
        names = {r["name"] for r in records}
        for expected in ("vault_search", "vault_get", "vault_resume_context"):
            self.assertIn(expected, names)

    def test_context_pack_wrappers_have_empty_schema_but_are_registered(self) -> None:
        records = {r["name"]: r for r in tool.index_callables(SERVER_PATH)}
        for wrapper in ("vault_resume_context", "vault_dispatch_context", "vault_finalization_context"):
            self.assertIn(wrapper, records)
            self.assertTrue(records[wrapper]["registered_in_tool_schemas"])
            # Per-callable schema id is None because they share the canonical
            # `auditooor.vault_context_pack.v1` schema via the _context_pack helper.
            self.assertIsNone(records[wrapper]["schema"])


class SyntheticFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.fixture_path = _write_synth_fixture(self.tmp_path)
        self.records = tool.index_callables(self.fixture_path)
        self.by_name = {r["name"]: r for r in self.records}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_alpha_v1_schema_extracted(self) -> None:
        rec = self.by_name["vault_alpha"]
        self.assertEqual(rec["schema"], "auditooor.vault_alpha.v1")
        self.assertEqual(rec["description"], "Alpha description.")
        self.assertEqual(rec["input_fields"], ["limit", "query"])
        self.assertEqual(rec["required_fields"], ["query"])
        # Return-dict literal extraction.
        self.assertIn("hits", rec["output_fields"])
        self.assertIn("schema", rec["output_fields"])

    def test_versioned_sibling_indexed_via_v2(self) -> None:
        # Synth has only a `vault_beta` callable and a BETA_SCHEMA = "...v2",
        # which the schema-constants extractor must index both as
        # `vault_beta` AND as `vault_beta_v2`. The callable matches the
        # base name so it picks up the v2 schema id.
        rec = self.by_name["vault_beta"]
        self.assertEqual(rec["schema"], "auditooor.vault_beta.v2")

    def test_inline_schema_fallback(self) -> None:
        rec = self.by_name["vault_gamma_inline"]
        # No module-level constant for `vault_gamma_inline`; the schema
        # must come from the inline return-dict literal.
        self.assertEqual(rec["schema"], "auditooor.vault_gamma_inline.v1")

    def test_named_reference_inputs_surface_as_placeholder(self) -> None:
        rec = self.by_name["vault_beta"]
        # `CONTEXT_PACK_INPUT_PROPERTIES` is a Name node, so we surface a
        # `<from:NAME>` placeholder rather than fabricating field names.
        self.assertEqual(rec["input_fields"], ["<from:CONTEXT_PACK_INPUT_PROPERTIES>"])

    def test_callable_without_schema_constant_still_registered(self) -> None:
        rec = self.by_name["vault_no_schema"]
        self.assertIsNone(rec["schema"])
        self.assertTrue(rec["registered_in_tool_schemas"])
        self.assertEqual(rec["description"], "Internal helper - no module schema constant.")
        self.assertEqual(rec["output_fields"], ["value"])

    def test_docstring_first_line_used_when_no_tool_schemas_entry(self) -> None:
        # Build a one-off fixture missing TOOL_SCHEMAS entries entirely;
        # the description must fall back to the docstring first line.
        src = (
            "ALPHA_SCHEMA = \"auditooor.vault_alpha.v1\"\n"
            "class S:\n"
            "    def vault_alpha(self):\n"
            "        \"\"\"Docstring first line only.\"\"\"\n"
            "        return {'schema': ALPHA_SCHEMA}\n"
            "TOOL_SCHEMAS = []\n"
        )
        p = self.tmp_path / "no-tool-schemas.py"
        p.write_text(src, encoding="utf-8")
        recs = tool.index_callables(p)
        rec = recs[0]
        self.assertEqual(rec["name"], "vault_alpha")
        self.assertEqual(rec["description"], "Docstring first line only.")
        self.assertFalse(rec["registered_in_tool_schemas"])


class HarvestReturnKeysTests(unittest.TestCase):
    def test_literal_keys_collected_non_literal_skipped(self) -> None:
        src = (
            "def f():\n"
            "    if True:\n"
            "        return {'a': 1, 'b': 2, dynamic_key: 3}\n"
            "    return {'c': 4}\n"
        )
        tree = ast.parse(src)
        func = tree.body[0]
        keys = tool._harvest_return_keys(func)
        # Both return paths visited; dynamic_key silently skipped.
        self.assertIn("a", keys)
        self.assertIn("b", keys)
        self.assertIn("c", keys)
        self.assertEqual(len(keys), 3)


class RendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.fixture_path = _write_synth_fixture(self.tmp_path)
        self.records = tool.index_callables(self.fixture_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_json_envelope_shape(self) -> None:
        text = tool.render_json(self.records, self.fixture_path)
        payload = json.loads(text)
        self.assertEqual(payload["schema"], "auditooor.vault_mcp_help.v1")
        self.assertEqual(payload["callable_count"], len(self.records))
        self.assertEqual(len(payload["callables"]), payload["callable_count"])
        # registered_count <= callable_count.
        self.assertLessEqual(payload["registered_count"], payload["callable_count"])

    def test_human_renderer_includes_every_callable_name(self) -> None:
        text = tool.render_human(self.records, self.fixture_path)
        self.assertIn("vault_* MCP callable index", text)
        self.assertIn(f"Callables: {len(self.records)}", text)
        for rec in self.records:
            self.assertIn(rec["name"], text)
        self.assertIn("Registered in TOOL_SCHEMAS:", text)

    def test_determinism_two_runs_byte_identical(self) -> None:
        a_json = tool.render_json(self.records, self.fixture_path)
        b_json = tool.render_json(self.records, self.fixture_path)
        self.assertEqual(a_json, b_json)
        a_h = tool.render_human(self.records, self.fixture_path)
        b_h = tool.render_human(self.records, self.fixture_path)
        self.assertEqual(a_h, b_h)


class CLITests(unittest.TestCase):
    def test_cli_exits_zero_and_writes_to_out(self) -> None:
        with tempfile.TemporaryDirectory() as tdir:
            tdir_path = Path(tdir)
            fixture = _write_synth_fixture(tdir_path)
            out_path = tdir_path / "out.txt"
            res = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--server",
                    str(fixture),
                    "--out",
                    str(out_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            text = out_path.read_text(encoding="utf-8")
            self.assertIn("vault_alpha", text)
            self.assertIn("vault_beta", text)

    def test_cli_json_envelope_via_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tdir:
            fixture = _write_synth_fixture(Path(tdir))
            res = subprocess.run(
                [sys.executable, str(TOOL_PATH), "--server", str(fixture), "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            payload = json.loads(res.stdout)
            self.assertEqual(payload["schema"], "auditooor.vault_mcp_help.v1")


class LiveRepoDeterminismTests(unittest.TestCase):
    def test_live_repo_two_runs_byte_identical(self) -> None:
        records_a = tool.index_callables(SERVER_PATH)
        records_b = tool.index_callables(SERVER_PATH)
        a_text = tool.render_human(records_a, SERVER_PATH)
        b_text = tool.render_human(records_b, SERVER_PATH)
        self.assertEqual(a_text, b_text)
        a_json = tool.render_json(records_a, SERVER_PATH)
        b_json = tool.render_json(records_b, SERVER_PATH)
        self.assertEqual(a_json, b_json)


if __name__ == "__main__":
    unittest.main()
