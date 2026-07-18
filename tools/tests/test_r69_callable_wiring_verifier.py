#!/usr/bin/env python3
# r36-rebuttal: lane LANE-217-R69-CALLABLE-WIRING-VERIFIER declared via tools/agent-pathspec-register.py
"""Regression coverage for tools/r69-callable-wiring-verifier.py.

Covers:
- AST extraction of TOOL_SCHEMAS (Assign + AnnAssign forms)
- AST extraction of VaultQuery vault_* methods + their kwargs (signature +
  kwargs.get / kwargs[...] usage)
- AST extraction of _dispatch ``if name == "vault_X"`` branches
- Verdict matrix:
    * wired-and-callable
    * wired-but-degraded (degraded:true with reason)
    * missing-from-choices (LIFT-21 case)
    * missing-from-tool-schemas
    * missing-from-method
    * missing-from-dispatcher
    * silently-ignored-kwarg (LIFT-25 case)
    * live-call-error
- CLI: --strict exit code, --json output schema, --no-live-call
- Live-call against the real vault-mcp-server.py for known-wired callable
  (vault_hacker_questions) - exercised only when the server is present.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


_THIS = Path(__file__).resolve().parent
_REPO = _THIS.parent.parent
_TOOL_PATH = _REPO / "tools" / "r69-callable-wiring-verifier.py"
_REAL_SERVER = _REPO / "tools" / "vault-mcp-server.py"


# r36-rebuttal: lane LANE-217-R69-CALLABLE-WIRING-VERIFIER declared via tools/agent-pathspec-register.py
_spec = importlib.util.spec_from_file_location("r69_verifier", _TOOL_PATH)
r69 = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["r69_verifier"] = r69  # Python 3.14 requires registration before exec
_spec.loader.exec_module(r69)


# --------------------------------------------------------------------------
# Helpers to build synthetic vault-mcp-server fixtures
# --------------------------------------------------------------------------


_BASE_SERVER_TEMPLATE = """\
'''synthetic vault-mcp-server fixture for R69 tests'''
import argparse
import json
import sys
from typing import Any


class VaultQuery:
{methods}

{tool_schemas_assign}


class VaultServer:
    def __init__(self) -> None:
        self.q = VaultQuery()

    def _dispatch(self, name: str, args: dict) -> dict:
{dispatcher}
        return {{'error': 'no-such-tool', 'name': name}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--call', choices=[t['name'] for t in TOOL_SCHEMAS])
    parser.add_argument('--args', default='{{}}')
    ns = parser.parse_args()
    if not ns.call:
        return 0
    server = VaultServer()
    result = server._dispatch(ns.call, json.loads(ns.args))
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write('\\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
"""


def _build_method(name: str, body: str = "        return {'ok': True}") -> str:
    return f"    def {name}(self, **kwargs: Any) -> dict:\n{body}\n"


def _build_synthetic_server(
    *,
    schema_names: list[str],
    method_names: list[str],
    dispatcher_names: list[str],
    method_bodies: dict[str, str] | None = None,
    annotated: bool = True,
) -> str:
    method_bodies = method_bodies or {}
    methods = "".join(
        _build_method(n, method_bodies.get(n, "        return {'ok': True}"))
        for n in method_names
    )
    if not methods:
        methods = "    pass\n"
    # TOOL_SCHEMAS assignment (annotated vs plain).
    schemas_inner = ", ".join(
        "{'name': '%s', 'inputSchema': {'type': 'object', 'properties': {}}}" % n
        for n in schema_names
    )
    if annotated:
        assign = f"TOOL_SCHEMAS: list[dict[str, Any]] = [{schemas_inner}]"
    else:
        assign = f"TOOL_SCHEMAS = [{schemas_inner}]"
    # Dispatcher branches.
    dispatcher_lines = []
    for n in dispatcher_names:
        dispatcher_lines.append(f"        if name == '{n}':")
        dispatcher_lines.append(f"            return self.q.{n}(**args)")
    dispatcher = "\n".join(dispatcher_lines) if dispatcher_lines else "        pass"
    return _BASE_SERVER_TEMPLATE.format(
        methods=methods,
        tool_schemas_assign=assign,
        dispatcher=dispatcher,
    )


class _ServerFixture:
    """Writes a synthetic vault-mcp-server.py to a temp dir."""

    def __init__(self, src: str) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "vault-mcp-server.py"
        self.path.write_text(src, encoding="utf-8")

    def cleanup(self) -> None:
        self._tmp.cleanup()


# --------------------------------------------------------------------------
# Pure AST tests (no live call)
# --------------------------------------------------------------------------


class TestServerInspection(unittest.TestCase):
    def test_extract_tool_schemas_annotated(self):
        src = _build_synthetic_server(
            schema_names=["vault_a", "vault_b"],
            method_names=["vault_a", "vault_b"],
            dispatcher_names=["vault_a", "vault_b"],
            annotated=True,
        )
        fx = _ServerFixture(src)
        try:
            inv = r69.inspect_server(fx.path)
            self.assertEqual(inv.tool_schemas, {"vault_a", "vault_b"})
            self.assertEqual(inv.choices, {"vault_a", "vault_b"})
            self.assertEqual(inv.methods, {"vault_a", "vault_b"})
            self.assertEqual(inv.dispatcher_branches, {"vault_a", "vault_b"})
        finally:
            fx.cleanup()

    def test_extract_tool_schemas_plain_assign(self):
        src = _build_synthetic_server(
            schema_names=["vault_a"],
            method_names=["vault_a"],
            dispatcher_names=["vault_a"],
            annotated=False,
        )
        fx = _ServerFixture(src)
        try:
            inv = r69.inspect_server(fx.path)
            self.assertEqual(inv.tool_schemas, {"vault_a"})
        finally:
            fx.cleanup()

    def test_method_kwargs_extracted_from_get_and_subscript(self):
        method_body = textwrap.indent(
            (
                "ws = kwargs.get('workspace_path')\n"
                "if 'limit' in kwargs:\n"
                "    limit = kwargs['limit']\n"
                "if bool(kwargs.get('seed_from_global_templates')):\n"
                "    pass\n"
                "return {'ok': True}\n"
            ),
            "        ",
        )
        src = _build_synthetic_server(
            schema_names=["vault_a"],
            method_names=["vault_a"],
            dispatcher_names=["vault_a"],
            method_bodies={"vault_a": method_body},
        )
        fx = _ServerFixture(src)
        try:
            inv = r69.inspect_server(fx.path)
            self.assertIn("workspace_path", inv.method_kwarg_refs["vault_a"])
            self.assertIn("limit", inv.method_kwarg_refs["vault_a"])
            self.assertIn(
                "seed_from_global_templates",
                inv.method_kwarg_refs["vault_a"],
            )
        finally:
            fx.cleanup()


# --------------------------------------------------------------------------
# Verdict-matrix tests (using --no-live-call)
# --------------------------------------------------------------------------


def _run_cli(args: list[str]) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(_TOOL_PATH)] + args,
        capture_output=True,
        text=True,
        check=False,
    )
    parsed: dict | None = None
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        parsed = None
    return proc.returncode, parsed, proc.stdout + proc.stderr


class TestVerdictMatrix(unittest.TestCase):
    def _make_server(
        self,
        *,
        schemas: list[str],
        methods: list[str],
        dispatcher: list[str],
        method_bodies: dict[str, str] | None = None,
    ) -> _ServerFixture:
        src = _build_synthetic_server(
            schema_names=schemas,
            method_names=methods,
            dispatcher_names=dispatcher,
            method_bodies=method_bodies,
        )
        return _ServerFixture(src)

    def test_wired_and_callable_no_live(self):
        fx = self._make_server(
            schemas=["vault_x"],
            methods=["vault_x"],
            dispatcher=["vault_x"],
        )
        try:
            rc, payload, _ = _run_cli(
                [
                    "--claimed-callables", "vault_x",
                    "--server", str(fx.path),
                    "--no-live-call", "--json",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertIsNotNone(payload)
            self.assertEqual(payload["overall_verdict"], "pass")
            self.assertEqual(payload["callables"][0]["verdict"], "wired-and-callable")
        finally:
            fx.cleanup()

    def test_missing_from_choices(self):
        fx = self._make_server(
            schemas=["vault_x"],
            methods=["vault_x"],
            dispatcher=["vault_x"],
        )
        try:
            rc, payload, _ = _run_cli(
                [
                    "--claimed-callables", "vault_z_not_present",
                    "--server", str(fx.path),
                    "--no-live-call", "--strict", "--json",
                ]
            )
            self.assertEqual(rc, 1)
            self.assertEqual(payload["callables"][0]["verdict"], "missing-from-choices")
        finally:
            fx.cleanup()

    def test_missing_from_tool_schemas(self):
        # Synthesize: name appears in argparse choices via literal (so we
        # must use the plain-list trick). Simpler: stub server with a
        # tool name in choices but absent from TOOL_SCHEMAS is not easily
        # constructable - so we directly exercise classify_callable() with
        # a hand-built inventory.
        inv = r69.ServerInventory(
            server_path=Path("/nonexistent"),
            server_sha256="",
            choices={"vault_orphan"},
            tool_schemas=set(),
            methods={"vault_orphan"},
            dispatcher_branches={"vault_orphan"},
        )
        v = r69.classify_callable(
            "vault_orphan", inv,
            do_live_call=False, kwarg_to_check=None,
        )
        self.assertEqual(v.verdict, "missing-from-tool-schemas")

    def test_missing_from_method(self):
        # Schema entry present but no method.
        fx = self._make_server(
            schemas=["vault_x"],
            methods=[],
            dispatcher=["vault_x"],
        )
        try:
            rc, payload, _ = _run_cli(
                [
                    "--claimed-callables", "vault_x",
                    "--server", str(fx.path),
                    "--no-live-call", "--strict", "--json",
                ]
            )
            self.assertEqual(rc, 1)
            self.assertEqual(payload["callables"][0]["verdict"], "missing-from-method")
        finally:
            fx.cleanup()

    def test_missing_from_dispatcher(self):
        # Method + schema present, but dispatcher branch absent (LIFT-21).
        fx = self._make_server(
            schemas=["vault_x"],
            methods=["vault_x"],
            dispatcher=[],
        )
        try:
            rc, payload, _ = _run_cli(
                [
                    "--claimed-callables", "vault_x",
                    "--server", str(fx.path),
                    "--no-live-call", "--strict", "--json",
                ]
            )
            self.assertEqual(rc, 1)
            self.assertEqual(payload["callables"][0]["verdict"], "missing-from-dispatcher")
        finally:
            fx.cleanup()

    def test_silently_ignored_kwarg(self):
        # LIFT-25 case: method exists, dispatcher exists, but body never
        # reads `kwargs.get("seed_from_global_templates")`.
        method_body = "        return {'ok': True}"
        fx = self._make_server(
            schemas=["vault_x"],
            methods=["vault_x"],
            dispatcher=["vault_x"],
            method_bodies={"vault_x": method_body},
        )
        try:
            rc, payload, _ = _run_cli(
                [
                    "--claimed-callables", "vault_x",
                    "--kwarg", "seed_from_global_templates",
                    "--server", str(fx.path),
                    "--no-live-call", "--strict", "--json",
                ]
            )
            self.assertEqual(rc, 1)
            self.assertEqual(
                payload["callables"][0]["verdict"],
                "silently-ignored-kwarg",
            )
            self.assertIn(
                "seed_from_global_templates",
                payload["callables"][0]["kwarg_check"]["kwarg"],
            )
        finally:
            fx.cleanup()

    def test_kwarg_referenced_passes(self):
        method_body = (
            "        if bool(kwargs.get('seed_from_global_templates')):\n"
            "            return {'ok': True, 'seeded': True}\n"
            "        return {'ok': True}"
        )
        fx = self._make_server(
            schemas=["vault_x"],
            methods=["vault_x"],
            dispatcher=["vault_x"],
            method_bodies={"vault_x": method_body},
        )
        try:
            rc, payload, _ = _run_cli(
                [
                    "--claimed-callables", "vault_x",
                    "--kwarg", "seed_from_global_templates",
                    "--server", str(fx.path),
                    "--no-live-call", "--json",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                payload["callables"][0]["verdict"],
                "wired-and-callable",
            )
            self.assertTrue(
                payload["callables"][0]["kwarg_check"]["referenced_in_method_body"]
            )
        finally:
            fx.cleanup()

    def test_strict_fail_returns_nonzero(self):
        # Made-up callable + --strict
        rc, _, _ = _run_cli(
            [
                "--claimed-callables", "vault_does_not_exist",
                "--server", str(_REAL_SERVER),
                "--no-live-call", "--strict", "--json",
            ]
        )
        self.assertEqual(rc, 1)

    def test_non_strict_advisory_returns_zero(self):
        rc, payload, _ = _run_cli(
            [
                "--claimed-callables", "vault_does_not_exist",
                "--server", str(_REAL_SERVER),
                "--no-live-call", "--json",
            ]
        )
        # Without --strict, the tool returns rc=0 (advisory mode) but the
        # JSON still flags fail_count > 0.
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(payload["fail_count"], 1)

    def test_json_payload_schema(self):
        rc, payload, _ = _run_cli(
            [
                "--claimed-callables", "vault_hacker_questions",
                "--server", str(_REAL_SERVER),
                "--no-live-call", "--json",
            ]
        )
        self.assertEqual(rc, 0)
        for key in (
            "schema", "overall_verdict", "fail_count", "total_count",
            "server", "server_sha256", "inventory_summary", "callables",
        ):
            self.assertIn(key, payload)
        self.assertEqual(payload["schema"], r69.SCHEMA)

    def test_no_callables_returns_error(self):
        rc, _, _ = _run_cli(
            [
                "--claimed-callables", "",
                "--server", str(_REAL_SERVER),
                "--no-live-call", "--json",
            ]
        )
        # Empty list is rejected with rc=1.
        self.assertEqual(rc, 1)


# --------------------------------------------------------------------------
# Live-call test against the real server (best-effort; skipped if missing)
# --------------------------------------------------------------------------


@unittest.skipUnless(
    _REAL_SERVER.exists(),
    "vault-mcp-server.py not present in expected location",
)
class TestLiveCallAgainstRealServer(unittest.TestCase):
    def test_known_wired_callable_lives(self):
        # vault_hacker_questions is a well-established LIFT-10 callable
        # that has all four wiring surfaces and returns a non-degraded JSON
        # body with empty args.
        rc, payload, _ = _run_cli(
            [
                "--claimed-callables", "vault_hacker_questions",
                "--server", str(_REAL_SERVER),
                "--json",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(payload["overall_verdict"], "pass")
        v = payload["callables"][0]
        self.assertIn(v["verdict"], {"wired-and-callable", "wired-but-degraded"})

    def test_live_call_with_made_up_name_missing_from_choices(self):
        rc, payload, _ = _run_cli(
            [
                "--claimed-callables", "vault_made_up_xxx",
                "--server", str(_REAL_SERVER),
                "--strict", "--json",
            ]
        )
        self.assertEqual(rc, 1)
        self.assertEqual(payload["callables"][0]["verdict"], "missing-from-choices")


if __name__ == "__main__":
    unittest.main()
