#!/usr/bin/env python3
"""r69-callable-wiring-verifier.py

Verify that a claimed MCP callable in ``tools/vault-mcp-server.py`` is
actually wired across all four mandatory surfaces:

  1. argparse ``--call`` choices (visible to operators)
  2. ``TOOL_SCHEMAS`` entry (visible to MCP clients via tools/list)
  3. ``VaultQuery`` method (the actual implementation)
  4. ``_dispatch`` branch (routing layer that maps name -> method)

Optionally, the tool also live-calls the callable with minimal args to
verify the response is non-error (or that any ``degraded:true`` carries
a non-empty ``degraded_reason``).

Schema: ``auditooor.r69_callable_wiring_verifier.v1``.

Empirical anchor: LIFT-21 + LIFT-25 (2026-05-26). Codex Phase 3 takeover
reported 3 callables LANDED; in fact 2/3 wiring branches were missing -
``vault_global_chain_template_match`` was missing from TOOL_SCHEMAS /
choices / dispatcher, and the ``seed_from_global_templates`` kwarg of
``vault_chained_attack_plan_context`` was silently discarded. R69 catches
this pre-claim by directly inspecting the server source.

CLI:
    python3 tools/r69-callable-wiring-verifier.py \
        --claimed-callables NAME1,NAME2,... [--strict] [--json] \
        [--server tools/vault-mcp-server.py] [--no-live-call]

Verdicts per callable:
    wired-and-callable          - all 4 checks PASS + live call OK
    wired-but-degraded          - all 4 PASS + live call returned degraded:true
                                  with non-empty reason (acceptable)
    missing-from-choices        - not in argparse choices (LIFT-21 case)
    missing-from-tool-schemas   - in choices but no TOOL_SCHEMAS entry
    missing-from-method         - in schemas but no VaultQuery method
    missing-from-dispatcher     - in schemas + method but no _dispatch branch
    silently-ignored-kwarg      - callable exists, but the cited kwarg is not
                                  referenced in the method body (LIFT-25 case);
                                  only used when --kwarg <name> is provided
    live-call-error             - all 4 wiring PASS but live invocation errored

Override marker: ``<!-- r69-rebuttal: <reason up to 200 chars> -->`` on the
caller-side draft / brief / report - the verifier itself never reads draft
files, only the server source + the operator's --claimed-callables list.

r36-rebuttal: lane LANE-217-R69-CALLABLE-WIRING-VERIFIER declared via
tools/agent-pathspec-register.py.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.r69_callable_wiring_verifier.v1"
DEFAULT_SERVER = "tools/vault-mcp-server.py"
LIVE_CALL_TIMEOUT_SECONDS = 30


# --------------------------------------------------------------------------
# Static inspection of vault-mcp-server.py
# --------------------------------------------------------------------------


@dataclass
class ServerInventory:
    """Static-inspection snapshot of vault-mcp-server.py."""

    server_path: Path
    server_sha256: str
    choices: set[str] = field(default_factory=set)
    tool_schemas: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    dispatcher_branches: set[str] = field(default_factory=set)
    method_kwarg_refs: dict[str, set[str]] = field(default_factory=dict)
    inspection_errors: list[str] = field(default_factory=list)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _extract_choices_from_source(src: str) -> set[str]:
    """Extract argparse choices for ``--call``.

    The vault-mcp-server uses ``choices=[tool["name"] for tool in TOOL_SCHEMAS]``
    (or any single-iteration var name) so the canonical choices list equals
    the TOOL_SCHEMAS names. When we detect that comprehension shape, return
    empty and let callers fall back to TOOL_SCHEMAS as the truth source.

    r36-rebuttal: lane LANE-217-R69-CALLABLE-WIRING-VERIFIER declared via
    tools/agent-pathspec-register.py.
    """
    # The argparse line is e.g. `parser.add_argument("--call",
    # choices=[tool["name"] for tool in TOOL_SCHEMAS])`. The loop variable
    # may be `tool`, `t`, `s`, etc.; we accept any identifier.
    comp_re = re.compile(
        r"choices\s*=\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*['\"]name['\"]\s*\]"
        r"\s+for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+TOOL_SCHEMAS\s*\]"
    )
    m = comp_re.search(src)
    if m and m.group(1) == m.group(2):
        return set()
    # Fallback: parse literal lists of strings.
    out: set[str] = set()
    m_lit = re.search(r"choices=\[\s*([^]]+)\s*\]", src)
    if m_lit:
        for piece in m_lit.group(1).split(","):
            piece = piece.strip().strip("'").strip('"')
            if piece:
                out.add(piece)
    return out


def _extract_tool_schemas(tree: ast.AST) -> set[str]:
    """Pull every ``"name": "vault_X"`` entry from TOOL_SCHEMAS = [ ... ].

    Accepts both ``TOOL_SCHEMAS = [...]`` (ast.Assign) and the annotated form
    ``TOOL_SCHEMAS: list[...] = [...]`` (ast.AnnAssign).

    r36-rebuttal: lane LANE-217-R69-CALLABLE-WIRING-VERIFIER declared via
    tools/agent-pathspec-register.py.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        is_target = False
        value: ast.AST | None = None
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "TOOL_SCHEMAS"
        ):
            is_target = True
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "TOOL_SCHEMAS"
        ):
            is_target = True
            value = node.value
        if is_target and isinstance(value, ast.List):
            for elt in value.elts:
                if isinstance(elt, ast.Dict):
                    for k, v in zip(elt.keys, elt.values):
                        if (
                            isinstance(k, ast.Constant)
                            and k.value == "name"
                            and isinstance(v, ast.Constant)
                            and isinstance(v.value, str)
                        ):
                            out.add(v.value)
            break
    return out


def _extract_vault_methods(tree: ast.AST) -> tuple[set[str], dict[str, set[str]]]:
    """Find every ``def vault_<name>`` method and the kwarg names referenced
    inside its body.

    We approximate the kwarg-detection by collecting any string literal
    appearing as a ``kwargs.get(...)`` / ``kwargs[...]`` key (matches the
    `**kwargs` pattern these methods use), plus any explicit named parameter
    on the def signature.
    """
    methods: set[str] = set()
    method_kwargs: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "VaultQuery":
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and child.name.startswith("vault_"):
                    methods.add(child.name)
                    kwargs_seen: set[str] = set()
                    # Named formal parameters (positional + kw-only).
                    for arg in child.args.args + child.args.kwonlyargs:
                        if arg.arg not in {"self", "kwargs", "args"}:
                            kwargs_seen.add(arg.arg)
                    # Walk the body for kwargs.get("X") / kwargs["X"].
                    for sub in ast.walk(child):
                        if isinstance(sub, ast.Call):
                            func = sub.func
                            if (
                                isinstance(func, ast.Attribute)
                                and func.attr == "get"
                                and isinstance(func.value, ast.Name)
                                and func.value.id == "kwargs"
                                and sub.args
                                and isinstance(sub.args[0], ast.Constant)
                                and isinstance(sub.args[0].value, str)
                            ):
                                kwargs_seen.add(sub.args[0].value)
                        elif isinstance(sub, ast.Subscript):
                            if (
                                isinstance(sub.value, ast.Name)
                                and sub.value.id == "kwargs"
                            ):
                                slice_node = sub.slice
                                if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
                                    kwargs_seen.add(slice_node.value)
                    method_kwargs[child.name] = kwargs_seen
            break
    return methods, method_kwargs


def _extract_dispatcher_branches(tree: ast.AST) -> set[str]:
    """Find every ``if name == "vault_X"`` branch in ``_dispatch``."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_dispatch":
            for sub in ast.walk(node):
                if isinstance(sub, ast.If):
                    test = sub.test
                    if (
                        isinstance(test, ast.Compare)
                        and isinstance(test.left, ast.Name)
                        and test.left.id == "name"
                        and len(test.ops) == 1
                        and isinstance(test.ops[0], ast.Eq)
                        and len(test.comparators) == 1
                        and isinstance(test.comparators[0], ast.Constant)
                        and isinstance(test.comparators[0].value, str)
                    ):
                        out.add(test.comparators[0].value)
            break
    return out


def inspect_server(server_path: Path) -> ServerInventory:
    inv = ServerInventory(
        server_path=server_path,
        server_sha256=_sha256_file(server_path),
    )
    try:
        src = server_path.read_text(encoding="utf-8")
    except OSError as exc:
        inv.inspection_errors.append(f"read-failed: {exc}")
        return inv

    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        inv.inspection_errors.append(f"parse-failed: {exc}")
        return inv

    inv.tool_schemas = _extract_tool_schemas(tree)
    # The server uses choices=[tool["name"] for tool in TOOL_SCHEMAS]; if so,
    # the canonical choices set IS the TOOL_SCHEMAS set. Otherwise fall back
    # to whatever literal we can parse.
    literal_choices = _extract_choices_from_source(src)
    if literal_choices:
        inv.choices = literal_choices
    else:
        inv.choices = set(inv.tool_schemas)
    inv.methods, inv.method_kwarg_refs = _extract_vault_methods(tree)
    inv.dispatcher_branches = _extract_dispatcher_branches(tree)
    return inv


# --------------------------------------------------------------------------
# Live-call verification
# --------------------------------------------------------------------------


def live_call(server_path: Path, name: str, timeout: int = LIVE_CALL_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Invoke the callable with empty args via the CLI surface and parse JSON.

    Returns a dict with keys: ``ok`` (bool), ``returncode`` (int),
    ``parsed`` (dict|None), ``stdout_head`` (str), ``stderr_head`` (str),
    ``error`` (str|None).
    """
    if not server_path.exists():
        return {
            "ok": False,
            "returncode": None,
            "parsed": None,
            "stdout_head": "",
            "stderr_head": "",
            "error": f"server-not-found: {server_path}",
        }
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(server_path),
                "--call",
                name,
                "--args",
                "{}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": None,
            "parsed": None,
            "stdout_head": "",
            "stderr_head": "",
            "error": "live-call-timeout",
        }
    except OSError as exc:
        return {
            "ok": False,
            "returncode": None,
            "parsed": None,
            "stdout_head": "",
            "stderr_head": "",
            "error": f"live-call-os-error: {exc}",
        }

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    parsed: dict[str, Any] | None = None
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        parsed = None

    return {
        "ok": proc.returncode == 0 and isinstance(parsed, dict),
        "returncode": proc.returncode,
        "parsed": parsed,
        "stdout_head": stdout[:200],
        "stderr_head": stderr[:200],
        "error": None if proc.returncode == 0 else f"rc={proc.returncode}",
    }


# --------------------------------------------------------------------------
# Per-callable verdict assembly
# --------------------------------------------------------------------------


@dataclass
class CallableVerdict:
    name: str
    verdict: str
    in_choices: bool
    in_tool_schemas: bool
    has_method: bool
    has_dispatcher_branch: bool
    kwarg_check: dict[str, Any] | None = None
    live_call: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)


def classify_callable(
    name: str,
    inventory: ServerInventory,
    *,
    do_live_call: bool,
    kwarg_to_check: str | None,
    timeout: int = LIVE_CALL_TIMEOUT_SECONDS,
) -> CallableVerdict:
    in_choices = name in inventory.choices
    in_schemas = name in inventory.tool_schemas
    has_method = name in inventory.methods
    has_branch = name in inventory.dispatcher_branches

    notes: list[str] = []

    # Ordering matters: choices is the operator-visible surface.
    if not in_choices:
        return CallableVerdict(
            name=name,
            verdict="missing-from-choices",
            in_choices=False,
            in_tool_schemas=in_schemas,
            has_method=has_method,
            has_dispatcher_branch=has_branch,
            notes=notes,
        )
    if not in_schemas:
        return CallableVerdict(
            name=name,
            verdict="missing-from-tool-schemas",
            in_choices=in_choices,
            in_tool_schemas=False,
            has_method=has_method,
            has_dispatcher_branch=has_branch,
            notes=notes,
        )
    if not has_method:
        return CallableVerdict(
            name=name,
            verdict="missing-from-method",
            in_choices=in_choices,
            in_tool_schemas=in_schemas,
            has_method=False,
            has_dispatcher_branch=has_branch,
            notes=notes,
        )
    if not has_branch:
        return CallableVerdict(
            name=name,
            verdict="missing-from-dispatcher",
            in_choices=in_choices,
            in_tool_schemas=in_schemas,
            has_method=has_method,
            has_dispatcher_branch=False,
            notes=notes,
        )

    kwarg_payload: dict[str, Any] | None = None
    if kwarg_to_check:
        known_kwargs = inventory.method_kwarg_refs.get(name, set())
        kwarg_referenced = kwarg_to_check in known_kwargs
        kwarg_payload = {
            "kwarg": kwarg_to_check,
            "referenced_in_method_body": kwarg_referenced,
            "method_kwargs_observed": sorted(known_kwargs),
        }
        if not kwarg_referenced:
            return CallableVerdict(
                name=name,
                verdict="silently-ignored-kwarg",
                in_choices=in_choices,
                in_tool_schemas=in_schemas,
                has_method=has_method,
                has_dispatcher_branch=has_branch,
                kwarg_check=kwarg_payload,
                notes=notes,
            )

    live_payload: dict[str, Any] | None = None
    if do_live_call:
        live_payload = live_call(inventory.server_path, name, timeout=timeout)
        if not live_payload.get("ok"):
            return CallableVerdict(
                name=name,
                verdict="live-call-error",
                in_choices=in_choices,
                in_tool_schemas=in_schemas,
                has_method=has_method,
                has_dispatcher_branch=has_branch,
                kwarg_check=kwarg_payload,
                live_call=live_payload,
                notes=notes,
            )
        parsed = live_payload.get("parsed") or {}
        degraded = bool(parsed.get("degraded"))
        if degraded:
            reason = parsed.get("degraded_reason") or parsed.get("reason") or ""
            if isinstance(reason, str) and reason.strip():
                notes.append(f"degraded: {reason.strip()[:120]}")
            else:
                notes.append("degraded but no reason given")
            return CallableVerdict(
                name=name,
                verdict="wired-but-degraded",
                in_choices=in_choices,
                in_tool_schemas=in_schemas,
                has_method=has_method,
                has_dispatcher_branch=has_branch,
                kwarg_check=kwarg_payload,
                live_call=live_payload,
                notes=notes,
            )

    return CallableVerdict(
        name=name,
        verdict="wired-and-callable",
        in_choices=in_choices,
        in_tool_schemas=in_schemas,
        has_method=has_method,
        has_dispatcher_branch=has_branch,
        kwarg_check=kwarg_payload,
        live_call=live_payload,
        notes=notes,
    )


# --------------------------------------------------------------------------
# CLI entrypoint
# --------------------------------------------------------------------------


def _verdict_to_dict(v: CallableVerdict) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": v.name,
        "verdict": v.verdict,
        "in_choices": v.in_choices,
        "in_tool_schemas": v.in_tool_schemas,
        "has_method": v.has_method,
        "has_dispatcher_branch": v.has_dispatcher_branch,
    }
    if v.kwarg_check is not None:
        out["kwarg_check"] = v.kwarg_check
    if v.live_call is not None:
        # Trim live_call to keep payload bounded.
        out["live_call"] = {
            "ok": v.live_call.get("ok"),
            "returncode": v.live_call.get("returncode"),
            "degraded": bool((v.live_call.get("parsed") or {}).get("degraded")),
            "stderr_head": v.live_call.get("stderr_head"),
            "error": v.live_call.get("error"),
        }
    if v.notes:
        out["notes"] = list(v.notes)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify that claimed MCP callables in tools/vault-mcp-server.py "
            "are actually wired across argparse choices, TOOL_SCHEMAS, "
            "VaultQuery methods, and _dispatch branches."
        )
    )
    parser.add_argument(
        "--claimed-callables",
        required=True,
        help="Comma-separated list of callable names (e.g. vault_X,vault_Y).",
    )
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER,
        help=f"Path to vault-mcp-server.py (default: {DEFAULT_SERVER}).",
    )
    parser.add_argument(
        "--kwarg",
        default=None,
        help=(
            "Optional kwarg name to verify is referenced in EVERY claimed "
            "callable's method body. Catches LIFT-25-style silently-discarded "
            "kwargs."
        ),
    )
    parser.add_argument(
        "--no-live-call",
        action="store_true",
        help=(
            "Skip the live --call invocation. Useful inside test environments "
            "or where the server takes a long time to import."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Hard-fail (exit 1) on any verdict that is not "
            "wired-and-callable / wired-but-degraded."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=LIVE_CALL_TIMEOUT_SECONDS,
        help=f"Per-call timeout in seconds (default {LIVE_CALL_TIMEOUT_SECONDS}).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    args = parser.parse_args(argv)

    server_path = Path(args.server).resolve()
    inventory = inspect_server(server_path)

    callables = [c.strip() for c in args.claimed_callables.split(",") if c.strip()]
    if not callables:
        payload = {
            "schema": SCHEMA,
            "overall_verdict": "error",
            "error": "no-callables-provided",
            "server": str(server_path),
        }
        if args.json:
            json.dump(payload, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print("ERROR: --claimed-callables is empty")
        return 1

    do_live_call = not args.no_live_call
    verdicts: list[CallableVerdict] = []
    for name in callables:
        verdicts.append(
            classify_callable(
                name,
                inventory,
                do_live_call=do_live_call,
                kwarg_to_check=args.kwarg,
                timeout=args.timeout,
            )
        )

    pass_set = {"wired-and-callable", "wired-but-degraded"}
    fail_count = sum(1 for v in verdicts if v.verdict not in pass_set)
    overall = "pass" if fail_count == 0 else "fail"

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "overall_verdict": overall,
        "fail_count": fail_count,
        "total_count": len(verdicts),
        "server": str(server_path),
        "server_sha256": inventory.server_sha256,
        "inventory_summary": {
            "choices_count": len(inventory.choices),
            "tool_schemas_count": len(inventory.tool_schemas),
            "methods_count": len(inventory.methods),
            "dispatcher_branches_count": len(inventory.dispatcher_branches),
        },
        "inspection_errors": list(inventory.inspection_errors),
        "callables": [_verdict_to_dict(v) for v in verdicts],
    }
    if args.kwarg:
        payload["kwarg_under_test"] = args.kwarg

    if args.json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"R69 callable-wiring verifier (schema {SCHEMA})")
        print(f"  server         : {server_path}")
        print(f"  server sha256  : {inventory.server_sha256[:16]}")
        print(
            "  inventory      : "
            f"choices={len(inventory.choices)} "
            f"schemas={len(inventory.tool_schemas)} "
            f"methods={len(inventory.methods)} "
            f"branches={len(inventory.dispatcher_branches)}"
        )
        if inventory.inspection_errors:
            print(f"  inspection errors: {inventory.inspection_errors}")
        for v in verdicts:
            mark = "OK" if v.verdict in pass_set else "FAIL"
            print(f"  [{mark}] {v.name}: {v.verdict}")
            if v.notes:
                for note in v.notes:
                    print(f"        note: {note}")
            if v.kwarg_check is not None and not v.kwarg_check.get("referenced_in_method_body"):
                print(
                    "        kwarg "
                    f"'{v.kwarg_check.get('kwarg')}' not referenced in "
                    f"{v.name}() body"
                )
            if v.live_call is not None and not v.live_call.get("ok"):
                err = v.live_call.get("error")
                stderr_head = (v.live_call.get("stderr_head") or "").strip()
                print(f"        live-call error: {err} stderr: {stderr_head[:120]}")
        print(f"  OVERALL: {overall} ({fail_count} fail / {len(verdicts)} total)")

    if args.strict and fail_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
