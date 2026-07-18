#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - navigable index of all
``vault_*`` MCP callables exposed by ``tools/vault-mcp-server.py``.

Companion to ``tools/hackerman-help.py``: that tool indexes ``hackerman-*``
Makefile targets; this tool indexes the MCP callables registered on the
``VaultMCPServer`` class and listed in the ``TOOL_SCHEMAS`` array.

For each callable, emits:

- ``name``      - callable name (e.g. ``vault_resume_context``)
- ``schema``    - the ``auditooor.vault_*.v1`` schema id detected from
                  module-level ``*_SCHEMA = "auditooor.vault_X.vN"``
                  constants OR from the first ``"schema"`` key of a
                  ``return {...}`` literal inside the function body.
                  Falls back to ``None`` when neither is present.
- ``description`` - the one-line description string from the matching
                    ``TOOL_SCHEMAS`` record. Empty string when no schema
                    record matches (some internal helpers are not exposed
                    via the JSON-RPC ``tools/list`` surface).
- ``input_fields`` - sorted list of property names from
                     ``inputSchema.properties``.
- ``required_fields`` - sorted list of property names from
                        ``inputSchema.required``.
- ``output_fields`` - sorted list of top-level keys best-effort extracted
                      from ``return {...}`` dict literals inside the
                      callable body. Determinism: deduped + sorted.
- ``lineno``    - source line where ``def vault_X`` appears in
                  ``tools/vault-mcp-server.py``.

Determinism guarantees:

- Callables listed lexicographically.
- Knob / field arrays deduped + sorted asc.
- Output is byte-stable across runs (no timestamps; no env-leak).

Wired into the Makefile as::

    make vault-mcp-help          # human index
    make vault-mcp-help-json     # JSON envelope (auditooor.vault_mcp_help.v1)
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"

VAULT_DEF_RE = re.compile(r"\bdef\s+(vault_[A-Za-z0-9_]+)\s*\(")


def _read_source(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"vault-mcp-server source not found: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def _extract_schema_constants(tree: ast.AST) -> dict[str, str]:
    """Walk module top level and collect ``NAME = "auditooor.vault_X.vN"``
    assignments. Returns a name -> schema string map.

    Two indexing keys are populated for each schema string:

    1. The schema's embedded callable name (e.g. ``vault_resume_context``).
    2. A versioned variant when the schema major-version is >= 2 (e.g.
       ``vault_attack_class_evidence.v2`` -> ``vault_attack_class_evidence_v2``).
       This is what the V2/V3 sibling callables in this repo are named.

    The first registration for a given key wins.
    """
    out: dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        schema_str = value.value
        if not schema_str.startswith("auditooor.vault_"):
            continue
        # Derive base callable name from schema id. Examples:
        #   auditooor.vault_resume_context.v1 -> vault_resume_context
        #   auditooor.vault_spark_engagement_context.v1.1 -> vault_spark_engagement_context
        #   auditooor.vault_attack_class_evidence.v2 -> vault_attack_class_evidence
        body = schema_str[len("auditooor."):]
        parts = body.split(".")
        keep: list[str] = []
        major: str | None = None
        for seg in parts:
            vmatch = re.fullmatch(r"v(\d+)", seg)
            if vmatch:
                major = vmatch.group(1)
                break
            keep.append(seg)
        base_name = ".".join(keep)
        if base_name and base_name not in out:
            out[base_name] = schema_str
        # Also index the versioned sibling form for v>=2 (callable in this
        # repo is suffixed _v2 / _v3).
        if major is not None and int(major) >= 2:
            versioned = f"{base_name}_v{major}"
            if versioned and versioned not in out:
                out[versioned] = schema_str
    return out


def _extract_tool_schemas(tree: ast.AST) -> dict[str, dict[str, Any]]:
    """Walk for ``TOOL_SCHEMAS = [...]`` and return name -> record map.

    Each record exposes the canonical fields the JSON-RPC ``tools/list``
    surface ships: ``description``, ``input_fields``, ``required_fields``.
    """
    out: dict[str, dict[str, Any]] = {}
    target_value: ast.AST | None = None
    for node in ast.iter_child_nodes(tree):
        # Match ``TOOL_SCHEMAS = [...]`` and ``TOOL_SCHEMAS: list[...] = [...]``.
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "TOOL_SCHEMAS":
                    target_value = node.value
                    break
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "TOOL_SCHEMAS":
                target_value = node.value
        if target_value is not None:
            break
    if target_value is None or not isinstance(target_value, ast.List):
        return out

    for elt in target_value.elts:
        if not isinstance(elt, ast.Dict):
            continue
        rec = _dict_node_to_summary(elt)
        name = rec.get("name")
        if isinstance(name, str) and name.startswith("vault_"):
            out[name] = rec
    return out


def _dict_node_to_summary(node: ast.Dict) -> dict[str, Any]:
    """Best-effort lift of a ``TOOL_SCHEMAS`` dict literal into a summary
    record. Non-string values are silently skipped. ``inputSchema`` is
    treated specially to harvest property names + required names.
    """
    rec: dict[str, Any] = {
        "name": None,
        "description": "",
        "input_fields": [],
        "required_fields": [],
    }
    for k_node, v_node in zip(node.keys, node.values):
        if not isinstance(k_node, ast.Constant) or not isinstance(k_node.value, str):
            continue
        key = k_node.value
        if key == "name" and isinstance(v_node, ast.Constant):
            if isinstance(v_node.value, str):
                rec["name"] = v_node.value
        elif key == "description" and isinstance(v_node, ast.Constant):
            if isinstance(v_node.value, str):
                rec["description"] = v_node.value
        elif key == "inputSchema" and isinstance(v_node, ast.Dict):
            props, required = _harvest_input_schema(v_node)
            rec["input_fields"] = sorted(set(props))
            rec["required_fields"] = sorted(set(required))
    return rec


def _harvest_input_schema(node: ast.Dict) -> tuple[list[str], list[str]]:
    props: list[str] = []
    required: list[str] = []
    for k_node, v_node in zip(node.keys, node.values):
        if not isinstance(k_node, ast.Constant) or not isinstance(k_node.value, str):
            continue
        key = k_node.value
        if key == "properties":
            # Two shapes: a literal ``{...}`` or a reference to a module
            # constant like ``CONTEXT_PACK_INPUT_PROPERTIES``. Only the
            # literal form yields property names here; the constant form
            # surfaces as a single ``<dynamic>`` placeholder so callers
            # know to consult the source.
            if isinstance(v_node, ast.Dict):
                for sub_k in v_node.keys:
                    if isinstance(sub_k, ast.Constant) and isinstance(sub_k.value, str):
                        props.append(sub_k.value)
            elif isinstance(v_node, ast.Name):
                props.append(f"<from:{v_node.id}>")
        elif key == "required" and isinstance(v_node, ast.List):
            for elt in v_node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    required.append(elt.value)
    return props, required


def _extract_vault_callables(source: str, tree: ast.AST) -> list[dict[str, Any]]:
    """Walk class bodies for ``def vault_*`` and harvest:
       name, lineno, docstring first line, return-dict top-level keys.
    """
    results: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fname = item.name
            if not fname.startswith("vault_"):
                continue
            doc = ast.get_docstring(item) or ""
            doc_first_line = doc.strip().splitlines()[0] if doc.strip() else ""
            output_keys = _harvest_return_keys(item)
            results.append({
                "name": fname,
                "lineno": item.lineno,
                "docstring_first_line": doc_first_line,
                "output_fields": sorted(set(output_keys)),
            })
    # Dedup by name, keep first (handles overrides/staticmethod redecls).
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for rec in results:
        if rec["name"] in seen:
            continue
        seen.add(rec["name"])
        deduped.append(rec)
    return deduped


def _harvest_return_keys(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Walk the function body for every ``return {<literal-key>: ...}`` and
    collect the top-level string keys. Non-literal keys (e.g. computed
    expressions) are silently skipped. This is a deterministic best-effort
    surface for the "output_fields" hint - callers must still consult the
    schema id for the authoritative shape.
    """
    keys: list[str] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Return):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for k_node in node.value.keys:
            if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                keys.append(k_node.value)
    return keys


def _harvest_inline_schema_from_returns(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """If the function returns a dict with a literal ``"schema": "auditooor.vault_..."``
    entry, lift the schema string. First match wins.
    """
    for node in ast.walk(func):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
            continue
        for k_node, v_node in zip(node.value.keys, node.value.values):
            if (
                isinstance(k_node, ast.Constant)
                and k_node.value == "schema"
                and isinstance(v_node, ast.Constant)
                and isinstance(v_node.value, str)
                and v_node.value.startswith("auditooor.vault_")
            ):
                return v_node.value
    return None


def index_callables(server_path: Path) -> list[dict[str, Any]]:
    """Return one record per ``vault_*`` callable, deterministically sorted
    by name. Each record exposes the join of (function metadata,
    TOOL_SCHEMAS metadata, module-level *_SCHEMA constant detection).
    """
    source = _read_source(server_path)
    tree = ast.parse(source, filename=str(server_path))

    schema_constants = _extract_schema_constants(tree)
    tool_schemas = _extract_tool_schemas(tree)
    callables = _extract_vault_callables(source, tree)

    # Walk callables a second time to harvest inline ``"schema"`` keys.
    inline_schemas: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("vault_"):
                hit = _harvest_inline_schema_from_returns(item)
                if hit is not None and item.name not in inline_schemas:
                    inline_schemas[item.name] = hit

    records: list[dict[str, Any]] = []
    for rec in callables:
        name = rec["name"]
        schema_id = (
            schema_constants.get(name)
            or inline_schemas.get(name)
        )
        ts_rec = tool_schemas.get(name, {})
        description = ts_rec.get("description", "") or rec["docstring_first_line"]
        records.append({
            "name": name,
            "schema": schema_id,
            "description": description,
            "input_fields": ts_rec.get("input_fields", []),
            "required_fields": ts_rec.get("required_fields", []),
            "output_fields": rec["output_fields"],
            "lineno": rec["lineno"],
            "registered_in_tool_schemas": name in tool_schemas,
        })
    records.sort(key=lambda r: r["name"])
    return records


def render_human(records: list[dict[str, Any]], server_path: Path) -> str:
    lines: list[str] = []
    lines.append("vault_* MCP callable index")
    lines.append(f"  Source:    {server_path}")
    lines.append(f"  Callables: {len(records)}")
    registered = sum(1 for r in records if r["registered_in_tool_schemas"])
    lines.append(f"  Registered in TOOL_SCHEMAS: {registered}/{len(records)}")
    lines.append("")
    for rec in records:
        lines.append(f"=== {rec['name']}  (vault-mcp-server.py:{rec['lineno']})")
        schema = rec["schema"] or "(no schema id detected)"
        lines.append(f"    schema: {schema}")
        desc = rec["description"] or "(no description)"
        lines.append(f"    desc:   {desc}")
        if rec["input_fields"]:
            lines.append(f"    inputs: {', '.join(rec['input_fields'])}")
        else:
            lines.append("    inputs: (none / not in tool_schemas)")
        if rec["required_fields"]:
            lines.append(f"    required: {', '.join(rec['required_fields'])}")
        if rec["output_fields"]:
            lines.append(f"    outputs: {', '.join(rec['output_fields'])}")
        else:
            lines.append("    outputs: (no literal return dict detected)")
        if not rec["registered_in_tool_schemas"]:
            lines.append("    note:   not registered in TOOL_SCHEMAS (internal / helper)")
        lines.append("")
    lines.append(
        "Tip: schema id (when present) is authoritative. output_fields is a"
        " best-effort hint extracted from literal return dicts."
    )
    return "\n".join(lines).rstrip() + "\n"


def render_json(records: list[dict[str, Any]], server_path: Path) -> str:
    envelope = {
        "schema": "auditooor.vault_mcp_help.v1",
        "source": str(server_path),
        "callable_count": len(records),
        "registered_count": sum(1 for r in records if r["registered_in_tool_schemas"]),
        "callables": records,
    }
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--server",
        type=Path,
        default=DEFAULT_SERVER,
        help="Path to vault-mcp-server.py to scan (default: repo tools/vault-mcp-server.py).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine envelope (auditooor.vault_mcp_help.v1).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write output to this path instead of stdout.",
    )
    args = parser.parse_args(argv)

    records = index_callables(args.server)
    if args.json:
        text = render_json(records, args.server)
    else:
        text = render_human(records, args.server)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
