#!/usr/bin/env python3
"""Emit parser-backed Oscript AA trigger-to-message flow records.

This adapter invokes the workspace's declared ``ocore`` parser and Nearley
grammar. It never treats a regex hit as a parsed Oscript formula: absent Node,
ocore, or parser dependencies produces a degraded record instead.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dataflow_schema as dfs

_NODE = r"""
const fs=require('fs'), nearley=require('nearley');
const root=process.argv[1], file=process.argv[2];
const parse=require(root+'/formula/parse_ojson'), grammar=require(root+'/formula/grammars/oscript');
function ast(v){ if(typeof v!=='string'||!v.startsWith('{')||!v.endsWith('}')) return null;
 let p=new nearley.Parser(nearley.Grammar.fromCompiled(grammar)); p.feed(v.slice(1,-1));
 if(p.results.length!==1) throw new Error('formula_ambiguous'); return p.results[0]; }
function walk(v, out, guard){ if(Array.isArray(v)) return v.forEach(x=>walk(x,out,guard));
 if(!v||typeof v!=='object') return; let next=typeof v.if==='string'?v.if:guard;
 if(typeof v.app==='string') out.push({app:v.app, guard:next, payload:v.payload||{}});
 Object.keys(v).forEach(k=>walk(v[k],out,next)); }
parse.parse(fs.readFileSync(file,'utf8'),(e,aa)=>{ if(e) throw new Error(e); let messages=[]; walk(aa[1],messages,null);
 for(const m of messages){m.guard_ast=ast(m.guard); m.payload_ast=JSON.parse(JSON.stringify(m.payload),(_,v)=>typeof v==='string'&&v.startsWith('{')&&v.endsWith('}')?{formula_ast:ast(v)}:v);}
 console.log(JSON.stringify({messages})); });
"""


def _ocore_root(workspace: Path, explicit: str | None) -> Path | None:
    candidates = [Path(explicit)] if explicit else [workspace / "src" / "ocore", workspace / "ocore"]
    for root in candidates:
        if (root / "formula" / "parse_ojson.js").is_file() and (root / "node_modules").is_dir():
            return root
    return None


def _contains_trigger(node: Any) -> bool:
    if isinstance(node, str):
        return node.startswith("trigger.")
    if isinstance(node, list):
        return any(_contains_trigger(item) for item in node)
    if isinstance(node, dict):
        return any(_contains_trigger(value) for value in node.values())
    return False


def _payload_trigger(node: Any) -> bool:
    if isinstance(node, dict):
        if "formula_ast" in node:
            return _contains_trigger(node["formula_ast"])
        return any(_payload_trigger(value) for value in node.values())
    if isinstance(node, list):
        return any(_payload_trigger(value) for value in node)
    return False


def run_parser(node: str, ocore: Path, source: Path) -> dict[str, Any]:
    proc = subprocess.run([node, "-e", _NODE, str(ocore), str(source)], text=True,
                          capture_output=True, timeout=30, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "ocore_parser_failed")
    data = json.loads(proc.stdout)
    if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
        raise RuntimeError("ocore_parser_output_invalid")
    return data


def extract(workspace: Path, ocore: Path | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    node = shutil.which("node")
    root = _ocore_root(workspace, str(ocore) if ocore else None)
    files = sorted(path for suffix in ("*.oscript", "*.aa") for path in workspace.rglob(suffix)
                   if ".auditooor" not in path.parts and "node_modules" not in path.parts)
    report: dict[str, Any] = {"backend": "ocore-nearley-ast", "files": len(files), "parsed": 0, "errors": []}
    if not files:
        return [], report
    if not node or not root:
        return [dfs.degrade_record("oscript", "ocore parser dependency unavailable")], {**report, "degraded": True}
    rows: list[dict[str, Any]] = []
    for source in files:
        try:
            parsed = run_parser(node, root, source)
            report["parsed"] += 1
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            report["errors"].append(f"{source}:{exc}")
            continue
        rel = str(source.relative_to(workspace))
        for index, message in enumerate(parsed["messages"]):
            payload = message.get("payload_ast", {})
            if not _payload_trigger(payload):
                continue
            guard_ast = message.get("guard_ast")
            guard = [{"file": rel, "line": None, "expr": "ocore AST guard"}] if guard_ast else []
            rows.append(dfs.new_path(
                path_id=f"oscript-ast:{rel}:{message.get('app')}:{index}", language="oscript",
                direction="forward", engine="ocore-nearley-ast",
                source={"kind": "oscript-trigger", "fn": f"message_{index}", "var": "trigger", "file": rel, "line": None},
                sink={"kind": "aa-message", "callee": str(message.get("app")), "arg_pos": None, "fn": f"message_{index}", "file": rel, "line": None},
                hops=[], guard_nodes=guard, source_unit_ids=[rel], sink_unit_ids=[rel], confidence="syntactic"))
    if report["errors"]:
        report["degraded"] = True
    return rows or ([dfs.degrade_record("oscript", "ocore parsed no trigger-tainted message payload")] if report["degraded"] else []), report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--ocore-root")
    ap.add_argument("--out")
    ap.add_argument("--no-merge", action="store_true",
                    help="truncate the default shared sidecar instead of language-scoped merge")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    workspace = Path(args.workspace).resolve()
    rows, report = extract(workspace, Path(args.ocore_root).resolve() if args.ocore_root else None)
    if args.out:
        written = dfs.write_jsonl(str(Path(args.out)), rows)
    else:
        out = workspace / ".auditooor" / "dataflow_paths.jsonl"
        written = (dfs.write_jsonl(str(out), rows) if args.no_merge
                   else dfs.merge_write(str(out), rows, "oscript"))
    result = {"status": "degraded" if report.get("degraded") else "ok",
              "backend": report["backend"], "degraded": bool(report.get("degraded")),
              "rows": len(rows), "records_written": written, "report": report}
    if args.json:
        print(json.dumps(result, indent=2))
    return 1 if report.get("degraded") else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
