#!/usr/bin/env python3
"""js-dataflow.py - the JS/Oscript arm of the cross-language def-use slicer.

Phase-1 JavaScript + Obyte-Oscript arm. It emits the SAME frozen DefUsePath v1
schema (tools/dataflow_schema.py) as the Solidity / Rust / Go / ZK arms and MERGES
its rows into the shared polyglot sidecar <ws>/.auditooor/dataflow_paths.jsonl via
dataflow_schema.merge_write, so it accumulates alongside the other languages'
rows instead of truncating them.

Two sub-arms, each language-scoped (independent merge_write purge):

  1. JavaScript (language="javascript"):
       A node+acorn AST def-use slicer. For every function it tracks a taint set
       seeded with the function PARAMETERS (attacker/caller-controlled entry
       points), propagates through intra-procedural assignments (VariableDeclarator
       / AssignmentExpression), and emits a path when a tainted value reaches a
       value-moving / balance-mutating SINK. Sinks for Obyte ocore:
         composeAndSaveJoint / composeJoint / composePaymentJoint  (joint compose)
         addTransaction / saveTransaction                          (ledger write)
         sendPayment / sendMultiPayment / sendAssetPayment / sendAllBTC (payment)
         outputs.push / arrOutputs.push                            (payment output)
         assocBalances[..]=.. / balances[..]=..                    (balance write)
       Guard nodes = the enclosing if-statement tests that dominate the sink; a
       dominated sink is NOT unguarded (schema new_path derives unguarded from
       guard_nodes). confidence="syntactic" (AST def-use, not full SSA).

  2. Oscript AAs (language="oscript"):
       Obyte autonomous-agent scripts are a formula DSL, not JS - acorn cannot
       parse them. Instead we REUSE the AA value-movers already enumerated into
       <ws>/.auditooor/inscope_units.jsonl (lang=="oscript", with value_movers /
       state_writes populated by the Oscript enumerator). Each such unit becomes a
       path: source = the trigger entry-point (trigger.data / trigger.output, the
       attacker-controlled AA input), sink = the enumerated value-mover / state
       write, guard = the case condition (`label`) when present.

R80 FAIL-LOUD / degrade contract (rule 3):
  - JS present but node or acorn unavailable, or every file fails to parse ->
    a single language="javascript" degrade row (degraded=True,
    engine="unsupported-or-compile-fail-degrade") so a 0 never reads as clean.
  - Oscript files present but 0 mover-bearing units enumerated -> a
    language="oscript" degrade/blind row.
  - A workspace with NO in-scope .js and NO .oscript is a clean no-op.

Usage:
  python3 tools/js-dataflow.py --workspace <ws> [--target <path>] [--json]
                               [--max-hops N] [--no-merge]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import dataflow_schema as dfs  # shared frozen schema  # noqa: E402

# path parts that mark a file as OUT-OF-SCOPE for the JS/Oscript arm
_EXCLUDE_PARTS = frozenset({
    "node_modules", "vendor", "bower_components", ".git",
    "dist", "build", "out", "coverage", ".auditooor",
})
# in-scope test dirs are excluded from the SLICE (they are not protocol code) but
# their presence never gates the arm; kept separate from _EXCLUDE_PARTS so the
# has-js router predicate does not depend on them.
_TEST_PARTS = frozenset({"test", "tests", "__tests__", "spec"})

_DEFAULT_MAX_HOPS = 64


# --------------------------------------------------------------------------- #
# node + acorn discovery
# --------------------------------------------------------------------------- #
def _find_node() -> Optional[str]:
    return shutil.which("node")


def _find_acorn(ws: Path) -> Optional[str]:
    """Locate an acorn package dir. Search order: NODE_PATH entries, then the
    workspace's own node_modules trees (AAs vendor acorn as an eslint dep), then a
    global npm root. Returns the acorn package DIRECTORY (node resolves its
    package.json main) or None."""
    cands: List[Path] = []
    for np in (os.environ.get("NODE_PATH") or "").split(os.pathsep):
        if np.strip():
            cands.append(Path(np.strip()) / "acorn")
    # workspace-vendored acorn (first match wins); glob is lazy so this returns
    # promptly on the first hit.
    for p in ws.glob("**/node_modules/acorn/package.json"):
        cands.append(p.parent)
        break
    # global npm root
    try:
        groot = subprocess.run(["npm", "root", "-g"], capture_output=True,
                               text=True, timeout=15)
        if groot.returncode == 0 and groot.stdout.strip():
            cands.append(Path(groot.stdout.strip()) / "acorn")
    except Exception:
        pass
    for c in cands:
        try:
            if (c / "package.json").is_file():
                return str(c)
        except OSError:
            continue
    return None


# The node AST slicer, written to a temp file and invoked once per JS file. It
# prints a single JSON object {functions:[...]} to stdout (or {error:...}).
_NODE_SLICER = r"""
'use strict';
const acorn = require(process.env.ACORN_DIR);
const fs = require('fs');
const file = process.argv[2];
let src;
try { src = fs.readFileSync(file, 'utf8'); }
catch (e) { process.stdout.write(JSON.stringify({error: 'read: ' + String(e)})); return; }

// strip a shebang so acorn 7 (no allowHashBang) still parses CLI scripts
if (src.charCodeAt(0) === 0x23 && src.charCodeAt(1) === 0x21) {
  const nl = src.indexOf('\n');
  src = nl >= 0 ? src.slice(nl) : '';
}

let ast = null;
for (const ev of [2022, 2020, 2019, 2018]) {
  try {
    ast = acorn.parse(src, {ecmaVersion: ev, locations: true,
                            allowReturnOutsideFunction: true, sourceType: 'script'});
    break;
  } catch (e) { /* try older ecmaVersion */ }
}
if (!ast) {
  // last resort: module source type
  for (const ev of [2022, 2020]) {
    try { ast = acorn.parse(src, {ecmaVersion: ev, locations: true, sourceType: 'module'}); break; }
    catch (e) {}
  }
}
if (!ast) { process.stdout.write(JSON.stringify({error: 'parse-failed'})); return; }

// value-moving / balance-mutating sinks (callee name -> sink kind)
const CALL_SINKS = {
  composeAndSaveJoint: 'value-move', composeJoint: 'value-move',
  composePaymentJoint: 'value-move', composePaymentAndTextJoint: 'value-move',
  addTransaction: 'state-write', saveTransaction: 'state-write',
  sendPayment: 'value-move', sendMultiPayment: 'value-move',
  sendAssetPayment: 'value-move', sendAllBTC: 'value-move',
  sendPaymentFromWallet: 'value-move', issueChangeAddressAndSendPayment: 'value-move',
};
// member-call sinks: object identifier matched loosely by name suffix, property 'push'
const PUSH_OBJ_HINT = /output|payment|msg|message/i;
// member-assignment (balance) sink objects
const BALANCE_OBJ = /balance|assocbalance/i;

function idName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && !node.computed && node.property &&
      node.property.type === 'Identifier') return node.property.name;
  return null;
}
function line(node) { return node && node.loc ? node.loc.start.line : null; }

// collect identifiers bound by a param pattern (Identifier/Object/Array/Assignment/Rest)
function collectParamNames(pat, out) {
  if (!pat) return;
  switch (pat.type) {
    case 'Identifier': out.push(pat.name); break;
    case 'AssignmentPattern': collectParamNames(pat.left, out); break;
    case 'RestElement': collectParamNames(pat.argument, out); break;
    case 'ArrayPattern': (pat.elements || []).forEach(e => collectParamNames(e, out)); break;
    case 'ObjectPattern': (pat.properties || []).forEach(p =>
        collectParamNames(p.value || p.argument, out)); break;
    default: break;
  }
}

// generic child iterator over an ESTree node
function children(node) {
  const kids = [];
  for (const k in node) {
    if (k === 'loc' || k === 'start' || k === 'end' || k === 'type') continue;
    const v = node[k];
    if (v && typeof v.type === 'string') kids.push(v);
    else if (Array.isArray(v)) for (const e of v) if (e && typeof e.type === 'string') kids.push(e);
  }
  return kids;
}

// find the first tainted identifier referenced anywhere inside an expression;
// returns that identifier's variable NAME (leaf) or null
function taintedLeaf(node, taint) {
  if (!node || typeof node.type !== 'string') return null;
  if (node.type === 'Identifier' && taint.has(node.name)) return node.name;
  if (node.type === 'MemberExpression') {
    // object taint flows to the member access
    const o = taintedLeaf(node.object, taint);
    if (o) return o;
    if (node.computed) { const p = taintedLeaf(node.property, taint); if (p) return p; }
    return null;
  }
  for (const c of children(node)) {
    const r = taintedLeaf(c, taint);
    if (r) return r;
  }
  return null;
}

const results = [];

function analyzeFunction(fnNode, fnName) {
  const params = [];
  (fnNode.params || []).forEach(p => collectParamNames(p, params));
  if (params.length === 0) return;              // no entry-point taint source
  const taint = new Set(params);
  const parent = new Map();                     // var -> immediate source var
  const defLine = new Map();                    // var -> assignment line
  const root = new Map();                       // var -> originating param
  params.forEach(p => root.set(p, p));
  const sinks = [];

  // in-order DFS over the function body, carrying the dominating if-test stack
  function walk(node, guardStack) {
    if (!node || typeof node.type !== 'string') return;
    switch (node.type) {
      case 'FunctionDeclaration':
      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
        if (node !== fnNode) return;            // nested fn analyzed on its own
        break;
      case 'IfStatement': {
        walk(node.test, guardStack);
        const g = {line: line(node.test), expr: 'if'};
        walk(node.consequent, guardStack.concat([g]));
        if (node.alternate) walk(node.alternate, guardStack.concat([g]));
        return;
      }
      case 'VariableDeclarator': {
        if (node.init) {
          walk(node.init, guardStack);
          const leaf = taintedLeaf(node.init, taint);
          if (leaf && node.id && node.id.type === 'Identifier') {
            const lhs = node.id.name;
            taint.add(lhs); parent.set(lhs, leaf);
            defLine.set(lhs, line(node)); root.set(lhs, root.get(leaf) || leaf);
          }
        }
        return;
      }
      case 'AssignmentExpression': {
        walk(node.right, guardStack);
        const leaf = taintedLeaf(node.right, taint);
        // member-write balance sink: assocBalances[x] = tainted
        if (node.left && node.left.type === 'MemberExpression') {
          const obj = idName(node.left.object) || '';
          if (leaf && BALANCE_OBJ.test(obj)) {
            sinks.push({kind: 'state-write', callee: obj, arg_pos: 0,
                        line: line(node), leaf: leaf, guards: guardStack.slice()});
          }
        } else if (leaf && node.left && node.left.type === 'Identifier') {
          const lhs = node.left.name;
          taint.add(lhs); parent.set(lhs, leaf);
          defLine.set(lhs, line(node)); root.set(lhs, root.get(leaf) || leaf);
        }
        walk(node.left, guardStack);
        return;
      }
      case 'CallExpression': {
        const cn = idName(node.callee);
        // own-property lookup only: a bare `CALL_SINKS[cn]` would resolve inherited
        // Object.prototype members (hasOwnProperty / toString / constructor / ...)
        // to truthy-but-non-sink values, emitting bogus null-kind sink rows for any
        // tainted `x.hasOwnProperty(...)` call.
        let kind = (cn && Object.prototype.hasOwnProperty.call(CALL_SINKS, cn))
                   ? CALL_SINKS[cn] : null;
        // member .push onto an outputs/messages-like array
        if (!kind && node.callee && node.callee.type === 'MemberExpression' &&
            idName(node.callee) === 'push') {
          const obj = idName(node.callee.object) || '';
          if (PUSH_OBJ_HINT.test(obj)) kind = 'value-move';
        }
        if (kind) {
          const args = node.arguments || [];
          for (let i = 0; i < args.length; i++) {
            const leaf = taintedLeaf(args[i], taint);
            if (leaf) {
              sinks.push({kind: kind, callee: cn || (idName(node.callee) + '@' +
                          (idName(node.callee.object) || '?')), arg_pos: i,
                          line: line(node), leaf: leaf, guards: guardStack.slice()});
              break;                            // one path per sink call
            }
          }
        }
        // still descend to catch nested sinks in arguments
        (node.arguments || []).forEach(a => walk(a, guardStack));
        walk(node.callee, guardStack);
        return;
      }
      default: break;
    }
    for (const c of children(node)) walk(c, guardStack);
  }

  walk(fnNode.body, []);

  if (sinks.length === 0) return;
  // reconstruct hop chain param -> leaf for each sink
  for (const s of sinks) {
    const hops = [];
    let cur = s.leaf;
    let guardHops = 0;
    while (parent.has(cur)) {
      const p = parent.get(cur);
      hops.push({from_var: p, to_var: cur, line: defLine.get(cur) || null});
      cur = p;
      if (hops.length > 128) break;
    }
    hops.reverse();
    const srcParam = root.get(s.leaf) || s.leaf;
    results.push({
      fn: fnName, source_param: srcParam, source_line: line(fnNode),
      sink_kind: s.kind, callee: s.callee, arg_pos: s.arg_pos, sink_line: s.line,
      guards: s.guards, hops: hops,
    });
  }
}

function fnNameOf(node, keyHint) {
  if (node.id && node.id.name) return node.id.name;
  return keyHint || '<anonymous>';
}

// top-level walk to find every function definition, then analyze each
function findFunctions(node, keyHint) {
  if (!node || typeof node.type !== 'string') return;
  if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression') {
    analyzeFunction(node, fnNameOf(node, keyHint));
  }
  // capture `var f = function(){}` / `x.y = function(){}` name hints
  if (node.type === 'VariableDeclarator' && node.id && node.id.name &&
      node.init && /Function/.test(node.init.type || '')) {
    // analyzed above via generic recursion; give it the var name
  }
  for (const k in node) {
    if (k === 'loc') continue;
    const v = node[k];
    let hint = keyHint;
    if (node.type === 'VariableDeclarator' && node.id) hint = node.id.name;
    if (node.type === 'Property' && node.key) hint = idName(node.key) || keyHint;
    if (node.type === 'AssignmentExpression' && node.left) hint = idName(node.left) || keyHint;
    if (v && typeof v.type === 'string') findFunctions(v, hint);
    else if (Array.isArray(v)) for (const e of v) if (e && typeof e.type === 'string') findFunctions(e, hint);
  }
}

findFunctions(ast, null);
process.stdout.write(JSON.stringify({functions: results}));
"""


def _write_slicer() -> str:
    fd, path = tempfile.mkstemp(prefix="js-dataflow-slicer-", suffix=".js")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(_NODE_SLICER)
    return path


# --------------------------------------------------------------------------- #
# in-scope file enumeration
# --------------------------------------------------------------------------- #
def _rel_parts(ws: Path, p: Path) -> Tuple[str, ...]:
    try:
        return p.relative_to(ws).parts
    except ValueError:
        return p.parts


def _is_excluded(ws: Path, p: Path, *, drop_tests: bool) -> bool:
    parts = set(_rel_parts(ws, p))
    if parts & _EXCLUDE_PARTS:
        return True
    if drop_tests and (parts & _TEST_PARTS):
        return True
    return False


def _inscope_js_files(ws: Path, target: Optional[str]) -> List[Path]:
    """In-scope .js files. The enumerator's inscope_units.jsonl (lang=='js') is
    AUTHORITATIVE: when that file exists we use ONLY its js rows - even if it lists
    zero, meaning JS is genuinely out of program scope (a Solidity-only workspace
    still ships hardhat.config.js etc., which must NOT be sliced). The glob is a
    fallback ONLY when inscope_units.jsonl is absent (a bare, un-enumerated ws).
    Always drop node_modules/vendor/test."""
    root = Path(target).expanduser().resolve() if target else ws
    files: List[Path] = []
    seen: set = set()
    units = ws / ".auditooor" / "inscope_units.jsonl"
    if units.is_file():
        try:
            with open(units, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if rec.get("lang") not in ("js", "javascript"):
                        continue
                    f = rec.get("file")
                    if not f:
                        continue
                    fp = (ws / f).resolve()
                    if fp in seen or not fp.is_file():
                        continue
                    if _is_excluded(ws, fp, drop_tests=True):
                        continue
                    if target and not str(fp).startswith(str(root)):
                        continue
                    seen.add(fp)
                    files.append(fp)
        except OSError:
            pass
        # inscope_units.jsonl is authoritative: return its js set (possibly empty)
        # WITHOUT falling back to a glob that would pull in out-of-scope scripts.
        return files
    # fallback glob (only reached when inscope_units.jsonl is absent)
    for fp in root.glob("**/*.js"):
        if fp in seen or not fp.is_file():
            continue
        if _is_excluded(ws, fp, drop_tests=True):
            continue
        seen.add(fp)
        files.append(fp)
    return files


def _has_oscript(ws: Path) -> bool:
    for p in ws.glob("**/*.oscript"):
        if not _is_excluded(ws, p, drop_tests=False):
            return True
    return False


# --------------------------------------------------------------------------- #
# JS sub-arm
# --------------------------------------------------------------------------- #
def _run_js_file(node_bin: str, slicer: str, acorn_dir: str, fp: Path,
                 timeout: int) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    env = dict(os.environ)
    env["ACORN_DIR"] = acorn_dir
    try:
        proc = subprocess.run([node_bin, slicer, str(fp)], capture_output=True,
                              text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except Exception as e:  # pragma: no cover - defensive
        return [], f"{type(e).__name__}: {e}"
    out = (proc.stdout or "").strip()
    if not out:
        return [], (proc.stderr or "")[-200:] or "empty-output"
    try:
        obj = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return [], "unparseable-json"
    if isinstance(obj, dict) and obj.get("error"):
        return [], str(obj.get("error"))
    return list((obj or {}).get("functions") or []), None


def _js_arm(ws: Path, target: Optional[str], max_hops: int,
            timeout: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return (records, report). records are language=='javascript' schema rows."""
    report: Dict[str, Any] = {"language": "javascript"}
    files = _inscope_js_files(ws, target)
    report["files_scanned"] = len(files)
    if not files:
        report["status"] = "no-inscope-js"
        return [], report

    node_bin = _find_node()
    if not node_bin:
        report["status"] = "degrade"
        report["degrade_reason"] = "node not found on PATH"
        return [dfs.degrade_record("javascript",
                                   "node runtime not found - JS arm blind")], report
    acorn_dir = _find_acorn(ws)
    if not acorn_dir:
        report["status"] = "degrade"
        report["degrade_reason"] = "acorn parser not found (NODE_PATH / ws node_modules / npm -g)"
        return [dfs.degrade_record("javascript",
                                   "acorn parser not found - JS arm blind")], report

    slicer = _write_slicer()
    records: List[Dict[str, Any]] = []
    parse_fail = 0
    per_file_err: Dict[str, str] = {}
    try:
        for fp in files:
            raws, err = _run_js_file(node_bin, slicer, acorn_dir, fp, timeout)
            if err:
                parse_fail += 1
                if len(per_file_err) < 8:
                    per_file_err[str(fp)] = err
                continue
            rel = str(fp)
            for r in raws:
                hops_in = r.get("hops") or []
                hops: List[Dict[str, Any]] = []
                for h in hops_in[:max_hops]:
                    hops.append({
                        "from_var": h.get("from_var"), "to_var": h.get("to_var"),
                        "fn": r.get("fn"), "via": "intra", "file": rel,
                        "line": h.get("line"), "ir": None, "guarded": False,
                    })
                guard_nodes = []
                for g in (r.get("guards") or []):
                    guard_nodes.append({"file": rel, "line": g.get("line"),
                                        "expr": g.get("expr") or "if"})
                truncated = len(hops_in) > max_hops
                src = {"kind": "param", "fn": r.get("fn"),
                       "var": r.get("source_param"), "file": rel,
                       "line": r.get("source_line")}
                snk = {"kind": r.get("sink_kind"), "callee": r.get("callee"),
                       "arg_pos": r.get("arg_pos"), "fn": r.get("fn"),
                       "file": rel, "line": r.get("sink_line")}
                pid = "js:%s:%s:%s->%s@%s" % (
                    Path(rel).name, r.get("fn"), r.get("source_param"),
                    r.get("callee"), r.get("sink_line"))
                rec = dfs.new_path(
                    path_id=pid, language="javascript", direction="forward",
                    engine="acorn-ast-defuse", source=src, sink=snk, hops=hops,
                    guard_nodes=guard_nodes, source_unit_ids=[rel],
                    sink_unit_ids=[rel], confidence="syntactic", degraded=False)
                if truncated:
                    rec["dataflow_truncated"] = True
                records.append(rec)
    finally:
        try:
            os.unlink(slicer)
        except OSError:
            pass

    report["parse_failures"] = parse_fail
    if per_file_err:
        report["parse_errors_sample"] = per_file_err
    # FAIL-LOUD: js files present but produced zero real paths AND every file
    # failed to parse -> degrade so 0 does not read as clean.
    if not records and parse_fail >= len(files) and files:
        report["status"] = "degrade"
        report["degrade_reason"] = "every in-scope JS file failed to parse"
        return [dfs.degrade_record("javascript",
                                   "all JS files failed to parse - arm blind")], report
    report["status"] = "ok"
    report["records"] = len(records)
    return records, report


# --------------------------------------------------------------------------- #
# Oscript sub-arm (reuse enumerated AA value-movers)
# --------------------------------------------------------------------------- #
def _oscript_arm(ws: Path, target: Optional[str],
                 max_hops: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    report: Dict[str, Any] = {"language": "oscript"}
    present = _has_oscript(ws)
    report["oscript_files_present"] = present
    units = ws / ".auditooor" / "inscope_units.jsonl"
    root = Path(target).expanduser().resolve() if target else ws
    records: List[Dict[str, Any]] = []
    rows = 0
    if units.is_file():
        try:
            with open(units, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if rec.get("lang") != "oscript":
                        continue
                    movers = rec.get("value_movers") or []
                    writes = rec.get("state_writes") or []
                    if not movers and not writes:
                        continue
                    f = rec.get("file")
                    if not f:
                        continue
                    fp = (ws / f).resolve()
                    if target and not str(fp).startswith(str(root)):
                        continue
                    rel = str(fp)
                    rows += 1
                    fn = rec.get("fn") or rec.get("function") or "<case>"
                    fl = rec.get("file_line") or f
                    ln_no = None
                    if isinstance(fl, str) and ":" in fl:
                        try:
                            ln_no = int(fl.rsplit(":", 1)[1])
                        except ValueError:
                            ln_no = None
                    label = rec.get("label")
                    guard_nodes = []
                    if label:
                        guard_nodes.append({"file": rel, "line": ln_no,
                                            "expr": str(label)[:200]})
                    # one path per enumerated sink (state write preferred, else mover)
                    sink_specs: List[Tuple[str, str]] = []
                    for w in writes:
                        sink_specs.append(("state-write", str(w)))
                    for m in movers:
                        sink_specs.append(("value-move", str(m)))
                    for i, (skind, callee) in enumerate(sink_specs):
                        src = {"kind": "oscript-trigger", "fn": fn,
                               "var": "trigger.data", "file": rel, "line": ln_no}
                        snk = {"kind": skind, "callee": callee, "arg_pos": None,
                               "fn": fn, "file": rel, "line": ln_no}
                        pid = "oscript:%s:%s:%s#%d" % (Path(rel).name, fn, callee, i)
                        rrec = dfs.new_path(
                            path_id=pid, language="oscript", direction="forward",
                            engine="oscript-enumerator-reuse", source=src, sink=snk,
                            hops=[], guard_nodes=guard_nodes,
                            source_unit_ids=[rel], sink_unit_ids=[rel],
                            confidence="syntactic", degraded=False)
                        records.append(rrec)
        except OSError:
            pass
    report["units_with_movers"] = rows
    report["records"] = len(records)
    # FAIL-LOUD: oscript files present but 0 rows emitted -> blind marker
    if present and not records:
        report["status"] = "degrade"
        report["degrade_reason"] = (
            "oscript files present but inscope_units.jsonl carried no "
            "value_movers/state_writes (enumerator not run or empty)")
        return [dfs.degrade_record("oscript",
                                   "oscript present but no enumerated movers - arm blind")], report
    report["status"] = "ok" if records else "no-oscript"
    return records, report


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def _merge(out_path: Path, records: List[Dict[str, Any]], language: str,
           merge: bool) -> int:
    if merge:
        return dfs.merge_write(str(out_path), records, language)
    # --no-merge: truncating append per language (legacy single-arm)
    return dfs.write_jsonl(str(out_path), records)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="JS/Oscript def-use slice arm (DefUsePath v1 into shared sidecar).")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--target", help="restrict to a subtree (abs path or ws-relative)")
    ap.add_argument("--max-hops", type=int, default=_DEFAULT_MAX_HOPS,
                    help="per-path intra-procedural hop ceiling")
    ap.add_argument("--per-file-timeout", type=int, default=60,
                    help="node parse timeout per JS file (s)")
    ap.add_argument("--no-merge", action="store_true",
                    help="truncate the sidecar instead of language-scoped merge "
                         "(legacy; only sane for a single-arm run)")
    ap.add_argument("--skip-oscript", action="store_true",
                    help="run only the JavaScript AST arm; the cross-language router "
                         "uses the parser-backed Oscript arm separately")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[js-dataflow] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    max_hops = args.max_hops if (args.max_hops and args.max_hops > 0) else _DEFAULT_MAX_HOPS
    merge = not args.no_merge
    out_path = ws / ".auditooor" / "dataflow_paths.jsonl"

    js_records, js_report = _js_arm(ws, args.target, max_hops, args.per_file_timeout)
    if args.skip_oscript:
        os_records, os_report = [], {"language": "oscript", "status": "skipped"}
    else:
        os_records, os_report = _oscript_arm(ws, args.target, max_hops)

    # language-scoped merges (independent purge per language)
    js_written = _merge(out_path, js_records, "javascript", merge)
    # after a --no-merge js write, the oscript merge must NOT truncate the js rows;
    # force merge semantics for the second language even under --no-merge so both
    # sub-arms coexist (a single arm writing two languages).
    os_written = _merge(out_path, os_records, "oscript", True if not merge else merge)

    total = js_written + os_written
    result = {
        "status": "ok",
        "language": "javascript+oscript",
        "workspace": str(ws),
        "out": str(out_path),
        "js": js_report,
        "oscript": os_report,
        "records_written": {"javascript": js_written, "oscript": os_written},
        "total_records": total,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"OK (js/oscript arm): {total} records -> {out_path}")
        print(f"  javascript={js_written} ({js_report.get('status')}) "
              f"oscript={os_written} ({os_report.get('status')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
