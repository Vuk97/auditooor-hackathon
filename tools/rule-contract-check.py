#!/usr/bin/env python3
"""rule-contract-check.py -- Rule/Check self-test contracts (P17).

A "contract" binds a standalone check tool to executable fixtures so that a
future edit to the check tool (or to a rule it enforces) cannot silently
weaken it without a red signal. Each contract declares, for one check tool:

  * >=1 MUST-CATCH fixture -- a draft/workspace the tool MUST FAIL (nonzero
    exit). If a must-catch fixture starts PASSing, the tool has been weakened.
  * >=1 MUST-PASS fixture -- a clean draft/workspace the tool MUST PASS
    (exit 0). If a must-pass fixture starts FAILing, the tool has a false red.
  * a rationale (why the binding exists) and, optionally, a mutation-proof
    predicate line so the fixture's DISCRIMINATING POWER is itself proven.

MUTATION-PROOF (anti coverage-theater)
--------------------------------------
A must-catch fixture that keeps FAILing even after the tool's decision
predicate is mutated proves nothing -- it might fail for an unrelated reason
(coverage-theater, memory: feedback_step4b_equivalent_mutant_selection). To
guard against that, a contract may name ``mutation_predicate`` (a 1-based line
number in the check tool holding the pass/fail predicate). This check then:

  1. Reuses tools/mutation-engine.py -- the canonical mutation-strength oracle
     (R80/R81) -- to generate behavior-changing mutants of that predicate
     line. The engine is brace-body oriented, so the predicate line is wrapped
     in a synthetic ``contract C { function f() public { <line> } }`` shell,
     mutated with the relational/boundary/arithmetic/boolean operator classes,
     and the mutated line is spliced back into a temp copy of the real tool.
  2. Runs each spliced mutant against the must-catch fixture.
  3. A mutant that flips the must-catch fixture from FAIL to PASS = the fixture
     genuinely discriminates on that predicate -> the contract has real
     killing power. If NO generated mutant flips it, the contract is flagged
     coverage-theater (advisory) -- unless the contract explicitly records the
     line as an equivalent-mutant region via ``mutation_equivalent: true``.

We do NOT fork or alter mutation-engine's public API/CLI -- we import
``generate_mutants`` (line 446) exactly as its four existing callers do.

ADVISORY-FIRST / OPT-IN STRICT
------------------------------
By default this tool is ADVISORY: it reports contract violations to stdout and
ALWAYS exits 0 (a violation prints ``[rule-contract] WARN ...``). This is the
byte-for-byte default so wiring it into the git pre-commit chain can never
brick a rule-editing commit. Set the opt-in env flag

    AUDITOOOR_RULE_CONTRACT_STRICT=1

to make a contract violation exit nonzero (enforcing mode -- an explicitly
approved graduation, never the default).

Usage
-----
    python3 tools/rule-contract-check.py                  # replay ALL contracts
    python3 tools/rule-contract-check.py --tool T         # only contracts for T
    python3 tools/rule-contract-check.py --changed A B     # only contracts whose
                                                           # tool is in {A,B}
    python3 tools/rule-contract-check.py --json            # machine-readable
    python3 tools/rule-contract-check.py --no-mutation     # skip mutation-proof
    python3 tools/rule-contract-check.py --list            # list bound tools

Exit codes
----------
    0  all replayed contracts held (or advisory mode -- always 0 on violation)
    1  a contract was violated AND AUDITOOOR_RULE_CONTRACT_STRICT is set
    2  input / setup error (bad contract yaml, missing tool, no contracts)

This tool emits no corpus record and touches no audit-complete / L37 gate. It
is generic editor-side capability infra, not an audit finding producer.
"""

from __future__ import annotations

import argparse
import importlib.util as _ilu
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = REPO_ROOT / "tools" / "rules" / "contracts"
MUTATION_ENGINE = REPO_ROOT / "tools" / "mutation-engine.py"
STRICT_ENV = "AUDITOOOR_RULE_CONTRACT_STRICT"
SCHEMA = "auditooor.rule_contract_check.v1"

# Mutation operator classes applied to a predicate line. These are all
# behavior-changing at the token level for typical check predicates
# (comparisons, thresholds, boolean joins).
_MUTATION_CLASSES = ["relational", "boundary", "arithmetic", "boolean"]


# ---------------------------------------------------------------------------
# YAML loading (PyYAML if present; else a tiny fallback that covers the subset
# our contract files use so the tool has no hard third-party dependency).
# ---------------------------------------------------------------------------
def _load_yaml(text: str) -> Any:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception:
        return _mini_yaml(text)


def _coerce_scalar(raw: str) -> Any:
    s = raw.strip()
    if s and s[0] in "'\"" and s[-1] == s[0]:
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _mini_yaml(text: str) -> Any:
    """Minimal block-style YAML: nested maps/lists + block scalars ( | ).

    Deliberately small; covers the contract schema. Not a general YAML parser.
    """
    lines = text.splitlines()

    def indent_of(ln: str) -> int:
        return len(ln) - len(ln.lstrip(" "))

    pos = 0

    def parse_block(min_indent: int):
        nonlocal pos
        # Decide list vs map by peeking the first non-blank/comment line.
        while pos < len(lines):
            raw = lines[pos]
            if not raw.strip() or raw.lstrip().startswith("#"):
                pos += 1
                continue
            break
        if pos >= len(lines):
            return None
        first = lines[pos]
        cur_indent = indent_of(first)
        if cur_indent < min_indent:
            return None
        is_list = first.lstrip().startswith("- ")
        return parse_list(cur_indent) if is_list else parse_map(cur_indent)

    def parse_list(indent: int):
        nonlocal pos
        out = []
        while pos < len(lines):
            raw = lines[pos]
            if not raw.strip() or raw.lstrip().startswith("#"):
                pos += 1
                continue
            if indent_of(raw) < indent:
                break
            if indent_of(raw) != indent or not raw.lstrip().startswith("- "):
                break
            body = raw.lstrip()[2:]
            if ":" in body and not body.strip().startswith("#"):
                # inline map on the dash line -> synthesize a map block.
                synth_indent = indent + 2
                lines[pos] = " " * synth_indent + body
                out.append(parse_map(synth_indent))
            else:
                pos += 1
                out.append(_coerce_scalar(body))
        return out

    def parse_map(indent: int):
        nonlocal pos
        out: dict[str, Any] = {}
        while pos < len(lines):
            raw = lines[pos]
            if not raw.strip() or raw.lstrip().startswith("#"):
                pos += 1
                continue
            if indent_of(raw) < indent:
                break
            if indent_of(raw) != indent:
                break
            if raw.lstrip().startswith("- "):
                break
            key, _, rest = raw.lstrip().partition(":")
            key = key.strip()
            # Unquote a quoted mapping key (e.g. "path/to/file": ...) so it maps
            # to the intended path, not a key with literal quote characters.
            if len(key) >= 2 and key[0] in "'\"" and key[-1] == key[0]:
                key = key[1:-1]
            rest = rest.strip()
            pos += 1
            if rest == "|" or rest == "|-" or rest == ">":
                # block scalar
                block_lines = []
                while pos < len(lines):
                    bl = lines[pos]
                    if bl.strip() and indent_of(bl) <= indent:
                        break
                    block_lines.append(bl[indent + 2:] if len(bl) >= indent + 2 else bl.strip())
                    pos += 1
                joiner = " " if rest == ">" else "\n"
                out[key] = joiner.join(block_lines).rstrip()
            elif rest == "":
                child = parse_block(indent + 1)
                out[key] = child
            else:
                out[key] = _coerce_scalar(rest)
        return out

    return parse_block(0)


# ---------------------------------------------------------------------------
# mutation-engine reuse (import generate_mutants; do NOT fork)
# ---------------------------------------------------------------------------
_ME_CACHE: Any = None


def _load_mutation_engine():
    global _ME_CACHE
    if _ME_CACHE is not None:
        return _ME_CACHE
    spec = _ilu.spec_from_file_location("mutation_engine", MUTATION_ENGINE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load mutation-engine at {MUTATION_ENGINE}")
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _ME_CACHE = mod
    return mod


def _predicate_mutants(predicate_line: str) -> list[str]:
    """Return distinct mutated variants of one predicate line.

    Reuses mutation-engine.generate_mutants by wrapping the line in a synthetic
    brace-bodied function (the engine is brace-body oriented). Returns the
    mutated predicate lines only (behavior-changing operator classes).
    """
    me = _load_mutation_engine()
    synthetic = (
        "contract C {\n"
        "  function f() public {\n"
        f"{predicate_line}\n"
        "  }\n"
        "}\n"
    )
    try:
        mutants, _fn, _span = me.generate_mutants(
            synthetic, "solidity", name="f", line_hint=None,
            classes=list(_MUTATION_CLASSES), max_mutants=64,
        )
    except LookupError:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for m in mutants:
        mut = m.get("mutated_line", "")
        if mut and mut != predicate_line and mut not in seen:
            seen.add(mut)
            out.append(mut)
    return out


# ---------------------------------------------------------------------------
# Fixture materialization
# ---------------------------------------------------------------------------
def _materialize_fixture(fixture: dict, workdir: Path) -> Path:
    """Write a fixture to disk under workdir; return the path passed to argv.

    Supported fixture shapes (additive):
      { file: <relpath>, content: <text> }        -> single-file fixture
      { files: { relpath: content, ... } }         -> directory-tree fixture
    Returns the file path (single-file) or the directory root (tree).
    """
    if "files" in fixture and isinstance(fixture["files"], dict):
        root = workdir
        for rel, content in fixture["files"].items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content if content is not None else "", encoding="utf-8")
        return root
    # single-file
    rel = fixture.get("file", "fixture.md")
    p = workdir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(fixture.get("content", "") or "", encoding="utf-8")
    return p


def _build_argv(tool_path: Path, argv_template: list[str], fixture_path: Path,
                workdir: Path) -> list[str]:
    """Expand {fixture}, {fixture_dir}, {tool} placeholders in argv_template."""
    subs = {
        "{fixture}": str(fixture_path),
        "{fixture_dir}": str(workdir),
        "{tool}": str(tool_path),
    }
    out = [sys.executable, str(tool_path)]
    for tok in argv_template:
        for k, v in subs.items():
            tok = tok.replace(k, v)
        out.append(tok)
    return out


def _run_tool(argv: list[str], tool_source: str | None = None) -> int:
    """Run a check tool; if tool_source is given, run a temp copy with it.

    Returns the process exit code.
    """
    if tool_source is None:
        r = subprocess.run(argv, capture_output=True, text=True)
        return r.returncode
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                     dir=tempfile.gettempdir()) as tf:
        tf.write(tool_source)
        tmp = tf.name
    try:
        alt = list(argv)
        alt[1] = tmp  # replace tool path with mutated copy
        r = subprocess.run(alt, capture_output=True, text=True)
        return r.returncode
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Contract evaluation
# ---------------------------------------------------------------------------
def _resolve_tool(tool_rel: str) -> Path:
    p = (REPO_ROOT / tool_rel).resolve()
    return p


def evaluate_contract(contract: dict, do_mutation: bool = True) -> dict:
    """Replay one contract; return a structured result dict."""
    name = contract.get("name") or contract.get("tool") or "<unnamed>"
    tool_rel = contract.get("tool")
    result: dict[str, Any] = {
        "name": name,
        "tool": tool_rel,
        "violations": [],
        "checks": [],
        "mutation": None,
    }
    if not tool_rel:
        result["violations"].append("contract missing 'tool' field")
        return result
    tool_path = _resolve_tool(tool_rel)
    if not tool_path.is_file():
        result["violations"].append(f"tool not found: {tool_rel}")
        return result

    argv_template = contract.get("argv") or ["{fixture}"]
    if not isinstance(argv_template, list):
        result["violations"].append("'argv' must be a list")
        return result

    must_catch = contract.get("must_catch") or []
    must_pass = contract.get("must_pass") or []
    if not must_catch:
        result["violations"].append("contract has no must_catch fixture (>=1 required)")
    if not must_pass:
        result["violations"].append("contract has no must_pass fixture (>=1 required)")

    # Replay must_catch (expect nonzero) and must_pass (expect zero).
    for kind, fixtures, want_fail in (("must_catch", must_catch, True),
                                      ("must_pass", must_pass, False)):
        for i, fx in enumerate(fixtures):
            with tempfile.TemporaryDirectory() as td:
                workdir = Path(td)
                fixture_path = _materialize_fixture(fx, workdir)
                argv = _build_argv(tool_path, argv_template, fixture_path, workdir)
                rc = _run_tool(argv)
            failed = rc != 0
            ok = (failed == want_fail)
            entry = {
                "kind": kind,
                "index": i,
                "label": fx.get("label", f"{kind}[{i}]"),
                "rc": rc,
                "expected": "FAIL" if want_fail else "PASS",
                "observed": "FAIL" if failed else "PASS",
                "ok": ok,
            }
            result["checks"].append(entry)
            if not ok:
                result["violations"].append(
                    f"{kind}[{i}] '{entry['label']}': expected "
                    f"{entry['expected']} but tool returned {entry['observed']} (rc={rc})"
                )

    # Mutation-proof: does the must_catch fixture discriminate on the predicate?
    pred_line = contract.get("mutation_predicate")
    equivalent = bool(contract.get("mutation_equivalent", False))
    if do_mutation and pred_line and must_catch and not result["violations"]:
        mut_result = _mutation_proof(tool_path, int(pred_line), argv_template,
                                     must_catch[0])
        result["mutation"] = mut_result
        if mut_result.get("flips", 0) == 0 and not equivalent:
            result["violations"].append(
                f"mutation-proof: no generated mutant of predicate line "
                f"{pred_line} flipped must_catch[0] to PASS -- fixture may be "
                f"coverage-theater (set mutation_equivalent: true to record an "
                f"equivalent-mutant region)"
            )
    elif do_mutation and equivalent:
        result["mutation"] = {"equivalent_recorded": True, "flips": None}

    return result


def _mutation_proof(tool_path: Path, pred_line_1based: int,
                    argv_template: list[str], must_catch_fixture: dict) -> dict:
    """Mutate the predicate line; count mutants that flip must_catch to PASS."""
    src_lines = tool_path.read_text(encoding="utf-8").splitlines(keepends=False)
    idx = pred_line_1based - 1
    proof: dict[str, Any] = {
        "predicate_line": pred_line_1based,
        "predicate_text": None,
        "mutants_generated": 0,
        "flips": 0,
        "flip_operators": [],
    }
    if idx < 0 or idx >= len(src_lines):
        proof["error"] = f"predicate line {pred_line_1based} out of range"
        return proof
    predicate = src_lines[idx]
    proof["predicate_text"] = predicate.strip()
    variants = _predicate_mutants(predicate)
    proof["mutants_generated"] = len(variants)

    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        fixture_path = _materialize_fixture(must_catch_fixture, workdir)
        base_argv = _build_argv(tool_path, argv_template, fixture_path, workdir)
        for mut in variants:
            new_lines = list(src_lines)
            new_lines[idx] = mut
            mutated_source = "\n".join(new_lines) + "\n"
            rc = _run_tool(base_argv, tool_source=mutated_source)
            if rc == 0:  # must_catch flipped from FAIL to PASS -> mutation caught
                proof["flips"] += 1
                proof["flip_operators"].append(mut.strip())
    return proof


# ---------------------------------------------------------------------------
# Discovery + CLI
# ---------------------------------------------------------------------------
def _load_contracts(only_tool: str | None,
                    changed: list[str] | None) -> list[dict]:
    contracts: list[dict] = []
    if not CONTRACTS_DIR.is_dir():
        return contracts
    changed_resolved = None
    if changed:
        changed_resolved = {str(Path(c).resolve()) for c in changed}
    for yf in sorted(CONTRACTS_DIR.glob("*.yaml")) + sorted(CONTRACTS_DIR.glob("*.yml")):
        try:
            doc = _load_yaml(yf.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            contracts.append({"name": yf.name, "tool": None,
                              "_load_error": f"{e}"})
            continue
        if doc is None:
            continue
        items = doc if isinstance(doc, list) else [doc]
        for it in items:
            if not isinstance(it, dict):
                continue
            it.setdefault("_source", yf.name)
            tool_rel = it.get("tool")
            if only_tool and tool_rel != only_tool:
                continue
            if changed_resolved is not None:
                if not tool_rel:
                    continue
                if str((REPO_ROOT / tool_rel).resolve()) not in changed_resolved:
                    continue
            contracts.append(it)
    return contracts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Replay rule/Check self-test contracts (advisory-first).")
    ap.add_argument("--tool", default=None,
                    help="only replay contracts bound to this tool (repo-relative)")
    ap.add_argument("--changed", nargs="*", default=None,
                    help="only replay contracts whose tool is among these paths")
    ap.add_argument("--no-mutation", action="store_true",
                    help="skip the mutation-proof (faster; less rigorous)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--list", action="store_true",
                    help="list bound tools and exit")
    args = ap.parse_args(argv)

    strict = bool(os.environ.get(STRICT_ENV))

    contracts = _load_contracts(args.tool, args.changed)

    if args.list:
        tools = sorted({c.get("tool") for c in contracts if c.get("tool")})
        if args.json:
            print(json.dumps({"schema": SCHEMA, "bound_tools": tools}, indent=2))
        else:
            for t in tools:
                print(t)
        return 0

    if not contracts:
        # No contracts to replay for this scope is not an error in advisory
        # mode -- e.g. an edit that touches a tool with no bound contract.
        if args.json:
            print(json.dumps({"schema": SCHEMA, "contracts": [],
                              "strict": strict, "note": "no contracts in scope"},
                             indent=2))
        else:
            scope = args.tool or (" ".join(args.changed) if args.changed else "all")
            print(f"[rule-contract] no contracts bound in scope ({scope})")
        return 0

    results = []
    any_violation = False
    load_error = False
    for c in contracts:
        if c.get("_load_error"):
            load_error = True
            results.append({"name": c.get("name"), "tool": None,
                            "violations": [f"load error: {c['_load_error']}"],
                            "checks": [], "mutation": None})
            continue
        res = evaluate_contract(c, do_mutation=not args.no_mutation)
        if res["violations"]:
            any_violation = True
        results.append(res)

    if args.json:
        print(json.dumps({"schema": SCHEMA, "strict": strict,
                          "contracts": results}, indent=2))
    else:
        for res in results:
            status = "VIOLATED" if res["violations"] else "held"
            print(f"[rule-contract] {res['name']} ({res.get('tool')}): {status}")
            for ch in res["checks"]:
                mark = "ok" if ch["ok"] else "MISMATCH"
                print(f"    {ch['kind']}[{ch['index']}] {ch['label']}: "
                      f"want {ch['expected']} got {ch['observed']} [{mark}]")
            mut = res.get("mutation")
            if mut and "flips" in mut and mut.get("flips") is not None:
                print(f"    mutation-proof: {mut['flips']} flip(s) / "
                      f"{mut.get('mutants_generated', 0)} mutant(s) of predicate "
                      f"line {mut.get('predicate_line')}")
            elif mut and mut.get("equivalent_recorded"):
                print("    mutation-proof: equivalent-mutant region (recorded)")
            for v in res["violations"]:
                sev = "FAIL" if strict else "WARN"
                print(f"    [{sev}] {v}")

    if load_error:
        # A malformed contract file is a setup error regardless of mode.
        print("[rule-contract] setup error: a contract file failed to load",
              file=sys.stderr)
        return 2

    if any_violation:
        if strict:
            print(f"[rule-contract] STRICT: contract violation(s) -> nonzero exit "
                  f"({STRICT_ENV} set)", file=sys.stderr)
            return 1
        # Advisory note goes to stderr so --json keeps stdout pure JSON.
        print(f"[rule-contract] advisory: contract violation(s) reported "
              f"(set {STRICT_ENV}=1 to enforce)",
              file=sys.stderr if args.json else sys.stdout)
        return 0

    print("[rule-contract] all contracts held",
          file=sys.stderr if args.json else sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
