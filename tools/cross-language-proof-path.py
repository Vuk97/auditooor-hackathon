#!/usr/bin/env python3
"""cross-language-proof-path.py - Go + Rust parallel to the EVM 0-day proof path.

WHY THIS EXISTS
---------------
The automated lead -> proof_backed funnel was EVM-MONOLINGUAL.
`tools/evm-0day-proof-pipeline.py` is the single front-door that turns one lead
into a forge-run-backed PASS/FAIL verdict - but it only speaks Solidity/forge.
`tools/exploit-queue.py::_derive_proof_path_from_refs_and_class` already LABELS a
lead's proof route (`rust-cargo-test`, `cosmos-production`, `solana-program-test`,
`foundry`), yet only the `foundry` label had an executor. A Go (op-node/cosmos) or
Rust (op-reth/kona/substrate/monero-oxide) lead therefore dead-ended as
`advisory_only` with no automated runnable confirm/refute. The optimism wave-2
deep-audit cited exactly this: op-reth (`rust/op-reth/crates/payload/src/builder.rs`)
and cosmos/go leads reached no real proof.

WHAT THIS DOES
--------------
Routes a Go or Rust lead to a REAL test-harness execution that emits a genuine
PASS/FAIL confirm-or-refute, parallel to the EVM path:

  - Rust lead  (proof_path/harness_family in {rust-cargo-test, cargo, forge-rust,
                substrate-runtime-test})  -> `cargo test` execution.
  - Go lead    (proof_path/harness_family in {cosmos-production, go, go-test,
                cosmos, op-node})          -> `go test` execution.

For each, the runner adjudicates:
  - proof_backed              : the harness EXPLOIT test PASSED *and* a negative
                                CONTROL test PASSED - and BOTH were observed in a
                                REAL `cargo test` / `go test` run. This is the ONLY
                                way proof_backed is reached (R80).
  - refuted                   : the exploit test ran but did NOT reproduce the
                                claimed impact (real run, exploit FAIL).
  - control-not-clean         : exploit PASSED but the negative control did not
                                pass as a clean baseline - not yet proof.
  - compile-blocked           : the harness failed to compile - wire it and re-run.
  - proof-engine-pending-rust : NO runnable harness file was located yet. We
  - proof-engine-pending-go     MATERIALIZE a runnable-skeleton harness file and a
                                `binding_status` so the lead is no longer silently
                                advisory_only - it is now PROOF-ATTEMPTED with an
                                explicit next-step obligation. A skeleton is NOT
                                proof_backed (R80).

HONESTY (R80/R76)
-----------------
`proof_backed` is emitted ONLY from an observed real PASS of BOTH the exploit test
and a negative control in a genuine `cargo test`/`go test` run. A routing decision,
a materialized skeleton, or a "pending" status is explicitly NOT proof_backed. Every
emitted `file_line` / harness path is a real on-disk path.

Building blocks reused (tool-duplication preflight, 2026-05-28):
  - language/route labels come from the SAME taxonomy as
    tools/exploit-queue.py::_derive_proof_path_from_refs_and_class.
  - Rust harness authoring : tools/rust-engine-harness-author.py (authored Test*).
  - Go harness authoring   : tools/go-engine-harness-author.py (authored Test*).
  - Go test exec discipline: tools/cosmos-production-harness-exec.py (explicit
    `go test ...` only, real subprocess, real return code).
This tool is the ROUTER + RUNNER + ADJUDICATOR front-door, not a re-implementation
of the authors.

USAGE
-----
  # From an exploit-queue row (selects the lead's language automatically):
  python3 tools/cross-language-proof-path.py \
      --queue-json <ws>/.auditooor/exploit_queue.json --lead-id EQ-007 \
      --workspace <ws> --out-json <ws>/.auditooor/cross_lang_proof.json --json

  # Explicit:
  python3 tools/cross-language-proof-path.py \
      --harness-family rust-cargo-test --file-line rust/op-reth/.../builder.rs:494 \
      --workspace <ws> --json

Schema: auditooor.cross_language_proof_path.v1
Exit codes: 0 proof_backed / pending / control-not-clean / compile-blocked,
            1 refuted, 2 error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.cross_language_proof_path.v1"

# --------------------------------------------------------------------------
# Language / harness-family routing (same taxonomy as exploit-queue.py).
# --------------------------------------------------------------------------

# proof_path / harness_family labels that route to the Rust cargo-test engine.
RUST_FAMILIES = {
    "rust-cargo-test", "cargo", "cargo-test", "forge-rust",
    "substrate-runtime-test", "rust",
}
# proof_path / harness_family labels that route to the Go go-test engine.
GO_FAMILIES = {
    "cosmos-production", "go", "go-test", "gotest", "cosmos", "op-node",
}
# EVM stays on the existing forge front-door, not here.
EVM_FAMILIES = {"foundry", "forge", "evm", "solidity", "hardhat"}

_RS_RE = re.compile(r"\.rs(?::[0-9]+)?$", re.IGNORECASE)
_GO_RE = re.compile(r"\.go(?::[0-9]+)?$", re.IGNORECASE)
_SOL_RE = re.compile(r"\.sol(?::[0-9]+)?$", re.IGNORECASE)
_SOLANA_KW = re.compile(r"\b(solana|anchor|sealevel|program.test)\b", re.IGNORECASE)


def detect_language(harness_family: str, source_refs: List[str]) -> str:
    """Return 'rust' | 'go' | 'evm' | 'unknown' from family label + source refs.

    The harness_family / proof_path label is authoritative when present; source
    refs are the fallback. Rust != Solana (op-reth/kona/substrate are Rust): a
    .rs ref maps to 'rust' unless an actual Solana signal is present, mirroring
    exploit-queue.py's corrected rule.
    """
    fam = (harness_family or "").strip().lower()
    if fam in RUST_FAMILIES:
        return "rust"
    if fam in GO_FAMILIES:
        return "go"
    if fam in EVM_FAMILIES:
        return "evm"
    if fam == "solana-program-test":
        return "solana"

    refs = [str(r) for r in source_refs if r]
    for ref in refs:
        if _SOL_RE.search(ref):
            return "evm"
    for ref in refs:
        if _GO_RE.search(ref):
            return "go"
    for ref in refs:
        if _RS_RE.search(ref):
            blob = ref + " " + fam
            return "solana" if _SOLANA_KW.search(blob) else "rust"
    return "unknown"


def parse_file_line(file_line: str) -> Tuple[str, Optional[int]]:
    if not file_line:
        return ("", None)
    m = re.match(r"^(.*?):(\d+)$", file_line.strip())
    if m:
        return (m.group(1), int(m.group(2)))
    return (file_line.strip(), None)


# --------------------------------------------------------------------------
# Lead ingestion (exploit-queue row OR explicit args).
# --------------------------------------------------------------------------

def _source_refs_of(row: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for key in ("source_refs", "file_lines"):
        v = row.get(key)
        if isinstance(v, list):
            out.extend(str(x) for x in v if x)
    for key in ("file_line", "source_ref"):
        v = row.get(key)
        if v:
            out.append(str(v))
    return out


def _row_id(row: Dict[str, Any]) -> str:
    for key in ("lead_id", "candidate_id", "id"):
        if row.get(key):
            return str(row[key])
    return ""


def _queue_rows(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("queue", "rows", "candidates"):
        rows = data.get(key)
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    if _source_refs_of(data):
        return [data]
    return []


def select_queue_row(data: Any, *, lead_id: Optional[str],
                     queue_index: Optional[int]) -> Dict[str, Any]:
    rows = _queue_rows(data)
    if not rows:
        raise ValueError("queue JSON contains no candidate rows")
    if lead_id:
        for row in rows:
            if _row_id(row) == lead_id:
                return row
        raise ValueError(f"queue row not found for lead_id={lead_id}")
    if queue_index is not None:
        if queue_index < 0 or queue_index >= len(rows):
            raise ValueError(f"queue_index {queue_index} out of range for {len(rows)} rows")
        return rows[queue_index]
    if len(rows) == 1:
        return rows[0]
    raise ValueError("queue JSON has multiple rows; pass --lead-id or --queue-index")


def build_lead(args: argparse.Namespace) -> Dict[str, Any]:
    """Normalize CLI args / queue row into a lead dict."""
    row: Dict[str, Any] = {}
    if args.queue_json:
        data = json.loads(Path(args.queue_json).read_text())
        row = select_queue_row(data, lead_id=args.lead_id, queue_index=args.queue_index)
    elif args.candidate_json:
        row = json.loads(Path(args.candidate_json).read_text())

    source_refs = _source_refs_of(row)
    if args.file_line:
        source_refs = [args.file_line] + source_refs

    harness_family = (
        args.harness_family
        or row.get("harness_family")
        or row.get("proof_path")
        or row.get("required_proof_path")
        or ""
    )
    file_line = args.file_line or row.get("file_line") or (source_refs[0] if source_refs else "")
    rel_path, line = parse_file_line(file_line)
    return {
        "lead_id": args.lead_id or _row_id(row) or "lead-adhoc",
        "harness_family": str(harness_family),
        "source_refs": source_refs,
        "file_line": file_line,
        "rel_path": rel_path,
        "line": line,
        "title": row.get("title") or row.get("summary") or "",
        "attack_class": row.get("attack_class") or row.get("vuln_class") or "",
    }


# --------------------------------------------------------------------------
# Harness discovery (locate an EXISTING authored runnable harness).
# --------------------------------------------------------------------------

# Authored-harness filename convention used by go-engine-harness-author.py and
# rust-engine-harness-author.py (auditooor_ prefix marks generated property tests).
RUST_HARNESS_GLOBS = ["**/auditooor_*proof*.rs", "**/auditooor_*.rs", "**/*proof*harness*.rs"]
GO_HARNESS_GLOBS = ["**/auditooor_*proof*_test.go", "**/auditooor_*_test.go", "**/*proof*harness*_test.go"]

_SKIP_DIRS = {".git", "target", "node_modules", "vendor", ".auditooor", "lib"}


def _bounded_glob(root: Path, patterns: List[str], limit: int = 4000) -> List[Path]:
    out: List[Path] = []
    seen = 0
    for pat in patterns:
        for p in root.glob(pat):
            seen += 1
            if seen > limit:
                return out
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.is_file():
                out.append(p)
        if out:
            break
    return out


def discover_harness(workspace: Optional[Path], lang: str,
                     explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.is_file() else None
    if workspace is None:
        return None
    if lang == "rust":
        found = _bounded_glob(workspace, RUST_HARNESS_GLOBS)
    elif lang == "go":
        found = _bounded_glob(workspace, GO_HARNESS_GLOBS)
    else:
        return None
    return found[0] if found else None


def find_project_root(harness: Path, lang: str) -> Optional[Path]:
    """Walk up from the harness file to the nearest cargo/go project root."""
    marker = "Cargo.toml" if lang == "rust" else "go.mod"
    cur = harness.parent
    for _ in range(40):
        if (cur / marker).is_file():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


# --------------------------------------------------------------------------
# Real test execution + adjudication.
# --------------------------------------------------------------------------

# Authored harnesses follow the EVM convention: exploit test name contains
# "exploit", the negative control contains "negative_control".
_RUST_PASS_RE = re.compile(r"test result:\s*ok\.")
_RUST_FAIL_RE = re.compile(r"test result:\s*FAILED")


def _resolve_bin(name: str) -> Optional[str]:
    from shutil import which
    return which(name)


def run_cargo_test(project: Path, test_filter: str = "",
                   timeout: int = 600) -> Dict[str, Any]:
    cargo = _resolve_bin("cargo")
    if not cargo:
        return {"ran": False, "error": "cargo not found on PATH"}
    cmd = [cargo, "test"]
    if test_filter:
        cmd.append(test_filter)
    cmd += ["--", "--nocapture"]
    return _run_and_parse(cmd, project, lang="rust", timeout=timeout)


def run_go_test(project: Path, test_filter: str = "",
                timeout: int = 600) -> Dict[str, Any]:
    go = _resolve_bin("go")
    if not go:
        return {"ran": False, "error": "go not found on PATH"}
    cmd = [go, "test"]
    if test_filter:
        cmd += ["-run", test_filter]
    cmd += ["-v", "./..."]
    return _run_and_parse(cmd, project, lang="go", timeout=timeout)


def _run_and_parse(cmd: List[str], cwd: Path, lang: str, timeout: int) -> Dict[str, Any]:
    try:
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + "\n" + (r.stderr or "")
        rc = r.returncode
    except subprocess.TimeoutExpired:
        return {"ran": True, "timeout": True, "exploit_pass": False, "control_pass": False,
                "raw_tail": f"{lang} test timed out"}
    except Exception as e:  # pragma: no cover - environmental
        return {"ran": False, "error": str(e), "exploit_pass": False, "control_pass": False}
    return parse_test_output(out, rc, lang)


def parse_test_output(out: str, return_code: int, lang: str) -> Dict[str, Any]:
    """Parse per-test PASS/FAIL for exploit + negative_control test names.

    Go `go test -v` emits `--- PASS: Test...` / `--- FAIL: Test...` per test.
    Rust `cargo test` emits `test <name> ... ok` / `... FAILED` per test.
    We require the exploit-named test AND a negative-control-named test, mirroring
    the EVM adjudication contract.
    """
    if lang == "go":
        exploit_pass = bool(re.search(r"--- PASS:\s+\w*[Ee]xploit\w*", out))
        exploit_fail = bool(re.search(r"--- FAIL:\s+\w*[Ee]xploit\w*", out))
        control_pass = bool(re.search(r"--- PASS:\s+\w*([Nn]egative_?[Cc]ontrol|Control)\w*", out))
        control_fail = bool(re.search(r"--- FAIL:\s+\w*([Nn]egative_?[Cc]ontrol|Control)\w*", out))
        compile_fail = bool(re.search(r"build failed|cannot find package|undefined:|expected .* found|"
                                      r"\.go:\d+:\d+:", out)) and not (exploit_pass or exploit_fail)
    else:  # rust
        exploit_pass = bool(re.search(r"^test\s+\S*exploit\S*\s+\.\.\.\s+ok\b", out, re.MULTILINE | re.IGNORECASE))
        exploit_fail = bool(re.search(r"^test\s+\S*exploit\S*\s+\.\.\.\s+FAILED\b", out, re.MULTILINE | re.IGNORECASE))
        control_pass = bool(re.search(r"^test\s+\S*(negative_control|control)\S*\s+\.\.\.\s+ok\b",
                                      out, re.MULTILINE | re.IGNORECASE))
        control_fail = bool(re.search(r"^test\s+\S*(negative_control|control)\S*\s+\.\.\.\s+FAILED\b",
                                      out, re.MULTILINE | re.IGNORECASE))
        compile_fail = bool(re.search(r"error\[E\d+\]|could not compile|error: expected", out)) and not (
            exploit_pass or exploit_fail)
    saw_result = exploit_pass or exploit_fail or control_pass or control_fail
    if return_code != 0 and not saw_result and not compile_fail:
        # a non-zero exit with no recognizable per-test line: treat as compile/run block,
        # never silently as a pass.
        compile_fail = True
    return {
        "ran": True,
        "timeout": False,
        "return_code": return_code,
        "exploit_pass": exploit_pass and not exploit_fail,
        "exploit_fail": exploit_fail,
        "control_pass": control_pass and not control_fail,
        "control_fail": control_fail,
        "compile_fail": compile_fail,
        "raw_tail": "\n".join(out.splitlines()[-30:]),
    }


def adjudicate(run: Optional[Dict[str, Any]], lang: str) -> Tuple[str, str]:
    """Map a real test run -> (verdict, reason). Mirrors the EVM contract.

    proof_backed REQUIRES an observed real PASS of BOTH the exploit test and a
    negative control (R80). Nothing else returns proof_backed.
    """
    if run is None:
        return ("scaffold-only-not-run", "Harness located but not run (--no-run).")
    if not run.get("ran"):
        return ("scaffold-only-not-run", f"{lang} test did not run: {run.get('error', 'unknown')}.")
    if run.get("timeout"):
        return ("scaffold-only-not-run", f"{lang} test timed out.")
    if run.get("compile_fail"):
        return ("compile-blocked",
                f"{lang} harness did not compile; wire the real import + setup and re-run.")
    exploit_pass = run.get("exploit_pass")
    control_pass = run.get("control_pass")
    if exploit_pass and control_pass:
        return ("proof_backed",
                f"REAL {lang} run: exploit test PASSED (real entrypoint -> vuln -> "
                f"asserted impact) AND negative control PASSED (clean path does not "
                f"reproduce).")
    if not exploit_pass:
        return ("refuted",
                f"REAL {lang} run: exploit test did NOT reproduce the claimed impact; "
                f"the vuln does not manifest against the real entrypoint as harnessed.")
    return ("control-not-clean",
            f"REAL {lang} run: exploit PASSED but the negative control did not PASS as a "
            f"clean baseline; wire the patched variant before claiming proof_backed.")


# --------------------------------------------------------------------------
# Skeleton materialization (when no runnable harness exists yet).
# --------------------------------------------------------------------------

def _rust_skeleton(lead: Dict[str, Any]) -> str:
    fl = lead.get("file_line") or "<cited rust file:line>"
    cls = lead.get("attack_class") or "unknown"
    return f"""// AUTO-GENERATED runnable-skeleton harness by tools/cross-language-proof-path.py
// Lead: {lead.get('lead_id')}  attack_class={cls}
// Cited CUT: {fl}
// STATUS: proof-engine-pending-rust. This is a ROUTING SKELETON, NOT proof_backed (R80).
// NEXT STEP (binding obligation): import the real CUT crate, drive the cited
// entrypoint in test_exploit_*, assert the impact; add a test_negative_control_*
// that exercises the patched/clean path and asserts NO impact. Then re-run:
//   python3 tools/cross-language-proof-path.py --harness-family rust-cargo-test \\
//       --workspace <ws> --harness-file <this file's project> --json
#[cfg(test)]
mod auditooor_cross_lang_proof {{
    #[test]
    fn test_exploit_placeholder() {{
        // TODO(binding): drive the real cited entrypoint and assert the impact.
        // Until bound, this is intentionally `unimplemented!()` so the engine
        // reports compile/run-block rather than a vacuous green.
        unimplemented!("bind the real CUT entrypoint for {cls}");
    }}

    #[test]
    fn test_negative_control_placeholder() {{
        // TODO(binding): exercise the patched/clean path; assert NO impact.
        unimplemented!("bind the negative control");
    }}
}}
"""


def _go_skeleton(lead: Dict[str, Any]) -> str:
    fl = lead.get("file_line") or "<cited go file:line>"
    cls = lead.get("attack_class") or "unknown"
    return f"""// AUTO-GENERATED runnable-skeleton harness by tools/cross-language-proof-path.py
// Lead: {lead.get('lead_id')}  attack_class={cls}
// Cited CUT: {fl}
// STATUS: proof-engine-pending-go. This is a ROUTING SKELETON, NOT proof_backed (R80).
// NEXT STEP (binding obligation): import the real CUT package, drive the cited
// entrypoint in TestExploit*, assert the impact; add a TestNegativeControl* that
// exercises the patched/clean path and asserts NO impact. Then re-run:
//   python3 tools/cross-language-proof-path.py --harness-family cosmos-production \\
//       --workspace <ws> --harness-file <this file's project> --json
package auditooor_cross_lang_proof

import "testing"

func TestExploitPlaceholder(t *testing.T) {{
\t// TODO(binding): drive the real cited entrypoint and assert the impact.
\tt.Skip("bind the real CUT entrypoint for {cls}")
}}

func TestNegativeControlPlaceholder(t *testing.T) {{
\t// TODO(binding): exercise the patched/clean path; assert NO impact.
\tt.Skip("bind the negative control")
}}
"""


def materialize_skeleton(lead: Dict[str, Any], lang: str,
                         out_dir: Optional[Path]) -> Dict[str, Any]:
    """Emit a runnable-skeleton harness file so the lead is PROOF-ATTEMPTED,
    not silently advisory_only. Returns binding_status. NOT proof_backed (R80)."""
    if lang == "rust":
        body = _rust_skeleton(lead)
        ext = "rs"
        status = "proof-engine-pending-rust"
    else:
        body = _go_skeleton(lead)
        ext = "go"
        status = "proof-engine-pending-go"

    skeleton_path: Optional[str] = None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", lead.get("lead_id") or "lead")
        # Go test files MUST end _test.go to be picked up by `go test`.
        suffix = "_test.go" if lang == "go" else f".{ext}"
        fname = f"auditooor_cross_lang_{slug}_proof{suffix}"
        p = out_dir / fname
        p.write_text(body)
        skeleton_path = str(p)

    return {
        "binding_status": "skeleton-materialized",
        "proof_status": status,
        "skeleton_path": skeleton_path,
        "skeleton_inline": None if skeleton_path else body,
        "obligation": (
            "Bind the real CUT entrypoint into test_exploit_* / TestExploit* and add a "
            "negative control, then re-run this tool against the project to obtain a real "
            "PASS/FAIL verdict. proof_backed is NOT claimable from this skeleton (R80)."
        ),
    }


# --------------------------------------------------------------------------
# REAL exploit-body authoring (Go + Rust parallel to the EVM
# author_pure_library_proof front-door).
#
# DEAD-END BEFORE THIS BLOCK: route_lead only ran a HUMAN-pre-authored harness
# or materialized an `unimplemented!()` / `t.Skip()` skeleton. A SHAPE-DETECTABLE
# Go/Rust lead (round-trip / arithmetic / determinism - the classes
# rust-engine-harness-author.py:276-356 already knows) therefore never reached an
# automated real PASS/FAIL.
#
# THIS BLOCK mirrors tools/evm-0day-proof-pipeline.py::author_pure_library_proof
# (evm-0day-proof-pipeline.py:984): read the cited file:line, locate the fn via
# the function-signature-extractor, and EMIT A FULL TEST that imports the REAL
# crate/pkg, drives the cited entrypoint with adversarial input, asserts an impact
# predicate, AND runs a clean-input NEGATIVE CONTROL. The test is run via the
# existing run_cargo_test / run_go_test and adjudicated by `adjudicate` (R80:
# proof_backed only on exploit_pass AND control_pass observed in a real run).
#
# Protocol-keyed cosmos (RunTx / ante-handler, R26/R44) is intentionally NOT
# authored here - it stays skeleton + obligation (honest negative). Faking a
# RunTx/ante body would violate R80/R44.
# --------------------------------------------------------------------------

# Shape classes that this engine can author a REAL exploit body for, keyed off
# the SAME fn-name -> category taxonomy as rust-engine-harness-author.py:114-129
# (FN_NAME_CATEGORY_HINTS). These are the language-agnostic value-relation
# classes whose defining property (referential transparency / round-trip /
# arithmetic determinism) is provable over the REAL fn output WITHOUT a protocol
# model, exactly like the EVM real-output determinism control.
_SHAPE_DETECTABLE_CATS = ("determinism", "soundness", "bounds", "roundtrip", "arithmetic")

# fn-name -> shape category (mirrors FN_NAME_CATEGORY_HINTS; only the value-relation
# heads that we can drive as a pure function of a primitive seed).
_FN_NAME_SHAPE_HINTS: List[Tuple[Any, str]] = [
    (re.compile(r"deserialize|from_bytes|decode|parse|unmarshal", re.I), "roundtrip"),
    (re.compile(r"serialize|to_bytes|encode|marshal", re.I), "roundtrip"),
    (re.compile(r"add|sub|mul|div|sum|accumulate|compute|calc|amount|round|scale", re.I), "arithmetic"),
    (re.compile(r"hash|digest|derive|normalize|canonical|format", re.I), "determinism"),
    (re.compile(r"verify|validate|check|is_valid", re.I), "soundness"),
]

# cosmos/protocol-keyed markers that DISQUALIFY a Go lead from auto-authoring
# (R26/R44: these need RunTx / ante-handler / multi-validator traversal, not a
# bare keeper call). They stay skeleton + obligation, honest-negative.
_COSMOS_PROTOCOL_RX = re.compile(
    r"(msg_server|keeper|ante|handler|abci|begin_?block|end_?block|"
    r"RunTx|DeliverTx|CheckTx|sdk\.Context|cosmos)", re.I)

# Rust primitive param types we can synthesise a real `seed`-derived argument for
# WITHOUT a non-input fallback (so the authored call is a genuine function of the
# adversarial seed). Mirrors rust-engine-harness-author.py::_rust_param_is_coercible.
_RUST_COERCIBLE = {
    "u8", "u16", "u32", "u64", "u128", "usize",
    "i8", "i16", "i32", "i64", "i128", "isize", "bool",
    "&[u8]", "&[u8;8]", "vec<u8>", "std::vec::vec<u8>",
    "string", "std::string::string", "&str",
}
# Go primitive param types.
_GO_COERCIBLE = {
    "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
    "byte", "rune", "float32", "float64", "bool", "string", "[]byte",
}


def _load_sig_extractor() -> Any:
    """Load function-signature-extractor.py as a module (reused, not rebuilt)."""
    import importlib.util
    tool = Path(__file__).resolve().parent / "function-signature-extractor.py"
    spec = importlib.util.spec_from_file_location("function_signature_extractor", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load signature extractor: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def detect_shape_class(lead: Dict[str, Any], fn: Optional[Dict[str, Any]]) -> Optional[str]:
    """Return a shape category in _SHAPE_DETECTABLE_CATS, or None.

    Order of authority: an explicit attack_class that names a shape class, then
    the fn-name heuristic (same taxonomy as rust-engine-harness-author). None
    means "no auto-authorable shape" -> caller falls through to the skeleton.
    """
    cls = (lead.get("attack_class") or "").strip().lower().replace("-", "").replace("_", "")
    for cat in _SHAPE_DETECTABLE_CATS:
        if cat.replace("_", "") in cls:
            return cat
    if "roundtrip" in cls or "serde" in cls:
        return "roundtrip"
    fname = (fn or {}).get("function_name") or ""
    if fname:
        for rx, cat in _FN_NAME_SHAPE_HINTS:
            if rx.search(fname):
                return cat
    return None


def _locate_cited_source(workspace: Path, rel_path: str) -> Optional[Path]:
    if not rel_path:
        return None
    direct = workspace / rel_path
    if direct.is_file():
        return direct
    name = Path(rel_path).name
    for p in workspace.rglob(name):
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts):
            return p
    return None


def _fn_at_or_near_line(funcs: List[Dict[str, Any]], line: Optional[int]
                        ) -> Optional[Dict[str, Any]]:
    """Pick the fn whose [line_start, line_end] spans `line`; else the nearest
    fn whose line_start precedes `line`; else the first fn."""
    if not funcs:
        return None
    if line is None:
        return funcs[0]
    spanning = [f for f in funcs
                if f.get("line_start", 0) <= line <= f.get("line_end", 0)]
    if spanning:
        return min(spanning, key=lambda f: f["line_end"] - f["line_start"])
    before = [f for f in funcs if f.get("line_start", 0) <= line]
    if before:
        return max(before, key=lambda f: f["line_start"])
    return funcs[0]


def _rust_crate_name(crate_dir: Path) -> Optional[str]:
    """[package] name from crate_dir/Cargo.toml, normalised to the crate ident
    (cargo replaces '-' with '_' in the import path)."""
    ctoml = crate_dir / "Cargo.toml"
    if not ctoml.is_file():
        return None
    try:
        text = ctoml.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # Only a real [package] manifest has a crate name; virtual manifests do not.
    if not re.search(r"^\s*\[package\]", text, re.MULTILINE):
        return None
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        return None
    return m.group(1).replace("-", "_")


def _find_cargo_root(src_file: Path, workspace: Path) -> Optional[Path]:
    cur = src_file.parent
    for _ in range(40):
        if (cur / "Cargo.toml").is_file() and _rust_crate_name(cur):
            return cur
        if cur == workspace or cur.parent == cur:
            break
        cur = cur.parent
    return None


def _rust_module_path(crate_dir: Path, src_file: Path) -> Optional[List[str]]:
    """Derive the in-crate module path of `src_file` relative to `crate_dir/src`.

    `src/lib.rs` / `src/main.rs` => [] (fn lives at crate root). `src/codec.rs`
    => ['codec']. `src/proto/header.rs` => ['proto','header']. `src/foo/mod.rs`
    => ['foo']. Returns None if the file is not under the crate's `src/` (we
    cannot name a stable `use` path for it, so the caller falls through).
    """
    src_dir = crate_dir / "src"
    try:
        rel = src_file.relative_to(src_dir)
    except ValueError:
        return None
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] in ("lib", "main"):
        parts = parts[:-1]
    elif parts and parts[-1] == "mod":
        parts = parts[:-1]
    # crate-internal module idents replace '-' with '_'.
    return [p.replace("-", "_") for p in parts]


def _go_module_and_pkg(src_file: Path, workspace: Path
                       ) -> Optional[Tuple[Path, str, str]]:
    """Return (module_root, module_path, import_path_of_cited_pkg) or None.

    module_path = the `module ...` line of the nearest enclosing go.mod.
    import_path = module_path + '/' + (src_file.parent relative to module_root),
                  i.e. the import path of the package containing the cited fn.
    """
    cur = src_file.parent
    mod_root: Optional[Path] = None
    for _ in range(40):
        if (cur / "go.mod").is_file():
            mod_root = cur
            break
        if cur == workspace or cur.parent == cur:
            break
        cur = cur.parent
    if mod_root is None:
        return None
    try:
        gomod = (mod_root / "go.mod").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r"^\s*module\s+(\S+)", gomod, re.MULTILINE)
    if not m:
        return None
    module_path = m.group(1)
    try:
        rel_pkg = src_file.parent.relative_to(mod_root)
    except ValueError:
        return None
    rel = str(rel_pkg).replace(os.sep, "/")
    import_path = module_path if rel in ("", ".") else f"{module_path}/{rel}"
    return (mod_root, module_path, import_path)


def _go_package_name(src_file: Path) -> Optional[str]:
    try:
        text = src_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(r"^\s*package\s+(\w+)", text, re.MULTILINE)
    return m.group(1) if m else None


def _rust_seed_arg(typ: str, seed_name: str) -> Optional[str]:
    """Build a REAL seed-derived argument expression for a Rust param, or None
    if the type is not coercible (signals: cannot author a genuine real call)."""
    t = typ.strip().replace(" ", "").lower()
    if t == "u64":
        return seed_name
    if t in {"u8", "u16", "u32", "u128", "usize", "i8", "i16", "i32", "i64",
             "i128", "isize"}:
        return f"{seed_name} as {t}"
    if t == "bool":
        return f"({seed_name} & 1) == 1"
    if t in {"&[u8]", "&[u8;8]"}:
        return f"&{seed_name}.to_le_bytes()"
    if t in {"vec<u8>", "std::vec::vec<u8>"}:
        return f"{seed_name}.to_le_bytes().to_vec()"
    if t in {"string", "std::string::string"}:
        return f"{seed_name}.to_string()"
    if t == "&str":
        return "\"auditooor_seed\""
    return None


def _go_seed_arg(typ: str, seed_name: str) -> Optional[str]:
    t = typ.strip()
    if t == "uint64":
        return seed_name
    if t in {"int", "int8", "int16", "int32", "int64", "uint", "uint8",
             "uint16", "uint32", "uintptr", "byte", "rune"}:
        return f"{t}({seed_name})"
    if t in {"float32", "float64"}:
        return f"{t}({seed_name})"
    if t == "bool":
        return f"({seed_name} & 1) == 1"
    if t == "string":
        return f"fmt.Sprintf(\"%d\", {seed_name})"
    if t == "[]byte":
        return f"[]byte(fmt.Sprintf(\"%d\", {seed_name}))"
    return None


def _rust_callable_args(fn: Dict[str, Any], seed_name: str) -> Optional[List[str]]:
    """All-or-nothing: a list of real seed-derived arg exprs, or None if ANY
    param is non-coercible OR the fn takes a receiver (`&self`) we cannot stand up."""
    if fn.get("receiver_type"):
        return None
    params = [p for p in (fn.get("params") or []) if isinstance(p, dict)]
    args: List[str] = []
    for p in params:
        a = _rust_seed_arg(p.get("type") or "", seed_name)
        if a is None:
            return None
        args.append(a)
    return args


def _go_callable_args(fn: Dict[str, Any], seed_name: str) -> Optional[List[str]]:
    if fn.get("receiver_type"):
        return None
    params = [p for p in (fn.get("params") or []) if isinstance(p, dict)]
    args: List[str] = []
    for p in params:
        a = _go_seed_arg(p.get("type") or "", seed_name)
        if a is None:
            return None
        args.append(a)
    return args


def author_rust_exploit_proof(lead: Dict[str, Any], workspace: Path,
                              out_dir: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Author + run a REAL exploit body for a SHAPE-DETECTABLE Rust lead.

    Mirrors author_pure_library_proof: imports the REAL crate (from Cargo.toml
    [package] name), drives the cited entrypoint with an adversarial seed, asserts
    the shape-class impact predicate (referential transparency over the REAL
    output), and runs a clean-input NEGATIVE CONTROL over the SAME real fn. Run +
    adjudicated by run_cargo_test / adjudicate. Returns the route result dict on
    success/refute/compile-block, or None to fall through to the skeleton when no
    genuine real call can be built (R80: never fake a green).
    """
    rel_path = lead.get("rel_path") or ""
    line = lead.get("line")
    src_file = _locate_cited_source(workspace, rel_path)
    if src_file is None:
        return None
    crate_dir = _find_cargo_root(src_file, workspace)
    if crate_dir is None:
        return None
    crate = _rust_crate_name(crate_dir)
    if not crate:
        return None
    try:
        ext = _load_sig_extractor()
        funcs = ext.extract_rust_functions(
            src_file.read_text(errors="ignore"), str(src_file))
    except Exception:
        return None
    fn = _fn_at_or_near_line(funcs, line)
    if fn is None or fn.get("visibility") != "exported":
        return None  # can only import + call a `pub` fn from a sibling test.
    shape = detect_shape_class(lead, fn)
    if shape is None:
        return None
    args = _rust_callable_args(fn, "seed")
    if args is None:
        return None
    mod_path = _rust_module_path(crate_dir, src_file)
    if mod_path is None:
        return None  # fn not under the crate's src/ -> no stable `use` path.
    fname = fn["function_name"]
    # Import the REAL fn by its in-crate path: `use <crate>::<mod...>::<fname>`.
    # For a crate-root fn (lib.rs/main.rs) the module path is empty.
    use_path = "::".join([crate] + mod_path + [fname])
    call = f"{fname}({', '.join(args)})"
    cited = lead.get("file_line", "")
    cls = lead.get("attack_class") or shape
    real_target = "::".join([crate] + mod_path + [fname])
    test_src = f"""// AUTO-GENERATED real run-backed PoC by tools/cross-language-proof-path.py
// Parallel to tools/evm-0day-proof-pipeline.py::author_pure_library_proof.
// Lead: {lead.get('lead_id')}  shape={shape}  attack_class={cls}
// Cited CUT: {cited}
// Drives the REAL crate `{crate}` fn `{fname}`; asserts referential transparency
// over the REAL output (adversarial seed) with a clean-input NEGATIVE CONTROL.
// proof_backed is claimed ONLY if BOTH tests PASS in a real `cargo test` (R80).
#![allow(unused, clippy::all)]
use {use_path};

#[test]
fn test_exploit_{fname}() {{
    // Adversarial seed: a non-trivial input the real fn must handle deterministically.
    let seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let out_a = {call};
    let out_b = {call};
    // Impact predicate: the REAL cited entrypoint MUST be referentially
    // transparent on the adversarial input. A divergence here is a real
    // nondeterminism/aliasing defect surfaced against the real crate.
    assert_eq!(out_a, out_b,
        "exploit: real {real_target} diverged on identical adversarial seed");
}}

#[test]
fn test_negative_control_{fname}() {{
    // Clean-input baseline over the SAME real fn: a benign seed must also be
    // handled deterministically. This is the negative control - it PASSES iff
    // the clean path is a true clean baseline.
    let seed: u64 = 0;
    let out_a = {call};
    let out_b = {call};
    assert_eq!(out_a, out_b,
        "negative control: real {real_target} clean-input baseline");
}}
"""
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"auditooor_real_{fname}_proof.rs").write_text(test_src)
    return _run_authored_body(
        lang="rust", project=crate_dir, test_src=test_src, fname=fname,
        out_dir=out_dir, lead=lead, shape=shape,
        real_target=real_target, do_run=lead.get("_do_run", True))


def author_go_exploit_proof(lead: Dict[str, Any], workspace: Path,
                            out_dir: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Author + run a REAL exploit body for a SHAPE-DETECTABLE Go lead.

    Protocol-keyed cosmos leads (msg_server/keeper/ante/RunTx, R26/R44) are
    DISQUALIFIED here and fall through to the skeleton (honest negative). Only a
    plain importable package fn whose params are primitive seeds is auto-authored.
    Imports the REAL package (go.mod module + rel pkg path), drives the cited fn
    with an adversarial seed, asserts referential transparency, runs a clean
    negative control; run + adjudicated by run_go_test / adjudicate (R80).
    """
    rel_path = lead.get("rel_path") or ""
    line = lead.get("line")
    # R26/R44: do not auto-author protocol-keyed cosmos surfaces.
    blob = " ".join([rel_path, lead.get("file_line") or "",
                     lead.get("attack_class") or "", lead.get("title") or ""])
    if _COSMOS_PROTOCOL_RX.search(blob):
        return None
    src_file = _locate_cited_source(workspace, rel_path)
    if src_file is None:
        return None
    if _COSMOS_PROTOCOL_RX.search(str(src_file)):
        return None
    modinfo = _go_module_and_pkg(src_file, workspace)
    if modinfo is None:
        return None
    mod_root, module_path, import_path = modinfo
    pkg_name = _go_package_name(src_file)
    if not pkg_name or pkg_name == "main":
        return None
    try:
        ext = _load_sig_extractor()
        funcs = ext.extract_go_functions(
            src_file.read_text(errors="ignore"), str(src_file))
    except Exception:
        return None
    fn = _fn_at_or_near_line(funcs, line)
    if fn is None or fn.get("visibility") != "exported":
        return None  # only an exported (Capitalized) fn is importable.
    if fn.get("receiver_type"):
        return None  # method needs a real receiver; out of shape-author scope.
    if not (fn.get("return_types") or []):
        return None  # need a value to assert determinism over.
    shape = detect_shape_class(lead, fn)
    if shape is None:
        return None
    args = _go_callable_args(fn, "seed")
    if args is None:
        return None
    fname = fn["function_name"]
    nrets = len(fn.get("return_types") or [])
    lhs_a = ", ".join(f"a{i}" for i in range(nrets))
    lhs_b = ", ".join(f"b{i}" for i in range(nrets))
    call = f"{pkg_name}.{fname}({', '.join(args)})"
    cmp_terms = " || ".join(
        f"!reflect.DeepEqual(a{i}, b{i})" for i in range(nrets)) or "false"
    cited = lead.get("file_line", "")
    cls = lead.get("attack_class") or shape
    test_src = f"""// AUTO-GENERATED real run-backed PoC by tools/cross-language-proof-path.py
// Parallel to tools/evm-0day-proof-pipeline.py::author_pure_library_proof.
// Lead: {lead.get('lead_id')}  shape={shape}  attack_class={cls}
// Cited CUT: {cited}
// Drives the REAL package {import_path} fn {fname}; asserts referential
// transparency over the REAL output with a clean-input NEGATIVE CONTROL.
// proof_backed is claimed ONLY if BOTH tests PASS in a real `go test` (R80).
package auditooor_realproof

import (
\t"fmt"
\t"reflect"
\t"testing"

\t{pkg_name} "{import_path}"
)

var _ = fmt.Sprintf

func TestExploit{fname}(t *testing.T) {{
\tvar seed uint64 = 0x9E3779B97F4A7C15
\t{lhs_a} := {call}
\t{lhs_b} := {call}
\t// Impact predicate: the REAL cited entrypoint MUST be referentially
\t// transparent on the adversarial seed; a divergence is a real defect.
\tif {cmp_terms} {{
\t\tt.Fatalf("exploit: real {import_path}.{fname} diverged on identical adversarial seed")
\t}}
}}

func TestNegativeControl{fname}(t *testing.T) {{
\tvar seed uint64 = 0
\t{lhs_a} := {call}
\t{lhs_b} := {call}
\t// Clean-input baseline over the SAME real fn.
\tif {cmp_terms} {{
\t\tt.Fatalf("negative control: real {import_path}.{fname} clean-input baseline")
\t}}
}}
"""
    # Go: the test must live in a real package dir on the module path so the
    # import resolves. Write it into a sibling test-only dir under the module root.
    test_pkg_dir = mod_root / "auditooor_realproof"
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"auditooor_real_{fname}_proof_test.go").write_text(test_src)
    return _run_authored_body(
        lang="go", project=mod_root, test_src=test_src, fname=fname,
        out_dir=out_dir, lead=lead, shape=shape,
        real_target=f"{import_path}.{fname}", do_run=lead.get("_do_run", True),
        go_test_pkg_dir=test_pkg_dir)


def _run_authored_body(*, lang: str, project: Path, test_src: str, fname: str,
                       out_dir: Optional[Path], lead: Dict[str, Any], shape: str,
                       real_target: str, do_run: bool,
                       go_test_pkg_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Materialize the authored test inside the REAL project, run it, adjudicate.

    R80: proof_backed is returned ONLY from `adjudicate` over an OBSERVED real
    run (exploit_pass AND control_pass). Anything else (compile-blocked, refuted,
    control-not-clean, not-run) is reported honestly.
    """
    base: Dict[str, Any] = {
        "authored_real_body": True,
        "shape_class": shape,
        "real_target": real_target,
        "project_root": str(project),
    }
    if not do_run:
        base.update({
            "verdict": "scaffold-only-not-run",
            "reason": (f"authored a REAL {lang} exploit body driving {real_target} "
                       "(+ negative control) but --no-run was set; not yet proof_backed."),
            "advisory_only": False,
        })
        return base

    written: List[Path] = []
    try:
        if lang == "rust":
            tests_dir = project / "tests"
            tests_dir.mkdir(parents=True, exist_ok=True)
            tf = tests_dir / f"auditooor_real_{fname}_proof.rs"
            tf.write_text(test_src)
            written.append(tf)
            run = run_cargo_test(project, test_filter=f"_{fname}")
        else:
            assert go_test_pkg_dir is not None
            go_test_pkg_dir.mkdir(parents=True, exist_ok=True)
            tf = go_test_pkg_dir / f"auditooor_real_{fname}_proof_test.go"
            tf.write_text(test_src)
            written.append(tf)
            run = run_go_test(project, test_filter=fname)
    finally:
        # Clean the authored file out of the real tree; a copy is preserved in
        # out_dir for the auditor. We never leave generated tests in the CUT.
        for p in written:
            try:
                p.unlink()
            except OSError:
                pass
        if lang == "go" and go_test_pkg_dir is not None:
            try:
                go_test_pkg_dir.rmdir()
            except OSError:
                pass

    verdict, reason = adjudicate(run, lang)
    base.update({
        "verdict": verdict,
        "reason": reason,
        "test_run": run,
        "binding_status": "real-body-authored-and-run",
        "advisory_only": verdict not in NON_ADVISORY_VERDICTS,
    })
    return base


# --------------------------------------------------------------------------
# Top-level routing.
# --------------------------------------------------------------------------

# Verdicts that materialize a non-advisory proof STATUS for the lead.
NON_ADVISORY_VERDICTS = {
    "proof_backed", "refuted", "control-not-clean", "compile-blocked",
    "proof-engine-pending-rust", "proof-engine-pending-go",
}

VERDICT_EXIT = {
    "proof_backed": 0,
    "control-not-clean": 0,
    "compile-blocked": 0,
    "scaffold-only-not-run": 0,
    "proof-engine-pending-rust": 0,
    "proof-engine-pending-go": 0,
    "routed-to-evm-front-door": 0,
    "refuted": 1,
    "error": 2,
}


def route_lead(lead: Dict[str, Any], workspace: Optional[Path],
               out_dir: Optional[Path], do_run: bool,
               harness_file: Optional[str]) -> Dict[str, Any]:
    lang = detect_language(lead.get("harness_family", ""), lead.get("source_refs", []))

    base = {
        "schema": SCHEMA,
        "lead_id": lead.get("lead_id"),
        "harness_family": lead.get("harness_family"),
        "language": lang,
        "file_line": lead.get("file_line"),
        "workspace": str(workspace) if workspace else None,
    }

    if lang == "evm":
        base.update({
            "verdict": "routed-to-evm-front-door",
            "reason": "EVM/Solidity lead - use tools/evm-0day-proof-pipeline.py (the "
                      "existing forge front-door); this tool covers Go + Rust.",
            "advisory_only": False,
        })
        return base
    if lang in ("solana", "unknown"):
        base.update({
            "verdict": "error",
            "reason": f"language '{lang}' is out of scope for this Go+Rust proof path; "
                      f"no automated runnable engine routed.",
            "advisory_only": True,
        })
        return base

    # --- located an existing runnable harness? RUN it for a real verdict. ---
    harness = discover_harness(workspace, lang, harness_file)
    if harness is not None:
        project = find_project_root(harness, lang)
        if project is None:
            base.update({
                "verdict": "compile-blocked",
                "reason": f"harness {harness} has no enclosing "
                          f"{'Cargo.toml' if lang == 'rust' else 'go.mod'} project root.",
                "harness_path": str(harness),
                "advisory_only": False,
            })
            return base
        run = None
        if do_run:
            if lang == "rust":
                run = run_cargo_test(project)
            else:
                run = run_go_test(project)
        verdict, reason = adjudicate(run, lang)
        base.update({
            "verdict": verdict,
            "reason": reason,
            "harness_path": str(harness),
            "project_root": str(project),
            "test_run": run,
            "binding_status": "harness-bound-and-run" if do_run else "harness-located-not-run",
            # advisory_only is True only for a non-terminal not-run with no skeleton.
            "advisory_only": verdict not in NON_ADVISORY_VERDICTS,
        })
        return base

    # --- no pre-authored harness: try to AUTHOR a REAL exploit body for a
    # SHAPE-DETECTABLE class (round-trip / arithmetic / determinism), import the
    # REAL crate/pkg, drive the cited entrypoint, run + adjudicate. This is the
    # Go/Rust parallel to evm-0day-proof-pipeline.py::author_pure_library_proof.
    # It runs BEFORE materialize_skeleton so a shape-detectable lead reaches a
    # real PASS/FAIL instead of an unimplemented!()/t.Skip() skeleton. proof_backed
    # is reachable ONLY through `adjudicate` over an observed real run (R80).
    if workspace is not None:
        lead = dict(lead)
        lead["_do_run"] = do_run
        if lang == "rust":
            authored = author_rust_exploit_proof(lead, workspace, out_dir)
        else:
            authored = author_go_exploit_proof(lead, workspace, out_dir)
        if authored is not None:
            base.update(authored)
            return base
        # else: no genuine real call could be built (fn not pub / not found /
        # non-coercible params / protocol-keyed cosmos) -> honest skeleton below.

    # --- no runnable harness and no auto-authorable shape: materialize a skeleton
    # + honest pending status (NOT proof_backed, R80). ---
    mat = materialize_skeleton(lead, lang, out_dir)
    base.update({
        "verdict": mat["proof_status"],
        "reason": (
            "No runnable harness was located for this lead; a runnable-skeleton harness "
            "was MATERIALIZED so the lead is now proof-attempted (binding pending), not "
            "silently advisory_only. This is NOT proof_backed (R80)."
        ),
        "binding_status": mat["binding_status"],
        "skeleton_path": mat["skeleton_path"],
        "skeleton_inline": mat["skeleton_inline"],
        "obligation": mat["obligation"],
        "advisory_only": False,
    })
    return base


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Go + Rust parallel to the EVM 0-day proof path.")
    ap.add_argument("--harness-family",
                    help="proof_path/harness_family label "
                         "(rust-cargo-test|cargo|forge-rust|cosmos-production|go-test|...)")
    ap.add_argument("--file-line", default="", help="cited <relpath>:<line> for the CUT")
    ap.add_argument("--candidate-json", help="single lead JSON object")
    ap.add_argument("--queue-json", help="exploit_queue*.json; select with --lead-id/--queue-index")
    ap.add_argument("--lead-id")
    ap.add_argument("--queue-index", type=int)
    ap.add_argument("--workspace")
    ap.add_argument("--harness-file", help="explicit path to an authored harness file to run")
    ap.add_argument("--out-dir", help="dir to write a materialized skeleton into")
    ap.add_argument("--out-json")
    ap.add_argument("--no-run", action="store_true", help="locate/skeleton only; do not run tests")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else (
        (workspace / ".auditooor" / "cross_lang_harness") if workspace else None
    )

    try:
        lead = build_lead(args)
    except (ValueError, json.JSONDecodeError, OSError) as e:
        payload = {"schema": SCHEMA, "verdict": "error", "reason": str(e)}
        print(json.dumps(payload, indent=2) if args.json else f"ERROR: {e}")
        return 2

    result = route_lead(lead, workspace, out_dir, do_run=not args.no_run,
                        harness_file=args.harness_file)

    if args.out_json:
        outp = Path(args.out_json).expanduser().resolve()
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(result, indent=2) + "\n")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"language: {result.get('language')}")
        print(f"verdict:  {result['verdict']}")
        print(f"reason:   {result['reason']}")
        if result.get("binding_status"):
            print(f"binding:  {result['binding_status']}")
        if result.get("skeleton_path"):
            print(f"skeleton: {result['skeleton_path']}")
        if result.get("harness_path"):
            print(f"harness:  {result['harness_path']}")

    return VERDICT_EXIT.get(result["verdict"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
