#!/usr/bin/env python3
"""brain-prime — Wave-8 user-facing payoff of brain construction.

Given a (new or existing) engagement workspace, generate a Brain Priming
Report — the artifact a human operator reads to know "where to hunt first"
before dispatching workers.

Pipeline:

  Phase A — Layer-1 MCP recall (10 callables; record context_pack_id/hash)
  Phase B — Scope resolution (--scope-globs OR heuristic auto-detect)
  Phase C — Function signature extraction (Go: full tree-sitter parse;
            Solidity: full tree-sitter via Wave-9; Rust: regex fallback)
  Phase D — Per-function ranker.rank() (in-process import per Wave-7 perf)
  Phase E — Cross-engagement fanout from all prior engagements onto this
            tree
  Phase F — Aggregate, dedupe, emit BRAIN_PRIMING_REPORT.md

Usage:
    python3 tools/brain-prime.py --workspace <ws> [--target-repo OWNER/REPO] \\
        [--language go|rust|solidity|mixed] \\
        [--scope-globs "external/**/protocol/x/**/*.go"] \\
        [--top-functions-per-file 5] \\
        [--min-confidence 0.5] \\
        [--max-files 50] \\
        [--out <ws>/BRAIN_PRIMING_REPORT.md]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
MCP_SERVER = TOOLS_DIR / "vault-mcp-server.py"
RANKER_PY = TOOLS_DIR / "ranker.py"
SIG_EXTRACTOR_PY = TOOLS_DIR / "function-signature-extractor.py"
FANOUT_PY = TOOLS_DIR / "cross-engagement-fanout.py"
ENGAGE_REPORT_PARSER_PY = TOOLS_DIR / "engage-report-parser.py"
RECEIPT_SCHEMA = "auditooor.brain_prime_receipt.v1"
DEFAULT_RECEIPT = ".auditooor/brain_prime_receipt.json"
# Overall wall-clock budget for the ADVISORY cross-engagement fanout (phase_e).
# This is a HANG-BACKSTOP (a destination-tree walk can stall, causing EXIT=124 /
# no receipt), NOT a work-cap we want hit in normal runs: a small budget silently
# truncates legitimate cross-engagement priming (e.g. "1/3 prior engagements
# scanned"). Set generously so all priors are scanned in realistic cases while
# still preventing a true hang. Overridable via --fanout-budget-seconds.
_FANOUT_DEFAULT_BUDGET_S = 600.0


# Promoted Wave-7 Layer-1 callables (per `~/.claude/CLAUDE.md` and
# `tools/auditooor-session-start.sh`).
LAYER1_CALLABLES: List[Tuple[str, Dict[str, Any]]] = [
    ("vault_resume_context", {"limit": 4}),
    ("vault_exploit_context", {"limit": 5}),
    ("vault_knowledge_gap_context", {"limit": 5}),
    ("vault_engagement_status", {}),
    ("vault_harness_context", {"limit": 5}),
    ("vault_outcome_context", {"limit": 5}),
    ("vault_dispatch_context", {"limit": 5}),
    ("vault_goal_state", None),  # no workspace_path
    ("vault_next_loop", None),  # no workspace_path; uses {"limit":5}
    ("vault_llm_calibration", {}),
]


# Map engagement workspace name -> known sibling-repo target_repo prefixes
# (mirrors ENGAGEMENT_REPO_PREFIXES in cross-engagement-fanout.py).
ENGAGEMENT_PREFIXES: Dict[str, List[str]] = {
    "dydx": ["dydxprotocol/", "cosmos/cosmos-sdk", "cosmos/iavl",
             "cometbft/cometbft", "skip-mev/slinky"],
    "spark": ["buildonspark/spark", "lightsparkdev/"],
    "base-azul": ["base-org/azul", "base-org/op-rs"],
    "morpho": ["morpho-org/"],
    "centrifuge-v3": ["centrifuge/"],
    "polymarket": ["polymarket/"],
    "reserve-governor": ["reserve-protocol/"],
    "kiln-v1": ["kiln/"],
    "monetrix": ["monetrix-protocol/"],
    "k2": ["k2-finance/"],
    "thegraph": ["graphprotocol/"],
    "revert-stableswap-hooks": ["revert-finance/"],
    "snowbridge": ["Snowfork/"],
}


# ---------------------------------------------------------------------------
# Module loaders (sibling hyphenated module names need importlib)
# ---------------------------------------------------------------------------


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_ranker():
    return _load_module("brain_prime_ranker", RANKER_PY)


def load_sig_extractor():
    return _load_module("brain_prime_sig", SIG_EXTRACTOR_PY)


def load_fanout():
    return _load_module("brain_prime_fanout", FANOUT_PY)


def load_engage_report_parser():
    return _load_module("brain_prime_engage_parser", ENGAGE_REPORT_PARSER_PY)


# ---------------------------------------------------------------------------
# Phase A: Layer-1 MCP recall
# ---------------------------------------------------------------------------


def phase_a_mcp_recall(workspace: Path,
                       mcp_server: Path = MCP_SERVER,
                       timeout_seconds: float = 30.0) -> Dict[str, Any]:
    """Run the 10 Layer-1 MCP callables. Record context_pack_id+hash from
    vault_resume_context. Failures on individual callables are logged but
    do not crash."""
    out: Dict[str, Any] = {
        "context_pack_id": "",
        "context_pack_hash": "",
        "callables_attempted": 0,
        "callables_succeeded": 0,
        "callables_failed": [],
        "duration_seconds": 0.0,
    }
    if not mcp_server.exists():
        out["error"] = f"MCP server not found at {mcp_server}"
        return out
    t0 = time.time()
    for name, base_args in LAYER1_CALLABLES:
        out["callables_attempted"] += 1
        if base_args is None:
            args_payload: Dict[str, Any] = {}
            if name == "vault_next_loop":
                args_payload = {"limit": 5}
        else:
            args_payload = dict(base_args)
            args_payload["workspace_path"] = str(workspace)
        try:
            res = subprocess.run(
                ["python3", str(mcp_server),
                 "--call", name,
                 "--args", json.dumps(args_payload)],
                capture_output=True, text=True, timeout=timeout_seconds,
            )
            if res.returncode != 0:
                out["callables_failed"].append({
                    "name": name,
                    "stderr": (res.stderr or "")[:200],
                })
                continue
            out["callables_succeeded"] += 1
            if name == "vault_resume_context" and not out["context_pack_id"]:
                stdout = res.stdout or ""
                idx = stdout.find("{")
                if idx >= 0:
                    try:
                        obj = json.loads(stdout[idx:])
                        out["context_pack_id"] = obj.get("context_pack_id", "")
                        out["context_pack_hash"] = obj.get("context_pack_hash", "")
                    except json.JSONDecodeError:
                        pass
        except subprocess.TimeoutExpired:
            out["callables_failed"].append({
                "name": name, "stderr": "timeout"
            })
        except Exception as e:  # pragma: no cover
            out["callables_failed"].append({
                "name": name, "stderr": str(e)[:200]
            })
    out["duration_seconds"] = round(time.time() - t0, 2)
    return out


# ---------------------------------------------------------------------------
# Phase B: Scope resolution
# ---------------------------------------------------------------------------


def _glob_to_re(g: str) -> re.Pattern:
    return re.compile(fnmatch.translate(g))


def heuristic_scope_resolution(
    workspace: Path,
    language: str,
) -> Tuple[str, str, List[str]]:
    """Returns (resolved_language, scope_glob, candidate_dirs).

    Auto-detect strategy:
      - workspace/{external,src}/<*>/protocol/x → cosmos-style Go
      - workspace/{external,src}/<*>/**/*.rs    → Rust
      - workspace/{external,src}/<*>/**/*.sol   → Solidity
    """
    if language and language != "mixed":
        guess = language
    else:
        guess = "go"

    roots = [p for p in (workspace / "external", workspace / "src") if p.exists()]
    if not roots:
        return language or "go", "", []

    def _root_globs(pattern: str) -> List[Path]:
        out: List[Path] = []
        for root in roots:
            out.extend(root.glob(pattern))
        return out

    def _scoped_glob(root_name: str, suffix_glob: str) -> str:
        return f"{root_name}/*/{suffix_glob}"

    # Try Go cosmos style first.
    go_cands = _root_globs("*/protocol/x")
    if go_cands:
        root_names = sorted({p.relative_to(workspace).parts[0] for p in go_cands})
        globs = [_scoped_glob(root, "protocol/x/**/*.go") for root in root_names]
        return "go", ",".join(globs), [str(p) for p in go_cands]
    # Fallback: look for protocol/ directories
    proto_cands = _root_globs("*/protocol")
    if proto_cands:
        root_names = sorted({p.relative_to(workspace).parts[0] for p in proto_cands})
        globs = [_scoped_glob(root, "protocol/**/*.go") for root in root_names]
        return "go", ",".join(globs), [str(p) for p in proto_cands]

    rust_files = _root_globs("**/*.rs")
    sol_files = _root_globs("**/*.sol")
    lang_globs: List[Tuple[str, str, List[Path]]] = []
    if rust_files:
        root_names = sorted({p.relative_to(workspace).parts[0] for p in rust_files})
        lang_globs.append((
            "rust",
            ",".join(_scoped_glob(root, "**/*.rs") for root in root_names),
            rust_files,
        ))
    if sol_files:
        root_names = sorted({p.relative_to(workspace).parts[0] for p in sol_files})
        lang_globs.append((
            "solidity",
            ",".join(_scoped_glob(root, "**/*.sol") for root in root_names),
            sol_files,
        ))

    if len(lang_globs) > 1 and not language:
        return (
            "mixed",
            ",".join(item[1] for item in lang_globs),
            [str(p.parent) for _, _, files in lang_globs for p in files[:10]],
        )
    if lang_globs:
        selected = next((item for item in lang_globs if item[0] == guess), lang_globs[0])
        return selected[0], selected[1], [str(p.parent) for p in selected[2][:20]]

    # Generic fallback: glob the first external repo's tree
    sub = sorted([p for root in roots for p in root.iterdir() if p.is_dir()])
    if sub:
        root_name = sub[0].relative_to(workspace).parts[0]
        return guess, f"{root_name}/{sub[0].name}/**/*", [str(sub[0])]
    return guess, "", []


def phase_b_resolve_scope(
    workspace: Path,
    language: str,
    scope_globs: Optional[str],
) -> Dict[str, Any]:
    if scope_globs:
        return {
            "language": language or "go",
            "scope_globs": scope_globs,
            "auto_detected": False,
            "candidate_dirs": [],
        }
    lang, glob, dirs = heuristic_scope_resolution(workspace, language or "")
    # Apply the SAME production-source filter the lane walk uses (segment-aware), so the
    # candidate_dirs display can't leak a middle non-prod segment (examples/custom-node/src,
    # testdata/testproject/script) - the leaf looked production ("src"/"script") but a middle
    # segment is "examples"/"testdata". iter_scope_files was already clean; this keeps the
    # informational scope field consistent with it.
    def _dir_is_production(d: str) -> bool:
        parts = tuple(p for p in str(d).replace("\\", "/").split("/") if p and p != ".")
        if not parts:
            return True
        return _is_production_source(parts, parts[-1])
    dirs = [d for d in dirs if _dir_is_production(d)]
    return {
        "language": lang,
        "scope_globs": glob,
        "auto_detected": True,
        "candidate_dirs": dirs,
    }


# ---------------------------------------------------------------------------
# Phase C: Function signature extraction
# ---------------------------------------------------------------------------


# Lightweight Rust + Solidity regex fallbacks (operator-eyeball-only quality;
# enough for ranker shape extraction).
RX_RUST_FN = re.compile(
    r"^[\s]*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:<[^>]*>)?\s*"
    r"\(",
    re.MULTILINE,
)

RX_SOL_FN = re.compile(
    r"^\s*function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def _extract_regex(text: str, file_path: str, language: str, rx: re.Pattern
                   ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for m in rx.finditer(text):
        name = m.group("name")
        line = text.count("\n", 0, m.start()) + 1
        out.append({
            "file_path": file_path,
            "language": language,
            "function_name": name,
            "function_signature": f"fn {name}(...)" if language == "rust"
                                  else f"function {name}(...)",
            "receiver_type": None,
            "visibility": ("exported" if (name and name[0].isupper())
                          else "unexported"),
            "line_start": line,
            "line_end": line,
            "modifiers": [],
            "params": [],
            "return_types": [],
            "calls_made": [],
            "guards_detected": [],
        })
    return out


# Path segments that mark NON-PRODUCTION code (tests / examples / mocks /
# fixtures / build artifacts). Mirrors corpus-driven-hunt.SKIP_DIRS so the
# producer (brain-prime) and the consumer (the hunt) agree on what is
# in-scope production code. Brain-prime ranks functions ABOVE the deep
# engines and seeds vault_brain_prime_context / corpus-driven-hunt; if its
# top lanes point at `*/examples/`, `*/testdata/`, `*.semgrep/tests/`, etc.
# (as the optimism receipt did), the hunt burns budget on code that is OUT OF
# SCOPE by the program rubric. We drop any file whose workspace-relative path
# contains one of these segments, or whose name carries a test suffix.
NON_PRODUCTION_DIR_SEGMENTS = frozenset({
    ".git", "node_modules", "lib", "out", "cache", "artifacts", "broadcast",
    "target", "vendor", "third_party", "deps", ".auditooor", "__pycache__",
    "test", "tests", "testdata", "mock", "mocks", "fixtures", "fixture",
    "example", "examples", "testing", "testutil", "testutils",
})

# Directory-SEGMENT suffixes that mark a non-production test-harness package
# (e.g. `op-reth-test-engine`, `foo-tests`, `bar-testutil`). Matched as a
# bounded suffix on a whole segment, NOT a free substring, so legitimate
# production names that merely contain the letters "test" -- `attestation`,
# `contest`, `manifest`, `latest` -- are NOT dropped.
_NON_PRODUCTION_SEG_SUFFIX_RE = re.compile(
    r"(?:[-_](?:test|tests|testing|testutil|testutils|mock|mocks|fixtures?)"
    r"|[-_]test[-_]engine)$",
    re.IGNORECASE,
)

# File-name suffix markers for test files that live alongside production code
# (Go `_test.go`, Solidity `.t.sol` / `.s.sol` scripts, Rust/JS `.test.*`).
_NON_PRODUCTION_NAME_RE = re.compile(
    r"(?:_test\.go|\.t\.sol|\.s\.sol|\.test\.[a-z]+|\.spec\.[a-z]+)$",
    re.IGNORECASE,
)


def _is_production_source(rel_parts: Tuple[str, ...], name: str) -> bool:
    """True when a workspace-relative path is in-scope production source.

    Generic (language-agnostic) filter:
      - reject any path component that EQUALS a known non-production segment;
      - reject any path component that ends with a bounded test-harness suffix
        (e.g. ``op-reth-test-engine``, ``foo-tests``) -- bounded so names that
        merely contain "test" (``attestation``, ``manifest``) survive;
      - reject any file whose name carries a test/script suffix.
    Comparison is case-insensitive.
    """
    for seg in rel_parts:
        low = seg.lower()
        if low in NON_PRODUCTION_DIR_SEGMENTS:
            return False
        if _NON_PRODUCTION_SEG_SUFFIX_RE.search(low):
            return False
    if _NON_PRODUCTION_NAME_RE.search(name):
        return False
    return True


def iter_scope_files(workspace: Path, scope_globs: str,
                     language: str) -> List[Path]:
    """Walk workspace using a recursive glob; supports `**` segments.

    Non-production paths (tests / examples / mocks / fixtures / build
    artifacts) are filtered out so the ranked lanes target in-scope
    production code only (see ``NON_PRODUCTION_DIR_SEGMENTS``)."""
    if not scope_globs:
        return []
    ws_resolved = workspace.resolve()
    candidates: List[Path] = []
    # Allow comma-separated multi-glob inputs
    for g in [s.strip() for s in scope_globs.split(",") if s.strip()]:
        # `Path.glob` understands `**` when used directly
        try:
            for p in workspace.glob(g):
                if not p.is_file():
                    continue
                try:
                    rel_parts = p.resolve().relative_to(ws_resolved).parts
                except ValueError:
                    rel_parts = p.parts
                if not _is_production_source(rel_parts, p.name):
                    continue
                candidates.append(p)
        except (ValueError, OSError):
            continue
    # Dedupe; sort for determinism
    seen = set()
    out: List[Path] = []
    for p in candidates:
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        out.append(p)
    out.sort()
    return out


def phase_c_extract_functions(
    workspace: Path,
    scope_files: List[Path],
    language: str,
    max_files: int,
    sig_mod,
) -> List[Dict[str, Any]]:
    """Returns a flat list of function records, each annotated with
    file_path (workspace-relative)."""
    out: List[Dict[str, Any]] = []
    files_processed = 0
    for fp in scope_files:
        if max_files and files_processed >= max_files:
            break
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(fp.resolve().relative_to(workspace.resolve()))
        except ValueError:
            rel = str(fp)
        if language == "go" or fp.suffix == ".go":
            recs = sig_mod.extract_go_functions(text, rel)
        elif language == "rust" or fp.suffix == ".rs":
            recs = _extract_regex(text, rel, "rust", RX_RUST_FN)
        elif language == "solidity" or fp.suffix == ".sol":
            # Wave-9: use tree-sitter-solidity if available via the sig-extractor.
            if hasattr(sig_mod, "extract_solidity_functions"):
                recs = sig_mod.extract_solidity_functions(text, rel)
            else:
                recs = _extract_regex(text, rel, "solidity", RX_SOL_FN)
        else:
            continue
        out.extend(recs)
        files_processed += 1
    return out


# ---------------------------------------------------------------------------
# Phase D: Per-function ranker.rank()
# ---------------------------------------------------------------------------


def phase_d_rank_functions(
    fn_records: List[Dict[str, Any]],
    target_repo: str,
    audit_pin: Optional[str],
    workspace_path: Path,
    top_functions_per_file: int,
    min_confidence: float,
    ranker_mod,
    workspace_engage_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """For each file's top-N functions, call ranker.rank() in-process.

    Wave-9: when workspace_engage_report is provided (parsed engage_report.md),
    it is threaded into ranker.rank() as the S6 grounding input.  This causes
    functions whose file+line range overlaps a mechanical detector hit to
    receive an S6 boost proportional to that detector's severity.

    Returns: {file_path: [ {function_name, line_start, shape_hash,
                            ranked_attack_classes: [...],
                            s6_boost: bool}, ... ]}
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for r in fn_records:
        by_file.setdefault(r["file_path"], []).append(r)
    # Disable prediction log writes during brain-prime (we're not training)
    prev_disabled = os.environ.get("RANKER_PREDICTION_LOG_DISABLED")
    os.environ["RANKER_PREDICTION_LOG_DISABLED"] = "1"
    try:
        results: Dict[str, List[Dict[str, Any]]] = {}
        for fpath, fns in sorted(by_file.items()):
            # Prioritize exported / handler-like functions first
            fns_sorted = sorted(
                fns,
                key=lambda r: (
                    0 if r.get("visibility") == "exported" else 1,
                    0 if r.get("function_name", "").startswith(
                        ("Handle", "Msg", "Register", "Update", "Set",
                         "Process", "Execute", "Withdraw", "Deposit",
                         "Transfer", "Mint", "Burn", "Validate")) else 1,
                    r.get("line_start", 0),
                ),
            )
            picked = fns_sorted[: top_functions_per_file]
            out_rows: List[Dict[str, Any]] = []
            for rec in picked:
                try:
                    rr = ranker_mod.rank(
                        target_repo=target_repo,
                        file_path=rec["file_path"],
                        function_signature=rec.get("function_signature", ""),
                        audit_pin_sha=audit_pin,
                        top_n=5,
                        min_confidence=min_confidence,
                        workspace_path=str(workspace_path),
                        workspace_engage_report=workspace_engage_report or None,
                        target_line_start=rec.get("line_start", 0),
                        target_line_end=rec.get("line_end", rec.get("line_start", 0)),
                    )
                    # Detect whether S6 fired for this function
                    s6_fired = any(
                        e.get("scorer") == "S6"
                        for ac in rr.ranked_attack_classes
                        for e in ac.get("evidence", [])
                    )
                    out_rows.append({
                        "function_name": rec.get("function_name", ""),
                        "function_signature": rec.get("function_signature", ""),
                        "line_start": rec.get("line_start", 0),
                        "visibility": rec.get("visibility", ""),
                        "shape_hash": rr.target.get("shape_hash", ""),
                        "ranked_attack_classes": rr.ranked_attack_classes,
                        "s6_boost": s6_fired,
                    })
                except Exception as e:  # pragma: no cover
                    out_rows.append({
                        "function_name": rec.get("function_name", ""),
                        "function_signature": rec.get("function_signature", ""),
                        "line_start": rec.get("line_start", 0),
                        "shape_hash": "",
                        "ranked_attack_classes": [],
                        "s6_boost": False,
                        "error": str(e)[:200],
                    })
            if out_rows:
                results[fpath] = out_rows
        return results
    finally:
        if prev_disabled is None:
            os.environ.pop("RANKER_PREDICTION_LOG_DISABLED", None)
        else:
            os.environ["RANKER_PREDICTION_LOG_DISABLED"] = prev_disabled


# ---------------------------------------------------------------------------
# Phase E.1: Apply mimo-observed yield priors to ranked attack classes
# r36-rebuttal: lane mega-learn-2026-05-28 pathspec-registered
# ---------------------------------------------------------------------------
#
# Wave mega-learn-2026-05-28: consume per-workspace brain_prime_priors_<ws>.json
# emitted by tools/mimo-corpus-miner.py. The priors file lists AUTO-BOOST and
# AUTO-DEPRIORITIZE cells (attack_class -> boost/penalty score) derived from
# observed MIMO yield. Phase E.1 walks each function's ranked_attack_classes
# and adjusts confidence scores accordingly, then re-sorts. This closes the
# learning loop: MIMO mining results directly shape the next brain-priming
# ranker output, so high-yield classes per workspace are surfaced first.


def phase_e1_apply_mimo_priors(
    phase_d_results: Dict[str, List[Dict[str, Any]]],
    workspace: Path,
) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Post-process phase_d ranked attack classes using mimo-observed priors.

    Reads audit/corpus_tags/derived/brain_prime_priors_<workspace_slug>.json.
    If absent, returns phase_d unchanged + empty summary.

    Adjustment rule:
      - confidence += boost_score / 10  (boost_score is yes_rate * 10, so
        a 10% YES rate adds +0.1 to confidence; 30% adds +0.3)
      - confidence += penalty_score / 10  (penalty_score is -3.0, so adds -0.3)
    Each adjusted entry gets `mimo_prior_applied: True` and a
    `mimo_prior_delta` field carrying the score delta.
    """
    # r36-rebuttal: lane mega-learn-2026-05-28 use REPO_ROOT not AUDITOOOR_ROOT
    workspace_slug = workspace.name
    # Try a few slug variants (workspace.name, lowercased)
    derived = REPO_ROOT / "audit" / "corpus_tags" / "derived"
    candidates = [
        derived / f"brain_prime_priors_{workspace_slug}.json",
        derived / f"brain_prime_priors_{workspace_slug.lower()}.json",
    ]
    priors_path = next((p for p in candidates if p.exists()), None)
    if priors_path is None:
        return phase_d_results, {
            "phase_e1": "skipped",
            "reason": f"no priors file at {candidates[0]}",
            "boosts_applied": 0,
            "deprios_applied": 0,
            "functions_touched": 0,
        }
    try:
        priors = json.loads(priors_path.read_text(encoding="utf-8"))
    except Exception as e:
        return phase_d_results, {
            "phase_e1": "skipped",
            "reason": f"priors parse fail: {e}",
            "boosts_applied": 0,
            "deprios_applied": 0,
            "functions_touched": 0,
        }
    boost_map = {c["attack_class"].lower(): c["boost_score"]
                 for c in priors.get("auto_boost_cells", [])}
    deprio_map = {c["attack_class"].lower(): c["penalty_score"]
                  for c in priors.get("auto_deprioritize_cells", [])}
    boosts = 0
    deprios = 0
    fns_touched = 0
    out: Dict[str, List[Dict[str, Any]]] = {}
    for fpath, fns in phase_d_results.items():
        out[fpath] = []
        for fn in fns:
            new_fn = dict(fn)
            classes = new_fn.get("ranked_attack_classes", [])
            new_classes = []
            touched_here = False
            for ac in classes:
                new_ac = dict(ac)
                klass = (new_ac.get("attack_class") or "").lower()
                delta = 0.0
                if klass in boost_map:
                    delta = boost_map[klass] / 10.0
                    boosts += 1
                    touched_here = True
                elif klass in deprio_map:
                    delta = deprio_map[klass] / 10.0  # negative
                    deprios += 1
                    touched_here = True
                if delta != 0:
                    conf = new_ac.get("confidence", 0.0) or 0.0
                    new_ac["confidence"] = round(float(conf) + delta, 4)
                    new_ac["mimo_prior_applied"] = True
                    new_ac["mimo_prior_delta"] = round(delta, 4)
                new_classes.append(new_ac)
            # Re-sort by confidence desc
            new_classes.sort(key=lambda a: -(a.get("confidence") or 0.0))
            new_fn["ranked_attack_classes"] = new_classes
            if touched_here:
                # r36-rebuttal: lane mega-learn-2026-05-28 use REPO_ROOT
                new_fn["mimo_prior_summary"] = {
                    "priors_file": str(priors_path.relative_to(REPO_ROOT)),
                }
                fns_touched += 1
            out[fpath].append(new_fn)
    return out, {
        "phase_e1": "applied",
        # r36-rebuttal: lane mega-learn-2026-05-28 use REPO_ROOT
        "priors_file": str(priors_path.relative_to(REPO_ROOT)),
        "boost_map_size": len(boost_map),
        "deprio_map_size": len(deprio_map),
        "boosts_applied": boosts,
        "deprios_applied": deprios,
        "functions_touched": fns_touched,
    }


# ---------------------------------------------------------------------------
# Phase E: Cross-engagement fanout
# ---------------------------------------------------------------------------


def list_prior_engagements(this_engagement: str) -> List[str]:
    """Identify prior engagement slugs by scanning corpus_tags/tags/.

    r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json

    Only CANONICAL engagement slugs (the keys of ``ENGAGEMENT_PREFIXES``) are
    returned. Tag filenames are noisy (``<engagement>_<id>.yaml``,
    ``hackerman_*``, ``mimo_*``, opaque hashes), and a naive ``stem.split('_')[0]``
    produces ~19,805 bogus "engagements" - each of which would trigger a full
    cross-engagement fanout walk. Restricting to known engagement prefixes keeps
    the fanout bounded to real prior engagements.
    """
    if not TAGS_DIR.exists():
        return []
    seen: set = set()
    out: List[str] = []
    for f in sorted(TAGS_DIR.glob("*.yaml")):
        stem = f.stem
        slug = stem.split("_")[0]
        # Map filename variants to canonical engagement slugs. A slug that does
        # not match any known engagement prefix is dropped (not a real prior
        # engagement) rather than admitted as a synthetic slug.
        canonical_match: Optional[str] = None
        for canonical in ENGAGEMENT_PREFIXES.keys():
            if slug == canonical or slug.startswith(canonical):
                canonical_match = canonical
                break
        if canonical_match is None:
            continue
        slug = canonical_match
        if slug == this_engagement or not slug:
            continue
        if slug not in seen:
            seen.add(slug)
            out.append(slug)
    return out


def _resolve_fanout_dest_roots(
    workspace: Path,
    dest_globs: Optional[str],
) -> List[Path]:
    """Resolve the destination roots the fanout should scan.

    r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json

    When ``dest_globs`` (comma-separated, workspace-relative) is supplied, the
    fanout scans only the matching subtrees instead of the entire ``external/``
    tree. This is what bounds the walk on large monorepo workspaces. Falls back
    to ``workspace/external`` when no glob is given or no glob matches.
    """
    if dest_globs:
        roots: List[Path] = []
        seen: set = set()
        for g in [s.strip() for s in dest_globs.split(",") if s.strip()]:
            try:
                for p in workspace.glob(g):
                    # For file-globs use the containing dir; for dir-globs use it directly.
                    root = p if p.is_dir() else p.parent
                    rp = root.resolve()
                    if rp not in seen:
                        seen.add(rp)
                        roots.append(root)
            except (ValueError, OSError):
                continue
        if roots:
            return roots
    dest_external = workspace / "external"
    return [dest_external] if dest_external.exists() else []


def phase_e_fanout(
    this_engagement: str,
    workspace: Path,
    fanout_mod,
    top_n: int = 10,
    audits_root: Optional[Path] = None,
    max_dest_files: Optional[int] = None,
    budget_seconds: Optional[float] = None,
    dest_globs: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Run cross-engagement-fanout from every prior engagement onto this
    workspace's external/ tree. Returns {source_engagement: [match_dicts...]}.

    r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json

    ``max_dest_files`` / ``budget_seconds`` bound each destination walk so a
    large monorepo ``external/`` tree degrades gracefully instead of spinning a
    core at 100% CPU. ``dest_globs`` restricts the walk to scoped subtrees.
    """
    out: Dict[str, List[Dict[str, Any]]] = {}
    priors = list_prior_engagements(this_engagement)
    dest_roots = _resolve_fanout_dest_roots(workspace, dest_globs)
    if not dest_roots:
        return out
    # Overall wall-clock deadline. The fanout is ADVISORY enrichment; it must
    # NEVER hang the (load-bearing) receipt/report write that follows it. Without
    # a bound it spins unbounded on two axes - the number of prior engagements
    # and a large destination tree (e.g. a vendored dependencies/ subtree when
    # the scope glob is empty) - which is exactly what timed brain-prime out on
    # hyperlane (EXIT=124, no receipt). budget_seconds, when provided, bounds the
    # WHOLE phase; otherwise a sane default applies. Each per-root scan is handed
    # the REMAINING budget so a single walk cannot blow the deadline either.
    overall_budget = (
        budget_seconds
        if (budget_seconds and budget_seconds > 0)
        else _FANOUT_DEFAULT_BUDGET_S
    )
    deadline = time.monotonic() + overall_budget
    truncated = False
    for src in priors:
        if time.monotonic() >= deadline:
            truncated = True
            break
        try:
            patterns = fanout_mod.load_source_patterns(src)
            if not patterns:
                continue
            src_matches: List[Dict[str, Any]] = []
            for dest_root in dest_roots:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    truncated = True
                    break
                matches = fanout_mod.scan_destination(
                    patterns, dest_root, top_n=top_n,
                    max_dest_files=max_dest_files,
                    budget_seconds=remaining,
                )
                src_matches.extend(m.as_dict() for m in matches)
            if src_matches:
                out[src] = src_matches
        except Exception as e:  # pragma: no cover
            out[src] = [{"error": str(e)[:200]}]
    if truncated:
        sys.stderr.write(
            f"[brain-prime] phase_e fanout truncated at overall budget "
            f"{overall_budget:.0f}s ({len(out)}/{len(priors)} prior engagement(s) "
            f"scanned); advisory enrichment partial, receipt write continues\n"
        )
    return out


# ---------------------------------------------------------------------------
# Phase F: Report rendering
# ---------------------------------------------------------------------------


def _guess_engagement_slug(workspace: Path) -> str:
    return workspace.name


def _extract_audit_pin(workspace: Path) -> str:
    """Pull the CURRENT audit-pin SHA from SCOPE.md / INTAKE_BASELINE.md /
    handoff + bootstrap docs.

    Resolution order is deliberate so the receipt always tracks the LIVE pin:

      1. The canonical ``PINNED COMMIT: `<sha>``` token (the format the
         bootstrap / re-pin step writes into SCOPE.md). This is the source of
         truth and is matched FIRST, across every candidate file.
      2. An explicit ``audit-pin`` / ``audit pin`` label followed by a SHA.
      3. A bare 40-hex SHA as a last resort.

    Earlier the tool tried (2)-as-regex then fell back to (3) per-file, where
    (3) grabs the FIRST 40-hex run in the file. When a re-pin leaves a stale
    history note (e.g. "was 7338e072 -> a5cfcc2c -> 56975322") OR an old full
    SHA appears textually above the live pin, the bare-SHA fallback silently
    returned the WRONG (stale) commit -- which is exactly how the optimism
    receipt stayed pinned to 7338e072 after SCOPE.md was re-pinned to
    56975322. Preferring the explicit ``PINNED COMMIT:`` token (scanned across
    all candidate files before any weaker pattern) makes re-pins
    authoritative.
    """
    candidate_files: List[Path] = []
    for fname in ("INTAKE_BASELINE.md", "SCOPE.md"):
        p = workspace / fname
        if p.exists():
            candidate_files.append(p)
    # Add any HANDOFF_*.md / BOOTSTRAP_*.md / README.md
    for pat in ("HANDOFF_*.md", "BOOTSTRAP_*.md", "README.md"):
        candidate_files.extend(sorted(workspace.glob(pat)))
    texts: List[str] = []
    for p in candidate_files:
        try:
            texts.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    # Highest-priority pattern first, and each pattern is scanned across ALL
    # files before the next (weaker) pattern is tried -- so a canonical
    # PINNED COMMIT in SCOPE.md wins over a bare SHA in any other file.
    rx_pinned_commit = re.compile(
        r"pinned\s+commit[^a-f0-9]*`?\s*([a-f0-9]{8,40})", re.IGNORECASE)
    rx_audit_pin = re.compile(
        r"audit[- _]?pin[^a-f0-9]*`?\s*([a-f0-9]{8,40})", re.IGNORECASE)
    rx_bare_sha = re.compile(r"\b([a-f0-9]{40})\b")
    for rx in (rx_pinned_commit, rx_audit_pin, rx_bare_sha):
        for text in texts:
            m = rx.search(text)
            if m:
                return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# Phase F — component-aware (architectural) lanes from the system model
# ---------------------------------------------------------------------------
#
# V3 workflow gap #4 (Sei field run, Lane-L gap): brain-prime ranks functions
# by detector confidence and proposes lanes from THAT shape signal only. On the
# Sei L1 it proposed `timestamp-manipulation` / `deadline-bypass` /
# `goroutine-deadlock` / `state-change-between-check-and-use` /
# `channel-send-blocked-forever` — all generic detector-shape lanes. None named
# the architectural Critical surfaces the productive hunt actually covered
# (custom EVM precompiles, the EVM<->Cosmos bank bridge, OCC parallel-execution
# nondeterminism, pointer contracts). brain-prime is COMPONENT-BLIND: it sees
# detector hits, not the system's components / trust-boundaries / value-flows.
#
# Fix: when `<ws>/.auditooor/system_model.json` exists (emitted by Lane-L's
# `tools/system-model.py`), Phase F ALSO proposes architectural lanes — one per
# high-value component / trust-boundary / value-flow — and ranks them ABOVE the
# detector-shape lanes. This is ADDITIVE; the detector-shape lanes are kept.

SYSTEM_MODEL_PY = TOOLS_DIR / "system-model.py"


def load_system_model_for_workspace(workspace: Path) -> Optional[Dict[str, Any]]:
    """Load `<ws>/.auditooor/system_model.json` (Lane-L artifact) if present
    and well-formed. Returns None when absent / unreadable / wrong schema —
    callers must keep the no-system-model path working without crashing."""
    path = workspace / ".auditooor" / "system_model.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("schema") != "auditooor.system_model.v1":
        return None
    return data


# Heuristic high-value-component keywords. A component whose path/name/
# responsibility matches one of these is treated as a direct-loss / trust-
# boundary surface and gets an architectural lane. Keyword -> short rationale.
_HIGH_VALUE_COMPONENT_HINTS: List[Tuple[str, str]] = [
    ("precompile", "custom precompile — direct EVM<->host trust boundary"),
    ("bridge", "cross-domain bridge — value-conservation surface"),
    ("bank", "bank / balance module — direct-loss surface"),
    ("vault", "vault / custody — direct-loss surface"),
    ("escrow", "escrow custody — direct-loss surface"),
    ("oracle", "oracle ingestion — trusted-input boundary"),
    ("evm", "EVM execution surface — composition / nondeterminism risk"),
    ("occ", "optimistic concurrency — parallel-execution nondeterminism"),
    ("parallel", "parallel execution — nondeterminism / ordering risk"),
    ("staking", "staking / slashing — economic-invariant surface"),
    ("gov", "governance — privilege-escalation surface"),
    ("mint", "mint / burn — supply-conservation surface"),
    ("pointer", "pointer contract — cross-VM aliasing surface"),
    ("transfer", "transfer path — value-flow surface"),
    ("token", "token module — value-conservation surface"),
    ("settlement", "settlement path — value-flow surface"),
    ("withdraw", "withdrawal path — egress / direct-loss surface"),
]


def _component_text(comp: Dict[str, Any]) -> str:
    parts = [
        str(comp.get("name", "")),
        str(comp.get("path", "")),
    ]
    resp = comp.get("responsibility")
    if isinstance(resp, str):
        parts.append(resp)
    return " ".join(parts).lower()


def _propose_architectural_lanes(
    system_model: Dict[str, Any],
    max_lanes: int = 8,
) -> List[Dict[str, Any]]:
    """Derive architectural hunt lanes from the Lane-L system model.

    One lane per high-value component, trust-boundary, value-flow, privileged
    role, and protocol-owned-defense family. Every lane cites the system-model
    section it came from and carries `lane_kind="architectural"`.
    """
    lanes: List[Dict[str, Any]] = []
    seen_keys: set = set()

    def _add(lane_id_kind: str, attack_class: str, component: str,
             model_section: str, rationale: str, detail: Dict[str, Any]) -> None:
        key = (model_section, attack_class)
        if key in seen_keys:
            return
        seen_keys.add(key)
        lanes.append({
            "attack_class": attack_class,
            "lane_kind": "architectural",
            "model_section": model_section,
            "component": component,
            "rationale": rationale,
            "detail": detail,
        })

    # 1. High-value components.
    components = system_model.get("components")
    if isinstance(components, list):
        for comp in components:
            if not isinstance(comp, dict):
                continue
            # Skip non-production components (e.g. *_test.go, .t.sol, fixtures,
            # mocks) so a component lane is never proposed over test/script
            # source. Consumer-side filter, consistent with iter_scope_files;
            # the upstream producer (tools/system-model.py) also emits these.
            _p = comp.get("path") or comp.get("name") or ""
            _parts = tuple(
                seg for seg in str(_p).replace("\\", "/").split("/")
                if seg and seg != "."
            ) if _p else ()
            _name = _parts[-1] if _parts else str(comp.get("name", ""))
            if not _is_production_source(_parts, _name):
                continue
            blob = _component_text(comp)
            for kw, rationale in _HIGH_VALUE_COMPONENT_HINTS:
                if kw in blob:
                    cpath = str(comp.get("path", comp.get("name", "?")))
                    _add(
                        "component", f"component: {cpath}", cpath,
                        "components", rationale,
                        {"language": comp.get("language", ""),
                         "loc": comp.get("loc", 0),
                         "responsibility": comp.get("responsibility", "")},
                    )
                    break  # one lane per component

    # 2. Value flows (asset ingress/egress) — the value-conservation surface.
    flows = system_model.get("asset_value_flows")
    if isinstance(flows, dict):
        ingress = flows.get("ingress_signal_paths") or []
        egress = flows.get("egress_signal_paths") or []
        if ingress or egress:
            _add(
                "value-flow", "value-flow: asset ingress/egress conservation",
                "asset_value_flows", "value-flow",
                "funds enter at ingress paths and exit at egress paths; "
                "verify total-in == total-out value conservation",
                {"ingress_paths": list(ingress)[:12],
                 "egress_paths": list(egress)[:12]},
            )

    # 3. Trust boundaries — caller assumes callee already validated X.
    tb = system_model.get("trust_boundaries")
    # When the system-model still carries the typed review placeholder, surface
    # it as a single "draw the trust boundaries" lane; when an operator/agent
    # has filled it with concrete boundaries, emit one lane per boundary.
    if isinstance(tb, list):
        for b in tb:
            if not isinstance(b, dict):
                continue
            label = str(b.get("name") or b.get("boundary") or
                        b.get("caller") or "trust boundary")
            _add(
                "trust-boundary", f"trust-boundary: {label}",
                label, "trust_boundaries",
                "caller-side component assumes the callee already validated "
                "an input — verify the assumption holds",
                {"boundary": b},
            )
    elif isinstance(tb, dict) and tb.get("status") == "needs_operator_or_agent_review":
        _add(
            "trust-boundary",
            "trust-boundary: cross-component validation assumptions",
            "trust_boundaries", "trust_boundaries",
            "system model flags trust boundaries as unreviewed — enumerate "
            "every cross-component call and state what the caller assumes",
            {"review": tb},
        )

    # 4. Privileged roles — privilege-escalation surface.
    roles = system_model.get("privileged_roles")
    if isinstance(roles, list):
        for role in roles[:6]:
            if not isinstance(role, dict):
                continue
            rname = str(role.get("role", "?"))
            _add(
                "privileged-role", f"privileged-role: {rname}",
                rname, "privileged_roles",
                "privileged role — verify access control cannot be bypassed "
                "and the role's capabilities cannot be abused",
                {"declared_in": role.get("declared_in", [])},
            )

    # 5. Protocol-owned defenses — Rule-14 opposed-trace surface.
    defenses = system_model.get("protocol_owned_defenses")
    if isinstance(defenses, list):
        for d in defenses[:6]:
            if not isinstance(d, dict):
                continue
            fam = str(d.get("family", "?"))
            _add(
                "protocol-defense", f"protocol-defense: {fam}",
                fam, "protocol_owned_defenses",
                "protocol-owned defense family — verify the defense path "
                "actually fires under the attack it is meant to stop",
                {"source_signal_paths": d.get("source_signal_paths", [])},
            )

    return lanes[:max_lanes]


def _propose_hunt_lanes(
    phase_d: Dict[str, List[Dict[str, Any]]],
    phase_e: Dict[str, List[Dict[str, Any]]],
    max_lanes: int = 8,
    system_model: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Cluster phase-D ranker hits + phase-E fanout candidates into proposed
    hunt lanes, grouped by attack_class / bug_class.

    Lane-L wiring (V3 gap #4 fix): when `system_model` is provided, COMPONENT-
    AWARE architectural lanes are derived from the component map / value-flows /
    trust-boundaries / privileged-roles / protocol-defenses and ranked ABOVE the
    detector-shape lanes. Every lane carries a `lane_kind` field
    (`architectural` vs `detector_shape`). Detector-shape lanes are kept (this
    is ADDITIVE). When `system_model` is None, behavior is unchanged except all
    lanes are tagged `lane_kind="detector_shape"`.
    """
    # Aggregate by attack_class
    by_ac: Dict[str, Dict[str, Any]] = {}
    for fpath, fns in phase_d.items():
        for fn in fns:
            for ac in fn.get("ranked_attack_classes", []):
                ac_name = ac.get("attack_class", "")
                if not ac_name:
                    continue
                slot = by_ac.setdefault(ac_name, {
                    "attack_class": ac_name,
                    "phase_d_hits": [],
                    "phase_e_hits": [],
                    "max_confidence": 0.0,
                })
                slot["phase_d_hits"].append({
                    "file": fpath,
                    "function": fn.get("function_name", ""),
                    "line": fn.get("line_start", 0),
                    "confidence": ac.get("confidence", 0.0),
                })
                slot["max_confidence"] = max(slot["max_confidence"],
                                             float(ac.get("confidence", 0.0)))
    # Also fold fanout hits in by their bug_class
    for src, matches in phase_e.items():
        for m in matches:
            if "error" in m:
                continue
            bc = m.get("bug_class", "") or "unknown"
            slot = by_ac.setdefault(f"fanout::{bc}", {
                "attack_class": bc,
                "phase_d_hits": [],
                "phase_e_hits": [],
                "max_confidence": 0.0,
            })
            slot["phase_e_hits"].append({
                "source": src,
                "score": m.get("score", 0.0),
                "dest_file": m.get("dest_file", ""),
                "fn": m.get("matched_function", ""),
                "pattern_slug": m.get("pattern_slug", ""),
            })
            # Treat fanout score as a confidence proxy when no Phase-D hits
            slot["max_confidence"] = max(
                slot["max_confidence"],
                float(m.get("score", 0.0))
            )
    # Rank: prefer lanes with both phase-D and phase-E provenance (signal
    # convergence), then by max_confidence
    ranked = sorted(
        by_ac.values(),
        key=lambda s: (
            -(1 if s["phase_d_hits"] and s["phase_e_hits"] else 0),
            -s["max_confidence"],
            -(len(s["phase_d_hits"]) + len(s["phase_e_hits"])),
        ),
    )
    # Map confidence -> severity heuristic
    def _severity(conf: float) -> str:
        if conf >= 0.75:
            return "CRITICAL/HIGH (confidence ≥0.75)"
        if conf >= 0.55:
            return "HIGH (confidence ≥0.55)"
        if conf >= 0.40:
            return "MEDIUM/HIGH (confidence ≥0.40)"
        return "MEDIUM-or-below (operator eyeball)"
    detector_lanes: List[Dict[str, Any]] = []
    for s in ranked[:max_lanes]:
        provenance_parts = []
        if s["phase_d_hits"]:
            provenance_parts.append(f"Phase-D ranker ({len(s['phase_d_hits'])} hits)")
        if s["phase_e_hits"]:
            sources = sorted({h["source"] for h in s["phase_e_hits"]})
            provenance_parts.append(
                f"Phase-E A6 fanout (sources={','.join(sources)}, "
                f"hits={len(s['phase_e_hits'])})"
            )
        detector_lanes.append({
            "attack_class": s["attack_class"],
            "lane_kind": "detector_shape",
            "max_confidence": round(s["max_confidence"], 3),
            "severity_guess": _severity(s["max_confidence"]),
            "provenance": " + ".join(provenance_parts) or "none",
            "phase_d_hits": s["phase_d_hits"][:8],
            "phase_e_hits": s["phase_e_hits"][:5],
        })

    # Lane-L wiring: architectural (component-aware) lanes rank ABOVE the
    # detector-shape lanes. The Sei field run showed the productive Critical
    # surfaces (precompiles, EVM<->Cosmos bank bridge, OCC nondeterminism,
    # pointer contracts) are architectural and never surface as detector
    # shapes — so they lead the recommended-lanes list.
    architectural_lanes: List[Dict[str, Any]] = []
    if system_model is not None:
        architectural_lanes = _propose_architectural_lanes(
            system_model, max_lanes=max_lanes
        )
        for lane in architectural_lanes:
            # Architectural lanes carry no detector confidence; severity is an
            # operator-eyeball judgement against the rubric.
            lane.setdefault("max_confidence", 0.0)
            lane.setdefault(
                "severity_guess",
                "architectural — operator eyeball vs rubric (no detector score)",
            )
            lane.setdefault(
                "provenance",
                f"Lane-L system_model.json :: {lane.get('model_section', '?')}",
            )
            lane.setdefault("phase_d_hits", [])
            lane.setdefault("phase_e_hits", [])

    # Architectural lanes lead; detector-shape lanes follow. Total still capped
    # at max_lanes so the report stays operator-readable.
    merged = (architectural_lanes + detector_lanes)[:max_lanes]
    lanes: List[Dict[str, Any]] = []
    for i, lane in enumerate(merged, 1):
        lane = dict(lane)
        lane["lane_id"] = f"LANE-H{i}"
        lane.setdefault("lane_kind", "detector_shape")
        lanes.append(lane)
    return lanes


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(obj: Any) -> str:
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _corpus_tag_hash() -> str:
    if not TAGS_DIR.is_dir():
        return ""
    # Keep receipt emission cheap. The tags/ fanout can contain tens of
    # thousands of YAML records; brain-prime already does heavy ranking work, so
    # this receipt fingerprint tracks corpus index/derived metadata instead of
    # re-hashing every tag body on each run.
    digest = hashlib.sha256()
    roots = [
        TAGS_DIR / "index",
        TAGS_DIR / "derived",
        TAGS_DIR / "schemas",
    ]
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            try:
                stat = path.stat()
            except OSError:
                digest.update(path.relative_to(TAGS_DIR).as_posix().encode("utf-8"))
                digest.update(b":unreadable\0")
                continue
            digest.update(path.relative_to(TAGS_DIR).as_posix().encode("utf-8"))
            digest.update(f":{stat.st_size}:{stat.st_mtime_ns}".encode("ascii"))
            digest.update(b"\0")
    for path in sorted(TAGS_DIR.glob("*.yaml")):
        try:
            stat = path.stat()
        except OSError:
            digest.update(path.name.encode("utf-8"))
            digest.update(b":unreadable\0")
            continue
        digest.update(path.name.encode("utf-8"))
        digest.update(f":{stat.st_size}:{stat.st_mtime_ns}".encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def build_brain_prime_receipt(
    *,
    workspace: Path,
    engagement: str,
    report_path: Path,
    report_text: str,
    audit_pin: str,
    target_repo: str,
    phase_a: Dict[str, Any],
    scope: Dict[str, Any],
    functions_extracted: int,
    phase_d_files: int,
    phase_e_sources: int,
    phase_f: List[Dict[str, Any]],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    generated_at = (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    scope_globs = str(scope.get("scope_globs", ""))
    top_lanes = [
        {
            "lane_id": lane.get("lane_id", ""),
            "attack_class": lane.get("attack_class", ""),
            "lane_kind": lane.get("lane_kind", "detector_shape"),
            "model_section": lane.get("model_section", ""),
            "max_confidence": lane.get("max_confidence", 0),
            "severity_guess": lane.get("severity_guess", ""),
            "provenance": lane.get("provenance", ""),
        }
        for lane in phase_f[:8]
    ]
    return {
        "schema": RECEIPT_SCHEMA,
        "generated_at": generated_at,
        "generated_ts": time.time(),
        "tool": "tools/brain-prime.py",
        "workspace_path": str(workspace),
        "engagement": engagement,
        "audit_pin": audit_pin or "",
        "target_repo": target_repo or "",
        "report_path": str(report_path),
        "report_sha256": _sha256_text(report_text),
        "report_mtime_epoch": report_path.stat().st_mtime if report_path.exists() else 0,
        "scope_globs": scope_globs,
        "scope_globs_hash": _sha256_text(scope_globs),
        "scope": {
            "language": scope.get("language", ""),
            "auto_detected": bool(scope.get("auto_detected", False)),
            "candidate_dirs": list(scope.get("candidate_dirs", []))[:20],
        },
        "corpus_tag_hash": _corpus_tag_hash(),
        "context_pack_id": phase_a.get("context_pack_id", ""),
        "context_pack_hash": phase_a.get("context_pack_hash", ""),
        "mcp": {
            "skipped": bool(phase_a.get("skipped", False)),
            "callables_attempted": int(phase_a.get("callables_attempted", 0) or 0),
            "callables_succeeded": int(phase_a.get("callables_succeeded", 0) or 0),
            "callables_failed": list(phase_a.get("callables_failed", [])),
            "duration_seconds": phase_a.get("duration_seconds", 0),
        },
        "summary": {
            "functions_extracted": functions_extracted,
            "phase_d_files": phase_d_files,
            "phase_e_sources": phase_e_sources,
            "phase_f_lanes": len(phase_f),
            "strict_ready": (
                not bool(phase_a.get("skipped", False))
                and bool(phase_a.get("context_pack_id"))
                and bool(phase_a.get("context_pack_hash"))
                and len(phase_f) > 0
            ),
            "top_functions_per_file": args.top_functions_per_file,
            "min_confidence": args.min_confidence,
            "max_files": args.max_files,
        },
        "top_phase_f_lanes": top_lanes,
    }


def write_brain_prime_receipt(
    workspace: Path,
    receipt: Dict[str, Any],
    out_path: Path | None = None,
) -> Path:
    path = out_path or workspace / DEFAULT_RECEIPT
    path.parent.mkdir(parents=True, exist_ok=True)
    receipt = dict(receipt)
    receipt["receipt_hash"] = _sha256_json(
        {k: v for k, v in receipt.items() if k != "receipt_hash"}
    )
    path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def validate_receipt_strict_ready(receipt_path: Path | str | None) -> Tuple[bool, str]:
    if not receipt_path:
        return False, "missing receipt_path"
    path = Path(receipt_path)
    if not path.exists():
        return False, f"receipt not found: {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"receipt is not valid JSON: {exc}"
    if payload.get("schema") != RECEIPT_SCHEMA:
        return False, f"unexpected receipt schema: {payload.get('schema', '')}"
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        return False, "receipt summary missing"
    if summary.get("strict_ready") is not True:
        return False, "receipt summary.strict_ready is not true"
    return True, "strict_ready"


def render_report(
    workspace: Path,
    engagement: str,
    target_repo: str,
    audit_pin: str,
    scope: Dict[str, Any],
    phase_a: Dict[str, Any],
    phase_c_count: int,
    phase_d: Dict[str, List[Dict[str, Any]]],
    phase_e: Dict[str, List[Dict[str, Any]]],
    phase_f: List[Dict[str, Any]],
    args: argparse.Namespace,
    phase_g_engage_report: Optional[Dict[str, Any]] = None,
    system_model: Optional[Dict[str, Any]] = None,
) -> str:
    lines: List[str] = []
    lines.append(f"# Brain Priming Report — {engagement}")
    lines.append("")
    lines.append(f"Generated: {_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"Workspace: `{workspace}`")
    lines.append(f"Audit-pin: `{audit_pin or 'unknown'}` (from "
                 f"`INTAKE_BASELINE.md`/`SCOPE.md`)")
    lines.append(f"Target repo: `{target_repo or 'unknown'}`")
    lines.append(f"Language: `{scope.get('language', 'unknown')}`")
    lines.append(f"Scope glob: `{scope.get('scope_globs', '(none)')}`")
    lines.append(f"Scope auto-detected: `{scope.get('auto_detected', False)}`")
    lines.append("")
    lines.append("## Phase A — Layer-1 MCP recall summary")
    lines.append("")
    lines.append(f"- context_pack_id: `{phase_a.get('context_pack_id', '')}`")
    lines.append(f"- context_pack_hash: `{phase_a.get('context_pack_hash', '')}`")
    lines.append(f"- callables_attempted: {phase_a.get('callables_attempted', 0)}")
    lines.append(f"- callables_succeeded: {phase_a.get('callables_succeeded', 0)}")
    lines.append(f"- callables_failed: {len(phase_a.get('callables_failed', []))}")
    if phase_a.get("callables_failed"):
        for f in phase_a["callables_failed"]:
            lines.append(f"  - `{f.get('name', '?')}`: {f.get('stderr', '')[:80]}")
    lines.append(f"- recall duration: {phase_a.get('duration_seconds', 0)}s")
    lines.append("")
    lines.append("## Phase B — Scope resolution")
    lines.append("")
    lines.append(f"- Resolved language: `{scope.get('language', '')}`")
    lines.append(f"- Resolved scope glob: `{scope.get('scope_globs', '')}`")
    lines.append(f"- Auto-detected: `{scope.get('auto_detected', False)}`")
    if scope.get("candidate_dirs"):
        lines.append("- Candidate dirs:")
        for d in scope["candidate_dirs"][:8]:
            lines.append(f"  - `{d}`")
    lines.append("")
    lines.append("## Phase C — Function signature extraction")
    lines.append("")
    lines.append(f"- Total functions extracted: {phase_c_count}")
    lines.append(f"- Files in Phase-D output: {len(phase_d)}")
    lines.append("")
    lines.append("## Phase D — Top-ranked attack hypotheses per function")
    lines.append("")
    if not phase_d:
        lines.append("_No ranked attack classes produced. Check ranker corpus + scope globs._")
    else:
        for fpath, fns in list(phase_d.items())[: args.max_files]:
            lines.append(f"### `{fpath}`")
            lines.append("")
            for fn in fns:
                visibility = fn.get("visibility", "")
                lines.append(
                    f"#### `{fn.get('function_name', '?')}` "
                    f"(line {fn.get('line_start', 0)}, {visibility})"
                )
                lines.append(f"shape_hash: `{fn.get('shape_hash', '')}`")
                lines.append("Top attack hypotheses (confidence ≥ "
                             f"{args.min_confidence}):")
                acs = fn.get("ranked_attack_classes") or []
                if not acs:
                    lines.append("  - _no attack classes above threshold_")
                else:
                    for i, ac in enumerate(acs, 1):
                        ac_name = ac.get("attack_class", "?")
                        conf = ac.get("confidence", 0.0)
                        prov = ", ".join(
                            f"S{s}" for s in (ac.get("scorer_contributions") or {}).keys()
                            if (ac.get("scorer_contributions") or {}).get(s, 0) > 0
                        )
                        lines.append(
                            f"  {i}. `{ac_name}` (conf {conf:.2f})"
                            + (f" — scorers: {prov}" if prov else "")
                        )
                lines.append("")
    lines.append("## Phase E — Cross-engagement fanout candidates")
    lines.append("")
    if not phase_e:
        lines.append("_No prior engagements with applicable patterns found._")
    else:
        for src, matches in phase_e.items():
            lines.append(f"### From `{src}` ({len(matches)} matches)")
            lines.append("")
            if not matches:
                lines.append("  _(no destination matches above threshold)_")
                lines.append("")
                continue
            for m in matches[:10]:
                if "error" in m:
                    lines.append(f"  - ERROR: {m['error']}")
                    continue
                lines.append(
                    f"  - [{m.get('score', 0):.2f}] "
                    f"`{m.get('bug_class', '?')}` "
                    f":: `{m.get('dest_file', '?')}` "
                    f"fn=`{m.get('matched_function', '')}` "
                    f"(pattern=`{m.get('pattern_slug', '')}`)"
                )
            lines.append("")
    lines.append("## Phase F — Recommended hunt lanes (consolidated)")
    lines.append("")
    # Lane-L wiring note: architectural lanes require the system model.
    if system_model is not None:
        ext = system_model.get("extraction", {}) if isinstance(system_model, dict) else {}
        n_comp = len(system_model.get("components", []) or []) \
            if isinstance(system_model, dict) else 0
        lines.append(
            f"_Component-aware lanes ENABLED — consuming "
            f"`.auditooor/system_model.json` (Lane-L artifact, "
            f"{n_comp} components, "
            f"{ext.get('source_files_indexed', '?')} source files indexed). "
            f"Architectural lanes (component / value-flow / trust-boundary / "
            f"privileged-role / protocol-defense) are ranked ABOVE the "
            f"detector-shape lanes._"
        )
    else:
        lines.append(
            "_Component-aware lanes UNAVAILABLE — no "
            "`.auditooor/system_model.json` found. brain-prime can only "
            "propose detector-shape lanes (generic detector confidence). The "
            "architecturally-important Critical surfaces (precompiles, cross-VM "
            "bridges, parallel-execution nondeterminism, custody components) "
            "are component-blind to the ranker. Run `make system-model "
            "WS=<ws>` (tools/system-model.py) and re-run brain-prime to enable "
            "architectural lanes._"
        )
    lines.append("")
    if not phase_f:
        lines.append("_No lanes proposed. Either corpus is empty or scope is too narrow._")
    else:
        for lane in phase_f:
            kind = lane.get("lane_kind", "detector_shape")
            kind_tag = ("architectural" if kind == "architectural"
                        else "detector-shape")
            lines.append(
                f"### {lane['lane_id']}: `{lane['attack_class']}` "
                f"[{kind_tag}]"
            )
            lines.append("")
            lines.append(f"- Lane kind: `{kind}`")
            if kind == "architectural":
                lines.append(
                    f"- System-model section: `{lane.get('model_section', '?')}`"
                )
                lines.append(
                    f"- Component / boundary: `{lane.get('component', '?')}`"
                )
                if lane.get("rationale"):
                    lines.append(f"- Rationale: {lane['rationale']}")
                lines.append(f"- Severity heuristic: `{lane['severity_guess']}`")
                lines.append(f"- Provenance: {lane['provenance']}")
                detail = lane.get("detail") or {}
                if detail:
                    for k in ("ingress_paths", "egress_paths",
                              "source_signal_paths", "declared_in"):
                        vals = detail.get(k)
                        if vals:
                            lines.append(f"- {k}:")
                            for v in list(vals)[:8]:
                                lines.append(f"  - `{v}`")
            else:
                lines.append(f"- Max confidence: `{lane['max_confidence']}`")
                lines.append(f"- Severity heuristic: `{lane['severity_guess']}`")
                lines.append(f"- Provenance: {lane['provenance']}")
                if lane.get("phase_d_hits"):
                    lines.append("- Phase-D targets:")
                    for h in lane["phase_d_hits"]:
                        lines.append(
                            f"  - `{h['file']}::{h['function']}:{h['line']}` "
                            f"(conf {h['confidence']:.2f})"
                        )
                if lane.get("phase_e_hits"):
                    lines.append("- Phase-E (A6 fanout) targets:")
                    for h in lane["phase_e_hits"]:
                        lines.append(
                            f"  - `{h['dest_file']}::{h['fn']}` "
                            f"(score {h['score']:.2f}, src={h['source']})"
                        )
            lines.append("")
    # Phase G — Mechanical detector grounding summary (Wave-9)
    lines.append("## Phase G — Mechanical detector grounding (S6)")
    lines.append("")
    if not phase_g_engage_report or not phase_g_engage_report.get("parse_ok"):
        lines.append("_No engage_report.md found at workspace root — S6 detector grounding disabled._")
        lines.append("Run `make audit WS=<ws>` to generate it; re-run brain-prime for S6 boost.")
    else:
        total_hits = phase_g_engage_report.get("total_hits", 0)
        n_clusters = len(phase_g_engage_report.get("clusters", []))
        by_sev = phase_g_engage_report.get("by_severity", {})
        lines.append(f"- Engage report parsed: {total_hits} hits / {n_clusters} detector clusters")
        lines.append(f"- Severity breakdown: HIGH={by_sev.get('HIGH', 0)}"
                     f" MEDIUM={by_sev.get('MEDIUM', 0)} LOW={by_sev.get('LOW', 0)}")
        # Count functions that got S6 boosts
        s6_boosted_fns: List[str] = []
        for fpath, fns in phase_d.items():
            for fn in fns:
                if fn.get("s6_boost"):
                    s6_boosted_fns.append(f"{fpath}::{fn.get('function_name', '?')}:{fn.get('line_start', 0)}")
        lines.append(f"- Functions with S6 boost (detector hit in line range): {len(s6_boosted_fns)}")
        if s6_boosted_fns:
            lines.append("- S6-boosted functions:")
            for loc in s6_boosted_fns[:20]:
                lines.append(f"  - `{loc}`")
            if len(s6_boosted_fns) > 20:
                lines.append(f"  - _(+{len(s6_boosted_fns)-20} more)_")
        else:
            lines.append("  - _No ranked functions overlap detector hits (check scope-glob vs detector file paths)._")
    lines.append("")
    lines.append("## Caveats — what the brain doesn't know")
    lines.append("")
    lines.append("- Functions outside the extracted scope-glob "
                 "(helper packages, internal/pkgs not matched).")
    lines.append("- Bug classes not yet represented in the per-target weight "
                 "matrix or the 51-class taxonomy.")
    lines.append("- Go extraction: full tree-sitter parse (production quality).")
    lines.append("- Solidity extraction: full tree-sitter via Wave-9 "
                 "(visibility + modifiers + params + return types; "
                 "shape-hash uniqueness materially improved over regex-only). "
                 "Falls back to regex if tree-sitter-solidity is unavailable.")
    lines.append("- Rust extraction: regex-only fallback (tree-sitter-rust "
                 "available but extractor not yet wired; out of Wave-9 scope). "
                 "Line-precise but no body parse; ranker shape-hash quality "
                 "is reduced for Rust files.")
    lines.append("- Corpus diversity gap (post-Wave-9 remaining gap): the "
                 "tagged-verdict corpus is currently >90% Go engagements. "
                 "Even with full Solidity extraction, the ranker matches "
                 "against thin Solidity signal until more Solidity verdicts "
                 "are tagged. Wave-9 closes the extraction-quality lever; "
                 "corpus-diversity is a separate, parallel lever requiring "
                 "additional tagging work on Solidity engagements.")
    lines.append("- Cross-engagement fanout depends on prior verdict tag "
                 "yaml files; an engagement with zero filed CRIT/HIGH yields "
                 "no fanout patterns.")
    lines.append("- Severity guesses are heuristic projections of ranker "
                 "confidence; rubric-verbatim validation still required "
                 "before filing (per L17 build-or-drop discipline).")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_brain_prime(args: argparse.Namespace) -> Dict[str, Any]:
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"workspace not found: {workspace}")
    engagement = _guess_engagement_slug(workspace)
    audit_pin = _extract_audit_pin(workspace)
    # Phase A — MCP recall
    if args.skip_mcp:
        phase_a = {
            "context_pack_id": "",
            "context_pack_hash": "",
            "callables_attempted": 0,
            "callables_succeeded": 0,
            "callables_failed": [],
            "duration_seconds": 0.0,
            "skipped": True,
        }
    else:
        phase_a = phase_a_mcp_recall(workspace,
                                     timeout_seconds=args.mcp_timeout)
    # Phase B — scope resolution
    scope = phase_b_resolve_scope(workspace, args.language, args.scope_globs)
    # Phase C — extraction
    sig_mod = load_sig_extractor()
    scope_files = iter_scope_files(workspace, scope["scope_globs"],
                                   scope["language"])
    if args.max_files and len(scope_files) > args.max_files:
        scope_files = scope_files[: args.max_files]
    fn_records = phase_c_extract_functions(
        workspace, scope_files, scope["language"], args.max_files, sig_mod,
    )
    # Phase D pre-step — parse engage_report.md for S6 grounding (Wave-9)
    engage_parser_mod = load_engage_report_parser()
    engage_report_path = workspace / "engage_report.md"
    workspace_engage_report: Optional[Dict[str, Any]] = None
    if engage_report_path.exists():
        try:
            workspace_engage_report = engage_parser_mod.parse_engage_report(engage_report_path)
            if not workspace_engage_report.get("parse_ok"):
                workspace_engage_report = None
        except Exception:
            workspace_engage_report = None
    # Phase D — ranker
    ranker_mod = load_ranker()
    # Target repo heuristic: take from --target-repo flag, OR infer from
    # workspace external/ subdir.
    target_repo = args.target_repo or ""
    if not target_repo:
        ext = workspace / "external"
        if ext.exists():
            subs = [p.name for p in ext.iterdir() if p.is_dir()]
            if subs:
                # Heuristic: workspace dydx + external/v4-chain → dydxprotocol/v4-chain
                if engagement in ENGAGEMENT_PREFIXES:
                    pref = ENGAGEMENT_PREFIXES[engagement][0].rstrip("/")
                    target_repo = f"{pref}/{subs[0]}" if "/" not in pref else f"{pref.split('/')[0]}/{subs[0]}"
                else:
                    target_repo = f"{engagement}/{subs[0]}"
    phase_d = phase_d_rank_functions(
        fn_records=fn_records,
        target_repo=target_repo or engagement,
        audit_pin=audit_pin or None,
        workspace_path=workspace,
        top_functions_per_file=args.top_functions_per_file,
        min_confidence=args.min_confidence,
        ranker_mod=ranker_mod,
        workspace_engage_report=workspace_engage_report,
    )
    # r36-rebuttal: lane mega-learn-2026-05-28 Phase E.1 mimo-priors wiring
    # Phase E.1 — apply mimo-observed yield priors to phase_d output
    phase_d, phase_e1_summary = phase_e1_apply_mimo_priors(phase_d, workspace)
    sys.stderr.write(
        f"[brain-prime] phase_e1 mimo-priors: {phase_e1_summary}\n"
    )
    # Phase E — fanout
    # r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json
    fanout_mod = load_fanout()
    # Propagate --max-files into the destination walk and scope the fanout to
    # --fanout-dest-globs (defaulting to the resolved scope glob) so a large
    # monorepo external/ tree (e.g. aztec-packages) does not spin unbounded.
    fanout_dest_globs = getattr(args, "fanout_dest_globs", None) or scope.get("scope_globs", "")
    fanout_budget = getattr(args, "fanout_budget_seconds", None)
    phase_e = phase_e_fanout(
        engagement, workspace, fanout_mod, top_n=10,
        max_dest_files=args.max_files,
        budget_seconds=fanout_budget,
        dest_globs=fanout_dest_globs or None,
    )
    # Phase F — lanes (component-aware when the Lane-L system model exists)
    system_model = load_system_model_for_workspace(workspace)
    phase_f = _propose_hunt_lanes(phase_d, phase_e, max_lanes=8,
                                  system_model=system_model)
    # Render
    report_text = render_report(
        workspace=workspace,
        engagement=engagement,
        target_repo=target_repo,
        audit_pin=audit_pin,
        scope=scope,
        phase_a=phase_a,
        phase_c_count=len(fn_records),
        phase_d=phase_d,
        phase_e=phase_e,
        phase_f=phase_f,
        args=args,
        phase_g_engage_report=workspace_engage_report,
        system_model=system_model,
    )
    out_path = (Path(args.out).expanduser()
                if args.out else workspace / "BRAIN_PRIMING_REPORT.md")
    out_path.write_text(report_text, encoding="utf-8")
    receipt_path: Path | None = None
    if not getattr(args, "no_receipt", False):
        receipt = build_brain_prime_receipt(
            workspace=workspace,
            engagement=engagement,
            report_path=out_path,
            report_text=report_text,
            audit_pin=audit_pin,
            target_repo=target_repo,
            phase_a=phase_a,
            scope=scope,
            functions_extracted=len(fn_records),
            phase_d_files=len(phase_d),
            phase_e_sources=len(phase_e),
            phase_f=phase_f,
            args=args,
        )
        receipt_override = getattr(args, "receipt_out", None)
        receipt_path = write_brain_prime_receipt(
            workspace,
            receipt,
            Path(receipt_override).expanduser() if receipt_override else None,
        )
    # Phase G stats for return dict
    s6_boosted_count = sum(
        1 for fns in phase_d.values()
        for fn in fns if fn.get("s6_boost")
    )
    return {
        "engagement": engagement,
        "workspace": str(workspace),
        "report_path": str(out_path),
        "receipt_path": str(receipt_path) if receipt_path else "",
        "audit_pin": audit_pin,
        "target_repo": target_repo,
        "phase_a": phase_a,
        "scope": scope,
        "functions_extracted": len(fn_records),
        "phase_d_files": len(phase_d),
        "phase_e_sources": len(phase_e),
        "phase_f_lanes": len(phase_f),
        "phase_g": {
            "engage_report_parsed": workspace_engage_report is not None,
            "total_hits": (workspace_engage_report or {}).get("total_hits", 0),
            "distinct_detectors": (workspace_engage_report or {}).get("distinct_detectors", 0),
            "s6_boosted_functions": s6_boosted_count,
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True,
                    help="Workspace path (e.g. ~/audits/dydx)")
    ap.add_argument("--target-repo", default=None,
                    help="owner/repo (e.g. dydxprotocol/v4-chain). "
                         "Inferred from workspace if omitted.")
    ap.add_argument("--language", default=None,
                    choices=["go", "rust", "solidity", "mixed"],
                    help="Primary language (auto-detected if omitted).")
    ap.add_argument("--scope-globs", default=None,
                    help="Comma-separated globs relative to workspace (e.g. "
                         "'external/*/protocol/x/**/*.go'). Auto-detected "
                         "via heuristics if omitted.")
    ap.add_argument("--top-functions-per-file", type=int, default=5)
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--max-files", type=int, default=50)
    # r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json
    ap.add_argument("--fanout-dest-globs", default=None,
                    help="Comma-separated workspace-relative globs restricting "
                         "the Phase-E cross-engagement fanout walk to scoped "
                         "subtrees. Defaults to --scope-globs. Bounds the walk "
                         "on large monorepo external/ trees.")
    ap.add_argument("--fanout-budget-seconds", type=float, default=60.0,
                    help="Wall-clock budget (seconds) for each Phase-E "
                         "destination walk. <=0 disables the budget.")
    ap.add_argument("--out", default=None,
                    help="Output path. Default: <ws>/BRAIN_PRIMING_REPORT.md")
    ap.add_argument("--receipt-out", default=None,
                    help="Receipt output path. Default: <ws>/.auditooor/brain_prime_receipt.json")
    ap.add_argument("--no-receipt", action="store_true",
                    help="Do not write the structured brain-prime receipt.")
    ap.add_argument("--strict", action="store_true",
                    help="Exit non-zero unless the written receipt has summary.strict_ready=true.")
    ap.add_argument("--skip-mcp", action="store_true",
                    help="Skip Layer-1 MCP recall (for tests).")
    ap.add_argument("--mcp-timeout", type=float, default=30.0,
                    help="Per-callable MCP timeout in seconds (default 30).")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON summary to stdout.")
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    summary = run_brain_prime(args)
    if getattr(args, "strict", False):
        ok, reason = validate_receipt_strict_ready(summary.get("receipt_path"))
        if not ok:
            print(f"brain-prime: STRICT=1 not dispatch-ready: {reason}", file=sys.stderr)
            return 1
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"brain-prime: engagement={summary['engagement']} "
              f"target_repo={summary['target_repo']} "
              f"audit_pin={summary['audit_pin'][:8] if summary['audit_pin'] else 'unknown'}")
        print(f"  Phase A: {summary['phase_a'].get('callables_succeeded', 0)}"
              f"/{summary['phase_a'].get('callables_attempted', 0)} MCP callables "
              f"in {summary['phase_a'].get('duration_seconds', 0)}s")
        print(f"  context_pack_id: {summary['phase_a'].get('context_pack_id', '')}")
        print(f"  Phase C: {summary['functions_extracted']} functions extracted")
        print(f"  Phase D: {summary['phase_d_files']} files ranked")
        print(f"  Phase E: {summary['phase_e_sources']} prior engagements feeding fanout")
        print(f"  Phase F: {summary['phase_f_lanes']} hunt lanes proposed")
        print(f"  Report: {summary['report_path']}")
        if summary.get("receipt_path"):
            print(f"  Receipt: {summary['receipt_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
