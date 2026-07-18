#!/usr/bin/env python3
"""auditooor-pre-source-read-injector — Wave-6 Track B Phase C (PUSH-mode).

Per-function mindset injection at the moment a worker calls ``Read`` on a
source file. Wave-5 Phase D-1 shipped pull-mode (worker briefs auto-populate
the cheat sheet up-front). Phase C wires the SAME per-function ranking into
a PreToolUse hook so the worker sees the top attack-class hypotheses for
every function defined in the file BEFORE the source body is exposed.

Design source: ``docs/next-loop/big_plan_2026-05-11/06_brain_architect_report.md`` §6
(push vs pull vs IDE).

CLI:
    python3 tools/auditooor-pre-source-read-injector.py <file_path> \\
        [--target-repo OWNER/REPO] [--top-n 3] [--min-confidence 0.4] \\
        [--max-functions 30] [--json]

Algorithm:
    1. Detect language from file extension (.go / .rs / .sol / .ts / .py).
    2. Extract function signatures via ``tools/function-signature-extractor.py``
       (Go, Rust, and Solidity structured extraction; other extensions
       silently emit ``functions_analyzed: 0``).
    3. Filter to handler-like functions (per Phase D-1 ``_HANDLER_HEURISTIC``).
    4. Truncate to top ``--max-functions`` by line number to stay in budget.
    5. For each function, call ``tools/ranker.py rank()`` inline (same API as
       MCP ``vault_function_mindset``).
    6. Emit a JSON payload matching schema ``auditooor.pre_source_read_injection.v1``.

Performance budget:
    Hook MUST complete within 2s for files with <=20 functions (per brief).
    Files with >30 functions are truncated to top-30 by line number.

Stdlib-only. Returns exit-0 on success. Never crashes — emits
``functions_analyzed: 0`` + ``skipped_reasons`` on any internal error.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import (
    build_corpus_backed_hypotheses as _common_build_corpus_backed_hypotheses,
    build_function_shape_recall_payload as _common_build_function_shape_recall_payload,
    merge_ranked_attack_classes as _common_merge_ranked_attack_classes,
    summarize_function_shape_recall as _common_summarize_function_shape_recall,
)
from hacker_question_renderer import HACKER_QUESTION_SCHEMA, render_hacker_questions

RANKER_PATH = REPO_ROOT / "tools" / "ranker.py"
EXTRACTOR_PATH = REPO_ROOT / "tools" / "function-signature-extractor.py"

# Per-function handler heuristic (mirrors Phase D-1 augmenter).
_HANDLER_HEURISTIC = re.compile(
    r"(?i)(handle|process|server|register|update|set|exec|create|withdraw|deposit"
    r"|transfer|claim|mint|burn|swap|finalize|redeem|withdraw|propose|vote)",
)
_HANDLER_RECEIVER_FAMILIES = {"msg-server-family", "hook-family"}


# Supported source extensions. Other extensions are skipped silently.
_SUPPORTED_EXTENSIONS = {".go", ".rs", ".sol", ".ts", ".py"}
# Languages where we currently have structured extraction via
# tools/function-signature-extractor.py in this hook path.
_PARSED_LANGUAGES = {".go", ".rs", ".sol"}


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _language_for_ext(ext: str) -> str:
    return {
        ".go": "go",
        ".rs": "rust",
        ".sol": "solidity",
        ".ts": "typescript",
        ".py": "python",
    }.get(ext, "unknown")


def _is_handler_like(rec: Dict[str, Any]) -> bool:
    name = rec.get("function_name") or ""
    recv_family = rec.get("receiver_family", "")
    if _HANDLER_HEURISTIC.search(name):
        return True
    if recv_family in _HANDLER_RECEIVER_FAMILIES:
        return True
    return False


def _compute_receiver_family(recv: Optional[str]) -> str:
    """Mirror agent-prompt-hacker-augmenter._compute_receiver_family_for_rec."""
    if not recv:
        return "misc-family"
    recv = recv.lstrip("*").strip()
    if "." in recv:
        recv = recv.split(".")[-1]
    for family, needles in [
        ("msg-server-family", ["msgServer", "MsgServer", "Keeper", "GovKeeper"]),
        ("ibc-module", ["IBCModule", "IBCMiddleware"]),
        ("hook-family", ["Hook", "IPostHook", "Hooks"]),
        ("amm-pool-family", ["Vault", "Pool", "Pair", "AMM"]),
        ("token-family", ["ERC20", "ERC4626", "Bank", "Token"]),
    ]:
        for needle in needles:
            if needle in recv:
                return family
    return "misc-family"


# --------------------------------------------------------------------------- #
# Extractors                                                                  #
# --------------------------------------------------------------------------- #


def _extract_functions_via_extractor(
    resolved: Path, rel_path: str, language: str
) -> List[Dict[str, Any]]:
    """Use function-signature-extractor.py via subprocess on the parent dir.

    Mirrors agent-prompt-hacker-augmenter._extract_functions_for_file but
    works against an absolute path resolved by the caller.
    """
    if not EXTRACTOR_PATH.is_file():
        return []
    try:
        parent_dir = resolved.parent
        proc = subprocess.run(
            [
                sys.executable,
                str(EXTRACTOR_PATH),
                str(parent_dir),
                "--language", language,
                "--filter-test-files",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        recs: List[Dict[str, Any]] = []
        target_basename = resolved.name
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec_fp = rec.get("file_path", "")
            if Path(rec_fp).name == target_basename:
                rec["file_path"] = rel_path
                recs.append(rec)
        return recs
    except Exception:
        return []


_RX_SOL_FUNC = re.compile(
    r"^\s*function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)
_RX_RUST_FUNC = re.compile(
    r"^\s*(?:pub\s+(?:\([^\)]*\)\s+)?)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[<(]",
    re.MULTILINE,
)


def _extract_regex_fallback(resolved: Path, rel_path: str, language: str) -> List[Dict[str, Any]]:
    """Best-effort regex fallback for Solidity and Rust.

    Returns minimal records (name + line + signature line text) with empty
    params/return_types/guards so the ranker can still synthesize a target
    record from the function signature.
    """
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    if language == "solidity":
        rx = _RX_SOL_FUNC
    elif language == "rust":
        rx = _RX_RUST_FUNC
    else:
        return []
    out: List[Dict[str, Any]] = []
    for m in rx.finditer(text):
        name = m.group("name")
        # Skip Rust test functions / lifetimes / impl-blocks accidentally hit
        if not name or name.startswith("_"):
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        # Capture signature up to the opening brace or semicolon on the same window
        sig_end = text.find("{", m.end())
        if sig_end == -1:
            sig_end = min(len(text), m.end() + 200)
        signature = text[m.start():sig_end].strip().splitlines()[0]
        out.append({
            "file_path": rel_path,
            "language": language,
            "function_name": name,
            "function_signature": signature,
            "receiver_type": None,
            "visibility": "exported" if not name[0].isdigit() and name[0].isupper() else "unexported",
            "line_start": line_no,
            "line_end": line_no,
            "modifiers": [],
            "params": [],
            "return_types": [],
            "calls_made": [],
            "guards_detected": [],
        })
    return out


# --------------------------------------------------------------------------- #
# Ranker invocation — in-process (Wave-7 perf upgrade)                        #
# --------------------------------------------------------------------------- #
# Wave-6 Phase C used subprocess-per-function due to Python 3.14's stricter
# dataclass.__module__ validation: dynamically-loaded modules via
# importlib.util.module_from_spec() have __module__ == <the name string>, but
# dataclasses._is_type() does sys.modules.get(cls.__module__).__dict__ which
# returned None because the module wasn't pre-registered in sys.modules.
#
# Fix (Wave-7): pre-register the module in sys.modules BEFORE calling
# spec.loader.exec_module(). This satisfies Python 3.14's invariant and allows
# in-process calling. Speedup: subprocess startup overhead (~50-100ms/call)
# eliminated; 4 functions 1.32s → ~0.29s (4.5x), 30 functions 3.10s → ~1.0s
# (3x). Subprocess fallback retained for environments where the import fails.
#
# context_pack_id: auditooor.vault_context_pack.v1:resume:0f215322f432e859
# context_pack_hash: 0f215322f432e85958d7066d789a969fde5a36155a57b8d5f3d2bc5d62a677ea


_RANKER_MODULE = None  # cached in-process module; loaded once per process
_HACKERMAN_FUNCTION_PAYLOAD_CACHE: Dict[Tuple[str, str, str, str, str, int], Dict[str, Any]] = {}


def _load_ranker_module():
    """Load tools/ranker.py in-process, caching the result.

    Uses sys.modules pre-registration to satisfy Python 3.14's dataclass
    __module__ validation (the fix for the Phase C subprocess caveat).
    Returns the module on success, None on failure (caller falls back to
    subprocess).
    """
    global _RANKER_MODULE
    if _RANKER_MODULE is not None:
        return _RANKER_MODULE
    if not RANKER_PATH.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_auditooor_ranker", str(RANKER_PATH))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        # Pre-register BEFORE exec_module — required for Python 3.14 dataclass
        # __module__ validation (dataclasses._is_type checks sys.modules).
        sys.modules["_auditooor_ranker"] = mod
        spec.loader.exec_module(mod)
        _RANKER_MODULE = mod
        return mod
    except Exception:
        return None


def _load_hackerman_function_mindset_module():
    """Legacy wrapper retained for tests that monkeypatch this symbol."""
    return True


def _build_hackerman_function_payload(
    *,
    target_repo: str,
    file_path: str,
    function_signature: str,
    shape_hash: str,
    language: str,
    top_n: int,
) -> Dict[str, Any]:
    """Return canonical Hackerman function-shape evidence, or an empty payload."""
    cache_key = (
        target_repo or "",
        file_path or "",
        function_signature or "",
        shape_hash or "",
        language or "",
        int(top_n),
    )
    if cache_key in _HACKERMAN_FUNCTION_PAYLOAD_CACHE:
        return dict(_HACKERMAN_FUNCTION_PAYLOAD_CACHE[cache_key])
    out = _common_build_function_shape_recall_payload(
        target_repo=target_repo,
        file_path=file_path,
        function_signature=function_signature,
        shape_hash=shape_hash,
        language=language,
        limit=top_n,
    )
    _HACKERMAN_FUNCTION_PAYLOAD_CACHE[cache_key] = dict(out)
    return out


def _merge_ranked_attack_classes(
    ranker_rows: List[Dict[str, Any]],
    hackerman_rows: List[Dict[str, Any]],
    limit: int,
) -> List[Dict[str, Any]]:
    return _common_merge_ranked_attack_classes(ranker_rows, hackerman_rows, limit)


def _first_hackerman_evidence(row: Dict[str, Any]) -> Dict[str, Any]:
    evidence = row.get("evidence")
    if isinstance(evidence, list):
        first = next((item for item in evidence if isinstance(item, dict)), None)
        if first is not None:
            return first
    return {}


def _evidence_record_id(evidence: Dict[str, Any]) -> str:
    for key in ("record_id", "verdict_id", "outcome_id", "tag_file", "source_ref"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _bounded_source_refs(values: Any, limit: int = 5) -> List[str]:
    refs: List[str] = []
    if not isinstance(values, list):
        return refs
    for value in values:
        text = str(value if value is not None else "").strip()
        if not text:
            continue
        try:
            path = Path(text).expanduser()
            if path.is_absolute():
                try:
                    text = path.resolve().relative_to(REPO_ROOT).as_posix()
                except (OSError, ValueError):
                    text = path.name
        except (OSError, RuntimeError):
            pass
        if text not in refs:
            refs.append(text)
        if len(refs) >= limit:
            break
    return refs


def _summarize_hackerman_payload(payload: Dict[str, Any], limit: int) -> Dict[str, Any]:
    return _common_summarize_function_shape_recall(payload, limit)


def _rank_function(
    target_repo: str,
    file_path: str,
    function_signature: str,
    top_n: int,
    min_confidence: float,
    timeout: float = 30.0,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Invoke ranker — in-process when possible, subprocess as fallback.

    Wave-7 perf upgrade: uses importlib in-process import with sys.modules
    pre-registration to fix Python 3.14 dataclass.__module__ issue. Falls
    back to subprocess when in-process load fails (backward compat).
    Returns (attack_classes, shape_info).
    """
    if not RANKER_PATH.is_file():
        return [], {}

    # Read-time hints are advisory context, not scored predictions with a
    # triage outcome. Keep them out of the ranker learning log unless an
    # operator explicitly opts in.
    log_predictions = os.environ.get("AUDITOOOR_PRE_SOURCE_READ_LOG_RANKER") == "1"
    previous_log_disabled = os.environ.get("RANKER_PREDICTION_LOG_DISABLED")

    # --- in-process path (preferred) ---
    mod = _load_ranker_module()
    if mod is not None:
        try:
            if not log_predictions:
                os.environ["RANKER_PREDICTION_LOG_DISABLED"] = "1"
            result = mod.rank(
                target_repo=target_repo,
                file_path=file_path,
                function_signature=function_signature,
                top_n=top_n,
                min_confidence=min_confidence,
            )
            if not log_predictions:
                if previous_log_disabled is None:
                    os.environ.pop("RANKER_PREDICTION_LOG_DISABLED", None)
                else:
                    os.environ["RANKER_PREDICTION_LOG_DISABLED"] = previous_log_disabled
            # RankResult.target is a plain dict; ranked_attack_classes is
            # List[Dict] (same structure as the subprocess JSON path).
            target_dict = result.target if isinstance(result.target, dict) else {}
            shape_info = {
                "shape_hash": target_dict.get("shape_hash", ""),
                "shape_hash_fine": target_dict.get("shape_hash_fine", ""),
            }
            return list(result.ranked_attack_classes), shape_info
        except Exception:
            if not log_predictions:
                if previous_log_disabled is None:
                    os.environ.pop("RANKER_PREDICTION_LOG_DISABLED", None)
                else:
                    os.environ["RANKER_PREDICTION_LOG_DISABLED"] = previous_log_disabled
            pass  # fall through to subprocess

    # --- subprocess fallback (backward compat) ---
    try:
        env = os.environ.copy()
        if not log_predictions:
            env["RANKER_PREDICTION_LOG_DISABLED"] = "1"
        proc = subprocess.run(
            [
                sys.executable,
                str(RANKER_PATH),
                "--target-repo", target_repo,
                "--file-path", file_path,
                "--function-signature", function_signature,
                "--top-n", str(top_n),
                "--min-confidence", str(min_confidence),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return [], {}
        data = json.loads(proc.stdout)
        shape_info = {
            "shape_hash": data.get("target", {}).get("shape_hash", ""),
            "shape_hash_fine": data.get("target", {}).get("shape_hash_fine", ""),
        }
        return data.get("ranked_attack_classes", []), shape_info
    except Exception:
        return [], {}


# --------------------------------------------------------------------------- #
# Main injector                                                               #
# --------------------------------------------------------------------------- #


def build_injection_payload(
    file_path: str,
    target_repo: Optional[str] = None,
    top_n: int = 3,
    min_confidence: float = 0.4,
    max_functions: int = 30,
) -> Dict[str, Any]:
    """Produce the injection payload for one file.

    Always returns a dict (never raises). On any miss, emits 0 functions and
    a non-empty ``skipped_reasons`` list.
    """
    skipped_reasons: List[str] = []
    p = Path(file_path)
    ext = p.suffix.lower()
    language = _language_for_ext(ext)

    # 1) Resolve file existence
    if not p.exists():
        skipped_reasons.append(f"file-not-found: {file_path}")
        return _empty_payload(file_path, target_repo, language, skipped_reasons)

    if not p.is_file():
        skipped_reasons.append(f"not-a-file: {file_path}")
        return _empty_payload(file_path, target_repo, language, skipped_reasons)

    # 2) Extension gate
    if ext not in _SUPPORTED_EXTENSIONS:
        skipped_reasons.append(f"unsupported-extension: {ext}")
        return _empty_payload(file_path, target_repo, language, skipped_reasons)

    # 3) Extract functions
    rel_path = _relativize_to_repo(p, target_repo)
    if ext in _PARSED_LANGUAGES:
        recs = _extract_functions_via_extractor(p, rel_path, language)
        if not recs:
            skipped_reasons.append(f"{language}-extractor-returned-zero")
            recs = _extract_regex_fallback(p, rel_path, language)
    elif ext == ".sol":
        recs = _extract_regex_fallback(p, rel_path, language)
        if not recs:
            skipped_reasons.append(f"regex-fallback-zero-{language}")
    else:
        # .ts / .py: no parser yet
        recs = []
        skipped_reasons.append(f"no-parser-for-{language}")

    if not recs:
        return _empty_payload(file_path, target_repo, language, skipped_reasons)

    # 4) Annotate receiver_family + filter to handler-like
    for rec in recs:
        if "receiver_family" not in rec:
            rec["receiver_family"] = _compute_receiver_family(rec.get("receiver_type"))

    handler_recs = [r for r in recs if r.get("visibility") == "exported" and _is_handler_like(r)]
    if not handler_recs:
        # Fall back to all exported
        handler_recs = [r for r in recs if r.get("visibility") == "exported"]
    if not handler_recs:
        # Final fallback: include unexported so something is surfaced
        handler_recs = list(recs)

    # 5) Truncate by line number (top-N earliest in the file)
    handler_recs.sort(key=lambda r: r.get("line_start", 0))
    if max_functions and len(handler_recs) > max_functions:
        skipped_reasons.append(
            f"truncated-to-top-{max_functions}-by-line "
            f"(total-handler-like={len(handler_recs)})"
        )
        handler_recs = handler_recs[:max_functions]

    # 6) Rank each
    function_payloads: List[Dict[str, Any]] = []
    effective_target_repo = target_repo or "unknown/unknown"
    context_pack_id = _read_context_pack_id()
    context_pack_hash = _read_context_pack_hash()
    bounded_hackerman_limit = max(1, min(int(top_n or 0) or 3, 5))
    for rec in handler_recs:
        sig = rec.get("function_signature") or ""
        fn_name = rec.get("function_name") or ""
        line = rec.get("line_start") or 0
        ranked, shape = _rank_function(
            target_repo=effective_target_repo,
            file_path=rel_path,
            function_signature=sig,
            top_n=top_n,
            min_confidence=min_confidence,
        )
        hackerman_payload = _build_hackerman_function_payload(
            target_repo=effective_target_repo,
            file_path=rel_path,
            function_signature=sig,
            shape_hash=shape.get("shape_hash", ""),
            language=language,
            top_n=bounded_hackerman_limit,
        )
        hackerman_ranked_raw = hackerman_payload.get("ranked_attack_classes", [])
        hackerman_ranked = [
            dict(row) for row in hackerman_ranked_raw if isinstance(row, dict)
        ] if isinstance(hackerman_ranked_raw, list) else []
        ranked = _merge_ranked_attack_classes(ranked, hackerman_ranked, top_n)
        # Trim each attack-class entry to the public schema (don't leak evidence)
        attack_classes_public: List[Dict[str, Any]] = []
        for ac in ranked:
            attack_classes_public.append({
                "class_id": ac.get("attack_class", ""),
                "score": round(float(ac.get("score", 0.0)), 4),
                "confidence": round(float(ac.get("confidence", 0.0)), 4),
            })
        hacker_questions = render_hacker_questions(
            ranked=ranked,
            function_name=fn_name,
            function_signature=sig,
            shape_hash=shape.get("shape_hash", ""),
            shape_hash_fine=shape.get("shape_hash_fine", ""),
            file_path=rel_path,
            context_pack_id=context_pack_id,
        )
        corpus_backed_hypotheses = _common_build_corpus_backed_hypotheses(
            ranked,
            hacker_questions,
            bounded_hackerman_limit,
        )
        function_payloads.append({
            "name": fn_name,
            "line": line,
            "shape_hash": shape.get("shape_hash", ""),
            "shape_hash_fine": shape.get("shape_hash_fine", ""),
            "top_attack_classes": attack_classes_public,
            "hacker_questions": hacker_questions,
            "hacker_question_count": len(hacker_questions),
            "hacker_question_counts_by_source": _question_source_counts([
                {"hacker_questions": hacker_questions}
            ]),
            "corpus_backed_hypotheses": corpus_backed_hypotheses,
            "corpus_backed_hypothesis_count": len(corpus_backed_hypotheses),
            "no_questions_reason": "" if hacker_questions else "renderer-produced-zero-questions",
        })
        hackerman_summary = _summarize_hackerman_payload(
            hackerman_payload,
            bounded_hackerman_limit,
        )
        if hackerman_summary:
            function_payloads[-1]["hackerman_shape_evidence"] = hackerman_summary

    payload = {
        "schema": "auditooor.pre_source_read_injection.v1",
        "hacker_question_schema": HACKER_QUESTION_SCHEMA,
        "context_pack_id": context_pack_id,
        "context_pack_hash": context_pack_hash,
        "file_path": rel_path,
        "absolute_file_path": str(p.resolve()),
        "target_repo": effective_target_repo,
        "language": language,
        "functions_analyzed": len(function_payloads),
        "functions": function_payloads,
        "summary": {
            "functions_analyzed": len(function_payloads),
            "hacker_question_count": _sum_function_list_field(
                function_payloads,
                "hacker_questions",
            ),
            "hacker_question_counts_by_source": _question_source_counts(function_payloads),
            "corpus_backed_hypothesis_count": _sum_function_list_field(
                function_payloads,
                "corpus_backed_hypotheses",
            ),
        },
        "skipped_reasons": skipped_reasons,
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "advisory_disclaimer": (
            "Mindset hints are advisory; do not skip rubric-verbatim check "
            "per SEVERITY.md."
        ),
        "performance_budget_note": (
            "Budget: <=2s for files with <=20 functions; files with >30 "
            "functions are truncated to top-30 by line number."
        ),
    }
    return payload


def _empty_payload(
    file_path: str,
    target_repo: Optional[str],
    language: str,
    skipped_reasons: List[str],
) -> Dict[str, Any]:
    return {
        "schema": "auditooor.pre_source_read_injection.v1",
        "hacker_question_schema": HACKER_QUESTION_SCHEMA,
        "context_pack_id": _read_context_pack_id(),
        "context_pack_hash": _read_context_pack_hash(),
        "file_path": file_path,
        "absolute_file_path": str(Path(file_path).resolve()) if file_path else "",
        "target_repo": target_repo or "unknown/unknown",
        "language": language,
        "functions_analyzed": 0,
        "functions": [],
        "summary": {
            "functions_analyzed": 0,
            "hacker_question_count": 0,
            "hacker_question_counts_by_source": {},
            "corpus_backed_hypothesis_count": 0,
            "no_questions_reason": "; ".join(skipped_reasons) if skipped_reasons else "no functions analyzed",
        },
        "skipped_reasons": skipped_reasons,
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "advisory_disclaimer": (
            "Mindset hints are advisory; do not skip rubric-verbatim check "
            "per SEVERITY.md."
        ),
        "performance_budget_note": (
            "Budget: <=2s for files with <=20 functions; files with >30 "
            "functions are truncated to top-30 by line number."
        ),
    }


def _read_context_pack_id() -> str:
    """Read the latest MCP context pack id from the workspace sentinel."""
    return _read_context_pack_field("context_pack_id")


def _read_context_pack_hash() -> str:
    """Read the latest MCP context pack hash from the workspace sentinel."""
    return _read_context_pack_field("context_pack_hash")


def _read_context_pack_field(field: str) -> str:
    sentinel = REPO_ROOT / ".auditooor" / "last_mcp_recall.json"
    if not sentinel.is_file():
        return ""
    try:
        data = json.loads(sentinel.read_text())
        return str(data.get(field, ""))
    except Exception:
        return ""


def _relativize_to_repo(p: Path, target_repo: Optional[str]) -> str:
    """Best-effort relative path for ranker (matches sig_extracts JSONL keys).

    Strategy:
      1. If the path contains "/<repo_name>/" (e.g. ".../v4-chain/protocol/..."),
         relativize from that segment.
      2. Else, return the absolute path string (ranker will still synthesize
         a record from function_signature).
    """
    if target_repo:
        repo_basename = target_repo.split("/")[-1]
        parts = p.parts
        for i, seg in enumerate(parts):
            if seg == repo_basename:
                return str(Path(*parts[i + 1:])) if i + 1 < len(parts) else p.name
    return str(p)


def _question_source_counts(functions: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for fn in functions:
        if not isinstance(fn, dict):
            continue
        for question in fn.get("hacker_questions") or []:
            if not isinstance(question, dict):
                continue
            source = str(question.get("question_source") or "unknown").strip() or "unknown"
            counts[source] = counts.get(source, 0) + 1
    return counts


def _sum_function_list_field(functions: List[Dict[str, Any]], field: str) -> int:
    total = 0
    for fn in functions:
        if not isinstance(fn, dict):
            continue
        items = fn.get(field)
        if isinstance(items, list):
            total += len(items)
    return total


def render_claude_hook_output(payload: Dict[str, Any], max_chars: int = 2000) -> str:
    """Render a Claude Code PreToolUse hook response.

    The normal injector JSON is useful for tools, but too large/noisy for the
    live Read hook. Claude's PreToolUse hook API injects context into the
    model via ``hookSpecificOutput.additionalContext`` (added in Claude Code
    2.1.x; changelog: "Added support for PreToolUse hooks to return
    additionalContext to the model"). The bounded card text is placed there so
    the attack-class hypotheses are surfaced IN the agent context BEFORE the
    source body is exposed.

    ``systemMessage`` is also included as a display-layer copy (shown in the
    TUI transcript) but ``additionalContext`` is the canonical injection field.
    """
    functions = payload.get("functions") or []
    if not functions:
        return ""

    file_path = payload.get("file_path") or payload.get("absolute_file_path") or "source file"
    lines = [
        f"Auditooor pre-source-read hacker questions for `{file_path}`.",
        "Advisory only: these are attack hypotheses, not proof, severity, or submission readiness.",
    ]
    context_pack_id = payload.get("context_pack_id")
    if context_pack_id:
        lines.append(f"MCP context: `{context_pack_id}`.")
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    if summary:
        lines.append(
            "Coverage: "
            f"{summary.get('functions_analyzed', payload.get('functions_analyzed', 0))} function(s), "
            f"{summary.get('hacker_question_count', 0)} hacker question(s), "
            f"{summary.get('corpus_backed_hypothesis_count', 0)} corpus-backed hypothesis item(s)."
        )

    rendered_functions = 0
    for fn in functions[:3]:
        rendered_functions += 1
        name = fn.get("name") or "unknown"
        line = fn.get("line") or "?"
        lines.append(f"\nFunction `{name}` near line {line}:")
        questions = fn.get("hacker_questions") or []
        if not questions:
            for ac in (fn.get("top_attack_classes") or [])[:3]:
                cls = ac.get("class_id") or ac.get("attack_class") or "attack-class"
                conf = ac.get("confidence")
                suffix = f" confidence={conf}" if conf not in (None, "") else ""
                lines.append(f"- Check `{cls}`.{suffix}")
            continue
        for q in questions[:3]:
            source = q.get("question_source") or "question"
            label = q.get("attack_class") or q.get("shape_class") or q.get("reasoning_axis") or "general"
            question = str(q.get("question") or "").strip()
            if not question:
                continue
            lines.append(f"- [{source}/{label}] {question}")

    if len(functions) > rendered_functions:
        lines.append(f"\n... {len(functions) - rendered_functions} additional function(s) omitted by hook budget.")

    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[: max(0, max_chars - 80)].rstrip() + "\n...[truncated to hook budget]"

    # ``additionalContext`` inside ``hookSpecificOutput`` is the canonical
    # PreToolUse field that Claude Code injects into the model's context window
    # before the tool result arrives. ``systemMessage`` is retained as a
    # display-layer copy visible in the TUI transcript.
    hook_payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "Auditooor pre-source-read hacker questions injected.",
            "additionalContext": text,
        },
        "systemMessage": text,
    }
    return json.dumps(hook_payload, indent=2, sort_keys=True)


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file_path", help="Path to the source file the worker is about to Read.")
    parser.add_argument("--target-repo", default=os.environ.get("TARGET_REPO", ""),
                        help="OWNER/REPO of the audit target (defaults to $TARGET_REPO).")
    parser.add_argument("--top-n", type=int, default=3,
                        help="Per-function top-N attack classes to emit (default 3).")
    parser.add_argument("--min-confidence", type=float, default=0.4,
                        help="Minimum ranker confidence to include an attack class (default 0.4).")
    parser.add_argument("--max-functions", type=int, default=30,
                        help="Max functions to rank per file (default 30, performance budget).")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON (default: JSON). Reserved for future YAML output.")
    parser.add_argument("--claude-hook-output", action="store_true",
                        help="Emit Claude PreToolUse hook JSON with a bounded systemMessage.")
    parser.add_argument("--hook-max-chars", type=int, default=2000,
                        help="Max characters in --claude-hook-output systemMessage (default 2000).")
    parser.add_argument(
        "--workspace",
        default=os.environ.get("AUDITOOOR_WORKSPACE", ""),
        help=(
            "Workspace root path for obligation persistence "
            "(defaults to $AUDITOOOR_WORKSPACE). "
            "When set, injected questions are appended to "
            "<ws>/.auditooor/hacker_question_obligations.jsonl as open obligations."
        ),
    )
    parser.add_argument(
        "--persist-receipt-only",
        action="store_true",
        default=(
            os.environ.get("AUDITOOOR_PRE_SOURCE_READ_RECEIPT_ONLY", "")
            in {"1", "true", "TRUE", "yes", "YES"}
        ),
        help=(
            "Persist the source-read receipt but SKIP appending injected "
            "questions as open obligations. Receipts still record that the "
            "file was Read; the obligation ledger is left untouched so no "
            "open reliance/obligation debt is created by the injector itself."
        ),
    )
    parser.add_argument(
        "--strict-persistence",
        action="store_true",
        default=(
            os.environ.get("AUDITOOOR_PRE_SOURCE_READ_STRICT_PERSISTENCE", "")
            in {"1", "true", "TRUE", "yes", "YES"}
            or os.environ.get("AUDITOOOR_PRE_SOURCE_READ_STRICT", "")
            in {"1", "true", "TRUE", "yes", "YES"}
        ),
        help=(
            "Fail nonzero if source-read receipt or obligation persistence fails "
            "(or when strict mode is requested without a workspace)."
        ),
    )
    args = parser.parse_args(argv)

    payload = build_injection_payload(
        file_path=args.file_path,
        target_repo=args.target_repo or None,
        top_n=args.top_n,
        min_confidence=args.min_confidence,
        max_functions=args.max_functions,
    )

    if args.claude_hook_output:
        rendered = render_claude_hook_output(payload, max_chars=max(200, args.hook_max_chars))
        if rendered:
            print(rendered)
    else:
        # Default output is JSON regardless of --json flag (single-format MVP).
        print(json.dumps(payload, indent=2, sort_keys=True))

    # Lane 5: persist a source-read receipt, then injected questions as open
    # obligations when workspace is known.
    workspace_str = (args.workspace or "").strip()
    if args.strict_persistence and not workspace_str:
        print(
            "[pre-source-read-injector] WARN strict persistence requested but no workspace was provided",
            file=sys.stderr,
        )
        return 1
    if workspace_str:
        ok, err = _persist_source_read_receipt(workspace_str, payload)
        if not ok:
            print(f"[pre-source-read-injector] WARN receipt persistence failed: {err}", file=sys.stderr)
            if args.strict_persistence:
                return 1
        if args.persist_receipt_only:
            print(
                "[pre-source-read-injector] INFO --persist-receipt-only: "
                "receipt recorded, obligation append skipped",
                file=sys.stderr,
            )
        elif payload.get("functions_analyzed", 0) > 0:
            ok, err = _persist_obligations(workspace_str, payload)
            if not ok:
                print(f"[pre-source-read-injector] WARN obligation persistence failed: {err}", file=sys.stderr)
                if args.strict_persistence:
                    return 1

    return 0


def _persist_obligations(workspace_str: str, payload: Dict[str, Any]) -> tuple[bool, str]:
    """Append injected hacker questions as open obligations (Lane 5).

    Imports hacker-question-obligations.py inline to avoid hard coupling
    (the obligations tool is optional infrastructure).  Silently no-ops on
    any import or runtime error so the injector's exit-0 contract is preserved.
    """
    obligations_path = TOOLS_DIR / "hacker-question-obligations.py"
    if not obligations_path.is_file():
        return False, f"missing obligations tool: {obligations_path}"
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("_hq_obligations", str(obligations_path))
        if _spec is None or _spec.loader is None:
            return False, "could not load obligations module spec"
        _mod = _ilu.module_from_spec(_spec)
        # Pre-register to satisfy Python 3.14 dataclass __module__ validation.
        import sys as _sys
        _sys.modules["_hq_obligations"] = _mod
        _spec.loader.exec_module(_mod)
        ws_path = Path(workspace_str).expanduser().resolve()
        _mod.ingest_injection_payload(ws_path, payload, workspace_str=workspace_str)
        return True, ""
    except Exception as exc:
        return False, str(exc) or "unexpected persistence error"


def _persist_source_read_receipt(workspace_str: str, payload: Dict[str, Any]) -> tuple[bool, str]:
    """Append a source-read receipt row (best-effort, non-blocking)."""
    obligations_path = TOOLS_DIR / "hacker-question-obligations.py"
    if not obligations_path.is_file():
        return False, f"missing obligations tool: {obligations_path}"
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("_hq_obligations_receipt", str(obligations_path))
        if _spec is None or _spec.loader is None:
            return False, "could not load obligations module spec"
        _mod = _ilu.module_from_spec(_spec)
        import sys as _sys
        _sys.modules["_hq_obligations_receipt"] = _mod
        _spec.loader.exec_module(_mod)
        ws_path = Path(workspace_str).expanduser().resolve()
        _mod.record_source_read_receipt(ws_path, payload, workspace_str=workspace_str)
        return True, ""
    except Exception as exc:
        return False, str(exc) or "unexpected persistence error"


if __name__ == "__main__":
    sys.exit(main())
