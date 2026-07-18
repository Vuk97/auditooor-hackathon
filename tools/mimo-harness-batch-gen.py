#!/usr/bin/env python3
"""
mimo-harness-batch-gen.py - Generate context-grounded MIMO hunt batches.

r36-rebuttal: registered lane mimo-harness-build-2026-05-27 in
.auditooor/agent_pathspec.json; this file is in the declared pathspec.

Replaces the naive "fire hacker_question at workspace_path" pattern with
a HARNESS-WRAPPED pattern that pre-fetches MCP context per workspace and
embeds it into every task's prompt. MIMO then has the same cached
knowledge a Claude Agent would see at Layer-1 recall time.

Per workspace, fetches (one shot, reused across all tasks for that ws):
  - vault_engagement_status / vault_live_target_report / vault_known_dead_ends
  - vault_exploit_context / vault_hackerman_chain_candidates
  - vault_hackerman_novel_vector_context / vault_resume_context
  - vault_invariant_library / vault_hacker_brief_for_lane

Plus reads workspace SCOPE.md + SEVERITY.md + BUG_BOUNTY.md if present.

MIMO emits strict-JSON candidate with applies_to_target/confidence/
candidate_finding/file_path_hint/severity_estimate/rubric_row_cited/
dupe_check/falsification_attempt/novel_angle_score/chain_with/notes.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import json
import random
import subprocess
import sys
import time
from pathlib import Path

VAULT_MCP = Path(__file__).resolve().parent / "vault-mcp-server.py"

MCP_CONTEXT_CAP = 2000
TOTAL_CONTEXT_CAP = 20000
TASK_CONTEXT_CAP = 8000
KNOWN_DEAD_END_BLOCK_LIMIT = 5

MCP_CALLS: list[tuple[str, dict]] = [
    ("vault_engagement_status", {}),
    ("vault_live_target_report", {"limit": 8}),
    ("vault_known_dead_ends", {"limit": 15}),
    ("vault_exploit_context", {"limit": 5}),
    ("vault_hackerman_chain_candidates", {"limit": 8}),
    ("vault_hackerman_novel_vector_context", {"limit": 5}),
    ("vault_resume_context", {"limit": 3}),
    ("vault_invariant_library", {"limit": 10}),
    ("vault_mimo_corpus_intelligence", {"limit": 12}),
    ("vault_exploit_narratives_synthesized", {"max_narratives": 5}),
    ("vault_global_chain_template_match", {"max_matches": 5}),
]


def fetch_mcp(workspace_path: str, callable_name: str, extra_args: dict,
              lane_id: str | None = None) -> str:
    args = {"workspace_path": workspace_path}
    args.update(extra_args)
    if callable_name == "vault_hacker_brief_for_lane" and lane_id:
        args["lane_id"] = lane_id
    cmd = ["python3", str(VAULT_MCP), "--call", callable_name,
           "--args", json.dumps(args)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=60, check=False)
        out = (result.stdout or "").strip() or (result.stderr or "").strip()
        return out[:MCP_CONTEXT_CAP] if out else f"<MCP-{callable_name}:no-output>"
    except subprocess.TimeoutExpired:
        return f"<MCP-{callable_name}:timeout>"
    except Exception as e:
        return f"<MCP-{callable_name}:error:{type(e).__name__}>"


def compact_json(obj: object, cap: int = MCP_CONTEXT_CAP) -> str:
    try:
        text = json.dumps(obj, sort_keys=True, ensure_ascii=True)
    except TypeError:
        text = str(obj)
    return text[:cap]


def latest_reweight_path(base_dir: Path) -> Path | None:
    paths = sorted(base_dir.glob("hacker_q_reweight_*.jsonl"))
    return paths[-1] if paths else None


def load_reweight_scores(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    out: dict[str, dict] = {}
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
        except json.JSONDecodeError:
            continue
        qid = str(row.get("question_id") or "").strip()
        if qid:
            out[qid] = row
    return out


def question_signal_score(question: dict, reweights: dict[str, dict]) -> float:
    row = reweights.get(str(question.get("question_id") or ""))
    if not row:
        return 0.0
    try:
        return float(row.get("signal_score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def normalize_question_record(row: dict) -> dict:
    qid = row.get("record_id") or row.get("question_id") or row.get("id") or "?"
    text = row.get("statement") or row.get("question_text") or row.get("prompt") or ""
    attack_class = (
        row.get("attack_class_anchor")
        or row.get("attack_class")
        or row.get("class")
        or "unknown"
    )
    return {
        "question_id": str(qid),
        "question_text": str(text),
        "attack_class": str(attack_class),
        "target_language": str(row.get("target_language") or row.get("language") or ""),
        "function_signature": str(row.get("function_signature") or ""),
        "target_contract_patterns": row.get("target_contract_patterns") or [],
        "target_function_patterns": row.get("target_function_patterns") or [],
        "raw": row,
    }


def load_dead_end_records(path: Path, workspace_name: str) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if row.get("workspace") != workspace_name:
            continue
        out.append(row)
    return out


# E1.2 (F1): the canonical exploit-queue corpus-driven-hunt writes with
# source=="corpus-hunt-fuel" (see corpus-driven-hunt.py:_hypothesis_to_row). Each
# such row carries broken_invariant_ids[0] (the matched corpus invariant) and
# negative_control (the differential_test_idea). We read these BEFORE building the
# mimo tasks so the pipeline's real LLM hunt is INV-grounded: the matched
# invariant + its differential become first-class fields on every task and are
# printed into the task prompt. Mirrors the field set corpus-driven-hunt.py's own
# build_mimo_batch (~1072) already emits; the pipeline-consumed batch-gen did not.
CORPUS_HUNT_FUEL_SOURCE = "corpus-hunt-fuel"


def load_corpus_hunt_fuel_index(workspace_path: str) -> dict:
    """Index corpus-hunt-fuel exploit-queue rows for INV-grounding tasks.

    Returns a dict with three lookup maps + a workspace-level fallback:
      by_unit:     "contract.function" (lowercased) -> {inv, diff}
      by_function: bare function name (lowercased)   -> {inv, diff}
      by_contract: contract file basename/path (low) -> {inv, diff}
      fallback:    the highest-priority fuel row's {inv, diff}, or {} if none.
    Each value picks the highest priority_score row for that key. Missing or
    malformed queue files degrade to empty maps (the attach becomes a no-op).
    """
    empty = {"by_unit": {}, "by_function": {}, "by_contract": {}, "fallback": {}}
    try:
        qpath = Path(workspace_path) / ".auditooor" / "exploit_queue.json"
        if not qpath.is_file():
            return empty
        rows = json.loads(qpath.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return empty
    if not isinstance(rows, list):
        return empty
    by_unit: dict[str, dict] = {}
    by_function: dict[str, dict] = {}
    by_contract: dict[str, dict] = {}
    best_fallback: dict = {}
    best_fallback_score = float("-inf")

    def _better(store: dict, key: str, score: float, payload: dict) -> None:
        cur = store.get(key)
        if cur is None or score > cur.get("_score", float("-inf")):
            store[key] = {**payload, "_score": score}

    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("source") or "") != CORPUS_HUNT_FUEL_SOURCE:
            continue
        inv_ids = row.get("broken_invariant_ids") or []
        if not isinstance(inv_ids, list) or not inv_ids:
            continue
        inv = str(inv_ids[0] or "").strip()
        if not inv:
            continue
        diff = str(row.get("negative_control") or "").strip()
        try:
            score = float(row.get("priority_score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        payload = {"matched_invariant_id": inv, "differential_test_idea": diff}
        contract = str(row.get("contract") or "").strip().lower()
        function = str(row.get("function") or "").strip().lower()
        if contract and function:
            _better(by_unit, contract + "." + function, score, payload)
        if function:
            _better(by_function, function, score, payload)
        if contract:
            _better(by_contract, contract, score, payload)
        if score > best_fallback_score:
            best_fallback_score, best_fallback = score, payload
    # strip the private _score book-keeping key from every stored payload
    for store in (by_unit, by_function, by_contract):
        for k in store:
            store[k] = {kk: vv for kk, vv in store[k].items() if kk != "_score"}
    return {"by_unit": by_unit, "by_function": by_function,
            "by_contract": by_contract, "fallback": best_fallback}


def resolve_inv_grounding(question: dict, fuel_index: dict) -> dict:
    """Pick the INV-grounding payload for one hunt question from the fuel index.

    Match precedence: an exact contract.function unit hit (when the question
    names both a contract and function pattern), then a bare-function-name hit,
    then a contract-file hit, then the workspace-level highest-priority fallback.
    Returns {} when the queue has no corpus-hunt-fuel rows (attach is a no-op).
    """
    if not fuel_index:
        return {}
    funcs = [str(x).strip().lower() for x in
             (question.get("target_function_patterns") or []) if str(x).strip()]
    contracts = [str(x).strip().lower() for x in
                 (question.get("target_contract_patterns") or []) if str(x).strip()]
    by_unit = fuel_index.get("by_unit") or {}
    by_function = fuel_index.get("by_function") or {}
    by_contract = fuel_index.get("by_contract") or {}
    for c in contracts:
        for fn in funcs:
            hit = by_unit.get(c + "." + fn)
            if hit:
                return hit
    for fn in funcs:
        if fn in by_function:
            return by_function[fn]
    for c in contracts:
        if c in by_contract:
            return by_contract[c]
        # contract patterns are frequently a basename or partial path; allow a
        # substring match against the indexed contract keys.
        for key, payload in by_contract.items():
            if c and (c in key or key in c):
                return payload
    return fuel_index.get("fallback") or {}


def relevant_dead_end_rows(rows: list[dict], attack_class: str) -> list[dict]:
    ac_lower = attack_class.lower()
    hits: list[dict] = []
    for row in rows:
        row_ac = str(row.get("attack_class") or "").lower()
        row_text = json.dumps(row, ensure_ascii=True).lower()
        if ac_lower and (row_ac == ac_lower or ac_lower in row_text):
            hits.append(row)
        if len(hits) >= KNOWN_DEAD_END_BLOCK_LIMIT:
            break
    return hits


def build_attack_context(workspace_path: str, question: dict,
                         reweight_record: dict | None,
                         dead_end_rows: list[dict],
                         cache: dict) -> tuple[str, dict]:
    attack_class = question.get("attack_class") or "unknown"
    target_language = question.get("target_language") or ""
    cache_key = (attack_class, target_language)
    if cache_key not in cache:
        snippets = {
            "vault_attack_class_evidence_v3": fetch_mcp(workspace_path, "vault_attack_class_evidence_v3", {
                "attack_class": attack_class,
                "target_language": target_language,
                "limit": 5,
                "min_verification_tier": 2,
                "exclude_quarantine": True,
                "with_fixtures": True,
                "cross_language_neighbors": bool(target_language),
                "neighbor_limit": 3,
            }),
            "vault_anti_pattern_corpus": fetch_mcp(workspace_path, "vault_anti_pattern_corpus", {
                "query": str(attack_class).replace("-", " "),
                "limit": 3,
                "body_chars": 450,
            }),
            "vault_exploit_narratives_synthesized": fetch_mcp(workspace_path, "vault_exploit_narratives_synthesized", {
                "max_narratives": 3,
            }),
            "vault_global_chain_template_match": fetch_mcp(workspace_path, "vault_global_chain_template_match", {
                "max_matches": 5,
            }),
        }
        cache[cache_key] = snippets
    snippets = cache[cache_key]

    sig = question.get("function_signature") or ""
    if sig:
        shape = fetch_mcp(workspace_path, "vault_function_signature_shape", {
            "function_signature": sig,
            "language": target_language or "go",
        })
    else:
        shape = compact_json({
            "status": "unavailable",
            "reason": "harness mode has no concrete file body",
            "target_function_patterns": question.get("target_function_patterns") or [],
            "target_contract_patterns": question.get("target_contract_patterns") or [],
        }, 900)

    dead_hits = relevant_dead_end_rows(dead_end_rows, attack_class)
    dead_lines = ["=== KNOWN DEAD-ENDS - DO NOT RE-INVESTIGATE ==="]
    if dead_hits:
        for row in dead_hits:
            dead_lines.append("- " + compact_json(row, 800))
    else:
        dead_lines.append("- no scoped dead-end row matched this attack class")

    reweight_lines = ["=== HACKER-Q REWEIGHT SCORE ==="]
    if reweight_record:
        reweight_lines.append(compact_json({
            "signal_score": reweight_record.get("signal_score", 0),
            "signal_class": reweight_record.get("signal_class", "unknown"),
            "yes_count": reweight_record.get("yes_count", 0),
            "maybe_count": reweight_record.get("maybe_count", 0),
            "no_count": reweight_record.get("no_count", 0),
            "total_evals": reweight_record.get("total_evals", 0),
        }, 700))
    else:
        reweight_lines.append("- unavailable: no matching reweight ledger row")

    lines = [
        "=== FUNCTION SIGNATURE SHAPE ===",
        shape[:900],
        "\n".join(dead_lines),
        "\n".join(reweight_lines),
        "=== ATTACK-CLASS EVIDENCE AND GUARDRAILS ===",
    ]
    for name, text in snippets.items():
        lines.append(f"### MCP {name}")
        lines.append((text or "<no context available>")[:MCP_CONTEXT_CAP])
    block = "\n".join(lines)[:TASK_CONTEXT_CAP]
    metadata = {
        "schema": "auditooor.mimo_prompt_context_feed.v1",
        "attack_class": attack_class,
        "target_language": target_language,
        "context_sha256": hashlib.sha256(block.encode("utf-8")).hexdigest(),
        "context_fields": [
            "function_signature_shape",
            "known_dead_ends_verbatim",
            "hacker_q_reweight_score",
            "attack_class_evidence",
            "anti_patterns",
            "exploit_narratives",
            "global_chain_templates",
        ],
        "known_dead_end_matches": len(dead_hits),
        "has_reweight_record": bool(reweight_record),
        "function_signature_present": bool(sig),
        "context_chars": len(block),
        "mcp_calls": list(snippets.keys()) + (["vault_function_signature_shape"] if sig else []),
    }
    return block, metadata


def read_workspace_doc(ws_path: Path, name: str, cap: int = 2500) -> str:
    p = ws_path / name
    if not p.is_file():
        return f"<NO-{name}>"
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:cap]
    except Exception as e:
        return f"<READ-FAIL-{name}:{type(e).__name__}>"


# r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
def build_deep_silo_block(ws: Path, cap: int = 4000) -> str:
    """Distil the two deep-analysis silos into a compact workspace-level block
    for the harness-mode brief (FIX 1 math_spec + FIX 2 guard_probe_packets).

    Harness mode has no concrete file body, so we surface a workspace-level
    digest: the math-spec one-sided-mutation VIOLATIONS + top fuzz candidates
    (per contract) and the per-guard 'what this guard does NOT check' packets.
    Returns '' when neither silo artifact is present."""
    lines: list[str] = []

    # --- Silo 1: math_spec.json ---
    mpath = ws / "math_invariants" / "math_spec.json"
    if mpath.is_file():
        try:
            spec = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception:
            spec = None
        contracts = spec.get("contracts") if isinstance(spec, dict) else None
        if isinstance(contracts, dict) and contracts:
            ml = ["=== MATH-INVARIANT SPEC (conservation laws + one-sided-mutation violations) ==="]
            shown = 0
            for cname in sorted(contracts.keys()):
                if shown >= 8:
                    break
                cdata = contracts.get(cname)
                if not isinstance(cdata, dict):
                    continue
                viols = cdata.get("violations") if isinstance(cdata.get("violations"), list) else []
                cands = cdata.get("candidates") if isinstance(cdata.get("candidates"), list) else []
                if not viols and not cands:
                    continue
                shown += 1
                ml.append(f"- contract {str(cname)[:60]}:")
                for v in viols[:3]:
                    if isinstance(v, dict):
                        fn = str(v.get("function") or v.get("fn") or "?")[:60]
                        law = str(v.get("law") or v.get("conservation_law") or v.get("hint") or "")[:140]
                        ml.append(f"    VIOLATION {fn}: {law}")
                for c in cands[:3]:
                    if isinstance(c, dict):
                        txt = str(c.get("invariant") or c.get("description") or c.get("hint") or "")[:140]
                    elif isinstance(c, str):
                        txt = c[:140]
                    else:
                        txt = ""
                    if txt:
                        ml.append(f"    fuzz: {txt}")
            if len(ml) > 1:
                lines.extend(ml)

    # --- Silo 2: guard_probe_packets.jsonl ---
    gpath = ws / ".auditooor" / "guard_probe_packets.jsonl"
    if gpath.is_file():
        gl = ["=== GUARD PROBE PACKETS (per-guard blind spot - what each guard does NOT check) ==="]
        n = 0
        try:
            with gpath.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or n >= 10:
                        continue
                    try:
                        r = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(r, dict):
                        continue
                    n += 1
                    gid = str(r.get("guard_id") or "?")[:80]
                    fl = str(r.get("file_line") or "?")[:120]
                    hint = str(r.get("invariant_hint") or r.get("checks") or "")[:160]
                    gl.append(f"- guard {gid} @ {fl}: blind spot: {hint}")
        except OSError:
            pass
        if len(gl) > 1:
            lines.extend(gl)

    if not lines:
        return ""
    return "\n".join(lines)[:cap]


def build_context_block(workspace_path: str, lane_id: str) -> str:
    ws = Path(workspace_path)
    parts: list[str] = []
    for doc in ["SCOPE.md", "SEVERITY.md", "BUG_BOUNTY.md"]:
        parts.append(f"### WORKSPACE-DOC: {doc}\n{read_workspace_doc(ws, doc)}\n")
    # r36-rebuttal: lane silo-brief-injection-2026-06 registered in .auditooor/agent_pathspec.json
    silo_block = build_deep_silo_block(ws)
    if silo_block:
        parts.append(f"### DEEP-ANALYSIS SILOS (math invariants + guard blind-spots)\n{silo_block}\n")
    for cb, kwargs in MCP_CALLS:
        sys.stderr.write(f"  mcp> {cb} ...\n"); sys.stderr.flush()
        parts.append(f"### MCP: {cb}\n{fetch_mcp(workspace_path, cb, kwargs, lane_id=lane_id)}\n")
    sys.stderr.write("  mcp> vault_hacker_brief_for_lane ...\n"); sys.stderr.flush()
    brief = fetch_mcp(workspace_path, "vault_hacker_brief_for_lane",
                      {"limit": 5}, lane_id=lane_id)
    parts.append(f"### MCP: vault_hacker_brief_for_lane\n{brief}\n")
    return "\n".join(parts)[:TOTAL_CONTEXT_CAP]



# --------------------------------------------------------------------------
# Language-aware question selection. The promoted question bank is untagged
# (target_language empty), so a Rust/crypto target was fed the full EVM-heavy
# bank and got ~0 signal. We INFER each question's language/domain from its
# text and rank/optionally-filter by the workspace's language so every
# workspace gets language-appropriate hypotheses. Generic + target-agnostic.
# --------------------------------------------------------------------------
_LANG_SIGNALS = {
    "solidity": ("msg.sender", "require(", "modifier ", "reentran", "erc20",
                 "erc721", "erc4626", " payable", "transferfrom", "delegatecall",
                 "uint256", "onlyowner", "slippage", "approve(", " wei", "gwei",
                 "selfdestruct", "solidity", "openzeppelin", " evm"),
    "rust": ("unsafe ", "unwrap(", "panic!", "vec<", "trait ", "&mut ",
             " borrow", "impl ", "option<", "result<", " cargo", ".clone()",
             "no_std", "#[derive", "as usize", "saturating_"),
    "go": ("goroutine", "cosmos-sdk", " keeper", "func (", "ante handler",
           " chan ", "cometbft", "tendermint", "msgserver", "sdk.context"),
    "move": (" move ", "aptos", " sui ", "resource ", "0x1::", "acquires "),
    "crypto": ("constant-time", "constant time", "timing side", "nonce reuse",
               "k-reuse", "fiat-shamir", "fiat shamir", "transcript", "scalar",
               "curve point", "subgroup", "bulletproof", "clsag", "mlsag",
               "schnorr", "frost", "threshold sig", "commitment", "zero-knowledge",
               "field element", "modular reduction", "point validation",
               "canonical encoding", "ed25519", "ristretto", "merkle proof"),
}


def _infer_question_language(text: str) -> str:
    """Classify a question by language/domain from its text. Returns one of
    solidity/rust/go/move/crypto, or '' (agnostic) when no clear signal."""
    t = (text or "").lower()
    best, best_n = "", 0
    for lang, sigs in _LANG_SIGNALS.items():
        n = sum(1 for sg in sigs if sg in t)
        if n > best_n:
            best, best_n = lang, n
    return best if best_n >= 1 else ""


# Directories that hold VENDORED / TOOLING code whose language must NOT define the
# workspace's target language. A Solidity workspace ships node_modules/@nomicfoundation/
# edr/Cargo.toml (Rust hardhat tooling); a Go workspace vendors deps; etc. Counting these
# misroutes the hunt (NUVA 2026-06-30: 512 .sol + go.mod workspace detected as "rust" off
# a single node_modules Cargo.toml, starving the EVM core of the right methodology).
_VENDOR_DIR_NAMES = {
    "node_modules", "lib", "vendor", "external", "third_party", "third-party",
    ".git", "target", "dist", "build", "out", "cache", ".foundry", "artifacts",
    "deps", "submodules", "testdata",
}
_EXT_TO_LANG = {".sol": "solidity", ".rs": "rust", ".go": "go", ".move": "move"}


def _iter_source_files(root):
    """Walk root yielding source files, pruning vendored/tooling dirs."""
    import os as _os
    for dirpath, dirnames, filenames in _os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _VENDOR_DIR_NAMES and not d.startswith(".")]
        for fn in filenames:
            yield fn


def _dominant_languages(counts: dict[str, int], floor_frac: float = 0.30) -> str:
    """Dominant language, comma-joining a genuinely-mixed secondary (>= floor_frac of
    max). Returns '' when no signal. Deterministic order by descending count then name.
    Callers pass a lower floor for an AUTHORITATIVE in-scope unit set (every language
    present is in-scope and must be hunted) than for a noisy file-count fallback."""
    counts = {k: v for k, v in counts.items() if v > 0}
    if not counts:
        return ""
    top = max(counts.values())
    keep = sorted((k for k, v in counts.items() if v >= max(1, top * floor_frac)),
                  key=lambda k: (-counts[k], k))
    return ",".join(keep)


def _detect_workspace_language(ws_path: str) -> str:
    """Target language by PREVALENCE of the workspace's own source (vendored/tooling
    code excluded), NOT first-match on a stray manifest. Prefers the authoritative
    in-scope unit set (.auditooor/inscope_units.jsonl) when present so the hunt targets
    exactly the in-scope languages; else counts source files per language. Returns a
    single lang or a comma-joined SET for genuinely-mixed workspaces ('' when unknown)."""
    from pathlib import Path as _P
    ws = _P(ws_path)
    if not ws.is_dir():
        return ""
    # 1) Authoritative: in-scope unit language distribution.
    units = ws / ".auditooor" / "inscope_units.jsonl"
    if units.is_file():
        import json as _json
        counts: dict[str, int] = {}
        try:
            for line in units.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = _json.loads(line)
                except Exception:
                    continue
                lang = str(d.get("language") or d.get("lang") or "").strip().lower()
                if not lang:
                    f = str(d.get("file") or d.get("path") or d.get("unit") or "")
                    lang = _EXT_TO_LANG.get("." + f.rsplit(".", 1)[-1], "") if "." in f else ""
                if lang:
                    counts[lang] = counts.get(lang, 0) + 1
        except OSError:
            counts = {}
        # Authoritative in-scope set: include every language with a meaningful share
        # (>=15%) - all are genuinely in-scope assets that must be hunted (NUVA's go
        # cosmos vault is 26% of units and a separate in-scope asset).
        dom = _dominant_languages(counts, floor_frac=0.15)
        if dom:
            return dom
    # 2) Fallback: count this workspace's OWN source files (vendored dirs pruned).
    src = ws / "src"
    roots = [src] if src.is_dir() else [ws]
    counts = {}
    for root in roots:
        try:
            for fn in _iter_source_files(root):
                ext = "." + fn.rsplit(".", 1)[-1] if "." in fn else ""
                lang = _EXT_TO_LANG.get(ext)
                if lang:
                    counts[lang] = counts.get(lang, 0) + 1
        except OSError:
            pass
    return _dominant_languages(counts)


def _language_fit(question_lang: str, target_language: str) -> int:
    """Score how well a question's language fits the target. Higher = better.
    Concrete cross-language mismatch is penalized; crypto/agnostic are broadly
    useful. ``target_language`` may be a comma-joined SET for mixed workspaces -
    score the BEST fit across the set so a sol+go ws ranks both sol and go
    questions as in-language (NUVA mixed EVM+cosmos)."""
    if not target_language:
        return 0
    targets = [t.strip() for t in str(target_language).split(",") if t.strip()]
    if not targets:
        return 0
    if not question_lang:
        return 1  # agnostic - broadly applicable
    best = -3
    for tgt in targets:
        if question_lang == tgt:
            best = max(best, 3)
        elif question_lang == "crypto":
            best = max(best, 3 if tgt == "rust" else 1)
        # else concrete different-language mismatch contributes -3 (the init value)
    return best


def load_questions(path: Path, n: int, seed: int = 42,
                   reweights: dict[str, dict] | None = None,
                   target_language: str = "",
                   exclude_mismatch: bool = False,
                   extra_paths: list[Path] | None = None) -> list[dict]:
    qs: list[dict] = []
    sources = [path] + list(extra_paths or [])
    seen_ids: set[str] = set()
    for src in sources:
        if not src or not Path(src).is_file():
            continue
        with Path(src).open(encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                q = normalize_question_record(r)
                stmt = q.get("question_text", "")
                if not (isinstance(stmt, str) and 80 < len(stmt) < 3000):
                    continue
                qid = str(q.get("question_id") or "")
                if qid and qid in seen_ids:
                    continue
                seen_ids.add(qid)
                # tag language: explicit field wins, else infer from text
                qlang = (q.get("target_language") or "").strip().lower()
                if not qlang:
                    qlang = _infer_question_language(stmt)
                    q["target_language"] = qlang
                qs.append(q)
    if target_language:
        # EMPIRICAL hard-exclude: questions observed to be inapplicable across
        # rust/solidity hunts (question-target-fit ledger) are dropped for this
        # target language - this catches EVM/DeFi questions that language
        # INFERENCE misses (zebra was 79% question-inapplicable). Self-correcting
        # as more hunts run. Skippable via AUDITOOOR_NO_FIT_EXCLUDE=1.
        if os.environ.get("AUDITOOOR_NO_FIT_EXCLUDE", "") not in ("1", "true", "yes"):
            try:
                _fit_path = (Path(__file__).resolve().parent.parent
                             / "audit/corpus_tags/derived/question_target_fit.jsonl")
                # target_language may be a single lang OR a comma-joined SET (mixed
                # workspace, e.g. "go,solidity,cadence"). A question is excluded only
                # if it is dead (exclude=true) for EVERY language the target contains,
                # so Solidity questions are NOT dropped on a mostly-Go repo.
                _tgt_langs = {x.strip() for x in str(target_language).split(",") if x.strip()}
                _excl_by_lang = {}
                if _fit_path.is_file() and _tgt_langs:
                    for _ln in _fit_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        if not _ln.strip():
                            continue
                        try:
                            _r = json.loads(_ln)
                        except ValueError:
                            continue
                        if _r.get("exclude"):
                            _excl_by_lang.setdefault(str(_r.get("target_language")), set()).add(
                                str(_r.get("question_id")))
                # dead-across-ALL-target-languages:
                _present = [l for l in _tgt_langs if l in _excl_by_lang]
                if _present:
                    _dead = set.intersection(*(_excl_by_lang[l] for l in _present))
                    if _dead:
                        qs = [q for q in qs if str(q.get("question_id")) not in _dead]
            except OSError:
                pass
        if exclude_mismatch:
            qs = [q for q in qs
                  if _language_fit(q.get("target_language", ""), target_language) >= 0]
        qs.sort(key=lambda q: (
            -_language_fit(q.get("target_language", ""), target_language),
            -question_signal_score(q, reweights or {}),
            str(q.get("question_id") or ""),
        ))
        return qs[:min(n, len(qs))]
    if reweights:
        qs.sort(key=lambda q: (
            -question_signal_score(q, reweights),
            str(q.get("question_id") or ""),
        ))
        return qs[:min(n, len(qs))]
    random.seed(seed)
    return random.sample(qs, min(n, len(qs)))


def build_task(idx, workspace_name, workspace_path,
               question, context_block, task_context_block,
               task_context_metadata, reweight_record=None,
               inv_grounding=None):
    # FIX: llm-fanout-dispatcher.py reads task["prompt"] (single field).
    # Do NOT split into system_prompt / user_prompt; those keys get dropped.
    nl = chr(10)
    hypothesis_id = question.get("question_id", "?")
    hypothesis = question.get("question_text", "")
    attack_class = question.get("attack_class", "unknown")
    # E1.2 (F1): INV-grounding from the corpus-hunt-fuel exploit-queue rows so
    # the hunt is anchored to a real corpus invariant + its differential idea.
    inv_grounding = inv_grounding or {}
    matched_invariant_id = str(inv_grounding.get("matched_invariant_id") or "")
    differential_test_idea = str(inv_grounding.get("differential_test_idea") or "")
    parts = [
        "You are a security auditor for the " + workspace_name + " bug-bounty target.",
        "Read the cached project context below and apply the hypothesis.",
        "Output STRICT JSON only - no prose around it.",
        "",
        "REQUIRED JSON KEYS (all required, even if null or 'NA'):",
        "  applies_to_target: yes | no | maybe",
        "  confidence: low | medium | high",
        "  candidate_finding: string (one-sentence brief)",
        "  file_path_hint: string (must match a file mentioned in context)",
        "  severity_estimate: LOW | MEDIUM | HIGH | CRITICAL | NA",
        "  rubric_row_cited: string verbatim from SEVERITY.md context",
        "  dupe_check: string (cross-ref filed / known_dead_ends)",
        "  falsification_attempt: string (what would disprove this?)",
        "  novel_angle_score: integer 1-5",
        "  chain_with: list of vault_hackerman_chain_candidates IDs (or [])",
        "  notes: string",
        "",
        "HARD RULES:",
        "  - If file_path_hint is not anchored to context, set applies_to_target='no'.",
        "  - If dupe_check finds a hit in filed or known_dead_ends, set applies_to_target='no'.",
        "  - If severity_estimate is HIGH or CRITICAL, cite rubric_row_cited verbatim.",
        "  - Refuse to hallucinate. Refuse to over-claim.",
        "  - NON-SELF IMPACT (R24): if the ONLY actor that can trigger the issue is a",
        "    privileged/trusted role (admin, owner, roleSetter, feeSetter, governance,",
        "    operator) harming the protocol it controls - with NO unprivileged attacker",
        "    and NO non-self victim - set applies_to_target='no'. Self-inflicted /",
        "    centralization is NOT a finding. A missing zero-address or validation check",
        "    on an admin-only setter (require msg.sender==<role>) is Informational at",
        "    most, never HIGH.",
        "  - DESIGNED-AS-INTENDED (R45): if the 'missing check' is a documented design",
        "    choice or a trusted-admin footgun, set applies_to_target='no' UNLESS an",
        "    UNPRIVILEGED caller can reach the impact. Trusted-role actions are trusted by",
        "    assumption; do not file them unless the rubric lists admin-abuse/",
        "    centralization as in-scope.",
        "  - RUBRIC FIT (R52): if candidate_finding does not map to a verbatim SEVERITY.md",
        "    row for an UNPRIVILEGED-attacker impact, set applies_to_target='no'.",
        "    severity_estimate must reflect the realistic attacker, not a worst-case",
        "    narrative that requires a trusted actor to misbehave.",
        "",
        "WORKSPACE: " + workspace_path,
        "",
        "HYPOTHESIS (source: " + str(hypothesis_id) + "):",
        hypothesis,
        "",
        "ATTACK_CLASS: " + str(attack_class),
        "",
    ]
    if matched_invariant_id:
        parts += [
            "INV-GROUNDING (corpus-hunt-fuel): this unit broke corpus invariant "
            + matched_invariant_id + ".",
            "Anchor your analysis to that invariant; treat it as the proof obligation.",
        ]
        if differential_test_idea:
            parts.append("DIFFERENTIAL TEST IDEA: " + differential_test_idea)
        parts.append("")
    parts += [
        "=== AGI-GRADE TASK CONTEXT (bounded, soft-fail safe) ===",
        task_context_block,
        "",
        "=== PROJECT CONTEXT (cached, read-only) ===",
        context_block,
        "=== END CONTEXT ===",
        "",
        "Apply hypothesis. Return STRICT JSON only.",
    ]
    prompt = nl.join(parts)
    return {
        "task_id": "mimo_harness_" + workspace_name + "_" + f"{idx:04d}",
        "task_type": "workspace_hunt_harnessed",
        "workspace": workspace_name,
        "workspace_path": workspace_path,
        "source_question_id": hypothesis_id,
        "attack_class": attack_class,
        "hacker_q_reweight": reweight_record or {},
        "mimo_context_feed": task_context_metadata,
        "matched_invariant_id": matched_invariant_id,
        "differential_test_idea": differential_test_idea,
        "prompt": prompt,
        "max_tokens": 1500,
    }



def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace-name", required=True)
    ap.add_argument("--workspace-path", required=True)
    ap.add_argument("--question-corpus",
                    default="audit/corpus_tags/derived/hacker_questions_library_promoted.jsonl")
    ap.add_argument("--num-questions", type=int, default=100)
    ap.add_argument("--lane-id", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dead-ends", default="reports/known_dead_ends.jsonl")
    ap.add_argument("--reweight", action="store_true",
                    help="Load latest hacker_q_reweight_*.jsonl and rank questions by signal_score.")
    ap.add_argument("--no-reweight", action="store_true",
                    help="Disable automatic hacker-q reweight loading.")
    ap.add_argument("--reweight-path", default="",
                    help="Explicit hacker-q reweight JSONL path. Implies --reweight.")
    ap.add_argument("--target-language", default="auto",
                    help="Rank/filter questions by target language (rust/solidity/go/"
                         "move). 'auto' detects from the workspace source tree; "
                         "'' disables language-aware selection.")
    ap.add_argument("--exclude-language-mismatch", action="store_true",
                    help="Drop questions tagged for a DIFFERENT concrete language "
                         "(e.g. solidity-only questions on a rust target).")
    ap.add_argument("--extra-questions", default="",
                    help="Extra question JSONL merged into the bank (e.g. a "
                         "crypto-specific seed). 'auto' adds the crypto seed for "
                         "rust/crypto targets.")
    args = ap.parse_args(argv)

    qpath = Path(args.question_corpus)
    if not qpath.is_absolute():
        qpath = Path(__file__).resolve().parent.parent / qpath
    if not qpath.is_file():
        sys.stderr.write(f"ERROR: question corpus not found: {qpath}\n")
        return 1

    repo_root = Path(__file__).resolve().parent.parent
    reweights: dict[str, dict] = {}
    reweight_path: Path | None = None
    if not args.no_reweight:
        if args.reweight_path:
            reweight_path = Path(args.reweight_path)
            if not reweight_path.is_absolute():
                reweight_path = repo_root / reweight_path
        else:
            reweight_path = latest_reweight_path(repo_root / "audit/corpus_tags/derived")
        reweights = load_reweight_scores(reweight_path)
        sys.stderr.write(
            f"[harness-gen] loaded {len(reweights)} reweight rows"
            f"{' from ' + str(reweight_path) if reweight_path else ''}\n"
        )

    dead_path = Path(args.dead_ends)
    if not dead_path.is_absolute():
        dead_path = repo_root / dead_path
    dead_end_rows = load_dead_end_records(dead_path, args.workspace_name)
    sys.stderr.write(
        f"[harness-gen] loaded {len(dead_end_rows)} dead-end rows for "
        f"{args.workspace_name}\n"
    )

    sys.stderr.write(f"[harness-gen] workspace={args.workspace_name}\n"
                     "[harness-gen] pre-fetching MCP context (one-shot, reused)...\n")
    t0 = time.time()
    ctx = build_context_block(args.workspace_path, args.lane_id)
    sys.stderr.write(
        f"[harness-gen] context: {len(ctx)} chars in {time.time()-t0:.1f}s\n")

    target_language = args.target_language
    if target_language == "auto":
        target_language = _detect_workspace_language(args.workspace_path)
    extra_paths: list[Path] = []
    crypto_seed = repo_root / "reference" / "crypto_hacker_questions.jsonl"
    if args.extra_questions == "auto":
        if target_language == "rust" and crypto_seed.is_file():
            extra_paths.append(crypto_seed)
    elif args.extra_questions:
        ep = Path(args.extra_questions)
        if not ep.is_absolute():
            ep = repo_root / ep
        if ep.is_file():
            extra_paths.append(ep)
    # default: auto-include the crypto seed for rust targets even if flag unset
    if not extra_paths and target_language == "rust" and crypto_seed.is_file():
        extra_paths.append(crypto_seed)
    questions = load_questions(qpath, args.num_questions, args.seed, reweights,
                               target_language=target_language,
                               exclude_mismatch=args.exclude_language_mismatch,
                               extra_paths=extra_paths)
    sys.stderr.write(
        f"[harness-gen] target_language={target_language or '(none)'} "
        f"extra_seeds={[e.name for e in extra_paths]} "
        f"sampled {len(questions)} hypotheses\n")

    # E1.2 (F1): load the corpus-hunt-fuel exploit-queue rows ONCE so every task
    # can be INV-grounded (matched_invariant_id + differential_test_idea).
    fuel_index = load_corpus_hunt_fuel_index(args.workspace_path)
    if fuel_index.get("fallback"):
        sys.stderr.write(
            f"[harness-gen] corpus-hunt-fuel INV-grounding loaded "
            f"(units={len(fuel_index.get('by_unit') or {})})\n")

    outp = Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)
    attack_context_cache: dict = {}
    with outp.open("w", encoding="utf-8") as f:
        for i, q in enumerate(questions):
            qid = str(q.get("question_id") or "").strip()
            task_context_block, task_context_metadata = build_attack_context(
                args.workspace_path,
                q,
                reweights.get(qid),
                dead_end_rows,
                attack_context_cache,
            )
            f.write(json.dumps(build_task(
                i,
                args.workspace_name,
                args.workspace_path,
                q,
                ctx,
                task_context_block,
                task_context_metadata,
                reweights.get(qid),
                resolve_inv_grounding(q, fuel_index),
            )) + "\n")
    sys.stderr.write(f"[harness-gen] wrote {len(questions)} tasks to {outp}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
