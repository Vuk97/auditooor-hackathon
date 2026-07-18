#!/usr/bin/env python3
"""Materialize per-function pre-flight packs for audit workers.

The pack is a bounded JSON artifact per Solidity function. It combines local
function shape data with best-effort Vault MCP context calls. Missing MCP
inputs are recorded as skipped blocks instead of blocking audit startup.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import os as _os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import importlib.util


SCHEMA = "auditooor.pre_flight_pack.v1"
MCP_CALLS = (
    "vault_function_signature_shape",
    "vault_function_shape_attack_evidence",
    "vault_per_function_hunter_brief",
    "vault_attack_class_evidence_v3",
    "vault_chained_attack_plan_context",
    "vault_global_chain_template_match",
    "vault_invariant_library",
    "vault_anti_pattern_corpus",
    "vault_known_dead_ends",
    "vault_cross_language_pattern_lift",
)


@dataclass(frozen=True)
class RustFunction:
    contract_name: str
    function_name: str
    contract_file: Path
    relative_file: str
    line: int
    attrs: str
    args: str = ""
    language: str = "rust"

    @property
    def selector(self) -> str:
        return f"{self.contract_name}.{self.function_name}"


def load_invariant_module(repo_root: Path):
    path = repo_root / "tools" / "per-function-invariant-gen.py"
    spec = importlib.util.spec_from_file_location("per_function_invariant_gen", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_coverage_heatmap_module(repo_root: Path):
    path = repo_root / "tools" / "workspace-coverage-heatmap.py"
    spec = importlib.util.spec_from_file_location("workspace_coverage_heatmap", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in value)


def solidity_signature(fn: Any) -> str:
    parts = [f"function {fn.function_name}({fn.args})"]
    if fn.attrs:
        parts.append(fn.attrs)
    return " ".join(part for part in parts if part).strip()


def function_language(fn: Any) -> str:
    return str(getattr(fn, "language", "solidity") or "solidity").lower()


def function_signature(fn: Any) -> str:
    if function_language(fn) == "rust":
        parts = [f"fn {fn.function_name}()"]
        if fn.attrs:
            parts.append(fn.attrs)
        return " ".join(part for part in parts if part).strip()
    return solidity_signature(fn)


def infer_contract_kind(fn: Any) -> str:
    haystack = f"{fn.contract_name} {fn.relative_file}".lower()
    for kind, needles in {
        "bridge": ("bridge", "ismp", "dispatcher", "gateway", "router"),
        "lending": ("lend", "borrow", "loan", "debt", "collateral"),
        "dex": ("swap", "amm", "pool", "pair", "exchange"),
        "oracle": ("oracle", "price", "feed"),
        "governance": ("governor", "governance", "vote"),
        "vault": ("vault", "erc4626", "strategy"),
        "rollup": ("rollup", "optimism", "arbitrum", "sequencer"),
        "custody": ("custody", "escrow", "wallet", "safe"),
        "minter": ("mint", "token"),
        "burner": ("burn",),
    }.items():
        if any(needle in haystack for needle in needles):
            return kind
    return ""


def payload_or_empty(block: dict[str, Any]) -> dict[str, Any]:
    payload = block.get("payload")
    return payload if isinstance(payload, dict) else {}


def call_status(block: dict[str, Any]) -> str:
    status = block.get("status")
    return str(status) if status else "unknown"


def _run_group_capture(
    cmd: list[str], *, cwd: Path, timeout: int
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with a HARD wall-clock timeout that survives grandchildren.

    subprocess.run(timeout=N) only signals the direct child. If that child spawns
    a grandchild that inherits the stdout/stderr pipe (vault-mcp-server.py and the
    LLM dispatcher both can), the pipe stays open after the child is killed and
    .communicate() blocks forever past the nominal timeout - an indefinite
    0%-CPU hang. Launching in a new session (own process group) and killing the
    whole group on timeout reaps the grandchildren too, so the timeout is
    actually enforced. Generic: any workspace / any child command.
    """
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            out, err = proc.communicate(timeout=10)
        except Exception:
            out, err = "", ""
        raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)


def call_vault(repo_root: Path, call: str, args: dict[str, Any], timeout: int) -> dict[str, Any]:
    cmd = [
        "python3",
        str(repo_root / "tools" / "vault-mcp-server.py"),
        "--call",
        call,
        "--args",
        json.dumps(args, sort_keys=True),
    ]
    try:
        proc = _run_group_capture(cmd, cwd=repo_root, timeout=timeout)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "call": call}
    if proc.returncode != 0:
        return {
            "status": "skipped",
            "call": call,
            "returncode": proc.returncode,
            "stderr_tail": proc.stderr[-2000:],
        }
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"raw_stdout_tail": proc.stdout[-4000:]}
    return {"status": "ok", "call": call, "payload": payload}


def _contract_filter_matches(contract_filter: str | None, path: Path, relative_file: str) -> bool:
    if not contract_filter:
        return True
    needle = contract_filter.strip()
    if not needle:
        return True
    return needle in {path.stem, path.name, relative_file, path.as_posix()}


def discover_scoped_solidity_files(
    repo_root: Path,
    workspace: Path,
    contract_filter: str | None,
) -> tuple[list[Path], dict[str, Any]]:
    """Discover Solidity files from the same scoped source set as coverage.

    ``workspace-coverage-heatmap.py`` owns the in-scope source denominator.
    Per-function preflight must use that filtered file set so full runs do not
    spend packs on generated PoC, test, or .auditooor helper contracts.
    """
    heatmap = load_coverage_heatmap_module(repo_root)
    scope = heatmap.resolve_scope(workspace)
    source_records = heatmap._source_file_records(workspace, scope)
    files: list[Path] = []
    seen: set[Path] = set()
    for record in source_records:
        if not isinstance(record, dict):
            continue
        relative_file = str(record.get("path") or "").strip()
        if not relative_file or Path(relative_file).is_absolute() or ".." in Path(relative_file).parts:
            continue
        if Path(relative_file).suffix.lower() != ".sol":
            continue
        path = workspace / relative_file
        if path in seen or not path.is_file():
            continue
        if not _contract_filter_matches(contract_filter, path, relative_file):
            continue
        seen.add(path)
        files.append(path)
    return sorted(files), {
        "source": "workspace-coverage-heatmap",
        "scope_mode": scope.get("scope_mode"),
        "source_root": scope.get("source_root"),
        "scope_globs": scope.get("scope_globs") or [],
        "scope_exclude_globs": scope.get("scope_exclude_globs") or [],
        "source_record_count": len(source_records),
        "solidity_file_count": len(files),
    }


def _guard_risk_scores(workspace: Path) -> dict[str, int]:
    """fn-name (lower) -> guard-risk score from ``.auditooor/guard_triage.json``
    (written by ``tools/guard-triage.py``). Empty dict (no prioritization) when the
    early guard-triage has not run - callers then keep their prior stable order.

    Mirrors ``tools/per-function-attack-worklist.py:_guard_risk_scores`` so the
    preflight cap/budget loop and the attack-worklist hunt order agree on which
    functions are guard-risky. The ``risk_units`` score is preferred; functions
    that appear only in ``hunt_priority_order`` get a small positive rank so they
    still sort ahead of un-flagged functions while preserving relative order.
    """
    p = workspace / ".auditooor" / "guard_triage.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    import re as _re

    out: dict[str, int] = {}
    for u in data.get("risk_units", []) or []:
        if not isinstance(u, dict):
            continue
        unit = str(u.get("unit") or u.get("loc") or "")
        m = _re.search(r"([A-Za-z_]\w*)\s*$", unit.split(":")[-1])
        if m:
            fn = m.group(1).lower()
            try:
                score = int(u.get("score") or 0)
            except (TypeError, ValueError):
                score = 0
            out[fn] = max(out.get(fn, 0), score)
    # hunt_priority_order lists function/unit names already ranked; give any not
    # already scored a small positive rank so they precede un-flagged functions.
    for entry in data.get("hunt_priority_order", []) or []:
        unit = str(entry if isinstance(entry, str) else (entry.get("unit") or entry.get("function") or "")) if entry else ""
        if not unit:
            continue
        m = _re.search(r"([A-Za-z_]\w*)\s*$", unit.split(":")[-1])
        if m:
            fn = m.group(1).lower()
            if fn not in out:
                out[fn] = 1
    return out


def vault_args_for_call(
    call: str,
    base_args: dict[str, Any],
    fn: Any,
    function_signature: str,
    shape_hash: str,
    attack_class: str,
    contract_kind_hint: str,
) -> dict[str, Any]:
    args = dict(base_args)
    language = function_language(fn)
    if call == "vault_function_signature_shape":
        args.update(
            {
                "language": language,
                "function_signature": function_signature,
                "guards_detected": [],
            }
        )
    elif call == "vault_function_shape_attack_evidence":
        args.update(
            {
                "language": language,
                "function_signature": function_signature,
                "shape_hash": shape_hash,
                "file_path": fn.relative_file,
                "limit": 5,
            }
        )
    elif call == "vault_per_function_hunter_brief":
        args.update(
            {
                "contract_path": fn.relative_file,
                "function_name": fn.function_name,
                "contract_kind_hint": contract_kind_hint,
                "target_language": language,
                "max_questions": 5,
                "max_templates": 5,
            }
        )
    elif call == "vault_attack_class_evidence_v3":
        args.update({"attack_class": attack_class, "limit": 5})
    elif call == "vault_chained_attack_plan_context":
        args.update(
            {
                "target_contract_path": fn.relative_file,
                "target_function_name": fn.function_name,
                "contract_kind_hint": contract_kind_hint,
                "limit": 5,
            }
        )
    elif call == "vault_global_chain_template_match":
        args.update(
            {
                "target_contract_path": fn.relative_file,
                "target_function_name": fn.function_name,
                "contract_kind_hint": contract_kind_hint,
                "max_matches": 5,
                "min_match_density": 0.25,
            }
        )
    elif call == "vault_invariant_library":
        args.update(
            {
                "target_contract_path": fn.relative_file,
                "target_function_name": fn.function_name,
                "attack_class": attack_class,
                "limit": 5,
            }
        )
    elif call == "vault_anti_pattern_corpus":
        args.update({"query": f"{fn.contract_name} {fn.function_name} {attack_class}".strip(), "limit": 3})
    elif call == "vault_known_dead_ends":
        args.update(
            {
                "candidate_pattern": f"{fn.contract_name}.{fn.function_name}",
                "attack_class": attack_class,
                "limit": 5,
            }
        )
    elif call == "vault_cross_language_pattern_lift":
        # target_language MUST be the fn's own language so lifted precedents land in the
        # language the hunter is reading; source_language picks a DIFFERING language to force
        # a real cross-language lift (the callable returns degraded:true when source==target
        # is empty or either side is missing).
        args.update(
            {
                "target_language": language,
                "source_language": ("rust" if language == "solidity" else "solidity"),
                "attack_class": attack_class,
                "target_domain": contract_kind_hint or "",
                "limit": 5,
            }
        )
    return args


def first_attack_class(*payloads: dict[str, Any]) -> str:
    for payload in payloads:
        for key in ("ranked_attack_classes", "matched_hacker_questions", "questions"):
            rows = payload.get(key)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                for field in ("attack_class", "attack_class_anchor", "class", "bug_class"):
                    value = row.get(field)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
    return ""


def find_local_harness_manifest_refs(workspace: Path, fn: Any) -> list[dict[str, Any]]:
    manifests = [
        workspace / "poc-tests" / "per_function_invariants" / "manifest.json",
        workspace / ".auditooor" / "per_function_invariants" / "manifest.json",
    ]
    refs: list[dict[str, Any]] = []
    for manifest_path in manifests:
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for row in manifest.get("functions") or []:
            if not isinstance(row, dict):
                continue
            if row.get("contract") == fn.contract_name and row.get("function") == fn.function_name:
                refs.append(
                    {
                        "manifest_path": str(manifest_path),
                        "harness_path": row.get("harness_path"),
                        "halmos_invocation": row.get("halmos_invocation") or row.get("halmos_args"),
                        "status": row.get("status"),
                    }
                )
    return refs


def build_llm_enrichment(
    repo_root: Path,
    workspace: Path,
    fn: Any,
    llm_enrich: bool,
    timeout: int,
) -> dict[str, Any]:
    if not llm_enrich:
        return {"status": "disabled", "reason": "llm_enrich disabled"}
    live_enabled = os.environ.get("AUDITOOOR_PREFLIGHT_LLM_ENRICH_LIVE") == "1"
    consent_source = None
    if os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1":
        consent_source = "env:AUDITOOOR_LLM_NETWORK_CONSENT"
    elif os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1":
        consent_source = "env:ADVERSARIAL_LIVE_CONSENT"
    if not live_enabled:
        return {
            "status": "skipped",
            "mode": "safe-dry-run",
            "reason": "live LLM enrichment requires AUDITOOOR_PREFLIGHT_LLM_ENRICH_LIVE=1",
            "network_consent_source": consent_source,
            "dispatch_invoked": False,
        }
    if consent_source is None:
        return {
            "status": "skipped",
            "mode": "safe-dry-run",
            "reason": "missing LLM network consent",
            "required_consent_env": ["AUDITOOOR_LLM_NETWORK_CONSENT=1", "ADVERSARIAL_LIVE_CONSENT=1"],
            "dispatch_invoked": False,
        }
    prompt = (
        f"Produce three concise, source-grounded audit hypotheses for this {function_language(fn)} function. "
        "Return JSON with an array named hypotheses. Do not claim exploitability.\n\n"
        f"Workspace: {workspace}\n"
        f"Function: {fn.contract_name}.{fn.function_name}\n"
        f"Source: {fn.relative_file}:{fn.line}\n"
        f"Signature: {function_signature(fn)}\n"
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
        handle.write(prompt)
        prompt_path = Path(handle.name)
    audit_dir = workspace / ".auditooor" / "pre_flight_llm"
    cmd = [
        "python3",
        str(repo_root / "tools" / "llm-dispatch.py"),
        "--prompt-file",
        str(prompt_path),
        "--provider",
        # MIMO-ENRICH-PROVIDER-WIRE: per-function hypothesis enrichment runs on
        # cheap/unmetered MIMO instead of burning Opus. Override via env.
        _os.environ.get("AUDITOOOR_PREFLIGHT_LLM_PROVIDER", "mimo"),
        "--max-tokens",
        "1000",
        "--task-type",
        "per-function-preflight",
        "--routing-purpose",
        "advisory",
        "--audit-dir",
        str(audit_dir),
    ]
    try:
        proc = _run_group_capture(cmd, cwd=repo_root, timeout=timeout)
    except Exception as exc:
        return {"status": "error", "mode": "live", "dispatch_invoked": True, "error": str(exc)}
    finally:
        try:
            prompt_path.unlink()
        except OSError:
            pass
    if proc.returncode != 0:
        return {
            "status": "error",
            "mode": "live",
            "dispatch_invoked": True,
            "returncode": proc.returncode,
            "stderr_tail": proc.stderr[-2000:],
        }
    return {
        "status": "ok",
        "mode": "live",
        "dispatch_invoked": True,
        "stdout_tail": proc.stdout[-4000:],
        "network_consent_source": consent_source,
        "audit_dir": str(audit_dir),
    }


def build_pack(
    repo_root: Path,
    workspace: Path,
    fn: Any,
    timeout: int,
    llm_enrich: bool,
) -> dict[str, Any]:
    base_args = {
        "workspace_path": str(workspace),
        "workspace": str(workspace),
        "language": function_language(fn),
        "target_language": function_language(fn),
        "contract": fn.contract_name,
        "function": fn.function_name,
        "function_name": fn.function_name,
        "contract_name": fn.contract_name,
        "file_path": fn.relative_file,
        "source_ref": f"{fn.relative_file}:{fn.line}",
        "limit": 5,
    }
    language = function_language(fn)
    signature = function_signature(fn)
    contract_kind_hint = infer_contract_kind(fn)
    mcp_context: dict[str, dict[str, Any]] = {}
    mcp_context["vault_function_signature_shape"] = call_vault(
        repo_root,
        "vault_function_signature_shape",
        vault_args_for_call(
            "vault_function_signature_shape",
            base_args,
            fn,
            signature,
            shape_hash="",
            attack_class="",
            contract_kind_hint=contract_kind_hint,
        ),
        timeout,
    )
    function_shape_payload = payload_or_empty(mcp_context["vault_function_signature_shape"])
    shape_hash = str(function_shape_payload.get("shape_hash") or "")
    mcp_context["vault_function_shape_attack_evidence"] = call_vault(
        repo_root,
        "vault_function_shape_attack_evidence",
        vault_args_for_call(
            "vault_function_shape_attack_evidence",
            base_args,
            fn,
            signature,
            shape_hash=shape_hash,
            attack_class="",
            contract_kind_hint=contract_kind_hint,
        ),
        timeout,
    )
    shape_attack_payload = payload_or_empty(mcp_context["vault_function_shape_attack_evidence"])
    mcp_context["vault_per_function_hunter_brief"] = call_vault(
        repo_root,
        "vault_per_function_hunter_brief",
        vault_args_for_call(
            "vault_per_function_hunter_brief",
            base_args,
            fn,
            signature,
            shape_hash=shape_hash,
            attack_class="",
            contract_kind_hint=contract_kind_hint,
        ),
        timeout,
    )
    hunter_payload = payload_or_empty(mcp_context["vault_per_function_hunter_brief"])
    attack_class = first_attack_class(shape_attack_payload, hunter_payload)
    for call in (
        "vault_attack_class_evidence_v3",
        "vault_chained_attack_plan_context",
        "vault_global_chain_template_match",
        "vault_invariant_library",
        "vault_anti_pattern_corpus",
        "vault_known_dead_ends",
        "vault_cross_language_pattern_lift",
    ):
        mcp_context[call] = call_vault(
            repo_root,
            call,
            vault_args_for_call(
                call,
                base_args,
                fn,
                signature,
                shape_hash=shape_hash,
                attack_class=attack_class,
                contract_kind_hint=contract_kind_hint,
            ),
            timeout,
        )
    attack_payload = payload_or_empty(mcp_context["vault_attack_class_evidence_v3"])
    chained_payload = payload_or_empty(mcp_context["vault_chained_attack_plan_context"])
    template_payload = payload_or_empty(mcp_context["vault_global_chain_template_match"])
    invariant_payload = payload_or_empty(mcp_context["vault_invariant_library"])
    anti_pattern_payload = payload_or_empty(mcp_context["vault_anti_pattern_corpus"])
    dead_end_payload = payload_or_empty(mcp_context["vault_known_dead_ends"])
    xlang_payload = payload_or_empty(mcp_context["vault_cross_language_pattern_lift"])
    local_shape = {
        "source": f"local-{language}-parser",
        "language": language,
        "contract_file": fn.relative_file,
        "source_ref": f"{fn.relative_file}:{fn.line}",
        "line": fn.line,
        "attrs": fn.attrs,
        "args": fn.args,
        "function_signature": signature,
        "state_writing_candidate": True,
        "contract_kind_hint": contract_kind_hint or None,
    }
    function_shape = dict(local_shape)
    if function_shape_payload:
        function_shape.update({"source": "vault_function_signature_shape", "mcp": function_shape_payload})
    relevant_invariants = []
    for value in hunter_payload.get("relevant_invariants") or []:
        if value not in relevant_invariants:
            relevant_invariants.append(value)
    for row in invariant_payload.get("invariants") or invariant_payload.get("items") or []:
        if isinstance(row, dict):
            value = row.get("invariant_id") or row.get("id")
            if value and value not in relevant_invariants:
                relevant_invariants.append(value)

    # CHAIN-LIFT (2026-05-28): re-call vault_global_chain_template_match with
    # broken_invariant_ids populated from the per-function invariant library
    # result.  The first call (inside the main MCP loop) passes no
    # broken_invariant_ids so always returns 0 matches.  Now that
    # relevant_invariants is resolved we can supply them and get real hits.
    # Only fires when there are INV-* ids to pass.
    if relevant_invariants:
        chain_args_with_inv = {
            "workspace_path": str(workspace),
            "target_contract_path": fn.relative_file,
            "target_function_name": fn.function_name,
            "contract_kind_hint": contract_kind_hint,
            "broken_invariant_ids": relevant_invariants,
            "max_matches": 5,
            "min_match_density": 0.25,
        }
        enriched_template_result = call_vault(
            repo_root,
            "vault_global_chain_template_match",
            chain_args_with_inv,
            timeout,
        )
        enriched_template_payload = payload_or_empty(enriched_template_result)
        if enriched_template_payload.get("matched_templates"):
            # Replace the empty first-pass result with the invariant-seeded result.
            template_payload = enriched_template_payload
            mcp_context["vault_global_chain_template_match_enriched"] = enriched_template_result

    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "language": language,
        "source_ref": f"{fn.relative_file}:{fn.line}",
        "contract": fn.contract_name,
        "function": fn.function_name,
        "selector": fn.selector,
        "target": {
            "contract": fn.contract_name,
            "function": fn.function_name,
            "source_ref": f"{fn.relative_file}:{fn.line}",
            "language": language,
            "contract_kind_hint": contract_kind_hint or None,
        },
        "function_shape": function_shape,
        "function_shape_local": {
            "contract_file": fn.relative_file,
            "source_ref": f"{fn.relative_file}:{fn.line}",
            "line": fn.line,
            "attrs": fn.attrs,
            "args": fn.args,
            "function_signature": signature,
            "language": language,
            "state_writing_candidate": True,
        },
        "attack_class_evidence": {
            "selected_attack_class": attack_class or None,
            "function_shape_attack_evidence": shape_attack_payload,
            "attack_class_evidence_v3": attack_payload,
            "mcp_status": {
                "vault_function_shape_attack_evidence": call_status(mcp_context["vault_function_shape_attack_evidence"]),
                "vault_attack_class_evidence_v3": call_status(mcp_context["vault_attack_class_evidence_v3"]),
            },
        },
        "per_function_hunter_brief": hunter_payload,
        "chain_candidates": {
            "chained_attack_plan_context": chained_payload,
            "global_chain_template_match": template_payload,
            "matched_templates": template_payload.get("matched_templates") or hunter_payload.get("matched_chain_templates") or [],
        },
        "invariants_touched": {
            "invariant_ids": relevant_invariants,
            "vault_invariant_library": invariant_payload,
        },
        "anti_patterns": anti_pattern_payload,
        "dead_ends_scoped": dead_end_payload,
        "cross_language_analogues": {
            "lift_candidates": xlang_payload.get("lift_candidates") or [],
            "target_language_precedents": xlang_payload.get("target_language_precedents") or [],
            "total_records_matched": xlang_payload.get("total_records_matched") or 0,
            "degraded": xlang_payload.get("degraded", True),
            "source_refs": xlang_payload.get("source_refs") or [],
        },
        "local_harness_manifest_references": find_local_harness_manifest_refs(workspace, fn),
        "mcp_context": mcp_context,
        "mcp_status_summary": {call: call_status(block) for call, block in mcp_context.items()},
        "llm_enriched_hypotheses": build_llm_enrichment(repo_root, workspace, fn, llm_enrich, timeout),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Audit workspace root.")
    parser.add_argument("--contract", help="Optional contract filename/stem filter.")
    parser.add_argument("--function", help="Optional function name filter.")
    parser.add_argument(
        "--output-dir",
        help="Output directory. Default: <workspace>/.auditooor/pre_flight_packs",
    )
    parser.add_argument("--llm-enrich", action="store_true", help="Reserve LLM enrichment slot in packs.")
    parser.add_argument("--mcp-timeout", type=int, default=8, help="Timeout per Vault MCP call.")
    parser.add_argument("--dry-run", action="store_true", help="Print summary without writing pack files.")
    parser.add_argument("--json", action="store_true", help="Print manifest JSON.")
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="Cap the number of in-scope functions processed. 0 or negative = unbounded (all in-scope, Pillar-1 full coverage).",
    )
    parser.add_argument(
        "--total-budget-seconds",
        type=float,
        default=float(
            os.environ.get("AUDITOOOR_PREFLIGHT_TOTAL_BUDGET", "0") or "0"
        ),
        help=(
            "Total wall-clock budget (s) for the whole per-function pre-flight pack "
            "sweep. Each pack does Vault MCP calls (--mcp-timeout each, which already "
            "guards a single hung call). DEFAULT 0 = UNBOUNDED: build a pack for EVERY "
            "in-scope function - an audit must not silently skip part of its coverage "
            "surface (a positive budget marks the manifest truncated_by_total_budget "
            "and drops the remainder). Set AUDITOOOR_PREFLIGHT_TOTAL_BUDGET=<seconds> "
            "only to deliberately cap the sweep."
        ),
    )
    return parser.parse_args(argv)


def _valid_rust_graph_schema(graph: Any) -> bool:
    if not isinstance(graph, dict):
        return False
    schema = graph.get("schema")
    meta = graph.get("_meta") if isinstance(graph.get("_meta"), dict) else {}
    return schema == "auditooor.rust_source_graph.v1" or meta.get("schema_version") == "auditooor.rust_source_graph.v1"


def _is_test_unit(fn_name: str, relative_file: str) -> bool:
    """True when a Rust graph entrypoint is test-only code (out of scope).

    Rust test code (#[cfg(test)] modules, #[test] fns, test utils) is OOS for
    every program rubric. The source graph does NOT reliably carry the cfg(test)
    attribute: it sits on the enclosing ``mod tests`` block, so each entrypoint's
    ``attrs``/``cfg_attrs`` come back empty (observed on near-intents:
    test_proposed_updates_interface_resharing @ lib.rs with attrs=[]). We
    therefore fall back to the standard Rust test conventions - a ``test_``-
    prefixed fn name, or a file under a ``tests/`` dir / named ``tests.rs`` /
    ``*_test.rs`` / ``*_tests.rs``. Without this filter the per-function preflight
    (and the Step-3 hunt it feeds) burns budget on - and could surface findings
    in - OOS test code, diverging from the clean inscope_units.jsonl manifest.
    """
    name = (fn_name or "").strip()
    rel = (relative_file or "").replace("\\", "/")
    if name.startswith("test_"):
        return True
    low = rel.lower()
    if "/tests/" in low or low.startswith("tests/"):
        return True
    base = low.rsplit("/", 1)[-1]
    if base == "tests.rs" or base.endswith("_test.rs") or base.endswith("_tests.rs"):
        return True
    return False


def _entry_attrs(entry: dict[str, Any]) -> str:
    attrs: list[str] = []
    for key in ("attrs", "cfg_attrs"):
        value = entry.get(key)
        if isinstance(value, list):
            attrs.extend(str(item) for item in value if str(item).strip())
    return " ".join(attrs)


def _rust_contract_matches(contract_filter: str | None, crate_name: str, relative_file: str) -> bool:
    if not contract_filter:
        return True
    needle = contract_filter.strip().lower()
    if not needle:
        return True
    file_path = Path(relative_file)
    haystacks = (
        crate_name,
        relative_file,
        file_path.name,
        file_path.stem,
    )
    return any(needle in str(value).lower() for value in haystacks)


def discover_rust_functions_from_graph(
    workspace: Path,
    function_filter: str | None = None,
    contract_filter: str | None = None,
) -> list[RustFunction]:
    functions, _malformed_refs = discover_rust_functions_from_graph_with_diagnostics(
        workspace,
        function_filter,
        contract_filter,
    )
    return functions


def _validate_source_ref(workspace: Path, relative_file: str, line: int) -> str | None:
    if not relative_file or Path(relative_file).is_absolute() or ".." in Path(relative_file).parts:
        return "invalid-relative-file"
    source_path = workspace / relative_file
    if not source_path.is_file():
        return "missing-source-file"
    if line < 1:
        return "invalid-line"
    try:
        line_count = len(source_path.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return "unreadable-source-file"
    if line > line_count:
        return "line-out-of-range"
    return None


def discover_rust_functions_from_graph_with_diagnostics(
    workspace: Path,
    function_filter: str | None = None,
    contract_filter: str | None = None,
) -> tuple[list[RustFunction], list[dict[str, Any]]]:
    graph_path = workspace / ".auditooor" / "rust_source_graph.json"
    if not graph_path.is_file():
        return [], []
    try:
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], []
    if not _valid_rust_graph_schema(graph):
        return [], []

    functions: list[RustFunction] = []
    malformed_refs: list[dict[str, Any]] = []
    for crate_name, crate_graph in graph.items():
        if crate_name == "_meta" or not isinstance(crate_graph, dict):
            continue
        entrypoints = crate_graph.get("entrypoints")
        if not isinstance(entrypoints, list):
            continue
        for entry in entrypoints:
            if not isinstance(entry, dict):
                continue
            fn_name = str(entry.get("fn") or entry.get("function") or entry.get("name") or "").strip()
            relative_file = str(entry.get("file") or entry.get("relative_file") or "").strip()
            if not fn_name or not relative_file:
                continue
            if not _rust_contract_matches(contract_filter, str(crate_name), relative_file):
                continue
            if function_filter and function_filter != fn_name:
                continue
            # Skip OOS Rust test code unless a caller explicitly targets it by name.
            if not function_filter and _is_test_unit(fn_name, relative_file):
                continue
            try:
                line = int(entry.get("line") or 1)
            except (TypeError, ValueError):
                line = 1
            malformed_reason = _validate_source_ref(workspace, relative_file, line)
            if malformed_reason:
                malformed_refs.append(
                    {
                        "contract": str(crate_name),
                        "function": fn_name,
                        "source_ref": f"{relative_file}:{line}",
                        "reason": malformed_reason,
                    }
                )
                continue
            functions.append(
                RustFunction(
                    contract_name=str(crate_name),
                    function_name=fn_name,
                    contract_file=workspace / relative_file,
                    relative_file=relative_file,
                    line=line,
                    attrs=_entry_attrs(entry),
                    args="",
                )
            )
    return functions, malformed_refs


def count_source_files(workspace: Path, extension: str) -> int:
    ignored = {".git", ".auditooor", ".audit_logs", "node_modules", "target"}
    count = 0
    for path in workspace.rglob(f"*{extension}"):
        if not path.is_file():
            continue
        if any(part in ignored for part in path.parts):
            continue
        count += 1
    return count


def function_denominator_status(
    known_total_in_scope: int,
    processable_total: int,
    unsupported_language_file_counts: dict[str, int],
    malformed_source_refs: list[dict[str, Any]],
    capped: bool,
) -> str:
    if capped:
        return "capped"
    if malformed_source_refs:
        return "malformed-source-refs"
    if not known_total_in_scope and unsupported_language_file_counts:
        return "source-unit-only"
    if known_total_in_scope == processable_total and not unsupported_language_file_counts:
        return "complete"
    return "partial"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[per-function-preflight-orchestrator] workspace not found: {workspace}", file=sys.stderr)
        return 2
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else workspace / ".auditooor" / "pre_flight_packs"
    )
    invariant = load_invariant_module(repo_root)
    files, solidity_discovery = discover_scoped_solidity_files(repo_root, workspace, args.contract)
    targeted_function_filter = bool(args.function)
    solidity_functions = invariant.parse_functions(
        workspace,
        files,
        include_internal=targeted_function_filter,
        function_filter=args.function,
        include_read_only=targeted_function_filter,
    )
    rust_functions, malformed_source_refs = discover_rust_functions_from_graph_with_diagnostics(
        workspace,
        args.function,
        args.contract,
    )
    unsupported_language_file_counts = {
        "go": count
        for _ext, count in ((".go", count_source_files(workspace, ".go")),)
        if count
    }
    if solidity_functions:
        functions = solidity_functions
        selected_discovery_source = "solidity"
    elif rust_functions:
        functions = rust_functions
        selected_discovery_source = "rust_graph"
    else:
        functions = []
        selected_discovery_source = "none"
    rust_discovered_total = len(rust_functions) + len(malformed_source_refs)
    known_total_in_scope = len(solidity_functions) + rust_discovered_total
    # GUARD-TRIAGE PRIORITY (additive): when guard-triage ran first, stable-sort the
    # discovered functions so guard-risky functions are preflighted BEFORE the rest.
    # This matters under --max-functions / total-budget truncation, where the prior
    # alphabetical discovery order would otherwise spend the budget on the
    # alphabetically-first functions while ignoring guard-risk. Functions absent from
    # guard_triage.json get score 0 and keep their existing relative order (Python's
    # sort is stable). Missing guard_triage.json -> empty map -> no reordering at all,
    # so the prior alphabetical behavior is preserved (no regression).
    guard_risk = _guard_risk_scores(workspace)
    if guard_risk and functions:
        functions = sorted(functions, key=lambda fn: -guard_risk.get(fn.function_name.lower(), 0))
    processable_total = len(functions)
    capped = False
    if args.max_functions and args.max_functions > 0 and processable_total > args.max_functions:
        functions = functions[: args.max_functions]
        capped = True
        print(
            f"[per-function-preflight-orchestrator] --max-functions={args.max_functions}: "
            f"capping {processable_total} processable functions to {args.max_functions} "
            f"({processable_total - args.max_functions} NOT processed - run with MAX_FUNCTIONS=0 for full coverage)",
            file=sys.stderr,
        )
    rows: list[dict[str, Any]] = []
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
    expected_pack_paths = {
        output_dir / f"pre_flight_pack_{safe_slug(fn.contract_name)}_{safe_slug(fn.function_name)}.json"
        for fn in functions
    }
    targeted_filter_active = bool(args.contract or args.function)
    stale_pack_paths: list[str] = []
    stale_pack_cleanup_skipped = ""
    if not args.dry_run and output_dir.is_dir() and not targeted_filter_active:
        for stale_path in sorted(output_dir.glob("pre_flight_pack_*.json")):
            if stale_path not in expected_pack_paths:
                stale_pack_paths.append(str(stale_path))
                try:
                    stale_path.unlink()
                except OSError:
                    pass
    elif not args.dry_run and output_dir.is_dir() and targeted_filter_active:
        stale_pack_cleanup_skipped = "targeted-filter"
    preflight_budget = (
        args.total_budget_seconds
        if args.total_budget_seconds and args.total_budget_seconds > 0
        else None
    )
    truncated_by_budget = False
    sweep_start = time.monotonic()

    def _build_and_write(fn: Any) -> dict[str, Any]:
        """Build a single function's pack and persist it. Thread-safe: each call
        does its own MCP subprocess calls (build_pack) and writes a distinct
        per-function filename, so concurrent invocations never collide."""
        pack = build_pack(repo_root, workspace, fn, args.mcp_timeout, args.llm_enrich)
        filename = (
            f"pre_flight_pack_{safe_slug(fn.contract_name)}_{safe_slug(fn.function_name)}.json"
        )
        path = output_dir / filename
        if not args.dry_run:
            path.write_text(
                json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        return {
            "contract": fn.contract_name,
            "function": fn.function_name,
            "source_ref": pack["source_ref"],
            "pack_path": str(path),
            "status": "would-write" if args.dry_run else "written",
        }

    if preflight_budget is not None:
        # Bounded-budget mode (opt-in via AUDITOOOR_PREFLIGHT_TOTAL_BUDGET): keep the
        # sequential loop so the wall-clock cutoff is precise.
        for fn in functions:
            if (time.monotonic() - sweep_start) >= preflight_budget:
                truncated_by_budget = True
                print(
                    f"[per-function-preflight-orchestrator] total budget {preflight_budget:.0f}s "
                    f"reached after {len(rows)}/{len(functions)} packs; skipping the rest "
                    f"(set AUDITOOOR_PREFLIGHT_TOTAL_BUDGET=0 for unbounded)",
                    file=sys.stderr,
                )
                break
            rows.append(_build_and_write(fn))
    elif functions:
        # Default (unbounded) path: each pack does ~10 cold vault-mcp-server
        # subprocess calls, so the per-function work is subprocess/IO-bound and the
        # GIL is released while we wait. Parallelize across functions to turn a
        # serial O(N * 10 * mcp_timeout) sweep into ~O(N/W) wall-clock without
        # dropping any coverage (every in-scope function still gets a pack).
        # Worker count is generic + tunable (AUDITOOOR_PREFLIGHT_WORKERS); the
        # default tracks engage's enrich pool (min(16, cpu)). Results are kept in
        # the original function order via executor.map.
        env_workers = int(os.environ.get("AUDITOOOR_PREFLIGHT_WORKERS", "0") or "0")
        max_workers = env_workers if env_workers > 0 else min(16, (os.cpu_count() or 4))
        max_workers = max(1, min(max_workers, len(functions)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            rows.extend(executor.map(_build_and_write, functions))
    manifest = {
        "schema": "auditooor.pre_flight_pack_manifest.v1",
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "output_dir": str(output_dir),
        "pack_count": len(rows),
        "function_coverage": {
            "total_in_scope": known_total_in_scope,
            "processable_total": processable_total,
            "processed": len(rows),
            "max_functions": args.max_functions,
            "capped": capped,
            "truncated_by_total_budget": truncated_by_budget,
            "total_budget_seconds": preflight_budget,
            "budget_skipped": max(0, len(functions) - len(rows)) if truncated_by_budget else 0,
            "not_selected_discovered": max(0, known_total_in_scope - processable_total),
            "not_processed": max(0, known_total_in_scope - len(rows)),
            "selected_discovery_source": selected_discovery_source,
            "discovered_function_counts": {
                "solidity": len(solidity_functions),
                "rust_graph": rust_discovered_total,
            },
            "solidity_discovery": solidity_discovery,
            "unsupported_language_file_counts": unsupported_language_file_counts,
            "malformed_source_refs": malformed_source_refs,
            "malformed_source_ref_count": len(malformed_source_refs),
            "stale_pack_paths_removed": stale_pack_paths,
            "stale_pack_count_removed": len(stale_pack_paths),
            "stale_pack_cleanup_skipped": stale_pack_cleanup_skipped,
            "function_denominator_status": function_denominator_status(
                known_total_in_scope,
                processable_total,
                unsupported_language_file_counts,
                malformed_source_refs,
                capped,
            ),
            "denominator_complete": (
                known_total_in_scope == processable_total
                and not unsupported_language_file_counts
                and not malformed_source_refs
                and not capped
            ),
            "full_coverage_hint": "run with MAX_FUNCTIONS=0 for full coverage" if capped else "",
        },
        "packs": rows,
    }
    if not args.dry_run:
        (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"[per-function-preflight-orchestrator] packs={len(rows)} output_dir={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
