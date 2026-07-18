#!/usr/bin/env python3
"""Offline chained-attack planner from existing local workspace artifacts.

This planner is intentionally advisory:
  - reads local exploit/swarm/big-loss/detector artifacts only
  - emits candidate chain plans, never promotion claims
  - keeps every row at candidate_not_submit_ready
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.chained_attack_plans.v1"
SOURCE_LINK_SCHEMA_VERSION = "auditooor.chain_synth_source_links.v1"
DEFAULT_MAX_PLANS = 5
PURE_ADVISORY_PAIR_SCORE = 1
DETECTOR_QDET_DERIVED_KINDS = {"detector_cluster", "hacker_brief_qdet"}
FILE_HINT_RE = re.compile(r"[A-Za-z0-9_./-]+\.(?:sol|rs|go|ts|js|py|move|cairo|vy)\b")
FILE_LINE_REF_RE = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]+:\d+")
INV_ID_RE = re.compile(r"\bINV-[A-Za-z0-9_.-]+\b")
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,}")
ENGAGE_CLUSTER_RE = re.compile(r"^###\s+Cluster:\s+`?([^`(]+)`?\s*\((\d+)\s+hits?\)")
ENGAGE_HIT_RE = re.compile(
    r"^-\s+\*\*\[([A-Z]+)\]\s+`([^`]+)`\*\*\s+-\s+`([^`]+)`"
)
QDET_RE = re.compile(r"\bQ-DET-([A-Za-z0-9._-]+)\b")
DEFIHACK_SECTION_RE = re.compile(r"^###\s+([A-Za-z0-9._-]+)\s+-\s+(.+?)\s+\[([^\]]+)\]")
DEFIHACK_PATTERN_RE = re.compile(r"^\*\*Pattern\*\*\s+`(.+?)`\s+(?:→|->)")
CAUSAL_SIGNAL_INLINE_RE = re.compile(
    r"(?i)\b(?:causal|bridge|chain)[ _-]?signal\s*[:=]\s*([A-Za-z0-9._:-]+)"
)
LIVE_ROW_SIGNAL_RE = re.compile(r"\bLIVE-[A-Za-z0-9._-]+\b")
EXECUTED_COMPOSITION_PROOF_STATES = {
    "executed",
    "executed_clean",
    "counterexample",
    "ok",
    "pass",
    "passed",
    "success",
    "succeeded",
    "complete",
    "completed",
    "proof_backed",
    "proof-backed",
    "proved",
    "proven",
}
WEAK_COMPOSITION_PROOF_STATES = {
    "",
    "advisory",
    "advisory_only",
    "blocked",
    "candidate",
    "candidate_not_submit_ready",
    "dry_run",
    "dryrun",
    "not_submit_ready",
    "pending",
    "required",
    "source_cited_unexecuted",
    "unexecuted",
    "unknown",
}


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _uniq(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "item"


def _normalize_path_hint(text: str) -> str:
    hint = str(text or "").strip()
    if not hint:
        return ""
    return hint.split(":", 1)[0]


def _extract_file_hints(values: list[str]) -> list[str]:
    hints: list[str] = []
    for value in values:
        text = str(value or "")
        if not text:
            continue
        if "." in text and "/" in text:
            hints.append(_normalize_path_hint(text))
        for match in FILE_HINT_RE.findall(text):
            hints.append(_normalize_path_hint(match))
    return _uniq(hints)


def _extract_contract_hints(values: list[str]) -> list[str]:
    hints: list[str] = []
    for value in values:
        text = str(value or "")
        if not text:
            continue
        for token in WORD_RE.findall(text):
            if token.lower() in {
                "source", "workspace", "proof", "required", "summary",
                "manual", "review", "artifact", "target", "line", "status",
                "scope", "contract", "angle", "title", "generated",
            }:
                continue
            if token[0].isupper() or token.isupper():
                hints.append(token)
    return _uniq(hints)


def _canon_key(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip().lower())


def _extract_causal_bridge_signals(values: list[str]) -> list[str]:
    signals: list[str] = []
    for value in values:
        text = str(value or "")
        if not text:
            continue
        for match in CAUSAL_SIGNAL_INLINE_RE.findall(text):
            signals.append(_canon_key(match))
        for match in LIVE_ROW_SIGNAL_RE.findall(text):
            signals.append(_canon_key(match))
    return _uniq(signals)


def _extract_invariant_ids(value: Any) -> list[str]:
    ids: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            ids.extend(_extract_invariant_ids(item))
    elif isinstance(value, list):
        for item in value:
            ids.extend(_extract_invariant_ids(item))
    elif value is not None:
        ids.extend(INV_ID_RE.findall(str(value)))
    return _uniq(ids)


def _extract_file_line_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            refs.extend(_extract_file_line_refs(item))
    elif isinstance(value, list):
        for item in value:
            refs.extend(_extract_file_line_refs(item))
    elif value is not None:
        refs.extend(FILE_LINE_REF_RE.findall(str(value)))
    return _uniq(refs)


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _status_token(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _collect_string_values_for_key(value: Any, wanted_key: str) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == wanted_key:
                if isinstance(item, list):
                    out.extend(str(child) for child in item if str(child or "").strip())
                elif str(item or "").strip():
                    out.append(str(item).strip())
            else:
                out.extend(_collect_string_values_for_key(item, wanted_key))
    elif isinstance(value, list):
        for item in value:
            out.extend(_collect_string_values_for_key(item, wanted_key))
    return _uniq(out)


def _proof_key_rows(proof_rows: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    display: list[str] = []
    keys: list[str] = []
    for row in proof_rows:
        if not isinstance(row, dict):
            continue
        summary = str(row.get("summary") or "").strip()
        artifact = str(row.get("artifact") or "").strip()
        source_ref = str(row.get("source_ref") or "").strip()
        item = summary or artifact or source_ref
        if item:
            display.append(item)
        for raw in (summary, artifact, source_ref):
            if raw:
                keys.append(_canon_key(raw))
    return _uniq(display), _uniq(keys)


def _candidate_source(path: Path | None) -> str | None:
    return str(path) if path is not None else None


def _optional_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    return _load_json(path)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace root")
    parser.add_argument("--exploit-json", default=None, help="Optional exploit-memory or vault_exploit_context JSON")
    parser.add_argument("--brief-candidates", default=None, help="Optional swarm/brief_candidates.json path")
    parser.add_argument("--swarm-manifest", default=None, help="Optional swarm/manifest.json path")
    parser.add_argument("--big-loss-json", default=None, help="Optional .auditooor/big_loss_template_composed.json path")
    parser.add_argument("--engage-report", default=None, help="Optional engage_report.md or engage_report.json path")
    parser.add_argument(
        "--defihack-report",
        action="append",
        default=[],
        help="Optional DeFiHackLabs class-matcher match_report.md path; may be repeated",
    )
    parser.add_argument(
        "--hacker-brief-json",
        action="append",
        default=[],
        help="Optional hacker-brief JSON sidecar path; may be repeated",
    )
    parser.add_argument("--out", default=None, help="Output JSON path")
    parser.add_argument("--markdown-out", default=None, help="Output markdown path")
    parser.add_argument(
        "--emit-chain-synth-source-links",
        action="store_true",
        help="Also emit .auditooor/chain_synth_source_links.json for source-backed chain edges",
    )
    parser.add_argument(
        "--source-links-out",
        default=None,
        help="Optional source-link sidecar path; implies --emit-chain-synth-source-links",
    )
    parser.add_argument("--max-plans", type=int, default=DEFAULT_MAX_PLANS, help="Maximum chain plans to emit")
    parser.add_argument("--print-json", action="store_true", help="Print JSON payload to stdout")
    return parser.parse_args(argv)


def _manifest_contract_context(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    ctx: dict[str, dict[str, Any]] = {}
    meta = manifest.get("brief_metadata")
    if not isinstance(meta, dict):
        return ctx
    for item in meta.values():
        if not isinstance(item, dict):
            continue
        contract = str(item.get("contract") or "").strip()
        if contract:
            ctx[contract] = item
    return ctx


def _normalize_angle(angle: dict[str, Any], artifact_path: Path | None) -> dict[str, Any]:
    proof_display, proof_keys = _proof_key_rows(list(angle.get("proof_prerequisites") or []))
    target_files = [str(item) for item in (angle.get("target_files") or []) if str(item or "").strip()]
    source_refs = [str(item) for item in (angle.get("source_refs") or []) if str(item or "").strip()]
    evidence_chain = [str(item) for item in (angle.get("evidence_chain") or []) if str(item or "").strip()]
    duplicate_guard = angle.get("duplicate_guard") if isinstance(angle.get("duplicate_guard"), dict) else {}
    oos_guard = angle.get("oos_guard") if isinstance(angle.get("oos_guard"), dict) else {}
    blockers = [str(item) for item in (angle.get("not_submit_ready_until") or []) if str(item or "").strip()]
    dup_status = str(duplicate_guard.get("status") or "clear")
    dup_material = str(duplicate_guard.get("material_distinction") or "").strip()
    if dup_status != "clear":
        blocker = f"duplicate guard: {dup_status}"
        if dup_material:
            blocker += f" ({dup_material})"
        blockers.append(blocker)
    oos_status = str(oos_guard.get("status") or "")
    if oos_status:
        blockers.append(f"OOS guard: {oos_status}")
    title = str(angle.get("title") or angle.get("bug_class_id") or angle.get("angle_id") or "exploit angle")
    return {
        "primitive_id": f"angle:{angle.get('angle_id') or _slugify(title)}",
        "source_kind": "exploit_angle",
        "title": title,
        "summary": str(angle.get("hypothesis") or angle.get("attack_surface") or title),
        "contract_hints": _uniq(
            _extract_contract_hints(target_files + source_refs + [str(angle.get("protocol_family") or ""), title])
        ),
        "attack_class_hints": _uniq(
            [str(angle.get("bug_class_id") or "").strip(), title]
        ),
        "file_hints": _extract_file_hints(target_files + source_refs + evidence_chain),
        "proof_items": proof_display,
        "proof_keys": proof_keys,
        "paired_live_row_ids": [],
        "paired_contracts": [],
        "involved_contracts": [],
        "source_refs": _uniq(source_refs + evidence_chain + ([str(artifact_path)] if artifact_path else [])),
        "blockers": _uniq(blockers),
        "duplicate_guard": duplicate_guard,
        "oos_guard": oos_guard,
        "material_distinction": dup_material,
        "attempted_stronger_impact": "",
        "recommended_next_step": str(angle.get("recommended_next_command") or "").strip(),
        "causal_bridge_signals": _extract_causal_bridge_signals(
            target_files + source_refs + evidence_chain + proof_display
        ),
    }


def _normalize_candidate(
    candidate: dict[str, Any],
    artifact_path: Path | None,
    manifest_ctx: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    contract = str(candidate.get("contract") or "").strip()
    involved = [str(item) for item in (candidate.get("involved_contracts") or []) if str(item or "").strip()]
    paired_contracts = [str(item) for item in (candidate.get("paired_contracts") or []) if str(item or "").strip()]
    paired_rows = [str(item) for item in (candidate.get("paired_live_row_ids") or []) if str(item or "").strip()]
    matched_briefs = [str(item) for item in (candidate.get("matched_mining_briefs") or []) if str(item or "").strip()]
    exploit_goal = str(candidate.get("exploit_goal") or "").strip()
    next_step = str(candidate.get("recommended_next_step") or "").strip()
    title = str(candidate.get("angle_title") or candidate.get("angle_id") or exploit_goal or "brief candidate")
    target_refs: list[str] = []
    for key in ("target_files", "source_refs", "source_locations", "suggested_functions"):
        raw = candidate.get(key)
        if isinstance(raw, list):
            target_refs.extend(str(item) for item in raw if str(item or "").strip())
        elif isinstance(raw, str) and raw.strip():
            target_refs.append(raw)
    blockers: list[str] = []
    if candidate.get("proof_poor"):
        blockers.append("source brief marked PROOF-POOR")
    if paired_rows and not candidate.get("executed_live_rows"):
        blockers.append("paired live proof rows are not executed")
    impact_contract = candidate.get("impact_contract") if isinstance(candidate.get("impact_contract"), dict) else {}
    decision = impact_contract.get("decision") if isinstance(impact_contract.get("decision"), dict) else {}
    if decision.get("blocked"):
        blockers.append(str(decision.get("summary") or "impact contract gate blocked"))
    ctx = manifest_ctx.get(contract, {})
    if ctx.get("missing_proof_context_angles"):
        blockers.append(
            "swarm manifest missing proof context for angles: "
            + ", ".join(str(item) for item in ctx["missing_proof_context_angles"])
        )
    if ctx.get("dispatch_blocked_missing_impact_contract"):
        blockers.append(
            "swarm manifest blocked dispatch pending impact contract: "
            + ", ".join(str(item) for item in (ctx.get("impact_contract_gate_sources") or []))
        )
    proof_items = _uniq(paired_rows + matched_briefs)
    proof_keys = _uniq([_canon_key(item) for item in proof_items + paired_contracts + involved])
    source_refs = [str(candidate.get("source_file") or "").strip()]
    source_refs.extend(target_refs)
    source_refs.extend(matched_briefs)
    source_refs.extend(str(item) for item in (ctx.get("impact_contract_gate_sources") or []))
    broken_invariant_ids = _extract_invariant_ids(
        [
            candidate.get("broken_invariant_ids"),
            candidate.get("matched_invariant_ids"),
            candidate.get("invariant_ids"),
        ]
    )
    return {
        "primitive_id": f"candidate:{contract or 'unknown'}:{candidate.get('angle_id') or _slugify(title)}",
        "source_kind": "brief_candidate",
        "title": title,
        "summary": exploit_goal or next_step or title,
        "contract_hints": _uniq([contract, *involved, *paired_contracts]),
        "attack_class_hints": _uniq([str(candidate.get("angle_id") or "").strip(), title]),
        "file_hints": _extract_file_hints(target_refs),
        "proof_items": proof_items,
        "proof_keys": proof_keys,
        "paired_live_row_ids": paired_rows,
        "paired_contracts": paired_contracts,
        "involved_contracts": _uniq([contract, *involved]),
        "source_refs": _uniq(source_refs + ([_candidate_source(artifact_path)] if artifact_path else [])),
        "broken_invariant_ids": broken_invariant_ids,
        "blockers": _uniq(blockers),
        "duplicate_guard": {},
        "oos_guard": {},
        "material_distinction": "",
        "attempted_stronger_impact": exploit_goal,
        "recommended_next_step": next_step,
        "causal_bridge_signals": _extract_causal_bridge_signals(
            target_refs + proof_items + [exploit_goal, next_step, *paired_rows, *paired_contracts]
        ),
    }


def _load_big_loss_module(repo_root: Path) -> Any:
    path = repo_root / "tools" / "big-loss-template-compose.py"
    spec = importlib.util.spec_from_file_location("big_loss_template_compose", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load big-loss-template-compose.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_compose_chain() -> Any:
    """Return chain-composition-harness.compose_chain (or None if unavailable).

    Reuse, do not rebuild: the runnable-vs-non-runnable verdict (D1 LIVE bridge
    present + composed command + survives defense-in-depth) already lives in
    tools/chain-composition-harness.py.  Loading it by path keeps the planner
    decoupled (the sibling has hyphens in its filename) and lets the emit path
    stamp an executed composition proof ONLY when that gate says the chain is
    actually runnable.
    """
    path = Path(__file__).resolve().parent / "chain-composition-harness.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "chain_composition_harness", path
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception:  # pragma: no cover - defensive; never block plan emission
        return None
    return getattr(module, "compose_chain", None)


def _load_big_loss_payload(
    workspace: Path,
    explicit_path: Path | None,
) -> tuple[dict[str, Any] | None, str]:
    if explicit_path is not None and explicit_path.exists():
        return _load_json(explicit_path), "artifact"
    default_path = workspace / ".auditooor" / "big_loss_template_composed.json"
    if default_path.exists():
        return _load_json(default_path), "artifact"
    ledger_path = workspace / ".auditooor" / "invariant_ledger.json"
    if not ledger_path.exists():
        return None, "missing"
    module = _load_big_loss_module(Path(__file__).resolve().parent.parent)
    rows = module._load_ledger(workspace)
    if not rows:
        return None, "missing"
    templates = module._load_templates()
    impact_contracts = module._load_impact_contracts(workspace)
    manifests = [
        module._compose_row(row, templates, impact_contracts, workspace, None)
        for row in rows
    ]
    return {
        "schema_version": module.SCHEMA_VERSION_OUT,
        "workspace": str(workspace),
        "manifests": manifests,
    }, "generated_in_process"


def _normalize_big_loss(
    payload: dict[str, Any] | None,
    workspace: Path,
    source_mode: str,
) -> list[dict[str, Any]]:
    if not payload:
        return []
    manifests = payload.get("manifests") if isinstance(payload.get("manifests"), list) else payload
    if not isinstance(manifests, list):
        return []
    ledger_rows: dict[str, dict[str, Any]] = {}
    ledger_path = workspace / ".auditooor" / "invariant_ledger.json"
    if ledger_path.exists():
        raw = _load_json(ledger_path)
        for row in raw.get("rows", []):
            if isinstance(row, dict) and row.get("id"):
                ledger_rows[str(row["id"])] = row
    out: list[dict[str, Any]] = []
    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue
        if manifest.get("composed_status") != "composed":
            continue
        actor_sequence = manifest.get("actor_sequence")
        if not isinstance(actor_sequence, list) or not actor_sequence:
            continue
        row_id = str(manifest.get("row_id") or "")
        row = ledger_rows.get(row_id, {})
        production_path = str(row.get("production_path") or "")
        title = f"{manifest.get('template_id') or 'big-loss'} actor sequence"
        proof_refs = []
        if source_mode == "artifact":
            proof_refs.append(str(workspace / ".auditooor" / "big_loss_template_composed.json"))
        elif source_mode == "generated_in_process":
            proof_refs.append("workspace:.auditooor/invariant_ledger.json")
        if row_id:
            proof_refs.append(f"ledger:{row_id}")
        out.append(
            {
                "primitive_id": f"big-loss:{row_id or _slugify(title)}",
                "source_kind": "big_loss_actor_sequence",
                "title": title,
                "summary": str(manifest.get("template_id") or "big-loss actor sequence"),
                "contract_hints": _extract_contract_hints([production_path, str(row.get("invariant_family") or ""), row_id]),
                "attack_class_hints": _uniq([str(row.get("invariant_family") or ""), str(manifest.get("template_id") or "")]),
                "file_hints": _extract_file_hints([production_path]),
                "proof_items": [],
                "proof_keys": [],
                "paired_live_row_ids": [],
                "paired_contracts": [],
                "involved_contracts": [],
                "source_refs": _uniq(proof_refs),
                "blockers": [],
                "duplicate_guard": {},
                "oos_guard": {},
                "material_distinction": "",
                "attempted_stronger_impact": "",
                "recommended_next_step": str(manifest.get("next_command") or "").strip(),
                "causal_bridge_signals": _extract_causal_bridge_signals(
                    [production_path, row_id, str(manifest.get("template_id") or "")]
                ),
                "actor_sequence": actor_sequence,
                "template_id": str(manifest.get("template_id") or ""),
                "row_id": row_id,
            }
        )
    return out


def _workspace_relative_path(path_text: str, workspace: Path, *, preserve_line: bool = False) -> str:
    text = str(path_text or "").strip()
    if not text:
        return ""
    for prefix in ("workspace:", "`"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = text.strip("`")
    if not preserve_line:
        text = _normalize_path_hint(text)
    workspace_aliases = {str(workspace)}
    if str(workspace).startswith("/private/var/"):
        workspace_aliases.add(str(workspace).replace("/private/var/", "/var/", 1))
    elif str(workspace).startswith("/var/"):
        workspace_aliases.add(str(workspace).replace("/var/", "/private/var/", 1))
    for alias in sorted(workspace_aliases, key=len, reverse=True):
        if alias and text.startswith(alias + "/"):
            text = text[len(alias) + 1:]
            break
    return text


def _sanitize_output_text(text: str, workspace: Path) -> str:
    """Remove local absolute path details from shareable planner output."""
    out = str(text)
    aliases = {str(workspace)}
    if str(workspace).startswith("/private/var/"):
        aliases.add(str(workspace).replace("/private/var/", "/var/", 1))
    elif str(workspace).startswith("/var/"):
        aliases.add(str(workspace).replace("/var/", "/private/var/", 1))
    repo = str(Path(__file__).resolve().parent.parent)
    repo_aliases = {repo}
    if repo.startswith("/private/var/"):
        repo_aliases.add(repo.replace("/private/var/", "/var/", 1))
    elif repo.startswith("/var/"):
        repo_aliases.add(repo.replace("/var/", "/private/var/", 1))
    for alias in sorted(aliases, key=len, reverse=True):
        out = out.replace(alias, "<workspace>")
    for alias in sorted(repo_aliases, key=len, reverse=True):
        out = out.replace(alias, "<repo>")
    out = re.sub(r"/private/var/folders/[^\s\"']+", "<tmp>", out)
    out = re.sub(r"/var/folders/[^\s\"']+", "<tmp>", out)
    out = re.sub(r"/Users/[^/\s\"']+", "<user>", out)
    out = re.sub(r"/home/[^/\s\"']+", "<user>", out)
    return out


def _sanitize_output_value(value: Any, workspace: Path) -> Any:
    if isinstance(value, str):
        return _sanitize_output_text(value, workspace)
    if isinstance(value, list):
        return [_sanitize_output_value(item, workspace) for item in value]
    if isinstance(value, dict):
        return {str(key): _sanitize_output_value(item, workspace) for key, item in value.items()}
    return value


def _normalize_detector_cluster(
    *,
    detector: str,
    hits: list[dict[str, Any]],
    source_path: Path | None,
    workspace: Path,
    source_note: str = "",
) -> dict[str, Any] | None:
    detector_name = str(detector or "").strip()
    if not detector_name:
        return None
    hit_summaries: list[str] = []
    file_values: list[str] = []
    severities: list[str] = []
    snippets: list[str] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        file_path = str(
            hit.get("file_path")
            or hit.get("path")
            or hit.get("file")
            or hit.get("location")
            or hit.get("loc")
            or ""
        ).strip()
        file_path = _workspace_relative_path(file_path, workspace)
        severity = str(hit.get("severity") or hit.get("severity_class") or hit.get("sev") or "UNKNOWN").strip()
        snippet = str(hit.get("snippet") or hit.get("message") or hit.get("excerpt") or hit.get("text") or "").strip()
        if file_path:
            file_values.append(file_path)
        if severity:
            severities.append(severity.upper())
        if snippet:
            snippets.append(snippet)
        summary = f"{severity or 'UNKNOWN'} detector fire {detector_name}"
        if file_path:
            summary += f" at {file_path}"
        if snippet:
            summary += f": {snippet[:160]}"
        hit_summaries.append(summary)
    source_refs = [str(source_path)] if source_path else []
    if source_note:
        source_refs.append(source_note)
    proof_items = hit_summaries or [f"detector cluster {detector_name} requires source confirmation"]
    return {
        "primitive_id": f"detector:{_slugify(detector_name)}",
        "source_kind": "detector_cluster",
        "title": detector_name,
        "summary": f"Detector cluster {detector_name} fired on {len(hit_summaries)} scoped hit(s)",
        "contract_hints": _extract_contract_hints([detector_name, *file_values, *snippets]),
        "attack_class_hints": _uniq([detector_name, _slugify(detector_name)]),
        "file_hints": _extract_file_hints(file_values + hit_summaries),
        "proof_items": proof_items,
        "proof_keys": _uniq([_canon_key(detector_name)] + [_canon_key(item) for item in file_values]),
        "paired_live_row_ids": [],
        "paired_contracts": [],
        "involved_contracts": [],
        "source_refs": _uniq(source_refs + file_values),
        "blockers": ["detector cluster is source signal only until file:line proof is manually confirmed"],
        "duplicate_guard": {},
        "oos_guard": {},
        "material_distinction": "",
        "attempted_stronger_impact": "",
        "recommended_next_step": f"confirm detector cluster `{detector_name}` against source and impact path",
        "causal_bridge_signals": _extract_causal_bridge_signals(
            [detector_name, *proof_items, *snippets, *file_values]
        ),
        "detector_slug": detector_name,
        "hit_count": len(hit_summaries),
        "severities": _uniq(severities),
        "detector_hits": proof_items,
    }


def _parse_engage_report_markdown(path: Path, workspace: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    clusters: list[dict[str, Any]] = []
    current_detector = ""
    current_hits: list[dict[str, Any]] = []
    pending_hit: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal current_detector, current_hits, pending_hit
        if pending_hit is not None:
            current_hits.append(pending_hit)
            pending_hit = None
        row = _normalize_detector_cluster(
            detector=current_detector,
            hits=current_hits,
            source_path=path,
            workspace=workspace,
        )
        if row is not None:
            clusters.append(row)
        current_detector = ""
        current_hits = []

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        cluster_match = ENGAGE_CLUSTER_RE.match(line)
        if cluster_match:
            if current_detector:
                flush()
            current_detector = cluster_match.group(1).strip()
            continue
        hit_match = ENGAGE_HIT_RE.match(line)
        if hit_match and current_detector:
            if pending_hit is not None:
                current_hits.append(pending_hit)
            pending_hit = {
                "severity": hit_match.group(1),
                "detector": hit_match.group(2),
                "file_path": hit_match.group(3),
            }
            continue
        if pending_hit is not None and line.startswith("- snippet:"):
            pending_hit["snippet"] = line.split(":", 1)[1].strip().strip("`")
    if current_detector:
        flush()
    return clusters


def _parse_engage_report_json(path: Path, workspace: Path) -> list[dict[str, Any]] | None:
    if not path.exists():
        return []
    try:
        payload = _load_json(path)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    raw_clusters = payload.get("clusters")
    if not isinstance(raw_clusters, list):
        return []
    clusters: list[dict[str, Any]] = []
    for item in raw_clusters:
        if not isinstance(item, dict):
            continue
        detector = str(item.get("detector_slug") or item.get("detector") or "").strip()
        if not detector:
            continue
        hits: list[dict[str, Any]] = []
        raw_hits = item.get("hits")
        if isinstance(raw_hits, list):
            for hit in raw_hits:
                if not isinstance(hit, dict):
                    continue
                file_path = str(
                    hit.get("file_path")
                    or hit.get("path")
                    or hit.get("file")
                    or hit.get("location")
                    or hit.get("loc")
                    or ""
                ).strip()
                hits.append(
                    {
                        "severity": str(
                            hit.get("severity")
                            or hit.get("severity_class")
                            or hit.get("sev")
                            or "UNKNOWN"
                        ).strip(),
                        "file_path": _workspace_relative_path(file_path, workspace),
                        "snippet": str(
                            hit.get("snippet")
                            or hit.get("message")
                            or hit.get("excerpt")
                            or hit.get("text")
                            or ""
                        ).strip(),
                    }
                )
        row = _normalize_detector_cluster(
            detector=detector,
            hits=hits,
            source_path=path,
            workspace=workspace,
            source_note="workspace:engage_report.json",
        )
        if row is not None:
            clusters.append(row)
    return clusters


def _resolve_engage_report_paths(workspace: Path, engage_report_arg: str | None) -> tuple[Path, Path]:
    if not engage_report_arg:
        return workspace / "engage_report.json", workspace / "engage_report.md"
    report_path = Path(engage_report_arg).expanduser().resolve()
    suffix = report_path.suffix.lower()
    if suffix == ".json":
        return report_path, report_path.with_suffix(".md")
    if suffix == ".md":
        return report_path.with_suffix(".json"), report_path
    return report_path.with_name("engage_report.json"), report_path


def _load_detector_clusters(workspace: Path, engage_report_arg: str | None) -> list[dict[str, Any]]:
    engage_report_json_path, engage_report_md_path = _resolve_engage_report_paths(workspace, engage_report_arg)
    if engage_report_json_path.exists():
        json_rows = _parse_engage_report_json(engage_report_json_path, workspace)
        if json_rows is not None:
            return json_rows
    return _parse_engage_report_markdown(engage_report_md_path, workspace)


def _defihack_report_paths(workspace: Path, explicit_paths: list[str]) -> list[Path]:
    paths = [Path(item).expanduser().resolve() for item in explicit_paths if str(item or "").strip()]
    if paths:
        return paths
    canonical = workspace / ".auditooor" / "defihack_match_report.md"
    if canonical.exists():
        return [canonical]
    candidates = sorted(
        (workspace / "scan-results").glob("defihack-match*/match_report.md"),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    )
    return candidates[:1]


def _normalize_defihack_row(
    row: dict[str, Any],
    path: Path,
    workspace: Path,
) -> dict[str, Any] | None:
    hit_lines = [str(item) for item in row.get("hit_lines", []) if str(item or "").strip()]
    if not hit_lines:
        return None
    attack_class = str(row.get("attack_class") or "").strip()
    row_id = str(row.get("id") or _slugify(attack_class)).strip()
    predicates = [str(item) for item in row.get("predicates", []) if str(item or "").strip()]
    mechanism = str(row.get("mechanism") or "").strip()
    hit_files = [_workspace_relative_path(item, workspace) for item in hit_lines]
    hit_files = [item for item in hit_files if item]
    proof_items = []
    for hit in hit_lines[:8]:
        rel = _workspace_relative_path(hit, workspace)
        proof_items.append(f"DeFiHack predicate hit {row_id}: {rel or hit}")
    source_values = [attack_class, mechanism, *predicates, *hit_files]
    return {
        "primitive_id": f"defihack:{_slugify(row_id)}",
        "source_kind": "defihack_predicate_match",
        "title": attack_class or row_id,
        "summary": mechanism or f"DeFiHackLabs predicate match {row_id}",
        "contract_hints": _extract_contract_hints(source_values),
        "attack_class_hints": _uniq([attack_class, _slugify(attack_class)]),
        "file_hints": _extract_file_hints(hit_files + hit_lines),
        "proof_items": _uniq(proof_items),
        "proof_keys": _uniq([_canon_key(row_id), _canon_key(attack_class)] + [_canon_key(item) for item in predicates]),
        "paired_live_row_ids": [],
        "paired_contracts": [],
        "involved_contracts": [],
        "source_refs": _uniq([str(path)] + hit_files),
        "blockers": ["DeFiHack predicate match is corpus analogue only until file:line exploitability is confirmed"],
        "duplicate_guard": {},
        "oos_guard": {},
        "material_distinction": "",
        "attempted_stronger_impact": "",
        "recommended_next_step": f"validate DeFiHack predicate class `{attack_class or row_id}` against the detector hit path",
        "causal_bridge_signals": _extract_causal_bridge_signals(source_values + proof_items),
        "attack_class": attack_class,
        "defihack_id": row_id,
        "predicates": _uniq(predicates),
    }


def _parse_defihack_report(path: Path, workspace: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_pattern = ""
    in_code = False

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        row = _normalize_defihack_row(current, path, workspace)
        if row is not None:
            rows.append(row)
        current = None

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip()
        section_match = DEFIHACK_SECTION_RE.match(line)
        if section_match:
            flush()
            current = {
                "id": section_match.group(1).strip(),
                "attack_class": section_match.group(2).strip(),
                "status": section_match.group(3).strip(),
                "predicates": [],
                "hit_lines": [],
                "mechanism": "",
            }
            current_pattern = ""
            in_code = False
            continue
        if current is None:
            continue
        if line.startswith("**Mechanism**:"):
            current["mechanism"] = line.split(":", 1)[1].strip().rstrip(" ")
            continue
        pattern_match = DEFIHACK_PATTERN_RE.match(line)
        if pattern_match:
            current_pattern = pattern_match.group(1).strip()
            current.setdefault("predicates", []).append(current_pattern)
            continue
        if line.strip() == "```":
            in_code = not in_code
            continue
        if in_code and line.strip():
            current.setdefault("hit_lines", []).append(line.strip())
            if current_pattern:
                current.setdefault("predicates", []).append(current_pattern)
    flush()
    return rows


def _load_defihack_primitives(workspace: Path, explicit_paths: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in _defihack_report_paths(workspace, explicit_paths):
        path_key = str(path)
        if path_key in seen:
            continue
        seen.add(path_key)
        out.extend(_parse_defihack_report(path, workspace))
    return out


def _hacker_brief_paths(workspace: Path, explicit_paths: list[str]) -> list[Path]:
    paths = [Path(item).expanduser().resolve() for item in explicit_paths if str(item or "").strip()]
    if paths:
        return paths
    default_path = workspace / ".auditooor" / "hacker_brief.md.json"
    return [default_path] if default_path.exists() else []


def _normalize_hacker_brief_payload(payload: dict[str, Any], path: Path, workspace: Path) -> list[dict[str, Any]]:
    sections = payload.get("sections") if isinstance(payload.get("sections"), dict) else {}
    files = [str(item) for item in (payload.get("files") or []) if str(item or "").strip()]
    lane_id = str(payload.get("lane_id") or path.stem).strip()

    detector_items_by_slug: dict[str, dict[str, Any]] = {}
    sec5 = sections.get("sec5_engage_report_fires") if isinstance(sections, dict) else {}
    if isinstance(sec5, dict):
        for item in sec5.get("items") or []:
            if not isinstance(item, dict):
                continue
            detector = str(item.get("detector") or item.get("detector_slug") or item.get("name") or "").strip()
            if detector:
                detector_items_by_slug[_slugify(detector)] = item

    questions: list[dict[str, Any]] = []
    sec13 = sections.get("sec13_question_list") if isinstance(sections, dict) else {}
    if isinstance(sec13, dict):
        for item in sec13.get("items") or sec13.get("questions") or []:
            if isinstance(item, dict) and str(item.get("id") or "").startswith("Q-DET-"):
                questions.append(item)
    if not questions:
        raw_text = json.dumps(sec13, sort_keys=True) if sec13 else ""
        for match in QDET_RE.finditer(raw_text):
            questions.append(
                {
                    "id": f"Q-DET-{match.group(1)}",
                    "text": f"Was detector fire `{match.group(1)}` investigated end-to-end?",
                    "evidence": "File:line confirmed or ruled out",
                }
            )

    out: list[dict[str, Any]] = []
    for question in questions:
        qid = str(question.get("id") or "").strip()
        detector_key = _slugify(qid.removeprefix("Q-DET-"))
        detector_item = detector_items_by_slug.get(detector_key, {})
        detector = str(
            detector_item.get("detector")
            or detector_item.get("detector_slug")
            or qid.removeprefix("Q-DET-")
        ).strip()
        fires = [str(item) for item in (detector_item.get("fires") or []) if str(item or "").strip()]
        question_text = str(question.get("text") or "").strip()
        evidence = str(question.get("evidence") or "").strip()
        source_values = files + fires + [question_text, evidence]
        out.append(
            {
                "primitive_id": f"qdet:{_slugify(lane_id)}:{_slugify(qid)}",
                "source_kind": "hacker_brief_qdet",
                "title": qid,
                "summary": question_text or f"Hacker brief requires detector question {qid} to be answered",
                "contract_hints": _extract_contract_hints(source_values + [detector]),
                "attack_class_hints": _uniq([detector, _slugify(detector)]),
                "file_hints": _extract_file_hints(source_values),
                "proof_items": _uniq([question_text, evidence] + fires),
                "proof_keys": _uniq([_canon_key(qid), _canon_key(detector)] + [_canon_key(item) for item in files]),
                "paired_live_row_ids": [],
                "paired_contracts": [],
                "involved_contracts": [],
                "source_refs": _uniq([str(path)] + files + fires),
                "blockers": [f"hacker-brief detector question {qid} is unanswered"],
                "duplicate_guard": {},
                "oos_guard": {},
                "material_distinction": "",
                "attempted_stronger_impact": "",
                "recommended_next_step": f"answer {qid} with PASS/FAIL/UNKNOWN plus file:line evidence",
                "causal_bridge_signals": _uniq(
                    [*_extract_causal_bridge_signals(source_values), *[
                        _canon_key(item)
                        for item in (question.get("causal_bridge_signals") or [])
                        if str(item or "").strip()
                    ]]
                ),
                "detector_slug": detector,
                "question_id": qid,
                "lane_id": lane_id,
            }
        )
    return out


def _load_hacker_brief_primitives(workspace: Path, explicit_paths: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in _hacker_brief_paths(workspace, explicit_paths):
        if not path.exists():
            continue
        payload = _load_json(path)
        if isinstance(payload, dict):
            out.extend(_normalize_hacker_brief_payload(payload, path, workspace))
    return out


def _source_artifact_paths(workspace: Path) -> list[Path]:
    artifact_dir = workspace / ".auditooor" / "source_artifacts"
    if not artifact_dir.is_dir():
        return []
    return sorted(artifact_dir.glob("*.source_artifact.json"))


def _source_ref_to_text(ref: Any, workspace: Path) -> str:
    if isinstance(ref, dict):
        path = _workspace_relative_path(str(ref.get("path") or ""), workspace)
        line = str(ref.get("line_start") or "").strip()
        if path and line:
            return f"{path}:{line}"
        return path or str(ref.get("source_ref") or "").strip()
    return _workspace_relative_path(str(ref or ""), workspace, preserve_line=True)


def _claim_live_bridge_id(claim: dict[str, Any]) -> str:
    for key in ("bridge_id", "live_bridge_id", "causal_bridge_signal"):
        value = str(claim.get(key) or "").strip()
        if value.startswith("LIVE-"):
            return value
    return ""


def _normalize_source_artifact_state_evidence(
    payload: dict[str, Any],
    path: Path,
    workspace: Path,
) -> dict[str, Any] | None:
    evidence = payload.get("state_evidence")
    if not isinstance(evidence, dict):
        return None
    claims = [claim for claim in (evidence.get("bridge_claims") or []) if isinstance(claim, dict)]
    if not claims:
        return None
    lead_id = str(evidence.get("lead_id") or payload.get("lead_id") or path.stem).strip()
    role = str(evidence.get("role") or "bridge_claim").strip()
    produces = [str(item) for item in (evidence.get("produces_state") or []) if str(item or "").strip()]
    requires = [str(item) for item in (evidence.get("requires_state") or []) if str(item or "").strip()]
    producer_state_artifact = str(
        evidence.get("producer_state_artifact")
        or evidence.get("state_artifact")
        or payload.get("producer_state_artifact")
        or ""
    ).strip()
    consumer_entrypoint = str(
        evidence.get("consumer_entrypoint")
        or evidence.get("entrypoint")
        or payload.get("consumer_entrypoint")
        or payload.get("target_entrypoint")
        or ""
    ).strip()
    impact_contract_id = str(
        evidence.get("impact_contract_id")
        or payload.get("impact_contract_id")
        or ""
    ).strip()
    artifact_refs = [_source_ref_to_text(ref, workspace) for ref in (payload.get("source_refs") or [])]
    claim_refs: list[str] = []
    bridge_ids: list[str] = []
    causal_signals: list[str] = []
    tokens: list[str] = []
    for claim in claims:
        token = str(claim.get("token") or "").strip()
        if token:
            tokens.append(token)
        bridge_id = _claim_live_bridge_id(claim)
        if bridge_id:
            bridge_ids.append(bridge_id)
            causal_signals.append(_canon_key(bridge_id))
        signal = str(claim.get("causal_bridge_signal") or "").strip()
        if signal:
            causal_signals.append(_canon_key(signal))
        claim_refs.extend(_source_ref_to_text(ref, workspace) for ref in (claim.get("source_refs") or []))
        producer_state_artifact = producer_state_artifact or str(claim.get("producer_state_artifact") or "").strip()
        consumer_entrypoint = consumer_entrypoint or str(
            claim.get("consumer_entrypoint") or claim.get("entrypoint") or ""
        ).strip()
        impact_contract_id = impact_contract_id or str(claim.get("impact_contract_id") or "").strip()
    source_refs = _uniq([str(path), *artifact_refs, *claim_refs])
    proof_items = _uniq(
        [
            f"source artifact {lead_id} {role} state `{token}` via {bridge_id or 'LIVE bridge'}"
            for token, bridge_id in zip(tokens or [lead_id], bridge_ids or [""])
        ]
    )
    return {
        "primitive_id": f"source-artifact:{_slugify(lead_id)}",
        "source_kind": "source_artifact_state_evidence",
        "title": f"{lead_id} state evidence",
        "summary": (
            f"Source-cited {role} state evidence for "
            + ", ".join(_uniq(produces + requires + tokens)[:4])
        ),
        "contract_hints": _extract_contract_hints(source_refs + produces + requires + tokens),
        "attack_class_hints": _uniq(tokens),
        "file_hints": _extract_file_hints(source_refs),
        "proof_items": proof_items,
        "proof_keys": _uniq([_canon_key(item) for item in tokens]),
        "paired_live_row_ids": _uniq(bridge_ids),
        "paired_contracts": [],
        "involved_contracts": [],
        "source_refs": source_refs,
        "broken_invariant_ids": _extract_invariant_ids(payload),
        "target_template_ids": _collect_string_values_for_key(payload, "target_template_ids"),
        "blockers": ["source-evidence bridge is source-cited but unexecuted; no runnable chain proof is claimed"],
        "duplicate_guard": {},
        "oos_guard": {},
        "material_distinction": "",
        "attempted_stronger_impact": "",
        "recommended_next_step": "compose and execute a harness that starts the consumer from the producer state",
        "causal_bridge_signals": _uniq(causal_signals),
        "lead_id": lead_id,
        "state_role": role,
        "produces_state": produces,
        "requires_state": requires,
        "bridge_claims": claims,
        "source_artifact_path": str(path),
        "producer_state_artifact": producer_state_artifact,
        "consumer_entrypoint": consumer_entrypoint,
        "generated_test_path": str(payload.get("generated_test_path") or evidence.get("generated_test_path") or "").strip(),
        "harness_command": str(payload.get("harness_command") or evidence.get("harness_command") or "").strip(),
        "gating_test": str(payload.get("gating_test") or evidence.get("gating_test") or "").strip(),
        "impact_contract_id": impact_contract_id,
    }


def _load_source_artifact_primitives(workspace: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in _source_artifact_paths(workspace):
        try:
            payload = _load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        row = _normalize_source_artifact_state_evidence(payload, path, workspace)
        if row is not None:
            out.append(row)
    return _dedupe_source_artifact_primitives(out)


def _dedupe_source_artifact_primitives(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse repeated state-evidence rows before the pairwise planner.

    Queue regeneration can emit thousands of rows that describe the same
    producer/consumer role, state tokens, and live bridge.  Keeping every
    rank-shaped copy makes the planner's O(n^2) pair scan both redundant and
    effectively unbounded.  The first row in deterministic artifact order is
    the representative; the count and a bounded sample preserve provenance
    without reintroducing the duplicate scan surface.
    """
    representatives: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("state_role") or "bridge_claim"),
            tuple(sorted(str(item) for item in row.get("produces_state") or [])),
            tuple(sorted(str(item) for item in row.get("requires_state") or [])),
            tuple(sorted(str(item) for item in row.get("attack_class_hints") or [])),
            tuple(sorted(str(item) for item in row.get("paired_live_row_ids") or [])),
            tuple(sorted(str(item) for item in row.get("causal_bridge_signals") or [])),
        )
        representative = representatives.get(key)
        if representative is None:
            item = dict(row)
            item["collapsed_source_artifact_count"] = 1
            item["collapsed_source_artifact_lead_ids"] = [str(row.get("lead_id") or "")]
            representatives[key] = item
            continue
        representative["collapsed_source_artifact_count"] = int(
            representative.get("collapsed_source_artifact_count") or 1
        ) + 1
        ids = representative.setdefault("collapsed_source_artifact_lead_ids", [])
        lead_id = str(row.get("lead_id") or "").strip()
        if lead_id and len(ids) < 8 and lead_id not in ids:
            ids.append(lead_id)
    return list(representatives.values())


def _pairwise_overlap(left: dict[str, Any], right: dict[str, Any]) -> dict[str, list[str]]:
    overlap = {
        "files": sorted(set(left["file_hints"]) & set(right["file_hints"])),
        "contracts": sorted(set(left["contract_hints"]) & set(right["contract_hints"])),
        "attack_classes": sorted(
            {_slugify(item) for item in (left.get("attack_class_hints") or []) if str(item or "").strip()}
            & {_slugify(item) for item in (right.get("attack_class_hints") or []) if str(item or "").strip()}
        ),
        "proof": sorted(set(left["proof_keys"]) & set(right["proof_keys"])),
        "paired_live_rows": sorted(set(left["paired_live_row_ids"]) & set(right["paired_live_row_ids"])),
        "paired_contracts": sorted(set(left["paired_contracts"]) & set(right["paired_contracts"])),
        "source_refs": sorted(set(left["source_refs"]) & set(right["source_refs"])),
        "causal_bridge_signals": sorted(
            set(left.get("causal_bridge_signals") or []) & set(right.get("causal_bridge_signals") or [])
        ),
    }
    left_detector = str(left.get("detector_slug") or "").strip()
    right_detector = str(right.get("detector_slug") or "").strip()
    overlap["detectors"] = [left_detector] if left_detector and left_detector == right_detector else []
    return overlap


def _pair_score(left: dict[str, Any], right: dict[str, Any], overlap: dict[str, list[str]]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if overlap["files"]:
        score += 5
        reasons.append("shared target file")
    if overlap["contracts"]:
        score += 4
        reasons.append("shared contract")
    if overlap["attack_classes"]:
        score += 4
        reasons.append("shared attack class")
    if overlap["proof"]:
        score += min(6, 2 * len(overlap["proof"]))
        reasons.append("shared proof prerequisite")
    if overlap["paired_live_rows"]:
        score += 5
        reasons.append("shared paired live row")
    if overlap["paired_contracts"]:
        score += 3
        reasons.append("shared paired contract")
    if overlap["detectors"]:
        score += 4
        reasons.append("shared detector question")
    if overlap["causal_bridge_signals"]:
        score += 6
        reasons.append("shared causal bridge signal")
    if left["source_kind"] == "detector_cluster" or right["source_kind"] == "detector_cluster":
        score += 1
        reasons.append("detector-cluster evidence seed")
    if left["source_kind"] == "hacker_brief_qdet" or right["source_kind"] == "hacker_brief_qdet":
        score += 1
        reasons.append("hacker-brief detector question seed")
    if left["source_kind"] != right["source_kind"]:
        score += 1
        reasons.append("cross-artifact composition")
    if left["paired_live_row_ids"] or right["paired_live_row_ids"]:
        score += 1
        reasons.append("live-proof dependency present")
    if left["blockers"] or right["blockers"]:
        score -= 1
    return score, reasons


def _has_chain_forming_overlap(overlap: dict[str, list[str]]) -> bool:
    """Source-artifact overlap alone is metadata, not an attack-chain signal."""
    return any(
        overlap.get(key)
        for key in (
            "files",
            "contracts",
            "attack_classes",
            "proof",
            "paired_live_rows",
            "paired_contracts",
            "detectors",
            "causal_bridge_signals",
        )
    )


def _is_detector_qdet_pair(left: dict[str, Any], right: dict[str, Any]) -> bool:
    pair = {left.get("source_kind"), right.get("source_kind")}
    return pair == {"detector_cluster", "hacker_brief_qdet"}


def _is_detector_qdet_derived_pair(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        str(left.get("source_kind") or "") in DETECTOR_QDET_DERIVED_KINDS
        or str(right.get("source_kind") or "") in DETECTOR_QDET_DERIVED_KINDS
    )


def _has_distinct_causal_bridge_signal(overlap: dict[str, list[str]]) -> bool:
    return bool(
        overlap.get("causal_bridge_signals")
        or overlap.get("paired_live_rows")
        or overlap.get("paired_contracts")
    )


def _has_non_detector_proof_bridge(
    left: dict[str, Any],
    right: dict[str, Any],
    overlap: dict[str, list[str]],
) -> bool:
    return bool(
        overlap.get("proof")
        and not _is_detector_qdet_derived_pair(left, right)
    )


def _has_big_loss_bridge_signal(
    left: dict[str, Any],
    right: dict[str, Any],
    overlap: dict[str, list[str]],
) -> bool:
    return _has_distinct_causal_bridge_signal(overlap) or _has_non_detector_proof_bridge(left, right, overlap)


def _candidate_pair_indices(primitives: list[dict[str, Any]]) -> list[tuple[int, int]]:
    """Return only primitive pairs that can have a non-empty overlap.

    The composition predicate is the union of intersections across the
    primitive metadata fields.  Indexing each field therefore preserves the
    exact eligible pair set while avoiding the quadratic comparison of every
    unrelated source-artifact row.
    """
    buckets: dict[tuple[str, str], list[int]] = {}
    fields = (
        ("file", "file_hints"),
        ("contract", "contract_hints"),
        ("attack", "attack_class_hints"),
        ("proof", "proof_keys"),
        ("live", "paired_live_row_ids"),
        ("paired_contract", "paired_contracts"),
        ("causal", "causal_bridge_signals"),
    )
    for index, primitive in enumerate(primitives):
        for namespace, field in fields:
            values = primitive.get(field) or []
            if namespace == "attack":
                values = [_slugify(item) for item in values if str(item or "").strip()]
            for value in set(str(item) for item in values if str(item or "").strip()):
                buckets.setdefault((namespace, value), []).append(index)
        detector = str(primitive.get("detector_slug") or "").strip()
        if detector:
            buckets.setdefault(("detector", detector), []).append(index)

    pairs: set[tuple[int, int]] = set()

    def composable_source_artifact(index: int) -> bool:
        """Exclude already-composed state evidence from fresh pair planning.

        ``producer_consumer`` rows are durable evidence of a chain that has
        already been composed upstream. They remain in the payload and summary
        for provenance, but pairing each one with every direct primitive would
        recreate the same chain thousands of times on every rerun.
        """
        primitive = primitives[index]
        if primitive.get("source_kind") != "source_artifact_state_evidence":
            return True
        role = str(primitive.get("state_role") or "").strip().lower()
        return role in {"producer", "consumer", "bridge_claim"}

    def add_pair(left: int, right: int) -> None:
        pairs.add((left, right) if left < right else (right, left))

    for indices in buckets.values():
        if len(indices) < 2:
            continue
        direct = [
            index
            for index in indices
            if primitives[index].get("source_kind") != "source_artifact_state_evidence"
        ]
        producers = [
            index
            for index in indices
            if primitives[index].get("source_kind") == "source_artifact_state_evidence"
            and str(primitives[index].get("state_role") or "").strip().lower() == "producer"
        ]
        consumers = [
            index
            for index in indices
            if primitives[index].get("source_kind") == "source_artifact_state_evidence"
            and str(primitives[index].get("state_role") or "").strip().lower() == "consumer"
        ]
        # Preserve every direct-direct and direct-artifact overlap. For two
        # source artifacts, only an explicit producer-consumer edge is a valid
        # composition; producer_consumer rows are already composed evidence.
        for offset, left in enumerate(direct[:-1]):
            for right in direct[offset + 1:]:
                add_pair(left, right)
        for left in direct:
            for right in indices:
                if (primitives[right].get("source_kind") == "source_artifact_state_evidence"
                        and composable_source_artifact(right)):
                    add_pair(left, right)
        for left in producers:
            for right in consumers:
                add_pair(left, right)
    return sorted(pairs)


def _select_big_loss(
    big_loss_rows: list[dict[str, Any]],
    pair: tuple[dict[str, Any], dict[str, Any]],
    overlap: dict[str, list[str]],
) -> tuple[dict[str, Any] | None, int]:
    if not big_loss_rows or not _has_big_loss_bridge_signal(pair[0], pair[1], overlap):
        return None, 0
    pair_files = set(pair[0]["file_hints"]) | set(pair[1]["file_hints"])
    pair_contracts = set(pair[0]["contract_hints"]) | set(pair[1]["contract_hints"])
    best: dict[str, Any] | None = None
    best_score = 0
    for row in big_loss_rows:
        score = 0
        if set(row["file_hints"]) & pair_files:
            score += 2
        if set(row["contract_hints"]) & pair_contracts:
            score += 2
        if score > best_score:
            best = row
            best_score = score
    return best, best_score


def _build_chain_steps(primitives: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    ordinal = 1
    for primitive in primitives:
        if primitive["source_kind"] == "big_loss_actor_sequence":
            for actor_step in primitive.get("actor_sequence", []):
                if not isinstance(actor_step, dict):
                    continue
                steps.append(
                    {
                        "step": ordinal,
                        "source_kind": "big_loss_actor_sequence",
                        "advisory_only": True,
                        "summary": (
                            f"{actor_step.get('actor') or 'actor'}: "
                            f"{actor_step.get('action') or 'act'} "
                            f"against {actor_step.get('target') or 'target'}"
                        ),
                        "evidence_required": str(actor_step.get("evidence_required") or "").strip(),
                        "prerequisite": str(actor_step.get("prerequisite") or "").strip(),
                    }
                )
                ordinal += 1
            continue
        steps.append(
            {
                "step": ordinal,
                "source_kind": primitive["source_kind"],
                "advisory_only": True,
                "summary": primitive["summary"],
                **(
                    {
                        "evidence_required": primitive["recommended_next_step"],
                        "detector_slug": primitive.get("detector_slug", ""),
                    }
                    if primitive["source_kind"] in {"detector_cluster", "hacker_brief_qdet", "defihack_predicate_match"}
                    else {}
                ),
            }
        )
        ordinal += 1
    return steps


def _source_artifact_composition_requirement(
    chain_id: str,
    left: dict[str, Any],
    right: dict[str, Any],
    overlap: dict[str, list[str]],
) -> dict[str, Any] | None:
    if {left.get("source_kind"), right.get("source_kind")} != {"source_artifact_state_evidence"}:
        return None
    if {
        str(left.get("state_role") or "").strip().lower(),
        str(right.get("state_role") or "").strip().lower(),
    } != {"producer", "consumer"}:
        return None
    live_rows = [item for item in overlap.get("paired_live_rows", []) if str(item).startswith("LIVE-")]
    live_signals = [item for item in overlap.get("causal_bridge_signals", []) if str(item).startswith("live-")]
    if not live_rows and not live_signals:
        return None

    if left.get("state_role") == "producer" or (left.get("produces_state") and not right.get("produces_state")):
        producer, consumer = left, right
    elif right.get("state_role") == "producer" or (right.get("produces_state") and not left.get("produces_state")):
        producer, consumer = right, left
    else:
        producer, consumer = left, right

    producer_lead_id = str(producer.get("lead_id") or "").strip()
    consumer_lead_id = str(consumer.get("lead_id") or "").strip()
    if not producer_lead_id or not consumer_lead_id or producer_lead_id == consumer_lead_id:
        return None

    producer_template_ids = _uniq(
        [str(item) for item in (producer.get("target_template_ids") or []) if str(item or "").strip()]
    )
    consumer_template_ids = _uniq(
        [str(item) for item in (consumer.get("target_template_ids") or []) if str(item or "").strip()]
    )
    if producer_template_ids and consumer_template_ids:
        target_template_ids = [
            item for item in producer_template_ids if item in set(consumer_template_ids)
        ]
        if not target_template_ids:
            return None
    else:
        target_template_ids = producer_template_ids or consumer_template_ids

    bridging_state = _uniq(
        [
            item
            for item in [*(producer.get("produces_state") or []), *(consumer.get("requires_state") or [])]
            if str(item or "").strip()
        ]
    )
    if not bridging_state:
        bridging_state = _uniq([*(overlap.get("proof") or []), *(live_rows or live_signals)])

    impact_contract_id = (
        str(producer.get("impact_contract_id") or "").strip()
        or str(consumer.get("impact_contract_id") or "").strip()
        or None
    )
    requirement: dict[str, Any] = {
        "binding_scope": "composed_chain_harness",
        "chain_id": chain_id or None,
        "primitive_pair_ids": [left.get("primitive_id"), right.get("primitive_id")],
        "producer_lead_id": producer_lead_id,
        "consumer_lead_id": consumer_lead_id,
        "bridging_state": bridging_state[0] if len(bridging_state) == 1 else bridging_state,
        "producer_state_artifact": producer.get("producer_state_artifact") or None,
        "producer_source_artifact": producer.get("source_artifact_path") or None,
        "producer_source_refs": producer.get("source_refs") or [],
        "producer_broken_invariant_ids": producer.get("broken_invariant_ids") or [],
        "consumer_entrypoint": consumer.get("consumer_entrypoint") or None,
        "consumer_source_refs": consumer.get("source_refs") or [],
        "consumer_broken_invariant_ids": consumer.get("broken_invariant_ids") or [],
        "generated_test_path": consumer.get("generated_test_path") or producer.get("generated_test_path") or None,
        "harness_command": consumer.get("harness_command") or producer.get("harness_command") or None,
        "gating_test": consumer.get("gating_test") or producer.get("gating_test") or None,
        "target_template_ids": target_template_ids,
    }
    if impact_contract_id:
        requirement["impact_contract_id"] = impact_contract_id
    return requirement


def _plan_row(
    chain_id: str,
    left: dict[str, Any],
    right: dict[str, Any],
    overlap: dict[str, list[str]],
    score: int,
    reasons: list[str],
    big_loss: dict[str, Any] | None,
    big_loss_score: int,
) -> dict[str, Any]:
    primitives = [left, right]
    if big_loss is not None:
        primitives.append(big_loss)
        score += 2 + big_loss_score
        reasons.append("big-loss actor sequence attached as advisory chain scaffold")
    primitive_labels = [f"{item['source_kind']}:{item['title']}" for item in primitives]
    source_refs = _uniq([ref for item in primitives for ref in item.get("source_refs", [])])
    proof_prerequisites = _uniq([item for primitive in primitives[:2] for item in primitive.get("proof_items", [])])
    proof_steps = _uniq(
        proof_prerequisites
        + [
            primitive["recommended_next_step"]
            for primitive in primitives[:2]
            if primitive.get("recommended_next_step")
        ]
    )
    blockers = _uniq(
        [item for primitive in primitives[:2] for item in primitive.get("blockers", [])]
        + ["pre-submit gate has not passed", "proof artifacts are not yet executed"]
    )
    attempted_stronger_impact = ""
    for primitive in primitives:
        attempted_stronger_impact = str(primitive.get("attempted_stronger_impact") or "").strip()
        if attempted_stronger_impact:
            break
    if not attempted_stronger_impact:
        attempted_stronger_impact = (
            "compose the selected primitives into a broader state-transition "
            "or asset-impact path than either primitive proves alone"
        )
    material_distinction = _uniq(
        [str(primitive.get("material_distinction") or "").strip() for primitive in primitives]
    )
    material = (
        " ".join(material_distinction)
        if material_distinction
        else "show that the combined chain adds a state transition or victim surface absent from each primitive alone"
    )
    shared_evidence: list[str] = []
    if overlap["files"]:
        shared_evidence.append("shared_files:" + ",".join(overlap["files"]))
    if overlap["contracts"]:
        shared_evidence.append("shared_contracts:" + ",".join(overlap["contracts"]))
    if overlap["attack_classes"]:
        shared_evidence.append("shared_attack_classes:" + ",".join(overlap["attack_classes"]))
    if overlap["proof"]:
        shared_evidence.append("shared_proof_keys:" + ",".join(overlap["proof"]))
    if overlap["paired_live_rows"]:
        shared_evidence.append("shared_live_rows:" + ",".join(overlap["paired_live_rows"]))
    if overlap["source_refs"]:
        shared_evidence.append("shared_source_refs:" + ",".join(overlap["source_refs"]))
    if overlap["detectors"]:
        shared_evidence.append("shared_detectors:" + ",".join(overlap["detectors"]))
    if overlap["causal_bridge_signals"]:
        shared_evidence.append("shared_causal_bridge_signals:" + ",".join(overlap["causal_bridge_signals"]))
    if big_loss is not None:
        shared_evidence.append(f"big_loss_template:{big_loss.get('template_id') or big_loss.get('row_id')}")
    metadata_overlap_only = not _has_distinct_causal_bridge_signal(overlap)
    if metadata_overlap_only:
        blockers.append("causal bridge is unproven; overlap is metadata-level until distinct bridge evidence exists")
    composition_requirement = _source_artifact_composition_requirement(chain_id, left, right, overlap)
    broken_invariant_ids = _uniq(
        [
            inv
            for primitive in primitives
            for inv in (primitive.get("broken_invariant_ids") or [])
            if str(inv or "").strip()
        ]
        + _extract_invariant_ids(primitives)
    )
    target_template_ids = _uniq(
        [
            template_id
            for primitive in primitives
            for template_id in (primitive.get("target_template_ids") or [])
            if str(template_id or "").strip()
        ]
    )
    duplicate_statuses = _uniq(
        [
            str((primitive.get("duplicate_guard") or {}).get("status") or "")
            for primitive in primitives
            if isinstance(primitive.get("duplicate_guard"), dict)
            and str((primitive.get("duplicate_guard") or {}).get("status") or "")
        ]
    )
    oos_statuses = _uniq(
        [
            str((primitive.get("oos_guard") or {}).get("status") or "")
            for primitive in primitives
            if isinstance(primitive.get("oos_guard"), dict)
            and str((primitive.get("oos_guard") or {}).get("status") or "")
        ]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "chain_id": chain_id,
        "status": "candidate_not_submit_ready",
        "advisory_only": True,
        "does_not_claim_exploitability": True,
        "causal_hypothesis_only": True,
        "causal_evidence_level": (
            "distinct_bridge_signal_present" if not metadata_overlap_only else "metadata_overlap_only_unproven"
        ),
        "metadata_overlap_only": metadata_overlap_only,
        "score": score,
        "primitives": [
            {
                "primitive_id": primitive["primitive_id"],
                "source_kind": primitive["source_kind"],
                "title": primitive["title"],
                "paired_live_row_ids": primitive.get("paired_live_row_ids", []),
                "causal_bridge_signals": primitive.get("causal_bridge_signals", []),
            }
            for primitive in primitives
        ],
        "attempted_stronger_impact": attempted_stronger_impact,
        "material_distinction_required": material,
        "composition_rationale": "; ".join(_uniq(reasons)) or "shared local evidence suggests the primitives may compose",
        "chain_steps": _build_chain_steps(primitives),
        "proof_steps": proof_steps,
        "shared_evidence": shared_evidence,
        "composition_harness_requirements": [composition_requirement] if composition_requirement else [],
        "broken_invariant_ids": broken_invariant_ids,
        "target_template_ids": target_template_ids,
        "paired_live_row_ids": overlap.get("paired_live_rows", []),
        "causal_bridge_signals": overlap.get("causal_bridge_signals", []),
        "proof_prerequisites": proof_prerequisites,
        "duplicate_guard": {
            "statuses": duplicate_statuses or ["clear_or_unset"],
        },
        "oos_guard": {
            "statuses": oos_statuses or ["manual_review_required"],
        },
        "kill_conditions": blockers,
        "blockers": blockers,
        "escalation_result": "blocked pending proof steps and blockers; advisory chain candidate only",
        "recommended_next_step": proof_steps[0] if proof_steps else "collect concrete source proof before attempting escalation",
        "source_refs": source_refs,
        "candidate_not_submit_ready": True,
    }


def _render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Chained Attack Plans",
        "",
        f"- schema_version: {payload['schema_version']}",
        f"- workspace: {payload['workspace']}",
        f"- plan_count: {payload['summary']['plan_count']}",
        "",
    ]
    for plan in payload.get("plans", []):
        lines.append(f"## {plan['chain_id']}")
        lines.append(f"- status: {plan['status']}")
        lines.append("- primitives: " + ", ".join(item["primitive_id"] for item in plan["primitives"]))
        lines.append(f"- attempted stronger impact: {plan['attempted_stronger_impact']}")
        lines.append(f"- material distinction: {plan['material_distinction_required']}")
        lines.append(f"- escalation result: {plan['escalation_result']}")
        lines.append("")
        lines.append("### Composition rationale")
        lines.append(plan["composition_rationale"])
        lines.append("")
        lines.append("### Chain steps")
        for step in plan["chain_steps"]:
            lines.append(f"{step['step']}. {step['summary']}")
        lines.append("")
        lines.append("### Proof steps")
        for step in plan["proof_steps"]:
            lines.append(f"- {step}")
        lines.append("")
        lines.append("### Blockers")
        for blocker in plan["blockers"]:
            lines.append(f"- {blocker}")
        lines.append("")
        lines.append("### Source refs")
        for ref in plan["source_refs"]:
            lines.append(f"- {ref}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _build_payload(
    workspace: Path,
    exploit_payload: dict[str, Any] | None,
    exploit_path: Path | None,
    candidate_payload: dict[str, Any] | list[Any] | None,
    candidate_path: Path | None,
    swarm_manifest: dict[str, Any] | None,
    swarm_manifest_path: Path | None,
    big_loss_payload: dict[str, Any] | None,
    big_loss_mode: str,
    detector_clusters: list[dict[str, Any]] | None,
    hacker_brief_primitives: list[dict[str, Any]] | None,
    defihack_primitives: list[dict[str, Any]] | None,
    source_artifact_primitives: list[dict[str, Any]] | None,
    max_plans: int,
) -> dict[str, Any]:
    manifest_ctx = _manifest_contract_context(swarm_manifest or {})
    angles = []
    if isinstance(exploit_payload, dict):
        raw_angles = exploit_payload.get("angles")
        if isinstance(raw_angles, list):
            angles = [_normalize_angle(row, exploit_path) for row in raw_angles if isinstance(row, dict)]
    raw_candidates: list[dict[str, Any]] = []
    if isinstance(candidate_payload, dict) and isinstance(candidate_payload.get("candidates"), list):
        raw_candidates = [row for row in candidate_payload["candidates"] if isinstance(row, dict)]
    elif isinstance(candidate_payload, list):
        raw_candidates = [row for row in candidate_payload if isinstance(row, dict)]
    # Composed chain rows are downstream obligations, not fresh primitives.
    # Feeding them back into pairwise composition creates a recursive
    # chain-of-chains explosion on reruns and can starve direct proof work.
    # Keep them in their source queue; only direct candidates may seed a new
    # composition round.
    chain_candidate_excluded_count = sum(
        1
        for row in raw_candidates
        if row.get("chain_id")
        or str(row.get("title") or "").strip().lower().startswith("chain ")
    )
    direct_candidates = [
        row
        for row in raw_candidates
        if not row.get("chain_id")
        and not str(row.get("title") or "").strip().lower().startswith("chain ")
    ]
    terminal_statuses = {
        "closed_negative",
        "closed_negative_source_proof",
        "disproved",
        "false_positive",
        "killed",
    }
    terminal_candidate_excluded_count = sum(
        1
        for row in direct_candidates
        if str(
            row.get("proof_status")
            or row.get("source_mined_proof_status")
            or row.get("quality_gate_status")
            or row.get("learning_route")
            or ""
        ).strip().lower() in terminal_statuses
        or str(row.get("quality_gate_status") or "").strip().lower().startswith("closed_negative")
        or str(row.get("learning_route") or "").strip().lower() in {"drop", "dropped", "closed-negative"}
    )
    direct_candidates = [
        row
        for row in direct_candidates
        if str(
            row.get("proof_status")
            or row.get("source_mined_proof_status")
            or row.get("quality_gate_status")
            or row.get("learning_route")
            or ""
        ).strip().lower() not in terminal_statuses
        and not str(row.get("quality_gate_status") or "").strip().lower().startswith("closed_negative")
        and str(row.get("learning_route") or "").strip().lower() not in {"drop", "dropped", "closed-negative"}
    ]
    candidates = [_normalize_candidate(row, candidate_path, manifest_ctx) for row in direct_candidates]
    big_loss_rows = _normalize_big_loss(big_loss_payload, workspace, big_loss_mode)
    detector_rows = detector_clusters or []
    qdet_rows = hacker_brief_primitives or []
    defihack_rows = defihack_primitives or []
    source_artifact_rows = source_artifact_primitives or []

    primitives = angles + candidates + detector_rows + qdet_rows + defihack_rows + source_artifact_rows
    plans: list[dict[str, Any]] = []
    for left_idx, right_idx in _candidate_pair_indices(primitives):
        left = primitives[left_idx]
        right = primitives[right_idx]
        overlap = _pairwise_overlap(left, right)
        if not _has_chain_forming_overlap(overlap):
            continue
        if _is_detector_qdet_pair(left, right) and not _has_distinct_causal_bridge_signal(overlap):
            # Same detector observation + Q-DET follow-up is not a causal chain by itself.
            continue
        score, reasons = _pair_score(left, right, overlap)
        if _is_detector_qdet_derived_pair(left, right) and not _has_distinct_causal_bridge_signal(overlap):
            # Detector / question metadata overlap is advisory only until a distinct causal bridge is shown.
            if score > PURE_ADVISORY_PAIR_SCORE:
                reasons.append(
                    "detector/question metadata overlap capped at pure advisory rank pending distinct causal bridge signal"
                )
            score = min(score, PURE_ADVISORY_PAIR_SCORE)
        if score <= 0:
            continue
        big_loss, big_loss_score = _select_big_loss(big_loss_rows, (left, right), overlap)
        plans.append(
            _plan_row(
                chain_id="",
                left=left,
                right=right,
                overlap=overlap,
                score=score,
                reasons=reasons,
                big_loss=big_loss,
                big_loss_score=big_loss_score,
            )
            )

    plans.sort(
        key=lambda row: (
            -int(row["score"]),
            len(row.get("shared_evidence", [])),
            ",".join(item["primitive_id"] for item in row["primitives"]),
        )
    )
    plans = plans[: max(0, max_plans)]
    for idx, plan in enumerate(plans, start=1):
        plan["chain_id"] = f"CHAIN-{idx:03d}"
        for requirement in plan.get("composition_harness_requirements", []):
            if isinstance(requirement, dict):
                requirement["chain_id"] = plan["chain_id"]

    generated_at = ""
    for payload in (exploit_payload or {}, swarm_manifest or {}, big_loss_payload or {}):
        if isinstance(payload, dict):
            stamp = str(payload.get("generated_at") or "").strip()
            if stamp:
                generated_at = stamp
                break
    return {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "generated_at": generated_at,
        "advisory_only": True,
        "submission_posture": "candidate_not_submit_ready",
        "sources": {
            "exploit_json": str(exploit_path) if exploit_path and exploit_path.exists() else None,
            "brief_candidates_json": str(candidate_path) if candidate_path and candidate_path.exists() else None,
            "swarm_manifest_json": str(swarm_manifest_path) if swarm_manifest_path and swarm_manifest_path.exists() else None,
            "engage_report_md": str(workspace / "engage_report.md") if (workspace / "engage_report.md").exists() else None,
            "hacker_brief_json_count": len(qdet_rows),
            "defihack_predicate_match_count": len(defihack_rows),
            "source_artifact_state_evidence_count": sum(
                int(row.get("collapsed_source_artifact_count") or 1)
                for row in source_artifact_rows
            ),
            "big_loss_mode": big_loss_mode,
        },
        "summary": {
            "exploit_angle_count": len(angles),
            "brief_candidate_count": len(candidates),
            "chain_candidate_excluded_count": chain_candidate_excluded_count,
            "terminal_candidate_excluded_count": terminal_candidate_excluded_count,
            "detector_cluster_count": len(detector_rows),
            "hacker_brief_qdet_count": len(qdet_rows),
            "defihack_predicate_match_count": len(defihack_rows),
            "source_artifact_state_evidence_count": sum(
                int(row.get("collapsed_source_artifact_count") or 1)
                for row in source_artifact_rows
            ),
            "source_artifact_state_evidence_unique_count": len(source_artifact_rows),
            "big_loss_actor_sequence_count": len(big_loss_rows),
            "plan_count": len(plans),
            "max_plans": max_plans,
        },
        "plans": plans,
    }


def _source_plan_artifact_ref(path: Path, workspace: Path) -> str:
    rel = _workspace_relative_path(str(path), workspace)
    return rel or _sanitize_output_text(str(path), workspace)


def _first_composition_requirement(plan: dict[str, Any]) -> dict[str, Any]:
    for item in plan.get("composition_harness_requirements") or []:
        if isinstance(item, dict):
            return item
    return {}


def _source_refs_exist_in_workspace(refs: list[str], workspace: Path | None) -> bool:
    if workspace is None:
        return True
    for ref in refs:
        path_part, sep, line_part = str(ref or "").strip().rpartition(":")
        if not sep or not path_part or not line_part.isdigit():
            return False
        path = Path(path_part)
        if not path.is_absolute():
            path = workspace / path
        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(workspace.resolve(strict=False))
        except (OSError, ValueError):
            return False
        if not resolved.is_file():
            return False
        line_no = int(line_part)
        if line_no < 1:
            return False
        try:
            with resolved.open(encoding="utf-8", errors="ignore") as fh:
                for idx, _line in enumerate(fh, start=1):
                    if idx >= line_no:
                        break
                else:
                    return False
        except OSError:
            return False
    return True


def _composition_proof_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in (
        "composition_proof",
        "chain_proof",
        "proof_execution",
        "poc_execution",
        "executed_composition_proof",
        "composition_proof_executed",
        "runnable_chain_proof_executed",
        "source_backed_composition_proof",
    ):
        value = plan.get(key)
        if isinstance(value, dict):
            rows.append(value)
    for key in ("composition_proofs", "chain_proofs", "proof_rows", "poc_executions"):
        value = plan.get(key)
        if not isinstance(value, list):
            continue
        rows.extend(item for item in value if isinstance(item, dict))
    return rows


def _composition_proof_state_tokens(row: dict[str, Any]) -> set[str]:
    return {
        token for token in {
            _status_token(row.get("status")),
            _status_token(row.get("verdict")),
            _status_token(row.get("result")),
            _status_token(row.get("final_result")),
            _status_token(row.get("proof_status")),
        } if token
    }


def _composition_proof_row_is_executed(row: dict[str, Any]) -> bool:
    states = _composition_proof_state_tokens(row)
    if not states or states <= {""}:
        return False
    if states & WEAK_COMPOSITION_PROOF_STATES:
        return False
    if _truthy(row.get("advisory_only")) or _truthy(row.get("blocked")) or _truthy(row.get("dry_run")):
        return False
    return bool(states & EXECUTED_COMPOSITION_PROOF_STATES)


def _proof_row_refs(row: dict[str, Any], *keys: str) -> list[str]:
    refs: list[str] = []
    for key in keys:
        value = row.get(key)
        if isinstance(value, list):
            refs.extend(_extract_file_line_refs(value))
        elif isinstance(value, dict):
            refs.extend(_extract_file_line_refs(value))
        elif value is not None:
            refs.extend(_extract_file_line_refs(str(value)))
    return _uniq(refs)


def _proof_row_lead_id(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def _matching_executed_composition_proof(
    plan: dict[str, Any],
    requirement: dict[str, Any],
    workspace: Path | None,
) -> dict[str, Any] | None:
    producer_lead_id = str(requirement.get("producer_lead_id") or "").strip()
    consumer_lead_id = str(requirement.get("consumer_lead_id") or "").strip()
    if not producer_lead_id or not consumer_lead_id or producer_lead_id == consumer_lead_id:
        return None
    for row in _composition_proof_rows(plan):
        if not _composition_proof_row_is_executed(row):
            continue
        proof_producer = _proof_row_lead_id(
            row,
            "producer_lead_id",
            "from_queue_lead_id",
            "from_lead_id",
        )
        proof_consumer = _proof_row_lead_id(
            row,
            "consumer_lead_id",
            "to_queue_lead_id",
            "to_lead_id",
        )
        if proof_producer != producer_lead_id or proof_consumer != consumer_lead_id:
            continue
        if proof_producer == proof_consumer:
            continue
        from_refs = _proof_row_refs(row, "from_source_refs", "producer_source_refs")
        to_refs = _proof_row_refs(row, "to_source_refs", "consumer_source_refs")
        if not from_refs or not to_refs:
            continue
        if not _source_refs_exist_in_workspace(_uniq(from_refs + to_refs), workspace):
            continue
        return row
    return None


def _plan_has_executed_composition_proof(plan: dict[str, Any]) -> bool:
    for key in (
        "composition_proof_status",
        "chain_proof_status",
        "proof_status",
        "composition_status",
        "final_result",
    ):
        if _status_token(plan.get(key)) in EXECUTED_COMPOSITION_PROOF_STATES:
            return True
    for row in _composition_proof_rows(plan):
        if _composition_proof_row_is_executed(row):
            return True
    return False


def _source_link_rows_from_payload(
    payload: dict[str, Any],
    workspace: Path | None = None,
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for plan in payload.get("plans") or []:
        if not isinstance(plan, dict):
            continue
        if (
            _truthy(plan.get("candidate_not_submit_ready"))
            or _truthy(plan.get("advisory_only"))
            or plan.get("blockers")
            or plan.get("kill_conditions")
        ) and not _plan_has_executed_composition_proof(plan):
            continue
        requirement = _first_composition_requirement(plan)
        if not requirement:
            continue
        producer_lead_id = str(requirement.get("producer_lead_id") or "").strip()
        consumer_lead_id = str(requirement.get("consumer_lead_id") or "").strip()
        if not producer_lead_id or not consumer_lead_id:
            continue
        if producer_lead_id == consumer_lead_id:
            continue
        proof_row = _matching_executed_composition_proof(plan, requirement, workspace)
        if proof_row is None:
            continue
        inv_ids = _uniq(
            _extract_invariant_ids(requirement.get("producer_broken_invariant_ids") or [])
            + _extract_invariant_ids(requirement.get("consumer_broken_invariant_ids") or [])
            + _extract_invariant_ids(plan.get("broken_invariant_ids") or [])
        )
        from_refs = _proof_row_refs(proof_row, "from_source_refs", "producer_source_refs")
        to_refs = _proof_row_refs(proof_row, "to_source_refs", "consumer_source_refs")
        refs = _uniq(from_refs + to_refs)
        if len(inv_ids) < 2 or len(refs) < 2:
            continue
        chain_id = str(plan.get("chain_id") or "CHAIN").strip()
        digest = hashlib.sha256(
            "|".join([chain_id, *inv_ids, *refs]).encode("utf-8")
        ).hexdigest()[:12]
        row: dict[str, Any] = {
            "link_id": f"SL-{chain_id}-{digest or 'source'}",
            "status": "source_backed",
            "broken_invariant_ids": inv_ids,
            "from_invariant_id": inv_ids[0],
            "to_invariant_id": inv_ids[1],
            "source_refs": refs,
            "from_source_refs": from_refs,
            "to_source_refs": to_refs,
            "manual_seeding_absent": True,
            "source_artifacts_complete": _source_refs_exist_in_workspace(refs, workspace),
            "causality": str(plan.get("composition_rationale") or "").strip(),
            "kill_condition_answer": "; ".join(
                str(item)
                for item in (plan.get("kill_conditions") or plan.get("blockers") or [])[:3]
                if str(item or "").strip()
            ),
        }
        target_template_ids = [
            item
            for item in (requirement.get("target_template_ids") or [])
            if str(item or "").strip()
        ]
        if target_template_ids:
            row["target_template_ids"] = _uniq([str(item) for item in target_template_ids])
        row["from_queue_lead_id"] = producer_lead_id
        row["to_queue_lead_id"] = consumer_lead_id
        bridge_state = requirement.get("bridging_state")
        if isinstance(bridge_state, list):
            bridge_state = ",".join(str(item) for item in bridge_state if str(item or "").strip())
        bridge_state_text = str(bridge_state or "").strip()
        if bridge_state_text:
            row["from_output"] = bridge_state_text
            row["to_input"] = bridge_state_text
        links.append(row)
    return links


def _attach_runnable_composition_proofs(
    payload: dict[str, Any],
    workspace: Path,
) -> int:
    """Stamp an executed composition proof onto every composition_runnable plan.

    This is the missing pipeline stage that turns the structurally-empty
    chain_synth_source_links artifact into a source-backed one.  Before this,
    every plan the planner built carried advisory_only/blockers/kill_conditions
    and NO executed composition proof, so _source_link_rows_from_payload hit the
    advisory `continue` on every plan and emitted links=[].

    We run the existing chain-composition-harness.compose_chain over each plan;
    a plan is only proven when that gate returns verdict == "composition_runnable"
    (every hop has a D1 LIVE bridge, a composed harness command exists, and the
    composed sequence survives defense-in-depth).  Only then do we attach the
    proof, carrying the producer/consumer lead ids and the real in-workspace
    file:line source refs from the plan's composition requirement.  Plans that
    are non_runnable / needs_defense_traversal are left untouched, so the honest
    0 (empty links) is preserved - this never greens a chain that cannot run.

    Returns the number of plans that received a proof.
    """
    compose_chain = _load_compose_chain()
    if compose_chain is None:
        return 0
    attached = 0
    for plan in payload.get("plans") or []:
        if not isinstance(plan, dict):
            continue
        # Never overwrite an already-present executed proof (idempotent / honest).
        if _plan_has_executed_composition_proof(plan):
            continue
        requirement = _first_composition_requirement(plan)
        if not requirement:
            continue
        producer_lead_id = str(requirement.get("producer_lead_id") or "").strip()
        consumer_lead_id = str(requirement.get("consumer_lead_id") or "").strip()
        if (
            not producer_lead_id
            or not consumer_lead_id
            or producer_lead_id == consumer_lead_id
        ):
            continue
        from_refs = _uniq(
            _extract_file_line_refs(requirement.get("producer_source_refs") or [])
        )
        to_refs = _uniq(
            _extract_file_line_refs(requirement.get("consumer_source_refs") or [])
        )
        if not from_refs or not to_refs:
            continue
        if not _source_refs_exist_in_workspace(_uniq(from_refs + to_refs), workspace):
            continue
        try:
            verdict = (compose_chain(plan, workspace) or {}).get("verdict")
        except Exception:  # pragma: no cover - defensive; advisory tool
            verdict = None
        if verdict != "composition_runnable":
            continue
        plan["executed_composition_proof"] = {
            "status": "executed",
            "producer_lead_id": producer_lead_id,
            "consumer_lead_id": consumer_lead_id,
            "from_source_refs": from_refs,
            "to_source_refs": to_refs,
            "verdict": verdict,
            "proof_source": "chain-composition-harness.compose_chain",
        }
        attached += 1
    return attached


def _build_source_link_artifact(
    payload: dict[str, Any],
    workspace: Path,
    source_plan_artifact: str,
) -> dict[str, Any]:
    links = _source_link_rows_from_payload(payload, workspace=workspace)
    for row in links:
        row.setdefault("source_plan_artifact", source_plan_artifact)
    return {
        "schema": SOURCE_LINK_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(workspace),
        "source_plan_artifact": source_plan_artifact,
        "links": links,
    }


def _write_chain_synth_mirror(mirror_path: Path, payload: dict[str, Any]) -> bool:
    """Mirror the planner output to the canonical chain_synthesis_<date>.json
    path the audit-completeness chain-synth gate reads - WITHOUT clobbering a
    canonical chain-synth-driver report.

    The planner mirrors here to close a path-gap when IT is the chain-synthesis
    step. But chain-synth-driver.py writes the SAME filename with the
    authoritative `auditooor.chain_synthesis_report.v1` schema (carrying
    input_counts / status). When both run on one date they race on one filename;
    the planner's plans-schema mirror was silently overwriting the driver's
    input_counts-bearing report, making the chain-synth gate see a HOLLOW
    artifact (the hyperlane chain-synth false-fail). Rule: a canonical v1 report
    is authoritative and must win - never overwrite it. Returns True if written.
    """
    if mirror_path.exists():
        try:
            existing = json.loads(mirror_path.read_text(encoding="utf-8"))
        except Exception:
            existing = None
        if isinstance(existing, dict) and str(
            existing.get("schema", "")
        ).startswith("auditooor.chain_synthesis_report"):
            return False  # do not clobber the canonical chain-synth-driver report
    mirror_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return True


def run(argv: list[str] | None = None) -> dict[str, Any]:
    args = _parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"workspace not found: {workspace}")

    exploit_path = Path(args.exploit_json).expanduser().resolve() if args.exploit_json else workspace / ".auditooor" / "exploit_memory_brief.json"
    candidate_path = Path(args.brief_candidates).expanduser().resolve() if args.brief_candidates else workspace / "swarm" / "brief_candidates.json"
    swarm_manifest_path = Path(args.swarm_manifest).expanduser().resolve() if args.swarm_manifest else workspace / "swarm" / "manifest.json"
    big_loss_path = Path(args.big_loss_json).expanduser().resolve() if args.big_loss_json else None
    out_path = Path(args.out).expanduser().resolve() if args.out else workspace / "swarm" / "chained_attack_plans.json"
    markdown_out = Path(args.markdown_out).expanduser().resolve() if args.markdown_out else workspace / "swarm" / "chained_attack_plans.md"
    source_links_out = (
        Path(args.source_links_out).expanduser().resolve()
        if args.source_links_out
        else workspace / ".auditooor" / "chain_synth_source_links.json"
    )

    exploit_payload = _optional_json(exploit_path) if exploit_path.exists() else None
    candidate_payload = _optional_json(candidate_path) if candidate_path.exists() else None
    swarm_manifest = _optional_json(swarm_manifest_path) if swarm_manifest_path.exists() else None
    big_loss_payload, big_loss_mode = _load_big_loss_payload(workspace, big_loss_path)
    detector_clusters = _load_detector_clusters(workspace, args.engage_report)
    hacker_brief_primitives = _load_hacker_brief_primitives(workspace, args.hacker_brief_json)
    defihack_primitives = _load_defihack_primitives(workspace, args.defihack_report)
    source_artifact_primitives = _load_source_artifact_primitives(workspace)

    payload = _build_payload(
        workspace=workspace,
        exploit_payload=exploit_payload if isinstance(exploit_payload, dict) else None,
        exploit_path=exploit_path if exploit_path.exists() else None,
        candidate_payload=candidate_payload,
        candidate_path=candidate_path if candidate_path.exists() else None,
        swarm_manifest=swarm_manifest if isinstance(swarm_manifest, dict) else None,
        swarm_manifest_path=swarm_manifest_path if swarm_manifest_path.exists() else None,
        big_loss_payload=big_loss_payload if isinstance(big_loss_payload, dict) else None,
        big_loss_mode=big_loss_mode,
        detector_clusters=detector_clusters,
        hacker_brief_primitives=hacker_brief_primitives,
        defihack_primitives=defihack_primitives,
        source_artifact_primitives=source_artifact_primitives,
        max_plans=args.max_plans,
    )
    payload = _sanitize_output_value(payload, workspace)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.write_text(_render_markdown(payload), encoding="utf-8")

    # Mirror the output to the path that audit-completeness-check.py reads so
    # the chain-synth signal passes when this planner was the chain-synthesis
    # step for the workspace.  The gate globs .auditooor/chain_synthesis*.json
    # but chained-attack-planner historically wrote only to swarm/, causing the
    # gate to see no artifact even when plans were produced (path mismatch).
    # Writing a dated mirror here closes the gap without touching the gate.
    _date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _audit_dir = workspace / ".auditooor"
    _audit_dir.mkdir(parents=True, exist_ok=True)
    _mirror_path = _audit_dir / f"chain_synthesis_{_date_str}.json"
    _write_chain_synth_mirror(_mirror_path, payload)

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    if args.emit_chain_synth_source_links or args.source_links_out:
        # Pipeline stage: stamp an executed composition proof onto every plan
        # whose composition is runnable (D1 LIVE bridge + composed command +
        # survives defense-in-depth, per chain-composition-harness).  Without
        # this stage the planner only ever READS executed_composition_proof and
        # never writes one, so _source_link_rows_from_payload `continue`s on
        # every advisory plan and emits links=[].  Re-persist the plans + mirror
        # so the on-disk artifact stays consistent with the source-link rows.
        if _attach_runnable_composition_proofs(payload, workspace):
            out_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            _write_chain_synth_mirror(_mirror_path, payload)
        source_link_artifact = _build_source_link_artifact(
            payload,
            workspace,
            _source_plan_artifact_ref(out_path, workspace),
        )
        source_link_artifact = _sanitize_output_value(source_link_artifact, workspace)
        source_links_out.parent.mkdir(parents=True, exist_ok=True)
        source_links_out.write_text(
            json.dumps(source_link_artifact, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return payload


def main(argv: list[str] | None = None) -> int:
    run(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
