#!/usr/bin/env python3
"""HACKERMAN_V3 Lane D1 - source-evidence chain bridge.

After ``exploit-queue-source-miner.py`` writes one ``*.source_artifact.json``
sidecar per exploit-queue row, this tool pairs source-mined hits by *semantic
state* rather than keyword overlap:

    hit A confirms it PRODUCES state token X (anchored to a source ref), and
    hit B confirms it REQUIRES state token X (anchored to a source ref)
    => the two hits compose, so a deterministic ``LIVE-<id>`` bridge row is
       written into BOTH artifacts' ``state_evidence.bridge_claims``.

``chained-attack-planner._has_distinct_causal_bridge_signal()`` already looks
for those ``LIVE-`` rows in ``paired_live_rows`` / ``causal_bridge_signals`` and
never finds them today, so every chain stays
``causal_evidence_level: metadata_overlap_only_unproven``. Populating the bridge
rows promotes a chain to ``distinct_bridge_signal_present`` - a real,
source-anchored causal bridge instead of token co-occurrence.

This tool only READS source artifacts and chain plans and WRITES bridge rows
back into the source artifacts. It does not rewrite the planner; the planner
already consumes ``state_evidence.bridge_claims`` via
``_normalize_source_artifact_state_evidence``.

A bridge is only emitted when BOTH sides of the pair carry a real source anchor
(``source_refs`` with ``path`` + ``line_start`` + ``excerpt``). Metadata-only
artifacts with no anchored produces/requires state are left untouched, so
metadata-only chains correctly stay ``metadata_overlap_only_unproven``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.source_evidence_chain_bridge.v1"
ARTIFACT_SCHEMA = "auditooor.exploit_queue_source_artifact.v1"
# The closed 11-token state vocabulary lives in hackerman-chain-unify. Bridge
# tokens are NOT restricted to it (source-mined produces/requires state may use
# concrete protocol nouns like ``vault_locked_balance``); the vocabulary is
# recorded for provenance only.
BRIDGE_CONFIDENCE = "source_cited_unexecuted"


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _as_text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_as_text(item) for item in value if _as_text(item)]


def _state_token_key(token: str) -> str:
    return " ".join(str(token or "").strip().lower().split())


def _live_bridge_id(token: str) -> str:
    """Deterministic LIVE-<id> for a state token.

    Mirrors exploit-queue-source-miner._live_bridge_id so a bridge minted here
    is byte-identical to one the source miner would mint for the same token.
    """
    key = _state_token_key(token)
    digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:12].upper()
    return "LIVE-" + digest


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _source_artifact_paths(workspace: Path, explicit: list[str]) -> list[Path]:
    if explicit:
        return [Path(item).expanduser().resolve() for item in explicit]
    artifact_dir = workspace / ".auditooor" / "source_artifacts"
    if not artifact_dir.is_dir():
        return []
    return sorted(artifact_dir.glob("*.source_artifact.json"))


def _has_source_anchor(artifact: dict[str, Any]) -> bool:
    """True when the artifact carries at least one exact line-cited source ref.

    A bridge is a *source-evidence* bridge - it must be anchored to real code,
    not inferred from prose. An artifact with no anchor is metadata-only and is
    skipped, so metadata-only chains stay unproven.
    """
    for ref in artifact.get("source_refs") or []:
        if not isinstance(ref, dict):
            continue
        path = _as_text(ref.get("path"))
        excerpt = _as_text(ref.get("excerpt"))
        try:
            line = int(ref.get("line_start") or 0)
        except (TypeError, ValueError):
            line = 0
        if path and line > 0 and excerpt:
            return True
    return False


def _state_evidence(artifact: dict[str, Any]) -> dict[str, Any]:
    ev = artifact.get("state_evidence")
    return ev if isinstance(ev, dict) else {}


def _confirmed_produces(artifact: dict[str, Any]) -> list[str]:
    """Produced-state tokens this hit's source mining CONFIRMED.

    Only counts when the artifact carries an exact source anchor; an
    unanchored produces_state list is treated as metadata, not confirmation.
    """
    if not _has_source_anchor(artifact):
        return []
    return _as_text_list(_state_evidence(artifact).get("produces_state"))


def _confirmed_requires(artifact: dict[str, Any]) -> list[str]:
    """Required-state tokens this hit's source mining CONFIRMED."""
    if not _has_source_anchor(artifact):
        return []
    return _as_text_list(_state_evidence(artifact).get("requires_state"))


def _lead_id(artifact: dict[str, Any], path: Path) -> str:
    ev = _state_evidence(artifact)
    return _as_text(ev.get("lead_id")) or _as_text(artifact.get("lead_id")) or path.stem


def _existing_bridge_keys(artifact: dict[str, Any]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for claim in _state_evidence(artifact).get("bridge_claims") or []:
        if not isinstance(claim, dict):
            continue
        bridge_id = _as_text(claim.get("bridge_id"))
        token_key = _state_token_key(_as_text(claim.get("token")))
        if bridge_id and token_key:
            keys.add((bridge_id, token_key))
    return keys


def _ensure_state_evidence(artifact: dict[str, Any], lead_id: str, role_hint: str) -> dict[str, Any]:
    ev = artifact.get("state_evidence")
    if not isinstance(ev, dict):
        ev = {
            "lead_id": lead_id,
            "role": role_hint,
            "produces_state": [],
            "requires_state": [],
            "bridge_claims": [],
        }
        artifact["state_evidence"] = ev
    ev.setdefault("lead_id", lead_id)
    ev.setdefault("role", role_hint)
    ev.setdefault("produces_state", [])
    ev.setdefault("requires_state", [])
    if not isinstance(ev.get("bridge_claims"), list):
        ev["bridge_claims"] = []
    return ev


def _claim_source_refs(artifact: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for ref in artifact.get("source_refs") or []:
        if isinstance(ref, dict):
            path = _as_text(ref.get("path"))
            line = _as_text(ref.get("line_start"))
            if path and line:
                refs.append(f"{path}:{line}")
            elif path:
                refs.append(path)
        elif _as_text(ref):
            refs.append(_as_text(ref))
    return refs


def build_bridge_rows(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Pair source-mined hits and mint LIVE-<id> bridge rows.

    ``artifacts`` is a list of ``{"path": Path, "artifact": dict}``. Returns a
    summary plus the mutated artifact dicts (callers decide whether to persist).
    """
    bridges: list[dict[str, Any]] = []
    mutated: set[str] = set()

    for producer in artifacts:
        prod_artifact = producer["artifact"]
        prod_path = producer["path"]
        prod_lead = _lead_id(prod_artifact, prod_path)
        produces = _confirmed_produces(prod_artifact)
        if not produces:
            continue
        for consumer in artifacts:
            if consumer is producer:
                continue
            cons_artifact = consumer["artifact"]
            cons_path = consumer["path"]
            cons_lead = _lead_id(cons_artifact, cons_path)
            requires = _confirmed_requires(cons_artifact)
            if not requires:
                continue
            produces_keys = {_state_token_key(item): item for item in produces}
            requires_keys = {_state_token_key(item): item for item in requires}
            shared = sorted(set(produces_keys) & set(requires_keys))
            for token_key in shared:
                token = produces_keys[token_key]
                bridge_id = _live_bridge_id(token)
                claim = {
                    "bridge_id": bridge_id,
                    "token": token,
                    "producer_lead_id": prod_lead,
                    "consumer_lead_id": cons_lead,
                    "source_refs": _claim_source_refs(prod_artifact) + _claim_source_refs(cons_artifact),
                    "causal_bridge_signal": bridge_id,
                    "confidence": BRIDGE_CONFIDENCE,
                }
                # Write the identical claim into BOTH artifacts. The planner's
                # pairwise overlap only fires when the SAME LIVE-<id> appears on
                # both sides (set intersection of paired_live_row_ids).
                for side_artifact, side_path, role_hint in (
                    (prod_artifact, prod_path, "producer"),
                    (cons_artifact, cons_path, "consumer"),
                ):
                    side_lead = _lead_id(side_artifact, side_path)
                    ev = _ensure_state_evidence(side_artifact, side_lead, role_hint)
                    if (bridge_id, token_key) in _existing_bridge_keys(side_artifact):
                        continue
                    ev["bridge_claims"].append(dict(claim))
                    side_artifact.setdefault("schema", ARTIFACT_SCHEMA)
                    mutated.add(str(side_path))
                bridges.append(
                    {
                        "bridge_id": bridge_id,
                        "token": token,
                        "producer_lead_id": prod_lead,
                        "consumer_lead_id": cons_lead,
                        "producer_artifact": str(prod_path),
                        "consumer_artifact": str(cons_path),
                        "causal_bridge_signal": bridge_id,
                        "confidence": BRIDGE_CONFIDENCE,
                    }
                )

    # De-dup bridge summary rows (a token can pair in both directions).
    seen: set[tuple[str, str, str]] = set()
    unique_bridges: list[dict[str, Any]] = []
    for row in bridges:
        key = (row["bridge_id"], row["producer_lead_id"], row["consumer_lead_id"])
        if key in seen:
            continue
        seen.add(key)
        unique_bridges.append(row)
    unique_bridges.sort(key=lambda r: (r["bridge_id"], r["producer_lead_id"], r["consumer_lead_id"]))

    return {
        "schema": SCHEMA,
        "source_artifacts_scanned": len(artifacts),
        "source_artifacts_mutated": len(mutated),
        "bridge_rows_emitted": len(unique_bridges),
        "metadata_overlap_only_unproven_promoted": bool(unique_bridges),
        "bridges": unique_bridges,
        "mutated_paths": sorted(mutated),
    }


def run(argv: list[str] | None = None) -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace root")
    parser.add_argument(
        "--source-artifact",
        action="append",
        default=[],
        help="Explicit *.source_artifact.json path; may be repeated. "
        "Defaults to <ws>/.auditooor/source_artifacts/*.source_artifact.json",
    )
    parser.add_argument("--out", default=None, help="Write the bridge summary JSON to this path")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute bridge rows but do not write them back into source artifacts",
    )
    parser.add_argument("--print-json", action="store_true", help="Print the summary JSON to stdout")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    paths = _source_artifact_paths(workspace, args.source_artifact)

    artifacts: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for path in paths:
        try:
            payload = _load_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            skipped.append({"path": str(path), "reason": f"unreadable: {exc}"})
            continue
        if not isinstance(payload, dict):
            skipped.append({"path": str(path), "reason": "not a JSON object"})
            continue
        artifacts.append({"path": path, "artifact": payload})

    summary = build_bridge_rows(artifacts)
    summary["workspace_path"] = str(workspace)
    summary["skipped"] = skipped

    if not args.dry_run:
        for item in artifacts:
            if str(item["path"]) in set(summary["mutated_paths"]):
                _write_json(item["path"], item["artifact"])

    if args.out:
        _write_json(Path(args.out).expanduser().resolve(), summary)
    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def main(argv: list[str] | None = None) -> int:
    run(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
