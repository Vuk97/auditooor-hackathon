#!/usr/bin/env python3
"""Emit derived proof-hardening rows for Hackerman corpus records.

The sidecar is intentionally advisory and conservative. Hackerman records are
recall evidence, not submission proof. This tool turns the codified L29/R30
discipline into machine-readable claim boundaries so briefs and rankers can
avoid promoting weak precedent or synthetic corpus rows into High/Critical
claims before the required proof exists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hackerman_query_common import DEFAULT_TAGS_DIR, safe_proof_artifact_path, yaml_load, utc_now


SCHEMA = "auditooor.hackerman_proof_hardening.v1"
MANIFEST_SCHEMA = "auditooor.hackerman_proof_hardening.manifest.v1"
RECORD_SCHEMAS = {"auditooor.hackerman_record.v1", "auditooor.hackerman_record.v1.1"}
DEFAULT_OUT = Path("audit") / "corpus_tags" / "derived" / "proof_hardening.jsonl"
DEFAULT_SHARD_TARGET_BYTES = 8 * 1024 * 1024  # 8 MiB per shard


def _manifest_path_ph(out_path: Path) -> Path:
    return out_path.with_name(f"{out_path.stem}.manifest.json")


def _shard_dir_ph(out_path: Path) -> Path:
    return out_path.with_name(f"{out_path.stem}.d")


def _sha256_file_ph(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_sharded_sidecar_ph(
    tag_dir: Path,
    out_path: Path,
    *,
    limit: int | None = None,
    shard_target_bytes: int = DEFAULT_SHARD_TARGET_BYTES,
) -> dict[str, Any]:
    """Build the proof_hardening sidecar in the sharded layout.

    Writes ``<stem>.manifest.json`` and ``<stem>.d/shard-NNNNN.jsonl`` shards.
    No individual shard file exceeds ``shard_target_bytes``.
    Consumers call ``read_jsonl`` (hackerman_query_common) which auto-detects
    the manifest and streams shards transparently.
    """
    rows = build_rows(tag_dir, limit)
    manifest_path = _manifest_path_ph(out_path)
    shard_dir = _shard_dir_ph(out_path)
    tmp_dir = shard_dir.with_name(f".{shard_dir.name}.{os.getpid()}.tmp")
    if tmp_dir.exists():
        for old in tmp_dir.glob("*"):
            old.unlink()
        tmp_dir.rmdir()
    tmp_dir.mkdir(parents=True, exist_ok=True)

    shard_target_bytes = max(1024, int(shard_target_bytes))
    shards: list[dict[str, Any]] = []
    current_fh = None
    current_path: Path | None = None
    current_records = 0
    current_bytes = 0
    first_record_id = ""
    last_record_id = ""

    def close_current() -> None:
        nonlocal current_fh, current_path, current_records, current_bytes
        nonlocal first_record_id, last_record_id
        if current_fh is None or current_path is None:
            return
        current_fh.close()
        shards.append(
            {
                "path": current_path.name,
                "records_emitted": current_records,
                "size_bytes": current_path.stat().st_size,
                "sha256": _sha256_file_ph(current_path),
                "first_record_id": first_record_id,
                "last_record_id": last_record_id,
            }
        )
        current_fh = None
        current_path = None
        current_records = 0
        current_bytes = 0
        first_record_id = ""
        last_record_id = ""

    try:
        for row in rows:
            line = json.dumps(row, sort_keys=True) + "\n"
            encoded_len = len(line.encode("utf-8"))
            if current_fh is None or (
                current_records > 0 and current_bytes + encoded_len > shard_target_bytes
            ):
                close_current()
                current_path = tmp_dir / f"shard-{len(shards):05d}.jsonl"
                current_fh = current_path.open("w", encoding="utf-8")
            rid = str(row.get("record_id") or "")
            if not first_record_id:
                first_record_id = rid
            last_record_id = rid
            current_fh.write(line)
            current_records += 1
            current_bytes += encoded_len
        close_current()

        total_shard_bytes = sum(int(s["size_bytes"]) for s in shards)
        manifest: dict[str, Any] = {
            "schema_version": MANIFEST_SCHEMA,
            "sidecar_schema": SCHEMA,
            "sidecar_layout": "sharded-jsonl",
            "sidecar_path": str(out_path),
            "manifest_path": str(manifest_path),
            "shard_dir": shard_dir.name,
            "shard_count": len(shards),
            "shard_target_bytes": shard_target_bytes,
            "shard_total_size_bytes": total_shard_bytes,
            "records_emitted": sum(s["records_emitted"] for s in shards),
            "generated_at_utc": utc_now(),
            "shards": shards,
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_manifest = manifest_path.with_name(f".{manifest_path.name}.{os.getpid()}.tmp")
        tmp_manifest.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")

        if shard_dir.exists():
            for old in shard_dir.glob("*.jsonl"):
                old.unlink()
        else:
            shard_dir.mkdir(parents=True, exist_ok=True)
        for shard in shards:
            (tmp_dir / shard["path"]).replace(shard_dir / shard["path"])
        tmp_dir.rmdir()
        tmp_manifest.replace(manifest_path)
        # Truncate monolith to 0-byte stub so the committed file is within budget.
        out_path.write_bytes(b"")
        return manifest
    except Exception:
        if current_fh is not None:
            current_fh.close()
        for old in tmp_dir.glob("*"):
            old.unlink()
        if tmp_dir.exists():
            tmp_dir.rmdir()
        raise
REPORTABLE_SEVERITIES = {"critical", "high"}

PRODUCTION_PROFILE_RE = re.compile(
    r"\b(db|database|storage|iavl|nodedb|rootmulti|goleveldb|pebbledb|rocksdb|"
    r"memdb|commit|finalizeblock|baseapp|cometbft|validator|"
    r"consensus|apphash|state-sync|matching-engine|batch\.write|"
    r"latency|race window|timing|disk)\b",
    re.IGNORECASE,
)
PERSISTENCE_RE = re.compile(
    r"\b(permanent|persistent|restart|halt|chain halt|validator halt|"
    r"block production|apphash|requires hardfork|governance intervention|"
    r"unrecoverable|freeze|freezing)\b",
    re.IGNORECASE,
)
CROSS_BOUNDARY_RE = re.compile(
    r"\b(l1|bitcoin|bridge|oracle|rpc|multi-process|multi-validator|gossip|"
    r"settlement|cross-chain|external trust boundary|chain watcher|watcher)\b",
    re.IGNORECASE,
)
SYNTHETIC_RE = re.compile(r"\b(dsl[_-]?pattern|canonical-dsl|patterns\.dsl|synthetic)\b", re.IGNORECASE)
SUBMISSION_RE = re.compile(r"\b(paste_ready|filed|cantina-|immunefi|submission)\b", re.IGNORECASE)
SKELETON_SIGNATURE_RE = re.compile(r"^function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s+internal\s+returns\s+\(bool\)$")
FUNCTION_NAME_HINT_RE = re.compile(r"^function-name-hint:\s*[A-Za-z_][A-Za-z0-9_]*$", re.IGNORECASE)


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def _is_hackerman_record(doc: Any) -> bool:
    return isinstance(doc, dict) and doc.get("schema_version") in RECORD_SCHEMAS


def iter_records(tag_dir: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    for path in sorted(tag_dir.glob("*.yaml")):
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _is_hackerman_record(doc):
            yield path, doc


def _record_text(record: dict[str, Any], tag_path: Path | None = None) -> str:
    function_shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    preconditions = record.get("required_preconditions") if isinstance(record.get("required_preconditions"), list) else []
    parts = [
        _as_text(record.get("record_id")),
        _as_text(record.get("source_audit_ref")),
        _as_text(record.get("target_domain")),
        _as_text(record.get("target_language")),
        _as_text(record.get("target_repo")),
        _as_text(record.get("target_component")),
        _as_text(function_shape.get("raw_signature")),
        _as_text(record.get("bug_class")),
        _as_text(record.get("attack_class")),
        _as_text(record.get("attacker_action_sequence")),
        " ".join(_as_text(item) for item in preconditions),
        _as_text(record.get("impact_class")),
        _as_text(record.get("impact_actor")),
        _as_text(record.get("fix_pattern")),
        _as_text(record.get("notes")),
        _as_text(tag_path),
    ]
    return " ".join(part for part in parts if part)


def _source_ref(tag_path: Path | None) -> str:
    if tag_path is None:
        return ""
    resolved = tag_path.resolve()
    for root in (Path.cwd().resolve(), Path(__file__).resolve().parent.parent):
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError:
            continue
    return tag_path.as_posix()


def _evidence_class(record: dict[str, Any], text: str) -> tuple[str, int, list[str]]:
    verdict_class = _as_text(record.get("verdict_class")).upper()
    source_ref = _as_text(record.get("source_audit_ref"))
    flags: list[str] = []

    if verdict_class == "CANDIDATE" or SYNTHETIC_RE.search(text):
        return "synthetic_candidate_not_audit_verified", 1, ["synthetic candidate, not audit-verified"]
    if SUBMISSION_RE.search(text) or verdict_class in {"CONFIRMED", "FILED", "ACCEPTED", "AMENDED"}:
        return "submission_or_filed_precedent", 4, []
    if source_ref.startswith("prior-audit"):
        return "prior_audit_precedent", 3, []
    if source_ref.startswith("solodit-spec"):
        flags.append("public corpus summary, not local exploit proof")
        return "public_corpus_precedent", 2, flags
    if source_ref.startswith("corpus-mined") or source_ref.startswith("git-mining"):
        flags.append("mined corpus signal, not local exploit proof")
        return "mined_corpus_signal", 2, flags
    return "unknown_proof_posture", 2, ["proof posture unknown"]


def _production_profile_trigger(record: dict[str, Any], text: str) -> bool:
    language = _as_text(record.get("target_language")).lower()
    domain = _as_text(record.get("target_domain")).lower()
    repo = _as_text(record.get("target_repo")).lower()
    production_repo = any(part in repo for part in ("dydx", "cosmos/iavl", "cosmos-sdk", "cometbft"))
    if language == "go" and (domain in {"consensus", "rpc-infra", "l1-client", "dex"} or production_repo):
        return bool(PRODUCTION_PROFILE_RE.search(text))
    return bool(PRODUCTION_PROFILE_RE.search(text) and _contains_any(text, ("validator", "consensus", "apphash", "chain halt", "finalizeblock")))


def infer_record_hardening(record: dict[str, Any], tag_path: Path | None = None) -> dict[str, Any]:
    record_id = _as_text(record.get("record_id"))
    source_ref = _as_text(record.get("source_audit_ref"))
    text = _record_text(record, tag_path)
    severity = _as_text(record.get("severity_at_finding")).lower()
    evidence_class, maturity, risk_flags = _evidence_class(record, text)
    proof_artifact = safe_proof_artifact_path(record.get("proof_artifact_path") or record.get("poc_path"))
    if proof_artifact and evidence_class != "synthetic_candidate_not_audit_verified":
        maturity = min(5, maturity + 1)
    function_shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    raw_signature = _as_text(function_shape.get("raw_signature"))
    if SKELETON_SIGNATURE_RE.match(raw_signature):
        function_shape_confidence = "skeleton_signature"
    elif FUNCTION_NAME_HINT_RE.match(raw_signature):
        function_shape_confidence = "function_name_hint"
    else:
        function_shape_confidence = "corpus_extracted"

    triggered_gates: list[str] = ["L29-FILING"]
    required_before_high_critical = [
        "rubric verbatim match for the selected impact",
        "title and selected impact must be subsets of runnable PoC proven_impacts",
        "every proven impact needs a PoC path plus PASS transcript lines",
        "known not_proven_impacts must not appear in title or selected impact",
    ]
    claim_boundary = "recall_precedent_only"
    promotion_blockers: list[str] = []
    production_profile_required = False

    if evidence_class != "submission_or_filed_precedent":
        promotion_blockers.append("record is precedent/recall evidence only; build local PoC before filing")
    if evidence_class == "synthetic_candidate_not_audit_verified":
        claim_boundary = "shape_only_not_submit_ready"
        promotion_blockers.append("synthetic candidate cannot support severity by itself")
    if severity in REPORTABLE_SEVERITIES and evidence_class in {
        "public_corpus_precedent",
        "mined_corpus_signal",
        "unknown_proof_posture",
    }:
        promotion_blockers.append("High/Critical source row lacks local proof posture")
    if function_shape_confidence == "skeleton_signature" and source_ref.startswith("solodit-spec"):
        promotion_blockers.append("detector skeleton function signature; verify the real callsite before shape-based matching")
    if function_shape_confidence == "function_name_hint" and source_ref.startswith("solodit-spec"):
        promotion_blockers.append("detector inferred function-name hint; verify the real signature/callsite before shape-based matching")

    if _production_profile_trigger(record, text):
        production_profile_required = True
        triggered_gates.extend(["R18", "R19", "R20", "R22", "R30"])
        required_before_high_critical.extend(
            [
                "real production-path entry such as FinalizeBlock/Commit/app.RunTx, not only a helper call",
                "real persistent backend such as goleveldb/pebbledb/rocksdb, not MemDB",
                "no DB timing/fault shim and no reflection/unsafe private-state mutation",
                "restart behavior transcript: survives restart or honestly walks back persistence",
                "multi-validator proof for network-level liveness/AppHash/chain-halt claims",
                "bug-class-shift disclosure if production-profile failure mode differs from the first harness",
            ]
        )
        promotion_blockers.append("production-profile proof required before High/Critical promotion")

    if PERSISTENCE_RE.search(text):
        if "R22" not in triggered_gates:
            triggered_gates.append("R22")
        required_before_high_critical.append("restart-survival evidence or restart-heals severity walk-back")

    if CROSS_BOUNDARY_RE.search(text):
        triggered_gates.append("L29-DISC-6")
        required_before_high_critical.append(
            "end-to-end proof across the external boundary, or explicit Source-Only Justification citing background protocol behavior"
        )

    triggered_gates = list(dict.fromkeys(triggered_gates))
    required_before_high_critical = list(dict.fromkeys(required_before_high_critical))
    promotion_blockers = list(dict.fromkeys([*risk_flags, *promotion_blockers]))
    maturity = max(1, min(5, maturity - (1 if promotion_blockers and maturity > 1 else 0)))

    if _production_profile_trigger(record, text) and evidence_class == "submission_or_filed_precedent":
        claim_boundary = "precedent_requires_reproduction_under_target_production_profile"

    gate_statuses = [
        {
            "gate": gate,
            "status": "required_before_promotion",
            "evidence_refs": [proof_artifact] if proof_artifact else [],
            "blockers": promotion_blockers[:3],
            "rebuttal_allowed": gate in {"R30"},
        }
        for gate in triggered_gates
    ]

    return {
        "schema": SCHEMA,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "result_class": "discovery_analogy",
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "evidence_class": evidence_class,
        "severity_ceiling": "none_without_local_target_proof",
        "rubric_match_status": "unverified_for_current_target",
        "listed_impact_proven": False,
        "function_shape_confidence": function_shape_confidence,
        "proof_maturity_score": maturity,
        "claim_boundary": claim_boundary,
        "triggered_gates": triggered_gates,
        "gate_statuses": gate_statuses,
        "required_before_high_critical": required_before_high_critical,
        "promotion_blockers": promotion_blockers,
        "production_profile_required": production_profile_required,
        "production_profile_constraints": {
            "persistent_backend": production_profile_required,
            "no_fault_shim": production_profile_required,
            "no_reflection_write": production_profile_required,
            "multi_validator": production_profile_required,
            "hardware_envelope": production_profile_required,
            "bug_class_shift_disclosure": production_profile_required,
        },
        "proof_artifacts": [proof_artifact] if proof_artifact else [],
        "source_ref": _source_ref(tag_path),
    }


def build_rows(tag_dir: Path, limit: int | None = None) -> list[dict[str, Any]]:
    rows = [infer_record_hardening(record, path) for path, record in iter_records(tag_dir)]
    rows.sort(key=lambda row: (int(row["proof_maturity_score"]), row["record_id"]))
    if limit is not None:
        rows = rows[: max(0, limit)]
    return rows


def write_jsonl(rows: Iterable[dict[str, Any]], out_path: Path | None) -> int:
    lines = [json.dumps(row, sort_keys=True) for row in rows]
    payload = "\n".join(lines) + ("\n" if lines else "")
    if out_path is None:
        sys.stdout.write(payload)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload, encoding="utf-8")
    return len(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output JSONL path. Use '-' for stdout.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--json-summary", action="store_true")
    parser.add_argument(
        "--shard-target-mb",
        type=float,
        default=None,
        help="Emit sharded layout with this target MiB per shard (default: 8). "
             "Writes <stem>.manifest.json + <stem>.d/shard-*.jsonl and truncates the monolith.",
    )
    args = parser.parse_args(argv)

    tag_dir = Path(args.tag_dir)
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2

    # Sharded emit path (J3e pattern).
    if args.shard_target_mb is not None and args.out != "-":
        out_path = Path(args.out)
        shard_target_bytes = int(float(args.shard_target_mb) * 1024 * 1024)
        manifest = build_sharded_sidecar_ph(tag_dir, out_path, limit=args.limit, shard_target_bytes=shard_target_bytes)
        print(json.dumps({"schema": MANIFEST_SCHEMA, "shard_count": manifest["shard_count"],
                          "records_emitted": manifest["records_emitted"],
                          "shard_total_size_bytes": manifest["shard_total_size_bytes"],
                          "shard_dir": manifest["shard_dir"]}, sort_keys=True))
        return 0

    out_path = None if args.out == "-" else Path(args.out)
    rows = build_rows(tag_dir, args.limit)
    written = write_jsonl(rows, out_path)
    if args.json_summary:
        print(json.dumps({"schema": SCHEMA, "records_scored": len(rows), "rows_written": written, "out": args.out}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
