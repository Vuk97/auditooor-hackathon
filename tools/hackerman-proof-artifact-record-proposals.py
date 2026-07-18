#!/usr/bin/env python3
"""Create submission-derived Hackerman records from proof review packets.

This consumes ``auditooor.hackerman_missing_record_review_packet.v1`` rows
emitted by ``hackerman-proof-artifact-import-queue.py``. It is deliberately
conservative: only packets with ``ready_for_manual_record_creation`` are
eligible, generated records are marked ``submission-derived`` /
``verdict_artefact: true``, and the original packet metadata is preserved in
``record_extensions`` for later human review.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PACKET_SCHEMA = "auditooor.hackerman_missing_record_review_packet.v1"
RECORD_SCHEMA = "auditooor.hackerman_record.v1.1"
SUMMARY_SCHEMA = "auditooor.hackerman_proof_artifact_record_proposals.v1"
DEFAULT_PACKETS = Path("reports") / "proof_artifact_missing_record_review_packets_slice12.jsonl"
DEFAULT_OUT_DIR = Path("audit") / "corpus_tags" / "tags"
ELIGIBLE_SUBMISSION_STATUSES = {"", "filed", "paste_ready", "ready", "submitted"}
SAFE_PROOF_PATH_RE = re.compile(
    r"^(?![A-Za-z][A-Za-z0-9+.-]*://)(?!/)(?!\.\.?/)(?![A-Za-z]:[\\/])"
    r"(?!\\\\)(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$"
)


def _slug(text: str, *, max_len: int = 70) -> str:
    raw = re.sub(r"[^A-Za-z0-9._-]+", "-", text.lower()).strip("-._")
    raw = re.sub(r"-{2,}", "-", raw)
    return (raw[:max_len].strip("-._") or "record")


def _is_safe_proof_path(path: str) -> bool:
    if not SAFE_PROOF_PATH_RE.match(path):
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def _first_proof_path(packet: dict[str, Any]) -> str:
    for candidate in packet.get("artifact_candidates") or []:
        if not isinstance(candidate, dict):
            continue
        path = str(candidate.get("candidate_proof_path") or "").strip()
        if path and _is_safe_proof_path(path):
            return path
    return ""


def _all_proof_paths(packet: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for candidate in packet.get("artifact_candidates") or []:
        if not isinstance(candidate, dict):
            continue
        path = str(candidate.get("candidate_proof_path") or "").strip()
        if path and _is_safe_proof_path(path):
            paths.append(path)
    return paths


def _raw_proof_paths(packet: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for candidate in packet.get("artifact_candidates") or []:
        if not isinstance(candidate, dict):
            continue
        path = str(candidate.get("candidate_proof_path") or "").strip()
        if path:
            paths.append(path)
    return paths


def _severity(packet: dict[str, Any]) -> str:
    haystack = " ".join(
        str(packet.get(key) or "")
        for key in ("submission_path", "submission_title", "queue_key")
    ).lower()
    for value in ("critical", "high", "medium", "low", "info"):
        if value in haystack:
            return value
    return "medium"


def _dollar_class(severity: str, title: str) -> str:
    low_title = title.lower()
    if "panic" in low_title or "misleading api" in low_title:
        return "non-financial"
    if severity == "critical":
        return ">=$1M"
    if severity == "high":
        return "$100K-$1M"
    if severity == "medium":
        return "$10K-$100K"
    return "<$10K"


def _target_language(packet: dict[str, Any]) -> str:
    title = str(packet.get("submission_title") or "").lower()
    paths = " ".join(_all_proof_paths(packet)).lower()
    engagement = str(packet.get("engagement") or "").lower()
    if engagement == "dydx" and (".go" in paths or "cosmos-sdk" in title or "accountplus" in title or "megavault" in title):
        return "go"
    if engagement == "mezo" and ("validator-kit" in title or ".go" in paths):
        return "go"
    if ".rs" in paths or "zkvm" in title:
        return "rust"
    if ".mjs" in paths or ".js" in paths:
        return "typescript-onchain"
    if ".ts" in paths or ".sol" in paths or engagement in {"mezo", "thegraph", "base-azul"}:
        return "solidity"
    return "solidity"


_GITHUB_REPO_RE = __import__("re").compile(r"github\.com[/:]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?]|$)")


def _extract_github_repo(packet: dict[str, Any]) -> str:
    """Generic owner/repo extraction from any github URL in the packet (proof
    paths, source_refs, repo fields, free text). Workspace-agnostic."""
    import json as _json
    blob = _json.dumps(packet, default=str)
    m = _GITHUB_REPO_RE.search(blob)
    return m.group(1) if m else ""


def _target_repo(packet: dict[str, Any], language: str) -> str:
    # (1) explicit field wins - generic, works for ANY engagement.
    for k in ("target_repo", "repo", "repository"):
        v = packet.get(k)
        if isinstance(v, str) and "/" in v and v.lower() not in ("", "unknown", "n/a"):
            return v.strip()
    title = str(packet.get("submission_title") or "").lower()
    engagement = str(packet.get("engagement") or "").lower()
    # (2) known per-engagement fast-paths (title-disambiguated multi-repo programs).
    if engagement == "dydx":
        if "indexer" in title or "comlink" in title:
            return "dydxprotocol/indexer"
        return "dydxprotocol/v4-chain"
    if engagement == "mezo":
        if "validator-kit" in title:
            return "mezo-org/validator-kit"
        if "musd" in title or language == "solidity":
            return "mezo-org/musd"
    if engagement == "thegraph":
        return "graphprotocol/contracts"
    # (3) GENERIC derivation: a github URL anywhere in the packet (the fix for
    # every non-fast-path engagement collapsing to 'unknown' and corrupting
    # repo-keyed corpus dedup/relevance - spark/ssv/polygon/optimism/near/...).
    repo = _extract_github_repo(packet)
    if repo:
        return repo
    # (4) last resort: 'unknown' (the validator-accepted sentinel - a bare
    # engagement label is not an owner/repo and fails record validation). The
    # generic wins are (1) explicit field + (3) github-URL extraction, which
    # cover the real packets; only a packet with neither lands here.
    return "unknown"


def _target_domain(title: str) -> str:
    low = title.lower()
    if any(term in low for term in ("zk", "proof", "verifier", "journal")):
        return "zk-proof"
    if any(term in low for term in ("p256verify", "precompile", "zkvm")):
        return "l1-client"
    if any(term in low for term in ("bridge", "bitcoin withdrawal", "btc")):
        return "bridge"
    if any(term in low for term in ("oracle", "pricefeed")):
        return "oracle"
    if any(term in low for term in ("megavault", "vault")):
        return "vault"
    if any(term in low for term in ("borroweroperations", "trovemanager", "stabilitypool", "refinance")):
        return "lending"
    if any(term in low for term in ("validator-kit", "json-rpc", "keyring")):
        return "rpc-infra"
    if any(term in low for term in ("gov", "proposals query")):
        return "governance"
    if any(term in low for term in ("comlink", "indexer", "feegrant", "accountplus", "subaccount")):
        return "dex"
    if any(term in low for term in ("l2gns", "curated", "grt")):
        return "staking"
    return "dex"


def _bug_attack_class(title: str) -> tuple[str, str]:
    low = title.lower()
    if any(term in low for term in ("rounding", "precision")):
        return "rounding-error", "precision-loss-drain"
    if "access control" in low or "public json-rpc" in low:
        return "missing-access-control", "unauthorized-signing-surface"
    if "keyring-password" in low or "disclosure" in low:
        return "secret-disclosure", "local-secret-exfiltration"
    if "timelock" in low or "typehash" in low:
        return "signature-domain-gap", "signed-message-parameter-grief"
    if "subaccountfilter" in low or "validation gap" in low or "validation bypass" in low:
        return "validation-bypass", "permission-scope-bypass"
    if "missing realized-pnl" in low or "missing" in low and "helper" in low:
        return "missing-state-update", "accounting-observation-gap"
    if "feegrant" in low:
        return "state-corruption", "authorization-state-destruction"
    if "nil-pointer" in low or "panic" in low:
        return "panic-on-malformed-input", "query-handler-panic"
    if "negative" in low or "accounting" in low:
        return "accounting-invariant-break", "vault-accounting-drain"
    if "sub-dust" in low or "stuck" in low:
        return "dust-threshold-mismatch", "bridge-withdrawal-freeze"
    if "oracle staleness" in low or "hard-revert" in low:
        return "oracle-liveness-hard-revert", "protocol-operation-freeze"
    if "gas-pricing" in low or "precompile" in low:
        return "execution-environment-divergence", "precompile-pricing-divergence"
    if "journal" in low or "chain_id" in low:
        return "domain-separation-missing", "cross-deployment-proof-replay"
    if "nullification" in low or "nullified" in low or "nullify" in low:
        return "shared-verifier-state-corruption", "global-finalization-freeze"
    if "unflag race" in low or ("resolvequestion" in low and "emergencyresolvequestion" in low):
        return "race-condition", "transaction-ordering-state-preemption"
    if "lacks recovery" in low or "mistransfer" in low:
        return "missing-recovery-function", "permanent-asset-lock"
    return "logic-bug", "state-machine-invariant-break"


def _impact(title: str, severity: str) -> tuple[str, str]:
    low = title.lower()
    if any(term in low for term in ("theft", "drain", "fund movement", "overcharge")):
        if any(term in low for term in ("lp", "stabilitypool", "vault")):
            return "theft", "depositor-class"
        return "theft", "specific-user"
    if any(term in low for term in ("stuck", "freeze", "disables", "hard-revert")):
        if "validator" in low:
            return "dos", "validator-set"
        return "freeze", "arbitrary-user"
    if "panic" in low or "json-rpc" in low:
        return "dos", "validator-set"
    if "keyring" in low:
        return "privilege-escalation", "validator-set"
    if "unflag race" in low or "wrong outcome" in low or "incorrect outcome" in low:
        return "theft", "specific-user"
    if "mistransfer" in low or "lacks recovery" in low:
        return "freeze", "specific-user"
    if "grief" in low or severity in {"low", "info"}:
        return "griefing", "arbitrary-user"
    return "griefing", "arbitrary-user"


def _attacker_role(title: str) -> str:
    low = title.lower()
    if "keyring" in low:
        return "local-host-observer"
    if "validator" in low and "json-rpc" in low:
        return "unprivileged"
    return "unprivileged"


def _component(title: str) -> str:
    cleaned = re.sub(r"\s+", " ", title).strip()
    if len(cleaned) <= 220:
        return cleaned
    return cleaned[:217].rstrip() + "..."


def _fix_pattern(bug_class: str, attack_class: str) -> str:
    if "validation" in bug_class:
        return "Validate the same actor/scope predicate at the runtime authorization boundary."
    if "rounding" in bug_class:
        return "Preserve value with explicit rounding guards and reject zero-share or zero-signal edge cases."
    if "accounting" in bug_class:
        return "Include all active liabilities in the accounting invariant before permitting withdrawals."
    if "panic" in bug_class:
        return "Return bounded query errors for malformed inputs instead of panicking."
    if "access" in bug_class or "secret" in bug_class:
        return "Disable exposed local signing surfaces by default and require explicit operator authentication."
    if "oracle" in bug_class:
        return "Use bounded stale-price handling paths that preserve protocol operations or fail only affected actions."
    if "domain" in bug_class:
        return "Bind proofs and signatures to the full domain including chain/deployment identifiers."
    if "execution-environment" in bug_class:
        return "Keep execution-environment pricing tables in lockstep with the canonical hardfork schedule."
    if "dust" in bug_class:
        return "Reject bridge withdrawals below downstream settlement dust thresholds before accepting user funds."
    return f"Patch the {attack_class} invariant at the runtime entrypoint and add a regression PoC."


def _record_id(packet: dict[str, Any]) -> str:
    engagement = _slug(str(packet.get("engagement") or "unknown"), max_len=24)
    slug = _slug(str(packet.get("suggested_record_slug") or packet.get("submission_title") or "record"), max_len=70)
    source = "|".join([
        str(packet.get("source_queue_path") or ""),
        str(packet.get("queue_key") or ""),
        str(packet.get("submission_path") or ""),
        str(packet.get("submission_title") or ""),
    ])
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    return f"submission-derived:{engagement}:{slug}:{digest}"[:160].rstrip(":-")


def _yaml_quote(value: str) -> str:
    if value == "":
        return "''"
    if re.match(r"^[A-Za-z0-9._/<>=@$+ -]+$", value) and not value.startswith((" ", "-", "{", "[", ">", "<", "=", "@")):
        return value
    return json.dumps(value)


def _render_yaml(value: Any, indent: int = 0) -> list[str]:
    prefix = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(nested, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_render_yaml(nested, indent + 2))
            elif isinstance(nested, bool):
                lines.append(f"{prefix}{key}: {'true' if nested else 'false'}")
            elif isinstance(nested, (int, float)):
                lines.append(f"{prefix}{key}: {nested}")
            else:
                lines.append(f"{prefix}{key}: {_yaml_quote(str(nested))}")
    elif isinstance(value, list):
        if not value:
            lines.append(f"{prefix}[]")
        for item in value:
            if isinstance(item, dict):
                lines.append(f"{prefix}-")
                lines.extend(_render_yaml(item, indent + 2))
            elif isinstance(item, bool):
                lines.append(f"{prefix}- {'true' if item else 'false'}")
            elif isinstance(item, (int, float)):
                lines.append(f"{prefix}- {item}")
            else:
                lines.append(f"{prefix}- {_yaml_quote(str(item))}")
    return lines


def _record_from_packet(packet: dict[str, Any]) -> OrderedDict[str, Any]:
    title = str(packet.get("submission_title") or "")
    severity = _severity(packet)
    language = _target_language(packet)
    bug_class, attack_class = _bug_attack_class(title)
    impact_class, impact_actor = _impact(title, severity)
    proof_paths = _all_proof_paths(packet)
    source_audit_ref = f"submission-derived:{packet.get('engagement')}:{packet.get('queue_key')}"
    if len(source_audit_ref) > 240:
        source_audit_ref = source_audit_ref[:227] + ":" + hashlib.sha256(source_audit_ref.encode()).hexdigest()[:12]
    shape_tags = [
        f"attack_class:{attack_class}",
        f"bug_class:{bug_class}",
        f"target_domain:{_target_domain(title)}",
        f"target_language:{language}",
        "submission-derived",
        "local-proof-artifact",
        "verification_tier:tier-3-synthetic-taxonomy-anchored",
    ]
    if packet.get("engagement"):
        shape_tags.append(f"engagement:{packet['engagement']}")

    return OrderedDict(
        [
            ("schema_version", RECORD_SCHEMA),
            ("record_id", _record_id(packet)),
            ("source_audit_ref", source_audit_ref),
            ("record_tier", "submission-derived"),
            ("record_quality_score", 3.5),
            ("source_extraction_method", "human-curated"),
            ("source_extraction_confidence", 0.85),
            ("target_domain", _target_domain(title)),
            ("target_language", language),
            ("target_repo", _target_repo(packet, language)),
            ("target_component", _component(title)),
            (
                "function_shape",
                OrderedDict(
                    [
                        ("raw_signature", f"submission-derived::{packet.get('engagement')}::{packet.get('suggested_record_slug')}"),
                        ("shape_tags", list(dict.fromkeys(shape_tags))),
                    ]
                ),
            ),
            ("bug_class", bug_class),
            ("attack_class", attack_class),
            ("attacker_role", _attacker_role(title)),
            (
                "attacker_action_sequence",
                f"Trigger the {attack_class} condition described by the local proof artifact and observe the submitted impact.",
            ),
            (
                "required_preconditions",
                [
                    "local submission-derived record; see record_extensions.submission_path",
                    "proof artifact was validated by hackerman-proof-artifact-import-queue",
                    "verification_tier=tier-3-synthetic-taxonomy-anchored",
                ],
            ),
            ("impact_class", impact_class),
            ("impact_actor", impact_actor),
            ("impact_dollar_class", _dollar_class(severity, title)),
            ("fix_pattern", _fix_pattern(bug_class, attack_class)),
            ("fix_anti_pattern_avoided", "Do not rely on caller-side or UI-only assumptions when the runtime path accepts the unsafe state."),
            ("severity_at_finding", severity),
            ("year", 2026),
            ("proof_artifact_path", _first_proof_path(packet)),
            ("verdict_artefact", True),
            ("verification_tier", "tier-3-synthetic-taxonomy-anchored"),
            ("verification_method", "manual"),
            ("cross_language_analogues", []),
            ("related_records", []),
            (
                "record_extensions",
                OrderedDict(
                    [
                        ("proof_artifact_record_source", "proof_artifact_missing_record_review_packet"),
                        ("source_queue_path", str(packet.get("source_queue_path") or "")),
                        ("queue_key", str(packet.get("queue_key") or "")),
                        ("engagement", str(packet.get("engagement") or "")),
                        ("submission_path", str(packet.get("submission_path") or "")),
                        ("submission_status", str(packet.get("submission_status") or "")),
                        ("submission_title", title),
                        ("suggested_record_slug", str(packet.get("suggested_record_slug") or "")),
                        ("all_proof_artifact_paths", proof_paths),
                    ]
                ),
            ),
        ]
    )


def _load_packets(path: Path) -> tuple[list[dict[str, Any]], Counter[str]]:
    rows: list[dict[str, Any]] = []
    errors: Counter[str] = Counter()
    if not path.is_file():
        errors["packets_missing"] += 1
        return rows, errors
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            errors["invalid_json"] += 1
            continue
        if not isinstance(row, dict):
            errors["row_not_object"] += 1
            continue
        if row.get("schema") != PACKET_SCHEMA:
            errors["schema_mismatch"] += 1
            continue
        rows.append(row)
    return rows, errors


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_records(
    packets_path: Path,
    *,
    out_dir: Path,
    dry_run: bool = False,
    overwrite: bool = False,
) -> OrderedDict[str, Any]:
    packets, load_errors = _load_packets(packets_path)
    records: list[OrderedDict[str, Any]] = []
    skipped: Counter[str] = Counter(load_errors)
    for packet in packets:
        if packet.get("validation_status") != "ready_for_manual_record_creation":
            skipped["packet_not_ready"] += 1
            continue
        submission_status = str(packet.get("submission_status") or "").strip()
        if submission_status not in ELIGIBLE_SUBMISSION_STATUSES:
            skipped["submission_status_not_eligible"] += 1
            continue
        if not _first_proof_path(packet):
            if _raw_proof_paths(packet):
                skipped["proof_artifact_path_unsafe"] += 1
            else:
                skipped["proof_artifact_missing"] += 1
            continue
        records.append(_record_from_packet(packet))

    seen_ids: set[str] = set()
    emitted: list[str] = []
    existing_files: list[str] = []
    collisions: list[str] = []
    existing_outputs = 0
    proof_path_counts: list[int] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        record_id = str(record["record_id"])
        if record_id in seen_ids:
            skipped["duplicate_record_id_in_run"] += 1
            collisions.append(record_id)
            continue
        seen_ids.add(record_id)
        extensions = record.get("record_extensions")
        if isinstance(extensions, dict):
            all_paths = extensions.get("all_proof_artifact_paths")
            if isinstance(all_paths, list):
                proof_path_counts.append(len(all_paths))
        filename = _slug(record_id.replace(":", "-"), max_len=150) + ".yaml"
        out_path = out_dir / filename
        if out_path.is_symlink():
            skipped["output_path_symlink"] += 1
            collisions.append(str(out_path))
            continue
        if out_path.exists() and not overwrite:
            skipped["output_exists"] += 1
            existing_outputs += 1
            collisions.append(str(out_path))
            existing_files.append(str(out_path))
            continue
        emitted.append(str(out_path))
        if not dry_run:
            out_path.write_text("\n".join(_render_yaml(record)) + "\n", encoding="utf-8")

    hard_failed_count = sum(
        int(value)
        for key, value in skipped.items()
        if key != "output_exists"
    )
    if dry_run and hard_failed_count == 0 and records and existing_outputs == len(records):
        conversion_status = "dry-run-already-materialized"
    elif dry_run and hard_failed_count == 0 and emitted and existing_outputs:
        conversion_status = "dry-run-partial-existing"
    elif dry_run:
        conversion_status = "dry-run"
    elif hard_failed_count == 0 and emitted and existing_outputs:
        conversion_status = "success-with-existing"
    elif hard_failed_count == 0 and emitted:
        conversion_status = "success"
    elif hard_failed_count == 0 and records and existing_outputs == len(records):
        conversion_status = "already-materialized"
    elif hard_failed_count == 0 and not records:
        conversion_status = "no-eligible-records"
    else:
        conversion_status = "partial"
    packets_sha256 = _sha256_file(packets_path) if packets_path.is_file() else ""

    return OrderedDict(
        [
            ("schema", SUMMARY_SCHEMA),
            ("generated_at_utc", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
            ("conversion_status", conversion_status),
            ("packets_path", str(packets_path)),
            ("packets_sha256", packets_sha256),
            ("out_dir", str(out_dir)),
            ("dry_run", dry_run),
            ("overwrite", overwrite),
            ("packets_loaded", len(packets)),
            ("records_built", len(records)),
            ("records_emitted", len(emitted)),
            ("records_existing", existing_outputs),
            ("records_with_multiple_proof_paths", sum(1 for count in proof_path_counts if count > 1)),
            ("max_proof_paths_per_record", max(proof_path_counts, default=0)),
            ("failed_count", hard_failed_count),
            ("skipped_counts", dict(sorted(skipped.items()))),
            ("collisions", collisions[:20]),
            ("existing_files", existing_files[:200]),
            ("files", emitted),
        ]
    )


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", default=str(DEFAULT_PACKETS))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    summary = generate_records(
        Path(args.packets).expanduser(),
        out_dir=Path(args.out_dir).expanduser(),
        dry_run=args.dry_run,
        overwrite=args.overwrite,
    )
    if args.json_summary:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"records_built={summary['records_built']} "
            f"records_emitted={summary['records_emitted']} "
            f"out_dir={summary['out_dir']} dry_run={summary['dry_run']}"
        )
    return 0 if int(summary.get("failed_count") or 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
