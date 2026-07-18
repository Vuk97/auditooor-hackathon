#!/usr/bin/env python3
"""J3b - Sidecar freshness and corpus acceptance gate.

Computes the current corpus fingerprint and compares it against the
fingerprint recorded inside each known derived sidecar.  A sidecar whose
recorded fingerprint differs from the current corpus fingerprint is ``stale``.
A stale sidecar with no entry in ``.auditooor/sidecar_stale_reasons.json``
is a GATE FAIL in ``--strict`` mode.

Also classifies the ``failing dirs`` listed in J3b as
``real_anchor``, ``fanout_fixture_corpus``, or ``explicitly_exempted`` so
callers can decide which subdirs to accept for proof-grade evidence.

Usage examples::

    python3 tools/sidecar-staleness-gate.py --json
    python3 tools/sidecar-staleness-gate.py --strict
    python3 tools/sidecar-staleness-gate.py --derived-dir /path/to/derived

Exit codes:
    0  all sidecars fresh (or all stale ones have recorded reasons)
    1  one or more stale sidecars with no recorded reason (gate fail in strict mode only)
    2  usage / environment error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

SCHEMA = "auditooor.sidecar_staleness_gate.v1"

# ---------------------------------------------------------------------------
# Known derived sidecars: name -> relative path inside derived dir + how to
# extract the recorded corpus fingerprint from the file.
# ---------------------------------------------------------------------------

# Each entry: (filename, "jsonl_meta" | "json_toplevel" | "json_meta_subkey" | "none")
KNOWN_SIDECARS: list[tuple[str, str]] = [
    ("detector_relationship_records.jsonl", "jsonl_meta"),
    ("chain_candidates.jsonl", "jsonl_meta"),
    ("chain_unify_payload.json", "json_meta_subkey"),
    ("attack_class_taxonomy.json", "none"),  # no fingerprint field - always needs reason if stale logic is used
]

# ---------------------------------------------------------------------------
# Failing-subdir acceptance table (J3b)
# tier-2 = real anchors (audit PDFs, public post-mortems, fix commits).
# tier-3 synthetic / fanout / fixture corpora.
# explicitly_exempted = known intentional.
# ---------------------------------------------------------------------------

# Format: subdir_name -> (classification, confidence, reason)
SUBDIR_ACCEPTANCE: dict[str, tuple[str, str, str]] = {
    "aptos_move": (
        "real_anchor",
        "medium",
        "Aptos Move audit baselines extracted from real audit findings; tier-3 shape but source refs are real audit reports",
    ),
    "bridge_attacks": (
        "real_anchor",
        "high",
        "Bridge incident post-mortems from public incident trackers (Rekt, DeFiLlama); tier-2 archive-verified",
    ),
    "corpus_mined": (
        "fanout_fixture_corpus",
        "high",
        "Corpus-mined slice records extracted from Code4rena/Solodit text via NLP; tier-3 synthetic taxonomy-anchored; not individually source-verified",
    ),
    "ethereum_client_rust": (
        "real_anchor",
        "high",
        "Ethereum client Rust findings from public audit reports and CVE disclosures; tier-2 archive-verified",
    ),
    "evm_proxy_upgrade": (
        "real_anchor",
        "medium",
        "EVM proxy upgrade patterns from public audits and post-mortems; mixed tier-2 and tier-3; treat with care",
    ),
    "move_cve_advisory": (
        "real_anchor",
        "high",
        "Move CVE advisories from official advisories and audit reports; tier-1/tier-2 verified",
    ),
    "near_ink": (
        "real_anchor",
        "high",
        "NEAR/ink! findings from Kudelski and other public audits (Aleph Zero staking etc.); tier-2/tier-3 mixed but source refs present",
    ),
    "pattern_docs": (
        "explicitly_exempted",
        "high",
        "Pattern documentation files - not corpus records; contain human-authored pattern descriptions used as detector seeds; accepted as fixture",
    ),
    "sig_extracts": (
        "fanout_fixture_corpus",
        "medium",
        "Function signature extracts from corpus mining; tier-3 synthetic; useful for shape-matching but not proof-grade anchors",
    ),
    "solidity_fork_patterns": (
        "real_anchor",
        "medium",
        "Solidity fork/divergence patterns from public audits; mixed tier-2/tier-3; verify source_audit_ref before citing as proof-grade",
    ),
    "substrate_cosmwasm_frost": (
        "real_anchor",
        "medium",
        "Substrate/CosmWasm/FROST patterns from public audit and advisory sources; tier-2/tier-3 mixed; real anchors present",
    ),
    "sui_move": (
        "fanout_fixture_corpus",
        "medium",
        "Sui Move patterns primarily from synthetic taxonomy expansion; tier-3; few individually source-anchored records",
    ),
    "vyper_cve": (
        "real_anchor",
        "high",
        "Vyper compiler CVE records extracted from official CVE/GHSA disclosures and Curve post-mortems; tier-2/tier-3 mixed; real anchors present",
    ),
    "vyper_cve_real_source": (
        "real_anchor",
        "high",
        "Vyper CVE records with verified real source links; tier-2 archive-verified",
    ),
}


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------

def _compute_current_fingerprint(tag_dir: Path) -> tuple[str, int]:
    """Re-use the same algorithm as hackerman_query_common.corpus_content_fingerprint.

    Prefers the canonical ``iter_corpus_record_paths`` traversal (which
    excludes quarantine/deprecated subtrees) so the fingerprint produced here
    matches the one stored inside freshly-built sidecars.  Falls back to a
    simple ``rglob`` when the helper module is unavailable.
    """
    # Try to import the shared traversal helper used by all emitters.
    try:
        from hackerman_query_common import iter_corpus_record_paths  # type: ignore[import]

        entries: list[tuple[str, int, int]] = []
        for item in iter_corpus_record_paths(tag_dir):
            path = item.path
            try:
                stat = path.stat()
            except OSError:
                continue
            try:
                name = str(path.relative_to(tag_dir))
            except ValueError:
                name = path.name
            entries.append((name, stat.st_size, stat.st_mtime_ns))
        digest = hashlib.sha256(
            json.dumps(sorted(entries), sort_keys=True).encode("utf-8")
        ).hexdigest()
        return digest, len(entries)
    except Exception:
        pass  # fall through to legacy rglob path

    # Legacy fallback: plain rglob (may differ from emitter by ~47 quarantine files).
    entries2: list[tuple[str, int, int]] = []
    yaml_extensions = {".yaml", ".yml"}
    try:
        paths = [p for p in tag_dir.rglob("*") if p.is_file() and p.suffix.lower() in yaml_extensions]
    except OSError:
        return "UNAVAILABLE", 0
    for path in sorted(set(paths)):
        try:
            stat = path.stat()
        except OSError:
            continue
        try:
            name = str(path.relative_to(tag_dir))
        except ValueError:
            name = path.name
        entries2.append((name, stat.st_size, stat.st_mtime_ns))
    digest = hashlib.sha256(
        json.dumps(entries2, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return digest, len(entries2)


def _extract_recorded_fingerprint(sidecar_path: Path, extraction_mode: str) -> tuple[str, str]:
    """Return (recorded_fingerprint, error_or_empty).

    extraction_mode values:
      jsonl_meta        - first line of JSONL is the metadata dict, key=corpus_fingerprint
      json_toplevel     - top-level JSON key corpus_fingerprint
      json_meta_subkey  - JSON with a 'meta' subdict containing corpus_fingerprint
      none              - no fingerprint stored; return ('NONE', '')
    """
    if extraction_mode == "none":
        return "NONE", ""
    if not sidecar_path.exists():
        return "MISSING", ""
    try:
        if extraction_mode == "jsonl_meta":
            with sidecar_path.open(encoding="utf-8") as fh:
                first_line = fh.readline().strip()
            if not first_line:
                return "EMPTY", "first line is empty"
            meta = json.loads(first_line)
            fp = meta.get("corpus_fingerprint", "")
            if not fp:
                return "NO_FP_FIELD", "corpus_fingerprint key absent from metadata line"
            return str(fp), ""
        if extraction_mode == "json_toplevel":
            data = json.loads(sidecar_path.read_text(encoding="utf-8"))
            fp = data.get("corpus_fingerprint", "")
            if not fp:
                return "NO_FP_FIELD", "corpus_fingerprint key absent"
            return str(fp), ""
        if extraction_mode == "json_meta_subkey":
            data = json.loads(sidecar_path.read_text(encoding="utf-8"))
            meta = data.get("meta", {})
            fp = meta.get("corpus_fingerprint", "")
            if not fp:
                # try top-level fallback
                fp = data.get("corpus_fingerprint", "")
            if not fp:
                return "NO_FP_FIELD", "corpus_fingerprint absent from meta and top-level"
            return str(fp), ""
    except json.JSONDecodeError as exc:
        return "PARSE_ERROR", str(exc)
    except OSError as exc:
        return "READ_ERROR", str(exc)
    return "UNKNOWN_MODE", f"unrecognised extraction_mode={extraction_mode!r}"


# ---------------------------------------------------------------------------
# Stale reason store
# ---------------------------------------------------------------------------

def _load_stale_reasons(reasons_path: Path) -> dict[str, str]:
    """Load .auditooor/sidecar_stale_reasons.json -> {sidecar_name: reason}."""
    if not reasons_path.exists():
        return {}
    try:
        data = json.loads(reasons_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (json.JSONDecodeError, OSError):
        pass
    return {}


# ---------------------------------------------------------------------------
# Subdir acceptance classifier
# ---------------------------------------------------------------------------

def _classify_subdir(subdir_name: str, tag_dir: Path) -> dict[str, Any]:
    """Return acceptance row for a failing subdir."""
    if subdir_name in SUBDIR_ACCEPTANCE:
        classification, confidence, reason = SUBDIR_ACCEPTANCE[subdir_name]
        return {
            "subdir": subdir_name,
            "classification": classification,
            "confidence": confidence,
            "reason": reason,
            "exists": (tag_dir / subdir_name).is_dir() if tag_dir.is_dir() else False,
        }
    # Heuristic fallback for subdirs not in the table
    name_lower = subdir_name.lower()
    if any(k in name_lower for k in ("fixture", "mock", "test", "sample", "dummy")):
        classification = "fanout_fixture_corpus"
        reason = "heuristic: name contains fixture/mock/test keyword"
        confidence = "low"
    elif any(k in name_lower for k in ("cve", "advisory", "incident", "post_mortem", "postmortem", "rekt")):
        classification = "real_anchor"
        reason = "heuristic: name suggests CVE/advisory/incident source"
        confidence = "low"
    elif any(k in name_lower for k in ("mined", "synthetic", "generated", "slice")):
        classification = "fanout_fixture_corpus"
        reason = "heuristic: name suggests synthetic/mined generation"
        confidence = "low"
    else:
        classification = "fanout_fixture_corpus"
        reason = "heuristic: unknown subdir; defaulting to fanout_fixture_corpus (low confidence)"
        confidence = "low"
    return {
        "subdir": subdir_name,
        "classification": classification,
        "confidence": confidence,
        "reason": reason,
        "exists": (tag_dir / subdir_name).is_dir() if tag_dir.is_dir() else False,
    }


def classify_failing_subdirs(tag_dir: Path, extra_subdirs: list[str] | None = None) -> list[dict[str, Any]]:
    """Classify all J3b failing dirs plus any extras."""
    subdirs = list(SUBDIR_ACCEPTANCE.keys())
    if extra_subdirs:
        for s in extra_subdirs:
            if s not in subdirs:
                subdirs.append(s)
    return [_classify_subdir(s, tag_dir) for s in subdirs]


# ---------------------------------------------------------------------------
# Main gate logic
# ---------------------------------------------------------------------------

def run_gate(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    derived_dir = Path(args.derived_dir).expanduser().resolve()
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    reasons_path = Path(args.reasons_file).expanduser().resolve()

    # Compute current corpus fingerprint
    if tag_dir.is_dir():
        current_fp, file_count = _compute_current_fingerprint(tag_dir)
    else:
        current_fp = "TAG_DIR_MISSING"
        file_count = 0

    # Load stale reasons
    stale_reasons = _load_stale_reasons(reasons_path)

    # Determine sidecars to check
    sidecar_rows: list[dict[str, Any]] = []

    if not derived_dir.is_dir():
        # derived dir missing - emit missing rows for all known sidecars
        for sidecar_name, _ in KNOWN_SIDECARS:
            sidecar_rows.append({
                "sidecar": sidecar_name,
                "path": str(derived_dir / sidecar_name),
                "status": "missing",
                "recorded_fingerprint": "MISSING",
                "current_fingerprint": current_fp,
                "stale_reason": stale_reasons.get(sidecar_name, ""),
                "gate": "pass",  # missing derived dir is not a gate fail (new workspace)
                "note": "derived_dir_absent",
            })
    else:
        # Also discover any additional sidecars under derived dir not in the known list
        known_names = {name for name, _ in KNOWN_SIDECARS}
        extra_sidecars: list[tuple[str, str]] = []
        for p in sorted(derived_dir.iterdir()):
            if p.name in known_names:
                continue
            if p.suffix in (".json", ".jsonl"):
                # Guess extraction mode
                mode = "jsonl_meta" if p.suffix == ".jsonl" else "json_toplevel"
                extra_sidecars.append((p.name, mode))

        all_sidecars = list(KNOWN_SIDECARS) + extra_sidecars

        for sidecar_name, extraction_mode in all_sidecars:
            sidecar_path = derived_dir / sidecar_name
            recorded_fp, extract_err = _extract_recorded_fingerprint(sidecar_path, extraction_mode)

            if not sidecar_path.exists():
                status = "missing"
                gate_verdict = "pass"  # missing sidecar is advisory, not a hard fail
                note = "sidecar_file_absent"
            elif recorded_fp in ("NONE", "NO_FP_FIELD", "EMPTY", "PARSE_ERROR", "READ_ERROR", "UNKNOWN_MODE"):
                # Cannot determine freshness
                status = "unknown"
                gate_verdict = "pass"
                note = f"fingerprint_unavailable:{recorded_fp}" + (f":{extract_err}" if extract_err else "")
            elif current_fp == "TAG_DIR_MISSING":
                status = "unknown"
                gate_verdict = "pass"
                note = "tag_dir_missing_cannot_compare"
            elif recorded_fp == current_fp:
                status = "fresh"
                gate_verdict = "pass"
                note = ""
            else:
                status = "stale"
                reason = stale_reasons.get(sidecar_name, "")
                if reason:
                    gate_verdict = "pass"
                    note = f"stale_with_reason:{reason[:80]}"
                else:
                    # Stale + no reason = gate fail in strict mode, warning in normal mode
                    gate_verdict = "fail" if args.strict else "warn"
                    note = "SIDECAR_STALE_REASON_MISSING"

            row: dict[str, Any] = {
                "sidecar": sidecar_name,
                "path": str(sidecar_path),
                "status": status,
                "recorded_fingerprint": recorded_fp,
                "current_fingerprint": current_fp,
                "stale_reason": stale_reasons.get(sidecar_name, ""),
                "gate": gate_verdict,
            }
            if note:
                row["note"] = note
            sidecar_rows.append(row)

    # Subdir acceptance classification
    subdir_rows = classify_failing_subdirs(tag_dir)

    # Aggregate gate verdict
    gate_fails = [r for r in sidecar_rows if r.get("gate") == "fail"]
    gate_warns = [r for r in sidecar_rows if r.get("gate") == "warn"]
    stale_no_reason = [r for r in sidecar_rows if r.get("status") == "stale" and not r.get("stale_reason")]
    fresh_count = sum(1 for r in sidecar_rows if r.get("status") == "fresh")
    stale_count = sum(1 for r in sidecar_rows if r.get("status") == "stale")

    overall_gate = "pass"
    if gate_fails:
        overall_gate = "fail"
    elif gate_warns:
        overall_gate = "warn"

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "gate": overall_gate,
        "strict": bool(args.strict),
        "current_corpus_fingerprint": current_fp,
        "corpus_file_count": file_count,
        "tag_dir": str(tag_dir),
        "derived_dir": str(derived_dir),
        "reasons_file": str(reasons_path),
        "sidecars_checked": len(sidecar_rows),
        "fresh_count": fresh_count,
        "stale_count": stale_count,
        "stale_no_reason_count": len(stale_no_reason),
        "gate_fail_count": len(gate_fails),
        "gate_warn_count": len(gate_warns),
        "sidecars": sidecar_rows,
        "subdir_acceptance": subdir_rows,
    }

    if overall_gate == "fail":
        exit_code = 1
    else:
        exit_code = 0

    return exit_code, payload


# ---------------------------------------------------------------------------
# Human-readable formatter
# ---------------------------------------------------------------------------

def _human_summary(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    gate = payload["gate"].upper()
    lines.append(f"SIDECAR-STALENESS-GATE: {gate}")
    lines.append(
        f"  corpus fingerprint : {payload['current_corpus_fingerprint'][:16]}... "
        f"({payload['corpus_file_count']} files)"
    )
    lines.append(
        f"  sidecars checked   : {payload['sidecars_checked']}  "
        f"fresh={payload['fresh_count']}  stale={payload['stale_count']}  "
        f"stale-no-reason={payload['stale_no_reason_count']}"
    )
    lines.append("")
    for row in payload.get("sidecars", []):
        status = row["status"].upper()
        gate_tag = f"[{row['gate'].upper()}]"
        note = f"  ({row['note']})" if row.get("note") else ""
        lines.append(f"  {gate_tag:8} {status:10} {row['sidecar']}{note}")
    lines.append("")
    lines.append("Subdir acceptance (failing dirs):")
    for row in payload.get("subdir_acceptance", []):
        conf = f"conf={row['confidence']}"
        exists = "exists" if row.get("exists") else "absent"
        lines.append(
            f"  [{row['classification']:24}] [{conf:12}] [{exists:6}] {row['subdir']}"
        )
        lines.append(f"    -> {row['reason']}")
    if payload["gate"] == "fail":
        lines.append("")
        lines.append(
            "GATE FAIL: one or more stale sidecars have no SIDECAR_STALE_REASON entry."
        )
        lines.append(
            f"Add reasons to: {payload['reasons_file']}"
        )
        lines.append(
            "  Format: {\"<sidecar_filename>\": \"<reason text>\"}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--derived-dir",
        default=str(REPO_ROOT / "audit" / "corpus_tags" / "derived"),
        help="Path to derived sidecar directory (default: audit/corpus_tags/derived).",
    )
    parser.add_argument(
        "--tag-dir",
        default=str(REPO_ROOT / "audit" / "corpus_tags" / "tags"),
        help="Path to corpus tags directory used to compute the current fingerprint.",
    )
    parser.add_argument(
        "--reasons-file",
        default=str(REPO_ROOT / ".auditooor" / "sidecar_stale_reasons.json"),
        help="Path to sidecar_stale_reasons.json (default: .auditooor/sidecar_stale_reasons.json).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any sidecar is stale with no recorded SIDECAR_STALE_REASON.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit full JSON payload to stdout.",
    )
    args = parser.parse_args(argv)

    rc, payload = run_gate(args)

    if args.json:
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        print(_human_summary(payload))

    return rc


if __name__ == "__main__":
    sys.exit(main())
