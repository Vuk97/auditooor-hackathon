#!/usr/bin/env python3
"""worker-delivery-contract.py - J4 worker-delivery contract checker and assembler.

Enforces that every High/Critical hunter packet carries a bounded lesson pack selected
by target domain, language, function shape, attack class, severity row, and platform OOS.

Two modes:
  CHECK (default): validate a worker packet file or workspace packet directory.
  ASSEMBLE (--assemble): emit a lesson-pack template skeleton with PENDING markers.

Schema: auditooor.worker_delivery_contract.v1

Usage:
  python3 tools/worker-delivery-contract.py <packet-file-or-dir>
  python3 tools/worker-delivery-contract.py <packet-file-or-dir> --strict
  python3 tools/worker-delivery-contract.py <packet-file-or-dir> --json
  python3 tools/worker-delivery-contract.py --assemble --severity High
  python3 tools/worker-delivery-contract.py --assemble --severity Critical --out lesson_pack.json

Exit codes:
  0  all checks PASS (or warn-only for non-High/Critical packets)
  1  --strict and at least one High/Critical packet FAILS
  2  bad input / IO error
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.worker_delivery_contract.v1"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
PACKET_SCHEMA_RE = re.compile(r"auditooor\.v3_worker_packet", re.IGNORECASE)
HIGH_CRITICAL_RE = re.compile(r"^(?:high|critical)$", re.IGNORECASE)
NO_LESSON_PACK_REASON_PREFIX = "NO_LESSON_PACK_REASON:"
FULL_TOOLING_RE = re.compile(r"full[\s_-]?tooling", re.IGNORECASE)

# Maximum rows per lesson-pack section (bounded discipline)
MAX_SECTION_ROWS = 10

# Required lesson-pack content sections (J4 plan verbatim)
REQUIRED_CONTENT_SECTIONS: list[str] = [
    "case_study_logic",
    "corpus_analogues",
    "hacker_questions",
    "triager_objections",
    "economic_viability_questions",
    "kill_rubrics",
]

# Required selection keys that scope/select the lesson pack
REQUIRED_SELECTION_KEYS: list[str] = [
    "target_domain",
    "language",
    "function_shape",
    "attack_class",
    "severity_row",
    "platform_oos",
]

# Required MCP receipt metadata fields
REQUIRED_MCP_FIELDS: list[str] = [
    "context_pack_id",
    "context_pack_hash",
]

PASS = "pass"
WARN = "warn"
FAIL = "fail"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bounded_text(value: Any, *, max_len: int = 400) -> str:
    text = str(value or "").strip()
    if len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."
    return text


def _is_non_empty_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def _bounded_list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        return []
    return value[:MAX_SECTION_ROWS]


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_packet(path: Path) -> tuple[dict[str, Any] | None, str]:
    """Load a JSON packet from path. Returns (packet, error_message)."""
    if not path.exists():
        return None, f"file not found: {path}"
    if not path.is_file():
        return None, f"path is not a file: {path}"
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"IO error reading {path}: {exc}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"JSON parse error in {path}: {exc}"
    if not isinstance(parsed, dict):
        return None, f"expected JSON object, got {type(parsed).__name__} in {path}"
    return parsed, ""


def _load_atomic_writer():
    path = AUDITOOOR_ROOT / "tools" / "lib" / "atomic_corpus_writer.py"
    spec = importlib.util.spec_from_file_location("atomic_corpus_writer", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"failed to load atomic writer from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("atomic_corpus_writer", mod)
    spec.loader.exec_module(mod)
    return mod


def _iso_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _workspace_slug(packet: dict[str, Any], workspace_override: str | None, source_path: Path) -> str:
    raw = workspace_override or packet.get("workspace") or packet.get("workspace_path") or ""
    if raw:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(str(raw)).name)[:80] or "unknown"
    return ""


# ---------------------------------------------------------------------------
# Lesson-pack shape validation
# ---------------------------------------------------------------------------


def _check_mcp_receipt(lesson_pack: dict[str, Any]) -> list[str]:
    """Return list of missing MCP receipt field names."""
    missing = []
    mcp_meta = lesson_pack.get("mcp_receipt") or {}
    if not isinstance(mcp_meta, dict):
        mcp_meta = {}
    for field in REQUIRED_MCP_FIELDS:
        value = lesson_pack.get(field) or mcp_meta.get(field)
        if not value or not str(value).strip():
            missing.append(field)
    return missing


def _check_selection_keys(lesson_pack: dict[str, Any]) -> list[str]:
    """Return list of missing selection key names."""
    missing = []
    selection = lesson_pack.get("selection_keys") or {}
    if not isinstance(selection, dict):
        selection = {}
    for key in REQUIRED_SELECTION_KEYS:
        # Accept at top level OR nested under selection_keys
        value = lesson_pack.get(key) or selection.get(key)
        if not value or not str(value).strip():
            missing.append(key)
    return missing


def _check_content_sections(lesson_pack: dict[str, Any]) -> list[str]:
    """Return list of missing (empty or absent) content section names."""
    missing = []
    for section in REQUIRED_CONTENT_SECTIONS:
        value = lesson_pack.get(section)
        # Accept non-empty list, non-empty string, or non-empty dict
        if isinstance(value, list) and len(value) == 0:
            missing.append(section)
        elif isinstance(value, str) and not value.strip():
            missing.append(section)
        elif isinstance(value, dict) and not value:
            missing.append(section)
        elif value is None:
            missing.append(section)
        # PENDING marker counts as missing only if ALL rows are PENDING
        elif isinstance(value, list) and all(
            isinstance(item, str) and item.strip().upper() == "PENDING" for item in value
        ):
            missing.append(section)
    return missing


def _extract_lesson_pack(packet: dict[str, Any]) -> dict[str, Any] | None:
    """Extract lesson_pack from packet. Returns None if absent."""
    lp = packet.get("lesson_pack")
    if isinstance(lp, dict):
        return lp
    return None


def _has_typed_no_reason(packet: dict[str, Any]) -> bool:
    """Return True if packet has a valid typed NO_LESSON_PACK_REASON."""
    reason = _bounded_text(packet.get("no_lesson_pack_reason") or "", max_len=400)
    return reason.startswith(NO_LESSON_PACK_REASON_PREFIX) and len(reason) > len(NO_LESSON_PACK_REASON_PREFIX)


def _claims_full_tooling(packet: dict[str, Any]) -> bool:
    """Return True if the packet text claims 'full tooling' anywhere."""
    haystack = json.dumps(packet, ensure_ascii=True).lower()
    return bool(FULL_TOOLING_RE.search(haystack))


# ---------------------------------------------------------------------------
# Core check logic for a single packet
# ---------------------------------------------------------------------------


def check_packet(packet: dict[str, Any], *, source_path: str = "") -> dict[str, Any]:
    """
    Validate a single packet dict. Returns a result dict with:
      status: "pass" | "warn" | "fail"
      issues: list of issue dicts
      summary: human-readable string
    """
    severity = _bounded_text(packet.get("severity") or "", max_len=40)
    is_high_or_critical = bool(HIGH_CRITICAL_RE.match(severity.strip()))
    issues: list[dict[str, str]] = []

    lesson_pack = _extract_lesson_pack(packet)
    has_lesson_pack = lesson_pack is not None
    has_no_reason = _has_typed_no_reason(packet)
    claims_tooling = _claims_full_tooling(packet)

    if not is_high_or_critical:
        # Advisory only for lower severities
        if not has_lesson_pack and not has_no_reason:
            issues.append({
                "code": "missing_lesson_pack_advisory",
                "level": WARN,
                "message": (
                    f"Non-High/Critical packet (severity={severity!r}) has no lesson_pack "
                    "and no NO_LESSON_PACK_REASON. Lesson pack is advisory at this severity."
                ),
            })
        status = WARN if issues else PASS
        return {
            "status": status,
            "severity": severity,
            "is_high_or_critical": False,
            "source_path": source_path,
            "issues": issues,
            "summary": f"WARN (advisory): lesson pack not required for severity={severity!r}" if issues else "PASS",
        }

    # High/Critical path: lesson pack is mandatory unless typed reason is present
    if has_no_reason and not has_lesson_pack:
        # Valid exemption
        status = PASS
        return {
            "status": status,
            "severity": severity,
            "is_high_or_critical": True,
            "source_path": source_path,
            "issues": [],
            "summary": f"PASS: NO_LESSON_PACK_REASON provided for High/Critical packet (severity={severity!r})",
        }

    if not has_lesson_pack:
        # Fail: no lesson pack AND no typed reason
        msg = (
            "High/Critical packet has no lesson_pack and no typed "
            f"{NO_LESSON_PACK_REASON_PREFIX}<reason> field."
        )
        if claims_tooling:
            msg += " Packet claims 'full tooling' but lacks lesson-pack receipt - this is a hard fail."
        issues.append({"code": "missing_lesson_pack", "level": FAIL, "message": msg})
        return {
            "status": FAIL,
            "severity": severity,
            "is_high_or_critical": True,
            "source_path": source_path,
            "issues": issues,
            "summary": f"FAIL: missing lesson_pack on High/Critical packet (severity={severity!r})",
        }

    # Lesson pack is present - validate its shape
    assert lesson_pack is not None

    missing_mcp = _check_mcp_receipt(lesson_pack)
    missing_sel = _check_selection_keys(lesson_pack)
    missing_content = _check_content_sections(lesson_pack)

    if missing_mcp:
        issues.append({
            "code": "missing_mcp_receipt_fields",
            "level": FAIL,
            "message": f"lesson_pack missing MCP receipt fields: {missing_mcp}",
        })

    if missing_sel:
        issues.append({
            "code": "missing_selection_keys",
            "level": FAIL,
            "message": f"lesson_pack missing selection keys: {missing_sel}",
        })

    if missing_content:
        issues.append({
            "code": "missing_content_sections",
            "level": FAIL,
            "message": f"lesson_pack missing/empty content sections: {missing_content}",
        })

    fail_issues = [i for i in issues if i["level"] == FAIL]
    if fail_issues:
        status = FAIL
        summary = f"FAIL: lesson_pack shape invalid for High/Critical (severity={severity!r}): " + \
            "; ".join(i["message"] for i in fail_issues)
    else:
        status = PASS
        summary = f"PASS: lesson_pack complete and valid for High/Critical packet (severity={severity!r})"

    return {
        "status": status,
        "severity": severity,
        "is_high_or_critical": True,
        "source_path": source_path,
        "issues": issues,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Batch check (file or directory)
# ---------------------------------------------------------------------------


def check_path(target: Path) -> list[dict[str, Any]]:
    """Check a packet file or directory of packet files. Returns list of results."""
    results: list[dict[str, Any]] = []

    if target.is_file():
        packet, err = _load_packet(target)
        if err:
            results.append({
                "status": "error",
                "source_path": str(target),
                "error": err,
                "issues": [],
                "summary": f"ERROR: {err}",
            })
        else:
            assert packet is not None
            results.append(check_packet(packet, source_path=str(target)))
        return results

    if target.is_dir():
        packet_files = sorted(target.glob("*.json"))
        if not packet_files:
            results.append({
                "status": "error",
                "source_path": str(target),
                "error": f"no *.json files found in directory: {target}",
                "issues": [],
                "summary": f"ERROR: no *.json files in {target}",
            })
            return results
        for p in packet_files:
            packet, err = _load_packet(p)
            if err:
                results.append({
                    "status": "error",
                    "source_path": str(p),
                    "error": err,
                    "issues": [],
                    "summary": f"ERROR: {err}",
                })
            else:
                assert packet is not None
                results.append(check_packet(packet, source_path=str(p)))
        return results

    return [{
        "status": "error",
        "source_path": str(target),
        "error": f"path is neither a file nor a directory: {target}",
        "issues": [],
        "summary": f"ERROR: {target} is not a file or directory",
    }]


def _iter_packet_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(target.glob("*.json"))
    return []


def persist_valid_lesson_packs(
    target: Path,
    *,
    workspace: str | None = None,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """Persist valid lesson_pack blocks to derived JSONL for later MCP recall."""
    rows_by_workspace: dict[str, list[dict[str, Any]]] = {}
    skipped = 0
    for packet_path in _iter_packet_files(target):
        packet, err = _load_packet(packet_path)
        if err or packet is None:
            skipped += 1
            continue
        result = check_packet(packet, source_path=str(packet_path))
        if result.get("status") != PASS:
            skipped += 1
            continue
        lesson_pack = _extract_lesson_pack(packet)
        if not lesson_pack:
            skipped += 1
            continue
        ws_slug = _workspace_slug(packet, workspace, packet_path)
        if not ws_slug:
            skipped += 1
            continue
        lesson_hash = _stable_hash(lesson_pack)
        rows_by_workspace.setdefault(ws_slug, []).append({
            "schema": "auditooor.lesson_pack_persistence.v1",
            "workspace": ws_slug,
            "source_path": str(packet_path),
            "severity": packet.get("severity") or "",
            "packet_id": packet.get("packet_id") or "",
            "lesson_pack_hash": lesson_hash,
            "lesson_pack": lesson_pack,
            "persisted_at_utc": _iso_now(),
        })

    if not rows_by_workspace:
        return {"persisted": 0, "skipped": skipped, "outputs": []}

    base = out_dir or AUDITOOOR_ROOT / "audit" / "corpus_tags" / "derived"
    atomic = _load_atomic_writer()
    outputs: list[dict[str, Any]] = []
    persisted = 0
    for ws_slug, new_rows in rows_by_workspace.items():
        out_path = base / f"lesson_pack_{ws_slug}_{_iso_date()}.jsonl"
        existing_rows: list[dict[str, Any]] = []
        existing_hashes: set[str] = set()
        if out_path.is_file():
            for raw in out_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not raw.strip():
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    existing_rows.append(row)
                    existing_hashes.add(str(row.get("lesson_pack_hash") or ""))
        added = 0
        for row in new_rows:
            if row["lesson_pack_hash"] in existing_hashes:
                continue
            existing_rows.append(row)
            existing_hashes.add(row["lesson_pack_hash"])
            added += 1
        if added:
            content = "".join(json.dumps(r, sort_keys=True, ensure_ascii=True) + "\n" for r in existing_rows)
            write_result = atomic.atomic_write_corpus_file(out_path, content, sha256_check=True)
        else:
            write_result = {"success": True, "path": str(out_path), "dedup_only": True}
        persisted += added
        outputs.append({"workspace": ws_slug, "path": str(out_path), "added": added, "atomic_write": write_result})
    return {"persisted": persisted, "skipped": skipped, "outputs": outputs}


# ---------------------------------------------------------------------------
# Assemble template
# ---------------------------------------------------------------------------


def assemble_template(*, severity: str = "High", out: Path | None = None) -> dict[str, Any]:
    """Emit a lesson-pack template skeleton with PENDING markers."""
    template: dict[str, Any] = {
        "schema": SCHEMA,
        "mode": "template",
        "note": "Fill every PENDING field before attaching to a High/Critical worker packet.",
        "severity": severity,
        # MCP receipt metadata
        "context_pack_id": "PENDING",
        "context_pack_hash": "PENDING",
        "mcp_receipt": {
            "context_pack_id": "PENDING",
            "context_pack_hash": "PENDING",
        },
        # Selection keys - scope the lesson pack
        "selection_keys": {
            "target_domain": "PENDING - e.g. defi-lending / amm / bridge / governance",
            "language": "PENDING - e.g. Solidity / Go / Rust / Move",
            "function_shape": "PENDING - e.g. reentrancy-guard-missing / unchecked-return",
            "attack_class": "PENDING - e.g. theft / freeze / dos / precision-loss",
            "severity_row": "PENDING - verbatim rubric row e.g. 'Direct loss of funds'",
            "platform_oos": "PENDING - platform OOS clauses that could kill this finding",
        },
        # Content sections (bounded to MAX_SECTION_ROWS rows each)
        "case_study_logic": [
            "PENDING - cite a real case study (title, source, what happened, how it applies)"
        ],
        "corpus_analogues": [
            "PENDING - cite corpus records matching this attack class (record_id, similarity)"
        ],
        "hacker_questions": [
            "PENDING - specific 'what if attacker does X?' questions to stress-test the finding"
        ],
        "triager_objections": [
            "PENDING - enumerate the most likely triager rejection phrases for this class"
        ],
        "economic_viability_questions": [
            "PENDING - is attacker profit > cost? What MEV/flash-loan assumptions are needed?"
        ],
        "kill_rubrics": [
            "PENDING - conditions under which this finding must be dropped (admin-gated, OOS, etc.)"
        ],
        # Metadata
        "_bounds": {
            "max_rows_per_section": MAX_SECTION_ROWS,
            "required_content_sections": REQUIRED_CONTENT_SECTIONS,
            "required_selection_keys": REQUIRED_SELECTION_KEYS,
            "required_mcp_fields": REQUIRED_MCP_FIELDS,
        },
    }
    template["template_hash"] = _stable_hash(
        {k: v for k, v in template.items() if k != "template_hash"}
    )

    if out is not None:
        out.write_text(
            json.dumps(template, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    return template


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def build_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a top-level JSON report from a list of per-packet results."""
    total = len(results)
    n_pass = sum(1 for r in results if r.get("status") == PASS)
    n_warn = sum(1 for r in results if r.get("status") == WARN)
    n_fail = sum(1 for r in results if r.get("status") == FAIL)
    n_error = sum(1 for r in results if r.get("status") == "error")

    any_hc_fail = any(
        r.get("status") == FAIL and r.get("is_high_or_critical")
        for r in results
    )

    overall = FAIL if any_hc_fail or n_error > 0 else (WARN if n_warn > 0 else PASS)

    return {
        "schema": SCHEMA,
        "overall_status": overall,
        "summary": {
            "total": total,
            "pass": n_pass,
            "warn": n_warn,
            "fail": n_fail,
            "error": n_error,
            "high_or_critical_fail": any_hc_fail,
        },
        "results": results,
    }


def _print_human(report: dict[str, Any]) -> None:
    overall = report["overall_status"].upper()
    s = report["summary"]
    print(f"[worker-delivery-contract] overall: {overall}")
    print(f"  packets: {s['total']} total / {s['pass']} pass / {s['warn']} warn / {s['fail']} fail / {s['error']} error")
    if s["high_or_critical_fail"]:
        print("  !! High/Critical packet(s) FAIL lesson-pack contract - dispatch lint will block these !!")
    for result in report["results"]:
        status = result.get("status", "?").upper()
        path = result.get("source_path", "")
        summary = result.get("summary", "")
        print(f"\n  [{status}] {path}")
        print(f"    {summary}")
        for issue in result.get("issues", []):
            level = issue.get("level", "?").upper()
            code = issue.get("code", "")
            msg = issue.get("message", "")
            print(f"    - [{level}] {code}: {msg}")
        if result.get("error"):
            print(f"    - [ERROR] {result['error']}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="worker-delivery-contract",
        description="J4 worker-delivery contract: check or assemble lesson packs for High/Critical worker packets.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Path to a worker packet JSON file or a directory containing packet JSON files (CHECK mode).",
    )
    parser.add_argument(
        "--assemble",
        action="store_true",
        help="Emit a lesson-pack template skeleton (ASSEMBLE mode).",
    )
    parser.add_argument(
        "--severity",
        default="High",
        help="Severity to annotate the assembled template (default: High).",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Write assembled template or JSON report to this file path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit full JSON report to stdout (CHECK mode) or assembled template JSON.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any High/Critical packet fails the lesson-pack contract.",
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help="Workspace path/name used for lesson_pack_<workspace>_<date>.jsonl persistence.",
    )
    parser.add_argument(
        "--lesson-pack-out-dir",
        default=None,
        help="Override lesson_pack JSONL output directory.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    out_path = Path(args.out) if args.out else None

    # ASSEMBLE mode
    if args.assemble:
        template = assemble_template(severity=args.severity, out=out_path)
        if args.json or not out_path:
            print(json.dumps(template, indent=2, ensure_ascii=True))
        if out_path:
            print(f"[worker-delivery-contract] template written to {out_path}", file=sys.stderr)
        return 0

    # CHECK mode
    if not args.target:
        print(
            "error: target path required in CHECK mode (pass a packet JSON file or directory).",
            file=sys.stderr,
        )
        return 2

    target = Path(args.target)
    results = check_path(target)
    report = build_report(results)
    out_dir = Path(args.lesson_pack_out_dir) if args.lesson_pack_out_dir else None
    report["lesson_pack_persistence"] = persist_valid_lesson_packs(
        target,
        workspace=args.workspace,
        out_dir=out_dir,
    )

    if args.json:
        output = json.dumps(report, indent=2, ensure_ascii=True)
        print(output)
        if out_path:
            out_path.write_text(output + "\n", encoding="utf-8")
    else:
        _print_human(report)
        if out_path:
            out_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    overall = report["overall_status"]
    any_hc_fail = report["summary"]["high_or_critical_fail"]

    if args.strict and (any_hc_fail or overall == "error"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
