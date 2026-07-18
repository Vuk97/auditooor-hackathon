#!/usr/bin/env python3
"""solodit-ingest.py — F1 Phase 1: pull High/Critical findings from Solodit MCP.

Wraps the `mcp__solodit__search_findings` tool (called from the orchestrator
environment) via a subprocess-friendly stdin/stdout JSON protocol.  In this
phase the tool is designed to be called from the shell as a standalone script;
the MCP connection is simulated via a thin JSON input wrapper so the
orchestrator can inject real or cached responses.

Usage (dry-run, no real MCP call — for CI / self-test):
    python3 tools/solodit-ingest.py \\
        --dry-run \\
        --inject-json /tmp/solodit_dry_run/mcp_response.json \\
        --max-findings 5 \\
        --out-dir /private/tmp/solodit-ingest

Usage (real — called by orchestrator after MCP query):
    python3 tools/solodit-ingest.py \\
        --from-json <findings_list.json> \\
        --max-findings 100 \\
        --out-dir /private/tmp/solodit-ingest \\
        --cursor-file reference/solodit_ingest_cursor.json

Exit codes:
  0  success (≥0 findings processed)
  1  input error / parse failure
  2  privacy-filter detected a secret pattern in output (hard abort)

Privacy filter: before any JSON is written to disk the tool redacts private-
key / mnemonic patterns. If a pattern fires it is replaced with
[REDACTED:<reason>] and a warning is printed to stderr.  If --strict-privacy
is set, the tool exits 2 instead of continuing.

Cursor management: the cursor file tracks the highest `id` seen so far.
On every successful run the cursor is updated. On the next run, any finding
whose `id` ≤ cursor is skipped (already ingested).

Note: this tool does NOT call the MCP directly — that happens in the
orchestrator shell script. The MCP response (a JSON array of finding objects)
is passed in via --from-json or --inject-json (dry-run mode).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_VERSION = "1.0.0"
TOOL_NAME = "solodit-ingest"

# Privacy-filter regexes (pattern, label)
# Applied to the full JSON text of each finding before disk write.
PRIVACY_PATTERNS: List[tuple[str, str]] = [
    (r"\b(0x)?[0-9a-fA-F]{64}\b", "hex-64-privkey-candidate"),
    (
        r"\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access"
        r"|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress"
        r"|actual){3,}\b",
        "mnemonic-phrase-candidate",
    ),
    (r"(?i)private[_\-\s]?key\s*[:=]\s*\S+", "privkey-assignment"),
    (r"(?i)mnemonic\s*[:=]\s*\S+", "mnemonic-assignment"),
    (r"(?i)secret\s*[:=]\s*['\"]?[0-9a-zA-Z/+=]{20,}", "secret-assignment"),
    (r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "pem-private-key"),
]

VALID_SEVERITIES = {"HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# Privacy filter
# ---------------------------------------------------------------------------

def _apply_privacy_filter(text: str, strict: bool = False) -> tuple[str, list[str]]:
    """Redact privacy-sensitive patterns. Returns (cleaned_text, list_of_warnings)."""
    warnings: list[str] = []
    for pattern, label in PRIVACY_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            # Only replace if the matched token looks truly suspicious (length check for hex)
            if label == "hex-64-privkey-candidate":
                # Skip contract addresses and tx hashes that appear in audit content;
                # those are expected. Only flag if it looks like a raw key literal
                # (no 0x prefix, or appears after 'key =').
                filtered_matches = [m for m in matches if not m.lower().startswith("0x")]
                if not filtered_matches:
                    continue
            warnings.append(f"PRIVACY-FILTER: redacted {len(matches)} instance(s) of {label}")
            text = re.sub(pattern, f"[REDACTED:{label}]", text)
    return text, warnings


# ---------------------------------------------------------------------------
# Cursor management
# ---------------------------------------------------------------------------

def _load_cursor(cursor_file: Path) -> int:
    """Return the last-seen finding id (0 if cursor file doesn't exist)."""
    if not cursor_file.exists():
        return 0
    try:
        data = json.loads(cursor_file.read_text())
        return int(data.get("last_id", 0))
    except (json.JSONDecodeError, ValueError, KeyError):
        return 0


def _save_cursor(cursor_file: Path, last_id: int, extra_meta: dict) -> None:
    """Write cursor with metadata."""
    cursor_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "last_id": last_id,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **extra_meta,
    }
    cursor_file.write_text(json.dumps(payload, indent=2))


# ---------------------------------------------------------------------------
# Finding normalization
# ---------------------------------------------------------------------------

def _normalize_finding(raw: dict) -> dict:
    """Normalize a Solodit finding dict to a canonical ingest schema."""
    # Extract id from various field names MCP might return
    finding_id = (
        raw.get("id")
        or raw.get("finding_id")
        or raw.get("solodit_id")
        or raw.get("numeric_id")
        or "unknown"
    )
    severity = str(raw.get("severity", "")).upper().strip()
    if severity not in VALID_SEVERITIES:
        severity = "HIGH"  # default conservatively

    return {
        "_schema_version": "solodit-ingest-v1",
        "_ingested_at": datetime.now(timezone.utc).isoformat(),
        "_tool_version": TOOL_VERSION,
        "id": str(finding_id),
        "severity": severity,
        "title": raw.get("title", ""),
        "firm": raw.get("firm", ""),
        "protocol": raw.get("protocol", ""),
        "language": raw.get("language", ""),
        "tags": raw.get("tags", []),
        "quality_score": raw.get("quality_score", raw.get("quality", 0)),
        "rarity_score": raw.get("rarity_score", raw.get("rarity", 0)),
        "solodit_url": raw.get("solodit_url", raw.get("url", "")),
        "content": raw.get("content", raw.get("description", "")),
        "has_public_fix": bool(raw.get("has_public_fix", True)),
        "reported_date": raw.get("reported_date", raw.get("date", "")),
        # Preserve full raw for downstream tools
        "_raw": raw,
    }


# ---------------------------------------------------------------------------
# Main ingest logic
# ---------------------------------------------------------------------------

def ingest(
    findings: List[dict],
    out_dir: Path,
    cursor_file: Optional[Path],
    max_findings: int,
    strict_privacy: bool,
    dry_run: bool,
    language_filter: Optional[List[str]] = None,
) -> dict:
    """Process findings list: filter, privacy-check, write to disk.

    If ``language_filter`` is non-empty, only findings whose ``language`` field
    matches one of the entries (case-insensitive, substring match) are kept.
    A finding with an empty/missing ``language`` field is dropped when a
    language filter is active. This is the Tier-A #3 hook used to ingest
    Rust-only corpora for Spark/zkbugs work.

    Returns summary dict suitable for orchestrator logging.
    """
    run_date = date.today().isoformat()
    run_dir = out_dir / run_date
    if not dry_run:
        run_dir.mkdir(parents=True, exist_ok=True)

    last_cursor = _load_cursor(cursor_file) if cursor_file else 0
    norm_lang_filter: List[str] = []
    if language_filter:
        for entry in language_filter:
            for token in str(entry).split(","):
                token = token.strip().lower()
                if token:
                    norm_lang_filter.append(token)
    summary = {
        "run_date": run_date,
        "run_dir": str(run_dir),
        "total_input": len(findings),
        "skipped_cursor": 0,
        "skipped_severity": 0,
        "skipped_no_fix": 0,
        "skipped_language": 0,
        "privacy_warnings": 0,
        "written": 0,
        "max_id_seen": last_cursor,
        "dry_run": dry_run,
        "language_filter": norm_lang_filter,
        "files": [],
    }

    processed = 0
    for raw in findings:
        if processed >= max_findings:
            break

        normalized = _normalize_finding(raw)
        finding_id_str = normalized["id"]

        # Try to parse numeric id for cursor comparison
        try:
            finding_id_num = int(finding_id_str)
        except (ValueError, TypeError):
            finding_id_num = 0

        # Cursor skip: already ingested
        if finding_id_num > 0 and finding_id_num <= last_cursor:
            summary["skipped_cursor"] += 1
            continue

        # Severity filter
        if normalized["severity"] not in VALID_SEVERITIES:
            summary["skipped_severity"] += 1
            continue

        # has_public_fix filter (lenient: True if field missing)
        if not normalized.get("has_public_fix", True):
            summary["skipped_no_fix"] += 1
            continue

        # Language filter (Tier-A #3): drop findings whose language doesn't
        # match any of the requested tokens. Substring match, case-insensitive.
        # An empty/missing language field counts as a non-match when a filter
        # is active — corpus mining for Rust must NOT silently ingest unlabeled
        # Solidity findings.
        if norm_lang_filter:
            finding_lang = str(normalized.get("language", "")).strip().lower()
            if not finding_lang or not any(
                tok in finding_lang for tok in norm_lang_filter
            ):
                summary["skipped_language"] += 1
                continue

        # Privacy filter
        raw_json_text = json.dumps(normalized, ensure_ascii=False)
        cleaned_text, priv_warnings = _apply_privacy_filter(raw_json_text, strict=strict_privacy)
        if priv_warnings:
            for w in priv_warnings:
                print(f"[solodit-ingest] {w}", file=sys.stderr)
            summary["privacy_warnings"] += len(priv_warnings)
            if strict_privacy:
                print(
                    "[solodit-ingest] ABORT: --strict-privacy set and privacy pattern found",
                    file=sys.stderr,
                )
                sys.exit(2)
            # Re-parse cleaned JSON
            try:
                normalized = json.loads(cleaned_text)
            except json.JSONDecodeError:
                # Fall back to original with a warning flag
                normalized["_privacy_redacted"] = True

        # Update max id seen
        if finding_id_num > summary["max_id_seen"]:
            summary["max_id_seen"] = finding_id_num

        # Write to disk (skip in dry-run)
        out_filename = f"{finding_id_str}.json"
        out_path = run_dir / out_filename

        if not dry_run:
            final_json = json.dumps(normalized, indent=2, ensure_ascii=False)
            out_path.write_text(final_json)
            summary["files"].append(str(out_path))
        else:
            # Dry-run: emit to stdout as a summary line
            print(
                f"[DRY-RUN] would write: {out_path}  (id={finding_id_str}, "
                f"severity={normalized['severity']}, title={normalized['title'][:60]!r})"
            )
            summary["files"].append(str(out_path))

        summary["written"] += 1
        processed += 1

    # Update cursor
    if not dry_run and cursor_file and summary["max_id_seen"] > last_cursor:
        _save_cursor(
            cursor_file,
            summary["max_id_seen"],
            {
                "run_date": run_date,
                "written": summary["written"],
            },
        )

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--from-json",
        metavar="FILE",
        help="JSON file containing list of findings from MCP query (real mode).",
    )
    p.add_argument(
        "--inject-json",
        metavar="FILE",
        help="Alias for --from-json; used in dry-run self-test contexts.",
    )
    p.add_argument(
        "--max-findings",
        type=int,
        default=100,
        metavar="N",
        help="Maximum findings to process per run (default 100).",
    )
    p.add_argument(
        "--out-dir",
        default="/private/tmp/solodit-ingest",
        metavar="DIR",
        help="Root output directory; findings land under <out-dir>/<date>/<id>.json.",
    )
    p.add_argument(
        "--cursor-file",
        metavar="FILE",
        help="Path to cursor JSON (default: reference/solodit_ingest_cursor.json).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be written but don't write any files.",
    )
    p.add_argument(
        "--strict-privacy",
        action="store_true",
        help="Exit 2 if any privacy pattern is detected (instead of redacting).",
    )
    p.add_argument(
        "--language",
        action="append",
        default=None,
        metavar="LANG",
        help=(
            "Restrict ingest to findings whose 'language' field matches "
            "(case-insensitive substring). Repeat or pass comma-separated "
            "(e.g. --language rust  or  --language rust,go). When set, "
            "findings with empty/missing language are dropped."
        ),
    )
    p.add_argument(
        "--summary-json",
        metavar="FILE",
        help="Write run summary JSON to this file (default: stdout).",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Resolve input file
    input_file = args.from_json or args.inject_json
    if not input_file:
        print(
            "[solodit-ingest] ERROR: provide --from-json or --inject-json with findings data",
            file=sys.stderr,
        )
        return 1

    input_path = Path(input_file)
    if not input_path.exists():
        print(f"[solodit-ingest] ERROR: input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        raw_data = json.loads(input_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"[solodit-ingest] ERROR: failed to parse JSON: {exc}", file=sys.stderr)
        return 1

    # Accept either a list directly or a dict with a 'findings' key
    if isinstance(raw_data, list):
        findings = raw_data
    elif isinstance(raw_data, dict):
        findings = raw_data.get("findings", raw_data.get("results", [raw_data]))
    else:
        print("[solodit-ingest] ERROR: JSON root must be list or dict", file=sys.stderr)
        return 1

    # Resolve paths
    out_dir = Path(args.out_dir)
    cursor_file: Optional[Path] = None
    if args.cursor_file:
        cursor_file = Path(args.cursor_file)
    else:
        # Default: relative to script location (repo root)
        script_dir = Path(__file__).parent.parent
        candidate = script_dir / "reference" / "solodit_ingest_cursor.json"
        if candidate.parent.exists():
            cursor_file = candidate

    summary = ingest(
        findings=findings,
        out_dir=out_dir,
        cursor_file=cursor_file,
        max_findings=args.max_findings,
        strict_privacy=args.strict_privacy,
        dry_run=args.dry_run,
        language_filter=args.language,
    )

    # Output summary
    summary_json_str = json.dumps(summary, indent=2)
    if args.summary_json:
        Path(args.summary_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary_json).write_text(summary_json_str)
        print(f"[solodit-ingest] Summary written to {args.summary_json}")
    else:
        print(summary_json_str)

    mode = "DRY-RUN" if args.dry_run else "REAL"
    print(
        f"[solodit-ingest] {mode} complete: "
        f"{summary['written']} written, "
        f"{summary['skipped_cursor']} cursor-skip, "
        f"{summary['privacy_warnings']} privacy-redactions",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
