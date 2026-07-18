#!/usr/bin/env python3
"""dispatch-receipt-check.py - B5 dispatch receipt enforcement.

Validates that High/Critical worker packets which MENTION MCP/Hackerman/vault
callables carry a machine-readable receipt block with ALL required fields:
  - context_pack_id
  - context_pack_hash
  - callable  (the callable name)
  - args_hash
  - artifact_path

A bare mention of a callable name WITHOUT a matching receipt is a FAIL for
High/Critical packets and a WARN for lower-severity packets.

Background (plan item B5, 2026-05-19):
  Worker prompts must carry machine-readable MCP receipt evidence for the
  actual recall calls used. Literal mentions of callable names are not enough.
  Task-dispatch lint and closeout fail High/Critical worker packets that mention
  MCP/Hackerman but lack receipts.

Usage:
  python3 tools/dispatch-receipt-check.py <packet-file> [--severity HIGH]
  python3 tools/dispatch-receipt-check.py --workspace <dir>
  python3 tools/dispatch-receipt-check.py <packet-file> --json
  python3 tools/dispatch-receipt-check.py <packet-file> --strict

Exit codes:
  0  all checks PASS (or only warnings)
  1  --strict and at least one High/Critical packet lacks receipt; or bad input
  2  bad arguments / unreadable file

Schema: auditooor.dispatch_receipt_check.v1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Schema / version
# ---------------------------------------------------------------------------
SCHEMA = "auditooor.dispatch_receipt_check.v1"

PASS = "pass"
WARN = "warn"
FAIL = "fail"
ERROR = "error"

# ---------------------------------------------------------------------------
# Patterns: what counts as an MCP/Hackerman/vault mention in a packet body
# ---------------------------------------------------------------------------

# Callable-name patterns - detect literal mentions of MCP callable names
MCP_CALLABLE_MENTION_PATTERNS: list[str] = [
    # vault_ prefixed callables (most common)
    r"\bvault_[a-z][a-z0-9_]+\b",
    # hackerman_ prefixed callables
    r"\bhackerman_[a-z][a-z0-9_]+\b",
    # mcp__ prefixed callables (MCP tool form)
    r"\bmcp__[a-z][a-z0-9_]+__[a-z][a-z0-9_]+\b",
    # Narrative references to the MCP server
    r"\bvault[-_\s]+mcp\b",
    r"\bvault[-_\s]+resume[-_\s]+context\b",
    r"\bvault[-_\s]+exploit[-_\s]+context\b",
    r"\bvault[-_\s]+knowledge[-_\s]+gap[-_\s]+context\b",
    r"\bvault[-_\s]+harness[-_\s]+context\b",
    r"\bvault[-_\s]+dispatch[-_\s]+context\b",
    # Generic MCP recall language that implies a callable was used
    r"\bMCP[-_\s]+recall\b",
    r"\bMCP[-_\s]+first\b",
    r"\bMCP[-_\s]+backed\b",
    r"\bHackerman\b",
    r"\bhackerman\b",
    r"\b--call\s+vault_[a-z][a-z0-9_]+",
    r"\bcontext_pack_id\b",  # mentioning the receipt field name implies MCP was used
]

# Receipt block detection: look for structured JSON/fenced blocks that contain
# all five required fields. We scan for inline JSON objects and fenced blocks.
RECEIPT_REQUIRED_FIELDS = (
    "context_pack_id",
    "context_pack_hash",
    "callable",
    "args_hash",
    "artifact_path",
)

# High/Critical severity patterns
HIGH_CRITICAL_RE = re.compile(r"\b(high|critical)\b", re.IGNORECASE)

# Severity extraction from common packet formats
SEVERITY_PATTERNS: list[str] = [
    r"(?im)^[-*]?\s*severity\s*[:\|]\s*[`\"']?\s*(high|critical|medium|low|info(?:rmational)?)\b",
    r"(?im)^severity\s*=\s*[`\"']?\s*(high|critical|medium|low|info(?:rmational)?)\b",
    r'"severity"\s*:\s*"(high|critical|medium|low|info(?:rmational)?)"',
    r"(?im)\bseverity_tier\s*[:\|=]\s*[`\"']?\s*(high|critical|medium|low)\b",
    r"(?im)\bproposed_severity\s*[:\|=]\s*[`\"']?\s*(high|critical|medium|low)\b",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ReceiptBlock:
    """A parsed receipt block found in a packet."""
    context_pack_id: str = ""
    context_pack_hash: str = ""
    callable: str = ""
    args_hash: str = ""
    artifact_path: str = ""
    source: str = ""  # "inline_json", "fenced_block", "sidecar_file"
    raw: str = ""

    def missing_fields(self) -> list[str]:
        missing = []
        for f in RECEIPT_REQUIRED_FIELDS:
            val = getattr(self, f, "")
            if not val or not str(val).strip():
                missing.append(f)
        return missing

    def is_complete(self) -> bool:
        return len(self.missing_fields()) == 0


@dataclass
class PacketCheckResult:
    """Result for a single packet file."""
    file: str
    verdict: str           # pass / warn / fail / error
    severity: str          # detected severity or "unknown"
    is_high_critical: bool
    has_mcp_mention: bool
    has_receipt: bool
    receipt_complete: bool
    missing_fields: list[str] = field(default_factory=list)
    mcp_mention_sample: str = ""
    receipt_source: str = ""
    message: str = ""


@dataclass
class Report:
    schema: str
    summary: dict
    results: list[dict]


# ---------------------------------------------------------------------------
# Core detection functions
# ---------------------------------------------------------------------------

def _has_any_pattern(text: str, patterns: list[str]) -> tuple[bool, str]:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return True, m.group(0)
    return False, ""


def detect_severity(text: str, explicit_severity: str = "") -> str:
    """Return the severity string found in the packet, or 'unknown'."""
    if explicit_severity:
        return explicit_severity.strip().lower()
    for pat in SEVERITY_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip().lower()
    return "unknown"


def is_high_critical(severity: str) -> bool:
    return severity.lower() in ("high", "critical")


def detect_mcp_mention(text: str) -> tuple[bool, str]:
    """Detect whether the packet mentions any MCP callable/hackerman/vault context."""
    return _has_any_pattern(text, MCP_CALLABLE_MENTION_PATTERNS)


def _try_parse_receipt_from_dict(obj: Any, source: str, raw: str) -> Optional[ReceiptBlock]:
    """Attempt to build a ReceiptBlock from a dict (parsed JSON object)."""
    if not isinstance(obj, dict):
        return None
    # Must contain at least one receipt field to be considered a receipt
    has_any = any(f in obj for f in RECEIPT_REQUIRED_FIELDS)
    if not has_any:
        return None
    rb = ReceiptBlock(source=source, raw=raw[:200])
    rb.context_pack_id = str(obj.get("context_pack_id") or "").strip()
    rb.context_pack_hash = str(obj.get("context_pack_hash") or "").strip()
    rb.callable = str(obj.get("callable") or "").strip()
    rb.args_hash = str(obj.get("args_hash") or "").strip()
    rb.artifact_path = str(obj.get("artifact_path") or "").strip()
    return rb


def _scan_inline_json_objects(text: str) -> list[ReceiptBlock]:
    """Find all {...} blocks in text and try to parse receipt fields from them."""
    receipts = []
    # Match JSON-like {...} blocks (non-greedy, single-level to avoid recursion)
    for m in re.finditer(r"\{[^{}]*\}", text, re.DOTALL):
        chunk = m.group(0)
        try:
            obj = json.loads(chunk)
        except (json.JSONDecodeError, ValueError):
            continue
        rb = _try_parse_receipt_from_dict(obj, "inline_json", chunk)
        if rb is not None:
            receipts.append(rb)
    # Also try larger nested blocks (two levels deep)
    for m in re.finditer(r"\{[^{}]*\{[^{}]*\}[^{}]*\}", text, re.DOTALL):
        chunk = m.group(0)
        try:
            obj = json.loads(chunk)
        except (json.JSONDecodeError, ValueError):
            continue
        rb = _try_parse_receipt_from_dict(obj, "inline_json_nested", chunk)
        if rb is not None:
            receipts.append(rb)
    return receipts


def _scan_fenced_blocks(text: str) -> list[ReceiptBlock]:
    """Find ```json ... ``` or ``` ... ``` fenced blocks and parse receipt fields."""
    receipts = []
    # Match fenced code blocks
    fence_re = re.compile(
        r"```(?:json)?\s*\n(.*?)```",
        re.DOTALL | re.IGNORECASE,
    )
    for m in fence_re.finditer(text):
        body = m.group(1).strip()
        # Try JSON parse first
        try:
            obj = json.loads(body)
            rb = _try_parse_receipt_from_dict(obj, "fenced_json", body)
            if rb is not None:
                receipts.append(rb)
                continue
        except (json.JSONDecodeError, ValueError):
            pass
        # Try YAML-like key: value parsing for the 5 required fields
        rb = _parse_kv_block(body, "fenced_block")
        if rb is not None:
            receipts.append(rb)
    return receipts


def _parse_kv_block(body: str, source: str) -> Optional[ReceiptBlock]:
    """Parse a key: value block for receipt fields (YAML-like)."""
    fields: dict[str, str] = {}
    kv_re = re.compile(
        r"^\s*[\"']?(" + "|".join(re.escape(f) for f in RECEIPT_REQUIRED_FIELDS) + r")[\"']?\s*[:\|=]\s*(.+)$",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in kv_re.finditer(body):
        key = m.group(1).strip().lower()
        val = m.group(2).strip().strip("\"'`")
        fields[key] = val
    if not fields:
        return None
    rb = ReceiptBlock(source=source, raw=body[:200])
    rb.context_pack_id = fields.get("context_pack_id", "")
    rb.context_pack_hash = fields.get("context_pack_hash", "")
    rb.callable = fields.get("callable", "")
    rb.args_hash = fields.get("args_hash", "")
    rb.artifact_path = fields.get("artifact_path", "")
    return rb


def _scan_prose_kv(text: str) -> list[ReceiptBlock]:
    """Scan prose (bullet lists, labeled lines) for receipt fields."""
    rb = _parse_kv_block(text, "prose_kv")
    if rb is not None:
        return [rb]
    return []


def find_receipt_blocks(text: str) -> list[ReceiptBlock]:
    """Find all receipt blocks in packet text. Returns list (may be empty).

    Priority order: fenced blocks first (they are the canonical structured form),
    then inline JSON objects found outside fences, then prose key-value.
    """
    receipts: list[ReceiptBlock] = []

    # 1. Fenced blocks (highest priority - explicitly delimited)
    fenced = _scan_fenced_blocks(text)
    receipts.extend(fenced)

    # 2. Strip fenced block content from text so inline scanner doesn't re-detect it
    text_no_fences = re.sub(r"```(?:json)?\s*\n.*?```", "", text, flags=re.DOTALL | re.IGNORECASE)
    inline = _scan_inline_json_objects(text_no_fences)
    receipts.extend(inline)

    # 3. Prose key-value only if nothing found yet
    if not receipts:
        receipts.extend(_scan_prose_kv(text))
    return receipts


def _load_sidecar_receipt(packet_path: Path) -> Optional[ReceiptBlock]:
    """Check for a sidecar .receipt.json file next to the packet."""
    # Build sidecar paths by appending to stem (avoids Path.with_suffix multi-dot issues)
    base = packet_path.parent / packet_path.name
    candidates = [
        packet_path.parent / (packet_path.stem + ".receipt.json"),
        packet_path.parent / (packet_path.stem + ".mcp_receipt.json"),
        Path(str(base) + ".receipt.json"),
        Path(str(base) + "-receipt.json"),
    ]
    for sidecar in candidates:
        if sidecar.is_file():
            try:
                obj = json.loads(sidecar.read_text(encoding="utf-8"))
                rb = _try_parse_receipt_from_dict(obj, "sidecar_file", str(sidecar))
                if rb is not None:
                    rb.artifact_path = rb.artifact_path or str(sidecar)
                    return rb
            except (OSError, json.JSONDecodeError):
                pass
    return None


# ---------------------------------------------------------------------------
# Per-file check
# ---------------------------------------------------------------------------

def check_packet_file(
    packet_path: Path,
    explicit_severity: str = "",
    strict: bool = False,
) -> PacketCheckResult:
    """Check a single worker-packet file."""
    if not packet_path.exists():
        return PacketCheckResult(
            file=str(packet_path),
            verdict=ERROR,
            severity="unknown",
            is_high_critical=False,
            has_mcp_mention=False,
            has_receipt=False,
            receipt_complete=False,
            message=f"File not found: {packet_path}",
        )
    try:
        text = packet_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return PacketCheckResult(
            file=str(packet_path),
            verdict=ERROR,
            severity="unknown",
            is_high_critical=False,
            has_mcp_mention=False,
            has_receipt=False,
            receipt_complete=False,
            message=f"Cannot read file: {exc}",
        )

    severity = detect_severity(text, explicit_severity)
    high_crit = is_high_critical(severity)
    has_mcp, mcp_sample = detect_mcp_mention(text)

    if not has_mcp:
        return PacketCheckResult(
            file=str(packet_path),
            verdict=PASS,
            severity=severity,
            is_high_critical=high_crit,
            has_mcp_mention=False,
            has_receipt=False,
            receipt_complete=False,
            message="no_mcp_claim: packet makes no MCP/Hackerman/vault callable mention",
        )

    # MCP mention detected - look for receipt blocks
    receipts = find_receipt_blocks(text)
    sidecar = _load_sidecar_receipt(packet_path)
    if sidecar is not None:
        receipts.append(sidecar)

    # Find the best (most complete) receipt
    best: Optional[ReceiptBlock] = None
    for rb in receipts:
        if best is None or len(rb.missing_fields()) < len(best.missing_fields()):
            best = rb

    has_receipt = best is not None
    receipt_complete = has_receipt and best.is_complete()
    missing = best.missing_fields() if best else list(RECEIPT_REQUIRED_FIELDS)
    receipt_source = best.source if best else ""

    if receipt_complete:
        return PacketCheckResult(
            file=str(packet_path),
            verdict=PASS,
            severity=severity,
            is_high_critical=high_crit,
            has_mcp_mention=True,
            has_receipt=True,
            receipt_complete=True,
            missing_fields=[],
            mcp_mention_sample=mcp_sample[:120],
            receipt_source=receipt_source,
            message="receipt_present_and_complete: all 5 required fields found",
        )

    # Receipt missing or incomplete
    if high_crit:
        verdict = FAIL
        msg = (
            f"High/Critical packet mentions MCP/vault but lacks complete machine-readable receipt. "
            f"Missing fields: {missing}. "
            f"Add a JSON block or fenced block with: "
            f"context_pack_id, context_pack_hash, callable, args_hash, artifact_path."
        )
    else:
        verdict = WARN
        msg = (
            f"Packet (severity={severity}) mentions MCP/vault but lacks complete receipt. "
            f"Missing fields: {missing}. "
            f"Not a hard failure for non-High/Critical packets, but add receipt for completeness."
        )

    return PacketCheckResult(
        file=str(packet_path),
        verdict=verdict,
        severity=severity,
        is_high_critical=high_crit,
        has_mcp_mention=True,
        has_receipt=has_receipt,
        receipt_complete=False,
        missing_fields=missing,
        mcp_mention_sample=mcp_sample[:120],
        receipt_source=receipt_source,
        message=msg,
    )


def check_packet_text(
    text: str,
    label: str = "<text>",
    explicit_severity: str = "",
) -> PacketCheckResult:
    """Check a worker-packet provided as a string (for programmatic use)."""
    severity = detect_severity(text, explicit_severity)
    high_crit = is_high_critical(severity)
    has_mcp, mcp_sample = detect_mcp_mention(text)

    if not has_mcp:
        return PacketCheckResult(
            file=label,
            verdict=PASS,
            severity=severity,
            is_high_critical=high_crit,
            has_mcp_mention=False,
            has_receipt=False,
            receipt_complete=False,
            message="no_mcp_claim: packet makes no MCP/Hackerman/vault callable mention",
        )

    receipts = find_receipt_blocks(text)
    best: Optional[ReceiptBlock] = None
    for rb in receipts:
        if best is None or len(rb.missing_fields()) < len(best.missing_fields()):
            best = rb

    has_receipt = best is not None
    receipt_complete = has_receipt and best.is_complete()
    missing = best.missing_fields() if best else list(RECEIPT_REQUIRED_FIELDS)
    receipt_source = best.source if best else ""

    if receipt_complete:
        return PacketCheckResult(
            file=label,
            verdict=PASS,
            severity=severity,
            is_high_critical=high_crit,
            has_mcp_mention=True,
            has_receipt=True,
            receipt_complete=True,
            missing_fields=[],
            mcp_mention_sample=mcp_sample[:120],
            receipt_source=receipt_source,
            message="receipt_present_and_complete: all 5 required fields found",
        )

    if high_crit:
        verdict = FAIL
        msg = (
            f"High/Critical packet mentions MCP/vault but lacks complete machine-readable receipt. "
            f"Missing fields: {missing}. "
            f"Add a JSON block or fenced block with: "
            f"context_pack_id, context_pack_hash, callable, args_hash, artifact_path."
        )
    else:
        verdict = WARN
        msg = (
            f"Packet (severity={severity}) mentions MCP/vault but lacks complete receipt. "
            f"Missing fields: {missing}. "
            f"Not a hard failure for non-High/Critical packets, but add receipt for completeness."
        )

    return PacketCheckResult(
        file=label,
        verdict=verdict,
        severity=severity,
        is_high_critical=high_crit,
        has_mcp_mention=True,
        has_receipt=has_receipt,
        receipt_complete=False,
        missing_fields=missing,
        mcp_mention_sample=mcp_sample[:120],
        receipt_source=receipt_source,
        message=msg,
    )


# ---------------------------------------------------------------------------
# Workspace scan
# ---------------------------------------------------------------------------

WORKSPACE_PACKET_GLOBS = (
    "*.md",
    "*.json",
    "*.txt",
    "*.yaml",
    "*.yml",
    "agent_outputs/**/*.md",
    "agent_outputs/**/*.json",
    ".auditooor/worker_packets/*.md",
    ".auditooor/worker_packets/*.json",
)


def check_workspace(
    workspace: Path,
    strict: bool = False,
) -> list[PacketCheckResult]:
    """Scan a workspace directory for worker packets."""
    results = []
    seen: set[Path] = set()
    for pattern in WORKSPACE_PACKET_GLOBS:
        for p in workspace.glob(pattern):
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            results.append(check_packet_file(p, strict=strict))
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _result_to_dict(r: PacketCheckResult) -> dict:
    return {
        "file": r.file,
        "verdict": r.verdict,
        "severity": r.severity,
        "is_high_critical": r.is_high_critical,
        "has_mcp_mention": r.has_mcp_mention,
        "has_receipt": r.has_receipt,
        "receipt_complete": r.receipt_complete,
        "missing_fields": r.missing_fields,
        "mcp_mention_sample": r.mcp_mention_sample,
        "receipt_source": r.receipt_source,
        "message": r.message,
    }


def build_json_report(results: list[PacketCheckResult]) -> dict:
    total = len(results)
    passes = sum(1 for r in results if r.verdict == PASS)
    warns = sum(1 for r in results if r.verdict == WARN)
    fails = sum(1 for r in results if r.verdict == FAIL)
    errors = sum(1 for r in results if r.verdict == ERROR)
    return {
        "schema": SCHEMA,
        "summary": {
            "total": total,
            "pass": passes,
            "warn": warns,
            "fail": fails,
            "error": errors,
            "overall": FAIL if fails > 0 else (WARN if warns > 0 else PASS),
        },
        "results": [_result_to_dict(r) for r in results],
    }


def print_human_report(results: list[PacketCheckResult], out=sys.stdout) -> None:
    report = build_json_report(results)
    summary = report["summary"]
    print(f"dispatch-receipt-check ({SCHEMA})", file=out)
    print(
        f"  total={summary['total']}  pass={summary['pass']}  "
        f"warn={summary['warn']}  fail={summary['fail']}  error={summary['error']}",
        file=out,
    )
    print(f"  overall: {summary['overall'].upper()}", file=out)
    for r in results:
        icon = {"pass": "OK", "warn": "WARN", "fail": "FAIL", "error": "ERR"}[r.verdict]
        print(f"\n[{icon}] {r.file}", file=out)
        print(f"      severity={r.severity}  high_crit={r.is_high_critical}", file=out)
        print(f"      has_mcp_mention={r.has_mcp_mention}  has_receipt={r.has_receipt}  "
              f"receipt_complete={r.receipt_complete}", file=out)
        if r.missing_fields:
            print(f"      missing_fields={r.missing_fields}", file=out)
        if r.mcp_mention_sample:
            print(f"      mcp_mention_sample: {r.mcp_mention_sample!r}", file=out)
        print(f"      message: {r.message}", file=out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="B5 dispatch receipt enforcement - check worker packets for MCP receipt blocks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("packet", nargs="?", type=Path, help="Worker packet file to check")
    group.add_argument("--workspace", type=Path, help="Scan all worker packets in workspace dir")

    parser.add_argument(
        "--severity",
        default="",
        help="Override severity (high/critical/medium/low). If not given, extracted from packet.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_out",
        help="Emit JSON report to stdout (schema: auditooor.dispatch_receipt_check.v1)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any High/Critical packet mentions MCP but lacks receipt",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.workspace is not None:
        ws = args.workspace.expanduser().resolve()
        if not ws.is_dir():
            print(f"ERROR: --workspace {ws} is not a directory", file=sys.stderr)
            return 2
        results = check_workspace(ws, strict=args.strict)
        if not results:
            # No packets found - emit a trivial pass
            results = [PacketCheckResult(
                file=str(ws),
                verdict=PASS,
                severity="unknown",
                is_high_critical=False,
                has_mcp_mention=False,
                has_receipt=False,
                receipt_complete=False,
                message="no_packets_found: workspace contained no scannable packet files",
            )]
    else:
        packet_path = args.packet.expanduser().resolve()
        results = [check_packet_file(packet_path, explicit_severity=args.severity, strict=args.strict)]

    if args.json_out:
        report = build_json_report(results)
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print_human_report(results)

    if args.strict:
        fails = sum(1 for r in results if r.verdict == FAIL)
        errors = sum(1 for r in results if r.verdict == ERROR)
        return 1 if (fails > 0 or errors > 0) else 0
    # Non-strict: exit 1 only for ERROR (bad input), not for FAIL/WARN
    errors = sum(1 for r in results if r.verdict == ERROR)
    return 1 if errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
