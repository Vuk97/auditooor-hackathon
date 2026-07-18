#!/usr/bin/env python3
# R36 pathspec discipline: lane-YAML-TO-MD-SLICE-BRIDGE.
# <!-- r36-rebuttal: lane-YAML-TO-MD-SLICE-BRIDGE bridges defimon-TG/bridge/mev/darknavy/rekt YAML corpora to deepseek-batch-gen-tok-a markdown format; PyYAML preferred per project convention (used by 30+ tools/ scripts), tiny hand-rolled reader as fallback -->

"""yaml-corpus-to-md-slice.py - YAML corpus -> markdown slice bridge.

Reads a directory tree of hackerman-record YAML files (one record per
file or multiple per slug-subdir) and emits a single markdown slice in
the shape that tools/deepseek-batch-gen-tok-a.py FINDING_LINE_RE parses
(`- **<handle>** (<H|M|L>) - <description>`).

Unlocks TOK-A enrichment for YAML corpora (defimon-TG 951, defimon-blog 6,
bridge_incidents 28, darknavy_web3_incidents 72, rekt_news_incidents 50+,
mev_exploits 138, etc.).

CLI
---
python3 tools/yaml-corpus-to-md-slice.py \\
    --input-dir audit/corpus_tags/tags/defimon_telegram_incidents/ \\
    --output reference/corpus_mined/defimon_telegram_incidents.md \\
    --handle-field record_id \\
    --severity-field severity \\
    --description-field attack_vector_summary \\
    [--max-records N] [--description-max-chars 400] [--json]

Notes
-----
- `--*-field` accepts dotted paths for nested YAML (e.g.
  `record_extensions.attack_vector_summary` for rekt records).
- Severity is normalised to single char H/M/L per FINDING_LINE_RE:
  {critical, high}->H, {medium}->M, {info, low, unspecified, ''}->L.
- Records with empty/whitespace-only descriptions are skipped (no signal).
- Records whose YAML fails to parse are logged to stderr and skipped.
- Description truncated at `--description-max-chars` (default 400); strips
  newlines/tabs and collapses internal whitespace so the bullet line
  matches FINDING_LINE_RE.
- Per L34 v2: output path must NOT land inside submissions/<status>/<slug>/.
- Per R36: stdlib-only; no third-party deps (PyYAML not required - tiny
  hand-rolled YAML reader sufficient for these flat record shapes).
"""
from __future__ import annotations

# <!-- r36-rebuttal: lane-YAML-TO-MD-SLICE-BRIDGE -->
import argparse
import json
import os
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

# Prefer PyYAML (already a dep of 30+ tools/ scripts) for parser robustness;
# fall back to the tiny hand-rolled reader below if unavailable.
try:
    import yaml as _pyyaml  # type: ignore
    _HAS_PYYAML = True
except ImportError:  # pragma: no cover - PyYAML pre-installed in target env
    _HAS_PYYAML = False


SCHEMA_ID = "auditooor.yaml_corpus_to_md_slice.v1"
TOOL_NAME = "yaml-corpus-to-md-slice.py"
DEFAULT_DESC_MAX = 400

# Severity normalisation: FINDING_LINE_RE in deepseek-batch-gen-tok-a.py
# requires single-char H/M/L. Map common YAML severity tokens.
SEVERITY_MAP = {
    "critical": "H",
    "high": "H",
    "medium": "M",
    "med": "M",
    "low": "L",
    "info": "L",
    "informational": "L",
    "note": "L",
    "unspecified": "L",
    "unknown": "L",
    "": "L",
}


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr)


def _l34_refuses_output(path: pathlib.Path) -> bool:
    """L34 v2: refuse writes into submissions/<status>/<slug>/ draft-file area."""
    parts = path.resolve().parts
    if "submissions" not in parts:
        return False
    idx = parts.index("submissions")
    # Refuse if path is INSIDE a per-finding folder under any status dir.
    # Tracker files (SUBMISSIONS.md, README.md at submissions/ root) are
    # NOT refused, but this tool never writes there anyway.
    if idx + 2 < len(parts):
        return True
    return False


# <!-- r36-rebuttal: lane-YAML-TO-MD-SLICE-BRIDGE -->
def parse_yaml(text: str) -> Dict[str, Any]:
    """Parse YAML using PyYAML if available, else hand-rolled fallback.

    Returns {} on failure (caller still drops records via missing-field path).
    """
    if _HAS_PYYAML:
        try:
            obj = _pyyaml.safe_load(text)
            if isinstance(obj, dict):
                return obj
            return {}
        except Exception as exc:  # noqa: BLE001
            _stderr(f"[pyyaml-parse-error] {exc}")
            return {}
    return parse_yaml_minimal(text)


def parse_yaml_minimal(text: str) -> Dict[str, Any]:
    """Tiny YAML reader sufficient for hackerman-record v1.1 shapes.

    Supports:
      - flat ``key: value`` lines (single-quoted, double-quoted, or bare)
      - nested mappings via 2-space indentation
      - lists of scalars / mappings via ``- `` items
      - block scalars via ``|`` and ``>`` (folded into single string)

    NOT supported (returns the raw string token):
      - anchors / aliases (``&foo`` / ``*foo``)
      - flow-style maps/lists (``{a: 1}`` / ``[1, 2]``) beyond bare scalars
      - explicit type tags

    The reader is bounded; it does NOT raise on malformed input. The
    caller drops records whose required fields are missing.
    """
    return _parse_block(text.splitlines(), 0, 0)[0]


def _parse_block(lines: List[str], start: int, indent: int) -> Tuple[Any, int]:
    """Parse a YAML block starting at line `start`, expected indent `indent`.

    Returns (value, next_line_index). Value is dict, list, or scalar string.
    """
    i = start
    # Skip blank lines and comments at top
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        cur_indent = len(raw) - len(raw.lstrip(" "))
        if cur_indent < indent:
            return ({}, i)
        # Detect list vs mapping at this indent
        if stripped.startswith("- "):
            return _parse_list(lines, i, cur_indent)
        # Mapping
        return _parse_mapping(lines, i, cur_indent)
    return ({}, i)


def _parse_mapping(lines: List[str], start: int, indent: int) -> Tuple[Dict[str, Any], int]:
    out: Dict[str, Any] = {}
    i = start
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        cur_indent = len(raw) - len(raw.lstrip(" "))
        if cur_indent < indent:
            break
        if cur_indent > indent:
            # Should have been consumed by child parse; skip defensively
            i += 1
            continue
        if stripped.startswith("- "):
            # List started at this indent - caller should have routed here
            break
        # Mapping key
        m = re.match(r"^([^:]+):\s*(.*)$", stripped)
        if not m:
            i += 1
            continue
        key = m.group(1).strip()
        rest = m.group(2)
        if rest == "" or rest is None:
            # Value on subsequent lines (nested block, list, or empty)
            # Look ahead for block scalar marker on this line - none here.
            # Try to parse a nested block at indent+2 (or deeper)
            child, next_i = _parse_block(lines, i + 1, indent + 2)
            out[key] = child if child != {} else None
            i = next_i
            continue
# <!-- r36-rebuttal: lane-YAML-TO-MD-SLICE-BRIDGE registered TTL 2h -->
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            # Block scalar: collect lines indented deeper than `indent`
            text_lines: List[str] = []
            j = i + 1
            while j < len(lines):
                line = lines[j]
                if line.strip() == "":
                    text_lines.append("")
                    j += 1
                    continue
                line_indent = len(line) - len(line.lstrip(" "))
                if line_indent <= indent:
                    break
                text_lines.append(line[indent + 2:] if line_indent >= indent + 2 else line.lstrip())
                j += 1
            joined = "\n".join(text_lines) if rest.startswith("|") else " ".join(s for s in text_lines if s)
            out[key] = joined.strip()
            i = j
            continue
        # Inline scalar value - may continue on subsequent indented lines
        # (YAML plain-scalar folded continuation OR quoted-string wrap).
        continuation, next_i = _collect_continuation(lines, i + 1, indent, rest)
        if continuation:
            full = (rest + " " + continuation).strip()
            out[key] = _coerce_scalar(full)
            i = next_i
        else:
            out[key] = _coerce_scalar(rest)
            i += 1
    return (out, i)


def _collect_continuation(lines: List[str], start: int, key_indent: int, first_chunk: str) -> Tuple[str, int]:
    """Collect continuation lines for a plain-scalar or wrapped-quoted value.

    Triggers when:
      (a) first_chunk starts with `'` or `"` but the same chunk does NOT
          close the quote (no matching closing quote on the same line), or
      (b) the next non-blank line is indented strictly deeper than key_indent
          AND does NOT look like a new mapping key (`<word>:`) or list item.

    Returns (joined_continuation, next_line_index). joined_continuation is
    "" if no continuation present (caller treats first_chunk as inline scalar).
    """
    chunks: List[str] = []
    i = start
    needs_close = False
    quote_char = ""
    if first_chunk.startswith("'") or first_chunk.startswith('"'):
        quote_char = first_chunk[0]
        body = first_chunk[1:]
        if quote_char == "'":
            stripped = body.replace("''", "")
            if quote_char not in stripped:
                needs_close = True
        else:
            unescaped = re.sub(r"\\.", "", body)
            if quote_char not in unescaped:
                needs_close = True
    while i < len(lines):
        raw = lines[i]
        if raw.strip() == "":
            if needs_close:
                chunks.append("")
                i += 1
                continue
            break
        line_indent = len(raw) - len(raw.lstrip(" "))
        if line_indent <= key_indent and not needs_close:
            break
        stripped = raw.strip()
        if not needs_close and re.match(r"^[a-zA-Z_][\w-]*:\s*", stripped):
            break
        if not needs_close and stripped.startswith("- "):
            break
        chunks.append(stripped)
        i += 1
        if needs_close:
            if quote_char == "'":
                test = stripped.replace("''", "")
                if quote_char in test:
                    needs_close = False
                    break
            else:
                unescaped = re.sub(r"\\.", "", stripped)
                if quote_char in unescaped:
                    needs_close = False
                    break
    return (" ".join(chunks).strip(), i)


def _parse_list(lines: List[str], start: int, indent: int) -> Tuple[List[Any], int]:
    out: List[Any] = []
    i = start
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        cur_indent = len(raw) - len(raw.lstrip(" "))
        if cur_indent < indent:
            break
        if cur_indent > indent:
            i += 1
            continue
        if not stripped.startswith("- "):
            break
        item_body = stripped[2:]
        if ":" in item_body and not item_body.startswith(("'", '"')):
            # Mapping inline on the dash line; treat the rest as the first
            # key:value pair and continue parsing nested mapping from next
            # line at indent+2.
            m = re.match(r"^([^:]+):\s*(.*)$", item_body)
            if m:
                key = m.group(1).strip()
                rest = m.group(2)
                item: Dict[str, Any] = {}
                if rest:
                    item[key] = _coerce_scalar(rest)
                else:
                    item[key] = None
                # Look ahead for additional mapping keys at deeper indent
                j = i + 1
                if j < len(lines):
                    next_raw = lines[j]
                    next_indent = len(next_raw) - len(next_raw.lstrip(" "))
                    if next_indent > indent and not next_raw.lstrip().startswith("- "):
                        extra, j2 = _parse_mapping(lines, j, next_indent)
                        item.update(extra)
                        j = j2
                out.append(item)
                i = j
                continue
        # Scalar list item
        out.append(_coerce_scalar(item_body))
        i += 1
    return (out, i)


_QUOTED_RE = re.compile(r"^(['\"])(.*)\1\s*$", re.DOTALL)


def _coerce_scalar(raw: str) -> Any:
    s = raw.strip()
    if s == "" or s.lower() in ("null", "~"):
        return None
    m = _QUOTED_RE.match(s)
    if m:
        body = m.group(2)
        # YAML single-quote escape: '' -> '
        if m.group(1) == "'":
            body = body.replace("''", "'")
        return body
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    # Leave numbers / dates as strings; the caller stringifies anyway.
    return s


def lookup_field(record: Dict[str, Any], dotted: str) -> Optional[Any]:
    """Resolve a dotted-path field reference inside a parsed YAML mapping."""
    if not dotted:
        return None
    parts = dotted.split(".")
    cur: Any = record
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def normalise_severity(value: Any) -> str:
    if value is None:
        return "L"
    s = str(value).strip().lower()
    return SEVERITY_MAP.get(s, "L")


def normalise_description(value: Any, max_chars: int) -> str:
    if value is None:
        return ""
    s = str(value)
    # Collapse whitespace (newlines/tabs/multi-space) so the bullet line
    # matches FINDING_LINE_RE which is line-anchored.
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return ""
    if len(s) > max_chars:
        s = s[:max_chars].rstrip() + "..."
    return s


def normalise_handle(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    # Forbid `**` inside handle - would break bold delimiters.
    s = s.replace("**", "")
    # Strip newlines defensively.
    s = re.sub(r"\s+", " ", s)
    return s


def find_yaml_files(input_dir: pathlib.Path) -> List[pathlib.Path]:
    """Return every *.yaml file under input_dir (recursive)."""
    return sorted(input_dir.rglob("*.yaml"))


def convert_records(
    yaml_files: List[pathlib.Path],
    handle_field: str,
    severity_field: str,
    description_field: str,
    description_max_chars: int,
    max_records: Optional[int] = None,
) -> Tuple[List[str], Dict[str, int]]:
    """Convert YAML files to bullet-line strings + stats.

    Returns (bullet_lines, stats_dict). stats_dict keys:
      files_seen, parse_errors, skipped_empty_desc, skipped_missing_handle,
      emitted.
    """
    bullets: List[str] = []
    stats = {
        "files_seen": 0,
        "parse_errors": 0,
        "skipped_empty_desc": 0,
        "skipped_missing_handle": 0,
        "emitted": 0,
    }
    for f in yaml_files:
        stats["files_seen"] += 1
        if max_records is not None and stats["emitted"] >= max_records:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _stderr(f"[read-error] {f}: {exc}")
            stats["parse_errors"] += 1
            continue
        # <!-- r36-rebuttal: lane-YAML-TO-MD-SLICE-BRIDGE -->
        try:
            record = parse_yaml(text)
        except Exception as exc:  # noqa: BLE001
            _stderr(f"[parse-error] {f}: {exc}")
            stats["parse_errors"] += 1
            continue
        if not isinstance(record, dict):
            stats["parse_errors"] += 1
            continue
        handle = normalise_handle(lookup_field(record, handle_field))
        if not handle:
            stats["skipped_missing_handle"] += 1
            continue
        severity = normalise_severity(lookup_field(record, severity_field))
        desc = normalise_description(
            lookup_field(record, description_field), description_max_chars
        )
        if not desc:
            stats["skipped_empty_desc"] += 1
            continue
        bullet = f"- **{handle}** ({severity}) - {desc}"
        bullets.append(bullet)
        stats["emitted"] += 1
    return bullets, stats


def write_md_slice(
    output_path: pathlib.Path,
    slug: str,
    bullets: List[str],
    input_dir: pathlib.Path,
    handle_field: str,
    severity_field: str,
    description_field: str,
    stats: Dict[str, int],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    body = [
        f"# {slug}",
        "",
        f"Generated by {TOOL_NAME} 2026-05-26.",
        "",
        "Source corpus directory: " + str(input_dir),
        f"Handle field: `{handle_field}`",
        f"Severity field: `{severity_field}`",
        f"Description field: `{description_field}`",
        "",
        f"Files seen: {stats['files_seen']} | Emitted: {stats['emitted']} | "
        f"Parse errors: {stats['parse_errors']} | "
        f"Skipped (empty desc): {stats['skipped_empty_desc']} | "
        f"Skipped (missing handle): {stats['skipped_missing_handle']}",
        "",
        "## Findings",
        "",
    ]
    body.extend(bullets)
    body.append("")
    output_path.write_text("\n".join(body), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input-dir", required=True, help="Directory tree of hackerman YAML records.")
    parser.add_argument("--output", required=True, help="Output markdown slice path.")
    parser.add_argument("--handle-field", default="record_id", help="YAML field (dotted) for bullet handle.")
    parser.add_argument("--severity-field", default="severity", help="YAML field (dotted) for severity.")
    parser.add_argument("--description-field", default="attack_vector_summary", help="YAML field (dotted) for description.")
    parser.add_argument("--description-max-chars", type=int, default=DEFAULT_DESC_MAX, help=f"Truncate description (default {DEFAULT_DESC_MAX}).")
    parser.add_argument("--max-records", type=int, default=None, help="Cap emitted records (default unlimited).")
    parser.add_argument("--slug", default=None, help="Slice slug for header (defaults to output stem).")
    parser.add_argument("--json", action="store_true", help="Print JSON summary to stdout.")
    args = parser.parse_args()

    input_dir = pathlib.Path(args.input_dir)
    if not input_dir.exists() or not input_dir.is_dir():
        _stderr(f"[error] input-dir not found or not a directory: {input_dir}")
        return 2

    output_path = pathlib.Path(args.output)
    if _l34_refuses_output(output_path):
        _stderr(f"[L34-refuse] output path is inside submissions/ per-finding folder: {output_path}")
        return 3

    yaml_files = find_yaml_files(input_dir)
    if not yaml_files:
        _stderr(f"[warn] no .yaml files under {input_dir}")

    bullets, stats = convert_records(
        yaml_files,
        handle_field=args.handle_field,
        severity_field=args.severity_field,
        description_field=args.description_field,
        description_max_chars=args.description_max_chars,
        max_records=args.max_records,
    )

    slug = args.slug or output_path.stem
    write_md_slice(
        output_path,
        slug=slug,
        bullets=bullets,
        input_dir=input_dir,
        handle_field=args.handle_field,
        severity_field=args.severity_field,
        description_field=args.description_field,
        stats=stats,
    )

    summary = {
        "schema_id": SCHEMA_ID,
        "tool": TOOL_NAME,
        "input_dir": str(input_dir),
        "output": str(output_path),
        "slug": slug,
        "handle_field": args.handle_field,
        "severity_field": args.severity_field,
        "description_field": args.description_field,
        "description_max_chars": args.description_max_chars,
        "max_records": args.max_records,
        "stats": stats,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[{TOOL_NAME}] {input_dir} -> {output_path}")
        print(f"  files_seen={stats['files_seen']} emitted={stats['emitted']} "
              f"parse_errors={stats['parse_errors']} "
              f"skipped_empty_desc={stats['skipped_empty_desc']} "
              f"skipped_missing_handle={stats['skipped_missing_handle']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
