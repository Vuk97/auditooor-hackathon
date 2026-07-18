#!/usr/bin/env python3
"""Rule-injection sync tool.

Reads ~/.claude/CLAUDE.md hard-rules block + do-not list, parses each rule
into a structured record, and emits a synced digest into pre-defined sync
targets.

Schema: auditooor.codified_rules_digest.v1

Usage:
  python3 tools/rule-injection-sync.py --sync          # write all targets
  python3 tools/rule-injection-sync.py --check         # validate sync targets up-to-date
  python3 tools/rule-injection-sync.py --diff          # show what would change
  python3 tools/rule-injection-sync.py --rule R43 --json  # single rule lookup

Exit codes:
  0 - success / up-to-date
  1 - drift detected (--check) or rule not found (--rule)
  2 - input error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.codified_rules_digest.v1"
TOOL_VERSION = "1.0.0"

DEFAULT_CLAUDE_MD = Path.home() / ".claude" / "CLAUDE.md"

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]

SYNC_TARGETS = {
    "json": WORKSPACE_ROOT / "reference" / "codified_rules_digest.json",
    "md": WORKSPACE_ROOT / "reference" / "codified_rules_digest.md",
    "claude_session": Path.home() / ".claude" / "projects" / "auditooor_codified_rules.md",
}


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _extract_rule_id_from_header(header: str) -> str | None:
    """Parse rule ID from headers like:
    ## Hard rule: foo (Rule 28)
    ### Rule 19 -- real-execution-path-required ...
    ### Rule 25 - defense-in-depth ... (em-dash or hyphen)
    ### L30 -- Missing-protection ...
    ### L31 -- Pre-filing ...
    ### L32 / Rule 18 -- In-process-vs-node-level ...
    """
    # Normalise em-dash / en-dash to hyphen for easier matching
    h = header.replace("—", "--").replace("–", "-")

    # ## Hard rule: ... (Rule NNN)
    m = re.search(r"\(Rule\s+(\d+)\)", h, re.IGNORECASE)
    if m:
        return f"R{m.group(1)}"
    # ### L32 / Rule NNN -- ...  (slash variant; pick up the Rule number)
    m = re.search(r"/\s*Rule\s+(\d+)\s*[-]+", h)
    if m:
        return f"R{m.group(1)}"
    # ### Rule NNN -- ... or ### Rule NNN - ...
    m = re.search(r"\bRule\s+(\d+)\s*[-]+", h)
    if m:
        return f"R{m.group(1)}"
    # ### LNN -- ...
    m = re.match(r"#+\s+(L\d+)\s*[/-]", h)
    if m:
        return m.group(1).upper()
    return None


def _extract_name_from_header(header: str) -> str:
    """Extract short descriptive name from the rule header."""
    # ## Hard rule: <name> (Rule NNN)
    m = re.match(r"#+\s+Hard rule:\s+([^(]+)", header)
    if m:
        name = m.group(1).strip().rstrip()
        return name
    # ### Rule NNN -- <name> ...
    m = re.search(r"Rule\s+\d+\s*[-]+\s+(.+?)(?:\s+\(|$)", header)
    if m:
        return m.group(1).strip()
    # ### LNN -- <name>
    m = re.match(r"#+\s+L\d+\s*[-]+\s+(.+?)(?:\s+\(|$)", header)
    if m:
        return m.group(1).strip()
    return header.strip("#").strip()


def _extract_section(text: str, label: str) -> str:
    """Extract the value after a label like 'Mechanical enforcement:' in text."""
    pattern = re.compile(rf"(?:^|\n){re.escape(label)}\s*(.+?)(?=\n\n|\n[A-Z]|\Z)", re.DOTALL)
    m = pattern.search(text)
    if m:
        return m.group(1).strip()
    return ""


def _extract_override_marker(text: str) -> str:
    """Find override marker like `<!-- rNN-rebuttal: ... -->` or rebuttal lines."""
    m = re.search(r"`<!--\s*(r\d+-rebuttal|l\d+-rebuttal)[^`]*-->`", text, re.IGNORECASE)
    if m:
        return m.group(0).strip("`")
    m = re.search(r"Override(?:\s+marker)?:\s*`([^`]+)`", text)
    if m:
        return m.group(1)
    m = re.search(r"Override:\s*`([^`]+)`", text)
    if m:
        return m.group(1)
    return ""


def _extract_empirical_anchor(text: str) -> str:
    """Extract the first empirical anchor sentence."""
    m = re.search(r"Empirical anchor[^:]*:\s*(.+?)(?:\.\s|\n\n)", text, re.DOTALL)
    if m:
        raw = m.group(1).strip().replace("\n", " ")
        # Collapse multiple spaces
        return re.sub(r"  +", " ", raw)[:300]
    return ""


def _extract_mechanical_gate(text: str) -> str:
    """Extract tool + check number from Mechanical enforcement / Hard gate lines."""
    # Look for Check #NN pattern
    check_m = re.search(r"Check\s+#(\d+)\s+\(`([^`]+)`\)", text)
    tool_m = re.search(r"`(tools/[^`]+\.py)`", text)
    parts = []
    if tool_m:
        parts.append(tool_m.group(1))
    if check_m:
        parts.append(f"Check #{check_m.group(1)} ({check_m.group(2)})")
    if parts:
        return "; ".join(parts)
    # Fallback: look for Hard gate line
    m = re.search(r"Hard gate[^:]*:\s*`([^`]+)`", text)
    if m:
        return m.group(1)
    return ""


def _extract_interacts_with(text: str) -> list[str]:
    """Extract list of other rule IDs from 'Interacts with' line."""
    m = re.search(r"Interacts with\s+(.+?)(?:\n|$)", text)
    if not m:
        return []
    chunk = m.group(1)
    ids = re.findall(r"\b(R\d+|L\d+)\b", chunk, re.IGNORECASE)
    return sorted(set(i.upper() for i in ids))


def _extract_severity_scope(text: str) -> str:
    """Infer severity scope from rule text."""
    text_l = text.lower()
    if "medium+" in text_l or "medium and above" in text_l:
        return "MEDIUM+"
    if "high+" in text_l or "high and above" in text_l or "high/critical" in text_l:
        return "HIGH+"
    if "critical" in text_l and "high" not in text_l:
        return "CRITICAL"
    if "low" in text_l:
        return "any"
    return "any"


def _extract_trigger_phrase(text: str) -> str:
    """Extract first 1-sentence summary from rule body."""
    # Take the first non-empty sentence from the block body
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
    if not lines:
        return ""
    first = lines[0]
    # Truncate at first sentence boundary
    m = re.match(r"(.+?[.!?])\s", first + " ")
    if m:
        return m.group(1)[:200]
    return first[:200]


# ---------------------------------------------------------------------------
# Do-not list parsing
# ---------------------------------------------------------------------------

def _parse_do_not_list(text: str) -> list[dict[str, Any]]:
    """Parse numbered do-not list entries into mini-records."""
    m = re.search(r'### Hard "do not" list.*?\n(.*?)(?=\n##|\Z)', text, re.DOTALL)
    if not m:
        return []
    block = m.group(1)
    records: list[dict[str, Any]] = []
    pattern = re.compile(r"^(\d+)\.\s+(\(([LR]\d+)\)\s+)?(.+?)(?=\n\d+\.|\Z)", re.DOTALL | re.MULTILINE)
    for hit in pattern.finditer(block):
        idx = int(hit.group(1))
        rule_ref = hit.group(3) or ""
        body = hit.group(4).strip().replace("\n", " ")
        body = re.sub(r"  +", " ", body)
        rec: dict[str, Any] = {
            "rule_id": f"DONT-{idx:02d}",
            "linked_rule": rule_ref.upper() if rule_ref else None,
            "trigger_phrase": body[:300],
            "source": "do-not-list",
        }
        records.append(rec)
    return records


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_claude_md(source: Path) -> dict[str, Any]:
    """Parse CLAUDE.md and return a digest dict."""
    text = source.read_text(encoding="utf-8")
    digest_hash = hashlib.sha256(text.encode()).hexdigest()

    rules: list[dict[str, Any]] = []

    # Split into sections by header boundaries (## or ###)
    # We collect every ## Hard rule: ... and ### Rule NNN / ### LNN section.
    # Accept both hyphen-minus (-) and em-dash (U+2014 —) as separators
    # because CLAUDE.md uses em-dashes in Wave-13 rule headings (R18-R27).
    # Also accept the "### L32 / Rule 18 --" slash-variant.
    header_pattern = re.compile(
        r"^(#{2,3}\s+(?:Hard rule:|Rule\s+\d+\s*(?:--+|—+|–+)|L\d+\s*(?:--+|—+|–+|/)).+)$",
        re.MULTILINE,
    )
    matches = list(header_pattern.finditer(text))

    for i, m in enumerate(matches):
        header = m.group(1)
        rule_id = _extract_rule_id_from_header(header)
        if not rule_id:
            continue

        # Block is from end of header to start of next match
        block_start = m.end()
        block_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[block_start:block_end]

        record: dict[str, Any] = {
            "rule_id": rule_id,
            "name": _extract_name_from_header(header),
            "severity_scope": _extract_severity_scope(block),
            "trigger_phrase": _extract_trigger_phrase(block),
            "mechanical_gate": _extract_mechanical_gate(block),
            "override_marker": _extract_override_marker(block),
            "empirical_anchor": _extract_empirical_anchor(block),
            "interacts_with": _extract_interacts_with(block),
            "source": "hard-rule-block",
        }
        rules.append(record)

    # Deduplicate by rule_id (take first occurrence)
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for r in rules:
        if r["rule_id"] not in seen:
            seen.add(r["rule_id"])
            deduped.append(r)

    # Add do-not list entries
    dont_records = _parse_do_not_list(text)

    return {
        "schema": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "source_file": str(source),
        "source_sha256": digest_hash,
        "rule_count": len(deduped),
        "do_not_count": len(dont_records),
        "rules": deduped,
        "do_not_list": dont_records,
    }


# ---------------------------------------------------------------------------
# Emit helpers
# ---------------------------------------------------------------------------

def _emit_json(digest: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(digest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _emit_md(digest: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        f"# Codified Rules Digest",
        f"",
        f"Schema: `{digest['schema']}`  ",
        f"Source: `{digest['source_file']}`  ",
        f"SHA256: `{digest['source_sha256'][:16]}...`  ",
        f"Rules: {digest['rule_count']}  |  Do-not entries: {digest['do_not_count']}",
        f"",
        f"---",
        f"",
    ]
    for r in digest["rules"]:
        lines += [
            f"## {r['rule_id']} - {r['name']}",
            f"",
            f"**Severity scope**: `{r['severity_scope']}`  ",
            f"**Trigger**: {r['trigger_phrase']}",
            f"",
        ]
        if r["mechanical_gate"]:
            lines.append(f"**Gate**: `{r['mechanical_gate']}`  ")
        if r["override_marker"]:
            lines.append(f"**Override**: `{r['override_marker']}`  ")
        if r["empirical_anchor"]:
            lines.append(f"**Anchor**: {r['empirical_anchor']}")
        if r["interacts_with"]:
            lines.append(f"**Interacts with**: {', '.join(r['interacts_with'])}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Do-Not List",
        "",
    ]
    for d in digest["do_not_list"]:
        linked = f" [{d['linked_rule']}]" if d["linked_rule"] else ""
        lines.append(f"- **{d['rule_id']}**{linked}: {d['trigger_phrase'][:200]}")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def _emit_claude_session(digest: dict[str, Any], path: Path) -> None:
    """Emit a compact version for auto-inclusion in Claude sessions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "# Auditooor Codified Rules - Auto-Included Session Context",
        "",
        f"Generated from `{digest['source_file']}`  ",
        f"SHA256: `{digest['source_sha256'][:16]}...`  ",
        f"{digest['rule_count']} rules | {digest['do_not_count']} do-not entries",
        "",
        "## Quick Reference: Rules",
        "",
    ]
    for r in digest["rules"]:
        gate_str = f" Gate: {r['mechanical_gate']}." if r["mechanical_gate"] else ""
        override_str = f" Override: `{r['override_marker']}`." if r["override_marker"] else ""
        lines.append(
            f"- **{r['rule_id']}** ({r['severity_scope']}): {r['name']}."
            f"{gate_str}{override_str}"
        )
    lines += [
        "",
        "## Do-Not List (abbreviated)",
        "",
    ]
    for d in digest["do_not_list"]:
        linked = f"[{d['linked_rule']}] " if d["linked_rule"] else ""
        lines.append(f"- {d['rule_id']} {linked}- {d['trigger_phrase'][:120]}")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Fingerprint helper (for drift detection)
# ---------------------------------------------------------------------------

def _digest_fingerprint(digest: dict[str, Any]) -> str:
    """Create a stable fingerprint of the parsed digest for drift comparison."""
    # Include rule_ids + source hash; ignore field ordering noise
    stable = {
        "source_sha256": digest["source_sha256"],
        "rule_ids": sorted(r["rule_id"] for r in digest["rules"]),
        "dont_count": len(digest["do_not_list"]),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def _load_existing_digest(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# CLI actions
# ---------------------------------------------------------------------------

def do_sync(digest: dict[str, Any], targets: list[str] | None = None) -> None:
    target_map = {
        "json": (_emit_json, SYNC_TARGETS["json"]),
        "md": (_emit_md, SYNC_TARGETS["md"]),
        "claude_session": (_emit_claude_session, SYNC_TARGETS["claude_session"]),
    }
    chosen = targets if targets else list(target_map.keys())
    for key in chosen:
        if key not in target_map:
            print(f"[rule-injection-sync] WARN: unknown target {key!r}; skipping", file=sys.stderr)
            continue
        fn, path = target_map[key]
        fn(digest, path)
        print(f"[rule-injection-sync] wrote {path}")


def do_check(digest: dict[str, Any]) -> int:
    """Return 0 if all targets are up-to-date, 1 if drift detected."""
    current_fp = _digest_fingerprint(digest)
    existing = _load_existing_digest(SYNC_TARGETS["json"])
    if existing is None:
        print(f"[rule-injection-sync] DRIFT: {SYNC_TARGETS['json']} does not exist")
        print(f"[rule-injection-sync] Run --sync to create targets.")
        return 1
    existing_fp = _digest_fingerprint(existing)
    if current_fp != existing_fp:
        new_ids = {r["rule_id"] for r in digest["rules"]}
        old_ids = {r["rule_id"] for r in existing.get("rules", [])}
        added = sorted(new_ids - old_ids)
        removed = sorted(old_ids - new_ids)
        changed_hash = existing.get("source_sha256", "") != digest["source_sha256"]
        print(f"[rule-injection-sync] DRIFT detected:")
        if added:
            print(f"  added rule IDs: {added}")
        if removed:
            print(f"  removed rule IDs: {removed}")
        if changed_hash:
            print(f"  source SHA256 changed ({existing.get('source_sha256','?')[:16]}... -> {digest['source_sha256'][:16]}...)")
        print(f"[rule-injection-sync] Run --sync to update targets.")
        return 1
    print(f"[rule-injection-sync] OK: sync targets are up-to-date ({digest['rule_count']} rules)")
    return 0


def do_diff(digest: dict[str, Any]) -> None:
    existing = _load_existing_digest(SYNC_TARGETS["json"])
    if existing is None:
        print(f"[rule-injection-sync] Target {SYNC_TARGETS['json']} does not exist.")
        print(f"Would write {len(digest['rules'])} rules + {len(digest['do_not_list'])} do-not entries.")
        return
    new_ids = {r["rule_id"] for r in digest["rules"]}
    old_ids = {r["rule_id"] for r in existing.get("rules", [])}
    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)
    if not added and not removed:
        print("[rule-injection-sync] No changes.")
    if added:
        print(f"Rules to add: {added}")
    if removed:
        print(f"Rules to remove: {removed}")


def do_rule_lookup(digest: dict[str, Any], rule_id: str, as_json: bool) -> int:
    rid = rule_id.upper()
    for r in digest["rules"]:
        if r["rule_id"] == rid:
            if as_json:
                print(json.dumps(r, indent=2, ensure_ascii=False))
            else:
                print(f"{r['rule_id']}: {r['name']}")
                for k, v in r.items():
                    if k not in ("rule_id", "name"):
                        print(f"  {k}: {v}")
            return 0
    print(f"[rule-injection-sync] rule {rid!r} not found", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Public API (for tests)
# ---------------------------------------------------------------------------

def run(
    source: Path | None = None,
    mode: str = "check",
    targets: list[str] | None = None,
    rule_id: str | None = None,
    as_json: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Public entry point used by tests.

    Returns (exit_code, digest).
    """
    src = source or DEFAULT_CLAUDE_MD
    if not src.exists():
        return 2, {"error": f"source not found: {src}"}
    digest = parse_claude_md(src)

    if mode == "sync":
        do_sync(digest, targets)
        return 0, digest
    elif mode == "check":
        rc = do_check(digest)
        return rc, digest
    elif mode == "diff":
        do_diff(digest)
        return 0, digest
    elif mode == "rule":
        if not rule_id:
            return 2, {"error": "rule_id required for --rule mode"}
        rc = do_rule_lookup(digest, rule_id, as_json)
        return rc, digest
    else:
        return 2, {"error": f"unknown mode: {mode}"}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rule-injection sync: parse CLAUDE.md hard rules and emit digest targets."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_CLAUDE_MD,
        help="Path to CLAUDE.md (default: ~/.claude/CLAUDE.md)",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Write all sync targets",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate sync targets are up-to-date (exit 1 if drift)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Show what would change without writing",
    )
    parser.add_argument(
        "--rule",
        metavar="RULE_ID",
        help="Return just one rule's digest (e.g. R43)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output as JSON (with --rule)",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        choices=["json", "md", "claude_session"],
        help="Limit which sync targets to write (default: all)",
    )

    args = parser.parse_args(argv)

    if not args.source.exists():
        print(f"[rule-injection-sync] ERROR: source not found: {args.source}", file=sys.stderr)
        return 2

    digest = parse_claude_md(args.source)

    if args.rule:
        return do_rule_lookup(digest, args.rule, args.as_json)

    if args.sync:
        do_sync(digest, args.targets)
        return 0

    if args.diff:
        do_diff(digest)
        return 0

    if args.check or (not args.sync and not args.diff and not args.rule):
        return do_check(digest)

    return 0


if __name__ == "__main__":
    sys.exit(main())
