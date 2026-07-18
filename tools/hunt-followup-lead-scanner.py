#!/usr/bin/env python3
"""hunt-followup-lead-scanner.py - generic, language-agnostic closer for the
"agent noticed something interesting but ruled it out / suggested a dedicated
follow-up hunt" gap.

WHY THIS EXISTS: per-function hunt agents routinely write two kinds of signal
into their sidecar verdict beyond a flat yes/no/kill:
  1. ``applies_to_target: "maybe"`` (low-confidence, not fully exhausted)
  2. free-text ``notes`` suggesting a targeted follow-up ("worth a dedicated
     hunt pass", "more promising ... target", "flagging for a future batch")
Both were previously only visible if a human (or this orchestrating session)
happened to read the agent's chat summary and remembered to act on it - there
was no mechanized scan + dispatch. Confirmed via dedup preflight (2026-07-05,
SEI engagement) that no existing tool (`anchor-lead-to-hunt-task.py` covers a
DIFFERENT input - OOS commit-mined leads, not hunt-sidecar maybe/notes) closes
this loop.

LANGUAGE-AGNOSTIC BY CONSTRUCTION: ``<ws>/.auditooor/hunt_findings_sidecars/``
uses the same schema (task_id / function_anchor / result-as-JSON-string with
applies_to_target + notes) regardless of whether the workspace is Solidity,
Go/Cosmos, or Rust - the scanner does zero language branching, it just reads
the uniform sidecar shape. Verified against SEI (Go) sidecars during
authoring; the same reader works unmodified for Solidity/Rust workspaces
since none of the fields it touches are language-specific.

WHAT IT DOES:
  1. Read every ``<ws>/.auditooor/hunt_findings_sidecars/*.json``.
  2. Extract (file, function, file_line, notes, applies_to_target) from the
     sidecar's top-level fields plus its ``result`` (a JSON-encoded string in
     every observed shape; parsed defensively - falls back to treating
     ``result`` as already-a-dict, and to "" if neither parses).
  3. Flag a lead if ``applies_to_target == "maybe"`` OR ``notes`` matches the
     FOLLOWUP_RE follow-up-suggestion pattern.
  4. Dedupe by (file, function) - a function flagged by 3 different batches
     is ONE lead, not 3.
  5. Cross-check RESOLUTION: a lead is "resolved" if a LATER sidecar for the
     same (file, function) exists whose task_id/notes marks it as a targeted
     follow-up dispatch (task_id contains "followup" case-insensitive, OR the
     sidecar's own notes says the follow-up was already run). This prevents
     the gate from nagging forever once the operator/orchestrator has acted.
  6. Emit ``<ws>/.auditooor/followup_leads.json`` (summary + per-lead detail)
     and, for every OPEN lead, a scoped task in
     ``<ws>/.auditooor/followup_lead_hunt_tasks.jsonl``
     (schema auditooor.followup_lead_hunt_task.v1) - deliberately
     spirit-compatible with anchor_hunt_task.v1 (task_id / workspace / prompt
     / function anchor) so a future wiring pass can fan both through the same
     dispatcher without a second reader.

CLI: python3 tools/hunt-followup-lead-scanner.py --workspace <ws> [--emit]
Without --emit, prints the summary only (dry run). With --emit, writes both
output files. Never modifies hunt_findings_sidecars/ itself.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_LEADS = "auditooor.followup_leads.v1"
SCHEMA_TASK = "auditooor.followup_lead_hunt_task.v1"
LEADS_FILE = "followup_leads.json"
TASKS_FILE = "followup_lead_hunt_tasks.jsonl"
SIDECAR_DIRNAME = "hunt_findings_sidecars"

# Deliberately broad: "worth a", "follow-up"/"followup", "dedicated hunt",
# "more promising", "deserves", "should be hunted", "flagging ... for" all
# recur verbatim across observed agent notes fields (SEI 2026-07-05 corpus).
FOLLOWUP_RE = re.compile(
    r"(?:worth a (?:dedicated|future|closer)|"
    r"follow[- ]?up (?:hunt|pass|batch|work|target)|"
    r"dedicated hunt|more promising|deserves? (?:a|dedicated)|"
    r"should be hunted|flagging (?:this )?for (?:a )?(?:future|follow)|"
    r"suggested? follow[- ]?up)",
    re.IGNORECASE,
)

_FNAME_RE = re.compile(
    r"^hunt__(?P<file>[^_]+(?:\.[a-zA-Z0-9]+)?)__(?P<fn>[^_]+)__[^_]+__L(?P<line>\d+)__"
)


def _parse_result_field(raw: object) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
    return {}


def _lead_key(sidecar_path: Path, result: dict) -> tuple:
    """Derive a (file, function) dedup key, preferring the filename convention
    (stable, language-agnostic) and falling back to file_line/notes text.

    The fallback MUST NOT duplicate the file path into both slots - that would
    silently collapse distinct leads in the same file (different lines/fns)
    into a single entry, dropping real leads. Use the full "file:line" string
    as the second slot so distinct lines stay distinct even without a parsed
    function name."""
    m = _FNAME_RE.match(sidecar_path.name)
    if m:
        return (m.group("file"), m.group("fn"))
    file_line = str(result.get("file_line") or "")
    if ":" in file_line:
        file_part = file_line.rsplit(":", 1)[0]
        return (file_part, file_line)
    return (sidecar_path.stem, str(sidecar_path))


def _is_followup_filename(sidecar_path: Path) -> bool:
    name = sidecar_path.name.lower()
    return "followup" in name or "follow_up" in name or "follow-up" in name


def _mentions_lead(raw_text: str, file_key: str, fn_key: str) -> bool:
    """Robust, schema-agnostic resolution match: a follow-up sidecar resolves
    a lead if its raw JSON text mentions both the file and the function -
    deliberately NOT tied to a rigid field shape, because real agent output
    for follow-up dispatches turned out more heterogeneous than a fixed
    schema (flat unit/file/verdict/reasoning single-lead files, multi-lead
    combined files with per-row arrays, etc all appeared in practice)."""
    file_base = file_key.rsplit("/", 1)[-1]
    if file_base not in raw_text:
        return False
    if not fn_key or fn_key == file_key:
        return True

    def _word_match(token: str) -> bool:
        if not token:
            return False
        pattern = re.compile(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])")
        return bool(pattern.search(raw_text))

    # word-boundary-ish check so "Add" doesn't match inside "AddPreimage" -
    # underscore is NOT excluded here since sidecar filenames delimit with
    # "__" (e.g. "..._Bar_..."), which would otherwise never match.
    if _word_match(fn_key):
        return True
    # Fallback keys (non-conforming original hunt filenames, e.g. missing the
    # "L<line>" segment) end up as a compound "path:line" or "68-69"-style
    # range string rather than a bare function name - a full-string match is
    # too strict since a follow-up sidecar rarely repeats it verbatim. Retry
    # against every standalone digit-run in the key (line numbers, either
    # side of a hyphenated range).
    for token in re.findall(r"\d+", fn_key):
        if _word_match(token):
            return True
    return False


def scan(ws: Path) -> dict:
    sidecar_dir = ws / ".auditooor" / SIDECAR_DIRNAME
    if not sidecar_dir.is_dir():
        return {
            "schema": SCHEMA_LEADS, "workspace": str(ws),
            "sidecars_scanned": 0, "total_flagged": 0,
            "open": 0, "resolved": 0, "leads": [],
            "note": "no hunt_findings_sidecars dir; nothing to scan (advisory)",
        }

    flagged: dict[tuple, dict] = {}
    followup_paths: list[Path] = []
    scanned = 0
    all_paths = sorted(sidecar_dir.glob("*.json"))

    for path in all_paths:
        scanned += 1
        if _is_followup_filename(path):
            followup_paths.append(path)
            # A followup-named file can ALSO legitimately carry the standard
            # hunt schema (some agents reused it) - still eligible to flag a
            # NEW maybe/note below if it somehow does, but never skip it as a
            # resolution source just because parsing its own schema fails.
        try:
            outer = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        result = _parse_result_field(outer.get("result"))
        if not result:
            continue
        key = _lead_key(path, result)

        applies = str(result.get("applies_to_target") or "").strip().lower()
        notes = str(result.get("notes") or "")
        is_maybe = applies == "maybe"
        has_followup_note = bool(FOLLOWUP_RE.search(notes))
        if not (is_maybe or has_followup_note):
            continue

        if key not in flagged:
            flagged[key] = {
                "file": key[0], "function": key[1],
                "file_line": result.get("file_line"),
                "reason": "maybe-verdict" if is_maybe else "notes-flagged-followup",
                "notes_excerpt": notes[:300],
                "source_sidecar": str(path.relative_to(ws)),
                "task_id": outer.get("task_id"),
            }

    followup_texts = [
        (p, p.name + "\n" + p.read_text(encoding="utf-8", errors="ignore"))
        for p in followup_paths
    ]
    resolved_keys: set = set()
    for key in flagged:
        file_key, fn_key = key
        for p, text in followup_texts:
            if _mentions_lead(text, file_key, fn_key):
                resolved_keys.add(key)
                break

    leads = []
    open_count = 0
    resolved_count = 0
    for key, lead in flagged.items():
        status = "resolved" if key in resolved_keys else "open"
        lead["status"] = status
        leads.append(lead)
        if status == "open":
            open_count += 1
        else:
            resolved_count += 1

    leads.sort(key=lambda r: (r["status"], r["file"], r["function"]))
    return {
        "schema": SCHEMA_LEADS, "workspace": str(ws),
        "sidecars_scanned": scanned, "total_flagged": len(leads),
        "open": open_count, "resolved": resolved_count, "leads": leads,
    }


def _build_task(ws: Path, lead: dict, idx: int) -> dict:
    return {
        "schema": SCHEMA_TASK,
        "task_id": f"followup_lead_{idx:04d}",
        "workspace": ws.name,
        "workspace_path": str(ws),
        "function_anchor": json.dumps({"file": lead["file"], "fn": lead["function"]}),
        "prompt": (
            f"TARGETED FOLLOW-UP HUNT (auto-escalated by hunt-followup-lead-scanner.py): "
            f"a prior residual-hunt batch flagged {lead['file']}:{lead['function']} "
            f"({lead['reason']}) with the note: \"{lead['notes_excerpt']}\". "
            f"Read the real source, resolve the flagged concern to a terminal verdict "
            f"(FINDING or NEGATIVE with cited guard/reason), and write a sidecar whose "
            f"filename contains 'followup' so this lead is marked resolved."
        ),
        "source_sidecar": lead["source_sidecar"],
        "status": "queued",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--emit", action="store_true", help="write output files (else dry-run to stdout)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"[hunt-followup-lead-scanner] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    summary = scan(ws)
    print(f"[hunt-followup-lead-scanner] scanned={summary['sidecars_scanned']} "
          f"flagged={summary['total_flagged']} open={summary['open']} resolved={summary['resolved']}")
    for lead in summary["leads"]:
        if lead["status"] == "open":
            print(f"  OPEN: {lead['file']}:{lead['function']} ({lead['reason']}) <- {lead['source_sidecar']}")

    if not args.emit:
        return 0

    adir = ws / ".auditooor"
    adir.mkdir(parents=True, exist_ok=True)
    (adir / LEADS_FILE).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    open_leads = [l for l in summary["leads"] if l["status"] == "open"]
    tasks_path = adir / TASKS_FILE
    with tasks_path.open("w", encoding="utf-8") as fh:
        for idx, lead in enumerate(open_leads):
            fh.write(json.dumps(_build_task(ws, lead, idx)) + "\n")

    print(f"[hunt-followup-lead-scanner] wrote {LEADS_FILE} + {len(open_leads)} task(s) to {TASKS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
