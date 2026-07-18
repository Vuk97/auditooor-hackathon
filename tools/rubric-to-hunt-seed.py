#!/usr/bin/env python3
# r36: lane AUTO-COVERAGE-CLOSER registered in .auditooor/agent_pathspec.json
"""rubric-to-hunt-seed.py - close the measure->act loop on the RUBRIC axis.

# This tool emits no corpus record.

WHAT IT DOES (the unique gap on the RUBRIC axis):
  ``rubric-coverage-workspace-check.py`` MEASURES which program SEVERITY.md
  impact/severity ROWS have ZERO candidate attempting them (the
  ``uncovered_rows`` list = UNATTEMPTED impact classes). This tool turns that
  measurement into ACTION: for each uncovered rubric row it seeds an
  IMPACT-CLASS HUNT BRIEF naming the class + the in-scope surfaces a hunter
  should read to attempt that impact class. It is the RUBRIC-axis mirror of
  ``coverage-to-hunt-seed.py`` (which seeds the SURFACE axis).

  Where ``coverage-to-hunt-seed`` says "this UNIT was never hunted - go look
  here", this tool says "this IMPACT CLASS was never attempted - go look for a
  <class> bug across these surfaces".

HONESTY IS NON-NEGOTIABLE (R76/R80 discipline):
  A rubric hunt brief is a TARGET, not a finding and not a hypothesis-with-a-
  claim. The brief names the impact class (verbatim from SEVERITY.md) and the
  in-scope surfaces to read; it carries NO ``attack_class`` proven against a
  specific unit, NO severity assertion beyond echoing the rubric tier, and NO
  claim that a bug of that class EXISTS. It asserts only "no candidate yet
  attempts this rubric row".

OUTPUTS:
  - ``<ws>/.auditooor/rubric_hunt_briefs/<brief-id>.md`` - one brief per
    uncovered impact class (human/agent readable).
  - ``<ws>/.auditooor/rubric_hunt_seed_snapshot.json`` - machine snapshot of
    what was seeded (schema auditooor.rubric_to_hunt_seed_snapshot.v1).
  Optionally also UPSERTs a claim-free queue row per uncovered class into
  ``exploit_queue.json`` (``--seed-queue``) so the impact-class axis is driven
  through the SAME downstream find machinery as the surface axis. The queue row
  uses the dedicated ``unattempted-rubric-class`` source namespace so it never
  collides with surface ``unhunted-surface`` rows.

RELATED TOOLS (read these first - this tool fills a distinct gap):
  - tools/rubric-coverage-workspace-check.py: PRODUCES the rubric coverage
    report (the MEASURE half). This tool is the ACT half on the rubric axis.
  - tools/coverage-to-hunt-seed.py: the SURFACE-axis sibling. It seeds one
    target per uncovered UNIT; this tool seeds one brief per uncovered
    rubric ROW. They are orthogonal axes; both feed the same queue.
  - tools/auto-coverage-closer.py: the ORCHESTRATOR that drives both axes in a
    bounded loop and shells this tool for the rubric half.

Deterministic, stdlib-only. Advisory: it does not prove exploitability and
emits TARGETS/BRIEFS only.

Schema (--json verdict): auditooor.rubric_to_hunt_seed.v1
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.rubric_to_hunt_seed.v1"
SNAPSHOT_SCHEMA = "auditooor.rubric_to_hunt_seed_snapshot.v1"
BRIEF_SCHEMA = "auditooor.rubric_hunt_brief.v1"

RUBRIC_REPORT_REL = os.path.join(".auditooor", "rubric_coverage_report.json")
COVERAGE_REPORT_REL = os.path.join(".auditooor", "coverage_report.json")
EXPLOIT_QUEUE_REL = os.path.join(".auditooor", "exploit_queue.json")
EXPLOIT_QUEUE_SCHEMA = "auditooor.exploit_queue.v1"
BRIEFS_DIR_REL = os.path.join(".auditooor", "rubric_hunt_briefs")
SNAPSHOT_REL = os.path.join(".auditooor", "rubric_hunt_seed_snapshot.json")

# The dedup namespace for impact-class rubric target rows. Distinct from
# ``unhunted-surface`` (surface axis) and corpus-hunt / preflight sources.
RUBRIC_CLASS_SOURCE = "unattempted-rubric-class"

# Fields a rubric BRIEF row MUST NOT carry (honest-target invariant): it must
# not assert a proven bug class against a unit or a severity beyond echoing the
# rubric tier label.
FORBIDDEN_CLAIM_FIELDS = (
    "attack_class", "likely_severity", "bug_class", "impact_proven",
    "claim", "suspicion", "vulnerability_class", "finding_class",
)

_RUBRIC_TOOL = Path(__file__).resolve().parent / "rubric-coverage-workspace-check.py"

# Up to this many in-scope source surfaces are listed in each brief.
DEFAULT_SURFACE_HINTS = 12


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=str(path.parent), suffix=".tmp", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(text)
        tmp = tf.name
    os.replace(tmp, str(path))


def _atomic_write_json(path: Path, data: dict) -> None:
    _atomic_write(path, json.dumps(data, indent=2))


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:80] or "row"


def _load_rubric_module() -> Any | None:
    if not _RUBRIC_TOOL.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "_rubric_cov_for_seed", _RUBRIC_TOOL
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


def load_rubric_report(ws_path: Path, rebuild: bool) -> dict:
    """Load the rubric coverage report, rebuilding via the MEASURE tool when
    requested or when the report is missing. Never re-implements the rubric
    parsing - it imports build_report from the canonical tool."""
    report_path = ws_path / RUBRIC_REPORT_REL
    if not rebuild and report_path.is_file():
        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    mod = _load_rubric_module()
    if mod is not None and hasattr(mod, "build_report"):
        try:
            _verdict, report = mod.build_report(ws_path)
            if isinstance(report, dict):
                if not report_path.is_file() or rebuild:
                    try:
                        _atomic_write_json(report_path, report)
                    except OSError:
                        pass
                return report
        except Exception:
            pass
    if report_path.is_file():
        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {}


_SOURCE_EXTS = (
    ".sol", ".vy", ".rs", ".go", ".move", ".cairo", ".nr", ".ts", ".js", ".py",
)
_SKIP_DIR_MARKERS = (
    "/node_modules/", "/.git/", "/target/", "/out/", "/cache/", "/lib/forge-std/",
    "/test/", "/tests/", "/.auditooor/", "/mock", "/__pycache__/",
)


def _surface_hints_from_coverage(ws_path: Path, limit: int) -> list[str]:
    """Best-effort in-scope source surfaces to read for a hunt.

    Prefers the coverage report's uncovered units (the units no hypothesis
    references - exactly where a fresh impact-class hunt should look); falls
    back to a bounded source-tree walk. Honest: these are READ TARGETS, not
    claims that any of them is vulnerable.
    """
    out: list[str] = []
    report_path = ws_path / COVERAGE_REPORT_REL
    if report_path.is_file():
        try:
            rep = json.loads(report_path.read_text(encoding="utf-8"))
            for unit in (rep.get("uncovered_units") or []):
                base = str(unit).split("::", 1)[0]
                if base and base not in out:
                    out.append(base)
                if len(out) >= limit:
                    return out
        except (OSError, ValueError):
            pass
    if out:
        return out[:limit]
    # fallback: bounded source walk
    for dirpath, dirnames, filenames in os.walk(ws_path):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        norm = ("/" + dirpath.replace("\\", "/").strip("/") + "/")
        if any(m in norm for m in _SKIP_DIR_MARKERS):
            continue
        for fn in sorted(filenames):
            if fn.endswith(_SOURCE_EXTS):
                rel = os.path.relpath(os.path.join(dirpath, fn), ws_path)
                out.append(rel)
                if len(out) >= limit:
                    return out
    return out[:limit]


def build_brief(
    ws_name: str,
    row: dict,
    surface_hints: list[str],
    run_id: str = "",
) -> tuple[str, dict, str]:
    """Build (brief_slug, brief_meta, brief_markdown) for ONE uncovered row.

    The brief is claim-free: it names the impact class + the surfaces to read,
    and asks the hunter to attempt that class. It does NOT assert a bug exists.
    """
    tier = str(row.get("tier") or "?")
    rubric_id = str(row.get("rubric_id") or "")
    sentence = str(row.get("sentence") or "").strip()
    slug = _slug((rubric_id + "-" + sentence) if rubric_id else sentence) or _slug(tier)
    row_hash = hashlib.sha256(
        (tier + "|" + rubric_id + "|" + sentence).encode("utf-8", "replace")
    ).hexdigest()[:10]
    brief_id = "RUBRIC-UNATTEMPTED-" + slug[:60] + "-" + row_hash

    meta = {
        "schema": BRIEF_SCHEMA,
        "brief_id": brief_id,
        "workspace": ws_name,
        "tier": tier,
        "rubric_id": rubric_id,
        "rubric_sentence": sentence,
        "source": RUBRIC_CLASS_SOURCE,
        "status": "unattempted",
        "surface_read_targets": surface_hints,
        "generated_at_utc": _utc_now(),
    }
    if run_id:
        meta["run_id"] = run_id
    # honest-target invariant
    for f in FORBIDDEN_CLAIM_FIELDS:
        if f in meta:
            raise AssertionError(
                "honest-target invariant violated: claim field %r in brief" % f
            )

    lines = [
        "<!-- schema: %s -->" % BRIEF_SCHEMA,
        "# Rubric hunt brief: UNATTEMPTED impact class",
        "",
        "- brief_id: `%s`" % brief_id,
        "- workspace: `%s`" % ws_name,
        "- rubric tier: **%s**%s" % (tier, (" (`%s`)" % rubric_id) if rubric_id else ""),
        "- impact class (verbatim from SEVERITY.md):",
        "",
        "  > %s" % (sentence or "(no sentence parsed)"),
        "",
        "## Why this brief exists",
        "",
        "The workspace rubric-coverage check found that NO candidate in the",
        "exploit queue / submissions attempts this impact class. This is the",
        "RUBRIC-axis complement of the surface-coverage gap: the surface may be",
        "fully swept, yet this *impact class* was never tried. Drive a hunt that",
        "specifically attempts a **%s**-class bug." % tier,
        "",
        "## Honesty",
        "",
        "This brief is a TARGET, not a finding. It does NOT claim a bug of this",
        "class exists. It records only that the class is UNATTEMPTED and points a",
        "hunter at the in-scope surfaces below. Any attack_class / severity is",
        "attached downstream only after a real candidate is proven.",
        "",
        "## In-scope surfaces to read (read targets, not claims)",
        "",
    ]
    if surface_hints:
        for s in surface_hints:
            lines.append("- `%s`" % s)
    else:
        lines.append("- (no in-scope source surfaces enumerated; bootstrap source first)")
    lines += [
        "",
        "## Next action",
        "",
        "Dispatch an LLM-depth hunt lane that reads the surfaces above and asks:",
        '"Where, if anywhere, can a **%s** bug matching the impact sentence be' % tier,
        'constructed against this code?" Convert only a source-grounded,',
        "mutation-verified candidate into a draft.",
        "",
    ]
    return slug, meta, "\n".join(lines)


def _empty_exploit_queue(workspace_name: str) -> dict:
    return {
        "schema": EXPLOIT_QUEUE_SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": workspace_name,
        "top_n": 0,
        "total_candidates": 0,
        "context_pack_hash": "",
        "context_pack_id": "",
        "benchmark": {},
        "source_artifacts_consumed": [],
        "queue": [],
    }


def _load_exploit_queue(queue_path: Path, workspace_name: str) -> dict:
    if not queue_path.exists():
        return _empty_exploit_queue(workspace_name)
    try:
        data = json.loads(queue_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return _empty_exploit_queue(workspace_name)
    if not isinstance(data, dict) or not isinstance(data.get("queue"), list):
        return _empty_exploit_queue(workspace_name)
    return data


def _build_queue_row(brief_meta: dict, run_id: str = "") -> dict:
    """Build a claim-free queue row pointing at the impact-class brief."""
    row = {
        "lead_id": brief_meta["brief_id"],
        # NOTE: the title deliberately does NOT echo the rubric impact
        # sentence OR the noun-bearing brief slug. This row is a claim-free
        # TARGET, not a candidate impact; any impact-noun in a blob-read field
        # (title/impact/...) would make the rubric-coverage enumerator
        # self-credit the very row this target says is UNATTEMPTED. The title
        # therefore uses only the tier + the brief_id's trailing content-hash.
        "title": "unattempted-rubric-class target tier=%s ref=%s" % (
            brief_meta["tier"], brief_meta["brief_id"].rsplit("-", 1)[-1]
        ),
        "proof_status": "open",
        "quality_gate_status": "open",
        "workspace": brief_meta["workspace"],
        "source": RUBRIC_CLASS_SOURCE,
        "rubric_tier": brief_meta["tier"],
        "rubric_id": brief_meta.get("rubric_id", ""),
        # rubric_sentence is intentionally NOT stored on the queue row (only in
        # the brief markdown + snapshot) so it can never be read as candidate
        # impact wording and self-credit the rubric row.
        "reason": "unattempted-rubric-class: no candidate attempts this impact class",
        "surface_read_targets": brief_meta.get("surface_read_targets", []),
        "source_refs": [],
        "broken_invariant_ids": [],
    }
    if run_id:
        row["run_id"] = run_id
    for f in FORBIDDEN_CLAIM_FIELDS:
        if f in row:
            raise AssertionError(
                "honest-target invariant violated: claim field %r in queue row" % f
            )
    return row


def seed(
    ws_path: Path,
    *,
    rebuild_report: bool = False,
    dry_run: bool = False,
    seed_queue: bool = False,
    surface_hint_cap: int = DEFAULT_SURFACE_HINTS,
    run_id: str = "",
) -> dict:
    ws_name = ws_path.name
    report = load_rubric_report(ws_path, rebuild=rebuild_report)
    uncovered_rows = list(report.get("uncovered_rows") or [])
    surface_hints = _surface_hints_from_coverage(ws_path, surface_hint_cap)

    briefs_dir = ws_path / BRIEFS_DIR_REL
    seeded: list[dict] = []
    queue_rows_written = 0
    queue_rows_updated = 0

    queue_data = None
    queue_path = ws_path / EXPLOIT_QUEUE_REL
    existing_index: dict[str, int] = {}
    if seed_queue and not dry_run:
        queue_data = _load_exploit_queue(queue_path, ws_name)
        for i, r in enumerate(queue_data.get("queue", [])):
            if isinstance(r, dict):
                existing_index[str(r.get("lead_id") or "")] = i

    for row in uncovered_rows:
        slug, meta, md = build_brief(ws_name, row, surface_hints, run_id=run_id)
        brief_path = briefs_dir / (meta["brief_id"] + ".md")
        if not dry_run:
            _atomic_write(brief_path, md)
        seeded.append({
            "brief_id": meta["brief_id"],
            "tier": meta["tier"],
            "rubric_id": meta["rubric_id"],
            "rubric_sentence": meta["rubric_sentence"],
            "brief_path": str(brief_path),
        })
        if seed_queue and not dry_run and queue_data is not None:
            qrow = _build_queue_row(meta, run_id=run_id)
            lead = qrow["lead_id"]
            if lead in existing_index:
                idx = existing_index[lead]
                prev = queue_data["queue"][idx]
                if str(prev.get("source") or "") == RUBRIC_CLASS_SOURCE:
                    queue_data["queue"][idx] = qrow
                    queue_rows_updated += 1
            else:
                queue_data["queue"].append(qrow)
                existing_index[lead] = len(queue_data["queue"]) - 1
                queue_rows_written += 1

    if seed_queue and not dry_run and queue_data is not None:
        queue_data["total_candidates"] = len(queue_data["queue"])
        queue_data["generated_at_utc"] = _utc_now()
        consumed = queue_data.get("source_artifacts_consumed") or []
        if RUBRIC_CLASS_SOURCE not in consumed:
            consumed.append(RUBRIC_CLASS_SOURCE)
        queue_data["source_artifacts_consumed"] = consumed
        _atomic_write_json(queue_path, queue_data)

    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "generated_at_utc": _utc_now(),
        "run_id": run_id or None,
        "workspace": ws_name,
        "workspace_path": str(ws_path),
        "rubric_report_present": bool(report),
        "total_rows": int(report.get("total_rows", 0)),
        "rows_uncovered": int(report.get("rows_uncovered", len(uncovered_rows))),
        "uncovered_rows_seeded": len(seeded),
        "seed_queue": bool(seed_queue),
        "queue_rows_written": queue_rows_written,
        "queue_rows_updated": queue_rows_updated,
        "briefs_dir": str(briefs_dir),
        "seeded_briefs": seeded,
        "surface_read_targets": surface_hints,
        "dry_run": bool(dry_run),
    }
    if not dry_run:
        _atomic_write_json(ws_path / SNAPSHOT_REL, snapshot)

    verdict = "pass-rubric-seeded" if seeded else "pass-nothing-to-seed"
    return {
        "schema": SCHEMA,
        "verdict": verdict,
        **snapshot,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--workspace-path", required=True,
                   help="Absolute workspace PATH (contains .auditooor/).")
    p.add_argument("--rebuild-report", action="store_true",
                   help="Recompute the rubric coverage report before seeding.")
    p.add_argument("--seed-queue", action="store_true",
                   help="Also UPSERT a claim-free queue row per uncovered class.")
    p.add_argument("--surface-hint-cap", type=int, default=DEFAULT_SURFACE_HINTS)
    p.add_argument("--dry-run", action="store_true",
                   help="Compute briefs but do not write them.")
    p.add_argument("--run-id",
                   default=os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID", ""))
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    ws_path = Path(args.workspace_path)
    if not ws_path.is_absolute():
        ws_path = (Path.cwd() / ws_path).resolve()
    if not ws_path.is_dir():
        print("error: workspace path not found: %s" % ws_path, file=sys.stderr)
        return 2

    result = seed(
        ws_path,
        rebuild_report=args.rebuild_report,
        dry_run=args.dry_run,
        seed_queue=args.seed_queue,
        surface_hint_cap=args.surface_hint_cap,
        run_id=args.run_id,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("%s: seeded %d unattempted-rubric-class briefs "
              "(%d queue rows new / %d refreshed)%s"
              % (result["workspace"], result["uncovered_rows_seeded"],
                 result["queue_rows_written"], result["queue_rows_updated"],
                 " [dry-run]" if result["dry_run"] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
