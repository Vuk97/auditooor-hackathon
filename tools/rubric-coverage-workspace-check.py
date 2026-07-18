#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-L37-RUBRIC-COVERAGE registered in .auditooor/agent_pathspec.json -->
"""rubric-coverage-workspace-check.py - WORKSPACE-LEVEL rubric coverage.

# This tool emits no corpus record.

The SECOND coverage axis (the complement of finite-A's SURFACE coverage).
-----------------------------------------------------------------------
finite-A's ``workspace-coverage-heatmap.py --coverage-report`` answers
"did every in-scope contract/function get a hypothesis?" (the SURFACE
axis). This tool answers the orthogonal question:

    "For the program's SEVERITY.md, did the workspace produce >=1
     candidate for EACH impact/severity ROW?" (the RUBRIC axis).

A complete audit wants BOTH axes:
  - SURFACE% catches "we never looked at 740 contracts".
  - RUBRIC%  catches "we never tried for a freeze-class bug".

Distinction from R52 (``rubric-row-coverage-check.py``)
------------------------------------------------------
R52 is a per-DRAFT gate run at FILING time: it checks that ONE draft's
impact wording verbatim-matches SOME row in SEVERITY.md. This tool is a
WORKSPACE-LEVEL audit-completeness signal run across ALL candidates: it
checks that EVERY rubric row has at least one candidate attempting it.
They are complementary and DO NOT overlap - R52 is "this draft maps to a
row", this is "every row has a draft".

REUSE (tool-duplication preflight, per global memory)
-----------------------------------------------------
This tool REUSES rather than re-implements:
  - ``lib.severity_rubric.find_severity_md(ws)`` + ``parse_tier_rows(text)``
    for SEVERITY.md discovery + canonical tier-row enumeration (the same
    G13 single-source-of-truth R52 uses).
  - ``rubric-row-coverage-check.LOAD_BEARING_NOUNS`` +
    ``_best_noun_match`` + ``_impact_contains_nouns`` for the
    candidate->row HONEST match (the same load-bearing-noun overlap R52
    uses for word-overlap verification). A candidate counts as covering a
    row ONLY when its impact wording contains a load-bearing noun for that
    row's impact class - vague gestures do NOT inflate coverage.

It ADDS (genuinely new, not in any existing tool):
  - Workspace candidate ENUMERATION across exploit_queue.json + submissions
    drafts + per-finding folders + candidate sidecars.
  - The cross-product mapping (candidate x rubric-row) and the AGGREGATE
    coverage report (rows_with_candidate / rows_uncovered / fraction).

``init-rubric-coverage.sh`` produces a HUMAN-maintained checklist
(``RUBRIC_COVERAGE.md``) whose verdict column the operator edits by hand.
This tool produces a MACHINE-computed mapping against real candidates. The
two are complementary: the checklist is the manual ledger, this is the
automatic cross-reference. This tool does NOT consume or write
RUBRIC_COVERAGE.md.

Report schema: auditooor.workspace_rubric_coverage.v1
  {
    "schema": "auditooor.workspace_rubric_coverage.v1",
    "workspace": "<ws>",
    "severity_md": "<path or null>",
    "total_rows": <int>,
    "rows_with_candidate": <int>,
    "rows_uncovered": <int>,
    "rubric_coverage_fraction": <float 0..1>,
    "candidates_scanned": <int>,
    "uncovered_rows": [ {tier, rubric_id, sentence}, ... ],
    "covered_rows": [ {tier, rubric_id, sentence, candidate_count,
                       example_candidates: [..]}, ... ],
    "rows": [ {tier, rubric_id, sentence, covered: bool,
               candidate_count, matched_candidates: [..]}, ... ]
  }

Verdict vocabulary (CLI):
  pass-rubric-coverage-report      report emitted (always; coverage fraction
                                   is informational, low coverage is a WARN
                                   not a fail - mirrors finite-A coverage-map)
  fail-no-severity-md              no SEVERITY.md found for the workspace
  fail-no-rubric-rows              SEVERITY.md present but no parseable rows
  error                            unreadable workspace

Exit codes:
  0 - report emitted (pass-rubric-coverage-report)
  1 - fail-no-severity-md / fail-no-rubric-rows
  2 - error

CLI:
    python3 tools/rubric-coverage-workspace-check.py <workspace> [--json]
        [--write-report] [--severity-md <path>] [--warn-fraction <0..1>]

``--write-report`` writes the report to
``<ws>/.auditooor/rubric_coverage_report.json`` (the artifact L37's
rubric-coverage signal reads).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

# REUSE: G13 single-source-of-truth SEVERITY.md discovery + row parsing.
try:
    from lib import severity_rubric as _sr  # type: ignore
except Exception:  # pragma: no cover - lib optional; degrade gracefully
    _sr = None

# REUSE: R52's load-bearing-noun tables + matching helpers. The R52 module
# file name has a hyphen, so load it via importlib under an importable alias.
import importlib.util as _ilu


def _load_r52_module():
    path = _HERE / "rubric-row-coverage-check.py"
    if not path.is_file():
        return None
    spec = _ilu.spec_from_file_location("_r52_rubric_row_coverage", path)
    if spec is None or spec.loader is None:
        return None
    mod = _ilu.module_from_spec(spec)
    sys.modules["_r52_rubric_row_coverage"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


_R52 = _load_r52_module()

SCHEMA_VERSION = "auditooor.workspace_rubric_coverage.v1"
GATE = "RUBRIC-COVERAGE-WORKSPACE"

_WARN_FRACTION_DEFAULT = 0.50

# Candidate impact-bearing text fields (exploit_queue rows + submission front
# matter). We concatenate every present field into one blob and match against
# the load-bearing nouns. Severity / tier strings are excluded from the impact
# blob (they are not impact WORDING) but are kept for the per-row tier hint.
_CANDIDATE_IMPACT_FIELDS = (
    "title", "impact", "selected_impact", "impact_path", "impact_probe",
    "summary", "description", "listed_impact", "attack_class",
    "truth_table_summary", "impact_claim",
)
_CANDIDATE_QUEUE_KEYS = ("queue", "items", "candidates")

_SUBMISSION_STATUS_DIRS = (
    "staging", "ready", "paste_ready", "filed", "packaged", "held",
    "superseded",
)


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _load_json(p: Path) -> Any:
    txt = _read_text(p)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------
# Candidate enumeration (the ADDED capability)
# --------------------------------------------------------------------------
def _candidate_blob_from_dict(row: dict) -> tuple[str, str]:
    """Return (impact_blob, label) for a candidate dict. The blob is the
    lower-cased concatenation of the impact-bearing fields; the label is a
    short human handle (title or first impact field)."""
    parts: list[str] = []
    label = ""
    for k in _CANDIDATE_IMPACT_FIELDS:
        v = row.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v.strip())
            if not label:
                label = v.strip()
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    parts.append(item.strip())
    return " ".join(parts).lower(), (label[:120] if label else "(unnamed candidate)")


def _enumerate_exploit_queue(ws: Path) -> list[tuple[str, str, dict]]:
    """Return (impact_blob, label, raw) for every exploit_queue candidate."""
    out: list[tuple[str, str, dict]] = []
    for name in ("exploit_queue.json", "exploit_queue.source_mined.json"):
        obj = _load_json(ws / ".auditooor" / name)
        if not isinstance(obj, dict):
            continue
        rows: list = []
        for key in _CANDIDATE_QUEUE_KEYS:
            v = obj.get(key)
            if isinstance(v, list):
                rows = v
                break
        for row in rows:
            if isinstance(row, dict):
                blob, label = _candidate_blob_from_dict(row)
                if blob.strip():
                    out.append((blob, label, row))
    return out


def _submission_impact_blob(md_text: str) -> tuple[str, str]:
    """Extract impact wording from a submission draft. Reuses the same
    extraction shape R52 uses (Impact heading / selected_impact / title)."""
    parts: list[str] = []
    label = ""
    # Title heading
    m = re.search(r"(?im)^#\s+(.+?)\s*$", md_text)
    if m:
        parts.append(m.group(1))
        label = m.group(1).strip()
    # Impact section prose
    mi = re.search(
        r"(?im)^#+\s*(?:impact|selected[_ ]impact|impact[_ ]claim)\b.*?\n(.*?)(?=^#+\s|\Z)",
        md_text, re.DOTALL | re.MULTILINE,
    )
    if mi:
        parts.append(mi.group(1))
    # selected_impact: front-matter line
    ms = re.search(r"(?im)^\s*selected_impact\s*:\s*(.+?)(?:\n|$)", md_text)
    if ms:
        parts.append(ms.group(1))
    return " ".join(parts).lower(), (label[:120] if label else "(submission draft)")


def _enumerate_submissions(ws: Path) -> list[tuple[str, str, dict]]:
    """Return (impact_blob, label, raw) for every submission draft .md.

    Skips status-dir bookkeeping files (SUBMISSIONS.md / README.md) so they
    do not get scored as candidates.
    """
    out: list[tuple[str, str, dict]] = []
    sub = ws / "submissions"
    if not sub.is_dir():
        return out
    skip_stems = {"submissions", "readme", "tracker", "index"}
    try:
        for md in sub.rglob("*.md"):
            if not md.is_file():
                continue
            if md.stem.lower() in skip_stems:
                continue
            txt = _read_text(md)
            if not txt:
                continue
            blob, label = _submission_impact_blob(txt)
            if blob.strip():
                out.append((blob, label, {"path": str(md)}))
    except OSError:
        pass
    return out


def _enumerate_hunt_sidecars(ws: Path) -> list[tuple[str, str, dict]]:
    """Return (impact_blob, label, raw) for every ADJUDICATED finding sidecar in
    hunt_findings_sidecars/.

    r36-rebuttal: lane-rubric-credits-hunt. The candidate enumeration previously
    read only exploit_queue + submissions, so a rubric impact class that the LLM
    hunt rigorously INVESTIGATED and ruled out (a source-cited FP-DEFENDED /
    NEGATIVE sidecar) was scored UNATTEMPTED - the gate measures "did the
    workspace produce >=1 candidate ATTEMPTING each row", and an adjudicated
    hunt verdict IS an attempt (the same principle by which function-coverage
    credits an FP-DEFENDED rule-out). Only sidecars carrying a real verdict /
    disposition / applies_to_target are included (raw un-adjudicated seeds are
    NOT counted); the downstream load-bearing-noun match still gates which row a
    sidecar can cover, so this cannot spuriously cover an unrelated row.
    """
    out: list[tuple[str, str, dict]] = []
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    if not d.is_dir():
        return out
    try:
        for p in sorted(d.glob("*.json")):
            if not p.is_file() or p.name.startswith("."):
                continue
            obj = _load_json(p)
            if not isinstance(obj, dict):
                continue
            # The spawn-worker Sonnet residual schema nests the verdict +
            # rubric_class inside a dict ``result``; the MIMO schema nests it in
            # a JSON-string ``result``. Surface the nested dict so the
            # adjudication gate + blob see applies_to_target / rubric_class /
            # candidate_finding regardless of which schema produced the sidecar.
            # Without this, result-as-dict sidecars are SKIPPED at the gate
            # below AND their rubric_class never enters the blob -> a fully
            # hunted impact class scores 0 candidates (false-red).
            # r36-rebuttal: lane L37-RUBRIC-DICT-RESULT-FIX registered in .auditooor/agent_pathspec.json
            r = obj.get("result")
            inner = r if isinstance(r, dict) else None
            # adjudicated only: must carry a verdict-bearing signal (top-level OR
            # nested in a dict ``result``).
            def _sig(d):
                return any(
                    str((d or {}).get(k) or "").strip()
                    for k in ("verdict", "disposition", "applies_to_target", "kill_verdict")
                )
            if not (_sig(obj) or _sig(inner)):
                continue
            parts: list[str] = []
            for k in ("title", "hypothesis", "analysis", "candidate_finding",
                      "rubric_class", "cluster", "impact_path", "severity_if_true"):
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    parts.append(v)
            if inner is not None:
                for k in ("rubric_class", "candidate_finding", "analysis",
                          "impact_path", "defending_lines", "attacker_path",
                          "hypothesis", "severity_if_true"):
                    v = inner.get(k)
                    if isinstance(v, str) and v.strip():
                        parts.append(v)
            elif isinstance(r, str) and r.strip():
                parts.append(r[:1200])
            blob = " ".join(parts).lower()
            if not blob.strip():
                continue
            label = str(obj.get("title") or obj.get("candidate_id") or p.stem)[:120]
            out.append((blob, label, {"path": str(p), "verdict": obj.get("verdict")}))
    except OSError:
        pass
    return out


def _enumerate_residual_verdicts(ws: Path) -> list[tuple[str, str, dict]]:
    """Return (impact_blob, label, raw) for every ADJUDICATED residual /
    unhunted terminal verdict in residual_hunt_verdicts.json +
    unhunted_terminal_verdicts.json.

    Same principle as _enumerate_hunt_sidecars: an impact class that the audit
    rigorously ATTEMPTED and ruled out via a source-cited residual verdict IS a
    candidate attempting that row. Before this, a refuted Theft-of-gas / Griefing
    residual verdict (reason e.g. "Theft-of-gas (Medium) impact class WAS
    attempted across the 217 per-fn hunt ...") sat in residual_hunt_verdicts.json
    UNCREDITED by the candidate enumeration, so a genuinely-attempted row scored
    0 candidates (a serving-join false-red: real evidence on disk keyed by a
    reader that did not look there). Only verdict-bearing entries are included,
    and the downstream load-bearing-noun match still gates which row each verdict
    can cover - a refuted verdict cannot spuriously cover an unrelated row.
    """
    out: list[tuple[str, str, dict]] = []
    for name in ("residual_hunt_verdicts.json", "unhunted_terminal_verdicts.json"):
        p = ws / ".auditooor" / name
        if not p.is_file():
            continue
        obj = _load_json(p)
        verdicts = obj.get("verdicts") if isinstance(obj, dict) else (obj if isinstance(obj, list) else [])
        if not isinstance(verdicts, list):
            continue
        for v in verdicts:
            if not isinstance(v, dict):
                continue
            # adjudicated only: must carry a verdict / disposition signal.
            if not any(str(v.get(k) or "").strip() for k in ("verdict", "disposition", "kill_verdict")):
                continue
            parts: list[str] = []
            for k in ("reason", "lead_id", "function", "rubric_class", "impact",
                      "impact_class", "title", "file_line"):
                val = v.get(k)
                if isinstance(val, str) and val.strip():
                    parts.append(val)
            blob = " ".join(parts).lower()
            if not blob.strip():
                continue
            label = str(v.get("lead_id") or v.get("function") or name)[:120]
            out.append((blob, label, {"source": name, "verdict": v.get("verdict")}))
    return out


def enumerate_candidates(ws: Path) -> list[tuple[str, str, dict]]:
    """All workspace candidates: exploit-queue rows + submission drafts +
    adjudicated hunt sidecars + adjudicated residual/unhunted terminal verdicts.

    De-duplicated by (label, blob[:200]) so a candidate present in both the
    queue and a draft is not double-counted.
    """
    seen: set = set()
    out: list[tuple[str, str, dict]] = []
    for blob, label, raw in (
        _enumerate_exploit_queue(ws)
        + _enumerate_submissions(ws)
        + _enumerate_hunt_sidecars(ws)
        + _enumerate_residual_verdicts(ws)
    ):
        key = (label, blob[:200])
        if key in seen:
            continue
        seen.add(key)
        out.append((blob, label, raw))
    return out


# --------------------------------------------------------------------------
# HONEST candidate -> rubric-row matching (REUSED from R52)
# --------------------------------------------------------------------------
def _candidate_covers_row(impact_blob: str, row_sentence: str) -> bool:
    """True iff the candidate's impact wording HONESTLY maps to the rubric
    row, using R52's load-bearing-noun overlap. A row counts as covered only
    when the candidate's impact wording contains a load-bearing noun for the
    row's impact class. A vague gesture does NOT count.

    Reuses R52's ``_best_noun_match`` (find the impact class the row belongs
    to) and ``_impact_contains_nouns`` (does the candidate contain a noun for
    that class). When R52 is unavailable OR the row's class is not in the
    load-bearing table, fall back to a conservative token-overlap rule so the
    tool degrades but never fabricates a match.
    """
    sentence = (row_sentence or "").strip()
    if not sentence:
        return False
    if _R52 is not None:
        extra = {}
        try:
            extra = _R52._load_env_noun_overrides()
        except Exception:
            extra = {}
        matched_class, required_nouns = _R52._best_noun_match(
            sentence, impact_blob, extra,
        )
        if matched_class is not None and required_nouns:
            found = _R52._impact_contains_nouns(impact_blob, required_nouns)
            return bool(found)
        # Row's impact class is not in the load-bearing table: fall through to
        # the conservative token-overlap rule below (do NOT auto-pass).
    return _conservative_token_overlap(impact_blob, sentence)


_STOP = {
    "the", "a", "an", "of", "in", "to", "and", "or", "with", "that", "is",
    "for", "at", "by", "on", "as", "its", "not", "be", "from", "this",
    "than", "greater", "equal", "respective", "affecting", "projects",
    "excluding", "related", "attack", "vector",
}


def _content_tokens(text: str) -> list[str]:
    return [
        t.lower() for t in re.findall(r"\b[a-zA-Z]{3,}\b", text)
        if t.lower() not in _STOP
    ]


def _conservative_token_overlap(impact_blob: str, row_sentence: str) -> bool:
    """Conservative fallback when the row's impact class is not in the
    load-bearing-noun table. Requires the candidate to contain a MAJORITY of
    the row's distinctive content tokens (so a one-word incidental overlap
    does NOT inflate coverage). This is intentionally strict - the honest-
    match guard prefers a false NEGATIVE (row marked uncovered) over a false
    POSITIVE (row marked covered on a vague gesture)."""
    row_tokens = set(_content_tokens(row_sentence))
    if not row_tokens:
        return False
    blob_lower = impact_blob.lower()
    hits = sum(1 for t in row_tokens if t in blob_lower)
    # Require >=60% of the row's distinctive tokens AND at least 2 hits.
    return hits >= max(2, int(len(row_tokens) * 0.6 + 0.999))


# --------------------------------------------------------------------------
# Report assembly
# --------------------------------------------------------------------------
def _find_severity_md(ws: Path, override: Path | None) -> Path | None:
    if override is not None and override.is_file():
        return override
    if _sr is not None:
        hit = _sr.find_severity_md(ws)
        if hit is not None:
            return hit
    # minimal fallback if lib unavailable
    for name in ("SEVERITY.md", "severity.md", "Severity.md"):
        c = ws / name
        if c.is_file():
            return c
    return None


def _parse_rows(severity_md_text: str) -> list[dict]:
    """Return canonical rubric rows as dicts. Reuses parse_tier_rows. Drops
    rows with an EMPTY sentence (a tier heading with no listed impact cannot
    be 'covered' by any candidate; counting it would only deflate coverage
    against an unscoreable row)."""
    if _sr is None:
        return []
    rows = _sr.parse_tier_rows(severity_md_text)
    out: list[dict] = []
    for r in rows:
        sent = (r.sentence or "").strip()
        if not sent:
            continue
        out.append({"tier": r.tier, "rubric_id": r.rubric_id, "sentence": sent})
    return out


def build_report(
    ws: Path,
    *,
    severity_md_override: Path | None = None,
    warn_fraction: float = _WARN_FRACTION_DEFAULT,
) -> tuple[str, dict]:
    """Return (verdict, report-dict)."""
    sev_path = _find_severity_md(ws, severity_md_override)
    base: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "workspace": str(ws),
        "severity_md": str(sev_path) if sev_path else None,
        "warn_fraction": warn_fraction,
    }
    if sev_path is None:
        return "fail-no-severity-md", {
            **base, "verdict": "fail-no-severity-md",
            "reason": "no SEVERITY.md found for the workspace; cannot compute "
                      "rubric coverage",
            "total_rows": 0, "rows_with_candidate": 0, "rows_uncovered": 0,
            "rubric_coverage_fraction": 0.0, "candidates_scanned": 0,
            "uncovered_rows": [], "covered_rows": [], "rows": [],
        }
    sev_text = _read_text(sev_path) or ""
    rubric_rows = _parse_rows(sev_text)
    if not rubric_rows:
        return "fail-no-rubric-rows", {
            **base, "verdict": "fail-no-rubric-rows",
            "reason": f"SEVERITY.md present ({sev_path}) but no parseable rubric "
                      "rows with a listed-impact sentence",
            "total_rows": 0, "rows_with_candidate": 0, "rows_uncovered": 0,
            "rubric_coverage_fraction": 0.0, "candidates_scanned": 0,
            "uncovered_rows": [], "covered_rows": [], "rows": [],
        }

    candidates = enumerate_candidates(ws)

    rows_out: list[dict] = []
    covered_rows: list[dict] = []
    uncovered_rows: list[dict] = []
    for row in rubric_rows:
        matched_labels: list[str] = []
        for blob, label, _raw in candidates:
            if _candidate_covers_row(blob, row["sentence"]):
                matched_labels.append(label)
        covered = len(matched_labels) > 0
        row_entry = {
            "tier": row["tier"],
            "rubric_id": row["rubric_id"],
            "sentence": row["sentence"],
            "covered": covered,
            "candidate_count": len(matched_labels),
            "matched_candidates": matched_labels[:5],
        }
        rows_out.append(row_entry)
        if covered:
            covered_rows.append({
                "tier": row["tier"], "rubric_id": row["rubric_id"],
                "sentence": row["sentence"],
                "candidate_count": len(matched_labels),
                "example_candidates": matched_labels[:3],
            })
        else:
            uncovered_rows.append({
                "tier": row["tier"], "rubric_id": row["rubric_id"],
                "sentence": row["sentence"],
            })

    total_rows = len(rubric_rows)
    rows_with_candidate = len(covered_rows)
    rows_uncovered = len(uncovered_rows)
    frac = round(rows_with_candidate / total_rows, 6) if total_rows else 0.0
    low = frac < warn_fraction

    report = {
        **base,
        "verdict": "pass-rubric-coverage-report",
        "total_rows": total_rows,
        "rows_with_candidate": rows_with_candidate,
        "rows_uncovered": rows_uncovered,
        "rubric_coverage_fraction": frac,
        "candidates_scanned": len(candidates),
        "low_coverage_warn": low,
        "uncovered_rows": uncovered_rows,
        "covered_rows": covered_rows,
        "rows": rows_out,
        "reason": (
            f"{rows_with_candidate}/{total_rows} rubric rows have >=1 candidate "
            f"(rubric_coverage_fraction={frac}); "
            f"{rows_uncovered} impact class(es) UNATTEMPTED"
            + (f"  [WARN: low rubric coverage < {warn_fraction}]" if low else "")
        ),
    }
    return "pass-rubric-coverage-report", report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("workspace", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--write-report", action="store_true",
                   help="Write the report to "
                        "<ws>/.auditooor/rubric_coverage_report.json")
    p.add_argument("--severity-md", type=Path, default=None,
                   help="Override the SEVERITY.md path")
    p.add_argument("--warn-fraction", type=float,
                   default=_WARN_FRACTION_DEFAULT,
                   help="Coverage fraction below which a non-fatal WARN fires")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(str(args.workspace))).resolve()
    if not ws.exists() or not ws.is_dir():
        payload = {
            "schema": SCHEMA_VERSION, "gate": GATE, "workspace": str(ws),
            "verdict": "error",
            "reason": "workspace path does not exist or is not a directory",
        }
        print(json.dumps(payload, indent=2))
        return 2

    verdict, report = build_report(
        ws,
        severity_md_override=args.severity_md,
        warn_fraction=args.warn_fraction,
    )

    if args.write_report and verdict == "pass-rubric-coverage-report":
        out = ws / ".auditooor" / "rubric_coverage_report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["written_to"] = str(out)

    print(json.dumps(report, indent=2))
    if not args.json:
        sys.stderr.write(f"[{GATE}] {report.get('verdict')}: "
                         f"{report.get('reason', '')}\n")
        if report.get("uncovered_rows"):
            sys.stderr.write(f"[{GATE}] UNCOVERED rubric rows:\n")
            for r in report["uncovered_rows"]:
                rid = f"{r['rubric_id']} " if r['rubric_id'] else ""
                sys.stderr.write(f"  - [{r['tier']}] {rid}{r['sentence'][:90]}\n")

    return 0 if verdict == "pass-rubric-coverage-report" else 1


if __name__ == "__main__":
    raise SystemExit(main())
