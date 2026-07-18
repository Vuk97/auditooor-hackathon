#!/usr/bin/env python3
"""ENFORCEMENT gate (pre-submit-check Check #136): make a HIGH+ finding ACCOUNTABLE
to the data-flow slice when its impact maps onto an UNGUARDED value-flow path.

Wiring 49d (companion to the VICE-VERSA on-demand backward slice in
tools/dataflow-slice.py --from-sink). The data-flow engine
(tools/dataflow-slice.py) already enumerates, for the whole workspace, the
backward DefUsePaths from a tainted source to each value-moving sink and flags
each one `unguarded`. Today a hunter can FIND such an unguarded value flow yet
write a HIGH+ submission that never grounds the finding in it. This gate closes
that: a HIGH+ submission whose impact LANDS on an unguarded DefUsePath
(by file:line) must either

  (a) cite a real DefUsePath id from <ws>/.auditooor/dataflow_paths.jsonl
      (e.g. `path_id: dfp-0123` / `DefUsePath dfp-0123` / `svp-0007`), OR
  (b) carry a closure verdict (it cites the closure correction / a guard that
      dominates - i.e. it acknowledges the path is actually guarded), OR
  (c) carry an honest walk-back marker `<!-- dataflow-rebuttal: <reason> -->`.

It is ADDITIVE and fail-closed ONLY for path-relevant HIGH+. Everything else
PASSES, never blocking honest work:
  - workspace has NO slice (or only a degrade record)         -> PASS (no-op)
  - finding is below HIGH                                       -> PASS
  - finding's impact does NOT map onto any unguarded path      -> PASS (prose-only
                                                                  / non-path)
  - finding cites a DefUsePath id / closure verdict / rebuttal -> PASS

R80 honesty: degraded slice rows are skipped (they are advisory-empty). The gate
only ever consults real, validated, non-degraded, UNGUARDED slice rows.

Verdicts (stdout, --json):
  pass-no-slice            no usable dataflow_paths.jsonl in the workspace
  pass-below-high          severity < High (gate is HIGH+ only)
  pass-not-path-relevant   no unguarded path overlaps the draft's cited file:lines
  pass-cited               draft cites a real DefUsePath id (or closure verdict)
  ok-rebuttal              draft carries <!-- dataflow-rebuttal: ... -->
  fail-uncited-unguarded-path  draft maps onto an unguarded path but cites nothing
  error                    unexpected failure (advisory; rc=2)

rc: 0 PASS/ok-rebuttal, 1 FAIL (uncited), 2 error/advisory.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# reuse the canonical schema reader (skip_degraded, validate) - EXTEND not rebuild
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import dataflow_schema as dfs  # noqa: E402
except Exception:  # pragma: no cover - import guard
    dfs = None


_HIGH_PLUS = {"high", "critical"}

# --- draft severity detection (mirrors pre-submit-check.sh's grep) ---
_SEV_RX = re.compile(
    r'^\s*[-*]*\s*\**severity\**\s*[:=]\s*\**\s*(critical|high|medium|low|info\w*)',
    re.IGNORECASE | re.MULTILINE,
)

# --- DefUsePath id citation in the draft body ---
# dfp-#### (value-flow), svp-#### (storage-value), sdp-#### (storage-mediated).
_PATHID_RX = re.compile(r'\b((?:dfp|svp|sdp)-\d{2,})\b', re.IGNORECASE)

# --- honest walk-back marker ---
_REBUTTAL_RX = re.compile(
    r'<!--\s*dataflow-rebuttal\s*:\s*(.{1,200}?)\s*-->'
    r'|^\s*dataflow-rebuttal\s*:\s*(.{1,200})$',
    re.IGNORECASE | re.MULTILINE,
)

# --- closure-verdict acknowledgement (the finding concedes a closure guard
#     dominates, i.e. it has reconciled with the slice). Accept either a literal
#     mention of the closure correction or a "guarded by closure" style phrase. ---
_CLOSURE_RX = re.compile(
    r'closure[- ]?(?:guarded|verdict|correct(?:ed|ion)?|consulted)'
    r'|unguarded_closure_corrected'
    r'|guard(?:ed)?\s+(?:in|by)\s+(?:the\s+)?closure',
    re.IGNORECASE,
)

# file:line references inside the draft body (e.g. CoreLib.sol:46,
# src/.../SSVClusters.sol:70). Captures (basename, line).
_FILELINE_RX = re.compile(
    r'([A-Za-z0-9_./-]+?\.(?:sol|rs|go|circom|vy))\s*[:#]\s*(\d{1,7})',
)


def _detect_severity(text: str, override: Optional[str]) -> str:
    if override:
        return override.strip().lower()
    m = _SEV_RX.search(text or "")
    if m:
        return m.group(1).strip().lower()
    return ""


def _is_high_plus(sev: str) -> bool:
    s = (sev or "").lower()
    if s.startswith("crit"):
        return True
    if s == "high":
        return True
    return False


def _draft_filelines(text: str) -> set:
    """Set of (basename, line) referenced in the draft. We compare on basename to
    be robust to absolute-vs-relative path divergence between the slice (absolute)
    and the draft (often repo-relative or bare filename)."""
    out = set()
    for m in _FILELINE_RX.finditer(text or ""):
        base = os.path.basename(m.group(1))
        try:
            out.add((base, int(m.group(2))))
        except ValueError:
            continue
    return out


def _row_anchor_filelines(rec: Dict[str, Any]) -> set:
    """The (basename, line) anchors a finding could plausibly cite for THIS path:
    the sink site, the source site, and every hop site. A finding that lands on
    any of these is 'path-relevant'."""
    out = set()

    def _add(d):
        if not isinstance(d, dict):
            return
        f = d.get("file")
        ln = d.get("line")
        if f and isinstance(ln, int):
            out.add((os.path.basename(str(f)), ln))

    _add(rec.get("sink"))
    _add(rec.get("source"))
    for h in rec.get("hops") or []:
        _add(h)
    return out


def _load_unguarded_paths(ws: str) -> Tuple[List[Dict[str, Any]], str]:
    """Return (unguarded_real_paths, status). status in {ok, no-slice, no-schema}.

    Only real (validated, non-degraded) rows with unguarded==True are returned -
    these are the rows a HIGH+ finding is accountable to.
    """
    if dfs is None:
        return [], "no-schema"
    path = os.path.join(str(ws), ".auditooor", "dataflow_paths.jsonl")
    if not os.path.isfile(path):
        return [], "no-slice"
    try:
        recs = dfs.read_paths(ws, skip_degraded=True)  # validated + non-degraded
    except Exception:
        return [], "no-slice"
    unguarded = [r for r in recs if r.get("unguarded") is True]
    if not recs:
        # file existed but held only degrade rows / unparseable lines
        return [], "no-slice"
    return unguarded, "ok"


def check(draft_path: str, ws: str, severity_override: Optional[str] = None) -> Dict[str, Any]:
    text = ""
    try:
        text = Path(draft_path).read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"verdict": "error", "reason": f"cannot read draft: {e}", "rc": 2}

    sev = _detect_severity(text, severity_override)

    # rebuttal short-circuits regardless (honest walk-back always passes)
    rb = _REBUTTAL_RX.search(text)
    if rb:
        reason = (rb.group(1) or rb.group(2) or "").strip()
        return {
            "verdict": "ok-rebuttal",
            "reason": f"dataflow-rebuttal present: {reason[:120]}",
            "severity": sev,
            "rc": 0,
        }

    if not _is_high_plus(sev):
        return {
            "verdict": "pass-below-high",
            "reason": f"severity={sev or 'unknown'} is below High; gate is HIGH+ only",
            "severity": sev,
            "rc": 0,
        }

    unguarded, status = _load_unguarded_paths(ws)
    if status != "ok" or not unguarded:
        return {
            "verdict": "pass-no-slice",
            "reason": (
                "no usable unguarded dataflow paths in workspace "
                f"({status}); gate is a no-op"
            ),
            "severity": sev,
            "rc": 0,
        }

    # Map the draft's cited file:lines against unguarded path anchors.
    draft_anchors = _draft_filelines(text)
    if not draft_anchors:
        return {
            "verdict": "pass-not-path-relevant",
            "reason": "draft cites no file:line that overlaps a value-flow sink/hop",
            "severity": sev,
            "rc": 0,
        }

    matched: List[Dict[str, Any]] = []
    for rec in unguarded:
        anchors = _row_anchor_filelines(rec)
        if draft_anchors & anchors:
            matched.append(rec)

    if not matched:
        return {
            "verdict": "pass-not-path-relevant",
            "reason": "draft's cited file:lines do not land on any unguarded value-flow path",
            "severity": sev,
            "rc": 0,
        }

    # The finding IS path-relevant. Require grounding: a DefUsePath id, a closure
    # verdict, or (already handled above) a rebuttal.
    cited_ids = {m.group(1).lower() for m in _PATHID_RX.finditer(text)}
    matched_ids = {str(r.get("path_id", "")).lower() for r in matched}
    # an exact match to one of THIS finding's paths is the strongest grounding,
    # but any real DefUsePath id from the sidecar counts as "grounded in the slice".
    all_ids = {str(r.get("path_id", "")).lower() for r in unguarded}
    cite_hit = cited_ids & all_ids

    if cite_hit:
        on_finding = sorted(cited_ids & matched_ids)
        note = (
            f"cites DefUsePath id(s): {sorted(cite_hit)}"
            + (f" (incl. this finding's path {on_finding})" if on_finding else "")
        )
        return {
            "verdict": "pass-cited",
            "reason": note,
            "severity": sev,
            "matched_path_ids": sorted(matched_ids),
            "rc": 0,
        }

    if _CLOSURE_RX.search(text):
        return {
            "verdict": "pass-cited",
            "reason": "draft carries a closure verdict (acknowledges closure-guard reconciliation)",
            "severity": sev,
            "matched_path_ids": sorted(matched_ids),
            "rc": 0,
        }

    # FAIL: path-relevant HIGH+ finding that cites nothing.
    sample = matched[0]
    sink = sample.get("sink") or {}
    sink_loc = f"{os.path.basename(str(sink.get('file')))}:{sink.get('line')}"
    return {
        "verdict": "fail-uncited-unguarded-path",
        "reason": (
            f"HIGH+ finding maps onto {len(matched)} UNGUARDED value-flow path(s) "
            f"(e.g. {sample.get('path_id')} sink {sink.get('callee')} @ {sink_loc}) "
            f"but cites no DefUsePath id, closure verdict, or dataflow-rebuttal"
        ),
        "severity": sev,
        "matched_path_ids": sorted(matched_ids)[:10],
        "uncited_path_id": sample.get("path_id"),
        "uncited_sink": sink_loc,
        "rc": 1,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="DefUsePath enforcement gate (Check #136)")
    ap.add_argument("draft", help="submission / draft markdown path")
    ap.add_argument("--workspace", required=False, default="",
                    help="workspace root containing .auditooor/dataflow_paths.jsonl")
    ap.add_argument("--severity", default=None,
                    help="override severity (else parsed from draft)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.workspace:
        # no workspace -> cannot consult slice -> no-op PASS (graceful, like siblings)
        res = {"verdict": "pass-no-slice", "reason": "no --workspace given; gate is a no-op", "rc": 0}
    else:
        res = check(args.draft, args.workspace, args.severity)

    if args.json:
        print(json.dumps(res, indent=2, default=str))
    else:
        print(f"{res.get('verdict')}: {res.get('reason')}")
    return int(res.get("rc", 2))


if __name__ == "__main__":
    sys.exit(main())
