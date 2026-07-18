"""WSITB EnforcementPlane node schema (v1) - frozen record + validator for the
"Was-Something-In-The-Bypass" (WSITB) B1 enforcement-plane, increment-1 (CONSERVATION
class only).

The plane covers ENFORCEMENT POINTS, not impacts. Each node is one delegated-trusted
safety property (here: a conserved-with coupled set - a must-move-together invariant) and
carries the 8-question WSITB analysis skeleton. A node whose q8_verdict is still
'unanalyzed' AND that is severity_eligible is an un-analyzed enforcement point the gate
fails-closed on under strict.

This mirrors tools/state_coupling_schema.py (frozen record + validate + a canonical
disk reader). It is DELIBERATELY a thin sibling: the substrate (StateCouplingEdge
semantic-ssa edges + dataflow storage-hop paths) is reused, not rebuilt.

Honesty contract (R80, identical tiers to state_coupling_schema / dataflow_schema):
  - ``semantic-ssa``: IR-backed (a real def-use slice + call-graph closure). Citable.
  - ``syntactic``: regex/name PROMPT. Advisory, probe-gated. Never a stand-alone claim.
  - ``heuristic``: name-only. NEVER cited.
A node inherits the confidence of the coupled edge it recomposes.

Producer:  tools/wsitb-enforcement-plane.py --emit-plane
Consumers: tools/audit-completeness-check.py::check_enforcement_point (L37 gate),
           Makefile:audit-deep.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Tuple

SCHEMA_VERSION = "auditooor.wsitb_enforcement_plane.v1"

# increment-1 covers ONLY the conservation class. The taxonomy is left open so
# freshness / coupled-state-consistency classes can be added without a schema bump.
INVARIANT_CLASSES = {"conservation"}

CONFIDENCES = {"semantic-ssa", "syntactic", "heuristic"}
# R80: only semantic-ssa may be CITED; syntactic is advisory; heuristic never cited.
CITABLE_CONFIDENCES = {"semantic-ssa"}

Q8_VERDICTS = {"unanalyzed", "safe", "bypassable", "invariant-unsound", "not-applicable"}

_TOP_KEYS = (
    "schema", "node_id", "invariant_class", "term", "owner",
    "writers", "readers", "coupled_set", "private_invariant",
    "q3_partial_flush", "q6_reader_blind", "q7_attacker_reachable",
    "q8_verdict", "analyzed", "severity_eligible", "confidence",
)
_WRITER_KEYS = ("fn", "file", "line", "guard_in_closure")


def new_node(
    node_id: str,
    term: str,
    owner: str,
    writers: List[Dict[str, Any]],
    readers: List[str],
    coupled_set: List[str],
    *,
    invariant_class: str = "conservation",
    private_invariant: str | None = None,
    q3_partial_flush: bool = False,
    q6_reader_blind: bool = False,
    q7_attacker_reachable: bool = False,
    q8_verdict: str = "unanalyzed",
    severity_eligible: bool = False,
    confidence: str = "semantic-ssa",
    evidence: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build a v1 EnforcementPlane node. `analyzed` is derived from q8_verdict
    (anything other than the placeholder 'unanalyzed' counts as analyzed)."""
    if private_invariant is None:
        members = ", ".join(sorted(set(coupled_set or [])))
        private_invariant = (
            f"conservation: every writer of the coupled set {{{members}}} must "
            f"preserve the sum/relation over ALL members; a writer that mutates a "
            f"strict subset partial-flushes the set (q3) and any reader outside the "
            f"writer set observes the desync (q6)")
    return {
        "schema": SCHEMA_VERSION,
        "node_id": node_id,
        "invariant_class": invariant_class,
        "term": term,
        "owner": owner,
        "writers": [
            {
                "fn": w.get("fn"),
                "file": w.get("file"),
                "line": w.get("line"),
                "guard_in_closure": w.get("guard_in_closure"),
            }
            for w in (writers or [])
        ],
        "readers": sorted(set(readers or [])),
        "coupled_set": sorted(set(coupled_set or [])),
        "private_invariant": private_invariant,
        "q3_partial_flush": bool(q3_partial_flush),
        "q6_reader_blind": bool(q6_reader_blind),
        "q7_attacker_reachable": bool(q7_attacker_reachable),
        "q8_verdict": q8_verdict,
        "analyzed": q8_verdict != "unanalyzed",
        "severity_eligible": bool(severity_eligible),
        "confidence": confidence,
        "evidence": evidence or {},
    }


def validate(rec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errs: List[str] = []
    if not isinstance(rec, dict):
        return False, ["record is not a dict"]
    for k in _TOP_KEYS:
        if k not in rec:
            errs.append(f"missing top key: {k}")
    if rec.get("schema") != SCHEMA_VERSION:
        errs.append(f"schema mismatch: {rec.get('schema')!r}")
    if rec.get("invariant_class") not in INVARIANT_CLASSES:
        errs.append(f"bad invariant_class: {rec.get('invariant_class')!r}")
    if rec.get("confidence") not in CONFIDENCES:
        errs.append(f"bad confidence: {rec.get('confidence')!r}")
    if rec.get("q8_verdict") not in Q8_VERDICTS:
        errs.append(f"bad q8_verdict: {rec.get('q8_verdict')!r}")
    for lk in ("readers", "coupled_set"):
        if not isinstance(rec.get(lk), list):
            errs.append(f"{lk} must be a list")
    ws = rec.get("writers")
    if isinstance(ws, list):
        for i, w in enumerate(ws):
            if not isinstance(w, dict):
                errs.append(f"writers[{i}] not a dict")
                continue
            for k in _WRITER_KEYS:
                if k not in w:
                    errs.append(f"writers[{i}] missing key: {k}")
    else:
        errs.append("writers must be a list")
    # bijection: analyzed must agree with q8_verdict (no hand-greened node).
    analyzed = rec.get("analyzed")
    if isinstance(analyzed, bool):
        expect = rec.get("q8_verdict") != "unanalyzed"
        if analyzed != expect:
            errs.append(
                f"analyzed={analyzed} disagrees with q8_verdict={rec.get('q8_verdict')!r}")
    return (len(errs) == 0), errs


def plane_path(ws) -> str:
    return os.path.join(str(ws), ".auditooor", "wsitb_enforcement_plane.json")


def points_path(ws) -> str:
    return os.path.join(str(ws), ".auditooor", "wsitb_enforcement_points.jsonl")


def accounting_path(ws) -> str:
    return os.path.join(str(ws), ".auditooor", "wsitb_enforcement_accounting.json")


def mechanism_scan_path(ws) -> str:
    """The mechanism_scan sidecar this plane feeds into the exploit queue via
    tools/mechanism-findings-to-exploit-queue.py (schema auditooor.mechanism_scan.v1)."""
    return os.path.join(str(ws), ".auditooor", "mechanism_scan",
                        "wsitb_enforcement_points.json")


def _owner_writer(node: Dict[str, Any]) -> Dict[str, Any]:
    """The writer anchor for a node's finding: the writer whose fn == owner and that
    carries a file, else the first writer with a file, else {}."""
    writers = node.get("writers") or []
    owner = node.get("owner")
    for w in writers:
        if isinstance(w, dict) and w.get("fn") == owner and w.get("file"):
            return w
    for w in writers:
        if isinstance(w, dict) and w.get("file"):
            return w
    return writers[0] if writers and isinstance(writers[0], dict) else {}


def write_plane(ws, nodes: Iterable[Dict[str, Any]],
                accounting: Dict[str, Any] | None = None) -> int:
    """Write the plane JSON (one object with a `nodes` list) + the per-un-analyzed-point
    JSONL + the feeder-health accounting JSON. Returns the node count."""
    nodes = list(nodes)
    pp = plane_path(ws)
    os.makedirs(os.path.dirname(pp), exist_ok=True)
    with open(pp, "w", encoding="utf-8") as fh:
        json.dump({"schema": SCHEMA_VERSION, "nodes": nodes},
                  fh, sort_keys=True, default=str, indent=2)
    open_points = [n for n in nodes
                   if not n.get("analyzed") and n.get("severity_eligible")]
    with open(points_path(ws), "w", encoding="utf-8") as fh:
        for n in open_points:
            fh.write(json.dumps(n, sort_keys=True, default=str) + "\n")
    # ALSO feed the OPEN enforcement points into the exploit queue via the
    # mechanism_scan sidecar (mechanism-findings-to-exploit-queue.py drains this).
    # ADDITIVE: one own sidecar file. Empty input (0 open points) -> no sidecar
    # (a stale one is removed) so no queue row is produced.
    msp = mechanism_scan_path(ws)
    findings = []
    for n in open_points:
        w = _owner_writer(n)
        findings.append({
            "file": w.get("file"),
            "line": w.get("line"),
            "function": n.get("owner"),
            "reason": n.get("private_invariant"),
        })
    if findings:
        os.makedirs(os.path.dirname(msp), exist_ok=True)
        with open(msp, "w", encoding="utf-8") as fh:
            json.dump({
                "schema": "auditooor.mechanism_scan.v1",
                "mechanism": "conservation-partial-flush",
                "impact": "accounting-desync",
                "finding_count": len(findings),
                "findings": findings,
            }, fh, sort_keys=True, default=str, indent=2)
    elif os.path.isfile(msp):
        os.remove(msp)
    if accounting is not None:
        with open(accounting_path(ws), "w", encoding="utf-8") as fh:
            json.dump(accounting, fh, sort_keys=True, default=str, indent=2)
    return len(nodes)


def read_plane(ws, *, min_confidence: str | None = None) -> List[Dict[str, Any]]:
    """Canonical reader. Returns the validated node list from the plane JSON. Drops
    malformed nodes (a bad producer must not poison a consumer). `min_confidence`
    filters to >= a tier (semantic-ssa > syntactic > heuristic). Returns [] when the
    file is absent/unreadable (fail-OPEN - a no-substrate workspace behaves as before
    the plane existed)."""
    p = plane_path(ws)
    if not os.path.isfile(p):
        return []
    order = {"heuristic": 0, "syntactic": 1, "semantic-ssa": 2}
    floor = order.get(min_confidence, -1) if min_confidence else -1
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    nodes = doc.get("nodes") if isinstance(doc, dict) else None
    if not isinstance(nodes, list):
        return []
    out: List[Dict[str, Any]] = []
    for rec in nodes:
        if not isinstance(rec, dict):
            continue
        ok, _e = validate(rec)
        if not ok:
            continue
        if order.get(rec.get("confidence"), -1) < floor:
            continue
        out.append(rec)
    return out
