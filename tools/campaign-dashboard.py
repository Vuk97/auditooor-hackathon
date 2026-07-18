#!/usr/bin/env python3
"""campaign-dashboard.py — aggregate campaign/candidate/submission outcomes.

The V5 campaign stack already writes useful pieces of telemetry:

* repo-level dispatch/submission JSONL ledgers under ``tools/calibration/``;
* workspace-local campaign summaries under ``.auditooor/campaigns/*``;
* typed ``deep_candidate.v1`` records under ``<workspace>/deep_candidates``;
* human submission ledgers under ``submissions/SUBMISSIONS.md``.

This tool joins those artifacts into a deterministic per-detector scoreboard.
It is intentionally stdlib-only and conservative: missing artifact families are
treated as empty, malformed JSON fails loud, and repeated runs on the same data
produce byte-equivalent output.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO = Path(__file__).resolve().parents[1]
DEFAULT_AUDITS_DIR = Path.home() / "audits"
DEFAULT_DISPATCH_LOG = REPO / "tools" / "calibration" / "campaign_dispatch_log.jsonl"
DEFAULT_SUBMISSION_LOG = REPO / "tools" / "calibration" / "campaign_submissions.jsonl"
DEFAULT_OUT_JSON = REPO / "tools" / "calibration" / "campaign_dashboard.json"
DEFAULT_OUT_MD = REPO / "docs" / "CAMPAIGN_DASHBOARD.md"
SCHEMA_VERSION = "auditooor.campaign_dashboard.v1"

ACCEPTED = {"accepted", "paid"}
REJECTED_OOS_MARKERS = {
    "out-of-scope",
    "out_of_scope",
    "oos",
    "rejected_oos",
    "rejected-oos",
}
SURVIVOR_PROMOTIONS = {"investigate", "poc_ready"}


@dataclass
class Row:
    detector: str
    campaigns_seen: set[str] = field(default_factory=set)
    candidates_emitted: int = 0
    survivors: int = 0
    submissions: int = 0
    accepted: int = 0
    rejected_oos: int = 0
    emission_confidence: List[float] = field(default_factory=list)
    submission_confidence: List[float] = field(default_factory=list)

    def as_json(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "campaigns": len(self.campaigns_seen),
            "candidates_emitted": self.candidates_emitted,
            "survivors": self.survivors,
            "submissions": self.submissions,
            "accepted": self.accepted,
            "rejected_oos": self.rejected_oos,
            "confidence_drift": _confidence_drift(
                self.emission_confidence, self.submission_confidence
            ),
        }


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    out: List[Dict[str, Any]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        out.append(data)
    return out


def _safe_slug(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    text = text.replace("\\", "/")
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    text = re.sub(r"\.py$", "", text)
    text = re.sub(r"\s+", "-", text)
    return text or "unknown"


def _confidence_to_float(value: object) -> Optional[float]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str):
        return None
    norm = value.strip().lower()
    if norm == "low":
        return 0.25
    if norm == "medium":
        return 0.5
    if norm == "high":
        return 0.9
    try:
        return float(norm)
    except ValueError:
        return None


def _confidence_drift(emission: Sequence[float], submission: Sequence[float]) -> Optional[float]:
    if not emission or not submission:
        return None
    e_avg = sum(emission) / len(emission)
    s_avg = sum(submission) / len(submission)
    return round(s_avg - e_avg, 4)


def _candidate_detector(doc: Dict[str, Any]) -> str:
    payload = doc.get("lane_payload")
    if isinstance(payload, dict):
        for key in ("tool", "detector", "detector_name", "pattern", "rule"):
            if payload.get(key):
                return _safe_slug(payload.get(key))
    for key in ("tool", "detector", "detector_name"):
        if doc.get(key):
            return _safe_slug(doc.get(key))
    lane = doc.get("lane")
    if isinstance(lane, str) and lane.strip():
        return _safe_slug(lane)
    cid = doc.get("candidate_id")
    if isinstance(cid, str) and "." in cid:
        parts = cid.split(".")
        if len(parts) >= 2:
            return _safe_slug(".".join(parts[:2]))
    return "unknown"


def _summary_detector(summary: Dict[str, Any]) -> str:
    for key in ("detector", "detector_name", "tool", "lane"):
        if summary.get(key):
            return _safe_slug(summary.get(key))
    campaign_id = summary.get("campaign_id")
    if isinstance(campaign_id, str):
        if campaign_id.startswith("source"):
            return "source_mine"
        if campaign_id.startswith("fuzz"):
            return "fuzz"
    return "unknown"


def _candidate_is_survivor(doc: Dict[str, Any]) -> bool:
    status = str(doc.get("promotion_status") or doc.get("status") or "").strip().lower()
    if status in SURVIVOR_PROMOTIONS:
        return True
    verdict = str(doc.get("verdict") or "").strip().lower()
    return verdict in {"survivor", "keep", "pass", "passed"}


def _candidate_is_oos(doc: Dict[str, Any]) -> bool:
    fields = [
        doc.get("promotion_status"),
        doc.get("rejection_reason"),
        doc.get("scope_verdict"),
        doc.get("verdict"),
    ]
    joined = " ".join(str(v).lower() for v in fields if v is not None)
    return any(marker in joined for marker in REJECTED_OOS_MARKERS)


def _submission_is_oos(row: Dict[str, Any]) -> bool:
    fields = [
        row.get("triager_outcome"),
        row.get("scope_verdict"),
        row.get("rejection_reason"),
        row.get("notes"),
    ]
    joined = " ".join(str(v).lower() for v in fields if v is not None)
    return any(marker in joined for marker in REJECTED_OOS_MARKERS)


def discover_workspaces(audits_dir: Path, explicit: Sequence[Path] = ()) -> List[Path]:
    if explicit:
        return sorted({p.expanduser().resolve() for p in explicit}, key=lambda p: str(p))
    root = audits_dir.expanduser()
    if not root.is_dir():
        return []
    candidates = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if (child / ".auditooor").exists() or (child / "deep_candidates").exists() or (child / "submissions").exists():
            candidates.append(child.resolve())
    return sorted(candidates, key=lambda p: str(p))


def load_campaign_summaries(workspaces: Sequence[Path]) -> List[Tuple[Path, Dict[str, Any]]]:
    out: List[Tuple[Path, Dict[str, Any]]] = []
    for ws in workspaces:
        root = ws / ".auditooor" / "campaigns"
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*/summary.json"), key=lambda p: str(p)):
            data = _read_json(path)
            data.setdefault("campaign_id", path.parent.name)
            data.setdefault("workspace", str(ws))
            out.append((ws, data))
    return out


def load_deep_candidates(workspaces: Sequence[Path]) -> List[Tuple[Path, Dict[str, Any]]]:
    out: List[Tuple[Path, Dict[str, Any]]] = []
    for ws in workspaces:
        root = ws / "deep_candidates"
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.json"), key=lambda p: str(p)):
            data = _read_json(path)
            if data.get("schema_version") != "deep_candidate.v1":
                continue
            data.setdefault("workspace", str(ws))
            out.append((ws, data))
    return out


def load_submission_ledger(path: Path) -> List[Dict[str, Any]]:
    rows = _read_jsonl(path)
    latest: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for row in rows:
        fid = row.get("finding_id")
        if not isinstance(fid, str) or not fid.strip():
            continue
        if fid not in latest:
            order.append(fid)
        previous = latest.get(fid, {})
        merged = dict(previous)
        for key, value in row.items():
            if value is not None:
                merged[key] = value
        latest[fid] = merged
    return [latest[fid] for fid in order]


def load_submission_md(workspaces: Sequence[Path]) -> List[Dict[str, Any]]:
    """Best-effort parser for human ledgers.

    This intentionally stays heuristic. The JSONL submission ledger is the
    canonical machine source; markdown only adds a low-resolution fallback so a
    workspace with hand-maintained outcomes is not invisible.
    """
    rows: List[Dict[str, Any]] = []
    for ws in workspaces:
        path = ws / "submissions" / "SUBMISSIONS.md"
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            lower = line.lower()
            if not line.lstrip().startswith("|"):
                continue
            if "accepted" not in lower and "rejected" not in lower and "out-of-scope" not in lower and "oos" not in lower:
                continue
            outcome = "pending"
            if "accepted" in lower or "paid" in lower:
                outcome = "accepted"
            elif "out-of-scope" in lower or "oos" in lower:
                outcome = "rejected_oos"
            elif "rejected" in lower:
                outcome = "rejected"
            cells = [c.strip(" `") for c in line.strip().strip("|").split("|")]
            finding_id = next((c for c in cells if c), "markdown-row")
            rows.append({
                "finding_id": finding_id,
                "workspace": str(ws),
                "triager_outcome": outcome,
                "detector": "markdown-ledger",
                "source": str(path),
            })
    return rows


def _map_campaign_to_detector(summaries: Sequence[Tuple[Path, Dict[str, Any]]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for _ws, summary in summaries:
        cid = summary.get("campaign_id")
        if isinstance(cid, str) and cid:
            out[cid] = _summary_detector(summary)
    return out


def build_dashboard(
    *,
    audits_dir: Path = DEFAULT_AUDITS_DIR,
    workspaces: Sequence[Path] = (),
    dispatch_log: Path = DEFAULT_DISPATCH_LOG,
    submission_log: Path = DEFAULT_SUBMISSION_LOG,
) -> Dict[str, Any]:
    workspace_list = discover_workspaces(audits_dir, workspaces)
    rows: Dict[str, Row] = {}

    def slot(detector: str) -> Row:
        key = _safe_slug(detector)
        if key not in rows:
            rows[key] = Row(detector=key)
        return rows[key]

    summaries = load_campaign_summaries(workspace_list)
    campaign_to_detector = _map_campaign_to_detector(summaries)

    for _ws, summary in summaries:
        detector = _summary_detector(summary)
        cid = str(summary.get("campaign_id") or "unknown")
        r = slot(detector)
        r.campaigns_seen.add(cid)
        for item in summary.get("survivors") or []:
            if isinstance(item, dict):
                det = item.get("detector") or item.get("detector_name") or item.get("tool")
                if det:
                    r = slot(str(det))
                    r.campaigns_seen.add(cid)
                    r.survivors += 1
            else:
                r.survivors += 1

    candidate_id_to_detector: Dict[str, str] = {}
    for _ws, doc in load_deep_candidates(workspace_list):
        detector = _candidate_detector(doc)
        cid = doc.get("candidate_id")
        if isinstance(cid, str) and cid:
            candidate_id_to_detector[cid] = detector
        r = slot(detector)
        r.candidates_emitted += 1
        if _candidate_is_survivor(doc):
            r.survivors += 1
        if _candidate_is_oos(doc):
            r.rejected_oos += 1
        cval = _confidence_to_float(doc.get("confidence"))
        if cval is not None:
            r.emission_confidence.append(cval)

    # Dispatch records increase campaign visibility even before campaign-state
    # summaries exist.
    for entry in _read_jsonl(dispatch_log):
        cid = entry.get("campaign_id")
        detector = campaign_to_detector.get(str(cid), _safe_slug(entry.get("lane") or "unknown"))
        if isinstance(cid, str) and cid:
            slot(detector).campaigns_seen.add(cid)

    submissions = load_submission_ledger(submission_log) + load_submission_md(workspace_list)
    for sub in submissions:
        detector = _safe_slug(sub.get("detector") or sub.get("detector_name") or "")
        candidate_id = sub.get("candidate_id")
        if detector == "unknown" and isinstance(candidate_id, str):
            detector = candidate_id_to_detector.get(candidate_id, "unknown")
        if detector == "unknown":
            for key in ("source_campaign_id", "fuzz_campaign_id", "symbolic_campaign_id", "deep_campaign_id", "campaign_id"):
                cid = sub.get(key)
                if isinstance(cid, str) and cid in campaign_to_detector:
                    detector = campaign_to_detector[cid]
                    break
        if detector == "unknown":
            # Last-resort lane projection keeps old submission rows visible.
            for key, lane in (
                ("source_campaign_id", "source_mine"),
                ("fuzz_campaign_id", "fuzz"),
                ("symbolic_campaign_id", "symbolic"),
                ("deep_campaign_id", "deep"),
            ):
                if sub.get(key):
                    detector = lane
                    break

        r = slot(detector)
        r.submissions += 1
        outcome = str(sub.get("triager_outcome") or "").strip().lower()
        if outcome in ACCEPTED:
            r.accepted += 1
        if _submission_is_oos(sub):
            r.rejected_oos += 1
        cval = _confidence_to_float(sub.get("submission_confidence") or sub.get("confidence_at_submission"))
        if cval is not None:
            r.submission_confidence.append(cval)

    json_rows = [row.as_json() for row in rows.values()]
    json_rows.sort(key=lambda item: (-int(item["submissions"]), -int(item["survivors"]), item["detector"]))

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": "not-recorded-for-idempotence",
        "workspace_count": len(workspace_list),
        "sources": {
            "audits_dir": str(audits_dir.expanduser()),
            "dispatch_log": str(dispatch_log),
            "submission_log": str(submission_log),
        },
        "rows": json_rows,
    }


def render_markdown(payload: Dict[str, Any]) -> str:
    rows = payload.get("rows") or []
    lines = [
        "# Campaign Dashboard",
        "",
        "Schema: `auditooor.campaign_dashboard.v1`",
        "",
        "This file is generated by `python3 tools/campaign-dashboard.py`. It is deterministic: the timestamp is intentionally not recorded so re-running on the same data is byte-equivalent.",
        "",
    ]
    if not rows:
        lines.extend([
            "No campaign data found. Run a source-mining, fuzz, symbolic, math, crypto, or econ campaign first, then re-run the dashboard.",
            "",
        ])
        return "\n".join(lines)

    lines.extend([
        "| detector | campaigns | candidates_emitted | survivors | submissions | accepted | rejected_oos | confidence_drift |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in rows:
        drift = row.get("confidence_drift")
        drift_text = "" if drift is None else str(drift)
        lines.append(
            "| {detector} | {campaigns} | {candidates_emitted} | {survivors} | {submissions} | {accepted} | {rejected_oos} | {confidence_drift} |".format(
                detector=str(row.get("detector", "unknown")).replace("|", "\\|"),
                campaigns=row.get("campaigns", 0),
                candidates_emitted=row.get("candidates_emitted", 0),
                survivors=row.get("survivors", 0),
                submissions=row.get("submissions", 0),
                accepted=row.get("accepted", 0),
                rejected_oos=row.get("rejected_oos", 0),
                confidence_drift=drift_text,
            )
        )
    lines.append("")
    return "\n".join(lines)


def write_outputs(payload: Dict[str, Any], *, out_json: Path, out_md: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    out_md.write_text(render_markdown(payload), encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the deterministic campaign outcome dashboard."
    )
    parser.add_argument("--audits-dir", type=Path, default=DEFAULT_AUDITS_DIR,
                        help="Directory containing audit workspaces (default: ~/audits).")
    parser.add_argument("--workspace", type=Path, action="append", default=[],
                        help="Explicit workspace to include. May be repeated; overrides --audits-dir discovery.")
    parser.add_argument("--dispatch-log", type=Path, default=DEFAULT_DISPATCH_LOG,
                        help="Repo-level campaign dispatch JSONL ledger.")
    parser.add_argument("--submission-log", type=Path, default=DEFAULT_SUBMISSION_LOG,
                        help="Repo-level campaign submission JSONL ledger.")
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON,
                        help="Output JSON sidecar path.")
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD,
                        help="Output markdown dashboard path.")
    parser.add_argument("--print-json", action="store_true",
                        help="Print JSON payload to stdout as well as writing outputs.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        payload = build_dashboard(
            audits_dir=args.audits_dir,
            workspaces=args.workspace,
            dispatch_log=args.dispatch_log,
            submission_log=args.submission_log,
        )
        write_outputs(payload, out_json=args.out_json, out_md=args.out_md)
    except ValueError as exc:
        print(f"[campaign-dashboard] ERR {exc}", file=sys.stderr)
        return 1
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[campaign-dashboard] OK rows={len(payload.get('rows') or [])} "
        f"json={args.out_json} md={args.out_md}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
