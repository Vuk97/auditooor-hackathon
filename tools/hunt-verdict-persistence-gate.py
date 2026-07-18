#!/usr/bin/env python3
"""hunt-verdict-persistence-gate.py - BLOCK a done / audit-complete claim while a
hunt workflow's verdicts remain un-sunk (not yet persisted into canonical
hunt_findings_sidecars via verdict-sink.py).

This is the enforcement half of the artifact-persistence guarantee. The companion
PostToolUse hook (auditooor-workflow-verdict-obligation.sh) appends an OBLIGATION
record to ~/.auditooor/verdict_obligations.jsonl every time a Workflow that touches
an audit workspace launches. Running tools/verdict-sink.py on that run's journal
writes a RESOLUTION to <repo>/.auditooor/verdict_sink_log.jsonl. This gate fails
(rc=1) if any obligation for the queried workspace has no matching resolution -
i.e. a hunt ran but its verdicts were never persisted, so they would evaporate
from the gates and the learning loop. Wire it into audit-done-guard.py and the
pre-commit hook so the failure mode can never recur silently.

Honesty: a resolution counts even if it sank 0 sidecars (the hunt was checked and
had nothing to persist). The gate enforces that verdict-sink was RUN per hunt, not
that findings exist - so it never pressures anyone to invent findings.

USAGE:
  python3 tools/hunt-verdict-persistence-gate.py --workspace ~/audits/<ws> [--json]
  python3 tools/hunt-verdict-persistence-gate.py --all [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_OBLIGATIONS = Path(os.environ.get("AUDITOOOR_VERDICT_OBLIGATION_LEDGER",
                                   os.path.expanduser("~/.auditooor/verdict_obligations.jsonl")))
_SINK_LOG = Path(os.environ.get("AUDITOOOR_VERDICT_SINK_LOG",
                                str(REPO_ROOT / ".auditooor" / "verdict_sink_log.jsonl")))
# Corpus stores the learning ETL (hackerman-etl-from-finding-sidecars.py) writes
# into. Env-overridable to match the ETL so the closure check can be tested without
# the real corpus. These mirror the ETL's AUDITOOOR_{KDE_PATH,INV_BATCH_ROOT,...}.
_DERIVED_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "derived"
_KDE_PATH = Path(os.environ.get("AUDITOOOR_KDE_PATH",
                                str(REPO_ROOT / "reports" / "known_dead_ends.jsonl")))
_INV_BATCH_ROOT = Path(os.environ.get("AUDITOOOR_INV_BATCH_ROOT",
                                      str(_DERIVED_ROOT / "invariant_library_extended")))
_DET_BATCH_ROOT = Path(os.environ.get("AUDITOOOR_DET_BATCH_ROOT",
                                      str(_DERIVED_ROOT / "detector_synthesis_v2")))
# Post-promotion canonical libraries (promote-mined-to-canonical.py target); a slug
# that has been promoted out of the derived dirs still counts as in-corpus.
_PROMOTED_INV = _DERIVED_ROOT / "invariants_pilot_audited.jsonl"
_PROMOTED_DET = _DERIVED_ROOT / "detector_seed_library_promoted.jsonl"

_CONFIRMED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")
# Kill-verdict tokens; kept in sync with hackerman-etl KILL_VERDICT_TOKENS so the
# gate fires on exactly the verdicts the ETL routes to known-dead-ends.
_KILL_TOKENS = (
    "DROP", "KILL", "KILLED", "NOT-A-BUG", "FP", "FALSE-POSITIVE", "VERIFIED-SOUND",
    "REFUTED", "OUT-OF-SCOPE", "OOS", "BENIGN", "NOT-REPRODUCED", "NO-FINDING",
    "NEEDS-VERIFICATION", "CONCESSION", "LOW-IMPACT", "COLLAPSE",
)


def _read_corpus_text() -> str:
    """Concatenate every corpus store the ETL writes, lowercased, for substring
    membership of a sidecar slug. Cheap and robust to schema drift (we only need
    to know the slug was ingested somewhere)."""
    parts: list[str] = []
    for p in (_KDE_PATH, _PROMOTED_INV, _PROMOTED_DET):
        if p.exists():
            try:
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    for root in (_INV_BATCH_ROOT, _DET_BATCH_ROOT):
        if root.is_dir():
            for f in root.rglob("*"):
                if f.is_file():
                    try:
                        parts.append(f.read_text(encoding="utf-8", errors="replace"))
                    except OSError:
                        pass
    return "\n".join(parts).lower()


def _sidecar_severity(d: dict) -> str:
    for k in ("proposed_severity", "severity_claim", "severity_estimate",
              "severity_final", "severity"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip().upper()
    return ""


def _sidecar_verdict_blob(d: dict) -> str:
    parts: list[str] = []
    for k in ("verdict", "severity_status", "status", "kill_verdict"):
        v = d.get(k)
        if isinstance(v, str):
            parts.append(v)
    r = d.get("result")
    if isinstance(r, dict):
        for k in ("final_verdict", "applies_to_target"):
            v = r.get(k)
            if isinstance(v, str):
                parts.append(v)
    return " ".join(parts).upper()


def _slug_norm(text: str, n: int = 48) -> str:
    """Match hackerman-etl-from-finding-sidecars.py _slug() so a corpus substring
    search finds the ETL-normalised slug (non-alnum -> '-', lower, truncate 48)."""
    import re as _re
    s = _re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip()).strip("-").lower()
    return s[:n] or "finding"


def _sidecar_slug(d: dict, path: Path) -> str:
    for k in ("candidate_slug", "slug", "task_id", "candidate_id", "title"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return _slug_norm(v.strip())
    return _slug_norm(path.stem)


def corpus_closure_violations(workspace: str) -> list[dict]:
    """Return per-sidecar records that SHOULD be in the corpus but are NOT.

    A CONFIRMED (CRITICAL/HIGH/MEDIUM, no kill verdict) or KILLED hunt-sidecar that
    has no matching slug anywhere in the corpus stores means the learning ETL never
    ran (or failed) for it: the verdict reached the gates but never the corpus, so
    the next reweighted batch re-dispatches an already-decided angle. Fail closed."""
    sc_dir = Path(workspace) / ".auditooor" / "hunt_findings_sidecars"
    if not sc_dir.is_dir():
        return []
    corpus = _read_corpus_text()
    out: list[dict] = []
    for p in sorted(sc_dir.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        blob = _sidecar_verdict_blob(d)
        sev = _sidecar_severity(d)
        is_kill = any(tok in blob.replace(" ", "-").replace("_", "-") for tok in
                      (t.replace("_", "-") for t in _KILL_TOKENS))
        is_confirmed = (not is_kill) and any(s in sev for s in _CONFIRMED_SEVERITIES)
        if not (is_kill or is_confirmed):
            continue
        slug = _sidecar_slug(d, p).lower()
        if slug and slug in corpus:
            continue
        out.append({
            "sidecar": p.name,
            "slug": slug,
            "class": "kill" if is_kill else "confirmed",
            "severity": sev,
        })
    return out


def _read_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def open_obligations(workspace: str | None) -> list[dict]:
    obligations = _read_jsonl(_OBLIGATIONS)
    resolved_runs = {r.get("run_id") for r in _read_jsonl(_SINK_LOG) if r.get("run_id")}
    ws_name = Path(workspace).name if workspace else None
    out = []
    for ob in obligations:
        if ob.get("status") == "cancelled":
            continue
        run_id = ob.get("run_id")
        if run_id in resolved_runs:
            continue  # verdict-sink was run for this hunt -> satisfied
        if ws_name:
            ob_ws = [Path(w).name for w in ob.get("workspaces", [])]
            # an obligation with NO recorded workspaces is conservatively global
            if ob_ws and ws_name not in ob_ws:
                continue
        out.append(ob)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-corpus-closure", action="store_true",
                    help="skip the corpus-feedback-closure check (CONFIRMED/kill "
                         "sidecars with no corpus record); persistence check only")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = None if args.all else (args.workspace or None)
    opens = open_obligations(ws)

    # Corpus-feedback-closure: CONFIRMED/kill sidecars that never reached the corpus
    # (learning ETL never ran for them). Only checkable for a concrete workspace.
    closure_gaps: list[dict] = []
    if ws and not args.no_corpus_closure:
        closure_gaps = corpus_closure_violations(ws)

    failed = bool(opens) or bool(closure_gaps)
    if opens and closure_gaps:
        verdict = "fail-unsunk-and-uncorpused-verdicts"
    elif opens:
        verdict = "fail-unsunk-hunt-verdicts"
    elif closure_gaps:
        verdict = "fail-uncorpused-verdicts"
    else:
        verdict = "pass"

    result = {
        "gate": "hunt-verdict-persistence",
        "workspace": ws or "(all)",
        "verdict": verdict,
        "open_obligations": [
            {"run_id": o.get("run_id"), "workspaces": o.get("workspaces"),
             "ts": o.get("ts"), "tool": o.get("tool")}
            for o in opens
        ],
        "corpus_closure_gaps": closure_gaps,
        "remedy": "" if not failed else
            ("run: python3 tools/verdict-sink.py --journal <run>/journal.jsonl --run-id <run_id> "
             "[--workspace <ws>]  for each open run; "
             "and python3 tools/hackerman-etl-from-finding-sidecars.py --workspace <ws> "
             "to route CONFIRMED/kill sidecars into the corpus, then re-check."),
    }
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        if not failed:
            print(f"[hunt-verdict-persistence] PASS ws={ws or '(all)'} - no un-sunk / un-corpused hunt verdicts")
        else:
            print(f"[hunt-verdict-persistence] FAIL ws={ws or '(all)'} verdict={verdict}")
            for o in opens:
                print(f"  - UNSUNK run_id={o.get('run_id')} workspaces={o.get('workspaces')} ts={o.get('ts')}")
            for g in closure_gaps:
                print(f"  - UNCORPUSED {g['class']} sidecar={g['sidecar']} slug={g['slug']} sev={g['severity']}")
            print("  REMEDY: " + result["remedy"])
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
