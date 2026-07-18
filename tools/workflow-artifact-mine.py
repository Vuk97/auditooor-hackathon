#!/usr/bin/env python3
"""Mine a completed workflow's agent artifacts into durable learnings.

Workflows leave ~dozens of agent transcripts (agent-*.jsonl) full of StructuredOutput
verdicts (CONFIRM / REFUTE / candidate objects). Those are real, source-verified
knowledge - but nothing harvests them, so each run's reasoning evaporates. This tool
walks a workflow transcript dir, extracts every verdict/candidate, and emits:

  - REFUTE / DROP verdicts  -> reports/known_dead_ends.jsonl  (do-not-reescalate rows)
  - CONFIRM verdicts        -> reports/workflow_confirms_<ts>.jsonl (lead -> staging/invariant)
  - the candidate set        -> a coverage summary (what surface was actually analyzed)

Dedup is by (workspace, file_line, class) so re-running is idempotent. This is the
mechanical form of the by-hand dead-end seeding done after the new-surface re-audit.

RELATED TOOLS:
  - tools/triage-kill-promoter.py : flows a single killed candidate to known_dead_ends. This
    tool batch-harvests a WHOLE workflow's verdicts (refutes + confirms + coverage) at once.
  - tools/promote-mined-to-canonical.py : promotes mined corpus records; downstream of this.

Usage:
  workflow-artifact-mine.py --transcript-dir <dir> --workspace <name> [--ts <stamp>] [--json]
  (find the dir from the Workflow launch output: .../subagents/workflows/wf_<id>)
"""
from __future__ import annotations

import argparse
import glob
import json
import re
from pathlib import Path

DEAD_ENDS = Path(__file__).resolve().parent.parent / "reports" / "known_dead_ends.jsonl"
CONFIRMS_DIR = Path(__file__).resolve().parent.parent / "reports"

# objects are single-line JSON in the transcript; .*? (no DOTALL) spans quoted fields
# without crossing newlines, and stops at the object's own closing marker field.
_VERDICT_RE = re.compile(r'\{"title":".*?"verdict":"(?:CONFIRM|REFUTE|NEEDS-POC)".*?"final_severity":"[^"]*"\}')
_CAND_RE = re.compile(r'\{"title":".*?"attack_class":".*?"(?:severity_guess|introduced_or_left)":"[^"]*"\}')


def _load_json_objs(text: str, rx: re.Pattern) -> list[dict]:
    out = []
    for m in rx.finditer(text):
        try:
            out.append(json.loads(m.group(0)))
        except json.JSONDecodeError:
            pass
    return out


def _existing_dead_keys() -> set:
    keys = set()
    if DEAD_ENDS.is_file():
        for ln in DEAD_ENDS.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
                keys.add((r.get("workspace"), r.get("surface"), r.get("class")))
            except json.JSONDecodeError:
                pass
    return keys


def mine(transcript_dir: Path, workspace: str, ts: str) -> dict:
    verdicts, candidates = [], []
    for f in sorted(glob.glob(str(transcript_dir / "agent-*.jsonl"))):
        txt = Path(f).read_text(encoding="utf-8", errors="replace")
        verdicts += _load_json_objs(txt, _VERDICT_RE)
        candidates += _load_json_objs(txt, _CAND_RE)

    # dedup verdicts by (title, file_line, verdict)
    seen_v = set()
    uv = []
    for v in verdicts:
        k = (v.get("title", "")[:80], v.get("file_line"), v.get("verdict"))
        if k not in seen_v:
            seen_v.add(k); uv.append(v)

    refutes = [v for v in uv if v.get("verdict") == "REFUTE" or v.get("final_severity") == "DROP"]
    confirms = [v for v in uv if v.get("verdict") == "CONFIRM"]
    needs = [v for v in uv if v.get("verdict") == "NEEDS-POC"]

    existing = _existing_dead_keys()
    new_dead = []
    for v in refutes:
        fl = v.get("file_line", "")
        cls = (v.get("attack_class") or "workflow-refuted")
        key = (workspace, fl, cls)
        if key in existing:
            continue
        existing.add(key)
        new_dead.append({
            "workspace": workspace,
            "surface": fl,
            "class": cls,
            "verdict": "REFUTED-by-workflow",
            "reason": (v.get("reason") or v.get("title") or "")[:600],
            "do_not_reescalate": True,
            "date": ts,
        })

    DEAD_ENDS.parent.mkdir(parents=True, exist_ok=True)
    with DEAD_ENDS.open("a", encoding="utf-8") as fh:
        for r in new_dead:
            fh.write(json.dumps(r) + "\n")

    confirms_path = CONFIRMS_DIR / f"workflow_confirms_{ts}.jsonl"
    if confirms or needs:
        with confirms_path.open("w", encoding="utf-8") as fh:
            for v in confirms + needs:
                fh.write(json.dumps({"workspace": workspace, **v}) + "\n")

    # coverage: what surface did the analyze phase actually touch
    covered = sorted({c.get("file_line", "").rsplit(":", 1)[0] for c in candidates if c.get("file_line")})

    return {
        "transcript_dir": str(transcript_dir),
        "workspace": workspace,
        "verdicts_found": len(uv),
        "refutes": len(refutes), "confirms": len(confirms), "needs_poc": len(needs),
        "new_dead_ends_written": len(new_dead),
        "confirms_file": str(confirms_path) if (confirms or needs) else None,
        "candidates_analyzed": len(candidates),
        "surface_files_covered": len(covered),
        "confirm_titles": [c.get("title", "")[:70] for c in confirms][:10],
        "needs_poc_titles": [c.get("title", "")[:70] for c in needs][:10],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transcript-dir", required=True, type=Path)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--ts", default="2026-06-05")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    td = args.transcript_dir.expanduser().resolve()
    if not td.is_dir():
        print(f"[workflow-artifact-mine] no such dir: {td}"); return 2
    out = mine(td, args.workspace, args.ts)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[workflow-artifact-mine] {out['verdicts_found']} verdicts "
              f"({out['refutes']} refute / {out['confirms']} confirm / {out['needs_poc']} needs-poc) "
              f"-> {out['new_dead_ends_written']} new dead-ends, "
              f"{out['surface_files_covered']} surface files covered")
        for t in out["confirm_titles"]:
            print(f"   CONFIRM: {t}")
        for t in out["needs_poc_titles"]:
            print(f"   NEEDS-POC: {t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
