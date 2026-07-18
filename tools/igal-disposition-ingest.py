#!/usr/bin/env python3
"""Fold IGAL triage agent verdicts into the gate's disposition file.

Reads the per-batch agent verdicts emitted for the prompts from igal-triage-emit.py and
writes the disposition rows that incomplete-guard-ack-gate.py consumes. Disposition policy
(honest, fail-closed-preserving):
  - benign                                  -> not-fileable  (reason = benign reason)
  - finding-candidate AND fileable=false    -> not-fileable  (reason = "<blocking_gate>: reason")
  - finding-candidate AND fileable=true     -> NO disposition. A fileable lead must be FILED
    (or rebutted) by a human; leaving it undisposed keeps the gate RED so the lead is not
    silently buried. These are reported as open_leads.
R76: a verdict's code_excerpt must be present in real source (grep), else the row is dropped
as a possible hallucination and the underlying hypothesis stays undisposed.

  IN:  <ws>/.auditooor/igal_triage/batch_*.jsonl   (agent verdicts; array or JSONL)
       <ws>/.auditooor/incomplete_guard_ack_hypotheses.jsonl  (for file resolution)
  OUT: <ws>/.auditooor/incomplete_guard_ack_dispositions.jsonl  (gate input; {file,ack_line,
                                                                  disposition,reason})
       <ws>/.auditooor/igal_open_leads.jsonl        (fileable-and-unfiled leads to act on)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TRIAGE_DIR_REL = ".auditooor/igal_triage"
DISPO_REL = ".auditooor/incomplete_guard_ack_dispositions.jsonl"
LEADS_REL = ".auditooor/igal_open_leads.jsonl"


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").replace("`", " ")).strip()


def _r76_ok(excerpt: str, file_line: str, ws: Path) -> bool:
    """True iff a meaningful excerpt anchor is found in the cited real source file."""
    needle = _normalize(excerpt)
    if len(needle) < 8:
        return False
    rel = str(file_line).split(":", 1)[0].strip().lstrip("/")
    for cand in (ws / rel, ws / "src" / rel):
        try:
            if cand.is_file():
                body = _normalize(cand.read_text(encoding="utf-8", errors="replace"))
                if needle in body:
                    return True
                # token-overlap fallback (mirror depth-probe-ingest): cosmetic drift
                ex = {t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", excerpt or "")}
                bt = {t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", cand.read_text(encoding='utf-8', errors='replace'))}
                if len(ex) >= 4 and len(ex & bt) / len(ex) >= 0.85:
                    return True
        except OSError:
            continue
    return False


def _load_verdicts(ws: Path) -> list[dict]:
    d = ws / TRIAGE_DIR_REL
    if not d.is_dir():
        return []
    rows: list[dict] = []
    for f in sorted(d.glob("batch_*.jsonl")):
        txt = f.read_text(encoding="utf-8", errors="replace").strip()
        if not txt:
            continue
        try:
            obj = json.loads(txt)
            rows.extend(obj if isinstance(obj, list) else [obj])
            continue
        except ValueError:
            pass
        for line in txt.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    rows.append(o)
            except ValueError:
                continue
    return rows


def ingest(ws: Path) -> dict:
    verdicts = _load_verdicts(ws)
    dispo, leads, r76_dropped, skipped = [], [], 0, 0
    seen = set()
    for v in verdicts:
        if not isinstance(v, dict):
            continue
        fl = str(v.get("file_line") or "")
        if not fl or ":" not in fl:
            continue
        file_part, _, ack = fl.rpartition(":")
        try:
            ack_line = int(v.get("ack_line") or ack)
        except (TypeError, ValueError):
            ack_line = ack
        key = f"{file_part}:{ack_line}"
        if key in seen:
            continue
        excerpt = str(v.get("code_excerpt") or "")
        if not _r76_ok(excerpt, fl, ws):
            r76_dropped += 1
            continue
        seen.add(key)
        cls = str(v.get("classification") or "").lower()
        fileable = v.get("fileable")
        reason = (v.get("reason") or "").strip()
        if cls == "benign":
            dispo.append({"file": file_part, "ack_line": ack_line,
                          "disposition": "not-fileable",
                          "reason": f"benign/by-design: {reason}"[:480]})
        elif cls == "finding-candidate" and fileable is False:
            gate = v.get("blocking_gate") or "not-fileable"
            dispo.append({"file": file_part, "ack_line": ack_line,
                          "disposition": "not-fileable",
                          "reason": f"verified not-fileable ({gate}): {reason}"[:480]})
        elif cls == "finding-candidate" and fileable is True:
            leads.append({"file_line": fl, "severity": v.get("severity"),
                          "reason": reason[:480]})  # NO disposition: must be filed
        else:
            skipped += 1  # ambiguous verdict -> leave undisposed (gate stays honest)

    (ws / DISPO_REL).write_text(
        "".join(json.dumps(d) + "\n" for d in dispo), encoding="utf-8")
    (ws / LEADS_REL).write_text(
        "".join(json.dumps(x) + "\n" for x in leads), encoding="utf-8")
    return {"verdicts_read": len(verdicts), "dispositioned_not_fileable": len(dispo),
            "open_fileable_leads": len(leads), "r76_dropped": r76_dropped,
            "ambiguous_left_undisposed": skipped,
            "dispositions_path": str(ws / DISPO_REL), "leads_path": str(ws / LEADS_REL)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", "--ws", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"[igal-disposition-ingest] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    res = ingest(ws)
    if args.json:
        print(json.dumps(res))
    else:
        for k, v in res.items():
            print(f"{k}: {v}")
        if res["open_fileable_leads"]:
            print(f"[igal-disposition-ingest] {res['open_fileable_leads']} FILEABLE lead(s) "
                  f"left undisposed (gate stays red) - file or rebut them: {res['leads_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
