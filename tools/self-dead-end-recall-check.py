#!/usr/bin/env python3
"""Self-dead-end recall: block re-litigating an impact claim WE already disproved.

R47 blocks claims the TEAM acknowledged externally; L31 blocks claims WE filed
internally; this gate blocks claims WE DISPROVED internally via a source-verification
lane (SV-class). The Spark LEAD-1 saga is the anchor: our own SV4 lane already proved
the receiver self-recovers, yet v8..v12 re-litigated the direct-loss claim for weeks
because that conclusion lived only in a per-iteration results.md and was never recalled.

Two modes:
  - default (gate): given a draft + workspace, scan reports/known_dead_ends.jsonl for
    records with dead_end_class='self-source-verification-falsification' whose
    falsified_claim semantically overlaps the draft's impact claim AT THE SAME target_pin.
    A match -> fail-blocked-self-dead-end (cite sv_record_id + recovery_path_cited),
    unless the draft cites a pin advance, an extension-distinct argument (R47-style), or
    carries a visible `self-dead-end-rebuttal: <reason>`.
  - --promote-marker <file>: scan a results.md / SV sidecar for the marker
    `<!-- sv-falsifies: <claim> | axis:<axis> | recovery:<file:line> -->` (emitted by the
    Rule-82 dispatch block when a worker finds a victim-recovery path survives) and append
    a pin-keyed self-source-verification-falsification record. Refuses to write without a
    target_pin (recall is pin-keyed, R47-style stale discipline).

Usage:
  self-dead-end-recall-check.py <draft.md> --workspace <ws> [--strict] [--json]
  self-dead-end-recall-check.py --promote-marker <results.md> --workspace <ws> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

SCHEMA = "auditooor.self_dead_end_recall.v1"
# P46 advisory flag (default OFF). When set, an unpinned/DRAFT self-dead-end record that
# suppresses a *pinned* workspace also carries a strict NOTE that the block may be stale
# post-repin. Advisory-only: the verdict string and return value are byte-identical whether
# or not the flag is set (Phase-1 emits an additive field only; it never flips the block).
_EXPIRY_STRICT_FLAG = "AUDITOOOR_DEAD_END_EXPIRY_STRICT"
KDE = Path(__file__).resolve().parent.parent / "reports" / "known_dead_ends.jsonl"
SELF_CLASS = "self-source-verification-falsification"
_MARKER_RE = re.compile(
    r"<!--\s*sv-falsifies:\s*(?P<claim>.+?)\s*\|\s*axis:\s*(?P<axis>[\w-]+)\s*"
    r"\|\s*recovery:\s*(?P<recovery>[\w./:-]+)\s*-->", re.I)
_REBUTTAL_RE = re.compile(r"(?:<!--\s*)?self-dead-end-rebuttal:\s*(.+?)(?:\s*-->)?\s*$", re.I | re.M)
_STOP = set("the a an of to in is are be for and or with that this it on at by as into "
            "victim funds fund loss claim impact permanent receiver user via after before".split())


def _pin(ws: Path) -> str | None:
    scope = ws / "SCOPE.md"
    if scope.is_file():
        m = re.search(r"[Aa]udit pin[^:`]*[:`]\s*`?([0-9a-f]{7,40})`?", scope.read_text(errors="replace"))
        if m:
            return m.group(1)
    return None


def _tokens(s: str) -> set:
    return {w for w in re.findall(r"[a-z_]{4,}", (s or "").lower()) if w not in _STOP}


def _load_self_dead_ends():
    out = []
    if KDE.is_file():
        for ln in KDE.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if r.get("dead_end_class") == SELF_CLASS:
                out.append(r)
    return out


def _rebuttal(text):
    for m in _REBUTTAL_RE.finditer(text):
        reason = (m.group(1) or "").strip().strip("-").strip()
        if 0 < len(reason) <= 200:
            return reason
    return None


def gate(draft_path: Path, ws: Path, strict: bool) -> dict:
    text = draft_path.read_text(encoding="utf-8", errors="replace")
    out = {"schema": SCHEMA, "draft": str(draft_path)}
    records = _load_self_dead_ends()
    if not records:
        out["verdict"] = "pass-no-self-dead-ends"
        out["reason"] = "no self-source-verification-falsification records in known_dead_ends.jsonl"
        return out
    pin = _pin(ws) if ws else None
    # the draft's impact claim = its title + first 600 chars (Summary/Impact region)
    claim_tokens = _tokens(text[:800])
    for r in records:
        ft = _tokens(r.get("falsified_claim", ""))
        if not ft:
            continue
        overlap = len(ft & claim_tokens) / max(1, len(ft))
        same_pin = (not pin) or (not r.get("target_pin")) or (pin[:12] == str(r.get("target_pin"))[:12])
        if overlap >= 0.5 and same_pin:
            reb = _rebuttal(text)
            if reb:
                out["verdict"] = "ok-rebuttal"; out["reason"] = f"self-dead-end-rebuttal: {reb}"; return out
            # extension-distinct escape (R47-style): the draft must say the new attack defeats the recovery
            if re.search(r"extension-distinct|defeats the (?:prior |previously-found )?recovery|"
                         r"pin advance|re-introduced", text, re.I):
                out["verdict"] = "pass-extension-distinct"
                out["reason"] = f"draft argues extension-distinct vs {r.get('sv_record_id','SV')}"
                return out
            out["verdict"] = "fail-blocked-self-dead-end"
            out["reason"] = (f"this impact claim was already disproved by our own {r.get('sv_record_id','SV-lane')} "
                             f"at pin {str(r.get('target_pin',''))[:12]} via recovery {r.get('recovery_path_cited','?')}. "
                             f"Cite a pin advance, an extension-distinct argument, or self-dead-end-rebuttal: <reason>.")
            out["matched_record"] = {"sv": r.get("sv_record_id"), "recovery": r.get("recovery_path_cited"),
                                     "pin": r.get("target_pin"), "overlap": round(overlap, 2)}
            # P46 (advisory-only, additive, DEFAULT OFF): the matched record is UNPINNED/DRAFT
            # yet the workspace IS pinned - the block rides the `not r.get("target_pin")` escape
            # at line ~98, so it fires regardless of whether the pin advanced past the disproof,
            # and may be STALE post-repin. Under AUDITOOOR_DEAD_END_EXPIRY_STRICT ONLY, emit a
            # read-only NOTE (extra keys; never touches the verdict string, matched_record, or
            # rc). Flag-unset is byte-identical to pre-P46. Keys ONLY on the record-side unpinned
            # case (`not r.get("target_pin")`), NOT the ws-side `not pin` clause.
            if os.environ.get(_EXPIRY_STRICT_FLAG) and pin and not r.get("target_pin"):
                out["unpinned_draft_advisory"] = (
                    f"unpinned/DRAFT self-dead-end record (sv={r.get('sv_record_id','SV')}) "
                    f"suppressing a pinned workspace (pin {pin[:12]}); this block does not "
                    f"track a pin advance and may be stale post-repin - re-verify the "
                    f"recovery path still holds, or re-promote the record pin-keyed.")
            return out
    out["verdict"] = "pass-no-match"
    out["reason"] = f"no self-falsified claim matches this draft at pin {pin or '(unknown)'}"
    return out


def promote(marker_file: Path, ws: Path) -> dict:
    text = marker_file.read_text(encoding="utf-8", errors="replace")
    pin = _pin(ws) if ws else None
    written, skipped = [], []
    KDE.parent.mkdir(parents=True, exist_ok=True)
    existing = KDE.read_text(errors="replace") if KDE.is_file() else ""
    for m in _MARKER_RE.finditer(text):
        claim = m.group("claim").strip()
        if not pin:
            skipped.append({"claim": claim[:80], "reason": "no target_pin (SCOPE.md audit pin) - recall is pin-keyed, refusing to write"})
            continue
        rec = {
            "dead_end_class": SELF_CLASS,
            "workspace": ws.name if ws else None,
            "falsified_claim": claim,
            "falsification_axis": m.group("axis").strip(),
            "recovery_path_cited": m.group("recovery").strip(),
            "sv_record_id": "sv-" + str(abs(hash(claim)) % 100000),
            "target_pin": pin,
            "do_not_reescalate": True,
        }
        if claim[:60] in existing:
            skipped.append({"claim": claim[:80], "reason": "already recorded"})
            continue
        with KDE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        written.append(rec["sv_record_id"])
    return {"schema": SCHEMA, "mode": "promote-marker", "written": written, "skipped": skipped,
            "target_pin": pin}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", nargs="?", type=Path)
    ap.add_argument("--workspace", type=Path)
    ap.add_argument("--promote-marker", type=Path)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = args.workspace.expanduser().resolve() if args.workspace else None

    if args.promote_marker:
        if not args.promote_marker.is_file():
            print(f"[self-dead-end] no marker file: {args.promote_marker}"); return 2
        out = promote(args.promote_marker.expanduser().resolve(), ws or Path.cwd())
        print(json.dumps(out, indent=2) if args.json else
              f"[self-dead-end] promoted {len(out['written'])} record(s), skipped {len(out['skipped'])}")
        return 0

    if not args.draft or not args.draft.is_file():
        print(f"[self-dead-end] no draft: {args.draft}"); return 2
    out = gate(args.draft.expanduser().resolve(), ws, args.strict)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[self-dead-end-recall] {out['verdict']}: {out.get('reason','')}")
    return 1 if (out["verdict"].startswith("fail") and args.strict) else 0


if __name__ == "__main__":
    raise SystemExit(main())
