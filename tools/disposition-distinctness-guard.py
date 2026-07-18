#!/usr/bin/env python3
"""disposition-distinctness-guard.py - anti-false-negative gate on NEGATIVE dispositions.

THE PROBLEM (operator-caught 2026-07-01, generalized from a reflexive NUVA dedup-kill):
every finding-KILL path in the pipeline (dup-of-audit / OOS / known-issue / R47 / R53 /
upstream-equivalent / designed-as-intended) fails CLOSED on SHALLOW evidence - a keyword,
a function-name overlap, a file-path match, a firm+date - WITHOUT proving the prior-art
actually matches the finding, and WITHOUT any adversarial verification before the finding
is closed. Adversarial rigor (adversarial-candidate-verify.py) is applied ONLY to POSITIVE
findings before FILING. The asymmetry is a false-NEGATIVE machine: killing a finding is
EASIER than keeping it, so genuine distinct findings die quietly on a shallow match.

THE FIX (invert the asymmetry - killing must be HARDER than keeping):
A kill is PERMITTED only when the disposition carries a FOUR-AXIS distinctness record
proving the finding matches the cited prior-art / OOS clause on ALL FOUR axes, each with a
concrete source-cited justification:
  1. root_cause  - same buggy line / same missing check?
  2. attack_path - same entrypoint, call sequence, trigger?
  3. privilege   - same attacker class / preconditions?
  4. impact      - same concrete outcome / same severity row?
If ANY axis is `differ` -> the finding is materially DISTINCT -> KEEP OPEN (do not kill).
If the four-axis record is MISSING/incomplete or any axis is `unknown` -> FAIL OPEN
(keep the finding live) - a shallow/keyword-only kill is rejected. Only an all-`match`
record with evidence on every axis permits the kill. This is symmetric to
adversarial-candidate-verify's "refuted-if-uncertain": here it is "kept-if-uncertain".

MODES:
  --record <file.json>   evaluate a single disposition record; exit 0 = kill-permitted,
                         1 = keep-open (blocked). Emits the verdict JSON.
  --sweep <ws>           retro-sweep: scan a workspace's persisted KILL dispositions
                         (.auditooor/oos_check_*.json, known_dead_ends.jsonl,
                         mechanism_dispositions.jsonl refutations, duplicate/R53 outputs)
                         and classify each as GUARDED (valid four-axis all-match) or
                         SHALLOW (no/incomplete four-axis record). Answers "how many did we
                         kill on shallow evidence" and FLAGS them for re-examination.
                         exit 0 = no shallow kills, 1 = shallow kills found.

Override marker (visible line or HTML comment, <=200 chars; per-gate operator approval
required per CLAUDE.md - never self-apply): `distinctness-guard-rebuttal: <reason>`.

Schema: auditooor.disposition_distinctness_guard.v1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_ID = "auditooor.disposition_distinctness_guard.v1"

AXES = ("root_cause", "attack_path", "privilege", "impact")

# Disposition types that CLOSE/KILL a finding and therefore need the four-axis proof.
KILL_DISPOSITION_TYPES = {
    "dupe", "duplicate", "dup-of-audit", "dupe-of-audit",
    "oos", "out-of-scope", "oos-acknowledged",
    "known-issue", "known_issue", "known-dead-end",
    "r47", "r53", "prior-audit", "superseded",
    "upstream", "upstream-equivalent", "upstream_inherited",
    "designed-as-intended", "r45",
    "refuted", "refuted-known-issue", "kill",
}

# DEDUP / prior-art-equivalence kills: a claim that the finding is THE SAME as some
# prior art. These are the reflexive-dedup false-negative risk and REQUIRE a four-axis
# all-`match` proof; a source-cited "reason" alone is NOT enough (citing the prior art
# does not prove distinctness on all four axes - that IS the trap this guard closes).
DEDUP_DISPOSITION_TYPES = {
    "dupe", "duplicate", "dup-of-audit", "dupe-of-audit",
    "r47", "r53", "prior-audit", "superseded",
    "upstream", "upstream-equivalent", "upstream_inherited",
}
# REFUTATION-class kills: a claim the finding is not-reachable / false-positive /
# design-intent / out-of-scope-by-code. These do NOT need a four-axis dedup proof; a
# SOURCE-CITED reason (>=1 file:line + substantive text) is the correct evidence, the
# same bar as an agent-cleared mechanism cell. A bare "KILLED" / keyword-only reason
# is still shallow. (Refinement surfaced by the strata re-audit: adversarial-verify's
# reachability refutations carry cited reasons but no four-axis block - they are
# legitimate kills, not the reflexive-dedup pattern.)

_REBUTTAL_RE = re.compile(
    r"distinctness-guard-rebuttal\s*:\s*(?P<reason>[^\n>]{1,200})", re.IGNORECASE
)

# A concrete source citation inside a free-text refutation reason: `File.sol:123`,
# `path/x.go:45`, `Foo.sol#L12`, or "line 424-430". Discriminates a real refutation
# from a keyword-only kill.
_SOURCE_CITATION_RE = re.compile(
    r"[\w/.\-]+\.(?:sol|go|rs|move|vy|cairo|py)(?::|#l?)\d+|line[s]?\s+\d+", re.IGNORECASE
)

# Minimum evidence length for an axis justification to count as "cited" (not a bare word).
_MIN_AXIS_EVIDENCE = 20
# Minimum length for a free-text refutation reason to count as substantive.
_MIN_REFUTATION_REASON = 40


def _rebuttal(text: str) -> str | None:
    if not text:
        return None
    m = _REBUTTAL_RE.search(text)
    if not m:
        return None
    reason = m.group("reason").strip()
    return reason or None


def _cited_refutation_reason(record: dict[str, Any]) -> str | None:
    """Return a source-cited, substantive refutation reason from the record, or None.
    Looks at `reason` / `kill_reason` / `justification` / `evidence` AND `verdict`
    (the mechanism_dispositions.jsonl schema embeds the reason inline as
    `verdict: "refuted: <cited reason>"`, so the citation lives in `verdict`).
    Requires >=1 concrete file:line citation AND length >= _MIN_REFUTATION_REASON, so a
    bare 'KILLED' or a short keyword-only 'matches-oos' verdict does NOT qualify (they
    lack a citation and/or the length), keeping the anti-false-negative teeth intact."""
    for key in ("reason", "kill_reason", "justification", "evidence", "verdict"):
        val = record.get(key)
        if isinstance(val, str) and len(val.strip()) >= _MIN_REFUTATION_REASON \
                and _SOURCE_CITATION_RE.search(val):
            return val.strip()
    return None


def evaluate_distinctness(record: dict[str, Any]) -> dict[str, Any]:
    """Core evaluator. record carries `disposition_type`, optional `finding_ref` /
    `prior_art_ref`, and a `distinctness` block with the four axes. Returns a verdict
    dict. Verdict vocabulary:
      kill-permitted                 - all four axes `match` with evidence -> the kill is
                                       a genuine duplicate/OOS; closing is justified.
      keep-open-extension-distinct   - >=1 axis is `differ` -> the finding is materially
                                       distinct from the prior-art; MUST stay live.
      keep-open-insufficient-evidence- four-axis record missing/incomplete (or an axis has
                                       no cited evidence) -> fail OPEN, shallow kill rejected.
      keep-open-uncertain            - >=1 axis is `unknown` -> fail OPEN.
      kill-permitted-via-rebuttal    - blocked, but an explicit operator rebuttal rules it in.
      not-a-kill                     - disposition_type is not a kill -> guard N/A (pass).
    """
    out: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "disposition_type": str(record.get("disposition_type") or "").strip().lower(),
        "finding_ref": record.get("finding_ref"),
        "prior_art_ref": record.get("prior_art_ref"),
        "verdict": None,
        "axes": {},
        "reasons": [],
    }
    dtype = out["disposition_type"]
    if dtype and dtype not in KILL_DISPOSITION_TYPES:
        out["verdict"] = "not-a-kill"
        out["reasons"].append(f"disposition_type '{dtype}' is not a finding-kill; guard N/A")
        return out

    dist = record.get("distinctness")
    rebuttal = _rebuttal(json.dumps(record) if not isinstance(record.get("_text"), str)
                         else record["_text"])
    is_dedup = dtype in DEDUP_DISPOSITION_TYPES
    cited_reason = _cited_refutation_reason(record)

    # No four-axis record at all.
    if not isinstance(dist, dict) or not dist:
        # REFUTATION-class kill (not-reachable / false-positive / design-intent / OOS-by-
        # code): a SOURCE-CITED reason is the correct evidence and permits the kill. This
        # is NOT the reflexive-dedup pattern. DEDUP-class kills never qualify this way -
        # citing prior art does not prove four-axis distinctness.
        if not is_dedup and cited_reason:
            out["verdict"] = "kill-permitted-refutation-cited"
            out["reasons"].append(
                "refutation-class kill with a source-cited reason (file:line + substantive "
                f"reasoning) -> legitimate: {cited_reason[:160]}")
            return out
        out["verdict"] = "keep-open-insufficient-evidence"
        out["reasons"].append(
            ("dedup/prior-art kill without a four-axis proof" if is_dedup else
             "kill without a four-axis proof OR a source-cited refutation reason")
            + " - a shallow/keyword-only kill is rejected - FAIL OPEN, finding stays live")
        if rebuttal:
            out["verdict"] = "kill-permitted-via-rebuttal"
            out["rebuttal"] = rebuttal
        return out

    differ, unknown, matched = [], [], []
    for ax in AXES:
        cell = dist.get(ax)
        if not isinstance(cell, dict):
            unknown.append(ax)
            out["axes"][ax] = {"verdict": "missing", "evidence": ""}
            continue
        v = str(cell.get("verdict") or "").strip().lower()
        ev = str(cell.get("evidence") or cell.get("justification") or "").strip()
        out["axes"][ax] = {"verdict": v or "missing", "evidence": ev}
        if v == "differ":
            differ.append(ax)
        elif v == "match":
            if len(ev) >= _MIN_AXIS_EVIDENCE:
                matched.append(ax)
            else:
                # a "match" with no real evidence is not a proof of match.
                unknown.append(ax)
                out["axes"][ax]["verdict"] = "match-uncited"
        else:
            unknown.append(ax)

    # Decision (KEEP is the default; killing needs positive all-axis proof):
    if differ:
        out["verdict"] = "keep-open-extension-distinct"
        out["reasons"].append(
            f"axis/axes differ from prior-art: {', '.join(differ)} -> finding is materially "
            "distinct; do NOT kill (this is exactly the reflexive-dedup false-negative)")
    elif unknown:
        out["verdict"] = "keep-open-uncertain" if any(
            out["axes"][a]["verdict"] in ("unknown", "missing", "match-uncited") for a in unknown
        ) else "keep-open-insufficient-evidence"
        out["reasons"].append(
            f"axis/axes not proven `match` with citation: {', '.join(unknown)} -> FAIL OPEN "
            "(closing a finding requires positive proof on ALL four axes)")
    else:
        out["verdict"] = "kill-permitted"
        out["reasons"].append(
            "all four axes (root_cause, attack_path, privilege, impact) proven `match` with "
            "cited evidence -> the finding is a genuine duplicate/OOS; kill is justified")

    if out["verdict"].startswith("keep-open") and rebuttal:
        out["verdict"] = "kill-permitted-via-rebuttal"
        out["rebuttal"] = rebuttal
        out["reasons"].append(f"operator rebuttal rules in the kill: {rebuttal}")
    return out


def _verdict_permits_kill(verdict: str) -> bool:
    return verdict in ("kill-permitted", "kill-permitted-refutation-cited",
                       "kill-permitted-via-rebuttal", "not-a-kill")


# --------------------------------------------------------------------------- sweep

def _iter_kill_dispositions(ws: Path):
    """Yield (source_path, record, text) for persisted KILL dispositions in a ws.
    Best-effort across the known sidecar shapes the recon mapped."""
    ad = ws / ".auditooor"
    if not ad.is_dir():
        return
    # OOS check sidecars (verdict=matches-oos is a kill).
    for fp in sorted(ad.glob("oos_check_*.json")):
        try:
            r = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(r, dict) and str(r.get("verdict") or "").lower() in (
                "matches-oos", "out-of-scope", "oos"):
            r.setdefault("disposition_type", "oos")
            yield fp, r, fp.read_text(encoding="utf-8", errors="replace")
    # mechanism_dispositions.jsonl - refuted/known-issue rows kill a mechanism cell.
    mdp = ad / "mechanism_dispositions.jsonl"
    if mdp.is_file():
        for line in mdp.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                v = str(r.get("verdict") or "").lower()
                if any(k in v for k in ("refut", "known", "dup", "oos", "kill", "superseded")):
                    r.setdefault("disposition_type", "known-issue")
                    yield mdp, r, line
    # known_dead_ends.jsonl (repo-level or ws-level).
    for cand in (ws / "reports" / "known_dead_ends.jsonl", ad / "known_dead_ends.jsonl"):
        if cand.is_file():
            for line in cand.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict) and str(r.get("kill_verdict") or r.get("verdict") or ""):
                    r.setdefault("disposition_type", "known-dead-end")
                    yield cand, r, line
    # duplicate / R53 supersede outputs.
    for fp in list(ad.glob("*duplicate*preflight*.json")) + list(ad.glob("*supersede*.json")):
        try:
            r = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(r, dict) and any(k in str(r.get("verdict") or "").lower()
                                       for k in ("duplicate", "superseded")):
            r.setdefault("disposition_type", "dupe")
            yield fp, r, fp.read_text(encoding="utf-8", errors="replace")


def sweep_workspace(ws: Path) -> dict[str, Any]:
    guarded, shallow = [], []
    for src, rec, text in _iter_kill_dispositions(ws):
        rec = dict(rec)
        rec["_text"] = text
        res = evaluate_distinctness(rec)
        item = {
            "source": str(src.relative_to(ws)) if str(src).startswith(str(ws)) else str(src),
            "disposition_type": res["disposition_type"],
            "verdict": res["verdict"],
            "finding_ref": rec.get("finding_ref") or rec.get("record_id") or rec.get("finding"),
        }
        if _verdict_permits_kill(res["verdict"]) and res["verdict"] != "keep-open-insufficient-evidence":
            guarded.append(item)
        else:
            shallow.append(item)
    return {
        "schema_id": SCHEMA_ID,
        "mode": "sweep",
        "workspace": ws.name,
        "kills_total": len(guarded) + len(shallow),
        "guarded": guarded,
        "shallow": shallow,
        "shallow_count": len(shallow),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--record", help="path to a single disposition record JSON")
    g.add_argument("--sweep", help="path to a workspace to retro-sweep for shallow kills")
    ap.add_argument("--json", action="store_true", help="emit full JSON")
    args = ap.parse_args(argv)

    if args.record:
        p = Path(args.record).expanduser()
        try:
            rec = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError) as e:
            print(f"[distinctness-guard] ERROR reading record: {e}", file=sys.stderr)
            return 2
        res = evaluate_distinctness(rec if isinstance(rec, dict) else {})
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[distinctness-guard] verdict={res['verdict']}")
            for r in res["reasons"]:
                print(f"  - {r}")
        return 0 if _verdict_permits_kill(res["verdict"]) else 1

    ws = Path(args.sweep).expanduser().resolve()
    if not (ws / ".auditooor").is_dir():
        print(f"[distinctness-guard] ERROR: no .auditooor/ in {ws}", file=sys.stderr)
        return 2
    res = sweep_workspace(ws)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[distinctness-guard] sweep {res['workspace']}: {res['kills_total']} kill "
              f"disposition(s); {res['shallow_count']} SHALLOW (no valid four-axis proof)")
        for it in res["shallow"]:
            print(f"  SHALLOW [{it['disposition_type']}] {it['source']} "
                  f"verdict={it['verdict']} finding={it['finding_ref']}")
    return 1 if res["shallow_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
