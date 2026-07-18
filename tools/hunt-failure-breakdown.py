#!/usr/bin/env python3
"""hunt-failure-breakdown.py - make a 0-finding hunt AUDITABLE.

A per-function LLM hunt that returns applies_to_target="no" for ~2000 tasks tells
you NOTHING about WHY each candidate died. "0 findings" is a black box. This tool
reads a workspace's hunt sidecars and categorizes every "no" verdict into an
auditable failure-aspect breakdown, so the operator can see whether the hunt
found nothing because the target is SAFE, because the QUESTIONS DID NOT APPLY
(e.g. EVM questions fired at a Rust node - a question-bank-fit signal), because a
candidate was UNANCHORED (R76), or because it failed a specific EXPLOITABILITY
AXIS (REACH / TRAVERSE / IMPACT / ORIGINAL / PROVEN).

Categories (per "no" verdict):
  question-inapplicable : the hypothesis is for a different target/stack
                          (notes/falsification mention EVM/solidity/bridge/cross-
                          chain/"if X had ..." while the target is not that). This
                          is the question-bank-fit signal, NOT target safety.
  unanchored-r76        : applies but file_path_hint is NA/conceptual (no real src).
  axis-REACH            : not reachable on default / privileged / unit-test-only.
  axis-TRAVERSE         : blocked by a defense.
  axis-IMPACT           : self / below-threshold / no rubric row / non-self absent.
  axis-ORIGINAL         : known / acknowledged / designed-as-intended / dupe.
  axis-PROVEN           : no real PoC path.
  genuine-safe          : real code inspected, no defect (the honest clean result).
  uncategorized         : a "no" whose reason text matched no rule.

Emits <ws>/.auditooor/hunt_failure_breakdown.json + a console rollup. The point:
"0 findings" must say WHAT FAILED ON WHAT ASPECT.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "auditooor.hunt_failure_breakdown.v1"
_REPO = Path(__file__).resolve().parent.parent
_DERIVED = _REPO / "audit" / "corpus_tags" / "derived"

_INAPPLICABLE = re.compile(
    r"(?i)(tailored to|specific to|designed for|applies to)\s+(evm|solidity|"
    r"ethereum|cosmos|substrate|move|a bridge|cross-chain|smart contract)"
    r"|\bif\s+\w+\s+(had|were|used)\b|not applicable to|does not apply|"
    r"\b(evm|solidity|erc-?20|erc-?721|nomad|synapse|uniswap)\b[^.\n]{0,40}"
    r"(zebra|zcash|rust|this (target|node|codebase))|"
    r"(zebra|zcash)[^.\n]{0,40}(is not|does not have|has no)\b")
_NA = re.compile(r"(?i)^\s*(na|n/?a|none|conceptual|unavailable|not found)\s*$")
_AXES = {
    "axis-REACH":    re.compile(r"(?i)\b(unprivileged|reachab|default config|"
                                r"opt-?in|disabled by default|authenticated|admin-only|"
                                r"unit test|non-default|not reachable)\b"),
    "axis-TRAVERSE": re.compile(r"(?i)\b(defense|guard|blocked by|mitigat|"
                                r"already (checked|validated|enforced)|cap)\b"),
    "axis-IMPACT":   re.compile(r"(?i)\b(self-?(harm|inflicted|throttl)|below "
                                r"threshold|no rubric|non-self|recoverable|transient|"
                                r"griefing|no fund|no impact|informational)\b"),
    "axis-ORIGINAL": re.compile(r"(?i)\b(known issue|acknowledged|designed as "
                                r"intended|by design|dupe|duplicate|already (reported|"
                                r"fixed))\b"),
    "axis-PROVEN":   re.compile(r"(?i)\b(no poc|cannot (prove|reproduce)|theoretical|"
                                r"no real path|unproven)\b"),
}
_SAFE = re.compile(r"(?i)\b(correctly (handles|validates|checks)|already (safe|"
                   r"bounded|guarded)|properly (validated|checked)|no (defect|bug|"
                   r"vulnerabilit)|code is (safe|correct))\b")


_SIDECAR_DIR_GLOBS = ("haiku_harness_*", "mimo_harness_*", "mega_perfn_*",
                      "mega_*", "mimo_hunt_*", "mimo_reeval*")


def _sidecar_dirs(ws_name: str) -> list[Path]:
    # Discover every derived dir that may hold this workspace's sidecars, across
    # the haiku/mimo/mega harness formats (dydx hunted into mimo_harness_dydx_full
    # + mega_perfn_dydx, not haiku). The per-file workspace field is the real
    # filter (applied in build()); here we just enumerate candidate dirs.
    seen = {}
    if not _DERIVED.is_dir():
        return []
    for pat in _SIDECAR_DIR_GLOBS:
        for d in _DERIVED.glob(pat):
            if d.is_dir():
                seen[str(d)] = d
    try:
        for d in _DERIVED.iterdir():
            if d.is_dir() and str(d) not in seen and any(d.glob("mimo_harness_*.json")):
                seen[str(d)] = d
    except OSError:
        pass
    return list(seen.values())


def _result_obj(rec: dict):
    res = rec.get("result")
    if isinstance(res, str):
        try:
            return json.loads(res)
        except (ValueError, TypeError):
            return {"_raw": res}
    return res if isinstance(res, dict) else {}


def categorize(res: dict, target_lang: str = "rust") -> str:
    applies = str(res.get("applies_to_target") or "").strip().lower()
    if applies in ("yes", "maybe"):
        return "candidate-" + applies
    notes = " ".join(str(res.get(k) or "") for k in
                     ("notes", "falsification_attempt", "candidate_finding", "dupe_check"))
    hint = str(res.get("file_path_hint") or "")
    # 1. question-inapplicable: hypothesis for a different stack/target
    if _INAPPLICABLE.search(notes):
        return "question-inapplicable"
    # 2. unanchored (R76): no real source path
    if _NA.match(hint.strip()) or not hint.strip():
        # but only count as unanchored if the text isn't an inapplicability note
        if not _SAFE.search(notes):
            return "unanchored-r76"
    # 3. explicit safety statement
    if _SAFE.search(notes):
        return "genuine-safe"
    # 4. exploitability-axis match (first axis whose vocabulary appears)
    for axis, rx in _AXES.items():
        if rx.search(notes):
            return axis
    return "uncategorized"


def build(ws: Path) -> dict:
    cats = Counter()
    examples: dict[str, str] = {}
    total = 0
    for d in _sidecar_dirs(ws.name):
        for f in d.glob("mimo_harness_*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            rec = rec if isinstance(rec, dict) else (rec[0] if isinstance(rec, list) and rec else {})
            if str(rec.get("workspace") or "") != ws.name:
                continue  # dirs now span all workspaces; keep only this ws
            res = _result_obj(rec)
            if not res:
                continue
            total += 1
            cat = categorize(res)
            cats[cat] += 1
            if cat not in examples:
                examples[cat] = str(res.get("candidate_finding") or res.get("notes") or "")[:120]
    return {
        "schema": SCHEMA, "workspace": str(ws), "ws_name": ws.name,
        "total_verdicts": total,
        "breakdown": dict(cats.most_common()),
        "examples": examples,
        "interpretation": {
            "genuinely_safe_or_axis_fail": sum(v for k, v in cats.items()
                if k.startswith("axis-") or k == "genuine-safe"),
            "question_bank_misfit": cats.get("question-inapplicable", 0),
            "unanchored": cats.get("unanchored-r76", 0),
            "real_candidates": cats.get("candidate-yes", 0) + cats.get("candidate-maybe", 0),
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Auditable hunt failure-aspect breakdown.")
    ap.add_argument("workspace")
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    ws = Path(a.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[hunt-failure-breakdown] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    rep = build(ws)
    out = Path(a.out).expanduser() if a.out else (ws / ".auditooor" / "hunt_failure_breakdown.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rep, indent=2, sort_keys=True), encoding="utf-8")
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[hunt-failure-breakdown] {ws.name}: {rep['total_verdicts']} verdicts ->")
        for k, v in rep["breakdown"].items():
            print(f"    {k:<22} {v}")
        i = rep["interpretation"]
        print(f"  => question-bank-misfit={i['question_bank_misfit']} "
              f"unanchored={i['unanchored']} safe/axis-fail={i['genuinely_safe_or_axis_fail']} "
              f"real-candidates={i['real_candidates']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
