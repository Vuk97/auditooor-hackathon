#!/usr/bin/env python3
"""business_flow_decompose - the combination-bug axis (article Part III, sec 5.2).

Module + per-function decomposition catches each unit in isolation, but many
real vulnerabilities live in a BUSINESS FLOW that crosses several modules - each
module looks correct alone, the assembled flow is wrong (strata 2026-07-01: the
insolvency loss path was a state-TRANSITION across Accounting->AccountingLib->
Tranche that the per-fn harness never exercised).

This tool derives cross-module flow slices of the five methodology types and
checks each was DRIVEN (>=1 member has a hunt verdict or a harness). It is a new
enumeration axis over the per-fn/per-invariant ones, and it is deliberately
LANGUAGE-AGNOSTIC: it groups the workspace's in-scope functions by lifecycle
VERB and shared state, which appear the same way in Solidity / Go / Rust /
Cosmos / Cairo. It does not parse a language.

Five flow types (methodology sec 5.2):
  operation           - a user operation from entrypoint to all its state changes
  asset-lifecycle     - an asset/balance from creation to disappearance
  state-machine       - the legal transitions of an entity's status/phase
  long-transaction    - multi-tx / multi-stage / multi-actor process + recovery
  invariant           - a system constraint that must hold across many paths

Outputs `<ws>/.auditooor/business_flows.jsonl` and a coverage summary. Advisory:
an UNDRIVEN flow is a smell (a cross-module flow no hunt/harness touched), not an
automatic finding.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Lifecycle verb -> flow type. These verbs are language-neutral (a Go MsgWithdraw,
# a Rust fn withdraw, a Solidity withdraw() all match). Grouped by the flow the
# verb participates in. A function may join more than one flow.
_ASSET_VERBS = ("mint", "burn", "deposit", "withdraw", "redeem", "transfer",
                "stake", "unstake", "borrow", "repay", "supply", "send", "receive",
                "wrap", "unwrap", "issue", "collect", "distribute", "accrue")
_STATE_VERBS = ("open", "close", "pause", "unpause", "activate", "deactivate",
                "enable", "disable", "start", "stop", "initialize", "finalize",
                "settle", "resolve", "expire", "transition", "setstate", "setstatus",
                "setphase", "advance", "lock", "unlock")
_LONGTX_VERBS = ("request", "claim", "cancel", "commit", "reveal", "propose",
                 "queue", "schedule", "execute", "cooldown", "liquidate",
                 "challenge", "dispute", "confirm", "batch", "flush", "process",
                 "rebalance", "checkpoint", "snapshot")


def _fnkey(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _base_fn(fn: str) -> str:
    """Strip a class/module prefix (Contract.fn -> fn) and a signature."""
    fn = (fn or "").split("(", 1)[0]
    if "." in fn:
        fn = fn.rsplit(".", 1)[-1]
    if "::" in fn:
        fn = fn.rsplit("::", 1)[-1]
    return fn


def _load_units(ws: Path) -> list:
    out = []
    p = ws / ".auditooor" / "inscope_units.jsonl"
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict) and (r.get("function") or r.get("fn")):
                out.append({"file": str(r.get("file", "")),
                            "fn": str(r.get("function") or r.get("fn"))})
    except OSError:
        pass
    return out


def _verb_hits(name_lc: str, verbs) -> list:
    return [v for v in verbs if v in name_lc]


def decompose(ws: Path) -> dict:
    units = _load_units(ws)
    # group by verb within each flow type; a flow = one verb-cluster spanning
    # >=2 in-scope functions (a genuine multi-function/likely cross-module flow).
    buckets: dict = {}  # (flow_type, verb) -> set of "file::fn"
    for u in units:
        base = _base_fn(u["fn"])
        nlc = _fnkey(base)
        for ftype, verbs in (("asset-lifecycle", _ASSET_VERBS),
                             ("state-machine", _STATE_VERBS),
                             ("long-transaction", _LONGTX_VERBS)):
            for v in _verb_hits(nlc, verbs):
                buckets.setdefault((ftype, v), set()).add(f"{u['file']}::{base}")
    flows = []
    for (ftype, verb), members in sorted(buckets.items()):
        if len(members) < 2:
            continue  # a single fn is covered by the per-fn axis already
        flows.append({
            "flow_id": f"BF-{ftype}-{verb}",
            "flow_type": ftype,
            "anchor_verb": verb,
            "members": sorted(members),
            "member_count": len(members),
        })
    # CALL-GRAPH / CROSS-FUNCTION grounded flows (the signal upgrade, all-lang):
    # each cross-function-invariant requirement is a set of functions the
    # cross-fn analysis found jointly bound by one invariant (e.g. deposit ->
    # {maxDeposit, deposit, previewDeposit} across Accounting + Tranche). That is
    # a genuine cross-module flow, derived from the call-graph, not a verb-name
    # cluster. Members carry real functions so coverage() can check them.
    for cand in ("cross_function_invariant_coverage.json",
                 "cross_function_invariant_requirements.json"):
        p = ws / ".auditooor" / cand
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        reqs = data.get("requirements") if isinstance(data, dict) else (data if isinstance(data, list) else [])
        seen_req = set()
        for r in (reqs if isinstance(reqs, list) else []):
            if not isinstance(r, dict):
                continue
            fns = r.get("functions") or []
            members = sorted({f"{f.get('file','')}::{_base_fn(str(f.get('name','')))}"
                              for f in fns if isinstance(f, dict) and f.get("name")})
            if len(members) < 2:
                continue  # single-fn requirement -> per-fn axis already covers it
            arm = str((fns[0] or {}).get("arm") or "").strip().lower() if fns else ""
            rid = str(r.get("invariant_id") or r.get("id") or arm or len(seen_req))
            if rid in seen_req:
                continue
            seen_req.add(rid)
            # classify by the arm verb where it maps, else a cross-fn invariant flow
            ftype = ("asset-lifecycle" if any(v in arm for v in _ASSET_VERBS) else
                     "state-machine" if any(v in arm for v in _STATE_VERBS) else
                     "long-transaction" if any(v in arm for v in _LONGTX_VERBS) else "invariant")
            flows.append({"flow_id": f"BF-xfn-{arm or rid}", "flow_type": ftype,
                          "anchor_verb": arm or rid, "members": members,
                          "member_count": len(members), "source": "cross-function-invariant"})
        break
    # operation flows: distinct entrypoint files (a per-file operation cluster).
    byfile: dict = {}
    for u in units:
        byfile.setdefault(str(u["file"]), 0)
        byfile[str(u["file"])] += 1
    return {"schema": "auditooor.business_flows.v1", "flows": flows,
            "flow_count": len(flows), "unit_count": len(units)}


_FLOW_INVARIANT_HINT = {
    "asset-lifecycle": "conservation: the asset's total is preserved across the flow "
                       "(sum in == sum out + fees); no value created or lost across modules",
    "state-machine": "legality: only legal state transitions occur across the flow; no "
                     "path reaches an illegal/stuck state or skips a required stage",
    "long-transaction": "atomicity+recovery: the multi-stage process completes or fully "
                        "recovers; no partial state strands funds; no double/early finalize",
    "operation": "end-to-end correctness of the user operation from entrypoint to all "
                 "cross-module state changes",
    "invariant": "the system constraint holds across every path in the flow",
}


def harness_targets(ws: Path, dec: dict | None = None) -> list:
    """P2c: flow-level CUT targets for harness authoring. Each DRIVABLE flow
    yields a target = its cross-module member files (the CUT set) + an
    invariant-class hint for the flow type, so harness authoring can build a
    FLOW-level invariant (not just a per-function one). This is what would have
    prompted a strata AccountingNavConservation harness that exercises the
    loss-transition across Accounting/AccountingLib/Tranche."""
    dec = dec or decompose(ws)
    out = []
    for fl in dec["flows"]:
        if fl["flow_type"] == "invariant" or not fl.get("members"):
            continue
        files = sorted({m.split("::", 1)[0] for m in fl["members"] if "::" in m})
        if len(files) < 2:
            continue  # a single-file flow is a per-fn harness target, not a cross-module one
        out.append({
            "schema": "auditooor.business_flow_harness_target.v1",
            "flow_id": fl["flow_id"], "flow_type": fl["flow_type"],
            "cut_files": files, "members": fl["members"],
            "invariant_hint": _FLOW_INVARIANT_HINT.get(fl["flow_type"], _FLOW_INVARIANT_HINT["operation"]),
        })
    return out


def _hunted_fnkeys(ws: Path) -> set:
    """The set of function keys that a hunt sidecar or harness touched."""
    keys = set()
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    try:
        import glob as _g
        for f in _g.glob(str(d / "*.json")):
            try:
                r = json.loads(Path(f).read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(r, dict):
                continue
            fa = r.get("function_anchor")
            fn = ""
            if isinstance(fa, dict):
                fn = str(fa.get("fn") or fa.get("function") or "")
            elif isinstance(fa, str) and fa.strip():
                # NUVA 2026-07-01: 184/380 hunt sidecars serialized function_anchor
                # as a JSON STRING (`'{"file":..,"fn":".."}'`) instead of a dict, so a
                # dict-only read silently DROPPED half the hunt evidence (burn /
                # sendTokens / custodyTokens uncredited -> business-flow-coverage +
                # completeness-matrix false-red on driven cross-module flows). Tolerate
                # both shapes: parse a string-serialized dict, else treat the string as
                # the fn name itself. False-green-safe (still needs a real fn anchor).
                try:
                    _fad = json.loads(fa)
                    fn = str(_fad.get("fn") or _fad.get("function") or "") if isinstance(_fad, dict) else fa
                except (ValueError, TypeError):
                    fn = fa
            if fn:
                keys.add(_fnkey(_base_fn(fn)))
    except OSError:
        pass
    return keys


_GO_PATH_RE = re.compile(r"src/[\w./-]+\.go")


def _mvc_cut_files(ws: Path) -> set:
    """Files that a MUTATION-VERIFIED mvc_sidecar / mutation_verify_coverage sidecar
    exercised as its CUT (code-under-test). A cross-module flow whose member FILE is
    the CUT of such a campaign IS driven by a harness (the SAME serving-join credit the
    completeness-matrix already applies for mvc coverage; the flow-coverage reader only
    consulted hunt sidecars, so a flow proven NEGATIVE by a real coverage-guided /
    mutation-verified campaign was false-red UNDRIVEN). NEVER-FALSE-PASS: only a sidecar
    flagged mutation_verified (or a non-vacuous / killed verdict) contributes, and only
    real ``src/...go`` paths it names (cut / bound_keeper / harness_path / mutant_desc /
    killing_assertion) are credited - a phantom path resolves to nothing downstream."""
    out: set = set()
    d = ws / ".auditooor" / "mvc_sidecar"
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.json")):
        try:
            r = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(r, dict):
            continue
        verd = str(r.get("verdict") or "").strip().lower()
        if not (r.get("mutation_verified") or verd in ("non-vacuous", "killed")):
            continue
        for k in ("cut", "bound_keeper", "harness_path", "mutant_desc",
                  "killing_assertion", "kill_evidence"):
            v = str(r.get(k) or "")
            for m in _GO_PATH_RE.findall(v):
                # a *_test.go harness path is not a member-file of a flow; keep only the
                # production CUT paths (members come from inscope production units).
                if not m.endswith("_test.go"):
                    out.add(m)
    return out


_FLOW_DISP_SCHEMA = "auditooor.business_flow_disposition.v1"
_FLOW_DISP_VERDICTS = {
    "driven-by-harness", "non-value-flow-terminal",
    "covered-by-fn-coverage-terminal", "negative-terminal",
}
_FLOW_DISP_MIN_RATIONALE = 60
_FILE_LINE_CITE_RE = re.compile(r"[\w./-]+\.(?:go|rs|sol):L?\d+")


def _load_flow_dispositions(ws: Path) -> dict:
    """flow_id -> accepted terminal disposition. A flow the verb/cross-fn decomposer
    surfaces that is a verb-NAME collision (Go ``errors.Unwrap`` matching the asset
    ``unwrap`` verb), a read-only capture, or a pure message-constructor cluster carries
    no cross-module VALUE/STATE transition to drive - it gets a terminal verdict here.

    NEVER-FALSE-PASS: a disposition credits a flow ONLY when (1) schema matches, (2)
    verdict is in the bounded terminal set, (3) rationale >= MIN chars (a real argument),
    (4) the rationale carries >=1 ``file.ext:LNN`` mechanism cite whose file EXISTS on
    disk (grounded in real in-scope code, not a keyword grep). A malformed / unproven row
    is dropped and the flow stays honestly UNDRIVEN."""
    p = ws / ".auditooor" / "business_flow_dispositions.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(d, dict) or d.get("schema") != _FLOW_DISP_SCHEMA:
        return {}
    out: dict = {}
    for row in d.get("dispositions") or []:
        if not isinstance(row, dict):
            continue
        fid = str(row.get("flow_id") or "").strip()
        verdict = str(row.get("verdict") or "").strip().lower()
        rationale = str(row.get("rationale") or "").strip()
        if not fid or verdict not in _FLOW_DISP_VERDICTS:
            continue
        if len(rationale) < _FLOW_DISP_MIN_RATIONALE:
            continue
        cite_src = rationale + " " + str(row.get("evidence_ref") or "")
        cite_ok = False
        for m in _FILE_LINE_CITE_RE.findall(cite_src):
            fp = m.split(":", 1)[0]
            if (ws / fp).is_file():
                cite_ok = True
                break
        if not cite_ok:
            continue
        out[fid] = {"verdict": verdict, "rationale": rationale,
                    "evidence_ref": str(row.get("evidence_ref") or "")}
    return out


def coverage(ws: Path, dec: dict | None = None) -> dict:
    dec = dec or decompose(ws)
    hunted = _hunted_fnkeys(ws)
    mvc_cuts = _mvc_cut_files(ws)
    flow_disp = _load_flow_dispositions(ws)
    undriven = []
    for fl in dec["flows"]:
        if fl["flow_type"] == "invariant":
            continue  # invariant flows are driven by the fuzz axis, not per-fn hunt
        mkeys = {_fnkey(m.split("::", 1)[-1]) for m in fl["members"]}
        mfiles = {m.split("::", 1)[0] for m in fl["members"]}
        # DRIVEN when (a) a member fn was hunted, OR (b) a member FILE is the CUT of a
        # mutation-verified campaign (harness-driven), OR (c) the flow carries an accepted
        # terminal disposition (verb-collision / read-only / message-constructor cluster).
        if fl["flow_id"] in flow_disp:
            continue
        if mfiles & mvc_cuts:
            continue
        if mkeys and not (mkeys & hunted):
            undriven.append(fl["flow_id"])
    n = len([f for f in dec["flows"] if f["flow_type"] != "invariant"])
    verdict = ("pass-no-flows" if n == 0 else
               "pass-all-flows-driven" if not undriven else
               "warn-undriven-flows")
    return {"verdict": verdict, "flow_count": dec["flow_count"],
            "drivable_flows": n, "undriven_flows": undriven,
            "undriven_count": len(undriven)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--write", action="store_true", help="write business_flows.jsonl")
    ap.add_argument("--coverage", action="store_true", help="report undriven flows")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace)
    dec = decompose(ws)
    if args.write:
        out = ws / ".auditooor" / "business_flows.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for fl in dec["flows"]:
                fh.write(json.dumps(fl, sort_keys=True) + "\n")
        # P2c: flow-level harness targets for the harness-authoring step.
        tgt = ws / ".auditooor" / "business_flow_harness_targets.jsonl"
        targets = harness_targets(ws, dec)
        with tgt.open("w", encoding="utf-8") as fh:
            for t in targets:
                fh.write(json.dumps(t, sort_keys=True) + "\n")
    rep = coverage(ws, dec) if args.coverage else dec
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        if args.coverage:
            print(f"[business-flow] {rep['verdict']}: {rep['drivable_flows']} drivable flow(s), "
                  f"{rep['undriven_count']} undriven")
            for f in rep["undriven_flows"][:20]:
                print(f"  UNDRIVEN: {f}")
        else:
            print(f"[business-flow] {dec['flow_count']} flow(s) across {dec['unit_count']} units")
    return 0


if __name__ == "__main__":
    sys.exit(main())
