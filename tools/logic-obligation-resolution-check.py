#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-LOGIC-OBLIGATION-RESOLUTION registered via agent-pathspec-register.py -->
"""logic-obligation-resolution-check.py - the terminal-verdict RESOLUTION gate for
the pre-hunt LOGIC REASONERS (docs/LOGIC_ARSENAL_ROADMAP.md, "ENFORCE, NOT ADVISORY").

The 8 core reasoners (callgraph-set-difference, atomic-sequence-economic-sequencer,
conservation-haircut-realization, default-degenerate-input, cross-contract-privilege-
trust-graph, adversarial-numeric-boundary-seeder, oracle-spot-price-manipulation,
crosschain-message-authenticity) + the language reasoners (go must-succeed panic,
rust account-owner/signer confusion, rust unchecked-arith) each EMIT an obligation
ledger (<ws>/.auditooor/*_obligations.jsonl). tools/exploit-queue.py INGESTS those
rows and tools/per-fn-mimo-batch-gen.py folds them into the per-fn OPEN-OBLIGATIONS
block so the step-3 hunt is STEERED by the reasoned obligation.

But nothing asserted the obligation ever reached a TERMINAL verdict: a reasoner
could emit 19 numeric-boundary obligations, the hunt could ignore all of them, and
audit-complete would still pass. That is the exact "reasoner-emitted obligation left
UNHUNTED / without a terminal verdict must FAIL audit-complete" hole the roadmap
names. This gate closes it.

RESOLUTION SEMANTICS (per obligation row):
  RESOLVED iff EITHER
    (a) the row's own ``proof_status`` OR ``quality_gate_status`` is in the TERMINAL
        set (killed / resolved / confirmed / filed / dispositioned / refuted /
        not_applicable / oos_rejected / a ``pass-*`` verified verdict), OR
    (b) a resolution sidecar row in
        <ws>/.auditooor/logic_obligation_resolutions.jsonl carries a TERMINAL
        ``state``/``verdict`` for this obligation's key (contract::function::attack_class,
        else file::function, else the row's ``obligation_id``).
  OPEN otherwise (needs_source / open / pending / '' / unknown).

The KILL-QUALITY of a value/conservation obligation (executed refutation vs grep) is
NOT this gate's job - that is the sibling ``executed-refutation-honesty`` signal
(tools/executed-refutation-negative-gate.py). This gate only asks "did every emitted
obligation reach A terminal verdict, and was the ledger CONSUMED by exploit_queue?".

CONSUMPTION: exploit_queue.json / exploit_queue.source_mined.json exists AND is at
least as new as the newest obligation ledger (the feed ran after the reasoners). A
never-consumed ledger is reported (advisory) but does not by itself fail - the OPEN
count is the load-bearing failure axis.

POLICY (advisory-first, per the enforcement-wiring discipline):
  - Default `make audit-complete`: WARN-pass (ok=True), reporting the OPEN count LOUD.
  - Fail-closed (ok=False, verdict ``fail-logic-obligation-unresolved``) ONLY under the
    dedicated AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT=1 OR the global AUDITOOOR_L37_STRICT=1
    when >=1 emitted obligation is still OPEN.
  - Fail-OPEN (WARN-pass) when NO reasoner ledger exists / no dataflow substrate
    (nothing was reasoned, so nothing to resolve) - mirrors callgraph-set-difference.

CLI: python3 tools/logic-obligation-resolution-check.py --workspace <ws> [--json] [--strict]
Exit: 0 = pass/advisory-warn-pass; 1 = fail (open obligations under strict); 2 = usage/IO.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Registry: obligation ledger filename -> (reasoner tool, language scope).
# Kept in lock-step with the step-2d-* runbook steps + exploit-queue._gather_from_*.
_REASONER_LEDGERS: tuple[tuple[str, str, str], ...] = (
    ("unguarded_mutation_obligations.jsonl", "callgraph-set-difference-hunter.py", "any"),
    ("atomic_sequence_obligations.jsonl", "atomic-sequence-economic-sequencer.py", "any"),
    ("conservation_haircut_obligations.jsonl", "conservation-haircut-realization-check.py", "any"),
    ("degenerate_input_verdict_obligations.jsonl", "default-degenerate-input-verdict-reasoner.py", "any"),
    ("signature_replay_digest_binding_obligations.jsonl", "signature-permit-replay-digest-binding-set-difference.py", "any"),
    ("payload_derived_trusted_dispatch_obligations.jsonl", "cross-contract-privilege-trust-graph.py", "any"),
    ("numeric_boundary_obligations.jsonl", "adversarial-numeric-boundary-seeder.py", "any"),
    ("oracle_spot_price_obligations.jsonl", "oracle-spot-price-manipulation-reasoner.py", "any"),
    ("crosschain_forgery_obligations.jsonl", "crosschain-message-authenticity-reasoner.py", "any"),
    ("mustsucceed_panic_obligations.jsonl", "go-mustsucceed-panic-reachability.py", "go"),
    ("account_confusion_obligations.jsonl", "rust-account-owner-signer-confusion.py", "rust"),
    ("rust_unchecked_arith_obligations.jsonl", "rust-unchecked-arith-value-overflow.py", "rust"),
    ("rust_numeric_overflow_obligations.jsonl", "rust-numeric-overflow-underflow-scan.py", "rust"),
    ("coupled_state_completeness_obligations.jsonl", "coupled-state-completeness-graph.py", "any"),
    ("directional_rounding_asymmetry_obligations.jsonl", "directional-rounding-asymmetry.py", "any"),
    # NOVELTY LAYER: PISVS-derived protocol-invariant violations (corpus_class=null).
    # A NOVEL candidate MUST reach a terminal verdict (hunt or cited-disposition) -
    # an unhunted NOVEL obligation FAILS audit-complete under STRICT (never silently
    # dropped). proof_status="open" until resolved.
    ("novelty_obligations.jsonl", "protocol-invariant-synth-violation-search.py", "any"),
    # WIRING WAVE (8 SHIP-verified reasoners). Each ledger's survivors must reach a
    # terminal verdict (executed refutation / disposition / filed) or audit-complete
    # FAILS at step-5. Kept in lock-step with the step-2d/2e/2f/2g runbook steps +
    # exploit-queue._gather_from_*. DIRM writes under the dirm/ subdir (aud / fname
    # resolves the subdir path).
    ("mustsucceed_arith_overflow_obligations.jsonl",
     "go-mustsucceed-arith-overflow-halt.py", "go"),
    ("transitive_crosscontract_cei.jsonl",
     "transitive-crosscontract-cei.py", "sol"),
    ("goroutine_shared_state_race_hypotheses.jsonl",
     "goroutine-shared-state-race.py", "go"),
    ("zk_constraint_coverage_obligations.jsonl",
     "zk-constraint-coverage.py", "zk"),
    ("amm_structural_manipulation_obligations.jsonl",
     "amm-structural-manipulation.py", "any"),
    ("authz_type_exhaustiveness_obligations.jsonl",
     "authz-type-exhaustiveness.py", "go"),
    ("permanent_freeze_dos_obligations.jsonl",
     "permanent-freeze-dos.py", "both"),
    ("dirm/differential_invariant_residual_obligations.jsonl",
     "differential-invariant-residual-miner.py", "any"),
    # WIRING WAVE (4 reasoners + assumption-negation novelty engine). Each ledger's
    # survivors must reach a terminal verdict or audit-complete FAILS at step-5.
    # Kept in lock-step with the step-2d/2g runbook steps + exploit-queue._gather_from_*.
    ("crossimpl_consensus_divergence_obligations.jsonl",
     "crossimpl-consensus-divergence.py", "go"),
    ("composition_novelty_obligations.jsonl",
     "composition-novelty-search.py", "any"),
    ("slice_oob_bounds_taint.jsonl",
     "slice-oob-bounds-taint.py", "go"),
    ("epoch_restake_replay_obligations.jsonl",
     "epoch-restake-replay.py", "go"),
    # NOVELTY ENGINE #3: reachable negated-assumption survivors (corpus_class=null).
    ("assumption_negation_obligations.jsonl",
     "assumption-negation-reachability.py", "any"),
    # WIRING WAVE (6 SHIP-verified reasoners). Each ledger's survivors must reach a
    # terminal verdict (executed refutation / disposition / filed) or audit-complete
    # FAILS at step-5. Lock-step with the step-2d-* runbook steps +
    # exploit-queue._gather_from_*.
    ("push_payment_misroute_obligations.jsonl",
     "push-payment-misroute.py", "any"),
    ("return_aliasing_escape_obligations.jsonl",
     "return-aliasing-escape.py", "go"),
    ("unbounded_alloc_resource_exhaustion_obligations.jsonl",
     "unbounded-alloc-resource-exhaustion.py", "both"),
    ("nondeterministic_deserialization_obligations.jsonl",
     "nondeterministic-deserialization.py", "go"),
    ("go_bitcoin_protocol_validation_obligations.jsonl",
     "go-bitcoin-protocol-validation.py", "go"),
    ("mpc_round_proof_obligation_obligations.jsonl",
     "mpc-round-proof-obligation.py", "rust"),
    # WAVE-2 (oracle price reachability lane). Substrate = <ws>/.auditooor/
    # value_moving_functions.json; when that is absent the lane is N/A (emits no
    # ledger), so this row reports ran=False here (not silently green). Each emitted
    # oracle_reachability_hypotheses row (verdict="needs-fuzz") is a SURVIVOR obligation
    # owing a terminal verdict or audit-complete FAILS at step-5. Lock-step with the
    # step-2d-oracle-reachability runbook step + exploit-queue._gather_from_oracle_
    # reachability_hypotheses.
    ("oracle_reachability_hypotheses.jsonl",
     "oracle-reachability-lane.py", "any"),
    # WAVE-2 ITEM 8 (4 now-non-vacuous SHIP-verified screens). Item 7 made every
    # FIRED survivor emit advisory=False + proof_status="open" (enumeration leads
    # stay advisory=True), so a fired row is a real OPEN obligation owing a terminal
    # verdict (executed refutation / disposition / filed) or audit-complete FAILS at
    # step-5 - this is NOT vacuity theater. Each screen is invoked in the step-2d
    # netnew-advisory-lanes screen pass (tools/audit-deep.sh) and its survivor rows
    # fold into the per-fn OPEN-OBLIGATIONS block. Per-target N/A gate = the lang
    # tag + ledger presence: on a workspace whose language the screen does not target
    # (no rust crate for the two rust screens; no .sol/.go for the divergence pair)
    # the screen emits no survivor rows, so this row scores total=0 (ran reflects the
    # sidecar's presence, never silently green).
    ("transmute_type_confusion_hypotheses.jsonl",
     "transmute-type-confusion-screen.py", "rust"),
    ("release_silent_overflow_hypotheses.jsonl",
     "release-silent-overflow-screen.py", "rust"),
    # DIVERGENCE PAIR: cross-layer-cardinality is Solidity+Go (both); verifier-executor
    # is language-general codegen/JIT/serializer surface (any).
    ("cross_layer_cardinality_divergence_hypotheses.jsonl",
     "cross-layer-cardinality-divergence-screen.py", "both"),
    ("verifier_executor_divergence_hypotheses.jsonl",
     "verifier-executor-divergence-screen.py", "any"),
    # WAVE-2 ITEM 9 (known-CVE x middleware-reachability, D6). The reasoner
    # (cve-middleware-reachability.py) is NOT a --workspace tool: it takes a fork's
    # app/app.go middleware-composition file + an upstream advisory list (and an
    # optional --fork-clone-path for the ancestry stage) and writes a per-advisory
    # JSON report. The adapter/emitter (cve-middleware-obligation-emit.py) converts
    # every reachability_status=="open" advisory into a hunt obligation
    # (advisory=False, proof_status="open", entrypoint+advisory_id anchor) here.
    # N/A gate: with no cosmos app.go middleware seam AND no --fork-clone-path the
    # emitter writes NOTHING, so this row scores ran=False (never silently green).
    # A fired survivor owes a terminal verdict (executed refutation / disposition /
    # filed) or audit-complete FAILS at step-5. Lock-step with the
    # step-2d-cve-middleware runbook step + exploit-queue._gather_from_cve_middleware_
    # reachability_obligations.
    ("cve_middleware_reachability_obligations.jsonl",
     "cve-middleware-reachability.py", "go"),
    # Typed async lifecycle obligations are advisory/non-proof hypotheses.  Keep
    # the substrate in generic resolution parity so emitted rows are visible to
    # the same ledger inventory without making them blocking obligations.
    ("async_cancel_coupled_state_hypotheses.jsonl",
     "async-cancel-coupled-state-screen.py", "rust"),
)

# Terminal (resolved) verdict tokens - normalized lowercase, non-alnum stripped to '-'.
_TERMINAL = {
    "killed", "kill", "resolved", "answered", "confirmed", "finding", "filed",
    "dispositioned", "disposition", "refuted", "not-applicable", "na",
    "oos-rejected", "oos", "verified", "cleared", "done", "closed", "terminal",
    # terminal-negative verdicts a hunt/adjudication worker emits interchangeably
    # with "refuted"/"killed" - all mean the hypothesis reached a terminal NEGATIVE.
    # Their absence made a genuine source-cited NEGATIVE read as OPEN (NUVA
    # 2026-07-14: freeze/epoch lanes wrote verdict="NEGATIVE" and stayed uncredited).
    "negative", "disproved", "not-exploitable", "closed-negative", "no",
}
# Non-terminal (open) tokens - anything not terminal is treated as open, but these
# are the known open sentinels the reasoners emit.
_OPEN_SENTINELS = {"needs-source", "open", "pending", "todo", "unknown",
                   "orchestrator-dispatch-required", "queued", ""}

_RESOLUTION_SIDECAR = "logic_obligation_resolutions.jsonl"


def _norm(v) -> str:
    s = str(v or "").strip().lower()
    out = []
    for ch in s:
        out.append(ch if ch.isalnum() else "-")
    # collapse runs of '-'
    res = "-".join(t for t in "".join(out).split("-") if t)
    return res


def _is_terminal_token(v) -> bool:
    n = _norm(v)
    if not n:
        return False
    if n in _TERMINAL:
        return True
    # pass-* verified verdicts (e.g. pass-verified-source-claim, pass-no-source-claim)
    if n.startswith("pass-") or n == "pass":
        return True
    return False


def _load_jsonl(p: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _obligation_keys(row: dict) -> list[str]:
    """Stable join keys for a reasoner obligation row (most-specific first)."""
    keys: list[str] = []
    contract = str(row.get("contract") or "").strip()
    fn = str(row.get("function") or row.get("source_function") or "").strip()
    ac = str(row.get("attack_class") or "").strip()
    file_ = str(row.get("file") or "").strip()
    oid = str(row.get("obligation_id") or row.get("id") or "").strip()
    if oid:
        keys.append(_norm(oid))
    if contract and fn and ac:
        keys.append(_norm(f"{contract}::{fn}::{ac}"))
    if contract and fn:
        keys.append(_norm(f"{contract}::{fn}"))
    if file_ and fn:
        keys.append(_norm(f"{file_}::{fn}"))
    # COMPOSITION obligations (novel-composition-violation) carry op_a/op_b + an
    # invariant_id instead of a function - key them on the sorted op pair so a
    # bridge resolution row (both ops driven terminal) can match. SITE-keyed
    # obligations (dirm ratio-authority / escrow-liability residual) carry site.file
    # / source_refs instead of a function - key on the file suffix.
    op_a = str(row.get("op_a") or "").strip().lower()
    op_b = str(row.get("op_b") or "").strip().lower()
    inv = str(row.get("invariant_id") or row.get("invariant_form") or "").strip().lower()
    if op_a and op_b:
        lo, hi = sorted([op_a, op_b])
        keys.append(_norm(f"comp::{lo}::{hi}" + (f"::{inv}" if inv else "")))
    site = row.get("site")
    site_file = (site.get("file") if isinstance(site, dict) else "") or ""
    if site_file:
        tail = str(site_file).split("src/", 1)
        suffix = ("src/" + tail[1]) if len(tail) > 1 else str(site_file)
        keys.append(_norm(f"site::{suffix}" + (f"::{inv}" if inv else "")))
    return keys


def _load_resolution_sidecar(ws: Path) -> dict[str, str]:
    """{normalized_key: state_token} from the optional external resolution ledger."""
    out: dict[str, str] = {}
    p = ws / ".auditooor" / _RESOLUTION_SIDECAR
    if not p.is_file():
        return out
    for row in _load_jsonl(p):
        state = row.get("state") or row.get("verdict") or row.get("resolution")
        for k in _obligation_keys(row):
            if k:
                out[k] = str(state or "")
        # also allow an explicit obligation_key field
        ek = row.get("obligation_key")
        if ek:
            out[_norm(ek)] = str(state or "")
    return out


def _has_dataflow_substrate(ws: Path) -> bool:
    aud = ws / ".auditooor"
    if not aud.is_dir():
        return False
    if (aud / "dataflow_paths.jsonl").is_file():
        return True
    try:
        return bool(list(aud.glob("dataflow_paths.*.jsonl")))
    except OSError:
        return False


_ADVISORY_VERDICTS = {"needs_source", "needs-source", "advisory"}


def _is_advisory_row(row: dict) -> bool:
    """True iff a reasoner row is an ADVISORY note, not a hunt obligation. A reasoner
    flags a row advisory when its OWN substrate analysis found no entrypoint-reachable
    impact path (or the negation is guard/closure-dominated pre-emit) - there is nothing
    to drive to a terminal verdict. Only non-advisory SURVIVOR rows owe a verdict.

    Also excludes a reasoner's CITED-EMPTY / DEGRADED summary REPORT row: a run that
    executed and found 0 survivors, or degraded because the target language/crate is
    absent (e.g. rust_unchecked_arith on a Go+Sol workspace with no cargo.toml), is a
    terminal-clean result, NOT an open obligation. Requires the explicit cited-empty
    marker or a report.degraded/0-survivor summary AND no function/op/site anchor."""
    if row.get("advisory") is True or row.get("row_is_advisory") is True:
        return True
    if _norm(row.get("verdict")) in {_norm(v) for v in _ADVISORY_VERDICTS}:
        return True
    has_anchor = bool(row.get("function") or row.get("op_a")
                      or (isinstance(row.get("site"), dict) and row["site"].get("file")))
    if not has_anchor:
        note = str(row.get("note") or "").lower()
        rep = row.get("report") if isinstance(row.get("report"), dict) else {}
        totals = rep.get("totals") if isinstance(rep.get("totals"), dict) else {}
        if "cited-empty" in note or "cited_empty" in note:
            return True
        if rep.get("degraded") is True and int(totals.get("survivors", 0) or 0) == 0:
            return True
    return False


def _row_resolved(row: dict, sidecar: dict[str, str]) -> bool:
    # (a) row's own terminal status
    if _is_terminal_token(row.get("proof_status")):
        return True
    if _is_terminal_token(row.get("quality_gate_status")):
        return True
    # (b) external resolution sidecar terminal state for any of the row's keys
    for k in _obligation_keys(row):
        if k in sidecar and _is_terminal_token(sidecar[k]):
            return True
    return False


def _exploit_queue_consumed(ws: Path, newest_ledger_mtime: float) -> bool:
    aud = ws / ".auditooor"
    newest_q = 0.0
    for name in ("exploit_queue.json", "exploit_queue.source_mined.json"):
        q = aud / name
        try:
            if q.is_file():
                newest_q = max(newest_q, q.stat().st_mtime)
        except OSError:
            continue
    if newest_q <= 0.0:
        return False
    # allow a small clock skew tolerance
    return newest_q >= (newest_ledger_mtime - 2.0)


def check(ws: Path) -> dict:
    """Return the resolution verdict dict for `ws` (advisory-first; strict env aware)."""
    ws = Path(ws).resolve()
    strict = (
        os.environ.get("AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT", "").strip() == "1"
        or os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1"
    )
    aud = ws / ".auditooor"
    result: dict = {
        "workspace": str(ws),
        "verdict": "pass",
        "ok": True,
        "strict": strict,
        "reason": "",
        "total_obligations": 0,
        "resolved": 0,
        "open": 0,
        "ledgers_ran": 0,
        "per_ledger": [],
        "consumed_by_exploit_queue": None,
        "artifacts": [],
    }
    if not aud.is_dir():
        result["reason"] = "no .auditooor dir; nothing to resolve (WARN-pass)"
        return result

    sidecar = _load_resolution_sidecar(ws)
    total = resolved = open_ct = ran = 0
    newest_mtime = 0.0
    arts: list[str] = []
    for fname, tool, lang in _REASONER_LEDGERS:
        p = aud / fname
        if not p.is_file():
            result["per_ledger"].append(
                {"ledger": fname, "tool": tool, "lang": lang, "ran": False,
                 "total": 0, "resolved": 0, "open": 0})
            continue
        ran += 1
        arts.append(str(p))
        try:
            newest_mtime = max(newest_mtime, p.stat().st_mtime)
        except OSError:
            pass
        all_rows = _load_jsonl(p)
        # ADVISORY rows are NOT hunt obligations: a reasoner marks a row advisory
        # (advisory=True / row_is_advisory / verdict in {needs_source, advisory}) when
        # its OWN substrate analysis found NO entrypoint-reachable impact path (or the
        # negation is closure/guard-dominated pre-emit) - i.e. nothing to drive. Only
        # SURVIVORS (a reachable, unguarded path to an impact sink) are real obligations
        # owing a terminal verdict. Counting advisory notes as blocking OPEN obligations
        # false-red the gate (NUVA: 393 of 549 were advisory needs_source). Same
        # discipline as check_exploit_queue_resolution, which filters row_is_advisory.
        rows = [r for r in all_rows if not _is_advisory_row(r)]
        l_adv = len(all_rows) - len(rows)
        l_total = len(rows)
        l_res = sum(1 for r in rows if _row_resolved(r, sidecar))
        l_open = l_total - l_res
        total += l_total
        resolved += l_res
        open_ct += l_open
        result["per_ledger"].append(
            {"ledger": fname, "tool": tool, "lang": lang, "ran": True,
             "total": l_total, "resolved": l_res, "open": l_open, "advisory": l_adv})

    result["total_obligations"] = total
    result["resolved"] = resolved
    result["open"] = open_ct
    result["ledgers_ran"] = ran
    result["artifacts"] = arts

    if ran == 0:
        # No reasoner emitted a ledger. If a dataflow substrate exists the reasoners
        # SHOULD have run - advisory-WARN by default, fail-closed under strict only.
        if _has_dataflow_substrate(ws):
            ok = not strict
            result["ok"] = ok
            result["verdict"] = "pass" if ok else "fail-logic-obligation-unresolved"
            result["reason"] = (
                "no logic-reasoner obligation ledger present despite a dataflow substrate "
                "- the pre-hunt reasoners were skipped"
                + ("" if ok else " (STRICT: run the step-2d-* reasoners, or add a "
                                 "logic-obligation-resolution-rebuttal, before done)"))
            return result
        result["reason"] = ("no dataflow substrate / no reasoner ledger; nothing reasoned "
                            "- WARN-pass")
        return result

    result["consumed_by_exploit_queue"] = _exploit_queue_consumed(ws, newest_mtime)

    if open_ct == 0:
        result["reason"] = (
            f"all {total} logic-reasoner obligation(s) across {ran} ledger(s) reached a "
            f"TERMINAL verdict (resolved/dispositioned)")
        return result

    # Open obligations remain -> advisory-WARN by default, fail-closed under strict.
    ok = not strict
    result["ok"] = ok
    result["verdict"] = "pass-advisory-open" if ok else "fail-logic-obligation-unresolved"
    consumed = result["consumed_by_exploit_queue"]
    result["reason"] = (
        f"{open_ct} of {total} logic-reasoner obligation(s) still OPEN (no terminal "
        f"verdict) across {ran} ledger(s)"
        + ("" if consumed else "; exploit_queue not (re)built after the reasoners "
                               "(obligations not consumed)")
        + ("; advisory - hunt-worklist debt, not a gate under default policy"
           if ok else
           "; (STRICT: drive each open obligation to a terminal verdict - hunt or "
           "disposition - or add a logic-obligation-resolution-rebuttal, before done)")
    )
    return result


def _print_human(res: dict) -> None:
    print(f"logic-obligation-resolution  ws={res['workspace']}")
    print(f"  strict={res['strict']}  ledgers_ran={res['ledgers_ran']}")
    print(f"  obligations: total={res['total_obligations']} "
          f"resolved={res['resolved']} open={res['open']}")
    print(f"  consumed_by_exploit_queue={res['consumed_by_exploit_queue']}")
    for l in res["per_ledger"]:
        if l["ran"]:
            print(f"    [{l['lang']:4s}] {l['ledger']:46s} total={l['total']:>4} "
                  f"resolved={l['resolved']:>4} open={l['open']:>4}")
    print(f"  verdict={res['verdict']} ok={res['ok']}")
    print(f"  {res['reason']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="force fail-closed on open obligations (same as "
                         "AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT=1)")
    args = ap.parse_args(argv)
    ws = Path(os.path.expanduser(args.workspace))
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2
    if args.strict:
        os.environ["AUDITOOOR_L37_LOGIC_OBLIGATION_STRICT"] = "1"
    res = check(ws)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        _print_human(res)
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
