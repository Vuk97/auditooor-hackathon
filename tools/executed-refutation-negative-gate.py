#!/usr/bin/env python3
"""executed-refutation-negative-gate (LOGIC_ARSENAL_ROADMAP logic #2).

A value / conservation / authz KILL (or `cleared`) is HONEST only if the cited
guard is proven LOAD-BEARING - i.e. a poc_execution_record exists carrying BOTH:
  (a) an EXECUTED refutation (a command that actually ran, exit 0 / status pass), and
  (b) a GUARD-NEUTRALIZATION mutant receipt (the hypothesis becomes reachable when
      the cited guard is removed).

The gate REJECTS as NON-HONEST any negative verdict on a value-mover unit whose
`local_verification_cmd` is grep-only (or absent) AND that lacks a mutation-killed
guard receipt. It reads:
  - .auditooor/agent_mechanism_verdicts/*.json  (verdict: cleared / finding)
  - .auditooor/hacker_question_verdicts/*.json   (verdict: KILL / CONFIRMED / ...)
and matches negatives against poc_execution/*/(execution_manifest|*harness_exec).json.

Advisory-first (roadmap stage 5): default exit 0, prints the flagged NON-HONEST
rows. `--strict` (or AUDITOOOR_EXEC_REFUTATION_STRICT=1) exits 1 when any
non-honest negative on a value-mover remains.

Usage: executed-refutation-negative-gate.py <workspace> [--strict] [--json]
"""
import argparse
import glob
import json
import os
import re
import sys

# ---- value / conservation / authz classification -------------------------------
# A unit is a "value-mover" when its impact / mechanism / attack-class / function
# touches fund movement, supply/accounting conservation, or authorization.
VALUE_MOVER_RX = re.compile(
    r"theft|freez|freeze|frozen|insolven|drain|steal|mint|burn|withdraw|deposit|"
    r"transfer|balance|fund|solven|conservation|accounting|collateral|redeem|"
    r"payout|share|reward|liquidat|slash|escrow|custody|swap|value|"
    r"authz|authoriz|access-control|access_control|onlyrole|only-role|role-gate|"
    r"privilege|permission|owner|admin|signature|sig-replay|replay|nonce",
    re.IGNORECASE,
)

# Verdicts that assert "no bug here" (a negative that must be proven, not asserted).
NEGATIVE_VERDICTS = {"cleared", "kill", "killed", "not-fileable", "not_fileable",
                     "refuted", "dead"}

# A command is "execution" (not grep-only) when it invokes a runner/compiler/fuzzer.
EXEC_RX = re.compile(
    r"\b(go\s+test|forge\s+test|forge\s+script|medusa|echidna|cargo\s+test|"
    r"npx\s+hardhat|hardhat\s+test|pytest|python3?\s+\S+\.py|foundry|halmos|"
    r"certora|simapp|make\s+\S*test|dapp\s+test)\b",
    re.IGNORECASE,
)
# Pure inspection primitives - if a cmd is ONLY these it is grep-only.
GREP_ONLY_TOKEN_RX = re.compile(
    r"^(grep|rg|ripgrep|find|ls|cat|sed|awk|head|tail|echo|wc|nl|sort|uniq|"
    r"true|false|:|test|\[|pwd|cd|printf)$"
)
# Guard-neutralization mutant receipt markers.
GUARD_NEUTRALIZATION_RX = re.compile(
    r"guard[-_ ]?neutraliz|guard[-_ ]?remov|mutant|mutation[-_ ]?kill|"
    r"neutraliz.*guard|remove.*guard|guard.*load[-_ ]?bearing|delete.*require",
    re.IGNORECASE,
)


def _load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def _as_records(obj):
    if obj is None:
        return []
    if isinstance(obj, list):
        return [r for r in obj if isinstance(r, dict)]
    if isinstance(obj, dict):
        return [obj]
    return []


def is_grep_only(cmd):
    """True when the verification command performs no real execution.

    Absent/empty cmd -> True (nothing was run). A cmd is execution when it invokes
    a runner (EXEC_RX); otherwise, if every leaf command is a pure inspection
    primitive, it is grep-only.
    """
    if not cmd or not str(cmd).strip():
        return True
    cmd = str(cmd)
    if EXEC_RX.search(cmd):
        return False
    # Split into leaf commands on shell operators and pipes.
    leaves = re.split(r"[;&|]+|\n", cmd)
    saw_real = False
    for leaf in leaves:
        leaf = leaf.strip()
        if not leaf:
            continue
        # strip a leading `bash -lc '` wrapper etc.
        m = re.match(r"[\"']?([A-Za-z0-9_./-]+)", leaf)
        if not m:
            continue
        head = os.path.basename(m.group(1))
        if GREP_ONLY_TOKEN_RX.match(head):
            continue
        saw_real = True
    return not saw_real


def is_value_mover(rec):
    hay = " ".join(str(rec.get(k, "")) for k in (
        "impact", "mechanism", "attack_class", "function_name", "reason",
        "reasoning", "verdict"))
    refs = rec.get("source_refs") or []
    if isinstance(refs, list):
        hay += " " + " ".join(str(x) for x in refs)
    hay += " " + str(rec.get("file_line", ""))
    return bool(VALUE_MOVER_RX.search(hay))


def _norm_verdict(v):
    return str(v or "").strip().lower()


def is_negative(rec):
    return _norm_verdict(rec.get("verdict")) in NEGATIVE_VERDICTS


def _unit_tokens(rec):
    """File basenames + mechanism/attack-class tokens used to match a poc record."""
    toks = set()
    refs = rec.get("source_refs") or []
    if isinstance(refs, list):
        for r in refs:
            base = os.path.basename(str(r).split(":")[0])
            if base:
                toks.add(base.lower())
    fl = rec.get("file_line")
    if fl:
        base = os.path.basename(str(fl).split(":")[0].split(" ")[0])
        if base:
            toks.add(base.lower())
    for k in ("mechanism", "attack_class", "function_name"):
        val = rec.get(k)
        if val:
            for w in re.split(r"[^a-z0-9]+", str(val).lower()):
                if len(w) >= 4:
                    toks.add(w)
    return toks


# Generic path/domain tokens that must NEVER be a match anchor - they leak from
# absolute paths (/Users/wolf/audits/nuva/...) and broad mechanism words and would
# spuriously match almost any unit, over-crediting a NEGATIVE (gaming). A match must
# rest on a SPECIFIC function name or a source-file basename, not these.
_GENERIC_POC_TOKENS = frozenset({
    "users", "wolf", "audits", "nuva", "vault", "keeper", "test", "tests",
    "invariant", "invariants", "src", "contracts", "prime", "auditooor",
    "poc", "poc_execution", "harness", "mvc", "sidecar", "json", "sol", "go",
    "rust", "move", "workspace", "home", "tmp", "private", "candidate",
})


def collect_poc_records(ws):
    """Return list of dicts: {tokens, executed, guard_neutralized, path}."""
    out = []
    # Scan BOTH the legacy ws/poc_execution/ and the canonical ws/.auditooor/
    # poc_execution/ (serving-join 2026-07-14): the runbook + spawn-worker write
    # poc_execution_records under .auditooor/ (like every other artifact + the
    # mvc_sidecar arm below), but this arm only globbed the bare ws/poc_execution/,
    # so a genuine executed refutation manifest at the canonical path was invisible.
    for pat in ("poc_execution/*/execution_manifest.json",
                "poc_execution/*/*harness_exec.json",
                "poc_execution/*/*.json",
                ".auditooor/poc_execution/*/execution_manifest.json",
                ".auditooor/poc_execution/*/*harness_exec.json",
                ".auditooor/poc_execution/*/*.json"):
        for path in glob.glob(os.path.join(ws, pat)):
            data = _load_json(path)
            if not isinstance(data, dict):
                continue
            blob = json.dumps(data).lower()
            executed = False
            for cmd in (data.get("commands_attempted") or []):
                if isinstance(cmd, dict) and (
                        cmd.get("status") == "pass" or cmd.get("exit_code") == 0):
                    executed = True
                    break
            ex = data.get("execution")
            if isinstance(ex, dict) and (
                    ex.get("status") == "pass" or ex.get("exit_code") == 0):
                executed = True
            guard = bool(GUARD_NEUTRALIZATION_RX.search(blob))
            toks = set()
            for key in ("candidate_id", "brief_path", "poc_dir"):
                v = data.get(key)
                if v:
                    toks.add(os.path.basename(str(v)).lower())
                    for w in re.split(r"[^a-z0-9]+", str(v).lower()):
                        if len(w) >= 4:
                            toks.add(w)
            # STRICT source anchors (serving-join 2026-07-14): a genuine executed
            # poc_execution_record cites its CUT via source_refs / cut / file_line and
            # its function - index the source-FILE basename (WITH a language extension)
            # + the exact function name so the record JOINs to a value-mover NEGATIVE on
            # that unit, the SAME per-file-unit crediting the mvc-sidecar arm already
            # does. Without this the poc arm only tokenized candidate_id/brief/poc_dir
            # words ("abci" != the unit's "abci.go" basename), so a genuine executed
            # mutation-verified refutation over abci.go could never credit its unit.
            # Extension-gated + fn-name-shaped (no path-word split) so no generic path
            # component leaks - the _GENERIC_POC_TOKENS drop below is the final guard.
            _refs = data.get("source_refs") if isinstance(data.get("source_refs"), list) else []
            for r in list(_refs) + [data.get("cut"), data.get("file_line")]:
                if not r:
                    continue
                base = os.path.basename(str(r).split(":")[0].split(" ")[0]).lower()
                if base.endswith((".go", ".sol", ".rs", ".move", ".vy", ".cairo")):
                    toks.add(base)
            _fn = str(data.get("function") or data.get("function_name") or "").strip().lower()
            if _fn and " " not in _fn and "/" not in _fn and 2 < len(_fn) <= 60:
                toks.add(_fn)
            out.append({"tokens": toks, "executed": executed,
                        "guard_neutralized": guard, "path": path})
    # MVC-SIDECAR arm (serving-join): the mutation-verified-coverage sidecars
    # (mvc_sidecar/*.json) ARE executed refutation + guard-neutralization evidence -
    # a real campaign that ran (campaign_calls / non_vacuous) AND killed a
    # guard-neutralizing mutant (mutants_killed>=1 / mutation_verified) over a
    # value-moving unit (SwapIn / payout / reconcile / shares / ERC4626 share-price /
    # the economic-invariant suites). collect_poc_records only scanned poc_execution/*,
    # so these never JOINED and every value-mover NEGATIVE on a fuzz-covered unit
    # read as grep-only. Anti-fabrication: emit ONLY when GENUINELY mutation-verified
    # AND non-vacuous - a vacuous campaign (0 mutants killed) is NOT credited.
    for path in glob.glob(os.path.join(ws, ".auditooor", "mvc_sidecar", "*.json")) \
            + glob.glob(os.path.join(ws, "mvc_sidecar", "*.json")):
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        mk = data.get("mutants_killed")
        killed = (str(mk).strip().isdigit() and int(mk) >= 1) or \
            str(data.get("mutation_verified")).strip().lower() in ("true", "1", "yes")
        nv = data.get("non_vacuous")
        non_vac = (nv is True) or ("non-vacuous" in str(nv or data.get("verdict") or "").lower())
        if not (killed and non_vac):
            continue  # vacuous / unverified -> NOT executed evidence
        # STRICT tokens ONLY: the specific function name + source FILE basenames that
        # carry a language extension (shares.go / dedicatedvaultrouter.sol). Do NOT
        # split paths into words - that leaks generic path components (users / wolf /
        # audits / nuva / vault / keeper) that spuriously match almost any unit and
        # would over-credit (gaming). A value-mover NEGATIVE is credited only when it
        # shares the exact function or the exact source-file basename with a genuine
        # mutation-verified campaign.
        toks = set()
        fn = str(data.get("function") or "").strip().lower()
        # a real function name, not a whole invariant-suite description
        if fn and " " not in fn and "/" not in fn and 2 < len(fn) <= 60:
            toks.add(fn)
        for key in ("source_file", "harness_path", "test_path", "contract", "cut"):
            v = data.get(key)
            if not v:
                continue
            base = os.path.basename(str(v).split(":")[0]).lower()
            if base.endswith((".go", ".sol", ".rs", ".move")):
                toks.add(base)
        if not toks:
            continue  # no specific anchor -> cannot honestly credit any unit
        out.append({"tokens": toks, "executed": True, "guard_neutralized": True,
                    "path": path})
    # Drop generic/path-leaked tokens from EVERY poc record so a match must rest on a
    # specific function or source-file anchor (anti-over-credit, both arms).
    for rec in out:
        rec["tokens"] = {t for t in rec["tokens"] if t not in _GENERIC_POC_TOKENS}
    return out


def _match_poc(unit_toks, poc_records):
    """Return the best matching poc record (token overlap) or None."""
    best = None
    for pr in poc_records:
        if unit_toks & pr["tokens"]:
            # prefer an executed + guard-neutralized receipt
            score = (pr["executed"], pr["guard_neutralized"])
            if best is None or score > (best["executed"], best["guard_neutralized"]):
                best = pr
    return best


def scan(ws):
    ws = str(ws)
    records = []
    for pat in ("agent_mechanism_verdicts/*.json",
                "hacker_question_verdicts/*.json"):
        for path in glob.glob(os.path.join(ws, ".auditooor", pat)):
            store = "mechanism" if "mechanism" in pat else "hacker_question"
            for rec in _as_records(_load_json(path)):
                rec["__store"] = store
                rec["__path"] = path
                records.append(rec)

    poc_records = collect_poc_records(ws)

    flagged = []        # NON-HONEST negatives on value-movers
    honest = []         # negatives with an executed+guard-neutralization receipt
    considered = 0
    for rec in records:
        if not is_negative(rec):
            continue
        if not is_value_mover(rec):
            continue
        considered += 1
        cmd = rec.get("local_verification_cmd")
        grep_only = is_grep_only(cmd)
        poc = _match_poc(_unit_tokens(rec), poc_records)
        has_receipt = bool(poc and poc["executed"] and poc["guard_neutralized"])
        entry = {
            "store": rec["__store"],
            "verdict": rec.get("verdict"),
            "impact": rec.get("impact"),
            "mechanism": rec.get("mechanism") or rec.get("attack_class"),
            "unit": (rec.get("source_refs") or [rec.get("file_line")])[0]
                    if (rec.get("source_refs") or rec.get("file_line")) else None,
            "grep_only": grep_only,
            "poc_match": poc["path"] if poc else None,
            "has_executed_refutation": bool(poc and poc["executed"]),
            "has_guard_neutralization": bool(poc and poc["guard_neutralized"]),
        }
        if has_receipt:
            honest.append(entry)
        else:
            # NON-HONEST: grep-only OR missing the mutation-killed guard receipt.
            reasons = []
            if grep_only:
                reasons.append("grep-only-or-no-execution local_verification_cmd")
            if not poc:
                reasons.append("no matching poc_execution_record")
            elif not poc["executed"]:
                reasons.append("poc_execution_record has no executed refutation (exit 0)")
            elif not poc["guard_neutralized"]:
                reasons.append("poc_execution_record lacks guard-neutralization mutant receipt")
            entry["reasons"] = reasons
            flagged.append(entry)

    return {
        "workspace": ws,
        "considered_value_mover_negatives": considered,
        "poc_records": len(poc_records),
        "honest": honest,
        "flagged": flagged,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("workspace")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when any non-honest value-mover negative remains")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    res = scan(args.workspace)
    strict = args.strict or os.environ.get("AUDITOOOR_EXEC_REFUTATION_STRICT") == "1"

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"executed-refutation-negative-gate  ws={res['workspace']}")
        print(f"  value-mover negatives considered : {res['considered_value_mover_negatives']}")
        print(f"  poc_execution_records found       : {res['poc_records']}")
        print(f"  HONEST (executed+guard-neutralized): {len(res['honest'])}")
        print(f"  NON-HONEST (advisory this wave)    : {len(res['flagged'])}")
        for e in res["flagged"][:200]:
            print(f"    [NON-HONEST] {e['store']} verdict={e['verdict']} "
                  f"unit={e['unit']} mech={e['mechanism']}")
            print(f"        -> {'; '.join(e['reasons'])}")

    if strict and res["flagged"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
