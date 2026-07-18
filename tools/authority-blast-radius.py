#!/usr/bin/env python3
"""authority-blast-radius.py  (A3) - authority SCOPE / blast-radius lane.

WHAT THIS TOOL DOES
===================
A3 hunts authority-SCOPE defects: a single role whose guard sits in front of
sinks of DIFFERING impact classes (over-broad blast radius), OR a powerful role
that a strictly lower-privilege role/actor can grant (privilege inversion). It
is complementary to, and DEDUPED against, the neighbouring authorization lanes:

  - access-control-coverage (A2 / ACL-COV) owns guard-ABSENCE (a sink with NO
    guard). A3 only fires on sinks whose guard is PRESENT.
  - acl-matrix confused-deputy owns DIFFERENT roles doing a SIMILAR action.
  - two-step-ownership owns ownership-transfer correctness.
  A3 owns SAME role over DIFFERING impact, and grant-of-power-by-a-weaker-role.

It CONSUMES the materialization already produced by tools/acl-matrix.py
(role_uses, role_grants, and per-fn priv_writes) rather than re-deriving it, and
reuses slither_predicates.has_guard_in_closure to CONFIRM each sink's guard is
actually present (not a hollow modifier body).

FLAGS
=====
  (a) BLAST-RADIUS      - |distinct impact classes in one role's sink_set| > 1.
  (b) PRIVILEGE-INVERSION - a role R is granted inside a fn guarded by a role
      strictly lower-privilege than the power R confers.

Impact classes: pause / fee / oracle / owner-implementation / fund-movement,
derived from priv_writes + PRIVILEGED_VAR_HINTS + sink fn-name hints.

NO-AUTO-CREDIT: every emitted row carries verdict="needs-fuzz". This tool never
flips a gate, never resolves a unit. Hang it on the completeness-matrix
AUTHORIZATION axis, not a silo.

FAIL-OPEN: on a degraded acl-matrix (Slither absent / no roles), emit an empty
hypotheses file + an accounting record with status, exit 0.

Usage:
  python3 tools/authority-blast-radius.py --workspace <ws> [--json]
  python3 tools/authority-blast-radius.py --workspace <ws> --strict [--json]

With ``--strict``, missing/degraded ACL or guard evidence fails closed and every
hypothesis must have an exact stable-ID terminal disposition. Without it, the
legacy fail-open advisory behavior is preserved.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
from collections import defaultdict

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

OUT_REL = os.path.join(".auditooor", "authority_blast_radius_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor", "authority_blast_radius_accounting.json")
DISPOSITIONS_REL = os.path.join(
    ".auditooor", "authority_blast_radius_dispositions.jsonl")

# These are terminal *types*, not free-form prose.  A disposition can close a
# strict hypothesis only when it carries one of these values and the exact
# stable id emitted by this tool.  The broad vocabulary is shared with the
# existing queue/completeness lanes; non-terminal states remain open.
_TERMINAL_DISPOSITIONS = frozenset({
    "covered", "covered-by-fuzz", "disposed", "killed", "not-applicable",
    "not_applicable", "oos", "out-of-scope", "refuted", "resolved",
    "ruled-out", "ruled_out", "ruled-out-source-cited",
})

# Impact-class buckets. Keyword hits are substring matches over a sink's
# priv_writes var names + its writes + its function name. Kept SHORT.
IMPACT_BUCKETS = (
    ("pause", ("paus", "resume", "unpaus", "freeze", "halt")),
    ("fee", ("fee", "rate", "premium", "commission", "threshold", "bps")),
    ("oracle", ("oracle", "pricefeed", "price", "feed", "valuation")),
    ("owner-implementation",
     ("owner", "admin", "implementation", "beacon", "guardian",
      "upgrade", "proxy", "authoriz")),
    ("fund-movement",
     ("withdraw", "transfer", "deposit", "mint", "burn", "redeem",
      "sweep", "rescue", "recover", "payout", "distribute",
      "stake", "unstake", "collateral", "balance")),
)

# Power severity per impact class (blast-radius sinks -> confer-power).
IMPACT_SEVERITY = {
    "fund-movement": 3,
    "owner-implementation": 3,
    "oracle": 2,
    "fee": 2,
    "pause": 1,
}

_TRIVIAL_ROLE = {"", "-", "?", "Role(?)", None}

# Ownership-transfer + admin-handover fns belong to the TWO-STEP-OWNERSHIP lane,
# not to blast-radius impact sinks. Their names carry a "transfer"/"owner" token
# that buckets a single handover fn into BOTH fund-movement AND
# owner-implementation, manufacturing a spurious >1-impact span (measured FP on
# lido: role Owner guards only renounce/transferOwnership). A3 DEFERS ownership
# transfer to two-step-ownership, so these fns are dropped from every A3 sink set.
_OWNERSHIP_XFER_FNS = {
    "transferownership", "renounceownership", "acceptownership",
    "pushownership", "pullownership", "claimownership",
    "transferadmin", "renounceadmin", "acceptadmin", "changeadmin",
    "begindefaultadmintransfer", "acceptdefaultadmintransfer",
    "canceldefaultadmintransfer",
}


def _is_ownership_transfer_fn(fn) -> bool:
    return str(fn or "").lower().lstrip("_") in _OWNERSHIP_XFER_FNS


def _load_acl():
    spec = importlib.util.spec_from_file_location(
        "acl_matrix_a3", HERE / "acl-matrix.py")
    if not spec or not spec.loader:
        raise ImportError("acl-matrix.py not loadable")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def _load_predicates():
    try:
        spec = importlib.util.spec_from_file_location(
            "slither_predicates_a3", HERE / "slither_predicates.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod
    except Exception:
        return None


def classify_impacts(row) -> set:
    """Impact classes a single sink fn touches (may be >1). Consumes acl-matrix
    priv_writes + writes_to + the fn name."""
    tokens = [str(row.get("fn", "")).lower()]
    for w in (row.get("priv_writes") or []):
        tokens.append(str(w).lower())
    for w in (row.get("writes_to") or []):
        tokens.append(str(w).lower())
    impacts = set()
    for bucket, kws in IMPACT_BUCKETS:
        for k in kws:
            if any(k in t for t in tokens):
                impacts.add(bucket)
                break
    return impacts


def _name_rank(role) -> int:
    """Coarse privilege rank of a role NAME. 3=admin/owner/governance,
    2=manager/curator/upgrader, 1=everything else (operator/pauser/keeper)."""
    r = (role or "").lower()
    if not r:
        return 1
    if "default_admin" in r:
        return 3
    if r in ("owner", "admin", "governance", "timelock"):
        return 3
    if "admin" in r or "governance" in r or "timelock" in r:
        return 3
    if "manager" in r or "upgrad" in r or "curator" in r:
        return 2
    return 1


def _role_power(role, impacts) -> int:
    p = _name_rank(role)
    for ic in impacts:
        p = max(p, IMPACT_SEVERITY.get(ic, 1))
    return p


def _sink_guard_role(row):
    """The role that guards this fn, from acl-matrix roles_via_mods /
    roles_via_requires. None if ungated or only-a-trivial-guard."""
    for r in (row.get("roles_via_mods") or []):
        if r not in _TRIVIAL_ROLE:
            return r
    for r in (row.get("roles_via_requires") or []):
        # requires are tagged like hasRole(X_ROLE)/==(owner); extract the core
        if r and r not in _TRIVIAL_ROLE:
            return r
    return None


def hypothesis_stable_id(flag_kind, role, sink_fns) -> str:
    """Return the canonical identity for one A3 hypothesis.

    The identity deliberately mirrors the A3 queue drain's edge key: a role,
    flag kind, and sorted sink function set.  It is independent of discovery
    order, file paths, and human prose.
    """
    sinks = sorted(
        f"{str(s.get('contract') or '')}.{str(s.get('fn') or '')}"
        for s in (sink_fns or []) if isinstance(s, dict)
    )
    edge = "::".join((str(flag_kind or ""), str(role or ""), ",".join(sinks)))
    return "A3-" + hashlib.sha256(edge.encode("utf-8")).hexdigest()[:16]


def load_typed_dispositions(ws):
    """Return ``(valid_ids, invalid_rows)`` from the A3 disposition ledger.

    Strict closure is intentionally exact: one identity field must be present,
    it must be a string, and the disposition type must be terminal.  Rows that
    only resemble a hypothesis (role/title/edge prose) never close anything.
    """
    path = ws / DISPOSITIONS_REL
    if not path.is_file():
        return {}, []
    valid = {}
    invalid = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {}, [{"line": 0, "reason": f"read-error:{exc}"}]
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            invalid.append({"line": line_no, "reason": "invalid-json"})
            continue
        if not isinstance(row, dict):
            invalid.append({"line": line_no, "reason": "row-not-object"})
            continue
        ids = [row.get(k) for k in ("stable_id", "hypothesis_id", "id")
               if isinstance(row.get(k), str) and row.get(k).strip()]
        dtype = row.get("disposition")
        if row.get("disposition_type") is not None:
            if dtype is not None and str(dtype).strip().lower() != str(
                    row.get("disposition_type")).strip().lower():
                invalid.append({"line": line_no, "reason": "conflicting-disposition-type"})
                continue
            dtype = row.get("disposition_type")
        if len(ids) != 1 or str(dtype or "").strip().lower() not in _TERMINAL_DISPOSITIONS:
            invalid.append({"line": line_no, "reason": "missing-exact-id-or-terminal-type"})
            continue
        valid[ids[0].strip()] = str(dtype).strip().lower()
    return valid, invalid


def _strict_prerequisites(pred_mod):
    blockers = []
    if pred_mod is None or not callable(getattr(pred_mod, "has_guard_in_closure", None)):
        blockers.append("missing-slither-predicates")
    try:
        from slither.slither import Slither  # noqa: F401
    except Exception:
        blockers.append("missing-slither")
    return blockers


def _index_functions(ws, needed, pred_mod):
    """Best-effort: slither the in-scope files and return
    (contract, fn) -> (guard_confirmed, file_line) for the NEEDED sink/grant fns.
    Fail-open: returns {} if Slither is unavailable."""
    if not needed or pred_mod is None:
        return {}
    try:
        from slither.slither import Slither  # noqa
    except Exception:
        return {}
    try:
        from _analyzer_common import iter_source_files
    except Exception:
        return {}
    has_guard = getattr(pred_mod, "has_guard_in_closure", None)
    degraded = getattr(pred_mod, "DEGRADED", object())
    out = {}
    want = set(needed)
    for sol in iter_source_files(ws, max_files=200):
        if not want:
            break
        try:
            sl = Slither(str(sol))
        except Exception:
            continue
        for c in sl.contracts:
            if c.is_interface or c.is_library:
                continue
            for fn in c.functions_and_modifiers_declared:
                key = (c.name, fn.name)
                if key not in want:
                    continue
                gc = None
                if has_guard is not None:
                    try:
                        res = has_guard(fn)
                        gc = None if res is degraded else bool(res)
                    except Exception:
                        gc = None
                fl = None
                sm = getattr(fn, "source_mapping", None)
                if sm is not None:
                    fname = getattr(sm, "filename", None)
                    short = getattr(fname, "short", None) or getattr(
                        fname, "absolute", None) or str(sol)
                    lines = getattr(sm, "lines", []) or []
                    ln = lines[0] if lines else "?"
                    fl = f"{short}:{ln}"
                out[key] = (gc, fl)
                want.discard(key)
    return out


def analyze(ws, acl_mod, pred_mod, *, strict=False, dispositions=None):
    """Returns (hypotheses:list, accounting:dict).

    The default remains fail-open.  Strict callers get an explicit prerequisite
    and unresolved-row ledger instead of a warning-shaped success.
    """
    acc = {
        "tool": "authority-blast-radius",
        "workspace": str(ws),
        "status": "ok",
        "roles_seen": 0,
        "blast_radius_flags": 0,
        "privilege_inversion_flags": 0,
        "hypotheses": 0,
        "mode": "canonical-strict" if strict else "legacy-advisory",
        "strict": bool(strict),
        "strict_blockers": [],
        "unresolved_hypotheses": [],
        "dispositioned_hypotheses": [],
    }
    if strict:
        acc["strict_blockers"].extend(_strict_prerequisites(pred_mod))
    try:
        rows, _ungated, _dead, role_grants, role_uses = acl_mod._analyze(ws)
    except Exception as exc:
        acc["status"] = "degraded-acl"
        acc["note"] = f"acl-matrix _analyze failed: {str(exc)[:120]}"
        if strict:
            acc["strict_blockers"].append("degraded-acl-analysis")
        return [], acc

    if not role_uses and not role_grants:
        acc["status"] = "no-roles"
        if strict:
            # acl-matrix treats both a missing Slither run and an empty role
            # materialization as degraded.  Strict cannot turn that absence
            # into a clean no-applicable result.
            acc["strict_blockers"].append("degraded-acl-no-roles")
        acc["strict_ok"] = not acc["strict_blockers"]
        if strict:
            acc["status"] = "strict-pass" if acc["strict_ok"] else "strict-fail"
        return [], acc

    acc["roles_seen"] = len(set(role_uses) | set(role_grants))
    row_index = {}
    for r in rows:
        row_index[(r["contract"], r["fn"])] = r

    # Role-admin fns (grant/revoke wrappers) are the PRIVILEGE-INVERSION lane's
    # subject, not blast-radius impact sinks; exclude them so their names
    # ("grant...Admin") do not masquerade as owner-implementation sinks.
    granter_keys = {
        (c, fn) for grs in role_grants.values() for (c, fn) in grs}

    # ---- pass 1: compute flags from acl-matrix outputs -------------------
    hyps = []
    needed = set()  # (contract, fn) sinks/granters to confirm-guard + locate

    # (a) BLAST-RADIUS
    br_records = []
    for role, uses in role_uses.items():
        if role in _TRIVIAL_ROLE:
            continue
        sink_fns = []
        union = set()
        for (c, fn) in uses:
            if (c, fn) in granter_keys:
                continue  # role-admin fn -> inversion lane, not a sink
            if _is_ownership_transfer_fn(fn):
                continue  # ownership handover -> two-step-ownership lane
            row = row_index.get((c, fn))
            if row is None:
                continue
            imps = classify_impacts(row)
            if not imps:
                continue
            sink_fns.append((c, fn, sorted(imps)))
            union |= imps
            needed.add((c, fn))
        if len(union) > 1:
            br_records.append((role, sink_fns, sorted(union)))

    # (b) PRIVILEGE-INVERSION
    pi_records = []
    for role, granters in role_grants.items():
        if role in _TRIVIAL_ROLE:
            continue
        # power the granted role confers (name rank + impact of its sinks)
        impacts_of_role = set()
        for (c, fn) in role_uses.get(role, []):
            if _is_ownership_transfer_fn(fn):
                continue  # ownership handover -> two-step-ownership lane
            row = row_index.get((c, fn))
            if row:
                impacts_of_role |= classify_impacts(row)
        power = _role_power(role, impacts_of_role)
        for (gc, gfn) in granters:
            grow = row_index.get((gc, gfn))
            if grow is None:
                continue
            guard_role = _sink_guard_role(grow)
            if guard_role is None:
                # ungated grant == guard-ABSENCE -> A2/ACL-COV owns it, skip
                continue
            grank = _name_rank(guard_role)
            if grank < power:
                needed.add((gc, gfn))
                needed |= {(c, fn) for (c, fn) in role_uses.get(role, [])}
                pi_records.append(
                    (role, gc, gfn, guard_role, grank, power,
                     sorted(impacts_of_role)))

    # ---- pass 2: confirm guards + file:line (best-effort Slither) ---------
    loc = _index_functions(ws, needed, pred_mod)

    def _fl(c, fn):
        v = loc.get((c, fn))
        return v[1] if v else None

    def _gc(c, fn):
        v = loc.get((c, fn))
        return v[0] if v else None

    for (role, sink_fns, union) in br_records:
        sinks = []
        any_confirmed = False
        for (c, fn, imps) in sink_fns:
            g = _gc(c, fn)
            any_confirmed = any_confirmed or (g is True)
            sinks.append({
                "contract": c, "fn": fn, "impacts": imps,
                "file_line": _fl(c, fn), "guard_confirmed": g,
            })
        gr = role_grants.get(role, [])
        hyps.append({
            "flag_kind": "blast-radius",
            "role": role,
            "granted_by": [f"{c}.{fn}" for (c, fn) in gr[:5]],
            "grant_guard_role": None,
            "distinct_impact_classes": union,
            "sink_fns": sinks,
            "guard_present_confirmed": any_confirmed,
            "verdict": "needs-fuzz",
            "attack_class": "authority-scope-blast-radius",
            "dedup_note": "A3 same-role/differing-impact; NOT A2 guard-absence",
        })

    for (role, gc, gfn, guard_role, grank, power, impacts) in pi_records:
        sinks = []
        for (c, fn) in role_uses.get(role, []):
            if _is_ownership_transfer_fn(fn):
                continue  # ownership handover -> two-step-ownership lane
            sinks.append({
                "contract": c, "fn": fn,
                "impacts": sorted(classify_impacts(row_index.get((c, fn), {}))),
                "file_line": _fl(c, fn), "guard_confirmed": _gc(c, fn),
            })
        hyps.append({
            "flag_kind": "privilege-inversion",
            "role": role,
            "granted_by": [f"{gc}.{gfn}"],
            "grant_guard_role": guard_role,
            "grant_guard_rank": grank,
            "granted_power_rank": power,
            "distinct_impact_classes": impacts,
            "sink_fns": sinks,
            "grant_file_line": _fl(gc, gfn),
            "verdict": "needs-fuzz",
            "attack_class": "authority-scope-privilege-inversion",
            "dedup_note": "A3 weak-role-grants-strong; NOT two-step-ownership",
        })

    for hyp in hyps:
        stable_id = hypothesis_stable_id(
            hyp["flag_kind"], hyp["role"], hyp.get("sink_fns"))
        hyp["stable_id"] = stable_id
        hyp["hypothesis_id"] = stable_id

    acc["blast_radius_flags"] = len(br_records)
    acc["privilege_inversion_flags"] = len(pi_records)
    acc["hypotheses"] = len(hyps)
    if strict:
        valid_dispositions = dispositions or {}
        for hyp in hyps:
            stable_id = hyp["stable_id"]
            if stable_id in valid_dispositions:
                acc["dispositioned_hypotheses"].append(stable_id)
                continue
            unresolved = []
            if hyp["flag_kind"] == "blast-radius":
                unresolved.extend(
                    f"{s['contract']}.{s['fn']}"
                    for s in hyp.get("sink_fns", [])
                    if s.get("guard_confirmed") is not True
                )
            else:
                unresolved.extend(
                    f"{s['contract']}.{s['fn']}"
                    for s in hyp.get("sink_fns", [])
                    if s.get("guard_confirmed") is not True
                )
                if hyp.get("grant_file_line") is None:
                    unresolved.append("grant-location")
            if unresolved:
                acc["strict_blockers"].append(
                    f"degraded-hypothesis-evidence:{stable_id}")
            acc["unresolved_hypotheses"].append({
                "stable_id": stable_id,
                "flag_kind": hyp["flag_kind"],
                "unresolved": unresolved or ["needs-terminal-disposition"],
            })
        # A hypothesis without a terminal typed disposition is still open even
        # when its source evidence is complete: A3 is a hypothesis producer.
        if acc["unresolved_hypotheses"]:
            acc["strict_blockers"].append("unresolved-applicable-hypotheses")
    acc["strict_ok"] = bool(strict and not acc["strict_blockers"] and
                             not acc["unresolved_hypotheses"]) if strict else True
    if strict:
        acc["status"] = "strict-pass" if acc["strict_ok"] else "strict-fail"
    return hyps, acc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--strict", action="store_true",
                    help="canonical fail-closed mode")
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        sys.exit(1)

    try:
        acl_mod = _load_acl()
    except Exception as exc:
        acc = {"tool": "authority-blast-radius", "status": "degraded-acl",
               "note": f"acl-matrix load failed: {str(exc)[:120]}",
               "hypotheses": 0, "mode": "canonical-strict" if args.strict
               else "legacy-advisory", "strict": bool(args.strict),
               "strict_blockers": ["missing-acl-matrix"],
               "unresolved_hypotheses": [], "strict_ok": not args.strict}
        _emit(ws, [], acc, args.out)
        if args.json:
            print(json.dumps(acc))
        else:
            prefix = "[fail]" if args.strict else "[ok]"
            suffix = "strict prerequisite failure" if args.strict else "fail-open"
            print(f"{prefix} A3 degraded (acl-matrix unavailable); {suffix}")
        sys.exit(1 if args.strict else 0)

    pred_mod = _load_predicates()
    dispositions, invalid_dispositions = load_typed_dispositions(ws)
    hyps, acc = analyze(ws, acl_mod, pred_mod, strict=args.strict,
                        dispositions=dispositions)
    if args.strict and invalid_dispositions:
        acc["strict_blockers"].append("invalid-disposition-rows")
    acc["invalid_dispositions"] = invalid_dispositions
    if args.strict and acc.get("strict_blockers"):
        acc["strict_ok"] = False
        acc["status"] = "strict-fail"
    _emit(ws, hyps, acc, args.out)

    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": hyps}))
    else:
        prefix = "[ok]" if not args.strict or acc.get("strict_ok") else "[fail]"
        print(f"{prefix} A3 authority-blast-radius: status={acc['status']}")
        print(f"     roles seen:            {acc['roles_seen']}")
        print(f"     blast-radius flags:    {acc['blast_radius_flags']}")
        print(f"     privilege-inversion:   {acc['privilege_inversion_flags']}")
        print(f"     hypotheses (needs-fuzz): {acc['hypotheses']}")
        if args.strict and acc.get("strict_blockers"):
            print("     strict blockers:         " + "; ".join(acc["strict_blockers"]))
    if args.strict and not acc.get("strict_ok"):
        return_code = 1
    else:
        return_code = 0
    if args.json:
        # JSON output above is intentionally retained; this is only the exit
        # contract for callers consuming the canonical artifact.
        pass
    if return_code:
        sys.exit(return_code)


def _emit(ws, hyps, acc, out=None):
    out_path = pathlib.Path(out) if out else (ws / OUT_REL)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for h in hyps:
            f.write(json.dumps(h) + "\n")
    acc_path = ws / ACC_REL
    acc_path.parent.mkdir(parents=True, exist_ok=True)
    with open(acc_path, "w") as f:
        json.dump(acc, f, indent=2)


if __name__ == "__main__":
    main()
