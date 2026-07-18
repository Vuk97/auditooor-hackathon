"""Regression tests for tools/rust-account-owner-signer-confusion.py.

Proves the Solana/Rust account-confusion set-difference reasoning query over the
owned dataflow backend (schema dataflow_path.v1):
  1. a caller-supplied account PARAM that flows to an authority-use sink whose
     closure carries an owner/signer/key-equality check is KEPT (removed from
     AUTH_USE\\CHECK) - it is NOT emitted;
  2. a caller-supplied account PARAM that flows to an authority-use sink whose
     closure reaches NO such check is a SURVIVOR and IS emitted as an
     account-owner-signer-confusion obligation;
  3. the CHECK is a CLOSURE property: an owner/signer/key check reached only
     through an N-hop HELPER record (not the same fn's own record) still removes
     the unit - impossible for a same-body regex;
  4. per-PARAM keying: in a fn taking TWO accounts, a check on ONE account does
     NOT credit the OTHER unchecked account (a per-fn key would hide the bug);
  5. authority-use is a REACHABILITY property: a benign non-authority sink
     (state-write with no authority callee) never populates AUTH_USE;
  6. NON-VACUITY (mutation): neutralising account_check_pred - or mutating the
     guard node from an owner/signer/key check to an unrelated bound guard -
     FLIPS a KEPT unit into a SURVIVOR, proving the check node is load-bearing;
  7. a fully DEGRADED substrate yields an empty diff + a warning, and
     --fail-closed exits 3;
  8. vendored / out-of-workspace files never carry an obligation.
"""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = (Path(__file__).resolve().parents[1]
             / "rust-account-owner-signer-confusion.py")
_spec = importlib.util.spec_from_file_location("acct_confusion", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# --------------------------------------------------------------------------
# synthetic dataflow_paths.jsonl builder (backward slice, param source)
# --------------------------------------------------------------------------
def _rec(lang, entry_fn, entry_file, sink_kind, guard_exprs, *,
         var="authority", sink_callee="", line=10, sink_fn=None):
    """A backward dataflow_path.v1 record: caller-supplied account param `var` of
    `entry_fn` (in `entry_file`) flows to sink (`sink_kind`, `sink_callee`),
    carrying the closure guard nodes `guard_exprs`."""
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "direction": "backward",
        "degraded": False,
        "source": {"kind": "param", "fn": entry_fn,
                   "file": entry_file, "line": line, "var": var},
        "sink": {"kind": sink_kind, "callee": sink_callee,
                 "fn": sink_fn or entry_fn, "file": entry_file, "line": line + 5},
        "hops": [],
        "guard_nodes": [{"file": entry_file, "line": line + 1, "expr": e}
                        for e in guard_exprs],
    }


def _mk_ws(tmp_path, records):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src").mkdir(parents=True)
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    with df.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return ws


def _run(ws, **kw):
    argv = ["--workspace", str(ws), "--json"]
    for k, v in kw.items():
        flag = "--" + k.replace("_", "-")
        if v is True:
            argv.append(flag)
        elif v is not None:
            argv.extend([flag, str(v)])
    return mod.run(argv)


def _load_obligations(ws):
    p = ws / ".auditooor" / "account_confusion_obligations.jsonl"
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip() and "examined_record" not in l]


# --------------------------------------------------------------------------
# 1 + 2: KEPT (checked) vs SURVIVOR (unchecked), the core set-difference
# --------------------------------------------------------------------------
def test_checked_kept_unchecked_emitted(tmp_path):
    f = str(tmp_path / "ws" / "src" / "escrow.rs")
    recs = [
        # SAFE: account param reaches a set_authority CPI but its closure has an
        # owner/key-equality check on the account.
        _rec("rust", "escrow::withdraw", f, "authority",
             ["require_keys_eq!(ctx.accounts.vault.owner, expected)"],
             var="vault", sink_callee="token::set_authority"),
        # BUG: account param reaches the same authority sink with only an
        # unrelated bound/amount guard - no owner/signer/key check.
        _rec("rust", "escrow::drain", f, "authority",
             ["amount > 0", "amount <= vault.balance"],
             var="vault", sink_callee="token::set_authority"),
    ]
    ws = _mk_ws(tmp_path, recs)
    summ = _run(ws)
    assert summ["size_AUTH_USE"] == 2
    assert summ["size_CHECK_among_auth"] == 1
    assert summ["size_DIFF_survivors"] == 1
    obs = _load_obligations(ws)
    assert len(obs) == 1
    ob = obs[0]
    assert ob["function"] == "drain"
    assert ob["account_param"] == "vault"
    assert ob["attack_class"] == "account-owner-signer-confusion"
    assert ob["schema"] == "auditooor.account_owner_signer_confusion.v1"


# --------------------------------------------------------------------------
# 3: CHECK is a CLOSURE property (helper N hops away still removes the unit)
# --------------------------------------------------------------------------
def test_check_in_helper_record_removes_unit(tmp_path):
    f = str(tmp_path / "ws" / "src" / "cpi.rs")
    recs = [
        # authority use with NO guard in this record ...
        _rec("rust", "cpi::transfer_out", f, "value-move", [],
             var="authority", sink_callee="token::transfer"),
        # ... but a SECOND record for the SAME (fn, param) carries the signer
        # check reached through a helper (guard accumulates over the closure).
        _rec("rust", "cpi::transfer_out", f, "value-move",
             ["ctx.accounts.authority.is_signer"],
             var="authority", sink_callee="verify_signer_helper", line=40),
    ]
    ws = _mk_ws(tmp_path, recs)
    summ = _run(ws)
    assert summ["size_AUTH_USE"] == 1
    assert summ["size_DIFF_survivors"] == 0  # signer check in the closure -> KEPT
    assert _load_obligations(ws) == []


# --------------------------------------------------------------------------
# 4: per-PARAM keying - a check on one account never credits another
# --------------------------------------------------------------------------
def test_per_param_keying_isolated(tmp_path):
    f = str(tmp_path / "ws" / "src" / "multi.rs")
    fn = "prog::settle"
    recs = [
        # account A: checked (has_one).
        _rec("rust", fn, f, "authority", ["has_one = admin"],
             var="admin", sink_callee="set_authority"),
        # account B: SAME fn, unchecked - must survive independently.
        _rec("rust", fn, f, "authority", ["clock.slot > start"],
             var="beneficiary", sink_callee="set_authority"),
    ]
    ws = _mk_ws(tmp_path, recs)
    summ = _run(ws)
    assert summ["size_AUTH_USE"] == 2
    assert summ["size_DIFF_survivors"] == 1
    obs = _load_obligations(ws)
    assert len(obs) == 1
    assert obs[0]["account_param"] == "beneficiary"


# --------------------------------------------------------------------------
# 5: authority-use is a reachability property (benign sink != AUTH_USE)
# --------------------------------------------------------------------------
def test_non_authority_sink_never_in_auth_use(tmp_path):
    f = str(tmp_path / "ws" / "src" / "cfg.rs")
    recs = [
        # a bare state-write whose callee is NOT an authority op: the account is
        # not USED as an authority, so it never enters AUTH_USE even unchecked.
        _rec("rust", "cfg::set_fee", f, "state-write", [],
             var="config", sink_callee="store_fee_bps"),
    ]
    ws = _mk_ws(tmp_path, recs)
    summ = _run(ws)
    assert summ["size_AUTH_USE"] == 0
    assert summ["size_DIFF_survivors"] == 0
    assert _load_obligations(ws) == []


# --------------------------------------------------------------------------
# 6: NON-VACUITY mutation - the check node is load-bearing
# --------------------------------------------------------------------------
def test_mutation_neutralising_check_flips_kept_to_survivor(tmp_path):
    fa = str(tmp_path / "a" / "ws" / "src" / "mut.rs")
    # A single authority-use unit that IS checked (owner equality) -> KEPT.
    good = _rec("rust", "prog::act", fa, "authority",
                ["account.owner == program_id"],
                var="acct", sink_callee="invoke_signed")
    ws_kept = _mk_ws(tmp_path / "a", [good])
    summ_kept = _run(ws_kept)
    assert summ_kept["size_AUTH_USE"] == 1
    assert summ_kept["size_DIFF_survivors"] == 0  # check present -> KEPT

    # MUTANT: replace the owner-equality check with an unrelated bound guard
    # (the ONLY change). The account-flow topology is identical; only the guard
    # node's semantics change. The unit must now SURVIVE - proving the verdict is
    # driven by account_check_pred, not by the flow shape / a name token.
    fb = str(tmp_path / "b" / "ws" / "src" / "mut.rs")
    mutant = _rec("rust", "prog::act", fb, "authority",
                  ["balance >= min_balance"],
                  var="acct", sink_callee="invoke_signed")
    ws_surv = _mk_ws(tmp_path / "b", [mutant])
    summ_surv = _run(ws_surv)
    assert summ_surv["size_AUTH_USE"] == 1
    assert summ_surv["size_DIFF_survivors"] == 1  # check neutralised -> SURVIVOR
    obs = _load_obligations(ws_surv)
    assert len(obs) == 1 and obs[0]["account_param"] == "acct"

    # And the direct node-predicate assertion (unit test of the load-bearing pred).
    assert mod.account_check_pred("account.owner == program_id") is True
    assert mod.account_check_pred("ctx.accounts.a.is_signer") is True
    assert mod.account_check_pred("require_keys_eq!(a.key(), b)") is True
    assert mod.account_check_pred("has_one = admin") is True
    assert mod.account_check_pred("balance >= min_balance") is False
    assert mod.account_check_pred("amount > 0") is False


# --------------------------------------------------------------------------
# 7: fully degraded substrate -> empty diff + warning + --fail-closed exits 3
# --------------------------------------------------------------------------
def test_degraded_substrate_fail_closed(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    with df.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "schema": "dataflow_path.v1", "language": "rust", "degraded": True,
            "source": {"kind": "none", "fn": None, "var": None,
                       "file": None, "line": None},
            "sink": {"kind": "none", "callee": None, "fn": None,
                     "file": None, "line": None},
            "guard_nodes": [],
        }) + "\n")
    summ = _run(ws)
    assert summ["size_AUTH_USE"] == 0
    assert summ["substrate_degraded"] is True
    assert any("DEGRADED" in w for w in summ["warnings"])
    rc = mod.run(["--workspace", str(ws), "--fail-closed"])
    assert rc == 3


# --------------------------------------------------------------------------
# 8: vendored / out-of-workspace files never carry an obligation
# --------------------------------------------------------------------------
def test_vendored_file_excluded(tmp_path):
    vendored = "/Users/x/.cargo/registry/src/spl-token-4.0.0/src/lib.rs"
    recs = [
        _rec("rust", "spl::set_authority", vendored, "authority", [],
             var="authority", sink_callee="set_authority"),
    ]
    ws = _mk_ws(tmp_path, recs)
    summ = _run(ws)
    assert summ["size_AUTH_USE"] == 0
    assert _load_obligations(ws) == []
