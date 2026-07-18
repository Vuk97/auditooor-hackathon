"""Regression tests for tools/callgraph-set-difference-hunter.py (LOGIC #3).

Proves the Euler set-difference reasoning query over the owned dataflow backend:
  1. a downward-mutation entrypoint whose closure REACHES a solvency/health check
     is KEPT (removed from DOWN\\CHECK) - it is NOT emitted;
  2. a downward-mutation entrypoint whose closure reaches NO such check is a
     SURVIVOR and IS emitted as an unguarded-mutation-entrypoint obligation;
  3. the CHECK is a CLOSURE property: a check reached only through an N-hop HELPER
     record (not in the same fn's own record) still removes the fn - impossible
     for a same-body regex;
  4. the solvency guard_pred distinguishes a post-state conservation assertion
     from an access-control / bound guard (the latter does NOT satisfy CHECK);
  5. non-downward sink kinds (mint / authority) never populate DOWN;
  6. a fully DEGRADED substrate yields an empty diff + a warning, and
     --fail-closed exits 3;
  7. vendored / out-of-workspace files never carry an obligation.
"""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "callgraph-set-difference-hunter.py"
_spec = importlib.util.spec_from_file_location("cg_setdiff", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# --------------------------------------------------------------------------
# synthetic dataflow_paths.jsonl builder
# --------------------------------------------------------------------------
def _rec(lang, entry_fn, entry_file, sink_kind, guard_exprs, *,
         sink_callee="X", line=10, sink_fn=None):
    """A backward dataflow_path.v1 record: entrypoint `entry_fn` (in `entry_file`)
    reaches sink `sink_kind`, carrying the closure guard nodes `guard_exprs`."""
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "direction": "backward",
        "degraded": False,
        "source": {"kind": "param-entrypoint", "fn": entry_fn,
                   "file": entry_file, "line": line, "var": "amount"},
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
    p = ws / ".auditooor" / "unguarded_mutation_obligations.jsonl"
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


# --------------------------------------------------------------------------
# 1 + 2: KEPT (checked) vs SURVIVOR (unchecked), the core set-difference
# --------------------------------------------------------------------------
def test_checked_kept_unchecked_emitted(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Vault.sol")
    recs = [
        # SAFE: burn entrypoint whose closure has a post-state conservation check.
        _rec("solidity", "Vault.safeBurn(uint256)", f, "burn",
             ["balanceAfter == balanceBefore + amount"]),
        # BUG: burn entrypoint with only an access-control / bound guard.
        _rec("solidity", "Vault.donate(uint256)", f, "burn",
             ["msg.sender == owner", "amount == 0"]),
    ]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws)
    assert out["size_DOWN"] == 2
    assert "safeBurn" in out["kept_down_and_checked"]
    surv = {s["fn"] for s in out["survivors"]}
    assert surv == {"donate"}, surv
    obls = _load_obligations(ws)
    assert len(obls) == 1
    assert obls[0]["function"] == "donate"
    assert obls[0]["obligation_type"] == "unguarded-mutation-entrypoint"
    assert obls[0]["down_sink_kinds"] == ["burn"]


# --------------------------------------------------------------------------
# 3: CHECK is a CLOSURE property - the check is reached via a helper record
# --------------------------------------------------------------------------
def test_check_reached_through_helper_closure(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Lend.sol")
    # The entrypoint's OWN record carries the mutation and NO solvency expr; a
    # SECOND record for the same entrypoint (a helper hop) carries the check.
    recs = [
        _rec("solidity", "Lend.withdraw(uint256)", f, "value-move", []),
        _rec("solidity", "Lend.withdraw(uint256)", f, "state-write",
             ["checkAccountLiquidity(msg.sender)"], line=40),
    ]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws)
    assert out["size_DOWN"] == 1
    # the closure-level union of guard exprs sees the helper check -> KEPT
    assert out["survivors"] == []
    assert "withdraw" in out["kept_down_and_checked"]
    assert _load_obligations(ws) == []


# --------------------------------------------------------------------------
# 4: the solvency predicate rejects a pure access-control / bound guard
# --------------------------------------------------------------------------
def test_solvency_pred_semantics():
    p = mod.solvency_guard_pred
    # conservation / health assertions -> True
    assert p("balanceAfter == balanceBefore + amount")
    assert p("healthFactor >= 1e18")
    assert p("checkLiquidity(account)")
    assert p("collateralValue >= debt")
    assert p("require(totalShares == sumOfShares)")
    # access-control / bounds / unrelated -> False
    assert not p("msg.sender == owner")
    assert not p("amount == 0")
    assert not p("i < destinationAddresses.length")
    assert not p("t3 != nil:error")
    assert not p("")


# --------------------------------------------------------------------------
# 5: non-downward sink kinds never populate DOWN (mint = increase, authority)
# --------------------------------------------------------------------------
def test_mint_and_authority_not_downward(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Token.sol")
    recs = [
        _rec("solidity", "Token.issue(uint256)", f, "mint", []),
        _rec("solidity", "Token.grant(address)", f, "authority", []),
        _rec("solidity", "Token.pull(uint256)", f, "safeTransferFrom", []),
    ]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws)
    assert out["size_DOWN"] == 0
    assert _load_obligations(ws) == []


def test_down_kinds_override_includes_mint(tmp_path):
    f = str(tmp_path / "ws" / "src" / "Token.sol")
    recs = [_rec("solidity", "Token.issue(uint256)", f, "mint", [])]
    ws = _mk_ws(tmp_path, recs)
    out = _run(ws, down_kinds="mint")
    assert out["size_DOWN"] == 1
    assert {s["fn"] for s in out["survivors"]} == {"issue"}


# --------------------------------------------------------------------------
# 6: degraded substrate -> empty diff + warning; --fail-closed exits 3
# --------------------------------------------------------------------------
def test_degraded_substrate_warns_and_fail_closed(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text(json.dumps({
        "schema": "dataflow_path.v1", "language": "go", "degraded": True,
        "degrade_reason": "go-dataflow timed out", "source": {"kind": "none"},
        "sink": {"kind": "none"}, "guard_nodes": [],
    }) + "\n", encoding="utf-8")
    out = _run(ws)
    assert out["size_DOWN"] == 0
    assert out["substrate_degraded"] is True
    assert any("DEGRADED" in w for w in out["warnings"])
    rc = mod.run(["--workspace", str(ws), "--json", "--fail-closed"])
    assert rc == 3


# --------------------------------------------------------------------------
# 7: vendored / out-of-workspace files never carry an obligation
# --------------------------------------------------------------------------
def test_vendored_out_of_ws_excluded(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src").mkdir(parents=True)
    infile = str(ws / "src" / "Real.sol")
    vendored = "/Users/somebody/go/pkg/mod/cosmossdk.io/collections/map.go"
    outside = str(tmp_path / "elsewhere" / "Other.sol")
    recs = [
        _rec("solidity", "Real.burnIt(uint256)", infile, "burn", []),
        _rec("go", "(*collections.Map).Remove", vendored, "state-write", []),
        _rec("solidity", "Other.burnIt(uint256)", outside, "burn", []),
    ]
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    with df.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    out = _run(ws)
    survs = {s["fn"] for s in out["survivors"]}
    assert survs == {"burnIt"}, survs
    files = {s["file"] for s in out["survivors"]}
    assert files == {infile}, files


# ==========================================================================
# Cosmos/Go workspace fixture + precision-fix regressions (direction, entrypoint,
# permissionless rank, module-boundary conservation).
# ==========================================================================
def _mk_go_ws(tmp_path, keeper_src, records, *, cov=None):
    """A cosmos-go workspace: go.mod importing cosmos-sdk (so the entrypoint
    narrowing fires) + a keeper .go source + the dataflow records + optional
    cross_function_invariant_coverage.json."""
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    kdir = ws / "src" / "x" / "vault" / "keeper"
    kdir.mkdir(parents=True)
    (ws / "go.mod").write_text(
        "module example.com/vault\n\nrequire github.com/cosmos/cosmos-sdk v0.50.0\n",
        encoding="utf-8")
    kf = kdir / "keeper.go"
    kf.write_text(keeper_src, encoding="utf-8")
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    with df.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    if cov is not None:
        (ws / ".auditooor" / "cross_function_invariant_coverage.json").write_text(
            json.dumps(cov), encoding="utf-8")
    return ws, str(kf)


def _line_of(src, needle):
    for i, ln in enumerate(src.splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(f"needle not found: {needle}")


# The keeper source: an INBOUND deposit (recipient -> vault), an OUTBOUND
# role-gated withdrawal (vault -> authority), an OUTBOUND permissionless drain
# (pool -> caller), and an OUTBOUND internal helper.
_KEEPER_SRC = '''package keeper

func (k msgServer) DepositFunds(goCtx context.Context, msg *types.MsgDepositFunds) (*types.MsgDepositFundsResponse, error) {
\tctx := sdk.UnwrapSDKContext(goCtx)
\tk.BankKeeper.SendCoins(markertypes.WithBypass(ctx), depositFromAddr, vaultAddr, coins) //DEPOSIT
\treturn nil, nil
}

func (k msgServer) WithdrawFunds(goCtx context.Context, msg *types.MsgWithdrawFunds) (*types.MsgWithdrawFundsResponse, error) {
\tctx := sdk.UnwrapSDKContext(goCtx)
\tif err := vault.ValidateManagementAuthority(msg.Authority); err != nil {
\t\treturn nil, err
\t}
\tk.BankKeeper.SendCoins(ctx, vaultAddr, authorityAddr, coins) //WITHDRAW
\treturn nil, nil
}

func (k msgServer) OpenDrain(goCtx context.Context, msg *types.MsgOpenDrain) (*types.MsgOpenDrainResponse, error) {
\tctx := sdk.UnwrapSDKContext(goCtx)
\tk.BankKeeper.SendCoins(ctx, poolAddr, msg.To, coins) //DRAIN
\treturn nil, nil
}

func (k Keeper) sweepDust(ctx sdk.Context) error {
\treturn k.BankKeeper.SendCoins(ctx, vaultAddr, feeCollector, coins) //SWEEP
}
'''


def _go_rec(entry_fn, sink_file, sink_line, *, callee, kind="value-move"):
    return {
        "schema": "dataflow_path.v1", "language": "go", "direction": "backward",
        "degraded": False,
        "source": {"kind": "param-entrypoint", "fn": entry_fn,
                   "file": sink_file, "line": sink_line, "var": "ctx"},
        "sink": {"kind": kind, "callee": callee, "fn": entry_fn,
                 "file": sink_file, "line": sink_line},
        "hops": [], "guard_nodes": [],
    }


def test_direction_aware_inbound_dropped_outbound_kept(tmp_path):
    """An INBOUND deposit (value ENTERS the vault) is not a downward mutation and
    must not populate DOWN; an OUTBOUND move is downward."""
    recs = [
        _go_rec("(example.com/vault/keeper.msgServer).DepositFunds", "SF",
                _line_of(_KEEPER_SRC, "//DEPOSIT"),
                callee="(types.BankKeeper).SendCoins"),
        _go_rec("(example.com/vault/keeper.msgServer).WithdrawFunds", "SF",
                _line_of(_KEEPER_SRC, "//WITHDRAW"),
                callee="(types.BankKeeper).SendCoins"),
    ]
    ws, kf = _mk_go_ws(tmp_path, _KEEPER_SRC, [])
    for r in recs:
        r["sink"]["file"] = kf
        r["source"]["file"] = kf
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")

    out = _run(ws)
    survs = {s["fn"] for s in out["survivors"]}
    assert survs == {"WithdrawFunds"}, survs
    assert out["direction_aware"] is True

    # toggle OFF: the inbound deposit is now (over-)counted as downward.
    out2 = _run(ws, no_direction_aware=True)
    survs2 = {s["fn"] for s in out2["survivors"]}
    assert survs2 == {"DepositFunds", "WithdrawFunds"}, survs2


def test_typed_bank_primitive_direction(tmp_path):
    """Direction read straight off a TYPED bank primitive callee (no source)."""
    ws, kf = _mk_go_ws(tmp_path, _KEEPER_SRC, [])
    recs = [
        # inbound: account -> module
        _go_rec("(example.com/vault/keeper.msgServer).Escrow", kf, 5,
                callee="(types.BankKeeper).SendCoinsFromAccountToModule"),
        # outbound: module -> account
        _go_rec("(example.com/vault/keeper.msgServer).Release", kf, 5,
                callee="(types.BankKeeper).SendCoinsFromModuleToAccount"),
    ]
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    out = _run(ws)
    assert {s["fn"] for s in out["survivors"]} == {"Release"}


def test_entrypoint_filter_prunes_internal_helper(tmp_path):
    """A Keeper-receiver internal helper survivor is pruned in a cosmos-go ws;
    a msgServer handler survivor is kept. --no-entrypoint-filter keeps both."""
    ws, kf = _mk_go_ws(tmp_path, _KEEPER_SRC, [])
    recs = [
        _go_rec("(example.com/vault/keeper.msgServer).WithdrawFunds", kf,
                _line_of(_KEEPER_SRC, "//WITHDRAW"),
                callee="(types.BankKeeper).SendCoins"),
        _go_rec("(example.com/vault/keeper.Keeper).sweepDust", kf,
                _line_of(_KEEPER_SRC, "//SWEEP"),
                callee="(types.BankKeeper).SendCoins"),
    ]
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")

    out = _run(ws)
    assert {s["fn"] for s in out["survivors"]} == {"WithdrawFunds"}
    assert "sweepDust" in out["non_entrypoint_pruned"]

    out2 = _run(ws, no_entrypoint_filter=True)
    assert {s["fn"] for s in out2["survivors"]} == {"WithdrawFunds", "sweepDust"}


def test_permissionless_rank(tmp_path):
    """Permissionless downward-mutators are ranked (and flagged) before role-gated
    ones; both are still emitted."""
    ws, kf = _mk_go_ws(tmp_path, _KEEPER_SRC, [])
    recs = [
        _go_rec("(example.com/vault/keeper.msgServer).WithdrawFunds", kf,
                _line_of(_KEEPER_SRC, "//WITHDRAW"),
                callee="(types.BankKeeper).SendCoins"),
        _go_rec("(example.com/vault/keeper.msgServer).OpenDrain", kf,
                _line_of(_KEEPER_SRC, "//DRAIN"),
                callee="(types.BankKeeper).SendCoins"),
    ]
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")

    out = _run(ws)
    order = [s["fn"] for s in out["survivors"]]
    assert order == ["OpenDrain", "WithdrawFunds"], order
    flags = {s["fn"]: s["permissionless"] for s in out["survivors"]}
    assert flags == {"OpenDrain": True, "WithdrawFunds": False}, flags
    obls = {o["function"]: o for o in _load_obligations(ws)}
    assert obls["OpenDrain"]["priority_rank"] == 0
    assert obls["WithdrawFunds"]["priority_rank"] == 1


# module-boundary conservation: a survivor moving value through a Cosmos
# module-boundary bank primitive whose module has a COVERED conservation
# invariant is credited to CHECK; a plain account-to-account SendCoins is not.
_CONS_SRC = '''package keeper

func mint(ctx sdk.Context, bank types.BankKeeper, toAddr sdk.AccAddress) error {
\treturn bank.SendCoinsFromModuleToAccount(ctx, types.ModuleName, toAddr, coins) //MINT
}

func (k msgServer) PayFee(goCtx context.Context, msg *types.MsgPayFee) (*types.MsgPayFeeResponse, error) {
\tctx := sdk.UnwrapSDKContext(goCtx)
\tk.BankKeeper.SendCoins(ctx, vaultAddr, feeAddr, coins) //FEE
\treturn nil, nil
}
'''


def _cov(label, killed_fns=None, killed_tests=None, status="covered"):
    return {"covered": [{
        "kind": "sibling-pair", "label": label, "status": status,
        "evidence": {"killed_functions": killed_fns or [],
                     "killed_tests": killed_tests or []},
    }]}


def test_module_boundary_conservation_credit(tmp_path):
    """mint (SendCoinsFromModuleToAccount, module x/vault) is credited by a covered
    mint|burn@x/vault invariant; PayFee (plain SendCoins) is NOT credited."""
    ws, kf = _mk_go_ws(
        tmp_path, _CONS_SRC, [],
        cov=_cov("mint|burn@x/vault/keeper"))
    # rewrite keeper source into the module path so file scope matches @x/vault.
    Path(kf).write_text(_CONS_SRC, encoding="utf-8")
    recs = [
        _go_rec("example.com/vault/keeper.mint", kf,
                _line_of(_CONS_SRC, "//MINT"),
                callee="(types.BankKeeper).SendCoinsFromModuleToAccount"),
        _go_rec("(example.com/vault/keeper.msgServer).PayFee", kf,
                _line_of(_CONS_SRC, "//FEE"),
                callee="(types.BankKeeper).SendCoins"),
    ]
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")

    out = _run(ws)
    # mint -> conservation-credited (KEPT, out of survivors); PayFee -> survivor.
    assert "mint" in out["conservation_credited"]
    assert out["size_CHECK_among_down"] >= 1
    assert {s["fn"] for s in out["survivors"]} == {"PayFee"}
    info = out["conservation_credited"]["mint"]
    assert info["credit_path"] == "module-boundary-bank-primitive"
    assert "sendcoinsfrommoduletoaccount" in info["matched_quantities"]

    # toggle OFF: no conservation credit -> mint would be a survivor were it an
    # entrypoint; it is an internal helper, so it is pruned - assert NO credit.
    out2 = _run(ws, no_conservation_credit=True)
    assert out2["size_conservation_credited"] == 0


def test_no_over_credit_plain_sendcoins(tmp_path):
    """A plain account-to-account SendCoins is NOT a module-boundary primitive, so
    even with a covered mint|burn invariant in the same module it earns no credit
    (guards the nuva withdrawal/burn survivors from being silently cleared)."""
    ws, kf = _mk_go_ws(
        tmp_path, _CONS_SRC, [],
        cov=_cov("mint|burn@x/vault/keeper"))
    Path(kf).write_text(_CONS_SRC, encoding="utf-8")
    rec = _go_rec("(example.com/vault/keeper.msgServer).PayFee", kf,
                  _line_of(_CONS_SRC, "//FEE"),
                  callee="(types.BankKeeper).SendCoins")
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    df.write_text(json.dumps(rec), encoding="utf-8")
    out = _run(ws)
    assert out["size_conservation_credited"] == 0
    assert {s["fn"] for s in out["survivors"]} == {"PayFee"}
