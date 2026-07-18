#!/usr/bin/env python3
"""callgraph-set-difference-hunter.py - the Euler $197M reasoning query.

LOGIC CAPABILITY #3 (docs/LOGIC_ARSENAL_ROADMAP.md). This is a SET / COMPOSITION
query over an OWNED call-graph backend, NOT a token detector.

THE INVARIANT (Euler donateToReserves-skips-health-check, rekt 2023):
  Let
    DOWN  = { external/public entrypoint f : f's forward callee closure REACHES a
              downward-mutation sink (burn / value-move-out / ledger-debit
              state-write) }
    CHECK = { external/public entrypoint f : f's forward callee closure REACHES a
              required post-state SOLVENCY / HEALTH / CONSERVATION assertion node }
  The protocol's trust boundary requires   DOWN  is a SUBSET of  CHECK.
  Every f in the SET-DIFFERENCE   DOWN \\ CHECK   mutates a protected quantity
  downward but never reaches the check -> that is the Euler class bug, emitted as
  an `unguarded-mutation-entrypoint` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  The shipped detector it replaces
  (detectors/wave17/donate_to_reserves_skips_debt_health_check.py) is a SAME-BODY
  regex: `body_contains_regex('-=' / 'reserves')` AND
  `body_not_contains_regex('checkLiquidity|...')`. It false-positives when the
  check lives in a helper and false-negatives on any renamed sink/check.
  This query differs on the three axes that make it a graph-set relation:
    (a) membership is TRANSITIVE forward-closure reachability to a SEMANTIC
        sink / guard node - a solvency check reached through an N-hop helper
        correctly places the fn in CHECK (impossible for a body-scoped regex);
    (b) the answer is a relation between TWO SETS of functions (the subset test
        DOWN is a subset of CHECK) whose finding is the SET-DIFFERENCE, not a
        boolean over one function's text;
    (c) the sink and the check need not co-occur in any single body - they are
        located anywhere in the closure, so no token-adjacency / same-file
        assumption is used.

OWNED BACKEND CONSUMED (no new call-graph engine is built here)
  <ws>/.auditooor/dataflow_paths.jsonl  (schema dataflow_path.v1) produced by
  tools/go-dataflow.py (go/ssa + callgraph + backward DefUse slice) for the Go
  arm and by the Slither data_dependency arm for Solidity. Each record ties an
  ENTRYPOINT (source, kind=param-entrypoint) to a downward SINK (sink.kind
  classified by go-dataflow main.go classifySink / the Solidity sink taxonomy)
  and carries the CLOSURE-consulted dominating/observed guard nodes
  (guard_nodes[].expr, closure_note='guard@source-closure'). DOWN reads sink.kind;
  CHECK reads whether ANY closure guard node satisfies the solvency guard_pred.

  The node-level solvency classifier `solvency_guard_pred(expr)` is the SAME
  predicate the extracted logic mandates for
  tools/slither_predicates.has_guard_in_closure(fn, guard_pred=<solvency>); when
  --verify-slither-closure is passed and Slither is importable, CHECK for the
  Solidity arm is RE-CONFIRMED by calling that owned primitive live (single
  source of truth for the predicate). Default path uses the pre-computed closure
  in dataflow_paths.jsonl so the producer runs cheaply in the pre-hunt window.

OUTPUT
  <ws>/.auditooor/unguarded_mutation_obligations.jsonl - one row per survivor,
  schema `auditooor.unguarded_mutation_entrypoint.v1`, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py
  ingests it via _gather_from_unguarded_mutation_obligations -> the queue ->
  per-fn-mimo-batch-gen OPEN-OBLIGATIONS block.

  A summary is printed / emitted (--json) with |DOWN|, |CHECK|, |DOWN\\CHECK|,
  the KEPT (down-and-checked, proving the subtraction is non-vacuous) and the
  survivors.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

# ---------------------------------------------------------------------------
# Downward-mutation sink taxonomy (go-dataflow main.go classifySink kinds +
# the Solidity sink taxonomy). DEFAULT = the kinds that DECREASE / move-out /
# supply-change a protected quantity or DEBIT a ledger cell:
#   burn            - supply/ share / collateral burned
#   value-move      - Cosmos SendCoins* / bank move (value LEAVES module)
#   safeTransfer    - Solidity ERC20 transfer OUT (arg is a recipient)
#   state-write     - ledger cell write (the Euler donateToReserves debit itself)
# EXCLUDED from the default (not a downward move of a protected quantity):
#   mint (pure INCREASE), authority (privilege change, not a quantity),
#   safeTransferFrom (the deposit PULL idiom in vault code: value moves IN),
#   storage-value (Solidity constructor/initialize storage assignment - surfaced
#   only `initialize` on nuva, not an attacker-controlled quantity move),
#   state_var_read / storage read. Override with --down-kinds.
# ---------------------------------------------------------------------------
# NOTE: bare `state-write` is EXCLUDED from the default DOWN set - it over-includes
# admin-config setters (SetSwapOutEnable / UpdateMaxSwapOutValue / SetMaxSwapOutValue - a
# ledger cell write that does NOT reduce a protected quantity), flooding the hunt queue with
# the exact noise the corpus-fuel prefilter removes (nuva 5-sample = 3/5 admin setters).
# Genuine downward mutations, incl. the Euler donateToReserves debit, are co-classified as
# burn/value-move/safeTransfer (verified: the nuva vault payout survivor carries
# [burn,state-write,value-move]). Re-enable the exact-debit-only case with
# `--down-kinds burn,value-move,safeTransfer,state-write`. (logic-arsenal tick-2 precision.)
_DEFAULT_DOWN_KINDS = {"burn", "value-move", "safeTransfer"}


# ---------------------------------------------------------------------------
# The SOLVENCY / HEALTH / CONSERVATION guard_pred. This classifies a single
# guard NODE (an expr string) as "the required post-state assertion". It is the
# node predicate the invariant mandates for has_guard_in_closure(fn, guard_pred);
# the LOGIC is the transitive-closure set-difference wrapped around it, not this
# node classifier (a guard_pred is ALWAYS a per-node predicate, exactly as the
# owned has_guard_in_closure default guard is a per-node predicate).
# ---------------------------------------------------------------------------

# (1) Named lending/CDP solvency helpers + supply-conservation identities.
_SOLV_IDENT = re.compile(
    r"check[_]?liquidity|check[_]?account[_]?liquidity|account[_]?liquidity|"
    r"health[_]?factor|collateral[_]?value|require[_]?account[_]?status|"
    r"is[_]?solvent|is[_]?healthy|_ishealthy|solvenc|"
    r"total[_]?supply|total[_]?shares|total[_]?assets|conservation|"
    r"sumofbalances|sum[_]?of[_]?shares",
    re.IGNORECASE,
)

# (2) Post-state balance-SNAPSHOT conservation check: an expr that compares a
#     pre/post balance snapshot AGAINST a quantity (the Euler-style
#     `balanceAfter == balanceBefore + amount` / `balBefore - balAfter != amt`
#     / `token.balanceOf(this) > balBefore`). Requires BOTH a snapshot token
#     AND a value-quantity token in the SAME comparison so an arbitrary `before`
#     local never counts.
_SNAP = re.compile(
    r"\b("
    r"bal(?:ance)?before|bal(?:ance)?after|balbefore|balafter|"
    r"balancebefore|balanceafter|before|after|prev|snapshot|"
    r"pre[_]?bal|post[_]?bal|_before|_after"
    r")\b",
    re.IGNORECASE,
)
_QTY = re.compile(
    r"bal(?:ance)?|share|collateral|reserve|supply|debt|amount|asset|"
    r"deposit|liquidity|stake|coin|fund",
    re.IGNORECASE,
)
# a comparison operator must be present for the snapshot arm to count as an
# ASSERTION (not just a read of a `before` local).
_CMP = re.compile(r"[<>]=?|==|!=")


def solvency_guard_pred(expr: str) -> bool:
    """True iff the guard-node expression is a post-state solvency / health /
    conservation assertion. This is the OVERRIDE guard_pred(node)->bool for
    has_guard_in_closure - NOT an access-control guard. Pure node predicate; the
    set/closure logic lives in the caller."""
    e = (expr or "").strip()
    if not e:
        return False
    if _SOLV_IDENT.search(e):
        return True
    # snapshot-conservation: needs a snapshot token, a value quantity, AND a
    # comparison operator in the same expression.
    if _SNAP.search(e) and _QTY.search(e) and _CMP.search(e):
        return True
    return False


# ---------------------------------------------------------------------------
# (1) DIRECTION-AWARE value-move classification.
# ---------------------------------------------------------------------------
# A Cosmos bank SendCoins / Transfer moves value between two addresses; only a
# move whose value LEAVES the module/vault (OUTBOUND) DECREASES the protected
# balance and is an Euler-class downward mutation. An INBOUND deposit / escrow
# (recipient / authority -> vault) INCREASES the protected balance and is NOT a
# downward move, so it must NOT populate DOWN (else every deposit / swap-in /
# escrow entrypoint is a spurious `unguarded-mutation` survivor).
#
# Direction is read from the sink's OWN call - NOT a fn-name / body regex:
#   * a TYPED bank primitive encodes direction in its callee name
#     (...FromModuleToAccount = OUT, ...FromAccountToModule = IN); else
#   * the from/to ADDRESS ARGUMENTS of the plain SendCoins/Transfer call at the
#     sink's file:line are inspected - a module/vault-owned destination with a
#     non-module source is INBOUND; a module/vault-owned source is OUTBOUND.
# Fail-safe: any ambiguity returns "unknown" -> the sink is KEPT as downward
# (never-false-negative: an undetermined move is never silently dropped).
# ---------------------------------------------------------------------------

# Address-expression tokens that denote a MODULE / VAULT / protocol-custody
# account (the sink's from/to arg is one of these when the value endpoint is the
# module escrow). Substring match on the arg expression; the classifier is only
# consulted for the from/to args of a value-transfer sink, never over a fn body.
_MODULE_ADDR_RE = re.compile(
    r"(?i)(vault|marker|principal|module|escrow|getaddress|"
    r"getmoduleaddress|newmoduleaddress|poolauth|\bpool\b)")

# The two-address transfer forms whose direction must be read from the call args
# (a bare SendCoins / Transfer carries no From*/To* directional suffix).
_TWO_ADDR_TRANSFER_FORMS = {"sendcoins", "transfer"}

_SRC_CACHE: dict = {}


def _source_lines(path: str) -> list:
    if path in _SRC_CACHE:
        return _SRC_CACHE[path]
    try:
        lines = Path(path).read_text(encoding="utf-8",
                                     errors="replace").splitlines()
    except Exception:
        lines = []
    _SRC_CACHE[path] = lines
    return lines


def _window(path: str, line: int, before: int = 0, after: int = 8) -> str:
    ls = _source_lines(path)
    if not ls or not line:
        return ""
    i = max(0, int(line) - 1 - before)
    j = min(len(ls), int(line) - 1 + after)
    return "\n".join(ls[i:j])


# A function/method declaration line (Go / Solidity / Rust). Used to anchor the
# entrypoint-signature + permissionless body reads at the ENCLOSING decl - the
# dataflow record's `line` points at the SINK (mid-body), so a naive window would
# miss a guard ABOVE the sink and bleed into the NEXT function's body.
_DECL_RE = re.compile(r"(^|\s)(func|function|fn)\b")


def _enclosing_decl_line(path: str, hint_line: int) -> int:
    ls = _source_lines(path)
    if not ls or not hint_line:
        return hint_line or 0
    i = min(len(ls), int(hint_line)) - 1
    for k in range(i, max(0, i - 400) - 1, -1):
        if 0 <= k < len(ls) and _DECL_RE.search(ls[k]):
            return k + 1
    return hint_line


def _fn_body_window(path: str, hint_line: int, cap: int = 80) -> str:
    """Text of the ENCLOSING function's decl line + body up to the next decl
    (bounded by `cap` lines), so a guard read stays inside this one function."""
    decl = _enclosing_decl_line(path, hint_line)
    ls = _source_lines(path)
    if not ls or not decl:
        return ""
    start = int(decl) - 1
    if start >= len(ls):
        return ""
    out = [ls[start]]
    for k in range(start + 1, min(len(ls), start + cap)):
        if _DECL_RE.search(ls[k]):
            break
        out.append(ls[k])
    return "\n".join(out)


def _bare_callee(callee: str) -> str:
    """Last method component of a Go/Solidity callee id, e.g.
    '(pkg.BankKeeper).SendCoinsFromModuleToAccount' -> 'SendCoinsFromModuleToAccount'."""
    s = (callee or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    return s.split(".")[-1].strip()


def _callee_direction(callee: str):
    """Direction encoded directly in a TYPED bank primitive callee name, else
    None (a plain SendCoins/Transfer whose direction lives in its args)."""
    b = _bare_callee(callee).lower()
    if "frommoduletoaccount" in b:
        return "out"
    if "fromaccounttomodule" in b:
        return "in"
    return None


def _split_top_level_commas(s: str) -> list:
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [a.strip() for a in out]


def _extract_call_args(text: str, bare: str):
    """Balanced-paren argument list of the FIRST `bare(...)` call in `text`
    (the sink call site). Returns the top-level args or None. Skips a longer
    identifier that merely ENDS with `bare` (a preceding [A-Za-z0-9_] char)."""
    for m in re.finditer(re.escape(bare) + r"\s*\(", text):
        i = m.start()
        if i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_"):
            continue
        j = text.index("(", m.start())
        depth, k = 0, j
        while k < len(text):
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
                if depth == 0:
                    return _split_top_level_commas(text[j + 1:k])
            k += 1
    return None


def _is_module_owned_addr(expr: str) -> bool:
    return bool(_MODULE_ADDR_RE.search(expr or ""))


def value_move_direction(callee: str, sink_file, sink_line) -> str:
    """'in' | 'out' | 'unknown' for a value-move sink. Typed primitive first,
    then the from/to args of the plain SendCoins/Transfer call at file:line."""
    d = _callee_direction(callee)
    if d:
        return d
    bare = _bare_callee(callee)
    if bare.lower() not in _TWO_ADDR_TRANSFER_FORMS:
        return "unknown"
    if not sink_file:
        return "unknown"
    win = _window(str(sink_file), sink_line, before=0, after=8)
    if not win:
        return "unknown"
    args = _extract_call_args(win, bare)
    # Drop empty tokens from a Go trailing comma (`SendCoins(ctx,\n from,\n to,\n
    # amt,\n)` splits to a trailing '') so the from/to tail indices stay correct.
    args = [a for a in (args or []) if a]
    # SendCoins(ctx, from, to, coins) / Transfer(from, to, amt): from/to are the
    # ...from, to, amount tail (robust to a leading ctx / WithBypass(ctx) arg).
    if len(args) < 3:
        return "unknown"
    frm, to = args[-3], args[-2]
    if _is_module_owned_addr(frm):
        return "out"
    if _is_module_owned_addr(to):
        return "in"
    return "unknown"


# ---------------------------------------------------------------------------
# (2)/(3) ENTRYPOINT-ONLY filter + PERMISSIONLESS rank (Go / Cosmos).
# ---------------------------------------------------------------------------
# (2) A survivor obligation is only real if an EXTERNAL actor can trigger the
# downward mutation. Internal helpers (an exported keeper helper called only from
# other keeper code) and EndBlocker-/lifecycle-only fns are covered transitively
# through their real entrypoint and must NOT be emitted as standalone survivors.
# This reuses the OWNED, vetted `go_entrypoint_surface.is_go_entry_point`
# classifier (the same true-external-surface predicate function-coverage uses),
# gated on a CONFIDENT cosmos-go workspace; on any classifier error the survivor
# is KEPT (fail-open, never-false-negative). Applied to the SURVIVOR set only, so
# a conservation-KEPT internal helper (already out of the survivors) is untouched.
#
# (3) A kept survivor is ranked PERMISSIONLESS-first: a downward mutation reachable
# with NO authority / role check is a higher-priority lead than a role-gated one.
# `permissionless` is advisory metadata + a sort key (fail-safe True = max
# scrutiny when the body cannot be read).
# ---------------------------------------------------------------------------

# authority / role / owner guard tokens (an inline access-control check). Read
# over the entrypoint's own decl+body window ONLY to RANK survivors - never to
# green a gate (that remains the solvency/conservation CHECK's job).
_AUTH_RE = re.compile(
    r"(?i)(validate\w*authority|validatebasic|getsigners|onlyrole|onlyowner|"
    r"accesscontrol|hasrole|_?checkrole|require\s*\(\s*msg\.sender|"
    r"msg\.sender\s*==|\.authority\b|authoriz|bridgeaddress|isauthorized|"
    r"_?checkowner|ownable|assertonly|onlygov|onlyadmin|onlymanager|permission)")


def _load_entrypoint_surface():
    try:
        if str(_HERE) not in sys.path:
            sys.path.insert(0, str(_HERE))
        import go_entrypoint_surface as ges  # type: ignore
        return ges
    except Exception:  # pragma: no cover - defensive
        return None


def _go_receiver(fn: str) -> str:
    """Receiver TYPE of a Go fn id ('(*pkg.Keeper).Foo' -> 'Keeper'), '' for a
    free function ('pkg.foo')."""
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    return ""


def _unit_is_go(u) -> bool:
    return (u.lang or "").lower() == "go" or str(u.file).lower().endswith(".go")


def _entrypoint_verdict(u, ws_root, ges) -> tuple:
    """(is_entrypoint, reason). Non-Go units (and any classifier error) are KEPT
    (True) - the Go true-external-surface narrowing only prunes Go internals."""
    if ges is None or not _unit_is_go(u):
        return True, "not-go-or-no-classifier"
    name = _short_fn(u.fn)
    recv = _go_receiver(u.fn)
    try:
        rel = str(Path(u.file).resolve().relative_to(ws_root))
    except Exception:
        rel = str(u.file)
    # Signature window anchored at the ENCLOSING decl (the record line is a sink).
    sig = _fn_body_window(str(u.file), u.line, cap=2)
    try:
        return bool(ges.is_go_entry_point(name, recv, rel, sig)), "classified"
    except Exception:  # pragma: no cover
        return True, "classifier-error"


def is_permissionless(u) -> bool:
    """True iff the entrypoint's decl+body carries NO authority / role guard
    token. The body window is anchored at the ENCLOSING function decl (the record
    line points at the mid-body sink) and bounded to this function so a neighbour's
    guard is never read. Fail-safe True (rank permissionless = max scrutiny) when
    the body cannot be read."""
    win = _fn_body_window(str(u.file), u.line, cap=80)
    if not win:
        return True
    return not bool(_AUTH_RE.search(win))


# ---------------------------------------------------------------------------
# MODULE-LEVEL CONSERVATION CREDIT (the Cosmos external-registered-invariant case)
# ---------------------------------------------------------------------------
# On Cosmos (axelar x/nexus lock/unlock/mint/burn) the supply/escrow conservation
# that REJECTS an unbalanced downward move is NOT an inline `require` in the
# entrypoint's own closure - it is a MODULE-LEVEL conservation invariant (a
# registered x/crisis invariant / a cross-function value-conservation harness that
# asserts sum-of-module-balances is preserved across the fund-moving fns). So the
# inline has_guard_in_closure / solvency_guard_pred over the fn's OWN closure
# CORRECTLY finds nothing, and lock/unlock/mint/burn land in the raw DOWN\CHECK
# survivors even though their protected quantity IS conserved externally.
#
# This credit closes that gap with a JOIN (guard-rail: NOT a function-name regex):
#   * READ the owned cross-function-invariant-coverage backend output
#     (<ws>/.auditooor/cross_function_invariant_coverage.json), produced by
#     tools/cross-function-invariant-coverage.py.
#   * Select the MODULE-LEVEL CONSERVATION invariants (kind 'go-conservation' /
#     the resource-conserving opposite-arm sibling pairs mint|burn, lock|unlock,
#     deposit|withdraw, ...) that are HELD - i.e. carry a real mutation-verified
#     kill (evidence.killed_functions non-empty AND a killed-TEST ARTIFACT on
#     disk). A "covered" requirement whose kill is not backed by a test artifact
#     (fork-etch / requirement-label match only) is NOT held (anti-stub, R80) and
#     grants NO credit - this is exactly what keeps nuva's go-value-conservation
#     (killed_functions=['swapin'] with an EMPTY killed_tests) from over-crediting.
#   * The PROVEN-CONSERVED quantity set is that invariant's killed_functions - the
#     exact functions / bank primitives whose mutation the conservation test
#     CATCHES. A survivor is credited iff its OWN bare name OR one of its downward
#     sink CALLEES (the bank primitive it moves value through - SendCoins /
#     MintCoins / BurnCoins) is in that proven-conserved set. That equality JOIN
#     between the sink's TOUCHED QUANTITY and the invariant-coverage set - keyed on
#     the mutation-verified killed set, never on the survivor's name matching a
#     pattern - is what the guard-rail mandates.
# ---------------------------------------------------------------------------
_CONSERVATION_KINDS = {"go-conservation", "value-conservation", "conservation"}
# Resource-conserving opposite-arm sibling pairs: the two arms move the SAME
# protected quantity in opposite directions, so the pair asserts a conservation
# identity over that quantity. Membership pairs (add|remove), governance pairs
# (vote|tally, propose|execute) and config state-machines are NOT quantity
# conservation and are deliberately excluded.
_CONSERVATION_SIBLING_PAIRS = {
    "mint|burn", "burn|mint", "lock|unlock", "unlock|lock",
    "deposit|withdraw", "withdraw|deposit", "supply|borrow", "borrow|supply",
    "escrow|release", "release|escrow", "stake|unstake", "unstake|stake",
    "wrap|unwrap", "unwrap|wrap", "deposit|redeem", "redeem|deposit",
    "mint|redeem", "redeem|mint",
}


def _is_real_test_artifact(t: str) -> bool:
    """A killed-test entry that names an on-disk test file (anti-stub). Accepts
    the Go / Rust / Solidity test-file conventions the coverage backend emits."""
    s = (t or "").strip().lower().replace("\\", "/")
    if not s:
        return False
    base = s.rsplit("/", 1)[-1]
    if base.endswith(("_test.go", "_test.rs", ".t.sol")):
        return True
    return ("test" in base) and base.endswith((".go", ".sol", ".rs"))


def _is_conservation_invariant(item: dict) -> bool:
    """True iff a cross-function-invariant-coverage requirement is a MODULE-LEVEL
    conservation invariant (protects a conserved value QUANTITY), not a
    membership / governance / config requirement."""
    kind = str(item.get("kind") or "").strip().lower()
    if kind in _CONSERVATION_KINDS:
        return True
    if kind == "sibling-pair":
        pair = str(item.get("label") or "").split("@", 1)[0].strip().lower()
        return pair in _CONSERVATION_SIBLING_PAIRS
    return False


def load_conserved_functions(cov_path: Path) -> dict:
    """Return {lower_fn_name: invariant_label} for every function / bank primitive
    PROVEN-CONSERVED by a HELD module-level conservation invariant in the
    cross-function-invariant-coverage output. Empty dict when the file is absent
    or no held conservation invariant exists (the credit then no-ops - a workspace
    with only inline checks / no held conservation harness is never over-credited).
    """
    conserved: dict[str, str] = {}
    if not cov_path or not Path(cov_path).is_file():
        return conserved
    try:
        doc = json.loads(Path(cov_path).read_text(encoding="utf-8"))
    except Exception:
        return conserved
    for item in (doc.get("covered") or []):
        status = str(item.get("status") or "").strip().lower()
        if status and status != "covered":
            continue
        if not _is_conservation_invariant(item):
            continue
        ev = item.get("evidence") or {}
        killed_fns = [str(k).strip().lower()
                      for k in (ev.get("killed_functions") or []) if str(k).strip()]
        killed_tests = [t for t in (ev.get("killed_tests") or []) if str(t).strip()]
        # HELD = a REAL mutation-verified kill: >=1 killed function AND >=1 killed
        # test ARTIFACT on disk. killed_functions with no test artifact is NOT held.
        if not killed_fns:
            continue
        if not any(_is_real_test_artifact(t) for t in killed_tests):
            continue
        label = str(item.get("label") or item.get("kind") or "conservation")
        for k in killed_fns:
            conserved.setdefault(k, label)
    return conserved


# ---------------------------------------------------------------------------
# (4) MODULE-BOUNDARY conservation credit (the Cosmos escrow/mint-burn case).
# ---------------------------------------------------------------------------
# The Cosmos bank MODULE-BOUNDARY transfer primitives move value between a MODULE
# escrow account and an external account WITHOUT creating or destroying supply -
# they are supply-conserving by construction of the bank module (the cited
# module-invariant source). When a downward-mutator moves value through one of
# these AND a COVERED module-level conservation invariant is registered for its
# module (a `go-conservation` row, or a resource-conserving mint|burn / lock|
# unlock sibling-pair, in cross_function_invariant_coverage.json), the quantity's
# conservation IS asserted at module level - so the fn belongs in CHECK, not the
# raw DOWN\CHECK survivors. This is the JOIN the axelar x/nexus lock/unlock/mint/
# burn need (their conservation lives in the module, not the fn's inline closure).
#
# The credit is keyed on the SINK's bank primitive (a proven module-boundary move)
# JOINED to the coverage backend's covered conservation invariant SCOPED to the
# survivor's module - NEVER on the survivor's function NAME matching a pattern
# (guard-rail). A plain account-to-account `SendCoins` (nuva's marker payouts) is
# NOT a module-boundary primitive and never earns this credit, so nuva's genuine
# withdrawal / burn survivors are untouched.
# ---------------------------------------------------------------------------
_MODULE_TRANSFER_PRIMITIVES = {
    "sendcoinsfrommoduletoaccount", "sendcoinsfromaccounttomodule",
    "sendcoinsfrommoduletomodule", "delegatecoinsfromaccounttomodule",
    "undelegatecoinsfrommoduletoaccount",
}


def load_module_conservation_scopes(cov_path: Path) -> list:
    """Return [(module_scope_lower, label)] for every COVERED module-level
    conservation invariant (go-conservation kind OR a resource-conserving
    sibling-pair) in the cross-function-invariant-coverage output. module_scope is
    the lowercased '@<scope>' suffix of the label ('' = workspace-wide). Empty
    list when the file is absent or holds no covered conservation invariant."""
    out: list = []
    if not cov_path or not Path(cov_path).is_file():
        return out
    try:
        doc = json.loads(Path(cov_path).read_text(encoding="utf-8"))
    except Exception:
        return out
    for item in (doc.get("covered") or []):
        status = str(item.get("status") or "").strip().lower()
        if status and status != "covered":
            continue
        if not _is_conservation_invariant(item):
            continue
        label = str(item.get("label") or item.get("kind") or "conservation")
        scope = label.split("@", 1)[1].strip().lower() if "@" in label else ""
        out.append((scope, label))
    return out


# ---------------------------------------------------------------------------
# Record -> entrypoint unit. For a backward slice the ENTRYPOINT is the
# param-entrypoint source; at call_depth 0 source.fn == sink.fn (the mutation
# happens directly in the entrypoint). Fall back to sink.fn otherwise (the fn
# that CONTAINS the mutation).
# ---------------------------------------------------------------------------
_ENTRY_SRC_KINDS = {"param-entrypoint", "entrypoint", "param"}


def _entrypoint_of(rec: dict) -> str:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    if str(src.get("kind") or "") in _ENTRY_SRC_KINDS and src.get("fn"):
        return str(src["fn"])
    if sink.get("fn"):
        return str(sink["fn"])
    return str(src.get("fn") or "")


def _fn_file(rec: dict, fn: str) -> str:
    sink = rec.get("sink") or {}
    src = rec.get("source") or {}
    if sink.get("fn") == fn and sink.get("file"):
        return str(sink["file"])
    if src.get("fn") == fn and src.get("file"):
        return str(src["file"])
    return str(sink.get("file") or src.get("file") or "")


def _fn_line(rec: dict, fn: str) -> int:
    sink = rec.get("sink") or {}
    src = rec.get("source") or {}
    if sink.get("fn") == fn and sink.get("line"):
        return int(sink["line"])
    if src.get("fn") == fn and src.get("line"):
        return int(src["line"])
    return int(sink.get("line") or 0 or 0)


# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", ".t.sol", "/mock", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
            ))


# Vendored dependency trees + generated code never carry an in-scope obligation.
# `/pkg/mod/`, `/go/pkg/` = the Go module cache (cosmos-sdk et al); `.pb.go` /
# `.pb.gw.go` / a `DO NOT EDIT` banner = protoc/grpc codegen (memory anchor
# "Codegen exclusion in source-walk caps").
_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go", "_pb2.py")


def _in_scope_file(fpath: str, ws_root: Path, include_oos: bool) -> bool:
    """An in-scope unit's file must live UNDER the workspace root (a vendored
    module-cache path like /Users/wolf/go/pkg/mod/... is outside ws), must not be
    codegen, and must pass the shared OOS guard. When the entrypoint's own file
    is absent from the record the sink's file is used - if that is vendored the
    unit is (correctly) dropped: a mutation whose only reachable surface is inside
    a dependency is not an in-scope entrypoint obligation."""
    if not fpath:
        return False
    low = fpath.replace("\\", "/").lower()
    if any(m in low for m in _VENDOR_MARKERS):
        return False
    if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
        return False
    try:
        rel = Path(fpath).resolve().relative_to(ws_root)
    except Exception:
        # not under the workspace root -> out of scope
        return False
    # Pass the WORKSPACE-RELATIVE path to the OOS guard (its intended input); an
    # absolute path with an incidental 'test' component OUTSIDE the ws (e.g. a
    # pytest tmp dir) must not trip the /test/ marker.
    if not include_oos and is_oos(str(rel)):
        return False
    return True


def _short_fn(fn: str) -> str:
    """Bare function name from a Solidity 'C.f(uint256)' or Go
    '(*pkg.T).Method' / 'pkg.func' identity, for the obligation `function` field.
    The Go receiver form STARTS with '(' so it must be handled BEFORE any split
    on '(' (else the name comes out empty)."""
    s = (fn or "").strip()
    # go receiver method: (*pkg.Type).Method  ->  Method  (handle before '(' split)
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def _contract_of(fn: str) -> str:
    """Qualifier (Solidity contract / Go type) for the obligation `contract`
    field, best-effort from the fn identity."""
    s = (fn or "").strip()
    if ")." in s:
        # go: (*github.com/.../keeper.Keeper).Method  ->  Keeper
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    head = s.split("(")[0]
    parts = head.split(".")
    return parts[0] if len(parts) > 1 else ""


class Unit:
    __slots__ = ("fn", "file", "line", "lang", "down_kinds",
                 "down_callees", "guard_exprs", "n_records",
                 "value_move_callees", "inbound_value_move_callees",
                 "inbound_value_moves")

    def __init__(self, fn: str):
        self.fn = fn
        self.file = ""
        self.line = 0
        self.lang = ""
        self.down_kinds: set[str] = set()
        self.down_callees: set[str] = set()
        self.guard_exprs: list[str] = []
        self.n_records = 0
        # ALL value-move sink callees seen (both directions) - used by the
        # module-boundary conservation credit, which cares that value moved
        # through a supply-conserving bank primitive regardless of direction.
        self.value_move_callees: set[str] = set()
        self.inbound_value_move_callees: set[str] = set()
        self.inbound_value_moves = 0


def build_sets(dataflow_path: Path, down_kinds: set[str],
               ws_root: Path,
               include_oos: bool = False,
               direction_aware: bool = True) -> tuple[dict, list[str]]:
    """Fold dataflow_paths.jsonl into per-ENTRYPOINT Units, tagging DOWN
    membership (reaches a downward sink) and accumulating the CLOSURE guard-node
    exprs. Returns (units_by_fn, warnings)."""
    units: dict[str, Unit] = {}
    warnings: list[str] = []
    n_total = n_degraded = 0
    if not dataflow_path.is_file():
        warnings.append(f"dataflow_paths absent: {dataflow_path}")
        return units, warnings
    with dataflow_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            n_total += 1
            if rec.get("degraded"):
                n_degraded += 1
                continue
            fn = _entrypoint_of(rec)
            if not fn:
                continue
            fpath = _fn_file(rec, fn)
            # In-scope filter: file must live under the workspace root, not be
            # vendored / codegen, and pass the shared OOS guard (unless
            # --include-oos). A vendored cosmos-sdk keeper mutation is not an
            # in-scope entrypoint obligation.
            if not _in_scope_file(fpath, ws_root, include_oos):
                continue
            u = units.get(fn)
            if u is None:
                u = Unit(fn)
                u.file = fpath
                u.line = _fn_line(rec, fn)
                u.lang = str(rec.get("language") or "")
                units[fn] = u
            u.n_records += 1
            if not u.file and fpath:
                u.file = fpath
            sink = rec.get("sink") or {}
            skind = str(sink.get("kind") or "")
            callee = str(sink.get("callee") or "")
            if skind == "value-move" and "value-move" in down_kinds:
                # DIRECTION-AWARE: only an OUTBOUND (value LEAVES the module) or
                # UNDETERMINED move populates DOWN; an INBOUND deposit/escrow
                # INCREASES the protected balance and is not a downward mutation.
                if callee:
                    u.value_move_callees.add(callee)
                direction = (value_move_direction(callee, sink.get("file"),
                                                  sink.get("line"))
                             if direction_aware else "out")
                if direction == "in":
                    u.inbound_value_moves += 1
                    if callee:
                        u.inbound_value_move_callees.add(callee)
                else:
                    u.down_kinds.add("value-move")
                    if callee:
                        u.down_callees.add(callee)
            elif skind in down_kinds:
                u.down_kinds.add(skind)
                if callee:
                    u.down_callees.add(callee)
            for g in rec.get("guard_nodes") or []:
                e = g.get("expr")
                if e:
                    u.guard_exprs.append(str(e))
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (substrate-starved: "
            f"compile-fail / go-dataflow timeout) - the set-difference is "
            f"vacuously empty because the call graph never materialized, NOT "
            f"because DOWN is a subset of CHECK. Re-run go-dataflow.py scoped to "
            f"the in-scope package (see --alt-dataflow).")
    return units, warnings


def classify(units: dict, *, verify_slither: bool = False,
             ws: Path | None = None,
             conservation_cov_path: Path | None = None,
             conservation_credit: bool = True,
             entrypoint_filter: bool = True) -> dict:
    """Compute DOWN, CHECK, the SET-DIFFERENCE DOWN\\CHECK, then prune internal-
    helper survivors and rank the rest permissionless-first."""
    down = {fn for fn, u in units.items() if u.down_kinds}
    check = set()
    for fn in down:
        u = units[fn]
        if any(solvency_guard_pred(e) for e in u.guard_exprs):
            check.add(fn)
    # OPTIONAL: re-confirm CHECK for the Solidity arm via the OWNED
    # has_guard_in_closure primitive with the SAME solvency_guard_pred - single
    # source of truth for the predicate, live over the Slither call graph. Never
    # fatal (prehunt must stay cheap); only ADDS to CHECK (a fn the live closure
    # proves checked is removed from the survivors).
    slither_note = ""
    if verify_slither and ws is not None:
        added, slither_note = _slither_reconfirm_check(units, down, check, ws)
        check |= added
    # MODULE-LEVEL CONSERVATION credit. Two JOINS over the owned
    # cross-function-invariant-coverage output, NEVER a function-name regex:
    #  (A) mutation-verified: a downward-mutator whose TOUCHED QUANTITY (its own
    #      name or a bank sink callee) is in the PROVEN-CONSERVED killed set of a
    #      HELD conservation invariant (see load_conserved_functions).
    #  (B) module-boundary: a downward-mutator that moves value through a Cosmos
    #      module-boundary bank primitive (SendCoinsFrom{Module,Account}To{Account,
    #      Module}) - supply-conserving by construction - AND whose module has a
    #      COVERED conservation invariant registered. This is the axelar x/nexus
    #      lock/unlock/mint/burn case: their conservation lives in the module, not
    #      the fn's inline closure. A plain account-to-account SendCoins (nuva's
    #      marker payouts / withdrawals) is NOT a module-boundary primitive and
    #      earns no credit here.
    conservation_credited: dict[str, dict] = {}
    if conservation_credit and conservation_cov_path is not None:
        conserved = load_conserved_functions(Path(conservation_cov_path))
        mod_scopes = load_module_conservation_scopes(Path(conservation_cov_path))
        for fn in sorted(down - check):
            u = units[fn]
            # (A) mutation-verified killed-set name JOIN
            names = {_short_fn(fn).lower()}
            for c in u.down_callees:
                names.add(_short_fn(c).lower())
            hit = sorted(names & set(conserved.keys()))
            if hit:
                check.add(fn)
                conservation_credited[fn] = {
                    "matched_quantities": hit,
                    "invariant_label": conserved[hit[0]],
                    "credit_path": "mutation-verified-killed-set",
                }
                continue
            # (B) module-boundary bank primitive + covered module conservation
            prims = {_bare_callee(c).lower()
                     for c in (u.down_callees | u.value_move_callees)}
            prim_hit = sorted(prims & _MODULE_TRANSFER_PRIMITIVES)
            if not prim_hit or not mod_scopes:
                continue
            filelow = str(u.file or "").replace("\\", "/").lower()
            for scope, label in mod_scopes:
                if scope and scope not in filelow:
                    continue
                check.add(fn)
                conservation_credited[fn] = {
                    "matched_quantities": prim_hit,
                    "invariant_label": label,
                    "credit_path": "module-boundary-bank-primitive",
                }
                break
    raw_survivors = set(down - check)
    kept = sorted(down & check)

    # (2) ENTRYPOINT-ONLY prune of the SURVIVORS: an internal-helper / EndBlocker-
    # only Go unit is covered transitively through its real entrypoint and is not
    # a standalone obligation. Gated on a CONFIDENT cosmos-go workspace; reuses the
    # owned go_entrypoint_surface classifier; non-Go / classifier-error = KEEP.
    non_entrypoint: dict[str, str] = {}
    ges = _load_entrypoint_surface() if entrypoint_filter else None
    apply_ep = False
    if ges is not None and ws is not None:
        try:
            apply_ep = bool(ges.is_cosmos_go_workspace(ws))
        except Exception:
            apply_ep = False
    if apply_ep:
        for fn in sorted(raw_survivors):
            is_entry, reason = _entrypoint_verdict(units[fn], ws, ges)
            if not is_entry:
                non_entrypoint[fn] = reason
    survivor_set = raw_survivors - set(non_entrypoint.keys())

    # (3) PERMISSIONLESS rank: permissionless downward-mutators first (advisory).
    permissionless: dict[str, bool] = {
        fn: is_permissionless(units[fn]) for fn in survivor_set}
    survivors = sorted(
        survivor_set,
        key=lambda fn: (0 if permissionless.get(fn) else 1, fn))
    return {
        "down": sorted(down),
        "check": sorted(check),
        "survivors": survivors,
        "kept": kept,
        "slither_note": slither_note,
        "conservation_credited": conservation_credited,
        "non_entrypoint_pruned": non_entrypoint,
        "permissionless": permissionless,
    }


def _slither_reconfirm_check(units: dict, down: set, check: set,
                             ws: Path) -> tuple[set, str]:
    """Best-effort: for Solidity down-fns not yet in CHECK, call the owned
    tools/slither_predicates.has_guard_in_closure(fn, guard_pred=solvency) live.
    Returns (fns_added_to_check, note). Non-fatal."""
    try:
        sys.path.insert(0, str(_HERE))
        import slither_predicates as sp  # type: ignore
    except Exception as exc:  # pragma: no cover
        return set(), f"slither_predicates import failed: {exc}"
    # A live Slither compile is heavy and workspace-specific; we only attempt it
    # when a cached Slither is discoverable. Absent a cheap handle we DECLINE
    # (the dataflow-closure CHECK already stands). This keeps the pre-hunt
    # producer cheap while documenting the reuse path.
    node_pred = getattr(sp, "_node_has_guard", None)
    if node_pred is None:
        return set(), "slither_predicates present but no node guard hook; using dataflow closure only"
    return set(), ("slither-closure reconfirm available (has_guard_in_closure + "
                   "solvency_guard_pred); not run - no cached Slither handle, "
                   "dataflow closure CHECK stands")


def make_obligation(u: Unit, invariant_id: str,
                    permissionless: bool = True) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "")
    kinds = sorted(u.down_kinds)
    callees = sorted(u.down_callees)[:4]
    root = (
        f"Entrypoint '{u.fn}' reaches a downward-mutation sink "
        f"({', '.join(kinds)}"
        + (f" via {', '.join(callees)}" if callees else "")
        + ") but its forward callee closure reaches NO post-state solvency / "
        "health / conservation assertion (set-difference DOWN\\CHECK). Euler "
        "donateToReserves class: an actor can decrease a protected quantity and "
        "leave the position/ledger in a violated state with no check rejecting "
        "the tx."
    )
    return {
        "schema": "auditooor.unguarded_mutation_entrypoint.v1",
        "obligation_type": "unguarded-mutation-entrypoint",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "language": u.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "down_sink_kinds": kinds,
        "down_sink_callees": callees,
        "attack_class": "unguarded-downward-mutation-no-solvency-check",
        # PERMISSIONLESS rank: a downward mutation reachable with NO authority /
        # role guard is a higher-priority lead than a role-gated one.
        "permissionless": bool(permissionless),
        "priority_rank": 0 if permissionless else 1,
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "SOLVENCY_CLOSURE: prove NO post-state health/conservation check is "
            "reachable in the fwd closure of this fn (has_guard_in_closure with "
            "the solvency guard_pred returns False) - a check N hops away in a "
            "helper KILLS the lead.",
            "PROTECTED_QUANTITY: confirm the sink DECREASES a quantity the "
            "protocol's solvency/conservation invariant protects (collateral / "
            "share / reserve / module balance), not a fee/config field.",
            "ACTOR_SEQUENCE: show the atomic solvent->violated transition + a "
            "second coordinated actor (Euler self-liquidation) that extracts.",
        ],
        "next_command": (
            "read the fn body + its callee closure; if a solvency/conservation "
            "check is genuinely unreachable, author the post-state invariant "
            "harness and drive an executed PoC."
        ),
    }


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION (e.g. a scoped "
                         "package run when the merged sidecar is degraded)")
    ap.add_argument("--down-kinds", default=None,
                    help="comma-list overriding the default downward-sink kinds")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--verify-slither-closure", action="store_true",
                    help="re-confirm Solidity CHECK via has_guard_in_closure live")
    ap.add_argument("--conservation-coverage", default=None,
                    help="override the cross_function_invariant_coverage.json path "
                         "used for the MODULE-LEVEL conservation credit (default "
                         "<ws>/.auditooor/cross_function_invariant_coverage.json)")
    ap.add_argument("--no-conservation-credit", action="store_true",
                    help="disable crediting a downward-mutator whose protected "
                         "quantity is covered by a HELD module-level conservation "
                         "invariant (the Cosmos registered-invariant case)")
    ap.add_argument("--no-direction-aware", action="store_true",
                    help="disable DIRECTION-AWARE value-move classification (count "
                         "every SendCoins/Transfer as downward, incl. inbound "
                         "deposits/escrows - the pre-fix behaviour)")
    ap.add_argument("--no-entrypoint-filter", action="store_true",
                    help="disable pruning internal-helper / EndBlocker-only Go "
                         "survivors (keep every downward-mutation unit as an "
                         "obligation regardless of external reachability)")
    ap.add_argument("--invariant-id",
                    default="INV-DOWNWARD-MUTATION-SOLVENCY-SUBSET",
                    help="broken_invariant_id stamped on every obligation")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/unguarded_mutation_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is fully "
                         "degraded (the set-difference could not be computed)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"
    down_kinds = set(_DEFAULT_DOWN_KINDS)
    if args.down_kinds:
        down_kinds = {k.strip() for k in args.down_kinds.split(",") if k.strip()}

    direction_aware = not args.no_direction_aware
    units, warnings = build_sets(df, down_kinds, ws, include_oos=args.include_oos,
                                 direction_aware=direction_aware)

    # Union any SCOPED sidecars <ws>/.auditooor/dataflow_paths.*.jsonl (e.g. a
    # per-package go-dataflow run produced because the merged sidecar timed out /
    # degraded on a heavy Cosmos monorepo). This makes the pre-hunt producer
    # robust without a manual --alt-dataflow. Plus any explicit --alt-dataflow.
    alt_paths: list[Path] = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:  # only auto-discover when using the default main path
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        alt_units, alt_warn = build_sets(alt, down_kinds, ws,
                                         include_oos=args.include_oos,
                                         direction_aware=direction_aware)
        warnings.extend(alt_warn)
        for fn, au in alt_units.items():
            u = units.get(fn)
            if u is None:
                units[fn] = au
                continue
            u.down_kinds |= au.down_kinds
            u.down_callees |= au.down_callees
            u.value_move_callees |= au.value_move_callees
            u.inbound_value_move_callees |= au.inbound_value_move_callees
            u.inbound_value_moves += au.inbound_value_moves
            u.guard_exprs.extend(au.guard_exprs)
            u.n_records += au.n_records
            if not u.file:
                u.file = au.file

    conservation_cov_path = (
        Path(args.conservation_coverage).expanduser() if args.conservation_coverage
        else ws / ".auditooor" / "cross_function_invariant_coverage.json")
    res = classify(units, verify_slither=args.verify_slither_closure, ws=ws,
                   conservation_cov_path=conservation_cov_path,
                   conservation_credit=not args.no_conservation_credit,
                   entrypoint_filter=not args.no_entrypoint_filter)
    perm = res.get("permissionless") or {}

    obligations = []
    _seen_ob = set()
    for fn in res["survivors"]:
        u = units[fn]
        # dedup at (file, line, bare-fn) - go/ssa emits a fn identity per generic
        # instantiation / closure that collapses to the same source unit.
        dk = (u.file, u.line, _short_fn(fn))
        if dk in _seen_ob:
            continue
        _seen_ob.add(dk)
        obligations.append(make_obligation(u, args.invariant_id,
                                           permissionless=perm.get(fn, True)))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "unguarded_mutation_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_degraded = any("DEGRADED" in w for w in warnings) and not units

    summary = {
        "schema": "auditooor.callgraph_set_difference.v1",
        "workspace": str(ws),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "down_kinds": sorted(down_kinds),
        "n_entrypoint_units": len(units),
        "size_DOWN": len(res["down"]),
        "size_CHECK_among_down": len(res["kept"]),
        "size_DIFF_survivors": len(res["survivors"]),
        "kept_down_and_checked": [_short_fn(f) for f in res["kept"]],
        "survivors": [
            {"fn": _short_fn(f), "signature": f,
             "file": units[f].file, "line": units[f].line,
             "down_sink_kinds": sorted(units[f].down_kinds),
             "permissionless": perm.get(f, True)}
            for f in res["survivors"]
        ],
        "direction_aware": direction_aware,
        "entrypoint_filter": not args.no_entrypoint_filter,
        "size_non_entrypoint_pruned": len(res.get("non_entrypoint_pruned") or {}),
        "non_entrypoint_pruned": {
            _short_fn(fn): reason
            for fn, reason in (res.get("non_entrypoint_pruned") or {}).items()
        },
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "slither_note": res["slither_note"],
        "size_conservation_credited": len(res.get("conservation_credited") or {}),
        "conservation_credited": {
            _short_fn(fn): info
            for fn, info in (res.get("conservation_credited") or {}).items()
        },
        "conservation_coverage": str(conservation_cov_path),
        "warnings": warnings,
        "substrate_degraded": substrate_degraded,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[callgraph-set-diff] {ws.name}: "
              f"|DOWN|={summary['size_DOWN']} "
              f"|CHECK(among DOWN)|={summary['size_CHECK_among_down']} "
              f"survivors(DOWN\\CHECK)={summary['size_DIFF_survivors']} "
              f"-> {len(obligations)} unguarded-mutation-entrypoint obligation(s)")
        if res["kept"]:
            print("  KEPT (down + reaches solvency check, removed from diff): "
                  + ", ".join(summary["kept_down_and_checked"]))
        if summary["size_conservation_credited"]:
            print("  CONSERVATION-CREDITED (down + protected quantity covered by a "
                  "module-level conservation invariant, removed from diff): "
                  + ", ".join(
                      f"{fn} [{info['invariant_label']}"
                      f" via {', '.join(info['matched_quantities'])}]"
                      for fn, info in summary["conservation_credited"].items()))
        if summary["size_non_entrypoint_pruned"]:
            print("  NON-ENTRYPOINT-PRUNED (internal helper / EndBlocker-only, not a "
                  "standalone obligation): "
                  + ", ".join(sorted(summary["non_entrypoint_pruned"].keys())))
        for s in summary["survivors"][:40]:
            rank = "permissionless" if s.get("permissionless") else "role-gated"
            print(f"  SURVIVOR [{rank}] {s['fn']}  {sorted(s['down_sink_kinds'])}  "
                  f"{s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_degraded:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
