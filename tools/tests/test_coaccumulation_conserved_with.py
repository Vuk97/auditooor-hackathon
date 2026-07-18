#!/usr/bin/env python3
"""Regression for the CO-ACCUMULATION Sigma-conservation tier of the State-Coupling
Graph (conserved-with subtype). In a SINGLE writer fn a mapping-indexed MEMBER cell and
an AGGREGATE cell accumulate the SAME delta with the SAME sign (the canonical DeFi
conservation sum(members) == aggregate, e.g. position[..].supplyShares += shares AND
market[..].totalSupplyShares += shares). The cross-fn conserved-with lane misses this
because VMF names the function-local delta, not the storage cells - so this tier reads
the cells straight from source. See tools/state-coupling-graph.py:_coaccumulation_edges.

Non-vacuous: mutating the pairing logic (drop the mapping-indexed member guard, drop the
aggregate strict-subset-key guard, or ignore the delta match) breaks a case here.
2026-07-10 (co-accumulation Sigma-conservation tier)."""
import importlib.util
import json
import os
import unittest
import tempfile
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


scg = _load("state_coupling_graph", "state-coupling-graph.py")
dfslice = _load("dataflow_slice_mod", "dataflow-slice.py")
scc = _load("state_coupling_completeness_check",
            "state-coupling-completeness-check.py")  # the GATE under test (v2 auto-close)
_df = scg._df  # dataflow_schema (path reader/writer used for the semantic-ssa overlay)


def _mk_ws(sol_src: str, rel: str = "src/T.sol") -> Path:
    """A minimal workspace: one in-scope Solidity file + inscope_units.jsonl. No dataflow
    slice, so co-accumulation edges resolve to the honest advisory 'syntactic' tier."""
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    fp = ws / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(sol_src, encoding="utf-8")
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        '{"file": "%s"}\n' % rel, encoding="utf-8")
    return ws


def _write_slice(ws: Path, hops):
    """Write a minimal dataflow_paths.jsonl of accum-delta hops so the co-accumulation
    overlay can join on the SAME base delta. `hops` = list of (base_delta, cell, fn) each
    becoming a distinct storage flow {from_var:base_delta, to_var:cell} in fn."""
    recs = []
    for i, (delta, cell, fn) in enumerate(hops):
        recs.append(_df.new_path(
            path_id="sda-%04d" % i, language="solidity", direction="forward",
            engine="slither.statevar-accum-delta",
            source={"kind": "delta_var", "fn": fn, "var": delta, "file": "x", "line": 1},
            sink={"kind": "state_var_accum", "callee": cell, "arg_pos": None, "fn": fn,
                  "file": "x", "line": 1},
            hops=[{"from_var": delta, "to_var": cell, "fn": fn, "via": "storage",
                   "file": "x", "line": 1, "ir": "accum", "guarded": False}],
            confidence="syntactic"))
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")


def _coaccum(ws):
    return [e for e in scg._coaccumulation_edges(ws)
            if e["evidence"].get("subtype") == "co-accumulation"]


def _pairs(edges):
    return {(e["evidence"]["member_cell"], e["evidence"]["aggregate_cell"])
            for e in edges}


class TCoAccumulation(unittest.TestCase):
    def test_member_plus_aggregate_emits_pair(self):
        """a[x] += d; total += d;  ->  the (member, aggregate) pair IS emitted."""
        src = """
        contract T {
            mapping(uint => uint) a;
            uint total;
            function f(uint x, uint d) external {
                a[x] += d;
                total += d;
            }
        }
        """
        edges = _coaccum(_mk_ws(src))
        self.assertEqual(len(edges), 1, edges)
        e = edges[0]
        self.assertEqual(_pairs(edges), {("a", "total")})
        self.assertEqual(e["kind"], "conserved-with")
        self.assertEqual(e["evidence"]["tier"],
                         "co-accumulation-sigma-conservation")
        self.assertEqual(e["evidence"]["delta"], "d")
        self.assertEqual(e["evidence"]["sign"], "+")
        # advisory: no dataflow slice -> honest syntactic tier, NOT auto-promoted
        self.assertEqual(e["confidence"], "syntactic")
        self.assertFalse(e["evidence"]["promotable"])

    def test_member_only_not_emitted(self):
        """a[x] += d;  with NO aggregate accumulating the same delta -> NOT emitted."""
        src = """
        contract T {
            mapping(uint => uint) a;
            function f(uint x, uint d) external {
                a[x] += d;
            }
        }
        """
        self.assertEqual(_coaccum(_mk_ws(src)), [])

    def test_member_access_index_key_not_mislabeled(self):
        """REGRESSION (2026-07-10 review): a member-access index key (bal[msg.sender][t])
        must NOT leak its dotted field .sender into the cell name. The member cell is the
        base identifier, not 'sender'."""
        self.assertEqual(scg._parse_lvalue("bal[msg.sender][t]"),
                         ("bal", ["msg.sender", "t"], True))
        self.assertEqual(
            scg._parse_lvalue("userToErc20Balance[msg.sender][token]"),
            ("userToErc20Balance", ["msg.sender", "token"], True))
        src = """
        contract T {
            mapping(address => mapping(address => uint)) userToErc20Balance;
            uint totalBalance;
            function deposit(address token, uint d) external {
                userToErc20Balance[msg.sender][token] += d;
                totalBalance += d;
            }
        }
        """
        edges = _coaccum(_mk_ws(src))
        pairs = _pairs(edges)
        self.assertEqual(pairs, {("userToErc20Balance", "totalBalance")}, edges)
        self.assertNotIn("sender", {c for p in pairs for c in p})

    def test_timestamp_aggregate_not_paired(self):
        """REGRESSION (2026-07-10 review): a value member co-written with a
        lastUpdate/timestamp bump is NOT a Sigma-conservation pair (the aggregate is a
        snapshot, not a conserved value amount)."""
        self.assertFalse(scg._is_value_cell("lastUpdateTimestamp"))
        src = """
        contract T {
            mapping(uint => uint) a;
            uint lastUpdateTimestamp;
            function f(uint x, uint d) external {
                a[x] += d;
                lastUpdateTimestamp += d;
            }
        }
        """
        self.assertEqual(_coaccum(_mk_ws(src)), [])

    def test_unrelated_cells_different_delta_not_emitted(self):
        """Two cells accumulating DIFFERENT deltas are not co-accumulating -> NOT
        emitted (the delta must match)."""
        src = """
        contract T {
            mapping(uint => uint) a;
            uint total;
            function f(uint x, uint p, uint q) external {
                a[x] += p;
                total += q;
            }
        }
        """
        self.assertEqual(_coaccum(_mk_ws(src)), [])

    def test_two_scalars_no_mapping_member_not_emitted(self):
        """Both cells scalar (no mapping-indexed member) -> NOT emitted (no aggregate<->
        member relationship; a coupling without a per-key member is not this tier)."""
        src = """
        contract T {
            uint one;
            uint total;
            function f(uint d) external {
                one += d;
                total += d;
            }
        }
        """
        self.assertEqual(_coaccum(_mk_ws(src)), [])

    def test_same_key_depth_coindexed_not_emitted(self):
        """a[x] += d; b[x] += d;  same index-key depth -> a co-INDEXED coupling, NOT an
        aggregate<->member pair (neither is the strict-subset-key aggregate)."""
        src = """
        contract T {
            mapping(uint => uint) a;
            mapping(uint => uint) b;
            function f(uint x, uint d) external {
                a[x] += d;
                b[x] += d;
            }
        }
        """
        self.assertEqual(_coaccum(_mk_ws(src)), [])

    def test_opposite_sign_not_grouped(self):
        """a[x] += d; total -= d;  opposite signs -> not the same accumulation, NOT
        emitted (grouping is keyed on (delta, sign))."""
        src = """
        contract T {
            mapping(uint => uint) a;
            uint total;
            function f(uint x, uint d) external {
                a[x] += d;
                total -= d;
            }
        }
        """
        self.assertEqual(_coaccum(_mk_ws(src)), [])

    def test_rate_field_aggregate_excluded(self):
        """A rate/ratio aggregate is a parameter, not a conserved balance -> excluded by
        the VALUE-cell FP guard even when co-accumulated."""
        src = """
        contract T {
            mapping(uint => uint) a;
            uint feeRate;
            function f(uint x, uint d) external {
                a[x] += d;
                feeRate += d;
            }
        }
        """
        self.assertEqual(_coaccum(_mk_ws(src)), [])

    def test_morpho_supply_shape_deep_member(self):
        """The real Morpho.supply() shape: position[id][onBehalf].supplyShares += shares;
        market[id].totalSupplyShares += shares.toUint128();  (the cast on the aggregate
        delta must NOT defeat the same-delta match). The other-delta assets line stays
        unpaired."""
        src = """
        contract T {
            struct Pos { uint128 supplyShares; }
            struct Mkt { uint128 totalSupplyShares; uint128 totalSupplyAssets; }
            mapping(bytes32 => mapping(address => Pos)) position;
            mapping(bytes32 => Mkt) market;
            function supply(bytes32 id, address onBehalf, uint shares, uint assets)
                external
            {
                position[id][onBehalf].supplyShares += shares;
                market[id].totalSupplyShares += shares.toUint128();
                market[id].totalSupplyAssets += assets.toUint128();
            }
        }
        """
        edges = _coaccum(_mk_ws(src))
        self.assertEqual(_pairs(edges), {("supplyShares", "totalSupplyShares")}, edges)

    def test_mutation_dropping_member_indexed_guard_would_overfire(self):
        """Guards the pairing precondition: if the mapping-indexed-member requirement were
        dropped, the two-scalar case (test_two_scalars...) would START emitting. Assert the
        member IS mapping-indexed in a real emitted edge, so that mutation is observable."""
        src = """
        contract T {
            mapping(uint => uint) a;
            uint total;
            function f(uint x, uint d) external {
                a[x] += d;
                total += d;
            }
        }
        """
        edges = _coaccum(_mk_ws(src))
        self.assertEqual(len(edges), 1)
        # member 'a' is mapping-indexed, aggregate 'total' is the scalar (subset-key) side
        self.assertEqual(edges[0]["evidence"]["member_cell"], "a")
        self.assertEqual(edges[0]["evidence"]["aggregate_cell"], "total")


class TSharedDeltaPromotionAndViolators(unittest.TestCase):
    """B1-inc2: (1) the dataflow accum-delta hop + (2) SHARED-DELTA keying + (3) the
    partial-flush OMIT-VIOLATOR. Mutating any of the three breaks a case here."""

    # ---- change (1): dataflow-slice accum base-delta parse -------------------------
    def test_base_delta_parse_strips_casts(self):
        """The accum-delta hop's base delta strips receiver-casts / prefix-casts so the
        member (`+= shares`) and aggregate (`+= shares.toUint128()`) join on 'shares'."""
        bd = dfslice._base_delta_of
        rhs = dfslice._accum_rhs_of
        self.assertEqual(bd(rhs("position[id][o].supplyShares += shares")), "shares")
        self.assertEqual(bd(rhs("market[id].totalSupplyShares += shares.toUint128()")),
                         "shares")
        self.assertEqual(bd("uint128(assets)"), "assets")
        self.assertEqual(bd("SafeCast.toUint128(delta)"), "delta")
        # a comparison / plain (non-accumulation) assignment is NOT an accum rhs
        self.assertIsNone(rhs("require(a <= b)"))
        self.assertIsNone(rhs("x = y"))

    # ---- change (2): SHARED-DELTA promotion predicate ------------------------------
    def test_same_delta_promotes_semantic_ssa(self):
        """(i) SAME base delta linked to BOTH cells -> promote to semantic-ssa."""
        lk = {("shares", "supplyShares"), ("shares", "totalSupplyShares")}
        self.assertTrue(scg._coaccum_promotes("shares", "supplyShares",
                                              "totalSupplyShares", lk))

    def test_different_delta_stays_syntactic(self):
        """(ii) the two cells receive DIFFERENT base deltas (supplyShares<-shares vs
        totalSupplyAssets<-assets) -> NOT promoted, stays syntactic. A co-write bug
        (membership-only, ignoring the delta) would wrongly return True here."""
        lk = {("shares", "supplyShares"), ("assets", "totalSupplyAssets")}
        # promotion keyed on the group delta 'shares' must fail: (shares,totalSupplyAssets)
        # is NOT in lk (that cell was fed 'assets', a different delta).
        self.assertFalse(scg._coaccum_promotes("shares", "supplyShares",
                                               "totalSupplyAssets", lk))
        # symmetric: neither delta links BOTH cells
        self.assertFalse(scg._coaccum_promotes("assets", "supplyShares",
                                               "totalSupplyAssets", lk))

    def test_end_to_end_same_delta_pair_promotes(self):
        """(i) end-to-end: Morpho.supply() shape with an accum-delta slice linking 'shares'
        to BOTH supplyShares and totalSupplyShares -> the emitted edge is semantic-ssa; the
        DIFFERENT-delta supplyShares/totalSupplyAssets pair is absent (never grouped)."""
        src = """
        contract T {
            struct Pos { uint128 supplyShares; }
            struct Mkt { uint128 totalSupplyShares; uint128 totalSupplyAssets; }
            mapping(bytes32 => mapping(address => Pos)) position;
            mapping(bytes32 => Mkt) market;
            function _noop() internal {}
            function supply(bytes32 id, address o, uint shares, uint assets) external {
                position[id][o].supplyShares += shares;
                market[id].totalSupplyShares += shares.toUint128();
                market[id].totalSupplyAssets += assets.toUint128();
            }
        }
        """
        ws = _mk_ws(src)
        _write_slice(ws, [("shares", "supplyShares", "supply"),
                          ("shares", "totalSupplyShares", "supply"),
                          ("assets", "totalSupplyAssets", "supply")])
        edges = _coaccum(ws)
        pairs = {(e["evidence"]["member_cell"], e["evidence"]["aggregate_cell"]): e
                 for e in edges}
        self.assertIn(("supplyShares", "totalSupplyShares"), pairs)
        self.assertEqual(pairs[("supplyShares", "totalSupplyShares")]["confidence"],
                         "semantic-ssa")
        # different-delta cell pair never groups -> absent (NOT semantic-ssa)
        self.assertNotIn(("supplyShares", "totalSupplyAssets"), pairs)

    def test_end_to_end_missing_hop_stays_syntactic(self):
        """(ii) mirror: if the slice links the delta to only ONE cell (the other hop
        absent) the pair is NOT promoted -> honest syntactic."""
        src = """
        contract T {
            struct Pos { uint128 supplyShares; }
            struct Mkt { uint128 totalSupplyShares; }
            mapping(bytes32 => mapping(address => Pos)) position;
            mapping(bytes32 => Mkt) market;
            function _noop() internal {}
            function supply(bytes32 id, address o, uint shares) external {
                position[id][o].supplyShares += shares;
                market[id].totalSupplyShares += shares.toUint128();
            }
        }
        """
        ws = _mk_ws(src)
        _write_slice(ws, [("shares", "supplyShares", "supply")])  # aggregate hop omitted
        edges = _coaccum(ws)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["confidence"], "syntactic")
        self.assertFalse(edges[0]["evidence"]["promotable"])

    # ---- change (3): partial-flush OMIT-VIOLATOR -----------------------------------
    def test_violators_helper(self):
        """A writer mutating a STRICT NON-EMPTY subset of the coupled set is a violator;
        one mutating ALL of it (or none) is not."""
        S = {"supplyShares", "totalSupplyShares"}
        fn_cells = {
            "supply": {"supplyShares"},                       # dropped totalSupplyShares
            "withdraw": {"supplyShares", "totalSupplyShares"},  # full set -> not a violator
            "unrelated": {"borrowShares"},                     # disjoint -> not a violator
        }
        viol = scg._coaccum_violators(S, fn_cells, Path("/tmp"), "src/T.sol")
        self.assertEqual(len(viol), 1, viol)
        v = viol[0]
        self.assertEqual(v["fn"], "supply")
        self.assertEqual(v["mutates"], ["supplyShares"])
        self.assertEqual(v["omits"], ["totalSupplyShares"])

    def test_end_to_end_dropping_member_writer_emits_violator(self):
        """(iii) a second writer mutating ONLY the member (the aggregate write dropped)
        yields nviol>0 with {mutates, omits}. A clean file where every writer touches both
        cells stays nviol=0 (the kill does not fire)."""
        # clean: both writers touch supplyShares AND totalSupplyShares -> no violator
        clean = """
        contract T {
            struct Pos { uint128 supplyShares; }
            struct Mkt { uint128 totalSupplyShares; }
            mapping(bytes32 => mapping(address => Pos)) position;
            mapping(bytes32 => Mkt) market;
            function _noop() internal {}
            function supply(bytes32 id, address o, uint s) external {
                position[id][o].supplyShares += s;
                market[id].totalSupplyShares += s.toUint128();
            }
            function withdraw(bytes32 id, address o, uint s) external {
                position[id][o].supplyShares -= s;
                market[id].totalSupplyShares -= s.toUint128();
            }
        }
        """
        e = _coaccum(_mk_ws(clean))
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["evidence"]["nviol"], 0)
        self.assertEqual(e[0]["violators"], [])
        # dropped: supply() no longer writes the aggregate -> supply is a violator
        dropped = """
        contract T {
            struct Pos { uint128 supplyShares; }
            struct Mkt { uint128 totalSupplyShares; }
            mapping(bytes32 => mapping(address => Pos)) position;
            mapping(bytes32 => Mkt) market;
            function _noop() internal {}
            function supply(bytes32 id, address o, uint s) external {
                position[id][o].supplyShares += s;
            }
            function withdraw(bytes32 id, address o, uint s) external {
                position[id][o].supplyShares -= s;
                market[id].totalSupplyShares -= s.toUint128();
            }
        }
        """
        e = _coaccum(_mk_ws(dropped))
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["evidence"]["nviol"], 1)
        v = e[0]["violators"][0]
        self.assertEqual(v["fn"], "supply")
        self.assertEqual(v["mutates"], ["supplyShares"])
        self.assertEqual(v["omits"], ["totalSupplyShares"])


class TTransferConservingExclusion(unittest.TestCase):
    """FP FIX (2026-07-10): a value-CONSERVING member-to-member transfer
    (`shares[from]-=amt; shares[to]+=amt;`) mutates the member cell only (omitting the
    coupled aggregate totalShares) but nets ZERO on sum(member), so the aggregate MUST NOT
    move - it is NOT a partial-flush. Before the fix this fleet-REDed every OZ/standard
    ERC20 under AUDITOOOR_L37_STRICT (etherfi _transferShares@EETH.sol:187-188). The
    exclusion must NOT swallow a genuine one-sided / unbalanced partial-flush."""

    # ---- _fn_conserving_cells: net-zero detection ----------------------------------
    def test_conserving_cells_transfer_is_net_zero(self):
        """A cell with a += and a -= of the SAME delta is net-zero VALUE-CONSERVING."""
        src = """
        contract T {
            mapping(address => uint) shares;
            function _noop() internal {}
            function transferShares(address from, address to, uint amt) external {
                shares[from] -= amt;
                shares[to]   += amt;
            }
        }
        """
        self.assertEqual(scg._fn_conserving_cells(src),
                         {"transferShares": {"shares"}})

    def test_conserving_cells_one_sided_not_net_zero(self):
        """A one-sided mint (only +=) or burn (only -=) is NOT conserving."""
        src = """
        contract T {
            mapping(address => uint) shares;
            function mintOnly(address u, uint a) external { shares[u] += a; }
            function burnOnly(address u, uint a) external { shares[u] -= a; }
        }
        """
        self.assertEqual(scg._fn_conserving_cells(src), {})

    def test_conserving_cells_unbalanced_not_net_zero(self):
        """`c += a; c -= a; c += fee;` nets a REAL change (the + multiset {a,fee} != the
        - multiset {a}) -> NOT conserving, so it stays a partial-flush candidate."""
        src = """
        contract T {
            mapping(address => uint) shares;
            function transferWithFee(address from, address to, uint amt, uint fee)
                external
            {
                shares[from]     -= amt;
                shares[to]       += amt;
                shares[treasury] += fee;
            }
        }
        """
        self.assertEqual(scg._fn_conserving_cells(src), {})

    # ---- _coaccum_violators: exclusion is precise ----------------------------------
    def test_violators_excludes_conserving_transfer(self):
        """Direct helper: a conserving transfer of the member is EXCLUDED; a genuine
        one-sided drop of the member is STILL a violator."""
        S = {"shares", "totalShares"}
        fn_cells = {
            "transferShares": {"shares"},   # member-to-member transfer (net-zero)
            "badMint":        {"shares"},   # one-sided += only (real partial-flush)
        }
        conserving = {"transferShares": {"shares"}}   # only the transfer nets to zero
        viol = scg._coaccum_violators(S, fn_cells, Path("/tmp"), "src/T.sol", conserving)
        self.assertEqual([v["fn"] for v in viol], ["badMint"], viol)
        self.assertEqual(viol[0]["mutates"], ["shares"])
        self.assertEqual(viol[0]["omits"], ["totalShares"])

    def test_violators_no_conserving_arg_preserves_old_behavior(self):
        """Back-compat: with no conserving map both member-only writers are violators (the
        pre-fix behavior; the exclusion is opt-in via the 5th arg)."""
        S = {"shares", "totalShares"}
        fn_cells = {"transferShares": {"shares"}, "badMint": {"shares"}}
        viol = scg._coaccum_violators(S, fn_cells, Path("/tmp"), "src/T.sol")
        self.assertEqual(sorted(v["fn"] for v in viol), ["badMint", "transferShares"])

    # ---- end-to-end through _coaccumulation_edges ----------------------------------
    def test_end_to_end_erc20_transfer_not_a_violator(self):
        """The mint/burn co-accumulation forms the member<->aggregate edge; a
        member-to-member transfer in the SAME file is NOT reported as a violator (nviol=0
        for the transfer), while a one-sided drop IS."""
        # clean ERC20: mint/burn couple shares<->totalShares; transferShares is net-zero.
        clean = """
        contract T {
            mapping(address => uint) shares;
            uint totalShares;
            function _noop() internal {}
            function mintShares(address u, uint s) external {
                shares[u]   += s;
                totalShares += s;
            }
            function burnShares(address u, uint s) external {
                shares[u]   -= s;
                totalShares -= s;
            }
            function transferShares(address from, address to, uint s) external {
                shares[from] -= s;
                shares[to]   += s;
            }
        }
        """
        e = _coaccum(_mk_ws(clean))
        self.assertEqual(_pairs(e), {("shares", "totalShares")}, e)
        self.assertEqual(len(e), 1)
        # the transfer must NOT be flagged; mint & burn touch both cells -> nviol 0
        self.assertEqual(e[0]["evidence"]["nviol"], 0, e[0]["violators"])
        self.assertEqual(e[0]["violators"], [])
        # add a GENUINE partial-flush: a mint that forgets the aggregate. The conserving
        # transfer stays excluded; only the one-sided writer is a violator.
        buggy = clean.replace(
            "            function transferShares(address from, address to, uint s) external {\n"
            "                shares[from] -= s;\n"
            "                shares[to]   += s;\n"
            "            }",
            "            function transferShares(address from, address to, uint s) external {\n"
            "                shares[from] -= s;\n"
            "                shares[to]   += s;\n"
            "            }\n"
            "            function badMint(address u, uint s) external {\n"
            "                shares[u] += s;\n"
            "            }")
        e2 = _coaccum(_mk_ws(buggy))
        self.assertEqual(len(e2), 1)
        self.assertEqual(e2[0]["evidence"]["nviol"], 1, e2[0]["violators"])
        self.assertEqual([v["fn"] for v in e2[0]["violators"]], ["badMint"])


class TConservationAutoCloseGate(unittest.TestCase):
    """B1-inc2 co-accumulation v2 GATE fix (2026-07-10): the state-coupling COMPLETENESS
    gate (state-coupling-completeness-check.py) must AUTO-CLOSE a PROVEN-conserved
    (evidence.nviol==0) PROMOTABLE co-accumulation edge, and fail-closed under
    AUDITOOOR_L37_STRICT ONLY on a SUSPECTED partial-flush (nviol>0).

    Pre-fix ROOT: the Track-1 dataflow broadening promotes every clean ERC20 mint/burn
    _balances<->_totalSupply co-accumulation to promotable=True; the gate computed open_edges
    keying ONLY on promotable (never on nviol), so a CLEAN ERC20 (v1's conserving-transfer
    exclusion drove nviol=0) STILL counted as an open edge -> fail-state-coupling-open -> rc=1.

    Drives the REAL pipeline path: the accum-delta slice (identical schema to
    dataflow-slice.py --mode both's statevar-accum-delta hop) -> state-coupling-graph --emit
    (auto-run inside scc.main) -> state-coupling-completeness under STRICT. Non-vacuous: the
    clean case flips rc 1->0 via auto-close; the one-sided badMint case keeps rc=1 (teeth)."""

    # Realistic OZ-style ERC20: state vars at the TOP; _mint is NOT the first fn; a value-
    # CONSERVING _transfer (net-zero on _balances). mint/burn couple _balances<->_totalSupply;
    # the conserving transfer omits _totalSupply but nets zero -> correctly NOT a partial-flush.
    _ERC20 = """
    contract Token {
        mapping(address => uint256) private _balances;
        uint256 private _totalSupply;
        string private _name;

        function transfer(address to, uint256 amount) external returns (bool) {
            _transfer(msg.sender, to, amount);
            return true;
        }
        function approve(address s, uint256 a) external returns (bool) { return true; }
        function _mint(address account, uint256 amount) internal {
            _balances[account] += amount;
            _totalSupply       += amount;
        }
        function _burn(address account, uint256 amount) internal {
            _balances[account] -= amount;
            _totalSupply       -= amount;
        }
        function _transfer(address from, address to, uint256 amount) internal {
            _balances[from] -= amount;
            _balances[to]   += amount;
        }
    }
    """

    def _slice_mint_burn(self, ws):
        # dataflow-slice --mode both accum-delta hops: base delta 'amount' flows into BOTH
        # _balances and _totalSupply in _mint AND _burn -> _coaccum_promotes -> promotable=True.
        _write_slice(ws, [("amount", "_balances", "_mint"),
                          ("amount", "_totalSupply", "_mint"),
                          ("amount", "_balances", "_burn"),
                          ("amount", "_totalSupply", "_burn")])

    def _run_scc_strict(self, ws):
        """Run the completeness gate (which AUTO-EMITS the SCG first) under STRICT; return
        (rc, verdict-json). Restores the prior AUDITOOOR_L37_STRICT env either way."""
        prev = os.environ.get("AUDITOOOR_L37_STRICT")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            rc = scc.main(["--workspace", str(ws)])
        finally:
            if prev is None:
                os.environ.pop("AUDITOOOR_L37_STRICT", None)
            else:
                os.environ["AUDITOOOR_L37_STRICT"] = prev
        res = json.loads((ws / ".auditooor" / "state_coupling_completeness.json")
                         .read_text(encoding="utf-8"))
        return rc, res

    def _the_coaccum_edge(self, ws):
        edges = [json.loads(l) for l in
                 (ws / ".auditooor" / "state_coupling_edges.jsonl")
                 .read_text(encoding="utf-8").splitlines() if l.strip()]
        ca = [e for e in edges
              if e.get("evidence", {}).get("subtype") == "co-accumulation"]
        self.assertEqual(len(ca), 1, ca)
        return ca[0]

    def test_clean_erc20_conserved_edge_auto_closes_rc0(self):
        """CLEAN OZ ERC20 -> the co-accumulation edge is promotable=True (gating-eligible)
        AND nviol=0 (proven-conserved) -> the gate AUTO-CLOSES it -> open_edges=0, rc=0.
        Pre-fix this was open_edges=1 -> rc=1 (the fleet-RED)."""
        ws = _mk_ws(self._ERC20, rel="src/Token.sol")
        self._slice_mint_burn(ws)
        rc, res = self._run_scc_strict(ws)
        e = self._the_coaccum_edge(ws)
        self.assertTrue(e["evidence"]["promotable"], e)      # WAS gating-eligible
        self.assertEqual(e["evidence"]["nviol"], 0, e["violators"])  # proven-conserved
        self.assertEqual(res["promotable_edges"], 1, res)
        self.assertEqual(res["auto_closed_conserved_edges"], 1, res)
        self.assertEqual(res["open_edges"], 0, res)
        self.assertEqual(res["verdict"], "pass-state-coupling-completeness")
        self.assertEqual(rc, 0)

    def test_one_sided_badmint_partial_flush_stays_open_rc1(self):
        """A one-sided badMint (mutates _balances, OMITS _totalSupply) is a REAL partial-flush
        -> nviol=1 -> the edge STAYS open -> open_edges>=1, rc=1 under STRICT (teeth intact).
        The proven-conserved auto-close must NOT swallow a genuine desync lead."""
        buggy = self._ERC20.replace(
            "        function _transfer(address from, address to, uint256 amount) internal {",
            "        function badMint(address account, uint256 amount) external {\n"
            "            _balances[account] += amount;\n"
            "        }\n"
            "        function _transfer(address from, address to, uint256 amount) internal {")
        ws = _mk_ws(buggy, rel="src/Token.sol")
        self._slice_mint_burn(ws)
        rc, res = self._run_scc_strict(ws)
        e = self._the_coaccum_edge(ws)
        self.assertTrue(e["evidence"]["promotable"], e)
        self.assertEqual(e["evidence"]["nviol"], 1, e["violators"])
        self.assertEqual([v["fn"] for v in e["violators"]], ["badMint"], e["violators"])
        self.assertEqual(res["auto_closed_conserved_edges"], 0, res)
        self.assertGreaterEqual(res["open_edges"], 1, res)
        self.assertEqual(res["verdict"], "fail-state-coupling-open")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
