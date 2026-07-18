#!/usr/bin/env python3
"""Regression for the State-Coupling Graph (SCG) - P0 schema + P1 dataflow-grounded
extractor. See reports/state_coupling_completeness_framework_design.md.
2026-07-08 (state-coupling-completeness framework, phase P0/P1)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


scs = _load("state_coupling_schema", "state_coupling_schema.py")
scg = _load("state_coupling_graph", "state-coupling-graph.py")


class TSchema(unittest.TestCase):
    def test_new_edge_valid_and_impact_mapped(self):
        e = scs.new_edge("id1", "solidity", "flush-group", "tyTagCache",
                         "structIndex", ["flushAll"], ["flushIndex"],
                         [{"fn": "flushIndex", "file": "C.sol", "line": 3,
                           "mutates": ["structIndex"], "omits": ["tyTagCache"]}])
        ok, errs = scs.validate(e)
        self.assertTrue(ok, errs)
        self.assertEqual(e["impact_class"],
                         "asymmetric-cache-invalidation-partial-flush")
        self.assertEqual(e["confidence"], "syntactic")

    def test_bad_kind_and_confidence_rejected(self):
        e = scs.new_edge("x", "go", "flush-group", "a", "b", [], [], [])
        e["kind"] = "not-a-kind"
        e["confidence"] = "vibes"
        ok, errs = scs.validate(e)
        self.assertFalse(ok)
        self.assertTrue(any("bad kind" in x for x in errs))
        self.assertTrue(any("bad confidence" in x for x in errs))

    def test_write_read_roundtrip_and_confidence_floor(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        edges = [
            scs.new_edge("e1", "go", "derived-from", "commitSet", "version",
                         [], [], [], confidence="semantic-ssa"),
            scs.new_edge("e2", "go", "paired-lifecycle", "a", "b", [], [], [],
                         confidence="syntactic"),
        ]
        self.assertEqual(scs.write_edges(ws, edges), 2)
        self.assertEqual(len(scs.read_edges(ws)), 2)
        sem = scs.read_edges(ws, min_confidence="semantic-ssa")
        self.assertEqual([e["edge_id"] for e in sem], ["e1"])
        self.assertEqual(
            [e["edge_id"] for e in scs.read_edges(ws, kinds=["paired-lifecycle"])],
            ["e2"])


_DERIVED_SRC = """contract C {
  function setEntry(uint k, uint v) external { structIndex = k; tyTagCache = structIndex + v; }
  function flushIndex() external { structIndex = 0; }
}"""


class TExtractor(unittest.TestCase):
    def test_single_file_emits_derived_edge_syntactic(self):
        ws = Path(tempfile.mkdtemp())
        f = ws / "C.sol"
        f.write_text(_DERIVED_SRC)
        rc = scg.main(["--file", str(f), "--emit"])
        self.assertEqual(rc, 0)

    def _ws_with_derived(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / "C.sol").write_text(_DERIVED_SRC)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "C.sol", "function": "flushIndex"}) + "\n")
        return ws

    def _storage_slice(self, ws, a, b, fn="setEntry", file="C.sol", line=2):
        df = _load("dataflow_schema", "dataflow_schema.py")
        rec = df.new_path(
            "p1", "solidity", "backward", "slither-ssa",
            source={"kind": "param", "fn": fn, "var": a, "file": file, "line": line},
            sink={"kind": "state-write", "callee": None, "arg_pos": None,
                  "fn": fn, "file": file, "line": line},
            hops=[{"from_var": a, "to_var": b, "fn": fn, "via": "storage",
                   "file": file, "line": line, "ir": "", "guarded": False}])
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])

    def test_no_slice_keeps_syntactic_advisory(self):
        # P2a: without a def-use slice, edges stay syntactic-advisory (degrade tier).
        ws = self._ws_with_derived()
        scg.main(["--workspace", str(ws), "--emit"])
        edges = scs.read_edges(ws)
        self.assertTrue(edges, "expected >=1 derived-from edge")
        self.assertTrue(all(e["confidence"] == "syntactic" for e in edges))
        self.assertTrue(all(e["evidence"].get("promotable") is False for e in edges),
                        "empty-writer edges must NEVER be promotable")

    def test_precision_persistent_grounding_promotable_with_writers(self):
        # P2a+P2b: a slice witnessing BOTH cells as STORAGE cells -> edge kept +
        # persistent_state; and P2b fills writers from the storage-hop fn -> promotable.
        ws = self._ws_with_derived()
        self._storage_slice(ws, "structIndex", "tyTagCache")
        scg.main(["--workspace", str(ws), "--emit"])
        edges = scs.read_edges(ws)
        self.assertTrue(edges, "persistent-grounded edge must survive")
        self.assertTrue(all(e["evidence"]["persistent_state"] for e in edges))
        self.assertTrue(all(e["writers_a"] or e["writers_b"] for e in edges),
                        "P2b: writers filled from the storage-hop fn")
        self.assertTrue(any(e["evidence"]["promotable"] for e in edges),
                        "persistent + writers -> promotable")

    def test_precision_drops_nonpersistent_when_slice_present(self):
        # P2a: with a slice present but the cells NOT storage cells (the param/local
        # FP class), the edge is DROPPED - the storage grounding subsumes param/local/
        # value-receiver/plural-collision FPs in one check.
        ws = self._ws_with_derived()
        self._storage_slice(ws, "someOtherCell", "unrelated")  # cells not in edge
        scg.main(["--workspace", str(ws), "--emit"])
        self.assertEqual(scs.read_edges(ws), [],
                         "non-persistent edges must drop when a slice exists")

    def test_precision_denylist_path(self):
        # P2a: an edge whose writer file is vendored/test is dropped.
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        sub = ws / "go-ethereum"
        sub.mkdir()
        (sub / "chain.go").write_text(
            "package x\nfunc set(v int){ver=v; commit=ver+1}\nfunc bump(){ver=ver+1}\n")
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "go-ethereum/chain.go", "function": "bump"}) + "\n")
        scg.main(["--workspace", str(ws), "--emit"])
        self.assertEqual(scs.read_edges(ws), [],
                         "vendored/go-ethereum edges must be denylisted")

    def _ws_with_vmf(self, functions):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
        (ws / ".auditooor" / "value_moving_functions.json").write_text(
            json.dumps({"functions": functions}))
        return ws

    def test_collapsed_examples_make_cited_negative_auditable(self):
        # AUDITABILITY (2026-07-08): a multi-field mover whose fields all EXCLUDE (rate/config)
        # collapses below the pair floor. The accounting must record WHICH fn collapsed (fn +
        # surviving_fields + n_raw_writes) so a cited-NEGATIVE over a subsystem is verifiable
        # (the reader confirms the fn was SEEN-and-drained, not silently unenumerated).
        ws = self._ws_with_vmf([
            {"file": "Rates.sol", "function": "UpdateInterestRates", "language": "sol",
             "transfer_hit": True,
             "ledger_write_evidence": ["minInterestRate", "maxInterestRate"]},
        ])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        ce = acct.get("collapsed_examples", [])
        self.assertTrue(any(e["fn"] == "UpdateInterestRates" for e in ce),
                        "a collapsed multi-field mover must be recorded in collapsed_examples")
        row = next(e for e in ce if e["fn"] == "UpdateInterestRates")
        self.assertEqual(row["surviving_fields"], [], "rate fields excluded -> empty surviving set")
        self.assertEqual(row["n_raw_writes"], 2)

    def test_p2b_conserved_with_fires_semantic(self):
        # P2b: a multi-field ledger set is a conservation obligation; a fn writing a
        # STRICT SUBSET is a violator -> conserved-with edge (semantic-ssa, promotable).
        ws = self._ws_with_vmf([
            {"file": "Vault.sol", "function": "accrue", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveAsset", "reserveNav"]},
            {"file": "Vault.sol", "function": "reduce", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveNav"]},
        ])
        scg.main(["--workspace", str(ws), "--emit"])
        cw = [e for e in scs.read_edges(ws) if e["kind"] == "conserved-with"]
        self.assertTrue(cw, "conserved-with must fire on a subset-writer")
        e = cw[0]
        self.assertEqual(e["confidence"], "semantic-ssa")
        self.assertTrue(e["evidence"]["promotable"])
        self.assertEqual(e["impact_class"], "value-conservation-break")
        self.assertTrue(any(v["fn"] == "reduce" for v in e["violators"]))

    def test_p2b_config_fn_and_addr_fields_excluded(self):
        # a config/factory fn re-pointing address handles is NOT value conservation
        # (measured NUVA FP: updateCrossChainConfig shareToken<->crossChainVault).
        ws = self._ws_with_vmf([
            {"file": "M.sol", "function": "updateCrossChainConfig", "language": "sol",
             "transfer_hit": False,
             "ledger_write_evidence": ["shareTokenAddress", "crossChainVaultAddress"]},
            {"file": "M.sol", "function": "initialize", "language": "sol",
             "transfer_hit": False,
             "ledger_write_evidence": ["shareTokenAddress"]},
        ])
        scg.main(["--workspace", str(ws), "--emit"])
        cw = [e for e in scs.read_edges(ws) if e["kind"] == "conserved-with"]
        self.assertEqual(cw, [], f"config/address conserved-with must not fire: {cw}")

    def test_p2b_violator_line_resolved(self):
        # violator line must resolve from source (was hardcoded 0 -> un-actionable).
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "accrue", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveVal", "reserveNav"]},
            {"file": "V.sol", "function": "reduce", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveNav"]},
        ])
        (ws / "V.sol").write_text(
            "contract V {\n"
            "  function accrue() external { reserveVal += 1; reserveNav += 1; }\n"
            "  function reduce() external { reserveNav -= 1; }\n"
            "}\n")
        scg.main(["--workspace", str(ws), "--emit"])
        cw = [e for e in scs.read_edges(ws) if e["kind"] == "conserved-with"]
        self.assertTrue(cw)
        red = next(v for e in cw for v in e["violators"] if v["fn"] == "reduce")
        self.assertEqual(red["line"], 3, f"reduce is on line 3, got {red['line']}")

    def test_p2b_store_type_names_excluded_but_asset_kept(self):
        # cosmos-Go FP: VMF ledger fields are store TYPES (VaultAccount/VaultLookup/
        # feeTimeoutQueue), not conserved amounts. Exclude them, but keep value fields
        # like reserveAsset (the "set" suffix must NOT match "asSET").
        ws = self._ws_with_vmf([
            {"file": "k.go", "function": "doThing", "language": "go", "transfer_hit": True,
             "ledger_write_evidence": ["VaultAccount", "VaultLookup", "feeTimeoutQueue"]},
            {"file": "k.go", "function": "other", "language": "go", "transfer_hit": True,
             "ledger_write_evidence": ["VaultAccount"]},
        ])
        scg.main(["--workspace", str(ws), "--emit"])
        self.assertEqual(
            [e for e in scs.read_edges(ws) if e["kind"] == "conserved-with"], [],
            "store/type-name pairs must not fire conserved-with")
        # sanity: reserveAsset (ends 'asset' -> not 'set'-excluded) still participates
        ws2 = self._ws_with_vmf([
            {"file": "V.sol", "function": "accrue", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["reserveAsset", "reserveNav"]},
            {"file": "V.sol", "function": "reduce", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["reserveNav"]},
        ])
        scg.main(["--workspace", str(ws2), "--emit"])
        self.assertTrue([e for e in scs.read_edges(ws2) if e["kind"] == "conserved-with"],
                        "value field reserveAsset must still conserve")

    def test_conserved_accounting_vacuity_signal_on_atomic_writers(self):
        # ANTI-SILENT-SUPPRESSION (NUVA 2026-07-08): a multi-field value-mover that
        # writes its WHOLE conserved set atomically (no cross-function strict-subset
        # writer) yields 0 edges. That 0 must be VISIBLE + explained, not an invisible
        # tuned-zero: acct records the surviving set(s) + flags no_subset_writer.
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "atomicDeposit", "language": "sol",
             "transfer_hit": True,
             "ledger_write_evidence": ["vaultShares", "stakingShares"]},
        ])
        acct = {}
        edges = scg._conservation_edges(ws, acct=acct)
        self.assertEqual(edges, [], "atomic single-writer must yield no edge")
        self.assertGreaterEqual(acct["multi_field_movers"], 1)
        self.assertGreaterEqual(acct["surviving_conserved_sets"], 1,
                                "the surviving conserved set must be recorded, not hidden")
        self.assertEqual(acct["edges_emitted"], 0)
        self.assertTrue(acct["no_subset_writer"],
                        "0-edges-with-surviving-set is the telltale that must be flagged")
        self.assertTrue(any(ex["fn"] == "atomicDeposit"
                            for ex in acct["surviving_examples"]))

    def _write_slice(self, ws, mappings):
        # mappings: list of (fn, local_name, persistent_cell) -> one storage-hop path each.
        df = _load("dataflow_schema", "dataflow_schema.py")
        recs = []
        for i, (fn, local, cell) in enumerate(mappings):
            recs.append(df.new_path(
                f"p{i}", "solidity", "backward", "slither-ssa",
                source={"kind": "param", "fn": fn, "var": local, "file": "V.sol", "line": 2},
                sink={"kind": "state-write", "callee": None, "arg_pos": None,
                      "fn": fn, "file": "V.sol", "line": 2},
                hops=[{"from_var": local, "to_var": cell, "fn": fn, "via": "storage",
                       "file": "V.sol", "line": 2, "ir": "", "guarded": False}]))
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), recs)

    def test_persistent_cell_resolution_fires_cross_fn_partial_flush(self):
        # task_dcd6e6d3: local temp names are unique per fn, so WITHOUT resolution a
        # cross-function partial-flush can never fire. distribute() writes locals
        # poolShareLocal/vaultShareLocal (whole coupled set); drain() writes a DIFFERENT
        # local poolShareLocal2 - no name overlap -> 0 edges pre-increment. The slice
        # resolves poolShareLocal & poolShareLocal2 BOTH to persistent cell poolShares,
        # so drain() is now a strict-subset writer of {poolShares, vaultShares} -> the
        # conserved-with edge fires. This is the Aptos shape the lane previously missed.
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "distribute", "language": "sol",
             "transfer_hit": True,
             "ledger_write_evidence": ["poolShareLocal", "vaultShareLocal"]},
            {"file": "V.sol", "function": "drain", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["poolShareLocal2"]},
        ])
        # sanity: WITHOUT a slice, the distinct local names never match -> 0 edges.
        self.assertEqual(scg._conservation_edges(ws), [],
                         "pre-resolution: distinct locals must NOT match cross-fn")
        # add the storage-hop slice grounding both pool locals to the same cell.
        self._write_slice(ws, [
            ("distribute", "poolShareLocal", "poolShares"),
            ("distribute", "vaultShareLocal", "vaultShares"),
            ("drain", "poolShareLocal2", "poolShares"),
        ])
        edges = scg._conservation_edges(ws)
        cw = [e for e in edges if e["kind"] == "conserved-with"]
        self.assertTrue(cw, "post-resolution: cross-fn partial-flush must fire")
        e = cw[0]
        self.assertEqual({e["cell_a"], e["cell_b"]}, {"poolShares", "vaultShares"},
                         "edge cells must be the PERSISTENT cells, not the locals")
        self.assertEqual(e["evidence"]["cell_resolution"], "persistent-ssa")
        self.assertTrue(any(v["fn"] == "drain" for v in e["violators"]),
                        "drain() is the strict-subset (partial-flush) violator")

    def test_go_sink_cell_conserved_with_reaches_promotion_gate(self):
        # tick-21 end-to-end: a Go/Cosmos value-mover resolved via sink.cell (tick-19) must
        # flow all the way to a PROMOTABLE semantic-ssa conserved-with edge - i.e. the new
        # Go resolution reaches consumer 1a (the exploit-queue promotion gate), not just the
        # resolver map. FullReconcile writes cells Vaults+Balances (cross-collection coupled
        # set); Drain writes only Vaults -> strict-subset partial-flush violator. All grounded
        # by Go state-write SINKS carrying sink.cell (0 via=storage hops - the Go form).
        df = _load("dataflow_schema", "dataflow_schema.py")
        # realistic NUVA-shaped value names (the loop's _doDeposit{vaultShares,stakingShares});
        # VCIS keeps value-root fields, so both survive to form a 2-cell coupled set.
        ws = self._ws_with_vmf([
            {"file": "k.go", "function": "(*x.Keeper).FullReconcile", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["vaultShares", "stakingShares"]},
            {"file": "k.go", "function": "(*x.Keeper).Drain", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["vaultShares"]},
        ])
        recs = []
        for i, (qfn, local, cell) in enumerate([
            ("(*x.Keeper).FullReconcile", "vaultShares", "Vaults"),
            ("(*x.Keeper).FullReconcile", "stakingShares", "Balances"),
            ("(*x.Keeper).Drain", "vaultShares", "Vaults"),
        ]):
            r = df.new_path(
                f"g{i}", "go", "backward", "go-ssa",
                source={"kind": "param", "fn": qfn, "var": local, "file": "k.go", "line": 2},
                sink={"kind": "state-write", "callee": "(collections.Map[K,V]).Set",
                      "arg_pos": 2, "fn": qfn, "cell": cell, "file": "k.go", "line": 9},
                hops=[])
            r["sink"]["cell"] = cell
            recs.append(r)
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), recs)
        edges = scg._conservation_edges(ws)
        cw = [e for e in edges if e["kind"] == "conserved-with"]
        self.assertTrue(cw, "Go sink.cell resolution must let the cross-collection partial-flush fire")
        e = cw[0]
        self.assertEqual({e["cell_a"], e["cell_b"]}, {"Vaults", "Balances"},
                         "edge cells must be the PERSISTENT collection cells from sink.cell")
        self.assertEqual(e["evidence"]["cell_resolution"], "persistent-ssa",
                         "a Go sink.cell-grounded edge must be persistent-ssa, not name-fallback")
        self.assertTrue(e["evidence"]["promotable"],
                        "the Go-resolved edge must be PROMOTABLE (reaches the exploit-queue gate)")
        self.assertTrue(any(v["fn"] == "(*x.Keeper).Drain" for v in e["violators"]),
                        "Drain is the strict-subset (partial-flush) violator")

    def test_fn_name_normalization_bridges_qualified_slice_to_bare_vmf(self):
        # task_ba16b499: the dataflow slice names fns fully-qualified
        # (`Router._doDeposit(uint256,uint256)`) while VMF uses the BARE name
        # (`_doDeposit`), so an exact (fn, name) join finds NOTHING. _norm_fn +
        # the bare-key layer must bridge them so the local resolves to its cell.
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "_doDeposit", "language": "sol",
             "transfer_hit": True,
             "ledger_write_evidence": ["vaultShareLocal", "stakingShareLocal"]},
            {"file": "V.sol", "function": "drain", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["vaultShareLocal2"]},
        ])
        # slice fn names are QUALIFIED; VMF names above are BARE.
        recs = []
        for i, (qfn, local, cell) in enumerate([
            ("Router._doDeposit(uint256,uint256)", "vaultShareLocal", "poolShares"),
            ("Router._doDeposit(uint256,uint256)", "stakingShareLocal", "vaultShares"),
            ("Router.drain(uint256)", "vaultShareLocal2", "poolShares"),
        ]):
            recs.append(df.new_path(
                f"p{i}", "solidity", "backward", "slither-ssa",
                source={"kind": "param", "fn": qfn, "var": local, "file": "V.sol", "line": 2},
                sink={"kind": "state-write", "callee": None, "arg_pos": None,
                      "fn": qfn, "file": "V.sol", "line": 2},
                hops=[{"from_var": local, "to_var": cell, "fn": qfn, "via": "storage",
                       "file": "V.sol", "line": 2, "ir": "", "guarded": False}]))
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), recs)
        # the resolver map must contain a BARE-fn key so the bare VMF name resolves.
        n2c = scg._name_to_cell(ws)
        self.assertEqual(n2c.get(("_doDeposit", "vaultShareLocal")), "poolShares",
                         "bare-fn key must resolve the qualified-slice local")
        edges = scg._conservation_edges(ws)
        cw = [e for e in edges if e["kind"] == "conserved-with"]
        self.assertTrue(cw, "qualified/bare bridge must let the partial-flush fire")
        self.assertEqual({cw[0]["cell_a"], cw[0]["cell_b"]}, {"poolShares", "vaultShares"})

    def test_fn_name_normalization_ambiguous_bare_key_disabled(self):
        # two DIFFERENT contracts with a same-bare-name fn writing the same local to
        # DIFFERENT cells must NOT mis-bind: the ambiguous bare key is disabled.
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        recs = []
        for i, (qfn, local, cell) in enumerate([
            ("A.f(uint256)", "amt", "cellA"),
            ("B.f(uint256)", "amt", "cellB"),  # same bare name+local, different cell
        ]):
            recs.append(df.new_path(
                f"p{i}", "solidity", "backward", "slither-ssa",
                source={"kind": "param", "fn": qfn, "var": local, "file": "V.sol", "line": 2},
                sink={"kind": "state-write", "callee": None, "arg_pos": None,
                      "fn": qfn, "file": "V.sol", "line": 2},
                hops=[{"from_var": local, "to_var": cell, "fn": qfn, "via": "storage",
                       "file": "V.sol", "line": 2, "ir": "", "guarded": False}]))
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), recs)
        n2c = scg._name_to_cell(ws)
        # exact qualified keys survive; the ambiguous bare key must be absent (disabled).
        self.assertEqual(n2c.get(("A.f(uint256)", "amt")), "cellA")
        self.assertEqual(n2c.get(("B.f(uint256)", "amt")), "cellB")
        self.assertNotIn(("f", "amt"), n2c, "ambiguous bare key must be disabled")

    def test_go_state_write_sink_cell_resolves_persistent_cell(self):
        # item-2 sub-step (ii)-consumer + (i) fn-name norm (tick-19): Go/Cosmos persists via
        # a terminal state-write SINK carrying sink.cell (the collection field), NOT a
        # via=storage hop (the Solidity form). The resolver must consume sink.cell so Go
        # value-movers resolve to the cell they write - without it the resolver is BLIND to
        # every cosmos-sdk storage write (NUVA: 603+ sinks, 0 via=storage). And the Go SSA fn
        # name is `(*pkg.Keeper).BadUpdate`, which the OLD _norm_fn turned into '' - breaking
        # the bare-fn join for every Go value-mover. Generic to all Go/Cosmos workspaces.
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        rec = df.new_path(
            "g0", "go", "backward", "go-ssa",
            source={"kind": "param", "fn": "(*pkg/x.Keeper).BadUpdate", "var": "dPrincipal",
                    "file": "k.go", "line": 5},
            sink={"kind": "state-write", "callee": "(collections.Map[string,V]).Set",
                  "arg_pos": 2, "fn": "(*pkg/x.Keeper).BadUpdate", "cell": "Vaults",
                  "file": "k.go", "line": 9},
            hops=[{"from_var": "dPrincipal", "to_var": "va", "fn": "(*pkg/x.Keeper).BadUpdate",
                   "via": "internal_call", "file": "k.go", "line": 7, "ir": "", "guarded": False}])
        # the schema may whitelist sink keys; ensure `cell` survives into the written record.
        rec["sink"]["cell"] = "Vaults"
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])
        stats = {}
        n2c = scg._name_to_cell(ws, stats=stats)
        self.assertEqual(n2c.get(("(*pkg/x.Keeper).BadUpdate", "dPrincipal")), "Vaults",
                         "Go state-write sink.cell must resolve the value-mover's local to the cell")
        self.assertGreaterEqual(stats.get("go_sink_cells", 0), 1,
                                "the Go sink-cell branch must fire (non-vacuous)")
        # (i) the Go receiver-qualified fn name must normalize to its bare method, so a bare
        # VMF name (`BadUpdate`) resolves via the bare key.
        self.assertEqual(scg._norm_fn("(*pkg/x.Keeper).BadUpdate"), "BadUpdate")
        self.assertEqual(scg._norm_fn("(*pkg.Keeper).Deposit(ctx,uint256)"), "Deposit")
        self.assertEqual(scg._norm_fn("Router._doDeposit(uint256,uint256)"), "_doDeposit")
        self.assertEqual(n2c.get(("BadUpdate", "dPrincipal")), "Vaults",
                         "bare Go method key must resolve after fn-name normalization")
        # anti-silent-suppression: the accounting must SURFACE the Go-lane visibility so a
        # 0 on a Go ws (old binary, no sink.cell) is distinguishable from a legit Sol 0.
        # Add a second Go value-mover so a conserved set can form and populate the accounting.
        vmf = {"functions": [
            {"file": "k.go", "function": "(*pkg/x.Keeper).BadUpdate", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["dPrincipal", "Vaults"]},
        ]}
        (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps(vmf))
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        self.assertGreaterEqual(acct.get("slice_go_sink_cells", 0), 1,
                                "accounting must surface slice_go_sink_cells (Go-lane visibility)")
        self.assertEqual(acct.get("slice_resolution_status"), "resolved",
                         "a Go slice with consumed sink cells is a RESOLVED status, not 0-inapplicable")

    def test_flush_group_fires_semantic_on_nonatomic_go_fn_but_not_atomic(self):
        # 3rd canonical shape (tick-32): FLUSH-GROUP = a Go/Cosmos fn writing 2+ coupled
        # persistent cells with a fallible error-return BETWEEN the writes and NO atomic
        # CacheContext+write() wrapper -> partial-flush on the error path. Plant-validated
        # (real ws are cache-context-correct -> honest NEGATIVE, like reconcile.go).
        df = _load("dataflow_schema", "dataflow_schema.py")

        def _mk(body):
            ws = Path(tempfile.mkdtemp())
            (ws / ".auditooor").mkdir()
            (ws / "keeper").mkdir()
            (ws / "keeper" / "k.go").write_text(body)
            (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({"functions": [
                {"file": "keeper/k.go", "function": "Reconcile", "language": "go",
                 "transfer_hit": True, "ledger_write_evidence": ["vaultShares", "stakingShares"]}]}))
            recs = []
            for i, (v, cell) in enumerate([("vaultShares", "Vaults"), ("stakingShares", "Balances")]):
                r = df.new_path(f"g{i}", "go", "backward", "go-ssa",
                                source={"kind": "param", "fn": "Reconcile", "var": v,
                                        "file": "keeper/k.go", "line": 2},
                                sink={"kind": "state-write", "callee": "(collections.Map).Set",
                                      "arg_pos": 2, "fn": "Reconcile", "cell": cell,
                                      "file": "keeper/k.go", "line": 3 + i}, hops=[])
                r["sink"]["cell"] = cell
                recs.append(r)
            df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), recs)
            return ws

        # NON-atomic: error-return between the two coupled Set writes, no CacheContext -> FIRES.
        bad = _mk("package keeper\nfunc (k Keeper) Reconcile(ctx Ctx, a Addr, vaultShares, stakingShares Coin) error {\n"
                  "\tk.Vaults.Set(ctx, a, vaultShares)\n\tif err := k.chk(ctx); err != nil {\n\t\treturn err\n\t}\n"
                  "\tk.Balances.Set(ctx, a, stakingShares)\n\treturn nil\n}\n")
        fg = [e for e in scg._conservation_edges(bad) if e["kind"] == "flush-group"]
        self.assertTrue(fg, "a non-atomic coupled-write Go fn (err-return between writes) must fire flush-group")
        self.assertEqual(fg[0]["confidence"], "semantic-ssa")
        self.assertTrue(fg[0]["evidence"]["promotable"])

        # ATOMIC: same writes wrapped in CacheContext+write() -> partial-flush impossible -> NEGATIVE.
        good = _mk("package keeper\nfunc (k Keeper) Reconcile(ctx Ctx, a Addr, vaultShares, stakingShares Coin) error {\n"
                   "\tcacheCtx, write := ctx.CacheContext()\n\tk.Vaults.Set(cacheCtx, a, vaultShares)\n"
                   "\tif err := k.chk(cacheCtx); err != nil {\n\t\treturn err\n\t}\n"
                   "\tk.Balances.Set(cacheCtx, a, stakingShares)\n\twrite()\n\treturn nil\n}\n")
        fg2 = [e for e in scg._conservation_edges(good) if e["kind"] == "flush-group"]
        self.assertEqual(fg2, [], "an atomic CacheContext+write() fn must NOT fire flush-group (cited-NEGATIVE)")

    def test_temporal_snapshot_pair_dropped_not_a_conservation(self):
        # FP drain (morpho firstTotalAssets<->_totalAssets 2026-07-08): a conserved-with PAIR
        # of two TEMPORAL variants of the same root (firstTotalAssets vs _totalAssets = the
        # same totalAssets before/after) is a snapshot/delta pair, NOT a must-move-together
        # conservation. Precise (edge-level): a REAL cross-root pair (idleAssets<->_totalAssets)
        # is KEPT; only same-root temporal pairs drop.
        self.assertTrue(scg._same_temporal_quantity("firstTotalAssets", "_totalAssets"))
        self.assertTrue(scg._same_temporal_quantity("newTotalAssets", "lastTotalAssets"))
        self.assertFalse(scg._same_temporal_quantity("idleAssets", "_totalAssets"),
                         "different roots (idle vs total) is a REAL coupling, not a snapshot")
        self.assertFalse(scg._same_temporal_quantity("shares", "assets"))
        # end-to-end: distribute writes {firstTotalAssets, _totalAssets, poolShares}; a
        # subset-writer 'skim' writes {firstTotalAssets}. The firstTotalAssets<->_totalAssets
        # PAIR must NOT emit an edge (snapshot); firstTotalAssets<->poolShares MAY.
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "distribute", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["firstTotalAssets", "_totalAssets", "poolShares"]},
            {"file": "V.sol", "function": "skim", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["firstTotalAssets"]},
        ])
        acct = {}
        edges = scg._conservation_edges(ws, acct=acct)
        cw = [e for e in edges if e["kind"] == "conserved-with"]
        pairs = {frozenset((e["cell_a"], e["cell_b"])) for e in cw}
        self.assertNotIn(frozenset(("firstTotalAssets", "_totalAssets")), pairs,
                         "a same-root temporal snapshot pair must NOT be a conserved-with edge")
        self.assertGreaterEqual(acct.get("edges_dropped_temporal_snapshot", 0), 1)

    def test_sink_cell_noise_filter_grounds_only_real_fields(self):
        # cell-quality (tick-29): sink.cell noise (collections-internal type/var names -
        # IndexedMap/keyset/refKeys/m/Store) must NOT be consumed as a persistent cell - only
        # EXPORTED keeper fields are real (Vaults/Balances). Measured NUVA: dropped 2009->1463
        # noise-inflated pairs, leaving 7 genuine keeper cells.
        self.assertFalse(scg._is_noise_cell("Vaults"))
        self.assertFalse(scg._is_noise_cell("PayoutVerificationSet"))
        for noise in ("IndexedMap", "keyset", "refKeys", "m", "Store", "Sequence", "NoValue"):
            self.assertTrue(scg._is_noise_cell(noise), f"{noise} must be filtered as noise")
        # a Go state-write sink whose cell is NOISE must NOT resolve; a real-field one must.
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        recs = []
        for i, (var, cell) in enumerate([("noiseVar", "IndexedMap"), ("realVar", "Vaults")]):
            r = df.new_path(
                f"g{i}", "go", "backward", "go-ssa",
                source={"kind": "param", "fn": "(*x.K).F", "var": var, "file": "k.go", "line": 2},
                sink={"kind": "state-write", "callee": "(collections.Map[K,V]).Set", "arg_pos": 2,
                      "fn": "(*x.K).F", "cell": cell, "file": "k.go", "line": 9}, hops=[])
            r["sink"]["cell"] = cell
            recs.append(r)
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), recs)
        n2c = scg._name_to_cell(ws)
        self.assertEqual(n2c.get(("(*x.K).F", "realVar")), "Vaults", "real keeper field must resolve")
        self.assertNotIn(("(*x.K).F", "noiseVar"), n2c, "noise cell (IndexedMap) must NOT resolve")

    def test_go_feeder_degraded_status_keys_on_degrade_record(self):
        # anti-silent-suppression, CORRECTED (2026-07-08 cross-ws sweep): the degraded-feeder
        # status keys on an actual Go-arm DEGRADE RECORD (build/load/timeout/panic), NOT on
        # "sinks-without-cell". A DEGRADE record means the go-dataflow arm genuinely failed
        # (NUVA: timeout+panic; sei: packages.Load err) -> the coupled-state surface was NOT
        # covered -> LOUD degraded status that blocks done under STRICT.
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = self._ws_with_vmf([
            {"file": "k.go", "function": "(*x.Keeper).Reconcile", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["vaultShares", "stakingShares"]},
        ])
        rec = df.new_path(
            "g0", "go", "backward", "go-ssa",
            source={"kind": "none", "fn": None, "var": None, "file": None, "line": None},
            sink={"kind": "none", "callee": None, "arg_pos": None, "fn": None,
                  "file": None, "line": None},
            hops=[])
        rec["degraded"] = True
        rec["degrade_reason"] = "run failure: go-dataflow run timed out (900s)"
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        self.assertTrue(acct.get("slice_go_arm_degraded"),
                        "a Go-arm degrade record must set slice_go_arm_degraded")
        self.assertEqual(acct.get("slice_resolution_status"), "0-go-feeder-degraded",
                         "a genuinely degraded Go arm must report the LOUD degraded status")

    def test_pure_calculator_drained_but_persisting_fn_kept(self):
        # FP drain (NUVA interest.go CalculatePeriods 2026-07-08): a fn that neither TRANSFERS
        # (transfer_hit False) NOR PERSISTS (no state-write sink in the slice) is a pure
        # calculator - VMF's Go regex mis-counts local param reassignments as ledger writes,
        # so it seeds a spurious "conserved set". It must be DRAINED. But a fn that persists
        # via a state-write sink (even with transfer_hit False - a Sol/Rust accounting fn)
        # must be KEPT (the over-drain that zeroed strata when keyed on grounding is fixed).
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = self._ws_with_vmf([
            {"file": "calc.go", "function": "CalcPeriods", "language": "go",
             "transfer_hit": False, "ledger_write_evidence": ["vaultShares", "stakingShares"]},
            {"file": "acct.go", "function": "Accrue", "language": "go",
             "transfer_hit": False, "ledger_write_evidence": ["vaultShares", "stakingShares"]},
        ])
        # slice: Accrue PERSISTS (state-write sink); CalcPeriods has NO persisting sink.
        rec = df.new_path(
            "g0", "go", "backward", "go-ssa",
            source={"kind": "param", "fn": "Accrue", "var": "vaultShares", "file": "acct.go", "line": 2},
            sink={"kind": "state-write", "callee": "(collections.Map[K,V]).Set", "arg_pos": 2,
                  "fn": "Accrue", "cell": "Vaults", "file": "acct.go", "line": 9},
            hops=[])
        rec["sink"]["cell"] = "Vaults"
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        self.assertGreaterEqual(acct.get("excluded_pure_calc", 0), 1,
                                "the pure-calc CalcPeriods (no transfer, no persist) must be drained")
        fns = {e["fn"] for e in acct.get("surviving_examples", [])}
        self.assertNotIn("CalcPeriods", fns, "pure calculator must NOT survive as a conserved set")
        self.assertIn("Accrue", fns, "a persisting fn (state-write sink) must be KEPT despite transfer_hit=False")

    def test_healthy_noncosmos_go_sinks_without_cell_NOT_flagged(self):
        # REGRESSION for the false-positive the cross-ws sweep caught (polygon = bor/cometbft,
        # a go-ethereum fork, NOT cosmos-sdk): its state-writes legitimately carry NO
        # collection cell and it has ZERO degrade records. It must NOT be flagged degraded -
        # the old sinks-without-cell heuristic wrongly did, and would have false-blocked it.
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = self._ws_with_vmf([
            {"file": "state.go", "function": "(*StateDB).SetBalance", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["amount"]},
        ])
        rec = df.new_path(
            "g0", "go", "backward", "go-ssa",
            source={"kind": "param", "fn": "(*StateDB).SetBalance", "var": "amount",
                    "file": "state.go", "line": 2},
            sink={"kind": "state-write", "callee": "(*state.StateDB).setStateObject",
                  "arg_pos": 1, "fn": "(*StateDB).SetBalance", "file": "state.go", "line": 9},
            hops=[])  # NO cell (non-cosmos), and NO degrade record
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        self.assertFalse(acct.get("slice_go_arm_degraded"),
                         "a healthy non-cosmos Go arm (0 degrade records) must NOT be flagged")
        self.assertNotEqual(acct.get("slice_resolution_status"), "0-go-feeder-degraded",
                            "sinks-without-cell + NO degrade record is healthy non-cosmos, NOT degraded")

    def test_slice_resolution_status_inapplicable_on_identity_hops(self):
        # anti-silent-suppression: a 0-pair resolution must be CHARACTERIZED - broken vs
        # inapplicable. A slice whose storage hops are all IDENTITY (from==to, a config
        # `x=x` write) has no local->distinct-cell flow to resolve -> 0 is CORRECT, not a
        # failure (NUVA: 861 identity hops). The accounting must say so.
        df = _load("dataflow_schema", "dataflow_schema.py")
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "f", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["shareA", "shareB"]},
        ])
        # identity storage hop: from_var == to_var (a param/config write, nothing to map).
        rec = df.new_path(
            "p_id", "solidity", "backward", "slither-ssa",
            source={"kind": "param", "fn": "f", "var": "asset", "file": "V.sol", "line": 2},
            sink={"kind": "state-write", "callee": None, "arg_pos": None,
                  "fn": "f", "file": "V.sol", "line": 2},
            hops=[{"from_var": "asset", "to_var": "asset", "fn": "f", "via": "storage",
                   "file": "V.sol", "line": 2, "ir": "", "guarded": False}])
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        self.assertEqual(acct.get("slice_resolution_pairs"), 0)
        self.assertEqual(acct.get("slice_resolution_status"),
                         "0-inapplicable-only-identity-hops")
        self.assertEqual(acct.get("slice_identity_hops"), 1)
        self.assertEqual(acct.get("slice_distinct_flow_hops"), 0)

    def test_slice_resolution_status_resolved_on_distinct_flow(self):
        # a real local->distinct-cell flow -> status 'resolved', pairs > 0.
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "distribute", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["poolLocal"]},
        ])
        self._write_slice(ws, [("distribute", "poolLocal", "poolShares")])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        self.assertEqual(acct.get("slice_resolution_status"), "resolved")
        self.assertGreater(acct.get("slice_resolution_pairs", 0), 0)
        self.assertGreater(acct.get("slice_distinct_flow_hops", 0), 0)

    def test_slice_resolution_status_no_slice(self):
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "f", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["shareA", "shareB"]},
        ])
        acct = {}
        scg._conservation_edges(ws, acct=acct)  # no dataflow_paths.jsonl
        self.assertEqual(acct.get("slice_resolution_status"), "0-no-slice-storage-hops")

    def test_persistent_resolution_falls_back_without_slice(self):
        # no slice -> identity fallback -> the ORIGINAL local-name behaviour is preserved
        # (a genuine same-name subset writer still fires, tagged local-name-fallback).
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "accrue", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveAsset", "reserveNav"]},
            {"file": "V.sol", "function": "reduce", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveNav"]},
        ])
        edges = scg._conservation_edges(ws)
        cw = [e for e in edges if e["kind"] == "conserved-with"]
        self.assertTrue(cw, "same-name subset writer must still fire without a slice")
        self.assertEqual(cw[0]["evidence"]["cell_resolution"], "local-name-fallback")

    def test_cross_domain_conservation_fires_on_transfer_asymmetry(self):
        # 10th kind (task_ea6aee1a): a share cell whose writers DISAGREE on the paired
        # external value-move - mintShares moves the asset (balanced), badMint omits it
        # (unbalanced) -> badMint is a cross-domain-conservation violator (inflation).
        ws = self._ws_with_vmf([
            {"file": "k.go", "function": "mintShares", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["totalShares"]},
            {"file": "k.go", "function": "badMint", "language": "go",
             "transfer_hit": False, "ledger_write_evidence": ["totalShares"]},
        ])
        edges = scg._cross_domain_conservation_edges(ws)
        xd = [e for e in edges if e["kind"] == "cross-domain-conservation"]
        self.assertTrue(xd, "transfer asymmetry on a share cell must fire the 10th kind")
        e = xd[0]
        self.assertEqual(e["cell_a"], "totalShares")
        self.assertEqual(e["cell_b"], "external:underlying-asset-balance")
        self.assertEqual(e["confidence"], "semantic-ssa")
        self.assertEqual(e["impact_class"], "value-conservation-break")
        self.assertTrue(e["evidence"]["promotable"])
        self.assertTrue(any(v["fn"] == "badMint" for v in e["violators"]),
                        "the no-transfer writer is the violator")
        self.assertFalse(any(v["fn"] == "mintShares" for v in e["violators"]))

    def test_cross_domain_all_balanced_is_cited_clean(self):
        # every share-writer pairs with a transfer -> NO edge (cited-clean, e.g. NUVA).
        ws = self._ws_with_vmf([
            {"file": "k.go", "function": "swapIn", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["totalShares"]},
            {"file": "k.go", "function": "swapOut", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["totalShares"]},
        ])
        acct = {}
        edges = scg._cross_domain_conservation_edges(ws, acct=acct)
        self.assertEqual([e for e in edges if e["kind"] == "cross-domain-conservation"], [],
                         "all-balanced share writers must be cited-clean, not a false edge")
        self.assertEqual(acct.get("cross_domain_asymmetric_cells"), 0)
        self.assertGreaterEqual(acct.get("cross_domain_share_writers", 0), 2)

    def test_cross_domain_dual_accounting_fires_marker_vs_field(self):
        # NUVA truth: BridgeBurnShares changes the share MARKER coin supply (value_move
        # True, EMPTY ledger field) but SwapIn writes the TotalShares FIELD - a dual
        # accounting. Once a field-writer establishes the coupling, the marker-only mover
        # is a VIOLATOR (marker moves without TotalShares) -> a fired dual-accounting edge.
        ws = self._ws_with_vmf([
            {"file": "msg_server.go", "function": "BridgeBurnShares", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": []},
            {"file": "vault.go", "function": "SwapIn", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["TotalShares"]},
        ])
        acct = {}
        edges = scg._cross_domain_conservation_edges(ws, acct=acct)
        dual = [e for e in edges
                if e["evidence"].get("tier") == "cross-domain-conservation-dual-accounting"]
        self.assertTrue(dual, "marker mover vs a field-writer must fire a dual-accounting edge")
        e = dual[0]
        self.assertEqual(e["cell_a"], "TotalShares")
        self.assertEqual(e["cell_b"], "external:share-marker-supply")
        self.assertEqual(e["confidence"], "semantic-ssa")
        self.assertTrue(e["evidence"]["promotable"])
        self.assertTrue(any(v["fn"] == "BridgeBurnShares" for v in e["violators"]))
        # now ASSESSED (a field-writer exists to couple against), not blind-incomplete.
        self.assertTrue(acct.get("cross_domain_assessment_complete"))
        self.assertEqual(acct.get("cross_domain_dual_accounting_edges"), 1)

    def test_cross_domain_marker_mover_unassessable_without_field_writer(self):
        # a marker mover with NO field-writer to couple against stays genuinely
        # UNASSESSABLE (nothing establishes the coupling) -> INCOMPLETE, no fabricated edge.
        ws = self._ws_with_vmf([
            {"file": "msg_server.go", "function": "BridgeBurnShares", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": []},
        ])
        acct = {}
        edges = scg._cross_domain_conservation_edges(ws, acct=acct)
        self.assertEqual([e for e in edges
                          if e["kind"] == "cross-domain-conservation"], [])
        self.assertFalse(acct.get("cross_domain_assessment_complete"))
        self.assertIn("BridgeBurnShares",
                      acct.get("cross_domain_unassessable_share_movers", []))

    def test_cross_domain_complete_when_no_marker_mover(self):
        # no marker-based share mover -> the assessment IS complete.
        ws = self._ws_with_vmf([
            {"file": "vault.go", "function": "SwapIn", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["TotalShares"]},
        ])
        acct = {}
        scg._cross_domain_conservation_edges(ws, acct=acct)
        self.assertTrue(acct.get("cross_domain_assessment_complete"))
        self.assertEqual(acct.get("cross_domain_unassessable_share_movers"), [])

    def test_cross_domain_config_fn_excluded(self):
        # a config/init fn writing a share field is not a value-conservation writer.
        ws = self._ws_with_vmf([
            {"file": "k.go", "function": "initialize", "language": "go",
             "transfer_hit": False, "ledger_write_evidence": ["totalShares"]},
            {"file": "k.go", "function": "mintShares", "language": "go",
             "transfer_hit": True, "ledger_write_evidence": ["totalShares"]},
        ])
        edges = scg._cross_domain_conservation_edges(ws)
        # initialize is excluded -> only the balanced mintShares remains -> no asymmetry.
        self.assertEqual([e for e in edges if e["kind"] == "cross-domain-conservation"], [])

    def test_conserved_accounting_records_config_fn_exclusion(self):
        # the exclusion COUNTS must be visible so an over-broad drain is reviewable.
        ws = self._ws_with_vmf([
            {"file": "M.sol", "function": "initialize", "language": "sol",
             "transfer_hit": False,
             "ledger_write_evidence": ["shareToken", "crossChainVault"]},
        ])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        self.assertEqual(acct["multi_field_movers"], 1)
        self.assertEqual(acct["excluded_config_fn"], 1,
                         "config-fn exclusion must be counted, not silent")
        self.assertEqual(acct["surviving_conserved_sets"], 0)
        self.assertFalse(acct.get("no_subset_writer"),
                         "no surviving set -> not the atomic-writer signal")

    def test_conserved_accounting_absent_when_no_acct_passed(self):
        # backward-compat: callers that pass no acct get identical behaviour.
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "accrue", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveAsset", "reserveNav"]},
            {"file": "V.sol", "function": "reduce", "language": "sol",
             "transfer_hit": True, "ledger_write_evidence": ["reserveNav"]},
        ])
        edges = scg._conservation_edges(ws)  # no acct
        self.assertTrue(edges, "edge emission unchanged when acct omitted")

    def test_p2b_bound_field_excluded_from_conservation(self):
        # cross-workspace FP drain (tick-13): a BOUND/limit (supplyCap / maxAssets /
        # minShares) is a config ceiling, NOT a conserved balance - pairing it into a
        # conservation set is an FP (measured morpho supplyCap<->shares, strata maxAssets).
        # camelCase-aware: drops maxAssets/supplyCap, keeps `capital`/`minted`.
        self.assertTrue(scg._is_bound_field("supplyCap"))
        self.assertTrue(scg._is_bound_field("maxAssets"))
        self.assertTrue(scg._is_bound_field("minShares"))
        self.assertFalse(scg._is_bound_field("capital"))
        self.assertFalse(scg._is_bound_field("minted"))
        self.assertFalse(scg._is_bound_field("shares"))
        # a fn writing {shares, supplyCap} -> only `shares` survives -> no >=2 set, no FP edge
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "supply", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["shares", "supplyCap"]},
            {"file": "V.sol", "function": "reduce", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["supplyCap"]},
        ])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        cw = [e for e in scs.read_edges(ws) if e["kind"] == "conserved-with"]
        self.assertFalse(any("supplyCap" in (e["cell_a"], e["cell_b"]) for e in cw),
                         f"a bound/cap field must not be a conserved cell: {cw}")
        self.assertGreaterEqual(acct.get("field_dropped_bound", 0), 1)

    def test_p2b_price_field_excluded_from_conservation(self):
        # cross-workspace FP drain (tick-16): a PRICE / oracle-quote (collateralPrice /
        # oraclePrice / sharePrice) is a per-unit exchange rate, NOT a conserved balance -
        # pairing it into a conservation set is an FP (measured morpho collateralPrice<->
        # badDebtAssets/repaidAssets/position, 6/51 conserved-with edges).
        # endswith-precise: drops *Price, keeps `pricedAssets` (an amount valued AT a price).
        self.assertTrue(scg._is_price_field("collateralPrice"))
        self.assertTrue(scg._is_price_field("oraclePrice"))
        self.assertTrue(scg._is_price_field("sharePrice"))
        self.assertFalse(scg._is_price_field("pricedAssets"),
                         "an amount valued at a price is still a conserved quantity")
        self.assertFalse(scg._is_price_field("assets"))
        # a fn writing {badDebtAssets, collateralPrice} -> only the value survives -> no FP edge
        ws = self._ws_with_vmf([
            {"file": "L.sol", "function": "liquidate", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["badDebtAssets", "collateralPrice"]},
            {"file": "L.sol", "function": "poke", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["collateralPrice"]},
        ])
        acct = {}
        scg._conservation_edges(ws, acct=acct)
        cw = [e for e in scs.read_edges(ws) if e["kind"] == "conserved-with"]
        self.assertFalse(any("collateralPrice" in (e["cell_a"], e["cell_b"]) for e in cw),
                         f"a price field must not be a conserved cell: {cw}")
        self.assertGreaterEqual(acct.get("field_dropped_price", 0), 1)

    def test_p2b_rate_field_excluded_from_conservation(self):
        # a bps/rate field is a parameter, not a conserved balance -> not paired.
        ws = self._ws_with_vmf([
            {"file": "V.sol", "function": "f", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["depositAsset", "feeBps"]},
            {"file": "V.sol", "function": "g", "language": "sol", "transfer_hit": True,
             "ledger_write_evidence": ["depositAsset"]},
        ])
        scg.main(["--workspace", str(ws), "--emit"])
        cw = [e for e in scs.read_edges(ws) if e["kind"] == "conserved-with"]
        self.assertFalse(any("feeBps" in (e["cell_a"], e["cell_b"]) for e in cw),
                         f"a bps rate field must not be a conserved cell: {cw}")

    def test_p2b_ordering_reclassification(self):
        # a derived-from over a monotonic counter (version) is retagged 'ordering'.
        src = """package x
func (s *S) set(v int){ s.version=v; s.commitIndex=s.version+1 }
func (s *S) bump(){ s.version=s.version+1 }
"""
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / "s.go").write_text(src)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "s.go", "function": "bump"}) + "\n")
        # no dataflow slice -> syntactic, but ordering reclassification still applies
        scg.main(["--workspace", str(ws), "--emit"])
        edges = scs.read_edges(ws)
        self.assertTrue(any(e["kind"] == "ordering" for e in edges),
                        f"version<->commit derived coupling must retag ordering: "
                        f"{[e['kind'] for e in edges]}")

    def test_is_denied_helper(self):
        for p in ("x/go-ethereum/core/chain.go", "a/tracers/call.go",
                  "pkg/foo_test.go", "sim/blocksim.go", "b/vendor/lib.go"):
            self.assertTrue(scg._is_denied(p), p)
        for p in ("src/vault/keeper/vault.go", "contracts/Accounting.sol"):
            self.assertFalse(scg._is_denied(p), p)

    def test_flush_shape_maps_to_flush_group_kind(self):
        aptos = """impl M {
  fn r(&self, e: &E) {
    if a { e.flush_all_caches(); self.module_cache.flush(); }
    else { e.module_id_pool().flush(); e.struct_name_index_map().flush(); self.module_cache.flush(); }
  }
}"""
        ws = Path(tempfile.mkdtemp())
        f = ws / "m.rs"
        f.write_text(aptos)
        # capture edges via single-file (printed) - just assert no crash + emit
        self.assertEqual(scg.main(["--file", str(f), "--emit"]), 0)


class TFreshness(unittest.TestCase):
    def test_p8_asymmetric_freshness_fires(self):
        # price is used under a staleness gate in readGuarded, but consume() reads it
        # without the gate -> freshness-coupled edge (the 9th kind).
        src = """contract O {
  function setPrice(uint p, uint t) external { price = p; priceUpdatedAt = t; }
  function readGuarded() external view returns (uint) {
    require(block.timestamp <= priceUpdatedAt + maxStale, "stale");
    return price;
  }
  function consume() external { settlement = price * qty; }
}"""
        rows = scg._freshness_edges(src, "O.sol")
        self.assertTrue(rows, f"asymmetric freshness must fire, got {rows}")
        e = rows[0]
        self.assertEqual(e["kind"], "freshness-coupled-to-external-clock")
        self.assertEqual(e["cell_a"], "price")
        self.assertEqual(e["impact_class"], "stale-state-freshness-desync")
        self.assertFalse(e["evidence"]["promotable"], "freshness is advisory until probed")
        self.assertTrue(any(v["fn"] == "consume" for v in e["violators"]))

    def test_p8_symmetric_no_fire(self):
        # every reader of price applies the freshness gate -> no asymmetry -> no edge.
        src = """contract O {
  function setPrice(uint p, uint t) external { price = p; priceUpdatedAt = t; }
  function a() external view returns (uint) { require(block.timestamp <= priceUpdatedAt + maxStale); return price; }
  function b() external view returns (uint) { require(block.timestamp <= priceUpdatedAt + maxStale); return price * 2; }
}"""
        self.assertEqual(scg._freshness_edges(src, "O.sol"), [])

    def test_p8_no_freshness_token_no_fire(self):
        # a plain getter/consumer pair with NO freshness gate anywhere -> not this class.
        src = """contract O {
  function setP(uint p) external { price = p; }
  function c() external { total = price * qty; }
}"""
        self.assertEqual(scg._freshness_edges(src, "O.sol"), [])


class TGoRustNonVacuity(unittest.TestCase):
    """P9: prove the SEMANTIC tier (dataflow-storage-grounded) FIRES on Go AND Rust,
    not just Solidity. The workflow found nuva/morpho/strata emit 0 edges; a 0-edge
    NON-Solidity result must NOT be treated as clean until this proof passes - else a
    real Go/Rust coupling silently false-greens."""

    def _fixture(self, rel, src, a, b, fn):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / rel).write_text(src)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": rel, "function": fn}) + "\n")
        df = _load("dataflow_schema", "dataflow_schema.py")
        lang = {"go": "go", "rs": "rust"}[rel.rsplit(".", 1)[1]]
        rec = df.new_path(
            "p1", lang, "backward", "ssa",
            source={"kind": "param", "fn": fn, "var": a, "file": rel, "line": 2},
            sink={"kind": "state-write", "callee": None, "arg_pos": None,
                  "fn": fn, "file": rel, "line": 2},
            hops=[{"from_var": a, "to_var": b, "fn": fn, "via": "storage",
                   "file": rel, "line": 2, "ir": "", "guarded": False}])
        df.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])
        return ws

    def test_go_semantic_tier_fires(self):
        src = ("package x\n"
               "func (s *S) Set(v int) { s.version = v; s.commitSet = s.version + 1 }\n"
               "func (s *S) Bump() { s.version = s.version + 1 }\n")
        ws = self._fixture("store.go", src, "version", "commitSet", "Set")
        scg.main(["--workspace", str(ws), "--emit"])
        edges = scs.read_edges(ws)
        prom = [e for e in edges if e["evidence"].get("promotable")]
        self.assertTrue(prom, f"Go semantic tier must FIRE on a storage-grounded "
                              f"coupling (non-vacuity), got {edges}")
        self.assertTrue(all(e["language"] == "go" for e in prom))
        self.assertTrue(all(e["evidence"]["persistent_state"] for e in prom))

    def test_rust_semantic_tier_fires(self):
        src = ("impl S {\n"
               "  fn set(&mut self, v: u64) { self.version = v; self.commit_set = self.version + 1; }\n"
               "  fn bump(&mut self) { self.version = self.version + 1; }\n"
               "}\n")
        ws = self._fixture("store.rs", src, "version", "commit_set", "set")
        scg.main(["--workspace", str(ws), "--emit"])
        edges = scs.read_edges(ws)
        prom = [e for e in edges if e["evidence"].get("promotable")]
        self.assertTrue(prom, f"Rust semantic tier must FIRE on a storage-grounded "
                              f"coupling (non-vacuity), got {edges}")
        self.assertTrue(all(e["language"] == "rust" for e in prom))

    def test_nonvacuity_guard_zero_edges_needs_a_slice(self):
        # a Go ws with NO dataflow slice -> 0 promotable (degrade tier). This is the
        # false-green trap: 0 promotable is only "clean" WITH a slice present.
        src = ("package x\n"
               "func (s *S) Set(v int) { s.version = v; s.commitSet = s.version + 1 }\n"
               "func (s *S) Bump() { s.version = s.version + 1 }\n")
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / "store.go").write_text(src)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "store.go", "function": "Bump"}) + "\n")
        scg.main(["--workspace", str(ws), "--emit"])
        prom = [e for e in scs.read_edges(ws) if e["evidence"].get("promotable")]
        self.assertEqual(prom, [], "no slice -> no promotable (degrade tier)")


if __name__ == "__main__":
    unittest.main()
