#!/usr/bin/env python3
"""Guard tests for the GENERIC fork+etch cross-function mechanics.

Pins:
  - tools/lib/fork_etch_link.py: linkReferences -> offline-linked bytecode with
    NO __$ residue; 20-byte enforcement; fail-closed on missing lib / leftover
    placeholder; deterministic fixed lib-addr assignment.
  - tools/cross-function-fork-etch-producer.py: parses fork config + recipe
    registry; merges canonical file preserving per_function rows; records a
    fail-closed verdict (never silent PASS) when forge/RPC/recipe is absent;
    parses a REAL forge differential flip ONLY as mutation_verified=true.
  - tools/templates/ForkEtchCrossFunctionBase.sol: the generic base test the
    producer's emitted harness extends - present + exposes the reusable hooks.

These are PURE unit tests: no network, no forge, no live fork. The end-to-end
generic reproduction of the proven SiloFacet kill is verified separately on the
live fork (reported in the structured output), not here.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(filename: str, modname: str):
    spec = importlib.util.spec_from_file_location(modname, str(_TOOLS / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


# load the link lib directly from tools/lib
sys.path.insert(0, str(_TOOLS / "lib"))
import fork_etch_link as FXL  # noqa: E402

PROD = _load("cross-function-fork-etch-producer.py", "_t_xfep")


def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TestLinkBytecode(unittest.TestCase):
    """The single hardest, most-load-bearing piece: offline library linking."""

    def _placeholder(self) -> str:
        # solc/forge placeholder: __$ + 34 hex + $__ = 40 chars (20 bytes).
        return "__$" + ("a" * 34) + "$__"

    def test_link_replaces_placeholder_no_residue(self):
        ph = self._placeholder()
        # bytecode: 4 bytes lead, 20-byte placeholder, 4 bytes tail.
        lead = "deadbeef"
        tail = "cafebabe"
        bc = "0x" + lead + ph + tail
        # placeholder starts at byte 4 (after 'deadbeef' = 4 bytes), length 20.
        link_refs = {"src/Lib.sol": {"MyLib": [{"start": 4, "length": 20}]}}
        addrs = {"MyLib": "0x" + "11" * 20}
        linked = FXL.link_bytecode(bc, link_refs, addrs)
        self.assertNotIn("__$", linked)
        # the address replaced exactly the placeholder span.
        self.assertEqual(linked, lead + ("11" * 20) + tail)
        # idempotent surrounding bytes preserved.
        self.assertTrue(linked.startswith(lead))
        self.assertTrue(linked.endswith(tail))

    def test_multiple_refs_and_libs_all_resolved(self):
        ph = self._placeholder()
        # two MyLib refs + one OtherLib ref, interleaved.
        # layout (bytes): [4 lead][20 MyLib][2 mid][20 OtherLib][2 mid2][20 MyLib]
        lead = "00" * 4
        mid = "abcd"
        mid2 = "ef01"
        bc = "0x" + lead + ph + mid + ph + mid2 + ph
        link_refs = {
            "src/A.sol": {"MyLib": [{"start": 4, "length": 20},
                                    {"start": 4 + 20 + 2 + 20 + 2, "length": 20}]},
            "src/B.sol": {"OtherLib": [{"start": 4 + 20 + 2, "length": 20}]},
        }
        addrs = {"MyLib": "0x" + "22" * 20, "OtherLib": "0x" + "33" * 20}
        linked = FXL.link_bytecode(bc, link_refs, addrs)
        self.assertNotIn("__$", linked)
        expect = lead + ("22" * 20) + mid + ("33" * 20) + mid2 + ("22" * 20)
        self.assertEqual(linked, expect)

    def test_missing_library_address_fails_closed(self):
        ph = self._placeholder()
        bc = "0x" + ph
        link_refs = {"src/Lib.sol": {"MyLib": [{"start": 0, "length": 20}]}}
        with self.assertRaises(ValueError):
            FXL.link_bytecode(bc, link_refs, {})  # no addr for MyLib

    def test_non_20_byte_reference_rejected(self):
        bc = "0x" + ("aa" * 32)
        link_refs = {"src/Lib.sol": {"MyLib": [{"start": 0, "length": 32}]}}
        with self.assertRaises(ValueError):
            FXL.link_bytecode(bc, link_refs, {"MyLib": "0x" + "11" * 20})

    def test_leftover_placeholder_after_link_raises(self):
        # link_refs only covers ONE of two placeholders -> residue must raise.
        ph = self._placeholder()
        bc = "0x" + ph + "abcd" + ph
        link_refs = {"src/Lib.sol": {"MyLib": [{"start": 0, "length": 20}]}}
        with self.assertRaises(ValueError):
            FXL.link_bytecode(bc, link_refs, {"MyLib": "0x" + "11" * 20})

    def test_address_normalization_pads_short_addr(self):
        ph = self._placeholder()
        bc = "0x" + ph
        link_refs = {"src/Lib.sol": {"MyLib": [{"start": 0, "length": 20}]}}
        # short hex addr -> left-zero-padded to 20 bytes.
        linked = FXL.link_bytecode(bc, link_refs, {"MyLib": "0xa5110"})
        self.assertEqual(linked, "0" * 35 + "a5110")
        self.assertEqual(len(linked), 40)

    def test_int_address_accepted(self):
        ph = self._placeholder()
        bc = "0x" + ph
        link_refs = {"src/Lib.sol": {"MyLib": [{"start": 0, "length": 20}]}}
        linked = FXL.link_bytecode(bc, link_refs, {"MyLib": 0xA5110})
        self.assertEqual(linked.lower(), ("%040x" % 0xA5110))


class TestLibAddressAssignment(unittest.TestCase):
    def test_deterministic_fixed_addresses(self):
        names = ["LibTokenSilo", "LibSilo", "LibSiloPermit"]
        addrs = FXL.assign_lib_addresses(names)
        # sorted order: LibSilo, LibSiloPermit, LibTokenSilo -> a5110, a5111, a5112
        self.assertEqual(addrs["LibSilo"].lower(), "0x" + "%040x" % 0xA5110)
        self.assertEqual(addrs["LibSiloPermit"].lower(), "0x" + "%040x" % 0xA5111)
        self.assertEqual(addrs["LibTokenSilo"].lower(), "0x" + "%040x" % 0xA5112)
        # stable across calls
        self.assertEqual(addrs, FXL.assign_lib_addresses(names))

    def test_library_names_extracted(self):
        link_refs = {"src/A.sol": {"LibX": [{"start": 0, "length": 20}]},
                     "src/B.sol": {"LibY": [{"start": 40, "length": 20}],
                                   "LibX": [{"start": 80, "length": 20}]}}
        self.assertEqual(FXL.library_names(link_refs), ["LibX", "LibY"])


class TestLinkArtifact(unittest.TestCase):
    """link_artifact reads a forge artifact JSON shape and links it - mirrors the
    real out/SiloFacet.sol/SiloFacet.json shape."""

    def test_link_artifact_from_forge_json(self):
        ph = "__$" + ("b" * 34) + "$__"
        obj = "0x" + "60" + ph + "00"  # 1 lead byte, placeholder at byte 1, 1 tail
        artifact = {
            "deployedBytecode": {
                "object": obj,
                "linkReferences": {"contracts/Lib.sol": {"LibZ": [{"start": 1, "length": 20}]}},
            }
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Facet.json"
            p.write_text(json.dumps(artifact), encoding="utf-8")
            addrs = FXL.assign_lib_addresses(["LibZ"])
            linked = FXL.link_artifact(p, addrs)
            self.assertTrue(linked.startswith("0x"))
            self.assertNotIn("__$", linked)
            self.assertEqual(linked, "0x60" + addrs["LibZ"][2:] + "00")

    def test_dump_library_bytecode_rejects_unlinked_sublib(self):
        artifact = {"deployedBytecode": {
            "object": "0x60__$" + ("c" * 34) + "$__00",
            "linkReferences": {"x": {"SubLib": [{"start": 1, "length": 20}]}}}}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Lib.json"
            p.write_text(json.dumps(artifact), encoding="utf-8")
            with self.assertRaises(ValueError):
                FXL.dump_library_bytecode(p)


class TestBaseTemplateExists(unittest.TestCase):
    def test_base_template_present_with_hooks(self):
        base = _TOOLS / "templates" / "ForkEtchCrossFunctionBase.sol"
        self.assertTrue(base.is_file(), "ForkEtchCrossFunctionBase.sol must exist")
        text = base.read_text(encoding="utf-8")
        # reusable hooks the producer's emitted harness extends.
        for needle in (
            "abstract contract ForkEtchCrossFunctionBase",
            "_fork()",
            "_facetAddress(",
            "_etchLibs()",
            "_etchFacet(",
            "_roundTripHolds()",       # the per-pair invariant fill-in hook
            "_assertMutantKilled()",   # the reusable kill oracle
            "vm.etch",
            "vm.parseBytes",
        ):
            self.assertIn(needle, text, f"base template missing hook: {needle}")
        # no em/en dashes in the template (formatting rule).
        self.assertNotIn("—", text)
        self.assertNotIn("–", text)


class TestProducerForkConfigAndRecipes(unittest.TestCase):
    def test_parse_fork_config_and_rpc(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / ".auditooor" / "fork_rpc_url.txt",
                   "# comment\nARBITRUM_RPC=https://arb1.arbitrum.io/rpc\n"
                   "DIAMOND=0xD1A0060ba708BC4BCD3DA6C37EFa8deDF015FB70\n"
                   "SiloFacet=0x5678345D444918a38ad9dC7CA1b0C208E1927094\n")
            cfg = PROD.parse_fork_config(ws)
            self.assertEqual(cfg["DIAMOND"], "0xD1A0060ba708BC4BCD3DA6C37EFa8deDF015FB70")
            self.assertEqual(PROD.fork_rpc_url(cfg), "https://arb1.arbitrum.io/rpc")

    def test_no_recipes_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / ".auditooor" / "fork_rpc_url.txt",
                   "ARBITRUM_RPC=https://arb1.arbitrum.io/rpc\n")
            payload = PROD.produce(ws, dry_run=True)
            # No recipe registry -> never a silent PASS; verdict no-recipes.
            self.assertEqual(payload["verdict"], "no-recipes")

    def test_recipe_registry_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / ".auditooor" / "fork_etch_recipes.json",
                   json.dumps({"recipes": [
                       {"requirement": "deposit|withdraw@silo/SiloFacet",
                        "foundry_root": "src/proto", "facet_source": "x.sol",
                        "facet_artifact": "out/x.sol/X.json"}]}))
            recs = PROD.read_recipes(ws)
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["requirement"], "deposit|withdraw@silo/SiloFacet")

    def test_merge_preserves_per_function_rows(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # pre-existing canonical file with a per_function verified row.
            _write(ws / ".auditooor" / "mutation_verify_coverage.json",
                   json.dumps({
                       "schema": PROD.SCHEMA,
                       "per_function": [{"function": "f", "mutation_verified": True,
                                         "verdict": "killed"}],
                       "cross_function": [],
                   }))
            cross = [{"requirement": "p|q", "mutation_verified": False, "verdict": "vacuous"}]
            payload = PROD.merge_into_canonical(ws, cross, "ok")
            # per_function preserved AND counted.
            self.assertEqual(payload["counts"]["per_function_total"], 1)
            self.assertEqual(payload["counts"]["per_function_verified"], 1)
            self.assertEqual(payload["counts"]["cross_function_total"], 1)
            self.assertEqual(payload["counts"]["cross_function_verified"], 0)

    def test_merge_by_label_preserves_unprocessed_pairs(self):
        """A `--only`/per-pair run must NOT clobber other pairs' verified records.

        Regression 2026-06-14: merge_into_canonical REPLACED the whole
        cross_function array with the current run's records, so an `--only
        convert` run wiped the silo/market/field kills from a prior full pass
        (last-writer-wins race). The merge now joins BY REQUIREMENT LABEL: the
        new run wins for the labels it processed, every other label is
        preserved."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / ".auditooor" / "mutation_verify_coverage.json",
                   json.dumps({
                       "schema": PROD.SCHEMA,
                       "per_function": [],
                       "cross_function": [
                           {"requirement": "deposit|withdraw@silo/SiloFacet",
                            "mutation_verified": True, "verdict": "killed"},
                           {"requirement": "createPodListing|fillPodListing@market/MarketplaceFacet",
                            "mutation_verified": True, "verdict": "killed"},
                       ],
                   }))
            # an --only run that processed ONLY the convert pair.
            cross = [{"requirement": "convert|antiConvert@silo/ConvertFacet",
                      "mutation_verified": True, "verdict": "killed"}]
            payload = PROD.merge_into_canonical(ws, cross, "ok")
            labels = {r["requirement"] for r in payload["cross_function"]}
            self.assertIn("deposit|withdraw@silo/SiloFacet", labels,
                          "silo kill must survive an --only convert run")
            self.assertIn("createPodListing|fillPodListing@market/MarketplaceFacet", labels,
                          "market kill must survive an --only convert run")
            self.assertIn("convert|antiConvert@silo/ConvertFacet", labels,
                          "convert kill must be added")
            self.assertEqual(payload["counts"]["cross_function_total"], 3)
            self.assertEqual(payload["counts"]["cross_function_verified"], 3)

    def test_merge_by_label_new_result_wins_for_processed_label(self):
        """If this run REPROCESSES a label, its fresher result wins (incl. an
        honest downgrade to vacuous) - no stale killed record is retained for a
        label the run actually touched."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / ".auditooor" / "mutation_verify_coverage.json",
                   json.dumps({
                       "schema": PROD.SCHEMA, "per_function": [],
                       "cross_function": [
                           {"requirement": "deposit|withdraw@silo/SiloFacet",
                            "mutation_verified": True, "verdict": "killed"},
                       ],
                   }))
            cross = [{"requirement": "deposit|withdraw@silo/SiloFacet",
                      "mutation_verified": False, "verdict": "vacuous"}]
            payload = PROD.merge_into_canonical(ws, cross, "ok")
            self.assertEqual(payload["counts"]["cross_function_total"], 1)
            self.assertEqual(payload["counts"]["cross_function_verified"], 0,
                             "reprocessed label takes the fresh vacuous result")

    def test_canonical_record_only_verified_when_real_flip(self):
        """The canonical record carries mutation_verified=true ONLY when the
        result says so (which only happens on a real forge flip). A vacuous
        result -> false + 'vacuous' verdict token."""
        sibling = PROD._load_sibling_producer()
        self.assertIsNotNone(sibling)
        killed = PROD._canonical_record(sibling, "p|q", {
            "verdict": "non-vacuous", "mutation_verified": True,
            "reason": "differential PASS"})
        self.assertTrue(killed["mutation_verified"])
        self.assertEqual(killed["verdict"], "killed")
        self.assertEqual(killed["mode"], "fork-etch")
        not_killed = PROD._canonical_record(sibling, "p|q", {
            "verdict": "vacuous", "mutation_verified": False,
            "reason": "NO flip"})
        self.assertFalse(not_killed["mutation_verified"])
        self.assertEqual(not_killed["verdict"], "vacuous")


class TestBindingAndIdentity(unittest.TestCase):
    """False-green resistance: the differential harness must etch the recipe's
    OWN clean+mutant hex (binding), and clean must differ from mutant (no-op)."""

    def _setup_ws(self, td, *, clean_body, mutant_body, harness_etches):
        ws = Path(td)
        hroot = ws / "harness"
        _write(hroot / "foundry.toml", "[profile.default]\n")
        _write(hroot / "mutants" / "clean.hex", clean_body)
        _write(hroot / "mutants" / "mutant.hex", mutant_body)
        # harness source references whatever paths `harness_etches` lists.
        etch_lines = "\n".join(
            f'        _etchFacet("{p}");' for p in harness_etches)
        _write(hroot / "test" / "X.t.sol",
               "contract XHarness {\n"
               "  function _etchFacet(string memory f) internal {\n"
               "    vm.etch(addr, vm.parseBytes(vm.readFile(f)));\n"
               "  }\n"
               "  function test_diff() public {\n"
               f"{etch_lines}\n"
               "  }\n"
               "}\n")
        return ws

    def _recipe(self, clean="mutants/clean.hex", mutant="mutants/mutant.hex"):
        return {"requirement": "p|q", "foundry_root": "harness",
                "harness_root": "harness", "match_contract": "XHarness",
                "clean_hex": clean, "mutant_hex": mutant}

    def test_binding_ok_when_harness_etches_recipe_hex(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._setup_ws(td, clean_body="0xdead", mutant_body="0xbeef",
                                harness_etches=["mutants/clean.hex", "mutants/mutant.hex"])
            res = PROD.check_binding_and_identity(ws, self._recipe())
            self.assertTrue(res["ok"], res["reason"])

    def test_binding_fails_when_harness_etches_other_hex(self):
        # The decoupled-harness false-green: recipe builds mutants_noop/* but the
        # harness etches mutants/* (unrelated pre-built kill) -> must NOT bind.
        with tempfile.TemporaryDirectory() as td:
            ws = self._setup_ws(td, clean_body="0xdead", mutant_body="0xbeef",
                                harness_etches=["mutants/clean.hex", "mutants/mutant.hex"])
            # write the noop hex the recipe points at, but the harness does NOT etch it.
            _write(ws / "harness" / "mutants_noop" / "clean.hex", "0x11")
            _write(ws / "harness" / "mutants_noop" / "mutant.hex", "0x22")
            recipe = self._recipe(clean="mutants_noop/clean.hex",
                                  mutant="mutants_noop/mutant.hex")
            res = PROD.check_binding_and_identity(ws, recipe)
            self.assertFalse(res["ok"])
            self.assertIn("DECOUPLED", res["reason"])

    def test_identity_fails_on_noop_mutation(self):
        # clean == mutant -> no-op mutation, cannot kill.
        with tempfile.TemporaryDirectory() as td:
            ws = self._setup_ws(td, clean_body="0xdeadbeef", mutant_body="0xdeadbeef",
                                harness_etches=["mutants/clean.hex", "mutants/mutant.hex"])
            res = PROD.check_binding_and_identity(ws, self._recipe())
            self.assertFalse(res["ok"])
            self.assertIn("no-op", res["reason"])

    def test_binding_matches_helper_call_argument_not_only_readfile(self):
        # The proven bean harness passes the facet hex via _etchFacet("X.hex"),
        # NOT directly inside readFile(. Binding must still detect it.
        with tempfile.TemporaryDirectory() as td:
            ws = self._setup_ws(td, clean_body="0xaa", mutant_body="0xbb",
                                harness_etches=["mutants/clean.hex", "mutants/mutant.hex"])
            res = PROD.check_binding_and_identity(ws, self._recipe())
            self.assertTrue(res["ok"], res["reason"])
            # the literal only appears as an _etchFacet argument, never as
            # readFile("mutants/clean.hex") - proving the broadened matcher works.
            harness_text = (ws / "harness" / "test" / "X.t.sol").read_text()
            self.assertNotIn('readFile("mutants/clean.hex")', harness_text)


class TestDifferentialFlipParsing(unittest.TestCase):
    """run_differential must classify a kill ONLY on a real PASS + 0 failures."""

    def test_flip_parsing_via_monkeypatched_subprocess(self):
        import subprocess as _sp

        class _R:
            def __init__(self, rc, out):
                self.returncode = rc
                self.stdout = out
                self.stderr = ""

        real_run = _sp.run
        # case 1: differential test PASSES, suite 0 failures -> flip True.
        good = ("Ran 1 test for test/X.t.sol:XfnForkFeasibility\n"
                "[PASS] test_03c_differential_clean_vs_mutant() (gas: 4013671)\n"
                "Suite result: ok. 1 passed; 0 failed; 0 skipped\n")
        # case 2: test FAILED -> flip False.
        bad = ("[FAIL: MUTANT NOT KILLED] test_03c_differential_clean_vs_mutant()\n"
               "Suite result: FAILED. 0 passed; 1 failed; 0 skipped\n")
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            recipe = {"foundry_root": ".", "harness_root": ".", "rpc_env": "ARB_RPC",
                      "differential_test": "test_03c_differential_clean_vs_mutant",
                      "match_contract": "XfnForkFeasibility"}
            try:
                _sp.run = lambda *a, **k: _R(0, good)
                res = PROD.run_differential(ws, recipe, "forge", "http://x", 60)
                self.assertTrue(res["flip"])
                self.assertEqual(res["n_fail"], 0)

                _sp.run = lambda *a, **k: _R(1, bad)
                res = PROD.run_differential(ws, recipe, "forge", "http://x", 60)
                self.assertFalse(res["flip"])
                self.assertEqual(res["n_fail"], 1)
            finally:
                _sp.run = real_run


if __name__ == "__main__":
    unittest.main()
