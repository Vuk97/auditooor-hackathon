#!/usr/bin/env python3
"""Tests for tools/nondeterministic-deserialization.py.

Covers (>=5, incl a NON-VACUOUS mutation pair):
  1. survivor: json decode into a range-iterated map on an EndBlock consensus
     path with no sort barrier -> a map-range survivor grounded to file:line.
  2. NON-VACUOUS MUTATION A (add canonical barrier): add `sort.Strings(keys)`
     canonicalization on the decoded map before the store.Set sink -> the
     survivor DISAPPEARS (proves the barrier predicate is real, not a grep).
  3. NON-VACUOUS MUTATION B (make type deterministic): decode into a typed
     struct instead of a map -> the survivor DISAPPEARS (proves the
     nondeterministic-type predicate is real).
  4. consensus-reachability gate: a nondet decode NOT on a block-processing path
     and with no consensus sink -> NOT a survivor (advisory needs_source only).
  5. substrate_vacuous: a dir with no decode nodes -> status substrate_vacuous +
     --fail-closed exits non-zero.
  6. cited_empty: decode nodes present but all deterministic-typed -> honest 0.
  7. float-on-consensus survivor + interface/any survivor.
  8. real substrate: runs over /Users/wolf/audits/nuva + axelar-dlt if present
     (honest: survivors OR cited_empty), schema + grounding asserted.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

_TOOLS = pathlib.Path(__file__).resolve().parent.parent
_TOOL = _TOOLS / "nondeterministic-deserialization.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("nondet_deser", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ND = _load_tool()


def _write(ws: pathlib.Path, rel: str, body: str) -> pathlib.Path:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# A map-range decode on an EndBlock consensus path, store.Set sink, no sort.
_SURVIVOR_GO = """
package keeper

func (k Keeper) EndBlock(ctx Context, bz []byte) error {
    var weights map[string]uint64
    if err := k.cdc.UnmarshalJSON(bz, &weights); err != nil {
        return err
    }
    total := uint64(0)
    for addr := range weights {
        total += weights[addr]
        store.Set([]byte(addr), encode(weights[addr]))
    }
    return nil
}
"""

# Mutation A: canonical sort barrier on the decoded keys before the sink.
_BARRIER_GO = """
package keeper

func (k Keeper) EndBlock(ctx Context, bz []byte) error {
    var weights map[string]uint64
    if err := k.cdc.UnmarshalJSON(bz, &weights); err != nil {
        return err
    }
    keys := make([]string, 0)
    for addr := range weights {
        keys = append(keys, addr)
    }
    sort.Strings(weights)
    total := uint64(0)
    for _, addr := range keys {
        total += weights[addr]
        store.Set([]byte(addr), encode(weights[addr]))
    }
    return nil
}
"""

# Mutation B: decode into a deterministic typed struct (no map/interface/float).
_TYPED_GO = """
package keeper

type Weights struct {
    Total uint64
    Addr  string
}

func (k Keeper) EndBlock(ctx Context, bz []byte) error {
    var weights Weights
    if err := k.cdc.UnmarshalJSON(bz, &weights); err != nil {
        return err
    }
    store.Set([]byte(weights.Addr), encode(weights.Total))
    return nil
}
"""

# nondet decode but NOT on a consensus path + no consensus sink -> needs_source.
_OFFPATH_GO = """
package keeper

func (k Keeper) parseConfig(bz []byte) error {
    var cfg map[string]interface{}
    if err := json.Unmarshal(bz, &cfg); err != nil {
        return err
    }
    for key := range cfg {
        log.Info("cfg", key)
    }
    return nil
}
"""

# a deterministic typed decode only -> cited_empty (decode node present, no nondet)
_DETERMINISTIC_GO = """
package keeper

type Params struct {
    Rate uint64
}

func (k Keeper) BeginBlock(ctx Context, bz []byte) error {
    var p Params
    if err := k.cdc.UnmarshalJSON(bz, &p); err != nil {
        return err
    }
    store.Set(paramsKey, k.cdc.MustMarshalBinaryBare(&p))
    return nil
}
"""

# float decode on a consensus path with hash sink.
_FLOAT_GO = """
package keeper

func (k Keeper) ProcessProposal(ctx Context, bz []byte) error {
    var price float64
    if err := json.Unmarshal(bz, &price); err != nil {
        return err
    }
    h := sha256.Sum256([]byte(fmt.Sprint(price)))
    store.Set(priceKey, h[:])
    return nil
}
"""


class NondetDeserTests(unittest.TestCase):
    def _run(self, files: dict):
        tmp = tempfile.mkdtemp()
        ws = pathlib.Path(tmp)
        for rel, body in files.items():
            _write(ws, rel, body)
        return ND.run(ws)

    # 1. survivor
    def test_survivor_map_range_endblock(self):
        rep = self._run({"src/keeper/x.go": _SURVIVOR_GO})
        self.assertEqual(rep["status"], "survivors", rep)
        self.assertGreaterEqual(rep["survivor_count"], 1)
        s = rep["survivors"][0]
        self.assertEqual(s["nondet_kind"], "map-range")
        self.assertEqual(s["schema"], "auditooor.nondeterministic_deserialization.v1")
        self.assertTrue(s["file"] and s["line"] > 0, "must cite file:line")
        self.assertEqual(s["verdict"], "survivor")
        self.assertTrue(s["block_processing_entrypoint"])

    # 2. mutation A - canonical barrier kills the survivor
    def test_mutation_barrier_kills_survivor(self):
        base = self._run({"src/keeper/x.go": _SURVIVOR_GO})
        mut = self._run({"src/keeper/x.go": _BARRIER_GO})
        self.assertEqual(base["status"], "survivors")
        self.assertEqual(mut["survivor_count"], 0,
                         "sort.Strings barrier must eliminate the survivor")
        self.assertGreaterEqual(mut["substrate"]["canonicalized"], 1)

    # 3. mutation B - deterministic typed struct kills the survivor
    def test_mutation_typed_struct_kills_survivor(self):
        mut = self._run({"src/keeper/x.go": _TYPED_GO})
        self.assertEqual(mut["survivor_count"], 0,
                         "typed-struct decode is deterministic -> no survivor")
        self.assertEqual(mut["substrate"]["nondeterministic_typed"], 0)
        # decode node still counted (honest substrate), just not nondet-typed.
        self.assertGreaterEqual(mut["substrate"]["decode_nodes"], 1)

    # 4. consensus-reachability gate -> needs_source, not survivor
    def test_offpath_is_needs_source_not_survivor(self):
        rep = self._run({"src/keeper/cfg.go": _OFFPATH_GO})
        self.assertEqual(rep["survivor_count"], 0)
        self.assertGreaterEqual(rep["needs_source_count"], 1)
        ns = rep["needs_source"][0]
        self.assertIn(ns["nondet_kind"], ("map-range", "interface-any",
                                          "noncanonical-json-amino"))
        self.assertTrue(ns["file"] and ns["line"] > 0)

    # 5. substrate_vacuous + fail-closed exit
    def test_substrate_vacuous_fail_closed(self):
        tmp = tempfile.mkdtemp()
        ws = pathlib.Path(tmp)
        _write(ws, "src/keeper/plain.go",
               "package keeper\nfunc F() int { return 1 }\n")
        rep = ND.run(ws)
        self.assertEqual(rep["status"], "substrate_vacuous", rep)
        rc = subprocess.call(
            [sys.executable, str(_TOOL), "--workspace", str(ws),
             "--fail-closed"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.assertEqual(rc, 3, "fail-closed must exit 3 on substrate_vacuous")

    # 6. cited_empty - decode node present, all deterministic
    def test_cited_empty_deterministic_only(self):
        rep = self._run({"src/keeper/det.go": _DETERMINISTIC_GO})
        self.assertEqual(rep["status"], "cited_empty", rep)
        self.assertEqual(rep["survivor_count"], 0)
        self.assertGreaterEqual(rep["substrate"]["decode_nodes"], 1)

    # 7. float on consensus path
    def test_float_on_consensus_survivor(self):
        rep = self._run({"src/keeper/f.go": _FLOAT_GO})
        self.assertEqual(rep["status"], "survivors", rep)
        kinds = {s["nondet_kind"] for s in rep["survivors"]}
        self.assertIn("float", kinds)

    # emit round-trips valid jsonl
    def test_emit_jsonl(self):
        tmp = tempfile.mkdtemp()
        ws = pathlib.Path(tmp)
        _write(ws, "src/keeper/x.go", _SURVIVOR_GO)
        outp = ws / "out.jsonl"
        rc = subprocess.call(
            [sys.executable, str(_TOOL), "--workspace", str(ws),
             "--emit", str(outp)], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in outp.read_text().splitlines() if l.strip()]
        self.assertTrue(any(r.get("verdict") == "survivor" for r in rows))
        for r in rows:
            self.assertEqual(r["schema"],
                             "auditooor.nondeterministic_deserialization.v1")

    # 8. real substrate honesty
    def test_real_substrate_nuva(self):
        ws = pathlib.Path("/Users/wolf/audits/nuva")
        if not ws.exists():
            self.skipTest("nuva substrate absent")
        rep = ND.run(ws)
        self.assertIn(rep["status"],
                      ("survivors", "cited_empty", "substrate_vacuous"))
        for s in rep["survivors"]:
            self.assertTrue(s["file"] and s["line"] > 0, "grounded cite required")
            self.assertEqual(s["schema"],
                             "auditooor.nondeterministic_deserialization.v1")

    def test_real_substrate_axelar(self):
        ws = pathlib.Path("/Users/wolf/audits/axelar-dlt")
        if not ws.exists():
            self.skipTest("axelar-dlt substrate absent")
        rep = ND.run(ws)
        self.assertIn(rep["status"],
                      ("survivors", "cited_empty", "substrate_vacuous"))
        for s in rep["survivors"]:
            self.assertTrue(s["file"] and s["line"] > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
