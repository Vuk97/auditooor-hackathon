"""G-CENSUS - go.consensus.state_write_nondeterministic_provenance (advisory).

The consensus-write determinism CENSUS FUSES the three DONE determinism arms
(G1 map-iteration, G4 time/float/rand, G5 non-canonical unmarshal) under ONE
provenance question over an enumerated consensus-state-WRITE universe (KVStore /
keeper-setter sinks UNIONed with the previously-uncovered cosmos `collections`
handles). It is NOT a 4th detector: it reuses the arms' predicates verbatim.

Non-vacuous:
  * a write whose value derives from map-range ORDER (G1) / time.Now (G4) /
    a non-canonical decode ladder (G5) FIRES with the correct source_arm;
  * a deterministic write (sorted keys / ctx.BlockTime / TypeUrl-discriminated
    decode) stays SILENT.
Load-bearing mutation witnesses prove each guard is real (not decorative):
  * blanking the collections write regex -> the collections positive stops
    firing (the sink gap-closure is load-bearing);
  * injecting a sort into the map-range positive -> it goes SILENT (the
    _MAP_KEY_ORDER precision guard is load-bearing);
  * blanking _G5_DISCRIMINATOR -> the canonical-decode negative FIRES (the
    decode-discriminator precision guard is load-bearing).
Plus env-gated emission (verdict=needs-fuzz, NO auto-credit) and the (file,line)
dedup vs the fused arms.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER_PATH = HERE.parent / "go-detector-runner.py"
FIX = HERE / "fixtures" / "GCENSUS"


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "go_detector_runner_gcensus", RUNNER_PATH
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_detector_runner_gcensus"] = mod
    spec.loader.exec_module(mod)
    return mod


class GConsensusWriteCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    # -- helpers -----------------------------------------------------------
    def _rel(self, src_path: Path) -> Path:
        # place under a keeper/ path so the consensus-context gate holds via
        # the module path as well as the sdk.Context param.
        return Path("x/mymod/keeper") / src_path.name

    def _funcs(self, src: str, rel: Path):
        return self.mod._extract_functions(src, rel)

    def _hits(self, src_path: Path):
        src = src_path.read_text(encoding="utf-8")
        rel = self._rel(src_path)
        # file_sources supplies the cross-file collections handle decls.
        return self.mod._detect_consensus_write_determinism_census(
            self._funcs(src, rel), {rel: src}
        )

    def _hits_at(self, src_path: Path, rel: Path):
        """Run the census with an EXPLICIT rel path (for the off-consensus /
        path-gate tests where the tree, not just the fn shape, is load-bearing)."""
        src = src_path.read_text(encoding="utf-8")
        return self.mod._detect_consensus_write_determinism_census(
            self._funcs(src, rel), {rel: src}
        )

    # -- positives (must FIRE with the right source_arm) -------------------
    def test_positive_map_range_collections_fires(self):
        hits = self._hits(FIX / "positive" / "coll_maprange.go")
        self.assertEqual(len(hits), 1, [h.to_json() for h in hits])
        self.assertEqual(hits[0].extra["source_arm"], "map_range_order")
        # the write is a collections handle .Push -> exercises the gap-closure.
        self.assertEqual(hits[0].extra["sink_kind"], "collections")
        self.assertEqual(hits[0].extra["function"], "DistributeAll")

    def test_positive_time_now_fires(self):
        hits = self._hits(FIX / "positive" / "time_now.go")
        self.assertEqual(len(hits), 1, [h.to_json() for h in hits])
        self.assertEqual(hits[0].extra["source_arm"], "wall_clock")
        self.assertFalse(hits[0].extra["advisory_float"])

    def test_positive_decode_ambiguity_fires(self):
        hits = self._hits(FIX / "positive" / "decode_ambiguity.go")
        self.assertGreaterEqual(len(hits), 1, [h.to_json() for h in hits])
        self.assertTrue(
            all(h.extra["source_arm"] == "noncanonical_decode" for h in hits),
            [h.to_json() for h in hits],
        )

    # -- negatives (deterministic provenance -> must stay SILENT) ----------
    def test_negative_blocktime_clean(self):
        hits = self._hits(FIX / "negative" / "blocktime.go")
        self.assertEqual(len(hits), 0, f"block-time write fired: {[h.to_json() for h in hits]}")

    def test_negative_sorted_keys_clean(self):
        hits = self._hits(FIX / "negative" / "sorted_keys.go")
        self.assertEqual(len(hits), 0, f"sorted-keys write fired: {[h.to_json() for h in hits]}")

    def test_negative_canonical_decode_clean(self):
        hits = self._hits(FIX / "negative" / "canonical_decode.go")
        self.assertEqual(len(hits), 0, f"canonical decode fired: {[h.to_json() for h in hits]}")

    # -- parity: string-literal count must NOT hide a map-range write ------
    def test_parity_string_literal_count_does_not_hide_maprange_write(self):
        """FN regression (_g7_mask_comments symmetric-mask fix). A genuine
        range-over-map + accumulator write must fire regardless of how many
        string/rune literals the loop body carries. Pre-fix, an ODD literal
        count left one stray close-quote in the masked body that flipped the
        downstream _balance_braces into string-mode so it swallowed the loop's
        closing brace -> the write was missed. Parity probe: 0/1/2 literals all
        fire (pre-fix the odd=1 case returned 0)."""
        rel = Path("x/mymod/keeper") / "parity.go"

        def _src(bodylines: str) -> str:
            return (
                "package keeper\n"
                "import (\n"
                '\t"fmt"\n'
                '\t"cosmossdk.io/collections"\n'
                '\tsdk "github.com/cosmos/cosmos-sdk/types"\n'
                ")\n"
                "type Keeper struct { Ledger collections.Sequence }\n"
                "func (k Keeper) DistributeAll(ctx sdk.Context) {\n"
                "\tpending := map[string]uint64{}\n"
                '\tpending["x"] = 5\n'
                "\tfor addr, amt := range pending {\n"
                "\t\t_ = addr\n"
                + bodylines +
                "\t\tk.Ledger.Push(amt)\n"
                "\t}\n"
                "}\n"
            )

        variants = {
            0: "",
            1: '\t\t_ = fmt.Sprintf("one literal")\n',
            2: '\t\t_ = fmt.Sprintf("a") + fmt.Sprintf("b")\n',
        }
        for nlit, bodylines in variants.items():
            src = _src(bodylines)
            hits = self.mod._detect_consensus_write_determinism_census(
                self.mod._extract_functions(src, rel), {rel: src}
            )
            self.assertEqual(
                len(hits), 1,
                f"{nlit} string literal(s) in the loop body: expected 1 map-range "
                f"hit, got {[h.to_json() for h in hits]}")
            self.assertEqual(hits[0].extra["source_arm"], "map_range_order")

    # -- wiring: the census jsonl must be in BOTH consumer lists -----------
    def test_census_jsonl_wired_into_both_consumer_lists(self):
        """methodology_capability_must_be_wired_not_just_built: the census
        output must be (a) cat'd into audit-deep.sh Step 5b adv_rows AND its env
        set, and (b) present in auto-coverage-closer GO_ADVISORY_HYPOTHESES_REL,
        or it is a built-but-dormant orphan."""
        jsonl = "consensus_write_determinism_census_hypotheses.jsonl"
        # (a) audit-deep.sh: env set (exact 3-O AUDITOOOR spelling matching the
        # GCENSUS_WRITE_DET_ENV constant) + the jsonl in the adv_rows cat list.
        ad = (RUNNER_PATH.parent / "audit-deep.sh").read_text(encoding="utf-8")
        self.assertIn("AUDITOOOR_G_CONSENSUS_WRITE_DETERMINISM=1", ad)
        self.assertIn(jsonl, ad)
        # (b) auto-coverage-closer GO_ADVISORY_HYPOTHESES_REL.
        spec = importlib.util.spec_from_file_location(
            "acc_wiring", RUNNER_PATH.parent / "auto-coverage-closer.py"
        )
        acc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(acc)
        self.assertIn(
            os.path.join(".auditooor", jsonl), acc.GO_ADVISORY_HYPOTHESES_REL,
            "census jsonl missing from GO_ADVISORY_HYPOTHESES_REL")
        # env constant name is the 3-O spelling (verified vs the sibling 2-O G-envs).
        self.assertEqual(self.mod.GCENSUS_WRITE_DET_ENV,
                         "AUDITOOOR_G_CONSENSUS_WRITE_DETERMINISM")

    # -- load-bearing mutation witnesses -----------------------------------
    def test_collections_sink_gap_closure_is_load_bearing(self):
        """Blank the collections write regex -> the collections positive stops
        firing (the Push write is enumerated ONLY by the census gap-closure)."""
        src = (FIX / "positive" / "coll_maprange.go").read_text()
        rel = self._rel(FIX / "positive" / "coll_maprange.go")
        funcs = self._funcs(src, rel)
        orig = self.mod._GCENSUS_COLLECTIONS_WRITE
        try:
            self.mod._GCENSUS_COLLECTIONS_WRITE = re.compile(r"(?!x)x")  # never
            hits = self.mod._detect_consensus_write_determinism_census(
                funcs, {rel: src}
            )
            self.assertEqual(len(hits), 0, "collections sink gap-closure is vacuous")
        finally:
            self.mod._GCENSUS_COLLECTIONS_WRITE = orig
        self.assertEqual(
            len(self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})),
            1,
        )

    def test_sort_suppressor_is_load_bearing(self):
        """Inject a sort call into the map-range positive -> it goes SILENT
        (the _MAP_KEY_ORDER precision guard neutralizes the map-range source)."""
        src = (FIX / "positive" / "coll_maprange.go").read_text()
        mutated = src.replace(
            "\tfor addr, amt := range pending {",
            "\tsort.Slice(nil, nil)\n\tfor addr, amt := range pending {",
        )
        self.assertNotEqual(src, mutated, "mutation did not apply")
        rel = self._rel(FIX / "positive" / "coll_maprange.go")
        hits = self.mod._detect_consensus_write_determinism_census(
            self._funcs(mutated, rel), {rel: mutated}
        )
        self.assertEqual(len(hits), 0, "sort did not suppress the map-range source")

    def test_decode_discriminator_is_load_bearing(self):
        """Blank _G5_DISCRIMINATOR -> the canonical-decode negative FIRES (the
        TypeUrl discriminator is the only thing keeping it GREEN)."""
        src = (FIX / "negative" / "canonical_decode.go").read_text()
        rel = self._rel(FIX / "negative" / "canonical_decode.go")
        funcs = self._funcs(src, rel)
        orig = self.mod._G5_DISCRIMINATOR
        try:
            self.mod._G5_DISCRIMINATOR = re.compile(r"(?!x)x")  # never matches
            hits = self.mod._detect_consensus_write_determinism_census(
                funcs, {rel: src}
            )
            self.assertGreaterEqual(len(hits), 1, "decode discriminator guard is vacuous")
            self.assertTrue(
                all(h.extra["source_arm"] == "noncanonical_decode" for h in hits)
            )
        finally:
            self.mod._G5_DISCRIMINATOR = orig
        self.assertEqual(
            len(self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})),
            0,
        )

    # -- env-gated emission + dedup ----------------------------------------
    def test_env_gated_emission(self):
        """scan_workspace writes the census jsonl ONLY when the env flag is set,
        with verdict=needs-fuzz + the apphash-divergence exploit class. Uses the
        collections fixture: no standalone arm surfaces that write, so the census
        row survives dedup and demonstrates the net-new catch."""
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            dst = wsp / "x" / "mymod" / "keeper"
            dst.mkdir(parents=True)
            shutil.copy(FIX / "positive" / "coll_maprange.go", dst / "k.go")
            out = wsp / ".auditooor" / self.mod.GCENSUS_WRITE_DET_OUT
            env = self.mod.GCENSUS_WRITE_DET_ENV

            os.environ.pop(env, None)
            self.mod.scan_workspace(wsp, tuple(self.mod._DEFAULT_GUARDS))
            self.assertFalse(out.exists(), "census jsonl emitted while env OFF")

            os.environ[env] = "1"
            try:
                self.mod.scan_workspace(wsp, tuple(self.mod._DEFAULT_GUARDS))
            finally:
                os.environ.pop(env, None)
            self.assertTrue(out.exists(), "census jsonl not emitted while env ON")
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 1, rows)
            self.assertEqual(rows[0]["verdict"], "needs-fuzz")
            self.assertEqual(rows[0]["pattern_id"], self.mod.GCENSUS_WRITE_DET_PID)
            self.assertEqual(rows[0]["exploit_class"], "apphash-divergence")
            self.assertEqual(rows[0]["lane"], "G-CENSUS")
            self.assertEqual(rows[0]["source_arm"], "map_range_order")

    def test_dedup_against_fused_arms(self):
        """A (file,line) already surfaced by a fused arm is dropped from the
        census lane (A1 dedup boundary)."""
        src = (FIX / "positive" / "time_now.go").read_text()
        rel = self._rel(FIX / "positive" / "time_now.go")
        funcs = self._funcs(src, rel)
        hits = self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})
        self.assertEqual(len(hits), 1)
        collide = self.mod.Hit(file=hits[0].file, line=hits[0].line, snippet="x")
        with tempfile.TemporaryDirectory() as ws:
            recs, _ = self.mod._emit_consensus_write_determinism_census_hypotheses(
                Path(ws), funcs, {rel: src}, [collide],
                out_path=Path(ws) / "out.jsonl",
            )
            self.assertEqual(recs, [], "collision not de-duplicated")

    def test_advisory_kept_out_of_pattern_results(self):
        """The census is advisory-first: its pattern id never appears in the
        pattern_results / go_findings payload (no auto-credit, no fire subset)."""
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            dst = wsp / "x" / "mymod" / "keeper"
            dst.mkdir(parents=True)
            shutil.copy(FIX / "positive" / "coll_maprange.go", dst / "k.go")
            summary = self.mod.scan_workspace(wsp, tuple(self.mod._DEFAULT_GUARDS))
            self.assertNotIn(self.mod.GCENSUS_WRITE_DET_PID, summary["patterns"])

    # -- FP-amplification precision fixes (adversarial-verifier catch) ------
    # (a) AppHash write-LHS: a bare AppHash token that is a RETURN / RHS read is
    #     NOT a write; (b) require a source->written-value DATAFLOW link, not
    #     mere window co-occurrence; (c) exclude off-consensus statesync/light
    #     paths; (d) suppress order-invariant distinct-key map-range writes.
    def test_negative_apphash_return_clean(self):
        """(a) `return header.AppHash` is a return, not a write-LHS: SILENT even
        though time.Now co-occurs in the body (the manufactured FP-2)."""
        hits = self._hits(FIX / "negative" / "apphash_return.go")
        self.assertEqual(len(hits), 0, f"apphash return fired: {[h.to_json() for h in hits]}")

    def test_negative_apphash_verify_arg_clean(self):
        """(b) time.Now reaches only a verification ARGUMENT; the written AppHash
        derives from the deterministic verified block: SILENT (the FP-3)."""
        hits = self._hits(FIX / "negative" / "apphash_verify_arg.go")
        self.assertEqual(len(hits), 0, f"verify-arg write fired: {[h.to_json() for h in hits]}")

    def test_negative_distinct_key_maprange_clean(self):
        """(d) each iteration writes a DISTINCT key -> order-invariant: SILENT."""
        hits = self._hits(FIX / "negative" / "distinct_key.go")
        self.assertEqual(len(hits), 0, f"distinct-key map-range fired: {[h.to_json() for h in hits]}")

    def test_positive_apphash_from_time_fires(self):
        """The precision fixes are NOT vacuous: a GENUINE AppHash write-LHS whose
        value is DERIVED from time.Now still fires (wall_clock / apphash sink)."""
        hits = self._hits(FIX / "positive" / "apphash_time.go")
        self.assertEqual(len(hits), 1, [h.to_json() for h in hits])
        self.assertEqual(hits[0].extra["source_arm"], "wall_clock")
        self.assertEqual(hits[0].extra["sink_kind"], "apphash")

    def test_apphash_write_lhs_is_load_bearing(self):
        """Blank _GCENSUS_APPHASH_WRITE -> the genuine AppHash positive stops
        firing (AppHash writes are enumerated ONLY via the write-LHS regex, never
        the bare token; the write-LHS gate is the (a) precision guard)."""
        src = (FIX / "positive" / "apphash_time.go").read_text()
        rel = self._rel(FIX / "positive" / "apphash_time.go")
        funcs = self._funcs(src, rel)
        orig = self.mod._GCENSUS_APPHASH_WRITE
        try:
            self.mod._GCENSUS_APPHASH_WRITE = re.compile(r"(?!x)x")  # never
            hits = self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})
            self.assertEqual(len(hits), 0, "AppHash write-LHS enumeration is vacuous")
        finally:
            self.mod._GCENSUS_APPHASH_WRITE = orig
        self.assertEqual(
            len(self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})), 1
        )

    def test_g4_dataflow_link_is_load_bearing(self):
        """Force the dataflow-link gate to always pass -> the verify-arg negative
        FIRES (proving (b): the link, not window co-occurrence, keeps it GREEN)."""
        src = (FIX / "negative" / "apphash_verify_arg.go").read_text()
        rel = self._rel(FIX / "negative" / "apphash_verify_arg.go")
        funcs = self._funcs(src, rel)
        orig = self.mod._gcensus_g4_source_links_write
        try:
            self.mod._gcensus_g4_source_links_write = lambda *a, **k: True
            hits = self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})
            self.assertGreaterEqual(len(hits), 1, "dataflow-link gate is vacuous")
            self.assertTrue(all(h.extra["source_arm"] == "wall_clock" for h in hits))
        finally:
            self.mod._gcensus_g4_source_links_write = orig
        self.assertEqual(
            len(self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})), 0
        )

    def test_distinct_key_suppressor_is_load_bearing(self):
        """Force the distinct-key check to always return False -> the distinct-key
        map-range negative FIRES (proving (d) is the only thing keeping it GREEN)."""
        src = (FIX / "negative" / "distinct_key.go").read_text()
        rel = self._rel(FIX / "negative" / "distinct_key.go")
        funcs = self._funcs(src, rel)
        orig = self.mod._gcensus_write_is_distinct_key
        try:
            self.mod._gcensus_write_is_distinct_key = lambda *a, **k: False
            hits = self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})
            self.assertGreaterEqual(len(hits), 1, "distinct-key suppressor is vacuous")
            self.assertTrue(all(h.extra["source_arm"] == "map_range_order" for h in hits))
        finally:
            self.mod._gcensus_write_is_distinct_key = orig
        self.assertEqual(
            len(self.mod._detect_consensus_write_determinism_census(funcs, {rel: src})), 0
        )

    def test_offconsensus_path_excluded(self):
        """(c) the SAME wall-clock-derived write FIRES under a consensus keeper
        path but is SILENT under an off-consensus statesync path (path gate)."""
        probe = FIX / "offconsensus_probe.go"
        fired = self._hits_at(probe, Path("x/mymod/keeper") / "probe.go")
        self.assertEqual(len(fired), 1, [h.to_json() for h in fired])
        self.assertEqual(fired[0].extra["source_arm"], "wall_clock")
        for offpath in (
            Path("cometbft/statesync") / "probe.go",
            Path("cometbft/light/provider") / "probe.go",
        ):
            silent = self._hits_at(probe, offpath)
            self.assertEqual(len(silent), 0, f"{offpath} fired: {[h.to_json() for h in silent]}")


if __name__ == "__main__":
    unittest.main()
