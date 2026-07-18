#!/usr/bin/env python3
"""Regression for tools/coupled-state-completeness.py - the coupled-state
completeness hunt dimension (extract->worklist->ingest->check), Aptos-desync axis.
2026-07-08 (coupled-state-completeness capability loop, box B/C)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
_s = importlib.util.spec_from_file_location("csc", _T / "coupled-state-completeness.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)

_APTOS = """impl M {
    fn check_ready(&self, env: &Env, cfg: &Cfg) {
        if a > cfg.x {
            env.flush_all_caches();
            self.module_cache.flush();
        } else if b > cfg.y {
            env.module_id_pool().flush();
            env.struct_name_index_map().flush();
            self.module_cache.flush();
        }
    }
}
"""
_SAFE = """impl M {
    fn check_ready(&self, env: &Env, cfg: &Cfg) {
        if a > cfg.x { env.flush_all_caches(); self.module_cache.flush(); }
        else if b > cfg.y { env.flush_all_caches(); self.module_cache.flush(); }
    }
}
"""
_SUPERSET = """fn flush_full(e: &E) { { e.a().flush(); e.b().flush(); e.c().flush(); } }
fn flush_partial(e: &E) { { e.a().flush(); e.b().flush(); } }
"""


class T(unittest.TestCase):
    def _rows(self, src):
        return m._rows_for_source(src, "x.rs")

    def test_aptos_partial_flush_flagged(self):
        rows = self._rows(_APTOS)
        self.assertTrue(rows, "Aptos-shape partial flush must yield a worklist row")
        kinds = {r["set_kind"] for r in rows}
        self.assertIn("aggregate-parity", kinds)
        self.assertTrue(any("module_id_pool" in r["mutates"] for r in rows))

    def test_safe_shape_zero_rows(self):
        self.assertEqual(self._rows(_SAFE), [])

    def test_superset_sibling_names_omission(self):
        rows = self._rows(_SUPERSET)
        strong = [r for r in rows if r["set_kind"] == "flush-set"]
        self.assertTrue(strong, f"expected a strict-superset row, got {rows}")
        self.assertIn("c", strong[0]["omits"])

    def test_worklist_row_schema(self):
        r = self._rows(_APTOS)[0]
        for f in ("schema_version", "set_id", "set_kind", "set_members",
                  "writer_file", "writer_line", "mutates", "omits", "question",
                  "probe_verdict"):
            self.assertIn(f, r)
        self.assertEqual(r["schema_version"], "auditooor.coupled_state_worklist.v1")

    def test_paired_stem_asymmetry_flagged(self):
        # mint writes 3 state vars; burn omits seniorAssets -> coupled desync row.
        src = """contract V {
  function mintSenior(uint a) external { seniorShares += a; totalSupply += a; seniorAssets += a; }
  function burnSenior(uint a) external { seniorShares -= a; totalSupply -= a; }
}"""
        rows = [r for r in m._rows_for_source(src, "V.sol")
                if r["set_kind"] == "paired-stem"]
        self.assertTrue(rows, "paired mint/burn state-write asymmetry must flag")
        self.assertIn("seniorAssets", rows[0]["omits"])

    def test_local_decls_not_counted_as_state(self):
        # deposit/withdraw naming DIFFERENT LOCAL amounts is NOT a coupled-state
        # desync (Strata FP class). Only persistent-storage writes couple.
        src = """contract V {
  function deposit(address t, uint256 amt) external {
    uint256 jrtAssetsIn = amt;   // local
    IStrategy strategy = cdo.strategy();  // local, comment-preceded
    accounting.updateBalanceFlow(jrtAssetsIn, 0);
  }
  function withdraw(address t, uint256 amt) external {
    // cooldown handling
    bool shouldSkipCooldown = true;   // local after comment
    uint256 jrtAssetsOut = amt;       // local
    accounting.updateBalanceFlow(0, jrtAssetsOut);
  }
}"""
        rows = [r for r in m._rows_for_source(src, "V.sol")
                if r["set_kind"] == "paired-stem"]
        self.assertEqual(rows, [], f"local-only asymmetry must NOT flag, got {rows}")

    def test_storage_writes_still_fire(self):
        # a REAL storage-level asymmetry (mapping/array writes) must still flag.
        src = """contract V {
  function addDest(address d) external { destinations.push(d); indexOf[d] = destinations.length; isDest[d] = true; }
  function removeDest(address d) external { isDest[d] = false; }
}"""
        rows = [r for r in m._rows_for_source(src, "V.sol")
                if r["set_kind"] == "paired-stem"]
        self.assertTrue(rows, "real storage add/remove asymmetry must still flag")

    # ---- heuristic (d): domain / derived-from coupling ----
    def test_derived_coupling_aptos_shape(self):
        # tyTagCache is DERIVED-FROM structIndex; flushIndex mutates structIndex
        # but not tyTagCache -> stale derived cache (Aptos keyed-by shape).
        src = """contract C {
  function setEntry(uint k, uint v) external { structIndex = k; tyTagCache = structIndex + v; }
  function flushIndex() external { structIndex = 0; }
}"""
        rows = [r for r in m._rows_for_source(src, "C.sol")
                if r["set_kind"] == "derived-coupling"]
        self.assertTrue(rows, f"derived-cache staleness must flag, got {rows}")
        self.assertEqual(rows[0]["omits"], ["tyTagCache"])
        self.assertEqual(rows[0]["mutates"], ["structIndex"])

    def test_derived_coupling_go_receiver_shape(self):
        # Sei-style: commitSet derived-from version; Bump moves version alone.
        src = """package x
func (s *Store) Set(v int) { s.version = v; s.commitSet = s.version + 1 }
func (s *Store) Bump() { s.version = s.version + 1 }
"""
        rows = [r for r in m._rows_for_source(src, "store.go")
                if r["set_kind"] == "derived-coupling"]
        self.assertTrue(rows, f"receiver-field derived coupling must flag, got {rows}")
        self.assertIn("commitSet", rows[0]["omits"])
        self.assertIn("version", rows[0]["mutates"])

    def test_derived_coupling_symmetric_zero(self):
        # every writer of the source ALSO re-establishes the derived cache -> safe.
        src = """contract C {
  function setEntry(uint k, uint v) external { structIndex = k; tyTagCache = structIndex + v; }
  function flushBoth() external { structIndex = 0; tyTagCache = 0; }
}"""
        self.assertEqual(
            [r for r in m._rows_for_source(src, "C.sol")
             if r["set_kind"] == "derived-coupling"], [])

    def test_derived_coupling_needs_witnessed_derivation(self):
        # two independent state vars, NO A=f(B) derivation -> must NOT flag on
        # names alone (anti-flood guarantee for large Go trees).
        src = """contract C {
  function a(uint v) external { alpha = v; }
  function b(uint v) external { beta = v; }
}"""
        self.assertEqual(
            [r for r in m._rows_for_source(src, "C.sol")
             if r["set_kind"] == "derived-coupling"], [])

    def test_lens_file_suppressed(self):
        src = """contract L {
  function q(uint v) external view { total = base + v; }
  function drop() external { base = 0; }
}"""
        self.assertEqual(
            [r for r in m._rows_for_source(src, "IntegrationsLens.sol")
             if r["set_kind"] == "derived-coupling"], [])

    def test_local_struct_single_writer_not_flagged(self):
        # a struct built in ONE function (geth `header := &Header{}`) has its
        # fields written once -> the multi-writer persistence guard suppresses it
        # (the Go local-struct FP class) even though a derivation exists.
        src = """package x
func build(cfg *Config) *Header {
  header := &Header{}
  header.GasLimit = cfg.GasLimit
  gasPool := header.GasLimit + 1
  header.pool = gasPool
  return header
}"""
        rows = [r for r in m._rows_for_source(src, "chain.go")
                if r["set_kind"] == "derived-coupling"]
        self.assertEqual(rows, [], f"single-fn local struct must not flag, got {rows}")

    def test_go_plumbing_names_excluded(self):
        # `ctx`/`start` are known plumbing locals - never coupled state.
        src = """package x
func a() { ctx = base; total = ctx + 1 }
func b() { ctx = other; total = 2 }
"""
        rows = [r for r in m._rows_for_source(src, "h.go")
                if r["set_kind"] == "derived-coupling"]
        self.assertEqual([r for r in rows if "ctx" in r["mutates"]], [],
                         f"ctx must be excluded as plumbing, got {rows}")

    def test_string_literal_words_not_coupled(self):
        # a word inside an error/log string must NOT create a coupling (the #1
        # Go FP: `errX = errors.New("... parent ...")`).
        src = """package x
func set(v int) { parent = v; header = parent + 1 }
func other() { parent = 0 }
var errX = fmt.Errorf("timestamp older than parent header")
"""
        rows = m._rows_for_source(src, "c.go")
        # header<-parent is a legit coupling (parent multi-writer); errX must not be.
        self.assertFalse(any("errX" in r["omits"] or "errX" in r["mutates"]
                             for r in rows), f"string words must not couple: {rows}")

    def test_co_indexed_opt_in_only(self):
        # co-indexed maps: OFF by default, ON with co_indexed=True.
        src = """contract C {
  function w(bytes32 k, uint v) external { store[k] = v; keys[k] = true; }
  function partial(bytes32 k, uint v) external { store[k] = v; }
}"""
        off = [r for r in m._rows_for_source(src, "MV.sol")
               if r["set_kind"] == "co-indexed"]
        self.assertEqual(off, [], "co-indexed must be OFF by default")
        on = [r for r in m._rows_for_source(src, "MV.sol", co_indexed=True)
              if r["set_kind"] == "co-indexed"]
        self.assertTrue(on, f"co-indexed must fire when opted-in, got {on}")

    def test_paired_stem_symmetric_zero(self):
        src = """contract V {
  function addFoo() external { a += 1; b += 1; }
  function removeFoo() external { a -= 1; b -= 1; }
}"""
        self.assertEqual(
            [r for r in m._rows_for_source(src, "V.sol")
             if r["set_kind"] == "paired-stem"], [])

    def test_emit_ingest_check_roundtrip(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / "cache.rs").write_text(_APTOS)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "cache.rs", "function": "check_ready"}) + "\n")
        self.assertEqual(m.main(["--workspace", str(ws), "--emit-worklist"]), 0)
        wl = ws / ".auditooor" / "coupled_state_worklist.jsonl"
        rows = [json.loads(l) for l in wl.read_text().splitlines() if l.strip()]
        self.assertTrue(rows)
        # check FAILS closed while rows are unprobed
        self.assertEqual(m.main(["--workspace", str(ws), "--check"]), 1)
        # probe every row -> ingest -> check passes
        v = ws / "verdicts.jsonl"
        v.write_text("\n".join(json.dumps(
            {"set_id": r["set_id"], "probe_verdict": "NEGATIVE-coupled-set-guarded"})
            for r in rows) + "\n")
        self.assertEqual(m.main(["--workspace", str(ws), "--ingest", str(v)]), 0)
        self.assertEqual(m.main(["--workspace", str(ws), "--check"]), 0)


_CHK = importlib.util.spec_from_file_location(
    "csc_chk", _T / "coupled-state-completeness-check.py")
_chk = importlib.util.module_from_spec(_CHK)
_CHK.loader.exec_module(_chk)


class TCheck(unittest.TestCase):
    def _ws(self, src, fn="check_ready"):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / "cache.rs").write_text(src)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "cache.rs", "function": fn}) + "\n")
        return ws

    def test_open_rows_no_marker_advisory_rc0(self):
        import os
        ws = self._ws(_APTOS)
        os.environ.pop("AUDITOOOR_L37_STRICT", None)
        rc = _chk.main(["--workspace", str(ws)])
        self.assertEqual(rc, 0)  # advisory: WARN, rc 0
        self.assertFalse((ws / ".auditooor" /
                          "coupled_state_completeness_pass.marker").is_file())

    def test_open_rows_strict_rc1(self):
        import os
        ws = self._ws(_APTOS)
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            rc = _chk.main(["--workspace", str(ws)])
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.assertEqual(rc, 1)  # strict: HARD FAIL

    def test_no_coupled_sets_writes_pass_marker(self):
        import os
        ws = self._ws("contract X { function f() external { a = 1; } }", fn="f")
        (ws / "cache.rs").rename(ws / "x.sol")
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "x.sol", "function": "f"}) + "\n")
        os.environ.pop("AUDITOOOR_L37_STRICT", None)
        rc = _chk.main(["--workspace", str(ws)])
        self.assertEqual(rc, 0)
        self.assertTrue((ws / ".auditooor" /
                         "coupled_state_completeness_pass.marker").is_file())


class TExploitQueueBridge(unittest.TestCase):
    def setUp(self):
        s = importlib.util.spec_from_file_location("eq", _T / "exploit-queue.py")
        self.eq = importlib.util.module_from_spec(s)
        s.loader.exec_module(self.eq)

    def test_gather_from_coupled_state_only_real_desync(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        gaps = [
            {"set_id": "aaa", "writer_file": "CDO.sol", "writer_line": 228,
             "mutates": ["srtAssetsIn"], "omits": ["srtAssetsOut"],
             "probe_verdict": "REAL-desync-reachable"},
            {"set_id": "bbb", "writer_file": "Lens.sol", "writer_line": 89,
             "mutates": ["x"], "omits": ["y"],
             "probe_verdict": "NEGATIVE-view-helper"},
            {"set_id": "ccc", "writer_file": "X.sol", "writer_line": 1,
             "mutates": ["a"], "omits": ["b"], "probe_verdict": ""},
        ]
        (ws / ".auditooor" / "coupled_state_gaps.jsonl").write_text(
            "\n".join(json.dumps(g) for g in gaps) + "\n")
        rows = self.eq._gather_from_coupled_state(ws)
        self.assertEqual(len(rows), 1)  # only REAL-desync; NEGATIVE + unprobed excluded
        self.assertEqual(rows[0]["attack_class"], "coupled-state-partial-update")
        self.assertIn("srtAssetsOut", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
