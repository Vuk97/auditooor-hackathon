#!/usr/bin/env python3
"""Regression for detectors/rust_wave1/asymmetric_cache_invalidation.py - the
net-new partial-cache-flush / asymmetric-invalidation detector seeded by the
Feb-2026 Aptos Move-VM struct-hijack bug. 2026-07-08.

Proves:
  - the VULNERABLE Aptos-shape fixture (Path-B enumerated flush omitting a cache
    the aggregate covers) IS flagged (signal B), at the Path-B arm;
  - the PATCHED fixture (both arms use the aggregate) is NOT flagged;
  - the STRONG signal A fires when a sibling block flushes a strict superset, and
    names the omitted cache;
  - a single-buffer flush does not trip the >=2-member floor;
  - the detector conforms to the rust_wave1 run(tree, source, filepath) interface.
"""
import importlib.util
import unittest
from pathlib import Path

_DET = Path(__file__).resolve().parent.parent.parent / "detectors" / "rust_wave1" / \
    "asymmetric_cache_invalidation.py"
_FIX = _DET.parent / "test_fixtures"
_s = importlib.util.spec_from_file_location("aci", _DET)
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def _run_file(self, name: str):
        src = (_FIX / name).read_bytes()
        return m.run(None, src, str(_FIX / name))

    def test_vuln_aptos_shape_flagged(self):
        hits = self._run_file("asymmetric_cache_invalidation_vuln.rs")
        self.assertTrue(hits, "expected the Path-B partial flush to be flagged")
        msgs = " ".join(h["message"] for h in hits)
        # the enumerated Path-B members are named
        self.assertIn("module_id_pool", msgs)
        self.assertIn("struct_name_index_map", msgs)
        # signal B references the aggregate / Aptos shape
        self.assertIn("aggregate", msgs)

    def test_safe_patched_shape_not_flagged(self):
        hits = self._run_file("asymmetric_cache_invalidation_safe.rs")
        self.assertEqual(hits, [], f"patched shape must be clean, got {hits}")

    def test_signal_a_superset_names_omission(self):
        # two enumerated sibling blocks, one a strict superset -> HIGH + names omit.
        src = b"""
fn flush_full(env: &Env) {
    { env.a_cache().flush(); env.b_cache().flush(); env.c_cache().flush(); }
}
fn flush_partial(env: &Env) {
    { env.a_cache().flush(); env.b_cache().flush(); }
}
"""
        hits = m.run(None, src, "x.rs")
        high = [h for h in hits if h["severity"] == "high"]
        self.assertTrue(high, f"expected a strong superset hit, got {hits}")
        self.assertIn("c_cache", high[0]["message"])
        self.assertIn("OMITS", high[0]["message"])

    def test_single_flush_not_flagged(self):
        src = b"fn write(buf: &Buffer) { buf.flush(); }"
        self.assertEqual(m.run(None, src, "x.rs"), [])

    def test_interface_and_scan(self):
        self.assertTrue(hasattr(m, "run"))
        self.assertTrue(hasattr(m, "scan"))
        # scan() skips test_fixtures/ by design, so copy the vuln fixture into a
        # plain temp source dir and confirm scan() surfaces it there.
        import tempfile
        d = Path(tempfile.mkdtemp())
        (d / "cache_mgr.rs").write_bytes(
            (_FIX / "asymmetric_cache_invalidation_vuln.rs").read_bytes())
        out = m.scan(d)
        self.assertTrue(any("module_id_pool" in msg for _f, _l, msg in out),
                        f"scan should surface the vuln hit, got {out}")


if __name__ == "__main__":
    unittest.main()
