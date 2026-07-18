#!/usr/bin/env python3
"""Tests for tools/return-aliasing-escape.py (RANK-13 return-aliasing escape).

Includes the mandatory NON-VACUOUS mutation pair: a survivor over a bare
persistent-field return DISAPPEARS when (a) a copy() is added on the return path,
and (b) the body returns a fresh allocation instead. Proves the escape relation
is load-bearing, not a `return` grep.
"""
import importlib.util
import json
import pathlib
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "return-aliasing-escape.py"
_spec = importlib.util.spec_from_file_location("return_aliasing_escape", _TOOL)
rae = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rae)


# --- fixtures ---------------------------------------------------------------

# A keeper getter returning a bare persistent slice field of a POINTER receiver.
SURVIVOR_SRC = """
package keeper

type Keeper struct {
    buf   []byte
    cache map[string]*Entry
}

type Entry struct{ v int }

func (k *Keeper) GetBuf() []byte {
    return k.buf
}
"""

# Same, but a defensive copy() on the return path -> NOT a survivor.
COPIED_SRC = """
package keeper

type Keeper struct {
    buf []byte
}

func (k *Keeper) GetBuf() []byte {
    out := make([]byte, len(k.buf))
    copy(out, k.buf)
    return out
}
"""

# Same, but returns a fresh allocation -> NOT a survivor.
FRESH_SRC = """
package keeper

type Keeper struct {
    buf []byte
}

func (k *Keeper) GetBuf() []byte {
    return append([]byte(nil), k.buf...)
}
"""


class ScanCore(unittest.TestCase):
    def _scan(self, src):
        return rae.scan_go_source(src, "x.go")

    def test_survivor_bare_field_return(self):
        survivors, needs, counts = self._scan(SURVIVOR_SRC)
        self.assertEqual(len(survivors), 1, survivors)
        s = survivors[0]
        self.assertEqual(s["alias_kind"], "field-return")
        self.assertEqual(s["returned_target"], "k.buf")
        self.assertIn("*Keeper", s["outlives_call"])
        self.assertEqual(counts["aliases_persistent"], 1)

    def test_mutation_copy_kills_survivor(self):
        # NON-VACUOUS pair (a): copy() on the return path -> survivor gone.
        survivors, _n, counts = self._scan(COPIED_SRC)
        self.assertEqual(survivors, [])
        self.assertEqual(counts["aliases_persistent"], 0)

    def test_direct_clone_on_return_tallied_guarded(self):
        # A copy wrapper ON the return expression itself: survivor gone AND the
        # guarded (defensively-copied) alias is tallied.
        src = """
package keeper
type Keeper struct { buf []byte }
func (k *Keeper) GetBuf() []byte { return slices.Clone(k.buf) }
"""
        survivors, _n, counts = self._scan(src)
        self.assertEqual(survivors, [])
        self.assertEqual(counts["defensively_copied"], 1)
        self.assertEqual(counts["aliases_persistent"], 0)

    def test_mutation_fresh_alloc_kills_survivor(self):
        # NON-VACUOUS pair (b): return a fresh allocation -> survivor gone.
        survivors, _n, counts = self._scan(FRESH_SRC)
        self.assertEqual(survivors, [])
        self.assertEqual(counts["aliases_persistent"], 0)

    def test_predicate_is_defensively_copied_load_bearing(self):
        self.assertTrue(rae.is_defensively_copied("copy(out, k.buf)"))
        self.assertTrue(rae.is_defensively_copied("append([]byte(nil), k.buf...)"))
        self.assertFalse(rae.is_defensively_copied("k.buf"))

    def test_value_receiver_not_persistent(self):
        # A value receiver's field is not treated as an outliving persistent
        # target (guard-rail: only pointer receivers persist).
        src = SURVIVOR_SRC.replace("(k *Keeper)", "(k Keeper)")
        survivors, _n, _c = self._scan(src)
        self.assertEqual([s for s in survivors if s["alias_kind"] == "field-return"], [])

    def test_mapvalue_return_ref_value(self):
        src = """
package keeper
type Keeper struct { cache map[string]*Entry }
type Entry struct{ v int }
func (k *Keeper) Get(id string) *Entry { return k.cache[id] }
"""
        survivors, _n, _c = self._scan(src)
        kinds = {s["alias_kind"] for s in survivors}
        self.assertIn("mapvalue-return", kinds)

    def test_pkgvar_return_survivor(self):
        src = """
package p
var globalBuf []byte
func GetGlobal() []byte { return globalBuf }
"""
        survivors, _n, _c = self._scan(src)
        self.assertEqual(len(survivors), 1)
        self.assertEqual(survivors[0]["alias_kind"], "pkgvar-return")

    def test_param_return_not_survivor(self):
        # returning a caller-supplied param aliases the caller's own input,
        # not internal persistent state -> not our class.
        src = """
package p
func Echo(b []byte) []byte { return b }
"""
        survivors, _n, _c = self._scan(src)
        self.assertEqual(survivors, [])

    def test_subslice_return_survivor(self):
        src = """
package keeper
type Keeper struct { buf []byte }
func (k *Keeper) Head(n int) []byte { return k.buf[:n] }
"""
        survivors, _n, _c = self._scan(src)
        self.assertEqual(survivors[0]["alias_kind"], "subslice-return")


class RunAndHonesty(unittest.TestCase):
    def _ws_with(self, files: dict) -> pathlib.Path:
        d = pathlib.Path(tempfile.mkdtemp())
        for name, content in files.items():
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return d

    def test_substrate_vacuous_no_go(self):
        d = self._ws_with({"README.md": "no go here"})
        rep = rae.run(d)
        self.assertEqual(rep["status"], "substrate_vacuous")
        self.assertTrue(rep["substrate"]["vacuous"])
        self.assertEqual(rep["survivor_count"], 0)

    def test_cited_empty_when_all_copied(self):
        d = self._ws_with({"k.go": COPIED_SRC})
        rep = rae.run(d)
        self.assertEqual(rep["status"], "cited_empty")
        self.assertEqual(rep["survivor_count"], 0)
        self.assertFalse(rep["substrate"]["vacuous"])

    def test_survivors_status_and_kept(self):
        d = self._ws_with({"k.go": SURVIVOR_SRC})
        rep = rae.run(d)
        self.assertEqual(rep["status"], "survivors")
        self.assertEqual(len(rep["kept"]), 1)
        self.assertTrue(rep["kept"][0].endswith("::GetBuf"))

    def test_emit_rows_schema(self):
        d = self._ws_with({"k.go": SURVIVOR_SRC})
        rep = rae.run(d)
        out = d / ".auditooor" / "return_aliasing_escape_obligations.jsonl"
        n = rae._emit_rows(rep, out)
        self.assertGreaterEqual(n, 1)
        rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        self.assertTrue(all(r["schema"] == "auditooor.return_aliasing_escape.v1"
                            for r in rows))
        self.assertTrue(any(r["verdict"] == "survivor" for r in rows))

    def test_fail_closed_exit_code(self):
        d = self._ws_with({"README.md": "x"})
        rc = rae.main(["--workspace", str(d), "--fail-closed"])
        self.assertEqual(rc, 3)

    def test_needs_source_advisory_opaque_local(self):
        # a reference-return of a bare local from an untraceable helper call.
        src = """
package keeper
type Keeper struct{ x int }
func (k *Keeper) Load() []byte {
    b := k.store.GetBytes()
    return b
}
"""
        d = self._ws_with({"k.go": src})
        rep = rae.run(d)
        self.assertGreaterEqual(rep["needs_source_count"], 1)
        self.assertEqual(rep["status"], "cited_empty")


if __name__ == "__main__":
    unittest.main()
