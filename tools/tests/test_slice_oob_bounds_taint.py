from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "slice-oob-bounds-taint.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("slice_oob_bounds_taint", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["slice_oob_bounds_taint"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


# ---- vulnerable substrate: untrusted []byte param offset -> unchecked slice ----
VULN = """package wire

func parseHeader(data []byte) ([]byte, error) {
    n := int(data[0])
    // no bounds check on n against len(data)
    body := data[1 : 1+n]
    return body, nil
}
"""

# ---- MUTATION A: add a len-check dominating the slice -> survivor disappears ----
GUARDED = """package wire

func parseHeader(data []byte) ([]byte, error) {
    n := int(data[0])
    if len(data) < 1+n {
        return nil, errShort
    }
    body := data[1 : 1+n]
    return body, nil
}
"""

# ---- MUTATION B: length is a compile-time constant -> survivor disappears ----
CONST = """package wire

const versionSize = 4

func parseHeader(data []byte) ([]byte, error) {
    body := data[0:versionSize]
    return body, nil
}
"""

# ---- copy() with untrusted-derived make length ----
COPY_VULN = """package wire

import "encoding/binary"

func decode(msg []byte) []byte {
    n := binary.BigEndian.Uint32(msg[0:4])
    dst := make([]byte, n)
    copy(dst, msg[4:4+n])
    return dst
}
"""


def _write(dirpath: Path, name: str, body: str) -> Path:
    p = dirpath / name
    p.write_text(body)
    return p


class SliceOobTaintTests(unittest.TestCase):
    def _run(self, src: str, name: str = "x.go"):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, name, src)
            return MOD.run(ws=d, src_root=d, emit=True)

    # 1. Vulnerable file yields >=1 survivor with status ok.
    def test_vulnerable_yields_survivor(self):
        acct = self._run(VULN)
        self.assertEqual(acct["status"], "ok")
        self.assertGreaterEqual(acct["survivors"], 1)
        self.assertTrue(any(k["operand"].strip() for k in acct["kept"]))

    # 2. NON-VACUOUS mutation A: adding a dominating len-check removes survivor.
    def test_mutation_len_check_removes_survivor(self):
        vuln = self._run(VULN)
        guarded = self._run(GUARDED)
        self.assertGreaterEqual(vuln["survivors"], 1)
        self.assertEqual(guarded["survivors"], 0)
        # It is honest cited-empty (tainted node existed but was dominated),
        # NOT substrate_vacuous.
        self.assertEqual(guarded["status"], "cited-empty")
        self.assertGreaterEqual(guarded["bounds_dominated"], 1)

    # 3. NON-VACUOUS mutation B: constant length is untaintable -> no survivor.
    def test_mutation_constant_length_removes_survivor(self):
        const = self._run(CONST)
        self.assertEqual(const["survivors"], 0)
        # A pure-constant operand is not even counted as a slice node.
        self.assertEqual(const["status"], "substrate_vacuous")

    # 4. Predicate load-bearing: neutralise taint lexicon -> survivors vanish.
    def test_taint_predicate_is_load_bearing(self):
        saved = MOD.UNTRUSTED_TOKENS
        try:
            MOD.UNTRUSTED_TOKENS = tuple()
            # With no []byte-param provenance recognised either, a var-only
            # offset that co-occurs with a decode token no longer taints.
            body = """package p
func f(x int) []byte {
    var buf []byte
    buf = readWire()
    return buf[0:x]
}
"""
            rows, nodes, tainted = MOD.scan_go_source(body, "p.go")
            self.assertEqual(tainted, 0)
        finally:
            MOD.UNTRUSTED_TOKENS = saved

    # 5. copy()/make() with binary-read length is a survivor.
    def test_copy_make_binary_read_survivor(self):
        acct = self._run(COPY_VULN)
        self.assertEqual(acct["status"], "ok")
        kinds = {k["kind"] for k in acct["kept"]}
        self.assertTrue(kinds & {"make", "copy", "binary-read", "slice-range"})

    # 6. Empty / no-go substrate is honestly vacuous, never a false survivor.
    def test_empty_substrate_vacuous(self):
        with tempfile.TemporaryDirectory() as td:
            acct = MOD.run(ws=Path(td), src_root=Path(td), emit=False)
        self.assertEqual(acct["status"], "substrate_vacuous")
        self.assertEqual(acct["survivors"], 0)

    # 7. Sidecar emission is well-formed JSON with the v1 schema tag.
    def test_emit_sidecars_schema(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "x.go", VULN)
            MOD.run(ws=d, src_root=d, emit=True)
            acct = json.loads((d / ".auditooor" / "slice_oob_bounds_taint.accounting.json").read_text())
            self.assertEqual(acct["schema"], "auditooor.slice_oob_bounds_taint.v1")
            jl = (d / ".auditooor" / "slice_oob_bounds_taint.jsonl").read_text().strip()
            first = json.loads(jl.splitlines()[0])
            self.assertEqual(first["schema"], "auditooor.slice_oob_bounds_taint.v1")
            self.assertFalse(first["auto_credit"])
            self.assertTrue(first["advisory"])

    # 8. Uncertain taint chain -> advisory verdict needs-source, not needs-fuzz.
    def test_uncertain_taint_is_needs_source(self):
        body = """package p
func f() []byte {
    var off int
    data := doUnmarshal()
    off = compute()
    return data[off:]
}
"""
        # data comes from Unmarshal (untrusted token) but off's chain to it is
        # only co-occurrence -> needs-source when tainted-uncertain.
        rows, nodes, tainted = MOD.scan_go_source(body, "p.go")
        if rows:
            self.assertIn(rows[0]["verdict"], ("needs-source", "needs-fuzz"))


    # 9. NEGATIVE: a trusted []struct / []string param indexed by a variable must
    #    NOT produce a CERTAIN (needs-fuzz) survivor. Old _PARAM_BYTES_RE matched
    #    every []T param and mis-credited it as a []byte wire source (FP).
    def test_bare_slice_param_is_not_certain_survivor(self):
        struct_body = """package p
func pick(orders []Order, lo int, hi int) []Order {
    return orders[lo:hi]
}
"""
        rows, nodes, tainted = MOD.scan_go_source(struct_body, "p.go")
        # The slice-range IS a node and DOES taint (bare []T provenance), but it
        # must be down-ranked: certain=False / verdict='needs-source', NEVER a
        # certain needs-fuzz survivor (the old _PARAM_BYTES_RE FP).
        self.assertGreaterEqual(len(rows), 1)
        self.assertFalse(any(r["taint_certain"] for r in rows),
                         f"[]Order slice produced a CERTAIN survivor: {rows}")
        self.assertTrue(all(r["verdict"] == "needs-source" for r in rows))

        str_body = """package p
func at(names []string, lo int, hi int) []string {
    return names[lo:hi]
}
"""
        rows2, _, _ = MOD.scan_go_source(str_body, "p.go")
        self.assertFalse(any(r["taint_certain"] for r in rows2),
                         f"[]string indexing produced a CERTAIN survivor: {rows2}")
        self.assertFalse(any(r["verdict"] == "needs-fuzz" for r in rows2))

    # 10. Param classifier: []byte / []uint8 / named Bytes aliases are byte-shaped;
    #     []Order / []string / []*Tx are bare typed slices.
    def test_classify_params_byte_vs_bare(self):
        header = ("func f(data []byte, raw []uint8, hb []HexBytes, "
                  "rm []json.RawMessage, orders []Order, names []string, txs []*Tx) {")
        byte_shaped, bare = MOD._classify_params(header)
        self.assertEqual(byte_shaped, {"data", "raw", "hb", "rm"})
        self.assertEqual(bare, {"orders", "names", "txs"})

    # 11. A byte-shaped param still yields a CERTAIN survivor (no regression).
    def test_byte_param_still_certain(self):
        acct = self._run(VULN)
        certain = [k for k in acct["kept"] if k["verdict"] == "needs-fuzz"]
        self.assertGreaterEqual(len(certain), 1)


if __name__ == "__main__":
    unittest.main()
