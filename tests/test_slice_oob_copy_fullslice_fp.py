"""Regression: slice-oob-bounds-taint does not flag a memory-safe Go copy() over a
full-slice / constant-bound argument as an OOB survivor (2026-07-14).

Go's builtin copy(dst,src) copies min(len(dst),len(src)) and can never OOB/panic. The
only OOB risk on a copy line is a slice EXPRESSION with a VARIABLE bound inside src/dst
(e.g. src[off:end]) - already caught independently by the slice-range detector. A bare
full-slice `x[:]` or a constant-bound slice is provably in-bounds. This was the dominant
slice-oob false-positive class on axelar (a[:] / h[:] / c[:] / idBz[:]).
"""
import importlib.util
import pathlib
import sys
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "slice-oob-bounds-taint.py"
_spec = importlib.util.spec_from_file_location("_slice_oob_fp", _TOOL)
_m = importlib.util.module_from_spec(_spec)
sys.modules["_slice_oob_fp"] = _m
_spec.loader.exec_module(_m)


class SliceOobCopyFullSliceFP(unittest.TestCase):
    def test_full_slice_bound_is_not_variable(self):
        self.assertFalse(_m._has_variable_slice_bound("a[:]"))
        self.assertFalse(_m._has_variable_slice_bound("copy dst, h[:]"))

    def test_constant_bound_is_not_variable(self):
        self.assertFalse(_m._has_variable_slice_bound("idBz[:32]"))
        self.assertFalse(_m._has_variable_slice_bound("x[3]"))

    def test_variable_bound_is_flagged(self):
        self.assertTrue(_m._has_variable_slice_bound("fullKey[addressOffset:]"))
        self.assertTrue(_m._has_variable_slice_bound("src[off:end]"))
        self.assertTrue(_m._has_variable_slice_bound("buf[i]"))

    def test_copy_fullslice_not_emitted(self):
        # copy(a, b[:]) -> no variable-bounded slice -> not an OOB survivor
        rows = _m.is_slice_node("\tcopy(a, h[:])")
        self.assertFalse(any(r[0] == "copy" for r in rows),
                         "a full-slice copy must not be an OOB survivor")

    def test_copy_variable_slice_emitted(self):
        rows = _m.is_slice_node("\tcopy(dst, fullKey[addressOffset:])")
        self.assertTrue(any(r[0] == "copy" for r in rows),
                        "a variable-bounded slice inside copy must still be surfaced")


if __name__ == "__main__":
    unittest.main()


class SliceOobMapIndexFP(unittest.TestCase):
    """Go maps never OOB (missing key -> zero value / comma-ok); map[K]V is a type
    literal, not an index. Neither is a slice-index OOB risk (2026-07-14 axelar FP)."""

    def test_map_type_literal_not_index(self):
        rows = _m.is_slice_node("\tfunc (m Command) DecodeParams() (map[string]string, error) {")
        self.assertFalse(any(r[0] == "index" for r in rows),
                         "map[K]V type literal must not be an index survivor")

    def test_map_type_assertion_not_index(self):
        rows = _m.is_slice_node("\t\targs, ok := msg.(map[string]interface{})")
        self.assertFalse(any(r[0] == "index" for r in rows),
                         "a map type assertion must not be an index survivor")

    def test_comma_ok_map_access_not_index(self):
        rows = _m.is_slice_node("\troute, ok := r.routes[msg.Recipient.Chain.Module]")
        self.assertFalse(any(r[0] == "index" for r in rows),
                         "a comma-ok map access must not be an index survivor")

    def test_real_slice_index_still_flagged(self):
        rows = _m.is_slice_node("\tx := data[offset]")
        self.assertTrue(any(r[0] == "index" for r in rows),
                        "a genuine variable slice index must still be surfaced")


class SliceOobMakeAndCliFP(unittest.TestCase):
    """make([]T, len(x)) is bounded by existing allocation (can't OOB/OOM on attacker
    input); client/cli tx builders are not consensus-reachable. Both 2026-07-14."""

    def test_make_of_len_is_bounded(self):
        for e in ("len(addrs", "len(commandIDs", "len(txIDs", "len(a)+len(b)", "len(args[3:]"):
            self.assertTrue(_m._is_len_bounded(e), f"{e} must be len-bounded")

    def test_make_of_raw_int_not_bounded(self):
        for e in ("msg.Size", "len(x)*n", "attackerLen"):
            self.assertFalse(_m._is_len_bounded(e), f"{e} must NOT be len-bounded (attacker)")

    def test_make_of_len_not_emitted(self):
        rows = _m.is_slice_node("\taddr := make(sdk.ValAddress, len(addrs))")
        self.assertFalse(any(r[0] == "make" for r in rows),
                         "make([]T, len(x)) must not be a survivor")

    def test_make_of_attacker_int_still_emitted(self):
        rows = _m.is_slice_node("\tbuf := make([]byte, msg.Size)")
        self.assertTrue(any(r[0] == "make" for r in rows),
                        "make([]byte, attackerInt) must still be surfaced")
