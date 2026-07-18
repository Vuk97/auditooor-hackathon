"""Container/heap.Interface trivial-method filter (SEI 2026-07-05).

A Go `func (h logMergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }` must NOT be
matched against a Solidity AMM `swap` sibling-guard packet on the shared identifier. The
filter suppresses trivial Len/Less/Swap/Push/Pop plumbing while leaving a same-named
function that contains real logic untouched.
"""
import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "cif", str(Path(__file__).resolve().parents[1] / "lib" / "container_interface_filter.py")
)
cif = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cif)


class ContainerInterfaceFilterTest(unittest.TestCase):
    def test_heap_swap_is_trivial(self):
        self.assertTrue(cif.is_trivial_container_interface_method(
            "Swap", "{ h[i], h[j] = h[j], h[i] }"))

    def test_len_is_trivial(self):
        self.assertTrue(cif.is_trivial_container_interface_method("Len", "{ return len(h) }"))

    def test_less_is_trivial(self):
        self.assertTrue(cif.is_trivial_container_interface_method(
            "Less", "{ return h[i].ts < h[j].ts }"))

    def test_push_pop_are_trivial(self):
        self.assertTrue(cif.is_trivial_container_interface_method(
            "Push", "{ *h = append(*h, x.(*node)) }"))
        pop = ("{\n\told := *h\n\tn := len(old)\n\tx := old[n-1]\n"
               "\t*h = old[:n-1]\n\treturn x\n}")
        self.assertTrue(cif.is_trivial_container_interface_method("Pop", pop))

    def test_non_container_name_never_trivial(self):
        # a real business swap must never be suppressed by name alone
        self.assertFalse(cif.is_trivial_container_interface_method(
            "swapExactTokensForTokens", "{ h[i], h[j] = h[j], h[i] }"))

    def test_container_name_with_real_logic_NOT_suppressed(self):
        # never-false-suppress: a method named Swap that calls into keeper/state keeps priority
        body = ("{\n\tk.bankKeeper.SendCoins(ctx, a, b, amt)\n"
                "\tif err != nil { return err }\n\treturn k.settle(ctx)\n}")
        self.assertFalse(cif.is_trivial_container_interface_method("Swap", body))

    def test_empty_body_not_trivial(self):
        self.assertFalse(cif.is_trivial_container_interface_method("Swap", ""))

    def test_is_container_method_name(self):
        self.assertTrue(cif.is_container_method_name("Swap"))
        self.assertTrue(cif.is_container_method_name("Pop"))
        self.assertFalse(cif.is_container_method_name("swap"))  # case-sensitive
        self.assertFalse(cif.is_container_method_name("deposit"))


if __name__ == "__main__":
    unittest.main()
