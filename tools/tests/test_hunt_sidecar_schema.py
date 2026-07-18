"""Golden-corpus test for tools/lib/hunt_sidecar_schema.py - the ONE canonical
hunt-verdict sidecar parser. Guards the recurring serving-join family (a reader
blind to a schema it did not hand-roll for). Every accepted schema + the R80
credit-gating must hold here so a schema change is a single-file edit.
"""
import importlib.util
import os
import sys
import unittest

_P = os.path.join(os.path.dirname(__file__), "..", "lib", "hunt_sidecar_schema.py")
_spec = importlib.util.spec_from_file_location("hunt_sidecar_schema", _P)
hss = importlib.util.module_from_spec(_spec)
# Register BEFORE exec so the @dataclass can resolve its own __module__ (Python 3.14).
sys.modules["hunt_sidecar_schema"] = hss
_spec.loader.exec_module(hss)

FILE = "/ws/src/x/evm/keeper/msg_server.go"


class TestSchemaNormalization(unittest.TestCase):
    # ---- (a) native FLAT ------------------------------------------------
    def test_flat_negative_with_excerpt_engaged_and_credits(self):
        r = {"unit": "msg_server.go::Send", "file": FILE, "function": "Send",
             "lines": "237", "verdict": "NEGATIVE", "applies_to_target": "no",
             "cited_excerpt": "FromAddress bound by GetSigners", "status": "ok"}
        nv = hss.normalize_sidecar_record(r)
        self.assertTrue(nv.is_flat)
        self.assertEqual(nv.unit_key, "msg_server.go::Send")
        self.assertTrue(nv.engaged)
        self.assertTrue(nv.credit_ok)          # has excerpt -> R80 satisfied
        self.assertEqual(nv.file_line, "msg_server.go:237")

    def test_flat_negative_NO_excerpt_engaged_but_no_credit(self):
        # R80: prose-only "no" parses + is engaged, but must NOT credit.
        r = {"unit": "f.go::Bar", "file": "/ws/f.go", "function": "Bar",
             "lines": "10", "verdict": "NEGATIVE", "applies_to_target": "no"}
        nv = hss.normalize_sidecar_record(r)
        self.assertTrue(nv.engaged)
        self.assertFalse(nv.credit_ok)

    def test_flat_verdict_only_maps_applies(self):
        nv = hss.normalize_sidecar_record({"file": FILE, "function": "X", "verdict": "NEGATIVE",
                                           "cited_excerpt": "guard"})
        self.assertEqual(nv.applies_to_target, "no")
        self.assertTrue(nv.credit_ok)

    def test_flat_positive_is_finding(self):
        nv = hss.normalize_sidecar_record({"file": FILE, "function": "X", "verdict": "CONFIRMED",
                                           "cited_excerpt": "bug at L5"})
        self.assertTrue(nv.is_finding)
        self.assertEqual(nv.applies_to_target, "yes")

    # ---- (b) nested-result (dict AND json-string) -----------------------
    def test_nested_dict_result(self):
        r = {"status": "ok", "function_anchor": {"file": FILE, "fn": "Send"},
             "result": {"applies_to_target": "no", "file_line": "msg_server.go:237",
                        "code_excerpt": "signer check"}}
        nv = hss.normalize_sidecar_record(r)
        self.assertTrue(nv.is_nested)
        self.assertEqual(nv.unit_key, "msg_server.go::Send")
        self.assertTrue(nv.credit_ok)

    def test_nested_jsonstring_result(self):
        import json
        r = {"status": "ok", "function_anchor": {"file": FILE, "fn": "Send"},
             "result": json.dumps({"applies_to_target": "no", "file_line": "msg_server.go:237",
                                   "code_excerpt": "signer check"})}
        nv = hss.normalize_sidecar_record(r)
        self.assertTrue(nv.is_nested)
        self.assertTrue(nv.credit_ok)

    def test_nested_failed_status_not_engaged(self):
        r = {"status": "failed", "function_anchor": {"file": FILE, "fn": "Send"},
             "result": None}
        nv = hss.normalize_sidecar_record(r)
        self.assertFalse(nv.engaged)

    # ---- (c) file_line variant -----------------------------------------
    def test_file_line_variant(self):
        r = {"file_line": "foo.go:53", "function": "Foo", "verdict": "NEGATIVE",
             "code_excerpt": "if x==nil"}
        nv = hss.normalize_sidecar_record(r)
        self.assertTrue(nv.credit_ok)

    # ---- discard / empty ------------------------------------------------
    def test_dropped_disposition_no_credit(self):
        r = {"file": FILE, "function": "X", "verdict": "NEGATIVE", "applies_to_target": "no",
             "cited_excerpt": "cite", "reasoning": "dropped as a false-positive by reasoning"}
        nv = hss.normalize_sidecar_record(r)
        self.assertFalse(nv.credit_ok)          # DROP -> no credit

    def test_empty_record_is_none(self):
        self.assertIsNone(hss.normalize_sidecar_record({}))
        self.assertIsNone(hss.normalize_sidecar_record("not a dict"))

    # ---- convenience wrappers ------------------------------------------
    def test_wrappers(self):
        r = {"file": FILE, "function": "Send", "verdict": "NEGATIVE",
             "cited_excerpt": "c", "status": "ok"}
        self.assertEqual(hss.unit_key(r), "msg_server.go::Send")
        self.assertTrue(hss.is_engaged(r))
        self.assertTrue(hss.is_terminal(r))
        self.assertTrue(hss.credit_ok(r))


if __name__ == "__main__":
    unittest.main()
