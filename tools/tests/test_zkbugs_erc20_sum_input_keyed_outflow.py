#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "circom_wave1" / "zkbugs_erc20_sum_input_keyed_outflow.py"
FIXTURES = ROOT / "detectors" / "circom_wave1" / "test_fixtures"


def _load_detector():
    spec = importlib.util.spec_from_file_location("zkbugs_erc20_sum_input_keyed_outflow", DETECTOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsErc20SumInputKeyedOutflowTest(unittest.TestCase):
    def test_flags_outflow_sum_keyed_only_by_input_token_addresses(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "zkbugs_erc20_sum_input_keyed_outflow_positive.circom").read_text(
            encoding="utf-8"
        )

        hits = detector.erc20_sum_input_keyed_outflow_hits(source)

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "medium")
        self.assertEqual(hits[0]["template"], "ZkTransactionLike")
        self.assertEqual(hits[0]["outflow_component"], "outflow_erc20")
        self.assertEqual(hits[0]["input_addr"], "spending_note_token_addr")

    def test_accepts_same_sum_shape_with_output_membership_guard(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "zkbugs_erc20_sum_input_keyed_outflow_negative.circom").read_text(
            encoding="utf-8"
        )

        self.assertEqual(detector.erc20_sum_input_keyed_outflow_hits(source), [])

    def test_comment_membership_hint_does_not_suppress_hit(self) -> None:
        detector = _load_detector()
        source = """
        template Tx(nIn, nOut) {
            signal input spending_note_token_addr[nIn];
            signal input output_note_token_addr[nOut];
            component inflow_erc20[nIn] = ERC20Sum(nIn);
            component outflow_erc20[nIn] = ERC20Sum(nOut);
            for (var i = 0; i < nIn; i++) {
                // AllOutputsInInputs();
                outflow_erc20[i].addr <== spending_note_token_addr[i];
                inflow_erc20[i].out === outflow_erc20[i].out;
            }
        }
        """

        self.assertEqual(len(detector.erc20_sum_input_keyed_outflow_hits(source)), 1)


if __name__ == "__main__":
    unittest.main()
