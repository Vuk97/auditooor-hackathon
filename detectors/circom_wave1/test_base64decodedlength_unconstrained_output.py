from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import base64decodedlength_unconstrained_output as detector


FIXTURES = Path(__file__).resolve().parent / "test_fixtures"


class Base64DecodedLengthUnconstrainedOutputTests(unittest.TestCase):
    def test_flags_unconstrained_decoded_len(self) -> None:
        fixture = FIXTURES / "base64decodedlength_unconstrained_output_positive.circom"
        hits = detector.scan_file(fixture)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["template"], "Base64DecodedLength")
        self.assertEqual(hits[0]["output"], "decoded_len")

    def test_ignores_constrained_decoded_len(self) -> None:
        fixture = FIXTURES / "base64decodedlength_unconstrained_output_negative.circom"
        self.assertEqual(detector.scan_file(fixture), [])

    def test_comment_does_not_count_as_constraint(self) -> None:
        source = """
template Base64DecodedLength(maxN) {
    signal output decoded_len;
    signal q;
    // decoded_len <== q;
}
"""
        hits = detector.scan_text(source)
        self.assertEqual(len(hits), 1)

    def test_non_target_template_is_ignored(self) -> None:
        source = """
template OtherLength(maxN) {
    signal output decoded_len;
}
"""
        self.assertEqual(detector.scan_text(source), [])


if __name__ == "__main__":
    unittest.main()
