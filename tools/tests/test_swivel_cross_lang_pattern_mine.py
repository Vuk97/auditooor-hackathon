#!/usr/bin/env python3
# r36-rebuttal: lane swivel-xlang-gapfix registered in agent_pathspec.json; sole writer of this test file
"""Sibling tests for tools/swivel-cross-lang-pattern-mine.py.

The tool mines the swivel rust + go public-archive corpus and emits
go<->rust cross-language pattern pairs. These tests lock:
  - the language-neutral attack-class classifier (`classify`),
  - the go<->rust pairing + lift-verdict logic (`build_pairs`),
  - Rule 37: every emitted pair declares verification_tier at emit time,
    and the tier is the expected tier-2-verified-public-archive value.

The tool filename is hyphenated, so it is loaded via importlib.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "swivel-cross-lang-pattern-mine.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("swivel_cross_lang_pattern_mine", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


class TestClassify(unittest.TestCase):
    def test_crypto_text_maps_to_crypto_primitive_misuse(self):
        # ecdsa / tls / x509 etc. are crypto_primitive_misuse triggers.
        classes = MOD.classify("ECDSA scalar not enforced near infinity on the TLS path")
        self.assertIn("crypto_primitive_misuse", classes)

    def test_bounds_text_maps_to_length_bounds_check(self):
        classes = MOD.classify("unchecked length leads to out-of-bounds over-read")
        self.assertIn("length_bounds_check", classes)

    def test_unmatched_text_falls_back_to_uncategorized(self):
        # No regex rule fires -> the classifier must never return empty.
        classes = MOD.classify("a perfectly ordinary sentence about nothing in particular")
        self.assertEqual(classes, ["uncategorized"])


class TestBuildPairsGoRustLogic(unittest.TestCase):
    def _rust(self, fid, classes):
        return {
            "language": "rust",
            "finding_id": fid,
            "title": f"rust finding {fid}",
            "attack_classes": classes,
            "primary_attack_class": classes[0],
            "bug_class": "",
        }

    def _go(self, fid, classes):
        return {
            "language": "go",
            "finding_id": fid,
            "title": f"go finding {fid}",
            "attack_classes": classes,
            "primary_attack_class": classes[0],
            "bug_class": "go.bug.class",
        }

    def test_bidirectional_when_class_in_both_languages(self):
        rust = [self._rust("swival-rust-stdlib-1", ["crypto_primitive_misuse"])]
        go = [self._go("swival-go-crypto-1", ["crypto_primitive_misuse"])]
        pairs = MOD.build_pairs(rust, go)
        byclass = {p["attack_class"]: p for p in pairs}
        self.assertIn("crypto_primitive_misuse", byclass)
        self.assertEqual(
            byclass["crypto_primitive_misuse"]["lift_verdict"], "bidirectional-analogue"
        )
        self.assertEqual(byclass["crypto_primitive_misuse"]["rust_count"], 1)
        self.assertEqual(byclass["crypto_primitive_misuse"]["go_count"], 1)

    def test_rust_only_lift_candidate(self):
        rust = [self._rust("swival-rust-stdlib-2", ["unsafe_memory_pointer"])]
        go = [self._go("swival-go-crypto-2", ["panic_dos"])]
        byclass = {p["attack_class"]: p for p in MOD.build_pairs(rust, go)}
        self.assertEqual(
            byclass["unsafe_memory_pointer"]["lift_verdict"], "rust-only-lift-to-go-candidate"
        )
        self.assertEqual(byclass["unsafe_memory_pointer"]["go_count"], 0)

    def test_go_only_lift_candidate(self):
        rust = [self._rust("swival-rust-stdlib-3", ["simd_cpu_feature"])]
        go = [self._go("swival-go-crypto-3", ["resource_leak"])]
        byclass = {p["attack_class"]: p for p in MOD.build_pairs(rust, go)}
        self.assertEqual(
            byclass["resource_leak"]["lift_verdict"], "go-only-lift-to-rust-candidate"
        )
        self.assertEqual(byclass["resource_leak"]["rust_count"], 0)


class TestRule37VerificationTier(unittest.TestCase):
    @staticmethod
    def _make_row(lang, fid, classes):
        return {
            "language": lang,
            "finding_id": fid,
            "title": f"{lang} {fid}",
            "attack_classes": classes,
            "primary_attack_class": classes[0],
            "bug_class": "",
        }

    def test_tier_constant_is_tier2_public_archive(self):
        # R37: tier declared as a first-class constant, not smuggled into tags.
        self.assertEqual(MOD.VERIFICATION_TIER, "tier-2-verified-public-archive")

    def test_every_emitted_pair_carries_verification_tier(self):
        rust = [
            self._make_row("rust", "swival-rust-stdlib-9", ["crypto_primitive_misuse"]),
            self._make_row("rust", "swival-rust-stdlib-10", ["length_bounds_check"]),
        ]
        go = [
            self._make_row("go", "swival-go-crypto-9", ["crypto_primitive_misuse"]),
            self._make_row("go", "swival-go-crypto-10", ["panic_dos"]),
        ]
        pairs = MOD.build_pairs(rust, go)
        self.assertTrue(pairs, "expected at least one emitted pair")
        for p in pairs:
            self.assertEqual(
                p.get("verification_tier"),
                "tier-2-verified-public-archive",
                f"pair for class {p.get('attack_class')!r} missing R37 tier",
            )
            self.assertEqual(p.get("schema"), MOD.SCHEMA_PAIRS)


if __name__ == "__main__":
    unittest.main()
