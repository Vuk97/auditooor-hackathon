#!/usr/bin/env python3
"""Regression: the ERC-4626 vault + tranching protocol-family invariant sets exist,
parse, and drive the completeness-matrix family-invariant RECALL (the code's own
"biggest false-negative surface"). Verified 2026-07-07: before this, no vault/
tranching family existed, so an ERC-4626 CDO (Strata/morpho/etherfi) got ZERO
family-specific invariant requirement - "all invariants held" was vacuous over a
thin generic set."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("cm", _H.parent / "completeness-matrix-build.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def test_family_files_exist_and_parse(self):
        base = _H.parent.parent / "audit" / "corpus_tags" / "derived"
        for fam in ("erc4626_vault", "tranching"):
            p = base / f"invariant_family_{fam}.jsonl"
            self.assertTrue(p.is_file(), f"missing {p}")
            rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(rows), 5, f"{fam} too few invariants")
            for r in rows:
                self.assertIn(r["category"], m.CANONICAL_INVARIANT_CATEGORIES)
                self.assertTrue(r["statement"].strip())

    def test_required_categories_cover_crown_jewel_classes(self):
        req = m._family_required_categories(["erc4626_vault", "tranching"])
        union = set().union(*req.values())
        # tranching MUST require the classes that catch the real bug families:
        for cat in ("conservation", "ordering", "custody", "determinism", "monotonicity", "bounds"):
            self.assertIn(cat, union, f"family recall must require {cat}")

    def _ws(self, sol_body):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / "src").mkdir()
        (ws / "src" / "Thing.sol").write_text(sol_body)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/Thing.sol", "function": "f"}) + "\n")
        return ws

    def test_detects_tranching_vault_with_two_discriminators(self):
        # >=2 distinct discriminators per family (a 4626 vault has convertToShares +
        # convertToAssets; a tranching protocol has tranche + junior + senior).
        ws = self._ws("contract Cdo { function convertToShares() external {} "
                      "function convertToAssets() external {} uint256 seniorNav; "
                      "uint256 juniorNav; // tranche senior junior waterfall srt jrt\n}")
        fams = m._detect_protocol_families(ws)
        self.assertIn("tranching", fams)
        self.assertIn("erc4626_vault", fams)

    def test_single_discriminator_does_not_tag(self):
        # over-detection guard (3-ws fix): ONE incidental discriminator must NOT claim a
        # family - a large multi-domain protocol mentions convertToShares once without
        # being a vault.
        ws = self._ws("contract Thing { function convertToShares() external {} "
                      "function deposit() external {} uint256 shares; }")
        self.assertNotIn("erc4626_vault", m._detect_protocol_families(ws))

    def test_generic_defi_not_mistagged(self):
        # cues present (deposit/vault/shares) but NO discriminating tokens -> not tagged.
        ws = self._ws("contract Staking { function deposit() external {} uint256 shares; }")
        fams = m._detect_protocol_families(ws)
        self.assertNotIn("tranching", fams)
        self.assertNotIn("erc4626_vault", fams)


if __name__ == "__main__":
    unittest.main()
