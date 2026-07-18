#!/usr/bin/env python3
"""Guard test: guard-negative-space-analyzer must skip Rust #[cfg(test)] guards.

Regression: guard-context-extract.py (probe-packet emit) was test-filtered in
commit 5a10022e70, but the WORKLIST emitter guard-negative-space-analyzer.py was
not. Result on optimism op-reth: negative_space_worklist.jsonl carried ~910
#[cfg(test)] assert_eq! oracles (1905 rows) that the probe never received (995
packets), so depth_certificate_build rolled up 234 enumerated-but-unadjudicated
guards and the cert was pinned at depth-pending forever. Both tools must now share
scope_exclusion.rust_test_line_ranges so the worklist == the probe set.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "guard-negative-space-analyzer.py"
_spec = importlib.util.spec_from_file_location("gnsa", _TOOL)
gnsa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gnsa)


_RUST_SRC = """\
pub fn to_genesis_chain_config(cfg: &ChainMetadata) -> ChainConfig {
    assert!(cfg.chain_id != 0);          // PRODUCTION guard - KEEP
    ChainConfig { chain_id: cfg.chain_id }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_to_genesis_chain_config() {
        let cc = to_genesis_chain_config(&cfg);
        assert_eq!(cc.eip150_block, Some(0));   // TEST oracle - DROP
        assert_eq!(cc.eip155_block, Some(0));   // TEST oracle - DROP
        assert_eq!(cc.byzantium_block, Some(0));// TEST oracle - DROP
    }
}
"""


class NegativeSpaceTestFilterTest(unittest.TestCase):
    def test_scan_skips_cfg_test_asserts(self):
        ws = Path(tempfile.mkdtemp())
        rel = "src/rust/op-reth/crates/chainspec/src/superchain/chain_metadata.rs"
        (ws / Path(rel).parent).mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text(_RUST_SRC, encoding="utf-8")

        hits = gnsa._scan_file_for_guards(ws, rel)
        lines = {h["line"] for h in hits}
        texts = " ".join(h["text"] for h in hits)

        # the production assert! (line 2) survives
        self.assertIn(2, lines, "production guard at line 2 was wrongly dropped")
        # none of the three #[cfg(test)] assert_eq! oracles survive
        self.assertNotIn("eip150_block", texts)
        self.assertNotIn("eip155_block", texts)
        self.assertNotIn("byzantium_block", texts)

    def test_shared_helper_used(self):
        # the analyzer must route through the single-source helper so it cannot
        # drift from guard-context-extract's probe-packet emitter.
        self.assertTrue(hasattr(gnsa._scope_exclusion, "rust_test_line_ranges"))
        rng = gnsa._scope_exclusion.rust_test_line_ranges(_RUST_SRC.splitlines())
        self.assertTrue(rng, "shared helper found no test range in a #[cfg(test)] mod")


class DevToolingConfigFilterTest(unittest.TestCase):
    """Guard: dev-tooling / build-config files carry NO on-chain value-moving guard
    and must be excluded from guard enumeration. Regression (nuva): a negative-space
    'guard' NS-... at src/nuva-evm-contracts/hardhat.config.js:1 was enumerated but
    never genuinely adjudicable, leaving 1 incomplete_guard_delta that pinned the
    depth certificate at depth-pending forever (blocking audit-complete). The filter
    is BASENAME-based so it never drops a real Oscript/JS contract source."""

    def test_is_dev_tooling_config_classifies(self):
        for p in ("src/x/hardhat.config.js", "hardhat.config.ts", "foundry.toml",
                  "webpack.config.js", "package.json", "remappings.txt",
                  "a/b/jest.config.ts"):
            self.assertTrue(gnsa._is_dev_tooling_config(p), f"{p} should be dev-tooling")
        for p in ("ocore/aa_validation.js", "src/vault/keeper/reconcile.go",
                  "src/Vault.sol", "contracts/Token.sol", "agents/definitions.js"):
            self.assertFalse(gnsa._is_dev_tooling_config(p), f"{p} is a real source, keep")

    def test_load_inscope_units_skips_dev_tooling_config(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        rows = [
            {"file": "src/nuva-evm-contracts/hardhat.config.js", "function": "", "file_line": "hardhat.config.js:1"},
            {"file": "src/Vault.sol", "function": "deposit", "file_line": "Vault.sol:42"},
        ]
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        units = gnsa._load_inscope_units(ws)
        files = {u["file"] for u in units}
        self.assertIn("src/Vault.sol", files, "real contract wrongly dropped")
        self.assertNotIn("src/nuva-evm-contracts/hardhat.config.js", files,
                         "hardhat.config.js dev-tooling config wrongly enumerated as a guard-bearing unit")


if __name__ == "__main__":
    unittest.main()
