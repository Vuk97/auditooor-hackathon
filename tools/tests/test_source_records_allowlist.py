#!/usr/bin/env python3
# <!-- r36-rebuttal: lane SOURCE-RECORDS-ALLOWLIST registered in commit message -->
"""Strata 2026-06-30: _source_file_records (feeds per-fn preflight + coverage denominator)
honored is_oos + scope_globs but NOT the SCOPE.md enumerated allowlist, so an "exactly N
targets" Immunefi scope leaked OOS files (lens/swap/Strategy) into the preflight, which
generated per-fn MCP packs over the whole repo (unbounded). Pins: _source_file_records
drops out-of-allowlist files when an allowlist exists; whole-repo docs unchanged."""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "workspace-coverage-heatmap.py"
spec = importlib.util.spec_from_file_location("wch", _TOOL)
wch = importlib.util.module_from_spec(spec); sys.modules["wch"] = wch; spec.loader.exec_module(wch)


def _ws(scope_text, files):
    d = Path(tempfile.mkdtemp(prefix="wsr_"))
    (d / "SCOPE.md").write_text(scope_text, encoding="utf-8")
    for rel in files:
        p = d / rel; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// solidity\ncontract C { function f() public {} }\n", encoding="utf-8")
    return d

_ENUM = "# SCOPE\n## IN SCOPE\n1. tranches/Tranche.sol\n2. governance/\n## OOS\n- 51%\n"
_WHOLE = "# SCOPE\n## In scope\nwhole repo\n"
_FILES = ["src/tranches/Tranche.sol", "src/governance/ACM.sol",
          "src/tranches/Strategy.sol", "src/lens/CDOLens.sol"]

# NUVA 2026-07-01: an Immunefi ADDRESS-scope SCOPE.md - the enumerated in-scope
# tokens are deployed addresses / symbolic names, NOT file paths. Non-empty but
# non-path-like, so it must NOT be used as a per-file allowlist (it matches zero
# real source files and empties the coverage denominator).
_ADDR = (
    "# SCOPE\n## Assets In Scope\n"
    "- Ethereum `ETH_NVPRIME_VAULT_ROUTER`: `0x50AE1e4A612A4623b747aEeFb30aFBA82804e12c`\n"
    "- Ethereum `ETH_NVPRIME_VAULT`: `0xC360e625F19A7ea47e47810B13E386221d5187D1`\n"
    "- Provenance `nvYLDS Vault Address`: `pb15y0f2zkc9a2cgyqkhpp3z9u6fmvtegf92s7ndx`\n"
    "## OOS\n- 51%\n"
)
# real in-scope source files live under the scope_globs dirs (src/vault, src/nuva-evm-contracts)
_ADDR_FILES = ["src/nuva-evm-contracts/contracts/CrossChainManager.sol",
               "src/vault/keeper/valuation_engine.go"]


class SourceRecordsAllowlistTest(unittest.TestCase):
    def test_allowlist_drops_oos_source_files(self):
        ws = _ws(_ENUM, _FILES)
        scope = wch.resolve_scope(ws)
        recs = wch._source_file_records(ws, scope)
        paths = [r.get("path", "") for r in recs]
        self.assertTrue(any("Tranche.sol" in p for p in paths))
        self.assertTrue(any("governance/ACM.sol" in p for p in paths))
        self.assertFalse(any("Strategy.sol" in p for p in paths), "OOS Strategy must be dropped")
        self.assertFalse(any("lens/" in p for p in paths), "OOS lens/ must be dropped")

    def test_whole_repo_doc_keeps_all(self):
        ws = _ws(_WHOLE, _FILES)
        scope = wch.resolve_scope(ws)
        recs = wch._source_file_records(ws, scope)
        # no enumerated allowlist -> allowlist filter is a NOOP (is_oos still applies, but
        # none of these are test/vendored) -> all 4 kept
        self.assertEqual(len([r for r in recs if r.get("path","").endswith(".sol")]), 4)

    def test_loader_returns_none_without_allowlist(self):
        ws = _ws(_WHOLE, [])
        mf, smp = wch._load_scope_md_allowlist(ws)
        self.assertIsNone(mf)

    def test_address_only_scope_is_not_a_file_allowlist(self):
        # NUVA regression: address/symbol-only enumerated scope must be treated as
        # ABSENT for the per-file allowlist (it can never match a source path).
        ws = _ws(_ADDR, _ADDR_FILES)
        mf, smp = wch._load_scope_md_allowlist(ws)
        self.assertIsNone(mf, "address/symbol-only scope must not be a file allowlist")

    def test_address_only_scope_keeps_source_denominator(self):
        # The whole coverage-map FAIL: an address-scope emptied _source_file_records
        # (0 units vs 205 inscope). With the fix the real source files survive.
        ws = _ws(_ADDR, _ADDR_FILES)
        scope = wch.resolve_scope(ws)
        recs = wch._source_file_records(ws, scope)
        paths = [r.get("path", "") for r in recs]
        self.assertTrue(any("CrossChainManager.sol" in p for p in paths),
                        "in-scope EVM source must survive an address-only scope")
        self.assertTrue(len(recs) >= 1, "denominator must not be emptied by address-only scope")

    def test_path_like_token_classifier(self):
        self.assertTrue(wch._scope_token_is_path_like("tranches/Tranche.sol"))
        self.assertTrue(wch._scope_token_is_path_like("Vault.sol"))
        self.assertTrue(wch._scope_token_is_path_like("keeper/valuation_engine.go"))
        self.assertFalse(wch._scope_token_is_path_like("ETH_NVPRIME_VAULT_ROUTER"))
        self.assertFalse(wch._scope_token_is_path_like("0x50AE1e4A612A4623b747aEeFb30aFBA82804e12c"))
        self.assertFalse(wch._scope_token_is_path_like("pb15y0f2zkc9a2cgyqkhpp3z9u6fmvtegf92s7ndx"))
        self.assertFalse(wch._scope_token_is_path_like("nvYLDS Vault Address"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
