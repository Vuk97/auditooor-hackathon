"""Tests for the contract-kind classifier proxy-vs-vault disambiguation in
tools/hacker_question_renderer.py.

Covers the L6 fix: the bare adjective "upgradeable" is boilerplate in nearly
every Immunefi SEVERITY.md/scope text, so it must NOT win the generic "proxy"
rule on its own. A genuine ERC-4626 DeFi vault scope that merely contains
"upgradeable" must classify as "vault" (so the lead impact is the vault family -
share-inflation/theft/insolvency - not access-control-bypass/unauthorized-upgrade).
A real proxy/upgrade-admin contract must still classify as "proxy".

Mirrors test_hacker_question_renderer_impact.py's loader style. Per Python 3.14,
the module is registered in sys.modules BEFORE exec_module so the module's own
`from __future__` / self-referential imports resolve.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_renderer():
    spec = importlib.util.spec_from_file_location(
        "hacker_question_renderer", str(TOOLS_DIR / "hacker_question_renderer.py")
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    # Python 3.14: register before exec so the module is importable by name
    # during its own execution.
    sys.modules["hacker_question_renderer"] = mod
    spec.loader.exec_module(mod)
    return mod


R = _load_renderer()


def _kind(scope_text: str) -> str:
    return R.classify_impact_target(scope_text=scope_text)["contract_kind"]


class TestProxyVsVaultDisambiguation(unittest.TestCase):
    """L6: bare 'upgradeable' must not steal a vault into the proxy family."""

    def test_erc4626_upgradeable_vault_classifies_vault(self):
        # Strata-shaped scope text: an ERC-4626 meta-vault whose SEVERITY/scope
        # text carries the boilerplate adjective "upgradeable". Pre-fix this was
        # mis-classified "proxy".
        scope = (
            "Strata = general-purpose risk-tranching protocol. Splits underlying "
            "yield into tokenized Senior + Junior tranches (ERC-4626 meta-vaults). "
            "The vaults are upgradeable and use previewDeposit / convertToShares."
        )
        self.assertEqual(_kind(scope), "vault")

    def test_bare_upgradeable_adjective_alone_does_not_win_proxy(self):
        # No vault/lending/amm/token signal, just the bare adjective: it must not
        # be enough to classify "proxy".
        self.assertNotEqual(_kind("This contract is upgradeable."), "proxy")

    def test_pure_proxy_admin_still_classifies_proxy(self):
        # A genuine proxy/upgrade-admin contract (real proxy noun + UUPS +
        # delegatecall + impl slot) must still classify "proxy".
        scope = (
            "ProxyAdmin manages a UUPS upgradeable proxy: it delegatecalls the "
            "implementation slot (ERC1967) and routes upgrade-handler calls."
        )
        self.assertEqual(_kind(scope), "proxy")

    def test_proxy_signals_individually_still_match(self):
        for txt in (
            "uups upgrade authorization",
            "erc1967 implementation slot read",
            "delegatecall to logic contract",
            "the Proxy forwards all calls",
        ):
            self.assertEqual(_kind(txt), "proxy", txt)


if __name__ == "__main__":
    unittest.main()
