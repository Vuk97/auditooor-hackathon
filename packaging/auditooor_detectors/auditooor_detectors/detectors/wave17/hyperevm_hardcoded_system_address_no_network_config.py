"""
hyperevm-hardcoded-system-address-no-network-config — generated from reference/patterns.dsl/hyperevm-hardcoded-system-address-no-network-config.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-hardcoded-system-address-no-network-config.yaml
Source: monetrix-zellic-v12-F50492
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmHardcodedSystemAddressNoNetworkConfig(AbstractDetector):
    ARGUMENT = "hyperevm-hardcoded-system-address-no-network-config"
    HELP = "HyperEVM contract hardcodes a chain-specific HL system address (HLP vault, CORE_DEPOSIT_WALLET, USDC_SYSTEM_ADDRESS) as `address constant`. Re-deploying to testnet / a different HL chain ships the wrong address baked in; HL silently routes funds to a non-existent recipient rather than reverting."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-hardcoded-system-address-no-network-config.yaml"
    WIKI_TITLE = "HyperEVM hardcodes chain-specific HL system address (no per-network config)"
    WIKI_DESCRIPTION = "Hyperliquid's L1 system addresses are NOT consistent across mainnet, testnet, and any future fork / chain-variant. Notable per-network-divergent addresses: HLP vault, CORE_DEPOSIT_WALLET, the HIP-1 USDC system address, user-defined core-vault registries. A contract that bakes any of these in as `address constant FOO = 0x...;` ships a deploy-time-frozen value — re-deploying to a different network w"
    WIKI_EXPLOIT_SCENARIO = "Stablecoin protocol developed against HL mainnet hardcodes `address constant HLP_VAULT = 0xa15099a30BBf2e68942d6F4c43d70D04FAEab0A0`. Team forks the codebase to deploy a testnet pilot. Forgets to update HLP_VAULT — keeps the mainnet address. Test deployment runs `sendVaultDeposit(HLP_VAULT, 100_000)` on testnet. CoreWriter accepts the action (CoreWriter doesn't validate the destination is a real t"
    WIKI_RECOMMENDATION = "Replace every chain-specific `address constant` with one of: (1) a constructor parameter that the deployer must explicitly supply per-network; (2) an `address public immutable HLP_VAULT` set in the constructor from a `block.chainid` switch; (3) an `address public HLP_VAULT` setter gated by a 24h gov"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'HyperCoreConstants|hyperliquid|HyperEVM|hyperevm|HLP|CORE_WRITER|CORE_DEPOSIT|HLP_VAULT|hlpVault|coreVault|hyperliquid'}, {'contract.source_matches_regex': 'address\\s+(?:public\\s+|private\\s+|internal\\s+)?constant\\s+(?:HLP_VAULT|HLP_ADDRESS|HLP|CORE_WRITER|CORE_READ|CORE_DEPOSIT_WALLET[A-Z_]*|USDC_SYSTEM_ADDRESS|HYPER_VAULT|HYPER_DEPOSIT|MAINNET_HLP|TESTNET_HLP|hlpVault|coreVault|hyperVault)\\s*='}, {'contract.source_not_contains_regex': 'function\\s+set(?:HLP|HlpVault|CoreVault|HyperVault|HlpAddress|HypeVault|CoreDepositWallet)|address\\s+public\\s+(?:immutable\\s+)?(?:HLP_VAULT|HLP_ADDRESS|HLP|hlpVault|coreVault)\\s*[;=]|address\\s+(?:public\\s+|private\\s+)?immutable\\s+(?:HLP_VAULT|HLP|hlpVault|coreVault)|block\\.chainid\\s*==|chainId\\s*=='}]
    _MATCH = [{'function.kind': 'any'}, {'function.source_matches_regex': 'HLP|hlp|coreVault|hyperVault|HLP_VAULT|CORE_DEPOSIT|HYPER_VAULT|HYPER_DEPOSIT|hlpVault'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — hyperevm-hardcoded-system-address-no-network-config: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
