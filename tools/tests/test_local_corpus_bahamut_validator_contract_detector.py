#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "local-corpus-bahamut-validator-contract-detector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("local_corpus_bahamut_validator_contract_detector", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


VULNERABLE_PROCESS_DEPOSIT_ZERO_CONTRACT = """
package altair

func ProcessDeposit(beaconState state.BeaconState, deposit *ethpb.Deposit, verifySignature bool) (state.BeaconState, bool, error) {
    contract := deposit.Data.DeployedContract
    owner, contractExist := beaconState.ValidatorIndexByContractAddress(bytesutil.ToBytes20(contract))
    if contractExist {
        log.Debugf("contract %x already registered by validator %d", contract, owner)
    }

    index, ok := beaconState.ValidatorIndexByPubkey(bytesutil.ToBytes48(deposit.Data.PublicKey))
    if !ok {
        if err := beaconState.AppendValidator(&ethpb.Validator{}); err != nil {
            return nil, false, err
        }
        contracts := [][]byte{contract}
        if contractExist {
            contracts = [][]byte{make([]byte, 20)}
        }
        if err := beaconState.AppendContracts(&ethpb.ContractsContainer{
            Contracts: contracts,
        }); err != nil {
            return nil, false, err
        }
    } else if index > 0 {
        helpers.AppendValidatorContracts(beaconState, index, contract)
    }
    return beaconState, true, nil
}
"""


VULNERABLE_APPEND_HELPER = """
package helpers

func appendValidatorContractsWithVal(cc *ethpb.ContractsContainer, contract []byte) *ethpb.ContractsContainer {
    contracts := cc.Contracts
    contracts = append(contracts, contract)
    cc.Contracts = contracts
    return cc
}
"""


CLEAN_PROCESS_DEPOSIT_APPENDS_ONLY_WHEN_CONTRACT_IS_NEW = """
package altair

func ProcessDeposit(beaconState state.BeaconState, deposit *ethpb.Deposit, verifySignature bool) (state.BeaconState, bool, error) {
    contract := deposit.Data.DeployedContract
    _, contractExist := beaconState.ValidatorIndexByContractAddress(bytesutil.ToBytes20(contract))
    _, ok := beaconState.ValidatorIndexByPubkey(bytesutil.ToBytes48(deposit.Data.PublicKey))
    if !ok {
        contracts := [][]byte{contract}
        if contractExist {
            contracts = [][]byte{make([]byte, 20)}
        } else {
            if err := beaconState.AppendContracts(&ethpb.ContractsContainer{Contracts: contracts}); err != nil {
                return nil, false, err
            }
        }
    }
    return beaconState, true, nil
}
"""


CLEAN_APPEND_HELPER_REMOVES_OLD_CONTRACT = """
package helpers

func appendValidatorContractsWithVal(cc *ethpb.ContractsContainer, contract []byte) *ethpb.ContractsContainer {
    contracts := removeOldValidatorContract(cc.Contracts, contract)
    contracts = append(contracts, contract)
    cc.Contracts = contracts
    return cc
}
"""


CLEAN_NEW_VALIDATOR_APPENDS_REAL_CONTRACT = """
package altair

func ProcessDeposit(beaconState state.BeaconState, deposit *ethpb.Deposit, verifySignature bool) (state.BeaconState, bool, error) {
    contract := deposit.Data.DeployedContract
    _, ok := beaconState.ValidatorIndexByPubkey(bytesutil.ToBytes48(deposit.Data.PublicKey))
    if !ok {
        contracts := [][]byte{contract}
        if err := beaconState.AppendContracts(&ethpb.ContractsContainer{
            Contracts: contracts,
        }); err != nil {
            return nil, false, err
        }
    }
    return beaconState, true, nil
}
"""


class LocalCorpusBahamutValidatorContractDetectorTests(unittest.TestCase):
    def test_detects_zero_contract_append_after_contract_exists(self) -> None:
        hits = MOD.detect_source(VULNERABLE_PROCESS_DEPOSIT_ZERO_CONTRACT, "deposit.go")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].packet_id, "LCCR-PKT-018")
        self.assertEqual(hits[0].function, "ProcessDeposit")
        self.assertEqual(hits[0].issue_kind, "zero_contract_append_after_contract_exists")

    def test_detects_append_helper_without_replacement(self) -> None:
        hits = MOD.detect_source(VULNERABLE_APPEND_HELPER, "contracts.go")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].function, "appendValidatorContractsWithVal")
        self.assertEqual(hits[0].issue_kind, "helper_appends_contract_without_replacement")

    def test_skips_process_deposit_when_append_is_inside_else_branch(self) -> None:
        self.assertEqual(
            MOD.detect_source(CLEAN_PROCESS_DEPOSIT_APPENDS_ONLY_WHEN_CONTRACT_IS_NEW, "deposit.go"),
            [],
        )

    def test_skips_append_helper_with_explicit_old_contract_removal(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_APPEND_HELPER_REMOVES_OLD_CONTRACT, "contracts.go"), [])

    def test_skips_new_validator_append_without_contract_exist_lookup(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_NEW_VALIDATOR_APPENDS_REAL_CONTRACT, "deposit.go"), [])

    def test_cli_emits_packet_payload_and_nonzero_on_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "deposit.go"
            fixture.write_text(VULNERABLE_PROCESS_DEPOSIT_ZERO_CONTRACT, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(fixture)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["selected_packet"], "LCCR-PKT-018")
            self.assertEqual(payload["hit_count"], 1)


if __name__ == "__main__":
    unittest.main()
