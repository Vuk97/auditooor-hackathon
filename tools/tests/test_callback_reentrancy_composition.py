#!/usr/bin/env python3
"""Unit tests for tools/callback-reentrancy-composition.py (CRC).

Coverage:
  1.  Solidity flashLoan-like fn (transfer-out + callback, NO guard) -> reentry hypothesis emitted.
  2.  Same fn WITH a nonReentrant guard -> 0 hypotheses (guard-detection fires).
  3.  Solidity fn with NO external call / callback -> 0 hypotheses.
  4.  Solidity flashLoan with ZERO OWN state writes (Midnight.sol shape) ->
      hypothesis emitted: window fn need not have its own writes (Defect 1 fix).
  5.  Go/Cosmos: wasmKeeper.Execute (attacker-reachable) + no lock -> hypothesis emitted.
  6.  Go/Cosmos: guarded (LIQUIDATION_LOCK) with wasmKeeper.Execute -> 0 hypotheses.
  7.  Go/Cosmos: ONLY internal k.BeforeX / k.AfterX hooks, no wasm/IBC/EVM ->
      0 hypotheses (internal hooks not attacker-reachable; Defect 2 fix).
  8.  Rust/CosmWasm: SubMsg reply_on_success before state write, no guard -> emitted.
  9.  Rust guarded (reentrancy_guard) -> 0 hypotheses.
  10. Every emitted hypothesis has verdict="needs-fuzz".
  11. Classic hypotheses have attack_class="reentrancy-into-settlement".
  12. Every emitted hypothesis has source="CRC" and guard_detected=False.
  13. No em-dash (U+2014) or en-dash (U+2013) in any emitted string field.
  14. RO-view: getVirtualPrice()/getReserves() returning a reserve/price field that a
      flashLoan-window writes -> flagged sub_class=read-only-reentrancy-view,
      attack_class=read-only-reentrancy.
  15. RO-view: getAdminFee() returning fee -> NOT flagged (not price/share class).
  16. RO-view: pure math helper -> NOT flagged.
  17. RO-view: view of a price field with NO window fn that writes it -> NOT flagged.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load the CRC module (hyphen-safe dynamic import).
# ---------------------------------------------------------------------------
_CRC_PATH = Path(__file__).resolve().parent.parent / "callback-reentrancy-composition.py"
_CRC_MOD_NAME = "callback_reentrancy_composition"


def _load_crc():
    spec = importlib.util.spec_from_file_location(_CRC_MOD_NAME, _CRC_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_CRC_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


crc = _load_crc()


# ---------------------------------------------------------------------------
# Minimal workspace builder (hermetic - no real workspace needed).
# ---------------------------------------------------------------------------
class _WS:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "src").mkdir()
        (self.root / ".auditooor").mkdir()

    def add(self, rel: str, body: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return p

    def write_vmf(self, records: list) -> Path:
        """Write a value_moving_functions.json directly (avoids file-scan)."""
        out = self.root / ".auditooor" / "value_moving_functions.json"
        import json as _j, datetime
        out.write_text(_j.dumps({
            "workspace": str(self.root),
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "function_count": len(records),
            "functions": records,
        }), encoding="utf-8")
        return out

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Fixture sources.
# ---------------------------------------------------------------------------

# Solidity: flashLoan-like - transfers tokens OUT, calls callback, NO guard.
# CEI violated: safeTransfer (interaction) before creditOf write (effect).
SOL_FLASH_NO_GUARD = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoanCallback {
    function onFlashLoan(address token, uint256 amount, bytes calldata data) external;
}

contract LendingPool {
    mapping(address => uint256) public creditOf;

    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external {
        // Interaction BEFORE effect: CEI violation
        IERC20(token).safeTransfer(receiver, amount);
        IFlashLoanCallback(receiver).onFlashLoan(token, amount, data);
        // Effect: ledger write happens after callback
        creditOf[receiver] += amount;
        require(IERC20(token).balanceOf(address(this)) >= amount, "not repaid");
    }

    function take(address payer, address receiver, uint256 units) external {
        creditOf[receiver] += units;
        creditOf[payer] -= units;
        IERC20(token).safeTransfer(receiver, units);
    }
}

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
    function balanceOf(address who) external view returns (uint256);
}
"""

# Same flashLoan but WITH nonReentrant guard.
SOL_FLASH_WITH_GUARD = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IFlashLoanCallback {
    function onFlashLoan(address token, uint256 amount, bytes calldata data) external;
}

contract LendingPool is ReentrancyGuard {
    mapping(address => uint256) public creditOf;

    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external nonReentrant {
        IERC20(token).safeTransfer(receiver, amount);
        IFlashLoanCallback(receiver).onFlashLoan(token, amount, data);
        creditOf[receiver] += amount;
    }
}

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
}
"""

# Solidity: pure arithmetic fn - no external call, no callback.
SOL_PURE_FN = """\
pragma solidity ^0.8.0;

contract Math {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}
"""

# Solidity: flashLoan-like with ZERO OWN state writes (Midnight.sol shape).
# The window fn only does safeTransfer-out + onFlashLoan callback + safeTransferFrom-back.
# No credit/debt writes in the window fn body itself.
# CRC v2 must still emit a hypothesis: the window fn qualifies purely by
# invoking an unguarded external callback.
SOL_FLASH_NO_OWN_WRITES = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoanCallback {
    function onFlashLoan(address sender, address[] calldata tokens, uint256[] calldata assets, bytes calldata data)
        external returns (bytes32);
}

library SafeTransferLib {
    function safeTransfer(address token, address to, uint256 amount) internal {}
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {}
}

contract Midnight {
    // flashLoan: zero ledger writes of its own.
    // Only: safeTransfer-out, onFlashLoan callback, safeTransferFrom-back.
    function flashLoan(
        address[] calldata tokens,
        uint256[] calldata assets,
        address callback,
        bytes calldata data
    ) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            SafeTransferLib.safeTransfer(tokens[i], callback, assets[i]);
        }
        IFlashLoanCallback(callback).onFlashLoan(msg.sender, tokens, assets, data);
        for (uint256 i = 0; i < tokens.length; i++) {
            SafeTransferLib.safeTransferFrom(tokens[i], callback, address(this), assets[i]);
        }
    }

    // take: writes credit/debt BEFORE settlement transfer (reentry target).
    mapping(address => uint256) public creditOf;
    function take(address payer, address recipient, uint256 units) external {
        creditOf[recipient] += units;
        creditOf[payer] -= units;
        SafeTransferLib.safeTransfer(address(0), recipient, units);
    }
}
"""

# Go/Cosmos: wasmKeeper.Execute (attacker-reachable CosmWasm call), no lock.
GO_WASM_NO_GUARD = """\
package keeper

import (
    "context"
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct {
    wasmKeeper WasmKeeper
    bankKeeper BankKeeper
}

type WasmKeeper interface {
    Execute(ctx sdk.Context, contractAddr sdk.AccAddress, caller sdk.AccAddress, msg []byte, coins sdk.Coins) ([]byte, error)
}

type BankKeeper interface {
    SendCoins(ctx sdk.Context, from, to sdk.AccAddress, amount sdk.Coins) error
}

func (k Keeper) FlashExecute(ctx context.Context, contractAddr sdk.AccAddress, caller sdk.AccAddress, msg []byte, coins sdk.Coins) error {
    sdkCtx := sdk.UnwrapSDKContext(ctx)
    // External CosmWasm contract call - attacker-reachable callback window
    _, err := k.wasmKeeper.Execute(sdkCtx, contractAddr, caller, msg, coins)
    if err != nil {
        return err
    }
    // State write after external call
    creditBalance := coins
    return k.bankKeeper.SendCoins(sdkCtx, caller, contractAddr, creditBalance)
}

func (k Keeper) Repay(ctx context.Context, borrower sdk.AccAddress, debtAmount sdk.Coins) error {
    sdkCtx := sdk.UnwrapSDKContext(ctx)
    debtBalance := debtAmount
    return k.bankKeeper.SendCoins(sdkCtx, borrower, borrower, debtBalance)
}
"""

# Go/Cosmos: wasmKeeper.Execute present but guarded with LIQUIDATION_LOCK.
GO_WASM_WITH_GUARD = """\
package keeper

import (
    "context"
    sdk "github.com/cosmos/cosmos-sdk/types"
)

const LIQUIDATION_LOCK = true

type Keeper struct {
    wasmKeeper WasmKeeper
    bankKeeper BankKeeper
}

type WasmKeeper interface {
    Execute(ctx sdk.Context, contractAddr sdk.AccAddress, caller sdk.AccAddress, msg []byte, coins sdk.Coins) ([]byte, error)
}

type BankKeeper interface {
    SendCoins(ctx sdk.Context, from, to sdk.AccAddress, amount sdk.Coins) error
}

func (k Keeper) Liquidate(ctx context.Context, contractAddr sdk.AccAddress, caller sdk.AccAddress, msg []byte, coins sdk.Coins) error {
    sdkCtx := sdk.UnwrapSDKContext(ctx)
    if LIQUIDATION_LOCK {
        return nil
    }
    _, err := k.wasmKeeper.Execute(sdkCtx, contractAddr, caller, msg, coins)
    if err != nil {
        return err
    }
    liquidationBalance := coins
    return k.bankKeeper.SendCoins(sdkCtx, caller, contractAddr, liquidationBalance)
}
"""

# Go/Cosmos: ONLY internal k.Before*/k.After* hooks - no wasm/IBC/EVM.
# Must emit ZERO hypotheses after the Defect 2 fix.
GO_INTERNAL_HOOKS_ONLY = """\
package keeper

import (
    "context"
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct {
    StakingHooks StakingHooks
    bankKeeper   BankKeeper
}

type StakingHooks interface {
    BeforeDelegationCreated(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) error
    AfterDelegationModified(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) error
}

type BankKeeper interface {
    SendCoins(ctx sdk.Context, from, to sdk.AccAddress, amount sdk.Coins) error
}

func (k Keeper) Delegate(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress, amount sdk.Coins) error {
    sdkCtx := sdk.UnwrapSDKContext(ctx)
    // Internal SDK hooks only - NOT attacker-reachable
    if err := k.StakingHooks.BeforeDelegationCreated(sdkCtx, delAddr, valAddr); err != nil {
        return err
    }
    creditBalance := amount
    if err := k.bankKeeper.SendCoins(sdkCtx, delAddr, valAddr.Bytes(), creditBalance); err != nil {
        return err
    }
    if err := k.StakingHooks.AfterDelegationModified(sdkCtx, delAddr, valAddr); err != nil {
        return err
    }
    return nil
}
"""

# Alias kept for the multi-language cross-fixture test (updated to wasm pattern).
GO_HOOK_NO_GUARD = GO_WASM_NO_GUARD
GO_HOOK_WITH_GUARD = GO_WASM_WITH_GUARD

# Rust/CosmWasm: SubMsg reply_on_success before state write, no guard.
RS_SUBMSG_NO_GUARD = """\
use cosmwasm_std::{
    DepsMut, Env, MessageInfo, Response, SubMsg, ReplyOn, WasmMsg, to_binary,
};

pub fn execute_flash_loan(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    receiver: String,
    amount: u128,
) -> Result<Response, ()> {
    // Callback via SubMsg before state is finalized
    let callback_msg = SubMsg {
        id: 1,
        msg: cosmwasm_std::CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: receiver.clone(),
            msg: to_binary(&"on_flash_loan").unwrap(),
            funds: vec![],
        }),
        gas_limit: None,
        reply_on: ReplyOn::Success,
    };
    // State write comes after SubMsg dispatch (CEI violation)
    self.loan_balance -= amount;
    Ok(Response::new().add_submessage(callback_msg))
}

pub fn execute_repay(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: u128,
) -> Result<Response, ()> {
    self.loan_balance += amount;
    Ok(Response::new())
}
"""

# Rust: guarded with reentrancy_guard.
RS_WITH_GUARD = """\
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, SubMsg, ReplyOn};

static reentrancy_guard: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn execute_flash_loan(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    receiver: String,
    amount: u128,
) -> Result<Response, ()> {
    // Guard is set
    if reentrancy_guard.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err(());
    }
    let callback_msg = SubMsg {
        id: 1,
        msg: cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: receiver.clone(),
            msg: cosmwasm_std::to_binary(&"on_flash_loan").unwrap(),
            funds: vec![],
        }),
        gas_limit: None,
        reply_on: ReplyOn::Success,
    };
    self.loan_balance -= amount;
    Ok(Response::new().add_submessage(callback_msg))
}
"""


# ---------------------------------------------------------------------------
# Helper: run CRC over a workspace and collect hypotheses.
# ---------------------------------------------------------------------------
def _run_crc(ws: "_WS", vmf_records: list | None = None) -> list[dict]:
    """Write VMF JSON if provided, then run produce_hypotheses."""
    if vmf_records is not None:
        vmf_path = ws.write_vmf(vmf_records)
    else:
        # Let CRC regenerate by scanning the workspace.
        vmf_path = None

    hyps = crc.produce_hypotheses(
        ws.root,
        vmf_json_path=vmf_path,
        regen_vmf=(vmf_records is None),
    )
    return hyps


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------

class TestSolidityNoGuard(unittest.TestCase):
    """flashLoan-like Solidity fn with callback and NO guard -> hypothesis emitted."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/LendingPool.sol", SOL_FLASH_NO_GUARD)
        # Provide a VMF record for the window fn + a target fn.
        cls.vmf_records = [
            {
                "file": "src/LendingPool.sol",
                "function": "flashLoan",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(receiver, amount)"],
                "ledger_write_evidence": ["creditOf"],
            },
            {
                "file": "src/LendingPool.sol",
                "function": "take",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(receiver, units)"],
                "ledger_write_evidence": ["creditOf"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_hypothesis_emitted(self):
        """At least one hypothesis must be emitted for the unguarded flashLoan."""
        self.assertGreater(len(self.hyps), 0, "Expected >=1 hypothesis for unguarded flashLoan")

    def test_window_fn_is_flashloan(self):
        """The window function in at least one hypothesis must be flashLoan."""
        window_fns = {h["function"] for h in self.hyps}
        self.assertIn("flashLoan", window_fns)

    def test_reentry_target_is_take(self):
        """At least one hypothesis must target the 'take' function."""
        targets = {h["reentry_target"] for h in self.hyps}
        self.assertIn("take", targets)

    def test_verdict_needs_fuzz(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")

    def test_attack_class(self):
        for h in self.hyps:
            self.assertEqual(h["attack_class"], "reentrancy-into-settlement")

    def test_source_crc(self):
        for h in self.hyps:
            self.assertEqual(h["source"], "CRC")

    def test_guard_detected_false(self):
        for h in self.hyps:
            self.assertFalse(h["guard_detected"])

    def test_no_em_dash_or_en_dash(self):
        for h in self.hyps:
            for v in h.values():
                if isinstance(v, str):
                    self.assertNotIn("—", v, f"em-dash found in: {v}")
                    self.assertNotIn("–", v, f"en-dash found in: {v}")


class TestSolidityWithGuard(unittest.TestCase):
    """Same flashLoan fn WITH nonReentrant guard -> 0 hypotheses."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/LendingPool.sol", SOL_FLASH_WITH_GUARD)
        cls.vmf_records = [
            {
                "file": "src/LendingPool.sol",
                "function": "flashLoan",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(receiver, amount)"],
                "ledger_write_evidence": ["creditOf"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_zero_hypotheses(self):
        """nonReentrant guard must suppress all CRC hypotheses for flashLoan."""
        flash_hyps = [h for h in self.hyps if h["function"] == "flashLoan"]
        self.assertEqual(len(flash_hyps), 0,
                         f"Expected 0 flashLoan hypotheses, got: {flash_hyps}")

    # Patch: the correct variable reference is cls -> self in assertions
    def test_zero_hypotheses_v2(self):
        flash_hyps = [h for h in self.hyps if h["function"] == "flashLoan"]
        self.assertEqual(len(flash_hyps), 0,
                         f"nonReentrant guard must block CRC emission; got: {flash_hyps}")


class TestSolidityNoPureCallbackFn(unittest.TestCase):
    """A pure arithmetic fn with no external call -> 0 hypotheses."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/Math.sol", SOL_PURE_FN)
        cls.vmf_records = [
            # add() is not value-moving but include it to check CRC doesn't hallucinate
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_zero_hypotheses(self):
        """Pure arithmetic fn must produce 0 hypotheses."""
        self.assertEqual(len(self.hyps), 0,
                         f"Expected 0 hypotheses for pure fn, got: {self.hyps}")


class TestGoHookNoGuard(unittest.TestCase):
    """Go/Cosmos: wasmKeeper.Execute (attacker-reachable) + no lock -> hypothesis emitted."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("keeper/keeper.go", GO_WASM_NO_GUARD)
        cls.vmf_records = [
            {
                "file": "keeper/keeper.go",
                "function": "FlashExecute",
                "language": "go",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["wasmKeeper.Execute("],
                "ledger_write_evidence": ["creditBalance"],
            },
            {
                "file": "keeper/keeper.go",
                "function": "Repay",
                "language": "go",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["SendCoins("],
                "ledger_write_evidence": ["debtBalance"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_hypothesis_emitted(self):
        """At least one hypothesis emitted for Go wasmKeeper.Execute window."""
        self.assertGreater(len(self.hyps), 0,
                           "Expected >=1 hypothesis for Go wasmKeeper.Execute window")

    def test_window_fn_is_flash_execute(self):
        window_fns = {h["function"] for h in self.hyps}
        self.assertIn("FlashExecute", window_fns)

    def test_verdict_needs_fuzz(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")

    def test_no_em_dash(self):
        for h in self.hyps:
            for v in h.values():
                if isinstance(v, str):
                    self.assertNotIn("—", v)
                    self.assertNotIn("–", v)


class TestGoHookWithGuard(unittest.TestCase):
    """Go/Cosmos: LIQUIDATION_LOCK present with wasmKeeper.Execute -> 0 hypotheses for that fn."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("keeper/keeper.go", GO_WASM_WITH_GUARD)
        cls.vmf_records = [
            {
                "file": "keeper/keeper.go",
                "function": "Liquidate",
                "language": "go",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["SendCoins("],
                "ledger_write_evidence": ["liquidationBalance"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_zero_hypotheses(self):
        """LIQUIDATION_LOCK guard must suppress CRC emission for Liquidate."""
        liquidate_hyps = [h for h in self.hyps if h["function"] == "Liquidate"]
        self.assertEqual(len(liquidate_hyps), 0,
                         f"LIQUIDATION_LOCK must block CRC; got: {liquidate_hyps}")


class TestRustSubMsgNoGuard(unittest.TestCase):
    """Rust/CosmWasm: SubMsg reply_on_success before state write, no guard -> emitted."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/contract.rs", RS_SUBMSG_NO_GUARD)
        cls.vmf_records = [
            {
                "file": "src/contract.rs",
                "function": "execute_flash_loan",
                "language": "rs",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["SubMsg {"],
                "ledger_write_evidence": ["loan_balance"],
            },
            {
                "file": "src/contract.rs",
                "function": "execute_repay",
                "language": "rs",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["Response::new()"],
                "ledger_write_evidence": ["loan_balance"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_hypothesis_emitted(self):
        """At least one hypothesis for Rust unguarded SubMsg window."""
        self.assertGreater(len(self.hyps), 0,
                           "Expected >=1 hypothesis for Rust SubMsg window")

    def test_window_fn_is_flash_loan(self):
        window_fns = {h["function"] for h in self.hyps}
        self.assertIn("execute_flash_loan", window_fns)

    def test_verdict_needs_fuzz(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")


class TestRustWithGuard(unittest.TestCase):
    """Rust: reentrancy_guard (AtomicBool) present -> 0 hypotheses for that fn."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/contract.rs", RS_WITH_GUARD)
        cls.vmf_records = [
            {
                "file": "src/contract.rs",
                "function": "execute_flash_loan",
                "language": "rs",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["SubMsg {"],
                "ledger_write_evidence": ["loan_balance"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_zero_hypotheses(self):
        """AtomicBool reentrancy_guard must suppress CRC emission."""
        flash_hyps = [h for h in self.hyps if h["function"] == "execute_flash_loan"]
        self.assertEqual(len(flash_hyps), 0,
                         f"reentrancy_guard must block CRC; got: {flash_hyps}")


class TestFlashLoanNoOwnWrites(unittest.TestCase):
    """Defect 1 fix: flashLoan with ZERO own state writes still qualifies as a window.

    Midnight.sol flashLoan: safeTransfer-out, onFlashLoan callback,
    safeTransferFrom-back - NO ledger writes of its own.
    CRC v2 must emit a hypothesis targeting the 'take' fn
    (which has write-before-settlement in its own body).
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/Midnight.sol", SOL_FLASH_NO_OWN_WRITES)
        cls.vmf_records = [
            # flashLoan: transfer_hit=True (safeTransfer present), ledger_write_hit=False
            # (no own ledger writes). Included in VMF because safeTransfer is present.
            {
                "file": "src/Midnight.sol",
                "function": "flashLoan",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": False,
                "transfer_evidence": ["safeTransfer"],
                "ledger_write_evidence": [],
            },
            # take: both write AND transfer -> valid reentry target.
            {
                "file": "src/Midnight.sol",
                "function": "take",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer"],
                "ledger_write_evidence": ["creditOf"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_hypothesis_emitted(self):
        """flashLoan with zero own writes must still emit a hypothesis."""
        self.assertGreater(
            len(self.hyps), 0,
            "Defect 1 regression: flashLoan (no own writes) must qualify as callback window"
        )

    def test_window_fn_is_flashloan(self):
        window_fns = {h["function"] for h in self.hyps}
        self.assertIn("flashLoan", window_fns,
                      "flashLoan must appear as the callback window fn")

    def test_reentry_target_is_take(self):
        """The reentry target must be 'take' (the fn with write-before-settlement)."""
        targets = {h["reentry_target"] for h in self.hyps}
        self.assertIn("take", targets,
                      "take must be a reentry target for the flashLoan window")

    def test_verdict_needs_fuzz(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")

    def test_no_em_dash(self):
        for h in self.hyps:
            for v in h.values():
                if isinstance(v, str):
                    self.assertNotIn("—", v, f"em-dash found: {v}")
                    self.assertNotIn("–", v, f"en-dash found: {v}")


class TestGoInternalHooksOnly(unittest.TestCase):
    """Defect 2 fix: Go fn with ONLY internal k.Before*/k.After* hooks -> 0 hypotheses.

    Internal Cosmos SDK module hooks (BeforeDelegationCreated, AfterDelegationModified)
    are synchronous, in-process, trusted keeper calls - NOT attacker-reachable.
    The narrowed Go callback lexicon must exclude them.
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("keeper/staking.go", GO_INTERNAL_HOOKS_ONLY)
        cls.vmf_records = [
            {
                "file": "keeper/staking.go",
                "function": "Delegate",
                "language": "go",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["SendCoins("],
                "ledger_write_evidence": ["creditBalance"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_zero_hypotheses(self):
        """Go fn with only internal SDK hooks must produce 0 hypotheses."""
        delegate_hyps = [h for h in self.hyps if h["function"] == "Delegate"]
        self.assertEqual(
            len(delegate_hyps), 0,
            f"Defect 2 regression: internal k.Before*/k.After* must not trigger CRC; got: {delegate_hyps}"
        )


class TestAllHypothesesAreNeedsFuzz(unittest.TestCase):
    """Cross-fixture invariant: every emitted hypothesis has verdict=needs-fuzz."""

    def test_needs_fuzz_invariant(self):
        ws = _WS()
        try:
            ws.add("src/A.sol", SOL_FLASH_NO_GUARD)
            ws.add("keeper/keeper.go", GO_WASM_NO_GUARD)
            ws.add("src/contract.rs", RS_SUBMSG_NO_GUARD)
            # Provide VMF records spanning all three files.
            vmf_records = [
                {"file": "src/A.sol", "function": "flashLoan", "language": "sol",
                 "transfer_hit": True, "ledger_write_hit": True,
                 "transfer_evidence": ["safeTransfer"], "ledger_write_evidence": ["creditOf"]},
                {"file": "src/A.sol", "function": "take", "language": "sol",
                 "transfer_hit": True, "ledger_write_hit": True,
                 "transfer_evidence": ["safeTransfer"], "ledger_write_evidence": ["creditOf"]},
                {"file": "keeper/keeper.go", "function": "FlashExecute", "language": "go",
                 "transfer_hit": True, "ledger_write_hit": True,
                 "transfer_evidence": ["wasmKeeper.Execute("], "ledger_write_evidence": ["creditBalance"]},
                {"file": "keeper/keeper.go", "function": "Repay", "language": "go",
                 "transfer_hit": True, "ledger_write_hit": True,
                 "transfer_evidence": ["SendCoins("], "ledger_write_evidence": ["debtBalance"]},
                {"file": "src/contract.rs", "function": "execute_flash_loan", "language": "rs",
                 "transfer_hit": True, "ledger_write_hit": True,
                 "transfer_evidence": ["SubMsg {"], "ledger_write_evidence": ["loan_balance"]},
                {"file": "src/contract.rs", "function": "execute_repay", "language": "rs",
                 "transfer_hit": True, "ledger_write_hit": True,
                 "transfer_evidence": ["Response::new()"], "ledger_write_evidence": ["loan_balance"]},
            ]
            hyps = _run_crc(ws, vmf_records)
            self.assertGreater(len(hyps), 0, "Expected hypotheses from multi-language workspace")
            _VALID_ATTACK_CLASSES = {"reentrancy-into-settlement", "read-only-reentrancy"}
            for h in hyps:
                self.assertEqual(h["verdict"], "needs-fuzz",
                                 f"Non-needs-fuzz verdict: {h}")
                self.assertIn(h["attack_class"], _VALID_ATTACK_CLASSES,
                              f"Unexpected attack_class: {h['attack_class']}")
                self.assertEqual(h["source"], "CRC")
                self.assertFalse(h["guard_detected"])
        finally:
            ws.cleanup()


# ---------------------------------------------------------------------------
# NEW: read-only-reentrancy-view tests (Curve-style tight discriminator).
# ---------------------------------------------------------------------------

# Solidity fixture: pool with flashLoan that writes `reserve` mid-window,
# and a public view getReserves() that reads `reserve`.
SOL_RO_VIEW_FLAGGED = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoanCallback {
    function onFlashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract CurvePool {
    uint256 public reserve;

    // flashLoan writes `reserve` BEFORE settling - callback window.
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external {
        IERC20(token).safeTransfer(receiver, amount);
        IFlashLoanCallback(receiver).onFlashLoan(token, amount, data);
        reserve -= amount;
        IERC20(token).safeTransferFrom(receiver, address(this), amount);
    }

    // getReserves: external view returning `reserve` - should be flagged.
    function getReserves() external view returns (uint256) {
        return reserve;
    }

    // getVirtualPrice: external view returning `reserve`-derived computation.
    function getVirtualPrice() external view returns (uint256) {
        return reserve * 1e18 / 1e6;
    }
}
"""

# Solidity fixture: getAdminFee returns `fee` - NOT price/share class, must NOT be flagged.
SOL_ADMIN_FEE_NOT_FLAGGED = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoanCallback {
    function onFlashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract FeePool {
    uint256 public fee;
    uint256 public reserve;

    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external {
        IERC20(token).safeTransfer(receiver, amount);
        IFlashLoanCallback(receiver).onFlashLoan(token, amount, data);
        reserve -= amount;
        IERC20(token).safeTransferFrom(receiver, address(this), amount);
    }

    // Returns `fee` - NOT a price/rate/share/reserve field - must NOT be flagged.
    function getAdminFee() external view returns (uint256) {
        return fee;
    }
}
"""

# Solidity fixture: pure math helper - no external call, no price field.
SOL_PURE_MATH = """\
pragma solidity ^0.8.0;

contract MathHelper {
    function calculateFee(uint256 amount, uint256 bps) external pure returns (uint256) {
        return amount * bps / 10000;
    }
}
"""

# Solidity fixture: view of a price field but NO window fn writes it.
SOL_PRICE_VIEW_NO_WINDOW_WRITER = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PriceOracle {
    uint256 public price;

    // A function that does a callback but does NOT write `price`.
    function doSomething(address receiver) external {
        (bool ok,) = receiver.call("");
        require(ok);
    }

    // View of price - but no window fn writes price -> must NOT be flagged.
    function getPrice() external view returns (uint256) {
        return price;
    }
}
"""


class TestROViewFlagged(unittest.TestCase):
    """getReserves/getVirtualPrice view of a reserve/price field written by flashLoan window
    -> flagged as sub_class=read-only-reentrancy-view, attack_class=read-only-reentrancy.
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/CurvePool.sol", SOL_RO_VIEW_FLAGGED)
        # flashLoan is the window fn (transfer_hit=True, ledger_write_hit can be either;
        # it writes `reserve` which is the price-class field).
        cls.vmf_records = [
            {
                "file": "src/CurvePool.sol",
                "function": "flashLoan",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(receiver, amount)"],
                "ledger_write_evidence": ["reserve"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_ro_view_hypothesis_emitted(self):
        """At least one read-only-reentrancy-view hypothesis must be emitted."""
        ro_hyps = [h for h in self.hyps if h.get("sub_class") == "read-only-reentrancy-view"]
        self.assertGreater(
            len(ro_hyps), 0,
            f"Expected >=1 read-only-reentrancy-view hypothesis; all hyps: {self.hyps}"
        )

    def test_ro_view_function_names(self):
        """getReserves or getVirtualPrice must appear as the flagged view fn."""
        ro_hyps = [h for h in self.hyps if h.get("sub_class") == "read-only-reentrancy-view"]
        flagged_fns = {h["function"] for h in ro_hyps}
        self.assertTrue(
            flagged_fns & {"getReserves", "getVirtualPrice"},
            f"Expected getReserves or getVirtualPrice in RO-view flags; got: {flagged_fns}"
        )

    def test_ro_view_attack_class(self):
        """Read-only-reentrancy-view hypotheses must have attack_class=read-only-reentrancy."""
        ro_hyps = [h for h in self.hyps if h.get("sub_class") == "read-only-reentrancy-view"]
        for h in ro_hyps:
            self.assertEqual(h["attack_class"], "read-only-reentrancy",
                             f"Wrong attack_class: {h}")

    def test_ro_view_verdict(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")

    def test_ro_view_source_guard(self):
        for h in self.hyps:
            self.assertEqual(h["source"], "CRC")
            self.assertFalse(h["guard_detected"])

    def test_no_em_dash(self):
        for h in self.hyps:
            for v in h.values():
                if isinstance(v, str):
                    self.assertNotIn("—", v)
                    self.assertNotIn("–", v)


class TestROViewAdminFeeNotFlagged(unittest.TestCase):
    """getAdminFee() returning `fee` field (not price/share class) -> NOT flagged as RO-view."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/FeePool.sol", SOL_ADMIN_FEE_NOT_FLAGGED)
        cls.vmf_records = [
            {
                "file": "src/FeePool.sol",
                "function": "flashLoan",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(receiver, amount)"],
                "ledger_write_evidence": ["reserve"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_admin_fee_not_flagged(self):
        """getAdminFee (returns `fee`, not price/share class) must NOT be flagged as RO-view."""
        ro_admin = [
            h for h in self.hyps
            if h.get("sub_class") == "read-only-reentrancy-view"
            and h.get("function") == "getAdminFee"
        ]
        self.assertEqual(
            len(ro_admin), 0,
            f"getAdminFee must NOT be flagged as RO-view; got: {ro_admin}"
        )


class TestROViewPureMathNotFlagged(unittest.TestCase):
    """Pure math helper with no external call and no price field -> 0 RO-view hypotheses."""

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/MathHelper.sol", SOL_PURE_MATH)
        cls.vmf_records: list = []
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_zero_ro_view(self):
        """Pure math helper must produce 0 hypotheses of any kind."""
        self.assertEqual(len(self.hyps), 0,
                         f"Expected 0 hypotheses for pure math helper; got: {self.hyps}")


class TestROViewNoPriceWriterNotFlagged(unittest.TestCase):
    """View of price field but no window fn writes it -> NOT flagged as RO-view.

    The `doSomething` fn opens a callback window (low-level .call), but it
    does NOT write `price`. So getPrice() must NOT be flagged.
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/PriceOracle.sol", SOL_PRICE_VIEW_NO_WINDOW_WRITER)
        # No VMF reentry targets (doSomething has no ledger writes + transfer).
        # Include doSomething as a window fn candidate only (no ledger_write_hit).
        cls.vmf_records = [
            {
                "file": "src/PriceOracle.sol",
                "function": "doSomething",
                "language": "sol",
                "transfer_hit": False,
                "ledger_write_hit": False,
                "transfer_evidence": [],
                "ledger_write_evidence": [],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_get_price_not_flagged(self):
        """getPrice view where no window fn writes price -> must NOT produce RO-view hypothesis."""
        ro_price = [
            h for h in self.hyps
            if h.get("sub_class") == "read-only-reentrancy-view"
            and h.get("function") == "getPrice"
        ]
        self.assertEqual(
            len(ro_price), 0,
            f"getPrice must NOT be flagged when no window fn writes price; got: {ro_price}"
        )


# ---------------------------------------------------------------------------
# NEW: Classic-reentrancy tightening tests (beanstalk Diamond flood fix).
# ---------------------------------------------------------------------------

# Fixture: a function that ONLY does safeTransfer (weak-only callback) with NO
# named on* / *Callback / .call{} pattern. Must NOT produce classic-reentrancy
# hypotheses because it is a weak-only window.
SOL_TRANSFER_ONLY_WINDOW = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
}

contract TransferOnly {
    // Only does a safeTransfer - no named callback, no .call{}.
    // Weak-only window: must NOT produce classic-reentrancy hypotheses.
    function sendReward(address token, address user, uint256 amt) external {
        IERC20(token).safeTransfer(user, amt);
    }

    // A target fn with both write + transfer.
    mapping(address => uint256) public balances;
    function settle(address payer, address recip, uint256 amt) external {
        balances[recip] += amt;
        balances[payer] -= amt;
        IERC20(token).safeTransfer(recip, amt);
    }
}
"""

# Fixture: a function with a generic .call{} (tier-2) window pointing at a
# TARGET IN A DIFFERENT FILE. Must NOT be emitted (tier-2 -> same-file only).
# The target in a separate file should be excluded.
SOL_TIER2_CROSS_FILE_WINDOW = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Caller {
    // Generic .call{} - tier-2 window.
    function refundEth(address payable user) external {
        (bool ok,) = user.call{value: address(this).balance}("");
        require(ok);
    }
}
"""

SOL_TIER2_CROSS_FILE_TARGET = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
}

contract Target {
    mapping(address => uint256) public credits;
    // Has write before transfer (CEI violation) - valid reentry target.
    function withdraw(address user, uint256 amt) external {
        credits[user] -= amt;
        IERC20(address(0)).safeTransfer(user, amt);
    }
}
"""

# Fixture: tier-2 generic .call{} window with a SAME-FILE target.
# MUST be emitted (tier-2 + same-file = emit).
SOL_TIER2_SAME_FILE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
}

contract ETHSender {
    mapping(address => uint256) public credits;

    // Tier-2 window: generic .call{} - same file as the target.
    function refundEth(address payable user) external {
        (bool ok,) = user.call{value: address(this).balance}("");
        require(ok);
    }

    // Same-file target: write before transfer.
    function withdraw(address user, uint256 amt) external {
        credits[user] -= amt;
        IERC20(address(0)).safeTransfer(user, amt);
    }
}
"""

# Fixture: morpho-style flashLoan (tier-1 named callback) with a target in a
# DIFFERENT FILE. MUST be emitted (tier-1 -> any file).
SOL_TIER1_CROSS_FILE_WINDOW = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashCallback {
    function onFlashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract FlashPool {
    // Tier-1 window: named onFlashLoan callback.
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external {
        IERC20(token).safeTransfer(receiver, amount);
        IFlashCallback(receiver).onFlashLoan(token, amount, data);
        IERC20(token).safeTransferFrom(receiver, address(this), amount);
    }
}
"""

SOL_TIER1_CROSS_FILE_TARGET = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
}

contract SettlementContract {
    mapping(address => uint256) public positions;
    // Target in a different file: write before transfer.
    function take(address user, uint256 amt) external {
        positions[user] += amt;
        IERC20(address(0)).safeTransfer(user, amt);
    }
}
"""


class TestWeakOnlyWindowNotFlagged(unittest.TestCase):
    """A function that ONLY does safeTransfer (no named callback, no .call{}) must
    NOT produce classic-reentrancy hypotheses (weak-only window is dropped).
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/TransferOnly.sol", SOL_TRANSFER_ONLY_WINDOW)
        cls.vmf_records = [
            {
                "file": "src/TransferOnly.sol",
                "function": "sendReward",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": False,
                "transfer_evidence": ["safeTransfer(user, amt)"],
                "ledger_write_evidence": [],
            },
            {
                "file": "src/TransferOnly.sol",
                "function": "settle",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(recip, amt)"],
                "ledger_write_evidence": ["balances"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_weak_only_window_not_flagged(self):
        """A safeTransfer-only window with no named callback must NOT emit
        classic-reentrancy hypotheses.
        """
        classic = [
            h for h in self.hyps
            if h.get("sub_class") == "classic-reentrancy"
            and h["function"] == "sendReward"
        ]
        self.assertEqual(
            len(classic), 0,
            f"Weak-only window (safeTransfer) must not produce classic-reentrancy; got: {classic}"
        )


class TestTier2CrossFileNotFlagged(unittest.TestCase):
    """A tier-2 generic .call{} window with a target in a DIFFERENT file must NOT
    produce a classic-reentrancy hypothesis (tier-2 = same-file only).
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/Caller.sol", SOL_TIER2_CROSS_FILE_WINDOW)
        cls.ws.add("src/Target.sol", SOL_TIER2_CROSS_FILE_TARGET)
        cls.vmf_records = [
            {
                "file": "src/Caller.sol",
                "function": "refundEth",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": False,
                "transfer_evidence": [".call{value:"],
                "ledger_write_evidence": [],
            },
            {
                "file": "src/Target.sol",
                "function": "withdraw",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(user, amt)"],
                "ledger_write_evidence": ["credits"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_tier2_cross_file_not_flagged(self):
        """Tier-2 (.call{}) window must NOT produce cross-file classic-reentrancy hypothesis."""
        cross_file = [
            h for h in self.hyps
            if h.get("sub_class") == "classic-reentrancy"
            and h["function"] == "refundEth"
            and h.get("reentry_target") == "withdraw"
            and h.get("reentry_target_file") == "src/Target.sol"
        ]
        self.assertEqual(
            len(cross_file), 0,
            f"Tier-2 cross-file hypothesis must be dropped; got: {cross_file}"
        )


class TestTier2SameFileIsEmitted(unittest.TestCase):
    """A tier-2 generic .call{} window with a target in the SAME file MUST
    produce a classic-reentrancy hypothesis.
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/ETHSender.sol", SOL_TIER2_SAME_FILE)
        cls.vmf_records = [
            {
                "file": "src/ETHSender.sol",
                "function": "refundEth",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": False,
                "transfer_evidence": [".call{value:"],
                "ledger_write_evidence": [],
            },
            {
                "file": "src/ETHSender.sol",
                "function": "withdraw",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(user, amt)"],
                "ledger_write_evidence": ["credits"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_tier2_same_file_emitted(self):
        """Tier-2 (.call{}) window MUST produce same-file classic-reentrancy hypothesis."""
        same_file = [
            h for h in self.hyps
            if h.get("sub_class") == "classic-reentrancy"
            and h["function"] == "refundEth"
            and h.get("reentry_target") == "withdraw"
        ]
        self.assertGreater(
            len(same_file), 0,
            f"Tier-2 same-file hypothesis must be emitted; hyps: {self.hyps}"
        )

    def test_verdict_needs_fuzz(self):
        classic = [h for h in self.hyps if h.get("sub_class") == "classic-reentrancy"]
        for h in classic:
            self.assertEqual(h["verdict"], "needs-fuzz")


class TestTier1CrossFileIsEmitted(unittest.TestCase):
    """A tier-1 named callback window (onFlashLoan) with a target in a DIFFERENT file
    MUST produce a classic-reentrancy hypothesis (tier-1 = any file).

    This is the morpho flashLoan->take shape: the window fn explicitly calls
    onFlashLoan, the attacker can re-enter any contract from that callback.
    """

    @classmethod
    def setUpClass(cls):
        cls.ws = _WS()
        cls.ws.add("src/FlashPool.sol", SOL_TIER1_CROSS_FILE_WINDOW)
        cls.ws.add("src/SettlementContract.sol", SOL_TIER1_CROSS_FILE_TARGET)
        cls.vmf_records = [
            {
                "file": "src/FlashPool.sol",
                "function": "flashLoan",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": False,
                "transfer_evidence": ["safeTransfer(receiver, amount)"],
                "ledger_write_evidence": [],
            },
            {
                "file": "src/SettlementContract.sol",
                "function": "take",
                "language": "sol",
                "transfer_hit": True,
                "ledger_write_hit": True,
                "transfer_evidence": ["safeTransfer(user, amt)"],
                "ledger_write_evidence": ["positions"],
            },
        ]
        cls.hyps = _run_crc(cls.ws, cls.vmf_records)

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_tier1_cross_file_emitted(self):
        """Tier-1 named callback (onFlashLoan) MUST produce cross-file classic-reentrancy
        hypothesis (morpho flashLoan->take shape must survive).
        """
        cross_file = [
            h for h in self.hyps
            if h.get("sub_class") == "classic-reentrancy"
            and h["function"] == "flashLoan"
            and h.get("reentry_target") == "take"
            and h.get("reentry_target_file") == "src/SettlementContract.sol"
        ]
        self.assertGreater(
            len(cross_file), 0,
            "Tier-1 (named callback) must produce cross-file hypothesis "
            "(morpho flashLoan->take shape); got 0"
        )

    def test_reentry_target_is_take(self):
        targets = {h["reentry_target"] for h in self.hyps if h.get("sub_class") == "classic-reentrancy"}
        self.assertIn("take", targets, "take must be a reentry target for the flashLoan window")

    def test_verdict_needs_fuzz(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")

    def test_attack_class(self):
        classic = [h for h in self.hyps if h.get("sub_class") == "classic-reentrancy"]
        for h in classic:
            self.assertEqual(h["attack_class"], "reentrancy-into-settlement")

    def test_no_em_dash(self):
        for h in self.hyps:
            for v in h.values():
                if isinstance(v, str):
                    self.assertNotIn("—", v, f"em-dash found: {v}")
                    self.assertNotIn("–", v, f"en-dash found: {v}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
