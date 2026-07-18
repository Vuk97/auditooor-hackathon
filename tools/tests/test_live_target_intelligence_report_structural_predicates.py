#!/usr/bin/env python3
"""Production-consumption tests for live-target AstEngine predicates."""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_structural_predicates", _TOOL_PATH
)
ltir_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ltir_mod)


class _FakeResult:
    ok = True
    captures = ()

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def capture_texts(self, name: str) -> list[str]:
        return self._calls if name == "call" else []


class _FakeEngine:
    query_calls: list[str] = []
    structural_calls: list[str] = []

    def __init__(self, _lang: str, _source: bytes) -> None:
        self._fn = object()

    def parse(self) -> object:
        return object()

    def functions(self) -> list[object]:
        return [self._fn]

    def fn_body(self, fn: object) -> object:
        return fn

    def fn_name(self, _fn: object) -> str:
        return "Send"

    def query_structural(self, predicate: str, node: object | None = None) -> _FakeResult:
        del node
        self.query_calls.append(predicate)
        return _FakeResult(
            [
                "router.msgServer.HandleMsgTransfer(ctx, msg)",
                "balances[module] = bankKeeper.SendCoinsFromModuleToAccount(ctx, module, recipient, coins)",
            ]
        )

    def predicate_structural_match(self, _fn: object, predicate: str) -> bool:
        self.structural_calls.append(predicate)
        return predicate == "assignment_to_subscript_call"


class _FakeAstModule:
    AstEngine = _FakeEngine


class _MoveFakeResult:
    ok = True
    captures = ()

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def capture_texts(self, name: str) -> list[str]:
        return self._calls if name == "call" else []


class _MoveFakeEngineBase:
    query_calls: list[str] = []
    call_texts: list[str] = []
    fn_name_value = "open"

    def __init__(self, _lang: str, _source: bytes) -> None:
        self._fn = object()

    def parse(self) -> object:
        return object()

    def functions(self) -> list[object]:
        return [self._fn]

    def fn_body(self, fn: object) -> object:
        return fn

    def fn_name(self, _fn: object) -> str:
        return self.fn_name_value

    def query_structural(self, predicate: str, node: object | None = None) -> _MoveFakeResult:
        del node
        self.query_calls.append(predicate)
        return _MoveFakeResult(list(self.call_texts))


class _RustFakeResult:
    ok = True
    captures = ()

    def __init__(self, assignments: list[str]) -> None:
        self._assignments = assignments

    def capture_texts(self, name: str) -> list[str]:
        return self._assignments if name == "assignment" else []


class _RustFakeNode:
    def __init__(self, text: str) -> None:
        self.text = text
        self.body = self


class _RustFakeEngine:
    query_calls: list[str] = []
    structural_calls: list[str] = []

    def __init__(self, _lang: str, source: bytes) -> None:
        self._fn = _RustFakeNode(source.decode("utf-8", errors="replace"))

    def parse(self) -> object:
        return object()

    def functions(self) -> list[object]:
        return [self._fn]

    def fn_body(self, fn: object) -> object:
        return fn.body

    def text(self, node: object) -> str:
        return str(node.text)

    def predicate_structural_match(self, _fn: object, predicate: str) -> bool:
        self.structural_calls.append(predicate)
        return predicate == "assignment"

    def query_structural(self, predicate: str, node: object | None = None) -> _RustFakeResult:
        del node
        self.query_calls.append(predicate)
        if predicate != "assignment":
            return _RustFakeResult([])
        return _RustFakeResult(["state.finalized_period = update.finalized_period"])


class _RustFakeAstModule:
    AstEngine = _RustFakeEngine


class LiveTargetStructuralPredicateTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeEngine.query_calls = []
        _FakeEngine.structural_calls = []
        _MoveFakeEngineBase.query_calls = []
        _RustFakeEngine.query_calls = []
        _RustFakeEngine.structural_calls = []
        ltir_mod._AST_ENGINE_CACHE.clear()

    def tearDown(self) -> None:
        ltir_mod._AST_ENGINE_CACHE.clear()

    def test_cosmos_001_consumes_query_structural_before_regex_fallback(self) -> None:
        source = "package app\nfunc Route(ctx Context, msg Msg) {}\n"
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_FakeAstModule):
            self.assertTrue(ltir_mod._p1_predicate_cosmos_001(source, ""))

        self.assertIn("call", _FakeEngine.query_calls)

    def test_cosmos_002_consumes_query_structural_before_regex_fallback(self) -> None:
        class _ProposalFakeEngine(_FakeEngine):
            def fn_name(self, _fn: object) -> str:
                return "ProcessProposal"

            def query_structural(self, predicate: str, node: object | None = None) -> _FakeResult:
                del node
                self.query_calls.append(predicate)
                return _FakeResult(["sdk.ABCIResponse.Accept"])

        class _ProposalAstModule:
            AstEngine = _ProposalFakeEngine

        source = (
            "package app\n"
            "func ProcessProposal(req Request) ResponseProcessProposal {\n"
            "    return ResponseProcessProposal_ACCEPT\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_ProposalAstModule):
            self.assertTrue(ltir_mod._p1_predicate_cosmos_002(source, ""))

        self.assertIn("call", _ProposalFakeEngine.query_calls)

    def test_cosmos_004_consumes_predicate_structural_match_before_regex_fallback(self) -> None:
        source = "package app\nfunc Send(ctx Context) { _ = SendCoinsFromModuleToAccount }\n"
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_FakeAstModule):
            self.assertTrue(ltir_mod._p1_predicate_cosmos_004(source, ""))

        self.assertIn("assignment_to_subscript_call", _FakeEngine.structural_calls)
        self.assertIn("call", _FakeEngine.query_calls)

    def test_cosmos_002_rejects_when_validation_is_present(self) -> None:
        class _ValidatedProposalFakeEngine(_FakeEngine):
            def fn_name(self, _fn: object) -> str:
                return "ProcessProposal"

            def query_structural(self, predicate: str, node: object | None = None) -> _FakeResult:
                del node
                self.query_calls.append(predicate)
                return _FakeResult(["ProcessProposal_ACCEPT"])

        class _ValidatedProposalAstModule:
            AstEngine = _ValidatedProposalFakeEngine

        source = (
            "package app\n"
            "func ProcessProposal(req Request) ResponseProcessProposal {\n"
            "    if len(req.Txs) == 0 { return ResponseProcessProposal_REJECT }\n"
            "    return ResponseProcessProposal_ACCEPT\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_ValidatedProposalAstModule):
            self.assertFalse(ltir_mod._p1_predicate_cosmos_002(source, ""))

        self.assertIn("call", _ValidatedProposalFakeEngine.query_calls)

    def test_cosmos_001_uses_regex_fallback_when_ast_predicates_are_disabled(self) -> None:
        source = (
            "package app\n"
            "func Route(ctx Context, msg Msg) {\n"
            "    router.msgServer.HandleMsgTransfer(ctx, msg)\n"
            "}\n"
        )
        with mock.patch.dict(os.environ, {"AUDITOOOR_P5_AST_PREDICATES": "0"}, clear=False), mock.patch.object(
            ltir_mod, "_load_ast_engine_module", side_effect=AssertionError("AST loader should not run")
        ) as load_mock:
            self.assertTrue(ltir_mod._p1_predicate_cosmos_001(source, ""))

        load_mock.assert_not_called()

    def test_cosmos_002_uses_regex_fallback_when_ast_predicates_are_disabled(self) -> None:
        source = (
            "package app\n"
            "func ProcessProposal(req Request) ResponseProcessProposal {\n"
            "    return ResponseProcessProposal_ACCEPT\n"
            "}\n"
        )
        with mock.patch.dict(os.environ, {"AUDITOOOR_P5_AST_PREDICATES": "0"}, clear=False), mock.patch.object(
            ltir_mod, "_load_ast_engine_module", side_effect=AssertionError("AST loader should not run")
        ) as load_mock:
            self.assertTrue(ltir_mod._p1_predicate_cosmos_002(source, ""))

        load_mock.assert_not_called()

    def test_cosmos_004_rejects_when_forbidden_guard_is_present(self) -> None:
        class _GuardedFakeEngine(_FakeEngine):
            def query_structural(self, predicate: str, node: object | None = None) -> _FakeResult:
                del node
                self.query_calls.append(predicate)
                return _FakeResult(
                    [
                        "balances[module] = bankKeeper.SendCoinsFromModuleToAccount(ctx, module, recipient, coins)",
                        "keeper.GetModuleAccountAddress(ctx, module)",
                    ]
                )

        class _GuardedAstModule:
            AstEngine = _GuardedFakeEngine

        source = (
            "package app\n"
            "func Send(ctx Context) {\n"
            "    balances[module] = bankKeeper.SendCoinsFromModuleToAccount(ctx, module, recipient, coins)\n"
            "    keeper.GetModuleAccountAddress(ctx, module)\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_GuardedAstModule):
            self.assertFalse(ltir_mod._p1_predicate_cosmos_004(source, ""))

        self.assertIn("assignment_to_subscript_call", _GuardedFakeEngine.structural_calls)
        self.assertIn("call", _GuardedFakeEngine.query_calls)

    def test_move_001_consumes_query_structural_before_regex_fallback(self) -> None:
        class _Move001FakeEngine(_MoveFakeEngineBase):
            call_texts = ["account::create_resource_account(@0x1, seed, addr)"]
            fn_name_value = "open"

        class _Move001AstModule:
            AstEngine = _Move001FakeEngine

        source = (
            "module test::m {\n"
            "  use aptos_framework::account;\n"
            "  public entry fun open(addr: address, seed: vector<u8>) {\n"
            "    let _resource_signer = account::create_resource_account(@0x1, seed, addr);\n"
            "  }\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_Move001AstModule):
            self.assertTrue(ltir_mod._p1_predicate_move_001(source, ""))

        self.assertIn("call", _Move001FakeEngine.query_calls)

    def test_move_001_preserves_forbidden_assert_guard_after_structural_match(self) -> None:
        class _Move001GuardedFakeEngine(_MoveFakeEngineBase):
            call_texts = [
                "account::create_resource_account(@0x1, seed, owner)",
                "signer::address_of(s)",
            ]
            fn_name_value = "open"

        class _Move001GuardedAstModule:
            AstEngine = _Move001GuardedFakeEngine

        source = (
            "module test::m {\n"
            "  use aptos_framework::account;\n"
            "  use std::signer;\n"
            "  public entry fun open(s: &signer, addr: address, seed: vector<u8>) {\n"
            "    let owner = signer::address_of(s);\n"
            "    assert!(signer::address_of(s) == owner, 42);\n"
            "    let _resource_signer = account::create_resource_account(owner, seed, owner);\n"
            "  }\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_Move001GuardedAstModule):
            self.assertFalse(ltir_mod._p1_predicate_move_001(source, ""))

        self.assertIn("call", _Move001GuardedFakeEngine.query_calls)

    def test_move_003_consumes_query_structural_before_regex_fallback(self) -> None:
        class _Move003FakeEngine(_MoveFakeEngineBase):
            call_texts = ["dof::add(parent, user_key, value)"]
            fn_name_value = "add"

        class _Move003AstModule:
            AstEngine = _Move003FakeEngine

        source = (
            "module test::m {\n"
            "  public fun add(parent: address, user_key: vector<u8>, value: u64) {\n"
            "    dof::add(parent, user_key, value);\n"
            "  }\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_Move003AstModule):
            self.assertTrue(ltir_mod._p1_predicate_move_003(source, ""))

        self.assertIn("call", _Move003FakeEngine.query_calls)

    def test_rust_missing_strict_increase_guard_consumes_structural_match_before_regex_fallback(self) -> None:
        source = (
            "pub fn update_state(state: &mut State, update: Update) {\n"
            "    state.finalized_period = update.finalized_period;\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_RustFakeAstModule):
            self.assertTrue(ltir_mod._p1_predicate_mon_001(source, ""))

        self.assertIn("assignment", _RustFakeEngine.structural_calls)
        self.assertIn("assignment", _RustFakeEngine.query_calls)

    def test_rust_missing_strict_increase_guard_rejects_guarded_path(self) -> None:
        source = (
            "pub fn update_state(state: &mut State, update: Update) {\n"
            "    ensure!(update.finalized_period > state.finalized_period);\n"
            "    state.finalized_period = update.finalized_period;\n"
            "}\n"
        )
        with mock.patch.object(ltir_mod, "_load_ast_engine_module", return_value=_RustFakeAstModule):
            self.assertFalse(ltir_mod._p1_predicate_mon_001(source, ""))

        self.assertIn("assignment", _RustFakeEngine.structural_calls)
        self.assertIn("assignment", _RustFakeEngine.query_calls)

    def test_rust_missing_strict_increase_guard_uses_regex_fallback_when_ast_is_disabled(self) -> None:
        source = (
            "pub fn update_state(state: &mut State, update: Update) {\n"
            "    state.finalized_period = update.finalized_period;\n"
            "}\n"
        )
        with mock.patch.dict(os.environ, {"AUDITOOOR_P5_AST_PREDICATES": "0"}, clear=False), mock.patch.object(
            ltir_mod, "_load_ast_engine_module", side_effect=AssertionError("AST loader should not run")
        ) as load_mock:
            self.assertTrue(ltir_mod._p1_predicate_mon_001(source, ""))

        load_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
