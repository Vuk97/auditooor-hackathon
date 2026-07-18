"""Unit tests for Rule 26 ante-handler traversal preflight."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "ante_handler_traversal_check",
    ROOT / "tools" / "ante-handler-traversal-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r26_ante_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests" / "case").mkdir(parents=True)
    return root


def _write(body: str, source: str | None = None, filename: str = "draft-HIGH.md") -> Path:
    root = _workspace()
    if source is not None:
        (root / "poc-tests" / "case" / "poc_test.go").write_text(source, encoding="utf-8")
        body += "\nPoC: `poc-tests/case`\n"
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


class AnteHandlerTraversalTests(unittest.TestCase):
    def test_medium_severity_out_of_scope(self) -> None:
        draft = _write("Severity: MEDIUM\nMsgSend drains funds.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_non_cosmos_draft_skips(self) -> None:
        draft = _write("Severity: HIGH\nERC20 transfer drains funds.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-cosmos-msg")

    def test_javascript_msg_data_variable_does_not_trigger_cosmos_msg(self) -> None:
        draft = _write(
            "Severity: CRITICAL\nArbitrum inbox message data drains funds.",
            "const msgData = utils.solidityPack(['uint8'], [1])\nreturn msgData\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-cosmos-msg")

    def test_direct_keeper_msg_fails(self) -> None:
        draft = _write(
            "Severity: HIGH\nMsgPlaceOrder causes fund loss.",
            "package poc\nfunc TestX(t *testing.T){ app.ClobKeeper.MsgServerPlaceOrder(ctx, msg) }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-ante-bypass")

    def test_baseapp_checktx_passes(self) -> None:
        draft = _write(
            "Severity: HIGH\nMsgSend causes fund loss.",
            "package poc\nfunc TestX(t *testing.T){ app.BaseApp.CheckTx(req) }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-ante-traversal")

    def test_run_tx_and_decorator_citation_passes(self) -> None:
        draft = _write("Severity: CRITICAL\nMsgExec path uses app.RunTx and cites ValidateNestedMsg + SigVerificationDecorator.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-ante-traversal")

    def test_honest_ante_walkback_passes(self) -> None:
        draft = _write("Severity: HIGH\nMsgExec path: ValidateNestedMsg returns Invalid nested msg; never reaches block.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-ante-traversal")

    def test_rebuttal_passes(self) -> None:
        draft = _write("Severity: HIGH\nMsgSend path. <!-- r26-rebuttal: proof targets internal BeginBlocker, no user Msg ante path -->")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_not_proven_msg_line_does_not_trigger(self) -> None:
        draft = _write("Severity: HIGH\nnot_proven: MsgExec path.")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-cosmos-msg")

    def test_missing_file_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
