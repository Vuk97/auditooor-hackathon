"""Test _r76_verify credits an excerpt that matches a NON-first cited file (multi-file
citation serving-join fix, NUVA 2026-07-04)."""
import importlib.util, sys, tempfile, unittest
from pathlib import Path
TOOL = Path(__file__).resolve().parents[1] / "hacker-question-obligation-resolve.py"
_spec = importlib.util.spec_from_file_location("hqor_t", TOOL)
hqor = importlib.util.module_from_spec(_spec); sys.modules["hqor_t"] = hqor
_spec.loader.exec_module(hqor)


class TestR76MultiFile(unittest.TestCase):
    def _ws(self, tmp):
        ws = Path(tmp)
        d = ws / "src" / "vault" / "keeper"; d.mkdir(parents=True)
        (d / "msg_server.go").write_text("package keeper\nfunc NewMsgServer() {}\n")
        (d / "abci.go").write_text("package keeper\nfunc (k *Keeper) BeginBlocker(ctx sdk.Context) error {\n\treturn nil\n}\n")
        return ws

    def test_excerpt_in_second_cited_file_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            # file_line lists msg_server.go FIRST, but the excerpt is from abci.go (2nd).
            ok, reason = hqor._r76_verify(
                ws,
                "src/vault/keeper/msg_server.go:28, src/vault/keeper/abci.go:2",
                "func (k *Keeper) BeginBlocker(ctx sdk.Context) error")
            self.assertTrue(ok, f"excerpt in a later-cited file must verify: {reason}")

    def test_excerpt_in_no_cited_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            ok, reason = hqor._r76_verify(
                ws,
                "src/vault/keeper/msg_server.go:28, src/vault/keeper/abci.go:2",
                "func TotallyFabricatedThatIsNowhere(x uint256) public")
            self.assertFalse(ok, "a genuinely-absent excerpt must still be rejected (never-false-pass)")
            self.assertIn("any cited source", reason)

    def test_hallucination_signal_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            ok, reason = hqor._r76_verify(ws, "N/A", "whatever")
            self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
