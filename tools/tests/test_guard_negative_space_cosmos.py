"""Loop-fix 2026-06-22: the guard-negative-space analyzer missed cosmos-SDK/cometbft
guard idioms (CamelCase ValidateBasic/HasPermission + panic() + return sdkerrors.Wrap),
extracting ~0 guards from cosmos-sdk (435 in-scope units) + cometbft (72) -> those Go
forks got zero depth-probe coverage. The added patterns (go-panic, cosmos-err-return,
go-has-permission, camel-verify-call) restore it. Bor/Solidity extraction must be
unaffected (the lowercase + if-err/nil patterns still fire).
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("gns_cosmos", str(_TOOLS / "guard-negative-space-analyzer.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gns_cosmos"] = mod
    spec.loader.exec_module(mod)
    return mod


_COSMOS = """package keeper

func (k BaseKeeper) MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error {
	acc := k.ak.GetModuleAccount(ctx, moduleName)
	if acc == nil {
		panic(errorsmod.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", moduleName))
	}
	if !acc.HasPermission(authtypes.Minter) {
		panic(errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "module %s has no mint permission", moduleName))
	}
	if err := amt.Validate(); err != nil {
		return errorsmod.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
	}
	return nil
}
"""


class TestGuardNegativeSpaceCosmos(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _scan(self, rel, body):
        ws = Path(tempfile.mkdtemp()).resolve()
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        return self.m._scan_file_for_guards(ws, rel)

    def test_cosmos_guards_extracted(self):
        g = self._scan("src/cosmos-sdk/x/bank/keeper/keeper.go", _COSMOS)
        texts = " ".join(str(x.get("text", "")) for x in g)
        # panic, errorsmod.Wrap error-return, and HasPermission must all be captured
        self.assertGreaterEqual(len(g), 4, f"expected >=4 cosmos guards, got {len(g)}")
        self.assertIn("panic(", texts)
        self.assertIn("HasPermission", texts)
        self.assertIn("errorsmod.Wrap", texts)

    def test_solidity_still_extracted(self):
        sol = ("contract V {\n"
               "  function f(uint a) external {\n"
               "    require(a > 0, \"zero\");\n"
               "    if (msg.sender != owner) revert();\n"
               "  }\n}\n")
        g = self._scan("src/pol-token/V.sol", sol)
        texts = " ".join(str(x.get("text", "")) for x in g)
        self.assertIn("require(", texts)  # solidity path unaffected


if __name__ == "__main__":
    unittest.main(verbosity=2)
