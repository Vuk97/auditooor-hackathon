from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
if str(REPO / "tools" / "lib") not in sys.path:
    sys.path.insert(0, str(REPO / "tools" / "lib"))

from tools.lib.scope_oos_globs import load_oos_spec, is_oos  # noqa: E402


SEI_LIKE_SCOPE = """\
# Scope

## In scope

- `giga/executor` - the Giga execution engine.

## Out of scope

The following are OUT of scope and not eligible for rewards:

- Autobahn consensus is OUT of scope.
- All code in `giga` packages other than `giga/executor` is out of scope.
- The EVMone backend is OUT of scope.
- StateSync-peer paths are excluded from scope.

## Rewards

Standard tiers apply.
"""


def _mk_tree(root: Path) -> None:
    for d in (
        "giga/executor",
        "giga/deps",
        "autobahn/consensus",
        "evmone/backend",
        "x/evm/keeper",
    ):
        (root / d).mkdir(parents=True, exist_ok=True)
    # a few source files so basename resolution & is_oos have something real
    (root / "giga/executor/exec.go").write_text("package executor\n")
    (root / "giga/deps/dep.go").write_text("package deps\n")
    (root / "autobahn/consensus/cons.go").write_text("package consensus\n")
    (root / "evmone/backend/be.go").write_text("package backend\n")
    (root / "x/evm/keeper/msg.go").write_text("package keeper\n")


class LoadOosSpecTests(unittest.TestCase):
    def test_sei_like_excludes_and_include_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_tree(ws)
            (ws / "SCOPE.md").write_text(SEI_LIKE_SCOPE)
            spec = load_oos_spec(str(ws))
            globs = spec["exclude_globs"]
            # autobahn, evmone must be excluded (real tree dirs).
            self.assertIn("**/autobahn/**", globs)
            self.assertIn("**/evmone/**", globs)
            # RECONCILIATION (crown-jewel guard): the over-broad `giga/**` must NOT
            # appear in exclude_globs when `giga/executor/**` is an include-exception
            # under it - a raw-glob consumer would otherwise swallow the crown jewel.
            # It is expanded into its OOS child dir(s) instead.
            self.assertNotIn("**/giga/**", globs)
            self.assertIn("**/giga/deps/**", globs)
            # and giga/executor must NOT be an exclude glob at all.
            self.assertNotIn("**/giga/executor/**", globs)
            # giga/executor is an include-exception.
            self.assertIn("**/giga/executor/**", spec["include_exceptions"])

    def test_giga_deps_is_oos_but_executor_kept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_tree(ws)
            (ws / "SCOPE.md").write_text(SEI_LIKE_SCOPE)
            spec = load_oos_spec(str(ws))
            # giga/deps -> OOS
            blocked, reason = is_oos("giga/deps/dep.go", spec, str(ws))
            self.assertTrue(blocked)
            self.assertTrue(reason)
            # autobahn -> OOS
            self.assertTrue(is_oos("autobahn/consensus/cons.go", spec, str(ws))[0])
            # evmone -> OOS
            self.assertTrue(is_oos("evmone/backend/be.go", spec, str(ws))[0])

    def test_never_false_exclude_giga_executor_stays_in_scope(self) -> None:
        # CRITICAL never-false-exclude assertion: the include-exception must win.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_tree(ws)
            (ws / "SCOPE.md").write_text(SEI_LIKE_SCOPE)
            spec = load_oos_spec(str(ws))
            blocked, _ = is_oos("giga/executor/exec.go", spec, str(ws))
            self.assertFalse(
                blocked,
                "giga/executor is an include-exception and MUST stay in scope",
            )
            # an in-scope, unrelated path stays in scope too.
            self.assertFalse(is_oos("x/evm/keeper/msg.go", spec, str(ws))[0])

    def test_empty_absent_oos_section_no_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_tree(ws)
            (ws / "SCOPE.md").write_text(
                "# Scope\n\n## In scope\n\n- Everything.\n"
            )
            spec = load_oos_spec(str(ws))
            self.assertEqual(spec["exclude_globs"], [])
            self.assertFalse(is_oos("autobahn/consensus/cons.go", spec, str(ws))[0])

    def test_no_scope_md_fails_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_tree(ws)
            spec = load_oos_spec(str(ws))
            self.assertEqual(spec["exclude_globs"], [])
            self.assertEqual(spec["include_exceptions"], [])

    def test_noun_with_no_tree_dir_not_excluded(self) -> None:
        # "Nimbus" appears in the OOS text but there is NO nimbus/ dir -> fail-open.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_tree(ws)
            (ws / "SCOPE.md").write_text(
                "# Scope\n\n## Out of scope\n\n"
                "- The Nimbus subsystem is OUT of scope.\n"
                "- Autobahn is OUT of scope.\n"
            )
            spec = load_oos_spec(str(ws))
            # autobahn dir exists -> excluded; nimbus has no dir -> NOT excluded.
            self.assertIn("**/autobahn/**", spec["exclude_globs"])
            self.assertNotIn("**/nimbus/**", spec["exclude_globs"])
            # nothing named nimbus is dropped.
            for g in spec["exclude_globs"]:
                self.assertNotIn("nimbus", g.lower())

    def test_lowercase_scope_md_also_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_tree(ws)
            (ws / "scope.md").write_text(SEI_LIKE_SCOPE)
            spec = load_oos_spec(str(ws))
            self.assertIn("**/autobahn/**", spec["exclude_globs"])


if __name__ == "__main__":
    unittest.main()


# --- Regression: SEI 2026-07-05 over-exclusion failure modes ---------------
def _sei_like_ws(tmp):
    """Build a tmp workspace mirroring the SEI SCOPE.md failure modes."""
    import os
    for d in ("src/sei-chain/giga/executor/internal", "src/sei-chain/giga/deps/xevm",
              "src/sei-chain/giga/storage", "src/sei-chain/integration_test/autobahn",
              "src/go-ethereum/rpc", "src/go-ethereum/core/state", "src/go-ethereum/p2p",
              "src/go-ethereum/node", "src/sei-chain/sei-cosmos/server",
              "src/sei-chain/evmrpc"):
        os.makedirs(os.path.join(tmp, d), exist_ok=True)
    scope = (
        "# Scope\n\n## Out of scope\n\n"
        "### Giga-related functionality\n"
        "IN scope: the `giga/executor` Go package. Any code in `giga` packages "
        "other than `giga/executor` is out of scope.\n"
        "- The Autobahn multi-proposer consensus protocol.\n"
        "- Giga storage.\n\n"
        "### Excluded StateSync Peer functionality (trusted infrastructure)\n"
        "A StateSync Peer is a TRUSTED node explicitly configured as an RPC server "
        "and persistent peer. Vulns requiring a malicious or compromised StateSync "
        "Peer, or P2P peer acting as a state provider, are not eligible.\n"
    )
    open(os.path.join(tmp, "SCOPE.md"), "w").write(scope)
    return tmp


def test_sei_giga_executor_exception_is_exact_not_parent():
    import tempfile
    from scope_oos_globs import load_oos_spec, is_oos
    ws = _sei_like_ws(tempfile.mkdtemp())
    spec = load_oos_spec(ws)
    # giga/executor IN; non-executor giga OUT (exception must NOT be bare giga/**)
    assert not is_oos("src/sei-chain/giga/executor/internal/x.go", spec, ws)[0]
    assert is_oos("src/sei-chain/giga/deps/xevm/y.go", spec, ws)[0]
    assert is_oos("src/sei-chain/giga/storage/s.go", spec, ws)[0]
    assert spec["include_exceptions"] == ["**/src/sei-chain/giga/executor/**"]


def test_sei_threatmodel_prose_does_not_exclude_infra_dirs():
    import tempfile
    from scope_oos_globs import load_oos_spec, is_oos
    ws = _sei_like_ws(tempfile.mkdtemp())
    spec = load_oos_spec(ws)
    # StateSync trust paragraph must NOT drop in-scope core dirs
    for p in ("src/go-ethereum/rpc/client.go", "src/go-ethereum/node/n.go",
              "src/go-ethereum/p2p/s.go", "src/go-ethereum/core/state/db.go",
              "src/sei-chain/sei-cosmos/server/start.go",
              "src/sei-chain/evmrpc/filter.go"):
        assert not is_oos(p, spec, ws)[0], f"{p} wrongly OOS"


def test_sei_autobahn_still_excluded():
    import tempfile
    from scope_oos_globs import load_oos_spec, is_oos
    ws = _sei_like_ws(tempfile.mkdtemp())
    spec = load_oos_spec(ws)
    assert is_oos("src/sei-chain/integration_test/autobahn/x.go", spec, ws)[0]


# --- Regression: SEI 2026-07-05 testnet/mock denominator carve-out ----------
def _testnet_mock_ws(tmp, *, with_carveout: bool):
    """A workspace with example/ + loadtest/ demo dirs and a real protocol dir."""
    import os
    for d in ("src/sei-chain/example/cosmwasm/cw20/src",
              "src/sei-chain/loadtest/contracts/mars/src",
              "src/sei-chain/testutil/sample",
              "src/sei-chain/x/evm/keeper"):
        os.makedirs(os.path.join(tmp, d), exist_ok=True)
    body = "# Scope\n\n## Out of scope\n\n- `src/sei-chain/nope` is out of scope.\n\n"
    if with_carveout:
        body += ("### General\n- Testnet + mock files are NOT covered under "
                 "Primacy of Impact.\n")
    open(os.path.join(tmp, "SCOPE.md"), "w").write(body)
    return tmp


def test_testnet_mock_carveout_drops_example_and_loadtest():
    import tempfile
    from scope_oos_globs import load_oos_spec, is_oos
    ws = _testnet_mock_ws(tempfile.mkdtemp(), with_carveout=True)
    spec = load_oos_spec(ws)
    # example/, loadtest/, testutil/ are dropped by the documented carve-out.
    assert is_oos("src/sei-chain/example/cosmwasm/cw20/src/contract.rs", spec, ws)[0]
    assert is_oos("src/sei-chain/loadtest/contracts/mars/src/contract.rs", spec, ws)[0]
    assert is_oos("src/sei-chain/testutil/sample/x.go", spec, ws)[0]
    # real protocol code stays IN.
    assert not is_oos("src/sei-chain/x/evm/keeper/msg_server.go", spec, ws)[0]


def test_testnet_mock_carveout_fail_open_without_documented_rule():
    # No "testnet/mock NOT covered" statement -> example/ stays IN (fail-open).
    import tempfile
    from scope_oos_globs import load_oos_spec, is_oos
    ws = _testnet_mock_ws(tempfile.mkdtemp(), with_carveout=False)
    spec = load_oos_spec(ws)
    assert not is_oos("src/sei-chain/example/cosmwasm/cw20/src/contract.rs", spec, ws)[0]
    assert not is_oos("src/sei-chain/loadtest/contracts/mars/src/contract.rs", spec, ws)[0]


def test_exclude_and_exception_lists_are_disjoint():
    # Crown-jewel guard: no exclude glob may equal or be a parent-that-swallows an
    # include-exception; the two lists must be non-overlapping after reconciliation.
    import tempfile
    from scope_oos_globs import load_oos_spec
    ws = _sei_like_ws(tempfile.mkdtemp())
    spec = load_oos_spec(ws)
    def _d(g):
        return g[3:-3] if g.startswith("**/") and g.endswith("/**") else g.strip("/")
    exc = {_d(x) for x in spec["include_exceptions"]}
    for g in spec["exclude_globs"]:
        gd = _d(g)
        for xd in exc:
            assert not (gd == xd or (xd + "/").startswith(gd + "/")), (
                f"exclude {g} swallows include-exception {xd}")
