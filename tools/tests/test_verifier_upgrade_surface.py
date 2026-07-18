#!/usr/bin/env python3
"""Tests for tools/verifier-upgrade-surface.py (PR #546 Lane B).

Stdlib-only. Synthetic Solidity fixtures under tempdir.

Coverage matrix:
  1. Synthetic source with all 5 canonical patterns -> 5 distinct rows
     (one per pattern_id).
  2. Default-to-kill: every emitted row has candidate_status="kill_or_reframe".
  3. Modifier extraction: onlyOwner / onlyProxyAdmin captured for guarded
     setters.
  4. JSON output schema is auditooor.verifier_upgrade_surface.v1.
  5. --strict exits 1 when default-to-kill rows remain.
  6. Empty workspace produces zero rows but still writes both files.
  7. Wave 4 P4: ``add_verify_route`` pattern fires on ``addVerifyRoute``
     (BA-C5 NitroEnclaveVerifier:402 site).
  8. Wave 4 P4: ``game_type_rotator`` pattern fires on ``setGameType``
     (BA-C5 TEEProverRegistry:121 site).
  9. Wave 4 P4: modifier extractor captures custom modifiers like
     ``proxyCallIfNotAdmin`` (BA-C5 Proxy.sol:60 false-negative).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "verifier-upgrade-surface.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("verifier_upgrade_surface", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verifier_upgrade_surface"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


def _run(args: list, *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(cwd) if cwd else None,
    )


SYNTHETIC_SOL = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract VerifierRegistry {
        address public implementation;
        address public verifier;
        address public proxy;
        mapping(uint32 => address) public gameImpl;

        modifier onlyOwner() { _; }
        modifier onlyProxyAdmin() { _; }

        function setImplementation(address newImpl) external onlyOwner {
            implementation = newImpl;
        }

        function upgradeTo(address newImpl) external onlyProxyAdmin {
            implementation = newImpl;
        }

        function _authorizeUpgrade(address newImpl) internal onlyOwner {
            // UUPS guard.
        }

        function setVerifier(address v) external onlyOwner {
            verifier = v;
        }

        function addGameType(uint32 gt, address impl) external onlyOwner {
            gameImpl[gt] = impl;
        }

        function deployClone(address logic) external returns (address) {
            return LibClone.deployERC1967(logic);
        }
    }
    library LibClone {
        function deployERC1967(address) internal pure returns (address) {
            return address(0);
        }
    }
    """
)


class TestSurfaceScanner(unittest.TestCase):
    def _make_workspace(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="vus_ws_"))
        (ws / "src").mkdir()
        (ws / "src" / "VerifierRegistry.sol").write_text(SYNTHETIC_SOL, encoding="utf-8")
        return ws

    def test_five_canonical_patterns_detected(self):
        ws = self._make_workspace()
        proc = _run(["--workspace", str(ws)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads((ws / "critical_hunt" / "verifier_upgrade_surface.json").read_text())
        self.assertEqual(out["schema"], "auditooor.verifier_upgrade_surface.v1")
        pattern_ids = {row["pattern_id"] for row in out["rows"]}
        # Five canonical OP1 patterns must all fire.
        for required in (
            "set_implementation",
            "upgrade_to",
            "authorize_upgrade",
            "set_verifier",
            "add_game_type",
        ):
            self.assertIn(required, pattern_ids, f"missing {required} in {pattern_ids}")
        # Bonus: lib_clone (call site) also fires.
        self.assertIn("lib_clone", pattern_ids)

    def test_default_to_kill(self):
        ws = self._make_workspace()
        _run(["--workspace", str(ws)])
        out = json.loads((ws / "critical_hunt" / "verifier_upgrade_surface.json").read_text())
        statuses = {row["candidate_status"] for row in out["rows"]}
        self.assertEqual(statuses, {"kill_or_reframe"})

    def test_modifier_extraction(self):
        ws = self._make_workspace()
        _run(["--workspace", str(ws)])
        out = json.loads((ws / "critical_hunt" / "verifier_upgrade_surface.json").read_text())
        by_pat = {row["pattern_id"]: row for row in out["rows"]}
        self.assertIn("onlyOwner", by_pat["set_implementation"]["modifier"])
        self.assertIn("onlyProxyAdmin", by_pat["upgrade_to"]["modifier"])

    def test_strict_exits_when_default_to_kill(self):
        ws = self._make_workspace()
        proc = _run(["--workspace", str(ws), "--strict"])
        # Synthetic workspace produces only default rows -> strict exits 1.
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_empty_workspace_writes_outputs(self):
        ws = Path(tempfile.mkdtemp(prefix="vus_empty_"))
        proc = _run(["--workspace", str(ws)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((ws / "critical_hunt" / "verifier_upgrade_surface.json").is_file())
        self.assertTrue((ws / "critical_hunt" / "verifier_upgrade_surface.md").is_file())
        out = json.loads((ws / "critical_hunt" / "verifier_upgrade_surface.json").read_text())
        self.assertEqual(out["row_count"], 0)


# ---------------------------------------------------------------------------
# Wave 4 Priority 4 — fixture tests for the 3 closed scanner gaps.
# ---------------------------------------------------------------------------

ADD_VERIFY_ROUTE_VULN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract NitroLikeVerifier {
        mapping(uint8 => mapping(bytes4 => address)) internal _zkVerifierRoutes;

        function addVerifyRoute(uint8 zkCoProcessor, bytes4 selector, address verifier) external {
            _zkVerifierRoutes[zkCoProcessor][selector] = verifier;
        }
    }
    """
)

ADD_VERIFY_ROUTE_CLEAN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract NitroLikeVerifierClean {
        mapping(uint8 => mapping(bytes4 => address)) internal _zkVerifierRoutes;

        modifier onlyOwner() { _; }

        function addVerifyRoute(uint8 zkCoProcessor, bytes4 selector, address verifier)
            external
            onlyOwner
        {
            _zkVerifierRoutes[zkCoProcessor][selector] = verifier;
        }
    }
    """
)

GAME_TYPE_ROTATOR_VULN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract TEERegistryLike {
        uint32 public gameType;

        function setGameType(uint32 gameType_) external {
            gameType = gameType_;
        }

        function replaceGameType(uint32 oldGt, uint32 newGt) external {
            gameType = newGt;
        }
    }
    """
)

GAME_TYPE_ROTATOR_CLEAN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract TEERegistryLikeClean {
        uint32 public gameType;

        modifier onlyOwner() { _; }

        function setGameType(uint32 gameType_) external onlyOwner {
            gameType = gameType_;
        }
    }
    """
)

PROXY_CALL_IF_NOT_ADMIN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract ProxyLike {
        modifier proxyCallIfNotAdmin() { _; }

        function upgradeTo(address _implementation) public virtual proxyCallIfNotAdmin {
            // _setImplementation(_implementation);
        }
    }
    """
)


class TestWave4ScannerGaps(unittest.TestCase):
    """Wave 4 Priority 4 — close 3 BA-C5 scanner gaps."""

    def _ws_with(self, name: str, body: str) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="vus_w4_"))
        (ws / "src").mkdir()
        (ws / "src" / name).write_text(body, encoding="utf-8")
        return ws

    def _rows(self, ws: Path):
        proc = _run(["--workspace", str(ws)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads((ws / "critical_hunt" / "verifier_upgrade_surface.json").read_text())
        return out["rows"]

    # Gap 1 — addVerifyRoute pattern.
    def test_add_verify_route_vulnerable_fires(self):
        ws = self._ws_with("NitroLikeVerifier.sol", ADD_VERIFY_ROUTE_VULN)
        rows = self._rows(ws)
        pat_ids = {r["pattern_id"] for r in rows}
        self.assertIn("add_verify_route", pat_ids, f"missing add_verify_route in {pat_ids}")
        for r in rows:
            if r["pattern_id"] == "add_verify_route":
                self.assertEqual(r["function"], "addVerifyRoute")
                self.assertEqual(r["modifier"], "none")
                self.assertEqual(r["target_type"], "verifier_route")

    def test_add_verify_route_clean_captures_modifier(self):
        ws = self._ws_with("NitroLikeVerifierClean.sol", ADD_VERIFY_ROUTE_CLEAN)
        rows = self._rows(ws)
        for r in rows:
            if r["pattern_id"] == "add_verify_route":
                self.assertIn("onlyOwner", r["modifier"])
                break
        else:
            self.fail("add_verify_route row not emitted on clean fixture")

    # Gap 2 — game_type_rotator pattern.
    def test_game_type_rotator_vulnerable_fires(self):
        ws = self._ws_with("TEERegistryLike.sol", GAME_TYPE_ROTATOR_VULN)
        rows = self._rows(ws)
        functions = {(r["pattern_id"], r["function"]) for r in rows}
        self.assertIn(("game_type_rotator", "setGameType"), functions)
        self.assertIn(("game_type_rotator", "replaceGameType"), functions)

    def test_game_type_rotator_clean_captures_modifier(self):
        ws = self._ws_with("TEERegistryLikeClean.sol", GAME_TYPE_ROTATOR_CLEAN)
        rows = self._rows(ws)
        for r in rows:
            if r["pattern_id"] == "game_type_rotator":
                self.assertIn("onlyOwner", r["modifier"])
                break
        else:
            self.fail("game_type_rotator row not emitted on clean fixture")

    # Gap 3 — proxyCallIfNotAdmin modifier extraction false-negative.
    def test_proxy_call_if_not_admin_extracted(self):
        ws = self._ws_with("ProxyLike.sol", PROXY_CALL_IF_NOT_ADMIN)
        rows = self._rows(ws)
        for r in rows:
            if r["pattern_id"] == "upgrade_to":
                self.assertIn(
                    "proxyCallIfNotAdmin",
                    r["modifier"],
                    f"modifier extractor missed proxyCallIfNotAdmin: {r['modifier']!r}",
                )
                self.assertEqual(r["function"], "upgradeTo")
                self.assertEqual(r["visibility"], "public")
                break
        else:
            self.fail("upgrade_to row not emitted on Proxy fixture")


# ---------------------------------------------------------------------------
# Wave H-3C — inline function-call access guard extraction.
# 4 guard variants × {vulnerable (no guard / empty), clean (guard present)}.
# ---------------------------------------------------------------------------

# Variant 1: _assertOnly* (AnchorStateRegistry pattern)
ASSERT_ONLY_GUARDIAN_VULN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract AnchorLike {
        uint32 public respectedGameType;

        function setRespectedGameType(uint32 _gameType) external {
            respectedGameType = _gameType;
        }
    }
    """
)

ASSERT_ONLY_GUARDIAN_CLEAN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract AnchorLikeClean {
        uint32 public respectedGameType;

        function setRespectedGameType(uint32 _gameType) external {
            _assertOnlyGuardian();
            respectedGameType = _gameType;
        }
    }
    """
)

# Variant 2: _check* inline guard
CHECK_ROLE_VULN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract VerifierLike {
        address public verifier;

        function setVerifier(address v) external {
            verifier = v;
        }
    }
    """
)

CHECK_ROLE_CLEAN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract VerifierLikeClean {
        address public verifier;

        function setVerifier(address v) external {
            _checkOwner();
            verifier = v;
        }
    }
    """
)

# Variant 3: _require* inline guard
REQUIRE_AUTH_VULN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract RegistryLike {
        address public registry;

        function setRegistry(address r) external {
            registry = r;
        }
    }
    """
)

REQUIRE_AUTH_CLEAN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract RegistryLikeClean {
        address public registry;

        function setRegistry(address r) external {
            _requireAuthorized();
            registry = r;
        }
    }
    """
)

# Variant 4: _ensure* / _validate* inline guards
ENSURE_VALIDATE_VULN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract ImplementationLike {
        address public implementation;

        function setImplementation(address impl) external {
            implementation = impl;
        }
    }
    """
)

ENSURE_VALIDATE_CLEAN = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract ImplementationLikeClean {
        address public implementation;

        function setImplementation(address impl) external {
            _ensureAdmin();
            _validateRole();
            implementation = impl;
        }
    }
    """
)


class TestWaveH3CInlineGuards(unittest.TestCase):
    """Wave H-3C — 8 tests: 4 inline-guard variants × {vulnerable, clean}.

    Vulnerable fixture: function with no guard (inline_access_guards=[]).
    Clean fixture: function with inline guard (inline_access_guards=[<name>]).
    """

    def _ws_with(self, name: str, body: str) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="vus_h3c_"))
        (ws / "src").mkdir()
        (ws / "src" / name).write_text(body, encoding="utf-8")
        return ws

    def _rows(self, ws: Path):
        proc = _run(["--workspace", str(ws)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads((ws / "critical_hunt" / "verifier_upgrade_surface.json").read_text())
        return out["rows"]

    # --- Variant 1: _assertOnly* ---

    def test_assert_only_vulnerable_no_inline_guard(self):
        """Unguarded setRespectedGameType emits empty inline_access_guards."""
        ws = self._ws_with("AnchorLike.sol", ASSERT_ONLY_GUARDIAN_VULN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setRespectedGameType"), None)
        self.assertIsNotNone(r, "setRespectedGameType row not emitted")
        self.assertEqual(
            r["inline_access_guards"],
            [],
            f"expected no inline guards, got {r['inline_access_guards']!r}",
        )

    def test_assert_only_clean_captures_inline_guard(self):
        """setRespectedGameType with _assertOnlyGuardian() is captured."""
        ws = self._ws_with("AnchorLikeClean.sol", ASSERT_ONLY_GUARDIAN_CLEAN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setRespectedGameType"), None)
        self.assertIsNotNone(r, "setRespectedGameType row not emitted")
        self.assertIn(
            "_assertOnlyGuardian",
            r["inline_access_guards"],
            f"_assertOnlyGuardian missing from inline_access_guards: {r['inline_access_guards']!r}",
        )

    # --- Variant 2: _check* ---

    def test_check_role_vulnerable_no_inline_guard(self):
        """Unguarded setVerifier emits empty inline_access_guards."""
        ws = self._ws_with("VerifierLike.sol", CHECK_ROLE_VULN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setVerifier"), None)
        self.assertIsNotNone(r, "setVerifier row not emitted")
        self.assertEqual(r["inline_access_guards"], [])

    def test_check_role_clean_captures_inline_guard(self):
        """setVerifier with _checkOwner() is captured as inline guard."""
        ws = self._ws_with("VerifierLikeClean.sol", CHECK_ROLE_CLEAN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setVerifier"), None)
        self.assertIsNotNone(r, "setVerifier row not emitted")
        self.assertIn("_checkOwner", r["inline_access_guards"])

    # --- Variant 3: _require* ---

    def test_require_auth_vulnerable_no_inline_guard(self):
        """Unguarded setRegistry emits empty inline_access_guards."""
        ws = self._ws_with("RegistryLike.sol", REQUIRE_AUTH_VULN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setRegistry"), None)
        self.assertIsNotNone(r, "setRegistry row not emitted")
        self.assertEqual(r["inline_access_guards"], [])

    def test_require_auth_clean_captures_inline_guard(self):
        """setRegistry with _requireAuthorized() is captured as inline guard."""
        ws = self._ws_with("RegistryLikeClean.sol", REQUIRE_AUTH_CLEAN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setRegistry"), None)
        self.assertIsNotNone(r, "setRegistry row not emitted")
        self.assertIn("_requireAuthorized", r["inline_access_guards"])

    # --- Variant 4: _ensure* / _validate* (multiple guards collected) ---

    def test_ensure_validate_vulnerable_no_inline_guard(self):
        """Unguarded setImplementation emits empty inline_access_guards."""
        ws = self._ws_with("ImplementationLike.sol", ENSURE_VALIDATE_VULN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setImplementation"), None)
        self.assertIsNotNone(r, "setImplementation row not emitted")
        self.assertEqual(r["inline_access_guards"], [])

    def test_ensure_validate_clean_captures_multiple_guards(self):
        """setImplementation with _ensureAdmin() + _validateRole() captures both."""
        ws = self._ws_with("ImplementationLikeClean.sol", ENSURE_VALIDATE_CLEAN)
        rows = self._rows(ws)
        r = next((r for r in rows if r["function"] == "setImplementation"), None)
        self.assertIsNotNone(r, "setImplementation row not emitted")
        self.assertIn("_ensureAdmin", r["inline_access_guards"])
        self.assertIn("_validateRole", r["inline_access_guards"])


if __name__ == "__main__":
    unittest.main()
