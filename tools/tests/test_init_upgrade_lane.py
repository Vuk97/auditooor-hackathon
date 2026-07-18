#!/usr/bin/env python3
"""Unit tests for tools/init-upgrade-lane.py (IUL).

Coverage matrix
---------------
SHAPE 1 - UNPROTECTED INITIALIZER
  SOL_UNPROTECTED_INIT_SRC      - public initialize() with no modifier -> MUST flag 1
  SOL_INITIALIZER_MOD_SRC       - initialize() with `initializer` modifier -> 0 (guarded)
  SOL_REINITIALIZER_MOD_SRC     - initializeV2() with `reinitializer` modifier -> 0 (guarded)
  SOL_ONLY_INITIALIZING_SRC     - internal _initialize() with `onlyInitializing` -> 0 (guarded)
  SOL_DISABLE_INITIALIZERS_SRC  - initialize() calls _disableInitializers() -> 0 (guarded)
  SOL_MANUAL_BOOL_GUARD_SRC     - initialize() sets `initialized = true` -> 0 (guarded)
  SOL_CONSTRUCTOR_NOT_FLAGGED   - constructor keyword not flagged as initializer
  SOL_INTERNAL_INIT_NOT_FLAGGED - internal initialize() not flagged (not public/external)

SUPPRESSORS (new)
  SOL_EMPTY_INIT_SRC            - init(){} with empty body -> NOT individually flagged (EMPTY-BODY)
  SOL_DIAMOND_INIT_CONTRACT_SRC - Init*-named contract init() -> folded into diamond_sink, NOT individually flagged
  SOL_DIAMOND_INIT_PATH_SRC     - init() in file under init/ path -> diamond_sink, NOT individually flagged
  SOL_UUPS_STILL_FLAGGED_SRC    - genuine UUPS initialize() with no modifier -> STILL flagged individually

SHAPE 2 - UNGUARDED UPGRADE AUTHORIZER
  SOL_BARE_AUTHORIZE_UPGRADE_SRC   - _authorizeUpgrade() with no guard in UUPS contract -> MUST flag
  SOL_ONLYOWNER_UPGRADE_SRC        - _authorizeUpgrade() with onlyOwner -> 0 (guarded)
  SOL_REQUIRE_SENDER_UPGRADE_SRC   - upgradeTo() with require(msg.sender == owner) -> 0 (guarded)
  SOL_NON_PROXY_SET_IMPL_SRC       - setImplementation() in non-proxy contract -> 0 (skipped by discriminator)
  SOL_BARE_UPGRADETO_SRC           - upgradeTo() in UUPSUpgradeable contract, no guard -> MUST flag

Invariant checks
----------------
- Every emitted hypothesis has verdict="needs-fuzz"
- Every emitted hypothesis has attack_class="unprotected-initialization-or-upgrade"
- Every emitted hypothesis has source="IUL"
- Every emitted hypothesis has init_or_upgrade in ("init", "upgrade")
- No em-dash (U+2014) or en-dash (U+2013) in any string field
- function field is non-empty
- file field is non-empty
"""
import importlib.util
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load the IUL module (hyphen-safe dynamic import).
# ---------------------------------------------------------------------------
_IUL_PATH = Path(__file__).resolve().parent.parent / "init-upgrade-lane.py"
_IUL_MOD_NAME = "init_upgrade_lane"


def _load_iul():
    spec = importlib.util.spec_from_file_location(_IUL_MOD_NAME, _IUL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_IUL_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


iul = _load_iul()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_init(source: str, fn_name: str = "") -> list[dict]:
    """Run initializer detection on source. fn_name unused (scans whole file)."""
    return iul.detect_unprotected_initializers(
        source=source,
        file_rel="fixture.sol",
        ws_abs="/tmp/iul_test_ws",
    )


def _run_upgrade(source: str) -> list[dict]:
    """Run upgrade-authorizer detection on source."""
    return iul.detect_unguarded_upgrade_authorizers(
        source=source,
        file_rel="fixture.sol",
        ws_abs="/tmp/iul_test_ws",
    )


def _assert_invariants(tc: unittest.TestCase, hyp: dict) -> None:
    tc.assertEqual(hyp["verdict"], "needs-fuzz")
    tc.assertEqual(hyp["attack_class"], "unprotected-initialization-or-upgrade")
    tc.assertEqual(hyp["source"], "IUL")
    tc.assertIn(hyp["init_or_upgrade"], ("init", "upgrade"))
    tc.assertTrue(hyp["function"], "function field must be non-empty")
    tc.assertTrue(hyp["file"], "file field must be non-empty")
    # No em-dash or en-dash in any string field.
    for v in hyp.values():
        if isinstance(v, str):
            tc.assertNotIn("—", v, f"em-dash found in field: {v!r}")
            tc.assertNotIn("–", v, f"en-dash found in field: {v!r}")


# ---------------------------------------------------------------------------
# SHAPE 1 fixtures
# ---------------------------------------------------------------------------

# Unprotected: public initialize() with no modifier, no disableInitializers,
# no manual bool guard.
SOL_UNPROTECTED_INIT_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyToken is Initializable {
    address public owner;
    uint256 public totalSupply;

    function initialize(address _owner, uint256 _supply) public {
        owner = _owner;
        totalSupply = _supply;
    }
}
"""

# Guarded: carries OZ `initializer` modifier.
SOL_INITIALIZER_MOD_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyToken is Initializable {
    address public owner;

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}
"""

# Guarded: carries `reinitializer` modifier (initializeV2).
SOL_REINITIALIZER_MOD_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyTokenV2 is Initializable {
    uint256 public version;

    function initializeV2() public reinitializer(2) {
        version = 2;
    }
}
"""

# Guarded: internal function with `onlyInitializing` - called by a child
# initializer. Internal visibility -> not flagged even if we inspect it.
SOL_ONLY_INITIALIZING_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract BaseContract is Initializable {
    uint256 internal _value;

    function __BaseContract_init(uint256 v) internal onlyInitializing {
        _value = v;
    }
}
"""

# Guarded: public initialize() calls _disableInitializers() (immutable pattern).
SOL_DISABLE_INITIALIZERS_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract ImmutableImpl is Initializable {
    constructor() {
        _disableInitializers();
    }

    function initialize() external {
        _disableInitializers();
    }
}
"""

# Guarded: manual bool guard `initialized = true`.
SOL_MANUAL_BOOL_GUARD_SRC = """\
pragma solidity ^0.8.0;

contract ManualGuard {
    bool public initialized;
    address public owner;

    function initialize(address _owner) external {
        require(!initialized, "already init");
        initialized = true;
        owner = _owner;
    }
}
"""

# Constructor: should NOT be flagged as an initializer even if named poorly.
SOL_CONSTRUCTOR_NOT_FLAGGED = """\
pragma solidity ^0.8.0;

contract RegularContract {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }
}
"""

# Internal visibility: should NOT be flagged.
SOL_INTERNAL_INIT_NOT_FLAGGED = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract BaseUpgradeable is Initializable {
    address internal _admin;

    function initialize(address admin) internal {
        _admin = admin;
    }
}
"""

# ---------------------------------------------------------------------------
# SUPPRESSOR fixtures (EMPTY-BODY + DIAMOND DISCRIMINATOR)
# ---------------------------------------------------------------------------

# EMPTY-BODY: init() with an empty body (like Beanstalk's InitEmpty.sol).
# The body contains only whitespace (none in this case).
# Must NOT be individually flagged - no privileged action possible.
SOL_EMPTY_INIT_SRC = """\
pragma solidity ^0.8.20;

contract InitEmpty {
    function init() external {}
}
"""

# DIAMOND by contract name: contract whose name starts with Init (Init + uppercase).
# The init() has a real body, but the contract name triggers the discriminator.
# Must NOT be individually flagged; must be collected into diamond_sink.
SOL_DIAMOND_INIT_CONTRACT_SRC = """\
pragma solidity ^0.8.20;

interface IBeanstalk {
    function owner() external view returns (address);
}

contract InitBipMiscImprovements {
    IBeanstalk private constant s_beanstalk = IBeanstalk(address(0xBEA));

    function init() external {
        // some Diamond state mutation
        s_beanstalk.owner();
    }
}
"""

# DIAMOND by path: file_rel contains "/init/" path segment.
# The contract name does NOT start with Init, but the path discriminates it.
# Must NOT be individually flagged; must be collected into diamond_sink.
SOL_DIAMOND_INIT_PATH_SRC = """\
pragma solidity ^0.8.20;

contract ReseedSilo {
    address public silo;

    function init(address _silo) external {
        silo = _silo;
    }
}
"""

# UUPS still flagged: genuine UUPS/Transparent proxy contract with
# unprotected initialize().  Must STILL be flagged individually even though
# the function name is "init"-prefix, because it is NOT in a Diamond context.
SOL_UUPS_STILL_FLAGGED_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyVaultUpgradeable is Initializable {
    address public owner;
    uint256 public totalSupply;

    function initialize(address _owner, uint256 _supply) public {
        owner = _owner;
        totalSupply = _supply;
    }
}
"""

# ---------------------------------------------------------------------------
# SHAPE 2 fixtures
# ---------------------------------------------------------------------------

# Unguarded: _authorizeUpgrade() in a UUPSUpgradeable contract with no access
# control modifier or inline check.
SOL_BARE_AUTHORIZE_UPGRADE_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract VaultUUPS is UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override {
    }
}
"""

# Guarded: _authorizeUpgrade() has onlyOwner modifier.
SOL_ONLYOWNER_UPGRADE_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract SafeVault is OwnableUpgradeable, UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
    }
}
"""

# Guarded: upgradeTo() has require(msg.sender == owner) inline check.
SOL_REQUIRE_SENDER_UPGRADE_SRC = """\
pragma solidity ^0.8.0;

contract ManualProxy is UUPSUpgradeable {
    address public owner;

    function upgradeTo(address newImpl) external {
        require(msg.sender == owner, "not owner");
        _upgradeToAndCallUUPS(newImpl, new bytes(0), false);
    }
}
"""

# Non-proxy contract: setImplementation() but the contract does NOT inherit
# from anything Upgradeable/UUPS/Proxy - discriminator fires, 0 hypotheses.
SOL_NON_PROXY_SET_IMPL_SRC = """\
pragma solidity ^0.8.0;

contract RegistryManager {
    address public implementation;

    function setImplementation(address newImpl) external {
        implementation = newImpl;
    }
}
"""

# Unguarded: upgradeTo() in a UUPSUpgradeable-inheriting contract, no guard.
SOL_BARE_UPGRADETO_SRC = """\
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract UnguardedProxy is UUPSUpgradeable {
    function upgradeTo(address newImpl) external {
        _upgradeToAndCallUUPS(newImpl, new bytes(0), false);
    }
}
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIULShape1Initializer(unittest.TestCase):

    def test_unprotected_initialize_flagged(self):
        """public initialize() with no OZ modifier and no bool guard -> flagged."""
        hyps = _run_init(SOL_UNPROTECTED_INIT_SRC)
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for unprotected initialize()")
        for h in hyps:
            _assert_invariants(self, h)
        fn_names = {h["function"] for h in hyps}
        self.assertIn("initialize", fn_names)
        kinds = {h["init_or_upgrade"] for h in hyps}
        self.assertIn("init", kinds)

    def test_initializer_modifier_not_flagged(self):
        """initialize() with `initializer` modifier -> 0 hypotheses."""
        hyps = _run_init(SOL_INITIALIZER_MOD_SRC)
        self.assertEqual(len(hyps), 0, f"OZ initializer modifier must suppress flag, got {hyps}")

    def test_reinitializer_modifier_not_flagged(self):
        """`reinitializer` modifier -> 0 hypotheses."""
        hyps = _run_init(SOL_REINITIALIZER_MOD_SRC)
        self.assertEqual(len(hyps), 0, f"reinitializer modifier must suppress flag, got {hyps}")

    def test_only_initializing_modifier_not_flagged(self):
        """`onlyInitializing` modifier -> 0 hypotheses."""
        hyps = _run_init(SOL_ONLY_INITIALIZING_SRC)
        self.assertEqual(len(hyps), 0, f"onlyInitializing modifier must suppress flag, got {hyps}")

    def test_disable_initializers_not_flagged(self):
        """`_disableInitializers()` call in body -> 0 hypotheses."""
        hyps = _run_init(SOL_DISABLE_INITIALIZERS_SRC)
        self.assertEqual(
            len(hyps), 0,
            f"_disableInitializers() in body must suppress flag, got {hyps}",
        )

    def test_manual_bool_guard_not_flagged(self):
        """`initialized = true` bool guard -> 0 hypotheses."""
        hyps = _run_init(SOL_MANUAL_BOOL_GUARD_SRC)
        self.assertEqual(
            len(hyps), 0,
            f"manual bool guard (initialized = true) must suppress flag, got {hyps}",
        )

    def test_constructor_not_flagged(self):
        """constructor() keyword is NOT an initializer fn -> 0 hypotheses."""
        hyps = _run_init(SOL_CONSTRUCTOR_NOT_FLAGGED)
        self.assertEqual(
            len(hyps), 0,
            f"constructor must not be flagged as an init fn, got {hyps}",
        )

    def test_internal_init_not_flagged(self):
        """internal initialize() -> 0 hypotheses (not public/external)."""
        hyps = _run_init(SOL_INTERNAL_INIT_NOT_FLAGGED)
        self.assertEqual(
            len(hyps), 0,
            f"internal initialize() must not be flagged, got {hyps}",
        )


class TestIULSupressors(unittest.TestCase):
    """Tests for EMPTY-BODY and DIAMOND DISCRIMINATOR suppressors."""

    def test_empty_body_init_not_individually_flagged(self):
        """init(){} with empty body must NOT be flagged individually (EMPTY-BODY suppressor)."""
        hyps = _run_init(SOL_EMPTY_INIT_SRC)
        self.assertEqual(
            len(hyps), 0,
            f"empty init() body must not be individually flagged, got {hyps}",
        )

    def test_empty_body_init_not_in_diamond_sink_either(self):
        """init(){} with empty body is suppressed before diamond check (nothing in sink)."""
        sink: list = []
        iul.detect_unprotected_initializers(
            source=SOL_EMPTY_INIT_SRC,
            file_rel="contracts/InitEmpty.sol",
            ws_abs="/tmp/iul_test_ws",
            diamond_sink=sink,
        )
        # Empty body is filtered before diamond discriminator; sink stays empty.
        self.assertEqual(
            len(sink), 0,
            f"empty body must be suppressed before reaching diamond discriminator, got {sink}",
        )

    def test_diamond_contract_name_not_individually_flagged(self):
        """Init*-named contract init() -> NOT individually flagged (DIAMOND DISCRIMINATOR)."""
        hyps = _run_init(SOL_DIAMOND_INIT_CONTRACT_SRC)
        self.assertEqual(
            len(hyps), 0,
            f"Init*-contract init() must not be individually flagged, got {hyps}",
        )

    def test_diamond_contract_name_folded_into_sink(self):
        """Init*-named contract init() -> folded into diamond_sink (not lost)."""
        sink: list = []
        iul.detect_unprotected_initializers(
            source=SOL_DIAMOND_INIT_CONTRACT_SRC,
            file_rel="contracts/InitBipMiscImprovements.sol",
            ws_abs="/tmp/iul_test_ws",
            diamond_sink=sink,
        )
        self.assertGreater(
            len(sink), 0,
            "Init*-contract init() must be collected into diamond_sink",
        )
        fn_names = {e["function"] for e in sink}
        self.assertIn("init", fn_names)

    def test_diamond_path_not_individually_flagged(self):
        """init() in file under init/ path -> NOT individually flagged (DIAMOND DISCRIMINATOR)."""
        # Use file_rel with /init/ path segment.
        hyps = iul.detect_unprotected_initializers(
            source=SOL_DIAMOND_INIT_PATH_SRC,
            file_rel="contracts/beanstalk/init/reseed/L2/ReseedSilo.sol",
            ws_abs="/tmp/iul_test_ws",
        )
        self.assertEqual(
            len(hyps), 0,
            f"init() under init/ path must not be individually flagged, got {hyps}",
        )

    def test_diamond_path_folded_into_sink(self):
        """init() in file under init/ path -> collected into diamond_sink."""
        sink: list = []
        iul.detect_unprotected_initializers(
            source=SOL_DIAMOND_INIT_PATH_SRC,
            file_rel="contracts/beanstalk/init/reseed/L2/ReseedSilo.sol",
            ws_abs="/tmp/iul_test_ws",
            diamond_sink=sink,
        )
        self.assertGreater(
            len(sink), 0,
            "init() under init/ path must be collected into diamond_sink",
        )

    def test_uups_initialize_still_flagged_individually(self):
        """UUPS/Transparent initialize() with no modifier is STILL flagged individually.

        This verifies that the diamond suppressors do NOT affect genuine UUPS
        contracts: neither the contract name nor the file path contains the
        Diamond init pattern.
        """
        hyps = iul.detect_unprotected_initializers(
            source=SOL_UUPS_STILL_FLAGGED_SRC,
            file_rel="contracts/MyVaultUpgradeable.sol",
            ws_abs="/tmp/iul_test_ws",
        )
        self.assertGreater(
            len(hyps), 0,
            "Genuine UUPS initialize() with no modifier must still be individually flagged",
        )
        fn_names = {h["function"] for h in hyps}
        self.assertIn("initialize", fn_names)
        for h in hyps:
            _assert_invariants(self, h)

    def test_non_diamond_path_not_suppressed(self):
        """init() in a normal (non-init-path) file with non-Init contract name is flagged."""
        # SOL_UNPROTECTED_INIT_SRC: contract MyToken is Initializable, file fixture.sol
        # -> neither diamond criterion fires -> individually flagged.
        hyps = _run_init(SOL_UNPROTECTED_INIT_SRC)
        self.assertGreater(
            len(hyps), 0,
            "init() in non-diamond context must still be individually flagged",
        )


class TestIULShape2UpgradeAuthorizer(unittest.TestCase):

    def test_bare_authorize_upgrade_flagged(self):
        """_authorizeUpgrade() with no guard in UUPSUpgradeable contract -> flagged."""
        hyps = _run_upgrade(SOL_BARE_AUTHORIZE_UPGRADE_SRC)
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for bare _authorizeUpgrade()")
        for h in hyps:
            _assert_invariants(self, h)
        fn_names = {h["function"] for h in hyps}
        self.assertIn("_authorizeUpgrade", fn_names)
        kinds = {h["init_or_upgrade"] for h in hyps}
        self.assertIn("upgrade", kinds)

    def test_onlyowner_upgrade_not_flagged(self):
        """_authorizeUpgrade() with onlyOwner modifier -> 0 hypotheses."""
        hyps = _run_upgrade(SOL_ONLYOWNER_UPGRADE_SRC)
        self.assertEqual(
            len(hyps), 0,
            f"onlyOwner on _authorizeUpgrade must suppress flag, got {hyps}",
        )

    def test_require_sender_upgrade_not_flagged(self):
        """upgradeTo() with require(msg.sender == owner) -> 0 hypotheses."""
        hyps = _run_upgrade(SOL_REQUIRE_SENDER_UPGRADE_SRC)
        self.assertEqual(
            len(hyps), 0,
            f"require(msg.sender == ...) must suppress upgrade flag, got {hyps}",
        )

    def test_non_proxy_set_implementation_not_flagged(self):
        """setImplementation() in a non-proxy contract -> 0 hypotheses (discriminator)."""
        hyps = _run_upgrade(SOL_NON_PROXY_SET_IMPL_SRC)
        self.assertEqual(
            len(hyps), 0,
            f"setImplementation() in non-proxy contract must NOT be flagged, got {hyps}",
        )

    def test_bare_upgradeto_in_uups_contract_flagged(self):
        """upgradeTo() with no guard in UUPSUpgradeable contract -> flagged."""
        hyps = _run_upgrade(SOL_BARE_UPGRADETO_SRC)
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for bare upgradeTo()")
        for h in hyps:
            _assert_invariants(self, h)
        fn_names = {h["function"] for h in hyps}
        self.assertIn("upgradeTo", fn_names)


class TestIULInvariants(unittest.TestCase):

    def test_all_flagged_have_needs_fuzz(self):
        """Every emitted hypothesis has verdict=needs-fuzz."""
        flagged_cases_init = [
            SOL_UNPROTECTED_INIT_SRC,
        ]
        flagged_cases_upgrade = [
            SOL_BARE_AUTHORIZE_UPGRADE_SRC,
            SOL_BARE_UPGRADETO_SRC,
        ]
        for src in flagged_cases_init:
            hyps = _run_init(src)
            for h in hyps:
                self.assertEqual(h["verdict"], "needs-fuzz")
        for src in flagged_cases_upgrade:
            hyps = _run_upgrade(src)
            for h in hyps:
                self.assertEqual(h["verdict"], "needs-fuzz")

    def test_no_em_dash_in_any_output(self):
        """No em-dash or en-dash in any hypothesis string field."""
        all_init = [
            SOL_UNPROTECTED_INIT_SRC,
            SOL_INITIALIZER_MOD_SRC,
            SOL_REINITIALIZER_MOD_SRC,
            SOL_MANUAL_BOOL_GUARD_SRC,
        ]
        all_upgrade = [
            SOL_BARE_AUTHORIZE_UPGRADE_SRC,
            SOL_ONLYOWNER_UPGRADE_SRC,
            SOL_BARE_UPGRADETO_SRC,
        ]
        for src in all_init:
            for h in _run_init(src):
                for v in h.values():
                    if isinstance(v, str):
                        self.assertNotIn("—", v, "em-dash found in init hypothesis")
                        self.assertNotIn("–", v, "en-dash found in init hypothesis")
        for src in all_upgrade:
            for h in _run_upgrade(src):
                for v in h.values():
                    if isinstance(v, str):
                        self.assertNotIn("—", v, "em-dash found in upgrade hypothesis")
                        self.assertNotIn("–", v, "en-dash found in upgrade hypothesis")

    def test_init_or_upgrade_field_values(self):
        """init_or_upgrade field is strictly 'init' or 'upgrade'."""
        init_hyps = _run_init(SOL_UNPROTECTED_INIT_SRC)
        for h in init_hyps:
            self.assertEqual(h["init_or_upgrade"], "init")

        upgrade_hyps = _run_upgrade(SOL_BARE_AUTHORIZE_UPGRADE_SRC)
        for h in upgrade_hyps:
            self.assertEqual(h["init_or_upgrade"], "upgrade")

    def test_fuzz_oracle_hint_present(self):
        """fuzz_oracle_hint field is non-empty for all flagged hypotheses."""
        for h in _run_init(SOL_UNPROTECTED_INIT_SRC):
            self.assertTrue(h.get("fuzz_oracle_hint"), "fuzz_oracle_hint must not be empty")
        for h in _run_upgrade(SOL_BARE_AUTHORIZE_UPGRADE_SRC):
            self.assertTrue(h.get("fuzz_oracle_hint"), "fuzz_oracle_hint must not be empty")


if __name__ == "__main__":
    unittest.main()
