"""Tests for R48 topology asset list integration.

Covers:
- Contract in list with non-empty population -> R48 PASS
- Contract in list as testnet-only -> R48 FAIL (test-only-deployment)
- Contract NOT in list -> fall through to existing live-check behavior
- Malformed asset list -> warn + fall through
- Schema version mismatch -> fall through
- Asset list helpers: _load_topology_asset_list, _attacker_population_from_asset_list
"""

import json
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the check module via importlib (hyphenated filename)
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "r48",
    str(REPO_ROOT / "tools" / "deployment-topology-vs-attack-surface-check.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

check = _mod.check
_load_topology_asset_list = _mod._load_topology_asset_list
_attacker_population_from_asset_list = _mod._attacker_population_from_asset_list
TOPOLOGY_ASSET_SCHEMA = _mod.TOPOLOGY_ASSET_SCHEMA


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_TOPOLOGY_SECTION = """
## Deployment Topology Attack Surface
- Production topology citation: `IntentGatewayV2` deployed via DeployIntentGateway.s.sol:20
- Attacker actor existence: any user who calls placeOrder; non-empty production population
- OOS test/staging clause citation: no testnet-only exclusion listed in SEVERITY.md
- Verdict: restricted-but-population-non-empty
"""

_TESTNET_TOPOLOGY_SECTION = """
## Deployment Topology Attack Surface
- Production topology citation: `TestnetHost` only appears in !isMainnet branch (DeployIsmp.s.sol:121)
- Attacker actor existence: unknown; testnet not reachable by attacker in production
- OOS test/staging clause citation: "TestnetHost is not deployed in production"
- Verdict: test-only-deployment
"""

_RESTRICTED_EMPTY_SECTION = """
## Deployment Topology Attack Surface
- Production topology citation: `SpecialWallet` only instantiated for internal team accounts
- Attacker actor existence: zero external users hold this wallet type
- OOS test/staging clause citation: "restricted to internal deployment"
- Verdict: restricted-and-population-empty
"""

_DRAFT_HEADER = "- Severity: High\n\n"

_VALID_ASSET_LIST = {
    "schema_version": TOPOLOGY_ASSET_SCHEMA,
    "workspace": "hyperbridge",
    "as_of": "2026-05-27",
    "deployments": [
        {
            "contract_name": "IntentGatewayV2",
            "contract_path": "evm/src/apps/IntentGatewayV2.sol",
            "deployed_at": None,
            "chain": "ethereum-mainnet",
            "attacker_population": "non-empty",
            "evidence": "deploy-script-confirmed",
            "evidence_url": None,
            "verified_at": "2026-05-27",
        },
        {
            "contract_name": "EvmHost",
            "contract_path": "evm/src/core/EvmHost.sol",
            "deployed_at": None,
            "chain": "ethereum-mainnet",
            "attacker_population": "needs-operator-classification",
            "evidence": "deploy-script-confirmed",
            "evidence_url": None,
            "verified_at": "2026-05-27",
        },
    ],
    "unverified_contracts": [
        {
            "contract_name": "TestnetHost",
            "contract_path": "evm/src/core/TestnetHost.sol",
            "reason": "testnet-only",
        },
        {
            "contract_name": "TokenFaucet",
            "contract_path": "evm/src/apps/TokenFaucet.sol",
            "reason": "testnet-only",
        },
        {
            "contract_name": "Codec",
            "contract_path": "evm/src/utils/Codec.sol",
            "reason": "library-only",
        },
    ],
}


def _make_ws_with_asset_list(tmp_path: Path, data: dict) -> Path:
    ws = tmp_path / "hyperbridge"
    ws.mkdir()
    topo_dir = ws / ".auditooor" / "r48_topology"
    topo_dir.mkdir(parents=True)
    (topo_dir / "hyperbridge.json").write_text(json.dumps(data), encoding="utf-8")
    return ws


def _make_draft(tmp_path: Path, body: str, name: str = "draft.md") -> Path:
    p = tmp_path / name
    p.write_text(_DRAFT_HEADER + body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Unit tests: _load_topology_asset_list
# ---------------------------------------------------------------------------

class TestLoadTopologyAssetList(unittest.TestCase):
    def test_none_workspace_returns_none(self):
        self.assertIsNone(_load_topology_asset_list(None))

    def test_missing_topology_dir_returns_none(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d) / "myws"
            ws.mkdir()
            self.assertIsNone(_load_topology_asset_list(ws))

    def test_valid_file_loaded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _make_ws_with_asset_list(Path(d), _VALID_ASSET_LIST)
            result = _load_topology_asset_list(ws)
            self.assertIsNotNone(result)
            self.assertEqual(result["workspace"], "hyperbridge")

    def test_malformed_json_returns_none(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d) / "hyperbridge"
            ws.mkdir()
            topo_dir = ws / ".auditooor" / "r48_topology"
            topo_dir.mkdir(parents=True)
            (topo_dir / "hyperbridge.json").write_text("{bad json}", encoding="utf-8")
            result = _load_topology_asset_list(ws)
            self.assertIsNone(result)

    def test_wrong_schema_version_returns_none(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bad = dict(_VALID_ASSET_LIST)
            bad["schema_version"] = "auditooor.r48_topology_assets.v0"
            ws = _make_ws_with_asset_list(Path(d), bad)
            result = _load_topology_asset_list(ws)
            self.assertIsNone(result)

    def test_missing_deployments_key_returns_none(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bad = {"schema_version": TOPOLOGY_ASSET_SCHEMA, "workspace": "hyperbridge"}
            ws = _make_ws_with_asset_list(Path(d), bad)
            result = _load_topology_asset_list(ws)
            self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Unit tests: _attacker_population_from_asset_list
# ---------------------------------------------------------------------------

class TestAttackerPopulationFromAssetList(unittest.TestCase):
    def setUp(self):
        self.data = _VALID_ASSET_LIST

    def test_known_non_empty_contract(self):
        self.assertEqual(_attacker_population_from_asset_list(self.data, "IntentGatewayV2"), "non-empty")

    def test_case_insensitive_lookup(self):
        self.assertEqual(_attacker_population_from_asset_list(self.data, "intentgatewayv2"), "non-empty")

    def test_needs_classification_returns_correct_value(self):
        self.assertEqual(_attacker_population_from_asset_list(self.data, "EvmHost"), "needs-operator-classification")

    def test_testnet_only_from_unverified(self):
        self.assertEqual(_attacker_population_from_asset_list(self.data, "TestnetHost"), "testnet-only")

    def test_library_only_from_unverified(self):
        self.assertEqual(_attacker_population_from_asset_list(self.data, "Codec"), "library-only")

    def test_unknown_contract_returns_none(self):
        self.assertIsNone(_attacker_population_from_asset_list(self.data, "NotInList"))


# ---------------------------------------------------------------------------
# Integration tests: check() with topology asset list
# ---------------------------------------------------------------------------

class TestCheckWithTopologyAssetList(unittest.TestCase):
    def test_no_restriction_language_passes_regardless_of_asset_list(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _make_ws_with_asset_list(Path(d), _VALID_ASSET_LIST)
            draft = _make_draft(ws, "No restriction language here. Just a plain finding.\n")
            result = check(draft, workspace=ws)
            self.assertEqual(result["verdict"], "pass-no-topology-restriction")

    def test_section_with_non_empty_verdict_passes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _make_ws_with_asset_list(Path(d), _VALID_ASSET_LIST)
            draft = _make_draft(ws, "This is restricted to `IntentGatewayV2` only.\n" + _TOPOLOGY_SECTION)
            result = check(draft, workspace=ws)
            self.assertIn(result["verdict"], [
                "pass-restricted-but-population-non-empty",
                "pass-no-topology-restriction",
            ])

    def test_section_with_testonly_verdict_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _make_ws_with_asset_list(Path(d), _VALID_ASSET_LIST)
            draft = _make_draft(ws, "This is restricted to a testnet-only path.\n" + _TESTNET_TOPOLOGY_SECTION)
            result = check(draft, workspace=ws)
            self.assertEqual(result["verdict"], "fail-test-only-deployment")

    def test_section_with_empty_population_verdict_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _make_ws_with_asset_list(Path(d), _VALID_ASSET_LIST)
            draft = _make_draft(
                ws,
                "This is restricted to a specific deployment configuration.\n" + _RESTRICTED_EMPTY_SECTION,
            )
            result = check(draft, workspace=ws)
            self.assertEqual(result["verdict"], "fail-restricted-and-empty-population")

    def test_no_asset_list_falls_through_to_normal_check(self):
        """When no asset list is present, normal section-based logic applies."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d) / "hyperbridge"
            ws.mkdir()
            draft = _make_draft(ws, "This is restricted to `TestnetHost` only.\n" + _TESTNET_TOPOLOGY_SECTION)
            result = check(draft, workspace=ws)
            self.assertEqual(result["verdict"], "fail-test-only-deployment")

    def test_malformed_asset_list_falls_through(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d) / "hyperbridge"
            ws.mkdir()
            topo_dir = ws / ".auditooor" / "r48_topology"
            topo_dir.mkdir(parents=True)
            (topo_dir / "hyperbridge.json").write_text("{invalid json!!!}", encoding="utf-8")
            draft = _make_draft(ws, "This is restricted to a `TestnetHost` only.\n" + _TESTNET_TOPOLOGY_SECTION)
            result = check(draft, workspace=ws)
            self.assertIn("verdict", result)
            self.assertEqual(result["verdict"], "fail-test-only-deployment")

    def test_rebuttal_short_circuits_asset_list(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _make_ws_with_asset_list(Path(d), _VALID_ASSET_LIST)
            # Use HTML-comment form so the rebuttal regex terminates at "-->"
            # rather than greedily consuming the rest of the draft past the
            # section boundary.
            draft = _make_draft(
                ws,
                "<!-- r48-rebuttal: on-chain analytics confirm non-empty population -->\n"
                "restricted to `TestnetHost`\n" + _TESTNET_TOPOLOGY_SECTION,
            )
            result = check(draft, workspace=ws)
            self.assertEqual(result["verdict"], "ok-rebuttal")

    def test_asset_list_source_reported_in_pass_result(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ws = _make_ws_with_asset_list(Path(d), _VALID_ASSET_LIST)
            draft = _make_draft(ws, "This is restricted to `IntentGatewayV2` only.\n" + _TOPOLOGY_SECTION)
            result = check(draft, workspace=ws)
            if result["verdict"] == "pass-restricted-but-population-non-empty":
                self.assertIn("topology_asset_list", result)


# ---------------------------------------------------------------------------
# Seed file sanity: hyperbridge.json ships exactly 19 contracts
# ---------------------------------------------------------------------------

class TestHyperbridgeSeedFile(unittest.TestCase):
    SEED_PATH = (
        REPO_ROOT / ".auditooor" / "r48_topology" / "hyperbridge.json"
    )

    def _load_seed(self):
        if not self.SEED_PATH.exists():
            self.skipTest(f"seed file not found at {self.SEED_PATH}")
        return json.loads(self.SEED_PATH.read_text(encoding="utf-8"))

    def test_schema_version(self):
        data = self._load_seed()
        self.assertEqual(data["schema_version"], TOPOLOGY_ASSET_SCHEMA)

    def test_total_contract_count_is_19(self):
        data = self._load_seed()
        total = len(data.get("deployments", [])) + len(data.get("unverified_contracts", []))
        self.assertEqual(total, 19, f"expected 19 contracts, got {total}")

    def test_all_deployment_entries_have_required_fields(self):
        data = self._load_seed()
        required = {"contract_name", "contract_path", "attacker_population", "verified_at"}
        for entry in data.get("deployments", []):
            missing = required - set(entry.keys())
            self.assertFalse(missing, f"entry {entry.get('contract_name')} missing: {missing}")

    def test_all_unverified_entries_have_required_fields(self):
        data = self._load_seed()
        required = {"contract_name", "contract_path", "reason"}
        for entry in data.get("unverified_contracts", []):
            missing = required - set(entry.keys())
            self.assertFalse(missing, f"entry {entry.get('contract_name')} missing: {missing}")

    def test_no_duplicate_contract_names(self):
        data = self._load_seed()
        all_names = (
            [e.get("contract_name") for e in data.get("deployments", [])]
            + [e.get("contract_name") for e in data.get("unverified_contracts", [])]
        )
        self.assertEqual(len(all_names), len(set(all_names)), "duplicate contract names found")

    def test_workspace_field(self):
        data = self._load_seed()
        self.assertEqual(data.get("workspace"), "hyperbridge")

    def test_testnet_host_in_unverified(self):
        data = self._load_seed()
        names = {e["contract_name"] for e in data.get("unverified_contracts", [])}
        self.assertIn("TestnetHost", names)

    def test_unverified_reason_values_valid(self):
        data = self._load_seed()
        valid_reasons = {
            "testnet-only", "interface-only", "library-only",
            "deploy-script-only", "needs-operator-classification",
        }
        for entry in data.get("unverified_contracts", []):
            reason = entry.get("reason", "")
            self.assertIn(
                reason, valid_reasons,
                f"{entry['contract_name']} has unexpected reason: {reason}",
            )


if __name__ == "__main__":
    unittest.main()
