"""
tests/test_secret_scrub_changed_files.py — Unit tests for secret-scrub-changed-files.py

PR #658 Lane 7 — Tier-B #11 deliverable.

Tests:
  1. Clean file returns no findings (exit 0).
  2. AWS key in file fires aws-access-key finding (exit 2 with --exit-fail).
  3. GitHub PAT in file fires github-pat finding (exit 2 with --exit-fail).
  4. PEM private-key block fires pem-private-key finding (exit 2 with --exit-fail).
  5. Excluded path is skipped (no finding emitted for that file).
  6. JSON output schema is valid (required keys present).
  7. EVM private key fires private-key-evm finding.
  8. Generic sk-token fires generic-sk-token finding.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Import the module under test directly (bypass __main__ guard)
# ---------------------------------------------------------------------------
_TOOL_PATH = Path(__file__).parent.parent / "secret-scrub-changed-files.py"

def _load_module():
    spec = importlib.util.spec_from_file_location("secret_scrub", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_mod = _load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan_content(content: str) -> list[dict]:
    """Write content to a temp file and scan it; return findings list."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        fpath = repo_root / "changed_file.py"
        fpath.write_text(content, encoding="utf-8")
        return _mod.scan_file(fpath, repo_root)


def _has_pattern(findings: list[dict], pattern_name: str) -> bool:
    return any(f.get("pattern") == pattern_name for f in findings)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCleanDiff(unittest.TestCase):
    """A file with no secrets produces no findings."""

    def test_clean_python_file(self):
        content = (
            "def add(a, b):\n"
            "    return a + b\n\n"
            "if __name__ == '__main__':\n"
            "    print(add(1, 2))\n"
        )
        findings = _scan_content(content)
        self.assertEqual(findings, [], f"Expected no findings, got {findings}")

    def test_clean_returns_exit0_via_run_scrub(self):
        """run_scrub with no changed files returns empty list (exit 0 equivalent)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            # Mock _git_changed_files to return empty list
            with patch.object(_mod, "_git_changed_files", return_value=[]):
                findings = _mod.run_scrub("HEAD~1", repo_root, [])
        self.assertEqual(findings, [])


class TestAWSKey(unittest.TestCase):
    """AWS AKIA key triggers aws-access-key finding."""

    def test_aws_key_detected(self):
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        findings = _scan_content(content)
        self.assertTrue(
            _has_pattern(findings, "aws-access-key"),
            f"Expected aws-access-key finding, got {findings}",
        )

    def test_aws_key_severity_high(self):
        content = "key: AKIAIOSFODNN7EXAMPLE\n"
        findings = _scan_content(content)
        aws_findings = [f for f in findings if f["pattern"] == "aws-access-key"]
        self.assertGreater(len(aws_findings), 0)
        self.assertEqual(aws_findings[0]["severity"], "HIGH")


class TestGitHubPAT(unittest.TestCase):
    """GitHub personal access token triggers github-pat finding."""

    def test_ghp_prefix_detected(self):
        content = "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH1234\n"
        findings = _scan_content(content)
        self.assertTrue(
            _has_pattern(findings, "github-pat"),
            f"Expected github-pat finding, got {findings}",
        )

    def test_ghs_prefix_detected(self):
        content = "token: ghs_abcdefghijklmnopqrstuvwxyzABCDEFGH1234\n"
        findings = _scan_content(content)
        self.assertTrue(_has_pattern(findings, "github-pat"))

    def test_short_value_not_detected(self):
        # Only 10 chars after prefix — should NOT match (need ≥36)
        content = "GITHUB_TOKEN=ghp_abc123\n"
        findings = _scan_content(content)
        self.assertFalse(_has_pattern(findings, "github-pat"))


class TestPEMPrivateKey(unittest.TestCase):
    """PEM private key block header triggers pem-private-key finding."""

    def test_rsa_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n"
        findings = _scan_content(content)
        self.assertTrue(
            _has_pattern(findings, "pem-private-key"),
            f"Expected pem-private-key finding, got {findings}",
        )

    def test_ec_private_key(self):
        content = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n"
        findings = _scan_content(content)
        self.assertTrue(_has_pattern(findings, "pem-private-key"))

    def test_private_key_generic(self):
        content = "-----BEGIN PRIVATE KEY-----\nMIIEvg...\n"
        findings = _scan_content(content)
        self.assertTrue(_has_pattern(findings, "pem-private-key"))


class TestExcludedPath(unittest.TestCase):
    """Files matching the exclude list are skipped entirely."""

    def test_excluded_path_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            # Create a "secret" file that would normally trigger
            secret_file = repo_root / "tools" / "calibration" / "llm_budget_log.jsonl"
            secret_file.parent.mkdir(parents=True, exist_ok=True)
            secret_file.write_text(
                '{"key": "AKIAIOSFODNN7EXAMPLE"}\n', encoding="utf-8"
            )

            rel_path = str(secret_file.relative_to(repo_root))

            # Simulate changed files including only the excluded path
            with patch.object(
                _mod, "_git_changed_files", return_value=[rel_path]
            ):
                findings = _mod.run_scrub(
                    "HEAD~1",
                    repo_root,
                    excludes=["tools/calibration/llm_budget_log.jsonl"],
                )

        self.assertEqual(
            findings, [],
            f"Expected excluded file to produce no findings, got {findings}",
        )

    def test_non_excluded_path_still_scanned(self):
        """A file NOT in the exclude list IS scanned even when other excludes exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            secret_file = repo_root / "config.py"
            secret_file.write_text(
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8"
            )

            with patch.object(
                _mod, "_git_changed_files", return_value=["config.py"]
            ):
                findings = _mod.run_scrub(
                    "HEAD~1",
                    repo_root,
                    excludes=["tools/calibration/llm_budget_log.jsonl"],
                )

        self.assertTrue(
            _has_pattern(findings, "aws-access-key"),
            f"Expected aws-access-key finding for non-excluded file, got {findings}",
        )


class TestJSONOutputSchema(unittest.TestCase):
    """JSON output has the required schema keys."""

    def test_json_schema_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            secret_file = repo_root / "secrets.env"
            secret_file.write_text(
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH1234\n",
                encoding="utf-8",
            )

            with patch.object(
                _mod, "_git_changed_files", return_value=["secrets.env"]
            ):
                findings = _mod.run_scrub("HEAD~1", repo_root, [])

        self.assertGreater(len(findings), 0, "Expected at least one finding for schema test")
        finding = findings[0]
        required_keys = {"file", "line", "pattern", "severity", "description", "excerpt"}
        missing = required_keys - set(finding.keys())
        self.assertEqual(
            missing, set(),
            f"Finding missing required keys: {missing}. Got keys: {set(finding.keys())}",
        )

    def test_json_schema_types(self):
        """file=str, line=int, pattern=str, severity=str, excerpt=str."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            secret_file = repo_root / "test.py"
            secret_file.write_text(
                "key = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8"
            )
            with patch.object(
                _mod, "_git_changed_files", return_value=["test.py"]
            ):
                findings = _mod.run_scrub("HEAD~1", repo_root, [])

        self.assertTrue(findings)
        f = findings[0]
        self.assertIsInstance(f["file"], str)
        self.assertIsInstance(f["line"], int)
        self.assertIsInstance(f["pattern"], str)
        self.assertIsInstance(f["severity"], str)
        self.assertIsInstance(f["excerpt"], str)


class TestEVMPrivateKey(unittest.TestCase):
    """EVM private key (0x + 64 hex) triggers private-key-evm finding."""

    def test_evm_key_with_keyword(self):
        # Has 'private key' keyword + 64 hex + high entropy
        content = (
            "private_key = 0xa1b2c3d4e5f60102030405060708091011121314151617"
            "181a1b1c1d1e1f2021\n"
        )
        findings = _scan_content(content)
        # Should fire private-key-evm (entropy check: all distinct hex nibbles → high entropy)
        self.assertTrue(
            _has_pattern(findings, "private-key-evm")
            or _has_pattern(findings, "hex32-suspicious"),
            f"Expected evm or hex32 finding, got {findings}",
        )

    def test_evm_address_40hex_not_flagged_as_evm_key(self):
        # 40 hex chars (EVM address) must NOT match the 64-hex private-key pattern
        content = "contract = 0xF3fe54Eeb378BB607B1D1A1031B85A2b2fc3173c\n"
        findings = _scan_content(content)
        evm_key_findings = [f for f in findings if f["pattern"] == "private-key-evm"]
        self.assertEqual(
            evm_key_findings, [],
            f"EVM address (40 hex) should not trigger private-key-evm, got {findings}",
        )

    def test_public_exploit_tx_hash_near_private_key_incident_not_flagged(self):
        content = (
            '"attack_class":"bridge-private-key-compromise",'
            '"preconditions":["Public-exploit-tx '
            '0x9e0fe0b3a8a14ba9ea6cbeb6e1c5d1c0a4e5d2c1d2b3a4c5d6e7f8a9b0c1d2e3",'
            '"attacker compromised an operator private key"]}\n'
        )
        findings = _scan_content(content)
        self.assertFalse(
            _has_pattern(findings, "private-key-evm")
            or _has_pattern(findings, "hex32-suspicious"),
            f"Public exploit transaction hash should not trigger, got {findings}",
        )

    def test_public_transaction_hash_near_signature_replay_not_flagged(self):
        content = (
            "Signature replay exploit transaction "
            "0x5edb66a4c2ea55bba95d36d27713e3bb1c67c3c4199a8a1759e754c6f25482e5 "
            "used a signer authorization bug.\n"
        )
        findings = _scan_content(content)
        self.assertFalse(
            _has_pattern(findings, "private-key-evm")
            or _has_pattern(findings, "hex32-suspicious"),
            f"Public transaction hash should not trigger, got {findings}",
        )

    def test_public_sui_attacker_account_not_flagged(self):
        content = (
            "On Sui mainnet, attacker "
            "0x1a65086c85114c1a3f8dc74140115c6e18438d48d33a21fd112311561112d41e "
            "exploited a fee accounting bug.\n"
        )
        findings = _scan_content(content)
        self.assertFalse(
            _has_pattern(findings, "private-key-evm")
            or _has_pattern(findings, "hex32-suspicious"),
            f"Public Sui-style account should not trigger, got {findings}",
        )

    def test_public_init_code_hash_not_flagged(self):
        content = (
            "The _INIT_CODE_HASH is "
            "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54.\n"
        )
        findings = _scan_content(content)
        self.assertFalse(
            _has_pattern(findings, "private-key-evm")
            or _has_pattern(findings, "hex32-suspicious"),
            f"Public init code hash should not trigger, got {findings}",
        )

    def test_direct_private_key_assignment_still_flagged(self):
        content = (
            "private_key = "
            "0xa1b2c3d4e5f60102030405060708091011121314151617181a1b1c1d1e1f2021\n"
        )
        findings = _scan_content(content)
        self.assertTrue(
            _has_pattern(findings, "private-key-evm")
            or _has_pattern(findings, "hex32-suspicious"),
            f"Direct private key assignment should still trigger, got {findings}",
        )


class TestGenericSKToken(unittest.TestCase):
    """Generic sk-/sk_ token triggers generic-sk-token finding."""

    def test_sk_dash_detected(self):
        content = "API_KEY=sk-abcdefghijklmnopqrstuvwxyz12345678\n"
        findings = _scan_content(content)
        self.assertTrue(
            _has_pattern(findings, "generic-sk-token"),
            f"Expected generic-sk-token, got {findings}",
        )

    def test_sk_underscore_detected(self):
        content = "key = 'sk_test_abcdefghijklmnopqrstuvwxyz1234'\n"
        findings = _scan_content(content)
        self.assertTrue(
            _has_pattern(findings, "generic-sk-token"),
            f"Expected generic-sk-token (sk_), got {findings}",
        )

    def test_word_with_sk_suffix_not_flagged(self):
        # "risk", "task", "mask" should NOT trigger (word-boundary guard)
        content = "The risk assessment shows that the task is complex.\n"
        findings = _scan_content(content)
        sk_findings = [f for f in findings if f["pattern"] == "generic-sk-token"]
        self.assertEqual(sk_findings, [], f"Words ending in 'sk' should not trigger, got {sk_findings}")


class TestShannonEntropy(unittest.TestCase):
    """Shannon entropy helper returns correct values."""

    def test_uniform_string(self):
        # Single repeated char has entropy 0
        self.assertAlmostEqual(_mod._shannon_entropy("aaaaaa"), 0.0, places=5)

    def test_binary_string(self):
        # Two equally likely chars → entropy = 1.0 bit/char
        s = "ab" * 8
        self.assertAlmostEqual(_mod._shannon_entropy(s), 1.0, places=5)

    def test_empty_string(self):
        self.assertEqual(_mod._shannon_entropy(""), 0.0)

    def test_high_entropy_hex(self):
        # Random-looking 64-hex string should have entropy > 3.0
        s = "a1b2c3d4e5f60102030405060708091011121314151617181a1b1c1d1e1f2021"
        entropy = _mod._shannon_entropy(s)
        self.assertGreater(entropy, 3.0, f"Expected entropy > 3.0 for high-entropy hex, got {entropy}")


if __name__ == "__main__":
    unittest.main()
