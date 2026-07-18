#!/usr/bin/env python3
"""
Wave-3 regression tests for pipeline wrapper authority and engine roots.

Bug A is now the inverse of the stale shell-driver assertions: the public
`audit-pipeline-full` target must stay a thin wrapper over the V2 manifest and
`tools/pipeline-executor.py`, not an embedded shell transcript with direct step
tokens.

Bug B is unchanged: echidna-campaign and medusa-fuzz must use
foundry_engine_root instead of project_root on mixed hardhat+foundry trees.

Each test parses the Makefile statically so the suite stays fast and reflects
the current file state.

r36-rebuttal: funnel-generic-fixes-wave3
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"


def _read_makefile() -> str:
    return MAKEFILE.read_text(encoding="utf-8")


def _extract_target_body(text: str, target: str) -> str:
    """Return the recipe text for a Makefile target.

    Extraction stops at the next top-level target (line starting without
    whitespace that contains a colon, excluding variable assignments and
    .PHONY lines).
    """
    start_marker = f"\n{target}:"
    start = text.find(start_marker)
    if start == -1:
        raise ValueError(f"target '{target}' not found in Makefile")
    # Skip past the line containing '<target>:'
    body_start = text.index("\n", start + 1) + 1
    # Find the next top-level target definition
    pos = body_start
    while pos < len(text):
        nl = text.find("\n", pos)
        if nl == -1:
            break
        line = text[nl + 1 :]
        # A new target: non-whitespace, contains ':', not a variable assignment
        if (
            line
            and not line[0].isspace()
            and ":" in line.split("=")[0]  # colon before any '='
            and not line.startswith(".PHONY")
            and not line.startswith("#")
        ):
            return text[body_start : nl + 1]
        pos = nl + 1
    return text[body_start:]


def _extract_audit_deep_solidity_body(text: str) -> str:
    """Extract the shell body of the audit-deep-solidity target."""
    start_marker = "\naudit-deep-solidity:"
    start = text.find(start_marker)
    if start == -1:
        # Try alternate (no leading newline at very start of file)
        start = text.find("audit-deep-solidity:")
    body_start = text.index("\n", start) + 1
    # Stop at the next target definition at column 0
    pos = body_start
    while pos < len(text):
        nl = text.find("\n", pos)
        if nl == -1:
            break
        line_start = nl + 1
        rest = text[line_start:]
        if (
            rest
            and not rest[0].isspace()
            and ":" in rest.split("=")[0]
            and not rest.startswith(".PHONY")
            and not rest.startswith("#")
        ):
            return text[body_start : line_start]
        pos = nl + 1
    return text[body_start:]


# ---------------------------------------------------------------------------
# Bug A: public audit-pipeline-full authority belongs to manifest + executor
# ---------------------------------------------------------------------------


class TestAuditPipelineFullPublicDelegation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")
        cls._text = _read_makefile()
        cls._public = _extract_target_body(cls._text, "audit-pipeline-full")

    def test_public_target_uses_manifest_and_executor(self) -> None:
        self.assertIn("pipeline-manifest-validate.py", self._public)
        self.assertIn("tools/readme_runbook_steps.json", self._public)
        self.assertIn("pipeline-executor.py", self._public)
        self.assertIn("run-all", self._public)

    def test_public_target_stays_thin_and_nonlegacy(self) -> None:
        self.assertNotIn("_audit-pipeline-full", self._public)
        self.assertNotIn("strict-pipeline-run.py", self._public)
        self.assertNotIn("chain-synth", self._public)
        self.assertNotIn("prove-top-leads", self._public)

    def test_drive_consent_is_a_hard_prerequisite(self) -> None:
        self.assertIn("an affirmative LLM hunt or network consent value is required", self._public)
        self.assertIn("false/0/empty cannot authorize", self._public)
        self.assertIn("1:*|true:*|yes:*|*:1|*:true|*:yes", self._public)
        self.assertIn("exit 2", self._public)

    def test_runtime_modes_are_forwarded_as_environment(self) -> None:
        for name in (
            "SOURCE_ONLY",
            "GITHUB_ONLY",
            "AUDITOOOR_LLM_HUNT",
            "AUDITOOOR_LLM_NETWORK_CONSENT",
            "PIPELINE_FORCE",
            "PIPELINE_STRICT",
        ):
            self.assertIn(name, self._public)


# ---------------------------------------------------------------------------
# Bug B: echidna-campaign and medusa-fuzz must use foundry_engine_root
#        (the same root halmos uses) not project_root
# ---------------------------------------------------------------------------


class TestEchidnaMedusaUsesFoundryEngineRoot(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not MAKEFILE.is_file():
            raise unittest.SkipTest(f"{MAKEFILE} not found")
        cls._text = _read_makefile()
        cls._body = _extract_audit_deep_solidity_body(cls._text)

    def _engine_invocation_line(self, engine_script: str) -> str:
        """Return the set -- run_in_project ... line for a given engine script."""
        for line in self._body.splitlines():
            if f"tools/{engine_script}" in line and "run_in_project" in line:
                return line.strip()
        return ""

    def test_halmos_uses_foundry_engine_root(self) -> None:
        """halmos-runner.sh must run in foundry_engine_root (baseline check)."""
        line = self._engine_invocation_line("halmos-runner.sh")
        self.assertIn(
            "foundry_engine_root",
            line,
            "halmos-runner.sh invocation must use foundry_engine_root (regression guard)",
        )
        self.assertNotIn(
            '"$$project_root"',
            line,
            "halmos-runner.sh must not use project_root (foundry_engine_root is the correct variable)",
        )

    def test_echidna_uses_foundry_engine_root_not_project_root(self) -> None:
        """echidna-campaign.sh must run in foundry_engine_root, not project_root.

        Bug: echidna was invoked with project_root (= first_hardhat_root, e.g.
        src/pipeline) which may lack a foundry.toml.  crytic-compile falls back to
        'npx hardhat' -> fails with HHE22 on Foundry-only sub-projects.
        Fix: use foundry_engine_root (same as halmos) so echidna finds foundry.toml.
        """
        line = self._engine_invocation_line("echidna-campaign.sh")
        self.assertTrue(
            line,
            "echidna-campaign.sh invocation line not found in audit-deep-solidity body",
        )
        self.assertIn(
            "foundry_engine_root",
            line,
            f"echidna-campaign.sh must use foundry_engine_root, not project_root. "
            f"Found: {line!r}",
        )
        self.assertNotIn(
            '"$$project_root"',
            line,
            f"echidna-campaign.sh still uses project_root; must be changed to "
            f"foundry_engine_root to match halmos. Found: {line!r}",
        )

    def test_medusa_uses_foundry_engine_root_not_project_root(self) -> None:
        """medusa-fuzz.sh must run in foundry_engine_root, not project_root.

        Same root cause as echidna: medusa also runs crytic-compile which resolves
        the compilation backend from the working directory.  If the cwd is a
        Hardhat project root lacking foundry.toml, medusa/crytic-compile use npx
        hardhat -> HHE22.  Fix: use foundry_engine_root.
        """
        line = self._engine_invocation_line("medusa-fuzz.sh")
        self.assertTrue(
            line,
            "medusa-fuzz.sh invocation line not found in audit-deep-solidity body",
        )
        self.assertIn(
            "foundry_engine_root",
            line,
            f"medusa-fuzz.sh must use foundry_engine_root, not project_root. "
            f"Found: {line!r}",
        )
        self.assertNotIn(
            '"$$project_root"',
            line,
            f"medusa-fuzz.sh still uses project_root; must be changed to "
            f"foundry_engine_root to match halmos. Found: {line!r}",
        )

    def test_halmos_echidna_medusa_use_same_root(self) -> None:
        """halmos, echidna, and medusa must all use the same root variable.

        This guards against future partial fixes that correct one engine but
        not the others.
        """
        halmos_line = self._engine_invocation_line("halmos-runner.sh")
        echidna_line = self._engine_invocation_line("echidna-campaign.sh")
        medusa_line = self._engine_invocation_line("medusa-fuzz.sh")

        for name, line in [
            ("halmos-runner.sh", halmos_line),
            ("echidna-campaign.sh", echidna_line),
            ("medusa-fuzz.sh", medusa_line),
        ]:
            self.assertIn(
                "foundry_engine_root",
                line,
                f"{name} must use foundry_engine_root; found: {line!r}",
            )

    def test_echidna_config_lookup_includes_foundry_engine_root(self) -> None:
        """echidna_config must be looked up in foundry_engine_root, not only project_root.

        When project_root is a Hardhat tree and foundry_engine_root is the real
        Foundry project, echidna.yaml lives in foundry_engine_root.  Looking only
        in project_root means the config is not found and echidna runs unconfigured.
        """
        # Find the echidna_config assignment block
        config_block_start = self._body.find('echidna_config=""')
        self.assertGreater(config_block_start, -1, "echidna_config assignment block not found")
        # Extract from that point until we see echidna_contract="" (end of config block)
        config_end = self._body.find('echidna_contract=""', config_block_start)
        if config_end == -1:
            config_block = self._body[config_block_start : config_block_start + 400]
        else:
            config_block = self._body[config_block_start:config_end]
        self.assertIn(
            "foundry_engine_root",
            config_block,
            "echidna_config lookup must check foundry_engine_root (not only project_root); "
            "on mixed hardhat+foundry workspaces the config lives in the foundry sub-project",
        )


if __name__ == "__main__":
    unittest.main()
