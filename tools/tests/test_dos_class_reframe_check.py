"""Unit tests for Rule 35 DoS-class-reframe preflight (general, any bounty)."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "dos_class_reframe_check",
    ROOT / "tools" / "dos-class-reframe-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace(severity_md: str | None = None) -> Path:
    root = Path(tempfile.mkdtemp(prefix="r35_dosreframe_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    if severity_md is not None:
        (root / "SEVERITY.md").write_text(severity_md, encoding="utf-8")
    return root


def _draft(
    *,
    severity: str = "High",
    impact: str = "Generic denial of service",
    body: str = "",
) -> str:
    return (
        f"Severity: {severity}\n"
        f"Selected impact: {impact}\n\n"
        f"{body}\n"
    )


def _write_case(
    body: str,
    *,
    filename: str = "draft-HIGH.md",
    severity_md: str | None = None,
) -> Path:
    root = _workspace(severity_md)
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _run(draft: Path, *, strict: bool = False, severity: str | None = None) -> tuple[int, dict]:
    return mod.run(draft, strict=strict, severity_override=severity)


class DosClassReframeScopeTests(unittest.TestCase):
    def test_medium_severity_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(severity="Medium", body="This is a denial of service attack."))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_low_severity_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(severity="Low", body="Resource exhaustion via spam."))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_raises_into_scope(self) -> None:
        draft = _write_case(
            _draft(severity="Medium", body="A pure denial of service with no fund impact."),
            filename="draft.md",
        )
        rc, payload = _run(draft, strict=True, severity="High")
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_source"], "cli")
        self.assertEqual(payload["verdict"], "fail-dos-class-not-reframed")

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class DosClassReframePassTests(unittest.TestCase):
    def test_not_dos_class_passes(self) -> None:
        draft = _write_case(
            _draft(impact="Direct theft of user funds", body="Attacker transfers victim funds out of the vault.")
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-dos-class")

    def test_dos_reframed_to_nondos_passes(self) -> None:
        draft = _write_case(
            _draft(
                impact="Liveness degradation that enables fund loss",
                body=(
                    "The denial of service window is the trigger, but the proven impact is "
                    "direct loss of funds: the insurance fund is drained while settlement is stalled."
                ),
            )
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-dos-reframed-to-nondos")

    def test_dos_reframed_to_temporary_freeze_passes(self) -> None:
        # NUVA 2026-06-30: a halt/DoS that LOCKS funds reframes to temporary/permanent
        # freezing of funds - a real Immunefi row that R35 was missing from its allow-list.
        # Draft reads as DoS-class (unbounded gas / denial of service) then reframes.
        draft = _write_case(
            _draft(
                impact="Unbounded gas consumption denial of service on withdrawals",
                body=("The denial of service is the trigger, but the proven impact is "
                      "temporary freezing of funds: user funds are frozen until the chain restarts."),
            )
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-dos-reframed-to-nondos")

    def test_dos_reframed_to_governance_manipulation_passes(self) -> None:
        draft = _write_case(
            _draft(
                impact="Block stuffing denial of service",
                body=("The denial of service / block-stuffing window enables governance vote "
                      "manipulation: the voting result deviates from the intended outcome."),
            )
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-dos-reframed-to-nondos")

    def test_dos_in_scope_via_severity_md_passes(self) -> None:
        severity_md = (
            "# Severity rubric\n"
            "- High: RPC API crash affecting projects with >= 25% market cap\n"
            "- Critical: Direct loss of funds\n"
        )
        draft = _write_case(
            _draft(impact="RPC API crash", body="A crafted request triggers a denial of service on the RPC node."),
            severity_md=severity_md,
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-dos-in-scope")
        self.assertIn("severity_md", payload)

    def test_dos_in_scope_validator_halt_row(self) -> None:
        severity_md = (
            "# Rubric\n"
            "- High: validator halt / chain halt affecting consensus\n"
        )
        draft = _write_case(
            _draft(impact="Generic denial of service", body="Attacker causes liveness failure."),
            severity_md=severity_md,
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-dos-in-scope")

    def test_visible_rebuttal_line_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "This is a denial of service.\n"
                    "r35-rebuttal: program operator confirmed DoS scope via direct email exception\n"
                )
            )
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_html_comment_rebuttal_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Resource exhaustion attack.\n"
                    "<!-- r35-rebuttal: bounded source-backed exception, operator approved -->\n"
                )
            )
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_overlong_rebuttal_is_ignored(self) -> None:
        draft = _write_case(
            _draft(body=f"This is a denial of service.\n<!-- r35-rebuttal: {'x' * 220} -->\n")
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-dos-class-not-reframed")


class DosClassReframeFailTests(unittest.TestCase):
    def test_generic_dos_only_fails(self) -> None:
        draft = _write_case(
            _draft(
                impact="Generic denial of service",
                body="The attacker floods the mempool with spam; no fund impact is demonstrated.",
            )
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-dos-class-not-reframed")

    def test_fail_verdict_is_rc0_without_strict(self) -> None:
        draft = _write_case(
            _draft(impact="Rate-limit pressure", body="Sustained rate limit exhaustion, gas griefing only.")
        )
        rc, payload = _run(draft, strict=False)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "fail-dos-class-not-reframed")

    def test_env_dos_keyword_extension_catches_custom_term(self) -> None:
        draft = _write_case(
            _draft(impact="Throughput collapse", body="The node suffers a throughput collapse under load.")
        )
        old_value = os.environ.get("AUDITOOOR_R35_DOS_KEYWORDS")
        os.environ["AUDITOOOR_R35_DOS_KEYWORDS"] = "throughput collapse"
        try:
            rc, payload = _run(draft, strict=True)
        finally:
            if old_value is None:
                os.environ.pop("AUDITOOOR_R35_DOS_KEYWORDS", None)
            else:
                os.environ["AUDITOOOR_R35_DOS_KEYWORDS"] = old_value
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-dos-class-not-reframed")

    def test_env_nondos_keyword_extension_reframes(self) -> None:
        draft = _write_case(
            _draft(
                impact="Generic denial of service",
                body="The denial of service window enables a custom reserve-pool drain.",
            )
        )
        old_value = os.environ.get("AUDITOOOR_R35_NONDOS_IMPACT_KEYWORDS")
        os.environ["AUDITOOOR_R35_NONDOS_IMPACT_KEYWORDS"] = "reserve-pool drain"
        try:
            rc, payload = _run(draft, strict=True)
        finally:
            if old_value is None:
                os.environ.pop("AUDITOOOR_R35_NONDOS_IMPACT_KEYWORDS", None)
            else:
                os.environ["AUDITOOOR_R35_NONDOS_IMPACT_KEYWORDS"] = old_value
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-dos-reframed-to-nondos")


if __name__ == "__main__":
    unittest.main(verbosity=2)
