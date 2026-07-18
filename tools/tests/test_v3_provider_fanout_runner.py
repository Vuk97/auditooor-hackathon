"""Regression tests for tools/v3-provider-fanout-runner.py.

Wave-12 Priority 2 audit (judgment-bundle gate). The runner's
``_make_child_env`` is the load-bearing wiring that forwards a queue row's
claimed severity and the manifest's local candidate-judgment bundle path
into the two env-var fallbacks that ``dispatch-preflight.py`` reads:

  - ``AUDITOOOR_DISPATCH_SEVERITY``     (severity hint)
  - ``AUDITOOOR_LOCAL_JUDGMENT_BUNDLE`` (local judgment bundle path)

Without this forwarding, a High/Critical fanout row would reach the
provider dispatcher without the local candidate-judgment gate ever
firing.  Before this file there was zero test coverage on the runner, so
a refactor could silently drop the forwarding and no test would catch
the regression.  These tests pin the wiring contract:

* High/Critical rows set ``AUDITOOOR_DISPATCH_SEVERITY`` so the gate
  fires in the child dispatch-preflight process.
* When the manifest carries ``local_judgment_bundle_path`` it is
  forwarded as ``AUDITOOOR_LOCAL_JUDGMENT_BUNDLE``.
* When the manifest has NO bundle path, the env var is left UNSET — and
  because dispatch-preflight refuses High/Critical dispatch with a
  severity but no bundle, the gate stays fail-closed (it does not get
  silently satisfied by an empty value).
* Medium/Low/empty severities still forward whatever value is present
  (the gate itself decides those do not require a bundle).
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "tools" / "v3-provider-fanout-runner.py"
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_runner():
    """Load tools/v3-provider-fanout-runner.py as a module (hyphenated name).

    The module must be registered in ``sys.modules`` BEFORE ``exec_module``
    because it defines an ``@dataclass`` whose processing looks the owning
    module up in ``sys.modules``.
    """
    spec = importlib.util.spec_from_file_location(
        "v3_provider_fanout_runner", RUNNER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load v3-provider-fanout-runner.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["v3_provider_fanout_runner"] = module
    spec.loader.exec_module(module)
    return module


RUNNER = _load_runner()


class MakeChildEnvJudgmentBundleWiringTests(unittest.TestCase):
    """The judgment-bundle gate env-var forwarding must not regress."""

    def _row(self, **overrides):
        row = {
            "provider": "kimi",
            "task_id": "lane-001",
        }
        row.update(overrides)
        return row

    def test_high_severity_forwards_dispatch_severity_env(self) -> None:
        env, summary = RUNNER._make_child_env(
            base_env={},
            manifest={"campaign_id": "c", "workspace": "/ws"},
            row=self._row(claimed_severity="High"),
            live_consent=False,
        )
        self.assertEqual(env.get("AUDITOOOR_DISPATCH_SEVERITY"), "High")
        self.assertEqual(summary.get("AUDITOOOR_DISPATCH_SEVERITY"), "High")

    def test_critical_likely_severity_forwarded_when_claimed_absent(self) -> None:
        env, _ = RUNNER._make_child_env(
            base_env={},
            manifest={},
            row=self._row(likely_severity="Critical"),
            live_consent=False,
        )
        self.assertEqual(env.get("AUDITOOOR_DISPATCH_SEVERITY"), "Critical")

    def test_manifest_bundle_path_forwarded_as_env(self) -> None:
        env, summary = RUNNER._make_child_env(
            base_env={},
            manifest={
                "local_judgment_bundle_path": "/ws/.auditooor/judgment.json"
            },
            row=self._row(claimed_severity="High"),
            live_consent=False,
        )
        self.assertEqual(
            env.get("AUDITOOOR_LOCAL_JUDGMENT_BUNDLE"),
            "/ws/.auditooor/judgment.json",
        )
        self.assertEqual(
            summary.get("AUDITOOOR_LOCAL_JUDGMENT_BUNDLE"),
            "/ws/.auditooor/judgment.json",
        )

    def test_high_severity_without_manifest_bundle_leaves_env_unset(self) -> None:
        """Fail-closed: High row + no bundle path => env var NOT set.

        dispatch-preflight then refuses (severity requires bundle, none
        present).  The empty value must NOT be injected, because an empty
        string would still be falsy in dispatch-preflight and trigger the
        same refusal -- but pinning 'unset' makes the contract explicit.
        """
        env, _ = RUNNER._make_child_env(
            base_env={},
            manifest={},
            row=self._row(claimed_severity="Critical"),
            live_consent=False,
        )
        self.assertEqual(env.get("AUDITOOOR_DISPATCH_SEVERITY"), "Critical")
        self.assertNotIn("AUDITOOOR_LOCAL_JUDGMENT_BUNDLE", env)

    def test_empty_severity_does_not_set_dispatch_severity_env(self) -> None:
        env, _ = RUNNER._make_child_env(
            base_env={},
            manifest={},
            row=self._row(),  # no severity at all
            live_consent=False,
        )
        self.assertNotIn("AUDITOOOR_DISPATCH_SEVERITY", env)

    def test_base_env_is_not_mutated(self) -> None:
        base = {"EXISTING": "1"}
        env, _ = RUNNER._make_child_env(
            base_env=base,
            manifest={"local_judgment_bundle_path": "/ws/j.json"},
            row=self._row(claimed_severity="High"),
            live_consent=False,
        )
        self.assertNotIn("AUDITOOOR_DISPATCH_SEVERITY", base)
        self.assertNotIn("AUDITOOOR_LOCAL_JUDGMENT_BUNDLE", base)
        self.assertEqual(env.get("EXISTING"), "1")


class BuildCommandRoutesThroughDispatchPreflightTests(unittest.TestCase):
    """No bypass path: every queue row is executed via dispatch-preflight."""

    def test_command_invokes_dispatch_preflight(self) -> None:
        row = {
            "provider": "kimi",
            "task_id": "lane-001",
            "template": "source-extract",
            "prompt_path": "/ws/prompt.md",
        }
        cmd = RUNNER._build_command(
            row,
            workspace=pathlib.Path("/ws"),
            dispatch_preflight=pathlib.Path("/tools/dispatch-preflight.py"),
            dry_run=True,
            mock_dispatcher=None,
            timeout_override=None,
            llm_audit_dir=pathlib.Path("/ws/audit"),
            output_path=pathlib.Path("/ws/out.txt"),
        )
        self.assertIn("/tools/dispatch-preflight.py", cmd)
        # The runner never shells out to llm-dispatch.py directly.
        self.assertFalse(
            any("llm-dispatch.py" in part for part in cmd),
            "fanout runner must not bypass dispatch-preflight",
        )


if __name__ == "__main__":
    unittest.main()
