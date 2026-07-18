from __future__ import annotations

import importlib.util
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_custom", RUN_CUSTOM)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")


class RunCustomGraveyardLoaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()

    def test_load_detectors_imports_nested_graveyard_detector_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detectors_dir = Path(tmp)
            _write(detectors_dir / "_template_utils.py", "SENTINEL = 1")
            _write(
                detectors_dir / "wave_graveyard" / "wave14_broken" / "graveyard_probe.py",
                """
                from _template_utils import SENTINEL

                class GraveyardProbe(object):
                    ARGUMENT = "graveyard-probe"
                """,
            )

            with mock.patch.object(self.mod, "_import_abstract_detector", return_value=object), \
                 mock.patch.object(self.mod, "_load_tier_registry", return_value={}):
                without_graveyard = self.mod.load_detectors(
                    detectors_dir,
                    include_graveyard=False,
                    tier_filter="ALL",
                )
                with_graveyard = self.mod.load_detectors(
                    detectors_dir,
                    include_graveyard=True,
                    tier_filter="ALL",
                )

        self.assertEqual(without_graveyard, [])
        self.assertEqual([det.ARGUMENT for det in with_graveyard], ["graveyard-probe"])

    def test_load_detectors_imports_syntax_broken_graveyard_detector_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detectors_dir = Path(tmp)
            _write(
                detectors_dir / "wave_graveyard" / "syntax_broken" / "syntax_probe.py",
                """
                class SyntaxProbe(object):
                    ARGUMENT = "syntax-probe"
                """,
            )

            with mock.patch.object(self.mod, "_import_abstract_detector", return_value=object), \
                 mock.patch.object(self.mod, "_load_tier_registry", return_value={}):
                loaded = self.mod.load_detectors(
                    detectors_dir,
                    include_graveyard=True,
                    tier_filter="ALL",
                )

        self.assertEqual([det.ARGUMENT for det in loaded], ["syntax-probe"])

    def test_name_filter_prefers_matching_graveyard_file_without_importing_broken_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detectors_dir = Path(tmp)
            _write(
                detectors_dir / "wave_graveyard" / "syntax_broken" / "syntax_probe.py",
                """
                class SyntaxProbe(object):
                    ARGUMENT = "syntax-probe"
                """,
            )
            _write(
                detectors_dir / "wave_graveyard" / "syntax_broken" / "broken_neighbor.py",
                """
                raise RuntimeError("unrelated detector should not be imported")
                """,
            )

            with mock.patch.object(self.mod, "_import_abstract_detector", return_value=object), \
                 mock.patch.object(self.mod, "_load_tier_registry", return_value={}), \
                 mock.patch("builtins.print") as printed:
                loaded = self.mod.load_detectors(
                    detectors_dir,
                    name_filter="syntax-probe",
                    include_graveyard=True,
                    tier_filter="ALL",
                )

        self.assertEqual([det.ARGUMENT for det in loaded], ["syntax-probe"])
        self.assertEqual(printed.call_args_list, [])

    def test_batch_main_forwards_include_graveyard_flag(self) -> None:
        captured: dict[str, object] = {}

        class DetectorStub:
            ARGUMENT = "graveyard-probe"

        class FakeSlither:
            def __init__(self, target: str):
                self.target = target
                self.compilation_units = []

        def fake_load_detectors(detectors_dir: Path, **kwargs):
            captured["include_graveyard"] = kwargs.get("include_graveyard")
            captured["tier_filter"] = kwargs.get("tier_filter")
            return [DetectorStub]

        with tempfile.TemporaryDirectory() as tmp:
            fixture_dir = Path(tmp)
            with mock.patch.object(self.mod, "load_detectors", side_effect=fake_load_detectors), \
                 mock.patch.object(self.mod, "_import_slither", return_value=FakeSlither):
                self.mod.batch_main([str(fixture_dir), "--include-graveyard", "--tier=ALL"])

        self.assertTrue(captured["include_graveyard"])
        self.assertEqual(captured["tier_filter"], "ALL")

    def test_tier_all_includes_paper_detectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detectors_dir = Path(tmp)
            _write(detectors_dir / "_tier_registry.yaml", """
                tiers:
                  paper-probe:
                    tier: PAPER
            """)
            _write(
                detectors_dir / "wave17" / "paper_probe.py",
                """
                class PaperProbe(object):
                    ARGUMENT = "paper-probe"
                """,
            )

            with mock.patch.object(self.mod, "_import_abstract_detector", return_value=object):
                loaded = self.mod.load_detectors(detectors_dir, tier_filter="ALL")

        self.assertEqual([det.ARGUMENT for det in loaded], ["paper-probe"])

    def test_tier_registry_maps_explicit_argument_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detectors_dir = Path(tmp)
            _write(detectors_dir / "_tier_registry.yaml", """
                tiers:
                  alias_probe:
                    tier: S
                    argument: alias-probe
            """)
            _write(
                detectors_dir / "wave17" / "alias_probe.py",
                """
                class AliasProbe(object):
                    ARGUMENT = "alias-probe"
                """,
            )

            with mock.patch.object(self.mod, "_import_abstract_detector", return_value=object):
                loaded = self.mod.load_detectors(detectors_dir)

        self.assertEqual([det.ARGUMENT for det in loaded], ["alias-probe"])

    def test_tier_registry_prefers_canonical_argument_row_over_later_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detectors_dir = Path(tmp)
            _write(detectors_dir / "_tier_registry.yaml", """
                tiers:
                  conflict-probe:
                    tier: S
                    argument: conflict-probe
                  conflict_probe:
                    tier: D
                    argument: conflict-probe
            """)

            tier_map = self.mod._load_tier_registry(detectors_dir)

        self.assertEqual(tier_map["conflict-probe"], "S")
        self.assertEqual(tier_map["conflict_probe"], "D")

    def test_tier_registry_keeps_first_alias_when_no_canonical_row_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detectors_dir = Path(tmp)
            _write(detectors_dir / "_tier_registry.yaml", """
                tiers:
                  conflict_probe_legacy:
                    tier: E
                    argument: conflict-probe
                  conflict_probe_other_alias:
                    tier: D
                    argument: conflict-probe
            """)

            tier_map = self.mod._load_tier_registry(detectors_dir)

        self.assertEqual(tier_map["conflict-probe"], "E")
        self.assertEqual(tier_map["conflict_probe_legacy"], "E")
        self.assertEqual(tier_map["conflict_probe_other_alias"], "D")

    def test_fixture_smoke_mode_disables_slither_cache_by_default(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "AUDITOOOR_FIXTURE_SMOKE_MODE": "1",
                "AUDITOOOR_SLITHER_NOCACHE": "",
                "AUDITOOOR_SLITHER_CACHE_IN_FIXTURE_SMOKE": "",
            },
            clear=False,
        ):
            disabled, reason = self.mod._slither_cache_disabled()

        self.assertTrue(disabled)
        self.assertEqual(reason, "fixture-smoke-mode")

    def test_fixture_smoke_mode_can_opt_back_into_slither_cache(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "AUDITOOOR_FIXTURE_SMOKE_MODE": "1",
                "AUDITOOOR_SLITHER_NOCACHE": "",
                "AUDITOOOR_SLITHER_CACHE_IN_FIXTURE_SMOKE": "1",
            },
            clear=False,
        ):
            disabled, reason = self.mod._slither_cache_disabled()

        self.assertFalse(disabled)
        self.assertEqual(reason, "cache-enabled")


if __name__ == "__main__":
    unittest.main()
