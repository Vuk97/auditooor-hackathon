"""Regression: SCOPE.md metadata header bullets (Asset class:, Platform:,
Program URL:, Source, Audit pin:, Local checkout:) must NOT be parsed as
in-scope clusters. They inflated the cluster count and made cluster-coverage /
dark-families un-passable on any workspace with a SCOPE.md metadata header.
Generic-fix anchor: monero-oxide showed 15 clusters (9 real crates + 6 metadata)
-> 6 permanent DARK rows.
"""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("hcc_meta", _T)
    m = importlib.util.module_from_spec(spec)
    sys.modules["hcc_meta"] = m  # py3.14 dataclass needs module registered
    spec.loader.exec_module(m)
    return m


HCC = _load()

SCOPE = """# thing - audit scope (Immunefi bug bounty)

- Asset class: Blockchain/DLT
- Platform: Immunefi. Max bounty $100,000
- Program URL: https://immunefi.com/bug-bounty/thing/
- Source (in scope): https://github.com/x/thing/tree/main
- Audit pin: deadbeef
- Local checkout: src/thing/

## In-scope crates (the crypto surface)
- thing/ed25519          - curve / scalar arithmetic
- thing/ringct/clsag     - CLSAG ring signatures
- thing/wallet(+address) - wallet + FROST
"""


class TestMetadataFilter(unittest.TestCase):
    def test_metadata_bullets_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
            clusters = HCC._parse_scope_clusters(ws)
            joined = " ".join(clusters)
            # real crates present
            self.assertTrue(any("ed25519" in c for c in clusters))
            self.assertTrue(any("clsag" in c for c in clusters))
            self.assertTrue(any("wallet" in c for c in clusters))
            # metadata excluded
            for bad in ("asset class", "platform", "program url", "audit pin",
                        "local checkout"):
                self.assertNotIn(bad, joined, f"metadata leaked: {bad}")
            self.assertNotIn("https://", joined)

    def test_helper_classifies(self):
        self.assertTrue(HCC._is_scope_metadata_bullet("Asset class: Blockchain/DLT"))
        self.assertTrue(HCC._is_scope_metadata_bullet("Audit pin: deadbeef"))
        self.assertTrue(HCC._is_scope_metadata_bullet("Source"))
        self.assertTrue(HCC._is_scope_metadata_bullet("https://example.com"))
        self.assertFalse(HCC._is_scope_metadata_bullet("thing/ringct/clsag"))
        self.assertFalse(HCC._is_scope_metadata_bullet("ed25519"))

    def test_provenance_version_bullet_excluded(self):
        # Regression: a "Deployed/audited version: tag `vX`" provenance bullet
        # under a "## Codebase (in-scope SOURCE)" heading evaded the filter (the
        # value is stripped at ':' before the check, and the "/" in the label
        # bailed the Label:value branch), becoming a phantom cluster with no
        # possible sidecar -> un-passable cluster-coverage on SSV. Both copies
        # (this hcc fallback + capability-coverage-matrix-build.py) must drop it.
        for bad in (
            "deployed/audited version",
            "Deployed/audited version: tag mainnet-v2.0.0",
            "audited version",
            "Pinned commit: deadbeefdeadbeef",
        ):
            self.assertTrue(
                HCC._is_scope_metadata_bullet(bad),
                f"provenance bullet not filtered: {bad!r}",
            )
        # real code-module clusters with no provenance word survive
        for good in ("operatorlib", "clusterlib", "ssvclusters", "types"):
            self.assertFalse(
                HCC._is_scope_metadata_bullet(good),
                f"real cluster wrongly filtered: {good!r}",
            )


if __name__ == "__main__":
    unittest.main()
