"""G-15 (enforcement-gap 2026-07-03): upgradeable storage-collision SURFACE detector.

An upgradeable contract can reach audit-complete with NO gate ever running a
storage-layout comparison, so a collision from a removed/shrunk/reordered slot is
never surfaced (tools/storage-layout.py --compare-dir was orphaned). This detector
makes the class VISIBLE: it FIRES when the workspace contains an upgradeable / proxy
target (UUPS / Transparent / Initializable / delegatecall-proxy) to which a
storage-layout collision is APPLICABLE, so the `storage-collision-upgradeable`
mechanism cell becomes an OPEN obligation the operator must DISPOSITION (run
storage-layout --compare-dir vs the prior version, source-cited rule-out, or finding).
A workspace with NO upgradeable target -> 0 findings (mechanism enumerated-clean).
Low-FP: keyed on real upgradeability tokens.

scan_root(root) -> {"schema","mechanism","impact","findings":[...]} (mechanism-scan contract).
"""
import os
import re

SCHEMA = "auditooor.mechanism_scan.v1"
MECHANISM = "storage-collision-upgradeable"
IMPACT = "permanent-freeze"

_UPGRADEABLE_RE = re.compile(
    r"\bUUPSUpgradeable\b|\bInitializable\b|\bTransparentUpgradeableProxy\b|"
    r"\bERC1967(?:Proxy|Upgrade)\b|\b_authorizeUpgrade\b|\bupgradeToAndCall\b|"
    r"\bBeaconProxy\b|\b__gap\b|\binitializer\b\s*\{|\breinitializer\s*\(")
# A captured storage-layout snapshot / compare artifact = evidence the check ran.
_LAYOUT_ARTIFACT = re.compile(r"storage[_-]?layout", re.IGNORECASE)


def _sol_files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in
                  ("node_modules", "lib", "out", "artifacts", "cache", "vendor")
                  and not d.startswith(".")]
        for fn in fns:
            if fn.endswith(".sol") and not fn.endswith(".t.sol"):
                yield os.path.join(dp, fn)


def scan_root(root: str) -> dict:
    findings = []
    for p in _sol_files(root):
        try:
            t = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if not _UPGRADEABLE_RE.search(t):
            continue
        rel = os.path.relpath(p, root) if os.path.isdir(root) else p
        findings.append({
            "schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT,
            "file": rel, "line": 1,
            "detail": ("upgradeable/proxy target present; storage-collision mechanism "
                       "APPLICABLE - disposition required (run tools/storage-layout.py "
                       "--compare-dir <prior-version-src>, source-cited rule-out, or finding). "
                       "A downward slot-shift (removed/shrunk slot) silently collides."),
        })
    findings.sort(key=lambda f: f["file"])
    return {"schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT, "findings": findings}
