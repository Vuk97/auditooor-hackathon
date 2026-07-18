#!/usr/bin/env python3
"""generate-tools-inventory.py

Scan tools/ and emit docs/TOOLS_INVENTORY.md grouping each tool by purpose
(extracted from first docstring or header comment) with a live-refs count
(how many other files reference the tool name).

Part of the Phase 1 consolidation megaplan.
"""
from __future__ import annotations
import re
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
REPO = TOOLS_DIR.parent

# Purpose keywords → bucket
BUCKETS = [
    ("Mining / Pattern Generation", ["mine-", "to-specs", "to-patterns", "to-dsl",
                                     "extract-patterns", "cluster-corpus",
                                     "digest-", "defihacklabs", "glider-"]),
    ("Compile / Test", ["pattern-compile", "test-detectors", "e2e-smoke",
                         "pattern-dedupe", "pattern-coverage", "gen-detector",
                         "detector-janitor", "detector-tier", "reactivate-graveyard"]),
    ("Parity / Reporting", ["parity-", "finding-stats", "dashboard", "iter-dashboard",
                            "stop-criteria", "coverage-report"]),
    ("Solodit / Corpus", ["solodit-", "boost-classifier", "scrape-diffs",
                          "scrape-outcomes", "scrape-target-history"]),
    ("Scope / Onboarding", ["setup-workspace", "onboard", "fetch-scope",
                             "fetch-targets", "orient-", "scope-review",
                             "env-check", "clone-hexens"]),
    ("Running / Scan / Slither", ["run-slither", "run-engagement", "scan",
                                   "full-audit", "slither-resilient",
                                   "mixed-pragma", "fix-remappings",
                                   "file-slither-bug", "apply-slither"]),
    ("PoC / Fuzzing", ["auto-poc", "gen-composition-fuzz", "gen-invariants",
                        "k2-poc", "invariant-", "poc-cowrite",
                        "concolic-scan", "fork-replay", "fork-snapshot"]),
    ("Triage / Draft / Submit", ["auto-triage", "triage-to-draft",
                                  "submit", "submission", "submissions",
                                  "verify-audit-fixes", "record-triage",
                                  "reframe-same-class", "rejection-"]),
    ("Adversarial / Self-Check", ["adversarial-read", "dupe-risk",
                                   "novel-vector-check", "check-novel",
                                   "check-arithmetic", "cross-workspace-originality",
                                   "originality-grep", "acl-matrix", "attack-"]),
    ("Agent / Dispatch / Flow", ["agent-dispatch", "auto-draft", "dispatch-",
                                  "multi-persona", "meta-review",
                                  "r49-gate", "flow-gate", "loop-gate",
                                  "pre-iter", "post-iter", "pre-submit",
                                  "skill-state", "append-iter", "latest-iter",
                                  "monitor-cron", "ledger-sync",
                                  "engagement-retro", "time-engagement"]),
    ("Intel / Analysis", ["ast-engine", "ast-migrate", "build-citation-graph",
                           "capture-intel", "deploy-state-lookup", "dupe-risk",
                           "economic-hypotheses", "generate-hypotheses",
                           "graph-query", "integration-assumptions",
                           "invariant-proposer", "layer4-baseline",
                           "learn-pattern", "rust-detect", "rust-scan",
                           "storage-layout", "mev-watch",
                           "scan-report-thicken", "classifier-platform",
                           "are-we-smarter", "backfill-tier-registry",
                           "missing-check-catalog", "lang-detect",
                           "phase2_real_code_anchor", "bytecode-hash",
                           "install-weth9-shim", "c3-compute",
                           "archive-workspace-artifacts", "init-rubric-coverage",
                           "hexens-coverage-init", "cold-read",
                           "dispatch-brief", "dispatch-capture",
                           "extract-oos", "extract-pdfs", "gen-predicate-docs",
                           "irdump", "digest-aggregate", "bug-family-atlas",
                           "apply-patterns", "apply-queries", "apply-queries-tightening",
                           "mine-fix-diffs", "mine-to-patterns",
                           "port-glider-query", "submissions-lint",
                           "post-audit-review", "submission-sync"]),
]


def bucket_for(name: str) -> str:
    for label, keys in BUCKETS:
        for k in keys:
            if k in name:
                return label
    return "Uncategorized"


def extract_purpose(path: Path) -> str:
    """First non-shebang / non-blank header line (docstring or comment)."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = [ln.rstrip() for ln in f.readlines()[:40]]
    except Exception:
        return ""
    # Python docstring
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('"""') or s.startswith("'''"):
            quote = s[:3]
            # Single-line docstring
            if len(s) > 3 and s.endswith(quote):
                return s[3:-3].strip()
            # Multi-line: take the first non-blank after opening
            for ln2 in lines[i + 1 :]:
                s2 = ln2.strip()
                if not s2:
                    continue
                if s2.endswith(quote):
                    return s2.rstrip(quote).strip()
                return s2
    # Shell comment block
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#!"):
            continue
        if s.startswith("#"):
            t = s.lstrip("#").strip()
            if t and not t.startswith("shellcheck") and "license" not in t.lower():
                return t
        elif s.startswith("//"):
            return s.lstrip("/").strip()
        else:
            break
    return ""


def ref_count(name: str) -> int:
    """Count files outside tools/{name} itself that mention the name."""
    stem = Path(name).stem
    commands = [
        [
            "rg",
            "-l",
            "--glob", "*.py",
            "--glob", "*.sh",
            "--glob", "*.md",
            "--glob", "Makefile",
            stem,
            ".",
        ],
        [
            "grep",
            "-rl",
            "--include=*.py",
            "--include=*.sh",
            "--include=*.md",
            "--include=Makefile",
            stem,
            ".",
        ],
    ]
    out = ""
    for cmd in commands:
        try:
            out = subprocess.check_output(
                cmd,
                cwd=REPO,
                stderr=subprocess.DEVNULL,
            ).decode("utf-8", errors="replace")
            break
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError:
            return 0
    refs = [
        r for r in out.splitlines()
        if r and f"tools/{name}" not in r and "__pycache__" not in r
    ]
    return len(refs)


def main():
    rows = []
    for p in sorted(TOOLS_DIR.iterdir()):
        if not p.is_file():
            continue
        if p.name.startswith(("_", ".")) and p.name != "_analyzer_common.py":
            continue
        if p.suffix not in (".py", ".sh"):
            continue
        purpose = extract_purpose(p) or "—"
        refs = ref_count(p.name)
        rows.append((bucket_for(p.name), p.name, purpose[:140], refs))

    # Group
    groups: dict[str, list] = {}
    for b, n, p, r in rows:
        groups.setdefault(b, []).append((n, p, r))

    out = []
    out.append("# Tools Inventory")
    out.append("")
    out.append(
        "Auto-generated by `tools/generate-tools-inventory.py`. "
        "Each row shows a tool's purpose (from its header comment) and the number of "
        "other files that reference it — zero refs + unclear purpose = candidate for retirement."
    )
    out.append("")
    out.append(f"**Total tools:** {len(rows)}")
    out.append(f"**Buckets:** {len(groups)}")
    out.append("")

    for bucket in [b for b, _ in BUCKETS] + ["Uncategorized"]:
        items = groups.get(bucket, [])
        if not items:
            continue
        out.append(f"## {bucket} ({len(items)})")
        out.append("")
        out.append("| Tool | Purpose | External refs |")
        out.append("|---|---|---:|")
        for name, purpose, refs in sorted(items):
            safe_purpose = purpose.replace("|", "\\|")
            out.append(f"| `{name}` | {safe_purpose} | {refs} |")
        out.append("")

    while out and not out[-1]:
        out.pop()
    (REPO / "docs" / "TOOLS_INVENTORY.md").write_text("\n".join(out) + "\n")
    print(f"[ok] wrote docs/TOOLS_INVENTORY.md ({len(rows)} tools, {len(groups)} buckets)")


if __name__ == "__main__":
    main()
