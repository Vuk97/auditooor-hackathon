#!/usr/bin/env python3
"""spark-cargo-fork-status — Spark FROST signer Cargo fork-ancestry wrapper.

Thin wrapper around tools/cargo-fork-ancestry-check.py scoped to the Spark
FROST/signer workspace.  Adds a Spark-specific classification pass that flags
diverged dependencies belonging to known crypto-primitive / RPC / DB crate
families (per L28-E upstream-fork-divergence discipline).

Usage:
    python3 tools/spark-cargo-fork-status.py [--workspace PATH]
    python3 tools/spark-cargo-fork-status.py [--json]
    python3 tools/spark-cargo-fork-status.py [--strict]
    python3 tools/spark-cargo-fork-status.py [--audit-pin SHA]

Exit codes:
    0 = no diverged git deps (or advisory divergence without --strict)
    1 = error (workspace missing, inner tool error)
    2 = diverged deps found when --strict is set

Environment:
    CARGO_FORK_ANCESTRY_OFFLINE=1  — passed through to inner tool (testing)

Default workspace: ~/audits/spark/external/spark/signer
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import subprocess
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WORKSPACE = pathlib.Path("~/audits/spark/external/spark/signer").expanduser()

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
INNER_TOOL = REPO_ROOT / "tools" / "cargo-fork-ancestry-check.py"

# Crypto-primitive and RPC/DB crate name substrings (case-insensitive).
# A diverged dep whose name contains any of these is flagged **candidate**.
# List mirrors the canonical set defined in the C5-iter8 task spec.
CRYPTO_CLASS_SUBSTRINGS = [
    "frost",
    "secp256k1",
    "bitcoin",
    "bdk",
    "lightning",
    "bls",
    "schnorr",
    "bip340",
    "ed25519",
    "ristretto",
    "sha2",
    "hmac",
    "pbkdf2",
    "argon2",
    "tonic",
    "prost",
    "grpc",
    "sqlx",
    "pgx",
    "tokio",
    "hyper",
    "reqwest",
    "serde",
    "protobuf",
    "ent",
]


# ---------------------------------------------------------------------------
# Classifier (pure Python — importable for unit tests)
# ---------------------------------------------------------------------------

def is_crypto_class(crate_name: str) -> bool:
    """Return True if crate_name matches any crypto-class substring (case-insensitive)."""
    lower = crate_name.lower()
    return any(sub in lower for sub in CRYPTO_CLASS_SUBSTRINGS)


def classify_diverged_deps(deps: list[dict]) -> list[dict]:
    """Annotate each dep dict with a 'candidate' bool based on crypto-class match."""
    out = []
    for dep in deps:
        annotated = dict(dep)
        annotated["candidate"] = is_crypto_class(dep.get("name", ""))
        out.append(annotated)
    return out


# ---------------------------------------------------------------------------
# Markdown rendering helpers
# ---------------------------------------------------------------------------

def _summary_table(
    total: int,
    git_sourced: int,
    diverged: int,
    crypto_diverged: int,
) -> str:
    lines = [
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total deps | {total} |",
        f"| Git-sourced deps | {git_sourced} |",
        f"| Diverged deps | {diverged} |",
        f"| Crypto-class diverged | {crypto_diverged} |",
    ]
    return "\n".join(lines)


def _render_classified_markdown(classified: list[dict]) -> str:
    """Render the Spark-specific classification section in markdown."""
    if not classified:
        return "_No git-sourced diverged dependencies detected._\n"
    lines = []
    for dep in classified:
        name = dep.get("name", "unknown")
        divergence = dep.get("divergence", "unknown")
        url = dep.get("git_url", "")
        flag = " **candidate**" if dep.get("candidate") else ""
        lines.append(f"- `{name}` ({divergence}){flag}  \n  git: {url}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run cargo-fork-ancestry-check against Spark FROST workspace "
                    "and classify divergences per L28-E.",
    )
    p.add_argument(
        "--workspace",
        type=pathlib.Path,
        default=DEFAULT_WORKSPACE,
        help=(
            "Path to the Spark FROST signer workspace "
            f"(default: {DEFAULT_WORKSPACE})"
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output (passed through to inner tool).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit 2 on any diverged dep (passed through to inner tool).",
    )
    p.add_argument(
        "--audit-pin",
        dest="audit_pin",
        default=None,
        help="Audit-pin SHA to anchor divergence comparison (optional).",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    workspace = pathlib.Path(args.workspace).expanduser().resolve()

    if not workspace.exists():
        print(
            f"[spark-cargo-fork-status] ERROR: workspace not found: {workspace}\n"
            "Run from a host with the Spark engagement bootstrapped; "
            "see ~/audits/spark/",
            file=sys.stderr,
        )
        return 1

    if not (workspace / "Cargo.toml").exists():
        print(
            f"[spark-cargo-fork-status] ERROR: no Cargo.toml at {workspace}\n"
            "Is --workspace pointing at the correct signer directory?",
            file=sys.stderr,
        )
        return 1

    # Build inner tool command
    cmd = [sys.executable, str(INNER_TOOL), "--workspace", str(workspace)]
    if getattr(args, "json"):
        cmd.append("--json")
    if args.strict:
        cmd.append("--strict")
    if args.audit_pin:
        cmd.extend(["--audit-pin", args.audit_pin])

    env = dict(os.environ)

    # --- JSON mode: pass through and return ---
    if getattr(args, "json"):
        result = subprocess.run(cmd, env=env)
        return result.returncode

    # --- Markdown mode: emit header + inner output + classification ---
    iso_date = datetime.date.today().isoformat()
    print(f"# Spark Cargo Fork-Ancestry Status — {iso_date}")
    print()
    print(
        f"Workspace: `{workspace}`  \n"
        f"Inner tool: `tools/cargo-fork-ancestry-check.py`"
    )
    print()

    # Run inner tool, capture output for classification
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
    )
    inner_stdout = result.stdout
    inner_stderr = result.stderr
    inner_rc = result.returncode

    # Print inner tool output verbatim
    if inner_stdout:
        print(inner_stdout, end="")
    if inner_stderr:
        print(inner_stderr, end="", file=sys.stderr)

    # Spark-specific classification section
    print()
    print("## Spark Crypto-Class Classification")
    print()
    print(
        "Diverged dependencies whose crate name matches a crypto-primitive, "
        "RPC, or DB substring are flagged **candidate** for L28-E review."
    )
    print()

    # We re-run inner tool with --json to parse deps for classification
    json_cmd = [sys.executable, str(INNER_TOOL), "--workspace", str(workspace), "--json"]
    if args.audit_pin:
        json_cmd.extend(["--audit-pin", args.audit_pin])

    json_result = subprocess.run(
        json_cmd,
        capture_output=True,
        text=True,
        env=env,
    )

    classified: list[dict] = []
    total_deps = 0
    git_sourced = 0
    diverged_count = 0
    crypto_diverged = 0

    if json_result.returncode in (0, 2) and json_result.stdout.strip():
        try:
            data = json.loads(json_result.stdout)
            deps_raw = data.get("deps", [])
            total_deps = data.get("total_deps", len(deps_raw))
            git_sourced = len(deps_raw)
            diverged_deps = [d for d in deps_raw if d.get("divergence", "same") != "same"]
            diverged_count = len(diverged_deps)
            classified = classify_diverged_deps(diverged_deps)
            crypto_diverged = sum(1 for d in classified if d.get("candidate"))
        except (json.JSONDecodeError, KeyError):
            pass

    print(_summary_table(total_deps, git_sourced, diverged_count, crypto_diverged))
    print()
    print("### Diverged Dependency Detail")
    print()
    print(_render_classified_markdown(classified))
    print()

    if crypto_diverged > 0:
        print(
            f"> **{crypto_diverged} crypto-class candidate(s) detected.**  \n"
            "> Verify each against GHSA / audit-pin commit log before drafting "
            "(L28-E + L31 discipline)."
        )
    else:
        print("> No crypto-class diverged dependencies flagged.")

    return inner_rc


if __name__ == "__main__":
    sys.exit(main())
