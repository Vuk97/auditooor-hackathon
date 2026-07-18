#!/usr/bin/env python3
"""Spark PoI (Primacy of Impact) scope-mechanic verifier.

For a given Spark engagement draft (markdown), parse cited file/repo paths
and classify which Immunefi form selector applies:

  listed-asset     trigger lives in buildonspark/spark or buildonspark/BTKN
  PoI-placeholder  trigger lives in a Spark-coordinator upstream dep that
                   routes mainnet impact through Spark (FROST, btcd, etc.)
  REDIRECT         trigger lives in another Lightspark program (NOT covered
                   under Spark PoI; file under that program separately)
  DROP             trigger lives in testnet / mocks / fixtures / dev (PoI
                   does not cover these surfaces)
  UNKNOWN          cited path doesn't match any rule; operator review

Empirical anchor:
  - LEAD 1 (chain-watcher) trigger inside buildonspark/spark -> listed-asset
  - FROST upstream collision triggers (PR #659 demos)         -> PoI-placeholder
  - lightspark-rs / go-sdk findings (HUNT-L2)                 -> REDIRECT
  - testnet/mock_signer.go style demos                        -> DROP

CLI:
  spark-poi-scope-verifier.py <draft.md> [--json]
  spark-poi-scope-verifier.py --classify-path <path> [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# --- Classification rules -----------------------------------------------------
# Order matters: testnet/mock check fires FIRST so a path like
# "buildonspark/spark/testnet/mock_signer.go" classifies as DROP, not
# listed-asset.

# Substrings that demote any otherwise-listed path to DROP (PoI does not
# cover these surfaces even if inside the listed asset tree).
_DROP_SUBSTRINGS = (
    "/testnet/",
    "/_test/",
    "/mock_",
    "/mocks/",
    "/fixtures/",
    "/dev/",
    "/testing/",
)
_DROP_SUFFIXES = (
    "_test.go",
    "_test.rs",
    "_mock.go",
    "_mock.rs",
)

# Repo orgs/paths -> listed-asset row on Spark's Immunefi form.
_LISTED_REPOS = (
    "buildonspark/spark",
    "buildonspark/btkn",
)

# Repo orgs/paths -> PoI placeholder (upstream deps Spark coordinator pulls).
_POI_UPSTREAM_REPOS = (
    "lightsparkdev/frost",  # FROST threshold-signing crate
    "cosmos/cosmos-sdk",
    "cosmos-sdk",
    "tendermint/tendermint",
    "cometbft/cometbft",
    "btcsuite/btcd",
    "btcsuite/btcwallet",
    "btcsuite/btcutil",
    "btcsuite/btcd-onion",
    "entgo/ent",
    "grpc/grpc-go",
    "protocolbuffers/protobuf-go",
    "hyperium/tonic",
    "tonic",
    "lightningnetwork/lnd",
    "lightninglabs/loop",
    # BIP340 schnorr / nonce libs commonly pulled via Cargo / Go.
    "bitcoin-core/secp256k1",
    "rust-bitcoin/rust-secp256k1",
    "decred/dcrd",
)

# Lightspark sibling products (NOT Spark): REDIRECT.
# Anything else under `lightsparkdev/` that isn't `lightsparkdev/frost`
# is treated as a Lightspark sibling program by default.
_LIGHTSPARK_REDIRECT_REPOS = (
    "lightsparkdev/lightspark-rs",
    "lightsparkdev/go-sdk",
    "lightsparkdev/lightspark-go",  # historical alias
    "lightsparkdev/lightspark-crypto-uniffi",
    "lightsparkdev/spark-sdk-js",
    "lightsparkdev/spark-sdk-ts",
    "lightsparkdev/spark-sdk-python",
    "lightsparkdev/spark-sdk-go",
    "lightsparkdev/spark-sdk-rs",
)

# --- Path extraction ----------------------------------------------------------
# Match `org/repo[/sub/path.ext]` style references in markdown bodies, code
# fences, backtick spans, list bullets. Also picks up bare file paths with
# known source extensions.
_FILE_EXTS = (
    r"\.go", r"\.rs", r"\.ts", r"\.tsx", r"\.py", r"\.sql",
    r"\.proto", r"\.move", r"\.sol", r"\.js", r"\.jsx",
)
_EXT_GROUP = "(?:" + "|".join(_FILE_EXTS) + ")"

# org/repo[/path...]: word chars + . _ - and forward slashes.
_REPO_RE = re.compile(
    r"(?<![/A-Za-z0-9])"
    r"(?:github\.com/)?"
    r"([A-Za-z][\w.-]+/[\w.-]+(?:/[\w./-]+)?)"
)

# Bare relative paths ending in a source-file extension (e.g. `coordinator/lib.rs`).
_BARE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_/])"
    r"([\w./-]+" + _EXT_GROUP + r")"
)


def extract_paths(text: str) -> list[str]:
    """Extract candidate cited paths from a markdown body.

    Returns a de-duplicated, order-preserved list of path-like tokens.
    """
    paths: list[str] = []
    seen: set[str] = set()

    # Strip leading `github.com/` so downstream classification is uniform.
    for m in _REPO_RE.finditer(text):
        raw = m.group(1).strip(".,;:`*)\"'")
        if raw.startswith("github.com/"):
            raw = raw[len("github.com/"):]
        # Avoid trivial junk like `a/b` from prose; require at least one of:
        # - a slash beyond org/repo (i.e. cites a file under the repo)
        # - explicit known org/repo prefix
        if _looks_like_repo_ref(raw) and raw not in seen:
            seen.add(raw)
            paths.append(raw)

    for m in _BARE_PATH_RE.finditer(text):
        raw = m.group(1).strip(".,;:`*)\"'")
        # Skip if it's already covered by the repo-prefixed extraction.
        if any(raw in p for p in paths):
            continue
        if raw not in seen:
            seen.add(raw)
            paths.append(raw)

    return paths


def _looks_like_repo_ref(path: str) -> bool:
    """Heuristic: does this look like a github org/repo reference?"""
    parts = path.split("/")
    if len(parts) < 2:
        return False
    org = parts[0].lower()
    # Known orgs we care about.
    known_orgs = {
        "buildonspark", "lightsparkdev", "cosmos", "cometbft", "tendermint",
        "btcsuite", "entgo", "grpc", "protocolbuffers", "hyperium",
        "lightningnetwork", "lightninglabs", "bitcoin-core",
        "rust-bitcoin", "decred", "cosmos-sdk", "tonic",
    }
    if org in known_orgs:
        return True
    # Heuristic: at least 3 path components and ends in a source extension.
    if len(parts) >= 3 and any(parts[-1].endswith(ext.strip(r"\.")) for ext in [".go", ".rs", ".ts", ".py", ".sql", ".proto", ".move", ".sol"]):
        return True
    return False


# --- Classification core ------------------------------------------------------

CLASSIFICATIONS = (
    "listed-asset",
    "PoI-placeholder",
    "REDIRECT",
    "DROP",
    "UNKNOWN",
)


def classify_path(path: str) -> dict[str, Any]:
    """Classify one cited path into an Immunefi-selector class."""
    p = path.lower().strip()

    # Strip leading `github.com/`.
    if p.startswith("github.com/"):
        p = p[len("github.com/"):]

    # Rule 4 first: testnet/mock/fixtures DROP, regardless of repo.
    for sub in _DROP_SUBSTRINGS:
        if sub in "/" + p:
            return {
                "path": path,
                "classification": "DROP",
                "repo_org": _repo_org(p),
                "reason": f"path matches testnet/mock substring {sub!r}",
            }
    for suf in _DROP_SUFFIXES:
        if p.endswith(suf):
            return {
                "path": path,
                "classification": "DROP",
                "repo_org": _repo_org(p),
                "reason": f"path matches dev/mock suffix {suf!r}",
            }

    # Rule 1: listed-asset (buildonspark/spark or buildonspark/BTKN).
    # Historical Go-module alias: `lightsparkdev/spark` resolves to the same
    # repo as `buildonspark/spark` (Go import path lag); treat as listed-asset.
    if p.startswith("lightsparkdev/spark/") or p == "lightsparkdev/spark":
        return {
            "path": path,
            "classification": "listed-asset",
            "repo_org": "buildonspark/spark",
            "reason": (
                "Go-module path 'lightsparkdev/spark' is the historical "
                "import alias for buildonspark/spark (listed asset)"
            ),
        }
    for repo in _LISTED_REPOS:
        if p.startswith(repo + "/") or p == repo:
            return {
                "path": path,
                "classification": "listed-asset",
                "repo_org": repo,
                "reason": f"trigger inside listed Spark asset {repo!r}",
            }

    # Rule 2: PoI placeholder (upstream coordinator deps).
    for repo in _POI_UPSTREAM_REPOS:
        if p.startswith(repo + "/") or p == repo or p.startswith(repo.split("/")[-1] + "/"):
            return {
                "path": path,
                "classification": "PoI-placeholder",
                "repo_org": repo,
                "reason": (
                    f"trigger in Spark-coordinator upstream dep {repo!r}; "
                    f"mainnet impact routes via Primacy of Impact selector"
                ),
            }

    # Rule 3: REDIRECT (Lightspark sibling programs).
    for repo in _LIGHTSPARK_REDIRECT_REPOS:
        if p.startswith(repo + "/") or p == repo:
            return {
                "path": path,
                "classification": "REDIRECT",
                "repo_org": repo,
                "reason": (
                    f"trigger in Lightspark sibling program {repo!r}; "
                    f"not covered under Spark PoI -- file separately"
                ),
            }
    # Catch-all for any lightsparkdev/* repo not in the explicit allow-list
    # (Spark PoI's hard exclusion in SCOPE.md:71 covers all of them except
    # `lightsparkdev/frost`, which is an upstream crypto library).
    if p.startswith("lightsparkdev/"):
        return {
            "path": path,
            "classification": "REDIRECT",
            "repo_org": p.split("/", 2)[:2] and "/".join(p.split("/", 2)[:2]),
            "reason": (
                "trigger inside lightsparkdev/* sibling program; "
                "SCOPE.md:71 excludes Lightspark programs from Spark PoI"
            ),
        }

    # Rule 5: UNKNOWN.
    return {
        "path": path,
        "classification": "UNKNOWN",
        "repo_org": _repo_org(p),
        "reason": "no rule matched; operator review required",
    }


def _repo_org(p: str) -> str | None:
    parts = p.split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return None


def classify_draft(text: str) -> dict[str, Any]:
    """Aggregate classification for a draft markdown body."""
    paths = extract_paths(text)
    if not paths:
        return {
            "recommended_selector": "UNKNOWN",
            "reasoning": "no cited paths found in draft body",
            "paths": [],
            "confidence": "low",
        }

    per_path = [classify_path(p) for p in paths]
    classes = {pp["classification"] for pp in per_path}

    # Recommended selector logic:
    # - All same -> that selector with high confidence
    # - All listed-asset/PoI mix and no REDIRECT/DROP/UNKNOWN -> dominant by count
    # - Any REDIRECT or DROP in the set -> mixed, surface those for operator
    if len(classes) == 1:
        only = next(iter(classes))
        return {
            "recommended_selector": only,
            "reasoning": _explain_selector(only, len(paths)),
            "paths": per_path,
            "confidence": "high",
        }

    # Mixed. Operator must adjudicate. Pick a "recommended" by precedence:
    # REDIRECT/DROP findings override listed-asset because they're red flags.
    precedence = ("DROP", "REDIRECT", "UNKNOWN", "PoI-placeholder", "listed-asset")
    recommended = next((c for c in precedence if c in classes), "UNKNOWN")
    return {
        "recommended_selector": recommended,
        "reasoning": (
            f"mixed-class citations ({sorted(classes)}); "
            f"surfacing highest-precedence concern -- operator review required"
        ),
        "paths": per_path,
        "confidence": "mixed",
    }


def _explain_selector(cls: str, n: int) -> str:
    if cls == "listed-asset":
        return (
            f"all {n} cited path(s) live inside buildonspark/spark|BTKN; "
            f"select listed-asset row on Immunefi form"
        )
    if cls == "PoI-placeholder":
        return (
            f"all {n} cited path(s) live in Spark-coordinator upstream deps; "
            f"select Primacy of Impact placeholder row"
        )
    if cls == "REDIRECT":
        return (
            f"all {n} cited path(s) live in Lightspark sibling programs; "
            f"do NOT file under Spark -- redirect to that program's bounty"
        )
    if cls == "DROP":
        return (
            f"all {n} cited path(s) live in testnet/mock/fixture surfaces; "
            f"PoI does not cover these -- drop"
        )
    return f"all {n} cited path(s) unclassified; operator review required"


# --- CLI ----------------------------------------------------------------------

def _emit(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"Recommended Immunefi selector: {result['recommended_selector']}")
    print(f"Reasoning: {result['reasoning']}")
    if result.get("paths"):
        print("Cited paths:")
        for pp in result["paths"]:
            print(f"  - {pp['path']} -> {pp['classification']} ({pp.get('reason','')})")
    print(f"Confidence: {result['confidence']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Classify a Spark engagement draft's Immunefi selector."
    )
    ap.add_argument("draft", nargs="?", help="path to draft markdown")
    ap.add_argument(
        "--classify-path",
        help="classify a single path (skip draft parse)",
    )
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args(argv)

    if args.classify_path:
        per = classify_path(args.classify_path)
        result = {
            "recommended_selector": per["classification"],
            "reasoning": per["reason"],
            "paths": [per],
            "confidence": "high",
        }
        _emit(result, args.json)
        return 0

    if not args.draft:
        ap.error("draft path required (or pass --classify-path)")

    draft_path = Path(args.draft)
    if not draft_path.exists():
        sys.stderr.write(f"ERROR: draft not found: {draft_path}\n")
        return 2

    text = draft_path.read_text(encoding="utf-8")
    result = classify_draft(text)
    _emit(result, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
