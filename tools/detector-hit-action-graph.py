#!/usr/bin/env python3
"""Build an advisory attacker action graph from one detector hit.

This is the missing local bridge between scanner output and hacker reasoning:
detector hit -> attack-class hypotheses -> attacker steps -> proof obligations.

It is intentionally evidence-bounded. The output is a worklist for source
review and PoC planning, not an exploitability, impact, severity, or submission
verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hacker_question_renderer import HACKER_QUESTION_SCHEMA, render_hacker_questions

SCHEMA = "auditooor.detector_hit_action_graph.v1"
HARNESS_TASK_SCHEMA = "auditooor.harness_task.v1"
PROOF_BOUNDARY = (
    "Advisory action graph only. Detector hits, corpus similarity, and chain "
    "candidates do not prove exploitability, production reachability, listed "
    "impact, severity, OOS status, duplicate status, or submission readiness."
)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[detector-hit-action-graph] ERR invalid JSON in {path}: {exc}") from None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "unknown"


def _uniq(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            out.append(text)
            seen.add(text)
    return out


def _detector_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def _workspace_relative(path_text: str, workspace: Path | None) -> str:
    text = str(path_text or "").strip()
    if not text:
        return ""
    if workspace is None:
        return text
    line_suffix = ""
    line_match = re.match(r"^(.+?)(:\d+(?::\d+)?)$", text)
    if line_match:
        text = line_match.group(1)
        line_suffix = line_match.group(2)
    path = Path(text).expanduser()
    if path.is_absolute():
        try:
            return path.resolve().relative_to(workspace.resolve()).as_posix() + line_suffix
        except ValueError:
            return "<external-path>/" + path.name + line_suffix
    return text.replace("\\", "/") + line_suffix


def _safe_context(value: str, *, max_chars: int = 500) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


def _source_anchor_keys(value: str) -> set[str]:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return set()
    text = re.sub(r"^(workspace:|file://)", "", text)
    text = re.sub(r"^<external-path>/", "", text)
    text = text.lower()
    keys = {text}
    line_match = re.match(r"^(.+?)(:\d+(?::\d+)?)$", text)
    if line_match:
        keys.add(line_match.group(1))
    return {key for key in keys if key}


def _plan_has_strong_anchor(plan: dict[str, Any], detector_slug: str, source_keys: set[str]) -> bool:
    detector_key = _detector_key(detector_slug)
    for source_ref in plan.get("source_refs", []) if isinstance(plan.get("source_refs"), list) else []:
        if _source_anchor_keys(str(source_ref)) & source_keys:
            return True

    for primitive in plan.get("primitives", []) if isinstance(plan.get("primitives"), list) else []:
        if not isinstance(primitive, dict):
            continue
        for key in ("detector_slug", "detector", "pattern_id", "primitive_id", "id", "title"):
            value_key = _detector_key(str(primitive.get(key) or ""))
            if detector_key and value_key and (value_key == detector_key or value_key.startswith(detector_key + "-")):
                return True
        primitive_refs = primitive.get("source_refs")
        if isinstance(primitive_refs, list):
            for source_ref in primitive_refs:
                if _source_anchor_keys(str(source_ref)) & source_keys:
                    return True
    return False


def _load_ranker_module(repo_root: Path) -> Any:
    path = repo_root / "tools" / "attack-class-ranker.py"
    if not path.is_file():
        path = REPO_ROOT / "tools" / "attack-class-ranker.py"
    spec = importlib.util.spec_from_file_location("attack_class_ranker_for_action_graph", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit("[detector-hit-action-graph] ERR could not load attack-class-ranker.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_engage_hits(workspace: Path | None, engage_report: Path | None) -> list[dict[str, Any]]:
    if engage_report is None and workspace is not None:
        engage_report = workspace / "engage_report.json"
    if engage_report is None:
        return []
    raw = _load_json(engage_report)
    if not isinstance(raw, dict):
        return []
    hits: list[dict[str, Any]] = []
    for cluster in raw.get("clusters") or []:
        if not isinstance(cluster, dict):
            continue
        detector_slug = str(cluster.get("detector_slug") or "").strip()
        if not detector_slug:
            continue
        for hit in cluster.get("hits") or []:
            if not isinstance(hit, dict):
                continue
            hits.append(
                {
                    "detector_slug": detector_slug,
                    "severity": str(hit.get("severity") or "UNKNOWN").upper(),
                    "file_path": _workspace_relative(str(hit.get("file_path") or ""), workspace),
                    "snippet": _safe_context(str(hit.get("snippet") or "")),
                    "cluster_hit_count": int(cluster.get("hit_count") or 0),
                    "source_ref": "workspace:engage_report.json",
                }
            )
    return hits


def _select_hit(args: argparse.Namespace, workspace: Path | None) -> dict[str, Any]:
    explicit = {
        "detector_slug": str(args.detector_slug or "").strip(),
        "severity": str(args.severity or "UNKNOWN").upper(),
        "file_path": _workspace_relative(str(args.file_path or ""), workspace),
        "snippet": _safe_context(args.context or args.snippet or ""),
        "cluster_hit_count": 0,
        "source_ref": "cli",
    }
    engage_hits = _load_engage_hits(workspace, Path(args.engage_report).expanduser() if args.engage_report else None)
    explicit_key = _detector_key(explicit["detector_slug"])
    if explicit["detector_slug"]:
        for hit in engage_hits:
            if _detector_key(hit["detector_slug"]) == explicit_key:
                if explicit["file_path"]:
                    hit["file_path"] = explicit["file_path"]
                if explicit["snippet"]:
                    hit["snippet"] = explicit["snippet"]
                if args.severity:
                    hit["severity"] = explicit["severity"]
                return hit
        return explicit
    if engage_hits:
        index = max(0, min(int(args.hit_index or 0), len(engage_hits) - 1))
        return engage_hits[index]
    if not explicit["detector_slug"]:
        raise SystemExit(
            "[detector-hit-action-graph] ERR provide --detector-slug or a workspace/engage_report.json with clusters"
        )
    return explicit


def _attack_class_goal(attack_class: str) -> dict[str, str]:
    low = attack_class.lower()
    if "reentr" in low:
        return {
            "attacker_goal": "reenter before accounting or authorization state is finalized",
            "precondition": "attacker can trigger an external callback or hook on the flagged path",
            "state_transition": "second entry observes stale state or bypasses a one-shot guard",
            "impact_probe": "assert asset balance, debt, share, or claim accounting changes twice",
        }
    if "oracle" in low or "price" in low:
        return {
            "attacker_goal": "move or select a price input that the protocol treats as authoritative",
            "precondition": "attacker can influence the quoted market, feed freshness, decimals, or fallback branch",
            "state_transition": "valuation-dependent mint, borrow, redeem, or liquidation uses the manipulated value",
            "impact_probe": "assert undercollateralized mint/borrow, unfair liquidation, or asset drain",
        }
    if "signature" in low or "replay" in low or "permit" in low:
        return {
            "attacker_goal": "replay or redirect an authorization outside its intended domain",
            "precondition": "attacker obtains a valid signature/proof for a different identity, chain, nonce, or payload",
            "state_transition": "target accepts the authorization without binding every domain field",
            "impact_probe": "assert unauthorized transfer, role action, order fill, or message execution",
        }
    if "bridge" in low or "message" in low or "cross" in low:
        return {
            "attacker_goal": "make the destination accept a message/proof from the wrong source or state",
            "precondition": "attacker controls message fields, source chain metadata, replay order, or proof payload",
            "state_transition": "destination mints, releases, finalizes, or marks state using the unbound message",
            "impact_probe": "assert unauthorized mint/release, stuck funds, replay, or inconsistent accounting",
        }
    if "zk" in low or "proof" in low or "fiat" in low or "shamir" in low:
        return {
            "attacker_goal": "prove a statement whose public inputs or transcript state were not fully bound",
            "precondition": "attacker can choose witness/proof/transcript values around the flagged verifier path",
            "state_transition": "verifier accepts a proof after missing an observation or constraint",
            "impact_probe": "assert false proof acceptance or forged state transition under local verifier tests",
        }
    if "access" in low or "auth" in low or "role" in low:
        return {
            "attacker_goal": "execute a privileged state transition from an unvetted caller",
            "precondition": "attacker can reach the flagged function without a role/owner/capability guard",
            "state_transition": "privileged storage, asset, or configuration state changes",
            "impact_probe": "assert unvetted caller can cause the listed impact, not just call the function",
        }
    return {
        "attacker_goal": "turn the flagged invariant gap into a controlled state transition",
        "precondition": "attacker controls the relevant caller, input, timing, or state setup",
        "state_transition": "the flagged branch changes persistent protocol state or accepted proof state",
        "impact_probe": "assert a concrete asset, role, liveness, or accounting consequence",
    }


# ---------------------------------------------------------------------------
# Harness task derivation (Lane 7 / Slice 5) + Lane C2 command generation
# ---------------------------------------------------------------------------

_HARNESS_TYPE_EVM = "Foundry test"
_HARNESS_TYPE_GO = "Go unit/integration test"
_HARNESS_TYPE_COSMOS = "Cosmos app-chain test"
_HARNESS_TYPE_SOLANA = "Solana program-test/LiteSVM"
_HARNESS_TYPE_BRIDGE = "bridge proof/replay harness"
_HARNESS_TYPE_GENERIC = "Go unit/integration test"

# Language keywords -> harness type (exact-word matches; Solana must come before Solidity)
_LANGUAGE_HARNESS: list[tuple[list[str], str]] = [
    (["solana", "anchor", "sealevel"], _HARNESS_TYPE_SOLANA),
    (["cosmos", "cosmwasm", "tendermint", "cometbft", "dydx", "osmosis"], _HARNESS_TYPE_COSMOS),
    (["solidity", "evm", "yul", "vyper", "huff"], _HARNESS_TYPE_EVM),
    (["rust", "rs"], _HARNESS_TYPE_GO),  # non-Solana Rust defaults to Go-style integration
    (["go", "golang"], _HARNESS_TYPE_GO),
]

# Attack-class keywords that imply bridge harness regardless of language
_BRIDGE_ATTACK_CLASSES = {"bridge", "cross-chain", "crosschain", "withdrawal", "relay", "proof-replay"}


def _strip_line_suffix(path: str) -> str:
    """Remove trailing :line or :line:col from a file path string."""
    return re.sub(r"(:\d+)+$", "", path)


def _choose_harness_type(language: str, file_path: str, attack_class: str) -> str:
    """Select the concrete harness type from detector hit metadata."""
    lang_low = (language or "").lower().strip()
    # Strip :line suffixes before extension checks
    file_low = _strip_line_suffix((file_path or "").lower())
    ac_low = (attack_class or "").lower()

    # Bridge attack class wins regardless of language
    if any(kw in ac_low for kw in _BRIDGE_ATTACK_CLASSES):
        return _HARNESS_TYPE_BRIDGE

    # Explicit language hint: exact-word match first (avoids "sol" matching "solana")
    for keywords, harness in _LANGUAGE_HARNESS:
        if lang_low in keywords:
            return harness
    # Substring fallback for compound language strings (e.g. "solidity-0.8")
    for keywords, harness in _LANGUAGE_HARNESS:
        if any(kw in lang_low for kw in keywords):
            return harness

    # Infer from file extension
    if any(file_low.endswith(ext) for ext in (".sol", ".vy", ".yul")):
        return _HARNESS_TYPE_EVM
    if file_low.endswith(".rs"):
        return _HARNESS_TYPE_SOLANA if "solana" in file_low or "anchor" in file_low else _HARNESS_TYPE_GO
    if file_low.endswith(".go"):
        return _HARNESS_TYPE_COSMOS if any(kw in file_low for kw in ("cosmos", "dydx", "osmosis", "cometbft", "tendermint")) else _HARNESS_TYPE_GO

    return _HARNESS_TYPE_GENERIC


def _harness_template(harness_type: str, attack_class: str) -> dict[str, str]:
    """Return harness-factory guidance for the given harness type."""
    if harness_type == _HARNESS_TYPE_EVM:
        return {
            "setup_notes": "Use Foundry fork or no-fork; label actors (attacker, victim, protocol); set up token balances and role assignments via cheatcodes",
            "fork_clarity": "state whether test uses vm.createFork/vm.selectFork (fork) or deploys from scratch (no-fork); justify the choice",
            "invariant_check": "assert token balance, share accounting, role state, or reentrancy guard after attack tx; compare before/after snapshots",
            "production_path": "call the flagged function from an unvetted attacker address (no privileged prank); exercise the real external call path",
        }
    if harness_type == _HARNESS_TYPE_COSMOS:
        return {
            "setup_notes": "Use simapp.Setup or cosmos-sdk testnet.New; open real store/backend (no MemDB for HIGH+); wire real ante decorators",
            "fork_clarity": "no fork available; deploy via app.Commit or app.BeginBlock/EndBlock; use BroadcastTxSync or app.RunTx for real ante chain",
            "invariant_check": "assert store state, module account balances, or consensus state via ctx.KVStore after FinalizeBlock or RunTx",
            "production_path": "exercise FinalizeBlock/RunTx entry path, not direct keeper calls; cite ante decorator chain",
        }
    if harness_type == _HARNESS_TYPE_SOLANA:
        return {
            "setup_notes": "Use solana-program-test BanksClient or LiteSVM; create attacker and victim keypairs; fund accounts; initialize program state",
            "fork_clarity": "state whether using BanksClient (full runtime) or LiteSVM (lite runtime); lite is acceptable for unit scope",
            "invariant_check": "assert lamport balances, account data fields, or authority state after instruction execution",
            "production_path": "invoke instruction via real transaction (signed by attacker keypair); do not bypass signer/authority checks in test",
        }
    if harness_type == _HARNESS_TYPE_BRIDGE:
        return {
            "setup_notes": "Set up source commitment, destination settlement, replay key, chain/domain binding; deploy or mock both sides",
            "fork_clarity": "fork from a recent block that contains the committed message; alternatively deploy minimal bridge contracts from scratch",
            "invariant_check": "assert duplicate proof rejection, correct domain binding, or replay prevention after second submission",
            "production_path": "submit forged/replayed proof via the real verifier entry point; assert acceptance or rejection",
        }
    # Go unit/integration (default)
    return {
        "setup_notes": "Use standard Go testing.T; open real filesystem-backed DB if severity requires it (no MemDB for HIGH+); wire real middleware",
        "fork_clarity": "not applicable; reproduce state from scratch via init functions or testutil helpers",
        "invariant_check": "assert struct fields, return values, error codes, or side-effect state after the flagged function executes",
        "production_path": "invoke through the real package API surface, not internal unexported helpers; exercise real middleware/hook chain",
    }


def _attack_class_negative_control(attack_class: str) -> str:
    """Return a negative control description for the attack class."""
    low = (attack_class or "").lower()
    if "reentr" in low:
        return "Deploy a contract with a reentrancy guard active; assert the second entry reverts"
    if "oracle" in low or "price" in low:
        return "Use a time-weighted or multi-source oracle; assert the manipulated single-block price is rejected or bounded"
    if "signature" in low or "replay" in low or "permit" in low:
        return "Submit the same signature with a different chain ID or nonce; assert it is rejected with the expected error"
    if "bridge" in low or "message" in low or "cross" in low:
        return "Submit a proof with a wrong domain separator or wrong source chain ID; assert the verifier reverts"
    if "zk" in low or "proof" in low:
        return "Submit a proof with a tampered public input; assert the verifier rejects it"
    if "access" in low or "auth" in low or "role" in low:
        return "Call the flagged function from a correctly-authorized address; assert it succeeds (control) vs from attacker (attack)"
    return "Exercise the same code path with all preconditions satisfied for the non-attack case; assert no harmful state change"


def _attack_class_kill_conditions(attack_class: str) -> list[str]:
    """Return kill conditions that would make this harness task obsolete."""
    low = (attack_class or "").lower()
    base = [
        "Source review shows the flagged path is unreachable from an unvetted external caller",
        "A guard or modifier already covers all reachable call sites (enumerate with missing-guard-callsite-enumerator.sh)",
    ]
    if "reentr" in low:
        return base + [
            "ReentrancyGuard or equivalent lock is confirmed present on all external-callback paths",
            "State is updated before the external call on every reachable branch",
        ]
    if "oracle" in low or "price" in low:
        return base + [
            "Oracle is time-weighted across >= 2 blocks or uses >= 2 independent sources with a deviation cap",
            "Price staleness and bounds checks are confirmed to reject the attacker-controlled value",
        ]
    if "signature" in low or "replay" in low or "permit" in low:
        return base + [
            "All domain fields (chain ID, nonce, deadline, verifying contract) are confirmed bound in the digest",
            "Nonce invalidation is confirmed after first use on all reachable paths",
        ]
    if "access" in low or "auth" in low or "role" in low:
        return base + [
            "All reachable entry points are confirmed guarded by the required role or capability check",
        ]
    return base + [
        "Independent security review or fix commit confirms the flagged invariant gap is closed",
    ]


def _test_slug(task_id: str, detector_slug: str, attack_class: str) -> str:
    """Derive a deterministic test name from candidate identifiers.

    The slug is used as the test function name suffix in generated harness
    commands.  It is stable: same inputs always produce the same slug.
    """
    # task_id is canonical (e.g. "HT-001"); use it as the primary discriminator
    id_part = re.sub(r"[^A-Za-z0-9]+", "_", task_id.strip()).strip("_").lower()
    # Include enough of detector_slug / attack_class to be human-readable
    det_part = re.sub(r"[^A-Za-z0-9]+", "_", (detector_slug or "unknown").strip()).strip("_").lower()[:30]
    ac_part = re.sub(r"[^A-Za-z0-9]+", "_", (attack_class or "unknown").strip()).strip("_").lower()[:20]
    slug = f"{id_part}_{det_part}_{ac_part}".strip("_")
    # Cap total length so test names stay readable in CLI output
    return slug[:80] if len(slug) <= 80 else slug[:80]


def _generate_harness_command(
    harness_type: str,
    task_id: str,
    detector_slug: str,
    attack_class: str,
    source_file: str,
    workspace: Path | None,
) -> tuple[str, str]:
    """Generate a concrete harness command for a task descriptor.

    Returns a (command, harness_status) tuple where harness_status is one of:
    - ``command_ready``: test file found on disk; command can be run immediately.
    - ``command_ready_test_missing``: command is syntactically concrete and
      deterministic but the test file does not yet exist; next step is to
      create it.
    - ``unresolvable``: harness type is unknown or not locally runnable.
    """
    slug = _test_slug(task_id, detector_slug, attack_class)
    # PascalCase test name for Go/Solana/Cosmos test functions
    pascal_slug = "".join(part.capitalize() for part in slug.split("_") if part)

    # -----------------------------------------------------------------------
    # Infer where the test file should live (relative to workspace or cwd)
    # -----------------------------------------------------------------------
    bare_source = _strip_line_suffix(source_file or "")
    # Derive the test file path convention for each harness type
    if harness_type == _HARNESS_TYPE_EVM:
        # Foundry: test file lives alongside source or in test/ directory
        if bare_source:
            src_path = Path(bare_source)
            stem = src_path.stem  # e.g. "Vault" from "src/Vault.sol"
            # Conventional Foundry test location: test/<Stem>.t.sol
            test_file = Path("test") / f"{stem}.t.sol"
        else:
            test_file = Path("test") / f"Harness_{slug}.t.sol"
        test_function = f"test_{slug}"
        command = f"forge test --match-test {test_function} -vvv"

    elif harness_type == _HARNESS_TYPE_COSMOS:
        # Cosmos: Go test in the same package as the source file
        if bare_source:
            pkg_dir = str(Path(bare_source).parent).replace("\\", "/")
        else:
            pkg_dir = "./..."
        test_function = f"Test{pascal_slug}"
        # Use GOTOOLCHAIN=local to avoid network fetches; -count=1 disables cache
        command = f"GOTOOLCHAIN=local go test {pkg_dir} -run {test_function} -count=1 -v"
        # Test file path: sibling _test.go in the package directory
        if bare_source and bare_source.endswith(".go"):
            test_file = Path(bare_source).parent / f"{slug}_test.go"
        else:
            test_file = Path(pkg_dir.lstrip("./")) / f"{slug}_test.go"

    elif harness_type == _HARNESS_TYPE_GO:
        # Plain Go unit/integration test
        if bare_source:
            pkg_dir = str(Path(bare_source).parent).replace("\\", "/") or "."
            pkg_spec = pkg_dir if pkg_dir and pkg_dir != "." else "./..."
        else:
            pkg_spec = "./..."
        test_function = f"Test{pascal_slug}"
        command = f"GOTOOLCHAIN=local go test {pkg_spec} -run {test_function} -count=1 -v"
        if bare_source and bare_source.endswith(".go"):
            test_file = Path(bare_source).parent / f"{slug}_test.go"
        else:
            test_file = Path("harness") / f"{slug}_test.go"

    elif harness_type == _HARNESS_TYPE_SOLANA:
        # Solana: cargo test using the crate root or an anchor test
        if bare_source and bare_source.endswith(".rs"):
            # Derive closest Cargo.toml parent - we can't resolve at generation time,
            # so emit the package-level cargo test command
            pkg_dir = str(Path(bare_source).parent).replace("\\", "/")
        else:
            pkg_dir = "."
        test_function = slug  # Rust test names are snake_case
        command = f"cargo test {test_function} -- --nocapture"
        if bare_source and bare_source.endswith(".rs"):
            test_file = Path(bare_source).parent / f"{slug}_test.rs"
        else:
            test_file = Path("tests") / f"{slug}.rs"

    elif harness_type == _HARNESS_TYPE_BRIDGE:
        # Bridge: prefer Foundry if source is Solidity, otherwise Go
        if bare_source and any(bare_source.endswith(ext) for ext in (".sol", ".vy", ".yul")):
            src_path = Path(bare_source)
            stem = src_path.stem
            test_file = Path("test") / f"{stem}.t.sol"
            test_function = f"test_{slug}"
            command = f"forge test --match-test {test_function} -vvv"
        else:
            # Default to Go integration test for non-EVM bridge
            pkg_dir = str(Path(bare_source).parent).replace("\\", "/") if bare_source else "./..."
            test_function = f"Test{pascal_slug}"
            command = f"GOTOOLCHAIN=local go test {pkg_dir} -run {test_function} -count=1 -v"
            if bare_source and bare_source.endswith(".go"):
                test_file = Path(bare_source).parent / f"{slug}_test.go"
            else:
                test_file = Path("harness") / f"{slug}_test.go"

    else:
        # Truly unresolvable harness type
        return ("", "unresolvable")

    # -----------------------------------------------------------------------
    # Determine harness_status by checking whether the test file exists
    # -----------------------------------------------------------------------
    # Resolve against workspace if available
    resolved_test: Path | None = None
    if workspace is not None and not test_file.is_absolute():
        resolved_test = workspace / test_file
    else:
        resolved_test = test_file if test_file.is_absolute() else None

    if resolved_test is not None and resolved_test.exists():
        harness_status = "command_ready"
    else:
        harness_status = "command_ready_test_missing"

    return (command, harness_status)


def _derive_harness_task(
    hit: dict[str, Any],
    ranked_row: dict[str, Any],
    language: str,
    task_index: int,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Derive a single harness task row from a detector hit + ranked attack class."""
    attack_class = str(ranked_row.get("attack_class") or "unknown")
    file_path = str(hit.get("file_path") or "")
    detector_slug = str(hit.get("detector_slug") or "")
    harness_type = _choose_harness_type(language, file_path, attack_class)
    template = _attack_class_goal(attack_class)
    harness_tmpl = _harness_template(harness_type, attack_class)
    task_id = f"HT-{task_index:03d}"

    restart_required = harness_type in (_HARNESS_TYPE_COSMOS, _HARNESS_TYPE_BRIDGE)
    multi_node_required = harness_type == _HARNESS_TYPE_COSMOS and any(
        kw in attack_class.lower() for kw in ("liveness", "consensus", "halt", "apphash", "fork")
    )

    # Lane C2: generate a concrete runnable command for this harness task.
    harness_command, harness_status = _generate_harness_command(
        harness_type=harness_type,
        task_id=task_id,
        detector_slug=detector_slug,
        attack_class=attack_class,
        source_file=file_path,
        workspace=workspace,
    )

    return {
        "schema": HARNESS_TASK_SCHEMA,
        "task_id": task_id,
        "detector_slug": detector_slug,
        "attack_class": attack_class,
        "harness_type": harness_type,
        "source_file": file_path,
        "harness_command": harness_command or None,
        "harness_status": harness_status,
        "attacker_setup": template["precondition"],
        "victim_setup": harness_tmpl["setup_notes"],
        "state_transition": template["state_transition"],
        "expected_impact": template["impact_probe"],
        "required_control_test": _attack_class_negative_control(attack_class),
        "production_path": harness_tmpl["production_path"],
        "fork_clarity": harness_tmpl["fork_clarity"],
        "invariant_check": harness_tmpl["invariant_check"],
        "restart_required": restart_required,
        "multi_node_required": multi_node_required,
        "negative_control": {
            "description": _attack_class_negative_control(attack_class),
            "assertion": "assert the non-attack path produces no harmful state change and that correct input is accepted",
        },
        "kill_conditions": _attack_class_kill_conditions(attack_class),
        "submission_posture": "NOT_SUBMIT_READY",
        "advisory_only": True,
        "proof_boundary": PROOF_BOUNDARY,
    }


def _build_harness_tasks(
    hit: dict[str, Any],
    ranked: list[dict[str, Any]],
    language: str,
    workspace: Path | None = None,
) -> list[dict[str, Any]]:
    """Build one harness task row per ranked attack class (up to 3)."""
    tasks: list[dict[str, Any]] = []
    for idx, row in enumerate(ranked[:3], start=1):
        tasks.append(_derive_harness_task(hit, row, language, idx, workspace=workspace))
    return tasks


def _build_action_graph(hit: dict[str, Any], ranked: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [
        {
            "id": "N-DET-001",
            "kind": "detector_signal",
            "actor": "auditor",
            "title": f"Confirm `{hit['detector_slug']}` at the source line",
            "evidence_required": "exact file:line citation, surrounding code, and whether the detector hit is real or a fixture/noise match",
            "source_refs": _uniq([hit.get("source_ref", ""), hit.get("file_path", "")]),
        }
    ]
    edges: list[dict[str, str]] = []
    for idx, row in enumerate(ranked[:3], start=1):
        attack_class = str(row.get("attack_class") or "unknown")
        template = _attack_class_goal(attack_class)
        prefix = f"N-AC-{idx:03d}"
        nodes.extend(
            [
                {
                    "id": f"{prefix}-GOAL",
                    "kind": "attacker_goal",
                    "actor": "attacker",
                    "attack_class": attack_class,
                    "title": template["attacker_goal"],
                    "evidence_required": "show the attacker can choose the relevant input/state without privileged access",
                    "ranker_score": row.get("score", 0),
                    "confidence": row.get("confidence", "low"),
                },
                {
                    "id": f"{prefix}-PRE",
                    "kind": "precondition",
                    "actor": "attacker",
                    "attack_class": attack_class,
                    "title": template["precondition"],
                    "evidence_required": "local source citation plus setup transaction or harness state that satisfies this precondition",
                },
                {
                    "id": f"{prefix}-STATE",
                    "kind": "state_transition",
                    "actor": "protocol",
                    "attack_class": attack_class,
                    "title": template["state_transition"],
                    "evidence_required": "runnable PoC or unit test showing the transition happens on the target path",
                },
                {
                    "id": f"{prefix}-IMPACT",
                    "kind": "impact_probe",
                    "actor": "protocol",
                    "attack_class": attack_class,
                    "title": template["impact_probe"],
                    "evidence_required": "before/after assertion mapped to an in-scope impact sentence and OOS review",
                },
            ]
        )
        edges.extend(
            [
                {"from": "N-DET-001", "to": f"{prefix}-GOAL", "relation": "suggests"},
                {"from": f"{prefix}-GOAL", "to": f"{prefix}-PRE", "relation": "requires"},
                {"from": f"{prefix}-PRE", "to": f"{prefix}-STATE", "relation": "enables"},
                {"from": f"{prefix}-STATE", "to": f"{prefix}-IMPACT", "relation": "must_prove"},
            ]
        )
    return {"nodes": nodes, "edges": edges}


def _build_proof_obligations(hit: dict[str, Any], ranked: list[dict[str, Any]], chain_candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    obligations: list[dict[str, Any]] = [
        {
            "id": "P-001",
            "kind": "source_confirmation",
            "title": "Confirm the detector hit on real target source",
            "required_evidence": [
                "exact source file and line",
                "surrounding function body",
                "why the hit is not generated fixture/test/vendor code",
            ],
            "source_refs": _uniq([hit.get("file_path", ""), hit.get("source_ref", "")]),
            "status": "open",
        },
        {
            "id": "P-002",
            "kind": "attacker_control",
            "title": "Prove an unvetted attacker controls the relevant input or call path",
            "required_evidence": [
                "actor model with attacker/victim/protocol roles",
                "privilege analysis for the flagged function",
                "setup transaction or harness state reaching the path",
            ],
            "status": "open",
        },
        {
            "id": "P-003",
            "kind": "state_and_impact",
            "title": "Demonstrate the state transition and map it to listed impact",
            "required_evidence": [
                "runnable local PoC or focused test",
                "before/after assertions on assets, roles, liveness, or accounting",
                "exact in-scope impact sentence and OOS/duplicate check",
            ],
            "status": "open",
        },
    ]
    next_id = 4
    for row in ranked[:3]:
        analogue_refs = [
            str(ref.get("source_ref") or "")
            for ref in row.get("analogue_refs", [])
            if isinstance(ref, dict)
        ]
        refs = analogue_refs + [
            str(ref.get("source_ref") or "")
            for ref in row.get("evidence_refs", [])
            if isinstance(ref, dict)
        ]
        obligations.append(
            {
                "id": f"P-{next_id:03d}",
                "kind": "corpus_analogue_review",
                "title": f"Review corpus analogues for `{row.get('attack_class')}`",
                "required_evidence": [
                    "which analogue predicate actually exists in target code",
                    "which analogue predicate is absent or killed",
                    "one concrete follow-up test or source-review question",
                ],
                "source_refs": _uniq(refs)[:5],
                "status": "open",
            }
        )
        next_id += 1
    for chain in chain_candidates[:2]:
        obligations.append(
            {
                "id": f"P-{next_id:03d}",
                "kind": "chain_candidate_bridge",
                "title": f"Prove or kill chained plan `{chain.get('chain_id')}`",
                "required_evidence": [
                    "material distinction from the base detector hit",
                    "causal bridge between primitives",
                    "all listed chain blockers resolved with local proof",
                ],
                "source_refs": _uniq(chain.get("source_refs", []) if isinstance(chain.get("source_refs"), list) else []),
                "status": "open",
            }
        )
        next_id += 1
    return obligations


def _load_chain_candidates(workspace: Path | None, hit: dict[str, Any], ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if workspace is None:
        return []
    path = workspace / "swarm" / "chained_attack_plans.json"
    raw = _load_json(path)
    plans = raw.get("plans") if isinstance(raw, dict) else None
    if not isinstance(plans, list):
        return []
    source_keys = set()
    for ref in (str(hit.get("file_path") or ""), str(hit.get("source_ref") or "")):
        source_keys.update(_source_anchor_keys(ref))
    detector_slug = str(hit.get("detector_slug") or "")
    if not detector_slug and not source_keys:
        return []
    out: list[dict[str, Any]] = []
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        if not _plan_has_strong_anchor(plan, detector_slug, source_keys):
            continue
        out.append(
            {
                "chain_id": plan.get("chain_id", ""),
                "status": plan.get("status", ""),
                "score": plan.get("score", 0),
                "composition_rationale": _safe_context(plan.get("composition_rationale", ""), max_chars=300),
                "blockers": plan.get("blockers", [])[:5] if isinstance(plan.get("blockers"), list) else [],
                "source_refs": plan.get("source_refs", [])[:5] if isinstance(plan.get("source_refs"), list) else [],
                "candidate_not_submit_ready": bool(plan.get("candidate_not_submit_ready", True)),
            }
        )
    return out[:3]


def _rank_attack_classes(repo_root: Path, hit: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    ranker = _load_ranker_module(repo_root)
    argv = [
        "--repo-root",
        str(repo_root),
        "--detector-slug",
        hit["detector_slug"],
        "--file-path",
        hit.get("file_path", ""),
        "--language",
        args.language or "",
        "--function-signature",
        args.function_signature or "",
        "--function-name",
        args.function_name or "",
        "--context",
        " ".join(
            part
            for part in (
                hit.get("snippet", ""),
                args.context or "",
            )
            if part
        ),
        "--top-n",
        str(max(1, int(args.top_n or 3))),
    ]
    payload = ranker.run(argv)
    return list(payload.get("ranked_attack_classes") or [])


def _build_hacker_questions(
    hit: dict[str, Any],
    ranked: list[dict[str, Any]],
    context_pack_id: str = "",
) -> list[dict[str, Any]]:
    return render_hacker_questions(
        ranked=ranked,
        function_name=str(hit.get("function_name") or hit.get("function") or ""),
        function_signature=str(hit.get("function_signature") or hit.get("signature") or ""),
        shape_hash=str(hit.get("shape_hash") or ""),
        file_path=str(hit.get("file_path") or ""),
        context_pack_id=context_pack_id,
        detector_slug=str(hit.get("detector_slug") or ""),
    )


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = Path(args.repo_root).expanduser().resolve()
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    hit = _select_hit(args, workspace)
    ranked = _rank_attack_classes(repo_root, hit, args)
    chain_candidates = _load_chain_candidates(workspace, hit, ranked)
    action_graph = _build_action_graph(hit, ranked)
    proof_obligations = _build_proof_obligations(hit, ranked, chain_candidates)
    hacker_questions = _build_hacker_questions(hit, ranked)
    harness_tasks = _build_harness_tasks(hit, ranked, args.language or "", workspace=workspace)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "harness_task_schema": HARNESS_TASK_SCHEMA,
        "hacker_question_schema": HACKER_QUESTION_SCHEMA,
        "advisory_only": True,
        "claim_scope": "attacker_worklist_only",
        "submission_posture": "NOT_SUBMIT_READY",
        "proof_boundary": PROOF_BOUNDARY,
        "workspace": workspace.name if workspace else "",
        "detector_hit": hit,
        "ranked_attack_classes": ranked,
        "hacker_questions": hacker_questions,
        "action_graph": action_graph,
        "chain_candidates": chain_candidates,
        "proof_obligations": proof_obligations,
        "harness_tasks": harness_tasks,
        "summary": {
            "ranked_attack_class_count": len(ranked),
            "action_node_count": len(action_graph["nodes"]),
            "hacker_question_count": len(hacker_questions),
            "proof_obligation_count": len(proof_obligations),
            "chain_candidate_count": len(chain_candidates),
            "harness_task_count": len(harness_tasks),
        },
        "limitations": [
            "Detector hit may be a false positive until source-confirmed.",
            "Attack-class ranking is corpus similarity, not proof strength.",
            "Action graph steps are hypotheses that must be killed or proved locally.",
            "No severity upgrade or submission readiness is implied.",
        ],
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    payload["context_pack_hash"] = digest
    payload["context_pack_id"] = f"{SCHEMA}:detector_hit_action_graph:{digest[:16]}"
    for question in payload.get("hacker_questions", []):
        if isinstance(question, dict):
            question["mcp_context_pack_id"] = payload["context_pack_id"]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--workspace", default="")
    parser.add_argument("--engage-report", default="")
    parser.add_argument("--hit-index", type=int, default=0)
    parser.add_argument("--detector-slug", default="")
    parser.add_argument("--severity", default="")
    parser.add_argument("--file-path", default="")
    parser.add_argument("--function-signature", default="")
    parser.add_argument("--function-name", default="")
    parser.add_argument("--language", default="")
    parser.add_argument("--snippet", default="")
    parser.add_argument("--context", default="")
    parser.add_argument("--top-n", type=int, default=3)
    parser.add_argument("--out", default="")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    # --json is an alias for --print-json (plan acceptance command uses it)
    parser.add_argument("--json", dest="print_json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = build_payload(args)
    if args.out:
        _write_json(Path(args.out).expanduser(), payload)
    if args.print_json or args.pretty or not args.out:
        print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=bool(args.pretty)))
    if args.out and not (args.print_json or args.pretty):
        print(f"[detector-hit-action-graph] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
