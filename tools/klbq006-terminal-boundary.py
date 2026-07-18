#!/usr/bin/env python3
"""Emit the KLBQ-006 terminal replay/applicability boundary packet."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.klbq_006_terminal_boundary.v1"
DEFAULT_DATE = "2026-05-05"
LIMITATION_ID = "KLBQ-006"
FINDING_ID = "30522"
DEFAULT_RENFT_ROOT = Path("/Users/wolf/audits/source-mirrors/re-nft-smart-contracts")
DEFAULT_PINNED_REF = "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291"
DEFAULT_HEAD_REF = "HEAD"
CANONICAL_LEAF = "safe-fallback-handler-setter-missing-address-guard"
PARENT_CLASS = "input-validation"
RUST_DETECTORS = (
    "r94_loop_safe_fallback_handler_setter_missing_address_guard",
    "setfallbackhandler_bypass_hijacks_rented_erc721_1155",
)
SOLIDITY_FILES = (
    "src/policies/Guard.sol",
    "src/policies/Factory.sol",
    "src/libraries/RentalConstants.sol",
    "test/unit/Guard/CheckTransaction.t.sol",
    "test/integration/prevented-exploits/SetCustomFallbackHandler.t.sol",
)
SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "out",
    "cache",
    ".cache",
    "dist",
    "build",
    "coverage",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_output_path(root: Path) -> Path:
    return root / "reports" / f"klbq_006_terminal_boundary_{DEFAULT_DATE}.json"


def default_docs_path(root: Path) -> Path:
    return root / "docs" / f"KLBQ_006_TERMINAL_BOUNDARY_{DEFAULT_DATE}.md"


def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
    if not (root / ".git").exists():
        return None
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _git_stdout(root: Path, args: list[str]) -> str | None:
    proc = _run_git(root, args)
    if proc is None or proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _git_text(root: Path, ref: str, rel_path: str) -> tuple[str, str]:
    proc = _run_git(root, ["show", f"{ref}:{rel_path}"])
    if proc is not None and proc.returncode == 0:
        return proc.stdout, "git_show"
    if ref in {"HEAD", "WORKTREE"}:
        path = root / rel_path
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace"), "worktree"
    return "", "missing"


def _count_source_files(root: Path, max_files: int) -> dict[str, Any]:
    counts = {"solidity": 0, "rust": 0, "other_source": 0}
    samples: dict[str, list[str]] = {"solidity": [], "rust": [], "other_source": []}
    considered = 0
    truncated = False
    if not root.exists():
        return {
            "root_exists": False,
            "files_considered": 0,
            "scan_truncated": False,
            "counts": counts,
            "samples": samples,
        }

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        for filename in filenames:
            suffix = Path(filename).suffix.lower()
            if suffix not in {".sol", ".rs", ".vy", ".cairo"}:
                continue
            considered += 1
            path = Path(dirpath) / filename
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = str(path)
            if suffix == ".sol":
                key = "solidity"
            elif suffix == ".rs":
                key = "rust"
            else:
                key = "other_source"
            counts[key] += 1
            if len(samples[key]) < 8:
                samples[key].append(rel)
            if considered >= max_files:
                truncated = True
                return {
                    "root_exists": True,
                    "files_considered": considered,
                    "scan_truncated": truncated,
                    "counts": counts,
                    "samples": samples,
                }

    return {
        "root_exists": True,
        "files_considered": considered,
        "scan_truncated": truncated,
        "counts": counts,
        "samples": samples,
    }


def _find_line_hits(text: str, patterns: tuple[str, ...], path: str, max_hits: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    regexes = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not any(regex.search(line) for regex in regexes):
            continue
        hits.append({"path": path, "line": line_no, "snippet": line.strip()[:220]})
        if len(hits) >= max_hits:
            break
    return hits


def _line_numbers_with(text: str, pattern: str) -> list[int]:
    regex = re.compile(pattern, re.IGNORECASE)
    return [idx for idx, line in enumerate(text.splitlines(), start=1) if regex.search(line)]


def _has_nearby_revert(text: str, anchor_pattern: str, window: int = 8) -> bool:
    lines = text.splitlines()
    anchors = _line_numbers_with(text, anchor_pattern)
    for anchor in anchors:
        start = max(1, anchor - window)
        end = min(len(lines), anchor + window)
        window_text = "\n".join(lines[start - 1 : end])
        if re.search(r"\brevert\b", window_text) and "UnauthorizedSelector" in window_text:
            return True
    return False


def probe_solidity_texts(texts: dict[str, str], *, ref: str, commit: str | None = None) -> dict[str, Any]:
    guard = texts.get("src/policies/Guard.sol", "")
    factory = texts.get("src/policies/Factory.sol", "")
    constants = texts.get("src/libraries/RentalConstants.sol", "")
    unit_test = texts.get("test/unit/Guard/CheckTransaction.t.sol", "")
    integration_test = texts.get("test/integration/prevented-exploits/SetCustomFallbackHandler.t.sol", "")
    tests = "\n".join([unit_test, integration_test])

    selector_pattern = r"setFallbackHandler|gnosis_safe_set_fallback_handler_selector|0xf08a0323"
    selector_declared = bool(re.search(selector_pattern, constants, re.IGNORECASE))
    guard_mentions_selector = bool(re.search(selector_pattern, guard, re.IGNORECASE))
    guard_reverts_selector = guard_mentions_selector and _has_nearby_revert(guard, selector_pattern)
    test_covers_revert = bool(
        re.search(r"SetFallbackHandler|setFallbackHandler|gnosis_safe_set_fallback_handler_selector", tests)
        and re.search(r"expectRevert|Reverts", tests)
    )
    factory_assigns_fallback_handler = bool(
        re.search(r"fallbackHandler", factory, re.IGNORECASE)
        and re.search(r"\bsetup\s*\(|ISafe", factory)
    )
    guard_checks_transactions = "_checkTransaction" in guard and "checkTransaction" in guard

    if guard_reverts_selector and test_covers_revert:
        classification = "source_aware_guard_rejects_setfallbackhandler_with_test_anchor"
    elif guard_reverts_selector:
        classification = "source_aware_guard_rejects_setfallbackhandler"
    elif guard_checks_transactions and factory_assigns_fallback_handler:
        classification = "source_aware_guard_boundary_missing_direct_setfallbackhandler_revert"
    elif guard_checks_transactions:
        classification = "source_aware_guard_present_selector_state_unknown"
    else:
        classification = "source_aware_anchor_absent_or_unknown"

    anchors = []
    for rel_path, text in texts.items():
        if not text:
            continue
        anchors.extend(
            _find_line_hits(
                text,
                (
                    r"setFallbackHandler",
                    r"gnosis_safe_set_fallback_handler_selector",
                    r"0xf08a0323",
                    r"fallbackHandler",
                    r"checkTransaction",
                ),
                rel_path,
                max_hits=8,
            )
        )

    return {
        "ref": ref,
        "commit": commit,
        "files_examined": sorted(path for path, text in texts.items() if text),
        "classification": classification,
        "signals": {
            "guard_file_present": bool(guard),
            "factory_file_present": bool(factory),
            "guard_checks_transactions": guard_checks_transactions,
            "factory_assigns_fallback_handler_to_safe_setup": factory_assigns_fallback_handler,
            "selector_constant_declared": selector_declared,
            "guard_mentions_setfallbackhandler_selector": guard_mentions_selector,
            "guard_reverts_setfallbackhandler_selector": guard_reverts_selector,
            "test_covers_setfallbackhandler_revert": test_covers_revert,
        },
        "claim_limits": {
            "source_aware_anchor_probe_only": True,
            "executable_solidity_replay_performed": False,
            "exploit_proof_allowed": False,
            "verification_claim_allowed": False,
        },
        "anchors": anchors[:40],
    }


def _source_probe(root: Path, ref: str) -> dict[str, Any]:
    commit = _git_stdout(root, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    commit_info = None
    if commit:
        raw = _git_stdout(root, ["show", "--no-patch", "--format=%H%n%cI%n%s", commit])
        if raw:
            parts = raw.splitlines()
            commit_info = {
                "commit": parts[0] if len(parts) > 0 else commit,
                "committed_at": parts[1] if len(parts) > 1 else None,
                "subject": parts[2] if len(parts) > 2 else None,
            }
    texts = {rel_path: _git_text(root, ref, rel_path)[0] for rel_path in SOLIDITY_FILES}
    probe = probe_solidity_texts(texts, ref=ref, commit=commit)
    probe["commit_info"] = commit_info
    return probe


def _rust_detector_boundary(root: Path, profile: dict[str, Any]) -> dict[str, Any]:
    counts = profile.get("counts") if isinstance(profile.get("counts"), dict) else {}
    sol_count = int(counts.get("solidity") or 0)
    rust_count = int(counts.get("rust") or 0)
    if sol_count > 0 and rust_count == 0:
        state = "terminal_inapplicable"
        reason = "source_language_mismatch_solidity_root_without_rust_files"
    elif rust_count > 0:
        state = "rust_source_present_not_terminal"
        reason = "rust_files_present_runner_applicability_not_blocked_by_language"
    else:
        state = "source_root_empty_or_missing"
        reason = "no_supported_source_files_found"

    return {
        "state": state,
        "reason": reason,
        "source_root": str(root),
        "detectors": list(RUST_DETECTORS),
        "rust_detect_failure_signature": f"[err] no Rust files found under {root}",
        "absence_interpretation": (
            "Rust detector absence on this Solidity mirror is not a pass, not a negative replay, "
            "not precision evidence, and not exploit proof."
        ),
        "can_interpret_detector_absence_as_clean_result": False,
        "claim_limits": {
            "pass_claim_allowed": False,
            "exploit_proof_allowed": False,
            "verification_claim_allowed": False,
            "promotion_ready": False,
        },
        "reproduce_commands": [
            (
                f"python3 tools/rust-detect.py {root} --only "
                "r94_loop_safe_fallback_handler_setter_missing_address_guard "
                "--log /tmp/klbq006_renft_r94.log"
            ),
            (
                f"python3 tools/rust-detect.py {root} --only "
                "setfallbackhandler_bypass_hijacks_rented_erc721_1155 "
                "--log /tmp/klbq006_renft_sibling.log"
            ),
        ],
    }


def build_report(
    *,
    renft_root: Path,
    pinned_ref: str = DEFAULT_PINNED_REF,
    head_ref: str = DEFAULT_HEAD_REF,
    max_files: int = 100_000,
) -> dict[str, Any]:
    root = renft_root.resolve()
    language_profile = _count_source_files(root, max_files=max_files)
    boundary = _rust_detector_boundary(root, language_profile)
    probes = [_source_probe(root, pinned_ref)]
    head_probe = _source_probe(root, head_ref)
    if head_probe.get("commit") != probes[0].get("commit") or head_ref != pinned_ref:
        probes.append(head_probe)

    return {
        "schema": SCHEMA,
        "date": DEFAULT_DATE,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "limitation_id": LIMITATION_ID,
        "finding_id": FINDING_ID,
        "source_root": str(root),
        "pinned_ref": pinned_ref,
        "head_ref": head_ref,
        "status": "terminal_rust_inapplicability_recorded_klbq_open",
        "closed_benefit": (
            "Closes the ambiguity that Rust detector absence on the pinned Solidity reNFT mirror "
            "could be treated as either a pass or exploit proof."
        ),
        "klbq_006_closed": False,
        "promotion_ready": False,
        "verification_claim_allowed": False,
        "source_language_profile": language_profile,
        "rust_detector_boundary": boundary,
        "taxonomy_reconciliation": {
            "canonical_leaf_family": CANONICAL_LEAF,
            "parent_class": PARENT_CLASS,
            "preferred_accounting_key": CANONICAL_LEAF,
            "input_validation_usage": "parent_or_alias_only",
            "repo_wide_metadata_updated": False,
            "closure_posture": "open",
            "promotion_posture": "hold",
        },
        "source_aware_solidity_probe": {
            "probe_type": "static_anchor_probe",
            "executable_replay_performed": False,
            "probes": probes,
        },
        "remaining_blockers": [
            "Exact Solodit #30522 GitHub blob/file-line anchor is still absent.",
            "No executable Solidity replay or Foundry proof has been run from the exact #30522 source citation.",
            "Rust detector absence on the Solidity-only mirror is terminally inapplicable and cannot be counted as a pass.",
            "No ground-truthed real-target clean corpus exists for this detector family.",
            "Repo-wide metadata still has broad input-validation entries outside this scoped packet.",
        ],
        "exact_next_commands": [
            (
                "python3 tools/klbq006-terminal-boundary.py "
                f"--renft-root {root} --pinned-ref {pinned_ref} "
                "--out reports/klbq_006_terminal_boundary_2026-05-05.json "
                "--docs docs/KLBQ_006_TERMINAL_BOUNDARY_2026-05-05.md"
            ),
            f"git -C {root} show --no-patch --format='%H %cI %s' {pinned_ref}",
            (
                f"git -C {root} grep -n "
                "\"setFallbackHandler\\|fallbackHandler\\|checkTransaction\\|f08a0323\" "
                f"{pinned_ref} -- \"*.sol\""
            ),
            (
                f"git -C {root} grep -n "
                "\"setFallbackHandler\\|fallbackHandler\\|checkTransaction\\|f08a0323\" "
                "HEAD -- \"*.sol\""
            ),
            (
                f"python3 tools/rust-detect.py {root} --only "
                "r94_loop_safe_fallback_handler_setter_missing_address_guard "
                "--log /tmp/klbq006_renft_r94.log"
            ),
            (
                f"python3 tools/rust-detect.py {root} --only "
                "setfallbackhandler_bypass_hijacks_rented_erc721_1155 "
                "--log /tmp/klbq006_renft_sibling.log"
            ),
            (
                f"forge test --root {root} --match-path test/unit/Guard/CheckTransaction.t.sol "
                "--match-test test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv"
            ),
        ],
        "do_not_claim": [
            "Do not claim KLBQ-006 closed.",
            "Do not claim Rust detector absence on Solidity is a pass.",
            "Do not claim exploit proof from this boundary packet.",
            "Do not claim exact #30522 replay until a Solidity-capable replay uses the exact cited source anchor.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    boundary = report["rust_detector_boundary"]
    taxonomy = report["taxonomy_reconciliation"]
    probes = report["source_aware_solidity_probe"]["probes"]
    lines = [
        "# KLBQ-006 Terminal Boundary",
        "",
        f"Date: {report['date']}",
        f"Status: {report['status']}",
        f"Source root: `{report['source_root']}`",
        "",
        "## Decision",
        "",
        (
            "Record Rust detector replay on the local reNFT mirror as "
            f"`{boundary['state']}` because `{boundary['reason']}`."
        ),
        "",
        boundary["absence_interpretation"],
        "",
        f"Closed benefit: {report['closed_benefit']}",
        "",
        "KLBQ-006 remains open.",
        "",
        "## Taxonomy",
        "",
        f"- Canonical leaf family: `{taxonomy['canonical_leaf_family']}`",
        f"- Parent class: `{taxonomy['parent_class']}`",
        f"- Preferred accounting key: `{taxonomy['preferred_accounting_key']}`",
        f"- Repo-wide metadata updated: `{taxonomy['repo_wide_metadata_updated']}`",
        "",
        "## Solidity Anchor Probe",
        "",
        "| Ref | Commit | Classification | Guard Rejects setFallbackHandler | Test Anchor |",
        "| --- | --- | --- | --- | --- |",
    ]
    for probe in probes:
        signals = probe["signals"]
        commit = probe.get("commit") or "-"
        lines.append(
            "| {ref} | {commit} | {classification} | {rejects} | {test} |".format(
                ref=probe["ref"],
                commit=commit,
                classification=probe["classification"],
                rejects=signals["guard_reverts_setfallbackhandler_selector"],
                test=signals["test_covers_setfallbackhandler_revert"],
            )
        )

    lines.extend(["", "## Remaining Blockers", ""])
    for blocker in report["remaining_blockers"]:
        lines.append(f"- {blocker}")

    lines.extend(["", "## Exact Next Commands", ""])
    for command in report["exact_next_commands"]:
        lines.extend(["```bash", command, "```", ""])

    lines.extend(["## Do Not Claim", ""])
    for claim in report["do_not_claim"]:
        lines.append(f"- {claim}")
    return "\n".join(lines).rstrip() + "\n"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--renft-root", type=Path, default=DEFAULT_RENFT_ROOT)
    parser.add_argument("--pinned-ref", default=DEFAULT_PINNED_REF)
    parser.add_argument("--head-ref", default=DEFAULT_HEAD_REF)
    parser.add_argument("--max-files", type=int, default=100_000)
    parser.add_argument("--out", type=Path, default=default_output_path(root))
    parser.add_argument("--docs", type=Path, default=default_docs_path(root))
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        renft_root=args.renft_root,
        pinned_ref=args.pinned_ref,
        head_ref=args.head_ref,
        max_files=args.max_files,
    )
    _write_json(args.out, report)
    _write_text(args.docs, render_markdown(report))
    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
