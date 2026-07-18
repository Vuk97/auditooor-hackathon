#!/usr/bin/env python3
"""Materialize a small, high-value Swival Rust fixture subset.

The output is deliberately hermetic and advisory. Generated crates model the
reported vulnerable/clean predicates closely enough for syntax/readiness smoke,
but they do not prove the original stdlib bug, severity, or project impact.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "auditooor.rust_swival_selected_fixture_materialization.v1"
DEFAULT_INDEX = Path(".audit_logs") / "rust_corpus_mining" / "rust_corpus_index.json"
DEFAULT_OUT_JSON = Path(".audit_logs") / "rust_corpus_mining" / "swival_selected_fixture_materialization.json"
DEFAULT_OUT_MD = Path(".audit_logs") / "rust_corpus_mining" / "swival_selected_fixture_materialization.md"


TEMPLATE_IDS = (
    "060-public-globals-allow-arbitrary-pointer-dereference",
    "071-shared-slice-reference-over-mutable-userspace",
    "020-remove-dir-all-follows-dot-entries",
    "111-timeout-can-exceed-waiter-counter",
    "142-sockaddr-storage-too-small-for-ipv6",
    "045-unchecked-exponent-digit-accumulation",
)


@dataclass(frozen=True)
class FixtureTemplate:
    family_reason: str
    lib_rs: str
    next_command: str


def _cargo_toml(crate_name: str) -> str:
    return f"""[package]
name = "{crate_name}"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"""


TEMPLATES: dict[str, FixtureTemplate] = {
    "060-public-globals-allow-arbitrary-pointer-dereference": FixtureTemplate(
        family_reason="High unsafe-memory boundary: public mutable global controls later unsafe dereference",
        next_command="cargo test --manifest-path test_fixtures/swival_selected/060-public-globals-allow-arbitrary-pointer-dereference/Cargo.toml",
        lib_rs=r'''//! Hermetic Swival fixture skeleton.
//! Boundary: models the public-global-to-safe-wrapper predicate only; not proof of stdlib impact.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub mod vulnerable {
    use super::*;

    pub mod globals {
        use super::*;
        pub static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        pub static BOOT_SERVICES_FLAG: AtomicBool = AtomicBool::new(false);
    }

    #[repr(C)]
    pub struct FakeSystemTable {
        pub boot_services: *mut c_void,
    }

    pub fn boot_services() -> Option<*mut c_void> {
        if !globals::BOOT_SERVICES_FLAG.load(Ordering::Acquire) {
            return None;
        }
        let table = globals::SYSTEM_TABLE.load(Ordering::Acquire) as *const FakeSystemTable;
        Some(unsafe { (*table).boot_services })
    }
}

pub mod clean {
    use super::*;

    mod globals {
        use super::*;
        pub static SYSTEM_TABLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        pub static BOOT_SERVICES_FLAG: AtomicBool = AtomicBool::new(false);
    }

    #[repr(C)]
    pub struct FakeSystemTable {
        pub boot_services: *mut c_void,
    }

    pub unsafe fn init_for_fixture(table: *mut c_void) {
        globals::SYSTEM_TABLE.store(table, Ordering::Release);
        globals::BOOT_SERVICES_FLAG.store(true, Ordering::Release);
    }

    pub fn boot_services() -> Option<*mut c_void> {
        if !globals::BOOT_SERVICES_FLAG.load(Ordering::Acquire) {
            return None;
        }
        let table = globals::SYSTEM_TABLE.load(Ordering::Acquire) as *const FakeSystemTable;
        Some(unsafe { (*table).boot_services })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_public_global_can_feed_safe_wrapper() {
        let mut table = vulnerable::FakeSystemTable { boot_services: 0xdead_beefusize as *mut c_void };
        vulnerable::globals::BOOT_SERVICES_FLAG.store(true, Ordering::Release);
        vulnerable::globals::SYSTEM_TABLE.store(&mut table as *mut _ as *mut c_void, Ordering::Release);
        assert_eq!(vulnerable::boot_services().unwrap() as usize, 0xdead_beef);
    }

    #[test]
    fn clean_model_requires_unsafe_internal_initialization() {
        let mut table = clean::FakeSystemTable { boot_services: 0xcafe_babeusize as *mut c_void };
        unsafe { clean::init_for_fixture(&mut table as *mut _ as *mut c_void) };
        assert_eq!(clean::boot_services().unwrap() as usize, 0xcafe_babe);
    }
}
''',
    ),
    "071-shared-slice-reference-over-mutable-userspace": FixtureTemplate(
        family_reason="High unsafe-memory boundary: user memory converted into ordinary shared slice references",
        next_command="cargo test --manifest-path test_fixtures/swival_selected/071-shared-slice-reference-over-mutable-userspace/Cargo.toml",
        lib_rs=r'''//! Hermetic Swival fixture skeleton.
//! Boundary: models reference construction shape only; no UB or exploit proof is claimed.

pub mod vulnerable {
    pub unsafe fn iter_model(ptr: *const u8, len: usize) -> std::slice::Iter<'static, u8> {
        std::slice::from_raw_parts(ptr, len).iter()
    }
}

pub mod clean {
    use std::marker::PhantomData;

    pub struct UserRef<T: ?Sized> {
        ptr: *const T,
    }

    pub struct Iter<'a> {
        ptr: *const u8,
        len: usize,
        _marker: PhantomData<&'a UserRef<u8>>,
    }

    impl<'a> Iter<'a> {
        pub fn new(ptr: *const u8, len: usize) -> Self {
            Self { ptr, len, _marker: PhantomData }
        }
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = *const UserRef<u8>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.len == 0 {
                return None;
            }
            let ptr = self.ptr;
            self.ptr = self.ptr.wrapping_add(1);
            self.len -= 1;
            Some(ptr as *const UserRef<u8>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_builds_slice_iterator_over_raw_user_memory() {
        let data = Box::leak(vec![1u8, 2, 3].into_boxed_slice());
        let collected: Vec<u8> = unsafe { vulnerable::iter_model(data.as_ptr(), data.len()) }.copied().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn clean_model_iterates_raw_addresses_without_materializing_u8_refs() {
        let data = [1u8, 2, 3];
        let got: Vec<usize> = clean::Iter::new(data.as_ptr(), data.len()).map(|p| p as usize).collect();
        assert_eq!(got.len(), 3);
        assert_eq!(got[1] - got[0], 1);
    }
}
''',
    ),
    "020-remove-dir-all-follows-dot-entries": FixtureTemplate(
        family_reason="High integer/path-boundary logic: recursive delete accepts dot entries",
        next_command="cargo test --manifest-path test_fixtures/swival_selected/020-remove-dir-all-follows-dot-entries/Cargo.toml",
        lib_rs=r'''//! Hermetic Swival fixture skeleton.
//! Boundary: models traversal decisions only; it never deletes files.

#[derive(Clone)]
pub struct DirEntry {
    name: &'static str,
    is_dir: bool,
}

fn mock_readdir() -> Vec<DirEntry> {
    vec![
        DirEntry { name: ".", is_dir: true },
        DirEntry { name: "..", is_dir: true },
        DirEntry { name: "child", is_dir: true },
    ]
}

pub mod vulnerable {
    use super::*;

    pub fn traversal_targets() -> Vec<&'static str> {
        mock_readdir().into_iter().filter(|entry| entry.is_dir).map(|entry| entry.name).collect()
    }
}

pub mod clean {
    use super::*;

    pub fn traversal_targets() -> Vec<&'static str> {
        mock_readdir()
            .into_iter()
            .filter(|entry| entry.is_dir)
            .filter(|entry| entry.name != "." && entry.name != "..")
            .map(|entry| entry.name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_reaches_dot_entries() {
        assert_eq!(vulnerable::traversal_targets(), vec![".", "..", "child"]);
    }

    #[test]
    fn clean_model_filters_dot_entries_before_recursion() {
        assert_eq!(clean::traversal_targets(), vec!["child"]);
    }
}
''',
    ),
    "111-timeout-can-exceed-waiter-counter": FixtureTemplate(
        family_reason="High integer/accounting boundary: timeout counter can exceed waiter counter",
        next_command="cargo test --manifest-path test_fixtures/swival_selected/111-timeout-can-exceed-waiter-counter/Cargo.toml",
        lib_rs=r'''//! Hermetic Swival fixture skeleton.
//! Boundary: models counter reconciliation only; it is not an executable Xous Condvar proof.

pub mod vulnerable {
    #[derive(Default)]
    pub struct Counters {
        pub counter: usize,
        pub timed_out: usize,
    }

    impl Counters {
        pub fn notify_selected_before_delivery(&mut self) {
            self.counter = self.counter.saturating_sub(1);
        }

        pub fn late_timeout(&mut self) {
            self.timed_out += 1;
        }

        pub fn impossible_state(&self) -> bool {
            self.timed_out > self.counter
        }
    }
}

pub mod clean {
    #[derive(Default)]
    pub struct Counters {
        pub counter: usize,
        pub timed_out: usize,
    }

    impl Counters {
        pub fn reconcile_timeouts(&mut self) {
            self.counter = self.counter.saturating_sub(self.timed_out);
            self.timed_out = 0;
        }

        pub fn confirmed_notify(&mut self, notified: usize) {
            self.counter = self.counter.saturating_sub(notified);
        }

        pub fn impossible_state(&self) -> bool {
            self.timed_out > self.counter
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_can_record_more_timeouts_than_waiters() {
        let mut counters = vulnerable::Counters { counter: 1, timed_out: 0 };
        counters.notify_selected_before_delivery();
        counters.late_timeout();
        assert!(counters.impossible_state());
    }

    #[test]
    fn clean_model_uses_saturating_reconciliation() {
        let mut counters = clean::Counters { counter: 0, timed_out: 1 };
        counters.reconcile_timeouts();
        counters.confirmed_notify(1);
        assert!(!counters.impossible_state());
        assert_eq!(counters.counter, 0);
    }
}
''',
    ),
    "142-sockaddr-storage-too-small-for-ipv6": FixtureTemplate(
        family_reason="High integer/layout boundary: generic socket storage smaller than IPv6 address",
        next_command="cargo test --manifest-path test_fixtures/swival_selected/142-sockaddr-storage-too-small-for-ipv6/Cargo.toml",
        lib_rs=r'''//! Hermetic Swival fixture skeleton.
//! Boundary: layout-size smoke only; it does not run SOLID networking APIs.

pub mod vulnerable {
    #[repr(C)]
    pub struct SockaddrStorage {
        s2_len: u8,
        ss_family: u8,
        s2_data1: [i8; 2],
        s2_data2: [u32; 3],
    }

    pub fn storage_size() -> usize {
        std::mem::size_of::<SockaddrStorage>()
    }
}

pub mod clean {
    #[repr(C)]
    pub struct SockaddrStorage {
        s2_len: u8,
        ss_family: u8,
        s2_data1: [i8; 2],
        s2_data2: [u32; 6],
    }

    pub fn storage_size() -> usize {
        std::mem::size_of::<SockaddrStorage>()
    }
}

#[repr(C)]
pub struct SockaddrIn6 {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

pub fn ipv6_size() -> usize {
    std::mem::size_of::<SockaddrIn6>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_storage_is_smaller_than_ipv6() {
        assert!(vulnerable::storage_size() < ipv6_size());
    }

    #[test]
    fn clean_model_storage_can_hold_ipv6() {
        assert!(clean::storage_size() >= ipv6_size());
    }
}
''',
    ),
    "045-unchecked-exponent-digit-accumulation": FixtureTemplate(
        family_reason="Medium recurring parser-boundary replay seed: saturating multiply followed by unchecked add",
        next_command="cargo test --manifest-path test_fixtures/swival_selected/045-unchecked-exponent-digit-accumulation/Cargo.toml",
        lib_rs=r'''//! Hermetic Swival replay skeleton.
//! Boundary: arithmetic parser model only; it does not import compiler-builtins/libm.

pub mod vulnerable {
    pub fn accumulate_release_model(digits: &[u8]) -> u32 {
        let mut pexp = 0u32;
        for &b in digits {
            pexp = pexp.saturating_mul(10);
            pexp = pexp.wrapping_add((b - b'0') as u32);
        }
        pexp
    }

    pub fn accumulate_checked_model(digits: &[u8]) -> Option<u32> {
        let mut pexp = 0u32;
        for &b in digits {
            pexp = pexp.saturating_mul(10);
            pexp = pexp.checked_add((b - b'0') as u32)?;
        }
        Some(pexp)
    }
}

pub mod clean {
    pub fn accumulate(digits: &[u8]) -> u32 {
        let mut pexp = 0u32;
        for &b in digits {
            pexp = pexp.saturating_mul(10);
            pexp = pexp.saturating_add((b - b'0') as u32);
        }
        pexp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_model_wraps_or_fails_after_saturating_mul() {
        let digits = b"4294967296";
        assert_eq!(vulnerable::accumulate_checked_model(digits), None);
        assert!(vulnerable::accumulate_release_model(digits) < 4_294_967_290);
    }

    #[test]
    fn clean_model_saturates_after_overflow_boundary() {
        assert_eq!(clean::accumulate(b"4294967296"), u32::MAX);
    }
}
''',
    ),
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _records_by_id(index_path: Path) -> dict[str, dict[str, Any]]:
    payload = _read_json(index_path)
    records = payload.get("records")
    if not isinstance(records, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for record in records:
        if isinstance(record, dict) and isinstance(record.get("item_id"), str):
            out[record["item_id"]] = record
    return out


def _crate_name(item_id: str) -> str:
    return "swival_" + item_id.replace("-", "_")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _smoke(crate_dir: Path, run_smoke: bool) -> dict[str, Any]:
    command = ["cargo", "test", "--manifest-path", str(crate_dir / "Cargo.toml")]
    if not run_smoke:
        return {"command": command, "status": "not_run", "returncode": None}
    proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return {
        "command": command,
        "status": "passed" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
    }


def _selected_records(records: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    not_selected: list[dict[str, Any]] = []
    for record in records.values():
        severity = str(record.get("corpus_severity") or "")
        family = str(record.get("family") or "")
        if severity == "High" or family == "rust_decode_or_parser_boundary":
            selected.append(record)
        else:
            not_selected.append(
                {
                    "item_id": record.get("item_id", ""),
                    "corpus_severity": severity,
                    "family": family,
                    "reason": "deferred_lower_priority_non_high_non_parser_family",
                }
            )

    def sort_key(record: dict[str, Any]) -> tuple[int, int, str]:
        severity_rank = {"High": 0, "Medium": 1, "Low": 2}.get(str(record.get("corpus_severity") or ""), 9)
        family_rank = {
            "rust_unsafe_memory_boundary": 0,
            "rust_integer_or_length_boundary": 1,
            "rust_decode_or_parser_boundary": 2,
        }.get(str(record.get("family") or ""), 9)
        return (severity_rank, family_rank, str(record.get("item_id") or ""))

    return sorted(selected, key=sort_key), sorted(not_selected, key=lambda row: str(row["item_id"]))


def _brief_next_command(row: dict[str, Any]) -> str:
    source = row["source_pointers"][0] if row["source_pointers"] else "<source-md>"
    poc = row["poc_pointers"][0] if row["poc_pointers"] else "<poc-or-fixture>"
    return f"source-read {source}; extract or adapt {poc}; only then create a crate-specific cargo smoke command"


def _task_readiness_md(row: dict[str, Any]) -> str:
    return f"""# {row['item_id']}

- title: {row['title']}
- corpus severity: {row['corpus_severity']}
- family: {row['family']}
- materialization: {row['materialization_kind']}
- proof boundary: organized replay/fixture task brief only; not original stdlib proof, severity proof, or project-impact proof
- source: {', '.join(row['source_pointers'])}
- PoC pointers: {', '.join(row['poc_pointers'])}
- patch pointers: {', '.join(row['patch_pointers'][:3])}{' ...' if len(row['patch_pointers']) > 3 else ''}
- fixture task artifact: {row['fixture_task_artifact']}
- route evidence artifact: {row['route_evidence_artifact']}

## Blockers Before Executable Proof

- Build a source-specific vulnerable/clean Rust crate or replay harness from the cited writeup/PoC.
- Confirm the harness executes locally and records stdout/stderr.
- Bind the predicate to a project/runtime impact path before any submission framing.

## Next Commands

```bash
{row['next_command']}
```
"""


def _readiness_md(row: dict[str, Any]) -> str:
    return f"""# {row['item_id']}

- title: {row['title']}
- corpus severity: {row['corpus_severity']}
- family: {row['family']}
- materialization: {row['materialization_kind']}
- proof boundary: hermetic vulnerable/clean skeleton only; not original stdlib proof, severity proof, or project-impact proof
- source: {', '.join(row['source_pointers'])}
- PoC pointers: {', '.join(row['poc_pointers'])}
- patch pointers: {', '.join(row['patch_pointers'][:3])}{' ...' if len(row['patch_pointers']) > 3 else ''}
- fixture task artifact: {row['fixture_task_artifact']}
- route evidence artifact: {row['route_evidence_artifact']}

## Next Commands

```bash
{row['next_command']}
```
"""


def materialize(workspace: Path, *, index_path: Path, run_smoke: bool) -> dict[str, Any]:
    records = _records_by_id(index_path)
    out_root = workspace / "test_fixtures" / "swival_selected"
    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    selected_records, deferred = _selected_records(records)
    fixture_task_artifact = str(workspace / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_fixture_tasks.json")
    route_evidence_artifact = str(workspace / ".audit_logs" / "rust_corpus_mining" / "rust_swival_route_evidence.json")

    for record in selected_records:
        item_id = str(record.get("item_id") or "")
        template = TEMPLATES.get(item_id)
        if not item_id:
            skipped.append({"item_id": "", "blocker": "missing_item_id"})
            continue

        row_dir = out_root / item_id
        materialization_kind = (
            "replay_task_brief_and_fixture_skeleton"
            if item_id == "045-unchecked-exponent-digit-accumulation"
            else "vulnerable_clean_fixture_skeleton"
            if template
            else "replay_or_fixture_task_brief"
        )
        row = {
            "item_id": item_id,
            "title": str(record.get("title") or item_id),
            "corpus_severity": str(record.get("corpus_severity") or "unknown"),
            "family": str(record.get("family") or "unknown"),
            "family_reason": template.family_reason if template else "Selected by High severity or recurring parser/decode family; brief only because no safe local skeleton template is available.",
            "materialization_kind": materialization_kind,
            "crate_dir": str(row_dir) if template else "",
            "task_dir": str(row_dir),
            "cargo_toml": str(row_dir / "Cargo.toml") if template else "",
            "lib_rs": str(row_dir / "src" / "lib.rs") if template else "",
            "readiness_md": str(row_dir / "README.md"),
            "manifest": str(row_dir / "fixture_manifest.json") if template else str(row_dir / "task_manifest.json"),
            "source_pointers": record.get("source_pointers") or [],
            "patch_pointers": record.get("patch_pointers") or [],
            "poc_pointers": record.get("poc_pointers") or record.get("fixture_pointers") or [],
            "fixture_task_artifact": fixture_task_artifact,
            "route_evidence_artifact": route_evidence_artifact,
            "next_command": template.next_command if template else "",
            "proof_status": "not_proved",
            "coverage_claim": "syntax_and_organization_smoke_only",
            "submission_posture": "NOT_SUBMIT_READY",
            "promotion_allowed": False,
            "blockers": [
                "hermetic_model_not_original_stdlib_execution",
                "no_project_impact_binding",
                "no_submission_proof_claim",
            ],
        }
        if template:
            _write(row_dir / "Cargo.toml", _cargo_toml(_crate_name(item_id)))
            _write(row_dir / "src" / "lib.rs", template.lib_rs)
            row["smoke"] = _smoke(row_dir, run_smoke)
            _write(row_dir / "README.md", _readiness_md(row))
            _write(row_dir / "fixture_manifest.json", json.dumps(row, indent=2, sort_keys=True) + "\n")
        else:
            row["next_command"] = _brief_next_command(row)
            row["blockers"].extend(
                [
                    "no_safe_local_skeleton_template",
                    "requires_source_specific_harness_extraction",
                ]
            )
            row["smoke"] = {
                "command": [],
                "status": "organized_task_brief",
                "returncode": None,
                "checks": ["README.md exists", "task_manifest.json exists", "source/patch/poc pointers retained"],
            }
            _write(row_dir / "README.md", _task_readiness_md(row))
            _write(row_dir / "task_manifest.json", json.dumps(row, indent=2, sort_keys=True) + "\n")
        rows.append(row)

    status_counts: dict[str, int] = {}
    for row in rows:
        status = str(row["smoke"]["status"])
        status_counts[status] = status_counts.get(status, 0) + 1

    payload = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "input_index": str(index_path),
        "selection_policy": "Materialize every High Swival row plus the full recurring rust_decode_or_parser_boundary family; use executable skeletons only where a safe local template exists, otherwise emit task briefs.",
        "selected_ids": [str(record.get("item_id") or "") for record in selected_records],
        "created_count": len(rows),
        "skipped_count": len(skipped),
        "deferred_count": len(deferred),
        "smoke_status_counts": dict(sorted(status_counts.items())),
        "proof_claims": 0,
        "coverage_claim": "syntax_and_organization_smoke_only",
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "rows": rows,
        "skipped": skipped,
        "deferred": deferred,
    }
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Swival Selected Fixture Materialization",
        "",
        f"_Schema: `{payload['schema']}`_",
        "",
        "These artifacts are hermetic vulnerable/clean skeletons or replay task briefs.",
        "They validate syntax and organization only; they do not prove the original stdlib findings, severity, exploitability, or project impact.",
        "",
        "## Counts",
        "",
        f"- selected ids: `{len(payload['selected_ids'])}`",
        f"- created artifacts: `{payload['created_count']}`",
        f"- skipped selected rows: `{payload['skipped_count']}`",
        f"- deferred lower-priority rows: `{payload['deferred_count']}`",
        f"- proof claims made: `{payload['proof_claims']}`",
        f"- smoke status counts: `{json.dumps(payload['smoke_status_counts'], sort_keys=True)}`",
        "",
        "## Created Rows",
        "",
        "| ID | Severity | Family | Kind | Smoke | Paths |",
        "|---|---|---|---|---|---|",
    ]
    for row in payload["rows"]:
        row_paths = [p for p in (row.get("cargo_toml"), row.get("lib_rs"), row.get("manifest"), row.get("readiness_md")) if p]
        paths = "<br>".join(row_paths)
        lines.append(
            f"| `{row['item_id']}` | `{row['corpus_severity']}` | `{row['family']}` | "
            f"`{row['materialization_kind']}` | `{row['smoke']['status']}` | {paths} |"
        )
    lines.extend(["", "## Next Commands", ""])
    for row in payload["rows"]:
        lines.append(f"- `{row['item_id']}`: `{row['next_command']}`")
    if payload["skipped"]:
        lines.extend(["", "## Skipped", ""])
        for row in payload["skipped"]:
            lines.append(f"- `{row['item_id']}`: `{row['blocker']}`")
    if payload["deferred"]:
        lines.extend(["", "## Deferred Lower-Priority Rows", ""])
        lines.append("Rows below were not materialized because continuing into them would dilute this pass beyond High severity and the selected recurring parser/decode family.")
        for row in payload["deferred"][:40]:
            lines.append(f"- `{row['item_id']}`: `{row['corpus_severity']}` `{row['family']}` `{row['reason']}`")
        if len(payload["deferred"]) > 40:
            lines.append(f"- ... `{len(payload['deferred']) - 40}` additional deferred rows recorded in JSON")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--index", type=Path, default=None)
    parser.add_argument("--no-smoke", action="store_true", help="Write artifacts without running cargo test")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    index_path = (args.index or (workspace / DEFAULT_INDEX)).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-swival-selected-fixture-materializer] workspace not found: {workspace}")
        return 2
    if not index_path.is_file():
        print(f"[rust-swival-selected-fixture-materializer] index not found: {index_path}")
        return 2

    payload = materialize(workspace, index_path=index_path, run_smoke=not args.no_smoke)
    out_json = workspace / DEFAULT_OUT_JSON
    out_md = workspace / DEFAULT_OUT_MD
    _write(out_json, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    _write(out_md, render_markdown(payload))

    if args.print_json:
        print(json.dumps({
            "created_count": payload["created_count"],
            "skipped_count": payload["skipped_count"],
            "smoke_status_counts": payload["smoke_status_counts"],
            "proof_claims": payload["proof_claims"],
            "out_json": str(out_json),
            "out_md": str(out_md),
        }, indent=2, sort_keys=True))
    else:
        print(f"[rust-swival-selected-fixture-materializer] wrote {out_json}")
        print(f"[rust-swival-selected-fixture-materializer] created={payload['created_count']} skipped={payload['skipped_count']}")
    return 0 if not payload["skipped"] and payload["smoke_status_counts"].get("failed", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
