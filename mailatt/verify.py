"""Read-only integrity verification of objects, manifest and ledger links."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import LedgerError, StorageError
from .ledger import Ledger
from .recovery import (
    ACTION_CLEAN,
    JOURNAL_FILENAME,
    TOMBSTONE_FILENAME,
    load_journal,
)
from .storage import OBJECT_REL_RE, ObjectStore
from .util import read_json, sha256_file


@dataclass
class VerificationResult:
    workdir: Path
    ok: bool = False
    checked_objects: int = 0
    checked_references: int = 0
    pending_commits: int = 0
    uncommitted_entries: int = 0
    issues: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "workdir": str(self.workdir),
            "checked_objects": self.checked_objects,
            "checked_references": self.checked_references,
            "pending_commits": self.pending_commits,
            "uncommitted_entries": self.uncommitted_entries,
            "issue_count": len(self.issues),
            "issues": list(self.issues),
        }


class _Issues:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str, str], dict[str, str]] = {}

    def add(self, code: str, path: str, detail: str) -> None:
        self._items[(code, path, detail)] = {
            "code": code,
            "path": path,
            "detail": detail,
        }

    def rows(self) -> list[dict[str, str]]:
        return [
            self._items[key]
            for key in sorted(self._items, key=lambda item: (item[0], item[1], item[2]))
        ]


def _unexpected_files(workdir: Path, issues: _Issues) -> None:
    for root_name in ("objects", "quarantine"):
        root = workdir / root_name
        if not root.exists():
            continue
        if root.is_symlink():
            issues.add("OBJECT_PATH_UNSAFE", root_name, "store root is a symbolic link")
            continue
        try:
            paths = sorted(root.rglob("*"))
        except OSError as exc:
            issues.add("STORE_UNREADABLE", root_name, str(exc))
            continue
        for path in paths:
            if path.is_symlink():
                issues.add("OBJECT_PATH_UNSAFE", path.relative_to(workdir).as_posix(),
                           "object path is a symbolic link")
            elif path.is_file():
                relative = path.relative_to(workdir).as_posix()
                if not OBJECT_REL_RE.fullmatch(relative):
                    issues.add("OBJECT_PATH_UNSAFE", relative, "unexpected object path")


def _load_manifest(workdir: Path, issues: _Issues) -> list[dict[str, Any]] | None:
    path = workdir / "manifest.json"
    if not path.is_file():
        issues.add("MANIFEST_MISSING", "manifest.json", "manifest file is missing")
        return None
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        issues.add("MANIFEST_INVALID", "manifest.json", str(exc))
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
        issues.add("MANIFEST_INVALID", "manifest.json", "objects array is missing")
        return None
    if payload.get("object_count") != len(payload["objects"]):
        issues.add("MANIFEST_INVALID", "manifest.json", "object_count does not match objects")
    return [item for item in payload["objects"] if isinstance(item, dict)]


def _actual_object_digests(store: ObjectStore, issues: _Issues) -> dict[str, str]:
    actual: dict[str, str] = {}
    for item in store.list_files():
        try:
            digest = sha256_file(store.workdir / item.relative_path)
        except OSError as exc:
            issues.add("OBJECT_UNREADABLE", item.relative_path, str(exc))
            continue
        actual[item.relative_path] = digest
        if digest != item.sha256:
            issues.add("OBJECT_CORRUPT", item.relative_path, "content hash does not match path")
    return actual


def _expected_references(ledger: Ledger, issues: _Issues) -> dict[str, str]:
    expected: dict[str, str] = {}
    for row in ledger.referenced_objects():
        status = row["status"]
        path = row["quarantine_path"] if status == "quarantined" else row["object_path"]
        if not path:
            continue
        if not OBJECT_REL_RE.fullmatch(path):
            issues.add("LEDGER_UNSAFE_PATH", path, "ledger contains an unsafe object path")
            continue
        expected.setdefault(path, row["sha256"])
        if path.rsplit("/", 1)[-1] != row["sha256"]:
            issues.add("LEDGER_HASH_PATH_MISMATCH", path, "ledger hash differs from object path")
    return expected


def _check_manifest(
    entries: list[dict[str, Any]],
    actual: dict[str, str],
    expected: dict[str, str],
    issues: _Issues,
) -> None:
    manifest_paths: set[str] = set()
    for entry in entries:
        path = str(entry.get("path", ""))
        digest = str(entry.get("sha256", ""))
        if not path or not OBJECT_REL_RE.fullmatch(path):
            issues.add("MANIFEST_UNSAFE_PATH", path or "(empty)", "manifest entry path is unsafe")
            continue
        if path in manifest_paths:
            issues.add("MANIFEST_DUPLICATE", path, "manifest contains the same path twice")
        manifest_paths.add(path)
        if path not in actual:
            issues.add("MANIFEST_ORPHAN", path, "manifest entry has no object file")
            continue
        if actual[path] != digest:
            issues.add("MANIFEST_HASH_MISMATCH", path, "manifest hash differs from content")
        if path not in expected:
            issues.add("MANIFEST_UNREFERENCED", path, "manifest entry is not referenced by ledger")
    for path in sorted(set(expected) - manifest_paths):
        issues.add("MANIFEST_OMISSION", path, "ledger object is absent from manifest")


def _pending_state(workdir: Path, issues: _Issues) -> tuple[set[str], set[str], int, int]:
    """Scan staging journals and uncommitted quarantine records (read-only).

    Returns the final object paths claimed by valid in-flight journals, the
    digests preserved in uncommitted quarantine, plus pending/uncommitted
    counters.  Objects claimed by a journal are reported as PENDING_COMMIT
    rather than OBJECT_ORPHAN.
    """
    claimed: set[str] = set()
    preserved_digests: set[str] = set()
    pending = 0
    uncommitted = 0
    staging = workdir / "staging"
    if staging.is_dir() and not staging.is_symlink():
        try:
            entries = sorted(staging.iterdir())
        except OSError as exc:
            issues.add("STORE_UNREADABLE", "staging", str(exc))
            entries = []
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue
            commit_key = entry.name
            pending += 1
            try:
                journal = load_journal(workdir, commit_key)
            except StorageError as exc:
                issues.add(exc.code, f"staging/{commit_key}", exc.detail)
                continue
            if journal is None:
                issues.add(
                    "COMMIT_JOURNAL_INVALID",
                    f"staging/{commit_key}/{JOURNAL_FILENAME}",
                    "commit journal is missing",
                )
                continue
            for attachment in journal.attachments:
                if attachment.final_path:
                    claimed.add(attachment.final_path)
            issues.add(
                "PENDING_COMMIT",
                f"staging/{commit_key}",
                f"uncommitted journal for {journal.source_ref}; run mailatt recover",
            )
    uncommitted_root = workdir / "uncommitted"
    if uncommitted_root.is_dir() and not uncommitted_root.is_symlink():
        try:
            entries = sorted(uncommitted_root.iterdir())
        except OSError as exc:
            issues.add("STORE_UNREADABLE", "uncommitted", str(exc))
            entries = []
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue
            uncommitted += 1
            tombstone = entry / TOMBSTONE_FILENAME
            if not tombstone.is_file():
                issues.add(
                    "UNCOMMITTED_PRESERVED",
                    f"uncommitted/{entry.name}",
                    "preserved uncommitted object without tombstone record",
                )
                continue
            try:
                payload = read_json(tombstone)
            except (OSError, json.JSONDecodeError, UnicodeError) as exc:
                issues.add(
                    "UNCOMMITTED_PRESERVED",
                    f"uncommitted/{entry.name}/{TOMBSTONE_FILENAME}",
                    f"tombstone is unreadable: {exc}",
                )
                continue
            action = str(payload.get("action", "")) if isinstance(payload, dict) else ""
            code = (
                "UNCOMMITTED_CLEANED"
                if action == ACTION_CLEAN
                else "UNCOMMITTED_PRESERVED"
            )
            detail = str(payload.get("reason", "")) if isinstance(payload, dict) else ""
            issues.add(code, f"uncommitted/{entry.name}", detail)
            objects_dir = entry / "objects"
            if objects_dir.is_dir() and not objects_dir.is_symlink():
                for child in objects_dir.iterdir():
                    if child.is_file() and not child.is_symlink():
                        preserved_digests.add(child.name)
    return claimed, preserved_digests, pending, uncommitted


def verify_workdir(workdir: Path) -> VerificationResult:
    workdir = workdir.expanduser().resolve(strict=False)
    result = VerificationResult(workdir=workdir)
    issues = _Issues()
    if not workdir.is_dir():
        issues.add("WORKDIR_MISSING", str(workdir), "work directory does not exist")
        result.issues = issues.rows()
        return result
    _unexpected_files(workdir, issues)
    claimed_paths, preserved_digests, pending, uncommitted = _pending_state(
        workdir, issues
    )
    result.pending_commits = pending
    result.uncommitted_entries = uncommitted
    try:
        store = ObjectStore(workdir, create=False)
        actual = _actual_object_digests(store, issues)
    except StorageError as exc:
        issues.add(exc.code, str(workdir), exc.detail)
        actual = {}
    try:
        with Ledger(workdir, readonly=True) as ledger:
            expected = _expected_references(ledger, issues)
    except LedgerError as exc:
        issues.add(exc.code, "ledger.sqlite3", exc.detail)
        expected = {}
    for path, digest in sorted(expected.items()):
        if path not in actual:
            issues.add("OBJECT_MISSING", path, f"referenced object {digest} is missing")
    for path in sorted(set(actual) - set(expected)):
        if path in claimed_paths:
            issues.add(
                "PENDING_COMMIT_OBJECT",
                path,
                "object is promoted but its commit journal is not yet ledger-committed",
            )
        elif path.rsplit("/", 1)[-1] in preserved_digests:
            # Already accounted for in uncommitted/; the original location may
            # remain until cleanup or be absent after preservation.
            continue
        else:
            issues.add("OBJECT_ORPHAN", path, "object file has no ledger reference")
    entries = _load_manifest(workdir, issues)
    if entries is not None:
        _check_manifest(entries, actual, expected, issues)
    result.checked_objects = len(actual)
    result.checked_references = len(expected)
    result.issues = issues.rows()
    result.ok = not result.issues
    return result
