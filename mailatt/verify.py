"""Read-only integrity verification of objects, manifest and ledger links."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import LedgerError, StorageError
from .ledger import Ledger
from .storage import OBJECT_REL_RE, ObjectStore
from .util import read_json, sha256_file


@dataclass
class VerificationResult:
    workdir: Path
    ok: bool = False
    checked_objects: int = 0
    checked_references: int = 0
    issues: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "workdir": str(self.workdir),
            "checked_objects": self.checked_objects,
            "checked_references": self.checked_references,
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


def _check_signature_evidence(ledger: Ledger, issues: _Issues) -> None:
    """Cross-check signature verdicts against attachment placement.

    The archive must never contain an attachment that is presented as trusted
    while its message signature is invalid, nor a "trusted" claim without an
    anchor fingerprint.
    """
    rows = ledger.signature_rows()
    verdicts = {f"{row['source_name']}/{row['relative_path']}": row for row in rows}
    for source, row in verdicts.items():
        if row["signature_verdict"] == "trusted" and not row["signature_anchor_fingerprint"]:
            issues.add(
                "SIGNATURE_TRUST_WITHOUT_ANCHOR", source,
                "message is marked trusted but records no local anchor fingerprint",
            )
        if row["signature_integrity"] == "invalid" and row["signature_trust"] == "trusted":
            issues.add(
                "SIGNATURE_INVALID_MARKED_TRUSTED", source,
                "invalid signature is marked with trusted identity",
            )
    for item in ledger.all_attachments():
        source = f"{item['message_source']}/{item['message_path']}"
        message = verdicts.get(source)
        if message is None:
            continue
        if message["signature_integrity"] == "invalid":
            if item["status"] in ("accepted", "duplicate"):
                issues.add(
                    "INVALID_SIGNATURE_ATTACHMENT_ACCEPTED", source,
                    f"attachment {item['part_id']} is accepted under an invalid signature",
                )
            if item["object_path"] and not item["quarantine_path"]:
                issues.add(
                    "INVALID_SIGNATURE_ATTACHMENT_DOWNLOADABLE", source,
                    f"attachment {item['part_id']} would be served as a trusted object",
                )


def verify_workdir(workdir: Path) -> VerificationResult:
    workdir = workdir.expanduser().resolve(strict=False)
    result = VerificationResult(workdir=workdir)
    issues = _Issues()
    if not workdir.is_dir():
        issues.add("WORKDIR_MISSING", str(workdir), "work directory does not exist")
        result.issues = issues.rows()
        return result
    _unexpected_files(workdir, issues)
    try:
        store = ObjectStore(workdir, create=False)
        actual = _actual_object_digests(store, issues)
    except StorageError as exc:
        issues.add(exc.code, str(workdir), exc.detail)
        actual = {}
    try:
        with Ledger(workdir, readonly=True) as ledger:
            expected = _expected_references(ledger, issues)
            _check_signature_evidence(ledger, issues)
    except LedgerError as exc:
        issues.add(exc.code, "ledger.sqlite3", exc.detail)
        expected = {}
    for path, digest in sorted(expected.items()):
        if path not in actual:
            issues.add("OBJECT_MISSING", path, f"referenced object {digest} is missing")
    for path in sorted(set(actual) - set(expected)):
        issues.add("OBJECT_ORPHAN", path, "object file has no ledger reference")
    entries = _load_manifest(workdir, issues)
    if entries is not None:
        _check_manifest(entries, actual, expected, issues)
    result.checked_objects = len(actual)
    result.checked_references = len(expected)
    result.issues = issues.rows()
    result.ok = not result.issues
    return result
