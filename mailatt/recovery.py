"""Recoverable per-message commit records spanning two storage systems.

Object bytes (filesystem) and the audit ledger (SQLite) cannot share a single
transaction.  The :class:`CommitJournal` is a durable write-ahead record with a
stable identity: the same source path, message digest, MIME part id and
attachment digest always map to the same journal and staged payload, so
repeated runs never create duplicate references.

Commit phases::

    staged   payloads live in staging/<key>/ and the journal is durably written
    promoting  payloads are moved into objects/ or quarantine/
    committed ledger rows exist for every journal entry
    done       journal and staging area are removed

A process killed at any point leaves enough state for :func:`build_recovery_plan`
to reconstruct what happened and drive the message to one consistent terminal
state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .errors import LedgerError, MailattError, StorageError
from .ledger import Ledger
from .manifest import write_manifest
from .mime import MimeOptions
from .models import (
    AttachmentRecord,
    Decision,
    MessageRecord,
    MessageStatus,
    StorageKind,
)
from .storage import OBJECT_REL_RE, ObjectStore
from .util import (
    SHA256_RE,
    atomic_write_json,
    iso_utc,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)

JOURNAL_SCHEMA = "1.0"
JOURNAL_FILENAME = "journal.json"
TOMBSTONE_FILENAME = "tombstone.json"

# Recovery action codes (also surfaced by verify and run summaries).
ACTION_COMMIT = "commit"
ACTION_QUARANTINE = "quarantine_uncommitted"
ACTION_CLEAN = "clean_uncommitted"
ACTION_BLOCKED = "blocked_source_changed"
ACTION_BLOCKED_MISSING = "blocked_attachment_unreproducible"
ACTION_BLOCKED_CORRUPT = "blocked_staged_corrupt"
ACTION_BLOCKED_JOURNAL = "blocked_journal_invalid"

QUARANTINE_STRATEGY = "quarantine"
CLEANUP_STRATEGY = "cleanup"
STRATEGIES = (QUARANTINE_STRATEGY, CLEANUP_STRATEGY)


@dataclass(frozen=True)
class CommitAttachment:
    """Everything needed to re-verify and re-create one attachment reference."""

    part_id: str
    sha256: str
    size: int
    filename: str
    safe_filename: str
    media_type: str
    disposition: str
    nested_depth: int
    status: str
    reason_code: str
    reason: str
    object_path: str
    quarantine_path: str

    @property
    def kind(self) -> StorageKind:
        return (
            StorageKind.QUARANTINE
            if self.status == Decision.QUARANTINED.value
            else StorageKind.OBJECT
        )

    @property
    def final_path(self) -> str:
        return self.quarantine_path or self.object_path

    def as_record(self) -> AttachmentRecord:
        return AttachmentRecord(
            part_id=self.part_id,
            sha256=self.sha256,
            size=self.size,
            filename=self.filename,
            safe_filename=self.safe_filename,
            media_type=self.media_type,
            disposition=self.disposition,
            nested_depth=self.nested_depth,
            status=Decision(self.status),
            reason_code=self.reason_code,
            reason=self.reason,
            object_path=self.object_path,
            quarantine_path=self.quarantine_path,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "part_id": self.part_id,
            "sha256": self.sha256,
            "size": self.size,
            "filename": self.filename,
            "safe_filename": self.safe_filename,
            "media_type": self.media_type,
            "disposition": self.disposition,
            "nested_depth": self.nested_depth,
            "status": self.status,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "object_path": self.object_path,
            "quarantine_path": self.quarantine_path,
        }

    @classmethod
    def from_record(cls, record: AttachmentRecord) -> "CommitAttachment":
        return cls(
            part_id=record.part_id,
            sha256=record.sha256,
            size=record.size,
            filename=record.filename,
            safe_filename=record.safe_filename,
            media_type=record.media_type,
            disposition=record.disposition,
            nested_depth=record.nested_depth,
            status=record.status.value,
            reason_code=record.reason_code,
            reason=record.reason,
            object_path=record.object_path,
            quarantine_path=record.quarantine_path,
        )

    @classmethod
    def from_dict(cls, payload: Any) -> "CommitAttachment":
        if not isinstance(payload, dict):
            raise ValueError("attachment entry must be an object")
        required = (
            "part_id", "sha256", "size", "filename", "safe_filename", "media_type",
            "disposition", "nested_depth", "status", "reason_code", "reason",
            "object_path", "quarantine_path",
        )
        missing = [key for key in required if key not in payload]
        if missing:
            raise ValueError(f"attachment entry missing keys: {', '.join(missing)}")
        if not SHA256_RE.fullmatch(str(payload["sha256"])):
            raise ValueError("attachment sha256 is invalid")
        status = str(payload["status"])
        Decision(status)
        nested = payload["nested_depth"]
        if not isinstance(nested, int) or isinstance(nested, bool) or nested < 0:
            raise ValueError("nested_depth must be a non-negative integer")
        size = payload["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("size must be a non-negative integer")
        for key in ("object_path", "quarantine_path"):
            value = str(payload[key])
            if value and not OBJECT_REL_RE.fullmatch(value):
                raise ValueError(f"{key} is not a canonical object path")
        return cls(
            part_id=str(payload["part_id"]),
            sha256=str(payload["sha256"]),
            size=size,
            filename=str(payload["filename"]),
            safe_filename=str(payload["safe_filename"]),
            media_type=str(payload["media_type"]),
            disposition=str(payload["disposition"]),
            nested_depth=nested,
            status=status,
            reason_code=str(payload["reason_code"]),
            reason=str(payload["reason"]),
            object_path=str(payload["object_path"]),
            quarantine_path=str(payload["quarantine_path"]),
        )


@dataclass(frozen=True)
class CommitJournal:
    """Stable write-ahead record for one message commit."""

    commit_key: str
    source_name: str
    relative_path: str
    source_absolute: str
    message_digest: str
    message_size: int
    policy_hash: str
    run_id: str
    mime_options: dict[str, Any]
    message: dict[str, Any]
    attachments: tuple[CommitAttachment, ...]

    @property
    def source_ref(self) -> str:
        return f"{self.source_name}/{self.relative_path}"

    def as_message_record(self) -> MessageRecord:
        return MessageRecord(
            source_name=self.source_name,
            relative_path=self.relative_path,
            digest=self.message_digest,
            size=self.message_size,
            message_id=str(self.message.get("message_id", "")),
            subject=str(self.message.get("subject", "")),
            sender=str(self.message.get("sender", "")),
            sent_at=str(self.message.get("sent_at", "")),
            status=MessageStatus.OK,
            warnings=tuple(self.message.get("warnings", ())),
        )

    def mime_options_value(self) -> MimeOptions:
        return MimeOptions(
            allow_nested_messages=bool(self.mime_options.get("allow_nested_messages", True)),
            max_nested_depth=int(self.mime_options.get("max_nested_depth", 3)),
            max_filename_length=int(self.mime_options.get("max_filename_length", 120)),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": JOURNAL_SCHEMA,
            "commit_key": self.commit_key,
            "source_name": self.source_name,
            "relative_path": self.relative_path,
            "source_absolute": self.source_absolute,
            "message_digest": self.message_digest,
            "message_size": self.message_size,
            "policy_hash": self.policy_hash,
            "run_id": self.run_id,
            "mime_options": dict(self.mime_options),
            "message": dict(self.message),
            "attachments": [item.as_dict() for item in self.attachments],
        }

    @classmethod
    def create(
        cls,
        *,
        source_name: str,
        relative_path: str,
        source_absolute: Path,
        message: MessageRecord,
        records: Iterable[AttachmentRecord],
        policy_hash: str,
        run_id: str,
        mime_options: MimeOptions,
    ) -> "CommitJournal":
        attachments = tuple(
            CommitAttachment.from_record(item)
            for item in sorted(records, key=lambda item: item.part_id)
        )
        identity = {
            "source_name": source_name,
            "relative_path": relative_path,
            "message_digest": message.digest,
            "attachments": [
                {"part_id": item.part_id, "sha256": item.sha256}
                for item in attachments
            ],
        }
        commit_key = sha256_bytes(
            json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
        )
        return cls(
            commit_key=commit_key,
            source_name=source_name,
            relative_path=relative_path,
            source_absolute=str(source_absolute),
            message_digest=message.digest,
            message_size=message.size,
            policy_hash=policy_hash,
            run_id=run_id,
            mime_options={
                "allow_nested_messages": mime_options.allow_nested_messages,
                "max_nested_depth": mime_options.max_nested_depth,
                "max_filename_length": mime_options.max_filename_length,
            },
            message={
                "message_id": message.message_id,
                "subject": message.subject,
                "sender": message.sender,
                "sent_at": message.sent_at,
                "warnings": list(message.warnings),
            },
            attachments=attachments,
        )

    @classmethod
    def from_dict(cls, payload: Any) -> "CommitJournal":
        if not isinstance(payload, dict):
            raise ValueError("journal must be a JSON object")
        if payload.get("schema_version") != JOURNAL_SCHEMA:
            raise ValueError("unsupported journal schema version")
        commit_key = str(payload.get("commit_key", ""))
        if not SHA256_RE.fullmatch(commit_key):
            raise ValueError("commit_key is invalid")
        message_digest = str(payload.get("message_digest", ""))
        if not SHA256_RE.fullmatch(message_digest):
            raise ValueError("message_digest is invalid")
        for key in ("source_name", "relative_path", "source_absolute", "policy_hash", "run_id"):
            if not isinstance(payload.get(key), str) or not payload[key]:
                raise ValueError(f"{key} must be a non-empty string")
        size = payload.get("message_size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("message_size must be a non-negative integer")
        message = payload.get("message")
        if not isinstance(message, dict):
            raise ValueError("message section is missing")
        mime_options = payload.get("mime_options")
        if not isinstance(mime_options, dict):
            raise ValueError("mime_options section is missing")
        raw_attachments = payload.get("attachments")
        if not isinstance(raw_attachments, list):
            raise ValueError("attachments must be a list")
        attachments = tuple(
            CommitAttachment.from_dict(item) for item in raw_attachments
        )
        part_ids = [item.part_id for item in attachments]
        if len(part_ids) != len(set(part_ids)):
            raise ValueError("duplicate part_id in journal")
        # Repeated attachment digests are legitimate: two MIME parts may carry
        # identical bytes, and content-addressed storage keeps one shared copy.
        return cls(
            commit_key=commit_key,
            source_name=str(payload["source_name"]),
            relative_path=str(payload["relative_path"]),
            source_absolute=str(payload["source_absolute"]),
            message_digest=message_digest,
            message_size=size,
            policy_hash=str(payload["policy_hash"]),
            run_id=str(payload["run_id"]),
            mime_options=dict(mime_options),
            message=dict(message),
            attachments=attachments,
        )


def journal_path(workdir: Path, commit_key: str) -> Path:
    return workdir / "staging" / commit_key / JOURNAL_FILENAME


def load_journal(workdir: Path, commit_key: str) -> CommitJournal | None:
    path = journal_path(workdir, commit_key)
    if not path.is_file():
        return None
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise StorageError(
            f"commit journal {commit_key} is unreadable: {exc}",
            code="COMMIT_JOURNAL_INVALID",
        ) from exc
    try:
        journal = CommitJournal.from_dict(payload)
    except ValueError as exc:
        raise StorageError(
            f"commit journal {commit_key} is invalid: {exc}",
            code="COMMIT_JOURNAL_INVALID",
        ) from exc
    if journal.commit_key != commit_key:
        raise StorageError(
            f"commit journal {commit_key} contains a mismatching commit key",
            code="COMMIT_JOURNAL_INVALID",
        )
    return journal


def write_journal(workdir: Path, journal: CommitJournal) -> Path:
    path = journal_path(workdir, journal.commit_key)
    atomic_write_json(path, journal.as_dict())
    return path


def remove_journal(workdir: Path, commit_key: str) -> None:
    path = journal_path(workdir, commit_key)
    try:
        if path.is_file() and not path.is_symlink():
            path.unlink()
    except OSError as exc:
        raise StorageError(f"cannot remove commit journal: {exc}") from exc


# ---------------------------------------------------------------------------
# Recovery planning
# ---------------------------------------------------------------------------


@dataclass
class AttachmentResolution:
    attachment: CommitAttachment
    staged_present: bool
    staged_digest_ok: bool
    final_present: bool
    final_digest_ok: bool
    referenced_by_ledger: bool
    detail: str = ""


@dataclass
class RecoveryItem:
    journal: CommitJournal | None
    commit_key: str
    journal_valid: bool
    source_exists: bool
    source_digest_matches: bool
    resolutions: list[AttachmentResolution] = field(default_factory=list)
    action: str = ""
    reason: str = ""
    journal_error: str = ""
    blocker: str = ""

    @property
    def blocked(self) -> bool:
        return bool(self.blocker)

    @property
    def can_commit(self) -> bool:
        if not self.journal_valid or not self.source_digest_matches:
            return False
        return all(
            (item.staged_present and item.staged_digest_ok)
            or (item.final_present and item.final_digest_ok)
            for item in self._staged_resolutions()
        )

    def _staged_resolutions(self) -> list[AttachmentResolution]:
        return [
            item
            for item in self.resolutions
            if item.attachment.status
            not in (Decision.REJECTED.value, Decision.DUPLICATE.value)
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "commit_key": self.commit_key,
            "source_ref": self.journal.source_ref if self.journal else "",
            "action": self.action,
            "reason": self.reason,
            "blocker": self.blocker,
            "source_exists": self.source_exists,
            "source_digest_matches": self.source_digest_matches,
            "journal_valid": self.journal_valid,
            "attachments": [
                {
                    "part_id": item.attachment.part_id,
                    "sha256": item.attachment.sha256,
                    "status": item.attachment.status,
                    "staged_present": item.staged_present,
                    "staged_digest_ok": item.staged_digest_ok,
                    "final_present": item.final_present,
                    "final_digest_ok": item.final_digest_ok,
                    "referenced_by_ledger": item.referenced_by_ledger,
                    "final_path": item.attachment.final_path,
                    "detail": item.detail,
                }
                for item in self.resolutions
            ],
        }


@dataclass
class OrphanResolution:
    path: str
    sha256: str
    size: int
    referenced_by_ledger: bool
    claimed_by_journal: bool
    action: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "referenced_by_ledger": self.referenced_by_ledger,
            "claimed_by_journal": self.claimed_by_journal,
            "action": self.action,
            "reason": self.reason,
        }


@dataclass
class RecoveryPlan:
    workdir: Path
    strategy: str
    dry_run: bool
    items: list[RecoveryItem] = field(default_factory=list)
    orphans: list[OrphanResolution] = field(default_factory=list)
    execution_errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def blocked_count(self) -> int:
        return sum(item.blocked for item in self.items)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.action] = counts.get(item.action, 0) + 1
        for orphan in self.orphans:
            counts[orphan.action] = counts.get(orphan.action, 0) + 1
        return dict(sorted(counts.items()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "workdir": str(self.workdir),
            "strategy": self.strategy,
            "dry_run": self.dry_run,
            "journal_count": len(self.items),
            "blocked_count": self.blocked_count,
            "orphan_count": len(self.orphans),
            "execution_error_count": len(self.execution_errors),
            "action_counts": self.counts(),
            "journals": [item.as_dict() for item in self.items],
            "orphans": [item.as_dict() for item in self.orphans],
            "execution_errors": list(self.execution_errors),
        }


def _check_source(journal: CommitJournal) -> tuple[bool, bool]:
    source = Path(journal.source_absolute)
    try:
        exists = source.is_file() and not source.is_symlink()
    except OSError:
        exists = False
    if not exists:
        return False, False
    try:
        digest = sha256_file(source)
    except OSError:
        return True, False
    return True, digest == journal.message_digest


def _resolve_attachments(
    workdir: Path,
    store: ObjectStore,
    journal: CommitJournal,
    ledger: Ledger,
) -> list[AttachmentResolution]:
    resolutions: list[AttachmentResolution] = []
    referenced = set()
    if ledger is not None:
        try:
            referenced = ledger.referenced_paths(
                item.final_path for item in journal.attachments if item.final_path
            )
        except LedgerError:
            referenced = set()
    for entry in journal.attachments:
        staged_path = store.staging_path(journal.commit_key, entry.sha256)
        staged_present = staged_path.is_file() and not staged_path.is_symlink()
        staged_ok = False
        detail = ""
        if staged_present:
            try:
                staged_ok = sha256_file(staged_path) == entry.sha256
                if not staged_ok:
                    detail = "staged bytes do not match recorded attachment digest"
            except OSError as exc:
                detail = f"staged payload unreadable: {exc}"
        final_path = entry.final_path
        final_present = False
        final_ok = False
        if final_path:
            target = workdir / final_path
            final_present = target.is_file() and not target.is_symlink()
            if final_present:
                try:
                    final_ok = sha256_file(target) == entry.sha256
                    if not final_ok:
                        detail = (detail + "; " if detail else "") + (
                            "promoted object does not match recorded digest"
                        )
                except OSError as exc:
                    detail = (detail + "; " if detail else "") + f"object unreadable: {exc}"
        resolutions.append(
            AttachmentResolution(
                attachment=entry,
                staged_present=staged_present,
                staged_digest_ok=staged_ok,
                final_present=final_present,
                final_digest_ok=final_ok,
                referenced_by_ledger=final_path in referenced,
                detail=detail,
            )
        )
    return resolutions


def _journal_item(
    workdir: Path,
    store: ObjectStore,
    ledger: Ledger,
    commit_key: str,
    strategy: str,
) -> RecoveryItem:
    try:
        journal = load_journal(workdir, commit_key)
    except StorageError as exc:
        return RecoveryItem(
            journal=None,
            commit_key=commit_key,
            journal_valid=False,
            source_exists=False,
            source_digest_matches=False,
            action=ACTION_QUARANTINE if strategy == QUARANTINE_STRATEGY else ACTION_CLEAN,
            reason=exc.detail,
            journal_error=exc.code,
            blocker=ACTION_BLOCKED_JOURNAL,
        )
    if journal is None:
        return RecoveryItem(
            journal=None,
            commit_key=commit_key,
            journal_valid=False,
            source_exists=False,
            source_digest_matches=False,
            action=ACTION_QUARANTINE if strategy == QUARANTINE_STRATEGY else ACTION_CLEAN,
            reason="journal.json is missing",
            journal_error="COMMIT_JOURNAL_INVALID",
            blocker=ACTION_BLOCKED_JOURNAL,
        )
    source_exists, source_matches = _check_source(journal)
    item = RecoveryItem(
        journal=journal,
        commit_key=commit_key,
        journal_valid=True,
        source_exists=source_exists,
        source_digest_matches=source_matches,
        resolutions=_resolve_attachments(workdir, store, journal, ledger),
    )
    staged_resolutions = [
        resolution
        for resolution in item.resolutions
        if resolution.attachment.status
        not in (Decision.REJECTED.value, Decision.DUPLICATE.value)
    ]
    if not source_matches:
        item.blocker = ACTION_BLOCKED
        item.reason = (
            "source message is missing"
            if not source_exists
            else "source message digest changed; refusing to attach new content to old history"
        )
    else:
        unavailable = [
            resolution.attachment.part_id
            for resolution in staged_resolutions
            if not (
                (resolution.staged_present and resolution.staged_digest_ok)
                or (resolution.final_present and resolution.final_digest_ok)
            )
        ]
        if unavailable:
            item.blocker = ACTION_BLOCKED_MISSING
            item.reason = (
                "attachment payloads cannot be reproduced from staging or object store: "
                + ", ".join(unavailable)
            )
        else:
            item.action = ACTION_COMMIT
            item.reason = "source and every staged attachment verify against recorded digests"
    if item.blocked:
        # The terminal action for a blocked journal is strategy-dependent.
        item.action = (
            ACTION_QUARANTINE if strategy == QUARANTINE_STRATEGY else ACTION_CLEAN
        )
    return item


def build_recovery_plan(
    workdir: Path,
    *,
    strategy: str = QUARANTINE_STRATEGY,
) -> RecoveryPlan:
    """Inspect staging journals and store orphans without mutating anything."""
    if strategy not in STRATEGIES:
        raise MailattError(
            f"unknown uncommitted-object strategy: {strategy}", code="INVALID_ARGUMENT"
        )
    workdir = workdir.expanduser().resolve(strict=False)
    plan = RecoveryPlan(workdir=workdir, strategy=strategy, dry_run=True)
    store = ObjectStore(workdir, create=False)
    try:
        ledger_cm = Ledger(workdir, readonly=True)
    except LedgerError:
        # No ledger yet: every object is necessarily unreferenced.
        ledger_cm = None
    if ledger_cm is not None:
        with ledger_cm as ledger:
            _populate_recovery_plan(plan, store, ledger)
    else:
        _populate_recovery_plan(plan, store, None)
    return plan


def _populate_recovery_plan(
    plan: RecoveryPlan,
    store: ObjectStore,
    ledger: "Ledger | None",
) -> None:
    workdir = plan.workdir
    strategy = plan.strategy
    commit_keys = store.list_commit_keys()
    for commit_key in commit_keys:
        plan.items.append(
            _journal_item(workdir, store, ledger, commit_key, strategy)
        )
    plan.items.sort(key=lambda item: item.commit_key)

    claimed_paths: set[str] = set()
    for item in plan.items:
        if item.journal is not None:
            for resolution in item.resolutions:
                if resolution.attachment.final_path:
                    claimed_paths.add(resolution.attachment.final_path)
    actual = {entry.relative_path: entry for entry in store.list_files()}
    referenced = (
        ledger.referenced_paths(actual.keys()) if ledger is not None else set()
    )
    for path in sorted(set(actual) - set(referenced)):
        entry = actual[path]
        claimed = path in claimed_paths
        if claimed:
            # Belongs to an in-flight journal (including a blocked one); the
            # journal item drives every claimed object to its terminal state.
            action = "retain_pending"
            reason = "promoted object is claimed by an in-flight commit journal"
        else:
            action = (
                ACTION_QUARANTINE if strategy == QUARANTINE_STRATEGY else ACTION_CLEAN
            )
            reason = "pre-existing orphan with no ledger reference"
        plan.orphans.append(
            OrphanResolution(
                path=path,
                sha256=entry.sha256,
                size=entry.size,
                referenced_by_ledger=False,
                claimed_by_journal=claimed,
                action=action,
                reason=reason,
            )
        )
    return plan


# ---------------------------------------------------------------------------
# Plan execution
# ---------------------------------------------------------------------------


def _tombstone_payload(
    journal: CommitJournal | None,
    *,
    commit_key: str,
    action: str,
    reason: str,
    entries: list[dict[str, Any]],
    clock_return: str,
) -> dict[str, Any]:
    return {
        "schema_version": JOURNAL_SCHEMA,
        "commit_key": commit_key,
        "resolved_at": clock_return,
        "action": action,
        "reason": reason,
        "source_ref": journal.source_ref if journal else "",
        "source_absolute": journal.source_absolute if journal else "",
        "message_digest": journal.message_digest if journal else "",
        "attachments": entries,
    }


def _write_tombstone(store: ObjectStore, payload: dict[str, Any]) -> None:
    commit_key = str(payload["commit_key"])
    directory = store.uncommitted_dir(commit_key)
    directory.mkdir(parents=True, exist_ok=True)
    atomic_write_json(directory / TOMBSTONE_FILENAME, payload)


def _promote_all(store: ObjectStore, item: RecoveryItem) -> list[str]:
    """Ensure every staged payload has reached its final object path."""
    assert item.journal is not None
    created_paths: list[str] = []
    for resolution in item.resolutions:
        entry = resolution.attachment
        if entry.status in (Decision.REJECTED.value, Decision.DUPLICATE.value):
            continue
        stored = store.promote_staged(
            item.commit_key,
            entry.sha256,
            entry.kind,
            expected_size=entry.size,
        )
        if stored.created:
            created_paths.append(stored.relative_path)
    return created_paths


def _journal_less_staged(store: ObjectStore, item: RecoveryItem) -> list[str]:
    """Staged payloads left behind when no valid journal describes them."""
    if item.journal is not None:
        return []
    return store.list_staged(item.commit_key)


def _quarantine_item(
    store: ObjectStore,
    ledger: Ledger,
    item: RecoveryItem,
    *,
    clock_return: str,
) -> None:
    """Preserve staged/promoted payloads in uncommitted/ for manual follow-up."""
    preserved: list[dict[str, Any]] = []
    if item.journal is not None:
        for resolution in item.resolutions:
            entry = resolution.attachment
            if entry.status in (Decision.REJECTED.value, Decision.DUPLICATE.value):
                continue
            origin = ""
            source: Path | None = None
            staged = store.staging_path(item.commit_key, entry.sha256)
            if staged.is_file() and not staged.is_symlink():
                origin, source = "staged", staged
            elif entry.final_path:
                promoted = store.workdir / entry.final_path
                if promoted.is_file() and not promoted.is_symlink():
                    origin, source = "promoted", promoted
            if source is None:
                preserved.append(
                    {
                        "part_id": entry.part_id,
                        "sha256": entry.sha256,
                        "status": entry.status,
                        "preserved": False,
                        "detail": resolution.detail or "payload unavailable",
                    }
                )
                continue
            preserved_path = store.quarantine_uncommitted(
                item.commit_key, source, entry.sha256, origin=origin
            )
            preserved.append(
                {
                    "part_id": entry.part_id,
                    "sha256": entry.sha256,
                    "status": entry.status,
                    "preserved": True,
                    "origin": origin,
                    "path": preserved_path,
                }
            )
            # Once bytes are safely copied into uncommitted/, remove any
            # promoted object so it cannot linger as an unreferenced orphan.
            if entry.final_path:
                final_target = store.workdir / entry.final_path
                if final_target.is_file() and not final_target.is_symlink():
                    if ledger.object_reference_count(entry.final_path) > 0:
                        raise StorageError(
                            f"refusing to quarantine referenced object {entry.final_path}",
                            code="RECOVERY_FAILED",
                        )
                    store.delete_object(entry.final_path)
    else:
        # No valid journal: keep every staged byte so nothing is lost silently.
        for digest in _journal_less_staged(store, item):
            staged = store.staging_path(item.commit_key, digest)
            preserved_path = store.quarantine_uncommitted(
                item.commit_key, staged, digest, origin="staged"
            )
            preserved.append(
                {
                    "part_id": "",
                    "sha256": digest,
                    "status": "",
                    "preserved": True,
                    "origin": "staged",
                    "path": preserved_path,
                }
            )
    _write_tombstone(
        store,
        _tombstone_payload(
            item.journal,
            commit_key=item.commit_key,
            action=ACTION_QUARANTINE,
            reason=item.reason,
            entries=preserved,
            clock_return=clock_return,
        ),
    )
    store.remove_staged(item.commit_key)
    remove_journal(store.workdir, item.commit_key)


def _cleanup_item(
    store: ObjectStore,
    ledger: Ledger,
    item: RecoveryItem,
    *,
    clock_return: str,
) -> None:
    """Remove uncommitted payloads after confirming no ledger reference."""
    removed: list[dict[str, Any]] = []
    if item.journal is not None:
        for resolution in item.resolutions:
            entry = resolution.attachment
            if entry.status in (Decision.REJECTED.value, Decision.DUPLICATE.value):
                continue
            final_path = entry.final_path
            if final_path:
                final_target = store.workdir / final_path
                if final_target.is_file() and not final_target.is_symlink():
                    if ledger.object_reference_count(final_path) > 0:
                        raise StorageError(
                            f"refusing cleanup: {final_path} still has ledger references",
                            code="RECOVERY_FAILED",
                        )
                    store.delete_object(final_path)
                    removed.append(
                        {
                            "part_id": entry.part_id,
                            "sha256": entry.sha256,
                            "status": entry.status,
                            "removed_path": final_path,
                        }
                    )
    else:
        # No valid journal: staged bytes have no identity beyond their digest.
        for digest in _journal_less_staged(store, item):
            removed.append(
                {
                    "part_id": "",
                    "sha256": digest,
                    "status": "",
                    "removed_path": f"staging/{item.commit_key}/{digest}",
                }
            )
    _write_tombstone(
        store,
        _tombstone_payload(
            item.journal,
            commit_key=item.commit_key,
            action=ACTION_CLEAN,
            reason=item.reason,
            entries=removed,
            clock_return=clock_return,
        ),
    )
    store.remove_staged(item.commit_key)
    remove_journal(store.workdir, item.commit_key)


def execute_recovery_plan(
    plan: RecoveryPlan,
    ledger: Ledger,
    *,
    clock=utc_now,
) -> RecoveryPlan:
    """Apply a plan. The plan object is marked as applied and returned.

    Per-entry failures are recorded on the plan instead of aborting the batch,
    so one unresolvable journal cannot block the other pending commits.
    """
    if not plan.dry_run:
        return plan
    store = ObjectStore(plan.workdir, create=False)
    for item in plan.items:
        clock_return = iso_utc(clock())
        try:
            if item.action == ACTION_COMMIT and item.journal is not None:
                _promote_all(store, item)
                journal = item.journal
                ledger.commit_message(
                    journal.as_message_record(),
                    (resolution.attachment.as_record() for resolution in item.resolutions),
                    journal.run_id,
                    journal.policy_hash,
                )
                store.remove_staged(item.commit_key)
                remove_journal(plan.workdir, item.commit_key)
            elif item.blocked:
                if plan.strategy == QUARANTINE_STRATEGY:
                    _quarantine_item(store, ledger, item, clock_return=clock_return)
                else:
                    _cleanup_item(store, ledger, item, clock_return=clock_return)
            # Unknown actions are left untouched for manual inspection.
        except Exception as exc:  # noqa: BLE001 - recorded, then batch continues
            normalized = (
                exc if isinstance(exc, MailattError) else MailattError(str(exc))
            )
            plan.execution_errors.append(
                {
                    "commit_key": item.commit_key,
                    "source_ref": item.journal.source_ref if item.journal else "",
                    "code": normalized.code,
                    "detail": (normalized.detail or str(normalized))[:2000],
                }
            )
    for orphan in plan.orphans:
        if orphan.action == "retain_pending":
            continue
        clock_return = iso_utc(clock())
        source = plan.workdir / orphan.path
        try:
            if orphan.action == ACTION_QUARANTINE:
                commit_key = sha256_bytes(f"orphan:{orphan.path}".encode("utf-8"))
                preserved_path = store.quarantine_uncommitted(
                    commit_key, source, orphan.sha256, origin="promoted"
                )
                _write_tombstone(
                    store,
                    {
                        "schema_version": JOURNAL_SCHEMA,
                        "commit_key": commit_key,
                        "resolved_at": clock_return,
                        "action": ACTION_QUARANTINE,
                        "reason": orphan.reason,
                        "source_ref": "",
                        "source_absolute": "",
                        "message_digest": "",
                        "attachments": [
                            {
                                "part_id": "",
                                "sha256": orphan.sha256,
                                "status": "",
                                "preserved": True,
                                "origin": "promoted",
                                "path": preserved_path,
                            }
                        ],
                    },
                )
                store.delete_object(orphan.path)
            elif orphan.action == ACTION_CLEAN:
                if ledger.object_reference_count(orphan.path) > 0:
                    raise StorageError(
                        f"refusing cleanup: {orphan.path} still has ledger references",
                        code="RECOVERY_FAILED",
                    )
                commit_key = sha256_bytes(f"orphan:{orphan.path}".encode("utf-8"))
                _write_tombstone(
                    store,
                    {
                        "schema_version": JOURNAL_SCHEMA,
                        "commit_key": commit_key,
                        "resolved_at": clock_return,
                        "action": ACTION_CLEAN,
                        "reason": orphan.reason,
                        "source_ref": "",
                        "source_absolute": "",
                        "message_digest": "",
                        "attachments": [
                            {
                                "part_id": "",
                                "sha256": orphan.sha256,
                                "status": "",
                                "removed_path": orphan.path,
                            }
                        ],
                    },
                )
                store.delete_object(orphan.path)
        except Exception as exc:  # noqa: BLE001 - recorded, then batch continues
            normalized = (
                exc if isinstance(exc, MailattError) else MailattError(str(exc))
            )
            plan.execution_errors.append(
                {
                    "commit_key": "",
                    "source_ref": orphan.path,
                    "code": normalized.code,
                    "detail": (normalized.detail or str(normalized))[:2000],
                }
            )
    plan.dry_run = False
    # Re-derive the manifest so it converges with the post-recovery ledger.
    last_run = ledger.last_run()
    write_manifest(
        plan.workdir,
        ledger,
        store,
        last_run["run_id"] if last_run else "",
    )
    return plan


def recover_workdir(
    workdir: Path,
    *,
    strategy: str = QUARANTINE_STRATEGY,
    apply: bool = False,
    clock=utc_now,
) -> RecoveryPlan:
    """Build the recovery plan and, when ``apply`` is true, execute it."""
    plan = build_recovery_plan(workdir, strategy=strategy)
    if apply:
        with Ledger(workdir) as ledger:
            execute_recovery_plan(plan, ledger, clock=clock)
    return plan


# ---------------------------------------------------------------------------
# Live two-phase commit used by the collector
# ---------------------------------------------------------------------------


def stage_message_commit(
    workdir: Path,
    store: ObjectStore,
    journal: CommitJournal,
) -> CommitJournal:
    """Durably write the journal once every payload is staged (phase one).

    Idempotent for an existing journal with the same stable identity: the
    journal is compared instead of duplicated, and staged payloads are written
    separately via :meth:`ObjectStore.put_staged`, which is itself idempotent.
    """
    existing = load_journal(workdir, journal.commit_key)
    if existing is not None and existing.as_dict() != journal.as_dict():
        raise StorageError(
            f"commit key {journal.commit_key} is already used by a different journal",
            code="COMMIT_JOURNAL_INVALID",
        )
    for entry in journal.attachments:
        # Rejected attachments have no bytes; duplicates reuse an existing
        # content-addressed object and are never staged.
        if entry.status in (Decision.REJECTED.value, Decision.DUPLICATE.value):
            continue
        if not entry.final_path:
            continue
        if not store.staged_exists(journal.commit_key, entry.sha256):
            raise StorageError(
                f"staged payload missing for {entry.sha256}", code="STAGING_MISSING"
            )
    write_journal(workdir, journal)
    return journal


def complete_message_commit(
    workdir: Path,
    store: ObjectStore,
    ledger: Ledger,
    journal: CommitJournal,
) -> tuple[int, list[str]]:
    """Promote payloads and write ledger rows (phase two), then clean up.

    Returns the ledger message id and the list of object paths created during
    promotion.  Safe to re-enter after a crash: existing objects and ledger rows
    are reused, and a fully committed journal is simply removed.
    """
    item = _journal_item(
        workdir,
        store,
        ledger,
        journal.commit_key,
        strategy=QUARANTINE_STRATEGY,
    )
    if not item.can_commit:
        raise StorageError(
            f"commit {journal.commit_key} cannot complete: {item.reason}",
            code="RECOVERY_FAILED",
        )
    created = _promote_all(store, item)
    message_id = ledger.commit_message(
        journal.as_message_record(),
        (resolution.attachment.as_record() for resolution in item.resolutions),
        journal.run_id,
        journal.policy_hash,
    )
    store.remove_staged(journal.commit_key)
    remove_journal(workdir, journal.commit_key)
    return message_id, created
