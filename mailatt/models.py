"""Data structures shared by discovery, parsing, policy and persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Decision(str, Enum):
    ACCEPTED = "accepted"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class MessageStatus(str, Enum):
    OK = "ok"
    ERROR = "error"


class StorageKind(str, Enum):
    OBJECT = "objects"
    QUARANTINE = "quarantine"


class RelatedRetention(str, Enum):
    """Business retention route for inline resources in multipart/related."""

    BODY_DEPENDENCY = "body-dependency"
    FULL_FORENSICS = "full-forensics"


@dataclass(frozen=True)
class RelatedReferenceIssue:
    """A non-guessed relationship problem anchored to a MIME tree path."""

    code: str
    related_path: str
    root_path: str = ""
    content_id: str = ""
    part_paths: tuple[str, ...] = ()
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "related_path": self.related_path,
            "root_path": self.root_path,
            "content_id": self.content_id,
            "part_paths": list(self.part_paths),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class DiscoveredFile:
    source_name: str
    relative_path: str
    absolute_path: Path
    size: int
    digest: str

    @property
    def source_ref(self) -> str:
        return f"{self.source_name}/{self.relative_path}"


@dataclass(frozen=True)
class DiscoveryOutcome:
    files: tuple[DiscoveredFile, ...]
    skipped_count: int
    ignored_symlinks: int


@dataclass(frozen=True)
class AttachmentCandidate:
    part_id: str
    filename: str
    safe_filename: str
    media_type: str
    disposition: str
    size: int
    sha256: str
    payload: bytes = field(repr=False)
    nested_depth: int = 0
    traversal_detected: bool = False
    warnings: tuple[str, ...] = ()
    related_root_path: str = ""
    related_part_path: str = ""
    related_container_path: str = ""
    content_id: str = ""
    reference_count: int = 0
    related_status: str = ""
    related_inline_only: bool = False
    related_issue_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedMessage:
    message_id: str
    subject: str
    sender: str
    sent_at: str
    candidates: tuple[AttachmentCandidate, ...]
    warnings: tuple[str, ...] = ()
    related_issues: tuple[RelatedReferenceIssue, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    status: Decision
    reason_code: str
    reason: str

    @property
    def is_stored(self) -> bool:
        return self.status in (Decision.ACCEPTED, Decision.QUARANTINED)


@dataclass(frozen=True)
class StoredObject:
    sha256: str
    size: int
    relative_path: str
    kind: StorageKind
    created: bool


@dataclass(frozen=True)
class MessageRecord:
    source_name: str
    relative_path: str
    digest: str
    size: int
    message_id: str
    subject: str
    sender: str
    sent_at: str
    status: MessageStatus
    error_code: str = ""
    error_detail: str = ""
    warnings: tuple[str, ...] = ()
    related_issues: tuple[RelatedReferenceIssue, ...] = ()

    @property
    def source_ref(self) -> str:
        return f"{self.source_name}/{self.relative_path}"


@dataclass(frozen=True)
class AttachmentRecord:
    part_id: str
    sha256: str
    size: int
    filename: str
    safe_filename: str
    media_type: str
    disposition: str
    nested_depth: int
    status: Decision
    reason_code: str
    reason: str
    object_path: str = ""
    quarantine_path: str = ""
    related_root_path: str = ""
    related_part_path: str = ""
    related_container_path: str = ""
    content_id: str = ""
    reference_count: int = 0
    related_status: str = ""


@dataclass
class RunSummary:
    run_id: str = ""
    status: str = "running"
    started_at: str = ""
    finished_at: str = ""
    messages_seen: int = 0
    messages_skipped: int = 0
    messages_ok: int = 0
    messages_error: int = 0
    attachments_seen: int = 0
    accepted: int = 0
    quarantined: int = 0
    rejected: int = 0
    duplicates: int = 0
    objects_created: int = 0
    ignored_symlinks: int = 0
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def messages_processed(self) -> int:
        return self.messages_ok + self.messages_error

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "messages_seen": self.messages_seen,
            "messages_skipped": self.messages_skipped,
            "messages_processed": self.messages_processed,
            "messages_ok": self.messages_ok,
            "messages_error": self.messages_error,
            "attachments_seen": self.attachments_seen,
            "accepted": self.accepted,
            "quarantined": self.quarantined,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "objects_created": self.objects_created,
            "ignored_symlinks": self.ignored_symlinks,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ObjectManifestEntry:
    """One deduplicated stored object; per-part relations live in ``parts``."""

    sha256: str
    size: int
    status: str
    path: str
    media_type: str
    filename: str
    safe_filename: str
    source_ref: str
    part_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "status": self.status,
            "path": self.path,
            "media_type": self.media_type,
            "filename": self.filename,
            "safe_filename": self.safe_filename,
            "source_ref": self.source_ref,
            "part_id": self.part_id,
        }
