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


class SignatureIntegrity(str, Enum):
    """Whether the signed bytes themselves check out.

    ``valid`` only proves that the signature mathematically covers the current
    MIME bytes.  It says nothing about whether the signing certificate is
    trusted by this machine; that is a separate decision.
    """

    NOT_SIGNED = "not_signed"
    VALID = "valid"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


class SignatureTrust(str, Enum):
    """Locally decided trust level for a cryptographically valid signature."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    NOT_APPLICABLE = "not_applicable"


class StorageKind(str, Enum):
    OBJECT = "objects"
    QUARANTINE = "quarantine"


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


@dataclass(frozen=True)
class ParsedMessage:
    message_id: str
    subject: str
    sender: str
    sent_at: str
    candidates: tuple[AttachmentCandidate, ...]
    warnings: tuple[str, ...] = ()
    signature: SignatureEvidence | None = None


@dataclass(frozen=True)
class SignerIdentity:
    """Facts read from the signing certificate; never a trust assertion."""

    subject: str
    issuer: str
    serial: str
    fingerprint_sha256: str
    not_before: str
    not_after: str
    self_issued: bool


@dataclass(frozen=True)
class SignatureEvidence:
    """One multipart/signed layer and the offline result for its bytes."""

    integrity: SignatureIntegrity
    trust: SignatureTrust
    reason_code: str
    reason: str
    signed_content_sha256: str = ""
    signature_sha256: str = ""
    protocol: str = "application/pkcs7-signature"
    micalg: str = ""
    signer: SignerIdentity | None = None
    anchor_fingerprint: str = ""
    signature_type: str = ""
    trust_reason_code: str = ""
    layer_count: int = 0
    digest_algorithm: str = ""

    @property
    def is_trusted(self) -> bool:
        return (
            self.integrity is SignatureIntegrity.VALID
            and self.trust is SignatureTrust.TRUSTED
        )

    @property
    def verdict(self) -> str:
        if self.integrity is SignatureIntegrity.VALID:
            if self.trust is SignatureTrust.TRUSTED:
                return "trusted"
            if self.trust is SignatureTrust.UNTRUSTED:
                return "integrity_valid_but_untrusted"
            return "integrity_valid_trust_undetermined"
        return self.integrity.value

    def as_dict(self) -> dict[str, Any]:
        signer = self.signer
        return {
            "integrity": self.integrity.value,
            "trust": self.trust.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "signed_content_sha256": self.signed_content_sha256,
            "signature_sha256": self.signature_sha256,
            "protocol": self.protocol,
            "micalg": self.micalg,
            "anchor_fingerprint": self.anchor_fingerprint,
            "signature_type": self.signature_type,
            "digest_algorithm": self.digest_algorithm,
            "trust_reason_code": self.trust_reason_code,
            "layer_count": self.layer_count,
            "verdict": self.verdict,
            "signer": None
            if signer is None
            else {
                "subject": signer.subject,
                "issuer": signer.issuer,
                "serial": signer.serial,
                "fingerprint_sha256": signer.fingerprint_sha256,
                "not_before": signer.not_before,
                "not_after": signer.not_after,
                "self_issued": signer.self_issued,
            },
        }


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
    signature: SignatureEvidence | None = None
    evidence_hash: str = ""
    attachment_findings: tuple[AttachmentFinding, ...] = ()

    @property
    def source_ref(self) -> str:
        return f"{self.source_name}/{self.relative_path}"


@dataclass(frozen=True)
class AttachmentFinding:
    """One audit line showing how message authenticity affects an attachment."""

    part_id: str
    status: str
    reason_code: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "part_id": self.part_id,
            "status": self.status,
            "reason_code": self.reason_code,
            "detail": self.detail,
        }


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
    signature_status: str = "none"
    signature_reason_code: str = ""
    signature_detail: str = ""


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
    signature_verdicts: dict[str, int] = field(default_factory=dict)
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
            "signature_verdicts": dict(sorted(self.signature_verdicts.items())),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ObjectManifestEntry:
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
