"""Collection pipeline with per-message failure isolation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .config import Config
from .discovery import discover
from .errors import MimeParseError, StorageError, normalize_error
from .ledger import Ledger
from .mime import MimeOptions, parse_message
from .models import (
    AttachmentCandidate,
    AttachmentFinding,
    AttachmentRecord,
    Decision,
    DiscoveredFile,
    MessageRecord,
    MessageStatus,
    ObjectManifestEntry,
    PolicyDecision,
    RunSummary,
    SignatureEvidence,
    SignatureIntegrity,
    SignatureTrust,
    StorageKind,
)
from .policy import assess_candidates
from .report import generate_reports
from .storage import ObjectStore
from .util import atomic_write_json, iso_utc, sha256_bytes, utc_now

Clock = Callable[[], datetime]

# Reasons an attachment's review status is downgraded by message authenticity.
SIGNATURE_INVALID_CODE = "message_signature_invalid"
SIGNATURE_UNTRUSTED_CODE = "message_signature_untrusted"


@dataclass(frozen=True)
class CollectionResult:
    summary: RunSummary
    manifest_path: Path
    report_paths: dict[str, Path]


def _message_error(file: DiscoveredFile, exc: BaseException) -> MessageRecord:
    error = normalize_error(exc)
    return MessageRecord(
        source_name=file.source_name,
        relative_path=file.relative_path,
        digest=file.digest,
        size=file.size,
        message_id="",
        subject="",
        sender="",
        sent_at="",
        status=MessageStatus.ERROR,
        error_code=error.code,
        error_detail=(error.detail or "")[:2000],
    )


def _read_file(file: DiscoveredFile, max_bytes: int) -> bytes:
    """Read one authoritative byte snapshot used for parse and signature."""
    if file.size > max_bytes:
        raise MimeParseError(
            f"message size {file.size} exceeds {max_bytes}", code="MESSAGE_TOO_LARGE"
        )
    try:
        data = file.absolute_path.read_bytes()
    except OSError as exc:
        raise MimeParseError(f"cannot read message: {exc}", code="MESSAGE_FAILED") from exc
    if len(data) > max_bytes:
        raise MimeParseError(
            f"message size {len(data)} exceeds {max_bytes}", code="MESSAGE_TOO_LARGE"
        )
    return data


def _evidence_hash(data: bytes, evidence: SignatureEvidence | None) -> str:
    """Bind signature state and certificate fingerprints to the source bytes."""
    payload = {
        "source_digest": sha256_bytes(data),
        "signature": evidence.as_dict() if evidence is not None else None,
    }
    return sha256_bytes(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    )


def _finding(candidate: AttachmentCandidate, evidence: SignatureEvidence | None) -> AttachmentFinding:
    if evidence is None or evidence.integrity in (
        SignatureIntegrity.NOT_SIGNED,
        SignatureIntegrity.VALID,
    ):
        if evidence is not None and evidence.integrity is SignatureIntegrity.VALID:
            if evidence.trust is not SignatureTrust.TRUSTED:
                return AttachmentFinding(
                    part_id=candidate.part_id,
                    status="untrusted_signer",
                    reason_code=SIGNATURE_UNTRUSTED_CODE,
                    detail="signature is valid but the signer is not a local trust anchor",
                )
        return AttachmentFinding(
            part_id=candidate.part_id,
            status="none",
            reason_code="",
            detail="",
        )
    if evidence.integrity is SignatureIntegrity.INVALID:
        return AttachmentFinding(
            part_id=candidate.part_id,
            status="signature_invalid",
            reason_code=SIGNATURE_INVALID_CODE,
            detail="attachment came from a message whose signature does not cover its bytes",
        )
    return AttachmentFinding(
        part_id=candidate.part_id,
        status="unverifiable",
        reason_code="message_signature_unverifiable",
        detail="attachment came from a message whose signature could not be verified",
    )


def _attachment_record(
    candidate: AttachmentCandidate,
    decision: PolicyDecision,
    object_path: str,
    quarantine_path: str,
    finding: AttachmentFinding | None = None,
) -> AttachmentRecord:
    finding = finding or AttachmentFinding(candidate.part_id, "none", "", "")
    return AttachmentRecord(
        part_id=candidate.part_id,
        sha256=candidate.sha256,
        size=candidate.size,
        filename=candidate.filename,
        safe_filename=candidate.safe_filename,
        media_type=candidate.media_type,
        disposition=candidate.disposition,
        nested_depth=candidate.nested_depth,
        status=decision.status,
        reason_code=decision.reason_code,
        reason=decision.reason,
        object_path=object_path,
        quarantine_path=quarantine_path,
        signature_status=finding.status,
        signature_reason_code=finding.reason_code,
        signature_detail=finding.detail,
    )


def _authenticity_override(
    decision: PolicyDecision, evidence: SignatureEvidence | None
) -> PolicyDecision:
    """Never let an invalid signature end up as a trusted accepted object.

    Evidence bytes are still preserved for audit, but they go to quarantine
    under an explicit reason so reports and downloads cannot read them as
    authenticated content.  Unverifiable signatures keep the policy decision
    and are surfaced separately; only a proven mismatch forces quarantine.
    """
    if evidence is None or evidence.integrity is not SignatureIntegrity.INVALID:
        return decision
    if decision.status in (Decision.ACCEPTED, Decision.DUPLICATE):
        return PolicyDecision(
            Decision.QUARANTINED,
            SIGNATURE_INVALID_CODE,
            "attachments from a message with an invalid signature are quarantined",
        )
    return decision


def _process_message(
    file: DiscoveredFile,
    config: Config,
    store: ObjectStore,
    known_hashes: set[str],
    summary: RunSummary,
    *,
    clock: Clock = utc_now,
) -> tuple[MessageRecord, list[AttachmentRecord]]:
    # One authoritative snapshot: parsing, signature verification and the
    # evidence hash all consume these same bytes.
    data = _read_file(file, config.policy.max_message_bytes)
    # Bind the record to the bytes actually verified, not to an earlier
    # discovery-time digest that the file may have raced past.
    snapshot_digest = sha256_bytes(data)
    parsed = parse_message(
        data,
        MimeOptions(
            allow_nested_messages=config.policy.allow_nested_messages,
            max_nested_depth=config.policy.max_nested_depth,
            max_filename_length=config.policy.max_filename_length,
            trust=config.trust,
            signature_time=clock(),
        ),
    )
    evidence = parsed.signature
    evidence_hash = _evidence_hash(data, evidence)
    if evidence is not None:
        summary.signature_verdicts[evidence.verdict] = (
            summary.signature_verdicts.get(evidence.verdict, 0) + 1
        )
    decisions = assess_candidates(parsed.candidates, config.policy, known_hashes)
    records: list[AttachmentRecord] = []
    findings: list[AttachmentFinding] = []
    for candidate, decision in zip(parsed.candidates, decisions):
        finding = _finding(candidate, evidence)
        findings.append(finding)
        overridden = _authenticity_override(decision, evidence)
        if overridden is not decision and decision.status == Decision.ACCEPTED:
            # assess_candidates registered this digest as archived; it is not.
            known_hashes.discard(candidate.sha256)
        decision = overridden
        object_path = ""
        quarantine_path = ""
        if decision.status == Decision.ACCEPTED:
            stored = store.put(StorageKind.OBJECT, candidate.payload, expected_sha256=candidate.sha256)
            object_path = stored.relative_path
            summary.objects_created += int(stored.created)
        elif decision.status == Decision.QUARANTINED:
            stored = store.put(
                StorageKind.QUARANTINE, candidate.payload, expected_sha256=candidate.sha256
            )
            quarantine_path = stored.relative_path
            summary.objects_created += int(stored.created)
        elif decision.status == Decision.DUPLICATE:
            object_path = store.relative_path(StorageKind.OBJECT, candidate.sha256)
            if not store.exists(StorageKind.OBJECT, candidate.sha256):
                stored = store.put(StorageKind.OBJECT, candidate.payload, expected_sha256=candidate.sha256)
                object_path = stored.relative_path
                summary.objects_created += int(stored.created)
                decision = PolicyDecision(
                    Decision.ACCEPTED,
                    "accepted_after_missing_object",
                    "duplicate reference was missing; object was restored",
                )
        records.append(
            _attachment_record(candidate, decision, object_path, quarantine_path, finding)
        )
    summary.attachments_seen += len(records)
    summary.accepted += sum(item.status == Decision.ACCEPTED for item in records)
    summary.quarantined += sum(item.status == Decision.QUARANTINED for item in records)
    summary.rejected += sum(item.status == Decision.REJECTED for item in records)
    summary.duplicates += sum(item.status == Decision.DUPLICATE for item in records)
    message = MessageRecord(
        source_name=file.source_name,
        relative_path=file.relative_path,
        digest=snapshot_digest,
        size=len(data),
        message_id=parsed.message_id,
        subject=parsed.subject,
        sender=parsed.sender,
        sent_at=parsed.sent_at,
        status=MessageStatus.OK,
        warnings=parsed.warnings,
        signature=evidence,
        evidence_hash=evidence_hash,
        attachment_findings=tuple(findings),
    )
    return message, records


def _manifest_entries(ledger: Ledger, store: ObjectStore) -> list[ObjectManifestEntry]:
    existing = {item.relative_path for item in store.list_files()}
    by_path: dict[str, ObjectManifestEntry] = {}
    for row in ledger.referenced_objects():
        status = row["status"]
        path = row["quarantine_path"] if status == "quarantined" else row["object_path"]
        if not path or path not in existing or path in by_path:
            continue
        manifest_status = "quarantined" if status == "quarantined" else "accepted"
        by_path[path] = ObjectManifestEntry(
            sha256=row["sha256"],
            size=row["size"],
            status=manifest_status,
            path=path,
            media_type=row["media_type"],
            filename=row["filename"],
            safe_filename=row["safe_filename"],
            source_ref=f"{row['message_source']}/{row['message_path']}",
            part_id=row["part_id"],
        )
    return sorted(by_path.values(), key=lambda item: (item.status, item.path))


def _write_manifest(config: Config, ledger: Ledger, store: ObjectStore, run_id: str) -> Path:
    entries = _manifest_entries(ledger, store)
    payload = {
        "schema_version": "1.0",
        "run_id": run_id,
        "object_count": len(entries),
        "objects": [entry.as_dict() for entry in entries],
    }
    path = config.workdir / "manifest.json"
    try:
        atomic_write_json(path, payload)
    except OSError as exc:
        raise StorageError(f"cannot write manifest: {exc}") from exc
    return path


def collect(config: Config, *, clock: Clock = utc_now, force: bool = False) -> CollectionResult:
    """Run a complete local collection and return stable run metadata."""
    started = iso_utc(clock())
    summary = RunSummary(started_at=started)
    with Ledger(config.workdir) as ledger:
        store = ObjectStore(config.workdir)
        run_id = ledger.begin_run(started, config.policy_fingerprint)
        summary.run_id = run_id
        try:
            def unchanged(file: DiscoveredFile) -> bool:
                if force or not file.digest:
                    return False
                state = ledger.message_state(file.source_name, file.relative_path)
                if not state:
                    return False
                if state["status"] != MessageStatus.OK.value:
                    return False
                if state["digest"] != file.digest:
                    return False
                if state["policy_hash"] != config.policy_fingerprint:
                    return False
                # Trust-anchor changes alter the verdict without changing the
                # source bytes, so re-verification is keyed on both hashes.
                if state.get("evidence_config_hash") != config.evidence_fingerprint:
                    return False
                return bool(state.get("evidence_hash"))

            outcome = discover(config, is_unchanged=unchanged)
            summary.messages_seen = len(outcome.files) + outcome.skipped_count
            summary.messages_skipped = outcome.skipped_count
            summary.ignored_symlinks = outcome.ignored_symlinks
            known_hashes = ledger.accepted_hashes() | store.accepted_digests()

            for file in outcome.files:
                try:
                    message, records = _process_message(
                        file, config, store, known_hashes, summary, clock=clock
                    )
                    message_id = ledger.upsert_message(
                        message, run_id, config.policy_fingerprint,
                        evidence_config_hash=config.evidence_fingerprint,
                    )
                    ledger.sync_attachments(message_id, records, run_id)
                    summary.messages_ok += 1
                except Exception as exc:
                    error = normalize_error(exc)
                    failed = _message_error(file, exc)
                    message_id = ledger.upsert_message(
                        failed, run_id, config.policy_fingerprint,
                        evidence_config_hash=config.evidence_fingerprint,
                    )
                    ledger.sync_attachments(message_id, [], run_id)
                    summary.messages_error += 1
                    summary.errors.append(
                        {
                            "source_ref": file.source_ref,
                            "code": error.code,
                            "detail": (error.detail or "")[:2000],
                        }
                    )

            manifest_path = _write_manifest(config, ledger, store, run_id)
            summary.finished_at = iso_utc(clock())
            summary.status = "completed_with_errors" if summary.errors else "completed"
            ledger.finish_run(summary)
            report_paths = generate_reports(config, ledger, clock)
            return CollectionResult(summary, manifest_path, report_paths)
        except Exception:
            if summary.status == "running":
                summary.finished_at = iso_utc(clock())
                summary.status = "failed"
                try:
                    ledger.finish_run(summary)
                except Exception:
                    pass
            raise
