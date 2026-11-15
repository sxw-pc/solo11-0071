"""Collection pipeline with per-message failure isolation.

Each message is committed with a recoverable two-phase record
(see :mod:`mailatt.recovery`): attachment payloads are staged under
``staging/<commit-key>/`` together with a durable journal, promoted into the
content-addressed object store, and only then written to the SQLite ledger in a
single transaction.  A crash between object writes and ledger sync therefore
leaves a resumable journal instead of unreferenced orphan objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .config import Config
from .discovery import discover
from .errors import MimeParseError, normalize_error
from .ledger import Ledger
from .manifest import write_manifest
from .mime import MimeOptions, parse_message
from .models import (
    AttachmentCandidate,
    AttachmentRecord,
    Decision,
    DiscoveredFile,
    MessageRecord,
    MessageStatus,
    PolicyDecision,
    RunSummary,
    StorageKind,
)
from .policy import assess_candidates
from .recovery import (
    ACTION_CLEAN,
    ACTION_COMMIT,
    ACTION_QUARANTINE,
    CommitJournal,
    build_recovery_plan,
    complete_message_commit,
    execute_recovery_plan,
    stage_message_commit,
)
from .report import generate_reports
from .storage import ObjectStore
from .util import iso_utc, utc_now

Clock = Callable[[], datetime]


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


def _attachment_record(
    candidate: AttachmentCandidate,
    decision: PolicyDecision,
    object_path: str,
    quarantine_path: str,
) -> AttachmentRecord:
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
    )


def _process_message(
    file: DiscoveredFile,
    config: Config,
    store: ObjectStore,
    known_hashes: set[str],
    summary: RunSummary,
    run_id: str,
) -> tuple[MessageRecord, list[AttachmentRecord], CommitJournal]:
    """Parse, policy-check and stage one message; no ledger writes happen here."""
    data = _read_file(file, config.policy.max_message_bytes)
    mime_options = MimeOptions(
        allow_nested_messages=config.policy.allow_nested_messages,
        max_nested_depth=config.policy.max_nested_depth,
        max_filename_length=config.policy.max_filename_length,
    )
    parsed = parse_message(data, mime_options)
    decisions = assess_candidates(parsed.candidates, config.policy, known_hashes)
    records: list[AttachmentRecord] = []
    staged: list[tuple[StorageKind, AttachmentCandidate]] = []
    for candidate, decision in zip(parsed.candidates, decisions):
        object_path = ""
        quarantine_path = ""
        if decision.status == Decision.ACCEPTED:
            kind = StorageKind.OBJECT
            object_path = store.relative_path(kind, candidate.sha256)
            staged.append((kind, candidate))
        elif decision.status == Decision.QUARANTINED:
            kind = StorageKind.QUARANTINE
            quarantine_path = store.relative_path(kind, candidate.sha256)
            staged.append((kind, candidate))
        elif decision.status == Decision.DUPLICATE:
            object_path = store.relative_path(StorageKind.OBJECT, candidate.sha256)
            if not store.exists(StorageKind.OBJECT, candidate.sha256):
                kind = StorageKind.OBJECT
                staged.append((kind, candidate))
                decision = PolicyDecision(
                    Decision.ACCEPTED,
                    "accepted_after_missing_object",
                    "duplicate reference was missing; object was restored",
                )
        records.append(_attachment_record(candidate, decision, object_path, quarantine_path))

    message = MessageRecord(
        source_name=file.source_name,
        relative_path=file.relative_path,
        digest=file.digest,
        size=file.size,
        message_id=parsed.message_id,
        subject=parsed.subject,
        sender=parsed.sender,
        sent_at=parsed.sent_at,
        status=MessageStatus.OK,
        warnings=parsed.warnings,
    )
    journal = CommitJournal.create(
        source_name=file.source_name,
        relative_path=file.relative_path,
        source_absolute=file.absolute_path,
        message=message,
        records=records,
        policy_hash=config.policy_fingerprint,
        run_id=run_id,
        mime_options=mime_options,
    )
    # Phase 1a: stage every payload under the stable commit key.
    for kind, candidate in staged:
        store.put_staged(
            journal.commit_key, candidate.payload, expected_sha256=candidate.sha256
        )
    # Phase 1b: durably record the intent to commit.
    stage_message_commit(config.workdir, store, journal)
    summary.attachments_seen += len(records)
    summary.accepted += sum(item.status == Decision.ACCEPTED for item in records)
    summary.quarantined += sum(item.status == Decision.QUARANTINED for item in records)
    summary.rejected += sum(item.status == Decision.REJECTED for item in records)
    summary.duplicates += sum(item.status == Decision.DUPLICATE for item in records)
    return message, records, journal


def _reconcile_pending(
    config: Config,
    store: ObjectStore,
    ledger: Ledger,
    summary: RunSummary,
    clock: Clock,
) -> None:
    """Resume journals left behind by earlier interrupted or failed commits.

    Uses the quarantine strategy so unrecoverable payloads stay locatable in
    ``uncommitted/``; the explicit ``recover`` command offers cleanup instead.
    """
    plan = build_recovery_plan(config.workdir)
    if not plan.items and not plan.orphans:
        return
    execute_recovery_plan(plan, ledger, clock=clock)
    for item in plan.items:
        summary.pending_commits += 1
        if item.action == ACTION_COMMIT:
            summary.messages_ok += 1
            continue
        summary.recovery_failures += 1
        summary.errors.append(
            {
                "source_ref": item.journal.source_ref
                if item.journal is not None
                else f"staging/{item.commit_key}",
                "code": "RECOVERY_FAILED",
                "detail": f"{item.action}: {item.reason}"[:2000],
            }
        )
        if item.action == ACTION_QUARANTINE:
            summary.uncommitted_quarantined += 1
        elif item.action == ACTION_CLEAN:
            summary.uncommitted_cleaned += 1
    for orphan in plan.orphans:
        if orphan.action == ACTION_QUARANTINE:
            summary.uncommitted_quarantined += 1
        elif orphan.action == ACTION_CLEAN:
            summary.uncommitted_cleaned += 1
    for failure in plan.execution_errors:
        summary.recovery_failures += 1
        summary.errors.append(
            {
                "source_ref": failure.get("source_ref") or f"staging/{failure['commit_key']}",
                "code": failure["code"],
                "detail": failure["detail"][:2000],
            }
        )


def collect(config: Config, *, clock: Clock = utc_now, force: bool = False) -> CollectionResult:
    """Run a complete local collection and return stable run metadata."""
    started = iso_utc(clock())
    summary = RunSummary(started_at=started)
    with Ledger(config.workdir) as ledger:
        store = ObjectStore(config.workdir)
        run_id = ledger.begin_run(started, config.policy_fingerprint)
        summary.run_id = run_id
        try:
            # Resume any interrupted commits before touching new messages so
            # object files and ledger references converge first.
            _reconcile_pending(config, store, ledger, summary, clock)

            def unchanged(file: DiscoveredFile) -> bool:
                if force or not file.digest:
                    return False
                state = ledger.message_state(file.source_name, file.relative_path)
                return bool(
                    state
                    and state["status"] == MessageStatus.OK.value
                    and state["digest"] == file.digest
                    and state["policy_hash"] == config.policy_fingerprint
                )

            outcome = discover(config, is_unchanged=unchanged)
            summary.messages_seen = len(outcome.files) + outcome.skipped_count
            summary.messages_skipped = outcome.skipped_count
            summary.ignored_symlinks = outcome.ignored_symlinks
            known_hashes = ledger.accepted_hashes() | store.accepted_digests()

            for file in outcome.files:
                try:
                    message, records, journal = _process_message(
                        file, config, store, known_hashes, summary, run_id
                    )
                    _, created_paths = complete_message_commit(
                        config.workdir, store, ledger, journal
                    )
                    summary.objects_created += len(created_paths)
                    summary.messages_ok += 1
                except Exception as exc:
                    error = normalize_error(exc)
                    failed = _message_error(file, exc)
                    message_id = ledger.upsert_message(failed, run_id, config.policy_fingerprint)
                    ledger.sync_attachments(message_id, [], run_id)
                    summary.messages_error += 1
                    summary.errors.append(
                        {
                            "source_ref": file.source_ref,
                            "code": error.code,
                            "detail": (error.detail or "")[:2000],
                        }
                    )

            manifest_path = write_manifest(config.workdir, ledger, store, run_id)
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
