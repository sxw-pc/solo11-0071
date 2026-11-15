from __future__ import annotations

from pathlib import Path

import pytest

from mailatt.errors import LedgerError, StorageError
from mailatt.ledger import Ledger
from mailatt.models import (
    AttachmentRecord,
    Decision,
    MessageRecord,
    MessageStatus,
    RunSummary,
    StorageKind,
)
from mailatt.storage import ObjectStore


def test_content_addressed_storage_deduplicates(tmp_path: Path) -> None:
    store = ObjectStore(tmp_path / "work")
    data = b"synthetic attachment bytes"
    first = store.put(StorageKind.OBJECT, data)
    second = store.put(StorageKind.OBJECT, data)
    assert first.created is True
    assert second.created is False
    assert first.relative_path == f"objects/{first.sha256[:2]}/{first.sha256}"
    assert first.relative_path.endswith(first.sha256)
    assert "attachment" not in first.relative_path
    assert store.read_bytes(first.relative_path) == data
    assert store.accepted_digests() == {first.sha256}
    assert first.sha256 in {item.sha256 for item in store.list_files()}


def test_quarantine_uses_separate_root(tmp_path: Path) -> None:
    store = ObjectStore(tmp_path / "work")
    stored = store.put(StorageKind.QUARANTINE, b"dangerous placeholder")
    assert stored.relative_path.startswith("quarantine/")
    assert not stored.relative_path.startswith("objects/")
    assert store.exists(StorageKind.QUARANTINE, stored.sha256)
    assert not store.exists(StorageKind.OBJECT, stored.sha256)


def test_unsafe_paths_are_rejected(tmp_path: Path) -> None:
    store = ObjectStore(tmp_path / "work")
    with pytest.raises(StorageError):
        store.read_bytes("../../outside")
    with pytest.raises(StorageError):
        store.relative_path(StorageKind.OBJECT, "not-a-hash")
    with pytest.raises(StorageError):
        store.read_bytes("objects/aa/" + "f" * 64)


def test_existing_object_size_mismatch_is_detected(tmp_path: Path) -> None:
    store = ObjectStore(tmp_path / "work")
    data = b"correct content"
    relative = store.relative_path(StorageKind.OBJECT, __import__("hashlib").sha256(data).hexdigest())
    target = tmp_path / "work" / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x")
    with pytest.raises(StorageError) as caught:
        store.put(StorageKind.OBJECT, data)
    assert caught.value.code == "STORAGE_MISMATCH"


def message_record(status: MessageStatus = MessageStatus.OK) -> MessageRecord:
    return MessageRecord(
        source_name="demo",
        relative_path="one.eml",
        digest="a" * 64,
        size=100,
        message_id="one@demo.invalid",
        subject="Synthetic",
        sender="demo@demo.invalid",
        sent_at="2023-01-02T09:30:00+00:00",
        status=status,
        error_code="MALFORMED_MIME" if status == MessageStatus.ERROR else "",
        error_detail="broken" if status == MessageStatus.ERROR else "",
        warnings=("DemoDefect",),
    )


def attachment(part_id: str, status: Decision = Decision.ACCEPTED) -> AttachmentRecord:
    return AttachmentRecord(
        part_id=part_id,
        sha256="b" * 64,
        size=10,
        filename="note.txt",
        safe_filename="note.txt",
        media_type="text/plain",
        disposition="attachment",
        nested_depth=0,
        status=status,
        reason_code=status.value,
        reason="test",
        object_path="objects/bb/" + "b" * 64 if status == Decision.ACCEPTED else "",
    )


def test_ledger_upserts_messages_idempotently(tmp_path: Path) -> None:
    with Ledger(tmp_path / "work") as ledger:
        first_run = ledger.begin_run("2024-01-01T00:00:00+00:00", "policy-a")
        assert first_run == "run-000001"
        message_id = ledger.upsert_message(message_record(), first_run, "policy-a")
        second_run = ledger.begin_run("2024-01-02T00:00:00+00:00", "policy-a")
        assert second_run == "run-000002"
        same_id = ledger.upsert_message(message_record(), second_run, "policy-a")
        assert same_id == message_id
        assert ledger.count_rows("messages") == 1
        row = ledger.get_message(message_id)
        assert row is not None
        assert row["first_seen_run"] == "run-000001"
        assert row["last_seen_run"] == "run-000002"
        assert ledger.message_state("demo", "one.eml")["digest"] == "a" * 64


def test_ledger_attachment_sync_preserves_and_deletes(tmp_path: Path) -> None:
    with Ledger(tmp_path / "work") as ledger:
        run_id = ledger.begin_run("2024-01-01T00:00:00+00:00", "policy")
        message_id = ledger.upsert_message(message_record(), run_id, "policy")
        ledger.sync_attachments(message_id, [attachment("p001"), attachment("p002")], run_id)
        assert len(ledger.attachments_for_message(message_id)) == 2
        next_run = ledger.begin_run("2024-01-02T00:00:00+00:00", "policy")
        ledger.sync_attachments(message_id, [attachment("p001")], next_run)
        rows = ledger.attachments_for_message(message_id)
        assert len(rows) == 1
        assert rows[0]["first_seen_run"] == "run-000001"
        assert ledger.accepted_hashes() == {"b" * 64}
        assert len(ledger.referenced_objects()) == 1


def test_ledger_error_rows_and_summary(tmp_path: Path) -> None:
    with Ledger(tmp_path / "work") as ledger:
        run_id = ledger.begin_run("2024-01-01T00:00:00+00:00", "policy")
        ledger.upsert_message(message_record(MessageStatus.ERROR), run_id, "policy")
        summary = RunSummary(
            run_id=run_id,
            status="completed_with_errors",
            started_at="2024-01-01T00:00:00+00:00",
            finished_at="2024-01-01T00:00:01+00:00",
            messages_seen=1,
            messages_error=1,
            errors=[{"source_ref": "demo/one.eml", "code": "X", "detail": "d"}],
        )
        ledger.finish_run(summary)
        assert ledger.errors()[0]["error_code"] == "MALFORMED_MIME"
        last = ledger.last_run()
        assert last["status"] == "completed_with_errors"
        assert last["summary"]["messages_error"] == 1
        assert ledger.count_rows("runs") == 1


def test_ledger_readonly_mode(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    with Ledger(workdir) as ledger:
        run_id = ledger.begin_run("2024-01-01T00:00:00+00:00", "policy")
        ledger.upsert_message(message_record(), run_id, "policy")
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("messages") == 1
        with pytest.raises(LedgerError):
            ledger.begin_run("2024-01-02T00:00:00+00:00", "policy")


