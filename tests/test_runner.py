from __future__ import annotations

import json
from pathlib import Path

from mailatt.config import default_config_for_fixtures
from mailatt.ledger import Ledger
from mailatt.runner import collect
from mailatt.storage import ObjectStore
from mailatt.verify import verify_workdir

from conftest import FIXTURES, fixed_clock


def test_demo_collection_matches_expected_summary(demo_run, expected_demo) -> None:
    summary = demo_run.result.summary
    assert summary.messages_seen == expected_demo["messages_total"]
    assert summary.messages_ok == expected_demo["messages_ok"]
    assert summary.messages_error == expected_demo["messages_error"]
    assert summary.attachments_seen == expected_demo["attachments_total"]
    assert summary.accepted == expected_demo["attachments_by_status"]["accepted"]
    assert summary.quarantined == expected_demo["attachments_by_status"]["quarantined"]
    assert summary.rejected == expected_demo["attachments_by_status"]["rejected"]
    assert summary.duplicates == expected_demo["attachments_by_status"]["duplicate"]
    assert summary.objects_created == expected_demo["objects_total"]
    assert summary.status == "completed_with_errors"


def test_bad_messages_are_isolated(demo_run, expected_demo) -> None:
    with Ledger(demo_run.workdir, readonly=True) as ledger:
        errors = ledger.errors()
        messages = ledger.all_messages()
    error_sources = sorted(f"{row['source_name']}/{row['relative_path']}" for row in errors)
    assert error_sources == expected_demo["expected_error_sources"]
    assert len(messages) == expected_demo["messages_total"]
    good = [row for row in messages if row["status"] == "ok"]
    assert len(good) == expected_demo["messages_ok"]


def test_manifest_and_ledger_reference_same_objects(demo_run, expected_demo) -> None:
    manifest = json.loads(demo_run.result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["object_count"] == expected_demo["objects_total"]
    assert len(manifest["objects"]) == expected_demo["objects_total"]
    assert manifest["run_id"] == demo_run.result.summary.run_id
    paths = [entry["path"] for entry in manifest["objects"]]
    assert paths == sorted(paths, key=lambda value: (value.startswith("quarantine"), value))
    assert all(entry["path"].endswith(entry["sha256"]) for entry in manifest["objects"])
    with Ledger(demo_run.workdir, readonly=True) as ledger:
        references = ledger.referenced_objects()
    referenced = {row["object_path"] or row["quarantine_path"] for row in references}
    assert referenced == set(paths)


def test_suspicious_content_is_written_only_to_quarantine(demo_run) -> None:
    with Ledger(demo_run.workdir, readonly=True) as ledger:
        rows = ledger.all_attachments()
    quarantined = [row for row in rows if row["status"] == "quarantined"]
    assert len(quarantined) == 1
    row = quarantined[0]
    assert row["safe_filename"] == "invoice.exe"
    assert row["quarantine_path"].startswith("quarantine/")
    assert row["object_path"] == ""
    store = ObjectStore(demo_run.workdir, create=False)
    data = store.read_bytes(row["quarantine_path"])
    assert b"plain text only" in data
    assert not data.startswith(b"MZ")


def test_object_names_never_use_original_filenames(demo_run) -> None:
    with Ledger(demo_run.workdir, readonly=True) as ledger:
        rows = ledger.all_attachments()
    for row in rows:
        for key in ("object_path", "quarantine_path"):
            path = row[key]
            if path:
                assert row["safe_filename"] not in path
                assert row["filename"] not in path
                assert len(Path(path).name) == 64


def test_verification_passes_for_demo(demo_run) -> None:
    result = verify_workdir(demo_run.workdir)
    assert result.ok
    assert result.checked_objects == 7
    assert result.checked_references == 7
    assert result.issues == []


def test_repeat_run_is_incremental_and_does_not_duplicate(tmp_path: Path) -> None:
    config = default_config_for_fixtures(FIXTURES, tmp_path / "work")
    first = collect(config, clock=fixed_clock)
    assert first.summary.run_id == "run-000001"
    with Ledger(config.workdir, readonly=True) as ledger:
        first_counts = (
            ledger.count_rows("runs"),
            ledger.count_rows("messages"),
            ledger.count_rows("attachments"),
        )
    second = collect(config, clock=fixed_clock)
    assert second.summary.run_id == "run-000002"
    assert second.summary.messages_seen == 11
    assert second.summary.messages_skipped == 9
    assert second.summary.messages_ok == 0
    assert second.summary.messages_error == 2
    assert second.summary.objects_created == 0
    with Ledger(config.workdir, readonly=True) as ledger:
        second_counts = (
            ledger.count_rows("runs"),
            ledger.count_rows("messages"),
            ledger.count_rows("attachments"),
        )
    assert second_counts == (first_counts[0] + 1, first_counts[1], first_counts[2])
    assert verify_workdir(config.workdir).ok


def test_repeat_run_keeps_manifest_object_entries(tmp_path: Path) -> None:
    config = default_config_for_fixtures(FIXTURES, tmp_path / "work")
    first = collect(config, clock=fixed_clock)
    before = json.loads(first.manifest_path.read_text(encoding="utf-8"))["objects"]
    second = collect(config, clock=fixed_clock)
    after = json.loads(second.manifest_path.read_text(encoding="utf-8"))["objects"]
    assert before == after
    assert before
    assert second.summary.run_id != first.summary.run_id
