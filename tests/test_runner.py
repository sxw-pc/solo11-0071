from __future__ import annotations

import json
from pathlib import Path

import pytest

from mailatt.config import default_config_for_fixtures
from mailatt.ledger import Ledger
from mailatt.recovery import (
    ACTION_CLEAN,
    ACTION_COMMIT,
    ACTION_QUARANTINE,
    build_recovery_plan,
    recover_workdir,
)
from mailatt.runner import collect
from mailatt.storage import ObjectStore
from mailatt.util import sha256_bytes, sha256_file
from mailatt.verify import verify_workdir

from conftest import FIXTURES, fixed_clock
from recovery_helpers import (
    build_email,
    staging_journals,
    uncommitted_entries,
    write_source,
)


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


# ---------------------------------------------------------------------------
# Recoverable two-phase commit tests
# ---------------------------------------------------------------------------


def _multi_attachment_source(tmp_path: Path) -> tuple[Path, Path, bytes, bytes]:
    first = b"first attachment payload alpha"
    second = b"second attachment payload beta"
    email = build_email(
        subject="Multi attachment",
        message_id="multi@demo.invalid",
        attachments=(
            ("alpha.txt", "text/plain", first),
            ("beta.txt", "text/plain", second),
        ),
    )
    config_path, workdir = write_source(tmp_path, files={"multi.eml": email})
    return config_path, workdir, first, second


def test_successful_commit_leaves_no_staging(tmp_path: Path) -> None:
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    result = collect(load_config(config_path), clock=fixed_clock)
    assert result.summary.messages_ok == 1
    assert result.summary.pending_commits == 0
    assert staging_journals(workdir) == []
    assert uncommitted_entries(workdir) == []
    assert verify_workdir(workdir).ok


def test_rerun_uses_one_stable_commit_identity(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    config = load_config(config_path)
    seen_keys: list[str] = []
    import mailatt.runner as runner_module

    original = runner_module.complete_message_commit

    def spying_complete(workdir_arg, store, ledger, journal):
        seen_keys.append(journal.commit_key)
        return original(workdir_arg, store, ledger, journal)

    monkeypatch.setattr(runner_module, "complete_message_commit", spying_complete)
    collect(config, clock=fixed_clock)
    # Second run reprocesses the same source (force bypasses incremental skip).
    collect(config, clock=fixed_clock, force=True)
    assert len(seen_keys) == 2
    assert seen_keys[0] == seen_keys[1]
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("messages") == 1
        assert ledger.count_rows("attachments") == 2
    assert verify_workdir(workdir).ok


def test_multi_attachment_midway_failure_is_resumed(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, first, second = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    config = load_config(config_path)
    import mailatt.runner as runner_module

    calls = {"n": 0}
    original = runner_module.complete_message_commit

    def fail_once(workdir_arg, store, ledger, journal):
        calls["n"] += 1
        if calls["n"] == 1:
            # Simulate the process dying after objects were promoted but before
            # the ledger transaction landed.
            from mailatt.recovery import _journal_item, _promote_all

            _promote_all(
                store,
                _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine"),
            )
            raise RuntimeError("simulated crash between object write and ledger commit")
        return original(workdir_arg, store, ledger, journal)

    monkeypatch.setattr(runner_module, "complete_message_commit", fail_once)
    first_run = collect(config, clock=fixed_clock)
    assert first_run.summary.messages_error == 1
    # Orphan objects and a journal remain; verify distinguishes them.
    verification = verify_workdir(workdir)
    codes = {issue["code"] for issue in verification.issues}
    assert "PENDING_COMMIT" in codes
    assert "PENDING_COMMIT_OBJECT" in codes
    assert "OBJECT_ORPHAN" not in codes
    assert staging_journals(workdir) != []

    monkeypatch.undo()
    second_run = collect(config, clock=fixed_clock)
    assert second_run.summary.pending_commits == 1
    # The resumed journal accounts for the one message; incremental discovery
    # then skips it, so it is not processed a second time.
    assert second_run.summary.messages_ok == 1
    assert second_run.summary.recovery_failures == 0
    assert staging_journals(workdir) == []
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("messages") == 1
        rows = ledger.attachments_for_message(1)
        assert len(rows) == 2
        assert {row["sha256"] for row in rows} == {
            sha256_bytes(first),
            sha256_bytes(second),
        }
    assert verify_workdir(workdir).ok


def test_recovery_command_dry_run_does_not_mutate(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        _promote_all(
            store,
            _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine"),
        )
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    collect(load_config(config_path), clock=fixed_clock)
    assert staging_journals(workdir) != []

    plan = recover_workdir(workdir)  # default dry-run
    assert plan.dry_run is True
    assert len(plan.items) == 1
    assert plan.items[0].action == ACTION_COMMIT
    assert staging_journals(workdir) != []
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("attachments") == 0


def test_recovery_command_apply_resumes_and_is_repeatable(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        _promote_all(
            store,
            _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine"),
        )
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    collect(load_config(config_path), clock=fixed_clock)

    first = recover_workdir(workdir, apply=True, clock=fixed_clock)
    assert first.dry_run is False
    assert first.items[0].action == ACTION_COMMIT
    assert staging_journals(workdir) == []
    # Repeating recovery is a no-op and creates no duplicate references.
    second = recover_workdir(workdir, apply=True, clock=fixed_clock)
    assert second.items == []
    assert second.orphans == []
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("messages") == 1
        assert ledger.count_rows("attachments") == 2
    assert verify_workdir(workdir).ok


def test_same_content_referenced_by_two_messages_keeps_one_object(tmp_path: Path) -> None:
    payload = b"shared attachment content across distinct messages"
    one = build_email(
        subject="One", message_id="one@demo.invalid",
        attachments=(("shared.txt", "text/plain", payload),),
    )
    two = build_email(
        subject="Two", message_id="two@demo.invalid",
        attachments=(("shared.txt", "text/plain", payload),),
    )
    config_path, workdir = write_source(
        tmp_path, files={"one.eml": one, "sub/two.eml": two}
    )
    from mailatt.config import load_config

    result = collect(load_config(config_path), clock=fixed_clock)
    assert result.summary.messages_ok == 2
    store = ObjectStore(workdir, create=False)
    digest = sha256_bytes(payload)
    assert store.exists(__import__("mailatt.models", fromlist=["StorageKind"]).StorageKind.OBJECT, digest)
    with Ledger(workdir, readonly=True) as ledger:
        rows = ledger.referenced_objects()
        paths = [row["object_path"] for row in rows if row["sha256"] == digest]
        assert len(paths) == 2
        assert set(paths) == {f"objects/{digest[:2]}/{digest}"}
        assert ledger.object_reference_count(paths[0]) == 2
    assert verify_workdir(workdir).ok


def test_changed_source_blocks_attachment_to_old_history_quarantine(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, first, second = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    config = load_config(config_path)
    import mailatt.runner as runner_module

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        _promote_all(
            store,
            _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine"),
        )
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    collect(config, clock=fixed_clock)
    journals_before = staging_journals(workdir)
    assert len(journals_before) == 1

    # The source message changes while its commit is still pending.
    source_file = config.sources[0].path / "multi.eml"
    original_bytes = source_file.read_bytes()
    source_file.write_bytes(original_bytes + b"\nX-Mutated: true\n")
    try:
        plan = build_recovery_plan(workdir)
        assert plan.items[0].blocked is True
        assert plan.items[0].source_digest_matches is False
        assert plan.items[0].action == ACTION_QUARANTINE
        applied = recover_workdir(workdir, apply=True, clock=fixed_clock)
        assert applied.items[0].blocker == "blocked_source_changed"
    finally:
        source_file.write_bytes(original_bytes)

    # No new content was attached to the old message history.
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("messages") == 1
        assert ledger.count_rows("attachments") == 0
    entries = uncommitted_entries(workdir)
    assert len(entries) == 1
    preserved = sorted(path.name for path in entries[0].joinpath("objects").iterdir())
    assert preserved == sorted({sha256_bytes(first), sha256_bytes(second)})
    tombstone = json.loads((entries[0] / "tombstone.json").read_text(encoding="utf-8"))
    assert tombstone["action"] == ACTION_QUARANTINE
    assert staging_journals(workdir) == []
    verification = verify_workdir(workdir)
    codes = {issue["code"] for issue in verification.issues}
    assert "UNCOMMITTED_PRESERVED" in codes
    assert "OBJECT_ORPHAN" not in codes


def test_cleanup_strategy_keeps_shared_referenced_objects(tmp_path: Path, monkeypatch) -> None:
    payload = b"payload shared with an already committed message"
    committed_mail = build_email(
        subject="Committed", message_id="committed@demo.invalid",
        attachments=(("shared.txt", "text/plain", payload),),
    )
    pending_mail = build_email(
        subject="Pending", message_id="pending@demo.invalid",
        attachments=(("shared.txt", "text/plain", payload),),
    )
    config_path, workdir = write_source(
        tmp_path, files={"committed.eml": committed_mail, "pending.eml": pending_mail}
    )
    from mailatt.config import load_config

    config = load_config(config_path)
    # First run commits both messages normally.
    collect(config, clock=fixed_clock)
    digest = sha256_bytes(payload)
    final_path = f"objects/{digest[:2]}/{digest}"
    with Ledger(workdir) as ledger:
        assert ledger.object_reference_count(final_path) == 2
        # Detach only the pending message while keeping the object on disk,
        # reproducing an orphan still referenced by the other message.
        pending_id = next(
            row["id"]
            for row in ledger.all_messages()
            if row["relative_path"] == "pending.eml"
        )
        ledger.conn.execute("DELETE FROM attachments WHERE message_id=?", (pending_id,))
        ledger.conn.commit()
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.object_reference_count(final_path) == 1

    plan = recover_workdir(workdir, strategy="cleanup")
    # The object is still referenced, so it must not be offered for cleanup.
    assert all(orphan.path != final_path for orphan in plan.orphans)


def test_cleanup_strategy_removes_true_orphans_with_tombstone(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, first, second = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        item = _journal_item(
            workdir_arg, store, ledger, journal.commit_key, "cleanup"
        )
        _promote_all(store, item)
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    collect(load_config(config_path), clock=fixed_clock)
    promoted = ObjectStore(workdir, create=False).list_files()
    assert len(promoted) == 2

    # With the source message gone the journal cannot be verified; the cleanup
    # strategy then removes the uncommitted objects after reference checks.
    source_file = load_config(config_path).sources[0].path / "multi.eml"
    source_file.unlink()
    plan = recover_workdir(workdir, strategy="cleanup")
    assert plan.items[0].action == ACTION_CLEAN
    applied = recover_workdir(workdir, strategy="cleanup", apply=True, clock=fixed_clock)
    assert applied.items[0].action == ACTION_CLEAN
    assert ObjectStore(workdir, create=False).list_files() == []
    entries = uncommitted_entries(workdir)
    assert len(entries) == 1
    tombstone = json.loads((entries[0] / "tombstone.json").read_text(encoding="utf-8"))
    assert tombstone["action"] == ACTION_CLEAN
    removed = {item["sha256"] for item in tombstone["attachments"]}
    assert removed == {sha256_bytes(first), sha256_bytes(second)}
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("attachments") == 0
    verification = verify_workdir(workdir)
    codes = {issue["code"] for issue in verification.issues}
    assert "UNCOMMITTED_CLEANED" in codes
    assert "OBJECT_ORPHAN" not in codes


def test_preexisting_orphan_is_handled_by_recovery(tmp_path: Path) -> None:
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    collect(load_config(config_path), clock=fixed_clock)
    orphan_bytes = b"orphan left behind by an older run without journal"
    orphan_digest = sha256_bytes(orphan_bytes)
    orphan_path = workdir / "objects" / orphan_digest[:2] / orphan_digest
    orphan_path.parent.mkdir(parents=True, exist_ok=True)
    orphan_path.write_bytes(orphan_bytes)

    verification = verify_workdir(workdir)
    assert any(issue["code"] == "OBJECT_ORPHAN" for issue in verification.issues)

    plan = recover_workdir(workdir)
    orphan_plans = [item for item in plan.orphans if item.path.endswith(orphan_digest)]
    assert len(orphan_plans) == 1
    assert orphan_plans[0].action == ACTION_QUARANTINE
    applied = recover_workdir(workdir, apply=True, clock=fixed_clock)
    assert not orphan_path.exists()
    entries = uncommitted_entries(workdir)
    preserved = [
        path
        for entry in entries
        for path in entry.glob("objects/*")
        if path.name == orphan_digest
    ]
    assert len(preserved) == 1
    assert preserved[0].read_bytes() == orphan_bytes
    # The preserved quarantine remains auditable instead of silently clean.
    verification = verify_workdir(workdir)
    codes = {issue["code"] for issue in verification.issues}
    assert "UNCOMMITTED_PRESERVED" in codes
    assert "OBJECT_ORPHAN" not in codes


def test_missing_staged_payload_blocks_recovery(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, first, second = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash_before_promotion(workdir_arg, store, ledger, journal):
        # Simulate dying after staging and the journal exist but before any
        # object promotion, with one staged payload lost afterwards.
        raise RuntimeError("simulated crash before promotion")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash_before_promotion)
    collect(load_config(config_path), clock=fixed_clock)
    journal_file = staging_journals(workdir)[0]
    journal = json.loads(journal_file.read_text(encoding="utf-8"))
    doomed = journal["attachments"][0]["sha256"]
    (journal_file.parent / doomed).unlink()
    assert ObjectStore(workdir, create=False).list_files() == []

    plan = build_recovery_plan(workdir)
    assert plan.items[0].blocked is True
    assert plan.items[0].blocker == "blocked_attachment_unreproducible"
    recover_workdir(workdir, apply=True, clock=fixed_clock)
    entries = uncommitted_entries(workdir)
    assert len(entries) == 1
    preserved = sorted(path.name for path in entries[0].joinpath("objects").iterdir())
    # The still-available payload is preserved for investigation; the missing
    # one is recorded as unavailable instead of silently dropped.
    assert preserved == [sha256_bytes(second)]
    tombstone = json.loads((entries[0] / "tombstone.json").read_text(encoding="utf-8"))
    statuses = {item["sha256"]: item["preserved"] for item in tombstone["attachments"]}
    assert statuses[doomed] is False  # the deleted staged payload
    assert statuses[sha256_bytes(second)] is True  # the surviving payload
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("attachments") == 0


def test_journal_less_staging_is_preserved_and_cleared(tmp_path: Path) -> None:
    config_path, workdir, first, second = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash_before_journal(workdir_arg, store, ledger, journal):
        raise RuntimeError("simulated crash before journal write")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(runner_module, "complete_message_commit", crash_before_journal)
    # Remove the journal after staging to reproduce a journal-less directory.
    original_stage = runner_module.stage_message_commit

    def stage_without_journal(workdir_arg, store_arg, journal_arg):
        original_stage(workdir_arg, store_arg, journal_arg)
        from mailatt.recovery import journal_path

        journal_path(workdir_arg, journal_arg.commit_key).unlink()

    monkeypatch.setattr(runner_module, "stage_message_commit", stage_without_journal)
    collect(load_config(config_path), clock=fixed_clock)
    monkeypatch.undo()

    staging_dirs = [path for path in (workdir / "staging").iterdir() if path.is_dir()]
    assert len(staging_dirs) == 1
    assert not (staging_dirs[0] / "journal.json").exists()

    plan = build_recovery_plan(workdir)
    assert plan.items[0].journal_valid is False
    assert plan.items[0].blocker == "blocked_journal_invalid"
    recover_workdir(workdir, apply=True, clock=fixed_clock)

    entries = uncommitted_entries(workdir)
    assert len(entries) == 1
    preserved = sorted(path.name for path in entries[0].joinpath("objects").iterdir())
    assert preserved == sorted({sha256_bytes(first), sha256_bytes(second)})
    assert not any(path.is_dir() for path in (workdir / "staging").iterdir())
    verification = verify_workdir(workdir)
    codes = {issue["code"] for issue in verification.issues}
    assert "UNCOMMITTED_PRESERVED" in codes


def test_recovery_plan_without_ledger_treats_objects_as_orphans(tmp_path: Path) -> None:
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    collect(load_config(config_path), clock=fixed_clock)
    (workdir / "ledger.sqlite3").unlink()

    plan = build_recovery_plan(workdir)
    assert len(plan.orphans) == 2
    assert all(orphan.action == ACTION_QUARANTINE for orphan in plan.orphans)
    assert plan.dry_run is True


def test_recovery_isolates_a_single_failing_entry(tmp_path: Path, monkeypatch) -> None:
    # Two distinct messages; make one journal unreadable while the other stays
    # valid so recovery must still complete the healthy commit.
    payload_a = b"message alpha payload"
    payload_b = b"message beta payload"
    mail_a = build_email(
        subject="Alpha", message_id="alpha@demo.invalid",
        attachments=(("alpha.txt", "text/plain", payload_a),),
    )
    mail_b = build_email(
        subject="Beta", message_id="beta@demo.invalid",
        attachments=(("beta.txt", "text/plain", payload_b),),
    )
    config_path, workdir = write_source(
        tmp_path, files={"alpha.eml": mail_a, "beta.eml": mail_b}
    )
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        _promote_all(
            store,
            _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine"),
        )
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    collect(load_config(config_path), clock=fixed_clock)
    assert len(staging_journals(workdir)) == 2

    # Corrupt one journal file.
    target = staging_journals(workdir)[0]
    target.write_text("{not valid json", encoding="utf-8")
    plan = build_recovery_plan(workdir)
    assert len(plan.items) == 2

    # Make the corrupt journal's quarantine step fail by turning its staging
    # directory into an unreadable path situation is hard portably; instead the
    # invalid journal still resolves via quarantine. Execute and assert the
    # healthy message commits while the broken one is quarantined.
    applied = recover_workdir(workdir, apply=True, clock=fixed_clock)
    actions = sorted(item.action for item in applied.items)
    assert actions == [ACTION_COMMIT, ACTION_QUARANTINE]
    with Ledger(workdir) as ledger:
        rows = ledger.all_messages()
        # The two crashed messages were recorded as errors during the first
        # run; recovery adds exactly one healthy message instead of touching
        # the blocked message's history.
        assert len(rows) == 2
        statuses = sorted(row["status"] for row in rows)
        assert statuses == ["error", "ok"]
        healthy = next(row for row in rows if row["status"] == "ok")
        attachments = ledger.attachments_for_message(healthy["id"])
        assert len(attachments) == 1
        blocked = next(row for row in rows if row["status"] == "error")
        assert ledger.attachments_for_message(blocked["id"]) == []
    assert staging_journals(workdir) == []
    # One entry preserves the corrupt journal's staged payloads, another holds
    # the already-promoted object that no ledger reference exists for.
    assert len(uncommitted_entries(workdir)) == 2
    assert applied.execution_errors == []


def test_quarantine_removes_promoted_object_when_staging_also_exists(tmp_path: Path, monkeypatch) -> None:
    # Both staging and the promoted object survive (crash after promotion but
    # before staging cleanup); quarantine must preserve one copy and remove the
    # promoted object so no OBJECT_ORPHAN remains.
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        _promote_all(
            store,
            _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine"),
        )
        raise RuntimeError("simulated crash after promotion")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    collect(load_config(config_path), clock=fixed_clock)
    assert len(ObjectStore(workdir, create=False).list_files()) == 2
    assert len(staging_journals(workdir)) == 1

    source_file = workdir.parent / "source" / "multi.eml"
    source_file.write_bytes(source_file.read_bytes() + b"\nX-Mutated: yes\n")
    recover_workdir(workdir, apply=True, clock=fixed_clock)

    assert ObjectStore(workdir, create=False).list_files() == []
    verification = verify_workdir(workdir)
    codes = {issue["code"] for issue in verification.issues}
    assert "OBJECT_ORPHAN" not in codes
    assert "UNCOMMITTED_PRESERVED" in codes
    entries = uncommitted_entries(workdir)
    assert len(entries) == 1
    assert len(list(entries[0].joinpath("objects").iterdir())) == 2


def test_cleanup_deletes_promoted_objects_after_reference_check(tmp_path: Path, monkeypatch) -> None:
    config_path, workdir, _, _ = _multi_attachment_source(tmp_path)
    from mailatt.config import load_config

    import mailatt.runner as runner_module

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        _promote_all(
            store,
            _journal_item(workdir_arg, store, ledger, journal.commit_key, "cleanup"),
        )
        raise RuntimeError("simulated crash after promotion")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    collect(load_config(config_path), clock=fixed_clock)
    (workdir.parent / "source" / "multi.eml").unlink()

    applied = recover_workdir(workdir, strategy="cleanup", apply=True, clock=fixed_clock)
    assert applied.items[0].action == ACTION_CLEAN
    assert ObjectStore(workdir, create=False).list_files() == []
    assert applied.execution_errors == []
    verification = verify_workdir(workdir)
    codes = {issue["code"] for issue in verification.issues}
    assert "OBJECT_ORPHAN" not in codes
    assert "UNCOMMITTED_CLEANED" in codes


def test_blocked_journal_never_deletes_object_referenced_elsewhere(tmp_path: Path, monkeypatch) -> None:
    payload = b"shared bytes protected by another committed message"
    committed_mail = build_email(
        subject="Committed", message_id="safe@demo.invalid",
        attachments=(("shared.txt", "text/plain", payload),),
    )
    pending_mail = build_email(
        subject="Pending", message_id="pending@demo.invalid",
        attachments=(("shared.txt", "text/plain", payload),),
    )
    config_path, workdir = write_source(
        tmp_path, files={"committed.eml": committed_mail, "pending.eml": pending_mail}
    )
    from mailatt.config import load_config

    config = load_config(config_path)
    # Commit both normally first so the object has two ledger references.
    collect(config, clock=fixed_clock)
    digest = sha256_bytes(payload)
    final_path = f"objects/{digest[:2]}/{digest}"

    # Fabricate a blocked journal that still claims the shared object.
    import mailatt.runner as runner_module
    from mailatt.recovery import (
        CommitJournal,
        stage_message_commit,
        write_journal,
    )
    from mailatt.models import MessageRecord, MessageStatus
    from mailatt.storage import ObjectStore

    store = ObjectStore(workdir)
    pending_file = config.sources[0].path / "pending.eml"
    fake_message = MessageRecord(
        source_name=config.sources[0].name,
        relative_path="pending.eml",
        digest="0" * 64,  # deliberately wrong -> source mismatch -> blocked
        size=pending_file.stat().st_size,
        message_id="", subject="", sender="", sent_at="",
        status=MessageStatus.OK,
    )
    from mailatt.models import AttachmentRecord, Decision

    record = AttachmentRecord(
        part_id="p001", sha256=digest, size=len(payload),
        filename="shared.txt", safe_filename="shared.txt",
        media_type="text/plain", disposition="attachment", nested_depth=0,
        status=Decision.ACCEPTED, reason_code="accepted", reason="",
        object_path=final_path, quarantine_path="",
    )
    journal = CommitJournal.create(
        source_name=config.sources[0].name,
        relative_path="pending.eml",
        source_absolute=pending_file,
        message=fake_message,
        records=[record],
        policy_hash=config.policy_fingerprint,
        run_id="run-000001",
        mime_options=__import__("mailatt.mime", fromlist=["MimeOptions"]).MimeOptions(),
    )
    # Stage the payload so the journal directory exists, then write the journal.
    store.put_staged(journal.commit_key, payload, expected_sha256=digest)
    write_journal(workdir, journal)

    plan = build_recovery_plan(workdir)
    blocked = next(item for item in plan.items if item.commit_key == journal.commit_key)
    assert blocked.blocked is True

    # Cleanup strategy must refuse to delete the still-referenced shared object.
    applied = recover_workdir(workdir, strategy="cleanup", apply=True, clock=fixed_clock)
    assert applied.execution_errors, "expected a refusal, not a silent delete"
    assert (workdir / final_path).is_file()
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.object_reference_count(final_path) == 2

    # Quarantine strategy likewise keeps the referenced object in place.
    applied_q = recover_workdir(workdir, apply=True, clock=fixed_clock)
    assert (workdir / final_path).is_file()
