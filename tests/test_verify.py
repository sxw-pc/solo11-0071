from __future__ import annotations

import json
import shutil
from pathlib import Path

from mailatt.recovery import recover_workdir
from mailatt.util import sha256_bytes
from mailatt.verify import verify_workdir


def copy_demo(source: Path, target: Path) -> Path:
    shutil.copytree(source, target)
    return target


def accepted_object_path(workdir: Path) -> str:
    manifest = json.loads((workdir / "manifest.json").read_text(encoding="utf-8"))
    return next(item["path"] for item in manifest["objects"] if item["status"] == "accepted")


def test_clean_archive_has_no_issues(demo_run) -> None:
    result = verify_workdir(demo_run.workdir)
    assert result.ok is True
    assert result.as_dict()["issue_count"] == 0
    assert result.checked_objects == 7


def test_missing_workdir_is_reported(tmp_path: Path) -> None:
    result = verify_workdir(tmp_path / "not-there")
    assert result.ok is False
    assert result.issues[0]["code"] == "WORKDIR_MISSING"


def test_corrupted_object_is_detected(demo_run, tmp_path: Path) -> None:
    workdir = copy_demo(demo_run.workdir, tmp_path / "copy")
    relative = accepted_object_path(workdir)
    (workdir / relative).write_bytes(b"tampered content")
    result = verify_workdir(workdir)
    codes = {issue["code"] for issue in result.issues}
    assert result.ok is False
    assert "OBJECT_CORRUPT" in codes
    assert "MANIFEST_HASH_MISMATCH" in codes


def test_missing_object_is_detected(demo_run, tmp_path: Path) -> None:
    workdir = copy_demo(demo_run.workdir, tmp_path / "copy")
    relative = accepted_object_path(workdir)
    (workdir / relative).unlink()
    result = verify_workdir(workdir)
    codes = {issue["code"] for issue in result.issues}
    assert result.ok is False
    assert "OBJECT_MISSING" in codes
    assert "MANIFEST_ORPHAN" in codes


def test_orphan_object_is_detected(demo_run, tmp_path: Path) -> None:
    workdir = copy_demo(demo_run.workdir, tmp_path / "copy")
    data = b"orphan object not referenced by ledger"
    digest = sha256_bytes(data)
    relative = f"objects/{digest[:2]}/{digest}"
    target = workdir / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    result = verify_workdir(workdir)
    codes = {issue["code"] for issue in result.issues}
    assert result.ok is False
    assert "OBJECT_ORPHAN" in codes


def test_missing_manifest_is_detected(demo_run, tmp_path: Path) -> None:
    workdir = copy_demo(demo_run.workdir, tmp_path / "copy")
    (workdir / "manifest.json").unlink()
    result = verify_workdir(workdir)
    assert result.ok is False
    assert result.issues[0]["code"] == "MANIFEST_MISSING"


def test_verification_does_not_modify_ledger(demo_run) -> None:
    ledger_path = demo_run.workdir / "ledger.sqlite3"
    before = ledger_path.stat().st_mtime_ns
    verify_workdir(demo_run.workdir)
    assert ledger_path.stat().st_mtime_ns == before


# ---------------------------------------------------------------------------
# Two-phase commit / uncommitted-object verification
# ---------------------------------------------------------------------------


def _crashed_workdir(tmp_path: Path):
    from mailatt.config import load_config

    import mailatt.runner as runner_module
    from recovery_helpers import build_email, write_source

    first = b"verify pending payload one"
    second = b"verify pending payload two"
    email = build_email(
        subject="Verify pending",
        message_id="verify-pending@demo.invalid",
        attachments=(
            ("one.txt", "text/plain", first),
            ("two.txt", "text/plain", second),
        ),
    )
    config_path, workdir = write_source(tmp_path, files={"pending.eml": email})

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        item = _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine")
        _promote_all(store, item)
        raise RuntimeError("simulated crash")

    original = runner_module.complete_message_commit
    runner_module.complete_message_commit = crash
    try:
        from mailatt.runner import collect

        collect(load_config(config_path))
    finally:
        runner_module.complete_message_commit = original
    return workdir, first, second


def test_pending_commit_is_distinct_from_orphan(tmp_path: Path) -> None:
    workdir, _, _ = _crashed_workdir(tmp_path)
    result = verify_workdir(workdir)
    assert result.ok is False
    assert result.pending_commits == 1
    codes = {issue["code"] for issue in result.issues}
    assert "PENDING_COMMIT" in codes
    assert "PENDING_COMMIT_OBJECT" in codes
    assert "OBJECT_ORPHAN" not in codes


def test_recovered_archive_verifies_clean(tmp_path: Path) -> None:
    workdir, _, _ = _crashed_workdir(tmp_path)
    recover_workdir(workdir, apply=True)
    result = verify_workdir(workdir)
    assert result.ok is True
    assert result.pending_commits == 0
    assert result.issues == []


def test_quarantined_uncommitted_is_reported_distinctly(tmp_path: Path) -> None:
    workdir, first, second = _crashed_workdir(tmp_path)
    source = workdir.parent / "source" / "pending.eml"
    source.write_bytes(source.read_bytes() + b"\nX-Mutated: yes\n")
    recover_workdir(workdir, apply=True)
    result = verify_workdir(workdir)
    codes = {issue["code"] for issue in result.issues}
    assert "UNCOMMITTED_PRESERVED" in codes
    assert "OBJECT_ORPHAN" not in codes
    assert result.uncommitted_entries == 1
    preserved = {
        path.name
        for entry in (workdir / "uncommitted").iterdir()
        for path in entry.joinpath("objects").iterdir()
    }
    assert preserved == {sha256_bytes(first), sha256_bytes(second)}


def test_cleanup_tombstone_is_reported_distinctly(tmp_path: Path) -> None:
    workdir, _, _ = _crashed_workdir(tmp_path)
    (workdir.parent / "source" / "pending.eml").unlink()
    recover_workdir(workdir, strategy="cleanup", apply=True)
    result = verify_workdir(workdir)
    codes = {issue["code"] for issue in result.issues}
    assert "UNCOMMITTED_CLEANED" in codes
    assert "OBJECT_ORPHAN" not in codes
    assert result.uncommitted_entries == 1


def test_verify_counts_pending_in_json_payload(tmp_path: Path) -> None:
    workdir, _, _ = _crashed_workdir(tmp_path)
    payload = verify_workdir(workdir).as_dict()
    assert payload["pending_commits"] == 1
    assert payload["uncommitted_entries"] == 0
    assert payload["ok"] is False
