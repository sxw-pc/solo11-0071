from __future__ import annotations

import json
import shutil
from pathlib import Path

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
