from __future__ import annotations

import json
from pathlib import Path

from mailatt.cli import main

from conftest import FIXTURES


def test_demo_command_runs_and_verifies(tmp_path: Path, capsys) -> None:
    workdir = tmp_path / "demo"
    code = main(["demo", "--workdir", str(workdir)])
    output = capsys.readouterr().out
    assert code == 0
    assert "运行 run-000001" in output
    assert "邮件：发现 11" in output
    assert "校验通过" in output
    assert (workdir / "manifest.json").is_file()
    assert (workdir / "reports" / "report.html").is_file()
    assert (workdir / "ledger.sqlite3").is_file()


def test_demo_is_idempotent_without_force(tmp_path: Path, capsys) -> None:
    workdir = tmp_path / "demo"
    assert main(["demo", "--workdir", str(workdir)]) == 0
    capsys.readouterr()
    assert main(["demo", "--workdir", str(workdir)]) == 0
    output = capsys.readouterr().out
    assert "运行 run-000002" in output
    assert "跳过 9" in output
    assert "校验通过" in output


def test_run_command_with_yaml(tmp_path: Path, capsys) -> None:
    config = FIXTURES / "policy" / "demo.yaml"
    workdir = tmp_path / "run"
    code = main(["run", "--config", str(config), "--workdir", str(workdir)])
    output = capsys.readouterr().out
    assert code == 0
    assert "运行 run-000001" in output
    assert "附件：10" in output
    assert (workdir / "reports" / "report.json").is_file()


def test_verify_json_command(tmp_path: Path, capsys) -> None:
    workdir = tmp_path / "demo"
    assert main(["demo", "--workdir", str(workdir)]) == 0
    capsys.readouterr()
    assert main(["verify", "--workdir", str(workdir), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["checked_objects"] == 7
    assert payload["issue_count"] == 0


def test_verify_command_returns_one_on_issue(demo_run, capsys) -> None:
    workdir = demo_run.workdir
    manifest = workdir / "manifest.json"
    original = manifest.read_bytes()
    manifest.unlink()
    try:
        code = main(["verify", "--workdir", str(workdir)])
        output = capsys.readouterr().err
        assert code == 1
        assert "MANIFEST_MISSING" in output
    finally:
        manifest.write_bytes(original)


def test_invalid_config_returns_one(tmp_path: Path, capsys) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("sources: nope\n", encoding="utf-8")
    code = main(["run", "--config", str(path), "--workdir", str(tmp_path / "work")])
    captured = capsys.readouterr()
    assert code == 1
    assert "CONFIG_INVALID" in captured.err


def test_serve_rejects_public_host(tmp_path: Path, capsys) -> None:
    workdir = tmp_path / "demo"
    assert main(["demo", "--workdir", str(workdir)]) == 0
    capsys.readouterr()
    code = main(["serve", "--workdir", str(workdir), "--host", "0.0.0.0", "--port", "8766"])
    captured = capsys.readouterr()
    assert code == 1
    assert "127.0.0.1" in captured.err


def test_recover_dry_run_then_apply(tmp_path: Path, capsys, monkeypatch) -> None:
    from mailatt.config import load_config

    import mailatt.runner as runner_module
    from recovery_helpers import build_email, write_source

    email = build_email(
        subject="Cli recover",
        message_id="cli-recover@demo.invalid",
        attachments=(("note.txt", "text/plain", b"cli recovery bytes"),),
    )
    config_path, workdir = write_source(tmp_path, files={"note.eml": email})

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        item = _journal_item(workdir_arg, store, ledger, journal.commit_key, "quarantine")
        _promote_all(store, item)
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    from mailatt.runner import collect

    collect(load_config(config_path))

    dry = main(["recover", "--workdir", str(workdir), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert dry == 0
    assert payload["dry_run"] is True
    assert payload["journals"][0]["action"] == "commit"
    # Dry run must not touch the ledger.
    from mailatt.ledger import Ledger

    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("attachments") == 0

    text_run = main(["recover", "--workdir", str(workdir)])
    assert text_run == 0
    assert "dry-run" in capsys.readouterr().out

    applied = main(["recover", "--workdir", str(workdir), "--apply", "--json"])
    applied_payload = json.loads(capsys.readouterr().out)
    assert applied == 0
    assert applied_payload["dry_run"] is False
    with Ledger(workdir, readonly=True) as ledger:
        assert ledger.count_rows("attachments") == 1
    assert main(["verify", "--workdir", str(workdir)]) == 0


def test_recover_cleanup_strategy_flag(tmp_path: Path, capsys, monkeypatch) -> None:
    from mailatt.config import load_config

    import mailatt.runner as runner_module
    from recovery_helpers import build_email, write_source

    email = build_email(
        subject="Cli cleanup",
        message_id="cli-cleanup@demo.invalid",
        attachments=(("note.txt", "text/plain", b"cli cleanup bytes"),),
    )
    config_path, workdir = write_source(tmp_path, files={"note.eml": email})

    def crash(workdir_arg, store, ledger, journal):
        from mailatt.recovery import _journal_item, _promote_all

        item = _journal_item(workdir_arg, store, ledger, journal.commit_key, "cleanup")
        _promote_all(store, item)
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(runner_module, "complete_message_commit", crash)
    from mailatt.runner import collect

    collect(load_config(config_path))
    (workdir.parent / "source" / "note.eml").unlink()

    code = main([
        "recover", "--workdir", str(workdir),
        "--uncommitted-policy", "cleanup", "--apply", "--json",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["strategy"] == "cleanup"
    assert payload["journals"][0]["action"] == "clean_uncommitted"
