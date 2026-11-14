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
