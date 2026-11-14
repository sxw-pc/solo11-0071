from __future__ import annotations

import json
from pathlib import Path

import pytest

from mailatt.errors import MailattError
from mailatt.ledger import Ledger
from mailatt.storage import ObjectStore
from mailatt.web import create_app, run_server


def test_report_files_exist(demo_run) -> None:
    paths = demo_run.result.report_paths
    assert set(paths) == {"json", "markdown", "html"}
    assert all(path.is_file() and path.stat().st_size > 0 for path in paths.values())
    assert paths["json"].parent.name == "reports"


def test_json_report_is_stable_and_complete(demo_run, expected_demo) -> None:
    payload = json.loads(demo_run.result.report_paths["json"].read_text(encoding="utf-8"))
    assert list(payload) == sorted(payload)
    assert payload["schema_version"] == "1.0"
    assert payload["summary"]["messages"]["total"] == expected_demo["messages_total"]
    assert payload["summary"]["attachments"]["by_status"]["accepted"] == 6
    assert payload["summary"]["objects"]["total"] == 7
    assert payload["run"]["summary"]["messages_error"] == 2
    keys = [(item["source_name"], item["relative_path"]) for item in payload["messages"]]
    assert keys == sorted(keys)
    attachments = [(item["message_source"], item["message_path"], item["part_id"]) for item in payload["attachments"]]
    assert attachments == sorted(attachments)


def test_markdown_report_contains_audit_sections(demo_run) -> None:
    text = demo_run.result.report_paths["markdown"].read_text(encoding="utf-8")
    assert "# 邮件附采台审计报告" in text
    assert "## 附件判定" in text
    assert "## 失败隔离" in text
    assert "bad/broken-multipart.eml" in text
    assert "python -m mailatt verify" in text
    assert "合同" not in text


def test_html_report_is_self_contained(demo_run) -> None:
    text = demo_run.result.report_paths["html"].read_text(encoding="utf-8")
    lowered = text.lower()
    assert "<!doctype html>" in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "<script" not in lowered
    assert "<link" not in lowered
    assert "月度报表.txt" in text
    assert "invoice.exe" in text
    assert "SHA-256" in text


def test_html_report_escapes_untrusted_names() -> None:
    from mailatt.report import _environment
    from mailatt.config import PolicyConfig
    from mailatt.config import Config, SourceConfig

    config = Config(
        sources=(SourceConfig("demo", Path("."), "eml"),),
        policy=PolicyConfig(),
        workdir=Path("."),
    )
    template = _environment(config).get_template("report.html")
    payload = {
        "generated_at": "2024-01-01T00:00:00+00:00",
        "run": {"run_id": "run-000001", "status": "completed"},
        "summary": {
            "messages": {"total": 1, "error": 0},
            "attachments": {"by_status": {"accepted": 1, "quarantined": 0, "rejected": 0, "duplicate": 0}},
        },
        "objects": [{
            "status": "accepted", "sha256": "a" * 64, "size": 1, "media_type": "text/plain",
            "safe_filename": "<script>alert(1)</script>", "source_ref": "demo/x", "part_id": "p001",
            "path": "objects/aa/" + "a" * 64,
        }],
        "attachments": [],
        "messages": [],
        "errors": [],
    }
    rendered = template.render(report=payload)
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered


def test_web_index_and_api(demo_run) -> None:
    app = create_app(demo_run.workdir)
    client = app.test_client()
    index = client.get("/")
    assert index.status_code == 200
    assert "复核台" in index.get_data(as_text=True)
    assert index.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in index.headers["Content-Security-Policy"]
    api = client.get("/api/summary")
    assert api.status_code == 200
    assert api.get_json()["messages_total"] == 11
    attachments = client.get("/api/attachments").get_json()
    assert attachments["count"] == 10
    assert set(attachments["attachments"][0]) == {
        "id", "message_source", "message_path", "part_id", "sha256", "size",
        "safe_filename", "media_type", "status", "reason_code", "object_path",
        "quarantine_path",
    }


def test_web_has_no_write_methods(demo_run) -> None:
    client = create_app(demo_run.workdir).test_client()
    for method in ("post", "put", "patch", "delete"):
        response = getattr(client, method)("/")
        assert response.status_code == 405


def test_web_serves_accepted_object_and_hides_quarantine(demo_run) -> None:
    with Ledger(demo_run.workdir, readonly=True) as ledger:
        rows = ledger.all_attachments()
    accepted = next(row for row in rows if row["status"] == "accepted")
    quarantined = next(row for row in rows if row["status"] == "quarantined")
    client = create_app(demo_run.workdir).test_client()
    response = client.get(f"/download/{accepted['id']}")
    assert response.status_code == 200
    expected = ObjectStore(demo_run.workdir, create=False).read_bytes(accepted["object_path"])
    assert response.data == expected
    assert "attachment" in response.headers["Content-Disposition"]
    hidden = client.get(f"/download/{quarantined['id']}")
    assert hidden.status_code == 404


def test_web_message_detail_and_missing_ids(demo_run) -> None:
    client = create_app(demo_run.workdir).test_client()
    assert client.get("/messages/999999").status_code == 404
    assert client.get("/attachments/999999").status_code == 404
    assert client.get("/download/999999").status_code == 404
    with Ledger(demo_run.workdir, readonly=True) as ledger:
        message = ledger.all_messages()[0]
    assert client.get(f"/messages/{message['id']}").status_code == 200


def test_web_reads_do_not_modify_ledger(demo_run) -> None:
    client = create_app(demo_run.workdir).test_client()
    ledger_path = demo_run.workdir / "ledger.sqlite3"
    before = ledger_path.stat().st_mtime_ns
    for path in ("/", "/api/summary", "/api/attachments"):
        assert client.get(path).status_code == 200
    assert ledger_path.stat().st_mtime_ns == before


def test_web_rejects_non_loopback_binding(demo_run) -> None:
    with pytest.raises(MailattError) as caught:
        run_server(demo_run.workdir, port=8766, host="0.0.0.0")
    assert caught.value.code == "INVALID_ARGUMENT"
    with pytest.raises(MailattError):
        run_server(demo_run.workdir, port=0)


def test_web_requires_ledger(tmp_path: Path) -> None:
    with pytest.raises(MailattError) as caught:
        create_app(tmp_path / "empty")
    assert caught.value.code == "WEB_NOT_READY"
