"""Loopback-only, read-only inspection service."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template, send_file

from .errors import MailattError
from .ledger import Ledger
from .storage import ObjectStore

LOOPBACK_HOST = "127.0.0.1"
SAMPLE_LIMIT = 300


def _summary(ledger: Ledger) -> dict[str, Any]:
    messages = ledger.all_messages()
    attachments = ledger.all_attachments()
    statuses = {key: 0 for key in ("accepted", "quarantined", "rejected", "duplicate")}
    for item in attachments:
        statuses[item["status"]] = statuses.get(item["status"], 0) + 1
    last_run = ledger.last_run() or {}
    return {
        "messages_total": len(messages),
        "messages_error": sum(item["status"] == "error" for item in messages),
        "attachments_total": len(attachments),
        "by_status": statuses,
        "last_run_id": last_run.get("run_id", ""),
        "last_run_status": last_run.get("status", ""),
        "last_run_finished_at": last_run.get("finished_at", ""),
    }


def create_app(workdir: Path | str) -> Flask:
    workdir = Path(workdir).expanduser().resolve(strict=False)
    if not (workdir / "ledger.sqlite3").is_file():
        raise MailattError(f"ledger not found under {workdir}", code="WEB_NOT_READY")
    app = Flask(__name__)
    app.config.update(MAILATT_WORKDIR=str(workdir), JSON_SORT_KEYS=True)

    def open_ledger() -> Ledger:
        return Ledger(workdir, readonly=True)

    @app.after_request
    def security_headers(response: Any) -> Any:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
            "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index() -> str:
        with open_ledger() as ledger:
            summary = _summary(ledger)
            messages = ledger.all_messages()[-SAMPLE_LIMIT:]
            all_attachments = ledger.all_attachments()
            attachments = all_attachments[-SAMPLE_LIMIT:]
            counts: dict[int, int] = {}
            for row in all_attachments:
                counts[row["message_id"]] = counts.get(row["message_id"], 0) + 1
            for row in messages:
                row["attachment_count"] = counts.get(row["id"], 0)
        return render_template(
            "inspect.html", view="index", summary=summary,
            messages=messages, attachments=attachments,
            message=None, attachment=None, message_attachments=[],
        )

    @app.get("/messages/<int:message_id>")
    def message_detail(message_id: int) -> str:
        with open_ledger() as ledger:
            message = ledger.get_message(message_id)
            if message is None:
                abort(404)
            attachments = ledger.attachments_for_message(message_id)
            summary = _summary(ledger)
        return render_template(
            "inspect.html", view="message", summary=summary, messages=[], attachments=[],
            message=message, attachment=None, message_attachments=attachments,
        )

    @app.get("/attachments/<int:attachment_id>")
    def attachment_detail(attachment_id: int) -> str:
        with open_ledger() as ledger:
            attachment = ledger.get_attachment(attachment_id)
            if attachment is None:
                abort(404)
            summary = _summary(ledger)
        return render_template(
            "inspect.html", view="attachment", summary=summary, messages=[], attachments=[],
            message=None, attachment=attachment, message_attachments=[],
        )

    @app.get("/download/<int:attachment_id>")
    def download(attachment_id: int) -> Any:
        with open_ledger() as ledger:
            attachment = ledger.get_attachment(attachment_id)
        if attachment is None or attachment["status"] not in ("accepted", "duplicate"):
            abort(404)
        relative = attachment["object_path"]
        if not relative:
            abort(404)
        store = ObjectStore(workdir, create=False)
        try:
            target = store.resolve_file(relative)
        except MailattError:
            abort(404)
        return send_file(
            target,
            mimetype=attachment["media_type"] or "application/octet-stream",
            as_attachment=True,
            download_name=attachment["safe_filename"] or "attachment.bin",
            max_age=0,
        )

    @app.get("/api/summary")
    def api_summary() -> Any:
        with open_ledger() as ledger:
            summary = _summary(ledger)
        return jsonify(summary)

    @app.get("/api/attachments")
    def api_attachments() -> Any:
        with open_ledger() as ledger:
            rows = ledger.all_attachments()[:SAMPLE_LIMIT]
        fields = (
            "id", "message_source", "message_path", "part_id", "sha256", "size",
            "safe_filename", "media_type", "status", "reason_code", "object_path",
            "quarantine_path",
        )
        return jsonify({"count": len(rows), "attachments": [
            {key: row.get(key, "") for key in fields} for row in rows
        ]})

    return app


def run_server(workdir: Path, port: int = 8766, host: str = LOOPBACK_HOST) -> None:
    """Start the read-only service; any non-loopback host is rejected."""
    if host != LOOPBACK_HOST:
        raise MailattError(
            "the inspection service only binds to 127.0.0.1", code="INVALID_ARGUMENT"
        )
    if not 1 <= port <= 65535:
        raise MailattError("port must be between 1 and 65535", code="INVALID_ARGUMENT")
    app = create_app(workdir)
    app.run(host=LOOPBACK_HOST, port=port, debug=False, use_reloader=False)
