"""Loopback-only, read-only inspection service."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template, send_file

from .errors import MailattError
from .ledger import Ledger
from .storage import ObjectStore

LOOPBACK_HOST = "127.0.0.1"
SAMPLE_LIMIT = 300
TRUSTED_ATTACHMENT_STATUSES = ("accepted", "duplicate")


def _summary(ledger: Ledger) -> dict[str, Any]:
    messages = ledger.all_messages()
    attachments = ledger.all_attachments()
    statuses = {key: 0 for key in ("accepted", "quarantined", "rejected", "duplicate")}
    for item in attachments:
        statuses[item["status"]] = statuses.get(item["status"], 0) + 1
    verdicts = {
        key: 0
        for key in (
            "trusted",
            "integrity_valid_but_untrusted",
            "valid",
            "invalid",
            "unverifiable",
            "not_signed",
        )
    }
    for item in messages:
        verdict = item.get("signature_verdict") or item.get("signature_integrity") or "not_signed"
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
    attachment_signatures = {
        key: 0 for key in ("none", "untrusted_signer", "unverifiable", "signature_invalid")
    }
    for item in attachments:
        key = item.get("signature_status") or "none"
        attachment_signatures[key] = attachment_signatures.get(key, 0) + 1
    last_run = ledger.last_run() or {}
    return {
        "messages_total": len(messages),
        "messages_error": sum(item["status"] == "error" for item in messages),
        "attachments_total": len(attachments),
        "by_status": statuses,
        "signature_verdicts": verdicts,
        "attachment_signatures": attachment_signatures,
        "last_run_id": last_run.get("run_id", ""),
        "last_run_status": last_run.get("status", ""),
        "last_run_finished_at": last_run.get("finished_at", ""),
    }


def _signer(message: dict[str, Any]) -> dict[str, Any]:
    try:
        signer = json.loads(str(message.get("signature_signer_json") or "{}"))
    except json.JSONDecodeError:
        return {}
    return signer if isinstance(signer, dict) else {}


def _attach_signature(message: dict[str, Any]) -> None:
    message["signer"] = _signer(message)
    message["signature_verdict"] = (
        message.get("signature_verdict") or message.get("signature_integrity") or "not_signed"
    )


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
                _attach_signature(row)
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
            _attach_signature(message)
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
            message = ledger.get_message(attachment["message_id"])
            # Show the message-level verdict next to the attachment so an
            # accepted status is never read as "sender authenticated".
            attachment["message_signature_integrity"] = (
                message.get("signature_integrity") if message else "not_signed"
            )
            attachment["message_signature_trust"] = (
                message.get("signature_trust") if message else "not_applicable"
            )
            attachment["message_signature_verdict"] = (
                message.get("signature_verdict") if message else "not_signed"
            )
            summary = _summary(ledger)
        return render_template(
            "inspect.html", view="attachment", summary=summary, messages=[], attachments=[],
            message=None, attachment=attachment, message_attachments=[],
        )

    @app.get("/download/<int:attachment_id>")
    def download(attachment_id: int) -> Any:
        with open_ledger() as ledger:
            attachment = ledger.get_attachment(attachment_id)
            message = (
                ledger.get_message(attachment["message_id"]) if attachment is not None else None
            )
            if attachment is not None:
                attachment["message_signature_integrity"] = (
                    message.get("signature_integrity") if message else "not_signed"
                )
                attachment["message_signature_verdict"] = (
                    message.get("signature_verdict") if message else "not_signed"
                )
        if attachment is None or attachment["status"] not in TRUSTED_ATTACHMENT_STATUSES:
            abort(404)
        # A download must never disguise an invalid signature as a trusted file.
        # Invalid-signature attachments stay undownloadable; untrusted-but-valid
        # files are served with an explicit warning header.
        if attachment.get("message_signature_integrity") == "invalid":
            abort(404)
        relative = attachment["object_path"]
        if not relative:
            abort(404)
        store = ObjectStore(workdir, create=False)
        try:
            target = store.resolve_file(relative)
        except MailattError:
            abort(404)
        response = send_file(
            target,
            mimetype=attachment["media_type"] or "application/octet-stream",
            as_attachment=True,
            download_name=attachment["safe_filename"] or "attachment.bin",
            max_age=0,
        )
        response.headers["X-Mailatt-Signature-Integrity"] = str(
            attachment.get("message_signature_integrity") or "not_signed"
        )
        response.headers["X-Mailatt-Signature-Verdict"] = str(
            attachment.get("message_signature_verdict") or "not_signed"
        )
        return response

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
            "quarantine_path", "signature_status", "signature_reason_code",
        )
        return jsonify({"count": len(rows), "attachments": [
            {key: row.get(key, "") for key in fields} for row in rows
        ]})

    @app.get("/api/messages/<int:message_id>/signature")
    def api_message_signature(message_id: int) -> Any:
        with open_ledger() as ledger:
            message = ledger.get_message(message_id)
        if message is None:
            abort(404)
        _attach_signature(message)
        signer = message["signer"]
        return jsonify(
            {
                "message_id": message["id"],
                "source": f"{message['source_name']}/{message['relative_path']}",
                "source_digest": message["digest"],
                "integrity": message.get("signature_integrity"),
                "trust": message.get("signature_trust"),
                "verdict": message["signature_verdict"],
                "reason_code": message.get("signature_reason_code"),
                "reason": message.get("signature_reason"),
                "signed_content_sha256": message.get("signature_signed_digest"),
                "signature_blob_sha256": message.get("signature_blob_sha256"),
                "anchor_fingerprint": message.get("signature_anchor_fingerprint"),
                "evidence_hash": message.get("evidence_hash"),
                "signer": signer,
                "trusted_identity": message["signature_verdict"] == "trusted",
            }
        )

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
