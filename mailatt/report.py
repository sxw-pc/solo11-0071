"""Deterministic JSON, Markdown and self-contained HTML audit reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import Config
from .ledger import Ledger
from .util import atomic_write_json, atomic_write_text, iso_utc, read_json, utc_now

REPORT_SCHEMA = "1.0"

SIGNATURE_FIELDS = (
    "signature_integrity",
    "signature_trust",
    "signature_verdict",
    "signature_reason_code",
    "signature_reason",
    "signature_signed_digest",
    "signature_blob_sha256",
    "signature_anchor_fingerprint",
    "evidence_hash",
)


def _signature_view(message: dict[str, Any]) -> dict[str, Any]:
    """Decode signer metadata and drop anything that could imply false trust."""
    signer: dict[str, Any] = {}
    try:
        parsed = json.loads(str(message.get("signature_signer_json", "{}") or "{}"))
        if isinstance(parsed, dict):
            signer = parsed
    except json.JSONDecodeError:
        signer = {}
    integrity = str(message.get("signature_integrity") or "not_signed")
    trust = str(message.get("signature_trust") or "not_applicable")
    verdict = str(message.get("signature_verdict") or integrity)
    return {
        "integrity": integrity,
        "trust": trust,
        "verdict": verdict,
        "reason_code": str(message.get("signature_reason_code") or ""),
        "reason": str(message.get("signature_reason") or ""),
        "signed_content_sha256": str(message.get("signature_signed_digest") or ""),
        "signature_sha256": str(message.get("signature_blob_sha256") or ""),
        "anchor_fingerprint": str(message.get("signature_anchor_fingerprint") or ""),
        "evidence_hash": str(message.get("evidence_hash") or ""),
        "signer": {
            "subject": str(signer.get("subject") or ""),
            "issuer": str(signer.get("issuer") or ""),
            "serial": str(signer.get("serial") or ""),
            "fingerprint_sha256": str(signer.get("fingerprint_sha256") or ""),
            "not_before": str(signer.get("not_before") or ""),
            "not_after": str(signer.get("not_after") or ""),
            "self_issued": bool(signer.get("self_issued", False)),
        }
        if signer
        else None,
    }


def _safe_manifest(config: Config) -> dict[str, Any]:
    path = config.workdir / "manifest.json"
    if not path.is_file():
        return {"objects": [], "object_count": 0, "run_id": ""}
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError, UnicodeError):
        return {"objects": [], "object_count": 0, "run_id": ""}
    return payload if isinstance(payload, dict) else {"objects": [], "object_count": 0, "run_id": ""}


def _parse_warnings(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def build_payload(config: Config, ledger: Ledger, generated_at: str) -> dict[str, Any]:
    messages = ledger.all_messages()
    attachments = ledger.all_attachments()
    errors = ledger.errors()
    last_run = ledger.last_run() or {}
    manifest = _safe_manifest(config)

    for message in messages:
        message["warnings"] = _parse_warnings(str(message.get("warnings_json", "[]")))
        message["signature"] = _signature_view(message)
        message["attachment_count"] = sum(
            1 for item in attachments if item["message_id"] == message["id"]
        )
        message["sender_authentication"] = (
            "message-level only; sender header is not authenticated by this tool"
        )
    message_counts = {
        "total": len(messages),
        "ok": sum(item["status"] == "ok" for item in messages),
        "error": sum(item["status"] == "error" for item in messages),
    }
    signature_counts = {
        verdict: sum(
            item["signature"]["verdict"] == verdict for item in messages
        )
        for verdict in (
            "not_signed",
            "trusted",
            "integrity_valid_but_untrusted",
            "integrity_valid_trust_undetermined",
            "invalid",
            "unverifiable",
        )
    }
    # Roll-up: every message whose signature mathematically checks out,
    # regardless of whether the signer is locally trusted.
    signature_counts["integrity_valid"] = sum(
        item["signature"]["integrity"] == "valid" for item in messages
    )
    signature_counts["trusted"] = sum(
        item["signature"]["verdict"] == "trusted" for item in messages
    )
    attachment_signature_counts = {
        status: sum(item.get("signature_status") == status for item in attachments)
        for status in ("none", "untrusted_signer", "unverifiable", "signature_invalid")
    }
    by_status = {key: 0 for key in ("accepted", "quarantined", "rejected", "duplicate")}
    for item in attachments:
        by_status[item["status"]] = by_status.get(item["status"], 0) + 1
    objects = manifest.get("objects", [])
    if not isinstance(objects, list):
        objects = []
    object_counts = {
        "total": len(objects),
        "accepted": sum(item.get("status") == "accepted" for item in objects),
        "quarantined": sum(item.get("status") == "quarantined" for item in objects),
    }
    trust = config.trust.as_dict()
    return {
        "schema_version": REPORT_SCHEMA,
        "generated_at": generated_at,
        "run": {
            "run_id": last_run.get("run_id", ""),
            "status": last_run.get("status", ""),
            "started_at": last_run.get("started_at", ""),
            "finished_at": last_run.get("finished_at", ""),
            "policy_hash": last_run.get("policy_hash", ""),
            "summary": last_run.get("summary", {}),
        },
        "sources": [source.name for source in config.sources],
        "signature_policy": {
            "offline_only": True,
            "anchors": trust.get("anchors", []),
            "anchor_count": len(trust.get("anchors", [])),
            "network_access": "none",
            "revocation_lookup": "not performed (offline)",
            "identity_claim": (
                "integrity proves only that the signature covers the bytes; "
                "trusted requires a certificate chaining to a local anchor"
            ),
        },
        "summary": {
            "messages": message_counts,
            "signatures": signature_counts,
            "attachment_signatures": attachment_signature_counts,
            "attachments": {"total": len(attachments), "by_status": by_status},
            "objects": object_counts,
            "runs": ledger.count_rows("runs"),
        },
        "policy": config.policy.as_dict(),
        "messages": messages,
        "attachments": attachments,
        "objects": objects,
        "errors": errors,
    }


def _md(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")[:180]


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    run = payload["run"]
    lines = [
        "# 邮件附采台审计报告",
        "",
        f"- 生成时间：{payload['generated_at']}",
        f"- 运行编号：{run['run_id'] or 'n/a'}",
        f"- 运行状态：{run['status'] or 'n/a'}",
        f"- 邮件来源：{', '.join(payload['sources']) or 'n/a'}",
        "",
        "## 汇总",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
        f"| 邮件总数 | {summary['messages']['total']} |",
        f"| 邮件正常 | {summary['messages']['ok']} |",
        f"| 邮件错误 | {summary['messages']['error']} |",
        f"| 附件判定 | {summary['attachments']['total']} |",
    ]
    for key in ("accepted", "quarantined", "rejected", "duplicate"):
        lines.append(f"| 附件 {key} | {summary['attachments']['by_status'].get(key, 0)} |")
    signatures = summary.get("signatures", {})
    lines.extend(
        [
            f"| 归档对象 | {summary['objects']['accepted']} |",
            f"| 隔离对象 | {summary['objects']['quarantined']} |",
            f"| 历史运行数 | {summary['runs']} |",
            "",
            "## 来源认证证据",
            "",
            (
                "签名完整性只表示签名字节覆盖了当前 MIME 内容；"
                "只有签发证书链到本机显式配置的信任锚时才显示 trusted。"
                "自签名或未知锚证书即使签名数学正确，也只记为 "
                "`integrity_valid_but_untrusted`。本工具不联网取证书、CRL 或 OCSP。"
            ),
            "",
            "| 结论 | 邮件数 |",
            "| --- | ---: |",
            f"| trusted | {signatures.get('trusted', 0)} |",
            f"| integrity_valid_but_untrusted | {signatures.get('integrity_valid_but_untrusted', 0)} |",
            f"| integrity_valid_trust_undetermined | {signatures.get('integrity_valid_trust_undetermined', 0)} |",
            f"| 数学有效的签名合计 | {signatures.get('integrity_valid', 0)} |",
            f"| invalid | {signatures.get('invalid', 0)} |",
            f"| unverifiable | {signatures.get('unverifiable', 0)} |",
            f"| not_signed | {signatures.get('not_signed', 0)} |",
            "",
            "| 信任锚名称 | SHA-256 指纹 | 来源 |",
            "| --- | --- | --- |",
        ]
    )
    anchors = payload.get("signature_policy", {}).get("anchors", [])
    if anchors:
        for anchor in anchors:
            lines.append(
                f"| {_md(anchor.get('name', ''))} | {_md(anchor.get('fingerprint_sha256', '') or '-')} | "
                f"{_md(anchor.get('path', '') or '-')} |"
            )
    else:
        lines.append("| （未配置信任锚，所有有效签名均为未被本地信任） | - | - |")
    lines.extend(
        [
            "",
            "## 签名邮件台账",
            "",
            "| 来源 | 完整性 | 信任 | 签发者证书指纹 | 签发者 | 结论 | 原因 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in payload["messages"]:
        signature = item.get("signature", {})
        signer = signature.get("signer") or {}
        source = f"{item['source_name']}/{item['relative_path']}"
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                _md(source),
                _md(signature.get("integrity", "not_signed")),
                _md(signature.get("trust", "not_applicable")),
                _md(signer.get("fingerprint_sha256", "-")),
                _md(signer.get("subject", "-")),
                _md(signature.get("verdict", "not_signed")),
                _md(signature.get("reason_code", "")),
            )
        )
    lines.extend(
        [
            "",
            "## 附件判定",
            "",
            "| 来源 | 文件名 | MIME | 字节 | 判定 | 来源认证 | 原因 | 对象路径 |",
            "| --- | --- | --- | ---: | --- | --- | --- | --- |",
        ]
    )
    for item in payload["attachments"]:
        path = item["quarantine_path"] or item["object_path"] or "-"
        source = f"{item['message_source']}/{item['message_path']}"
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                _md(source), _md(item["safe_filename"]), _md(item["media_type"]),
                item["size"], _md(item["status"]),
                _md(item.get("signature_status") or "none"),
                _md(item["reason_code"]), _md(path),
            )
        )
    lines.extend(["", "## 邮件台账", "", "| 来源 | 主题 | 发件人 | 状态 | 签名结论 | 排除数 |", "| --- | --- | --- | --- | --- | ---: |"])
    for item in payload["messages"]:
        source = f"{item['source_name']}/{item['relative_path']}"
        verdict = item.get("signature", {}).get("verdict", "not_signed")
        lines.append(
            f"| {_md(source)} | {_md(item['subject'])} | {_md(item['sender'])} | "
            f"{_md(item['status'])} | {_md(verdict)} | {item['attachment_count']} |"
        )
    lines.extend(["", "## 失败隔离", ""])
    if payload["errors"]:
        lines.append("| 来源 | 错误码 | 详情 |")
        lines.append("| --- | --- | --- |")
        for item in payload["errors"]:
            source = f"{item['source_name']}/{item['relative_path']}"
            lines.append(f"| {_md(source)} | {_md(item['error_code'])} | {_md(item['error_detail'])} |")
    else:
        lines.append("本批次没有邮件级错误。")
    lines.extend(
        [
            "",
            "## 策略摘要",
            "",
            "```json",
            json.dumps(payload["policy"], ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## 复核",
            "",
            "```text",
            "python -m mailatt verify --workdir <workdir>",
            "python -m mailatt serve --workdir <workdir>",
            "```",
            "",
            "本报告仅引用本地合成 fixture 与本地归档对象，不包含远程资源引用。",
            "签名验证完全离线执行；报告不含私钥、证书文件内容或联网取得的信息。",
            "",
        ]
    )
    return "\n".join(lines)


def _environment(config: Config) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_reports(
    config: Config,
    ledger: Ledger,
    clock: Callable[[], datetime] = utc_now,
) -> dict[str, Path]:
    generated_at = iso_utc(clock())
    payload = build_payload(config, ledger, generated_at)
    reports = config.workdir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": reports / "report.json",
        "markdown": reports / "report.md",
        "html": reports / "report.html",
    }
    atomic_write_json(paths["json"], payload)
    atomic_write_text(paths["markdown"], render_markdown(payload))
    template = _environment(config).get_template("report.html")
    rendered = template.render(report=payload)
    atomic_write_text(paths["html"], rendered)
    return paths
