"""Deterministic JSON, Markdown and self-contained HTML audit reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import Config
from .ledger import Ledger
from .related import path_sort_key
from .util import atomic_write_json, atomic_write_text, iso_utc, read_json, utc_now

REPORT_SCHEMA = "1.0"


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


def _parse_related_issues(value: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(value or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    issues = [item for item in parsed if isinstance(item, dict)]
    return sorted(
        issues,
        key=lambda item: (
            path_sort_key(str(item.get("related_path", ""))),
            str(item.get("code", "")),
            path_sort_key(str(item.get("root_path", ""))),
            str(item.get("content_id", "")),
            tuple(path_sort_key(str(path)) for path in item.get("part_paths", []) or []),
        ),
    )


def build_payload(config: Config, ledger: Ledger, generated_at: str) -> dict[str, Any]:
    messages = ledger.all_messages()
    attachments = ledger.all_attachments()
    errors = ledger.errors()
    last_run = ledger.last_run() or {}
    manifest = _safe_manifest(config)

    for message in messages:
        message["warnings"] = _parse_warnings(str(message.get("warnings_json", "[]")))
        message["related_issues"] = _parse_related_issues(
            str(message.get("related_issues_json", "[]"))
        )
        message["attachment_count"] = sum(
            1 for item in attachments if item["message_id"] == message["id"]
        )
    related_issues = [
        {"source_name": message["source_name"], "relative_path": message["relative_path"],
         **issue}
        for message in messages
        for issue in message["related_issues"]
    ]
    related_issues.sort(
        key=lambda item: (
            item["source_name"],
            item["relative_path"],
            path_sort_key(str(item.get("related_path", ""))),
            str(item.get("code", "")),
        )
    )
    message_counts = {
        "total": len(messages),
        "ok": sum(item["status"] == "ok" for item in messages),
        "error": sum(item["status"] == "error" for item in messages),
    }
    by_status = {key: 0 for key in ("accepted", "quarantined", "rejected", "duplicate")}
    for item in attachments:
        by_status[item["status"]] = by_status.get(item["status"], 0) + 1
    # Relation metadata is an audit aid; older ledgers do not carry the columns.
    for item in attachments:
        for key, default in (
            ("related_root_path", ""), ("related_part_path", ""),
            ("related_container_path", ""), ("content_id", ""),
            ("reference_count", 0), ("related_status", ""),
        ):
            item.setdefault(key, default)
        item["reference_count"] = int(item.get("reference_count") or 0)
    objects = manifest.get("objects", [])
    if not isinstance(objects, list):
        objects = []
    object_counts = {
        "total": len(objects),
        "accepted": sum(item.get("status") == "accepted" for item in objects),
        "quarantined": sum(item.get("status") == "quarantined" for item in objects),
    }
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
        "summary": {
            "messages": message_counts,
            "attachments": {"total": len(attachments), "by_status": by_status},
            "objects": object_counts,
            "runs": ledger.count_rows("runs"),
        },
        "policy": config.policy.as_dict(),
        "messages": messages,
        "attachments": attachments,
        "objects": objects,
        "related_issues": related_issues,
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
    lines.extend(
        [
            "| 归档对象 | {0} |".format(summary['objects']['accepted']),
            f"| 隔离对象 | {summary['objects']['quarantined']} |",
            f"| 历史运行数 | {summary['runs']} |",
            "",
            "## 附件判定",
            "",
            "| 来源 | 文件名 | MIME | 字节 | 判定 | 原因 | 对象路径 |",
            "| --- | --- | --- | ---: | --- | --- | --- |",
        ]
    )
    for item in payload["attachments"]:
        path = item["quarantine_path"] or item["object_path"] or "-"
        source = f"{item['message_source']}/{item['message_path']}"
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                _md(source), _md(item["safe_filename"]), _md(item["media_type"]),
                item["size"], _md(item["status"]), _md(item["reason_code"]), _md(path),
            )
        )
    lines.extend(
        [
            "",
            "## inline 资源关系",
            "",
            "| 来源 | related 容器 | 根路径 | 部件路径 | Content-ID | 引用数 | 状态 | 原因 |",
            "| --- | --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    related_rows = [item for item in payload["attachments"] if item.get("related_part_path")]
    if related_rows:
        for item in related_rows:
            source = f"{item['message_source']}/{item['message_path']}"
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    _md(source), _md(item.get("related_container_path", "")),
                    _md(item.get("related_root_path", "")),
                    _md(item.get("related_part_path", "")),
                    _md(item.get("content_id", "")), item.get("reference_count", 0),
                    _md(item.get("related_status", "")), _md(item["reason_code"]),
                )
            )
    else:
        lines.append("| — | — | — | — | — | 0 | — | 本批次没有 inline 关系候选 |")
    lines.extend(["", "## inline 引用问题", ""])
    if payload["related_issues"]:
        lines.append("| 来源 | 代码 | related 路径 | 根路径 | Content-ID | 部件路径 | 说明 |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for item in payload["related_issues"]:
            source = f"{item['source_name']}/{item['relative_path']}"
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} |".format(
                    _md(source), _md(item.get("code", "")),
                    _md(item.get("related_path", "")), _md(item.get("root_path", "")),
                    _md(item.get("content_id", "")),
                    _md(", ".join(item.get("part_paths", []) or [])),
                    _md(item.get("detail", "")),
                )
            )
    else:
        lines.append("本批次没有 inline 引用歧义或缺失。")
    lines.extend(
        ["", "## 邮件台账", "", "| 来源 | 主题 | 发件人 | 状态 | 排除数 |",
         "| --- | --- | --- | --- | ---: |"]
    )
    for item in payload["messages"]:
        source = f"{item['source_name']}/{item['relative_path']}"
        lines.append(
            f"| {_md(source)} | {_md(item['subject'])} | {_md(item['sender'])} | "
            f"{_md(item['status'])} | {item['attachment_count']} |"
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
