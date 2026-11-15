"""Command-line entry points for demo, collection, verification and serving."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import default_config_for_fixtures, load_config
from .errors import MailattError
from .recovery import QUARANTINE_STRATEGY, recover_workdir
from .runner import collect
from .verify import verify_workdir


def _repo_fixtures() -> Path:
    return Path(__file__).resolve().parent.parent / "fixtures"


def _print_collection(result: object) -> None:
    summary = result.summary
    print(f"运行 {summary.run_id}：{summary.status}")
    print(
        "邮件：发现 {seen}，处理 {processed}，跳过 {skipped}，成功 {ok}，失败 {error}".format(
            seen=summary.messages_seen,
            processed=summary.messages_processed,
            skipped=summary.messages_skipped,
            ok=summary.messages_ok,
            error=summary.messages_error,
        )
    )
    print(
        "附件：{seen}；归档 {accepted}，隔离 {quarantined}，拒绝 {rejected}，重复 {duplicates}".format(
            seen=summary.attachments_seen,
            accepted=summary.accepted,
            quarantined=summary.quarantined,
            rejected=summary.rejected,
            duplicates=summary.duplicates,
        )
    )
    print(f"新增对象：{summary.objects_created}")
    if summary.pending_commits or summary.uncommitted_quarantined or summary.uncommitted_cleaned:
        print(
            "提交恢复：待提交 {pending}，隔离未提交 {quarantined}，清理未提交 {cleaned}，失败 {failed}".format(
                pending=summary.pending_commits,
                quarantined=summary.uncommitted_quarantined,
                cleaned=summary.uncommitted_cleaned,
                failed=summary.recovery_failures,
            )
        )
    print(f"清单：{result.manifest_path}")
    for kind in ("json", "markdown", "html"):
        print(f"报告 {kind}: {result.report_paths[kind]}")
    if summary.errors:
        print("失败隔离：")
        for item in summary.errors:
            print(f"  - {item['source_ref']} [{item['code']}] {item['detail']}")


def _verify_and_print(workdir: Path, as_json: bool = False) -> int:
    result = verify_workdir(workdir)
    if as_json:
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    elif result.ok:
        print(
            f"校验通过：{result.checked_objects} 个对象，"
            f"{result.checked_references} 个台账引用。"
        )
    else:
        print(f"校验失败：发现 {len(result.issues)} 个问题。", file=sys.stderr)
        for issue in result.issues:
            print(
                f"  - [{issue['code']}] {issue['path']}: {issue['detail']}",
                file=sys.stderr,
            )
    return 0 if result.ok else 1


def _command_demo(args: argparse.Namespace) -> int:
    fixtures = Path(args.fixtures).expanduser().resolve()
    config_path = fixtures / "policy" / "demo.yaml"
    if not config_path.is_file():
        raise MailattError(f"demo fixture config not found: {config_path}", code="CONFIG_NOT_FOUND")
    workdir = Path(args.workdir).expanduser().resolve()
    config = default_config_for_fixtures(fixtures, workdir)
    result = collect(config, force=args.force)
    _print_collection(result)
    print("\n本地复核：")
    return _verify_and_print(workdir)


def _command_run(args: argparse.Namespace) -> int:
    if not args.config:
        raise MailattError("--config is required", code="INVALID_ARGUMENT")
    config = load_config(args.config, workdir_override=args.workdir)
    result = collect(config, force=args.force)
    _print_collection(result)
    return 0


def _command_verify(args: argparse.Namespace) -> int:
    return _verify_and_print(Path(args.workdir).expanduser().resolve(), as_json=args.json)


def _command_recover(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).expanduser().resolve()
    plan = recover_workdir(
        workdir,
        strategy=args.uncommitted_policy,
        apply=args.apply,
    )
    if args.json:
        print(json.dumps(plan.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        return 1 if plan.execution_errors else 0
    mode = "apply" if args.apply else "dry-run"
    print(f"恢复计划（{mode}，策略 {plan.strategy}）：{workdir}")
    if not plan.items and not plan.orphans:
        print("没有待恢复的提交记录或孤儿对象。")
        return 0
    for item in plan.items:
        source = item.journal.source_ref if item.journal is not None else f"staging/{item.commit_key}"
        print(f"  - 提交 {item.commit_key[:12]}… {source}")
        print(f"      动作：{item.action}；原因：{item.reason}")
    for orphan in plan.orphans:
        print(f"  - 孤儿对象 {orphan.path}")
        print(f"      动作：{orphan.action}；原因：{orphan.reason}")
    counts = plan.counts()
    summary_bits = [f"{key}={value}" for key, value in counts.items()]
    print("动作汇总：" + (", ".join(summary_bits) if summary_bits else "无"))
    if plan.execution_errors:
        print("恢复执行错误：", file=sys.stderr)
        for failure in plan.execution_errors:
            print(
                f"  - [{failure['code']}] {failure['source_ref']}: {failure['detail']}",
                file=sys.stderr,
            )
    if not args.apply:
        print("当前为 dry-run，仅输出恢复计划；追加 --apply 才会执行。")
    return 1 if plan.execution_errors else 0


def _command_serve(args: argparse.Namespace) -> int:
    from .web import LOOPBACK_HOST, run_server

    workdir = Path(args.workdir).expanduser().resolve()
    print(f"只读复核台：http://{LOOPBACK_HOST}:{args.port}")
    print("按 Ctrl+C 停止；服务不会写入台账或对象。")
    run_server(workdir, port=args.port, host=args.host)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailatt",
        description="本地邮件导出附件采集、内容寻址归档与只读复核工具",
    )
    parser.add_argument("--version", action="version", version=f"mailatt {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="用内置合成 fixture 跑完整演示")
    demo.add_argument("--workdir", default=".mailatt-demo", help="工作目录（默认 .mailatt-demo）")
    demo.add_argument("--fixtures", default=str(_repo_fixtures()), help="fixture 根目录")
    demo.add_argument("--force", action="store_true", help="忽略增量跳过并重算")
    demo.set_defaults(handler=_command_demo)

    run = sub.add_parser("run", help="按 YAML 配置采集本地邮件")
    run.add_argument("--config", required=True, help="YAML 配置文件")
    run.add_argument("--workdir", default=None, help="覆盖配置文件中的工作目录")
    run.add_argument("--force", action="store_true", help="忽略增量跳过并重算")
    run.set_defaults(handler=_command_run)

    verify = sub.add_parser("verify", help="重算哈希并核对 manifest / 台账")
    verify.add_argument("--workdir", default=".mailatt-demo")
    verify.add_argument("--json", action="store_true", help="输出 JSON 结果")
    verify.set_defaults(handler=_command_verify)

    recover = sub.add_parser(
        "recover",
        help="恢复中断的两阶段提交；默认 dry-run 只给恢复计划，--apply 才执行",
    )
    recover.add_argument("--workdir", default=".mailatt-demo")
    recover.add_argument(
        "--uncommitted-policy",
        choices=("quarantine", "cleanup"),
        default=QUARANTINE_STRATEGY,
        help="无法完成提交时的显式策略：保留到 uncommitted/ 隔离区（默认）或确认无台账引用后清理",
    )
    recover.add_argument(
        "--apply",
        action="store_true",
        help="执行恢复计划；缺省时仅输出计划，不修改任何文件或台账",
    )
    recover.add_argument("--json", action="store_true", help="输出 JSON 恢复计划")
    recover.set_defaults(handler=_command_recover)

    serve = sub.add_parser("serve", help="启动 127.0.0.1 只读复核台")
    serve.add_argument("--workdir", default=".mailatt-demo")
    serve.add_argument("--port", type=int, default=8766)
    serve.add_argument("--host", default="127.0.0.1", help="只允许 127.0.0.1")
    serve.set_defaults(handler=_command_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except MailattError as exc:
        payload = exc.as_dict()
        print(f"错误 [{payload['code']}]：{payload['detail'] or payload['message']}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"错误 [IO_ERROR]：{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已停止。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
