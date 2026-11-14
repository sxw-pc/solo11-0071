"""Command-line entry points for demo, collection, verification and serving."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import default_config_for_fixtures, load_config
from .errors import MailattError
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
