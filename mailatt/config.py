"""YAML configuration loading, defaults and path-safety validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

import yaml

from .errors import ConfigurationError
from .mbox import MBOX_DIALECTS, MBOX_MODES
from .util import is_within, sha256_bytes

SOURCE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TOP_LEVEL_KEYS = {"version", "sources", "policy", "workdir"}
SOURCE_KINDS = ("auto", "eml", "maildir", *MBOX_DIALECTS)

DEFAULT_QUARANTINE_EXTENSIONS = (
    ".bat", ".cmd", ".com", ".cpl", ".dll", ".docm", ".exe", ".hta",
    ".jar", ".js", ".msi", ".ps1", ".scr", ".vbs", ".xlsm",
)
DEFAULT_BLOCKED_EXTENSIONS = (".iso", ".lnk", ".reg", ".url")
DEFAULT_ALLOWED_EXTENSIONS = (
    ".csv", ".docx", ".eml", ".jpeg", ".jpg", ".json", ".log", ".pdf",
    ".png", ".txt", ".xlsx", ".zip",
)
DEFAULT_ALLOWED_MEDIA_TYPES = (
    "application/json",
    "application/msword",
    "application/octet-stream",
    "application/pdf",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/zip",
    "image/gif",
    "image/jpeg",
    "image/png",
    "text/csv",
    "text/plain",
)


@dataclass(frozen=True)
class PolicyConfig:
    allowed_extensions: tuple[str, ...] = DEFAULT_ALLOWED_EXTENSIONS
    allowed_media_types: tuple[str, ...] = DEFAULT_ALLOWED_MEDIA_TYPES
    quarantine_extensions: tuple[str, ...] = DEFAULT_QUARANTINE_EXTENSIONS
    blocked_extensions: tuple[str, ...] = DEFAULT_BLOCKED_EXTENSIONS
    max_file_bytes: int = 8 * 1024 * 1024
    min_file_bytes: int = 0
    max_attachments_per_message: int = 20
    max_nested_depth: int = 3
    max_message_bytes: int = 32 * 1024 * 1024
    max_filename_length: int = 120
    allow_nested_messages: bool = True
    allow_inline_attachments: bool = True
    reject_path_traversal: bool = True
    skip_duplicate_content: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed_extensions": list(self.allowed_extensions),
            "allowed_media_types": list(self.allowed_media_types),
            "quarantine_extensions": list(self.quarantine_extensions),
            "blocked_extensions": list(self.blocked_extensions),
            "max_file_bytes": self.max_file_bytes,
            "min_file_bytes": self.min_file_bytes,
            "max_attachments_per_message": self.max_attachments_per_message,
            "max_nested_depth": self.max_nested_depth,
            "max_message_bytes": self.max_message_bytes,
            "max_filename_length": self.max_filename_length,
            "allow_nested_messages": self.allow_nested_messages,
            "allow_inline_attachments": self.allow_inline_attachments,
            "reject_path_traversal": self.reject_path_traversal,
            "skip_duplicate_content": self.skip_duplicate_content,
        }


@dataclass(frozen=True)
class SourceConfig:
    name: str
    path: Path
    kind: str
    mbox_mode: str = "strict"


@dataclass(frozen=True)
class Config:
    sources: tuple[SourceConfig, ...]
    policy: PolicyConfig
    workdir: Path
    config_path: Path | None = None

    @property
    def policy_fingerprint(self) -> str:
        payload = json.dumps(self.policy.as_dict(), sort_keys=True).encode("utf-8")
        return sha256_bytes(payload)

    @property
    def source_names(self) -> tuple[str, ...]:
        return tuple(source.name for source in self.sources)


def _fail(message: str) -> ConfigurationError:
    return ConfigurationError(message, code="CONFIG_INVALID")


def _as_bool(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(f"policy.{key} must be a boolean")
    return value


def _as_int(value: Any, key: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"policy.{key} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        limit = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
        raise _fail(f"policy.{key} must be {limit}")
    return value


def _extension_list(value: Any, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _fail(f"policy.{key} must be a list of strings")
    normalized: list[str] = []
    for item in value:
        item = item.strip().lower()
        if not item or "/" in item or "\\" in item:
            raise _fail(f"policy.{key} contains an invalid extension")
        if not item.startswith("."):
            item = f".{item}"
        normalized.append(item)
    return tuple(sorted(set(normalized)))


def _media_type_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _fail("policy.allowed_media_types must be a list of strings")
    normalized: list[str] = []
    for item in value:
        item = item.strip().lower()
        if "/" not in item:
            raise _fail("policy.allowed_media_types contains an invalid media type")
        normalized.append(item)
    return tuple(sorted(set(normalized)))


def _policy_from_mapping(raw: Any) -> PolicyConfig:
    if raw is None:
        return PolicyConfig()
    if not isinstance(raw, dict):
        raise _fail("policy must be a mapping")
    known = set(PolicyConfig.__dataclass_fields__)
    unknown = sorted(set(raw) - known)
    if unknown:
        raise _fail(f"unknown policy keys: {', '.join(unknown)}")
    values: dict[str, Any] = {}
    for key in ("allowed_extensions", "quarantine_extensions", "blocked_extensions"):
        if key in raw:
            values[key] = _extension_list(raw[key], key)
    if "allowed_media_types" in raw:
        values["allowed_media_types"] = _media_type_list(raw["allowed_media_types"])
    bounds = {
        "max_file_bytes": (0, 2**31),
        "min_file_bytes": (0, 2**31),
        "max_attachments_per_message": (0, 10000),
        "max_nested_depth": (0, 20),
        "max_message_bytes": (1, 2**31),
        "max_filename_length": (16, 255),
    }
    for key, (minimum, maximum) in bounds.items():
        if key in raw:
            values[key] = _as_int(raw[key], key, minimum, maximum)
    for key in (
        "allow_nested_messages", "allow_inline_attachments",
        "reject_path_traversal", "skip_duplicate_content",
    ):
        if key in raw:
            values[key] = _as_bool(raw[key], key)
    policy = replace(PolicyConfig(), **values)
    if policy.min_file_bytes > policy.max_file_bytes:
        raise _fail("policy.min_file_bytes cannot exceed max_file_bytes")
    return policy


def _declared_path(value: str | Path, base: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def _resolve_path(value: str | Path, base: Path) -> Path:
    return _declared_path(value, base).resolve(strict=False)


def _validate_workdir(workdir: Path, sources: Iterable[SourceConfig]) -> None:
    workdir = workdir.resolve(strict=False)
    if workdir == Path(workdir.anchor):
        raise _fail("workdir cannot be a filesystem root")
    if workdir.exists():
        if workdir.is_symlink():
            raise _fail("workdir cannot be a symbolic link")
        if not workdir.is_dir():
            raise _fail("workdir exists and is not a directory")
    for source in sources:
        if is_within(workdir, source.path):
            raise ConfigurationError(
                f"workdir {workdir} is inside source {source.name}", code="SOURCE_UNSAFE"
            )
        if is_within(source.path, workdir):
            raise ConfigurationError(
                f"source {source.name} is inside workdir", code="SOURCE_UNSAFE"
            )


def load_config(path: str | Path, *, workdir_override: str | Path | None = None) -> Config:
    config_path = Path(path).expanduser().resolve(strict=False)
    if not config_path.exists():
        raise ConfigurationError(f"configuration not found: {config_path}", code="CONFIG_NOT_FOUND")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise _fail(f"cannot read YAML configuration: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise _fail("configuration root must be a mapping")
    unknown = sorted(set(raw) - TOP_LEVEL_KEYS)
    if unknown:
        raise _fail(f"unknown configuration keys: {', '.join(unknown)}")
    if raw.get("version", 1) != 1:
        raise _fail("only configuration version 1 is supported")

    source_rows = raw.get("sources")
    if not isinstance(source_rows, list) or not source_rows:
        raise _fail("sources must be a non-empty list")
    base_dir = config_path.parent
    sources: list[SourceConfig] = []
    names: set[str] = set()
    for index, row in enumerate(source_rows):
        if not isinstance(row, dict):
            raise _fail(f"sources[{index}] must be a mapping")
        unknown_source = sorted(set(row) - {"name", "path", "kind", "mbox_mode"})
        if unknown_source:
            raise _fail(f"sources[{index}] has unknown keys: {', '.join(unknown_source)}")
        name = row.get("name")
        source_path = row.get("path")
        kind = row.get("kind", "auto")
        mbox_mode = row.get("mbox_mode", "strict")
        if not isinstance(name, str) or not SOURCE_NAME_RE.fullmatch(name):
            raise _fail(f"sources[{index}].name is invalid")
        if name in names:
            raise _fail(f"duplicate source name: {name}")
        if not isinstance(source_path, str) or not source_path.strip():
            raise _fail(f"sources[{index}].path is invalid")
        if kind not in SOURCE_KINDS:
            raise _fail(
                f"sources[{index}].kind must be one of: {', '.join(SOURCE_KINDS)}"
            )
        if not isinstance(mbox_mode, str) or mbox_mode not in MBOX_MODES:
            raise _fail(f"sources[{index}].mbox_mode must be one of: {', '.join(MBOX_MODES)}")
        if "mbox_mode" in row and kind not in MBOX_DIALECTS:
            raise _fail(f"sources[{index}].mbox_mode is only valid for mbox sources")
        declared = _declared_path(source_path, base_dir)
        if declared.is_symlink():
            raise ConfigurationError(f"source cannot be a symlink: {source_path}", code="SOURCE_UNSAFE")
        resolved = declared.resolve(strict=False)
        if not resolved.exists():
            raise ConfigurationError(
                f"source directory not found: {source_path}", code="SOURCE_NOT_FOUND"
            )
        if not resolved.is_dir():
            raise _fail(f"source is not a directory: {source_path}")
        names.add(name)
        sources.append(SourceConfig(name=name, path=resolved, kind=kind, mbox_mode=mbox_mode))

    policy = _policy_from_mapping(raw.get("policy"))
    workdir_value = workdir_override if workdir_override is not None else raw.get("workdir", ".mailatt-work")
    if not isinstance(workdir_value, (str, Path)):
        raise _fail("workdir must be a path string")
    workdir_base = Path.cwd() if workdir_override is not None else base_dir
    declared_workdir = _declared_path(workdir_value, workdir_base)
    if declared_workdir.is_symlink():
        raise _fail("workdir cannot be a symbolic link")
    workdir = declared_workdir.resolve(strict=False)
    _validate_workdir(workdir, sources)
    return Config(
        sources=tuple(sources),
        policy=policy,
        workdir=workdir,
        config_path=config_path,
    )


def default_config_for_fixtures(fixtures_dir: Path, workdir: Path) -> Config:
    """Load the shipped demo policy while keeping fixture paths local."""
    config_path = fixtures_dir / "policy" / "demo.yaml"
    return load_config(config_path, workdir_override=workdir)
