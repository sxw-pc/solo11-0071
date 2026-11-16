"""YAML configuration loading, defaults and path-safety validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .errors import ConfigurationError
from .util import is_within, sha256_bytes

SOURCE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ANCHOR_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TOP_LEVEL_KEYS = {"version", "sources", "policy", "workdir", "trust"}
TRUST_KEYS = {"anchors"}
ANCHOR_KEYS = {"name", "certificate"}
MAX_ANCHOR_BYTES = 1024 * 1024
PRIVATE_KEY_MARKERS = (b"PRIVATE KEY", b"OPENSSH PRIVATE KEY", b"RSA PRIVATE KEY")


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


@dataclass(frozen=True)
class TrustAnchor:
    """One certificate explicitly pinned as a local trust anchor.

    The certificate itself is kept out of reports; only its SHA-256 fingerprint
    and a caller-supplied label are disclosed.
    """

    name: str
    fingerprint_sha256: str
    path: str
    certificate: x509.Certificate = field(repr=False, compare=False)

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "fingerprint_sha256": self.fingerprint_sha256,
            "path": self.path,
        }


@dataclass(frozen=True)
class TrustConfig:
    anchors: tuple[TrustAnchor, ...] = ()
    fingerprint: str = ""

    def anchor_fingerprints(self) -> tuple[str, ...]:
        return tuple(anchor.fingerprint_sha256 for anchor in self.anchors)

    def as_dict(self) -> dict[str, Any]:
        return {
            "anchors": [anchor.as_dict() for anchor in self.anchors],
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class Config:
    sources: tuple[SourceConfig, ...]
    policy: PolicyConfig
    workdir: Path
    config_path: Path | None = None
    trust: TrustConfig = field(default_factory=TrustConfig)

    @property
    def policy_fingerprint(self) -> str:
        payload = json.dumps(self.policy.as_dict(), sort_keys=True).encode("utf-8")
        return sha256_bytes(payload)

    @property
    def evidence_fingerprint(self) -> str:
        """Policy plus trust anchors: a change in either forces re-verification."""
        payload = json.dumps(
            {
                "policy": self.policy.as_dict(),
                "trust": [anchor.fingerprint_sha256 for anchor in self.trust.anchors],
            },
            sort_keys=True,
        ).encode("utf-8")
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


def _load_anchor(row: Any, index: int, base_dir: Path) -> TrustAnchor:
    if not isinstance(row, dict):
        raise _fail(f"trust.anchors[{index}] must be a mapping")
    unknown = sorted(set(row) - ANCHOR_KEYS)
    if unknown:
        raise _fail(f"trust.anchors[{index}] has unknown keys: {', '.join(unknown)}")
    name = row.get("name")
    certificate = row.get("certificate")
    if not isinstance(name, str) or not ANCHOR_NAME_RE.fullmatch(name):
        raise _fail(f"trust.anchors[{index}].name is invalid")
    if not isinstance(certificate, str) or not certificate.strip():
        raise _fail(f"trust.anchors[{index}].certificate is invalid")
    declared = _declared_path(certificate, base_dir)
    if declared.is_symlink():
        raise ConfigurationError(
            f"trust anchor cannot be a symlink: {certificate}", code="TRUST_ANCHOR_UNSAFE"
        )
    resolved = declared.resolve(strict=False)
    if not resolved.is_file():
        raise ConfigurationError(
            f"trust anchor not found: {certificate}", code="TRUST_ANCHOR_NOT_FOUND"
        )
    try:
        if resolved.stat().st_size > MAX_ANCHOR_BYTES:
            raise _fail(f"trust.anchors[{index}].certificate is too large")
        data = resolved.read_bytes()
    except OSError as exc:
        raise ConfigurationError(
            f"cannot read trust anchor: {certificate}", code="TRUST_ANCHOR_NOT_FOUND"
        ) from exc
    if any(marker in data for marker in PRIVATE_KEY_MARKERS):
        raise ConfigurationError(
            f"trust anchor must not contain a private key: {certificate}",
            code="TRUST_ANCHOR_UNSAFE",
        )
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise _fail(
                f"trust.anchors[{index}].certificate is not a certificate"
            ) from exc
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = constraints.ca
    except x509.ExtensionNotFound:
        is_ca = True
    if not is_ca:
        raise _fail(f"trust.anchors[{index}].certificate is not a CA certificate")
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return TrustAnchor(
        name=name,
        fingerprint_sha256=fingerprint,
        path=certificate,
        certificate=cert,
    )


def _trust_from_mapping(raw: Any, base_dir: Path) -> TrustConfig:
    if raw is None:
        return TrustConfig()
    if not isinstance(raw, dict):
        raise _fail("trust must be a mapping")
    unknown = sorted(set(raw) - TRUST_KEYS)
    if unknown:
        raise _fail(f"unknown trust keys: {', '.join(unknown)}")
    rows = raw.get("anchors", [])
    if not isinstance(rows, list):
        raise _fail("trust.anchors must be a list")
    anchors: list[TrustAnchor] = []
    names: set[str] = set()
    fingerprints: set[str] = set()
    for index, row in enumerate(rows):
        anchor = _load_anchor(row, index, base_dir)
        if anchor.name in names:
            raise _fail(f"duplicate trust anchor name: {anchor.name}")
        if anchor.fingerprint_sha256 in fingerprints:
            raise _fail("duplicate trust anchor certificate")
        names.add(anchor.name)
        fingerprints.add(anchor.fingerprint_sha256)
        anchors.append(anchor)
    ordered = tuple(sorted(anchors, key=lambda item: item.name))
    fingerprint = sha256_bytes(
        json.dumps([item.fingerprint_sha256 for item in ordered], sort_keys=True).encode("utf-8")
    )
    return TrustConfig(anchors=ordered, fingerprint=fingerprint)


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
        unknown_source = sorted(set(row) - {"name", "path", "kind"})
        if unknown_source:
            raise _fail(f"sources[{index}] has unknown keys: {', '.join(unknown_source)}")
        name = row.get("name")
        source_path = row.get("path")
        kind = row.get("kind", "auto")
        if not isinstance(name, str) or not SOURCE_NAME_RE.fullmatch(name):
            raise _fail(f"sources[{index}].name is invalid")
        if name in names:
            raise _fail(f"duplicate source name: {name}")
        if not isinstance(source_path, str) or not source_path.strip():
            raise _fail(f"sources[{index}].path is invalid")
        if kind not in {"auto", "eml", "maildir"}:
            raise _fail(f"sources[{index}].kind must be auto, eml or maildir")
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
        sources.append(SourceConfig(name=name, path=resolved, kind=kind))

    policy = _policy_from_mapping(raw.get("policy"))
    trust = _trust_from_mapping(raw.get("trust"), base_dir)
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
        trust=trust,
    )


def default_config_for_fixtures(fixtures_dir: Path, workdir: Path) -> Config:
    """Load the shipped demo policy while keeping fixture paths local."""
    config_path = fixtures_dir / "policy" / "demo.yaml"
    return load_config(config_path, workdir_override=workdir)