"""Manifest derivation shared by the collector and recovery commands."""

from __future__ import annotations

from pathlib import Path

from .errors import StorageError
from .ledger import Ledger
from .models import ObjectManifestEntry
from .storage import ObjectStore
from .util import atomic_write_json

MANIFEST_SCHEMA = "1.0"


def manifest_entries(ledger: Ledger, store: ObjectStore) -> list[ObjectManifestEntry]:
    existing = {item.relative_path for item in store.list_files()}
    by_path: dict[str, ObjectManifestEntry] = {}
    for row in ledger.referenced_objects():
        status = row["status"]
        path = row["quarantine_path"] if status == "quarantined" else row["object_path"]
        if not path or path not in existing or path in by_path:
            continue
        manifest_status = "quarantined" if status == "quarantined" else "accepted"
        by_path[path] = ObjectManifestEntry(
            sha256=row["sha256"],
            size=row["size"],
            status=manifest_status,
            path=path,
            media_type=row["media_type"],
            filename=row["filename"],
            safe_filename=row["safe_filename"],
            source_ref=f"{row['message_source']}/{row['message_path']}",
            part_id=row["part_id"],
        )
    return sorted(by_path.values(), key=lambda item: (item.status, item.path))


def write_manifest(
    workdir: Path, ledger: Ledger, store: ObjectStore, run_id: str
) -> Path:
    entries = manifest_entries(ledger, store)
    payload = {
        "schema_version": MANIFEST_SCHEMA,
        "run_id": run_id,
        "object_count": len(entries),
        "objects": [entry.as_dict() for entry in entries],
    }
    path = workdir / "manifest.json"
    try:
        atomic_write_json(path, payload)
    except OSError as exc:
        raise StorageError(f"cannot write manifest: {exc}") from exc
    return path
