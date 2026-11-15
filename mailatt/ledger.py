"""SQLite ledger with idempotent message and attachment writes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Sequence

from .errors import LedgerError
from .models import AttachmentRecord, MessageRecord, RunSummary

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    digest TEXT NOT NULL,
    size INTEGER NOT NULL,
    message_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    sent_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    error_detail TEXT NOT NULL DEFAULT '',
    warnings_json TEXT NOT NULL DEFAULT '[]',
    policy_hash TEXT NOT NULL,
    first_seen_run TEXT NOT NULL,
    last_seen_run TEXT NOT NULL,
    UNIQUE(source_name, relative_path)
);
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    filename TEXT NOT NULL DEFAULT '',
    safe_filename TEXT NOT NULL DEFAULT '',
    media_type TEXT NOT NULL DEFAULT '',
    disposition TEXT NOT NULL DEFAULT '',
    nested_depth INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    reason_code TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    object_path TEXT NOT NULL DEFAULT '',
    quarantine_path TEXT NOT NULL DEFAULT '',
    first_seen_run TEXT NOT NULL,
    last_seen_run TEXT NOT NULL,
    UNIQUE(message_id, part_id)
);
CREATE INDEX IF NOT EXISTS idx_messages_source ON messages(source_name, relative_path);
CREATE INDEX IF NOT EXISTS idx_attachments_sha ON attachments(sha256);
CREATE INDEX IF NOT EXISTS idx_attachments_status ON attachments(status);
"""


class Ledger:
    def __init__(self, workdir: Path, *, readonly: bool = False) -> None:
        self.workdir = workdir.resolve(strict=False)
        self.path = self.workdir / "ledger.sqlite3"
        self.readonly = readonly
        if readonly:
            if not self.path.is_file():
                raise LedgerError(f"ledger not found: {self.path}", code="LEDGER_NOT_FOUND")
            uri = f"{self.path.as_uri()}?mode=ro"
            try:
                self.conn = sqlite3.connect(uri, uri=True)
            except sqlite3.Error as exc:
                raise LedgerError(f"cannot open ledger read-only: {exc}") from exc
        else:
            self.workdir.mkdir(parents=True, exist_ok=True)
            try:
                self.conn = sqlite3.connect(self.path)
                self.conn.execute("PRAGMA foreign_keys = ON")
                self.conn.execute("PRAGMA busy_timeout = 5000")
                self.conn.executescript(SCHEMA)
                self.conn.commit()
            except sqlite3.Error as exc:
                raise LedgerError(f"cannot initialise ledger: {exc}") from exc
        self.conn.row_factory = sqlite3.Row

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        try:
            rows = self.conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise LedgerError(f"ledger query failed: {exc}") from exc
        return [dict(row) for row in rows]

    def _one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        rows = self._query(sql, params)
        return rows[0] if rows else None

    def begin_run(self, started_at: str, policy_hash: str) -> str:
        if self.readonly:
            raise LedgerError("ledger is read-only")
        row = self.conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM runs").fetchone()
        seq = int(row["next_seq"])
        run_id = f"run-{seq:06d}"
        try:
            self.conn.execute(
                "INSERT INTO runs(run_id, seq, started_at, status, policy_hash) VALUES (?, ?, ?, 'running', ?)",
                (run_id, seq, started_at, policy_hash),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            raise LedgerError(f"cannot start run: {exc}") from exc
        return run_id

    def finish_run(self, summary: RunSummary) -> None:
        payload = json.dumps(summary.as_dict(), ensure_ascii=False, sort_keys=True)
        try:
            self.conn.execute(
                "UPDATE runs SET finished_at=?, status=?, summary_json=? WHERE run_id=?",
                (summary.finished_at, summary.status, payload, summary.run_id),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            raise LedgerError(f"cannot finish run: {exc}") from exc

    def message_state(self, source_name: str, relative_path: str) -> dict[str, Any] | None:
        return self._one(
            "SELECT digest, policy_hash, status FROM messages WHERE source_name=? AND relative_path=?",
            (source_name, relative_path),
        )

    def upsert_message(self, record: MessageRecord, run_id: str, policy_hash: str) -> int:
        warnings = json.dumps(list(record.warnings), ensure_ascii=False, sort_keys=True)
        try:
            self.conn.execute(
                """INSERT INTO messages(
                    source_name, relative_path, digest, size, message_id, subject, sender,
                    sent_at, status, error_code, error_detail, warnings_json, policy_hash,
                    first_seen_run, last_seen_run)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_name, relative_path) DO UPDATE SET
                    digest=excluded.digest, size=excluded.size, message_id=excluded.message_id,
                    subject=excluded.subject, sender=excluded.sender, sent_at=excluded.sent_at,
                    status=excluded.status, error_code=excluded.error_code,
                    error_detail=excluded.error_detail, warnings_json=excluded.warnings_json,
                    policy_hash=excluded.policy_hash, last_seen_run=excluded.last_seen_run""",
                (
                    record.source_name, record.relative_path, record.digest, record.size,
                    record.message_id, record.subject, record.sender, record.sent_at,
                    record.status.value, record.error_code, record.error_detail, warnings,
                    policy_hash, run_id, run_id,
                ),
            )
            self.conn.commit()
            row = self.conn.execute(
                "SELECT id FROM messages WHERE source_name=? AND relative_path=?",
                (record.source_name, record.relative_path),
            ).fetchone()
        except sqlite3.Error as exc:
            raise LedgerError(f"cannot upsert message: {exc}") from exc
        if row is None:
            raise LedgerError("message upsert did not return an id")
        return int(row["id"])

    def sync_attachments(
        self, message_id: int, records: Iterable[AttachmentRecord], run_id: str
    ) -> None:
        rows = list(records)
        try:
            for item in rows:
                self.conn.execute(
                    """INSERT INTO attachments(
                        message_id, part_id, sha256, size, filename, safe_filename, media_type,
                        disposition, nested_depth, status, reason_code, reason, object_path,
                        quarantine_path, first_seen_run, last_seen_run)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(message_id, part_id) DO UPDATE SET
                        sha256=excluded.sha256, size=excluded.size, filename=excluded.filename,
                        safe_filename=excluded.safe_filename, media_type=excluded.media_type,
                        disposition=excluded.disposition, nested_depth=excluded.nested_depth,
                        status=excluded.status, reason_code=excluded.reason_code,
                        reason=excluded.reason, object_path=excluded.object_path,
                        quarantine_path=excluded.quarantine_path,
                        last_seen_run=excluded.last_seen_run""",
                    (
                        message_id, item.part_id, item.sha256, item.size, item.filename,
                        item.safe_filename, item.media_type, item.disposition, item.nested_depth,
                        item.status.value, item.reason_code, item.reason, item.object_path,
                        item.quarantine_path, run_id, run_id,
                    ),
                )
            if rows:
                marks = ",".join("?" for _ in rows)
                self.conn.execute(
                    f"DELETE FROM attachments WHERE message_id=? AND part_id NOT IN ({marks})",
                    (message_id, *(item.part_id for item in rows)),
                )
            else:
                self.conn.execute("DELETE FROM attachments WHERE message_id=?", (message_id,))
            self.conn.commit()
        except sqlite3.Error as exc:
            raise LedgerError(f"cannot sync attachments: {exc}") from exc

    def commit_message(
        self,
        record: MessageRecord,
        attachments: Iterable[AttachmentRecord],
        run_id: str,
        policy_hash: str,
    ) -> int:
        """Upsert a message and replace its attachments in one transaction."""
        warnings = json.dumps(list(record.warnings), ensure_ascii=False, sort_keys=True)
        rows = list(attachments)
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self.conn.execute(
                """INSERT INTO messages(
                    source_name, relative_path, digest, size, message_id, subject, sender,
                    sent_at, status, error_code, error_detail, warnings_json, policy_hash,
                    first_seen_run, last_seen_run)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_name, relative_path) DO UPDATE SET
                    digest=excluded.digest, size=excluded.size, message_id=excluded.message_id,
                    subject=excluded.subject, sender=excluded.sender, sent_at=excluded.sent_at,
                    status=excluded.status, error_code=excluded.error_code,
                    error_detail=excluded.error_detail, warnings_json=excluded.warnings_json,
                    policy_hash=excluded.policy_hash, last_seen_run=excluded.last_seen_run""",
                (
                    record.source_name, record.relative_path, record.digest, record.size,
                    record.message_id, record.subject, record.sender, record.sent_at,
                    record.status.value, record.error_code, record.error_detail, warnings,
                    policy_hash, run_id, run_id,
                ),
            )
            row = self.conn.execute(
                "SELECT id FROM messages WHERE source_name=? AND relative_path=?",
                (record.source_name, record.relative_path),
            ).fetchone()
            if row is None:
                raise LedgerError("message upsert did not return an id")
            message_id = int(row["id"])
            for item in rows:
                self.conn.execute(
                    """INSERT INTO attachments(
                        message_id, part_id, sha256, size, filename, safe_filename, media_type,
                        disposition, nested_depth, status, reason_code, reason, object_path,
                        quarantine_path, first_seen_run, last_seen_run)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(message_id, part_id) DO UPDATE SET
                        sha256=excluded.sha256, size=excluded.size, filename=excluded.filename,
                        safe_filename=excluded.safe_filename, media_type=excluded.media_type,
                        disposition=excluded.disposition, nested_depth=excluded.nested_depth,
                        status=excluded.status, reason_code=excluded.reason_code,
                        reason=excluded.reason, object_path=excluded.object_path,
                        quarantine_path=excluded.quarantine_path,
                        last_seen_run=excluded.last_seen_run""",
                    (
                        message_id, item.part_id, item.sha256, item.size, item.filename,
                        item.safe_filename, item.media_type, item.disposition, item.nested_depth,
                        item.status.value, item.reason_code, item.reason, item.object_path,
                        item.quarantine_path, run_id, run_id,
                    ),
                )
            if rows:
                marks = ",".join("?" for _ in rows)
                self.conn.execute(
                    f"DELETE FROM attachments WHERE message_id=? AND part_id NOT IN ({marks})",
                    (message_id, *(item.part_id for item in rows)),
                )
            else:
                self.conn.execute("DELETE FROM attachments WHERE message_id=?", (message_id,))
            self.conn.commit()
        except sqlite3.Error as exc:
            self.conn.rollback()
            raise LedgerError(f"cannot commit message: {exc}") from exc
        except LedgerError:
            self.conn.rollback()
            raise
        return message_id

    def referenced_paths(self, paths: Iterable[str]) -> set[str]:
        """Return the subset of object paths currently referenced by the ledger."""
        wanted = [path for path in paths if path]
        if not wanted:
            return set()
        unique = list(dict.fromkeys(wanted))
        marks = ",".join("?" for _ in unique)
        rows = self._query(
            f"""SELECT object_path AS path FROM attachments WHERE object_path IN ({marks})
                UNION
                SELECT quarantine_path AS path FROM attachments WHERE quarantine_path IN ({marks})""",
            (*unique, *unique),
        )
        return {row["path"] for row in rows if row["path"]}

    def object_reference_count(self, relative_path: str) -> int:
        row = self._one(
            """SELECT COUNT(*) AS count FROM attachments
               WHERE object_path=? OR quarantine_path=?""",
            (relative_path, relative_path),
        )
        return int(row["count"]) if row else 0

    def accepted_hashes(self) -> set[str]:
        rows = self._query("SELECT DISTINCT sha256 FROM attachments WHERE status='accepted'")
        return {row["sha256"] for row in rows}

    def all_messages(self) -> list[dict[str, Any]]:
        return self._query(
            "SELECT * FROM messages ORDER BY source_name, relative_path, id"
        )

    def all_attachments(self) -> list[dict[str, Any]]:
        return self._query(
            """SELECT a.*, m.source_name AS message_source, m.relative_path AS message_path,
                      m.subject AS message_subject, m.status AS message_status
               FROM attachments a JOIN messages m ON m.id=a.message_id
               ORDER BY m.source_name, m.relative_path, a.part_id, a.id"""
        )

    def referenced_objects(self) -> list[dict[str, Any]]:
        return self._query(
            """SELECT a.*, m.source_name AS message_source, m.relative_path AS message_path
               FROM attachments a JOIN messages m ON m.id=a.message_id
               WHERE a.object_path <> '' OR a.quarantine_path <> ''
               ORDER BY a.object_path, a.quarantine_path, m.source_name, m.relative_path, a.part_id"""
        )

    def errors(self) -> list[dict[str, Any]]:
        return self._query(
            """SELECT source_name, relative_path, error_code, error_detail
               FROM messages WHERE status='error' ORDER BY source_name, relative_path"""
        )

    def get_message(self, message_id: int) -> dict[str, Any] | None:
        return self._one("SELECT * FROM messages WHERE id=?", (message_id,))

    def get_attachment(self, attachment_id: int) -> dict[str, Any] | None:
        return self._one(
            """SELECT a.*, m.source_name AS message_source, m.relative_path AS message_path,
                      m.subject AS message_subject, m.status AS message_status
               FROM attachments a JOIN messages m ON m.id=a.message_id WHERE a.id=?""",
            (attachment_id,),
        )

    def attachments_for_message(self, message_id: int) -> list[dict[str, Any]]:
        return self._query(
            "SELECT * FROM attachments WHERE message_id=? ORDER BY part_id", (message_id,)
        )

    def last_run(self) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM runs ORDER BY seq DESC LIMIT 1")
        if row is None:
            return None
        try:
            row["summary"] = json.loads(row.get("summary_json") or "{}")
        except json.JSONDecodeError:
            row["summary"] = {}
        return row

    def runs(self) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM runs ORDER BY seq")

    def count_rows(self, table: str) -> int:
        if table not in {"runs", "messages", "attachments"}:
            raise LedgerError("unknown table")
        row = self._one(f"SELECT COUNT(*) AS count FROM {table}")
        return int(row["count"]) if row else 0
