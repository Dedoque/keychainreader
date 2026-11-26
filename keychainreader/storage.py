from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from .models import DEFAULT_DB_PATH, SecretEntry


@dataclass(slots=True)
class VaultIndex:
    db_path: Path = field(default=DEFAULT_DB_PATH)

    SCHEMA_SQL: ClassVar[str] = """
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        username TEXT NOT NULL,
        UNIQUE(service, username)
    );

    CREATE TABLE IF NOT EXISTS secret_tags (
        secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
        tag TEXT NOT NULL,
        PRIMARY KEY (secret_id, tag)
    );

    CREATE INDEX IF NOT EXISTS idx_secrets_lookup
        ON secrets(service COLLATE NOCASE, username COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_tags_lookup
        ON secret_tags(tag COLLATE NOCASE);
    """

    def __post_init__(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(self.SCHEMA_SQL)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _escape_like(value: str) -> str:
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def upsert(self, entry: SecretEntry, replace_tags: bool = True) -> bool:
        clean_tags = tuple(dict.fromkeys(t.strip() for t in entry.tags if t.strip()))
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM secrets WHERE service = ? AND username = ?",
                (entry.service, entry.username),
            ).fetchone()

            if existing is None:
                cur = conn.execute(
                    "INSERT INTO secrets (service, username) VALUES (?, ?)",
                    (entry.service, entry.username),
                )
                secret_id = int(cur.lastrowid or 0)
                is_new = True
            else:
                secret_id = int(existing["id"])
                is_new = False

            if replace_tags:
                conn.execute("DELETE FROM secret_tags WHERE secret_id = ?", (secret_id,))

            if clean_tags:
                conn.executemany(
                    "INSERT OR IGNORE INTO secret_tags (secret_id, tag) VALUES (?, ?)",
                    [(secret_id, tag) for tag in clean_tags],
                )
            return is_new

    def sync_many(self, entries: Iterable[SecretEntry]) -> tuple[int, int]:
        added = 0
        total = 0
        for entry in entries:
            total += 1
            if self.upsert(entry, replace_tags=False):
                added += 1
        return added, total

    def search(self, query: str) -> list[dict[str, object]]:
        pattern = f"%{self._escape_like(query.strip())}%"
        with self._connect() as conn:
            rows = conn.execute(
                r"""
                SELECT DISTINCT s.id, s.service, s.username
                FROM secrets s
                LEFT JOIN secret_tags st ON st.secret_id = s.id
                WHERE s.service LIKE ? ESCAPE '\' COLLATE NOCASE
                   OR s.username LIKE ? ESCAPE '\' COLLATE NOCASE
                   OR st.tag LIKE ? ESCAPE '\' COLLATE NOCASE
                ORDER BY s.service COLLATE NOCASE, s.username COLLATE NOCASE
                """,
                (pattern, pattern, pattern),
            ).fetchall()

            results: list[dict[str, object]] = []
            for row in rows:
                tag_rows = conn.execute(
                    "SELECT tag FROM secret_tags WHERE secret_id = ? ORDER BY tag COLLATE NOCASE",
                    (row["id"],),
                ).fetchall()
                entry = SecretEntry(
                    service=row["service"],
                    username=row["username"],
                    tags=tuple(r["tag"] for r in tag_rows),
                )
                results.append(entry.to_dict())
            return results
