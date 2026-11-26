from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

type SecretKey = tuple[str, str]
type CommandArgs = list[str]

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "keycahainreader"
DEFAULT_DB_PATH = DEFAULT_CACHE_DIR / "index.sqlite3"


@dataclass(slots=True, frozen=True)
class SecretEntry:
    service: str
    username: str
    tags: tuple[str, ...] = ()

    @property
    def key(self) -> SecretKey:
        return (self.service, self.username)

    def to_dict(self) -> dict[str, object]:
        return {
            "service": self.service,
            "username": self.username,
            "tags": list(self.tags),
        }

