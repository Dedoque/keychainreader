from __future__ import annotations

import base64
import threading
import time
from contextlib import suppress
from typing import ClassVar

import pyperclip


class SecretProtector:
    FORBIDDEN_BINS: ClassVar[frozenset[str]] = frozenset({"env", "printenv", "set", "export"})

    @staticmethod
    def redact(text: str, secret: str) -> str:
        if not text or not secret:
            return text
        b64 = base64.b64encode(secret.encode()).decode()
        return text.replace(secret, "***REDACTED***").replace(b64, "***REDACTED_B64***")

    @staticmethod
    def copy_with_ttl(secret: str, ttl_sec: int = 30) -> None:
        pyperclip.copy(secret)
        if ttl_sec <= 0:
            return

        def _wipe() -> None:
            time.sleep(ttl_sec)
            with suppress(Exception):
                if pyperclip.paste() == secret:
                    pyperclip.copy("")

        threading.Thread(target=_wipe, daemon=True).start()

