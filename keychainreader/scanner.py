from __future__ import annotations

import platform
import re
import shutil
import subprocess
from typing import ClassVar

from .models import SecretEntry, SecretKey


class KeychainScanner:
    _MAC_ATTR_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'^\s*"(?P<key>svce|acct|desc)"<blob>="(?P<val>[^"]*)"'
    )

    @classmethod
    def scan(cls) -> list[SecretEntry]:
        match platform.system():
            case "Darwin":
                return cls._scan_macos()
            case "Linux":
                return cls._scan_linux()
            case other:
                raise RuntimeError(f"Auto-scanning is not supported on OS: {other}")

    @classmethod
    def _scan_macos(cls) -> list[SecretEntry]:
        if not shutil.which("security"):
            raise RuntimeError("The 'security' CLI utility was not found in PATH.")

        proc = subprocess.run(
            ["security", "dump-keychain"],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        if not proc.stdout.strip():
            return []

        entries: dict[SecretKey, SecretEntry] = {}
        current: dict[str, str] = {}

        def _flush() -> None:
            service = current.get("svce", "").strip()
            username = current.get("acct", "").strip()
            if service and username:
                tags = ["auto-discovered", "macos-keychain"]
                if desc := current.get("desc", "").strip():
                    tags.append(desc)
                entry = SecretEntry(service=service, username=username, tags=tuple(tags))
                entries[entry.key] = entry
            current.clear()

        for line in proc.stdout.splitlines():
            if line.startswith(("keychain:", "class:")):
                _flush()
                continue
            if m := cls._MAC_ATTR_RE.match(line):
                current[m["key"]] = m["val"]

        _flush()
        return list(entries.values())

    @classmethod
    def _scan_linux(cls) -> list[SecretEntry]:
        if not shutil.which("secret-tool"):
            raise RuntimeError(
                "The 'secret-tool' utility was not found. Please install libsecret-tools."
            )

        proc = subprocess.run(
            ["secret-tool", "search", "--all", "xdg:schema", "org.freedesktop.Secret.Generic"],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        raw_output = f"{proc.stdout}\n{proc.stderr}"
        entries: dict[SecretKey, SecretEntry] = {}
        block: dict[str, str] = {}

        def _flush() -> None:
            service = (
                block.get("attribute.service")
                or block.get("attribute.application")
                or block.get("attribute.server")
                or ""
            ).strip()
            username = (
                block.get("attribute.username")
                or block.get("attribute.user")
                or block.get("attribute.account")
                or ""
            ).strip()
            if service and username:
                tags = ["auto-discovered", "linux-keyring"]
                if label := block.get("label", "").strip():
                    tags.append(label)
                entry = SecretEntry(service=service, username=username, tags=tuple(tags))
                entries[entry.key] = entry
            block.clear()

        for line in raw_output.splitlines():
            stripped = line.strip()
            if stripped.startswith("[/org/freedesktop/secrets/"):
                _flush()
                continue
            if "=" in stripped:
                k, _, v = stripped.partition("=")
                block[k.strip()] = v.strip()

        _flush()
        return list(entries.values())
