from __future__ import annotations

import os
import subprocess
from contextlib import suppress
from pathlib import Path

import keyring
from mcp.server.mcpserver import MCPServer

from .models import CommandArgs, SecretEntry
from .scanner import KeychainScanner
from .security import SecretProtector
from .storage import VaultIndex


class SecureVaultServer:
    def __init__(
        self,
        name: str = "secure-vault-mcp",
        index: VaultIndex | None = None,
        auto_sync_on_start: bool = True,
    ) -> None:
        self.mcp = MCPServer(name)
        self.index = index or VaultIndex()
        if auto_sync_on_start:
            with suppress(Exception):
                self.index.sync_many(KeychainScanner.scan())
        self._register_tools()

    def _register_tools(self) -> None:
        self.mcp.tool()(self.sync_keychain_index)
        self.mcp.tool()(self.save_secret_metadata)
        self.mcp.tool()(self.search_secrets)
        self.mcp.tool()(self.copy_secret_to_clipboard)
        self.mcp.tool()(self.run_cli_with_secret)

    def sync_keychain_index(self) -> str:
        try:
            discovered = KeychainScanner.scan()
        except Exception as err:
            return f"Keychain scan failed: {err}"

        added, total = self.index.sync_many(discovered)
        return f"Scan complete: {total} entries found, {added} new entries added to index."

    def save_secret_metadata(
        self,
        service: str,
        username: str,
        tags: list[str] | None = None,
    ) -> str:
        entry = SecretEntry(service=service, username=username, tags=tuple(tags or ()))
        self.index.upsert(entry, replace_tags=True)
        return f"Metadata for '{service}' ({username}) saved to SQLite index."

    def search_secrets(self, query: str) -> list[dict[str, object]]:
        return self.index.search(query)

    def copy_secret_to_clipboard(
        self,
        service: str,
        username: str,
        auto_clear_sec: int = 30,
    ) -> str:
        if not (secret := keyring.get_password(service, username)):
            return f"Error: secret for '{service}' ({username}) was not found."

        SecretProtector.copy_with_ttl(secret, ttl_sec=auto_clear_sec)
        return f"Secret for '{service}' copied to clipboard (auto-clear in {auto_clear_sec}s)."

    def run_cli_with_secret(
        self,
        command: CommandArgs,
        service: str,
        username: str,
        env_var_name: str,
        timeout_sec: int = 30,
    ) -> str:
        match command:
            case []:
                return "Error: empty command provided."
            case [binary, *_] if Path(binary).name in SecretProtector.FORBIDDEN_BINS:
                return f"Blocked: command '{binary}' is forbidden by security policy."

        if not (secret := keyring.get_password(service, username)):
            return f"Error: secret for '{service}' ({username}) was not found in Keychain."

        child_env = os.environ | {env_var_name: secret}

        try:
            proc = subprocess.run(
                command,
                env=child_env,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return f"Error: command timed out after {timeout_sec}s."
        except Exception as err:
            return SecretProtector.redact(f"Execution error: {err}", secret)

        stdout = SecretProtector.redact(proc.stdout, secret)
        stderr = SecretProtector.redact(proc.stderr, secret)
        return f"Exit code: {proc.returncode}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"

    def run(self) -> None:
        self.mcp.run()


def main() -> None:
    SecureVaultServer().run()


if __name__ == "__main__":
    main()
