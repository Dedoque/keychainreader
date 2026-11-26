# keychainreader

A zero-leakage Model Context Protocol (MCP) server for **macOS Keychain** and **Linux Secret Service**.

`keychainreader` allows AI agents (such as OpenCode, Claude Code, Cursor, or Claude Desktop) to discover stored credentials, copy secrets directly to your clipboard, and execute CLI commands with injected environment variables—**without ever exposing raw secret values to the LLM context**.

## Features

- **Zero-Exposure Architecture:** Secret values are retrieved locally and never returned in MCP tool responses.
- **Direct Clipboard Transfer:** Copies secrets straight to your OS clipboard with automatic TTL-based wiping (default: 30s).
- **Transparent CLI Proxy:** Injects secrets into subprocess environment variables (`shell=False`) and automatically redacts both raw and Base64-encoded secret occurrences from `stdout` and `stderr`.
- **Metadata Auto-Discovery:** Scans macOS Keychain (`security dump-keychain`) and Linux Secret Service (`secret-tool`) for service/account metadata without triggering decryption prompts.
- **SQLite Metadata Index:** Stores searchable service names, usernames, and custom tags locally in `~/.cache/keycahainreader/index.sqlite3` (never stores passwords).

## Requirements

- **Python:** 3.12+
- **uv / uvx:** Recommended for zero-setup execution.
- **macOS:** Uses built-in `security` CLI and `pbcopy` (works out of the box).
- **Linux:** Requires `libsecret-tools` (`secret-tool`) and a clipboard utility (`wl-clipboard` for Wayland or `xclip`/`xsel` for X11).

## Installation & Usage

### Run directly from Git via `uvx`

```bash
uvx --python 3.12 --from git+https://github.com/Dedoque/keychainreader.git keychainreader
```

### Run from a local clone

```bash
git clone https://github.com/Dedoque/keychainreader.git
cd keychainreader
uv run keychainreader
```

## MCP Client Configuration

### OpenCode (`~/.config/opencode/opencode.json`)

Add via CLI:

```bash
opencode mcp add keychainreader --global -- uvx --python 3.12 --from git+https://github.com/Dedoque/keychainreader.git keychainreader
```

Or add manually to `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "keychainreader": {
        "type": "local",
        "command": [
          "uvx",
          "--python",
          "3.12",
          "--from",
          "git+https://github.com/Dedoque/keychainreader.git",
          "keychainreader"
        ]
      }
    }
  }
}
```

### Claude Desktop / Cursor (`mcp.json`)

```json
{
  "mcpServers": {
    "keychainreader": {
      "command": "uvx",
      "args": [
        "--python",
        "3.12",
        "--from",
        "git+https://github.com/Dedoque/keychainreader.git",
        "keychainreader"
      ]
    }
  }
}
```

## Available MCP Tools

| Tool | Description |
| :--- | :--- |
| `sync_keychain_index` | Scans OS Keychain / Secret Service metadata and updates the local SQLite index. |
| `search_secrets` | Searches indexed secrets by `service`, `username`, or `tags`. Returns metadata only. |
| `save_secret_metadata` | Registers or updates tags for an existing Keychain entry in the search index. |
| `copy_secret_to_clipboard` | Copies the secret value to the system clipboard and wipes it after `auto_clear_sec`. |
| `run_cli_with_secret` | Runs a CLI command (`list[str]`, `shell=False`) with the secret injected into `env_var_name` and redacts outputs. |

## Security Model

1. **No Secret Echoing:** None of the MCP tools return plaintext credentials to the model.
2. **Process Isolation:** CLI commands execute via `subprocess.run(..., shell=False)` with argument lists to prevent shell expansion attacks (e.g., `echo \$TOKEN`).
3. **Output Sanitization:** Both raw and Base64-encoded representations of the injected secret are scrubbed (`***REDACTED***`) from `stdout` and `stderr` before returning to the client.
4. **Blocked Dump Binaries:** Direct environment inspection commands (`env`, `printenv`, `set`, `export`) are blocked by default.

## Credits

This project was developed with the assistance of **Google AI (Gemini)**.


## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.

