"""Credential/config resolution: flags > env vars > .env files."""

import os
from pathlib import Path

ENV_FILES = (Path.cwd() / ".env", Path.home() / ".config" / "saltrouter" / ".env")


def load_env_files(extra: str | None = None) -> None:
    """Populate os.environ from .env files without overriding existing vars."""
    paths = [Path(extra)] if extra else []
    for path in [*paths, *ENV_FILES]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.removeprefix("export ").partition("=")
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            os.environ.setdefault(key.strip(), val)


def env_password() -> str | None:
    return os.environ.get("SALTROUTER_PASSWORD") or os.environ.get("SALTROUTER_PW")
