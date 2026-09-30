"""Agent-first CLI and Python client for Salt Fiber Box (Sagemcom XMO) routers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("saltrouter-cli")
except PackageNotFoundError:
    __version__ = "0.0.0"


def main() -> None:
    from .cli import main as _main

    _main()
