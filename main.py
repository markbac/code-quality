"""
main.py -- repository-level convenience wrapper: `python main.py report`.

Not packaged. The installed command is `fwlens` (entry point fwlens.cli:main).
"""

import fwlens.cli.commands as _commands

cli = _commands.cli
main = _commands.main


def __getattr__(name: str):
    return getattr(_commands, name)


if __name__ == "__main__":
    cli()
