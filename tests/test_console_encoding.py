"""A legacy Windows code page must not stop a run at the first warning icon (Measure-Command, pipes, redirects)."""

from __future__ import annotations

import os
import subprocess
import sys

SNIPPET = ("import fwlens.cli.commands as c\n"
           "with c.cli.make_context('fwlens', ['init']):\n"
           "    c.cli.callback()\n"                  # what click runs first for every command
           "    c.console.print('[yellow]\\u26a0 a warning[/yellow]')\n")


def run(extra_env):
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0", **extra_env}
    return subprocess.run([sys.executable, "-c", SNIPPET], capture_output=True, env=env, timeout=60)


def test_an_icon_the_code_page_cannot_encode_is_written_as_a_question_mark():
    done = run({})
    assert done.returncode == 0, done.stderr.decode(errors="replace")
    assert b"? a warning" in done.stdout


def test_the_failure_is_real_without_the_fix():
    """Guards the test above: the same print on a strict cp1252 stream does fail."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    done = subprocess.run([sys.executable, "-c", "import fwlens.cli.commands as c\nc.console.print('\\u26a0')"],
                          capture_output=True, env=env, timeout=60)
    assert done.returncode != 0 and b"UnicodeEncodeError" in done.stderr
