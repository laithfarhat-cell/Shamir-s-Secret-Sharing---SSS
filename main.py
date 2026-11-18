#!/usr/bin/env python3
"""Entry point for the ``sss`` command.

Two ways in::

    python main.py split --secret "hello" -k 2 -n 3
    sss split --secret "hello" -k 2 -n 3      # after `pip install .`

``main()`` returns a process exit code and never calls ``sys.exit`` itself, so
it can be imported and exercised directly by the test-suite.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

from cli.interface import run

__all__ = ["main", "cli_main"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return its exit code."""
    return run(argv)


#: Alias used by ``[project.scripts]`` in ``pyproject.toml``.
cli_main = main


if __name__ == "__main__":  # pragma: no cover - manual execution
    sys.exit(main())
