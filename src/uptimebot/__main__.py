"""Process entrypoint.

Delegates to :func:`uptimebot.cli.main` so that both ``python -m uptimebot`` and
the ``uptimebot`` console script accept the same subcommands.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
