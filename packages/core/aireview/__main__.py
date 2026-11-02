"""Entrypoint so `python3 -m aireview` works with PYTHONPATH=packages/core.

The Actions runner uses this form rather than an installed console script,
because `packages/core` is stdlib-only and therefore needs no install step.
"""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
