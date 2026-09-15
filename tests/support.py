"""Shared test helpers.

Importing this module puts the repository root on sys.path, so every test file can
start with `import support` and then import the clauderestart package.
"""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clauderestart import winapi  # noqa: E402


def frozen_at(executable: Path) -> ExitStack:
    """Pretend to run as the frozen executable at `executable`.

    Frozen mode is read in exactly one place, winapi.is_frozen(), so this patches
    that function and sys.executable and nothing else.
    """
    stack = ExitStack()
    stack.enter_context(mock.patch.object(winapi, "is_frozen", return_value=True))
    stack.enter_context(mock.patch.object(sys, "executable", str(executable)))
    return stack
