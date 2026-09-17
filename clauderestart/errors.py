"""Exception types shared by every module.

A leaf module: it imports nothing from the package, so every other module,
including the other leaves, may import it.
"""

from __future__ import annotations


class RecoveryError(RuntimeError):
    """A discovery, repair, or verification operation failed."""


class SafetyStop(RecoveryError):
    """The observed state did not satisfy the strict repair boundary."""
