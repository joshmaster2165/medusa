"""Backwards-compatible re-export shim.

All patterns have been moved to ``medusa.utils.patterns.*`` submodules.
This file ensures that existing ``from medusa.utils.pattern_matching import X``
statements continue to work without modification.
"""

from medusa.utils.patterns import *  # noqa: F401, F403
