"""TypeScript/JavaScript security scanner."""

from securecode.scanners.typescript.scanner import TypeScriptScanner

# Import rules to register them
from securecode.scanners.typescript.rules import crypto  # noqa: F401
from securecode.scanners.typescript.rules import injection  # noqa: F401
from securecode.scanners.typescript.rules import path_traversal  # noqa: F401
from securecode.scanners.typescript.rules import prototype_pollution  # noqa: F401
from securecode.scanners.typescript.rules import redirect  # noqa: F401
from securecode.scanners.typescript.rules import secrets  # noqa: F401
from securecode.scanners.typescript.rules import xss  # noqa: F401

__all__ = ["TypeScriptScanner"]
