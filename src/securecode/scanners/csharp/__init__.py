"""C# security scanner."""

from securecode.scanners.csharp.scanner import CSharpScanner

# Import rules to register them
from securecode.scanners.csharp.rules import crypto  # noqa: F401
from securecode.scanners.csharp.rules import deserialization  # noqa: F401
from securecode.scanners.csharp.rules import injection  # noqa: F401
from securecode.scanners.csharp.rules import ldap  # noqa: F401
from securecode.scanners.csharp.rules import path_traversal  # noqa: F401
from securecode.scanners.csharp.rules import redirect  # noqa: F401
from securecode.scanners.csharp.rules import secrets  # noqa: F401
from securecode.scanners.csharp.rules import xxe  # noqa: F401

__all__ = ["CSharpScanner"]
