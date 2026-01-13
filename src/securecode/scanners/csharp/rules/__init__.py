"""C# security rules."""

from securecode.scanners.csharp.rules.crypto import WeakCryptoRule
from securecode.scanners.csharp.rules.deserialization import InsecureDeserializationRule
from securecode.scanners.csharp.rules.injection import CommandInjectionRule, SQLInjectionRule
from securecode.scanners.csharp.rules.secrets import HardcodedSecretsRule
from securecode.scanners.csharp.rules.ssrf import SSRFRule

__all__ = [
    "SQLInjectionRule",
    "CommandInjectionRule",
    "WeakCryptoRule",
    "InsecureDeserializationRule",
    "HardcodedSecretsRule",
    "SSRFRule",
]
