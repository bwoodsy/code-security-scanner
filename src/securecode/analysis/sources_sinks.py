"""Source, sink, and sanitizer definitions for data flow analysis."""

from __future__ import annotations

# =============================================================================
# TypeScript/JavaScript Sources (User Input)
# =============================================================================

TYPESCRIPT_SOURCES = [
    # Express.js request object
    "req.params",
    "req.query",
    "req.body",
    "req.headers",
    "req.cookies",
    "req.files",
    "req.file",
    "req.path",
    "req.url",
    "req.originalUrl",
    # Alternative request patterns
    "request.params",
    "request.query",
    "request.body",
    "request.headers",
    # Koa.js
    "ctx.params",
    "ctx.query",
    "ctx.request.body",
    "ctx.request.query",
    # Fastify
    "request.params",
    "request.query",
    "request.body",
    # AWS Lambda
    "event.body",
    "event.queryStringParameters",
    "event.pathParameters",
    "event.headers",
    # Browser APIs
    "document.location",
    "window.location",
    "location.href",
    "location.hash",
    "location.search",
    "location.pathname",
    "document.URL",
    "document.referrer",
    "document.cookie",
    # Storage APIs
    "localStorage.getItem",
    "sessionStorage.getItem",
    # Form data
    "FormData",
    "URLSearchParams",
    # WebSocket
    "message.data",
    "event.data",
    # User input elements
    ".value",  # input.value, textarea.value
    "innerHTML",  # When reading (though usually a sink)
    "innerText",
    "textContent",
]

# =============================================================================
# C# Sources (User Input)
# =============================================================================

CSHARP_SOURCES = [
    # ASP.NET Core
    "Request.Query",
    "Request.Form",
    "Request.Body",
    "Request.Headers",
    "Request.Cookies",
    "Request.Path",
    "Request.RouteValues",
    "HttpContext.Request",
    # Controller parameters (common names)
    "id",
    "userId",
    "userName",
    "name",
    "query",
    "search",
    "filter",
    "input",
    "data",
    "payload",
    "content",
    "message",
    "file",
    "path",
    "url",
    "returnUrl",
    "redirectUrl",
    # MVC Model binding
    "model.",
    "Model.",
    "viewModel.",
    # Query string
    "QueryString[",
    "Form[",
    "RouteData.Values",
    # File uploads
    "IFormFile",
    "Request.Files",
]

# =============================================================================
# Sinks by Vulnerability Type
# =============================================================================

TYPESCRIPT_SINKS = {
    "SQL_INJECTION": [
        "query(",
        "execute(",
        "raw(",
        "$queryRaw",
        "$executeRaw",
        "sequelize.query",
        "knex.raw",
        "pool.query",
        "connection.query",
        "db.query",
        "mysql.query",
        "pg.query",
        ".query`",  # Tagged template
    ],
    "XSS": [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "document.writeln",
        "dangerouslySetInnerHTML",
        ".html(",  # jQuery
        "$(", # jQuery selector with user input
        "eval(",
        "Function(",
        "setTimeout(",  # When first arg is string
        "setInterval(",  # When first arg is string
    ],
    "COMMAND_INJECTION": [
        "exec(",
        "execSync(",
        "spawn(",
        "spawnSync(",
        "execFile(",
        "execFileSync(",
        "child_process",
        "shell.exec",
        "shelljs",
    ],
    "PATH_TRAVERSAL": [
        "readFile(",
        "readFileSync(",
        "writeFile(",
        "writeFileSync(",
        "createReadStream(",
        "createWriteStream(",
        "appendFile(",
        "unlink(",
        "rmdir(",
        "mkdir(",
        "readdir(",
        "stat(",
        "access(",
        "sendFile(",
        "download(",
        "res.sendFile",
        "res.download",
    ],
    "OPEN_REDIRECT": [
        "res.redirect(",
        "response.redirect(",
        "location.href",
        "location.replace(",
        "location.assign(",
        "window.open(",
    ],
    "SSRF": [
        "fetch(",
        "axios(",
        "axios.get(",
        "axios.post(",
        "http.request(",
        "https.request(",
        "request(",
        "got(",
        "superagent",
    ],
}

CSHARP_SINKS = {
    "SQL_INJECTION": [
        "ExecuteSqlRaw(",
        "FromSqlRaw(",
        "ExecuteSqlCommand(",
        "SqlCommand(",
        "OleDbCommand(",
        "OdbcCommand(",
        ".CommandText",
        "ExecuteReader(",
        "ExecuteNonQuery(",
        "ExecuteScalar(",
        "query(",
    ],
    "XSS": [
        "Html.Raw(",
        "Response.Write(",
        "HtmlString(",
        "@Html.Raw",
        "Content(",  # When returning HTML
    ],
    "COMMAND_INJECTION": [
        "Process.Start(",
        "ProcessStartInfo(",
        "cmd.exe",
        "powershell.exe",
        "/bin/bash",
        "/bin/sh",
    ],
    "PATH_TRAVERSAL": [
        "File.ReadAllText(",
        "File.ReadAllBytes(",
        "File.WriteAllText(",
        "File.WriteAllBytes(",
        "File.Delete(",
        "File.Copy(",
        "File.Move(",
        "File.Open(",
        "FileStream(",
        "StreamReader(",
        "StreamWriter(",
        "Directory.GetFiles(",
        "Directory.Delete(",
        "PhysicalFile(",
        "PhysicalFileResult(",
    ],
    "OPEN_REDIRECT": [
        "Redirect(",
        "RedirectPermanent(",
        "RedirectToAction(",
        "Response.Redirect(",
    ],
    "INSECURE_DESERIALIZATION": [
        "BinaryFormatter(",
        "Deserialize(",
        "JsonConvert.DeserializeObject(",
        "XmlSerializer(",
    ],
    "XXE": [
        "XmlReader.Create(",
        "XmlDocument.Load(",
        "XDocument.Load(",
        "XmlTextReader(",
    ],
    "LDAP_INJECTION": [
        "DirectorySearcher(",
        ".Filter",
        "DirectoryEntry(",
    ],
}

# =============================================================================
# Sanitizers and Safe Patterns
# =============================================================================

TYPESCRIPT_SANITIZERS = [
    # Encoding functions
    r"encodeURI\(",
    r"encodeURIComponent\(",
    r"escape\(",
    r"\.escape\(",
    r"htmlEncode\(",
    r"escapeHtml\(",
    # Sanitization libraries
    r"DOMPurify\.sanitize\(",
    r"sanitize-html",
    r"sanitizeHtml\(",
    r"xss\(",
    r"validator\.",
    r"\.sanitize\(",
    # Type coercion (for SQL injection)
    r"parseInt\(",
    r"parseFloat\(",
    r"Number\(",
    r"BigInt\(",
    r"Boolean\(",
    # Validation
    r"\.trim\(\)",
    r"\.replace\(",
    r"\.match\(",
    r"\.test\(",
    r"RegExp\(",
    # Parameterized queries
    r"\?\s*,",  # Placeholder syntax
    r"\$\d+",  # PostgreSQL placeholders $1, $2
    r":[\w]+",  # Named parameters :param
    # Framework-specific
    r"Joi\.",
    r"yup\.",
    r"zod\.",
    r"express-validator",
]

CSHARP_SANITIZERS = [
    # Encoding
    r"HtmlEncode\(",
    r"UrlEncode\(",
    r"JavaScriptStringEncode\(",
    r"WebUtility\.HtmlEncode",
    r"HttpUtility\.HtmlEncode",
    r"AntiXss\.",
    # Parameterized queries
    r"@\w+",  # SQL parameters @param
    r"Parameters\.Add",
    r"SqlParameter\(",
    r"AddWithValue\(",
    r"new\s+\{\s*\w+\s*=",  # Anonymous type parameters
    # Validation
    r"Regex\.",
    r"int\.TryParse\(",
    r"Guid\.TryParse\(",
    r"DateTime\.TryParse\(",
    r"\.IsNullOrEmpty\(",
    r"\.IsNullOrWhiteSpace\(",
    # Path validation
    r"Path\.GetFileName\(",
    r"Path\.GetFullPath\(",
    r"\.StartsWith\(",
    r"\.Contains\(\"\.\.\"\)",
    # Framework
    r"\[FromBody\]",
    r"\[FromQuery\]",
    r"ModelState\.IsValid",
    r"DataAnnotations",
]

# =============================================================================
# Safe Value Patterns (definitely not user input)
# =============================================================================

SAFE_VALUE_PATTERNS = [
    # Literals
    r'^["\'].*["\']$',  # String literals
    r'^\d+$',  # Number literals
    r'^(true|false)$',  # Boolean literals
    r'^null$',
    r'^undefined$',
    # Constants
    r'^[A-Z_][A-Z0-9_]*$',  # CONSTANT_CASE
    r'\.env\.',  # Environment variables (config, not user input)
    r'process\.env\.',
    r'Environment\.GetEnvironmentVariable',
    # Configuration
    r'config\.',
    r'Config\.',
    r'configuration\.',
    r'Configuration\[',
    r'appsettings',
    r'IOptions<',
    # Static/hardcoded
    r'__dirname',
    r'__filename',
    r'import\.meta',
]

# =============================================================================
# Helper Functions
# =============================================================================

def get_sources(language: str) -> list[str]:
    """Get user input sources for a language."""
    if language in ("typescript", "javascript"):
        return TYPESCRIPT_SOURCES
    elif language == "csharp":
        return CSHARP_SOURCES
    return []


def get_sinks(language: str, vuln_type: str) -> list[str]:
    """Get dangerous sinks for a language and vulnerability type."""
    if language in ("typescript", "javascript"):
        return TYPESCRIPT_SINKS.get(vuln_type, [])
    elif language == "csharp":
        return CSHARP_SINKS.get(vuln_type, [])
    return []


def get_sanitizers(language: str) -> list[str]:
    """Get sanitizer patterns for a language."""
    if language in ("typescript", "javascript"):
        return TYPESCRIPT_SANITIZERS
    elif language == "csharp":
        return CSHARP_SANITIZERS
    return []


def is_known_source(code: str, language: str) -> tuple[bool, str | None]:
    """Check if code contains a known user input source."""
    sources = get_sources(language)
    code_lower = code.lower()

    for source in sources:
        if source.lower() in code_lower:
            return True, source

    return False, None


def is_safe_value(code: str) -> bool:
    """Check if code represents a safe (non-user) value."""
    import re

    code = code.strip()

    for pattern in SAFE_VALUE_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            return True

    return False
