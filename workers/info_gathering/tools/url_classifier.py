# workers/info_gathering/tools/url_classifier.py
"""Classify discovered URLs into canonical asset types.

Maps URL characteristics (extension, path keywords) to the asset types
defined in lib_webbh.database.ASSET_TYPES.
"""

from urllib.parse import urlparse

# Extensions that indicate sensitive / leaked files
_SENSITIVE_EXTENSIONS = frozenset({
    ".env", ".sql", ".bak", ".old", ".backup", ".dump",
    ".conf", ".cfg", ".ini", ".yml", ".yaml", ".toml", ".properties",
    ".key", ".pem", ".p12", ".pfx", ".jks",
    ".log", ".tar", ".gz", ".zip", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
    ".xml", ".json", ".wsdl",
})

# Path fragments that indicate directory listings / admin panels
_DIRECTORY_KEYWORDS = frozenset({
    "/admin", "/administrator", "/cpanel", "/wp-admin",
    "/dashboard", "/manage", "/control",
    "index+of", "index%20of", "parent+directory",
    "/.git/", "/.svn/", "/.env",
    "/wp-content/uploads/",
})

# Path fragments that indicate error / debug pages
_ERROR_KEYWORDS = frozenset({
    "error", "500", "404", "traceback", "stack-trace", "stacktrace",
    "debug", "exception",
})

# Dork category → asset type mapping
DORK_CATEGORY_MAP: dict[str, str] = {
    "exposed_files": "sensitive_file",
    "backup_files": "sensitive_file",
    "config_leaks": "sensitive_file",
    "admin_panels": "directory",
    "sensitive_dirs": "directory",
    "error_pages": "error",
    "login_pages": "undetermined",
    "api_endpoints": "undetermined",
}


def classify_url(url: str) -> str:
    """Classify a URL into a canonical asset type based on its characteristics.

    Returns one of: sensitive_file, directory, error, undetermined.
    Does NOT return domain/ip/subdomain/form/upload — those are set by
    the tools that have richer context (DNS enumeration, form detection, etc.).
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Check extension for sensitive files
    for ext in _SENSITIVE_EXTENSIONS:
        if path.endswith(ext):
            return "sensitive_file"

    # Check path for directory listings / admin panels
    path_lower = url.lower()
    for kw in _DIRECTORY_KEYWORDS:
        if kw in path_lower:
            return "directory"

    # Check for error pages (less reliable from URL alone)
    last_segment = path.rsplit("/", 1)[-1].lower()
    for kw in _ERROR_KEYWORDS:
        if kw in last_segment:
            return "error"

    return "undetermined"
