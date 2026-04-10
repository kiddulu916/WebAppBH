"""Core payload mutation engine.

Applies vuln-type-specific mutation strategies to generate WAF-bypass variants.
Optionally filters strategies by InjectionContext when provided.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from workers.sandbox_worker.context import InjectionContext


# ---------------------------------------------------------------------------
# Individual mutation strategy functions
# ---------------------------------------------------------------------------

def _url_encode(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def _double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _html_entity(payload: str) -> str:
    return "".join(f"&#{ord(c)};" for c in payload)


def _unicode_escape(payload: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in payload)


def _case_variation(payload: str) -> str:
    return payload.swapcase()


def _null_byte_inject(payload: str) -> str:
    return payload + "%00"


def _comment_insert_html(payload: str) -> str:
    mid = len(payload) // 2
    return payload[:mid] + "<!--x-->" + payload[mid:]


def _tag_nesting(payload: str) -> str:
    return f"<div>{payload}</div>"


def _event_handler_swap(payload: str) -> str:
    return payload.replace("onerror=", "onload=").replace("onload=", "onfocus=")


def _svg_wrapper(payload: str) -> str:
    return f"<svg/onload={payload}>"


def _math_wrapper(payload: str) -> str:
    return f"<math><mtext>{payload}</mtext></math>"


# SQLi strategies
def _comment_insert_sql(payload: str) -> str:
    return payload.replace(" ", "/**/")


def _char_concat(payload: str) -> str:
    return "CONCAT(" + ",".join(f"CHAR({ord(c)})" for c in payload[:10]) + ")"


def _hex_encoding(payload: str) -> str:
    return "0x" + payload.encode().hex()


def _whitespace_sub(payload: str) -> str:
    return payload.replace(" ", "%0a")


def _quote_doubling(payload: str) -> str:
    return payload.replace("'", "''")


def _union_alt(payload: str) -> str:
    return payload.replace("UNION", "/*!UNION*/").replace("SELECT", "/*!SELECT*/")


# SSRF strategies
def _ip_decimal(payload: str) -> str:
    return payload.replace("127.0.0.1", "2130706433").replace("localhost", "2130706433")


def _ip_octal(payload: str) -> str:
    return payload.replace("127.0.0.1", "0177.0.0.1").replace("localhost", "0177.0.0.1")


def _ip_hex(payload: str) -> str:
    return payload.replace("127.0.0.1", "0x7f000001").replace("localhost", "0x7f000001")


def _url_parser_confusion(payload: str) -> str:
    return payload.replace("://", "://@")


def _localhost_variant(payload: str) -> str:
    return payload.replace("localhost", "127.0.0.1").replace("127.0.0.1", "[::1]")


# Command injection strategies
def _shell_metachar(payload: str) -> str:
    return payload.replace(";", "|").replace("|", "&&")


def _ifs_whitespace(payload: str) -> str:
    return payload.replace(" ", "${IFS}")


def _backtick_wrap(payload: str) -> str:
    # Wrap the core command in backticks
    return payload.replace("cat", "`cat`")


def _base64_pipe(payload: str) -> str:
    import base64
    cmd_part = payload.lstrip("; |&")
    encoded = base64.b64encode(cmd_part.encode()).decode()
    return f"echo {encoded}|base64 -d|sh"


# XXE strategies
def _parameter_entity(payload: str) -> str:
    return payload.replace("<!ENTITY", "<!ENTITY % xxe")


def _svg_xxe(payload: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg">{payload}</svg>'


def _utf16_xxe(payload: str) -> str:
    return f'<?xml version="1.0" encoding="UTF-16"?>{payload}'


# Template injection strategies
def _jinja2_variant(payload: str) -> str:
    return payload.replace("{{", "{%print ").replace("}}", "%}")


def _twig_variant(payload: str) -> str:
    return payload.replace("{{", "{{").replace("7*7", "'7'~'7'")


def _erb_variant(payload: str) -> str:
    return payload.replace("{{", "<%= ").replace("}}", " %>")


def _whitespace_ssti(payload: str) -> str:
    return payload.replace("{{", "{{ ").replace("}}", " }}")


# Path traversal strategies
def _dot_encoding(payload: str) -> str:
    return payload.replace("..", "%2e%2e")


def _slash_variation(payload: str) -> str:
    return payload.replace("/", "\\")


def _double_encode_path(payload: str) -> str:
    return payload.replace("../", "%252e%252e%252f")


def _null_byte_path(payload: str) -> str:
    return payload + "%00"


# ---------------------------------------------------------------------------
# Strategy registries per vuln type
# ---------------------------------------------------------------------------

STRATEGIES: dict[str, dict[str, callable]] = {
    "xss": {
        "url_encode": _url_encode,
        "double_url_encode": _double_url_encode,
        "html_entity": _html_entity,
        "unicode_escape": _unicode_escape,
        "case_variation": _case_variation,
        "null_byte_inject": _null_byte_inject,
        "comment_insert": _comment_insert_html,
        "tag_nesting": _tag_nesting,
        "event_handler_swap": _event_handler_swap,
        "svg_wrapper": _svg_wrapper,
        "math_wrapper": _math_wrapper,
    },
    "sqli": {
        "comment_insert": _comment_insert_sql,
        "case_variation": _case_variation,
        "char_concat": _char_concat,
        "hex_encoding": _hex_encoding,
        "whitespace_sub": _whitespace_sub,
        "quote_doubling": _quote_doubling,
        "union_alt": _union_alt,
    },
    "ssrf": {
        "ip_decimal": _ip_decimal,
        "ip_octal": _ip_octal,
        "ip_hex": _ip_hex,
        "url_parser_confusion": _url_parser_confusion,
        "localhost_variant": _localhost_variant,
        "url_encode": _url_encode,
    },
    "command_injection": {
        "shell_metachar": _shell_metachar,
        "ifs_whitespace": _ifs_whitespace,
        "backtick_wrap": _backtick_wrap,
        "base64_pipe": _base64_pipe,
        "url_encode": _url_encode,
        "case_variation": _case_variation,
    },
    "xxe": {
        "parameter_entity": _parameter_entity,
        "svg_xxe": _svg_xxe,
        "utf16_xxe": _utf16_xxe,
        "url_encode": _url_encode,
    },
    "template_injection": {
        "jinja2_variant": _jinja2_variant,
        "twig_variant": _twig_variant,
        "erb_variant": _erb_variant,
        "whitespace_ssti": _whitespace_ssti,
        "unicode_escape": _unicode_escape,
    },
    "path_traversal": {
        "dot_encoding": _dot_encoding,
        "slash_variation": _slash_variation,
        "double_encode_path": _double_encode_path,
        "null_byte_path": _null_byte_path,
        "url_encode": _url_encode,
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def mutate(
    payload: str,
    vuln_type: str,
    context: "InjectionContext | None" = None,
) -> list[str]:
    """Apply all applicable mutation strategies and return unique variants.

    If ``context`` is provided, only strategies valid for that context are used.
    The original payload is never included in the output.
    """
    strategies = STRATEGIES.get(vuln_type)
    if strategies is None:
        return []

    # Filter by context if provided
    if context is not None:
        from workers.sandbox_worker.context import CONTEXT_VALID_STRATEGIES
        ctx_map = CONTEXT_VALID_STRATEGIES.get(vuln_type, {})
        valid_names = ctx_map.get(context)
        if valid_names is not None:
            strategies = {k: v for k, v in strategies.items() if k in valid_names}

    variants: list[str] = []
    seen: set[str] = {payload}

    for _name, fn in strategies.items():
        try:
            v = fn(payload)
        except Exception:
            continue
        if v and v not in seen:
            variants.append(v)
            seen.add(v)

    return variants
