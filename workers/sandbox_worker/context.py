"""Injection context enum for context-aware mutation dispatch."""

from __future__ import annotations

from enum import Enum


class InjectionContext(Enum):
    HTML_TAG = "html_tag"
    HTML_ATTR = "html_attr"
    HTML_ATTR_EVENT = "html_attr_event"
    JS_STRING = "js_string"
    JS_CODE = "js_code"
    URL_PARAM = "url_param"
    URL_PATH = "url_path"
    SQL_STRING = "sql_string"
    SQL_NUMBER = "sql_number"
    HEADER_VALUE = "header_value"
    JSON_STRING = "json_string"


# Which mutation strategy names are valid per context.
# If a vuln_type + context combo is not listed, all strategies apply.
CONTEXT_VALID_STRATEGIES: dict[str, dict[InjectionContext, set[str]]] = {
    "xss": {
        InjectionContext.HTML_TAG: {
            "url_encode", "double_url_encode", "html_entity", "unicode_escape",
            "case_variation", "null_byte_inject", "comment_insert", "tag_nesting",
            "event_handler_swap", "svg_wrapper", "math_wrapper",
        },
        InjectionContext.HTML_ATTR: {
            "url_encode", "double_url_encode", "html_entity", "unicode_escape",
            "case_variation", "event_handler_swap",
        },
        InjectionContext.JS_STRING: {
            "unicode_escape", "case_variation", "null_byte_inject",
            "comment_insert",
        },
        InjectionContext.JS_CODE: {
            "unicode_escape", "case_variation", "comment_insert",
        },
        InjectionContext.URL_PARAM: {
            "url_encode", "double_url_encode", "unicode_escape",
            "case_variation", "null_byte_inject",
        },
    },
    "sqli": {
        InjectionContext.SQL_STRING: {
            "comment_insert", "case_variation", "char_concat",
            "hex_encoding", "whitespace_sub", "quote_doubling",
        },
        InjectionContext.SQL_NUMBER: {
            "comment_insert", "case_variation", "hex_encoding",
            "whitespace_sub",
        },
        InjectionContext.URL_PARAM: {
            "url_encode", "double_url_encode", "comment_insert",
            "case_variation", "whitespace_sub",
        },
    },
}
