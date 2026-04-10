"""mitmproxy addon that applies RuleStore transforms to intercepted traffic."""

from mitmproxy import http

from workers.proxy.rule_store import RuleStore


class RuleAddon:
    """Intercept requests/responses and apply matching rules from the store."""

    def __init__(self, store: RuleStore):
        self.store = store

    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        rules = self.store.match_url(url)

        for rule in rules:
            action = rule.get("action", {})
            action_type = action.get("type")

            if action_type == "replace_param":
                self._replace_param(flow, action)
            elif action_type == "strip_header":
                self._strip_header(flow.request.headers, action)
            elif action_type == "inject_header":
                self._inject_header(flow.request.headers, action)
            elif action_type == "replace_body":
                self._replace_body(flow, action)
            elif action_type == "strip_cookie":
                self._strip_cookie(flow, action)

    def response(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        rules = self.store.match_url(url)

        for rule in rules:
            action = rule.get("action", {})
            action_type = action.get("type")

            if action_type == "inject_response_header":
                self._inject_header(flow.response.headers, action)
            elif action_type == "strip_response_header":
                self._strip_header(flow.response.headers, action)

    # -- Transform helpers --

    @staticmethod
    def _replace_param(flow: http.HTTPFlow, action: dict) -> None:
        name = action.get("name", "")
        value = action.get("value", "")
        if flow.request.method in ("GET", "HEAD", "OPTIONS"):
            flow.request.query[name] = value
        else:
            if flow.request.urlencoded_form:
                flow.request.urlencoded_form[name] = value

    @staticmethod
    def _strip_header(headers, action: dict) -> None:
        name = action.get("name", "")
        if name in headers:
            del headers[name]

    @staticmethod
    def _inject_header(headers, action: dict) -> None:
        name = action.get("name", "")
        value = action.get("value", "")
        headers[name] = value

    @staticmethod
    def _replace_body(flow: http.HTTPFlow, action: dict) -> None:
        content = action.get("content", "")
        flow.request.text = content

    @staticmethod
    def _strip_cookie(flow: http.HTTPFlow, action: dict) -> None:
        name = action.get("name", "")
        cookies = flow.request.cookies
        if name in cookies:
            del cookies[name]
