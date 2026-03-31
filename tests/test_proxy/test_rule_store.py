# tests/test_proxy/test_rule_store.py
import pytest


def test_add_rule():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    rule_id = store.add_rule({
        "match": {"url_pattern": "*/api/login*"},
        "transform": {"type": "replace_param", "param": "username", "value": "admin"},
    })

    assert rule_id is not None
    assert store.get_rule(rule_id) is not None


def test_list_rules():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    store.add_rule({"match": {"url_pattern": "*"}, "transform": {"type": "inject_header", "header": "X-Test", "value": "1"}})
    store.add_rule({"match": {"url_pattern": "*/admin*"}, "transform": {"type": "strip_header", "header": "Cookie"}})

    rules = store.list_rules()
    assert len(rules) == 2


def test_delete_rule():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    rule_id = store.add_rule({"match": {"url_pattern": "*"}, "transform": {"type": "delay", "ms": 500}})
    assert store.delete_rule(rule_id) is True
    assert store.get_rule(rule_id) is None
    assert store.delete_rule("nonexistent") is False


def test_match_url():
    from workers.proxy.rule_store import RuleStore

    store = RuleStore()
    store.add_rule({"match": {"url_pattern": "*/api/*"}, "transform": {"type": "inject_header", "header": "X-Proxy", "value": "true"}})

    matches = store.match_url("https://target.com/api/users")
    assert len(matches) == 1

    matches = store.match_url("https://target.com/static/style.css")
    assert len(matches) == 0
