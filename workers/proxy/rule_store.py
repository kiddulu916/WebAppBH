import fnmatch
import uuid
from typing import Optional


class RuleStore:
    """In-memory rule storage for the traffic proxy."""

    def __init__(self):
        self._rules: dict[str, dict] = {}

    def add_rule(self, rule: dict) -> str:
        rule_id = str(uuid.uuid4())[:8]
        self._rules[rule_id] = {**rule, "id": rule_id}
        return rule_id

    def get_rule(self, rule_id: str) -> Optional[dict]:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[dict]:
        return list(self._rules.values())

    def delete_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def match_url(self, url: str) -> list[dict]:
        matches = []
        for rule in self._rules.values():
            pattern = rule.get("match", {}).get("url_pattern", "*")
            if fnmatch.fnmatch(url, pattern):
                matches.append(rule)
        return matches
