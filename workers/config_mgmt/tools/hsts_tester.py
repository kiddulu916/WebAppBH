"""HSTS configuration tester."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class HstsTester(ConfigMgmtTool):
    """Test HSTS configuration (WSTG-CONFIG-007)."""

    name = "hsts_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(follow_redirects=False, timeout=10, verify=False)

    try:
        resp = client.get(base_url)
        hsts_header = resp.headers.get("strict-transport-security", "")

        if not hsts_header:
            results.append({{
                "vulnerability": {{
                    "name": "Missing HSTS header",
                    "severity": "medium",
                    "description": "The Strict-Transport-Security header is not set, leaving the site vulnerable to protocol downgrade attacks",
                    "location": base_url
                }}
            }})
        else:
            max_age_match = re.search(r"max-age=(\d+)", hsts_header)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    results.append({{
                        "vulnerability": {{
                            "name": "HSTS max-age too low",
                            "severity": "low",
                            "description": f"HSTS max-age is {{max_age}} seconds (recommended: >= 31536000)",
                            "location": base_url
                        }}
                    }})
                else:
                    results.append({{
                        "observation": {{
                            "type": "hsts_config",
                            "value": "max_age_ok",
                            "details": {{"max_age": max_age, "header": hsts_header}}
                        }}
                    }})

            if "includesubdomains" not in hsts_header.lower():
                results.append({{
                    "vulnerability": {{
                        "name": "HSTS missing includeSubDomains",
                        "severity": "low",
                        "description": "HSTS header does not include the includeSubDomains directive",
                        "location": base_url
                    }}
                }})
            else:
                results.append({{
                    "observation": {{
                        "type": "hsts_config",
                        "value": "include_subdomains",
                        "details": {{"header": hsts_header}}
                    }}
                }})

            if "preload" not in hsts_header.lower():
                results.append({{
                    "observation": {{
                        "type": "hsts_config",
                        "value": "no_preload",
                        "details": {{
                            "header": hsts_header,
                            "note": "preload directive not set - site cannot be added to HSTS preload list"
                        }}
                    }}
                }})
            else:
                results.append({{
                    "observation": {{
                        "type": "hsts_config",
                        "value": "preload_enabled",
                        "details": {{"header": hsts_header}}
                    }}
                }})

    except Exception as e:
        results.append({{
            "observation": {{
                "type": "test_error",
                "value": str(e),
                "details": {{"error": str(e)}}
            }}
        }})

    try:
        http_url = base_url.replace("https://", "http://")
        resp_http = client.get(http_url)
        if resp_http.status_code in (200, 301, 302):
            hsts_http = resp_http.headers.get("strict-transport-security", "")
            if not hsts_http:
                results.append({{
                    "observation": {{
                        "type": "hsts_config",
                        "value": "http_no_hsts",
                        "details": {{
                            "note": "HTTP version does not return HSTS header (expected)"
                        }}
                    }}
                }})
    except Exception:
        pass

    client.close()

except Exception as e:
    results.append({{
        "observation": {{
            "type": "test_error",
            "value": str(e),
            "details": {{"error": str(e)}}
        }}
    }})

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
