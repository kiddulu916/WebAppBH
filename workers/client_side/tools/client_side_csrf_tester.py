"""Client-side CSRF testing tool (WSTG-CLIENT-003)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClientSideCsrfTester(ClientSideTool):
    """Test for client-side CSRF vulnerabilities (WSTG-CLIENT-003).

    Analyzes forms for CSRF tokens, checks cookie attributes (SameSite),
    and verifies CSRF token implementation quality.
    """

    name = "client_side_csrf_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"

headers = {{}}
if credentials and credentials.get("token"):
    headers["Authorization"] = f"Bearer {{credentials.get('token')}}"

try:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False)

    resp = client.get(base_url, headers=headers)
    content = resp.text
    resp_headers = resp.headers

    # Check for forms and CSRF tokens
    forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
    forms_with_method = re.findall(r'<form[^>]*method=["\\']?(post|put|patch|delete)["\\']?[^>]*>', content, re.IGNORECASE)

    csrf_token_patterns = [
        r'name=["\\']?_token["\\']?',
        r'name=["\\']?csrf_token["\\']?',
        r'name=["\\']?csrf["\\']?',
        r'name=["\\']?authenticity_token["\\']?',
        r'name=["\\']?_csrf["\\']?',
        r'name=["\\']?xsrf["\\']?',
        r'name=["\\']?XSRF-TOKEN["\\']?',
        r'X-CSRF-Token',
        r'X-XSRF-Token',
        r'csrfmiddlewaretoken',
    ]

    csrf_tokens_found = []
    for pattern in csrf_token_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        csrf_tokens_found.extend(matches)

    # Extract actual token values
    token_values = re.findall(r'(?:name=["\\']?(?:_token|csrf_token|csrf|authenticity_token|_csrf|xsrf|XSRF-TOKEN|csrfmiddlewaretoken)["\\']?\\s+value=["\\']?([^"\\'>\\s]+))', content, re.IGNORECASE)

    # Check for forms without CSRF tokens
    state_changing_forms = []
    for i, form in enumerate(forms):
        method_match = re.search(r'method=["\\']?(post|put|patch|delete)["\\']?', form, re.IGNORECASE)
        if method_match:
            has_token = any(re.search(p, form, re.IGNORECASE) for p in csrf_token_patterns)
            if not has_token:
                action_match = re.search(r'action=["\\']?([^"\\'>\\s]*)["\\']?', form)
                action = action_match.group(1) if action_match else "self"
                state_changing_forms.append({{
                    "form_index": i,
                    "method": method_match.group(1),
                    "action": action,
                    "has_csrf_token": False
                }})

    if state_changing_forms:
        results.append({{
            "title": "Forms missing CSRF tokens",
            "description": f"Found {{len(state_changing_forms)}} form(s) with state-changing methods but no CSRF token protection",
            "severity": "high",
            "data": {{
                "url": base_url,
                "vulnerable_forms": state_changing_forms,
                "total_forms": len(forms)
            }}
        }})

    # Check for CSRF token predictability
    if len(token_values) >= 2:
        if len(set(token_values)) == 1:
            results.append({{
                "title": "Potentially static CSRF token",
                "description": "Multiple CSRF token instances found with identical values, suggesting static/predictable tokens",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "token_count": len(token_values),
                    "unique_values": len(set(token_values)),
                    "sample_token": token_values[0][:20] + "..." if len(token_values[0]) > 20 else token_values[0]
                }}
            }})
        elif all(len(t) < 16 for t in token_values):
            results.append({{
                "title": "Short CSRF tokens",
                "description": f"CSRF tokens found are shorter than 16 characters ({{min(len(t) for t in token_values)}} chars min), potentially vulnerable to brute force",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "min_token_length": min(len(t) for t in token_values),
                    "max_token_length": max(len(t) for t in token_values)
                }}
            }})

    # Check SameSite cookie attribute
    set_cookie_headers = resp_headers.get_list("set-cookie")
    cookies_without_samesite = []
    for cookie in set_cookie_headers:
        if "samesite" not in cookie.lower():
            cookie_name = cookie.split("=")[0].split(";")[0].strip()
            cookies_without_samesite.append(cookie_name)

    if cookies_without_samesite:
        results.append({{
            "title": "Cookies missing SameSite attribute",
            "description": f"Found {{len(cookies_without_samesite)}} cookie(s) without SameSite attribute, increasing CSRF risk",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "cookies_without_samesite": cookies_without_samesite[:10]
            }}
        }})

    # Check for SameSite=None without Secure
    for cookie in set_cookie_headers:
        if "samesite=none" in cookie.lower() and "secure" not in cookie.lower():
            cookie_name = cookie.split("=")[0].split(";")[0].strip()
            results.append({{
                "title": "SameSite=None without Secure flag",
                "description": f"Cookie '{{cookie_name}}' has SameSite=None but missing Secure flag, vulnerable to CSRF",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "cookie_name": cookie_name
                }}
            }})

    # Check for state-changing endpoints via GET
    get_links = re.findall(r'<a[^>]+href=["\\']([^"\\'>]+)["\\']', content, re.IGNORECASE)
    suspicious_get = [link for link in get_links if any(action in link.lower() for action in ['delete', 'remove', 'update', 'change', 'edit', 'logout', 'transfer'])]
    if suspicious_get:
        results.append({{
            "title": "State-changing operations via GET",
            "description": f"Found {{len(suspicious_get)}} link(s) that appear to perform state-changing operations via GET requests",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "suspicious_links": suspicious_get[:10]
            }}
        }})

    client.close()

except Exception as e:
    results.append({{
        "title": "CSRF test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}}
    }})

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout: str) -> list:
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
