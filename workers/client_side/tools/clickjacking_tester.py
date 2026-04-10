"""Clickjacking tester (WSTG-CLIENT-02)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClickjackingTester(ClientSideTool):
    """Tests for clickjacking vulnerabilities via missing X-Frame-Options
    and Content-Security-Policy frame-ancestors directives (WSTG-CLIENT-002).
    """

    name = "clickjacking_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"
        token = credentials.get("token") if credentials else None

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"
token = {repr(token)}

headers = {{}}
if token:
    headers["Authorization"] = f"Bearer {{token}}"

try:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False, headers=headers)
    resp = client.get(base_url)

    xfo = resp.headers.get("X-Frame-Options", "")
    csp = resp.headers.get("Content-Security-Policy", "")
    csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")

    xfo_missing = not xfo.strip()
    csp_frame_ancestors_missing = True
    csp_frame_ancestors_value = None

    for policy in [csp, csp_ro]:
        if policy:
            fa_match = re.search(r'frame-ancestors\\s+([^;]+)', policy, re.IGNORECASE)
            if fa_match:
                csp_frame_ancestors_missing = False
                csp_frame_ancestors_value = fa_match.group(1).strip()
                break

    if xfo_missing and csp_frame_ancestors_missing:
        results.append({{
            "title": "Missing clickjacking protection",
            "description": f"Neither X-Frame-Options nor Content-Security-Policy frame-ancestors directive found in response from {{base_url}}",
            "severity": "high",
            "data": {{
                "url": base_url,
                "x_frame_options": "missing",
                "csp_frame_ancestors": "missing",
                "status_code": resp.status_code
            }}
        }})
    elif xfo_missing:
        results.append({{
            "title": "Missing X-Frame-Options header",
            "description": f"X-Frame-Options header not set in response from {{base_url}}. CSP frame-ancestors is present but X-Frame-Options provides defense-in-depth.",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "x_frame_options": "missing",
                "csp_frame_ancestors": csp_frame_ancestors_value
            }}
        }})
    elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
        results.append({{
            "title": "Weak X-Frame-Options configuration",
            "description": f"X-Frame-Options header has unexpected value: {{xfo}} in response from {{base_url}}",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "x_frame_options": xfo,
                "expected": "DENY or SAMEORIGIN"
            }}
        }})

    if not csp_frame_ancestors_missing and csp_frame_ancestors_value:
        if "*" in csp_frame_ancestors_value:
            results.append({{
                "title": "Overly permissive CSP frame-ancestors",
                "description": f"CSP frame-ancestors allows framing from any origin (*) in {{base_url}}",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "csp_frame_ancestors": csp_frame_ancestors_value
                }}
            }})

    frame_bust_patterns = [
        r'if\\s*\\(\\s*self\\s*!==\\s*top\\s*\\)',
        r'if\\s*\\(\\s*window\\s*!==\\s*window\\.top\\s*\\)',
        r'top\\.location\\s*=',
        r'self\\.location\\s*=',
        r'break.*frame',
    ]
    has_frame_busting = any(re.search(p, resp.text, re.IGNORECASE) for p in frame_bust_patterns)

    if not has_frame_busting and (xfo_missing or csp_frame_ancestors_missing):
        results.append({{
            "title": "No frame-busting JavaScript detected",
            "description": f"No frame-busting JavaScript code found in {{base_url}}. Combined with missing headers, page is vulnerable to clickjacking.",
            "severity": "info",
            "data": {{
                "url": base_url,
                "frame_busting_js": False
            }}
        }})

    if re.search(r'<form[^>]*>', resp.text, re.IGNORECASE):
        if xfo_missing and csp_frame_ancestors_missing:
            results.append({{
                "title": "Clickjacking risk with forms present",
                "description": f"Page contains forms but lacks framing protection at {{base_url}}. Attackers could trick users into submitting forms.",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "has_forms": True,
                    "x_frame_options": "missing",
                    "csp_frame_ancestors": "missing"
                }}
            }})

    client.close()
except Exception as e:
    results.append({{
        "title": "Clickjacking test error",
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
