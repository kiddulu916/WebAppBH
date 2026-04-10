"""CSP bypass testing tool (WSTG-CLIENT-004)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class CspBypassTester(ClientSideTool):
    """Test for Content-Security-Policy bypass vectors (WSTG-CLIENT-004).

    Analyzes CSP headers for unsafe-inline, unsafe-eval, wildcard sources,
    missing directives, and potential bypass endpoints.
    """

    name = "csp_bypass_tester"
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
    resp_headers = resp.headers
    content = resp.text

    csp = resp_headers.get("Content-Security-Policy", "")
    csp_report_only = resp_headers.get("Content-Security-Policy-Report-Only", "")

    if not csp and not csp_report_only:
        results.append({{
            "title": "Missing Content-Security-Policy",
            "description": f"No Content-Security-Policy header found in response from {base_url}",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "csp_present": False,
                "csp_report_only": False
            }}
        }})
    else:
        csp_full = csp if csp else csp_report_only
        csp_is_report_only = not csp and bool(csp_report_only)

        if csp_is_report_only:
            results.append({{
                "title": "CSP in report-only mode",
                "description": f"Content-Security-Policy is in Report-Only mode at {base_url}, violations are not blocked",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "csp_report_only": True
                }}
            }})

        # Parse directives
        directives = {{}}
        for part in csp_full.split(";"):
            part = part.strip()
            if ":" in part:
                key, _, value = part.partition(":")
                directives[key.strip().lower()] = value.strip()

        # Check script-src for unsafe-inline
        script_src = directives.get("script-src", "")
        if "unsafe-inline" in script_src:
            results.append({{
                "title": "CSP script-src allows unsafe-inline",
                "description": f"Content-Security-Policy script-src directive contains 'unsafe-inline', allowing inline script execution",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "directive": "script-src",
                    "value": script_src
                }}
            }})

        # Check script-src for unsafe-eval
        if "unsafe-eval" in script_src:
            results.append({{
                "title": "CSP script-src allows unsafe-eval",
                "description": f"Content-Security-Policy script-src directive contains 'unsafe-eval', allowing eval() and similar",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "directive": "script-src",
                    "value": script_src
                }}
            }})

        # Check for wildcard sources
        for directive_name, directive_value in directives.items():
            if "*" in directive_value.split():
                results.append({{
                    "title": f"CSP {{directive_name}} allows wildcard source",
                    "description": f"Content-Security-Policy {{directive_name}} directive contains wildcard '*', allowing any origin",
                    "severity": "high",
                    "data": {{
                        "url": base_url,
                        "directive": directive_name,
                        "value": directive_value
                    }}
                }})
            if "data:" in directive_value:
                if directive_name in ("script-src", "style-src", "img-src"):
                    results.append({{
                        "title": f"CSP {{directive_name}} allows data: URIs",
                        "description": f"Content-Security-Policy {{directive_name}} directive allows data: URIs which can be used for XSS",
                        "severity": "medium",
                        "data": {{
                            "url": base_url,
                            "directive": directive_name,
                            "value": directive_value
                        }}
                    }})

        # Check for missing important directives
        important_directives = ["default-src", "script-src", "object-src", "base-uri"]
        for directive in important_directives:
            if directive not in directives:
                results.append({{
                    "title": f"Missing CSP directive: {{directive}}",
                    "description": f"Content-Security-Policy missing '{{directive}}' directive at {base_url}",
                    "severity": "low",
                    "data": {{
                        "url": base_url,
                        "missing_directive": directive
                    }}
                }})

        # Check for JSONP endpoints that could bypass CSP
        jsonp_patterns = [
            r'/jsonp\\b',
            r'/api.*\\?callback=',
            r'/api.*\\?jsonp=',
            r'/api.*\\?cb=',
            r'callback\\s*=',
            r'\\bjsonp\\b',
        ]
        for pattern in jsonp_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results.append({{
                    "title": "Potential JSONP endpoint (CSP bypass vector)",
                    "description": f"Found potential JSONP endpoint pattern matching '{{pattern}}' which could be used to bypass CSP",
                    "severity": "medium",
                    "data": {{
                        "url": base_url,
                        "pattern": pattern
                    }}
                }})
                break

        # Check for upload endpoints that could serve malicious JS
        upload_patterns = [
            r'/upload\\b',
            r'/api/files',
            r'/api/media',
            r'/api/attachments',
            r'action=["\\'][^"\\'>]*upload[^"\\'>]*["\\']',
        ]
        for pattern in upload_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results.append({{
                    "title": "File upload endpoint found (potential CSP bypass)",
                    "description": f"Found file upload endpoint pattern '{{pattern}}' - if uploaded files are served without proper CSP, they could bypass restrictions",
                    "severity": "low",
                    "data": {{
                        "url": base_url,
                        "pattern": pattern
                    }}
                }})
                break

    client.close()

except Exception as e:
    results.append({{
        "title": "CSP bypass test error",
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
