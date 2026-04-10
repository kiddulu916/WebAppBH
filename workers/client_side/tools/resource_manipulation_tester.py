"""Resource manipulation testing tool (WSTG-CLIENT-009)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ResourceManipulationTester(ClientSideTool):
    """Test for client-side resource manipulation (WSTG-CLIENT-009).

    Checks for CORS misconfigurations, missing access controls on static
    resources, path traversal, cache poisoning, and information disclosure.
    """

    name = "resource_manipulation_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re
from urllib.parse import urlparse

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

    # CORS misconfiguration checks
    acao = resp_headers.get("Access-Control-Allow-Origin", "")
    acac = resp_headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*" and acac.lower() == "true":
        results.append({{
            "title": "CORS misconfiguration: wildcard origin with credentials",
            "description": f"Access-Control-Allow-Origin is '*' and Allow-Credentials is 'true' at {base_url}. This allows any origin to make authenticated requests.",
            "severity": "critical",
            "data": {{
                "url": base_url,
                "acao": acao,
                "allow_credentials": acac
            }}
        }})
    elif acao and acao != "*" and acac.lower() == "true":
        # Check if the origin is reflected
        test_headers = dict(headers)
        test_headers["Origin"] = "https://evil.example.com"
        try:
            test_resp = client.get(base_url, headers=test_headers)
            test_acao = test_resp.headers.get("Access-Control-Allow-Origin", "")
            if test_acao == "https://evil.example.com":
                results.append({{
                    "title": "CORS misconfiguration: arbitrary origin reflection",
                    "description": f"Server reflects arbitrary Origin header in Access-Control-Allow-Origin at {base_url}, allowing any origin with credentials",
                    "severity": "high",
                    "data": {{
                        "url": base_url,
                        "acao": test_acao,
                        "allow_credentials": acac,
                        "test_origin": "https://evil.example.com"
                    }}
                }})
        except Exception:
            pass

    # Check for missing access controls on static resources
    static_patterns = [
        r'<link[^>]+href=["\\']([^"\\'>]+\\.css)["\\']',
        r'<script[^>]+src=["\\']([^"\\'>]+\\.js)["\\']',
        r'<img[^>]+src=["\\']([^"\\'>]+)["\\']',
    ]

    static_resources = []
    for pattern in static_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if match.startswith('/'):
                match = base_url.rstrip('/') + match
            elif not match.startswith(('http://', 'https://', 'data:', '//')):
                match = base_url.rstrip('/') + '/' + match
            static_resources.append(match)

    # Check if static resources are accessible without authentication
    accessible_without_auth = []
    for url in static_resources[:10]:
        try:
            no_auth_resp = client.get(url)
            if no_auth_resp.status_code == 200:
                content_type = no_auth_resp.headers.get("content-type", "")
                if "javascript" in content_type or "json" in content_type:
                    accessible_without_auth.append(url)
        except Exception:
            pass

    if accessible_without_auth:
        results.append({{
            "title": "Static resources accessible without authentication",
            "description": f"Found {{len(accessible_without_auth)}} static resource(s) accessible without authentication. These may contain sensitive logic or data.",
            "severity": "low",
            "data": {{
                "url": base_url,
                "accessible_resources": accessible_without_auth[:10]
            }}
        }})

    # Path traversal in resource loading
    traversal_patterns = [
        r'\\./\\.\\./',
        r'\\.\\.\\.\\./',
        r'\\%2e\\%2e\\%2f',
        r'\\%2e\\%2e/',
        r'\\.\\.\\%2f',
    ]

    for pattern in traversal_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": "Potential path traversal in resource loading",
                "description": f"Found path traversal pattern '{{pattern}}' in client-side code at {base_url}",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "pattern": pattern
                }}
            }})
            break

    # Information disclosure in error responses
    error_patterns = [
        (r'stack\\s*trace', 'Stack trace'),
        (r'internal\\s*server\\s*error', 'Internal server error'),
        (r'undefined\\s*(?:method|variable|property)', 'Undefined reference'),
        (r'syntax\\s*error', 'Syntax error'),
        (r'at\\s+\\w+\\s*\\(.*:\\d+:\\d+\\)', 'Stack frame reference'),
        (r'File\\s+"[^"]+",\\s+line\\s+\\d+', 'File path disclosure'),
        (r'(?:/etc/|/var/|/tmp/|C:\\\\)', 'File path disclosure'),
        (r'(?:SQL|database)\\s*(?:syntax|error|exception)', 'Database error'),
    ]

    for pattern, desc in error_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": f"Information disclosure: {{desc}}",
                "description": f"Found {{desc}} pattern in response from {base_url}",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }}
            }})

    # Cache poisoning vectors
    cache_headers = {{
        "cache_control": resp_headers.get("Cache-Control", ""),
        "pragma": resp_headers.get("Pragma", ""),
        "expires": resp_headers.get("Expires", ""),
        "vary": resp_headers.get("Vary", ""),
    }}

    # Check for missing cache controls on sensitive pages
    if not cache_headers["cache_control"] and not cache_headers["pragma"]:
        results.append({{
            "title": "Missing cache control headers",
            "description": f"No Cache-Control or Pragma headers found at {base_url}. Sensitive responses may be cached.",
            "severity": "low",
            "data": {{
                "url": base_url,
                "cache_control": "missing",
                "pragma": "missing"
            }}
        }})

    # Check for cache poisoning via unkeyed headers
    if "Vary" not in resp_headers:
        param_patterns = [
            r'[?&](?:redirect|url|next|return|continue|callback)',
            r'[?&](?:lang|locale|currency)',
        ]
        for pattern in param_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results.append({{
                    "title": "Potential cache poisoning vector",
                    "description": f"Response at {base_url} lacks Vary header and contains URL parameters that could affect content. Response may be cacheable with user-specific content.",
                    "severity": "medium",
                    "data": {{
                        "url": base_url,
                        "vary_header": "missing",
                        "pattern": pattern
                    }}
                }})
                break

    # Resource exhaustion vectors
    exhaustion_patterns = [
        (r'setInterval\\s*\\(\\s*function', 'setInterval without cleanup'),
        (r'setTimeout\\s*\\(.*setInterval', 'setTimeout creating intervals'),
        (r'while\\s*\\(\\s*true\\s*\\)', 'Infinite loop'),
        (r'for\\s*\\(\\s*;\\s*;\\s*\\)', 'Infinite for loop'),
        (r'new\\s+Array\\s*\\(\\s*\\d{{7,}}', 'Large array allocation'),
    ]

    for pattern, desc in exhaustion_patterns:
        if re.search(pattern, content):
            results.append({{
                "title": f"Resource exhaustion vector: {{desc}}",
                "description": f"Found {{desc}} pattern in client-side code at {base_url}",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }}
            }})

    # Check for external resource loading from untrusted origins
    external_resources = re.findall(r'(?:src|href)=["\\'](https?://[^"\\'>]+)["\\']', content)
    trusted_domains = [urlparse(base_url).netloc]
    untrusted = [r for r in external_resources if urlparse(r).netloc and urlparse(r).netloc not in trusted_domains and not urlparse(r).netloc.endswith('.googleapis.com') and not urlparse(r).netloc.endswith('.cloudflare.com') and not urlparse(r).netloc.endswith('.jsdelivr.net') and not urlparse(r).netloc.endswith('.unpkg.com') and not urlparse(r).netloc.endswith('.cdn.jsdelivr.net')]

    if untrusted:
        results.append({{
            "title": "External resources from untrusted origins",
            "description": f"Found {{len(untrusted)}} resource(s) loaded from external origins not in trusted CDN list",
            "severity": "low",
            "data": {{
                "url": base_url,
                "untrusted_resources": untrusted[:10]
            }}
        }})

    client.close()

except Exception as e:
    results.append({{
        "title": "Resource manipulation test error",
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
