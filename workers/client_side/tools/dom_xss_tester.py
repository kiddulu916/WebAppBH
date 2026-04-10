"""DOM-based XSS tester (WSTG-CLIENT-01)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class DomXssTester(ClientSideTool):
    """Tests for DOM-based cross-site scripting vulnerabilities (WSTG-CLIENT-001)."""

    name = "dom_xss_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"
        token = credentials.get("token") if credentials else None

        script = f'''
import httpx
import json
import re
import sys

results = []
base_url = "{base_url}"
token = {repr(token)}

sinks = [
    (r'document\\.write\\s*\\(', 'document.write() sink'),
    (r'document\\.writeln\\s*\\(', 'document.writeln() sink'),
    (r'\\.innerHTML\\s*=', 'innerHTML assignment sink'),
    (r'\\.outerHTML\\s*=', 'outerHTML assignment sink'),
    (r'\\.insertAdjacentHTML\\s*\\(', 'insertAdjacentHTML() sink'),
    (r'\\beval\\s*\\(', 'eval() sink'),
    (r'setTimeout\\s*\\(\\s*[\\'\\"]', 'setTimeout string sink'),
    (r'setInterval\\s*\\(\\s*[\\'\\"]', 'setInterval string sink'),
    (r'Function\\s*\\(', 'Function() constructor sink'),
    (r'\\.html\\s*\\(', 'jQuery .html() sink'),
    (r'\\.append\\s*\\(', 'jQuery .append() sink'),
    (r'\\.before\\s*\\(', 'jQuery .before() sink'),
    (r'\\.after\\s*\\(', 'jQuery .after() sink'),
    (r'\\.replaceWith\\s*\\(', 'jQuery .replaceWith() sink'),
    (r'document\\.domain\\s*=', 'document.domain sink'),
]

sources = [
    (r'location\\.hash', 'location.hash source'),
    (r'location\\.search', 'location.search source'),
    (r'location\\.pathname', 'location.pathname source'),
    (r'document\\.URL', 'document.URL source'),
    (r'document\\.documentURI', 'document.documentURI source'),
    (r'document\\.referrer', 'document.referrer source'),
    (r'document\\.baseURI', 'document.baseURI source'),
    (r'window\\.name', 'window.name source'),
    (r'event\\.data', 'postMessage event.data source'),
    (r'message\\.data', 'postMessage message.data source'),
]

headers = {{}}
if token:
    headers["Authorization"] = f"Bearer {{token}}"

try:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False, headers=headers)
    urls_to_check = [base_url]
    js_urls_found = set()

    try:
        resp = client.get(base_url)
        if resp.status_code == 200:
            content = resp.text
            js_urls = re.findall(r'<script[^>]+src=["\\'\\']([^"\\'>]+)["\\'\\']', content)
            for js_url in js_urls:
                if js_url.startswith('/'):
                    js_url = base_url.rstrip('/') + js_url
                elif not js_url.startswith(('http://', 'https://')):
                    js_url = base_url.rstrip('/') + '/' + js_url
                js_urls_found.add(js_url)
    except Exception:
        pass

    urls_to_check.extend(js_urls_found)

    for url in list(urls_to_check)[:25]:
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                continue
            content = resp.text

            found_sinks = []
            for pattern, name in sinks:
                if re.search(pattern, content, re.IGNORECASE):
                    found_sinks.append(name)

            found_sources = []
            for pattern, name in sources:
                if re.search(pattern, content, re.IGNORECASE):
                    found_sources.append(name)

            if found_sinks and found_sources:
                results.append({{
                    "title": "Potential DOM-based XSS",
                    "description": f"Found DOM XSS sinks ({{', '.join(found_sinks[:3])}}) and sources ({{', '.join(found_sources[:3])}}) in {{url}}",
                    "severity": "high",
                    "data": {{
                        "url": url,
                        "sinks": found_sinks,
                        "sources": found_sources,
                        "content_length": len(content)
                    }}
                }})
            elif found_sinks:
                results.append({{
                    "title": "DOM XSS sink found",
                    "description": f"Found DOM XSS sinks ({{', '.join(found_sinks[:3])}}) in {{url}}. Verify if user-controlled input reaches these sinks.",
                    "severity": "info",
                    "data": {{
                        "url": url,
                        "sinks": found_sinks,
                        "sources": []
                    }}
                }})

            postmsg_pattern = r'addEventListener\\s*\\(\\s*[\\'\\"]message[\\'\\"]'
            origin_check = r'event\\.origin|message\\.origin'
            if re.search(postmsg_pattern, content):
                if not re.search(origin_check, content):
                    results.append({{
                        "title": "postMessage handler without origin validation",
                        "description": f"Found postMessage event listener without origin check in {{url}}",
                        "severity": "medium",
                        "data": {{
                            "url": url,
                            "issue": "Missing origin validation in postMessage handler"
                        }}
                    }})

        except Exception:
            pass

    client.close()

except Exception as e:
    results.append({{
        "title": "DOM XSS test error",
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
