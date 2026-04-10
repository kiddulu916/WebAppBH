"""Client-side XSS testing tool (WSTG-CLIENT-011)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClientXssTester(ClientSideTool):
    """Test for client-side XSS vulnerabilities (WSTG-CLIENT-011).

    Tests for reflected XSS, stored XSS, DOM-based XSS, header-based XSS,
    and mutation XSS vectors from a client-side perspective.
    """

    name = "client_xss_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re
from urllib.parse import urlencode, urlparse, parse_qs

results = []
base_url = "{base_url}"

headers = {{}}
if credentials and credentials.get("token"):
    headers["Authorization"] = f"Bearer {{credentials.get('token')}}"

# XSS payloads for testing
xss_payloads = [
    "<script>alert(1)</script>",
    "\'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
]

# DOM XSS sinks
dom_sinks = [
    (r'document\\.write\\s*\\(', 'document.write'),
    (r'document\\.writeln\\s*\\(', 'document.writeln'),
    (r'\\.innerHTML\\s*=', 'innerHTML'),
    (r'\\.outerHTML\\s*=', 'outerHTML'),
    (r'\\.insertAdjacentHTML\\s*\\(', 'insertAdjacentHTML'),
    (r'\\beval\\s*\\(', 'eval'),
    (r'setTimeout\\s*\\(\\s*[\\'\"]', 'setTimeout'),
    (r'setInterval\\s*\\(\\s*[\\'\"]', 'setInterval'),
    (r'\\.html\\s*\\(', 'jQuery .html()'),
    (r'\\.append\\s*\\(', 'jQuery .append()'),
    (r'\\.before\\s*\\(', 'jQuery .before()'),
    (r'\\.after\\s*\\(', 'jQuery .after()'),
]

# DOM XSS sources
dom_sources = [
    (r'location\\.hash', 'location.hash'),
    (r'location\\.search', 'location.search'),
    (r'location\\.pathname', 'location.pathname'),
    (r'document\\.URL', 'document.URL'),
    (r'document\\.referrer', 'document.referrer'),
    (r'window\\.name', 'window.name'),
]

try:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False)

    # Test reflected XSS via URL parameters
    try:
        resp = client.get(base_url, headers=headers)
        if resp.status_code == 200:
            # Find URL parameters used in the page
            url_params = parse_qs(urlparse(base_url).query)

            # Extract forms to find action URLs and parameters
            forms = re.findall(r'<form[^>]*action=["\\']([^"\\'>]*)["\\']', resp.text)
            inputs = re.findall(r'<input[^>]+name=["\\']([^"\\'>]+)["\\']', resp.text)

            test_urls = [base_url]

            # Build test URLs with common parameters
            common_params = ['q', 'search', 'query', 'id', 'name', 'page', 'redirect', 'url', 'next', 'return', 'callback', 'msg', 'message', 'title', 'content', 'input', 'field', 'value']
            for param in common_params:
                for payload in xss_payloads[:3]:
                    test_url = f"{{base_url}}?{{param}}={{payload}}"
                    test_urls.append(test_url)

            # Test each URL
            tested_count = 0
            for test_url in test_urls[:30]:
                try:
                    test_resp = client.get(test_url, headers=headers)
                    if test_resp.status_code == 200:
                        for payload in xss_payloads[:3]:
                            if payload in test_resp.text:
                                # Check if payload is reflected without proper encoding
                                if '<script>' in test_resp.text or 'onerror=' in test_resp.text or 'onload=' in test_resp.text:
                                    # Check for lack of encoding
                                    if '&lt;script&gt;' not in test_resp.text and '&lt;img' not in test_resp.text:
                                        results.append({{
                                            "title": "Potential reflected XSS",
                                            "description": f"XSS payload reflected in response from {{test_url}} without proper encoding",
                                            "severity": "high",
                                            "data": {{
                                                "url": test_url,
                                                "reflected_payload": payload[:50],
                                                "response_length": len(test_resp.text)
                                            }}
                                        }})
                                        tested_count += 1
                                        break
                except Exception:
                    pass

    except Exception:
        pass

    # Test DOM-based XSS
    try:
        resp = client.get(base_url, headers=headers)
        content = resp.text

        # Extract JS files
        js_urls = re.findall(r'<script[^>]+src=["\\']([^"\\'>]+)["\\']', content)
        all_js = content
        for js_url in js_urls[:15]:
            try:
                if js_url.startswith('/'):
                    js_url = base_url.rstrip('/') + js_url
                elif not js_url.startswith(('http://', 'https://')):
                    js_url = base_url.rstrip('/') + '/' + js_url
                js_resp = client.get(js_url)
                if js_resp.status_code == 200:
                    all_js += "\\n" + js_resp.text
            except Exception:
                pass

        # Find sink+source combinations
        found_sinks = []
        found_sources = []
        for pattern, name in dom_sinks:
            if re.search(pattern, all_js):
                found_sinks.append(name)
        for pattern, name in dom_sources:
            if re.search(pattern, all_js):
                found_sources.append(name)

        if found_sinks and found_sources:
            results.append({{
                "title": "DOM-based XSS vector",
                "description": f"Found DOM XSS sinks ({{', '.join(found_sinks[:3])}}) and sources ({{', '.join(found_sources[:3])}}) at {base_url}",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "sinks": found_sinks,
                    "sources": found_sources
                }}
            }})
        elif found_sinks:
            results.append({{
                "title": "DOM XSS sink found",
                "description": f"Found DOM XSS sinks ({{', '.join(found_sinks[:3])}}) at {base_url}",
                "severity": "info",
                "data": {{
                    "url": base_url,
                    "sinks": found_sinks
                }}
            }})

    except Exception:
        pass

    # Test XSS via HTTP headers
    try:
        header_tests = [
            ("User-Agent", "<script>alert(1)</script>"),
            ("Referer", "<script>alert(1)</script>"),
            ("X-Forwarded-For", "<script>alert(1)</script>"),
        ]

        for header_name, payload in header_tests:
            test_headers = dict(headers)
            test_headers[header_name] = payload
            test_resp = client.get(base_url, headers=test_headers)
            if test_resp.status_code == 200 and payload in test_resp.text:
                results.append({{
                    "title": f"XSS via {{header_name}} header",
                    "description": f"XSS payload reflected in response when sent via {{header_name}} header at {base_url}",
                    "severity": "high",
                    "data": {{
                        "url": base_url,
                        "header": header_name,
                        "payload": payload
                    }}
                }})
    except Exception:
        pass

    # Check for stored XSS indicators
    try:
        resp = client.get(base_url, headers=headers)
        content = resp.text

        # Look for user-generated content areas
        ugc_patterns = [
            r'<div[^>]*class=["\\'][^"\\'>]*(?:comment|post|message|review|feedback|content)[^"\\'>]*["\\']',
            r'<p[^>]*class=["\\'][^"\\'>]*(?:comment|post|message|review|feedback)[^"\\'>]*["\\']',
            r'(?:comment|post|message|review|feedback)s?',
        ]

        has_ugc = any(re.search(p, content, re.IGNORECASE) for p in ugc_patterns)
        if has_ugc:
            # Check for output encoding
            encoding_checks = [
                r'escape\\s*\\(',
                r'encodeURI',
                r'encodeURIComponent',
                r'htmlspecialchars',
                r'sanitize',
                r'DOMPurify',
                r'xss\\s*filter',
                r'anti[-_]?xss',
            ]
            has_encoding = any(re.search(p, content, re.IGNORECASE) for p in encoding_checks)

            if not has_encoding:
                results.append({{
                    "title": "User-generated content without output encoding",
                    "description": f"Found user-generated content areas at {base_url} but no output encoding/sanitization detected",
                    "severity": "medium",
                    "data": {{
                        "url": base_url,
                        "has_ugc": True,
                        "has_encoding": False
                    }}
                }})

    except Exception:
        pass

    # Check for mXSS (mutation XSS) vectors
    mxss_patterns = [
        (r'\\.innerHTML\\s*=.*\\.innerHTML', 'innerHTML to innerHTML'),
        (r'(?:<math|<svg|<annotation)', 'MathML/SVG elements'),
        (r'(?:<noscript|<noembed)', 'No-script elements'),
        (r'(?:<textarea|<title|<style)\\s*>', 'Elements with special parsing'),
    ]

    for pattern, desc in mxss_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": f"Mutation XSS vector: {{desc}}",
                "description": f"Found {{desc}} pattern at {base_url} which could be exploited for mXSS",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }}
            }})

    client.close()

except Exception as e:
    results.append({{
        "title": "Client XSS test error",
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
