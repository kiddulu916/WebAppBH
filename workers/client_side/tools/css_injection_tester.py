"""CSS injection testing tool (WSTG-CLIENT-012)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class CssInjectionTester(ClientSideTool):
    """Test for CSS injection vulnerabilities (WSTG-CLIENT-012).

    Checks for CSS-based keylogging, attribute exfiltration, CSS injection
    via user-controlled styles, and CSS-based clickjacking.
    """

    name = "css_injection_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = '''
import httpx
import json
import re
import sys

results = []
base_url = "''' + base_url + '''"

headers = {}
if credentials and credentials.get("token"):
    headers["Authorization"] = f"Bearer {credentials.get('token')}"

try:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False)

    resp = client.get(base_url, headers=headers)
    content = resp.text

    # Check for CSS-based keylogging via attribute selectors
    keylog_patterns = [
        (r'\\[value\\^=', 'Attribute prefix selector (value^=)'),
        (r'\\[value\\*=', 'Attribute substring selector (value*=)'),
        (r'\\[value\\$=', 'Attribute suffix selector (value$=)'),
        (r'\\[content\\^=', 'Content attribute selector'),
        (r'\\[data-\\w+\\^=', 'Data attribute prefix selector'),
    ]

    for pattern, desc in keylog_patterns:
        if re.search(pattern, content):
            results.append({
                "title": f"CSS attribute selector found ({desc})",
                "description": f"Found CSS attribute selector pattern at {base_url} that could be used for data exfiltration",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "pattern": desc,
                    "regex": pattern
                }
            })

    # Check for CSS injection via user-controlled styles
    style_injection_patterns = [
        (r'style\\s*=\\s*["\\'][^"\\'>]*["\\'][^>]*>', 'Inline style attribute'),
        (r'style\\s*=\\s*["\\'][^"\\'>]*url\\s*\\(', 'Inline style with url()'),
        (r'style\\s*=\\s*["\\'][^"\\'>]*@import', 'Inline style with @import'),
        (r'style\\s*=\\s*["\\'][^"\\'>]*expression\\s*\\(', 'Inline style with expression()'),
        (r'style\\s*=\\s*["\\'][^"\\'>]*behavior\\s*:', 'Inline style with behavior'),
        (r'<style[^>]*>.*</style>', 'Inline style block'),
    ]

    for pattern, desc in style_injection_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            results.append({
                "title": f"CSS injection vector: {desc}",
                "description": f"Found {desc} at {base_url} which could be exploited for CSS injection",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # Check for CSS exfiltration of sensitive data
    exfil_patterns = [
        (r'background-image\\s*:\\s*url\\s*\\(.*(?:http|https)', 'Background image URL exfiltration'),
        (r'list-style-image\\s*:\\s*url\\s*\\(', 'List-style-image exfiltration'),
        (r'cursor\\s*:\\s*url\\s*\\(', 'Cursor URL exfiltration'),
        (r'@import\\s+url\\s*\\(\\s*["\\']?https?://', 'External @import'),
        (r'font-face.*url\\s*\\(\\s*["\\']?https?://', 'External font-face URL'),
    ]

    for pattern, desc in exfil_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({
                "title": f"CSS data exfiltration vector: {desc}",
                "description": f"Found {desc} at {base_url} which could be used to exfiltrate sensitive data",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # Check for CSS-based clickjacking
    css_clickjack_patterns = [
        (r'opacity\\s*:\\s*0', 'Zero opacity element'),
        (r'visibility\\s*:\\s*hidden', 'Hidden visibility element'),
        (r'z-index\\s*:\\s*\\d{4,}', 'Very high z-index'),
        (r'position\\s*:\\s*(?:absolute|fixed).*(?:top|left)\\s*:\\s*0', 'Positioned overlay element'),
        (r'pointer-events\\s*:\\s*none', 'Pointer events manipulation'),
    ]

    for pattern, desc in css_clickjack_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({
                "title": f"CSS-based clickjacking vector: {desc}",
                "description": f"Found {desc} at {base_url} which could be used for CSS-based clickjacking",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # Check for CSS injection in user-generated content
    ugc_css_patterns = [
        r'<[^>]+style\\s*=\\s*["\\'][^"\\'>]*["\\'][^>]*>',
        r'\\{\\{.*style.*\\}\\}',
        r'v-bind:style',
        r'\\[ngStyle\\]',
        r'dangerouslySetInnerHTML.*style',
    ]

    for pattern in ugc_css_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({
                "title": "CSS injection in user-generated content",
                "description": f"Found pattern at {base_url} that could allow CSS injection via user-generated content",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "pattern": pattern
                }
            })
            break

    # Check for @import-based CSS injection
    import_patterns = [
        r'@import\\s+url\\s*\\(\\s*["\\']?https?://[^)]+["\\']?\\s*\\)',
        r'@import\\s+["\\']https?://',
        r'<link[^>]+rel\\s*=\\s*["\\']stylesheet["\\'][^>]+href\\s*=\\s*["\\']https?://',
    ]

    external_css = []
    for pattern in import_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        external_css.extend(matches)

    if external_css:
        results.append({
            "title": "External CSS resources loaded",
            "description": f"Found {len(external_css)} external CSS resource(s) at {base_url}. If these are user-controllable, they could be used for CSS injection.",
            "severity": "low",
            "data": {
                "url": base_url,
                "external_css_count": len(external_css),
                "resources": external_css[:5]
            }
        })

    # Check for CSS-based UI redressing
    redress_patterns = [
        (r'::before|::after', 'Pseudo-element injection'),
        (r'content\\s*:\\s*["\\'][^"\\'>]*["\\']', 'CSS content property'),
        (r'transform\\s*:', 'CSS transform (potential UI manipulation)'),
        (r'transition\\s*:', 'CSS transition (potential UI manipulation)'),
    ]

    for pattern, desc in redress_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({
                "title": f"CSS UI redressing vector: {desc}",
                "description": f"Found {desc} at {base_url} which could be used for UI redressing",
                "severity": "low",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    client.close()

except Exception as e:
    results.append({
        "title": "CSS injection test error",
        "description": str(e),
        "severity": "info",
        "data": {"error": str(e)}
    })

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout: str) -> list:
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
