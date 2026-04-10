"""DOM injection testing tool (WSTG-CLIENT-008)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class DomInjectionTester(ClientSideTool):
    """Test for DOM injection vulnerabilities (WSTG-CLIENT-008).

    Checks for DOM Clobbering, prototype pollution, client-side template
    injection, and mutation XSS vectors.
    """

    name = "dom_injection_tester"
    weight_class = WeightClass.HEAVY

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

    # Extract JS content
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

    # DOM Clobbering checks
    clobberable_patterns = [
        (r'id=["\\'](?:location|document|window|parent|top|self|history|navigator)\\b', 'DOM Clobbering: critical global variable'),
        (r'name=["\\'](?:location|document|window|parent|top|self|history|navigator)\\b', 'DOM Clobbering: critical global variable via name'),
        (r'id=["\\'](?:addEventListener|removeEventListener|dispatchEvent)\\b', 'DOM Clobbering: event method'),
        (r'name=["\\'](?:getElementById|querySelector|querySelectorAll)\\b', 'DOM Clobbering: DOM method via name'),
    ]

    for pattern, desc in clobberable_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({
                "title": f"Potential {desc}",
                "description": f"Found element with id/name that could clobber global objects at {base_url}",
                "severity": "high",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # Check for code that accesses DOM elements by ID directly
    direct_id_access = re.findall(r'window\\.(\\w+)|document\\.(\\w+)', content)
    dangerous_id_access = []
    for match in direct_id_access:
        prop = match[0] or match[1]
        if prop and not prop.startswith(('addEventListener', 'removeEventListener', 'createElement', 'querySelector')):
            if re.search(rf'<[^>]+id=["\\']{prop}["\\']', content, re.IGNORECASE):
                dangerous_id_access.append(prop)

    if dangerous_id_access:
        results.append({
            "title": "DOM element accessed by ID directly",
            "description": f"Found {len(dangerous_id_access)} DOM element(s) accessed directly by ID, vulnerable to DOM Clobbering",
            "severity": "medium",
            "data": {
                "url": base_url,
                "accessed_ids": dangerous_id_access[:10]
            }
        })

    # Prototype pollution checks
    pp_patterns = [
        (r'Object\\.prototype\\s*\\[', 'Direct prototype modification'),
        (r'__proto__\\s*=', '__proto__ assignment'),
        (r'constructor\\.prototype\\s*\\[', 'Constructor prototype modification'),
        (r'\\bmerge\\s*\\(.*\\btarget\\b.*\\bsource\\b', 'Object merge without prototype check'),
        (r'\\.extend\\s*\\(.*true', 'jQuery extend with deep merge'),
        (r'JSON\\.parse\\s*\\(', 'JSON.parse without prototype sanitization'),
        (r'cloneDeep\\s*\\(', 'Deep clone operation'),
        (r'lodash|underscore', 'Use of lodash/underscore (known PP vectors)'),
    ]

    for pattern, desc in pp_patterns:
        if re.search(pattern, all_js, re.IGNORECASE):
            results.append({
                "title": f"Prototype pollution vector: {desc}",
                "description": f"Found {desc} pattern in client-side code at {base_url}",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # Client-side template injection
    template_patterns = [
        (r'\\{\\{.*\\}\\}', 'Template syntax'),
        (r'<%.*%>', 'ERB-style template syntax'),
        (r'v-html\\s*=', 'Vue v-html directive'),
        (r'ng-bind-html', 'Angular ng-bind-html'),
        (r'\\$sce\\.trustAsHtml', 'Angular $sce.trustAsHtml'),
        (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML'),
        (r'innerHTML\\s*=.*template', 'innerHTML with template content'),
    ]

    for pattern, desc in template_patterns:
        if re.search(pattern, all_js, re.IGNORECASE):
            results.append({
                "title": f"Client-side template injection vector: {desc}",
                "description": f"Found {desc} in client-side code at {base_url}",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # Unsafe DOM manipulation
    unsafe_dom_patterns = [
        (r'document\\.write\\s*\\(', 'document.write()'),
        (r'document\\.writeln\\s*\\(', 'document.writeln()'),
        (r'\\.insertAdjacentHTML\\s*\\(', 'insertAdjacentHTML()'),
        (r'\\.createContextualFragment\\s*\\(', 'createContextualFragment()'),
        (r'document\\.execCommand\\s*\\(', 'execCommand()'),
    ]

    for pattern, desc in unsafe_dom_patterns:
        if re.search(pattern, all_js):
            results.append({
                "title": f"Unsafe DOM manipulation: {desc}",
                "description": f"Found {desc} usage in client-side code at {base_url}",
                "severity": "info",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # Mutation XSS vectors
    mxss_patterns = [
        (r'\\.innerHTML\\s*=.*\\.innerHTML', 'innerHTML to innerHTML copy (mXSS)'),
        (r'\\.outerHTML\\s*=.*\\.outerHTML', 'outerHTML to outerHTML copy (mXSS)'),
        (r'(?:<math|<svg|<mathml|<annotation)', 'MathML/SVG elements (mXSS vectors)'),
        (r'(?:<noscript|<noembed|<noframes)', 'No-script elements (mXSS vectors)'),
        (r'(?:<textarea|<title|<style)\\s*>.*<', 'Elements with nested content (mXSS)'),
    ]

    for pattern, desc in mxss_patterns:
        if re.search(pattern, all_js, re.IGNORECASE):
            results.append({
                "title": f"Mutation XSS vector: {desc}",
                "description": f"Found {desc} pattern in client-side code at {base_url}",
                "severity": "medium",
                "data": {
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }
            })

    # CSS injection-based DOM manipulation
    css_dom_patterns = [
        (r'element\\.style\\s*=.*(?:location|URL|hash|search)', 'Style manipulation with URL data'),
        (r'\\.setAttribute\\s*\\(\\s*["\\']style["\\']', 'setAttribute style with potential injection'),
        (r'@import\\s+url\\s*\\(', 'CSS @import (potential injection)'),
    ]

    for pattern, desc in css_dom_patterns:
        if re.search(pattern, all_js, re.IGNORECASE):
            results.append({
                "title": f"CSS-based DOM manipulation: {desc}",
                "description": f"Found {desc} pattern in client-side code at {base_url}",
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
        "title": "DOM injection test error",
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
