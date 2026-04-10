"""Client-side logic analyzer tool (WSTG-CLIENT-007)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class ClientLogicAnalyzer(ClientSideTool):
    """Analyze client-side business logic enforcement (WSTG-CLIENT-007).

    Identifies hardcoded credentials, client-side only validation,
    debug code in production, and client-side access controls.
    """

    name = "client_logic_analyzer"
    weight_class = WeightClass.HEAVY

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

    # Extract JS file URLs
    js_urls = []
    js_urls_raw = re.findall(r'<script[^>]+src=["\\']([^"\\'>]+)["\\']', content)
    for js_url in js_urls_raw:
        if js_url.startswith('/'):
            js_url = base_url.rstrip('/') + js_url
        elif not js_url.startswith(('http://', 'https://')):
            js_url = base_url.rstrip('/') + '/' + js_url
        js_urls.append(js_url)

    # Also check inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)

    all_js_content = content
    for url in js_urls[:15]:
        try:
            js_resp = client.get(url)
            if js_resp.status_code == 200:
                all_js_content += "\\n" + js_resp.text
        except Exception:
            pass

    # Check for hardcoded credentials/API keys
    credential_patterns = [
        (r'["\\']?(?:api[_-]?key|apikey|api[_-]?secret)["\\']?\\s*[:=]\\s*["\\']([a-zA-Z0-9_\\-]{{8,}})["\\']', 'Hardcoded API key'),
        (r'["\\']?(?:password|passwd|pwd)["\\']?\\s*[:=]\\s*["\\']([^"\\']{{4,}})["\\']', 'Hardcoded password'),
        (r'["\\']?(?:secret[_-]?key|secret)["\\']?\\s*[:=]\\s*["\\']([a-zA-Z0-9_\\-]{{8,}})["\\']', 'Hardcoded secret'),
        (r'["\\']?(?:access[_-]?token|auth[_-]?token)["\\']?\\s*[:=]\\s*["\\']([a-zA-Z0-9_\\-.]{{8,}})["\\']', 'Hardcoded token'),
        (r'(?:sk|pk|rk)_[a-zA-Z0-9]{{20,}}', 'Potential API key (Stripe-like)'),
        (r'AKIA[0-9A-Z]{{16}}', 'AWS Access Key ID'),
        (r'["\\']?(?:private[_-]?key)["\\']?\\s*[:=]\\s*["\\']([^"\\']{{8,}})["\\']', 'Hardcoded private key'),
    ]

    for pattern, desc in credential_patterns:
        matches = re.findall(pattern, all_js_content, re.IGNORECASE)
        if matches:
            results.append({{
                "title": f"{{desc}} found",
                "description": f"Found {{len(matches)}} instance(s) of {{desc}} in client-side code at {base_url}",
                "severity": "critical",
                "data": {{
                    "url": base_url,
                    "pattern_type": desc,
                    "match_count": len(matches),
                    "sample_matches": [m[:20] + "..." if len(m) > 20 else m for m in matches[:3]]
                }}
            }})

    # Check for client-side only validation
    validation_patterns = [
        (r'(?:if|check|validate)\\s*\\(.*(?:role|admin|permission|access)', 'Client-side role/permission check'),
        (r'(?:is_admin|isAuthenticated|isLoggedIn|hasAccess|canAccess)\\s*[=:]\\s*true', 'Client-side auth state manipulation'),
        (r'(?:price|cost|amount|total)\\s*[=:]\\s*\\d+', 'Client-side price manipulation'),
        (r'(?:discount|coupon)\\s*[=:]\\s*["\\']?\\d+', 'Client-side discount manipulation'),
        (r'\\.disabled\\s*=\\s*false', 'Client-side disabled field manipulation'),
        (r'readonly\\s*[=:]\\s*false', 'Client-side readonly bypass'),
    ]

    for pattern, desc in validation_patterns:
        if re.search(pattern, all_js_content, re.IGNORECASE):
            results.append({{
                "title": f"Client-side only {{desc.lower()}}",
                "description": f"Found {{desc}} in client-side code at {base_url}. This should be validated server-side.",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "issue": desc,
                    "pattern": pattern
                }}
            }})

    # Check for commented-out security checks
    comment_security_patterns = [
        r'//.*(?:security|auth|validate|check|verify|sanitize|escape)',
        r'/\\*.*(?:security|auth|validate|check|verify|sanitize|escape)',
        r'//.*(?:TODO|FIXME|HACK).*(?:security|auth|bypass)',
        r'//.*(?:disabled|removed|skipped).*(?:check|validation|auth)',
    ]

    for pattern in comment_security_patterns:
        matches = re.findall(pattern, all_js_content, re.IGNORECASE)
        if matches:
            results.append({{
                "title": "Commented-out security code",
                "description": f"Found {{len(matches)}} comment(s) referencing security-related code that may have been disabled",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "comment_count": len(matches),
                    "sample_comments": [m.strip()[:80] for m in matches[:3]]
                }}
            }})
            break

    # Check for debug/development code in production
    debug_patterns = [
        (r'console\\.log\\s*\\(', 'console.log statements'),
        (r'console\\.debug\\s*\\(', 'console.debug statements'),
        (r'console\\.warn\\s*\\(', 'console.warn statements'),
        (r'debugger\\s*;', 'debugger statement'),
        (r'//\\s*@sourceMappingURL', 'Source map reference'),
        (r'process\\.env\\.NODE_ENV\\s*===\\s*["\\']development["\\']', 'Development environment check'),
        (r'\\bdev\\b.*(?:mode|environment|build)', 'Development mode reference'),
    ]

    debug_findings = []
    for pattern, desc in debug_patterns:
        count = len(re.findall(pattern, all_js_content))
        if count > 0:
            debug_findings.append({{"pattern": desc, "count": count}})

    if debug_findings:
        results.append({{
            "title": "Debug/development code in production",
            "description": f"Found debug/development artifacts in client-side code at {base_url}",
            "severity": "low",
            "data": {{
                "url": base_url,
                "findings": debug_findings
            }}
        }})

    # Check for client-side access controls
    access_control_patterns = [
        r'if\\s*\\(\\s*user\\.role\\s*===\\s*["\\']admin["\\']',
        r'if\\s*\\(\\s*user\\.isAdmin\\s*\\)',
        r'if\\s*\\(\\s*user\\.permissions',
        r'\\breadmin\\b.*(?:panel|dashboard|console)',
        r'requireAdmin\\s*\\(',
        r'checkPermission\\s*\\(',
    ]

    for pattern in access_control_patterns:
        if re.search(pattern, all_js_content, re.IGNORECASE):
            results.append({{
                "title": "Client-side access control",
                "description": f"Found client-side access control check at {base_url}. Access controls must be enforced server-side.",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "pattern": pattern
                }}
            }})
            break

    # Check for price/quantity manipulation
    price_patterns = [
        r'(?:price|amount|total|cost)\\s*[=:]\\s*["\\']?\\d+\\.?\\d*',
        r'(?:quantity|qty|count)\\s*[=:]\\s*["\\']?\\d+',
        r'(?:discount|coupon|promo)\\s*[=:]\\s*["\\']?\\d+',
    ]

    for pattern in price_patterns:
        if re.search(pattern, all_js_content, re.IGNORECASE):
            results.append({{
                "title": "Client-side price/quantity handling",
                "description": f"Found client-side price/quantity manipulation vectors at {base_url}. These values must be validated server-side.",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "pattern": pattern
                }}
            }})
            break

    client.close()

except Exception as e:
    results.append({{
        "title": "Client logic analysis error",
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
