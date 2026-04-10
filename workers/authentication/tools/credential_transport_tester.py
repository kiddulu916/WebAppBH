"""Credential transport security testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class CredentialTransportTester(AuthenticationTool):
    """Test credential transport security (WSTG-ATHN-001)."""

    name = "credential_transport_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"

        script = f'''
import httpx
import json
import re
import sys
from urllib.parse import urlparse, urljoin

results = []
base_url = "{base_url}"
parsed = urlparse(base_url)
host = parsed.netloc
scheme = parsed.scheme

def safe_get(url, **kwargs):
    try:
        return httpx.get(url, follow_redirects=False, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

def safe_get_redirect(url, **kwargs):
    try:
        return httpx.get(url, follow_redirects=True, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

# Test 1: Check if HTTP version of site is accessible
http_url = base_url.replace("https://", "http://")
if base_url.startswith("https://"):
    r = safe_get(http_url)
    if r and r.status_code == 200:
        results.append({{
            "title": "Login page accessible over HTTP",
            "description": f"The site at {{http_url}} is accessible over unencrypted HTTP. Credentials transmitted over this connection could be intercepted.",
            "severity": "high",
            "data": {{"url": http_url, "status_code": r.status_code, "content_length": len(r.text)}}
        }})

# Test 2: Check HTTPS redirect
r = safe_get(http_url)
if r and r.status_code not in (301, 302, 307, 308):
    results.append({{
        "title": "No HTTPS redirect configured",
        "description": f"HTTP requests to {{http_url}} are not redirected to HTTPS (status: {{r.status_code}})",
        "severity": "high",
        "data": {{"url": http_url, "status_code": r.status_code}}
    }})
elif r and r.status_code in (301, 302, 307, 308):
    location = r.headers.get("location", "")
    if not location.startswith("https://"):
        results.append({{
            "title": "HTTPS redirect points to non-HTTPS URL",
            "description": f"The redirect from {{http_url}} points to {{location}} which is not HTTPS",
            "severity": "high",
            "data": {{"url": http_url, "redirect_to": location}}
        }})

# Test 3: Check for mixed content on login page
r = safe_get_redirect(base_url)
if r and r.status_code == 200:
    text = r.text
    # Find all http:// references (not https://)
    http_refs = re.findall(r'["\\']http://[^"\\'>\\s]+["\\']', text)
    http_refs = [ref.strip('"\\'') for ref in http_refs]
    # Filter out common false positives
    http_refs = [ref for ref in http_refs if not any(x in ref.lower() for x in ['schema.org', 'w3.org', 'xml'])]
    if http_refs:
        results.append({{
            "title": "Mixed content detected on login page",
            "description": f"Found {{len(http_refs)}} HTTP resource references on HTTPS page. Credentials or session data could be leaked.",
            "severity": "medium",
            "data": {{"http_refs": http_refs[:10], "total_count": len(http_refs)}}
        }})

    # Test 4: Check form action URLs
    forms = re.findall(r'<form[^>]*action=["\\']([^"\\']*)["\\']', text, re.IGNORECASE)
    for form_action in forms:
        if form_action.startswith("http://"):
            results.append({{
                "title": "Form submits credentials over HTTP",
                "description": f"Form action URL uses unencrypted HTTP: {{form_action}}",
                "severity": "critical",
                "data": {{"form_action": form_action, "page_url": base_url}}
            }})

    # Test 5: Check if credentials might be sent via GET
    forms_with_get = re.findall(r'<form[^>]*method=["\\']get["\\']', text, re.IGNORECASE)
    if forms_with_get:
        # Check if form has password or username fields
        has_credential_fields = bool(re.search(r'<input[^>]*(type=["\\']?(password|text)["\\']?|name=["\\']?(password|user|username|login|email)["\\']?)', text, re.IGNORECASE))
        if has_credential_fields:
            results.append({{
                "title": "Credentials may be sent via GET parameters",
                "description": "Login form uses GET method. Credentials will appear in URL, browser history, and server logs.",
                "severity": "high",
                "data": {{"page_url": base_url}}
            }})

    # Test 6: Check for autocomplete on password fields
    password_fields = re.findall(r'<input[^>]*type=["\\']password["\\'][^>]*>', text, re.IGNORECASE)
    for pf in password_fields:
        if 'autocomplete="off"' not in pf and "autocomplete='off'" not in pf:
            results.append({{
                "title": "Password field has autocomplete enabled",
                "description": "Password input field does not have autocomplete disabled. Browser may cache credentials.",
                "severity": "low",
                "data": {{"field_html": pf[:200]}}
            }})

    # Test 7: Check Strict-Transport-Security header
    hsts = r.headers.get("strict-transport-security", "")
    if not hsts:
        results.append({{
            "title": "Missing HSTS header",
            "description": "The Strict-Transport-Security header is not set. Browser will not enforce HTTPS connections.",
            "severity": "medium",
            "data": {{"url": base_url, "headers": dict(r.headers)}}
        }})

# Test 8: Check for credentials in URL parameters
r = safe_get_redirect(base_url)
if r:
    final_url = str(r.url)
    sensitive_params = ['password', 'passwd', 'pwd', 'token', 'secret', 'key', 'auth']
    for param in sensitive_params:
        if param in final_url.lower():
            results.append({{
                "title": "Sensitive data in URL parameters",
                "description": f"URL contains potentially sensitive parameter '{{param}}': {{final_url}}",
                "severity": "high",
                "data": {{"url": final_url, "sensitive_param": param}}
            }})

if not results:
    results.append({{
        "title": "Credential transport checks passed",
        "description": "No credential transport issues detected. HTTPS is properly configured with redirects and HSTS.",
        "severity": "info",
        "data": {{"url": base_url, "checks_performed": ["http_access", "https_redirect", "mixed_content", "form_action", "get_method", "autocomplete", "hsts", "url_params"]}}
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
