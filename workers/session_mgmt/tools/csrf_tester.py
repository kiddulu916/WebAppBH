"""CSRF token presence and validation testing tool."""

from workers.session_mgmt.base_tool import SessionMgmtTool
from workers.session_mgmt.concurrency import WeightClass


class CsrfTester(SessionMgmtTool):
    """Test CSRF token presence and validation (WSTG-SESS-005)."""

    name = "csrf_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(verify=False, follow_redirects=True, timeout=10)

    # Step 1: Get a session and collect pages to analyze
    pages_analyzed = []
    forms_found = []
    csrf_tokens_found = []
    state_changing_endpoints = []

    # Common state-changing endpoints to test
    state_changing_paths = [
        "/api/user/update", "/api/user/delete", "/api/profile/update",
        "/api/settings/update", "/api/account/update", "/api/password/change",
        "/api/email/change", "/user/update", "/user/delete", "/profile/update",
        "/settings/update", "/account/update", "/password/change", "/email/change",
        "/api/transfer", "/api/payment", "/api/order", "/api/withdraw"
    ]

    # Fetch main page and look for forms
    try:
        resp = client.get(base_url)
        pages_analyzed.append("/")
        body = resp.text

        # Find all forms
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        forms = form_pattern.findall(body)

        for form in forms:
            form_action = re.search(r'action=["\']([^"\']*)["\']', form)
            form_method = re.search(r'method=["\']([^"\']*)["\']', form)
            action = form_action.group(1) if form_action else ""
            method = form_method.group(1) if form_method else "get"

            # Check for CSRF tokens in form
            csrf_patterns = [
                r'name=["\']csrf_token["\']',
                r'name=["\']_token["\']',
                r'name=["\']_csrf["\']',
                r'name=["\']authenticity_token["\']',
                r'name=["\']xsrf_token["\']',
                r'name=["\']XSRF-TOKEN["\']',
                r'name=["\']__RequestVerificationToken["\']'
            ]

            has_csrf_token = any(re.search(p, form, re.IGNORECASE) for p in csrf_patterns)

            if method.lower() in ["post", "put", "patch", "delete"]:
                forms_found.append({{
                    "action": action,
                    "method": method,
                    "has_csrf_token": has_csrf_token
                }})

                if has_csrf_token:
                    csrf_tokens_found.append(action)

        # Check for CSRF token in meta tags
        meta_csrf = re.search(r'<meta[^>]*name=["\\']?(csrf-token|xsrf-token|_token)["\\']?[^>]*content=["\\']?([^"\\'>]*)["\\']?', body, re.IGNORECASE)
        if meta_csrf:
            csrf_tokens_found.append("meta:" + meta_csrf.group(1))

        # Check for CSRF token in headers
        for header_name, header_value in resp.headers.items():
            if "csrf" in header_name.lower() or "xsrf" in header_name.lower():
                csrf_tokens_found.append("header:" + header_name)

    except Exception:
        pass

    # Step 2: Test state-changing endpoints without CSRF tokens
    csrf_vulnerabilities = []

    for path in state_changing_paths:
        try:
            url = base_url.rstrip("/") + path

            # Test POST without CSRF token
            resp = client.post(url, data={{"test": "1"}}, timeout=10)

            # Check if the request was accepted (not rejected with 403/401)
            if resp.status_code not in (403, 401, 405):
                # Check if the response indicates success
                body_lower = resp.text.lower()
                success_indicators = ["success", "updated", "saved", "changed", "completed", "200"]
                is_success = any(ind in body_lower for ind in success_indicators)

                if is_success or resp.status_code == 200:
                    # Check if there's any CSRF validation happening
                    error_indicators = ["csrf", "invalid token", "missing token", "forbidden", "unauthorized"]
                    has_csrf_error = any(ind in body_lower for ind in error_indicators)

                    if not has_csrf_error:
                        csrf_vulnerabilities.append({{
                            "endpoint": path,
                            "method": "POST",
                            "status_code": resp.status_code,
                            "response_indicates_success": is_success
                        }})
        except Exception:
            pass

    # Step 3: Check for custom header CSRF protection
    custom_header_protection = False
    try:
        resp = client.post(
            base_url.rstrip("/") + "/api/test",
            headers={{"X-CSRF-Token": "test"}},
            timeout=10
        )
        if resp.status_code == 403:
            custom_header_protection = True
    except Exception:
        pass

    # Step 4: Check SameSite cookie attribute as CSRF mitigation
    samesite_protection = False
    try:
        resp = client.get(base_url)
        for header_name, header_value in resp.headers.multi_items():
            if header_name.lower() == "set-cookie":
                if "samesite=strict" in header_value.lower():
                    samesite_protection = True
                    break
    except Exception:
        pass

    # Compile results
    if forms_found:
        forms_without_csrf = [f for f in forms_found if not f["has_csrf_token"]]
        if forms_without_csrf:
            results.append({{
                "title": "Forms without CSRF tokens",
                "description": f"Found {{len(forms_without_csrf)}} form(s) using state-changing methods without CSRF tokens: {{[f['action'] for f in forms_without_csrf]}}",
                "severity": "high",
                "data": {{
                    "forms_without_csrf": forms_without_csrf,
                    "total_forms_analyzed": len(forms_found)
                }}
            }})
        else:
            results.append({{
                "title": "All forms have CSRF tokens",
                "description": f"All {{len(forms_found)}} state-changing forms include CSRF tokens",
                "severity": "info",
                "data": {{
                    "forms_analyzed": len(forms_found),
                    "csrf_tokens_found": csrf_tokens_found
                }}
            }})

    if csrf_vulnerabilities:
        results.append({{
            "title": "Potential CSRF vulnerabilities in API endpoints",
            "description": f"Found {{len(csrf_vulnerabilities)}} endpoint(s) that may be vulnerable to CSRF: {{[v['endpoint'] for v in csrf_vulnerabilities]}}",
            "severity": "high",
            "data": {{
                "vulnerable_endpoints": csrf_vulnerabilities,
                "recommendation": "Implement CSRF token validation for all state-changing endpoints"
            }}
        }})

    # Check Referer header validation
    referer_validation = False
    try:
        resp = client.post(
            base_url.rstrip("/") + "/api/test",
            headers={{"Referer": "https://evil.com"}},
            timeout=10
        )
        if resp.status_code == 403:
            referer_validation = True
    except Exception:
        pass

    if referer_validation:
        results.append({{
            "title": "Referer header validation detected",
            "description": "The application validates the Referer header, providing additional CSRF protection",
            "severity": "info",
            "data": {{"referer_validation": True}}
        }})

    if samesite_protection:
        results.append({{
            "title": "SameSite=Strict cookie attribute detected",
            "description": "Session cookies use SameSite=Strict, providing browser-level CSRF protection",
            "severity": "info",
            "data": {{"samesite_protection": True}}
        }})

    if custom_header_protection:
        results.append({{
            "title": "Custom header CSRF protection detected",
            "description": "The application appears to validate custom headers for CSRF protection",
            "severity": "info",
            "data": {{"custom_header_protection": True}}
        }})

    if not results:
        results.append({{
            "title": "CSRF test completed",
            "description": "No obvious CSRF vulnerabilities detected. Manual testing recommended for comprehensive coverage.",
            "severity": "info",
            "data": {{
                "pages_analyzed": pages_analyzed,
                "forms_analyzed": len(forms_found),
                "endpoints_tested": len(state_changing_paths)
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

    def parse_output(self, stdout):
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
