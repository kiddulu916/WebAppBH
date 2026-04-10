"""Browser cache weakness testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class BrowserCacheWeaknessTester(AuthenticationTool):
    """Test for browser cache weaknesses (WSTG-ATHN-006)."""

    name = "browser_cache_weakness_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"

        script = f'''
import httpx
import json
import re
from urllib.parse import urljoin

results = []
base_url = "{base_url}"

def safe_get(url, **kwargs):
    try:
        return httpx.get(url, follow_redirects=True, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

def safe_post(url, **kwargs):
    try:
        return httpx.post(url, follow_redirects=False, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

def check_cache_headers(response, url):
    """Check cache-control headers on a response."""
    if response is None:
        return []
    
    findings = []
    headers = response.headers
    
    cache_control = headers.get("cache-control", "")
    pragma = headers.get("pragma", "")
    expires = headers.get("expires", "")
    
    # Check for cache-control directives
    no_cache = "no-cache" in cache_control.lower()
    no_store = "no-store" in cache_control.lower()
    must_revalidate = "must-revalidate" in cache_control.lower()
    private = "private" in cache_control.lower()
    
    has_cache_protection = no_cache or no_store
    
    if not has_cache_protection:
        findings.append({{
            "title": f"Missing cache protection on {{url}}",
            "description": f"The response from {{url}} does not have Cache-Control: no-cache or no-store. Sensitive content may be cached by the browser.",
            "severity": "medium",
            "data": {{
                "url": url,
                "cache_control": cache_control or "(not set)",
                "pragma": pragma or "(not set)",
                "expires": expires or "(not set)",
                "missing_directives": [
                    d for d, present in [
                        ("no-cache", no_cache),
                        ("no-store", no_store),
                        ("must-revalidate", must_revalidate),
                        ("private", private)
                    ] if not present
                ]
            }}
        }})
    elif no_cache and not no_store:
        findings.append({{
            "title": f"Cache-Control has no-cache but not no-store on {{url}}",
            "description": f"The response has Cache-Control: no-cache but not no-store. Content may still be stored on disk.",
            "severity": "low",
            "data": {{
                "url": url,
                "cache_control": cache_control
            }}
        }})
    
    # Check Pragma header (HTTP/1.0 backwards compatibility)
    if pragma.lower() != "no-cache" and not has_cache_protection:
        findings.append({{
            "title": f"Missing Pragma: no-cache on {{url}}",
            "description": f"The response does not have Pragma: no-cache header. Older browsers may cache sensitive content.",
            "severity": "low",
            "data": {{
                "url": url,
                "pragma": pragma or "(not set)"
            }}
        }})
    
    # Check Expires header
    if expires and not has_cache_protection:
        findings.append({{
            "title": f"Expires header set without cache protection on {{url}}",
            "description": f"Expires header is set to '{{expires}}' but no cache protection directives are present.",
            "severity": "low",
            "data": {{
                "url": url,
                "expires": expires
            }}
        }})
    
    return findings

# Test 1: Check cache headers on login page
login_url = None
for path in ["/login", "/auth/login", "/signin", "/wp-login.php", "/admin/login", "/"]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        if re.search(r'<form[^>]*>', r.text, re.IGNORECASE) or re.search(r'<input[^>]*type=["\\']?password', r.text, re.IGNORECASE):
            login_url = url
            break

if not login_url:
    login_url = urljoin(base_url, "/login")

r = safe_get(login_url)
if r:
    cache_findings = check_cache_headers(r, login_url)
    results.extend(cache_findings)

# Test 2: Check cache headers on common authenticated pages
auth_paths = [
    "/admin", "/admin/dashboard", "/dashboard", "/profile", "/account",
    "/settings", "/api/users", "/api/profile", "/user/settings",
    "/wp-admin", "/phpmyadmin", "/console",
]

for path in auth_paths:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        cache_findings = check_cache_headers(r, url)
        results.extend(cache_findings)
    elif r and r.status_code in (301, 302, 303, 307, 308):
        # Follow redirect and check final response
        r2 = safe_get(url)
        if r2 and r2.status_code == 200:
            cache_findings = check_cache_headers(r2, str(r2.url))
            results.extend(cache_findings)

# Test 3: Check if sensitive pages return cache headers with different content types
content_paths = [
    ("/api/users", "application/json"),
    ("/api/profile", "application/json"),
    ("/config.json", "application/json"),
]

for path, expected_type in content_paths:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        content_type = r.headers.get("content-type", "")
        if expected_type in content_type.lower():
            cache_findings = check_cache_headers(r, url)
            results.extend(cache_findings)

# Test 4: Check for sensitive data in cached responses
# Look for pages that might contain sensitive info
sensitive_paths = ["/profile", "/account", "/settings", "/api/me", "/api/user"]

for path in sensitive_paths:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        text = r.text.lower()
        
        # Check for sensitive data patterns
        sensitive_patterns = [
            (r'["\\']?(?:email|password|ssn|credit[_-]?card|token|api[_-]?key|secret)["\\']?\\s*[:=]\\s*["\\']?[^"\\'>\\s]+', "sensitive data field"),
            (r'["\\']?(?:authorization|bearer|token)["\\']?\\s*[:=]\\s*["\\']?[a-zA-Z0-9._-]{{10,}}', "authorization token"),
        ]
        
        for pattern, desc in sensitive_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                results.append({{
                    "title": f"Sensitive data potentially cacheable on {{path}}",
                    "description": f"Found {{len(matches)}} occurrence(s) of {{desc}} on {{path}}. If page is cached, this data could be exposed.",
                    "severity": "high",
                    "data": {{
                        "path": path,
                        "pattern_type": desc,
                        "match_count": len(matches)
                    }}
                }})

# Test 5: Check Cache-Control on error pages (should also not be cached)
error_paths = ["/login?error=1", "/admin?error=invalid", "/auth?error=expired"]

for path in error_paths:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        cache_control = r.headers.get("cache-control", "")
        if "no-store" not in cache_control.lower() and "no-cache" not in cache_control.lower():
            results.append({{
                "title": f"Error page may be cached: {{path}}",
                "description": f"Error page at {{path}} does not have cache protection. Error messages with sensitive info could be cached.",
                "severity": "low",
                "data": {{
                    "url": url,
                    "cache_control": cache_control or "(not set)"
                }}
            }})

# Summary
if not results:
    results.append({{
        "title": "Browser cache checks completed",
        "description": "All tested pages have appropriate cache-control headers",
        "severity": "info",
        "data": {{
            "pages_tested": len(auth_paths) + len(content_paths) + len(sensitive_paths),
            "base_url": base_url
        }}
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
