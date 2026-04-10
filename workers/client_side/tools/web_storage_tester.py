"""Web storage testing tool (WSTG-CLIENT-006)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class WebStorageTester(ClientSideTool):
    """Test for web storage vulnerabilities (WSTG-CLIENT-006).

    Checks localStorage, sessionStorage, and IndexedDB for sensitive data
    storage, encryption status, and proper cleanup mechanisms.
    """

    name = "web_storage_tester"
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
    content = resp.text

    # Check localStorage usage for sensitive data
    ls_set_patterns = [
        r'localStorage\\.setItem\\s*\\(\\s*["\\']([^"\\'>]+)["\\']\\s*,\\s*["\\']?([^"\\'>\\s,)]+)["\\']?',
        r'localStorage\\[["\\']([^"\\'>]+)["\\']\\]\\s*=',
    ]

    sensitive_patterns = ['token', 'password', 'secret', 'key', 'auth', 'session', 'jwt', 'cookie', 'credit', 'card', 'ssn', 'email', 'phone', 'address', 'api_key', 'apikey', 'access_token', 'refresh_token']

    ls_keys = []
    for pattern in ls_set_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if isinstance(match, tuple):
                ls_keys.append(match[0])
            else:
                ls_keys.append(match)

    sensitive_ls_keys = [k for k in ls_keys if any(s in k.lower() for s in sensitive_patterns)]
    if sensitive_ls_keys:
        results.append({{
            "title": "Sensitive data in localStorage",
            "description": f"Found {{len(sensitive_ls_keys)}} localStorage key(s) that may contain sensitive data: {{', '.join(sensitive_ls_keys[:5])}}",
            "severity": "high",
            "data": {{
                "url": base_url,
                "storage_type": "localStorage",
                "sensitive_keys": sensitive_ls_keys,
                "total_keys": len(ls_keys)
            }}
        }})

    # Check sessionStorage usage for sensitive data
    ss_keys = []
    ss_pattern = r'sessionStorage\\.setItem\\s*\\(\\s*["\\']([^"\\'>]+)["\\']'
    ss_matches = re.findall(ss_pattern, content)
    ss_keys.extend(ss_matches)

    sensitive_ss_keys = [k for k in ss_keys if any(s in k.lower() for s in sensitive_patterns)]
    if sensitive_ss_keys:
        results.append({{
            "title": "Sensitive data in sessionStorage",
            "description": f"Found {{len(sensitive_ss_keys)}} sessionStorage key(s) that may contain sensitive data",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "storage_type": "sessionStorage",
                "sensitive_keys": sensitive_ss_keys
            }}
        }})

    # Check IndexedDB for sensitive data storage
    idb_patterns = [
        r'indexedDB\\.open\\s*\\(\\s*["\\']([^"\\'>]+)["\\']',
        r'createObjectStore\\s*\\(\\s*["\\']([^"\\'>]+)["\\']',
    ]

    idb_names = []
    for pattern in idb_patterns:
        matches = re.findall(pattern, content)
        idb_names.extend(matches)

    sensitive_idb = [n for n in idb_names if any(s in n.lower() for s in sensitive_patterns)]
    if sensitive_idb:
        results.append({{
            "title": "Sensitive data in IndexedDB",
            "description": f"Found IndexedDB database/store names that may contain sensitive data",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "storage_type": "IndexedDB",
                "sensitive_names": sensitive_idb
            }}
        }})

    # Check for encryption before storage
    encryption_patterns = [
        r'crypto\\s*\\.\\s*subtle',
        r'CryptoJS',
        r'forge\\s*\\.\\s*encrypt',
        r'AES\\.encrypt',
        r'encrypt\\s*\\(',
        r'btoa\\s*\\(',
        r'atob\\s*\\(',
    ]

    has_encryption = any(re.search(p, content) for p in encryption_patterns)
    has_storage = bool(ls_keys or ss_keys or idb_names)

    if has_storage and not has_encryption:
        results.append({{
            "title": "Data stored without encryption",
            "description": f"Web storage is used at {base_url} but no encryption mechanism was detected. Sensitive data may be stored in plaintext.",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "has_encryption": False,
                "storage_types_used": {{
                    "localStorage": bool(ls_keys),
                    "sessionStorage": bool(ss_keys),
                    "indexedDB": bool(idb_names)
                }}
            }}
        }})

    # Check for base64 encoding (not encryption) used for sensitive data
    if re.search(r'btoa\\s*\\(', content) and has_storage:
        results.append({{
            "title": "Base64 encoding used for storage (not encryption)",
            "description": f"btoa() found alongside storage operations at {base_url}. Base64 is encoding, not encryption.",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "issue": "Base64 is not encryption"
            }}
        }})

    # Check for logout/cleanup mechanisms
    logout_patterns = [
        r'localStorage\\.clear\\s*\\(',
        r'sessionStorage\\.clear\\s*\\(',
        r'localStorage\\.removeItem',
        r'sessionStorage\\.removeItem',
        r'logout',
        r'signout',
        r'sign.out',
    ]

    has_cleanup = any(re.search(p, content, re.IGNORECASE) for p in logout_patterns[:4])
    has_logout = any(re.search(p, content, re.IGNORECASE) for p in logout_patterns[4:])

    if has_storage and not has_cleanup:
        severity = "low" if has_logout else "medium"
        results.append({{
            "title": "Missing storage cleanup on logout",
            "description": f"Web storage is used at {base_url} but no clear()/removeItem calls found for cleanup. Data may persist after logout.",
            "severity": severity,
            "data": {{
                "url": base_url,
                "has_cleanup": has_cleanup,
                "has_logout_function": has_logout
            }}
        }})

    # Check for cross-origin storage access attempts
    cross_origin_patterns = [
        r'window\\.postMessage.*localStorage',
        r'window\\.postMessage.*sessionStorage',
        r'iframe.*contentWindow.*localStorage',
    ]
    for pattern in cross_origin_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": "Potential cross-origin storage access",
                "description": f"Code pattern found that may attempt cross-origin storage access at {base_url}",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "pattern": pattern
                }}
            }})
            break

    client.close()

except Exception as e:
    results.append({{
        "title": "Web storage test error",
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
