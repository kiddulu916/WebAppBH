"""HTML5 injection testing tool (WSTG-CLIENT-005)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class Html5InjectionTester(ClientSideTool):
    """Test for HTML5 injection vulnerabilities (WSTG-CLIENT-005).

    Checks for insecure postMessage handlers, WebSocket connections,
    WebSQL/IndexedDB usage, and cross-origin resource sharing issues.
    """

    name = "html5_injection_tester"
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

    # Check postMessage handlers for origin validation
    pm_listener_pattern = r'addEventListener\\s*\\(\\s*["\\']message["\\']\\s*,'
    pm_listeners = re.findall(pm_listener_pattern, content)

    if pm_listeners:
        # Check for origin validation in the handler
        origin_checks = [
            r'event\\.origin\\s*===',
            r'event\\.origin\\s*!==',
            r'message\\.origin\\s*===',
            r'message\\.origin\\s*!==',
            r'e\\.origin\\s*===',
            r'e\\.origin\\s*!==',
            r'allowedOrigins',
            r'allowed_origins',
            r'\\.includes\\s*\\(.*origin',
        ]
        has_origin_check = any(re.search(p, content) for p in origin_checks)

        if not has_origin_check:
            results.append({{
                "title": "postMessage handler without origin validation",
                "description": f"Found postMessage event listener at {base_url} without proper origin validation",
                "severity": "high",
                "data": {{
                    "url": base_url,
                    "issue": "Missing origin validation in postMessage handler",
                    "listener_count": len(pm_listeners)
                }}
            }})
        else:
            # Check if origin validation uses exact match or is too permissive
            if re.search(r'event\\.origin\\.endsWith|event\\.origin\\.includes', content):
                results.append({{
                    "title": "Weak postMessage origin validation",
                    "description": f"postMessage handler at {base_url} uses partial origin matching (endsWith/includes) which can be bypassed",
                    "severity": "medium",
                    "data": {{
                        "url": base_url,
                        "issue": "Weak origin validation using partial matching"
                    }}
                }})

    # Check for insecure WebSocket connections
    ws_patterns = [
        (r'new\\s+WebSocket\\s*\\(\\s*["\\']ws://', 'Insecure WebSocket connection (ws://)'),
        (r'wss?://[^"\'>\\s]+', 'WebSocket connection found'),
    ]

    ws_connections = re.findall(r'new\\s+WebSocket\\s*\\(\\s*["\\']([^"\\'>]+)["\\']', content)
    insecure_ws = [ws for ws in ws_connections if ws.startswith('ws://')]

    if insecure_ws:
        results.append({{
            "title": "Insecure WebSocket connections",
            "description": f"Found {{len(insecure_ws)}} WebSocket connection(s) using unencrypted ws:// protocol",
            "severity": "high",
            "data": {{
                "url": base_url,
                "insecure_websockets": insecure_ws[:10]
            }}
        }})

    # Check for WebSQL usage (deprecated but still potentially vulnerable)
    if re.search(r'openDatabase\\s*\\(', content):
        results.append({{
            "title": "WebSQL usage detected",
            "description": f"WebSQL API (openDatabase) found at {base_url}. WebSQL is deprecated and may have security implications",
            "severity": "low",
            "data": {{
                "url": base_url,
                "api": "WebSQL (openDatabase)"
            }}
        }})

    # Check for IndexedDB usage with potential sensitive data
    idb_patterns = [
        r'indexedDB\\.open',
        r'\\.createObjectStore',
        r'\\.add\\s*\\(.*password',
        r'\\.put\\s*\\(.*token',
        r'\\.put\\s*\\(.*secret',
        r'\\.put\\s*\\(.*key',
    ]
    for pattern in idb_patterns[2:]:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": "Potential sensitive data in IndexedDB",
                "description": f"IndexedDB operations found that may store sensitive data at {base_url}",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "pattern": pattern,
                    "storage": "IndexedDB"
                }}
            }})
            break

    # Check for drag-and-drop event handlers (potential XSS vector)
    drag_events = re.findall(r'ondrop\\s*=|ondragover\\s*=|ondragenter\\s*=', content)
    if drag_events:
        results.append({{
            "title": "Drag-and-drop event handlers found",
            "description": f"Found {{len(drag_events)}} drag-and-drop event handler(s) which could be exploited for XSS if not properly sanitized",
            "severity": "low",
            "data": {{
                "url": base_url,
                "drag_event_count": len(drag_events)
            }}
        }})

    # Check CORS headers for overly permissive configuration
    cors_headers = {{
        "access_control_allow_origin": resp.headers.get("Access-Control-Allow-Origin", ""),
        "access_control_allow_credentials": resp.headers.get("Access-Control-Allow-Credentials", ""),
        "access_control_allow_methods": resp.headers.get("Access-Control-Allow-Methods", ""),
    }}

    acao = cors_headers["access_control_allow_origin"]
    if acao == "*":
        results.append({{
            "title": "Overly permissive CORS configuration",
            "description": f"Access-Control-Allow-Origin is set to '*' at {base_url}, allowing any origin to make cross-origin requests",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "acao": acao,
                "allow_credentials": cors_headers["access_control_allow_credentials"]
            }}
        }})
    elif acao and "null" in acao.lower():
        results.append({{
            "title": "CORS allows null origin",
            "description": f"Access-Control-Allow-Origin includes 'null' at {base_url}, which can be exploited via sandboxed iframes",
            "severity": "medium",
            "data": {{
                "url": base_url,
                "acao": acao
            }}
        }})

    # Check for HTML5 storage-based injection vectors
    storage_patterns = [
        (r'localStorage\\.setItem\\s*\\(\\s*["\\']([^"\\'>]+)["\\']', 'localStorage.setItem'),
        (r'sessionStorage\\.setItem\\s*\\(\\s*["\\']([^"\\'>]+)["\\']', 'sessionStorage.setItem'),
    ]
    for pattern, name in storage_patterns:
        keys = re.findall(pattern, content)
        sensitive_keys = [k for k in keys if any(s in k.lower() for s in ['token', 'password', 'secret', 'key', 'auth', 'session', 'jwt', 'cookie'])]
        if sensitive_keys:
            results.append({{
                "title": f"Sensitive data stored in {{name.split('.')[0]}}",
                "description": f"Found {{len(sensitive_keys)}} potentially sensitive storage key(s) in {{name}} at {base_url}",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "sensitive_keys": sensitive_keys[:10],
                    "storage_type": name.split('.')[0]
                }}
            }})

    client.close()

except Exception as e:
    results.append({{
        "title": "HTML5 injection test error",
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
