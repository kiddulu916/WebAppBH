"""API discovery tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class ApiDiscoveryTool(ConfigMgmtTool):
    """Discover API endpoints and configuration (WSTG-CONFIG-005)."""

    name = "api_discovery_tool"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"

API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/graphql/",
    "/graphiql",
    "/graphiql/",
    "/api/graphql",
    "/graphql/console",
    "/playground",
    "/altair",
]

API_DOCS_PATHS = [
    "/swagger",
    "/swagger/",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/api-docs",
    "/api-docs/",
    "/docs",
    "/redoc",
    "/redoc/",
    "/openapi.json",
    "/api/openapi.json",
    "/swagger.json",
    "/api/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/swagger-resources",
    "/api/swagger-resources",
    "/api/v1/docs",
    "/api/v2/docs",
]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    base_path = base_url.rstrip('/')

    for path in API_PATHS:
        try:
            resp = client.get(base_path + path)
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "")
                results.append({{
                    "observation": {{
                        "type": "api_endpoint",
                        "value": path,
                        "details": {{
                            "location": base_path + path,
                            "status": resp.status_code,
                            "content_type": content_type,
                            "content_length": len(resp.text)
                        }}
                    }}
                }})
            elif resp.status_code == 405:
                results.append({{
                    "observation": {{
                        "type": "api_endpoint",
                        "value": path,
                        "details": {{
                            "location": base_path + path,
                            "status": resp.status_code,
                            "note": "Method not allowed - endpoint exists"
                        }}
                    }}
                }})
        except Exception:
            pass

    for path in API_DOCS_PATHS:
        try:
            resp = client.get(base_path + path)
            if resp.status_code == 200:
                results.append({{
                    "vulnerability": {{
                        "name": f"Exposed API documentation at {{path}}",
                        "severity": "medium",
                        "description": f"API documentation/interactive console accessible at {{path}}",
                        "location": base_path + path
                    }}
                }})
        except Exception:
            pass

    js_paths = ["/", "/static/js/", "/assets/", "/js/"]
    api_key_patterns = [
        r'["\'](?:api[_-]?key|apikey|apiKey)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{{16,}})["\']',
        r'["\'](?:secret|secret[_-]?key)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{{16,}})["\']',
        r'["\'](?:token|access[_-]?token)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{{16,}})["\']',
        r'["\'](?:auth[_-]?token)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{{16,}})["\']',
    ]

    for js_path in js_paths:
        try:
            resp = client.get(base_path + js_path)
            if resp.status_code == 200 and "javascript" in resp.headers.get("content-type", ""):
                for pattern in api_key_patterns:
                    matches = re.findall(pattern, resp.text)
                    if matches:
                        results.append({{
                            "vulnerability": {{
                                "name": "Potential API key exposed in JavaScript",
                                "severity": "high",
                                "description": f"Found potential API key(s) in JavaScript at {{js_path}}",
                                "location": base_path + js_path
                            }}
                        }})
                        break
        except Exception:
            pass

    try:
        resp = client.get(base_path + "/api/v1")
        www_auth = resp.headers.get("www-authenticate", "")
        if not www_auth and resp.status_code not in (404, 405):
            results.append({{
                "observation": {{
                    "type": "api_auth_config",
                    "value": "no_auth_required",
                    "details": {{
                        "location": base_path + "/api/v1",
                        "note": "API endpoint may not require authentication"
                    }}
                }}
            }})
    except Exception:
        pass

    client.close()

except Exception as e:
    results.append({{
        "observation": {{
            "type": "test_error",
            "value": str(e),
            "details": {{"error": str(e)}}
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
