"""HTTP methods configuration tester."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class HttpMethodTester(ConfigMgmtTool):
    """Test HTTP methods configuration (WSTG-CONFIG-006)."""

    name = "http_method_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"

DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH", "COPY", "MOVE", "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK"]
TEST_PATHS = ["/", "/api", "/api/v1", "/upload", "/files", "/static"]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    base_path = base_url.rstrip('/')

    try:
        resp = client.request("TRACE", base_path)
        if resp.status_code == 200:
            results.append({{
                "vulnerability": {{
                    "name": "TRACE method enabled (Cross-Site Tracing)",
                    "severity": "medium",
                    "description": "The TRACE HTTP method is enabled, which can be exploited for cross-site tracing attacks",
                    "location": base_path
                }}
            }})
        elif resp.status_code == 405:
            results.append({{
                "observation": {{
                    "type": "http_method_config",
                    "value": "TRACE_disabled",
                    "details": {{"method": "TRACE", "status": 405}}
                }}
            }})
    except Exception:
        pass

    try:
        resp = client.request("OPTIONS", base_path)
        if resp.status_code == 200:
            allowed = resp.headers.get("allow", "") or resp.headers.get("access-control-allow-methods", "")
            if allowed:
                results.append({{
                    "observation": {{
                        "type": "http_method_config",
                        "value": "OPTIONS_enabled",
                        "details": {{
                            "allowed_methods": allowed,
                            "location": base_path
                        }}
                    }}
                }})
                for method in DANGEROUS_METHODS:
                    if method.upper() in allowed.upper():
                        results.append({{
                            "vulnerability": {{
                                "name": f"Dangerous HTTP method {{method}} allowed",
                                "severity": "medium",
                                "description": f"The {{method}} method is listed in the Allow header at {{base_path}}",
                                "location": base_path
                            }}
                        }})
    except Exception:
        pass

    for method in ["PUT", "DELETE", "PATCH"]:
        for path in TEST_PATHS:
            try:
                resp = client.request(method, base_path + path)
                if resp.status_code in (200, 201, 204):
                    results.append({{
                        "vulnerability": {{
                            "name": f"{{method}} method accepted at {{path}}",
                            "severity": "high",
                            "description": f"The {{method}} method returns HTTP {{resp.status_code}} at {{path}}, indicating it may be accepted",
                            "location": base_path + path
                        }}
                    }})
                elif resp.status_code == 405:
                    pass
            except Exception:
                pass

    webdav_paths = ["/webdav", "/dav", "/webdav/", "/dav/", "/remote.php/webdav"]
    for path in webdav_paths:
        try:
            resp = client.request("PROPFIND", base_path + path)
            if resp.status_code in (200, 207):
                results.append({{
                    "vulnerability": {{
                        "name": f"WebDAV enabled at {{path}}",
                        "severity": "high",
                        "description": f"WebDAV PROPFIND method returns HTTP {{resp.status_code}} at {{path}}",
                        "location": base_path + path
                    }}
                }})
        except Exception:
            pass

    try:
        resp = client.get(base_path, headers={{"X-HTTP-Method-Override": "DELETE"}})
        if resp.status_code in (200, 204):
            results.append({{
                "observation": {{
                    "type": "http_method_config",
                    "value": "method_override_detected",
                    "details": {{
                        "header": "X-HTTP-Method-Override",
                        "note": "Server may accept method override headers"
                    }}
                }}
            }})
    except Exception:
        pass

    try:
        resp = client.get(base_path, headers={{"X-HTTP-Method": "DELETE"}})
        if resp.status_code in (200, 204):
            results.append({{
                "observation": {{
                    "type": "http_method_config",
                    "value": "x_http_method_detected",
                    "details": {{
                        "header": "X-HTTP-Method",
                        "note": "Server may accept X-HTTP-Method override header"
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
