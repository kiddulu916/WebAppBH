"""Network configuration testing tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class NetworkConfigTester(ConfigMgmtTool):
    """Test network configuration issues (WSTG-CONFIG-001)."""

    name = "network_config_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import sys

results = []
base_url = "{base_url}"

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    admin_paths = [
        "/admin", "/administrator", "/admin/login", "/admin/dashboard",
        "/manage", "/manager", "/console", "/wp-admin", "/phpmyadmin",
        "/pma", "/cpanel", "/webmin", "/solr", "/jenkins", "/actuator",
        "/status", "/server-status", "/nginx_status",
    ]

    for path in admin_paths:
        try:
            resp = client.get(base_url.rstrip('/') + path)
            if resp.status_code == 200:
                results.append({{
                    "vulnerability": {{
                        "name": f"Exposed admin panel at {{path}}",
                        "severity": "high",
                        "description": f"Admin panel accessible at {{path}} without proper access controls",
                        "location": base_url.rstrip('/') + path
                    }}
                }})
            elif resp.status_code in (301, 302, 307, 308):
                results.append({{
                    "observation": {{
                        "type": "admin_redirect",
                        "value": path,
                        "details": {{
                            "location": path,
                            "redirect_status": resp.status_code,
                            "redirect_to": resp.headers.get("location", "unknown")
                        }}
                    }}
                }})
        except Exception:
            pass

    try:
        resp = client.get(base_url, headers={{"Origin": "http://evil.com"}})
        acao = resp.headers.get("access-control-allow-origin", "")
        if acao == "*" or acao == "http://evil.com":
            results.append({{
                "observation": {{
                    "type": "cors_config",
                    "value": acao,
                    "details": {{
                        "allow_origin": acao,
                        "allow_credentials": resp.headers.get("access-control-allow-credentials", "false")
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
