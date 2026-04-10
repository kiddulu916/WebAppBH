"""File extension handling tester."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class FileExtensionTester(ConfigMgmtTool):
    """Test file extension handling security (WSTG-CONFIG-003)."""

    name = "file_extension_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".swp", ".tmp", ".backup", ".save"]
CONFIG_EXTENSIONS = [".xml", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".properties", ".toml"]
SOURCE_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".java", ".go"]
DATABASE_EXTENSIONS = [".sql", ".db", ".sqlite", ".sqlite3", ".mdb"]
ARCHIVE_EXTENSIONS = [".zip", ".tar", ".gz", ".tar.gz", ".tgz", ".rar", ".7z"]

SENSITIVE_CONTENT_PATTERNS = [
    "password", "secret", "api_key", "apikey", "token",
    "private", "credential", "auth", "connection_string",
    "database_url", "db_pass", "mysql", "postgres",
]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    base_path = base_url.rstrip('/')

    for ext in BACKUP_EXTENSIONS:
        try:
            resp = client.get(base_path + "/config" + ext)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                severity = "high" if any(p in body_lower for p in SENSITIVE_CONTENT_PATTERNS) else "medium"
                results.append({{
                    "vulnerability": {{
                        "name": f"Accessible backup file: /config{{ext}}",
                        "severity": severity,
                        "description": f"Backup file /config{{ext}} is accessible and returns HTTP 200",
                        "location": base_path + "/config" + ext
                    }}
                }})
        except Exception:
            pass

    for ext in CONFIG_EXTENSIONS:
        try:
            resp = client.get(base_path + "/config" + ext)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                severity = "high" if any(p in body_lower for p in SENSITIVE_CONTENT_PATTERNS) else "medium"
                results.append({{
                    "vulnerability": {{
                        "name": f"Accessible configuration file: /config{{ext}}",
                        "severity": severity,
                        "description": f"Configuration file /config{{ext}} is accessible and returns HTTP 200",
                        "location": base_path + "/config" + ext
                    }}
                }})
        except Exception:
            pass

    for ext in SOURCE_EXTENSIONS:
        try:
            resp = client.get(base_path + "/index" + ext)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                severity = "critical" if any(p in body_lower for p in SENSITIVE_CONTENT_PATTERNS) else "high"
                results.append({{
                    "vulnerability": {{
                        "name": f"Accessible source code file: /index{{ext}}",
                        "severity": severity,
                        "description": f"Source file /index{{ext}} is accessible and returns HTTP 200",
                        "location": base_path + "/index" + ext
                    }}
                }})
        except Exception:
            pass

    for ext in DATABASE_EXTENSIONS:
        try:
            resp = client.get(base_path + "/database" + ext)
            if resp.status_code == 200:
                results.append({{
                    "vulnerability": {{
                        "name": f"Accessible database file: /database{{ext}}",
                        "severity": "critical",
                        "description": f"Database file /database{{ext}} is accessible and returns HTTP 200",
                        "location": base_path + "/database" + ext
                    }}
                }})
        except Exception:
            pass

    for ext in ARCHIVE_EXTENSIONS:
        try:
            resp = client.get(base_path + "/backup" + ext)
            if resp.status_code == 200:
                results.append({{
                    "vulnerability": {{
                        "name": f"Accessible archive file: /backup{{ext}}",
                        "severity": "high",
                        "description": f"Archive file /backup{{ext}} is accessible and returns HTTP 200",
                        "location": base_path + "/backup" + ext
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
