"""Backup file discovery tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class BackupFileFinder(ConfigMgmtTool):
    """Find backup and unlinked files (WSTG-CONFIG-004)."""

    name = "backup_file_finder"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"

BACKUP_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.svn/entries",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.bak",
    "/.env.old",
    "/.DS_Store",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/web.config.bak",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/.well-known/robots.txt",
]

EDITOR_BACKUPS = [
    "/index.php~",
    "/index.php.bak",
    "/index.php.old",
    "/index.php.orig",
    "/index.php.swp",
    "/index.php.save",
    "/config.php.bak",
    "/config.php.old",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/database.yml.bak",
    "/settings.py.bak",
    "/settings.py.old",
]

DEPLOYMENT_ARTIFACTS = [
    "/.dockerignore",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Makefile",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/composer.json",
    "/composer.lock",
    "/pom.xml",
    "/build.gradle",
    "/Cargo.toml",
    "/go.mod",
    "/go.sum",
]

DB_DUMPS = [
    "/dump.sql",
    "/dump.sql.gz",
    "/backup.sql",
    "/backup.sql.gz",
    "/database.sql",
    "/database.sql.gz",
    "/db.sql",
    "/db.sql.gz",
    "/data.sql",
    "/data.sql.gz",
    "/export.sql",
    "/export.sql.gz",
    "/mysqldump.sql",
    "/mysqldump.sql.gz",
    "/pg_dump.sql",
    "/pg_dump.sql.gz",
]

CONFIG_BACKUPS = [
    "/config.bak",
    "/config.old",
    "/config.xml.bak",
    "/config.yml.bak",
    "/config.yaml.bak",
    "/config.ini.bak",
    "/config.json.bak",
    "/application.yml.bak",
    "/application.properties.bak",
    "/settings.json.bak",
    "/settings.xml.bak",
]

SOURCE_REPOS = [
    "/.git/",
    "/.svn/",
    "/.hg/",
    "/.bzr/",
]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    base_path = base_url.rstrip('/')

    all_paths = BACKUP_PATHS + EDITOR_BACKUPS + DEPLOYMENT_ARTIFACTS + DB_DUMPS + CONFIG_BACKUPS

    for path in all_paths:
        try:
            resp = client.get(base_path + path)
            if resp.status_code == 200 and len(resp.text) > 0:
                severity = "high"
                if path in DB_DUMPS:
                    severity = "critical"
                elif path in ["/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production"]:
                    severity = "critical"
                elif path in ["/.htpasswd", "/.env.bak", "/.env.old"]:
                    severity = "critical"
                elif path in CONFIG_BACKUPS or path in EDITOR_BACKUPS:
                    severity = "medium"

                results.append({{
                    "vulnerability": {{
                        "name": f"Exposed backup/sensitive file: {{path}}",
                        "severity": severity,
                        "description": f"File {{path}} is accessible and returns HTTP 200 with content",
                        "location": base_path + path
                    }}
                }})
            elif resp.status_code in (301, 302, 307, 308):
                results.append({{
                    "observation": {{
                        "type": "backup_redirect",
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

    for path in SOURCE_REPOS:
        try:
            resp = client.get(base_path + path)
            if resp.status_code in (200, 403):
                results.append({{
                    "vulnerability": {{
                        "name": f"Exposed source control directory: {{path}}",
                        "severity": "critical",
                        "description": f"Source control directory {{path}} exists (HTTP {{resp.status_code}})",
                        "location": base_path + path
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
