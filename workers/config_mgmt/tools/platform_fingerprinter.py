"""Platform configuration testing tool — WSTG-CONF-02.

Covers:
  - Server/framework identification via HTTP headers, cookies, and favicon hashes
  - Version disclosure in Server / X-Powered-By headers  (vulnerability, low)
  - Debug mode indicators in response headers and known debug paths (vulnerability, high)
  - Default and sample files left on the server  (vulnerability, medium/high)
  - Platform status and info pages exposed  (vulnerability, medium/high)
  - Stack trace / exception disclosure in error pages  (vulnerability, medium)
"""

import json as _json

from workers.config_mgmt.base_tool import ConfigMgmtTool


class PlatformFingerprinter(ConfigMgmtTool):
    """Test application platform configuration per WSTG-CONF-02."""

    name = "platform_fingerprinter"

    def build_command(self, target, headers=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = (
            target_url
            if target_url.startswith(("http://", "https://"))
            else f"https://{target_url}"
        )
        base_url_json = _json.dumps(base_url)
        headers_json = _json.dumps(headers or {})

        script = f"""
import httpx, json, hashlib, re

results = []
base_url = {base_url_json}
custom_headers = json.loads({_json.dumps(headers_json)})

# ──────────────────────────────────────────────────────────────────────────────
# 1. Known server/framework fingerprint maps
# ──────────────────────────────────────────────────────────────────────────────
SERVER_MAP = {{
    "apache":     "Apache HTTP Server",
    "nginx":      "Nginx",
    "iis":        "Microsoft IIS",
    "openresty":  "OpenResty",
    "cloudflare": "Cloudflare",
    "gunicorn":   "Gunicorn",
    "uvicorn":    "Uvicorn",
    "tornado":    "Tornado",
    "tomcat":     "Apache Tomcat",
    "jetty":      "Eclipse Jetty",
    "lighttpd":   "Lighttpd",
    "caddy":      "Caddy",
}}

FRAMEWORK_SIGNALS = {{
    "x-powered-by":   {{"express": "Express.js", "asp.net": "ASP.NET", "php": "PHP", "sinatra": "Sinatra"}},
    "x-aspnet-version": {{"*": "ASP.NET"}},
    "x-generator":    {{"drupal": "Drupal", "wordpress": "WordPress", "joomla": "Joomla", "ghost": "Ghost"}},
    "x-django":       {{"*": "Django"}},
    "x-rails":        {{"*": "Ruby on Rails"}},
    "x-spring":       {{"*": "Spring Framework"}},
    "server":         {{
        "django": "Django", "rails": "Ruby on Rails", "flask": "Flask",
        "fastapi": "FastAPI", "tornado": "Tornado", "gunicorn": "Gunicorn (Python)",
        "uvicorn": "Uvicorn (Python)", "werkzeug": "Werkzeug (Python)", "plack": "Perl Plack",
    }},
}}

# Matches "Product/1.2.3" or "Product/1.2" anywhere in a header value.
VERSION_RE = re.compile(r'[\\w\\-]+/(\\d+\\.\\d+[.\\d]*)', re.IGNORECASE)

# ──────────────────────────────────────────────────────────────────────────────
# 2. Debug mode indicators
# ──────────────────────────────────────────────────────────────────────────────
DEBUG_RESPONSE_HEADERS = [
    "x-debug-token", "x-debug", "x-debug-token-link",
    "x-debug-info", "x-debug-mode",
]

DEBUG_PATHS = [
    "/_debug", "/__debug__", "/debug", "/debug/toolbar",
    "/debug/default/view", "/?debug=true",
    "/?XDEBUG_SESSION_START=1", "/phpdebug.php",
    "/actuator/env", "/actuator/beans",
]

# ──────────────────────────────────────────────────────────────────────────────
# 3. Platform default / sample files (WSTG-CONF-02 §3.1)
# ──────────────────────────────────────────────────────────────────────────────
DEFAULT_FILES = [
    # PHP
    ("/phpinfo.php",            "PHP info page",               "high"),
    ("/info.php",               "PHP info page",               "high"),
    ("/test.php",               "PHP test file",               "medium"),
    ("/phpmyadmin/",            "phpMyAdmin",                  "high"),
    ("/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000", "PHP credits page", "medium"),
    # Apache
    ("/server-status",          "Apache server-status",        "high"),
    ("/server-info",            "Apache server-info",          "high"),
    ("/icons/apache_pb.gif",    "Apache default icons dir",    "low"),
    ("/manual/",                "Apache manual",               "medium"),
    # Nginx
    ("/nginx_status",           "Nginx status page",           "high"),
    # IIS
    ("/iisstart.htm",           "IIS default start page",      "medium"),
    ("/localstart.asp",         "IIS local start page",        "medium"),
    ("/_vti_bin/shtml.exe",     "IIS FrontPage extensions",    "high"),
    ("/_private/",              "IIS FrontPage private dir",   "medium"),
    ("/scripts/iisadmin/",      "IIS admin scripts",           "high"),
    # Tomcat
    ("/examples/jsp/",          "Tomcat JSP examples",         "medium"),
    ("/examples/servlets/",     "Tomcat servlet examples",     "medium"),
    ("/manager/html",           "Tomcat manager console",      "high"),
    ("/host-manager/html",      "Tomcat host-manager console", "high"),
    # JBoss / WildFly
    ("/web-console/",           "JBoss web console",           "high"),
    ("/jmx-console/",           "JBoss JMX console",           "high"),
    ("/jboss-net/services/",    "JBoss .NET services",         "high"),
    # WebSphere / WebLogic
    ("/ibm/console/",           "WebSphere admin console",     "high"),
    ("/console/login/LoginForm.jsp", "WebLogic admin console", "high"),
    # Spring Boot Actuator
    ("/actuator",               "Spring Boot Actuator root",   "high"),
    ("/actuator/health",        "Spring Boot Actuator health", "medium"),
    # Generic leftovers
    ("/test/",   "Test directory",   "medium"),
    ("/temp/",   "Temp directory",   "medium"),
    ("/demo/",   "Demo directory",   "medium"),
    ("/sample/", "Sample directory", "medium"),
]

# ──────────────────────────────────────────────────────────────────────────────
# 4. Favicon fingerprints
# ──────────────────────────────────────────────────────────────────────────────
FAVICON_HASHES = {{
    "/favicon.ico": {{
        "-1587136868": "Apache",
        "116323821":   "Nginx",
        "81586352":    "IIS",
        "-1277814690": "Django",
        "246145559":   "Flask",
        "192998300":   "Ruby on Rails",
        "1747282678":  "Tomcat",
    }},
}}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def vuln(name, severity, description, location=""):
    v = {{"vulnerability": {{
        "name": name, "severity": severity,
        "description": description, "section_id": "WSTG-CONF-02",
    }}}}
    if location:
        v["vulnerability"]["location"] = location
    return v

def obs(obs_type, value, details=None):
    return {{"observation": {{"type": obs_type, "value": value, "details": details or {{}}}}}}

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
try:
    client = httpx.Client(
        follow_redirects=True, timeout=10, verify=False, headers=custom_headers
    )

    # ── Base request ──────────────────────────────────────────────────────────
    resp = client.get(base_url)
    hl = {{k.lower(): v for k, v in resp.headers.items()}}

    # ── 1a. Server software detection ─────────────────────────────────────────
    server_header = hl.get("server", "")
    if server_header:
        detected = [name for key, name in SERVER_MAP.items() if key in server_header.lower()]
        if detected:
            results.append(obs("server_software", ", ".join(detected), {{"server_header": server_header}}))

        # Version string in Server header → information disclosure vulnerability
        if VERSION_RE.search(server_header):
            results.append(vuln(
                "Server version disclosed in Server header",
                "low",
                f"The Server header exposes a product version string: {{server_header}}. "
                "Remove or sanitise the Server header in production.",
                base_url,
            ))

    # ── 1b. X-Powered-By version disclosure ───────────────────────────────────
    powered_by = hl.get("x-powered-by", "")
    if powered_by:
        if VERSION_RE.search(powered_by):
            results.append(vuln(
                "Technology version disclosed in X-Powered-By header",
                "low",
                f"X-Powered-By exposes a version: {{powered_by}}. "
                "Remove this header or strip the version component.",
                base_url,
            ))

    # ── 1c. Framework detection via response headers ───────────────────────────
    for header_name, signals in FRAMEWORK_SIGNALS.items():
        hval = hl.get(header_name, "")
        if hval:
            for key, framework in signals.items():
                if key == "*" or key in hval.lower():
                    results.append(obs("framework_detected", framework,
                                       {{"header": header_name, "header_value": hval}}))
                    break

    # ── 1d. Collect technology-revealing headers ───────────────────────────────
    tech_headers = {{k: v for k, v in resp.headers.items()
                     if k.lower().startswith("x-") or k.lower() in ("server", "via")}}
    if tech_headers:
        results.append(obs("technology_headers", str(list(tech_headers.keys())), tech_headers))

    # ── 1e. Cookie-based framework fingerprinting ──────────────────────────────
    set_cookie = hl.get("set-cookie", "")
    if "jsessionid" in set_cookie.lower():
        results.append(obs("language_detected", "Java", {{"indicator": "JSESSIONID cookie"}}))
    elif "phpsessid" in set_cookie.lower():
        results.append(obs("language_detected", "PHP", {{"indicator": "PHPSESSID cookie"}}))
    elif "csrftoken" in set_cookie.lower() and "sessionid" in set_cookie.lower():
        results.append(obs("framework_detected", "Django", {{"indicator": "Django session cookies"}}))

    # ── 2. Debug mode detection ────────────────────────────────────────────────
    for dh in DEBUG_RESPONSE_HEADERS:
        if dh in hl:
            results.append(vuln(
                f"Debug header present: {{dh}}",
                "high",
                f"The response includes '{{dh}}: {{hl[dh]}}', indicating debug mode is active. "
                "Debug mode must be disabled in production environments.",
                base_url,
            ))

    for path in DEBUG_PATHS:
        try:
            dr = client.get(base_url.rstrip("/") + path)
            if dr.status_code == 200 and len(dr.text) > 100:
                results.append(vuln(
                    "Debug endpoint accessible",
                    "high",
                    f"{{path}} returned HTTP 200 with content. Debug endpoints expose internal "
                    "application state and must be disabled or restricted in production.",
                    base_url.rstrip("/") + path,
                ))
        except Exception:
            pass

    # ── 3. Default / sample files (WSTG-CONF-02 §3.1) ─────────────────────────
    for path, label, severity in DEFAULT_FILES:
        try:
            dr = client.get(base_url.rstrip("/") + path)
            if dr.status_code == 200 and len(dr.text) > 50:
                results.append(vuln(
                    f"Default/sample file accessible: {{label}}",
                    severity,
                    f"{{path}} returned HTTP 200. {{label}} should be removed or restricted "
                    "before deploying to production.",
                    base_url.rstrip("/") + path,
                ))
        except Exception:
            pass

    # ── 4. Error page tech disclosure and stack trace ─────────────────────────
    TECH_INDICATORS = {{
        "apache": "Apache HTTP Server", "nginx": "Nginx", "iis": "Microsoft IIS",
        "tomcat": "Apache Tomcat", "php": "PHP", "python": "Python",
        "django": "Django", "flask": "Flask", "rails": "Ruby on Rails",
        "express": "Express.js", "node.js": "Node.js", "java": "Java", "asp.net": "ASP.NET",
    }}
    for ep in ["/nonexistent_xyz_12345_conf02", "/.env.bak"]:
        try:
            er = client.get(base_url.rstrip("/") + ep)
            bl = er.text.lower()
            for indicator, tech in TECH_INDICATORS.items():
                if indicator in bl:
                    results.append(obs("error_page_disclosure", tech,
                                       {{"page": ep, "status": er.status_code}}))
                    break
            if any(kw in bl for kw in ("stack trace", "traceback", "exception in")):
                results.append(vuln(
                    "Stack trace / exception disclosure in error page",
                    "medium",
                    f"The error page at {{ep}} exposes a stack trace or exception details. "
                    "Configure the application to show generic error pages in production.",
                    base_url.rstrip("/") + ep,
                ))
        except Exception:
            pass

    # ── 5. Favicon fingerprinting ──────────────────────────────────────────────
    for favicon_path, hashes in FAVICON_HASHES.items():
        try:
            fr = client.get(base_url.rstrip("/") + favicon_path)
            if fr.status_code == 200:
                fh = hashlib.md5(fr.content).hexdigest()
                fh_int = int(fh[:8], 16)
                if fh_int > 0x7FFFFFFF:
                    fh_int -= 0x100000000
                for hash_val, tech in hashes.items():
                    if hash_val == str(fh_int):
                        results.append(obs("favicon_fingerprint", tech,
                                           {{"path": favicon_path, "md5_hash": fh}}))
                        break
        except Exception:
            pass

    client.close()

except Exception as e:
    results.append(obs("test_error", str(e), {{"error": str(e)}}))

print(json.dumps(results))
"""
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        try:
            return _json.loads(stdout.strip())
        except (ValueError, _json.JSONDecodeError):
            return []
