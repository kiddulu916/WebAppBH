"""Platform fingerprinting tool."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class PlatformFingerprinter(ConfigMgmtTool):
    """Fingerprint web server and application platform (WSTG-CONFIG-002)."""

    name = "platform_fingerprinter"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import hashlib

results = []
base_url = "{base_url}"

SERVER_MAP = {{
    "apache": "Apache HTTP Server",
    "nginx": "Nginx",
    "iis": "Microsoft IIS",
    "openresty": "OpenResty",
    "cloudflare": "Cloudflare",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "tornado": "Tornado",
    "tomcat": "Apache Tomcat",
    "jetty": "Eclipse Jetty",
    "lighttpd": "Lighttpd",
    "caddy": "Caddy",
}}

FRAMEWORK_SIGNALS = {{
    "x-powered-by": {{
        "express": "Express.js",
        "asp.net": "ASP.NET",
        "php": "PHP",
        "sinatra": "Sinatra",
    }},
    "x-aspnet-version": {{
        "*": "ASP.NET"
    }},
    "x-generator": {{
        "drupal": "Drupal",
        "wordpress": "WordPress",
        "joomla": "Joomla",
        "ghost": "Ghost",
    }},
    "x-django": {{
        "*": "Django"
    }},
    "x-rails": {{
        "*": "Ruby on Rails"
    }},
    "x-spring": {{
        "*": "Spring Framework"
    }},
    "server": {{
        "django": "Django",
        "rails": "Ruby on Rails",
        "flask": "Flask",
        "fastapi": "FastAPI",
        "tornado": "Tornado",
        "gunicorn": "Gunicorn (Python)",
        "uvicorn": "Uvicorn (Python)",
        "werkzeug": "Werkzeug (Python)",
        "plack": "Perl Plack",
    }}
}}

FAVICON_HASHES = {{
    "/favicon.ico": {{
        "-1587136868": "Apache",
        "116323821": "Nginx",
        "81586352": "IIS",
        "-1277814690": "Django",
        "246145559": "Flask",
        "192998300": "Ruby on Rails",
        "1747282678": "Tomcat",
    }},
    "/static/favicon.ico": {{
        "-1587136868": "Apache",
        "116323821": "Nginx",
    }},
}}

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    resp = client.get(base_url)
    headers_lower = {{k.lower(): v for k, v in resp.headers.items()}}

    server_header = headers_lower.get("server", "")
    if server_header:
        detected = []
        for key, name in SERVER_MAP.items():
            if key in server_header.lower():
                detected.append(name)
        if detected:
            results.append({{
                "observation": {{
                    "type": "server_software",
                    "value": ", ".join(detected),
                    "details": {{
                        "server_header": server_header
                    }}
                }}
            }})

    for header_name, signals in FRAMEWORK_SIGNALS.items():
        header_value = headers_lower.get(header_name, "")
        if header_value:
            for key, framework in signals.items():
                if key == "*" or key in header_value.lower():
                    results.append({{
                        "observation": {{
                            "type": "framework_detected",
                            "value": framework,
                            "details": {{
                                "header": header_name,
                                "header_value": header_value
                            }}
                        }}
                    }})
                    break

    set_cookie = headers_lower.get("set-cookie", "")
    if "jsessionid" in set_cookie.lower():
        results.append({{
            "observation": {{
                "type": "language_detected",
                "value": "Java",
                "details": {{"indicator": "JSESSIONID cookie"}}
            }}
        }})
    elif "phpsessid" in set_cookie.lower():
        results.append({{
            "observation": {{
                "type": "language_detected",
                "value": "PHP",
                "details": {{"indicator": "PHPSESSID cookie"}}
            }}
        }})
    elif "csrftoken" in set_cookie.lower() and "sessionid" in set_cookie.lower():
        results.append({{
            "observation": {{
                "type": "framework_detected",
                "value": "Django",
                "details": {{"indicator": "Django session cookies"}}
            }}
        }})

    error_pages = ["/nonexistent_page_xyz_12345", "/.env.bak", "/this-does-not-exist"]
    for ep in error_pages:
        try:
            err_resp = client.get(base_url.rstrip('/') + ep)
            if err_resp.status_code not in (404, 301, 302, 403):
                body_lower = err_resp.text.lower()
                tech_indicators = {{
                    "apache": "Apache HTTP Server",
                    "nginx": "Nginx",
                    "iis": "Microsoft IIS",
                    "tomcat": "Apache Tomcat",
                    "php": "PHP",
                    "python": "Python",
                    "django": "Django",
                    "flask": "Flask",
                    "rails": "Ruby on Rails",
                    "sinatra": "Sinatra",
                    "express": "Express.js",
                    "node.js": "Node.js",
                    "java": "Java",
                    "asp.net": "ASP.NET",
                }}
                for indicator, tech in tech_indicators.items():
                    if indicator in body_lower:
                        results.append({{
                            "observation": {{
                                "type": "error_page_disclosure",
                                "value": tech,
                                "details": {{
                                    "page": ep,
                                    "status": err_resp.status_code,
                                    "indicator": indicator
                                }}
                            }}
                        }})
                        break
                if "stack trace" in body_lower or "traceback" in body_lower:
                    results.append({{
                        "vulnerability": {{
                            "name": "Stack trace disclosure in error page",
                            "severity": "medium",
                            "description": f"Error page at {{ep}} exposes stack trace or technical details",
                            "location": base_url.rstrip('/') + ep
                        }}
                    }})
        except Exception:
            pass

    for favicon_path, hashes in FAVICON_HASHES.items():
        try:
            fav_resp = client.get(base_url.rstrip('/') + favicon_path)
            if fav_resp.status_code == 200:
                fh = hashlib.md5(fav_resp.content).hexdigest()
                fh_int = int(fh[:8], 16)
                if fh_int > 0x7FFFFFFF:
                    fh_int -= 0x100000000
                for hash_val, tech in hashes.items():
                    if hash_val == str(fh_int):
                        results.append({{
                            "observation": {{
                                "type": "favicon_fingerprint",
                                "value": tech,
                                "details": {{
                                    "path": favicon_path,
                                    "md5_hash": fh
                                }}
                            }}
                        }})
                        break
        except Exception:
            pass

    tech_headers = {{}}
    for k, v in resp.headers.items():
        kl = k.lower()
        if kl.startswith("x-") or kl in ("server", "via", "x-powered-by"):
            tech_headers[k] = v
    if tech_headers:
        results.append({{
            "observation": {{
                "type": "technology_headers",
                "value": str(list(tech_headers.keys())),
                "details": tech_headers
            }}
        }})

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
