"""Subdomain takeover checker."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class SubdomainTakeoverChecker(ConfigMgmtTool):
    """Check for subdomain takeover vulnerabilities (WSTG-CONFIG-010)."""

    name = "subdomain_takeover_checker"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))

        script = f'''
import httpx
import json
import socket
import re

results = []
target_domain = "{target_url}"

CNAME_PATTERNS = {{
    "github": [r"github\.io", r"pages\.github\.com"],
    "heroku": [r"herokuapp\.com", r"herokudns\.com", r"herokussl\.com"],
    "aws_s3": [r"s3.*\.amazonaws\.com", r"\.s3-website"],
    "azure": [r"azurewebsites\.net", r"cloudapp\.net", r"trafficmanager\.net", r"azurefd\.net"],
    "shopify": [r"myshopify\.com"],
    "bitbucket": [r"bitbucket\.io"],
    "ghost": [r"ghost\.io"],
    "surge": [r"surge\.sh"],
    "netlify": [r"netlify\.app", r"netlify\.com"],
    "vercel": [r"vercel\.app", r"zeit\.co"],
    "firebase": [r"firebaseapp\.com"],
    "zendesk": [r"zendesk\.com"],
    "helpjuice": [r"helpjuice\.com"],
    "helpscout": [r"helpscoutdocs\.com"],
    "tumblr": [r"tumblr\.com"],
    "campaign_monitor": [r"cmail\.com"],
    "uservoice": [r"uservoice\.com"],
    "wp_engine": [r"wpengine\.com"],
    "pantheon": [r"pantheonsite\.io"],
}}

TAKEOVER_FINGERPRINTS = {{
    "github": ["There isn't a GitHub Pages site here", "For root URLs"],
    "heroku": ["No such app", "Heroku | Application not found", "herokucdn.com/error-pages/no-such-app.html"],
    "aws_s3": ["NoSuchBucket", "The specified bucket does not exist", "All access to this object has been disabled"],
    "azure": ["404 Web Site not found", "Web App not found"],
    "shopify": ["Sorry, this shop is closed", "Sorry, this store is currently unavailable"],
    "bitbucket": ["Repository not found", "The page you have requested has not been found"],
    "ghost": ["The thing you were looking for is no longer here", "Error: Page not found"],
    "surge": ["project not found", "surge.sh"],
    "netlify": ["Page not found", "Not Found - Request ID"],
    "vercel": ["The deployment could not be found on Vercel", "DEPLOYMENT_NOT_FOUND"],
    "firebase": ["There isn't a Firebase Hosting site here"],
    "zendesk": ["Help Center Closed"],
    "tumblr": ["There's nothing here"],
}}

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    subdomains_to_check = []

    if HAS_DNS:
        try:
            answers = dns.resolver.resolve(target_domain, 'A')
            subdomains_to_check.append(target_domain)
        except Exception:
            pass

        try:
            answers = dns.resolver.resolve(target_domain, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata.target).rstrip('.')
                subdomains_to_check.append(target_domain)
        except Exception:
            pass

        try:
            answers = dns.resolver.resolve(target_domain, 'MX')
            for rdata in answers:
                mx_domain = str(rdata.exchange).rstrip('.')
                subdomains_to_check.append(mx_domain)
        except Exception:
            pass

        try:
            answers = dns.resolver.resolve(target_domain, 'NS')
            for rdata in answers:
                ns_domain = str(rdata.target).rstrip('.')
                subdomains_to_check.append(ns_domain)
        except Exception:
            pass

        try:
            answers = dns.resolver.resolve(target_domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                for pattern_name, patterns in CNAME_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, txt):
                            subdomains_to_check.append(target_domain)
        except Exception:
            pass
    else:
        subdomains_to_check.append(target_domain)

    common_subdomains = [
        "www", "mail", "ftp", "blog", "dev", "staging", "test",
        "api", "app", "admin", "cdn", "static", "assets",
        "docs", "support", "help", "status", "portal",
    ]
    for sub in common_subdomains:
        subdomains_to_check.append(f"{{sub}}.{{target_domain}}")

    seen = set()
    for subdomain in subdomains_to_check:
        if subdomain in seen:
            continue
        seen.add(subdomain)

        try:
            ip = socket.gethostbyname(subdomain)
            if ip in ("127.0.0.1", "0.0.0.0"):
                continue
        except socket.gaierror:
            if HAS_DNS:
                try:
                    answers = dns.resolver.resolve(subdomain, 'CNAME')
                    for rdata in answers:
                        cname_target = str(rdata.target).rstrip('.')
                        for service, patterns in CNAME_PATTERNS.items():
                            for pattern in patterns:
                                if re.search(pattern, cname_target):
                                    results.append({{
                                        "vulnerability": {{
                                            "name": f"Potential subdomain takeover: {{subdomain}}",
                                            "severity": "high",
                                            "description": f"Subdomain {{subdomain}} has CNAME pointing to {{cname_target}} ({{service}}) but does not resolve to an IP",
                                            "location": subdomain
                                        }}
                                    }})
                except Exception:
                    pass
            continue

        if not subdomain.startswith("http"):
            for scheme in ["https://", "http://"]:
                try:
                    url = scheme + subdomain
                    resp = client.get(url)
                    body = resp.text
                    for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                        for fp in fingerprints:
                            if fp.lower() in body.lower():
                                results.append({{
                                    "vulnerability": {{
                                        "name": f"Confirmed subdomain takeover: {{subdomain}}",
                                        "severity": "critical",
                                        "description": f"Subdomain {{subdomain}} is vulnerable to takeover via {{service}} service",
                                        "location": url
                                    }}
                                }})
                                break
                except Exception:
                    continue
        else:
            try:
                resp = client.get(subdomain)
                body = resp.text
                for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                    for fp in fingerprints:
                        if fp.lower() in body.lower():
                            results.append({{
                                "vulnerability": {{
                                    "name": f"Confirmed subdomain takeover: {{subdomain}}",
                                    "severity": "critical",
                                    "description": f"Subdomain {{subdomain}} is vulnerable to takeover via {{service}} service",
                                    "location": subdomain
                                }}
                            }})
                            break
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
