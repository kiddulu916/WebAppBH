"""Network configuration testing: server version detection and CVE lookup (WSTG-CONF-01)."""

import json

from workers.config_mgmt.base_tool import ConfigMgmtTool


class NetworkConfigTester(ConfigMgmtTool):
    """Extract server version strings from HTTP headers and cross-reference NVD CVE database."""

    name = "network_config_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, "target_value", str(target))
        base_url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"

        script = f"""
import httpx, json, re, sys, time
import os as _os

results = []
base_url = {json.dumps(base_url)}

VERSION_HEADERS = [
    "server", "x-powered-by", "x-generator",
    "x-aspnet-version", "x-runtime", "x-served-by",
]

def extract_product_version(value):
    m = re.match(r'^([A-Za-z][\\w.-]*)[\\/]?(\\d[\\d.]+)?', value.strip())
    if m:
        product = m.group(1).lower()
        version = m.group(2) or ""
        return product, version
    return None, None

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    try:
        resp = client.head(base_url)
        if resp.status_code >= 400:
            resp = client.get(base_url)
    except Exception:
        resp = client.get(base_url)

    detected = []
    for h in VERSION_HEADERS:
        value = resp.headers.get(h, "")
        if not value:
            continue
        product, version = extract_product_version(value)
        if not product or not version:
            continue
        detected.append({{"header": h, "raw_value": value, "product": product, "version": version}})
        results.append({{"vulnerability": {{
            "name": f"Server software version disclosed: {{value}}",
            "severity": "low",
            "description": (
                f"The server disclosed its software version in the {{h}} header: {{value}}. "
                "Version disclosure enables targeted exploitation of known CVEs."
            ),
            "location": base_url,
            "section_id": "WSTG-CONF-01",
        }}}})
    client.close()

    nvd_api_key = _os.environ.get("NVD_API_KEY", "")
    nvd_headers = {{"Accept": "application/json"}}
    if nvd_api_key:
        nvd_headers["apiKey"] = nvd_api_key

    nvd = httpx.Client(timeout=15)
    for item in detected:
        if not item["version"]:
            continue
        keyword = item["product"] + " " + item["version"]
        try:
            r = nvd.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={{"keywordSearch": keyword, "resultsPerPage": 10}},
                headers=nvd_headers,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            for cve_item in data.get("vulnerabilities", []):
                cve = cve_item.get("cve", {{}})
                cve_id = cve.get("id", "")
                metrics = cve.get("metrics", {{}})
                base_score = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        base_score = entries[0].get("cvssData", {{}}).get("baseScore")
                        break
                if base_score is None:
                    continue
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                if base_score >= 7.0:
                    severity = "critical" if base_score >= 9.0 else "high"
                    results.append({{"vulnerability": {{
                        "name": f"{{cve_id}}: {{item['product']}} {{item['version']}}",
                        "severity": severity,
                        "description": desc,
                        "location": base_url,
                        "section_id": "WSTG-CONF-01",
                    }}}})
                else:
                    results.append({{"vulnerability": {{
                        "name": f"{{cve_id}}: {{item['product']}} {{item['version']}} (low CVSS {{base_score}})",
                        "severity": "low",
                        "description": desc,
                        "location": base_url,
                        "section_id": "WSTG-CONF-01",
                    }}}})
        except Exception as e:
            import sys
            print(f"[network_config_tester] probe failed: {{e}}", file=sys.stderr)
        time.sleep(0.6)
    nvd.close()

except Exception:
    pass

print(json.dumps(results))
"""
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        try:
            return json.loads(stdout.strip())
        except (ValueError, json.JSONDecodeError):
            return []
