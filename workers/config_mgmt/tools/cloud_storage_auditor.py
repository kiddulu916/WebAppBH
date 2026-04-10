"""Cloud storage configuration auditor."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class CloudStorageAuditor(ConfigMgmtTool):
    """Audit cloud storage configurations (WSTG-CONFIG-011)."""

    name = "cloud_storage_auditor"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"

S3_BUCKET_PATTERNS = [
    r"[a-z0-9][a-z0-9.\-]*\.s3\.amazonaws\.com",
    r"s3\.amazonaws\.com/[a-z0-9][a-z0-9.\-]*",
    r"[a-z0-9][a-z0-9.\-]*\.s3-website\.[a-z0-9\-]+\.amazonaws\.com",
]

AZURE_BLOB_PATTERNS = [
    r"[a-z0-9][a-z0-9\-]*\.blob\.core\.windows\.net",
    r"[a-z0-9][a-z0-9\-]*\.file\.core\.windows\.net",
    r"[a-z0-9][a-z0-9\-]*\.queue\.core\.windows\.net",
    r"[a-z0-9][a-z0-9\-]*\.table\.core\.windows\.net",
]

GCS_BUCKET_PATTERNS = [
    r"[a-z0-9][a-z0-9.\-_]*\.storage\.googleapis\.com",
    r"storage\.cloud\.google\.com/[a-z0-9][a-z0-9.\-_]*",
    r"storage\.googleapis\.com/[a-z0-9][a-z0-9.\-_]*",
]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    base_path = base_url.rstrip('/')

    try:
        resp = client.get(base_path)
        body = resp.text

        for pattern in S3_BUCKET_PATTERNS:
            matches = re.findall(pattern, body)
            for match in matches:
                bucket_url = match if "http" in match else f"https://{{match}}"
                try:
                    bucket_resp = client.get(bucket_url)
                    if bucket_resp.status_code == 200:
                        if "ListBucketResult" in bucket_resp.text or "<Contents>" in bucket_resp.text:
                            results.append({{
                                "vulnerability": {{
                                    "name": f"Publicly accessible S3 bucket: {{match}}",
                                    "severity": "critical",
                                    "description": f"S3 bucket {{match}} is publicly accessible and allows listing",
                                    "location": bucket_url
                                }}
                            }})
                        else:
                            results.append({{
                                "observation": {{
                                    "type": "cloud_storage",
                                    "value": f"s3_bucket_found: {{match}}",
                                    "details": {{
                                        "location": bucket_url,
                                        "status": bucket_resp.status_code
                                    }}
                                }}
                            }})
                    elif bucket_resp.status_code == 403:
                        results.append({{
                            "observation": {{
                                "type": "cloud_storage",
                                "value": f"s3_bucket_restricted: {{match}}",
                                "details": {{
                                    "location": bucket_url,
                                    "status": bucket_resp.status_code,
                                    "note": "Bucket exists but access is restricted"
                                }}
                            }}
                        }})
                    elif bucket_resp.status_code == 404:
                        results.append({{
                            "observation": {{
                                "type": "cloud_storage",
                                "value": f"s3_bucket_not_found: {{match}}",
                                "details": {{
                                    "location": bucket_url,
                                    "note": "S3 bucket does not exist - potential takeover"
                                }}
                            }}
                        }})
                except Exception:
                    pass

        for pattern in AZURE_BLOB_PATTERNS:
            matches = re.findall(pattern, body)
            for match in matches:
                blob_url = match if "http" in match else f"https://{{match}}"
                try:
                    blob_resp = client.get(blob_url)
                    if blob_resp.status_code == 200:
                        if "EnumerationResults" in blob_resp.text:
                            results.append({{
                                "vulnerability": {{
                                    "name": f"Publicly accessible Azure Blob Storage: {{match}}",
                                    "severity": "critical",
                                    "description": f"Azure Blob Storage {{match}} is publicly accessible",
                                    "location": blob_url
                                }}
                            }})
                        else:
                            results.append({{
                                "observation": {{
                                    "type": "cloud_storage",
                                    "value": f"azure_blob_found: {{match}}",
                                    "details": {{
                                        "location": blob_url,
                                        "status": blob_resp.status_code
                                    }}
                                }}
                            }})
                except Exception:
                    pass

        for pattern in GCS_BUCKET_PATTERNS:
            matches = re.findall(pattern, body)
            for match in matches:
                gcs_url = match if "http" in match else f"https://{{match}}"
                try:
                    gcs_resp = client.get(gcs_url)
                    if gcs_resp.status_code == 200:
                        if "ListBucketResult" in gcs_resp.text:
                            results.append({{
                                "vulnerability": {{
                                    "name": f"Publicly accessible GCS bucket: {{match}}",
                                    "severity": "critical",
                                    "description": f"Google Cloud Storage bucket {{match}} is publicly accessible",
                                    "location": gcs_url
                                }}
                            }})
                        else:
                            results.append({{
                                "observation": {{
                                    "type": "cloud_storage",
                                    "value": f"gcs_bucket_found: {{match}}",
                                    "details": {{
                                        "location": gcs_url,
                                        "status": gcs_resp.status_code
                                    }}
                                }}
                            }})
                except Exception:
                    pass

    except Exception:
        pass

    try:
        resp = client.get(base_path + "/robots.txt")
        if resp.status_code == 200:
            for pattern in S3_BUCKET_PATTERNS + AZURE_BLOB_PATTERNS + GCS_BUCKET_PATTERNS:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    results.append({{
                        "observation": {{
                            "type": "cloud_storage",
                            "value": f"cloud_storage_in_robots: {{match}}",
                            "details": {{"source": "robots.txt"}}
                        }}
                    }})
    except Exception:
        pass

    try:
        resp = client.get(base_path + "/sitemap.xml")
        if resp.status_code == 200:
            for pattern in S3_BUCKET_PATTERNS + AZURE_BLOB_PATTERNS + GCS_BUCKET_PATTERNS:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    results.append({{
                        "observation": {{
                            "type": "cloud_storage",
                            "value": f"cloud_storage_in_sitemap: {{match}}",
                            "details": {{"source": "sitemap.xml"}}
                        }}
                    }})
    except Exception:
        pass

    js_paths = ["/", "/static/js/", "/assets/js/", "/js/"]
    for js_path in js_paths:
        try:
            resp = client.get(base_path + js_path)
            if resp.status_code == 200 and "javascript" in resp.headers.get("content-type", ""):
                for pattern in S3_BUCKET_PATTERNS + AZURE_BLOB_PATTERNS + GCS_BUCKET_PATTERNS:
                    matches = re.findall(pattern, resp.text)
                    for match in matches:
                        results.append({{
                            "observation": {{
                                "type": "cloud_storage",
                                "value": f"cloud_storage_in_js: {{match}}",
                                "details": {{"source": js_path}}
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
