"""IDOR testing tool."""

from workers.authorization.base_tool import AuthorizationTool
from workers.authorization.concurrency import WeightClass


class IdorTester(AuthorizationTool):
    """Test for Insecure Direct Object Reference vulnerabilities (WSTG-AUTHZ-004)."""

    name = "idor_tester"
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
import uuid

results = []
base_url = "{base_url}"
credentials = json.loads('{cred_json}') if '{cred_json}' != "None" else None

resource_patterns = [
    "/profile/{{id}}",
    "/profile/{{id}}/",
    "/account/{{id}}",
    "/account/{{id}}/",
    "/users/{{id}}",
    "/users/{{id}}/",
    "/user/{{id}}",
    "/user/{{id}}/",
    "/api/users/{{id}}",
    "/api/users/{{id}}/",
    "/api/user/{{id}}",
    "/api/user/{{id}}/",
    "/api/profile/{{id}}",
    "/api/account/{{id}}",
    "/api/customers/{{id}}",
    "/api/customers/{{id}}/",
    "/orders/{{id}}",
    "/orders/{{id}}/",
    "/api/orders/{{id}}",
    "/api/orders/{{id}}/",
    "/order/{{id}}",
    "/api/transactions/{{id}}",
    "/api/payments/{{id}}",
    "/api/invoices/{{id}}",
    "/documents/{{id}}",
    "/documents/{{id}}/",
    "/api/documents/{{id}}",
    "/api/files/{{id}}",
    "/files/{{id}}",
    "/api/records/{{id}}",
    "/records/{{id}}",
    "/api/items/{{id}}",
    "/items/{{id}}",
    "/api/products/{{id}}",
    "/products/{{id}}",
]

query_param_patterns = [
    "/profile?id={{id}}",
    "/user?id={{id}}",
    "/account?id={{id}}",
    "/api/user?id={{id}}",
    "/api/profile?id={{id}}",
    "/api/account?id={{id}}",
    "/api/data?id={{id}}",
    "/api/record?id={{id}}",
    "/api/item?id={{id}}",
    "/api/document?id={{id}}",
    "/download?file_id={{id}}",
    "/file?id={{id}}",
    "/document?id={{id}}",
    "/api/download?id={{id}}",
    "/api/file?id={{id}}",
    "/view?id={{id}}",
    "/api/view?id={{id}}",
    "/get?id={{id}}",
    "/api/get?id={{id}}",
    "/api/resource?id={{id}}",
]

numeric_ids = ["1", "2", "3", "100", "999", "1000", "10000"]
uuid_ids = [
    str(uuid.UUID(int=1)),
    str(uuid.UUID(int=2)),
    str(uuid.UUID(int=3)),
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
]

methods_to_test = ["GET", "PUT", "DELETE", "PATCH"]

def check_idor(url, resp, test_type, id_info, method="GET"):
    idor_found = False
    severity = "medium"
    reason = ""

    if resp.status_code == 200:
        text_lower = resp.text.lower()
        data_indicators = [
            ("email", "email address exposed"),
            ("password", "password field exposed"),
            ("ssn", "SSN exposed"),
            ("social_security", "SSN exposed"),
            ("credit_card", "credit card data exposed"),
            ("phone", "phone number exposed"),
            ("address", "address data exposed"),
            ("dob", "date of birth exposed"),
            ("date_of_birth", "date of birth exposed"),
            ("name", "personal name exposed"),
            ("username", "username exposed"),
            ("user_id", "user ID exposed"),
            ("account", "account data exposed"),
            ("balance", "financial balance exposed"),
            ("salary", "salary data exposed"),
        ]

        for indicator, desc in data_indicators:
            if indicator in text_lower:
                idor_found = True
                reason = desc
                severity = "high"
                break

        if not idor_found and len(resp.text) > 50:
            try:
                data = resp.json()
                if isinstance(data, dict):
                    sensitive_keys = ["email", "password", "ssn", "phone", "address", "balance", "salary", "credit_card"]
                    for key in sensitive_keys:
                        if key in data:
                            idor_found = True
                            reason = f"sensitive key '{{key}}' in JSON response"
                            severity = "high"
                            break
            except Exception:
                pass

        if not idor_found:
            idor_found = True
            reason = "resource accessible with modified ID"
            severity = "medium"

    if idor_found:
        results.append({{
            "title": f"IDOR vulnerability - {{test_type}}",
            "description": f"Insecure direct object reference via {{test_type}}: {{url}}",
            "severity": severity,
            "data": {{
                "url": url,
                "test_type": test_type,
                "id_info": id_info,
                "method": method,
                "reason": reason,
                "status_code": resp.status_code,
                "content_length": len(resp.text)
            }}
        }})

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    auth_headers = {{"User-Agent": "WebAppBH-Authorization-Tester"}}
    if credentials and credentials.get("token"):
        auth_headers["Authorization"] = "Bearer " + credentials["token"]

    for pattern in resource_patterns:
        for test_id in numeric_ids[:3]:
            url = base_url + pattern.format(id=test_id)

            for method in methods_to_test:
                try:
                    if method == "GET":
                        resp = client.get(url, headers=auth_headers)
                    elif method == "DELETE":
                        resp = client.delete(url, headers=auth_headers)
                    else:
                        resp = client.request(method, url, headers=auth_headers, json={{"test": True}})

                    check_idor(url, resp, f"numeric_id_{{method}}", test_id, method)
                except Exception:
                    pass

        for test_id in uuid_ids[:2]:
            url = base_url + pattern.format(id=test_id)
            try:
                resp = client.get(url, headers=auth_headers)
                check_idor(url, resp, "uuid_enumeration", test_id)
            except Exception:
                pass

    for pattern in query_param_patterns:
        for test_id in numeric_ids[:3]:
            url = base_url + pattern.format(id=test_id)
            try:
                resp = client.get(url, headers=auth_headers)
                check_idor(url, resp, "query_param_idor", test_id)
            except Exception:
                pass

    for method in methods_to_test:
        for test_id in numeric_ids[:2]:
            url = base_url + f"/api/users/{{test_id}}"
            try:
                if method == "GET":
                    resp = client.get(url, headers=auth_headers)
                elif method == "DELETE":
                    resp = client.delete(url, headers=auth_headers)
                else:
                    resp = client.request(method, url, headers=auth_headers, json={{"role": "user"}})

                check_idor(url, resp, f"http_method_{{method}}", test_id, method)
            except Exception:
                pass

    filename_patterns = [
        "/download?filename=user{{id}}.doc",
        "/files/user{{id}}.doc",
        "/documents/user{{id}}.pdf",
        "/api/files/user{{id}}.txt",
        "/uploads/user{{id}}.jpg",
        "/api/documents/user{{id}}.pdf",
    ]

    for pattern in filename_patterns:
        for test_id in ["1", "2"]:
            url = base_url + pattern.format(id=test_id)
            try:
                resp = client.get(url, headers=auth_headers)
                check_idor(url, resp, "filename_idor", f"user{{test_id}}")
            except Exception:
                pass

    client.close()

except Exception as e:
    results.append({{
        "title": "IDOR test error",
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
