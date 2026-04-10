"""Malicious file upload client-side testing tool (WSTG-CLIENT-013)."""

from __future__ import annotations

from workers.client_side.base_tool import ClientSideTool
from workers.client_side.concurrency import WeightClass


class MaliciousUploadClientTester(ClientSideTool):
    """Test for client-side file upload validation bypasses (WSTG-CLIENT-013).

    Checks for client-side only file type validation, MIME type confusion,
    double extension bypasses, SVG-based XSS, and HTML file execution.
    """

    name = "malicious_upload_client_tester"
    weight_class = WeightClass.LIGHT

    def build_command(self, target, credentials: dict | None = None) -> list[str]:
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json
import re

results = []
base_url = "{base_url}"

headers = {{}}
if credentials and credentials.get("token"):
    headers["Authorization"] = f"Bearer {{credentials.get('token')}}"

try:
    client = httpx.Client(follow_redirects=True, timeout=15, verify=False)

    resp = client.get(base_url, headers=headers)
    content = resp.text

    # Find file upload forms
    upload_forms = re.findall(r'<form[^>]*enctype=["\\']multipart/form-data["\\'][^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
    file_inputs = re.findall(r'<input[^>]+type=["\\']file["\\'][^>]*>', content, re.IGNORECASE)
    file_input_details = re.findall(r'<input[^>]+type=["\\']file["\\'][^>]*name=["\\']([^"\\'>]+)["\\'][^>]*(?:accept=["\\']([^"\\'>]+)["\\'])?[^>]*>', content, re.IGNORECASE)

    if file_inputs:
        # Check for client-side accept attribute restrictions
        for name, accept in file_input_details:
            if accept:
                results.append({{
                    "title": "Client-side file type restriction",
                    "description": f"File input '{{name}}' at {base_url} has accept attribute '{{accept}}'. Client-side restrictions can be bypassed.",
                    "severity": "low",
                    "data": {{
                        "url": base_url,
                        "input_name": name,
                        "accept_attribute": accept
                    }}
                }})

        # Check for client-side JavaScript file validation
        js_validation_patterns = [
            (r'(?:file|upload)\\.type\\s*(?:===|==|!=)', 'Client-side file type check'),
            (r'(?:file|upload)\\.name\\s*(?:===|==|!=)', 'Client-side file name check'),
            (r'(?:file|upload)\\.size\\s*(?:>|<|===)', 'Client-side file size check'),
            (r'(?:check|validate)\\s*\\(.*(?:file|upload)', 'Client-side file validation function'),
            (r'(?:allowed|permitted)\\s*(?:types|extensions|files)', 'Client-side allowed types list'),
            (r'(?:jpg|jpeg|png|gif|pdf)\\s*[,\\]]', 'File extension whitelist'),
        ]

        for pattern, desc in js_validation_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results.append({{
                    "title": f"Client-side file validation: {{desc}}",
                    "description": f"Found {{desc}} in client-side code at {base_url}. Client-side validation can be bypassed.",
                    "severity": "medium",
                    "data": {{
                        "url": base_url,
                        "issue": desc,
                        "pattern": pattern
                    }}
                }})
                break

        # Check for MIME type validation on client side
        if re.search(r'(?:file|upload)\\.type', content, re.IGNORECASE):
            results.append({{
                "title": "Client-side MIME type validation",
                "description": f"File upload at {base_url} validates MIME type client-side. MIME types can be spoofed.",
                "severity": "medium",
                "data": {{
                    "url": base_url,
                    "issue": "Client-side MIME type validation"
                }}
            }})

    # Check for upload endpoints
    upload_patterns = [
        r'action=["\\'][^"\\'>]*(?:upload|file|media|image|document|attachment)[^"\\'>]*["\\']',
        r'fetch\\s*\\(\\s*["\\'][^"\\'>]*(?:upload|file|media|image)[^"\\'>]*["\\']',
        r'axios\\s*\\.\\s*(?:post|put)\\s*\\(\\s*["\\'][^"\\'>]*(?:upload|file|media|image)[^"\\'>]*["\\']',
        r'/api/(?:upload|files|media|images|documents|attachments)',
    ]

    upload_endpoints = []
    for pattern in upload_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        upload_endpoints.extend(matches)

    if upload_endpoints:
        results.append({{
            "title": "File upload endpoints found",
            "description": f"Found {{len(upload_endpoints)}} file upload endpoint(s) at {base_url}",
            "severity": "info",
            "data": {{
                "url": base_url,
                "endpoints": upload_endpoints[:10]
            }}
        }})

    # Check for SVG upload handling
    svg_patterns = [
        r'(?:accept|allowed).*svg',
        r'image/svg\\+xml',
        r'\\.svg["\\']',
        r'SVG',
    ]

    allows_svg = any(re.search(p, content, re.IGNORECASE) for p in svg_patterns)
    if allows_svg:
        results.append({{
            "title": "SVG file uploads allowed",
            "description": f"SVG file uploads appear to be allowed at {base_url}. SVG files can contain JavaScript and lead to XSS.",
            "severity": "high",
            "data": {{
                "url": base_url,
                "issue": "SVG uploads allowed"
            }}
        }})

    # Check for HTML file upload handling
    html_upload_patterns = [
        r'(?:accept|allowed).*(?:html|htm)',
        r'text/html',
        r'\\.html["\\']',
        r'\\.htm["\\']',
    ]

    allows_html = any(re.search(p, content, re.IGNORECASE) for p in html_upload_patterns)
    if allows_html:
        results.append({{
            "title": "HTML file uploads allowed",
            "description": f"HTML file uploads appear to be allowed at {base_url}. HTML files can contain JavaScript and lead to XSS.",
            "severity": "high",
            "data": {{
                "url": base_url,
                "issue": "HTML uploads allowed"
            }}
        }})

    # Check for double extension handling
    double_ext_patterns = [
        r'(?:php|asp|aspx|jsp)\\.(?:jpg|png|gif)',
        r'(?:jpg|png|gif)\\.(?:php|asp|aspx|jsp)',
        r'double\\s*extension',
        r'multiple\\s*extensions',
    ]

    for pattern in double_ext_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": "Double extension handling detected",
                "description": f"Found double extension handling code at {base_url}. Verify server-side validation is also present.",
                "severity": "low",
                "data": {{
                    "url": base_url,
                    "pattern": pattern
                }}
            }})
            break

    # Check for file upload without CSRF protection
    if upload_forms:
        csrf_patterns = [
            r'_token',
            r'csrf_token',
            r'csrf',
            r'authenticity_token',
            r'_csrf',
            r'xsrf',
        ]

        for form in upload_forms:
            has_csrf = any(re.search(p, form, re.IGNORECASE) for p in csrf_patterns)
            if not has_csrf:
                results.append({{
                    "title": "File upload form without CSRF token",
                    "description": f"Found file upload form at {base_url} without CSRF token protection",
                    "severity": "medium",
                    "data": {{
                        "url": base_url,
                        "issue": "Upload form missing CSRF token"
                    }}
                }})
                break

    # Check for client-side file size limits
    size_limit_patterns = [
        r'maxFileSize\\s*[:=]\\s*\\d+',
        r'max_size\\s*[:=]\\s*\\d+',
        r'(?:file|upload)\\.size\\s*(?:>|<)',
        r'\\d+\\s*(?:MB|KB|GB)',
    ]

    for pattern in size_limit_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            results.append({{
                "title": "Client-side file size limit",
                "description": f"Found client-side file size limit at {base_url}. Size limits must be enforced server-side.",
                "severity": "low",
                "data": {{
                    "url": base_url,
                    "pattern": pattern
                }}
            }})
            break

    # Check for content-type validation on the server
    content_type_patterns = [
        r'Content-Type\\s*:',
        r'content_type',
        r'mimeType',
        r'file\\.type',
    ]

    has_content_type_check = any(re.search(p, content, re.IGNORECASE) for p in content_type_patterns)
    if not has_content_type_check and file_inputs:
        results.append({{
            "title": "No content-type validation detected",
            "description": f"File upload found at {base_url} but no content-type validation detected in client-side code",
            "severity": "info",
            "data": {{
                "url": base_url,
                "issue": "No content-type validation"
            }}
        }})

    client.close()

except Exception as e:
    results.append({{
        "title": "Malicious upload client test error",
        "description": str(e),
        "severity": "info",
        "data": {{"error": str(e)}}
    }})

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout: str) -> list:
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
