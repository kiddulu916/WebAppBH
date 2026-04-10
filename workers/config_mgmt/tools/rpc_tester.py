"""RPC configuration tester."""

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import WeightClass


class RpcTester(ConfigMgmtTool):
    """Test RPC configuration (WSTG-CONFIG-008)."""

    name = "rpc_tester"

    def build_command(self, target, headers=None):
        target_url = getattr(target, 'target_value', str(target))
        base_url = target_url if target_url.startswith(('http://', 'https://')) else f"https://{target_url}"

        script = f'''
import httpx
import json

results = []
base_url = "{base_url}"

XMLRPC_PATHS = [
    "/xmlrpc.php",
    "/xmlrpc/",
    "/rpc/xmlrpc.php",
    "/wp/xmlrpc.php",
    "/wordpress/xmlrpc.php",
]

JSONRPC_PATHS = [
    "/jsonrpc",
    "/jsonrpc/",
    "/api/jsonrpc",
    "/api/v1/jsonrpc",
    "/rpc",
    "/rpc/",
    "/api/rpc",
]

SOAP_PATHS = [
    "/soap",
    "/soap/",
    "/api/soap",
    "/services/soap",
    "/ws",
    "/ws/",
    "/webservice",
    "/webservice/",
    "/axis2/services",
    "/axis2/",
]

GRPC_PATHS = [
    "/grpc",
    "/grpc/",
    "/api/grpc",
]

try:
    client = httpx.Client(follow_redirects=True, timeout=10, verify=False)
    base_path = base_url.rstrip('/')

    for path in XMLRPC_PATHS:
        try:
            xml_body = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
            resp = client.post(
                base_path + path,
                content=xml_body,
                headers={{"Content-Type": "application/xml"}}
            )
            if resp.status_code == 200:
                if "methodResponse" in resp.text or "system.listMethods" in resp.text:
                    results.append({{
                        "vulnerability": {{
                            "name": f"Exposed XML-RPC endpoint at {{path}}",
                            "severity": "medium",
                            "description": f"XML-RPC service is accessible at {{path}} and responds to method calls",
                            "location": base_path + path
                        }}
                    }})
                else:
                    results.append({{
                        "observation": {{
                            "type": "rpc_endpoint",
                            "value": path,
                            "details": {{
                                "type": "xmlrpc",
                                "location": base_path + path,
                                "status": resp.status_code
                            }}
                        }}
                    }})
            elif resp.status_code == 405:
                results.append({{
                    "observation": {{
                        "type": "rpc_endpoint",
                        "value": path,
                        "details": {{
                            "type": "xmlrpc",
                            "location": base_path + path,
                            "status": resp.status_code,
                            "note": "Method not allowed - endpoint exists"
                        }}
                    }}
                }})
        except Exception:
            pass

    for path in JSONRPC_PATHS:
        try:
            json_body = json.dumps({{
                "jsonrpc": "2.0",
                "method": "system.listMethods",
                "id": 1
            }})
            resp = client.post(
                base_path + path,
                content=json_body,
                headers={{"Content-Type": "application/json"}}
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "result" in data or "error" in data:
                        results.append({{
                            "vulnerability": {{
                                "name": f"Exposed JSON-RPC endpoint at {{path}}",
                                "severity": "medium",
                                "description": f"JSON-RPC service is accessible at {{path}}",
                                "location": base_path + path
                            }}
                        }})
                    else:
                        results.append({{
                            "observation": {{
                                "type": "rpc_endpoint",
                                "value": path,
                                "details": {{
                                    "type": "jsonrpc",
                                    "location": base_path + path,
                                    "status": resp.status_code
                                }}
                            }}
                        }})
                except Exception:
                    results.append({{
                        "observation": {{
                            "type": "rpc_endpoint",
                            "value": path,
                            "details": {{
                                "type": "jsonrpc",
                                "location": base_path + path,
                                "status": resp.status_code
                            }}
                        }}
                    }})
        except Exception:
            pass

    for path in SOAP_PATHS:
        try:
            soap_lines = [
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">',
                '<soapenv:Body>',
                '<soapenv:Fault>',
                '<faultcode>soapenv:Client</faultcode>',
                '<faultstring>Test</faultstring>',
                '</soapenv:Fault>',
                '</soapenv:Body>',
                '</soapenv:Envelope>',
            ]
            soap_body = "\\n".join(soap_lines)
            resp = client.post(
                base_path + path,
                content=soap_body,
                headers={{"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "test"}}
            )
            if resp.status_code == 200 and ("soap" in resp.text.lower() or "fault" in resp.text.lower()):
                results.append({{
                    "vulnerability": {{
                        "name": f"Exposed SOAP endpoint at {{path}}",
                        "severity": "medium",
                        "description": f"SOAP service is accessible at {{path}}",
                        "location": base_path + path
                    }}
                }})
            elif resp.status_code in (200, 500):
                results.append({{
                    "observation": {{
                        "type": "rpc_endpoint",
                        "value": path,
                        "details": {{
                            "type": "soap",
                            "location": base_path + path,
                            "status": resp.status_code
                        }}
                    }}
                }})
        except Exception:
            pass

    for path in GRPC_PATHS:
        try:
            resp = client.get(base_path + path)
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "")
                if "grpc" in content_type.lower():
                    results.append({{
                        "vulnerability": {{
                            "name": f"Exposed gRPC endpoint at {{path}}",
                            "severity": "medium",
                            "description": f"gRPC service is accessible at {{path}}",
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
