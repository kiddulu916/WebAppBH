# WSTG-Aligned Restructure — 01 Infrastructure Services

**Date:** 2026-03-29
**Series:** restructure-00 through restructure-12
**Depends on:** restructure-00-overview

---

## Overview

Two new infrastructure services are added as always-running Docker containers alongside PostgreSQL, Redis, the orchestrator, and the dashboard. They serve fundamentally different roles in the testing pipeline:

- **Traffic Proxy** — Sits inline between a worker and the target. Intercepts, inspects, and modifies HTTP requests and responses mid-flight.
- **Callback Server** — Sits behind the target waiting for it to reach out. Catches out-of-band results from blind injection, DNS exfiltration, and reverse shell connections.

```
Worker ──► Traffic Proxy ──► Target Application
                                    │
                                    │ (blind payload triggers callback)
                                    ▼
                           Callback Server ◄── Worker polls for hits
```

These are separate containers, separate network paths, separate purposes. They must never be combined.

---

## Traffic Proxy

### Purpose

Programmatic HTTP request/response interception for stages that need to catch, inspect, or alter traffic mid-flight. This replaces the need for manual Burp Suite usage — workers can register interception rules via a Python API.

### Use Cases by Worker

| Worker | Stage | Use Case |
|--------|-------|----------|
| session_mgmt | session_fixation | Capture session token before login, inject fixation cookie |
| session_mgmt | csrf | Strip anti-CSRF tokens from requests before forwarding |
| authorization | auth_schema_bypass | Swap user identifiers in request parameters mid-flight |
| authorization | privilege_escalation | Manipulate role parameters in-flight |
| business_logic | request_forgery | Alter order totals, swap product IDs before submission |
| business_logic | integrity_checks | Modify hidden fields between multi-step form submissions |
| business_logic | application_misuse | Coordinate concurrent request release for race conditions |
| authentication | auth_bypass | Manipulate isAdmin/role parameters in-flight |
| input_validation | Various | Inject payloads into specific request positions |

### Implementation

**Base:** mitmproxy in programmatic mode (not interactive). Runs as a Python process with a custom addon that exposes a REST API for rule management.

**Container:** `proxy`

**Dockerfile:** `docker/Dockerfile.proxy`

```dockerfile
FROM python:3.12-slim
RUN pip install mitmproxy aiohttp
COPY proxy/ /app/proxy/
WORKDIR /app
CMD ["python", "-m", "proxy.server"]
```

### Architecture

```
┌─────────────────────────────────────────────┐
│                 Proxy Container              │
│                                             │
│  ┌─────────────┐     ┌──────────────────┐  │
│  │ mitmproxy    │     │ Rule Manager API │  │
│  │ (port 8080)  │◄───►│ (port 8081)      │  │
│  │              │     │                  │  │
│  │ Addon:       │     │ POST /rules      │  │
│  │ - match req  │     │ DELETE /rules/id │  │
│  │ - transform  │     │ GET /rules       │  │
│  │ - log        │     │ GET /captures    │  │
│  └─────────────┘     └──────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
```

**Two ports:**
- **8080** — mitmproxy listener. Workers set `HTTP_PROXY=http://proxy:8080` on specific requests.
- **8081** — Rule Manager REST API. Workers register interception rules before sending requests.

### Rule Manager API

#### Register a rule

```
POST http://proxy:8081/rules
{
    "id": "swap-user-id",
    "match": {
        "url_pattern": "/api/users/*",
        "method": "GET",
        "header_match": {}
    },
    "transform": {
        "type": "replace_param",
        "param": "user_id",
        "original": "tester_123",
        "replacement": "testing_user_456"
    },
    "capture": true,
    "expires_after": 60
}
```

#### Transform types

| Type | Description | Example |
|------|------------|---------|
| `replace_param` | Replace a query/body parameter value | Swap user_id for IDOR testing |
| `replace_header` | Replace a request header value | Swap Authorization token |
| `strip_header` | Remove a request header | Strip X-CSRF-Token |
| `strip_param` | Remove a query/body parameter | Remove anti-CSRF param |
| `inject_header` | Add a header to the request | Add X-Forwarded-For |
| `inject_param` | Add a parameter to the request | Add role=admin |
| `replace_body` | Replace the entire request body | Swap POST payload |
| `modify_response` | Alter the response before returning to worker | Test client-side handling |
| `delay` | Add latency to the request | Race condition coordination |
| `duplicate` | Send the request N times concurrently | Race condition testing |

#### Retrieve captures

```
GET http://proxy:8081/captures?rule_id=swap-user-id
[
    {
        "timestamp": "2026-03-29T12:00:00Z",
        "original_request": { ... },
        "modified_request": { ... },
        "response": { ... },
        "response_status": 200,
        "response_body_preview": "..."
    }
]
```

#### Delete a rule

```
DELETE http://proxy:8081/rules/swap-user-id
```

### Opt-In Mechanism

Workers do NOT route all traffic through the proxy. Only specific requests go through it.

**In base_tool.py:**

```python
async def request_via_proxy(self, method, url, **kwargs):
    """Route a single request through the traffic proxy."""
    kwargs.setdefault("proxy", f"http://proxy:8080")
    return await self.http_client.request(method, url, **kwargs)

async def request_direct(self, method, url, **kwargs):
    """Send a request directly to the target (default)."""
    return await self.http_client.request(method, url, **kwargs)
```

Tools explicitly call `request_via_proxy()` when they need interception. The default `request_direct()` bypasses the proxy entirely.

**Rule lifecycle:**
1. Tool registers rule via `POST /rules` before sending the request
2. Tool sends request via `request_via_proxy()`
3. Proxy applies matching rule, captures traffic
4. Tool retrieves captures via `GET /captures`
5. Tool deletes rule via `DELETE /rules/{id}`

Rules auto-expire after `expires_after` seconds (default 60) to prevent stale rules from accumulating.

### Resource Allocation

| Resource | Allocation |
|----------|-----------|
| CPU | 0.25 cores reserved |
| Memory | 128MB reserved |
| Disk | Captures stored in-memory, flushed every 5 minutes |
| Network | Same Docker network as workers and targets |

### TLS Handling

The proxy generates ephemeral CA certificates for TLS interception. Workers trust this CA via an environment variable pointing to the CA cert file mounted from the proxy container's volume.

```yaml
# docker-compose.yml
proxy:
  volumes:
    - proxy-certs:/app/certs
workers:
  environment:
    - REQUESTS_CA_BUNDLE=/app/certs/mitmproxy-ca-cert.pem
  volumes:
    - proxy-certs:/app/certs:ro
```

---

## Callback Server

### Purpose

Self-hosted out-of-band interaction listener. Replaces external dependency on interactsh for blind injection confirmation. Generates unique per-test callback URLs and DNS names, records all incoming connections, and exposes a polling API for workers to check results.

### Use Cases by Worker

| Worker | Stage | Use Case |
|--------|-------|----------|
| input_validation | xml_injection | Blind XXE — external entity fetches callback URL |
| input_validation | ssrf_ssti | Blind SSRF — target fetches callback URL |
| input_validation | code_injection | RFI — target includes callback URL as remote file |
| input_validation | command_injection | Reverse shell — target connects back to callback |
| input_validation | sql_injection | OOB SQLi — DNS exfiltration via callback domain |
| input_validation | http_splitting_smuggling | Smuggled request hits callback |
| chain | chain_execution | Escalation verification — confirm reachability via callback |

### Implementation

**Base:** Custom Python asyncio server. Listens on HTTP, HTTPS, DNS, and raw TCP.

**Container:** `callback`

**Dockerfile:** `docker/Dockerfile.callback`

```dockerfile
FROM python:3.12-slim
RUN pip install aiohttp aiodns
COPY callback/ /app/callback/
WORKDIR /app
CMD ["python", "-m", "callback.server"]
```

### Architecture

```
┌──────────────────────────────────────────────────────┐
│                 Callback Container                    │
│                                                      │
│  ┌───────────────┐  ┌────────────┐  ┌─────────────┐│
│  │ HTTP Listener  │  │ DNS Listener│  │ TCP Listener ││
│  │ (port 9090)    │  │ (port 9053) │  │ (port 9443)  ││
│  └───────┬───────┘  └─────┬──────┘  └──────┬──────┘│
│          │                │                 │        │
│          ▼                ▼                 ▼        │
│  ┌─────────────────────────────────────────────────┐│
│  │              Interaction Store                   ││
│  │  (in-memory dict, keyed by callback_id)          ││
│  └─────────────────────┬───────────────────────────┘│
│                        │                             │
│  ┌─────────────────────▼───────────────────────────┐│
│  │           Polling API (port 9091)                ││
│  │  POST /callbacks      — register new callback    ││
│  │  GET  /callbacks/{id} — check for interactions   ││
│  │  DELETE /callbacks/{id} — cleanup                ││
│  └─────────────────────────────────────────────────┘│
│                                                      │
└──────────────────────────────────────────────────────┘
```

### Callback Registration API

#### Register a callback

```
POST http://callback:9091/callbacks
{
    "target_id": 42,
    "worker_type": "input_validation",
    "stage_name": "xml_injection",
    "tool_name": "XxeInjectorTool",
    "protocols": ["http", "dns"],
    "expires_after": 300
}
```

Response:

```json
{
    "callback_id": "a1b2c3d4e5f6",
    "http_url": "http://callback:9090/cb/a1b2c3d4e5f6",
    "dns_name": "a1b2c3d4e5f6.cb.internal",
    "tcp_port": 9443,
    "created_at": "2026-03-29T12:00:00Z",
    "expires_at": "2026-03-29T12:05:00Z"
}
```

The `http_url` and `dns_name` are what the worker injects into payloads. When the target application processes the payload and reaches out to these URLs/domains, the callback server records the interaction.

#### Poll for interactions

```
GET http://callback:9091/callbacks/a1b2c3d4e5f6
{
    "callback_id": "a1b2c3d4e5f6",
    "interactions": [
        {
            "timestamp": "2026-03-29T12:00:05Z",
            "protocol": "http",
            "source_ip": "10.0.1.50",
            "method": "GET",
            "path": "/cb/a1b2c3d4e5f6",
            "headers": { "User-Agent": "Java/1.8.0", ... },
            "body": null
        },
        {
            "timestamp": "2026-03-29T12:00:06Z",
            "protocol": "dns",
            "source_ip": "10.0.1.50",
            "query_type": "A",
            "query_name": "a1b2c3d4e5f6.cb.internal"
        }
    ],
    "hit_count": 2
}
```

If `interactions` is non-empty, the blind injection was successful. The worker records a confirmed Vulnerability.

#### Cleanup

```
DELETE http://callback:9091/callbacks/a1b2c3d4e5f6
```

### Callback ID Generation

Each callback gets a unique 12-character hex ID generated via `secrets.token_hex(6)`. This provides 48 bits of entropy — enough to prevent collision across concurrent tests while keeping URLs short for payload size constraints.

### Protocol Listeners

**HTTP Listener (port 9090):**
- Accepts any HTTP request to `/cb/{callback_id}`
- Records method, headers, body, source IP
- Returns 200 OK with empty body (minimal fingerprint)

**DNS Listener (port 9053):**
- Responds to A/AAAA/TXT queries for `{callback_id}.cb.internal`
- Records query type, source IP, query name
- Returns 127.0.0.1 for A queries (non-routable)

**TCP Listener (port 9443):**
- Accepts raw TCP connections
- Records source IP, connection timestamp, first 1KB of data received
- Used for reverse shell catch verification (connection confirmed, no interactive session established)
- Closes connection after recording — no shell interaction

### Integration with base_tool.py

```python
async def register_callback(self, protocols=None):
    """Register a callback and return the URLs for payload injection."""
    if protocols is None:
        protocols = ["http"]
    payload = {
        "target_id": self.target_id,
        "worker_type": self.worker_type,
        "stage_name": self.stage_name,
        "tool_name": self.__class__.__name__,
        "protocols": protocols,
        "expires_after": 300
    }
    resp = await self.http_client.post("http://callback:9091/callbacks", json=payload)
    return resp.json()

async def check_callback(self, callback_id, timeout=30, poll_interval=2):
    """Poll for callback interactions with timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = await self.http_client.get(f"http://callback:9091/callbacks/{callback_id}")
        data = resp.json()
        if data["interactions"]:
            return data
        await asyncio.sleep(poll_interval)
    return None

async def cleanup_callback(self, callback_id):
    """Remove callback registration after test completes."""
    await self.http_client.delete(f"http://callback:9091/callbacks/{callback_id}")
```

### Networking Considerations

The callback server must be reachable from the target application for blind injection to work. This means:

**Internal targets (same Docker network):** Callback server is directly reachable via Docker DNS (`callback:9090`). No special config needed.

**External targets (internet-facing):** The callback server needs a public IP or domain that the target can reach. This requires:
- Port forwarding (9090, 9053, 9443) from the host to the callback container
- A configurable `CALLBACK_EXTERNAL_HOST` environment variable that workers use in payloads instead of the internal Docker hostname
- DNS configuration for the callback domain if DNS-based exfiltration is needed

```python
# In base_tool.py
def get_callback_url(self, callback_id):
    external_host = os.getenv("CALLBACK_EXTERNAL_HOST", "callback")
    external_port = os.getenv("CALLBACK_EXTERNAL_PORT", "9090")
    return f"http://{external_host}:{external_port}/cb/{callback_id}"
```

### Resource Allocation

| Resource | Allocation |
|----------|-----------|
| CPU | 0.25 cores reserved |
| Memory | 128MB reserved |
| Disk | Interactions stored in-memory, pruned on expiry |
| Network | Same Docker network + optional port forwarding for external targets |

### Expiry and Cleanup

- Callbacks expire after `expires_after` seconds (default 300 / 5 minutes)
- A background task runs every 60 seconds to prune expired callbacks
- Workers should call `cleanup_callback()` explicitly when done, but expiry handles forgotten cleanups
- Maximum concurrent callbacks: 10,000 (configurable via `MAX_CALLBACKS` env var)

---

## Docker Compose Integration

```yaml
services:
  # ... existing services (postgres, redis, orchestrator, dashboard) ...

  proxy:
    build:
      context: .
      dockerfile: docker/Dockerfile.proxy
    ports:
      - "8080:8080"   # mitmproxy listener
      - "8081:8081"   # rule manager API
    volumes:
      - proxy-certs:/app/certs
    deploy:
      resources:
        limits:
          cpus: "0.25"
          memory: 128M
        reservations:
          cpus: "0.25"
          memory: 128M
    networks:
      - webbh

  callback:
    build:
      context: .
      dockerfile: docker/Dockerfile.callback
    ports:
      - "9090:9090"   # HTTP listener
      - "9091:9091"   # polling API
      - "9053:9053/udp"  # DNS listener
      - "9443:9443"   # TCP listener
    environment:
      - CALLBACK_EXTERNAL_HOST=${CALLBACK_EXTERNAL_HOST:-callback}
      - CALLBACK_EXTERNAL_PORT=${CALLBACK_EXTERNAL_PORT:-9090}
      - MAX_CALLBACKS=10000
    deploy:
      resources:
        limits:
          cpus: "0.25"
          memory: 128M
        reservations:
          cpus: "0.25"
          memory: 128M
    networks:
      - webbh

volumes:
  proxy-certs:

networks:
  webbh:
    driver: bridge
```

Both services start with `docker compose up` alongside the existing infrastructure. They are lightweight and always-on — no dynamic launching needed.
