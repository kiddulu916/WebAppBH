# API Resting worker

Act as a Senior API Security Researcher.
Task: Create the "API-Testing-Engine" Dockerized worker. This container specializes in discovering, mapping, and testing REST, GraphQL, and SOAP interfaces.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Go and Python 3.10+.
- **Primary Tools**: 
    - **Kiterunner**: For ultra-fast API endpoint brute-forcing using API-specific wordlists.
    - **Akamai/Arjun**: For deep parameter discovery.
    - **GraphQLmap / InQL**: For GraphQL introspection and query testing.
    - **Postman-to-k6 / Newman**: To execute automated API collections if found.
    - **TruffleHog**: To scan API documentation (Swagger/OpenAPI) for hardcoded keys.

## 2. API Discovery & Mapping

- **Input**: Query the `endpoints` table for keywords like `/api/`, `/v1/`, `/graphql`, `/swagger.json`, or `/openapi.yaml`.
- **Intelligent Brute-forcing**: 
    - Run **Kiterunner** using the `routes-large.kite` dataset against discovered API roots.
    - If a GraphQL endpoint is found, attempt **Introspection** to map the entire schema (Queries, Mutations, and Types).
- **Schema Analysis**: If a Swagger/OpenAPI spec is found, parse it to identify every available method (GET, POST, PUT, DELETE) and required headers.

## 3. Vulnerability Logic (The OWASP API Top 10)

Implement a Python controller that executes:

1. **Broken Object Level Authorization (BOLA)**: Iterate through numeric IDs (e.g., `/api/user/1000` -> `/api/user/1001`) and look for unauthorized data leakage.
2. **Mass Assignment**: Attempt to "PUT" or "POST" extra fields like `{"is_admin": true}` to account update endpoints.
3. **Improper Inventory Management**: Search for "Shadow APIs" (e.g., `/v2/` is live but `/v1/` is unpatched and still active).

## 4. Database & Event Reporting

- **API Map Sync**: Write the full API tree (Path + Method + Required Params) to a specialized `api_schemas` table (added to the OAM model).
- **Vulnerability Sync**: Report BOLA, IDOR, or Lack of Rate Limiting to the `vulnerabilities` and `alerts` tables.
- **Credential Leakage**: If API keys are found in Swagger docs or JS bundles, log them immediately.

## 5. Compliance & Headers

- **Custom Headers**: Inject `Authorization: Bearer <token>` or custom API keys found in the `.env` or previous phases.
- **Rate Limiting**: Strictly follow the PPS limits to avoid triggering API circuit breakers.

Deliverables: Dockerfile, Kiterunner wrapper, GraphQL analysis script, and API-schema parsing logic.