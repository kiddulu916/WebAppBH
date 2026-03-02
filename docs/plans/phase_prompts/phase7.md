# Vulnerability Scanning Worker

Act as a Senior Security Engineer specializing in Automated Vulnerability Assessment.
Task: Create the "Vuln-Scanner" Dockerized worker. This container uses template-based scanning to identify security flaws across the discovered attack surface.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Go 1.21+.
- **Primary Tool**: **Nuclei** (ProjectDiscovery).
- **Templates**: 
    - Automated daily sync of **Nuclei-Templates**.
    - Integration for **Cent** (to manage community-contributed templates).
    - Custom Template Folder: `/app/shared/custom_templates/` for proprietary logic.

## 2. Scanning Logic & Input Injection

- **Target Ingestion**: 
    - Query the `locations` table for live web services.
    - Query the `endpoints` table for specific high-risk paths found during fuzzing.
    - Query the `cloud_assets` table for buckets to check for misconfigurations.
- **Context-Aware Scanning**:
    - If `observations` table shows "Apache", trigger Apache-specific templates.
    - If `observations` table shows "WordPress", trigger WP-plugin and core templates.
- **Header Injection**: Must pass `custom_headers` to Nuclei via the `-H` flag for authenticated scanning.

## 3. Execution Strategy

Implement a Python controller that orchestrates Nuclei runs:
1. **Critical/High Scan**: Run a fast sweep of high-impact templates (RCE, SQLi, SSRF, LFI) across all live assets.
2. **Tech-Specific Scan**: Filter templates based on the "Tech Stack" fingerprints found in the Observations table.
3. **Exclusion Logic**: Automatically skip templates that match the `oos_attacks` list (e.g., "No DoS", "No Brute Force").

## 4. Database & Event Reporting

- **Vulnerability Sync**: Every finding must be written to the `vulnerabilities` table with:
    - Severity (Critical, High, Medium, Low, Info).
    - Template-ID and Type.
    - **Proof of Concept (PoC)**: The matched request/response pair.
- **Alerting**: Immediate insertion into the `alerts` table for any finding with Severity >= High.
- **Mapping**: Link the vulnerability to the specific `asset_id` or `location_id` in the DB.

## 5. Resource & Performance

- **Rate Limiting**: Adhere to the `rate_limit` (PPS/Requests per second).
- **Persistence**: Use the 24-hour rule to avoid re-scanning the same asset/template combination unless a "Force Scan" is triggered.

Deliverables: Dockerfile, Nuclei wrapper script, Template update automation, and SQL mapping logic.