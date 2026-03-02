# Reporting & Export Worker

Act as a Senior Technical Writer and Security Analyst.
Task: Create the "Reporting-Engine" Dockerized worker. This container aggregates findings from the PostgreSQL database and generates high-quality, professional security reports.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Python 3.10+ and Pandoc (for document conversion).
- **Core Libraries**: 
    - **Jinja2**: For templating logic.
    - **ReportLab / WeasyPrint**: For PDF generation.
    - **Python-Markdown**: To handle PoC documentation.

## 2. Report Aggregation Logic

Implement a Python controller that performs the following:

1. **Data Gathering**: Fetch all entries from the `vulnerabilities` table for a specific `target_id`.
2. **Context Enrichment**: Join findings with the `assets` and `locations` tables to provide the full context (e.g., URL, IP, Port, Tech Stack).
3. **Deduplication**: Group similar findings (e.g., the same Nuclei template hitting multiple subdomains) to avoid repetitive report bloat.
4. **Severity Scoring**: Calculate the final CVSS (Common Vulnerability Scoring System) score based on the template data.

## 3. Template Architecture

Use Jinja2 to support multiple export formats:

- **HackerOne/Bugcrowd (Markdown)**: Optimized for quick copy-pasting with clear "Steps to Reproduce" and "Impact" sections.
- **Executive Summary (PDF)**: A high-level overview with charts showing vulnerability distribution by severity.
- **Full Technical Report**: A detailed breakdown including the raw HTTP Request/Response PoCs found in Phase 6 and 7.

## 4. Media & Proof of Concept (PoC)

- **Log Parsing**: Extract the "Proof of Concept" data stored in the DB.
- **Image Integration**: If the Web-App Testing worker (Phase 4) captured screenshots of a vulnerability, embed those images into the final PDF.
- **Remediation Advice**: Include a "Recommended Fix" section based on the type of vulnerability (e.g., "Set X-Frame-Options header").

## 5. Export & Notification

- **Volume Storage**: Save generated reports to `/app/shared/reports/{target_name}_{date}.pdf`.
- **External Integration**: (Optional) Add logic to push findings to a Jira board or a Slack/Discord webhook.

Deliverables: Dockerfile, Jinja2 Templates, Report Generation Script, and a PoC formatting utility.