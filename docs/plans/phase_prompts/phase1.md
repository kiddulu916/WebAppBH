# Phase 1: Data Persistence & Schema Foundation

Act as a Senior Database Architect and DevSecOps Engineer.
Task: Create the PostgreSQL for a modular Bug Bounty Framework. This is the foundation for all other containers.

## 1. Database Infrastructure

- **Engine**: PostgreSQL 15+ (Alpine-based).
- **Persistence**: Configure a Docker Volume for `/var/lib/postgresql/data`.
- **Connectivity**: Enable access for all containers in the framework's internal network using environment variables for credentials.

## 2. OAM-Compliant Relational Schema

Generate a `schema.sql` script that implements the following (incorporating Cloud and Parameter tracking):

- **targets**: Stores `company_name`, `base_domain`, and a JSONB `target_profile` (wildcards, scope rules, rate limits, custom headers).
- **assets**: Primary table for subdomains, IPs, and CIDRs.
- **identities**: ASN, Organization, and Whois data.
- **locations**: Maps assets to `ports`, `protocols`, and `services`.
- **observations**: Tech stacks, page titles, HTTP status codes, and security headers.
- **cloud_assets**: Track `provider` (AWS/Azure/GCP), `asset_type` (Bucket/Function/Storage), `url`, `is_public` (bool), and `findings` (JSONB).
- **parameters**: Unique URL parameters, values, and source URLs for fuzzing targets.
- **vulnerabilities**: Findings from vuln scanners, including severity and PoC.
- **job_state**: Tracks worker containers: `container_name`, `current_phase`, `status` (RUNNING/COMPLETED/QUEUED), `last_seen`, and `last_tool_executed`.
- **alerts**: High-priority findings for real-time UI notifications.

## 3. Shared Filesystem & Models

- Create a shared Docker Volume structure: `/app/shared/raw/`, `/app/shared/config/`, and `/app/shared/logs/`.
- Generate a Python `models.py` (SQLAlchemy 2.0) reflecting the schema above.
- Generate a TypeScript `interfaces.ts` for the Next.js frontend to ensure end-to-end type safety.

## 4. Redis Message Broker
- **Redis Broker**: Include a Redis service in the compose file to serve as the message broker.
Deliverables: schema.sql, models.py, interfaces.ts, and docker-compose.yml for the DB service.