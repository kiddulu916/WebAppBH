# Cloud Testing Worker

Act as a Senior Cloud Security Architect.
Task: Create the "Cloud-Testing-Engine" Dockerized worker. This container specializes in identifying misconfigurations and data leaks across AWS, Azure, and Google Cloud Platform.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Python 3.10+, Go, and Cloud CLI tools (aws-cli, azure-cli, gcloud).
- **Core Tools**: 
    - **CloudEnum**: For multi-cloud OSINT and bucket discovery.
    - **S3Scanner / Cloud-Scanner**: For checking S3/Azure/GCP bucket permissions.
    - **TruffleHog**: To scan public buckets for secrets/credentials.
    - **Prowler (CLI modules)**: For targeted resource configuration checks.
    - **SkyArk**: For discovering "Shadow" admins in Azure/AWS.

## 2. Cloud-Specific Intelligence

- **Input**: Query the `cloud_assets` table for URLs (e.g., `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.appspot.com`).
- **Bucket Probing**: 
    - Check for Public Read/Write/ACL permissions.
    - If a bucket is readable, list the top 100 files to identify sensitive data (DB backups, `.env` files, `.ssh` keys).
- **Service Enumeration**: 
    - Identify exposed Lambda/Function endpoints.
    - Check for open ElasticSearch, RDS, or Firebase instances linked to the target.

## 3. Vulnerability Detection Logic

Implement a Python controller that orchestrates:

1. **Unauthenticated Access**: Verify if resources can be accessed without a cloud identity.
2. **Credential Leakage**: Scan discovered cloud files for API keys, passwords, or configuration files using TruffleHog.
3. **Identity Mapping**: Use found cloud metadata to map the relationship between different cloud resources (e.g., this Bucket is used by this Lambda function).

## 4. Database & Event Reporting

- **Asset Update**: Update the `cloud_assets` table with `is_public` status, `findings` JSONB, and a summary of contents.
- **Vulnerability Sync**: Log "Public S3 Bucket" or "Exposed Firebase DB" to the `vulnerabilities` and `alerts` tables.
- **Trigger Next Step**: If a Cloud CLI key is found, flag the target for "Post-Exploitation/IAM" analysis.

## 5. Resource Control

- Strictly respect rate limits to avoid Cloud Provider throttling or "Denial of Wallet" on the target.
- Use the `ScopeManager` to ensure the bucket actually belongs to the target company (to avoid legal issues with shared cloud space).

Deliverables: Dockerfile, Cloud-probing script, S3Scanner integration, and Cloud-asset mapping logic.
