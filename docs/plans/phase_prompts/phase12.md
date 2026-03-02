# Exploit Chainer & Path Analyzer

Act as an Elite Red Team Operator and Exploit Developer.
Task: Create the "Exploit-Chainer" Dockerized worker. This is the most advanced worker in the framework, designed to link disparate findings into high-impact attack chains.

### 1. Toolchain & Environment

- **Base**: Kali Linux (slim) with Python 3.11+, Go, and Ruby (for Metasploit/specialized exploits).
- **Core Engine**: A custom Python "Chain Logic" engine.
- **Support Tools**: 
    - **Metasploit-Framework**: For pivoting and session management.
    - **Burp Suite (Headless/Rest API)**: For advanced request manipulation.
    - **Interactsh**: To detect out-of-band (OOB) interactions during chaining.
    - **PwnTools**: For binary and low-level exploit scripting.

### 2. The Chaining Logic (The "Brain")

Implement a "Graph-Based" analysis engine that queries the `vulnerabilities`, `parameters`, and `observations` tables to identify linkable paths:

- **Chain Type A (Information -> Access)**: If an "Information Leak" (Phase 6) reveals a `config.php.bak` with DB credentials, use those credentials to probe the "Network Services" (Phase 10) for Database access.
- **Chain Type B (SSRF -> Metadata)**: If a "Server-Side Request Forgery" is found in an API (Phase 7), automatically attempt to chain it to "Cloud Testing" (Phase 9) by hitting the Cloud Metadata Services (e.g., `169.254.169.254`).
- **Chain Type C (XSS -> CSRF/Session)**: If XSS is found (Phase 4), attempt to chain it with a discovered CSRF vulnerability to perform an "Account Takeover" (ATO).

### 3. Automated Chaining Workflow

1. **Dependency Mapping**: Build a dependency graph of all current findings. 
2. **Path Simulation**: For every "Low" or "Medium" finding, ask: "Does this provide an Input (Key, Path, Cookie) for a 'High' target?"
3. **Execution**: Perform the multi-stage attack. 
   - *Example*: 
     - Step 1: Use LFI to read `/etc/passwd`.
     - Step 2: Extract usernames.
     - Step 3: Trigger Phase 10 (Network) to spray those usernames against SSH.

### 4. Database & Event Reporting

- **Impact Escalation**: When a chain is successful, create a new entry in the `vulnerabilities` table marked as **"CHAINED"** with a "Critical" severity.
- **Visual Mapping**: Write the "Attack Path" (Step 1 -> Step 2 -> Step 3) into the `observations` table for the Reporting phase.
- **Alerting**: Immediate High-Priority alert to the Next.js dashboard when a chain is completed.

### 5. Ethical Safeguards

- **Non-Destructive Only**: Only perform "Read" or "Verify" chains. Do not delete data or crash services.
- **Manual Approval Gate**: (Optional) Send a "Request to Chain" to the Orchestrator, requiring the user to click "Approve" in the UI before launching high-risk exploits.

Deliverables: Dockerfile, Chaining Engine (Python), Logic Graph for vulnerability linking, and Metasploit RPC integration.