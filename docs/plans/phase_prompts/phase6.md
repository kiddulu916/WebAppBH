# Fuzzing Worker

Act as a Senior Penetration Tester specializing in Content Discovery.
Task: Create the "Fuzzing-Engine" Dockerized worker. This container is responsible for discovering hidden files, directories, and vulnerable parameters.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Go and Python 3.10+.
- **Core Tools**:
    - **ffuf**: The primary high-speed fuzzer.
    - **dirsearch**: For intelligent directory bruteforcing with recursion.
    - **Arjun**: For automated HTTP parameter discovery.
    - **Feroxbuster**: A recursive content discovery tool.
- **Wordlists**:
    - Include **Seclists** (Discovery/Web-Content) in a compressed format or via a volume mount.
    - Include a custom "Small" and "Large" wordlist strategy to optimize for the `rate_limit`.

## 2. Intelligent Logic & Scope

- **Input**: Query the `endpoints` and `locations` tables. Filter for unique directories to avoid redundant fuzzing.
- **Header Injection**: Must use the `custom_headers` from the target profile (crucial for bypassing WAFs or accessing authenticated areas).
- **Scope Manager**: Any new path discovered (e.g., `example.com/backup.zip`) must be validated against the `out_of_scope` rules before being logged.

## 3. Fuzzing Workflow

Implement a Python controller that executes:

1. **Directory Fuzzing (ffuf/feroxbuster)**: Identify hidden paths (`/backup`, `/.git`, `/.env`, `/admin`, `/v2`).
2. **Parameter Discovery (Arjun)**: Probe live endpoints for hidden GET/POST parameters (e.g., `?debug=true`, `?admin=1`).
3. **Response Analysis**: 
    - Filter out "Soft 404s" and junk responses.
    - Flag 403 Forbidden or 401 Unauthorized paths for the "Web App Testing" container to attempt bypasses.

## 4. Database & Event Reporting

- **Endpoint Sync**: Every unique 200/204/301/302 response found must be added to the `endpoints` table.
- **Parameter Sync**: Discovered parameters must be added to the `parameters` table for the "API Testing" and "Vulnerability Scanning" phases.
- **High-Priority Alerts**: If a sensitive file is found (e.g., `config.php.bak`, `.ssh/id_rsa`), write an entry to the `alerts` table immediately.

## 5. Resource Control

- **Rate Limiting**: Strictly adhere to the `rate_limit` provided in the target profile to avoid IP bans or crashing the target server.
- **Concurrency**: Limit active fuzzing threads based on `os.cpu_count()`.

Deliverables: Dockerfile, Python Fuzzing Controller, and a script to manage Seclist integrations.