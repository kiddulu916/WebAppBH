# Web App Worker

Act as a Senior Security Researcher specializing in Client-Side Vulnerabilities.
Task: Create the "Web-App-Testing" Dockerized worker. This container focuses on headless browser-based analysis of the frontend and DOM.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Node.js (latest LTS) and Python 3.10+.
- **Headless Browser**: Install Playwright or Puppeteer with Chromium dependencies.
- **Analysis Tools**:
    - **Mantra**: For finding secrets in JS files.
    - **LinkFinder**: To extract endpoints from JavaScript.
    - **SecretFinder**: For sensitive data discovery in JS.
    - **JSMiner**: For uncovering hidden endpoints and parameters in scripts.
    - **DOMPurify/Custom Scripts**: To test for DOM-based XSS sinks.
    - **dalfox**: For reflected and stored XSS scanning with WAF bypass and PoC generation.
    - **ppmap**: For detecting client-side and server-side prototype pollution in JS frameworks.

## 2. Integration & Intelligence

- **Input**: Query the `locations` table in the PostgreSQL DB for services running on port 80/443 with a 200 OK status.
- **Scope Compliance**: Every URL extracted from JS files must pass through the `ScopeManager` (shared logic) before being added to the `endpoints` or `parameters` tables.
- **Custom Headers**: Inject the `custom_headers` (Auth tokens, User-Agents) provided by the Orchestrator into the headless browser session.

## 3. Automated Analysis Logic

Implement a Python/Node orchestrator within the container that:
- **JS Discovery**: Crawls the target and identifies every loaded `.js` file.
- **Endpoint Extraction**: Runs LinkFinder/JSMiner on discovered scripts and saves new paths to the `endpoints` table.
- **PostMessage Monitoring**: Uses Playwright to listen for `postMessage` events and logs listeners that lack origin validation.
- **Sink Analysis**: Identifies dangerous sinks (e.g., `innerHTML`, `setTimeout()`) and attempts basic payload injection to verify DOM XSS.
- **XSS Scanning (dalfox)**: After sink analysis, run dalfox against all `assets` (type='url') with discovered parameters. dalfox performs reflected and stored XSS testing with WAF bypass techniques. Writes confirmed XSS findings to `vulnerabilities` with full PoC (payload + reflected response).
- **Prototype Pollution (ppmap)**: After JS file analysis, run ppmap against JS file URLs discovered by LinkFinder/JSMiner and all URLs where `observations.tech_stack` indicates Node.js/Express. Writes prototype pollution findings to `vulnerabilities`. Only triggered when JS frameworks are detected.

## 4. Persistence & Event Reporting

- **Persistence**: Before scanning a URL, check the `job_state` table. If the DOM/JS analysis was performed in the last 24 hours, skip.
- **Observation Logging**: Write findings (e.g., "Found AWS Key in main.js", "Insecure postMessage listener found") to the `observations` and `vulnerabilities` tables.
- **Progress Heartbeat**: Update the `job_state` every 60 seconds so the Next.js UI can show progress (e.g., "Analyzing main.chunk.js...").

## 5. Resource Management

- Limit the headless browser to X concurrent tabs (based on RAM) to prevent container crashes.
- Implement a 30-second timeout per page to handle heavy React/Angular/Vue applications gracefully.

Deliverables: Dockerfile, Playwright-based analysis script, Python wrapper, dalfox/ppmap integration, and updated models integration.
