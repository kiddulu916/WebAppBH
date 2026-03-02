# Phase 3: The Web-App

Act as a Senior Frontend Architect.

Task: Create the "Web-App" Command & Control (C2) dashboard using Next.js (App Router), TypeScript, and Tailwind CSS.

## 1. Automated Security & Auth

- **Connection Logic**: On initial load, the app must attempt to read the framework API Key from the shared volume or a pre-defined environment variable.
- **Auto-Config**: Since the API key is generated at Docker build-time, implement a "System Check" component that verifies connectivity with the Orchestrator before allowing user interaction.

## 2. Scope Builder & Campaign Launcher

- Create a multi-step form for target initialization (Company, Base Domain, Wildcards, CIDR In-Scope, URLs In-Scope, URL Blacklist).
- **Scope Configuration**:
    - Textareas for In-Scope and Out-of-Scope (supporting wildcards and CIDR ranges).
    - Toggle for "Out-of-Scope Attacks" (to visualize what is forbidden).
    - CIDR, IPv4, IPv6, and URLs entered are stored in seperately in DB.

- **Control Interface**: Provide a "Settings" drawer to inject Custom Headers and PPS (Packets Per Second) rate limits.
- **Action**: Submit to `POST /api/v1/targets/initialize` and redirect the user to the Live Campaign View.

## 3. Command & Control (C2) Interface

- **The Drill-Down View**: Instead of a node graph, implement a hierarchical "Tree View" (similar to a code editor's file explorer) to navigate assets:
    - `Root (Target Domain)` -> `Subdomain` -> `IP` -> `Ports/Services` -> `Endpoints/Parameters`.
- **Worker Management Console**:
    - Display a list of all active/queued containers (Recon-Core, Cloud-Scan, Fuzzing).
    - Implement action buttons for each worker: **Pause**, **Stop**, and **Relaunch**.
    - These buttons must call Orchestrator endpoints (e.g., `POST /api/v1/workers/{id}/stop`).

## 4. Real-Time Monitoring (SSE)

- **Live Event Stream**: Connect to the SSE endpoint to update the UI without refreshes.
- **Global Status**: A progress bar showing the current phase (RECON -> VULN -> EXPLOIT) and a "Heartbeat" indicator.
- **Worker Feed**: A scrolling terminal-style log window showing `WORKER_SPAWNED` and `TOOL_PROGRESS` events.
- **Progress Synchronization**: Use the `heartbeat` data to show a "Status Board" of which tools (Amass, Katana, etc.) are currently running within the Recon-Core container.
- **Toast Alerts**: Use **Sonner** or **React-Toastify** to trigger instant popups when a high-priority "Alert" (exposed .env, open bucket) hits the database.

## 5. Findings & Data Tables

- **Master Findings Table**: Use **TanStack Table** (React Table) for a searchable, filterable list of all findings across all phases.
- **Categorized Tabs**: 
    - `Assets`: Filterable list of subdomains/IPs.
    - `Cloud`: Dedicated view for the `cloud_assets` table.
    - `Vulnerabilities`: Grouped by severity (Critical, High, Medium, Low).

## 6. Persistence & State Management

- **State Recovery UI**: If the page is refreshed, the app must fetch the current state from the Orchestrator's `/api/v1/jobs` and re-sync the SSE stream to the current progress.
- **API Security**: Securely store the Framework API Key in a `.env.local` or a session-based state to authenticate all backend calls.

## 7. Design & UX

- **Theme**: "Obsidian" Dark Mode using Tailwind CSS.
- **Iconography**: Use **Lucide-react**.
- **State Management**: Use **Zustand** to persist the current active campaign view and user preferences.
- Use the `interfaces.ts` generated in Phase 1 for all data typing.

### Deliverables: Next.js components, C2 Controller hooks, Tree-view implementation logic, and SSE integration.
