# Mobile App Testing Worker

Act as a Senior Mobile Security Researcher.
Task: Create the "Mobile-App-Testing" Dockerized worker. This container performs automated Static Application Security Testing (SAST) on Android and iOS binaries.

## 1. Toolchain & Environment

- **Base**: Debian-slim with Java (JRE/JDK), Python 3.10+, and Node.js.
- **Core Tools**: 
    - **MobSF (Mobile Security Framework)**: The primary engine for static analysis.
    - **Apktool / Jadx**: For decompiling Android APKs to Smali/Java.
    - **Dumping/Extraction**: Tools to pull strings and secrets from IPA (iOS) files.
    - **Inspeckage / Objection (CLI components)**: For identifying potential hook points.

## 2. Binary Acquisition & Analysis

- **Input**: 
    - Query the `endpoints` table for links ending in `.apk`, `.ipa`, or `.zip` (containing binaries).
    - If a Play Store or App Store link is found, the worker attempts to fetch the latest metadata (or binary if an external downloader is configured).
- **Decompilation**: Automatically decompile binaries to extract `AndroidManifest.xml`, strings, and source code.

## 3. Vulnerability Detection Logic

Implement a Python controller that orchestrates the following:

1. **Hardcoded Secret Extraction**: Scan the decompiled source for API keys, Firebase URLs, AWS credentials, and hardcoded 'Admin' credentials.
2. **Endpoint Discovery**: Extract every URL and IP address found in the code and feed them back to the `assets` and `endpoints` tables for the Orchestrator to trigger new scans.
3. **Insecure Configurations**: 
    - **Android**: Check for `allowBackup="true"`, `debuggable="true"`, or insecure `FileProvider` permissions.
    - **iOS**: Check for insecure App Transport Security (ATS) settings.
4. **Deeplink Analysis**: Identify custom URL schemes and intent filters that could lead to unauthorized data access or account takeover.

## 4. Database & Event Reporting

- **Asset Expansion**: Any new domain/IP found in the mobile code is treated as "High Priority" recon and sent to **Recon-Core**.
- **Vulnerability Sync**: Report insecure permissions or hardcoded secrets to the `vulnerabilities` and `alerts` tables.
- **Artifact Storage**: Save the decompiled source summary to the shared volume `/app/shared/mobile_analysis/`.

## 5. Resource Control

- Limit concurrent decompilation tasks (heavy CPU/RAM usage).
- Implement a 100MB file size limit for automated processing to avoid "Zip Bombs" or massive asset bundles.

Deliverables: Dockerfile, MobSF-integration script, Secret-extraction regex suite, and Jadx wrapper.