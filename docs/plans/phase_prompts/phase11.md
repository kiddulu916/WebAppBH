# Network Testing Worker

Act as a Senior Network Penetration Tester.
Task: Create the "Network-Testing-Engine" Dockerized worker. This container performs advanced port enumeration and automated service exploitation.

## 1. Toolchain & Environment

- **Base**: Kali Linux (slim) or Debian-slim.
- **Core Tools**:
    - **Nmap**: For deep service versioning and NSE script execution.
    - **Metasploit Framework (MSF)**: For automated vulnerability verification.
    - **Naabu**: To rapidly re-verify port status before exploitation.
    - **Medusa**: For safe, rate-limited credential stuffing against open services.
    - **Socat**: For connectivity testing.
    - **Custom LDAP Injection Payloads**: For LDAP filter manipulation and authentication bypass testing.

## 2. Service Enumeration & NSE Logic

- **Input**: Query the `locations` table for non-HTTP ports (e.g., 21, 22, 445, 3306, 5432).
- **Deep Scanning**: Run `nmap -sV -sC --script=vuln` against non-standard ports to identify specific versions and known CVEs.
- **Service Mapping**: Update the `observations` table with precise service details (e.g., "OpenSSH 7.2p2 - Vulnerable to Enumeration").

## 3. Automated Exploitation Logic

Implement a Python controller that triggers Metasploit modules or scripts for:

1. **Default Credentials**: Check for "admin/admin", "root/root", or "guest/guest" on databases (Redis, MongoDB) and management interfaces (Telnet, SSH).
2. **Safe CVE Verification**: Use Metasploit's `check` command to verify if a service is vulnerable to a specific exploit without actually executing a disruptive payload.
3. **SMB/RPC Probing**: If port 445 is open, check for "Null Sessions" or vulnerabilities like EternalBlue (CVE-2017-0144) using safe detection scripts.
4. **LDAP Injection**: After credential testing, run LDAP injection tests against detected LDAP services:
    - **Input**: `assets` (type='url') where `observations.tech_stack` shows LDAP/Active Directory/OpenLDAP, plus `locations` where `service` matches LDAP (port 389/636). Also test login forms on web assets when backend LDAP is suspected from headers/error messages.
    - **Tests**: LDAP filter manipulation (`*)(uid=*`, `)(cn=*`), blind LDAP injection via response timing, authentication bypass via `*)(&`, wildcard data extraction.
    - **Output**: LDAP injection findings → `vulnerabilities` with full payload + response as PoC.

## 4. Database & Event Reporting

- **Vulnerability Sync**: Log findings like "Weak Password on MySQL", "Vulnerable FTP Version", or "LDAP Injection — Authentication Bypass" to the `vulnerabilities` table.
- **Alerting**: High-priority alerts for "RCE-capable" service vulnerabilities and LDAP injection findings.
- **Network Map**: Store the "OS Fingerprint" and "System Uptime" in the `identities` or `assets` table.

## 5. Ethical Safety & Throttling

- **Exclusion List**: Ensure the Orchestrator passes the `oos_attacks` list to avoid DoS (Denial of Service) scripts.
- **Rate Limiting**: Limit Hydra/Medusa to a maximum of 1-2 attempts per second to avoid account lockouts or firewall bans.

Deliverables: Dockerfile, Nmap-to-MSF wrapper script, LDAP injection testing module, and a service-specific attack decision tree.
