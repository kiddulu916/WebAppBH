# workers/cryptography/tools/tls_auditor.py
"""TLS auditing tool — tests SSL/TLS configurations."""

import json
from workers.cryptography.base_tool import CryptographyTool


class TlsAuditor(CryptographyTool):
    """Audit TLS configurations using testssl.sh."""

    async def execute(self, target_id: int, **kwargs):
        """Execute TLS auditing against target domains."""
        domains = await self._get_target_domains(target_id)

        for domain in domains:
            await self._audit_domain_tls(target_id, domain)

    async def _get_target_domains(self, target_id: int):
        """Get all domains for the target."""
        from lib_webbh import get_session, Target
        from sqlalchemy import select

        async with get_session() as session:
            result = await session.execute(
                select(Target.base_domain).where(Target.id == target_id)
            )
            row = result.fetchone()
            if row:
                return [row[0]]
        return []

    async def _audit_domain_tls(self, target_id: int, domain: str):
        """Audit TLS configuration for a single domain."""
        try:
            # Run testssl.sh in JSON mode
            cmd = ["testssl.sh", "--jsonfile", "/tmp/testssl_output.json", "--quiet", domain]
            await self.run_subprocess(cmd, timeout=300)

            # Read and parse the results
            with open("/tmp/testssl_output.json", "r") as f:
                results = json.load(f)

            # Analyze results for vulnerabilities
            await self._analyze_testssl_results(target_id, domain, results)

        except Exception as e:
            # Fallback to basic checks if testssl.sh fails
            await self._basic_tls_checks(target_id, domain)

    async def _analyze_testssl_results(self, target_id: int, domain: str, results: dict):
        """Analyze testssl.sh results for vulnerabilities."""

        # Check for SSL/TLS protocol issues
        if "protocols" in results:
            protocols = results["protocols"]
            if protocols.get("SSLv2", {}).get("is_supported", False):
                await self.save_vulnerability(
                    target_id=target_id,
                    severity="high",
                    title="SSLv2 Protocol Supported",
                    description=f"Domain {domain} supports deprecated SSLv2 protocol",
                    poc=f"https://{domain}",
                    vuln_type="weak_crypto",
                )

            if protocols.get("SSLv3", {}).get("is_supported", False):
                await self.save_vulnerability(
                    target_id=target_id,
                    severity="high",
                    title="SSLv3 Protocol Supported",
                    description=f"Domain {domain} supports deprecated SSLv3 protocol (POODLE vulnerable)",
                    poc=f"https://{domain}",
                    vuln_type="weak_crypto",
                )

            if not protocols.get("TLS1_2", {}).get("is_supported", False) and not protocols.get("TLS1_3", {}).get("is_supported", False):
                await self.save_vulnerability(
                    target_id=target_id,
                    severity="medium",
                    title="Weak TLS Protocol Support",
                    description=f"Domain {domain} does not support TLS 1.2 or 1.3",
                    poc=f"https://{domain}",
                    vuln_type="weak_crypto",
                )

        # Check for weak cipher suites
        if "ciphers" in results:
            ciphers = results["ciphers"]
            weak_ciphers = []

            for cipher_name, cipher_info in ciphers.items():
                if cipher_info.get("is_weak", False) or cipher_name.startswith("RC4") or "NULL" in cipher_name:
                    weak_ciphers.append(cipher_name)

            if weak_ciphers:
                await self.save_vulnerability(
                    target_id=target_id,
                    severity="medium",
                    title="Weak Cipher Suites Supported",
                    description=f"Domain {domain} supports weak cipher suites: {', '.join(weak_ciphers[:5])}",
                    poc=f"https://{domain}",
                    vuln_type="weak_crypto",
                )

        # Check for certificate issues
        if "certificates" in results:
            certs = results["certificates"]
            if certs.get("has_self_signed", False):
                await self.save_vulnerability(
                    target_id=target_id,
                    severity="low",
                    title="Self-Signed Certificate",
                    description=f"Domain {domain} uses a self-signed certificate",
                    poc=f"https://{domain}",
                    vuln_type="certificate_issue",
                )

    async def _basic_tls_checks(self, target_id: int, domain: str):
        """Perform basic TLS checks if testssl.sh is not available."""
        import ssl
        import socket

        try:
            # Basic SSL context check
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Check certificate validity
                    if cert:
                        # This is a very basic check - in production you'd validate the cert chain
                        await self.save_vulnerability(
                            target_id=target_id,
                            severity="info",
                            title="TLS Connection Established",
                            description=f"Domain {domain} has a valid TLS certificate and connection",
                            poc=f"https://{domain}",
                            vuln_type="tls_info",
                        )

        except ssl.SSLError as e:
            await self.save_vulnerability(
                target_id=target_id,
                severity="high",
                title="TLS/SSL Error",
                description=f"Domain {domain} has TLS/SSL configuration issues: {str(e)}",
                poc=f"https://{domain}",
                vuln_type="tls_error",
            )
        except Exception:
            # Connection failed - might not support HTTPS
            pass