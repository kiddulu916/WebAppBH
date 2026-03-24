# workers/chain_worker/chains/ssrf_infrastructure.py
"""20 SSRF / infrastructure chain templates."""
from __future__ import annotations

from datetime import datetime

from workers.chain_worker.registry import BaseChainTemplate, ChainContext, register_chain
from workers.chain_worker.models import (
    ChainViability,
    ChainResult,
    ChainStep,
    EvaluationResult,
    TargetFindings,
)
from workers.chain_worker.base_tool import step_delay, take_screenshot

_CAT = "ssrf_infrastructure"
_SEV = "critical"


def _now() -> str:
    return datetime.utcnow().isoformat()


def _has_ssrf(findings: TargetFindings) -> list:
    return findings.vulns_by_title_contains("SSRF")


def _obs_contains(findings: TargetFindings, *keywords: str) -> list:
    """Return observations whose tech_stack JSON contains any keyword."""
    matched = []
    for obs in findings.observations:
        text = str(getattr(obs, "tech_stack", "") or "").lower()
        if any(kw.lower() in text for kw in keywords):
            matched.append(obs)
    return matched


# ---------------------------------------------------------------------------
# 1. ssrf_cloud_compromise
# ---------------------------------------------------------------------------
@register_chain
class SsrfCloudCompromise(BaseChainTemplate):
    name = "ssrf_cloud_compromise"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        if ssrf:
            return EvaluationResult(
                viability=ChainViability.VIABLE,
                matched_preconditions=["SSRF vulnerability found"],
                matched_findings={"ssrf_vulns": ssrf},
            )
        return EvaluationResult(
            viability=ChainViability.NOT_VIABLE,
            matched_preconditions=[],
            missing_preconditions=["No SSRF vulnerability found"],
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Probe SSRF endpoint with cloud metadata URL",
            target="http://169.254.169.254/latest/meta-data/",
            result="Sent SSRF payload targeting AWS metadata service",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Extract IAM role credentials from metadata response",
            target="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            result="Attempted to retrieve temporary IAM credentials",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Use stolen credentials to enumerate S3 buckets",
            target="AWS S3 API",
            result="Attempted to list S3 buckets with extracted credentials",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 2. ssrf_internal_service_discovery
# ---------------------------------------------------------------------------
@register_chain
class SsrfInternalServiceDiscovery(BaseChainTemplate):
    name = "ssrf_internal_service_discovery"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        if ssrf:
            return EvaluationResult(
                viability=ChainViability.VIABLE,
                matched_preconditions=["SSRF vulnerability found"],
                matched_findings={"ssrf_vulns": ssrf},
            )
        return EvaluationResult(
            viability=ChainViability.NOT_VIABLE,
            matched_preconditions=[],
            missing_preconditions=["No SSRF vulnerability found"],
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Send SSRF probes to common internal ports",
            target="http://127.0.0.1:8080, :9200, :6379, :27017",
            result="Scanned common internal service ports via SSRF",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Enumerate internal subnet hosts via SSRF",
            target="http://10.0.0.0/24 range",
            result="Probed internal /24 subnet for responsive hosts",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Fingerprint discovered internal services",
            target="Responsive internal hosts",
            result="Attempted to identify service versions on open ports",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 3. s3_bucket_data_exfil
# ---------------------------------------------------------------------------
@register_chain
class S3BucketDataExfil(BaseChainTemplate):
    name = "s3_bucket_data_exfil"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        s3 = findings.vulns_by_title_contains("S3") + findings.vulns_by_title_contains("bucket")
        if s3:
            return EvaluationResult(
                viability=ChainViability.VIABLE,
                matched_preconditions=["S3/bucket misconfiguration found"],
                matched_findings={"bucket_vulns": s3},
            )
        return EvaluationResult(
            viability=ChainViability.NOT_VIABLE,
            matched_preconditions=[],
            missing_preconditions=["No S3/bucket misconfiguration found"],
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Enumerate bucket contents via public listing",
            target="Target S3 bucket",
            result="Attempted to list bucket objects without authentication",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Download sensitive files from bucket",
            target="Discovered bucket objects",
            result="Attempted to read sensitive objects (config, backups, credentials)",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Test write access to bucket",
            target="Target S3 bucket",
            result="Attempted to upload test file to verify write permissions",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 4. xxe_internal_recon
# ---------------------------------------------------------------------------
@register_chain
class XxeInternalRecon(BaseChainTemplate):
    name = "xxe_internal_recon"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        xxe = (findings.vulns_by_title_contains("XXE")
               + findings.vulns_by_title_contains("XML external"))
        if xxe:
            return EvaluationResult(
                viability=ChainViability.VIABLE,
                matched_preconditions=["XXE vulnerability found"],
                matched_findings={"xxe_vulns": xxe},
            )
        return EvaluationResult(
            viability=ChainViability.NOT_VIABLE,
            matched_preconditions=[],
            missing_preconditions=["No XXE vulnerability found"],
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Send XXE payload to read /etc/passwd",
            target="Vulnerable XML endpoint",
            result="Attempted to exfiltrate local file via XXE",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Use XXE to probe internal network via SSRF",
            target="http://169.254.169.254/latest/meta-data/",
            result="Attempted to reach cloud metadata via XXE-based SSRF",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Exfiltrate internal configuration files",
            target="Application config files (/etc/hosts, /proc/net/tcp)",
            result="Attempted to map internal network topology via XXE",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 5. path_traversal_source_auth_bypass
# ---------------------------------------------------------------------------
@register_chain
class PathTraversalSourceAuthBypass(BaseChainTemplate):
    name = "path_traversal_source_auth_bypass"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        pt = (findings.vulns_by_title_contains("path traversal")
              + findings.vulns_by_title_contains("directory traversal"))
        if pt:
            return EvaluationResult(
                viability=ChainViability.VIABLE,
                matched_preconditions=["Path/directory traversal found"],
                matched_findings={"traversal_vulns": pt},
            )
        return EvaluationResult(
            viability=ChainViability.NOT_VIABLE,
            matched_preconditions=[],
            missing_preconditions=["No path/directory traversal found"],
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Exploit path traversal to read application source code",
            target="../../app/config/settings.py",
            result="Attempted to read application source via traversal",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Extract hardcoded credentials from source",
            target="Configuration files and .env",
            result="Searched extracted source for API keys and secrets",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Use extracted credentials to bypass authentication",
            target="Admin/API endpoints",
            result="Attempted authentication with discovered credentials",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Escalate privileges using admin access",
            target="Administrative functions",
            result="Attempted privilege escalation with bypassed auth",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 6. ssrf_docker_api_escape
# ---------------------------------------------------------------------------
@register_chain
class SsrfDockerApiEscape(BaseChainTemplate):
    name = "ssrf_docker_api_escape"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        docker_obs = _obs_contains(findings, "docker")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if docker_obs:
            matched.append("Docker environment observed")
            mf["docker_obs"] = docker_obs
        else:
            missing.append("No Docker indicators observed")

        if ssrf and docker_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or docker_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Probe Docker daemon socket via SSRF",
            target="http://127.0.0.1:2375/version",
            result="Attempted to reach unauthenticated Docker API",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Create privileged container via Docker API",
            target="http://127.0.0.1:2375/containers/create",
            result="Attempted to spawn privileged container with host mount",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Execute command in privileged container to access host",
            target="Spawned container with host filesystem",
            result="Attempted container escape to host OS",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 7. ssrf_kubernetes_cluster_compromise
# ---------------------------------------------------------------------------
@register_chain
class SsrfKubernetesClusterCompromise(BaseChainTemplate):
    name = "ssrf_kubernetes_cluster_compromise"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        k8s_obs = _obs_contains(findings, "kubernetes", "k8s")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if k8s_obs:
            matched.append("Kubernetes environment observed")
            mf["k8s_obs"] = k8s_obs
        else:
            missing.append("No Kubernetes indicators observed")

        if ssrf and k8s_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or k8s_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Access Kubernetes API via SSRF",
            target="https://kubernetes.default.svc:443/api/v1/namespaces",
            result="Attempted to reach K8s API server via SSRF",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Read service account token from pod filesystem",
            target="/var/run/secrets/kubernetes.io/serviceaccount/token",
            result="Attempted to extract Kubernetes service account token",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Enumerate cluster secrets with stolen token",
            target="K8s secrets API",
            result="Attempted to list cluster-wide secrets",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Deploy malicious pod for lateral movement",
            target="K8s pod creation API",
            result="Attempted to create privileged pod in cluster",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 8. ssrf_redis_rce
# ---------------------------------------------------------------------------
@register_chain
class SsrfRedisRce(BaseChainTemplate):
    name = "ssrf_redis_rce"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        redis_loc = findings.locations_by_service("redis")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if redis_loc:
            matched.append("Redis service discovered")
            mf["redis_locations"] = redis_loc
        else:
            missing.append("No Redis service discovered")

        if ssrf and redis_loc:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Send SSRF payload to Redis via gopher protocol",
            target="gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO",
            result="Attempted to interact with Redis via SSRF+gopher",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Write crontab via Redis SLAVEOF / CONFIG SET",
            target="Redis server",
            result="Attempted to write cron entry for reverse shell via Redis",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Verify code execution via callback",
            target="Attacker callback listener",
            result="Checked for incoming connection from exploited host",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 9. ssrf_elasticsearch_exfil
# ---------------------------------------------------------------------------
@register_chain
class SsrfElasticsearchExfil(BaseChainTemplate):
    name = "ssrf_elasticsearch_exfil"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        es_loc = findings.locations_by_service("elasticsearch")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if es_loc:
            matched.append("Elasticsearch service discovered")
            mf["es_locations"] = es_loc
        else:
            missing.append("No Elasticsearch service discovered")

        if ssrf and es_loc:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Query Elasticsearch cluster info via SSRF",
            target="http://127.0.0.1:9200/",
            result="Attempted to fingerprint Elasticsearch cluster version",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="List all indices via _cat/indices",
            target="http://127.0.0.1:9200/_cat/indices?v",
            result="Attempted to enumerate all Elasticsearch indices",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Dump sensitive index data via _search",
            target="http://127.0.0.1:9200/users/_search?size=1000",
            result="Attempted to exfiltrate user data from Elasticsearch",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 10. ssrf_gcp_azure_metadata
# ---------------------------------------------------------------------------
@register_chain
class SsrfGcpAzureMetadata(BaseChainTemplate):
    name = "ssrf_gcp_azure_metadata"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        cloud_obs = _obs_contains(findings, "cloud", "gcp", "azure")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if cloud_obs:
            matched.append("GCP/Azure cloud environment observed")
            mf["cloud_obs"] = cloud_obs
        else:
            missing.append("No GCP/Azure cloud indicators observed")

        if ssrf and cloud_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or cloud_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Probe GCP metadata endpoint via SSRF",
            target="http://metadata.google.internal/computeMetadata/v1/",
            result="Attempted to access GCP metadata with Metadata-Flavor header",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Probe Azure IMDS endpoint via SSRF",
            target="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            result="Attempted to access Azure instance metadata service",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Extract access tokens from metadata response",
            target="Cloud metadata token endpoints",
            result="Attempted to retrieve OAuth2 access tokens from cloud provider",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 11. ssrf_internal_git_source_theft
# ---------------------------------------------------------------------------
@register_chain
class SsrfInternalGitSourceTheft(BaseChainTemplate):
    name = "ssrf_internal_git_source_theft"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        git_obs = _obs_contains(findings, "git")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if git_obs:
            matched.append("Internal Git service observed")
            mf["git_obs"] = git_obs
        else:
            missing.append("No internal Git indicators observed")

        if ssrf and git_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or git_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Access internal Gitea/GitLab API via SSRF",
            target="http://git.internal:3000/api/v1/repos/search",
            result="Attempted to enumerate internal Git repositories",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Clone private repository via SSRF proxy",
            target="Internal Git repository archive endpoint",
            result="Attempted to download repository archive via SSRF",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Extract secrets from repository contents",
            target="Downloaded repository files",
            result="Searched for credentials, API keys, and secrets in source",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 12. ssrf_consul_service_compromise
# ---------------------------------------------------------------------------
@register_chain
class SsrfConsulServiceCompromise(BaseChainTemplate):
    name = "ssrf_consul_service_compromise"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        consul_loc = findings.locations_by_service("consul")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if consul_loc:
            matched.append("Consul service discovered")
            mf["consul_locations"] = consul_loc
        else:
            missing.append("No Consul service discovered")

        if ssrf and consul_loc:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Query Consul catalog via SSRF",
            target="http://127.0.0.1:8500/v1/catalog/services",
            result="Attempted to enumerate all registered services in Consul",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Read KV store secrets from Consul",
            target="http://127.0.0.1:8500/v1/kv/?recurse",
            result="Attempted to dump all Consul KV store entries",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Register malicious service for traffic interception",
            target="Consul service registration API",
            result="Attempted to register rogue service for DNS-based redirection",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 13. ssrf_vault_secret_extraction
# ---------------------------------------------------------------------------
@register_chain
class SsrfVaultSecretExtraction(BaseChainTemplate):
    name = "ssrf_vault_secret_extraction"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        vault_obs = _obs_contains(findings, "vault")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if vault_obs:
            matched.append("HashiCorp Vault observed")
            mf["vault_obs"] = vault_obs
        else:
            missing.append("No Vault indicators observed")

        if ssrf and vault_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or vault_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Access Vault health endpoint via SSRF",
            target="http://vault.internal:8200/v1/sys/health",
            result="Attempted to verify Vault instance status",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="List secret engines via Vault API",
            target="http://vault.internal:8200/v1/sys/mounts",
            result="Attempted to enumerate mounted secret engines",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Extract secrets from KV engine",
            target="http://vault.internal:8200/v1/secret/data/",
            result="Attempted to read stored secrets from Vault",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 14. ssrf_memcached_session_hijack
# ---------------------------------------------------------------------------
@register_chain
class SsrfMemcachedSessionHijack(BaseChainTemplate):
    name = "ssrf_memcached_session_hijack"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        mc_loc = findings.locations_by_service("memcached")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if mc_loc:
            matched.append("Memcached service discovered")
            mf["memcached_locations"] = mc_loc
        else:
            missing.append("No Memcached service discovered")

        if ssrf and mc_loc:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Send Memcached stats command via SSRF",
            target="gopher://127.0.0.1:11211/_stats",
            result="Attempted to retrieve Memcached statistics via SSRF",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Dump cached session keys from Memcached",
            target="Memcached slab dump via stats cachedump",
            result="Attempted to enumerate cached session identifiers",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Replay stolen session token to hijack user session",
            target="Application authentication endpoint",
            result="Attempted to authenticate using stolen session data",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 15. ssrf_internal_smtp_phishing
# ---------------------------------------------------------------------------
@register_chain
class SsrfInternalSmtpPhishing(BaseChainTemplate):
    name = "ssrf_internal_smtp_phishing"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        smtp_loc = findings.locations_by_service("smtp")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if smtp_loc:
            matched.append("SMTP service discovered")
            mf["smtp_locations"] = smtp_loc
        else:
            missing.append("No SMTP service discovered")

        if ssrf and smtp_loc:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Connect to internal SMTP via SSRF gopher protocol",
            target="gopher://127.0.0.1:25/_EHLO attacker",
            result="Attempted to interact with internal SMTP server via SSRF",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Send spoofed email from internal domain",
            target="Internal SMTP relay",
            result="Attempted to send phishing email from trusted internal sender",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Verify email delivery via DNS callback",
            target="Attacker-controlled DNS server",
            result="Checked for DNS callback confirming SMTP interaction",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 16. ssrf_mongodb_data_dump
# ---------------------------------------------------------------------------
@register_chain
class SsrfMongodbDataDump(BaseChainTemplate):
    name = "ssrf_mongodb_data_dump"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        mongo_loc = findings.locations_by_service("mongodb")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if mongo_loc:
            matched.append("MongoDB service discovered")
            mf["mongodb_locations"] = mongo_loc
        else:
            missing.append("No MongoDB service discovered")

        if ssrf and mongo_loc:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Probe MongoDB via SSRF to check authentication",
            target="http://127.0.0.1:27017/",
            result="Attempted to determine if MongoDB requires authentication",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Enumerate databases via MongoDB HTTP interface",
            target="MongoDB internal interface",
            result="Attempted to list available databases",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Dump user collection from target database",
            target="MongoDB users collection",
            result="Attempted to exfiltrate user records from MongoDB",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 17. ssrf_prometheus_secret_leak
# ---------------------------------------------------------------------------
@register_chain
class SsrfPrometheusSecretLeak(BaseChainTemplate):
    name = "ssrf_prometheus_secret_leak"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        prom_obs = _obs_contains(findings, "prometheus", "grafana")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if prom_obs:
            matched.append("Prometheus/Grafana observed")
            mf["prometheus_obs"] = prom_obs
        else:
            missing.append("No Prometheus/Grafana indicators observed")

        if ssrf and prom_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or prom_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Access Prometheus configuration via SSRF",
            target="http://127.0.0.1:9090/api/v1/status/config",
            result="Attempted to retrieve Prometheus configuration with targets",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Query Prometheus targets for internal service map",
            target="http://127.0.0.1:9090/api/v1/targets",
            result="Attempted to map internal services via Prometheus targets",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Extract secrets from Prometheus config or Grafana datasources",
            target="Prometheus/Grafana configuration endpoints",
            result="Searched for database passwords and API keys in monitoring config",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 18. ssrf_etcd_config_extraction
# ---------------------------------------------------------------------------
@register_chain
class SsrfEtcdConfigExtraction(BaseChainTemplate):
    name = "ssrf_etcd_config_extraction"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        etcd_obs = _obs_contains(findings, "etcd")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if etcd_obs:
            matched.append("etcd service observed")
            mf["etcd_obs"] = etcd_obs
        else:
            missing.append("No etcd indicators observed")

        if ssrf and etcd_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or etcd_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Access etcd version endpoint via SSRF",
            target="http://127.0.0.1:2379/version",
            result="Attempted to fingerprint etcd cluster version",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Dump all keys from etcd via range API",
            target="http://127.0.0.1:2379/v3/kv/range",
            result="Attempted to enumerate all etcd keys",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Extract sensitive configuration from etcd values",
            target="etcd key-value store",
            result="Searched for database credentials and TLS keys in etcd data",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 19. ssrf_zookeeper_manipulation
# ---------------------------------------------------------------------------
@register_chain
class SsrfZookeeperManipulation(BaseChainTemplate):
    name = "ssrf_zookeeper_manipulation"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ssrf = _has_ssrf(findings)
        zk_obs = _obs_contains(findings, "zookeeper")
        matched: list[str] = []
        missing: list[str] = []
        mf: dict = {}
        if ssrf:
            matched.append("SSRF vulnerability found")
            mf["ssrf_vulns"] = ssrf
        else:
            missing.append("No SSRF vulnerability found")
        if zk_obs:
            matched.append("ZooKeeper service observed")
            mf["zookeeper_obs"] = zk_obs
        else:
            missing.append("No ZooKeeper indicators observed")

        if ssrf and zk_obs:
            return EvaluationResult(ChainViability.VIABLE, matched, missing, mf)
        if ssrf or zk_obs:
            return EvaluationResult(ChainViability.PARTIAL, matched, missing, mf)
        return EvaluationResult(ChainViability.NOT_VIABLE, matched, missing, mf)

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Send ZooKeeper 4-letter command via SSRF",
            target="http://127.0.0.1:2181 (ruok, envi, dump)",
            result="Attempted to query ZooKeeper status via SSRF",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Enumerate ZooKeeper znodes for sensitive config",
            target="ZooKeeper znode tree",
            result="Attempted to list znodes containing service configuration",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Modify ZooKeeper znode to redirect service traffic",
            target="ZooKeeper write API",
            result="Attempted to manipulate service discovery znodes",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )


# ---------------------------------------------------------------------------
# 20. webhook_injection_ssrf
# ---------------------------------------------------------------------------
@register_chain
class WebhookInjectionSsrf(BaseChainTemplate):
    name = "webhook_injection_ssrf"
    category = _CAT
    severity_on_success = _SEV
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        webhook = (findings.vulns_by_title_contains("webhook")
                   + findings.vulns_by_title_contains("callback"))
        if webhook:
            return EvaluationResult(
                viability=ChainViability.VIABLE,
                matched_preconditions=["Webhook/callback injection found"],
                matched_findings={"webhook_vulns": webhook},
            )
        return EvaluationResult(
            viability=ChainViability.NOT_VIABLE,
            matched_preconditions=[],
            missing_preconditions=["No webhook/callback injection found"],
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        steps.append(ChainStep(
            action="Inject attacker-controlled URL into webhook configuration",
            target="Application webhook settings",
            result="Attempted to set webhook URL to internal metadata service",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Trigger webhook to hit internal service",
            target="http://169.254.169.254/latest/meta-data/",
            result="Triggered webhook to make server-side request to metadata",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Capture webhook response with sensitive data",
            target="Attacker callback server",
            result="Attempted to capture server response containing internal data",
            timestamp=_now(),
        ))
        await step_delay()
        steps.append(ChainStep(
            action="Pivot using leaked credentials from webhook response",
            target="Cloud provider APIs",
            result="Attempted to use extracted tokens for further access",
            timestamp=_now(),
        ))
        return ChainResult(
            success=False, steps=steps, poc=None, chain_name=self.name,
            failure_reason="Dry-run: manual verification required",
        )
