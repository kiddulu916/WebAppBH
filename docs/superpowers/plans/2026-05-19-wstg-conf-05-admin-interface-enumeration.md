# WSTG-CONF-05: Admin Interface Enumeration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated `admin_interface_enumeration` pipeline stage to the `config_mgmt` worker implementing the full WSTG-CONF-05 methodology: wordlist path probing, platform-aware path injection, HTML link mining, auth-header fingerprinting, and parameter tampering.

**Architecture:** Two new tools (`AdminInterfaceEnumerator` + `AdminParamTamperer`) run concurrently in a new `admin_interface_enumeration` stage inserted after `backup_files`. `AdminInterfaceEnumerator` probes paths from a bundled wordlist (supplemented by DB platform fingerprints) and mines HTML for admin links. `AdminParamTamperer` reads discovered admin-interface Assets from the DB, fetches each page, and flips suspicious hidden-form fields and cookies to detect privilege-escalation via parameter tampering. Three-layer coherence (pipeline + playbooks + dashboard) is maintained throughout.

**Tech Stack:** Python 3.10, httpx (async), BeautifulSoup4, SQLAlchemy async (asyncpg), structlog, pytest, asyncio

---

## File Map

| File | Action |
|---|---|
| `workers/config_mgmt/wordlists/admin-panels.txt` | Create — bundled admin path wordlist (~800 entries) |
| `docker/Dockerfile.config_mgmt` | Modify — `COPY workers/config_mgmt/wordlists/ /wordlists/` |
| `workers/config_mgmt/tools/admin_interface_enumerator.py` | Create — Phase 0–3 enumerator tool |
| `workers/config_mgmt/tools/admin_param_tamperer.py` | Create — parameter tampering tool |
| `workers/config_mgmt/tools/__init__.py` | Modify — add two imports + `__all__` entries |
| `workers/config_mgmt/concurrency.py` | Modify — add two `TOOL_WEIGHTS` entries |
| `workers/config_mgmt/pipeline.py` | Modify — add `admin_interface_enumeration` stage |
| `shared/lib_webbh/playbooks.py` | Modify — add stage name to config_mgmt list |
| `dashboard/src/lib/worker-stages.ts` | Modify — add stage entry, fix api_discovery sectionId, renumber |
| `tests/unit/workers/config_mgmt/test_admin_interface_enumerator.py` | Create — unit tests for pure functions |
| `tests/unit/workers/config_mgmt/test_admin_param_tamperer.py` | Create — unit tests for pure functions |

---

## Task 1: Wordlist file and Dockerfile update

**Files:**
- Create: `workers/config_mgmt/wordlists/admin-panels.txt`
- Modify: `docker/Dockerfile.config_mgmt`

- [ ] **Step 1: Create the wordlists directory and populate admin-panels.txt**

Create `workers/config_mgmt/wordlists/admin-panels.txt` with the following content (curated subset of SecLists `Discovery/Web-Content/AdminPanels.txt`):

```
/admin
/admin/
/admin/login
/admin/login.php
/admin/index.php
/admin/index.html
/admin/dashboard
/admin/dashboard/
/admin/home
/admin/main
/admin/panel
/admin/cp
/admin/account
/admin/user/login
/admin/auth/login
/admin/controlpanel
/admin2
/adminpanel
/admin_panel
/adminarea
/admincp
/admin1
/administrator
/administrator/
/administrator/index.php
/administrator/login
/administrator/login.php
/manager
/manager/html
/manager/login
/manage
/manage/
/management
/management/
/control
/control/
/console
/console/
/server-status
/server-info
/nginx_status
/actuator
/actuator/health
/actuator/env
/actuator/metrics
/actuator/beans
/actuator/configprops
/actuator/mappings
/actuator/threaddump
/actuator/heapdump
/actuator/shutdown
/host-manager/html
/wp-admin
/wp-admin/
/wp-login.php
/wp-admin/admin-ajax.php
/wp-admin/admin.php
/administrator/index.php
/admin.php
/admin.html
/admin.asp
/admin.aspx
/admin.jsp
/phpmyadmin
/phpmyadmin/
/phpMyAdmin
/phpMyAdmin/
/phpMyAdmin/index.php
/pma
/pma/
/mysql
/mysql/
/cpanel
/cpanel/
/webmin
/webmin/
/kibana
/app/kibana
/app/kibana#/
/grafana
/grafana/
/prometheus
/prometheus/
/prometheus/targets
/jenkins
/jenkins/
/blue/organizations/jenkins
/solr
/solr/
/solr/admin
/solr/#/
/elasticsearch
/elasticsearch/
/_cluster/health
/_cat/indices
/_nodes
/horizon
/telescope
/nova
/filament
/django-admin/
/django-admin
/backend
/backend/
/backend/login
/backoffice
/backoffice/
/control-panel
/controlpanel
/cp
/cp/
/panel
/panel/
/portal
/portal/admin
/portal/login
/secure
/secure/
/security
/security/admin
/setup
/setup/
/install
/install/
/install.php
/maintenance
/maintenance/
/typo3
/typo3/
/TYPO3
/typo3/index.php
/sitecore
/sitecore/login
/umbraco
/umbraco/
/umbraco/login.aspx
/kentico
/EPiServer
/episerver
/adm
/adm/
/supervisor
/supervisor/
/supervisord
/user/admin
/users/admin
/mailman/admin
/roundcube
/squirrelmail
/horde
/webmail/admin
/myadmin
/_admin
/_manage
/_cpanel
/__admin
/adminer
/adminer.php
/db
/db/
/database
/database/
/dbadmin
/dbadmin/
/phpinfo
/phpinfo.php
/info.php
/test.php
/debug
/debug/
/trace
/trace/
/status
/status/
/health
/health/
/ping
/ping/
/metrics
/metrics/
/monitoring
/monitoring/
/nagios
/nagios/
/zabbix
/zabbix/
/icinga
/icinga/
/icingaweb2
/prtg
/prtg/
/cacti
/cacti/
/munin
/munin/
/netdata
/netdata/
/portainer
/portainer/
/traefik
/traefik/
/rabbitmq
/rabbitmq/
/flower
/celery
/celery/
/sidekiq
/sidekiq/
/resque
/resque/
/delayed_job
/airflow
/airflow/
/mlflow
/mlflow/
/jupyter
/jupyter/
/jupyterlab
/lab
/rstudio
/rstudio/
/shiny
/shiny/
/matomo
/matomo/
/piwik
/piwik/
/analytics
/analytics/
/stats
/stats/
/awstats
/awstats/
/webalizer
/webalizer/
/logwatch
/goaccess
/wp-admin/network/
/wp-admin/network/sites.php
/wp-admin/users.php
/wp-admin/options-general.php
/wp-admin/plugins.php
/administrator/components
/administrator/modules
/administrator/plugins
/joomla/administrator
/drupal/admin
/drupal/user/login
/craft/admin
/craft/admin/login
/statamic/cp
/statamic/cp/auth/login
/cockpit/admin
/directus/admin
/strapi/admin
/keystone/admin
/ghost/ghost
/ghost/ghost/signin
/october/backend
/october/backend/auth/signin
/pyrocms/admin
/flarum/admin
/phpbb/adm
/phpbb/adm/index.php
/vbulletin/admincp
/xenforo/admin.php
/mediawiki/index.php?title=Special:UserLogin
/dokuwiki/?do=admin
/redmine/login
/gitlab/admin
/gitea/admin
/nextcloud/settings/admin
/owncloud/settings/admin
/moodle/admin
/moodle/login
/magento/admin
/admin/dashboard/catalog
/admin/dashboard/sales
/prestashop/admin
/opencart/admin
/woocommerce/wp-admin
/bigcommerce/admin
/spree/admin
/ror/admin
/rails/info/properties
/rails/info/routes
/rails/mailers
/_profiler
/_profiler/phpinfo
/_wdt
/app_dev.php
/app_dev.php/_profiler
/app_dev.php/_wdt
/_debugbar
/debug/default/view
/elfinder
/elfinder/
/filemanager
/filemanager/
/file-manager
/images/admin
/attachments/admin
/uploads/admin
/favicon.ico
/robots.txt
/sitemap.xml
/.well-known/security.txt
/api/admin
/api/v1/admin
/api/v2/admin
/api/admin/users
/api/admin/config
/rest/admin
/rest/v1/admin
/graphql
/graphiql
/graphql/console
/api/graphql
```

- [ ] **Step 2: Update docker/Dockerfile.config_mgmt to copy the wordlist**

In `docker/Dockerfile.config_mgmt`, add the COPY line immediately before the `ENTRYPOINT` line:

Current last lines (around line 46–50):
```dockerfile
# Worker source
COPY workers/__init__.py /app/workers/__init__.py
COPY workers/config_mgmt /app/workers/config_mgmt

# Verify
RUN python -c "from workers.config_mgmt.main import main; print('config-mgmt OK')"

ENTRYPOINT ["python", "-m", "workers.config_mgmt.main"]
```

Replace with:
```dockerfile
# Worker source
COPY workers/__init__.py /app/workers/__init__.py
COPY workers/config_mgmt /app/workers/config_mgmt

# Admin interface wordlist
RUN mkdir -p /wordlists
COPY workers/config_mgmt/wordlists/ /wordlists/

# Verify
RUN python -c "from workers.config_mgmt.main import main; print('config-mgmt OK')"

ENTRYPOINT ["python", "-m", "workers.config_mgmt.main"]
```

- [ ] **Step 3: Commit**

```bash
git add workers/config_mgmt/wordlists/admin-panels.txt docker/Dockerfile.config_mgmt
git commit -m "feat(conf05): add admin-panels wordlist and Dockerfile COPY"
```

---

## Task 2: AdminInterfaceEnumerator — pure functions + unit tests

**Files:**
- Create: `workers/config_mgmt/tools/admin_interface_enumerator.py` (pure functions only — no execute() yet)
- Create: `tests/unit/workers/config_mgmt/test_admin_interface_enumerator.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/workers/config_mgmt/test_admin_interface_enumerator.py`:

```python
"""Unit tests for AdminInterfaceEnumerator pure functions (WSTG-CONF-05)."""
import pytest

from workers.config_mgmt.tools.admin_interface_enumerator import (
    AdminInterfaceEnumerator,
    _classify_200_response,
    _extract_admin_links,
    _inject_platform_paths,
    _load_wordlist,
)


# ── _load_wordlist ────────────────────────────────────────────────────────────

def test_load_wordlist_returns_list_of_strings(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("/admin\n/manager\n/admin\n")
    result = _load_wordlist(str(wl))
    assert "/admin" in result
    assert "/manager" in result


def test_load_wordlist_deduplicates(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("/admin\n/admin\n/manager\n")
    result = _load_wordlist(str(wl))
    assert result.count("/admin") == 1


def test_load_wordlist_strips_whitespace(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("  /admin  \n  /manager  \n")
    result = _load_wordlist(str(wl))
    assert "/admin" in result
    assert "  /admin  " not in result


def test_load_wordlist_skips_empty_lines(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("/admin\n\n/manager\n\n")
    result = _load_wordlist(str(wl))
    assert "" not in result


def test_load_wordlist_skips_comment_lines(tmp_path):
    wl = tmp_path / "test.txt"
    wl.write_text("# This is a comment\n/admin\n")
    result = _load_wordlist(str(wl))
    assert "# This is a comment" not in result
    assert "/admin" in result


def test_load_wordlist_missing_file_returns_empty_list():
    result = _load_wordlist("/nonexistent/path/wordlist.txt")
    assert result == []


# ── _inject_platform_paths ────────────────────────────────────────────────────

def test_inject_platform_paths_wordpress():
    result = _inject_platform_paths(["wordpress 6.2"])
    assert "/wp-admin" in result
    assert "/wp-login.php" in result
    assert "/wp-admin/admin-ajax.php" in result


def test_inject_platform_paths_django():
    result = _inject_platform_paths(["django 4.2"])
    assert "/admin/" in result
    assert "/django-admin/" in result


def test_inject_platform_paths_spring_actuator():
    result = _inject_platform_paths(["spring boot 3.0"])
    assert "/actuator" in result
    assert "/actuator/env" in result
    assert "/actuator/health" in result


def test_inject_platform_paths_tomcat():
    result = _inject_platform_paths(["apache tomcat 9"])
    assert "/manager/html" in result
    assert "/host-manager/html" in result


def test_inject_platform_paths_joomla():
    result = _inject_platform_paths(["joomla 4.3"])
    assert "/administrator/" in result
    assert "/administrator/index.php" in result


def test_inject_platform_paths_laravel():
    result = _inject_platform_paths(["laravel 10"])
    assert "/horizon" in result
    assert "/telescope" in result


def test_inject_platform_paths_jenkins():
    result = _inject_platform_paths(["jenkins 2.400"])
    assert "/jenkins" in result


def test_inject_platform_paths_kibana():
    result = _inject_platform_paths(["kibana 8.0"])
    assert "/kibana" in result
    assert "/app/kibana" in result


def test_inject_platform_paths_unknown_platform_returns_empty():
    result = _inject_platform_paths(["unknown framework 1.0"])
    assert result == []


def test_inject_platform_paths_empty_list_returns_empty():
    result = _inject_platform_paths([])
    assert result == []


def test_inject_platform_paths_case_insensitive():
    result = _inject_platform_paths(["WordPress 6.2"])
    assert "/wp-admin" in result


# ── _classify_200_response ────────────────────────────────────────────────────

def test_classify_200_no_password_field_is_high():
    severity, vuln_type = _classify_200_response("<html><body>Welcome Admin</body></html>")
    assert severity == "high"
    assert vuln_type == "admin_interface_exposed_unauthenticated"


def test_classify_200_with_password_field_is_medium():
    html = '<html><form><input type="password" name="pass"/></form></html>'
    severity, vuln_type = _classify_200_response(html)
    assert severity == "medium"
    assert vuln_type == "admin_interface_exposed"


def test_classify_200_password_type_detection_case_insensitive():
    html = '<input TYPE="PASSWORD" name="pass"/>'
    severity, _ = _classify_200_response(html)
    assert severity == "medium"


def test_classify_200_empty_body_is_high():
    severity, _ = _classify_200_response("")
    assert severity == "high"


# ── _extract_admin_links ──────────────────────────────────────────────────────

def test_extract_admin_links_finds_href_with_admin_keyword():
    html = '<html><body><a href="/admin/panel">Panel</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert "/admin/panel" in result


def test_extract_admin_links_finds_form_action():
    html = '<html><body><form action="/manage/settings"></form></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert "/manage/settings" in result


def test_extract_admin_links_skips_external_urls():
    html = '<html><body><a href="https://evil.com/admin">bad</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert "https://evil.com/admin" not in result


def test_extract_admin_links_skips_non_admin_hrefs():
    html = '<html><body><a href="/login">login</a><a href="/dashboard">dash</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    # /login has no admin keyword; /dashboard has no admin keyword in the KEYWORDS set
    for link in result:
        assert any(kw in link for kw in [
            "admin", "administrator", "manage", "manager", "control",
            "console", "panel", "backend", "backoffice", "setup",
            "config", "cpanel", "webmin", "plesk", "dashboard",
        ])


def test_extract_admin_links_deduplicates():
    html = '<html><body><a href="/admin">1</a><a href="/admin">2</a></body></html>'
    result = _extract_admin_links(html, "https://example.com")
    assert result.count("/admin") == 1


def test_extract_admin_links_empty_html_returns_empty():
    result = _extract_admin_links("", "https://example.com")
    assert result == []


# ── AdminInterfaceEnumerator class ────────────────────────────────────────────

def test_tool_has_correct_name():
    assert AdminInterfaceEnumerator.name == "admin_interface_enumerator"


def test_build_command_raises():
    tool = AdminInterfaceEnumerator()
    with pytest.raises(NotImplementedError):
        tool.build_command(object())


def test_parse_output_raises():
    tool = AdminInterfaceEnumerator()
    with pytest.raises(NotImplementedError):
        tool.parse_output("")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd C:\Users\dat1k\Projects\WebAppBH
python -m pytest tests/unit/workers/config_mgmt/test_admin_interface_enumerator.py -v 2>&1 | head -30
```

Expected: `ImportError` or `ModuleNotFoundError` — the file does not exist yet.

- [ ] **Step 3: Create admin_interface_enumerator.py with pure functions**

Create `workers/config_mgmt/tools/admin_interface_enumerator.py`:

```python
"""Admin interface enumeration tool — WSTG-CONF-05."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf05")

_WORDLIST_PATH = "/wordlists/admin-panels.txt"
_HTTP_CONCURRENCY = 20
_SECTION_ID = "WSTG-CONF-05"

_ADMIN_KEYWORDS = frozenset({
    "admin", "administrator", "manage", "manager", "control",
    "console", "panel", "backend", "backoffice", "maintenance",
    "setup", "config", "configure", "cpanel", "webmin", "plesk", "dashboard",
})

_PLATFORM_PATHS: dict[str, list[str]] = {
    "wordpress":  ["/wp-admin", "/wp-login.php", "/wp-admin/admin-ajax.php"],
    "joomla":     ["/administrator/", "/administrator/index.php"],
    "django":     ["/admin/", "/django-admin/"],
    "laravel":    ["/admin", "/horizon", "/telescope"],
    "spring":     ["/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics"],
    "actuator":   ["/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics"],
    "tomcat":     ["/manager/html", "/host-manager/html"],
    "jenkins":    ["/jenkins", "/blue/organizations/jenkins"],
    "kibana":     ["/kibana", "/app/kibana"],
}


def _load_wordlist(path: str) -> list[str]:
    """Load paths from a wordlist file, deduplicate, strip whitespace, skip comments."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            result.append(line)
    return result


def _inject_platform_paths(fingerprints: list[str]) -> list[str]:
    """Return platform-specific admin paths for each detected fingerprint."""
    paths: list[str] = []
    joined = " ".join(fingerprints).lower()
    for keyword, extra in _PLATFORM_PATHS.items():
        if keyword in joined:
            paths.extend(extra)
    return paths


def _classify_200_response(body: str) -> tuple[str, str]:
    """Return (severity, vuln_type) for an HTTP 200 admin path response."""
    if re.search(r'<input[^>]+type\s*=\s*["\']?password', body, re.IGNORECASE):
        return "medium", "admin_interface_exposed"
    return "high", "admin_interface_exposed_unauthenticated"


def _extract_admin_links(html: str, base_url: str) -> list[str]:
    """Parse HTML and return same-origin paths that contain an admin keyword."""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []
    base_host = urlparse(base_url).netloc
    seen: set[str] = set()
    result: list[str] = []
    for tag in soup.find_all(["a", "form", "link"]):
        href = tag.get("href") or tag.get("action") or ""
        if not href:
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.netloc and parsed.netloc != base_host:
            continue
        path = parsed.path
        if not path or path in seen:
            continue
        if any(kw in path.lower() for kw in _ADMIN_KEYWORDS):
            seen.add(path)
            result.append(path)
    return result


class AdminInterfaceEnumerator(ConfigMgmtTool):
    """Enumerate admin interfaces via wordlist probing, HTML link mining,
    and auth-header fingerprinting. WSTG-CONF-05."""

    name = "admin_interface_enumerator"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("AdminInterfaceEnumerator uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("AdminInterfaceEnumerator uses execute() directly")

    def _base_url(self, target) -> str:
        value = getattr(target, "target_value", str(target))
        if value.startswith(("http://", "https://")):
            return value.rstrip("/")
        return f"https://{value.rstrip('/')}"

    async def _probe_path(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
        sem: asyncio.Semaphore,
    ) -> dict | None:
        """HEAD (fallback GET on 405) one path. Return result dict or None."""
        url = base_url + path
        async with sem:
            try:
                resp = await client.head(url)
                if resp.status_code == 405:
                    resp = await client.get(url)
                status = resp.status_code
                if status == 200:
                    body = resp.text if hasattr(resp, "text") else ""
                    if not body:
                        full = await client.get(url)
                        body = full.text
                        status = full.status_code
                    severity, vuln_type = _classify_200_response(body)
                    return {
                        "vulnerability": {
                            "name": f"Admin interface accessible: {path}",
                            "severity": severity,
                            "description": (
                                f"Admin path {url} returned HTTP 200. "
                                f"{'No login form detected — may be accessible without authentication.' if severity == 'high' else 'Login form present.'}"
                            ),
                            "location": url,
                            "section_id": _SECTION_ID,
                        }
                    }
                if status in (401, 403):
                    return {"observation": {
                        "type": "admin_access_denied",
                        "value": url,
                        "details": {"path": path, "status": status},
                    }}
                if status in (301, 302, 307, 308):
                    return {"observation": {
                        "type": "admin_redirect",
                        "value": url,
                        "details": {
                            "path": path,
                            "status": status,
                            "location": resp.headers.get("location", ""),
                        },
                    }}
            except httpx.RequestError:
                pass
        return None

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, tool=self.name)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0,
                "message": f"{self.name} started",
            })

            base_url = self._base_url(target)

            # Phase 0 — DB reads + wordlist
            async with get_session() as session:
                stmt = select(Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type == "platform_fingerprint",
                )
                rows = (await session.execute(stmt)).scalars().all()
                fingerprints = list(rows)

            paths = _load_wordlist(_WORDLIST_PATH)
            paths.extend(_inject_platform_paths(fingerprints))
            # deduplicate while preserving order
            seen_paths: set[str] = set()
            deduped: list[str] = []
            for p in paths:
                if p not in seen_paths:
                    seen_paths.add(p)
                    deduped.append(p)
            paths = deduped

            inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)
            all_results: list[dict] = []
            realms: list[str] = []

            client_kwargs = dict(
                verify=False, follow_redirects=False, timeout=10,
                headers=headers or {},
            )

            async with httpx.AsyncClient(**client_kwargs) as client:
                # Phase 1 — wordlist probing
                probe_tasks = [
                    self._probe_path(client, base_url, p, inner_sem)
                    for p in paths
                ]
                phase1 = await asyncio.gather(*probe_tasks, return_exceptions=True)
                for r in phase1:
                    if isinstance(r, dict):
                        all_results.append(r)
                        # collect 401 locations for WWW-Authenticate fingerprinting
                        if (r.get("observation", {}).get("type") == "admin_access_denied"
                                and r["observation"]["details"].get("status") == 401):
                            realms.append(r["observation"]["value"])

                # Phase 2 — HTML link mining
                for home_path in ("/", "/index"):
                    try:
                        resp = await client.get(base_url + home_path)
                        if resp.status_code == 200:
                            links = _extract_admin_links(resp.text, base_url)
                            link_tasks = [
                                self._probe_path(client, base_url, lnk, inner_sem)
                                for lnk in links
                            ]
                            link_results = await asyncio.gather(*link_tasks, return_exceptions=True)
                            for r in link_results:
                                if isinstance(r, dict):
                                    all_results.append(r)
                            # record discovered links as observations
                            for lnk in links:
                                all_results.append({"observation": {
                                    "type": "admin_link",
                                    "value": base_url + lnk,
                                    "details": {"path": lnk, "source": "html_mining"},
                                }})
                    except httpx.RequestError:
                        pass

                # Phase 3 — auth-header fingerprinting on 401 URLs
                for url_401 in realms:
                    try:
                        resp = await client.get(url_401)
                        www_auth = resp.headers.get("www-authenticate", "")
                        if www_auth:
                            realm_match = re.search(r'realm\s*=\s*["\']?([^"\'>,]+)', www_auth, re.I)
                            realm = realm_match.group(1).strip() if realm_match else www_auth
                            all_results.append({"observation": {
                                "type": "auth_realm",
                                "value": url_401,
                                "details": {"realm": realm, "www_authenticate": www_auth},
                            }})
                    except httpx.RequestError:
                        pass

            # Persist
            found = len(all_results)
            new_count = in_scope_count = 0
            for item in all_results:
                inserted = await self._process_result(item, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            # Update job_state
            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                job = (await session.execute(stmt)).scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.utcnow()
                    await session.commit()

            stats = {"found": found, "in_scope": in_scope_count, "new": new_count, "skipped_cooldown": False}
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": f"{self.name}: {new_count} new, {in_scope_count} in scope, {found} total",
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/workers/config_mgmt/test_admin_interface_enumerator.py -v
```

Expected: All tests pass. If `bs4` is not installed in the local dev env, run `pip install -e "shared/lib_webbh[dev]"` then check if `beautifulsoup4` is in `workers/config_mgmt/requirements.txt` (add if missing).

- [ ] **Step 5: Check beautifulsoup4 is in worker requirements**

Read `workers/config_mgmt/requirements.txt`. If `beautifulsoup4` is not present, add it:

```
beautifulsoup4>=4.12.0
```

- [ ] **Step 6: Commit**

```bash
git add workers/config_mgmt/tools/admin_interface_enumerator.py \
        tests/unit/workers/config_mgmt/test_admin_interface_enumerator.py
git commit -m "feat(conf05): add AdminInterfaceEnumerator with pure functions and unit tests"
```

---

## Task 3: AdminParamTamperer — pure functions + unit tests

**Files:**
- Create: `workers/config_mgmt/tools/admin_param_tamperer.py`
- Create: `tests/unit/workers/config_mgmt/test_admin_param_tamperer.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/workers/config_mgmt/test_admin_param_tamperer.py`:

```python
"""Unit tests for AdminParamTamperer pure functions (WSTG-CONF-05)."""
import pytest

from workers.config_mgmt.tools.admin_param_tamperer import (
    AdminParamTamperer,
    _build_flip_values,
    _classify_tamper_response,
    _extract_hidden_inputs,
    _filter_admin_params,
)


# ── _extract_hidden_inputs ────────────────────────────────────────────────────

def test_extract_hidden_inputs_finds_hidden_field():
    html = '<form><input type="hidden" name="admin" value="0"/></form>'
    result = _extract_hidden_inputs(html)
    assert ("admin", "0") in result


def test_extract_hidden_inputs_ignores_visible_inputs():
    html = '<form><input type="text" name="username" value="user"/></form>'
    result = _extract_hidden_inputs(html)
    assert ("username", "user") not in result


def test_extract_hidden_inputs_handles_missing_value():
    html = '<form><input type="hidden" name="debug"/></form>'
    result = _extract_hidden_inputs(html)
    assert ("debug", "") in result


def test_extract_hidden_inputs_empty_html_returns_empty():
    assert _extract_hidden_inputs("") == []


def test_extract_hidden_inputs_no_hidden_fields_returns_empty():
    html = '<form><input type="text" name="q"/></form>'
    assert _extract_hidden_inputs(html) == []


def test_extract_hidden_inputs_multiple_fields():
    html = '''<form>
        <input type="hidden" name="admin" value="0"/>
        <input type="hidden" name="role" value="user"/>
    </form>'''
    result = _extract_hidden_inputs(html)
    assert ("admin", "0") in result
    assert ("role", "user") in result


# ── _filter_admin_params ──────────────────────────────────────────────────────

def test_filter_admin_params_keeps_admin_param():
    result = _filter_admin_params([("admin", "0"), ("username", "alice")])
    assert ("admin", "0") in result


def test_filter_admin_params_removes_non_suspicious_param():
    result = _filter_admin_params([("username", "alice"), ("email", "a@b.com")])
    assert ("username", "alice") not in result
    assert ("email", "a@b.com") not in result


def test_filter_admin_params_keeps_role_param():
    result = _filter_admin_params([("role", "user")])
    assert ("role", "user") in result


def test_filter_admin_params_keeps_is_admin_param():
    result = _filter_admin_params([("is_admin", "false")])
    assert ("is_admin", "false") in result


def test_filter_admin_params_keeps_debug_param():
    result = _filter_admin_params([("debug", "0")])
    assert ("debug", "0") in result


def test_filter_admin_params_empty_input_returns_empty():
    assert _filter_admin_params([]) == []


def test_filter_admin_params_partial_match():
    # "useradmin" contains "admin"
    result = _filter_admin_params([("useradmin", "0")])
    assert ("useradmin", "0") in result


# ── _build_flip_values ────────────────────────────────────────────────────────

def test_build_flip_values_zero_becomes_one():
    result = _build_flip_values("0")
    assert "1" in result


def test_build_flip_values_false_becomes_true():
    result = _build_flip_values("false")
    assert "true" in result


def test_build_flip_values_no_becomes_yes():
    result = _build_flip_values("no")
    assert "yes" in result


def test_build_flip_values_user_becomes_admin():
    result = _build_flip_values("user")
    assert "admin" in result


def test_build_flip_values_guest_becomes_admin():
    result = _build_flip_values("guest")
    assert "admin" in result


def test_build_flip_values_unknown_value_includes_admin_and_one():
    result = _build_flip_values("xyz_unknown")
    assert "admin" in result
    assert "1" in result


def test_build_flip_values_returns_list():
    assert isinstance(_build_flip_values("0"), list)


# ── _classify_tamper_response ─────────────────────────────────────────────────

def test_classify_tamper_status_bypass_is_critical():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=403, new_status=200,
        baseline_len=100, new_len=100, new_body="some content",
    )
    assert severity == "critical"
    assert vuln_type == "parameter_tampering_bypass"


def test_classify_tamper_redirect_bypass_is_critical():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=302, new_status=200,
        baseline_len=100, new_len=500, new_body="dashboard panel",
    )
    assert severity == "critical"
    assert vuln_type == "parameter_tampering_bypass"


def test_classify_tamper_admin_keyword_in_body_is_high():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=150, new_body="welcome to the admin dashboard",
    )
    assert severity == "high"
    assert vuln_type == "parameter_tampering_escalation"


def test_classify_tamper_large_body_change_is_medium():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=200, new_body="some regular content here",
    )
    assert severity == "medium"
    assert vuln_type == "parameter_tampering_indicator"


def test_classify_tamper_no_change_returns_none():
    severity, vuln_type = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=102, new_body="same content roughly",
    )
    assert severity is None
    assert vuln_type is None


def test_classify_tamper_admin_keywords_panel():
    severity, _ = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=110, new_body="control panel settings",
    )
    assert severity == "high"


def test_classify_tamper_admin_keywords_users():
    severity, _ = _classify_tamper_response(
        baseline_status=200, new_status=200,
        baseline_len=100, new_len=110, new_body="manage users configuration",
    )
    assert severity == "high"


# ── AdminParamTamperer class ──────────────────────────────────────────────────

def test_tool_has_correct_name():
    assert AdminParamTamperer.name == "admin_param_tamperer"


def test_build_command_raises():
    tool = AdminParamTamperer()
    with pytest.raises(NotImplementedError):
        tool.build_command(object())


def test_parse_output_raises():
    tool = AdminParamTamperer()
    with pytest.raises(NotImplementedError):
        tool.parse_output("")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/workers/config_mgmt/test_admin_param_tamperer.py -v 2>&1 | head -20
```

Expected: `ImportError` — the module does not exist yet.

- [ ] **Step 3: Create admin_param_tamperer.py**

Create `workers/config_mgmt/tools/admin_param_tamperer.py`:

```python
"""Admin parameter tampering tool — WSTG-CONF-05."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select

from lib_webbh import Asset, JobState, get_session, push_task, setup_logger
from lib_webbh.scope import ScopeManager

from workers.config_mgmt.base_tool import ConfigMgmtTool
from workers.config_mgmt.concurrency import get_semaphore

logger = setup_logger("config-mgmt-conf05")

_HTTP_CONCURRENCY = 10
_SECTION_ID = "WSTG-CONF-05"

_ADMIN_PARAM_PATTERNS = frozenset({
    "admin", "useradmin", "is_admin", "isadmin", "administrator",
    "role", "user_type", "usertype", "access", "privilege", "level",
    "debug", "test", "dev", "development", "staff", "superuser",
    "su", "root", "authorized", "auth", "authenticated",
})

_FLIP_MAP: dict[str, str] = {
    "0": "1",
    "false": "true",
    "no": "yes",
    "user": "admin",
    "guest": "admin",
    "readonly": "admin",
}

_ADMIN_BODY_KEYWORDS = frozenset({
    "dashboard", "panel", "settings", "users", "configuration",
    "logout", "welcome", "administrator", "manage", "control",
})


def _extract_hidden_inputs(html: str) -> list[tuple[str, str]]:
    """Return list of (name, value) pairs for all hidden input fields."""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []
    result = []
    for inp in soup.find_all("input"):
        if str(inp.get("type", "")).lower() == "hidden":
            name = inp.get("name", "")
            value = inp.get("value", "") or ""
            if name:
                result.append((name, value))
    return result


def _filter_admin_params(
    params: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Keep only params whose name contains a suspicious admin-related keyword."""
    result = []
    for name, value in params:
        name_lower = name.lower()
        if any(kw in name_lower for kw in _ADMIN_PARAM_PATTERNS):
            result.append((name, value))
    return result


def _build_flip_values(value: str) -> list[str]:
    """Return a list of candidate replacement values to test for this parameter."""
    lower = value.lower().strip()
    if lower in _FLIP_MAP:
        return [_FLIP_MAP[lower], "admin", "1"]
    return ["admin", "1", "true", "yes"]


def _classify_tamper_response(
    baseline_status: int,
    new_status: int,
    baseline_len: int,
    new_len: int,
    new_body: str,
) -> tuple[str | None, str | None]:
    """Return (severity, vuln_type) if the tampered response differs meaningfully.

    Returns (None, None) if no significant change is detected.
    """
    # Status code bypass
    if baseline_status in (403, 302, 401) and new_status == 200:
        return "critical", "parameter_tampering_bypass"

    new_body_lower = new_body.lower()

    # Admin keywords appeared in body
    if any(kw in new_body_lower for kw in _ADMIN_BODY_KEYWORDS):
        return "high", "parameter_tampering_escalation"

    # Significant body length change (> 20%)
    if baseline_len > 0 and abs(new_len - baseline_len) / baseline_len > 0.20:
        return "medium", "parameter_tampering_indicator"

    return None, None


class AdminParamTamperer(ConfigMgmtTool):
    """Test parameter tampering on discovered admin interfaces. WSTG-CONF-05."""

    name = "admin_param_tamperer"

    def build_command(self, target, headers=None) -> list[str]:
        raise NotImplementedError("AdminParamTamperer uses execute() directly")

    def parse_output(self, stdout: str) -> list:
        raise NotImplementedError("AdminParamTamperer uses execute() directly")

    async def execute(
        self,
        target,
        scope_manager: ScopeManager,
        target_id: int,
        container_name: str,
        headers: dict | None = None,
    ) -> dict:
        log = logger.bind(target_id=target_id, tool=self.name)

        if await self.check_cooldown(target_id, container_name):
            log.info("Skipping — within cooldown period")
            return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": True}

        sem = get_semaphore(self.weight_class)
        await sem.acquire()
        try:
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 0,
                "message": f"{self.name} started",
            })

            # Phase 0 — DB reads
            async with get_session() as session:
                stmt = select(Asset.asset_value).where(
                    Asset.target_id == target_id,
                    Asset.asset_type.in_(["admin_interface", "admin_redirect"]),
                    Asset.source_tool.in_([
                        "admin_interface_finder",
                        "admin_interface_enumerator",
                    ]),
                )
                rows = (await session.execute(stmt)).scalars().all()
                urls = list(rows)

            if not urls:
                log.info(f"{self.name}: no admin interfaces in DB — skipping")
                await push_task(f"events:{target_id}", {
                    "event": "TOOL_PROGRESS", "container": container_name,
                    "tool": self.name, "progress": 100,
                    "message": f"{self.name}: no targets found",
                })
                return {"found": 0, "in_scope": 0, "new": 0, "skipped_cooldown": False}

            all_results: list[dict] = []
            inner_sem = asyncio.Semaphore(_HTTP_CONCURRENCY)

            client_kwargs = dict(
                verify=False, follow_redirects=False, timeout=10,
                headers=headers or {},
            )

            async def _tamper_url(client: httpx.AsyncClient, url: str) -> list[dict]:
                results: list[dict] = []
                async with inner_sem:
                    try:
                        base_resp = await client.get(url)
                        baseline_status = base_resp.status_code
                        baseline_body = base_resp.text
                        baseline_len = len(baseline_body)

                        params = _filter_admin_params(
                            _extract_hidden_inputs(baseline_body)
                        )

                        # Also check Set-Cookie for suspicious names
                        for cookie_header in base_resp.headers.get_list("set-cookie"):
                            name_part = cookie_header.split("=", 1)
                            if len(name_part) == 2:
                                name = name_part[0].strip()
                                value = name_part[1].split(";")[0].strip()
                                params.extend(_filter_admin_params([(name, value)]))

                        for param_name, param_value in params:
                            for flip in _build_flip_values(param_value):
                                try:
                                    tampered = await client.get(
                                        url, params={param_name: flip}
                                    )
                                    severity, vuln_type = _classify_tamper_response(
                                        baseline_status=baseline_status,
                                        new_status=tampered.status_code,
                                        baseline_len=baseline_len,
                                        new_len=len(tampered.text),
                                        new_body=tampered.text,
                                    )
                                    if severity:
                                        results.append({"vulnerability": {
                                            "name": f"Parameter tampering on {param_name}: {url}",
                                            "severity": severity,
                                            "description": (
                                                f"Setting {param_name}={flip} on {url} "
                                                f"changed response from HTTP {baseline_status} "
                                                f"to HTTP {tampered.status_code}."
                                            ),
                                            "location": url,
                                            "section_id": _SECTION_ID,
                                        }})
                                        break  # one finding per param is enough
                                except httpx.RequestError:
                                    pass
                    except httpx.RequestError:
                        pass
                return results

            async with httpx.AsyncClient(**client_kwargs) as client:
                tasks = [_tamper_url(client, url) for url in urls]
                gathered = await asyncio.gather(*tasks, return_exceptions=True)
                for r in gathered:
                    if isinstance(r, list):
                        all_results.extend(r)

            found = len(all_results)
            new_count = in_scope_count = 0
            for item in all_results:
                inserted = await self._process_result(item, scope_manager, target_id, log)
                if inserted is not None:
                    in_scope_count += 1
                    if inserted:
                        new_count += 1

            async with get_session() as session:
                stmt = select(JobState).where(
                    JobState.target_id == target_id,
                    JobState.container_name == container_name,
                )
                job = (await session.execute(stmt)).scalar_one_or_none()
                if job:
                    job.last_tool_executed = self.name
                    job.last_seen = datetime.utcnow()
                    await session.commit()

            stats = {"found": found, "in_scope": in_scope_count, "new": new_count, "skipped_cooldown": False}
            await push_task(f"events:{target_id}", {
                "event": "TOOL_PROGRESS", "container": container_name,
                "tool": self.name, "progress": 100,
                "message": f"{self.name}: {new_count} new, {in_scope_count} in scope, {found} total",
            })
            log.info(f"{self.name} complete", extra=stats)
            return stats

        finally:
            sem.release()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/workers/config_mgmt/test_admin_param_tamperer.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add workers/config_mgmt/tools/admin_param_tamperer.py \
        tests/unit/workers/config_mgmt/test_admin_param_tamperer.py
git commit -m "feat(conf05): add AdminParamTamperer with pure functions and unit tests"
```

---

## Task 4: Three-layer sync — wire up all integration points

**Files:**
- Modify: `workers/config_mgmt/tools/__init__.py`
- Modify: `workers/config_mgmt/concurrency.py`
- Modify: `workers/config_mgmt/pipeline.py`
- Modify: `shared/lib_webbh/playbooks.py`
- Modify: `dashboard/src/lib/worker-stages.ts`

- [ ] **Step 1: Update tools/__init__.py**

Read `workers/config_mgmt/tools/__init__.py` — it currently imports 14 tools. Add the two new ones:

```python
# Config management tools package

from .network_config_tester import NetworkConfigTester
from .admin_interface_finder import AdminInterfaceFinder
from .admin_interface_enumerator import AdminInterfaceEnumerator
from .admin_param_tamperer import AdminParamTamperer
from .default_credential_tester import DefaultCredentialTester
from .platform_fingerprinter import PlatformFingerprinter
from .file_extension_tester import FileExtensionTester
from .backup_file_finder import BackupFileFinder
from .ffuf_tool import FfufTool
from .api_discovery_tool import ApiDiscoveryTool
from .http_method_tester import HttpMethodTester
from .hsts_tester import HstsTester
from .rpc_tester import RpcTester
from .file_inclusion_tester import FileInclusionTester
from .subdomain_takeover_checker import SubdomainTakeoverChecker
from .cloud_storage_auditor import CloudStorageAuditor

__all__ = [
    "NetworkConfigTester",
    "AdminInterfaceFinder",
    "AdminInterfaceEnumerator",
    "AdminParamTamperer",
    "DefaultCredentialTester",
    "PlatformFingerprinter",
    "FileExtensionTester",
    "BackupFileFinder",
    "FfufTool",
    "ApiDiscoveryTool",
    "HttpMethodTester",
    "HstsTester",
    "RpcTester",
    "FileInclusionTester",
    "SubdomainTakeoverChecker",
    "CloudStorageAuditor",
]
```

- [ ] **Step 2: Update concurrency.py**

Read `workers/config_mgmt/concurrency.py`. Add two entries to `TOOL_WEIGHTS` after the `"admin_interface_finder"` entry:

```python
TOOL_WEIGHTS = {
    "network_config_tester":      WeightClass.LIGHT,
    "admin_interface_finder":     WeightClass.HEAVY,
    "admin_interface_enumerator": WeightClass.HEAVY,   # ADD
    "admin_param_tamperer":       WeightClass.LIGHT,   # ADD
    "default_credential_tester":  WeightClass.HEAVY,
    "platform_fingerprinter":     WeightClass.LIGHT,
    "file_extension_tester":      WeightClass.LIGHT,
    "backup_file_finder":         WeightClass.LIGHT,
    "FfufTool":                   WeightClass.HEAVY,
    "api_discovery_tool":         WeightClass.LIGHT,
    "http_method_tester":         WeightClass.LIGHT,
    "hsts_tester":                WeightClass.LIGHT,
    "rpc_tester":                 WeightClass.LIGHT,
    "file_inclusion_tester":      WeightClass.LIGHT,
    "subdomain_takeover_checker": WeightClass.LIGHT,
    "cloud_storage_auditor":      WeightClass.LIGHT,
}
```

- [ ] **Step 3: Update pipeline.py**

Read `workers/config_mgmt/pipeline.py`. Add the import and new stage. The full updated imports block and STAGES list:

```python
from workers.config_mgmt.tools import (
    NetworkConfigTester,
    AdminInterfaceFinder,
    AdminInterfaceEnumerator,
    AdminParamTamperer,
    DefaultCredentialTester,
    PlatformFingerprinter,
    FileExtensionTester,
    BackupFileFinder,
    FfufTool,
    ApiDiscoveryTool,
    HttpMethodTester,
    HstsTester,
    RpcTester,
    FileInclusionTester,
    SubdomainTakeoverChecker,
    CloudStorageAuditor,
)
```

```python
STAGES = [
    Stage("network_config",               [NetworkConfigTester, AdminInterfaceFinder]),
    Stage("network_config_cred_test",     [DefaultCredentialTester]),
    Stage("platform_config",              [PlatformFingerprinter]),
    Stage("file_extension_handling",      [FileExtensionTester]),
    Stage("backup_files",                 [BackupFileFinder, FfufTool]),
    Stage("admin_interface_enumeration",  [AdminInterfaceEnumerator, AdminParamTamperer]),
    Stage("api_discovery",                [ApiDiscoveryTool]),
    Stage("http_methods",                 [HttpMethodTester]),
    Stage("hsts_testing",                 [HstsTester]),
    Stage("rpc_testing",                  [RpcTester]),
    Stage("file_inclusion",               [FileInclusionTester]),
    Stage("subdomain_takeover",           [SubdomainTakeoverChecker]),
    Stage("cloud_storage",                [CloudStorageAuditor]),
]
```

- [ ] **Step 4: Update playbooks.py**

Read `shared/lib_webbh/playbooks.py`. Find the `"config_mgmt"` list. Add `"admin_interface_enumeration"` after `"backup_files"`:

```python
"config_mgmt": [
    "network_config",
    "network_config_cred_test",
    "platform_config",
    "file_extension_handling",
    "backup_files",
    "admin_interface_enumeration",
    "api_discovery",
    "http_methods",
    "hsts_testing",
    "rpc_testing",
    "file_inclusion",
    "subdomain_takeover",
    "cloud_storage",
],
```

- [ ] **Step 5: Update worker-stages.ts**

Read `dashboard/src/lib/worker-stages.ts`. Replace the entire `config_mgmt` array:

```typescript
config_mgmt: [
  { id: "1",  name: "Network Configuration",          stageName: "network_config",               sectionId: "WSTG-CONF-01" },
  { id: "1b", name: "Credential Testing",              stageName: "network_config_cred_test",     sectionId: "WSTG-CONF-01" },
  { id: "2",  name: "Platform Configuration",          stageName: "platform_config",              sectionId: "WSTG-CONF-02" },
  { id: "3",  name: "File Extension Handling",         stageName: "file_extension_handling",      sectionId: "WSTG-CONF-03" },
  { id: "4",  name: "Backup Files",                    stageName: "backup_files",                 sectionId: "WSTG-CONF-04" },
  { id: "5",  name: "Admin Interface Enumeration",     stageName: "admin_interface_enumeration",  sectionId: "WSTG-CONF-05" },
  { id: "6",  name: "API Discovery",                   stageName: "api_discovery",                sectionId: "WSTG-INFO-06" },
  { id: "7",  name: "HTTP Methods",                    stageName: "http_methods",                 sectionId: "WSTG-CONF-06" },
  { id: "8",  name: "HTTP Strict Transport Security",  stageName: "hsts_testing",                 sectionId: "WSTG-CONF-07" },
  { id: "9",  name: "RPC Testing",                     stageName: "rpc_testing",                  sectionId: "WSTG-CONF-08" },
  { id: "10", name: "File Inclusion",                  stageName: "file_inclusion",               sectionId: "WSTG-CONF-09" },
  { id: "11", name: "Subdomain Takeover",              stageName: "subdomain_takeover",           sectionId: "WSTG-CONF-10" },
  { id: "12", name: "Cloud Storage",                   stageName: "cloud_storage",                sectionId: "WSTG-CONF-11" },
],
```

- [ ] **Step 6: Verify the pipeline import works**

```bash
python -c "from workers.config_mgmt.pipeline import STAGES; print([s.name for s in STAGES])"
```

Expected output:
```
['network_config', 'network_config_cred_test', 'platform_config', 'file_extension_handling', 'backup_files', 'admin_interface_enumeration', 'api_discovery', 'http_methods', 'hsts_testing', 'rpc_testing', 'file_inclusion', 'subdomain_takeover', 'cloud_storage']
```

- [ ] **Step 7: Verify playbooks stage list matches pipeline**

```bash
python -c "
from lib_webbh.playbooks import PIPELINE_STAGES
from workers.config_mgmt.pipeline import STAGES
pipeline_names = [s.name for s in STAGES]
playbook_names = PIPELINE_STAGES['config_mgmt']
missing = set(pipeline_names) - set(playbook_names)
extra = set(playbook_names) - set(pipeline_names)
print('Missing from playbooks:', missing)
print('Extra in playbooks:', extra)
print('OK' if not missing and not extra else 'MISMATCH')
"
```

Expected output:
```
Missing from playbooks: set()
Extra in playbooks: set()
OK
```

- [ ] **Step 8: Run the full unit test suite**

```bash
python -m pytest tests/unit/workers/config_mgmt/ -v
```

Expected: All tests pass including the two new test files.

- [ ] **Step 9: Commit all three-layer changes together**

```bash
git add workers/config_mgmt/tools/__init__.py \
        workers/config_mgmt/concurrency.py \
        workers/config_mgmt/pipeline.py \
        shared/lib_webbh/playbooks.py \
        dashboard/src/lib/worker-stages.ts
git commit -m "feat(conf05): wire admin_interface_enumeration stage — three-layer sync"
```

---

## Self-Review Notes

**Spec coverage check:**
- ✅ External wordlist bundled at `workers/config_mgmt/wordlists/admin-panels.txt` — Task 1
- ✅ Dockerfile COPY for `/wordlists/` — Task 1
- ✅ `AdminInterfaceEnumerator` Phase 0 (DB reads + wordlist load) — Task 2
- ✅ Phase 1 (wordlist path probing with 200/401/403/redirect routing) — Task 2
- ✅ Phase 2 (HTML link mining with BeautifulSoup + admin keywords) — Task 2
- ✅ Phase 3 (auth-header / WWW-Authenticate fingerprinting) — Task 2
- ✅ Platform-aware path injection from `platform_fingerprint` DB assets — Task 2
- ✅ `section_id = "WSTG-CONF-05"` on all vulnerability rows — Task 2 + 3
- ✅ `AdminParamTamperer` Phase 0 (DB reads — admin_interface + admin_redirect assets) — Task 3
- ✅ Phase 1 (hidden input extraction, cookie parsing, suspicious param filter) — Task 3
- ✅ Phase 2 (flip values, response comparison, status bypass detection) — Task 3
- ✅ Early exit if no admin URLs in DB — Task 3
- ✅ `TOOL_WEIGHTS` entries for both tools — Task 4
- ✅ pipeline.py new stage — Task 4
- ✅ playbooks.py stage name — Task 4
- ✅ worker-stages.ts new entry + api_discovery sectionId fix — Task 4
- ✅ tools/__init__.py imports — Task 4

**Type consistency:** `_classify_200_response` returns `tuple[str, str]`. `_classify_tamper_response` returns `tuple[str | None, str | None]`. Both used consistently in `execute()` methods and tested with matching signatures.

**`TOOL_WEIGHTS` key alignment:** Keys `"admin_interface_enumerator"` and `"admin_param_tamperer"` match `name` class attributes exactly — `get_tool_weight(self.name)` will resolve correctly.
