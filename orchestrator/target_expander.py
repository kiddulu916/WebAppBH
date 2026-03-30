# orchestrator/target_expander.py
import shutil
import os
from collections import defaultdict
from pathlib import Path
from typing import Optional

from lib_webbh.database import get_session, Target, Asset
from lib_webbh.messaging import push_priority_task
from lib_webbh.scope import ScopeManager
from sqlalchemy import select


class TargetExpander:
    """Creates child targets from info_gathering results."""

    async def expand(self, parent_target_id: int):
        async with get_session() as session:
            assets = await session.execute(
                select(Asset)
                .where(Asset.target_id == parent_target_id)
                .where(Asset.asset_type.in_(["subdomain", "vhost", "live_url"]))
            )
            assets = assets.scalars().all()
            parent = await session.get(Target, parent_target_id)

            unique_hosts = self._deduplicate(assets)

            for host_info in unique_hosts:
                if host_info["hostname"] == parent.base_domain:
                    continue

                priority = self._score_priority(host_info, parent)

                child = Target(
                    company_name=parent.company_name,
                    base_domain=host_info["hostname"],
                    parent_target_id=parent_target_id,
                    campaign_id=parent.campaign_id,
                    target_type="child",
                    priority=priority,
                    wildcard=host_info.get("wildcard", False),
                    wildcard_count=host_info.get("wildcard_count"),
                )
                session.add(child)

            await session.commit()

            children = await session.execute(
                select(Target)
                .where(Target.parent_target_id == parent_target_id)
                .where(Target.target_type == "child")
            )
            for child in children.scalars().all():
                self._copy_credentials(parent_target_id, child.id)
                await push_priority_task(
                    "config_mgmt_queue",
                    {"target_id": child.id, "parent_target_id": parent_target_id},
                    priority_score=child.priority,
                )

    def _deduplicate(self, assets):
        by_hostname = {}
        for asset in assets:
            hostname = asset.data.get("hostname", "").lower().strip(".")
            if not hostname:
                continue
            if hostname not in by_hostname:
                by_hostname[hostname] = {
                    "hostname": hostname,
                    "ips": set(),
                    "sources": [],
                    "asset_type": asset.asset_type,
                }
            if asset.data.get("ip"):
                by_hostname[hostname]["ips"].add(asset.data["ip"])
            by_hostname[hostname]["sources"].append(asset.source_tool)

        ip_groups = defaultdict(list)
        for info in by_hostname.values():
            for ip in info["ips"]:
                ip_groups[ip].append(info)

        for ip, hosts in ip_groups.items():
            if len(hosts) > 50:
                for host in hosts[1:]:
                    host["skip"] = True
                hosts[0]["wildcard"] = True
                hosts[0]["wildcard_count"] = len(hosts)

        return [h for h in by_hostname.values() if not h.get("skip")]

    def _score_priority(self, host_info, parent) -> int:
        score = 50

        if host_info.get("is_seed"):
            return 100

        if len(host_info.get("ips", set())) == 1:
            score += 20

        hostname = host_info["hostname"]
        high_value = ["api", "admin", "portal", "app", "dashboard", "login",
                      "auth", "sso", "internal", "staging", "dev", "test", "uat", "preprod"]
        for prefix in high_value:
            if hostname.startswith(f"{prefix}."):
                score += 15
                break

        low_value = ["cdn", "static", "assets", "img", "images", "media", "fonts", "css", "js"]
        for prefix in low_value:
            if hostname.startswith(f"{prefix}."):
                score -= 15
                break

        source_count = len(set(host_info.get("sources", [])))
        if source_count >= 3:
            score += 10
        elif source_count == 1:
            score -= 5

        if host_info.get("wildcard"):
            score -= 30

        return max(0, min(100, score))

    def _copy_credentials(self, parent_id: int, child_id: int):
        parent_creds = Path(f"shared/config/{parent_id}/credentials.json")
        child_dir = Path(f"shared/config/{child_id}")
        child_dir.mkdir(parents=True, exist_ok=True)
        if parent_creds.exists():
            shutil.copy2(parent_creds, child_dir / "credentials.json")
            os.chmod(child_dir / "credentials.json", 0o600)