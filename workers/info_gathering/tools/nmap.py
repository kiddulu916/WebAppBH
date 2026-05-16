# workers/info_gathering/tools/nmap.py
"""Nmap wrapper — port scanning and service detection."""

import json
import xml.etree.ElementTree as ET
import tempfile
import os

from workers.info_gathering.base_tool import InfoGatheringTool


class Nmap(InfoGatheringTool):
    """Port scanning and service detection using Nmap."""

    async def execute(self, target_id: int, **kwargs):
        target = kwargs.get("target")
        if not target:
            return

        from lib_webbh.database import Asset
        from lib_webbh import get_session
        from sqlalchemy import select

        async with get_session() as session:
            stmt = select(Asset.asset_value).where(
                Asset.target_id == target_id,
                Asset.asset_type.in_(["ip", "domain"]),
            )
            result = await session.execute(stmt)
            targets = [row[0] for row in result.all()]

        if not targets:
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            input_file = f.name

        try:
            output_file = input_file + ".xml"
            cmd = [
                "nmap", "-iL", input_file,
                "-sV", "-sC", "--top-ports", "1000",
                "-oX", output_file,
            ]
            await self.run_subprocess(cmd, timeout=1800)

            if os.path.exists(output_file):
                tree = ET.parse(output_file)
                root = tree.getroot()

                for host in root.findall(".//host"):
                    addr = host.find("address")
                    if addr is None:
                        continue
                    ip = addr.get("addr", "")

                    for port in host.findall(".//port"):
                        port_num = port.get("portid")
                        protocol = port.get("protocol", "tcp")
                        state = port.find("state")
                        service = port.find("service")

                        if state is not None and state.get("state") == "open":
                            await self.save_asset(
                                target_id, "ip", ip, "nmap",
                                port=int(port_num) if port_num else None,
                                protocol=protocol,
                                service=service.get("name") if service is not None else None,
                            )
                os.unlink(output_file)
        finally:
            if os.path.exists(input_file):
                os.unlink(input_file)