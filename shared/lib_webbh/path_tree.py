# shared/lib_webbh/path_tree.py
"""PathTreeBuilder — build and upsert a directory hierarchy from URL-valued assets."""

from __future__ import annotations

from urllib.parse import urlparse


class PathTreeBuilder:
    """Upsert path_nodes rows from a URL, building the full ancestor chain."""

    @staticmethod
    def _parse_segments(url: str) -> list[tuple[str, str]]:
        """Return list of (full_path, segment) tuples for each path component.

        E.g. "https://example.com/a/b/c" -> [("/a","a"),("/a/b","b"),("/a/b/c","c")]
        Strips trailing slashes. Returns [] for URLs with no meaningful path.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return []

        # Require a scheme and a netloc; bare strings like "not-a-url" are rejected.
        if not parsed.scheme or not parsed.netloc:
            return []

        path = parsed.path.rstrip("/")
        if not path or path == "/":
            return []

        parts = [p for p in path.split("/") if p]
        result = []
        for i, part in enumerate(parts):
            full = "/" + "/".join(parts[: i + 1])
            result.append((full, part))
        return result

    @classmethod
    async def upsert(
        cls,
        target_id: int,
        asset_id: int | None,
        url: str,
        node_type: str | None,
        source_tool: str | None,
    ) -> None:
        """Walk ``url``'s path and upsert one path_nodes row per segment.

        The leaf segment gets ``asset_id`` set. Intermediate nodes are created
        with ``asset_id=None`` and ``node_type="directory"`` if they don't
        already exist.

        Uses ON CONFLICT DO UPDATE so repeated calls from concurrent tools are safe.
        """
        from lib_webbh.database import PathNode
        from lib_webbh import get_session
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        segments = cls._parse_segments(url)
        if not segments:
            return

        async with get_session() as session:
            parent_id: int | None = None

            for i, (full_path, segment) in enumerate(segments):
                is_leaf = i == len(segments) - 1
                this_asset_id = asset_id if is_leaf else None
                this_node_type = node_type if is_leaf else "directory"

                stmt = (
                    pg_insert(PathNode)
                    .values(
                        target_id=target_id,
                        asset_id=this_asset_id,
                        parent_id=parent_id,
                        path_segment=segment,
                        full_path=full_path,
                        node_type=this_node_type,
                        source_tool=source_tool,
                    )
                    .on_conflict_do_update(
                        index_elements=["target_id", "full_path"],
                        set_={
                            "asset_id": pg_insert(PathNode).excluded.asset_id,
                            "node_type": pg_insert(PathNode).excluded.node_type,
                            "source_tool": pg_insert(PathNode).excluded.source_tool,
                        },
                    )
                    .returning(PathNode.id)
                )
                result = await session.execute(stmt)
                row = result.fetchone()
                parent_id = row[0] if row else None

            await session.commit()
