"""Add path_nodes table for URL directory hierarchy.

Revision ID: 002_add_path_nodes
Revises: 001_m1_initial_restructure
"""

from alembic import op
import sqlalchemy as sa

revision = "002_add_path_nodes"
down_revision = "001_m1_initial_restructure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "path_nodes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer,
                  sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer,
                  sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("parent_id", sa.Integer,
                  sa.ForeignKey("path_nodes.id", ondelete="CASCADE"), nullable=True),
        sa.Column("path_segment", sa.Text, nullable=False),
        sa.Column("full_path", sa.Text, nullable=False),
        sa.Column("node_type", sa.String(50), nullable=True),
        sa.Column("source_tool", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  nullable=True, onupdate=sa.func.now()),
        sa.UniqueConstraint("target_id", "full_path", name="uq_path_nodes_target_path"),
    )
    op.create_index("ix_path_nodes_target", "path_nodes", ["target_id"])
    op.create_index("ix_path_nodes_parent", "path_nodes", ["parent_id"])
    op.create_index("ix_path_nodes_asset", "path_nodes", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_path_nodes_asset", "path_nodes")
    op.drop_index("ix_path_nodes_parent", "path_nodes")
    op.drop_index("ix_path_nodes_target", "path_nodes")
    op.drop_table("path_nodes")
