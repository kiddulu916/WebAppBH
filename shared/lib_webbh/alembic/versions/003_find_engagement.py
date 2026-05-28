"""Add conditional_stages to campaigns and chain_only to vulnerabilities.

Revision ID: 003_find_engagement
Revises: 002_add_path_nodes
"""

from alembic import op
import sqlalchemy as sa

revision = "003_find_engagement"
down_revision = "002_add_path_nodes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("campaigns", sa.Column("conditional_stages", sa.JSON(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("chain_only", sa.Boolean(), nullable=False, server_default="false"))
    op.create_index("ix_vulns_chain_only", "vulnerabilities", ["chain_only"])


def downgrade() -> None:
    op.drop_index("ix_vulns_chain_only", "vulnerabilities")
    op.drop_column("vulnerabilities", "chain_only")
    op.drop_column("campaigns", "conditional_stages")
