"""support the native HTTP runtime and advisory local model

Revision ID: 4d3c6a8f1b2e
Revises: 159cb606fed2
Create Date: 2026-10-12 12:20:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "4d3c6a8f1b2e"
down_revision = "159cb606fed2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "idempotency_records",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_index(op.f("ix_idempotency_records_created_at"), "idempotency_records", ["created_at"], unique=False)
    op.add_column("incidents", sa.Column("local_ai_status", sa.String(length=32), nullable=False, server_default="not_configured"))
    op.add_column("incidents", sa.Column("local_ai_summary", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("incidents", "local_ai_summary")
    op.drop_column("incidents", "local_ai_status")
    op.drop_index(op.f("ix_idempotency_records_created_at"), table_name="idempotency_records")
    op.drop_table("idempotency_records")
