"""Add product engineering capability fields.

Revision ID: e2d8a11c6a91
Revises: b4d97d3c49bf
Create Date: 2026-07-25 09:16:45.467518
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e2d8a11c6a91"
down_revision: str | Sequence[str] | None = "b4d97d3c49bf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add engineering capability fields to products."""

    op.add_column(
        "products",
        sa.Column(
            "minimum_process_temperature_c",
            sa.Float(),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "maximum_process_temperature_c",
            sa.Float(),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "minimum_process_pressure_bar",
            sa.Float(),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "maximum_process_pressure_bar",
            sa.Float(),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "minimum_ambient_temperature_c",
            sa.Float(),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "maximum_ambient_temperature_c",
            sa.Float(),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "accuracy_percent",
            sa.Float(),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "ingress_protection_rating",
            sa.String(length=20),
            nullable=True,
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "hazardous_area_approvals",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "wetted_materials",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
    )

    op.add_column(
        "products",
        sa.Column(
            "process_connections",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
    )

    op.alter_column(
        "products",
        "hazardous_area_approvals",
        server_default=None,
    )

    op.alter_column(
        "products",
        "wetted_materials",
        server_default=None,
    )

    op.alter_column(
        "products",
        "process_connections",
        server_default=None,
    )


def downgrade() -> None:
    """Remove engineering capability fields from products."""

    op.drop_column(
        "products",
        "process_connections",
    )

    op.drop_column(
        "products",
        "wetted_materials",
    )

    op.drop_column(
        "products",
        "hazardous_area_approvals",
    )

    op.drop_column(
        "products",
        "ingress_protection_rating",
    )

    op.drop_column(
        "products",
        "accuracy_percent",
    )

    op.drop_column(
        "products",
        "maximum_ambient_temperature_c",
    )

    op.drop_column(
        "products",
        "minimum_ambient_temperature_c",
    )

    op.drop_column(
        "products",
        "maximum_process_pressure_bar",
    )

    op.drop_column(
        "products",
        "minimum_process_pressure_bar",
    )

    op.drop_column(
        "products",
        "maximum_process_temperature_c",
    )

    op.drop_column(
        "products",
        "minimum_process_temperature_c",
    )