"""Add STIX 2.1 tables

Revision ID: 002_add_stix_tables
Revises: 001_initial_mitre
Create Date: 2026-01-13 00:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "002_add_stix_tables"
down_revision: Union[str, None] = "001_initial_mitre"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "stix_objects",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("spec_version", sa.String(length=10), nullable=True),
        sa.Column("created", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("stix_data", sa.JSON(), nullable=False),
        sa.Column("created_by_ref", sa.String(length=255), nullable=True),
        sa.Column("labels", sa.JSON(), nullable=True),
        sa.Column("external_references", sa.JSON(), nullable=True),
        sa.Column("pattern", sa.Text(), nullable=True),
        sa.Column("pattern_type", sa.String(length=50), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observable_type", sa.String(length=50), nullable=True),
        sa.Column("observable_value", sa.String(length=512), nullable=True),
        sa.Column("connector_id", sa.String(length=100), nullable=True),
        sa.Column("connector_name", sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_stix_objects")),
    )
    op.create_index(op.f("ix_stix_objects_type"), "stix_objects", ["type"], unique=False)
    op.create_index(
        op.f("ix_stix_objects_observable_value"),
        "stix_objects",
        ["observable_value"],
        unique=False,
    )
    op.create_index(
        op.f("ix_stix_objects_connector_id"),
        "stix_objects",
        ["connector_id"],
        unique=False,
    )
    op.create_index("idx_type_created", "stix_objects", ["type", "created"], unique=False)
    op.create_index(
        "idx_observable_lookup",
        "stix_objects",
        ["observable_type", "observable_value"],
        unique=False,
    )
    op.create_index("idx_connector", "stix_objects", ["connector_id"], unique=False)

    op.create_table(
        "stix_relationships",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=50), nullable=True),
        sa.Column("spec_version", sa.String(length=10), nullable=True),
        sa.Column("created", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("relationship_type", sa.String(length=50), nullable=False),
        sa.Column("source_ref", sa.String(length=255), nullable=False),
        sa.Column("target_ref", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("stix_data", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_stix_relationships")),
    )
    op.create_index(
        op.f("ix_stix_relationships_relationship_type"),
        "stix_relationships",
        ["relationship_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_stix_relationships_source_ref"),
        "stix_relationships",
        ["source_ref"],
        unique=False,
    )
    op.create_index(
        op.f("ix_stix_relationships_target_ref"),
        "stix_relationships",
        ["target_ref"],
        unique=False,
    )
    op.create_index(
        "idx_relationship_lookup",
        "stix_relationships",
        ["source_ref", "target_ref", "relationship_type"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_relationship_lookup", table_name="stix_relationships")
    op.drop_index(op.f("ix_stix_relationships_target_ref"), table_name="stix_relationships")
    op.drop_index(op.f("ix_stix_relationships_source_ref"), table_name="stix_relationships")
    op.drop_index(
        op.f("ix_stix_relationships_relationship_type"),
        table_name="stix_relationships",
    )
    op.drop_table("stix_relationships")

    op.drop_index("idx_connector", table_name="stix_objects")
    op.drop_index("idx_observable_lookup", table_name="stix_objects")
    op.drop_index("idx_type_created", table_name="stix_objects")
    op.drop_index(op.f("ix_stix_objects_connector_id"), table_name="stix_objects")
    op.drop_index(op.f("ix_stix_objects_observable_value"), table_name="stix_objects")
    op.drop_index(op.f("ix_stix_objects_type"), table_name="stix_objects")
    op.drop_table("stix_objects")
