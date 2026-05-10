"""Add MITRE ATT&CK tables

Revision ID: 001_initial_mitre
Revises: 
Create Date: 2026-01-12 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial_mitre'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # === Mitre Tables ===
    
    # Tactics
    op.create_table('mitre_tactics',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('stix_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created', sa.String(length=32), nullable=True),
        sa.Column('modified', sa.String(length=32), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=True),
        sa.Column('deprecated', sa.Boolean(), nullable=True),
        sa.Column('url', sa.String(length=512), nullable=True),
        sa.Column('short_name', sa.String(length=64), nullable=False),
        sa.Column('external_id', sa.String(length=32), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_mitre_tactics'))
    )
    op.create_index(op.f('ix_mitre_tactics_stix_id'), 'mitre_tactics', ['stix_id'], unique=True)
    op.create_index(op.f('ix_mitre_tactics_name'), 'mitre_tactics', ['name'], unique=False)
    op.create_index(op.f('ix_mitre_tactics_short_name'), 'mitre_tactics', ['short_name'], unique=False)
    op.create_index(op.f('ix_mitre_tactics_external_id'), 'mitre_tactics', ['external_id'], unique=False)

    # Techniques
    op.create_table('mitre_techniques',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('stix_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created', sa.String(length=32), nullable=True),
        sa.Column('modified', sa.String(length=32), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=True),
        sa.Column('deprecated', sa.Boolean(), nullable=True),
        sa.Column('url', sa.String(length=512), nullable=True),
        sa.Column('external_id', sa.String(length=32), nullable=True),
        sa.Column('is_subtechnique', sa.Boolean(), nullable=True),
        sa.Column('platforms', sa.String(length=512), nullable=True),
        sa.Column('detection', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_mitre_techniques'))
    )
    op.create_index(op.f('ix_mitre_techniques_stix_id'), 'mitre_techniques', ['stix_id'], unique=True)
    op.create_index(op.f('ix_mitre_techniques_name'), 'mitre_techniques', ['name'], unique=False)
    op.create_index(op.f('ix_mitre_techniques_external_id'), 'mitre_techniques', ['external_id'], unique=False)

    # Groups
    op.create_table('mitre_groups',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('stix_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created', sa.String(length=32), nullable=True),
        sa.Column('modified', sa.String(length=32), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=True),
        sa.Column('deprecated', sa.Boolean(), nullable=True),
        sa.Column('url', sa.String(length=512), nullable=True),
        sa.Column('external_id', sa.String(length=32), nullable=True),
        sa.Column('aliases', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_mitre_groups'))
    )
    op.create_index(op.f('ix_mitre_groups_stix_id'), 'mitre_groups', ['stix_id'], unique=True)
    op.create_index(op.f('ix_mitre_groups_name'), 'mitre_groups', ['name'], unique=False)
    op.create_index(op.f('ix_mitre_groups_external_id'), 'mitre_groups', ['external_id'], unique=False)

    # Software
    op.create_table('mitre_software',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('stix_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created', sa.String(length=32), nullable=True),
        sa.Column('modified', sa.String(length=32), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=True),
        sa.Column('deprecated', sa.Boolean(), nullable=True),
        sa.Column('url', sa.String(length=512), nullable=True),
        sa.Column('external_id', sa.String(length=32), nullable=True),
        sa.Column('is_malware', sa.Boolean(), nullable=True),
        sa.Column('platforms', sa.String(length=512), nullable=True),
        sa.Column('aliases', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_mitre_software'))
    )
    op.create_index(op.f('ix_mitre_software_stix_id'), 'mitre_software', ['stix_id'], unique=True)
    op.create_index(op.f('ix_mitre_software_name'), 'mitre_software', ['name'], unique=False)
    op.create_index(op.f('ix_mitre_software_external_id'), 'mitre_software', ['external_id'], unique=False)

    # Mitigations
    op.create_table('mitre_mitigations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('stix_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created', sa.String(length=32), nullable=True),
        sa.Column('modified', sa.String(length=32), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=True),
        sa.Column('deprecated', sa.Boolean(), nullable=True),
        sa.Column('url', sa.String(length=512), nullable=True),
        sa.Column('external_id', sa.String(length=32), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_mitre_mitigations'))
    )
    op.create_index(op.f('ix_mitre_mitigations_stix_id'), 'mitre_mitigations', ['stix_id'], unique=True)
    op.create_index(op.f('ix_mitre_mitigations_name'), 'mitre_mitigations', ['name'], unique=False)
    op.create_index(op.f('ix_mitre_mitigations_external_id'), 'mitre_mitigations', ['external_id'], unique=False)

    # Relationships
    op.create_table('mitre_relationships',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('source_ref', sa.String(length=64), nullable=False),
        sa.Column('target_ref', sa.String(length=64), nullable=False),
        sa.Column('relationship_type', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_mitre_relationships')),
        sa.UniqueConstraint('source_ref', 'target_ref', 'relationship_type', name='uq_mitre_relationship')
    )
    op.create_index(op.f('ix_mitre_relationships_source_ref'), 'mitre_relationships', ['source_ref'], unique=False)
    op.create_index(op.f('ix_mitre_relationships_target_ref'), 'mitre_relationships', ['target_ref'], unique=False)

    # Tactic-Technique Link
    op.create_table('mitre_tactic_technique',
        sa.Column('tactic_id', sa.Integer(), nullable=False),
        sa.Column('technique_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['tactic_id'], ['mitre_tactics.id'], name=op.f('fk_mitre_tactic_technique_tactic_id_mitre_tactics')),
        sa.ForeignKeyConstraint(['technique_id'], ['mitre_techniques.id'], name=op.f('fk_mitre_tactic_technique_technique_id_mitre_techniques')),
        sa.PrimaryKeyConstraint('tactic_id', 'technique_id', name=op.f('pk_mitre_tactic_technique'))
    )


def downgrade() -> None:
    op.drop_table('mitre_tactic_technique')
    op.drop_table('mitre_relationships')
    op.drop_table('mitre_mitigations')
    op.drop_table('mitre_software')
    op.drop_table('mitre_groups')
    op.drop_table('mitre_techniques')
    op.drop_table('mitre_tactics')
