"""remove redundant columns

Revision ID: 79e0ad4ca8e0
Revises: 600ea334339f
Create Date: 2022-10-28 10:45:32.511105

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '79e0ad4ca8e0'
down_revision = '600ea334339f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'favorite_color')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('favorite_color', mysql.VARCHAR(length=120), nullable=True))
    # ### end Alembic commands ###
