from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import Table

from app.db.database import Base

product_protocols = Table(
    "product_protocols",
    Base.metadata,
    Column(
        "product_id",
        ForeignKey("products.id"),
        primary_key=True,
    ),
    Column(
        "protocol_id",
        ForeignKey("protocols.id"),
        primary_key=True,
    ),
)