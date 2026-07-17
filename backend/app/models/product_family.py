from sqlalchemy import ForeignKey
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.db.database import Base


class ProductFamily(Base):
    __tablename__ = "product_families"

    id: Mapped[int] = mapped_column(
        primary_key=True,
    )

    manufacturer_id: Mapped[int] = mapped_column(
        ForeignKey("manufacturers.id"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    description: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    manufacturer = relationship(
        "Manufacturer",
        back_populates="families",
    )

    products = relationship(
        "Product",
        back_populates="family",
    )