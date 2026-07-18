from sqlalchemy import ForeignKey
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.product_protocol import product_protocols


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(
        primary_key=True,
    )

    manufacturer_id: Mapped[int] = mapped_column(
        ForeignKey("manufacturers.id"),
        nullable=False,
    )

    measurement_id: Mapped[int] = mapped_column(
        ForeignKey("measurements.id"),
        nullable=False,
    )

    family_id: Mapped[int] = mapped_column(
        ForeignKey("product_families.id"),
        nullable=False,
    )

    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id"),
        nullable=False,
    )

    technology_id: Mapped[int | None] = mapped_column(
        ForeignKey("technologies.id"),
        nullable=True,
    )

    model: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    manufacturer = relationship(
        "Manufacturer",
        back_populates="products",
    )

    measurement = relationship(
        "Measurement",
        back_populates="products",
    )

    family = relationship(
        "ProductFamily",
        back_populates="products",
    )

    application = relationship(
        "Application",
        back_populates="products",
    )

    technology = relationship(
        "Technology",
        back_populates="products",
    )

    protocols = relationship(
        "Protocol",
        secondary=product_protocols,
        back_populates="products",
    )
