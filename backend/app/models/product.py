from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import JSON
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

    minimum_process_temperature_c: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    maximum_process_temperature_c: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    minimum_process_pressure_bar: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    maximum_process_pressure_bar: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    minimum_ambient_temperature_c: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    maximum_ambient_temperature_c: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    accuracy_percent: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    ingress_protection_rating: Mapped[
        str | None
    ] = mapped_column(
        String(20),
        nullable=True,
    )

    hazardous_area_approvals: Mapped[
        list[str]
    ] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    wetted_materials: Mapped[
        list[str]
    ] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    process_connections: Mapped[
        list[str]
    ] = mapped_column(
        JSON,
        nullable=False,
        default=list,
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