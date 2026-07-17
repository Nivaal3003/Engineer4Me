from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.db.database import Base


class Manufacturer(Base):
    __tablename__ = "manufacturers"

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    website: Mapped[str | None] = mapped_column(String(255))

    country: Mapped[str | None] = mapped_column(String(100))

    products = relationship(
        "Product",
        back_populates="manufacturer"
    )
    families = relationship(
    "ProductFamily",
    back_populates="manufacturer"
)