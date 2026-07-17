from sqlalchemy import ForeignKey
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from app.db.database import Base


class Fault(Base):
    __tablename__ = "faults"

    id: Mapped[int] = mapped_column(primary_key=True)

    equipment_id: Mapped[int] = mapped_column(
        ForeignKey("equipment.id")
    )

    symptom: Mapped[str] = mapped_column(
        String(500)
    )

    description: Mapped[str | None] = mapped_column(
        String(500)
    )

    equipment = relationship(
        "Equipment",
        back_populates="faults"
    )

    solutions = relationship(
        "Solution",
        back_populates="fault",
        cascade="all, delete-orphan"
    )