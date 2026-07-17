from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.manufacturer import Manufacturer
from app.schemas.manufacturer import ManufacturerCreate
from app.schemas.manufacturer import ManufacturerUpdate


class ManufacturerRepository:
    @staticmethod
    def list_all(db: Session) -> list[Manufacturer]:
        statement = select(Manufacturer).order_by(Manufacturer.name)

        return list(
            db.scalars(statement).all()
        )

    @staticmethod
    def get_by_id(
        db: Session,
        manufacturer_id: int,
    ) -> Manufacturer | None:
        return db.get(
            Manufacturer,
            manufacturer_id,
        )

    @staticmethod
    def get_by_name(
        db: Session,
        name: str,
    ) -> Manufacturer | None:
        statement = select(Manufacturer).where(
            Manufacturer.name == name
        )

        return db.scalar(statement)

    @staticmethod
    def create(
        db: Session,
        manufacturer_data: ManufacturerCreate,
    ) -> Manufacturer:
        manufacturer = Manufacturer(
            **manufacturer_data.model_dump()
        )

        db.add(manufacturer)
        db.commit()
        db.refresh(manufacturer)

        return manufacturer

    @staticmethod
    def update(
        db: Session,
        manufacturer: Manufacturer,
        manufacturer_data: ManufacturerUpdate,
    ) -> Manufacturer:
        update_data = manufacturer_data.model_dump(
            exclude_unset=True
        )

        for field, value in update_data.items():
            setattr(
                manufacturer,
                field,
                value,
            )

        db.commit()
        db.refresh(manufacturer)

        return manufacturer

    @staticmethod
    def delete(
        db: Session,
        manufacturer: Manufacturer,
    ) -> None:
        db.delete(manufacturer)
        db.commit()