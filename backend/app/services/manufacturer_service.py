from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.manufacturer import Manufacturer
from app.repositories.manufacturer_repository import (
    ManufacturerRepository,
)
from app.schemas.manufacturer import ManufacturerCreate
from app.schemas.manufacturer import ManufacturerUpdate


class ManufacturerService:
    @staticmethod
    def list_manufacturers(
        db: Session,
    ) -> list[Manufacturer]:
        return ManufacturerRepository.list_all(db)

    @staticmethod
    def get_manufacturer(
        db: Session,
        manufacturer_id: int,
    ) -> Manufacturer:
        manufacturer = ManufacturerRepository.get_by_id(
            db,
            manufacturer_id,
        )

        if manufacturer is None:
            raise HTTPException(
                status_code=404,
                detail="Manufacturer not found.",
            )

        return manufacturer

    @staticmethod
    def create_manufacturer(
        db: Session,
        manufacturer_data: ManufacturerCreate,
    ) -> Manufacturer:
        existing_manufacturer = (
            ManufacturerRepository.get_by_name(
                db,
                manufacturer_data.name,
            )
        )

        if existing_manufacturer is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A manufacturer named "
                    f"'{manufacturer_data.name}' already exists."
                ),
            )

        return ManufacturerRepository.create(
            db,
            manufacturer_data,
        )

    @staticmethod
    def update_manufacturer(
        db: Session,
        manufacturer_id: int,
        manufacturer_data: ManufacturerUpdate,
    ) -> Manufacturer:
        manufacturer = ManufacturerService.get_manufacturer(
            db,
            manufacturer_id,
        )

        if (
            manufacturer_data.name is not None
            and manufacturer_data.name != manufacturer.name
        ):
            existing_manufacturer = (
                ManufacturerRepository.get_by_name(
                    db,
                    manufacturer_data.name,
                )
            )

            if existing_manufacturer is not None:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"A manufacturer named "
                        f"'{manufacturer_data.name}' already exists."
                    ),
                )

        return ManufacturerRepository.update(
            db,
            manufacturer,
            manufacturer_data,
        )

    @staticmethod
    def delete_manufacturer(
        db: Session,
        manufacturer_id: int,
    ) -> None:
        manufacturer = ManufacturerService.get_manufacturer(
            db,
            manufacturer_id,
        )

        ManufacturerRepository.delete(
            db,
            manufacturer,
        )