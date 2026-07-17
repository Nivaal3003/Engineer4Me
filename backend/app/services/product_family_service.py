from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.product_family import ProductFamily
from app.repositories.manufacturer_repository import (
    ManufacturerRepository,
)
from app.repositories.product_family_repository import (
    ProductFamilyRepository,
)
from app.schemas.product_family import ProductFamilyCreate
from app.schemas.product_family import ProductFamilyUpdate


class ProductFamilyService:
    @staticmethod
    def list_product_families(
        db: Session,
        manufacturer_id: int | None = None,
    ) -> list[ProductFamily]:
        if manufacturer_id is not None:
            manufacturer = ManufacturerRepository.get_by_id(
                db,
                manufacturer_id,
            )

            if manufacturer is None:
                raise HTTPException(
                    status_code=404,
                    detail="Manufacturer not found.",
                )

        return ProductFamilyRepository.list_all(
            db,
            manufacturer_id,
        )

    @staticmethod
    def get_product_family(
        db: Session,
        product_family_id: int,
    ) -> ProductFamily:
        product_family = ProductFamilyRepository.get_by_id(
            db,
            product_family_id,
        )

        if product_family is None:
            raise HTTPException(
                status_code=404,
                detail="Product family not found.",
            )

        return product_family

    @staticmethod
    def create_product_family(
        db: Session,
        product_family_data: ProductFamilyCreate,
    ) -> ProductFamily:
        manufacturer = ManufacturerRepository.get_by_id(
            db,
            product_family_data.manufacturer_id,
        )

        if manufacturer is None:
            raise HTTPException(
                status_code=404,
                detail="Manufacturer not found.",
            )

        existing_product_family = (
            ProductFamilyRepository.get_by_name_and_manufacturer(
                db,
                product_family_data.name,
                product_family_data.manufacturer_id,
            )
        )

        if existing_product_family is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A product family named "
                    f"'{product_family_data.name}' already exists "
                    f"for this manufacturer."
                ),
            )

        return ProductFamilyRepository.create(
            db,
            product_family_data,
        )

    @staticmethod
    def update_product_family(
        db: Session,
        product_family_id: int,
        product_family_data: ProductFamilyUpdate,
    ) -> ProductFamily:
        product_family = ProductFamilyService.get_product_family(
            db,
            product_family_id,
        )

        target_manufacturer_id = (
            product_family_data.manufacturer_id
            if product_family_data.manufacturer_id is not None
            else product_family.manufacturer_id
        )

        target_name = (
            product_family_data.name
            if product_family_data.name is not None
            else product_family.name
        )

        if product_family_data.manufacturer_id is not None:
            manufacturer = ManufacturerRepository.get_by_id(
                db,
                product_family_data.manufacturer_id,
            )

            if manufacturer is None:
                raise HTTPException(
                    status_code=404,
                    detail="Manufacturer not found.",
                )

        existing_product_family = (
            ProductFamilyRepository.get_by_name_and_manufacturer(
                db,
                target_name,
                target_manufacturer_id,
            )
        )

        if (
            existing_product_family is not None
            and existing_product_family.id != product_family.id
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A product family named "
                    f"'{target_name}' already exists "
                    f"for this manufacturer."
                ),
            )

        return ProductFamilyRepository.update(
            db,
            product_family,
            product_family_data,
        )

    @staticmethod
    def delete_product_family(
        db: Session,
        product_family_id: int,
    ) -> None:
        product_family = ProductFamilyService.get_product_family(
            db,
            product_family_id,
        )

        if product_family.products:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Product family cannot be deleted because "
                    "it contains products."
                ),
            )

        ProductFamilyRepository.delete(
            db,
            product_family,
        )