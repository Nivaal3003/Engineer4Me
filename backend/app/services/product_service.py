from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.application import Application
from app.models.manufacturer import Manufacturer
from app.models.measurement import Measurement
from app.models.product import Product
from app.models.product_family import ProductFamily
from app.models.protocol import Protocol
from app.models.technology import Technology
from app.repositories.product_repository import ProductRepository
from app.schemas.product import ProductCreate
from app.schemas.product import ProductUpdate


class ProductService:
    @staticmethod
    def list_products(
        db: Session,
        manufacturer_id: int | None = None,
        measurement_id: int | None = None,
        family_id: int | None = None,
        application_id: int | None = None,
        technology_id: int | None = None,
        protocol_id: int | None = None,
    ) -> list[Product]:
        return ProductRepository.list_all(
            db=db,
            manufacturer_id=manufacturer_id,
            measurement_id=measurement_id,
            family_id=family_id,
            application_id=application_id,
            technology_id=technology_id,
            protocol_id=protocol_id,
        )

    @staticmethod
    def get_product(
        db: Session,
        product_id: int,
    ) -> Product:
        product = ProductRepository.get_by_id(
            db,
            product_id,
        )

        if product is None:
            raise HTTPException(
                status_code=404,
                detail="Product not found.",
            )

        return product

    @staticmethod
    def _get_manufacturer(
        db: Session,
        manufacturer_id: int,
    ) -> Manufacturer:
        manufacturer = db.get(
            Manufacturer,
            manufacturer_id,
        )

        if manufacturer is None:
            raise HTTPException(
                status_code=400,
                detail="Manufacturer does not exist.",
            )

        return manufacturer

    @staticmethod
    def _get_measurement(
        db: Session,
        measurement_id: int,
    ) -> Measurement:
        measurement = db.get(
            Measurement,
            measurement_id,
        )

        if measurement is None:
            raise HTTPException(
                status_code=400,
                detail="Measurement does not exist.",
            )

        return measurement

    @staticmethod
    def _get_family(
        db: Session,
        family_id: int,
        manufacturer_id: int,
    ) -> ProductFamily:
        family = db.get(
            ProductFamily,
            family_id,
        )

        if family is None:
            raise HTTPException(
                status_code=400,
                detail="Product family does not exist.",
            )

        if family.manufacturer_id != manufacturer_id:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Product family does not belong to "
                    "the selected manufacturer."
                ),
            )

        return family

    @staticmethod
    def _get_application(
        db: Session,
        application_id: int,
    ) -> Application:
        application = db.get(
            Application,
            application_id,
        )

        if application is None:
            raise HTTPException(
                status_code=400,
                detail="Application does not exist.",
            )

        return application

    @staticmethod
    def _get_technology(
        db: Session,
        technology_id: int | None,
    ) -> Technology | None:
        if technology_id is None:
            return None

        technology = db.get(
            Technology,
            technology_id,
        )

        if technology is None:
            raise HTTPException(
                status_code=400,
                detail="Technology does not exist.",
            )

        return technology

    @staticmethod
    def _get_protocols(
        db: Session,
        protocol_ids: list[int],
    ) -> list[Protocol]:
        unique_ids = list(dict.fromkeys(protocol_ids))

        if not unique_ids:
            return []

        statement = (
            select(Protocol)
            .where(Protocol.id.in_(unique_ids))
            .order_by(Protocol.id)
        )

        protocols = list(db.scalars(statement).all())
        found_ids = {protocol.id for protocol in protocols}
        missing_ids = sorted(
            set(unique_ids) - found_ids
        )

        if missing_ids:
            missing_values = ", ".join(
                str(protocol_id)
                for protocol_id in missing_ids
            )

            raise HTTPException(
                status_code=400,
                detail=(
                    "The following protocols do not exist: "
                    f"{missing_values}."
                ),
            )

        protocol_by_id = {
            protocol.id: protocol
            for protocol in protocols
        }

        return [
            protocol_by_id[protocol_id]
            for protocol_id in unique_ids
        ]

    @staticmethod
    def _ensure_unique_model(
        db: Session,
        manufacturer_id: int,
        model: str,
        exclude_product_id: int | None = None,
    ) -> None:
        existing_product = (
            ProductRepository
            .get_by_model_and_manufacturer(
                db=db,
                manufacturer_id=manufacturer_id,
                model=model,
                exclude_product_id=exclude_product_id,
            )
        )

        if existing_product is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "A product with this model already exists "
                    "for the selected manufacturer."
                ),
            )

    @staticmethod
    def create_product(
        db: Session,
        product_data: ProductCreate,
    ) -> Product:
        ProductService._get_manufacturer(
            db,
            product_data.manufacturer_id,
        )

        ProductService._get_measurement(
            db,
            product_data.measurement_id,
        )

        ProductService._get_family(
            db,
            product_data.family_id,
            product_data.manufacturer_id,
        )

        ProductService._get_application(
            db,
            product_data.application_id,
        )

        ProductService._get_technology(
            db,
            product_data.technology_id,
        )

        protocols = ProductService._get_protocols(
            db,
            product_data.protocol_ids,
        )

        ProductService._ensure_unique_model(
            db=db,
            manufacturer_id=product_data.manufacturer_id,
            model=product_data.model,
        )

        product = Product(
            manufacturer_id=product_data.manufacturer_id,
            measurement_id=product_data.measurement_id,
            family_id=product_data.family_id,
            application_id=product_data.application_id,
            technology_id=product_data.technology_id,
            model=product_data.model.strip(),
            description=product_data.description,
            protocols=protocols,
        )

        try:
            created_product = ProductRepository.create(
                db,
                product,
            )
        except IntegrityError as error:
            db.rollback()

            raise HTTPException(
                status_code=409,
                detail="Product could not be created.",
            ) from error

        if created_product is None:
            raise HTTPException(
                status_code=500,
                detail="Created product could not be loaded.",
            )

        return created_product

    @staticmethod
    def update_product(
        db: Session,
        product_id: int,
        product_data: ProductUpdate,
    ) -> Product:
        product = ProductService.get_product(
            db,
            product_id,
        )

        changes = product_data.model_dump(
            exclude_unset=True
        )

        manufacturer_id = changes.get(
            "manufacturer_id",
            product.manufacturer_id,
        )

        measurement_id = changes.get(
            "measurement_id",
            product.measurement_id,
        )

        family_id = changes.get(
            "family_id",
            product.family_id,
        )

        application_id = changes.get(
            "application_id",
            product.application_id,
        )

        technology_id = changes.get(
            "technology_id",
            product.technology_id,
        )

        model = changes.get(
            "model",
            product.model,
        )

        ProductService._get_manufacturer(
            db,
            manufacturer_id,
        )

        ProductService._get_measurement(
            db,
            measurement_id,
        )

        ProductService._get_family(
            db,
            family_id,
            manufacturer_id,
        )

        ProductService._get_application(
            db,
            application_id,
        )

        ProductService._get_technology(
            db,
            technology_id,
        )

        ProductService._ensure_unique_model(
            db=db,
            manufacturer_id=manufacturer_id,
            model=model,
            exclude_product_id=product.id,
        )

        product.manufacturer_id = manufacturer_id
        product.measurement_id = measurement_id
        product.family_id = family_id
        product.application_id = application_id
        product.technology_id = technology_id
        product.model = model.strip()

        if "description" in changes:
            product.description = changes["description"]

        if "protocol_ids" in changes:
            product.protocols = ProductService._get_protocols(
                db,
                changes["protocol_ids"] or [],
            )

        try:
            updated_product = ProductRepository.update(
                db,
                product,
            )
        except IntegrityError as error:
            db.rollback()

            raise HTTPException(
                status_code=409,
                detail="Product could not be updated.",
            ) from error

        if updated_product is None:
            raise HTTPException(
                status_code=500,
                detail="Updated product could not be loaded.",
            )

        return updated_product

    @staticmethod
    def delete_product(
        db: Session,
        product_id: int,
    ) -> None:
        product = ProductService.get_product(
            db,
            product_id,
        )

        try:
            ProductRepository.delete(
                db,
                product,
            )
        except IntegrityError as error:
            db.rollback()

            raise HTTPException(
                status_code=409,
                detail=(
                    "Product cannot be deleted because it "
                    "is referenced by other records."
                ),
            ) from error
