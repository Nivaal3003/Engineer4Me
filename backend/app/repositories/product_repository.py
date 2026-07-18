from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm import selectinload

from app.models.product import Product
from app.models.protocol import Protocol


class ProductRepository:
    @staticmethod
    def _base_query():
        return select(Product).options(
            selectinload(Product.manufacturer),
            selectinload(Product.measurement),
            selectinload(Product.family),
            selectinload(Product.application),
            selectinload(Product.technology),
            selectinload(Product.protocols),
        )

    @staticmethod
    def list_all(
        db: Session,
        manufacturer_id: int | None = None,
        measurement_id: int | None = None,
        family_id: int | None = None,
        application_id: int | None = None,
        technology_id: int | None = None,
        protocol_id: int | None = None,
    ) -> list[Product]:
        statement = ProductRepository._base_query()

        if manufacturer_id is not None:
            statement = statement.where(
                Product.manufacturer_id == manufacturer_id
            )

        if measurement_id is not None:
            statement = statement.where(
                Product.measurement_id == measurement_id
            )

        if family_id is not None:
            statement = statement.where(
                Product.family_id == family_id
            )

        if application_id is not None:
            statement = statement.where(
                Product.application_id == application_id
            )

        if technology_id is not None:
            statement = statement.where(
                Product.technology_id == technology_id
            )

        if protocol_id is not None:
            statement = statement.join(Product.protocols).where(
                Protocol.id == protocol_id
            )

        statement = statement.order_by(
            Product.manufacturer_id,
            Product.model,
        )

        return list(
            db.scalars(statement).unique().all()
        )

    @staticmethod
    def get_by_id(
        db: Session,
        product_id: int,
    ) -> Product | None:
        statement = ProductRepository._base_query().where(
            Product.id == product_id
        )

        return db.scalars(statement).unique().one_or_none()

    @staticmethod
    def get_by_model_and_manufacturer(
        db: Session,
        manufacturer_id: int,
        model: str,
        exclude_product_id: int | None = None,
    ) -> Product | None:
        statement = select(Product).where(
            Product.manufacturer_id == manufacturer_id,
            func.lower(Product.model) == model.strip().lower(),
        )

        if exclude_product_id is not None:
            statement = statement.where(
                Product.id != exclude_product_id
            )

        return db.scalar(statement)

    @staticmethod
    def create(
        db: Session,
        product: Product,
    ) -> Product:
        db.add(product)
        db.commit()

        return ProductRepository.get_by_id(
            db,
            product.id,
        )

    @staticmethod
    def update(
        db: Session,
        product: Product,
    ) -> Product:
        db.add(product)
        db.commit()

        return ProductRepository.get_by_id(
            db,
            product.id,
        )

    @staticmethod
    def delete(
        db: Session,
        product: Product,
    ) -> None:
        db.delete(product)
        db.commit()
