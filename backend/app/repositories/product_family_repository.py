from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.product_family import ProductFamily
from app.schemas.product_family import ProductFamilyCreate
from app.schemas.product_family import ProductFamilyUpdate


class ProductFamilyRepository:
    @staticmethod
    def list_all(
        db: Session,
        manufacturer_id: int | None = None,
    ) -> list[ProductFamily]:
        statement = select(ProductFamily)

        if manufacturer_id is not None:
            statement = statement.where(
                ProductFamily.manufacturer_id == manufacturer_id
            )

        statement = statement.order_by(
            ProductFamily.name,
        )

        return list(
            db.scalars(statement).all()
        )

    @staticmethod
    def get_by_id(
        db: Session,
        product_family_id: int,
    ) -> ProductFamily | None:
        return db.get(
            ProductFamily,
            product_family_id,
        )

    @staticmethod
    def get_by_name_and_manufacturer(
        db: Session,
        name: str,
        manufacturer_id: int,
    ) -> ProductFamily | None:
        statement = select(ProductFamily).where(
            ProductFamily.name == name,
            ProductFamily.manufacturer_id == manufacturer_id,
        )

        return db.scalar(statement)

    @staticmethod
    def create(
        db: Session,
        product_family_data: ProductFamilyCreate,
    ) -> ProductFamily:
        product_family = ProductFamily(
            **product_family_data.model_dump()
        )

        db.add(product_family)
        db.commit()
        db.refresh(product_family)

        return product_family

    @staticmethod
    def update(
        db: Session,
        product_family: ProductFamily,
        product_family_data: ProductFamilyUpdate,
    ) -> ProductFamily:
        update_data = product_family_data.model_dump(
            exclude_unset=True,
        )

        for field, value in update_data.items():
            setattr(
                product_family,
                field,
                value,
            )

        db.commit()
        db.refresh(product_family)

        return product_family

    @staticmethod
    def delete(
        db: Session,
        product_family: ProductFamily,
    ) -> None:
        db.delete(product_family)
        db.commit()