from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from fastapi import Response
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.product import ProductCreate
from app.schemas.product import ProductResponse
from app.schemas.product import ProductUpdate
from app.services.product_service import ProductService


router = APIRouter(
    prefix="/products",
    tags=["Products"],
)


@router.get(
    "",
    response_model=list[ProductResponse],
)
def list_products(
    manufacturer_id: int | None = Query(
        default=None,
        gt=0,
    ),
    measurement_id: int | None = Query(
        default=None,
        gt=0,
    ),
    family_id: int | None = Query(
        default=None,
        gt=0,
    ),
    application_id: int | None = Query(
        default=None,
        gt=0,
    ),
    technology_id: int | None = Query(
        default=None,
        gt=0,
    ),
    protocol_id: int | None = Query(
        default=None,
        gt=0,
    ),
    db: Session = Depends(get_db),
) -> list[ProductResponse]:
    return ProductService.list_products(
        db=db,
        manufacturer_id=manufacturer_id,
        measurement_id=measurement_id,
        family_id=family_id,
        application_id=application_id,
        technology_id=technology_id,
        protocol_id=protocol_id,
    )


@router.get(
    "/{product_id}",
    response_model=ProductResponse,
)
def get_product(
    product_id: int,
    db: Session = Depends(get_db),
) -> ProductResponse:
    return ProductService.get_product(
        db,
        product_id,
    )


@router.post(
    "",
    response_model=ProductResponse,
    status_code=201,
)
def create_product(
    product_data: ProductCreate,
    db: Session = Depends(get_db),
) -> ProductResponse:
    return ProductService.create_product(
        db,
        product_data,
    )


@router.patch(
    "/{product_id}",
    response_model=ProductResponse,
)
def update_product(
    product_id: int,
    product_data: ProductUpdate,
    db: Session = Depends(get_db),
) -> ProductResponse:
    return ProductService.update_product(
        db,
        product_id,
        product_data,
    )


@router.delete(
    "/{product_id}",
    status_code=204,
)
def delete_product(
    product_id: int,
    db: Session = Depends(get_db),
) -> Response:
    ProductService.delete_product(
        db,
        product_id,
    )

    return Response(status_code=204)
