from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from fastapi import Response
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.product_family import ProductFamilyCreate
from app.schemas.product_family import ProductFamilyResponse
from app.schemas.product_family import ProductFamilyUpdate
from app.services.product_family_service import ProductFamilyService


router = APIRouter(
    prefix="/product-families",
    tags=["Product Families"],
)


@router.get(
    "",
    response_model=list[ProductFamilyResponse],
)
def list_product_families(
    manufacturer_id: int | None = Query(
        default=None,
        gt=0,
    ),
    db: Session = Depends(get_db),
) -> list[ProductFamilyResponse]:
    return ProductFamilyService.list_product_families(
        db,
        manufacturer_id,
    )


@router.get(
    "/{product_family_id}",
    response_model=ProductFamilyResponse,
)
def get_product_family(
    product_family_id: int,
    db: Session = Depends(get_db),
) -> ProductFamilyResponse:
    return ProductFamilyService.get_product_family(
        db,
        product_family_id,
    )


@router.post(
    "",
    response_model=ProductFamilyResponse,
    status_code=201,
)
def create_product_family(
    product_family_data: ProductFamilyCreate,
    db: Session = Depends(get_db),
) -> ProductFamilyResponse:
    return ProductFamilyService.create_product_family(
        db,
        product_family_data,
    )


@router.patch(
    "/{product_family_id}",
    response_model=ProductFamilyResponse,
)
def update_product_family(
    product_family_id: int,
    product_family_data: ProductFamilyUpdate,
    db: Session = Depends(get_db),
) -> ProductFamilyResponse:
    return ProductFamilyService.update_product_family(
        db,
        product_family_id,
        product_family_data,
    )


@router.delete(
    "/{product_family_id}",
    status_code=204,
)
def delete_product_family(
    product_family_id: int,
    db: Session = Depends(get_db),
) -> Response:
    ProductFamilyService.delete_product_family(
        db,
        product_family_id,
    )

    return Response(
        status_code=204,
    )