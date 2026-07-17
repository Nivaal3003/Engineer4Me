from fastapi import APIRouter
from fastapi import Depends
from fastapi import Response
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.manufacturer import ManufacturerCreate
from app.schemas.manufacturer import ManufacturerResponse
from app.schemas.manufacturer import ManufacturerUpdate
from app.services.manufacturer_service import ManufacturerService


router = APIRouter(
    prefix="/manufacturers",
    tags=["Manufacturers"],
)


@router.get(
    "",
    response_model=list[ManufacturerResponse],
)
def list_manufacturers(
    db: Session = Depends(get_db),
) -> list[ManufacturerResponse]:
    return ManufacturerService.list_manufacturers(db)


@router.get(
    "/{manufacturer_id}",
    response_model=ManufacturerResponse,
)
def get_manufacturer(
    manufacturer_id: int,
    db: Session = Depends(get_db),
) -> ManufacturerResponse:
    return ManufacturerService.get_manufacturer(
        db,
        manufacturer_id,
    )


@router.post(
    "",
    response_model=ManufacturerResponse,
    status_code=201,
)
def create_manufacturer(
    manufacturer_data: ManufacturerCreate,
    db: Session = Depends(get_db),
) -> ManufacturerResponse:
    return ManufacturerService.create_manufacturer(
        db,
        manufacturer_data,
    )


@router.patch(
    "/{manufacturer_id}",
    response_model=ManufacturerResponse,
)
def update_manufacturer(
    manufacturer_id: int,
    manufacturer_data: ManufacturerUpdate,
    db: Session = Depends(get_db),
) -> ManufacturerResponse:
    return ManufacturerService.update_manufacturer(
        db,
        manufacturer_id,
        manufacturer_data,
    )


@router.delete(
    "/{manufacturer_id}",
    status_code=204,
)
def delete_manufacturer(
    manufacturer_id: int,
    db: Session = Depends(get_db),
) -> Response:
    ManufacturerService.delete_manufacturer(
        db,
        manufacturer_id,
    )

    return Response(status_code=204)