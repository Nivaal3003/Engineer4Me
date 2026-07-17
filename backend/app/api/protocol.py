from collections.abc import Generator

from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from fastapi import Response
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.schemas.protocol import ProtocolCreate
from app.schemas.protocol import ProtocolResponse
from app.schemas.protocol import ProtocolUpdate
from app.services import protocol as protocol_service


router = APIRouter(
    prefix="/protocols",
    tags=["Protocols"],
)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.get(
    "",
    response_model=list[ProtocolResponse],
)
def list_protocols(
    skip: int = Query(
        default=0,
        ge=0,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    db: Session = Depends(get_db),
) -> list[ProtocolResponse]:
    return protocol_service.list_protocols(
        db=db,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{protocol_id}",
    response_model=ProtocolResponse,
)
def get_protocol(
    protocol_id: int,
    db: Session = Depends(get_db),
) -> ProtocolResponse:
    return protocol_service.get_protocol(
        db=db,
        protocol_id=protocol_id,
    )


@router.post(
    "",
    response_model=ProtocolResponse,
    status_code=201,
)
def create_protocol(
    protocol_data: ProtocolCreate,
    db: Session = Depends(get_db),
) -> ProtocolResponse:
    return protocol_service.create_protocol(
        db=db,
        protocol_data=protocol_data,
    )


@router.patch(
    "/{protocol_id}",
    response_model=ProtocolResponse,
)
def update_protocol(
    protocol_id: int,
    protocol_data: ProtocolUpdate,
    db: Session = Depends(get_db),
) -> ProtocolResponse:
    return protocol_service.update_protocol(
        db=db,
        protocol_id=protocol_id,
        protocol_data=protocol_data,
    )


@router.delete(
    "/{protocol_id}",
    status_code=204,
)
def delete_protocol(
    protocol_id: int,
    db: Session = Depends(get_db),
) -> Response:
    protocol_service.delete_protocol(
        db=db,
        protocol_id=protocol_id,
    )

    return Response(status_code=204)