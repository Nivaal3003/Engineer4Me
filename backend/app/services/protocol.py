from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crud import protocol as protocol_crud
from app.models.protocol import Protocol
from app.schemas.protocol import ProtocolCreate
from app.schemas.protocol import ProtocolUpdate


def list_protocols(
    db: Session,
    skip: int = 0,
    limit: int = 100,
) -> list[Protocol]:
    return protocol_crud.get_protocols(
        db=db,
        skip=skip,
        limit=limit,
    )


def get_protocol(
    db: Session,
    protocol_id: int,
) -> Protocol:
    protocol = protocol_crud.get_protocol_by_id(
        db=db,
        protocol_id=protocol_id,
    )

    if protocol is None:
        raise HTTPException(
            status_code=404,
            detail="Protocol not found.",
        )

    return protocol


def create_protocol(
    db: Session,
    protocol_data: ProtocolCreate,
) -> Protocol:
    normalized_name = protocol_data.name.strip()

    existing_protocol = protocol_crud.get_protocol_by_name(
        db=db,
        name=normalized_name,
    )

    if existing_protocol is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A protocol named '{normalized_name}' "
                "already exists."
            ),
        )

    try:
        return protocol_crud.create_protocol(
            db=db,
            protocol_data=protocol_data,
        )
    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="The protocol could not be created because it already exists.",
        ) from exc


def update_protocol(
    db: Session,
    protocol_id: int,
    protocol_data: ProtocolUpdate,
) -> Protocol:
    protocol = get_protocol(
        db=db,
        protocol_id=protocol_id,
    )

    if protocol_data.name is not None:
        normalized_name = protocol_data.name.strip()

        existing_protocol = protocol_crud.get_protocol_by_name(
            db=db,
            name=normalized_name,
        )

        if (
            existing_protocol is not None
            and existing_protocol.id != protocol_id
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A protocol named '{normalized_name}' "
                    "already exists."
                ),
            )

    try:
        return protocol_crud.update_protocol(
            db=db,
            protocol=protocol,
            protocol_data=protocol_data,
        )
    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="The protocol update conflicts with existing data.",
        ) from exc


def delete_protocol(
    db: Session,
    protocol_id: int,
) -> None:
    protocol = get_protocol(
        db=db,
        protocol_id=protocol_id,
    )

    try:
        protocol_crud.delete_protocol(
            db=db,
            protocol=protocol,
        )
    except IntegrityError as exc:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail=(
                "This protocol cannot be deleted because it is "
                "currently linked to one or more products."
            ),
        ) from exc