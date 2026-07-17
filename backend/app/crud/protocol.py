from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.protocol import Protocol
from app.schemas.protocol import ProtocolCreate
from app.schemas.protocol import ProtocolUpdate


def get_protocol_by_id(
    db: Session,
    protocol_id: int,
) -> Protocol | None:
    statement = select(Protocol).where(
        Protocol.id == protocol_id
    )

    return db.scalar(statement)


def get_protocol_by_name(
    db: Session,
    name: str,
) -> Protocol | None:
    statement = select(Protocol).where(
        func.lower(Protocol.name) == name.strip().lower()
    )

    return db.scalar(statement)


def get_protocols(
    db: Session,
    skip: int = 0,
    limit: int = 100,
) -> list[Protocol]:
    statement = (
        select(Protocol)
        .order_by(Protocol.name.asc())
        .offset(skip)
        .limit(limit)
    )

    return list(db.scalars(statement).all())


def create_protocol(
    db: Session,
    protocol_data: ProtocolCreate,
) -> Protocol:
    protocol = Protocol(
        name=protocol_data.name.strip(),
        description=(
            protocol_data.description.strip()
            if protocol_data.description
            else None
        ),
    )

    db.add(protocol)
    db.commit()
    db.refresh(protocol)

    return protocol


def update_protocol(
    db: Session,
    protocol: Protocol,
    protocol_data: ProtocolUpdate,
) -> Protocol:
    update_values = protocol_data.model_dump(
        exclude_unset=True
    )

    if "name" in update_values:
        update_values["name"] = update_values["name"].strip()

    if (
        "description" in update_values
        and update_values["description"] is not None
    ):
        update_values["description"] = (
            update_values["description"].strip()
        )

    for field_name, field_value in update_values.items():
        setattr(protocol, field_name, field_value)

    db.add(protocol)
    db.commit()
    db.refresh(protocol)

    return protocol


def delete_protocol(
    db: Session,
    protocol: Protocol,
) -> None:
    db.delete(protocol)
    db.commit()