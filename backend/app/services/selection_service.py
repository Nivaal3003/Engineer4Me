from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engineering.recommendation_engine import RecommendationEngine
from app.models.application import Application
from app.models.manufacturer import Manufacturer
from app.models.measurement import Measurement
from app.models.product_family import ProductFamily
from app.models.protocol import Protocol
from app.models.technology import Technology
from app.repositories.product_repository import ProductRepository
from app.schemas.selection import SelectionRequest
from app.schemas.selection import SelectionResponse


class SelectionService:
    @staticmethod
    def _validate_reference_data(
        db: Session,
        request: SelectionRequest,
    ) -> None:
        measurement = db.get(
            Measurement,
            request.measurement_id,
        )

        if measurement is None:
            raise HTTPException(
                status_code=400,
                detail="Measurement does not exist.",
            )

        if request.manufacturer_id is not None:
            manufacturer = db.get(
                Manufacturer,
                request.manufacturer_id,
            )

            if manufacturer is None:
                raise HTTPException(
                    status_code=400,
                    detail="Manufacturer does not exist.",
                )

        if request.family_id is not None:
            family = db.get(
                ProductFamily,
                request.family_id,
            )

            if family is None:
                raise HTTPException(
                    status_code=400,
                    detail="Product family does not exist.",
                )

            if (
                request.manufacturer_id is not None
                and family.manufacturer_id
                != request.manufacturer_id
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Product family does not belong to "
                        "the selected manufacturer."
                    ),
                )

        if request.application_id is not None:
            application = db.get(
                Application,
                request.application_id,
            )

            if application is None:
                raise HTTPException(
                    status_code=400,
                    detail="Application does not exist.",
                )

        if request.technology_id is not None:
            technology = db.get(
                Technology,
                request.technology_id,
            )

            if technology is None:
                raise HTTPException(
                    status_code=400,
                    detail="Technology does not exist.",
                )

        if request.protocol_ids:
            statement = select(Protocol.id).where(
                Protocol.id.in_(request.protocol_ids)
            )

            found_protocol_ids = set(
                db.scalars(statement).all()
            )

            missing_protocol_ids = sorted(
                set(request.protocol_ids)
                - found_protocol_ids
            )

            if missing_protocol_ids:
                missing_values = ", ".join(
                    str(protocol_id)
                    for protocol_id in missing_protocol_ids
                )

                raise HTTPException(
                    status_code=400,
                    detail=(
                        "The following protocols do not exist: "
                        f"{missing_values}."
                    ),
                )

    @staticmethod
    def select_products(
        db: Session,
        request: SelectionRequest,
    ) -> SelectionResponse:
        SelectionService._validate_reference_data(
            db,
            request,
        )

        candidates = ProductRepository.list_all(
            db=db,
            measurement_id=request.measurement_id,
        )

        recommendations = RecommendationEngine.recommend(
            products=candidates,
            request=request,
        )

        return SelectionResponse(
            total_candidates=len(candidates),
            total_recommendations=len(recommendations),
            recommendations=recommendations,
        )
