from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator


class SelectionRequest(BaseModel):
    measurement_id: int = Field(gt=0)

    manufacturer_id: int | None = Field(
        default=None,
        gt=0,
    )

    family_id: int | None = Field(
        default=None,
        gt=0,
    )

    application_id: int | None = Field(
        default=None,
        gt=0,
    )

    technology_id: int | None = Field(
        default=None,
        gt=0,
    )

    protocol_ids: list[int] = Field(
        default_factory=list,
    )

    minimum_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    limit: int = Field(
        default=10,
        ge=1,
        le=100,
    )

    @field_validator("protocol_ids")
    @classmethod
    def validate_protocol_ids(
        cls,
        value: list[int],
    ) -> list[int]:
        if any(protocol_id <= 0 for protocol_id in value):
            raise ValueError(
                "Every protocol ID must be greater than zero."
            )

        return list(dict.fromkeys(value))


class SelectionReason(BaseModel):
    criterion: str
    matched: bool
    score: int
    explanation: str


class ProductRecommendation(BaseModel):
    product_id: int
    manufacturer: str
    family: str
    model: str
    description: str | None
    score: int
    maximum_score: int
    match_percentage: float
    reasons: list[SelectionReason]


class SelectionResponse(BaseModel):
    total_candidates: int
    total_recommendations: int
    recommendations: list[ProductRecommendation]
