from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator


class ProductCreate(BaseModel):
    manufacturer_id: int = Field(gt=0)
    measurement_id: int = Field(gt=0)
    family_id: int = Field(gt=0)
    application_id: int = Field(gt=0)
    technology_id: int | None = Field(default=None, gt=0)
    model: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=255)
    protocol_ids: list[int] = Field(default_factory=list)

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        cleaned_value = value.strip()

        if not cleaned_value:
            raise ValueError("Model cannot be empty.")

        return cleaned_value

    @field_validator("description")
    @classmethod
    def validate_description(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned_value = value.strip()
        return cleaned_value or None

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


class ProductUpdate(BaseModel):
    manufacturer_id: int | None = Field(default=None, gt=0)
    measurement_id: int | None = Field(default=None, gt=0)
    family_id: int | None = Field(default=None, gt=0)
    application_id: int | None = Field(default=None, gt=0)
    technology_id: int | None = Field(default=None, gt=0)
    model: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )
    description: str | None = Field(
        default=None,
        max_length=255,
    )
    protocol_ids: list[int] | None = None

    @field_validator("model")
    @classmethod
    def validate_model(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned_value = value.strip()

        if not cleaned_value:
            raise ValueError("Model cannot be empty.")

        return cleaned_value

    @field_validator("description")
    @classmethod
    def validate_description(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned_value = value.strip()
        return cleaned_value or None

    @field_validator("protocol_ids")
    @classmethod
    def validate_protocol_ids(
        cls,
        value: list[int] | None,
    ) -> list[int] | None:
        if value is None:
            return None

        if any(protocol_id <= 0 for protocol_id in value):
            raise ValueError(
                "Every protocol ID must be greater than zero."
            )

        return list(dict.fromkeys(value))


class ManufacturerSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class MeasurementSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class ProductFamilySummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    manufacturer_id: int
    name: str


class ApplicationSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class TechnologySummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class ProtocolSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class ProductResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    manufacturer_id: int
    measurement_id: int
    family_id: int
    application_id: int
    technology_id: int | None
    model: str
    description: str | None

    manufacturer: ManufacturerSummary
    measurement: MeasurementSummary
    family: ProductFamilySummary
    application: ApplicationSummary
    technology: TechnologySummary | None
    protocols: list[ProtocolSummary]
