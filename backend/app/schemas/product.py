from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator


def normalize_text_list(values: list[str]) -> list[str]:
    """Remove blank values and duplicates from text lists."""
    normalized_values: list[str] = []

    for value in values:
        cleaned_value = value.strip()

        if (
            cleaned_value
            and cleaned_value not in normalized_values
        ):
            normalized_values.append(cleaned_value)

    return normalized_values


class ProductCreate(BaseModel):
    manufacturer_id: int = Field(gt=0)
    measurement_id: int = Field(gt=0)
    family_id: int = Field(gt=0)
    application_id: int = Field(gt=0)
    technology_id: int | None = Field(default=None, gt=0)

    model: str = Field(
        min_length=1,
        max_length=100,
    )

    description: str | None = Field(
        default=None,
        max_length=255,
    )

    protocol_ids: list[int] = Field(
        default_factory=list,
    )

    minimum_process_temperature_c: float | None = None
    maximum_process_temperature_c: float | None = None

    minimum_process_pressure_bar: float | None = None
    maximum_process_pressure_bar: float | None = None

    minimum_ambient_temperature_c: float | None = None
    maximum_ambient_temperature_c: float | None = None

    accuracy_percent: float | None = Field(
        default=None,
        gt=0,
        le=100,
    )

    ingress_protection_rating: str | None = Field(
        default=None,
        max_length=20,
    )

    hazardous_area_approvals: list[str] = Field(
        default_factory=list,
    )

    wetted_materials: list[str] = Field(
        default_factory=list,
    )

    process_connections: list[str] = Field(
        default_factory=list,
    )

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

    @field_validator("ingress_protection_rating")
    @classmethod
    def validate_ingress_protection_rating(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned_value = value.strip().upper()
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

    @field_validator(
        "hazardous_area_approvals",
        "wetted_materials",
        "process_connections",
    )
    @classmethod
    def validate_text_lists(
        cls,
        value: list[str],
    ) -> list[str]:
        return normalize_text_list(value)

    @model_validator(mode="after")
    def validate_engineering_ranges(self):
        ranges = [
            (
                self.minimum_process_temperature_c,
                self.maximum_process_temperature_c,
                "process temperature",
            ),
            (
                self.minimum_process_pressure_bar,
                self.maximum_process_pressure_bar,
                "process pressure",
            ),
            (
                self.minimum_ambient_temperature_c,
                self.maximum_ambient_temperature_c,
                "ambient temperature",
            ),
        ]

        for minimum_value, maximum_value, name in ranges:
            if (
                minimum_value is not None
                and maximum_value is not None
                and minimum_value > maximum_value
            ):
                raise ValueError(
                    f"Minimum {name} cannot exceed "
                    f"maximum {name}."
                )

        return self


class ProductUpdate(BaseModel):
    manufacturer_id: int | None = Field(
        default=None,
        gt=0,
    )

    measurement_id: int | None = Field(
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

    minimum_process_temperature_c: float | None = None
    maximum_process_temperature_c: float | None = None

    minimum_process_pressure_bar: float | None = None
    maximum_process_pressure_bar: float | None = None

    minimum_ambient_temperature_c: float | None = None
    maximum_ambient_temperature_c: float | None = None

    accuracy_percent: float | None = Field(
        default=None,
        gt=0,
        le=100,
    )

    ingress_protection_rating: str | None = Field(
        default=None,
        max_length=20,
    )

    hazardous_area_approvals: list[str] | None = None
    wetted_materials: list[str] | None = None
    process_connections: list[str] | None = None

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

    @field_validator("ingress_protection_rating")
    @classmethod
    def validate_ingress_protection_rating(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned_value = value.strip().upper()
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

    @field_validator(
        "hazardous_area_approvals",
        "wetted_materials",
        "process_connections",
    )
    @classmethod
    def validate_optional_text_lists(
        cls,
        value: list[str] | None,
    ) -> list[str] | None:
        if value is None:
            return None

        return normalize_text_list(value)

    @model_validator(mode="after")
    def validate_engineering_ranges(self):
        ranges = [
            (
                self.minimum_process_temperature_c,
                self.maximum_process_temperature_c,
                "process temperature",
            ),
            (
                self.minimum_process_pressure_bar,
                self.maximum_process_pressure_bar,
                "process pressure",
            ),
            (
                self.minimum_ambient_temperature_c,
                self.maximum_ambient_temperature_c,
                "ambient temperature",
            ),
        ]

        for minimum_value, maximum_value, name in ranges:
            if (
                minimum_value is not None
                and maximum_value is not None
                and minimum_value > maximum_value
            ):
                raise ValueError(
                    f"Minimum {name} cannot exceed "
                    f"maximum {name}."
                )

        return self


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

    minimum_process_temperature_c: float | None = None
    maximum_process_temperature_c: float | None = None

    minimum_process_pressure_bar: float | None = None
    maximum_process_pressure_bar: float | None = None

    minimum_ambient_temperature_c: float | None = None
    maximum_ambient_temperature_c: float | None = None

    accuracy_percent: float | None = None
    ingress_protection_rating: str | None = None

    hazardous_area_approvals: list[str] = Field(
        default_factory=list,
    )

    wetted_materials: list[str] = Field(
        default_factory=list,
    )

    process_connections: list[str] = Field(
        default_factory=list,
    )

    manufacturer: ManufacturerSummary
    measurement: MeasurementSummary
    family: ProductFamilySummary
    application: ApplicationSummary
    technology: TechnologySummary | None
    protocols: list[ProtocolSummary]