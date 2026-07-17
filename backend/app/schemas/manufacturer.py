from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class ManufacturerBase(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=100,
        examples=["Emerson"],
    )

    website: str | None = Field(
        default=None,
        max_length=255,
        examples=["https://www.emerson.com"],
    )

    country: str | None = Field(
        default=None,
        max_length=100,
        examples=["United States"],
    )


class ManufacturerCreate(ManufacturerBase):
    pass


class ManufacturerUpdate(BaseModel):
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    website: str | None = Field(
        default=None,
        max_length=255,
    )

    country: str | None = Field(
        default=None,
        max_length=100,
    )


class ManufacturerResponse(ManufacturerBase):
    model_config = ConfigDict(from_attributes=True)

    id: int