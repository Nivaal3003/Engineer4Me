from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class ProductFamilyBase(BaseModel):
    manufacturer_id: int = Field(
        gt=0,
        examples=[1],
    )

    name: str = Field(
        min_length=1,
        max_length=100,
        examples=["Rosemount Pressure"],
    )

    description: str | None = Field(
        default=None,
        max_length=255,
        examples=[
            "Pressure measurement products and transmitter families."
        ],
    )


class ProductFamilyCreate(ProductFamilyBase):
    pass


class ProductFamilyUpdate(BaseModel):
    manufacturer_id: int | None = Field(
        default=None,
        gt=0,
    )

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    description: str | None = Field(
        default=None,
        max_length=255,
    )


class ProductFamilyResponse(ProductFamilyBase):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: int