from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class ProtocolBase(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=100,
        examples=["HART"],
    )

    description: str | None = Field(
        default=None,
        max_length=500,
        examples=["Highway Addressable Remote Transducer protocol."],
    )


class ProtocolCreate(ProtocolBase):
    pass


class ProtocolUpdate(BaseModel):
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    description: str | None = Field(
        default=None,
        max_length=500,
    )


class ProtocolResponse(ProtocolBase):
    model_config = ConfigDict(from_attributes=True)

    id: int