from fastapi import FastAPI

from app.api.manufacturers import router as manufacturer_router
from app.api.measurements import router as measurement_router
from app.api.product_families import router as product_family_router
from app.api.products import router as product_router
from app.api.protocol import router as protocol_router


app = FastAPI(
    title="Engineer4Me API",
    version="0.4.0",
    description=(
        "Vendor-neutral engineering knowledge platform "
        "for process instrumentation."
    ),
)


@app.get(
    "/",
    tags=["System"],
)
def root() -> dict[str, str]:
    return {
        "application": "Engineer4Me",
        "status": "running",
        "version": "0.4.0",
    }


@app.get(
    "/health",
    tags=["System"],
)
def health() -> dict[str, str]:
    return {
        "status": "healthy",
    }


app.include_router(
    manufacturer_router,
    prefix="/api/v1",
)

app.include_router(
    measurement_router,
    prefix="/api/v1",
)

app.include_router(
    protocol_router,
    prefix="/api/v1",
)

app.include_router(
    product_family_router,
    prefix="/api/v1",
)

app.include_router(
    product_router,
    prefix="/api/v1",
)
