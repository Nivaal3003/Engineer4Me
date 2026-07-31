from fastapi import FastAPI

from app.api.calculations import CalculationRequestBodyLimitMiddleware
from app.api.calculations import router as calculation_router
from app.api.filesystem_document_execution_api import (
    router as filesystem_document_execution_router,
)
from app.api.filesystem_document_upload_api import (
    router as filesystem_document_upload_router,
)
from app.api.ingestion import router as ingestion_router
from app.api.knowledge import router as knowledge_router
from app.api.manufacturers import router as manufacturer_router
from app.api.measurements import router as measurement_router
from app.api.product_families import router as product_family_router
from app.api.products import router as product_router
from app.api.protocol import router as protocol_router
from app.api.selections import router as selection_router


APPLICATION_VERSION = "0.10.0"


app = FastAPI(
    title="Engineer4Me API",
    version=APPLICATION_VERSION,
    description=(
        "Vendor-neutral engineering knowledge platform "
        "for process instrumentation."
    ),
)
app.add_middleware(CalculationRequestBodyLimitMiddleware)


@app.get(
    "/",
    tags=["System"],
)
def root() -> dict[str, str]:
    return {
        "application": "Engineer4Me",
        "status": "running",
        "version": APPLICATION_VERSION,
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

app.include_router(
    selection_router,
    prefix="/api/v1",
)

app.include_router(
    knowledge_router,
    prefix="/api/v1",
)

app.include_router(
    ingestion_router,
    prefix="/api/v1",
)

app.include_router(
    filesystem_document_upload_router,
    prefix="/api/v1",
)

app.include_router(
    filesystem_document_execution_router,
    prefix="/api/v1",
)

app.include_router(
    calculation_router,
    prefix="/api/v1",
)
