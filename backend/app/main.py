from fastapi import FastAPI
from app.api.manufacturers import router as manufacturer_router

app = FastAPI(
    title="Engineer4Me API",
    version="0.1.0",
    description="Engineering knowledge platform for process instrumentation."
)

@app.get("/")
def root():
    return {
        "application": "Engineer4Me",
        "status": "running",
        "version": "0.1.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


app.include_router(
    manufacturer_router,
    prefix="/api/v1"
)
from app.api.measurements import router as measurement_router
app.include_router(
    measurement_router,
    prefix="/api/v1"
)