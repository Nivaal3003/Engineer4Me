from fastapi import APIRouter

router = APIRouter(
    prefix="/measurements",
    tags=["Measurements"]
)


@router.get("/")
def list_measurements():
    return [
        {"id": 1, "name": "Pressure"},
        {"id": 2, "name": "Temperature"},
        {"id": 3, "name": "Flow"},
        {"id": 4, "name": "Level"},
        {"id": 5, "name": "Tank Gauging"},
    ]