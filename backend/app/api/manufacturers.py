from fastapi import APIRouter

router = APIRouter(
    prefix="/manufacturers",
    tags=["Manufacturers"]
)


@router.get("/")
def list_manufacturers():
    return [
        {
            "id": 1,
            "name": "Emerson"
        }
    ]


@router.get("/{manufacturer_id}")
def get_manufacturer(manufacturer_id: int):
    return {
        "id": manufacturer_id,
        "name": "Emerson"
    }


@router.post("/")
def create_manufacturer():
    return {
        "message": "Manufacturer created"
    }


@router.put("/{manufacturer_id}")
def update_manufacturer(manufacturer_id: int):
    return {
        "message": f"Manufacturer {manufacturer_id} updated"
    }


@router.delete("/{manufacturer_id}")
def delete_manufacturer(manufacturer_id: int):
    return {
        "message": f"Manufacturer {manufacturer_id} deleted"
    }