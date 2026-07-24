from fastapi import APIRouter
from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.selection import SelectionRequest
from app.schemas.selection import SelectionResponse
from app.services.selection_service import SelectionService


router = APIRouter(
    prefix="/selections",
    tags=["Selections"],
)


@router.post(
    "",
    response_model=SelectionResponse,
)
def select_products(
    request: SelectionRequest,
    db: Session = Depends(get_db),
) -> SelectionResponse:
    return SelectionService.select_products(
        db=db,
        request=request,
    )
