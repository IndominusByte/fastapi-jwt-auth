from fastapi import APIRouter, Depends
from fastapi_jwt_auth import AuthJWT

router = APIRouter()

@router.get('/items')
def items(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    items = [
        "item1",
        "item2",
        "item3"
    ]

    return {"items": items}
