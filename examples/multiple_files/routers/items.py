from fastapi import APIRouter, Depends
from async_fastapi_jwt_auth import AuthJWT

router = APIRouter()


@router.get('/items')
async def items(Authorize: AuthJWT = Depends()):
    await Authorize.jwt_required()

    items = [
        "item1",
        "item2",
        "item3"
    ]

    return {"items": items}
