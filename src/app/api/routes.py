from fastapi import APIRouter

router = APIRouter()

@router.get("/auth")
def authorize():
    return(f"Redirecting to auth")
