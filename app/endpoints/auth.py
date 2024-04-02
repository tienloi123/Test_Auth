from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from datetime import timedelta
from app.schemas.login import UserLoginForm
from app.schemas.token import Token, TokenData
from app.services.auth import auth_service

router = APIRouter()


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: UserLoginForm):
    if not form_data.username or not form_data.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required",
        )

    # sử dụng thông tin login giả để minh họa
    fake_name = "Doan Tien Loi"
    fake_username = "1"
    fake_password_hash = auth_service.get_password_hash("1")

    if not auth_service.verify_password(form_data.password, fake_password_hash) \
            or form_data.username != fake_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect account or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=30)
    access_token = auth_service.create_access_token(
        data={"sub": fake_name}, expires_delta=access_token_expires
    )

    return access_token


@router.post("/token/cookie", response_model=Token)
async def login_for_access_token_cookie(response: Response, form_data: UserLoginForm):
    if not form_data.username or not form_data.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required",
        )

    # sử dụng thông tin login giả để minh họa
    fake_name = "Nguyen Van A"
    fake_username = "2"
    fake_password_hash = auth_service.get_password_hash("2")

    if not auth_service.verify_password(form_data.password, fake_password_hash) \
            or form_data.username != fake_username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect account or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=30)
    access_token = auth_service.create_access_token(
        data={"sub": fake_name}, expires_delta=access_token_expires
    )

    # Thêm JWT token vào cookie
    response.set_cookie(key="access_token", value=access_token.access_token, httponly=True)
    return access_token


@router.get("/protected_resource")
async def protected_resource(current_user: TokenData = Depends(auth_service.decode_access_token)):
    return {"message": "This is a protected resource", "Name:": current_user.sub}


@router.post("/test")
async def test(request: Request):
    # Xem giá trị của Cookie header
    cookie_value = request.headers.get("Cookie")
    print(cookie_value)
    return {"message": "Received request"}
