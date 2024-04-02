from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from app.services.auth import auth_service
from app.schemas.token import TokenData


async def get_current_user(token: str = Depends(auth_service.oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth_service.SECRET_KEY, algorithms=[auth_service.ALGORITHM])
        name: str = payload.get("sub")
        if name is None:
            raise credentials_exception
        token_data = TokenData(sub=name)
    except JWTError:
        raise credentials_exception
    return token_data
