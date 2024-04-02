from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from app.schemas.token import Token, TokenData

# Secret key để ký và giải mã JWT token
SECRET_KEY = "doantienloi"
ALGORITHM = "HS256"


class AuthService:
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    # Mã hóa mật khẩu
    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    # Kiểm tra mật khẩu hợp lệ
    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    # Tạo JWT token
    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return Token(access_token=encoded_jwt, token_type="bearer")

    # Decode JWT token
    @staticmethod
    def decode_access_token(token: str) -> TokenData:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(sub=payload.get("sub"))


auth_service = AuthService()
