import os
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from jose import JWTError, jwt
from fastapi import HTTPException, status

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRY_DAYS = 7


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def create_token(data: dict, expires_delta: timedelta, secret_key: str):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)


def create_access_token(data: dict):
    return create_token(
        data, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES), SECRET_KEY
    )


def create_refresh_token(data: dict):
    return create_token(
        data,
        timedelta(minutes=REFRESH_TOKEN_EXPIRY_DAYS),
        SECRET_KEY,
    )


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or Expired Token"
        )
