from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, Cookie, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy.orm import Session
from database import sessionLocal, engine
from models import Base, User
from schemas import UserCreate
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    create_refresh_token,
)


@asynccontextmanager
async def init_db(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(lifespan=init_db)


oauth_scheme = OAuth2PasswordBearer(tokenUrl="signin")


def get_db():
    db = sessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/signup", status_code=201)
def sign_up(user: UserCreate, db: Session = Depends(get_db)):
    print(user.email, user.password)
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    hashed_pw = hash_password(user.password)
    new_user = User(email=user.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User Created Successfully"}


@app.post("/signin")
def sign_in(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    db_user = db.query(User).filter(User.email == form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Credentials"
        )
    access_token = create_access_token({"sub": db_user.email})
    refresh_token = create_refresh_token({"sub": db_user.email})
    db_user.refresh_token = refresh_token
    db.commit()
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
    }


@app.post("/refresh")
def refresh_token(
    refresh_token_cookie: str = Cookie(None),
    refresh_token_header: str = Header(None, alias="X-Refresh-Token"),
    db: Session = Depends(get_db),
):
    refresh_token = refresh_token_cookie or refresh_token_header
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token is missing"
        )

    try:
        payload = decode_token(refresh_token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token"
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or Expired Token"
        )

    user = db.query(User).filter(User.email == email).first()
    if not user or user.refresh_token != refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or Expired Token"
        )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    user.refresh_token = refresh_token
    db.commit()
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
    }


@app.get("/me")
def read_user_me(token: str = Depends(oauth_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token=token)
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )
    return {"email": user.email}
