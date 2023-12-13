import os, secrets, re
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel

from fastapi import Depends, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

import pbkdf2
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet

from database import get_user, insert_user_database, get_all_list_users, delete_user_by_username

SECRET_KEY = "befe2f412b5f730948661e780640eb7f82453f706064a7119365798e7122eb4c"

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token : str
    token_type : str

class TokenData(BaseModel):
    username : Optional[str] = None

class User(BaseModel):
    username : str
    email : Optional[str] = None
    full_name : Optional[str] = None
    password : str
    disabled : Optional[bool] = False

pwd_context = CryptContext(schemes=['bcrypt'],deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
router = APIRouter()

def verify_password(plain_password,hashed_password):
    return pwd_context.verify(plain_password,hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username : str, password : str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user

def create_access_token(data : dict, expires_delta : Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp" : expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY,algorithm = ALGORITHM)
    return encoded_jwt

async def get_current_user(token : str = Depends(oauth2_scheme)):
    crendentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate" : "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username : str = payload.get("sub")
        if username is None:
            raise crendentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise crendentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise crendentials_exception
    return user

async def get_current_active_user(current_user : User = Depends(get_current_user)):
    if current_user['disabled']:
        raise HTTPException(status_code=400,detail="Inactive user")
    return current_user

@router.post("/register")
async def register(new_user : User):
    exist_username = get_user(new_user.username)
    if exist_username:
        raise HTTPException(status_code=400,detail="Username Existed")
    username = new_user.username
    email = new_user.email
    full_name = new_user.full_name
    password_regex = re.compile("(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})")
    if password_regex.fullmatch(new_user.password):
        raise HTTPException(status_code=400,detail="Password Not Match")
    password = get_password_hash(new_user.password)
    disabled = new_user.disabled
    if disabled == None:
        disabled = False
    with open(f"{username}-secretkey-fernet.bin","wb") as f:
        f.write(Fernet.generate_key())
    insert_user_database(username,email,full_name,password,disabled)
    return {"message" : "successfull register"}

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data : OAuth2PasswordRequestForm = Depends()):
    crendentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate" : "Bearer"}
    )
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise crendentials_exception
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub" : user['username']}, expires_delta=access_token_expires)
    return {"access_token" : access_token, "token_type" : "bearer"}