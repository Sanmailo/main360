from fastapi import FastAPI, HTTPException, Depends, Request, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List, Optional
from bson import ObjectId
from dotenv import load_dotenv
import os
import uvicorn
import requests
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# CORS middleware should be added after the app instance is created
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
client = MongoClient("mongodb+srv://sanmi2009:oeVE5JKWBEjf9BlH@cluster0.n1cvn6z.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["callpoint"]
users_collection = db["users"]


# Secret key generation
SECRET_KEY = os.getenv("SECRET_KEY")
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")

# JWT configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
RESET_TOKEN_EXPIRE_MINUTES = 15  # Token expiration time for password reset

# HTTP Bearer security scheme
bearer_scheme = HTTPBearer()

# Password hashing and verification
pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str = None

class User(BaseModel):
    email: str = None
    firstName: str = None
    middleName: str = None
    lastName: str = None
    disabled: bool = None

class UserInDB(User):
    hashed_password: str

class SignUp(BaseModel):
    firstName: str = None
    middleName: str = None
    lastName: str = None
    email: EmailStr
    phoneNumber: str
    sex: str
    password: str
    confirmPassword: str

class SignIn(BaseModel):
    email: Optional[EmailStr] = None
    phoneNumber: Optional[str] = None
    password: str


class PaystackPayment(BaseModel):
    email: EmailStr
    amount: int

class ResetPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordForm(BaseModel):
    token: str
    new_password: str

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_cxt.verify(plain_password, hashed_password)

def get_user_by_email(email: str):
    return users_collection.find_one({"email": email})

def get_user_by_phone(phoneNumber: str):
    return users_collection.find_one({"phoneNumber": phoneNumber})

def authenticate_user(email: Optional[str], phoneNumber: Optional[str], password: str):
    user = None
    if email:
        user = get_user_by_email(email)
    elif phoneNumber:
        user = get_user_by_phone(phoneNumber)
    
    if not user or not verify_password(password, user["password"]):
        return False
    return user


async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def create_reset_token(email: str):
    to_encode = {"sub": email}
    expire = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Routes
@app.post("/token", response_model=Token)
async def sign_in_for_access_token(email: str = None, phoneNumber: str = None, password: str = Body(...)):
    user = authenticate_user(email, phoneNumber, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email/phone number or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": user["email"] if user["email"] else user["phoneNumber"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(token_data.email)
    if user is None:
        raise credentials_exception
    return user

@app.post("/SignUp")
async def sign_up_user(user: SignUp):
   if user.password != user.confirmPassword:
      raise HTTPException(status_code=400, detail="Passwords do not match")
   hashed_password = pwd_cxt.hash(user.password)
   user_data = user.dict()
   user_data["password"] = hashed_password
   del user_data["confirmPassword"]
   users_collection.insert_one(user_data)
   return {"message": "User SignUp successfully"}

@app.post("/SignIn")
async def sign_in_user(form_data: SignIn):
    user = authenticate_user(form_data.email, form_data.phoneNumber, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email/phone number or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": user["email"] if user["email"] else user["phoneNumber"]}, expires_delta=access_token_expires
    )
    return {"message": "SignIn successfully", "accessToken": access_token}

@app.post("/SignOut")
async def sign_out_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        # Invalidate the token
        return {"message": "SignOut successfully"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/forget_password")
async def forget_password(request: ResetPasswordRequest):
    user = get_user_by_email(request.email)
    if user is None:
        raise HTTPException(status_code=404, detail="Email not found")
    
    reset_token = await create_reset_token(request.email)
    
    # Here you would typically send the reset token via email to the user.
    # send_reset_email(user["email"], reset_token)  # Implement this function
    
    return {"message": "Password reset token sent successfully", "reset_token": reset_token}  # For testing purposes

@app.post("/reset_password")
async def reset_password(form_data: ResetPasswordForm):
    try:
        payload = jwt.decode(form_data.token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user_by_email(email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    hashed_password = pwd_cxt.hash(form_data.new_password)
    users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
    
    return {"message": "Password has been reset successfully"}


# Paystack payment integration
@app.post("/paystack/pay")
async def paystack_payment(payment: PaystackPayment):
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "email": payment.email,
        "amount": payment.amount * 100  # Paystack expects amount in kobo (1 NGN = 100 kobo)
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()

# Running the application with Uvicorn
# if __name__ == "__main__":
#     port = int(os.environ.get("PORT", 8000))
#     uvicorn.run("main:app", host="0.0.0.0", port=port)