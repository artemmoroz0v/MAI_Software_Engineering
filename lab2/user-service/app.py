from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from uvicorn import run
from starlette.middleware.cors import CORSMiddleware

app = FastAPI(docs_url='/api/docs', title='user-service')

app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        # allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

SECRET_KEY = "supersecretkey"

users_db = {
    "admin": {"password": "secret", "id": 1}
}

class UserCreate(BaseModel):
    username: str
    password: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth")

def generate_token(username: str):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/auth", summary="Authenticate user and get JWT token")
def auth(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Аутентификация пользователя и получение JWT-токена.
    """
    username = form_data.username
    password = form_data.password
    user = users_db.get(username)
    if user and user["password"] == password:
        token = generate_token(username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/users/find/{login}", summary="Find user by login")
def find_user_by_login(login: str, username: str = Depends(verify_token)):
    """
    Поиск пользователя по логину.
    """
    user = users_db.get(login)
    if user:
        return user
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/users/search", summary="Find users by name mask")
def find_user_by_name_mask(nameMask: str, username: str = Depends(verify_token)):
    """
    Поиск пользователей по маске имени.
    """
    matching_users = [
        username
        for username in users_db.keys()
        if nameMask.lower() in username.lower()
    ]
    return matching_users

@app.post("/users", status_code=201, summary="Create a new user")
def create_user(data: UserCreate):
    """
    Создание нового пользователя.
    """
    username = data.username
    password = data.password
    if username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    users_db[username] = {"password": password, "id": len(users_db) + 1}
    return {"message": "User created"}

if __name__ == '__main__':
    run(app, host='0.0.0.0', port=8001)