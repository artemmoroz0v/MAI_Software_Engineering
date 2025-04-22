import logging
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from uvicorn import run
from starlette.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
import asyncpg
from typing import List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log")
    ]
)
logger = logging.getLogger(__name__)


app = FastAPI(docs_url='/api/docs', title='user-service')


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


DATABASE_URL = "postgresql://postgres:postgres@database:5432/lab3"


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


SECRET_KEY = "supersecretkey"


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
        logger.info(f"Token verified for user: {payload['username']}")
        return payload["username"]
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()


@app.on_event("startup")
async def startup_event():
    logger.info("Running database initialization script...")
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        logger.info("Table 'users' initialized.")
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        logger.info("Index 'idx_username' created.")

        count = await conn.fetchval('SELECT COUNT(*) FROM users')
        if count == 0:
            hashed_password = pwd_context.hash("secret")
            await conn.execute('''
                INSERT INTO users (username, password_hash) VALUES
                ('admin', $1),
                ('user1', $2),
                ('user2', $3)
            ''', hashed_password, pwd_context.hash("password123"), pwd_context.hash("qwerty"))
            logger.info("Test data added to the database.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")
    finally:
        await conn.close()

@app.post("/auth", summary="Authenticate user and get JWT token")
async def auth(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    logger.info(f"Authenticating user: {form_data.username}")
    user = await db.fetchrow('SELECT * FROM users WHERE username = $1', form_data.username)
    if not user or not pwd_context.verify(form_data.password, user['password_hash']):
        logger.warning(f"Authentication failed for user: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = generate_token(user['username'])
    logger.info(f"User {form_data.username} authenticated successfully.")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/users", status_code=201, summary="Create a new user")
async def create_user(data: UserCreate, db=Depends(get_db)):
    logger.info(f"Creating user: {data.username}")
    existing_user = await db.fetchrow('SELECT * FROM users WHERE username = $1', data.username)
    if existing_user:
        logger.warning(f"User already exists: {data.username}")
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = pwd_context.hash(data.password)
    await db.execute('INSERT INTO users (username, password_hash) VALUES ($1, $2)', data.username, hashed_password)
    logger.info(f"User created: {data.username}")
    return {"message": "User created"}

@app.get("/users/find/{login}", summary="Find user by login")
async def find_user_by_login(login: str, username: str = Depends(verify_token), db=Depends(get_db)):
    logger.info(f"Finding user by login: {login}")
    user = await db.fetchrow('SELECT * FROM users WHERE username = $1', login)
    if not user:
        logger.warning(f"User not found: {login}")
        raise HTTPException(status_code=404, detail="User not found")
    logger.info(f"User found: {login}")
    return {"id": user['id'], "username": user['username'], "created_at": user['created_at']}

@app.get("/users/search", summary="Find users by name mask")
async def find_user_by_name_mask(nameMask: str, username: str = Depends(verify_token), db=Depends(get_db)):
    logger.info(f"Searching users by name mask: {nameMask}")
    users = await db.fetch('SELECT * FROM users WHERE username ILIKE $1', f"%{nameMask}%")
    logger.info(f"Found {len(users)} users matching mask: {nameMask}")
    return [{"id": user['id'], "username": user['username']} for user in users]

@app.put("/users/{username}", summary="Update user data")
async def update_user(
    username: str, 
    data: UserCreate, 
    current_user: str = Depends(verify_token), 
    db=Depends(get_db)
):
    logger.info(f"Updating user: {username}")
    if current_user != username:
        logger.warning(f"Unauthorized attempt to update user: {username} by {current_user}")
        raise HTTPException(status_code=403, detail="You can only update your own account")
    user = await db.fetchrow('SELECT * FROM users WHERE username = $1', username)
    if not user:
        logger.warning(f"User not found: {username}")
        raise HTTPException(status_code=404, detail="User not found")
    hashed_password = pwd_context.hash(data.password)
    await db.execute('UPDATE users SET password_hash = $1 WHERE username = $2', hashed_password, username)
    logger.info(f"User updated successfully: {username}")
    return {"message": "User updated successfully"}

@app.delete("/users/{username}", summary="Delete user")
async def delete_user(
    username: str, 
    current_user: str = Depends(verify_token), 
    db=Depends(get_db)
):
    logger.info(f"Deleting user: {username}")
    if current_user != username:
        logger.warning(f"Unauthorized attempt to delete user: {username} by {current_user}")
        raise HTTPException(status_code=403, detail="You can only delete your own account")
    user = await db.fetchrow('SELECT * FROM users WHERE username = $1', username)
    if not user:
        logger.warning(f"User not found: {username}")
        raise HTTPException(status_code=404, detail="User not found")
    await db.execute('DELETE FROM users WHERE username = $1', username)
    logger.info(f"User deleted successfully: {username}")
    return {"message": "User deleted successfully"}

if __name__ == '__main__':
    logger.info("Starting the application...")
    run(app, host='0.0.0.0', port=8001)