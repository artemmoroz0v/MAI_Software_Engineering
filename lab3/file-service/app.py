import logging
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from uvicorn import run
import asyncpg
from typing import List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("file_service.log")
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(docs_url='/api/docs', title='file-service')

DATABASE_URL = "postgresql://postgres:postgres@database:5432/lab3"

SECRET_KEY = "supersecretkey"

class FileUpload(BaseModel):
    filename: str
    content: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="http://localhost:8001/auth")

def verify_token(token: str = Security(oauth2_scheme)):
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
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                folder_name VARCHAR(255) NOT NULL,
                filename VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(folder_name, filename)
            )
        ''')
        logger.info("Table 'files' initialized.")
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_filename ON files(filename)')
        logger.info("Index 'idx_filename' created.")

        count = await conn.fetchval('SELECT COUNT(*) FROM files')
        if count == 0:
            await conn.execute('''
                INSERT INTO files (folder_name, filename, content) VALUES
                ('folder1', 'file1.txt', 'This is the content of file1'),
                ('folder1', 'file2.txt', 'This is the content of file2'),
                ('folder2', 'file3.txt', 'This is the content of file3')
            ''')
            logger.info("Test data added to the database.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")
    finally:
        await conn.close()

@app.post("/folders/{folder_name}/files", status_code=201, summary="Upload a file to a folder")
async def upload_file_to_folder(
    folder_name: str, 
    file_data: FileUpload, 
    username: str = Depends(verify_token),
    db=Depends(get_db)
):
    """
    Загрузка файла в указанную папку.
    """
    logger.info(f"Uploading file '{file_data.filename}' to folder '{folder_name}' by user '{username}'")
    existing_file = await db.fetchrow(
        'SELECT * FROM files WHERE folder_name = $1 AND filename = $2',
        folder_name, file_data.filename
    )
    if existing_file:
        logger.warning(f"File '{file_data.filename}' already exists in folder '{folder_name}'")
        raise HTTPException(status_code=400, detail="File already exists in this folder")
    
    await db.execute(
        'INSERT INTO files (folder_name, filename, content) VALUES ($1, $2, $3)',
        folder_name, file_data.filename, file_data.content
    )
    logger.info(f"File '{file_data.filename}' uploaded to folder '{folder_name}'")
    return {"message": f"File uploaded to folder {folder_name}"}

@app.get("/files", summary="Get a file by name")
async def get_file_by_name(name: str, username: str = Depends(verify_token), db=Depends(get_db)):
    """
    Получение файла по имени.
    """
    logger.info(f"Fetching file '{name}' by user '{username}'")
    file = await db.fetchrow(
        'SELECT * FROM files WHERE filename = $1',
        name
    )
    if not file:
        logger.warning(f"File '{name}' not found")
        raise HTTPException(status_code=404, detail="File not found")
    logger.info(f"File '{name}' fetched successfully")
    return {file['filename']: file['content']}

@app.delete("/files/{filename}", summary="Delete a file by filename")
async def delete_file(filename: str, username: str = Depends(verify_token), db=Depends(get_db)):
    """
    Удаление файла.
    """
    logger.info(f"Deleting file '{filename}' by user '{username}'")
    result = await db.execute(
        'DELETE FROM files WHERE filename = $1',
        filename
    )
    if result == "DELETE 0":
        logger.warning(f"File '{filename}' not found for deletion")
        raise HTTPException(status_code=404, detail="File not found")
    logger.info(f"File '{filename}' deleted successfully")
    return {"message": f"File {filename} deleted"}

if __name__ == '__main__':
    logger.info("Starting the application...")
    run(app, host='0.0.0.0', port=8000)