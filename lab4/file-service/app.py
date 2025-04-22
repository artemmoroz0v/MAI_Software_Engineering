import logging
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from uvicorn import run
from motor.motor_asyncio import AsyncIOMotorClient
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

MONGO_URL = "mongodb://mongo:27017"
DATABASE_NAME = "lab4"

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
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DATABASE_NAME]
    try:
        yield db
    finally:
        client.close()

@app.on_event("startup")
async def startup_event():
    logger.info("Running database initialization script...")
    db = AsyncIOMotorClient(MONGO_URL)[DATABASE_NAME]
    try:
        # Ensure unique index on folder_name and filename
        await db.files.create_index([("folder_name", 1), ("filename", 1)], unique=True)
        logger.info("Index 'folder_name_filename' created.")

        # Check if the collection is empty and insert test data
        count = await db.files.count_documents({})
        if count == 0:
            await db.files.insert_many([
                {"folder_name": "folder1", "filename": "file1.txt", "content": "This is the content of file1", "created_at": datetime.utcnow()},
                {"folder_name": "folder1", "filename": "file2.txt", "content": "This is the content of file2", "created_at": datetime.utcnow()},
                {"folder_name": "folder2", "filename": "file3.txt", "content": "This is the content of file3", "created_at": datetime.utcnow()}
            ])
            logger.info("Test data added to the database.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")

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
    existing_file = await db.files.find_one({"folder_name": folder_name, "filename": file_data.filename})
    if existing_file:
        logger.warning(f"File '{file_data.filename}' already exists in folder '{folder_name}'")
        raise HTTPException(status_code=400, detail="File already exists in this folder")
    
    await db.files.insert_one({
        "folder_name": folder_name,
        "filename": file_data.filename,
        "content": file_data.content,
        "created_at": datetime.utcnow()
    })
    logger.info(f"File '{file_data.filename}' uploaded to folder '{folder_name}'")
    return {"message": f"File uploaded to folder {folder_name}"}

@app.get("/files", summary="Get a file by name")
async def get_file_by_name(name: str, username: str = Depends(verify_token), db=Depends(get_db)):
    """
    Получение файла по имени.
    """
    logger.info(f"Fetching file '{name}' by user '{username}'")
    file = await db.files.find_one({"filename": name})
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
    result = await db.files.delete_one({"filename": filename})
    if result.deleted_count == 0:
        logger.warning(f"File '{filename}' not found for deletion")
        raise HTTPException(status_code=404, detail="File not found")
    logger.info(f"File '{filename}' deleted successfully")
    return {"message": f"File {filename} deleted"}

if __name__ == '__main__':
    logger.info("Starting the application...")
    run(app, host='0.0.0.0', port=8000)