from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from uvicorn import run

app = FastAPI(docs_url='/api/docs', title='file-service')

SECRET_KEY = "supersecretkey"

files_db = {}

class FileUpload(BaseModel):
    filename: str
    content: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="http://localhost:8001/auth")

def verify_token(token: str = Security(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/folders/{folder_id}/files", status_code=201, summary="Upload a file to a folder")
def upload_file_to_folder(
    folder_id: str, 
    file_data: FileUpload, 
    username: str = Depends(verify_token)
):
    """
    Загрузка файла в указанную папку.
    """
    if folder_id not in files_db:
        files_db[folder_id] = {}
    if file_data.filename in files_db[folder_id]:
        raise HTTPException(status_code=400, detail="File already exists in this folder")
    files_db[folder_id][file_data.filename] = file_data.content
    return {"message": f"File uploaded to folder {folder_id}"}

@app.get("/files", summary="Get a file by name")
def get_file_by_name(name: str, username: str = Depends(verify_token)):
    """
    Получение файла по имени.
    """
    for folder_id, files in files_db.items():
        if name in files:
            return {name: files[name]}
    raise HTTPException(status_code=404, detail="File not found")

@app.delete("/files/{file_id}", summary="Delete a file by filename")
def delete_file(file_id: str, username: str = Depends(verify_token)):
    for folder_id, files in files_db.items():
        if file_id in files:
            del files[file_id]
            return {"message": f"File {file_id} deleted"}
    raise HTTPException(status_code=404, detail="File not found")

if __name__ == '__main__':
    run(app, host='0.0.0.0', port=8000)