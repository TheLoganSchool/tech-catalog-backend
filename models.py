from typing import Optional

from pydantic import BaseModel
from fastapi import UploadFile, File


class Login(BaseModel):
    g_csrf_token: str


class Item(BaseModel):
    name: str
    description: str
    image: UploadFile = File(...)
    location: Optional[str] = None
