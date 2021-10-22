from pydantic import BaseModel


class Login(BaseModel):
    g_csrf_token: str
