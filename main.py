import os
import io
import time
from typing import Optional

from fastapi import FastAPI, Cookie, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from deta import Deta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import jwt
import PIL


from models import Login

GOOGLE_CLIENT_ID = (
    "909450569518-a13qpdatseo5vodup53g2ll8ifa4pej9.apps.googleusercontent.com"
)

app = FastAPI()


deta = Deta(os.environ["DETA_PROJECT_KEY"])
items_db = deta.Base("items")
items_drive = deta.Drive("items")

origins = [
    "localhost",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
def root():
    return "<center><h1>🐰🥚 🔴🐟</h1></center>"


@app.post("/login")
def login_endpoint(login: Login, g_csrf_token: str = Cookie(None)):
    token = login.g_csrf_token

    # Check for CSRF Attacks
    if not g_csrf_token:
        raise HTTPException(400, "No CSRF token in Cookie.")
    if not token:
        raise HTTPException(400, "No CSRF token in post body.")
    if g_csrf_token != token:
        raise HTTPException(400, "Failed to verify double submit cookie.")

    try:
        id_info = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        name = id_info["name"]
    except ValueError:
        raise HTTPException(400, "Invalid Google auth token.")

    encoded_session = jwt.encode(
        {
            "iss": "Logan Tech Catalog",
            "sub": name,
            "iat": int(time.time()),
            "exp": int(time.time())
            + 60 * 60 * 24 * 365,  # expire in one year from issuing time
        },
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )

    return encoded_session


@app.post("/check-add-item-auth")
def check_add_item_auth_endpoint(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(400, "Missing Authorization header.")

    auth_header = auth_header.split()

    if len(auth_header) != 2 or auth_header[0] != "Basic":
        raise HTTPException(400, "Invalid Authorization header.")

    if auth_header[1] != os.environ["ADD_ITEM_PASSWORD"]:
        raise HTTPException(400, "Incorrect password in Authorization header.")
    return True


@app.post("/add-item")
def add_item_endpoint(
    request: Request,
    name: str = Form(...),
    description: str = Form(...),
    image: UploadFile = File(...),
    location: Optional[str] = Form(None),
):
    check_add_item_auth_endpoint(request)

    item_dict = {
        "name": name,
        "description": description,
    }
    if location:
        item_dict["location"] = location

    key = items_db.put(item_dict)["key"]

    image = PIL.Image.open(image.file)

    image_byte_array = io.BytesIO()
    image.save(image_byte_array)

    items_drive.put(key, image_byte_array.getvalue())


@app.get("/get-items")
def get_items_endpoint():
    return items_db.fetch(limit=10000).items


@app.get("/error")
def error_endpoint():
    raise Exception
