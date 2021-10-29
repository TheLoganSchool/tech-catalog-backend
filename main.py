import os
import io
import time
import traceback
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic.main import BaseModel
from deta import Deta
from discord import Webhook, RequestsWebhookAdapter
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import jwt
from PIL import Image


GOOGLE_CLIENT_ID = (
    "909450569518-a13qpdatseo5vodup53g2ll8ifa4pej9.apps.googleusercontent.com"
)

app = FastAPI()

webhook = Webhook.from_url(os.environ["WEBHOOK_URL"], adapter=RequestsWebhookAdapter())

deta = Deta(os.environ["DETA_PROJECT_KEY"])
items_db = deta.Base("items")
items_drive = deta.Drive("items")

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Login(BaseModel):
    g_csrf_token: str


@app.exception_handler(Exception)
def custom_http_exception_handler(request, exc):
    webhook.send(
        "```"
        + "".join(
            traceback.format_exception(
                etype=type(exc), value=exc, tb=exc.__traceback__, limit=-8
            )
        )
        + "```"
    )
    return PlainTextResponse("Internal Server Error :)", 500)


@app.get("/", response_class=HTMLResponse)
def root():
    return "<center><h1>🐰🥚 🔴🐟</h1></center>"


@app.post("/login")
def login_endpoint(login: Login):
    token = login.g_csrf_token
    if not token:
        raise HTTPException(400, "No CSRF token in post body.")

    try:
        id_info = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        name = id_info["name"]
        email = id_info["email"]
    except ValueError:
        raise HTTPException(400, "Invalid Google auth token.")

    encoded_session = jwt.encode(
        {
            "iss": "Logan Tech Catalog",
            "sub": name,
            "email": email,
            "iat": int(time.time()),
            "exp": int(time.time())
            + 60 * 60 * 24 * 365,  # expire in one year from issuing time
        },
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )

    return encoded_session


@app.post("/check_add_item_auth")
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


@app.post("/add_item")
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

    image = Image.open(image.file)

    image_byte_array = io.BytesIO()
    image.save(image_byte_array, format="png")

    key = items_db.put(item_dict)["key"]
    items_drive.put(key + ".png", image_byte_array.getvalue())

    return key


@app.get("/get_items")
def get_items_endpoint():
    return items_db.fetch(limit=10000).items


@app.get("/get_item")
def get_item_endpoint(item_key: str):
    result = items_db.get(item_key)
    if not result:
        raise HTTPException(400, "Item with key doesn't exist.")
    return result


@app.get("/get_item_image")
def get_item_image_endpoint(item_key: str):
    data = items_drive.get(f"{item_key}.png")
    return StreamingResponse(data.iter_chunks(), media_type="image/png")


@app.get("/error")
def error_endpoint():
    raise Exception
