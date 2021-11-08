import io
import os
import time
import traceback
from typing import Optional
import smtplib
import ssl

import jwt
from deta import Deta
from discord import RequestsWebhookAdapter, Webhook
from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from PIL import Image
from pydantic.main import BaseModel

GOOGLE_CLIENT_ID = (
    "909450569518-a13qpdatseo5vodup53g2ll8ifa4pej9.apps.googleusercontent.com"
)

app = FastAPI()

webhook = Webhook.from_url(os.environ["WEBHOOK_URL"], adapter=RequestsWebhookAdapter())

deta = Deta(os.environ["DETA_PROJECT_KEY"])
items_db = deta.Base("items")
items_drive = deta.Drive("items")

used_sessions_db = deta.Base("used_sessions")

ssl_context = ssl.create_default_context()

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


def write_image(name: str, data: bytes):
    items_drive.put(name, data)


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
            + 60 * 60 * 24 * 7,  # expire in one week from issuing time
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
    background_tasks: BackgroundTasks,
    name: str = Form(...),
    description: str = Form(...),
    quantity: str = Form(...),
    image: UploadFile = File(...),
    location: Optional[str] = Form(None),
):
    check_add_item_auth_endpoint(request)

    item_dict = {"name": name, "description": description, "quantity": quantity}
    if location:
        item_dict["location"] = location

    image = Image.open(image.file)

    image_byte_array = io.BytesIO()
    image.save(image_byte_array, format="png")

    key = items_db.put(item_dict)["key"]
    background_tasks.add_task(write_image, key + ".png", image_byte_array.getvalue())

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


@app.post("/easter_egg_trigger")
def easter_egg_trigger_endpoint(encoded_session: str):
    decoded = jwt.decode(
        encoded_session, os.environ["JWT_SECRET"], algorithms=["HS256"]
    )
    for used_session in used_sessions_db.fetch().items:
        if used_session["value"] == encoded_session:
            raise HTTPException(
                400, "Easter egg has been triggered on session previously."
            )

    used_sessions_db.put(encoded_session)

    try:
        email = decoded["email"]
        name = decoded["sub"]
    except KeyError:
        raise HTTPException(400, "Session doesn't include email or sub.")
    webhook.send(
        "<@375419186798657536><@555709231697756160>"
        + f" {name} <{email}> has triggered the easter egg"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", context=ssl_context) as server:
        server.login(os.environ["EMAIL"], os.environ["EMAIL_PASSWORD"])

        message = (
            f"""\
        Subject: Tech Catalog Easter Egg Trigger

        {name} <{email}> has triggered the easter egg. """
            + "Please place a candy bag for them in the tech office door. "
            + "When done please click the link below: "
        )

        server.sendmail(os.environ["EMAIL"], os.environ["EASTER_EGG_EMAIL"], message)

    return True


@app.get("/easter_egg")
def easter_egg_endpoint():
    pass
