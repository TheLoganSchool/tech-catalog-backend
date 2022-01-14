import io
import os
import smtplib
import ssl
from pymongo import MongoClient
import time
from typing import Optional
import asyncio

import boto3
import jwt
import sentry_sdk
from deta import Deta
from discord import RequestsWebhookAdapter, Webhook
from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from PIL import Image
from pydantic.main import BaseModel
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware

GOOGLE_CLIENT_ID = (
    "909450569518-a13qpdatseo5vodup53g2ll8ifa4pej9.apps.googleusercontent.com"
)

UPLOADED_IMAGE_SIZE = 720

app = FastAPI()

sentry_sdk.init(
    dsn="https://bc4e7e5cd13b463cb6a4e3a9a7073e84@o1079805.ingest.sentry.io/6084956",
    traces_sample_rate=1.0,
)
app.add_middleware(SentryAsgiMiddleware)

webhook = Webhook.from_url(os.environ["WEBHOOK_URL"], adapter=RequestsWebhookAdapter())

"""
deta = Deta(os.environ["DETA_PROJECT_KEY"])

items_db = deta.Base("items")
used_sessions_db = deta.Base("used_sessions")
events_db = deta.Base("events")
"""

mongo_client = MongoClient(
    f"mongodb+srv://{os.environ['MONGO_USER']}:{os.environ['MONGO_PASSWORD']}@cluster0.8mtwa.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
)
mongo_db = mongo_client.catalog

items_col = mongo_db.items
used_sessions_col = mongo_db.used_sessions
events_col = mongo_db.events

s3 = boto3.client(
    "s3",
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
)


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
    name: str = Form(...),
    description: str = Form(...),
    quantity: str = Form(...),
    categories: str = Form("all"),
    image: UploadFile = File(...),
    rotation: int = 0,
    checkoutable: bool = True,
    location: Optional[str] = Form(None),
):
    # check_add_item_auth_endpoint(request)

    item_dict = {
        "name": name,
        "description": description,
        "quantity": quantity,
        "categories": categories,
        "rotation": rotation,
        "checkoutable": checkoutable,
    }
    if location:
        item_dict["location"] = location

    image = Image.open(image.file)

    image.thumbnail((UPLOADED_IMAGE_SIZE, UPLOADED_IMAGE_SIZE))

    image_byte_array = io.BytesIO()
    image.save(image_byte_array, format="png", optimize=True, quality=50)

    key = items_col.insert_one(item_dict)["_id"]

    s3.put_object(
        Body=image_byte_array.getvalue(),
        Bucket="tech-catalog-images",
        Key=key + ".png",
        ACL="public-read",
    )

    return key


class Item(BaseModel):
    key: str
    name: str
    description: str
    quantity: str
    rotation: int = 0
    categories: str
    checkoutable: bool = True


@app.post("/update_item")
def update_item(item: Item):
    items_col.update_one(
        item.key,
        {
            "name": item.name,
            "description": item.description,
            "quantity": item.quantity,
            "categories": item.categories,
            "rotation": item.rotation,
            "checkoutable": item.checkoutable,
        },
    )

    return True


@app.post("/delete_item")
def delete_item(key: str):
    items_col.delete_one(key)

    return True


@app.get("/get_items")
def get_items_endpoint():
    items = list(items_col.find({}))
    for index, item in enumerate(items):
        items[index]["_id"] = str(item["_id"])
    return sorted(list(items_col.find({})), key=lambda a: a["name"])


@app.get("/get_item")
def get_item_endpoint(item_key: str):
    result = items_col.find_one(item_key)
    if not result:
        raise HTTPException(400, "Item with key doesn't exist.")
    return result


@app.get("/error")
def error_endpoint():
    raise Exception()


# Not mongo ported
@app.post("/easter_egg_trigger")
def easter_egg_trigger_endpoint(encoded_session: str):
    decoded = jwt.decode(
        encoded_session, os.environ["JWT_SECRET"], algorithms=["HS256"]
    )
    for used_session in used_sessions_col.fetch().items:
        if used_session["value"] == encoded_session:
            raise HTTPException(
                400, "Easter egg has been triggered on session previously."
            )

    used_sessions_col.insert_one(encoded_session)

    try:
        email = decoded["email"]
        name = decoded["sub"].split()[0]
    except KeyError:
        raise HTTPException(400, "Session doesn't include email or sub.")
    webhook.send(
        "<@375419186798657536><@555709231697756160>"
        + f" {name} <{email}> has triggered the easter egg"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", context=ssl_context) as server:
        server.login(os.environ["EMAIL"], os.environ["EMAIL_PASSWORD"])

        message = (
            f"Subject: Tech Catalog Easter Egg Triggered\n\n{name} <{email}> has triggered the easter egg. Please "
            f"place a candy bag for them in the tech office door. When done please click the link "
            f"below:\n\nhttps://tech-catalog-backend.herokuapp.com/placed_easter_egg?name={name}&email={email}"
        )

        server.sendmail(os.environ["EMAIL"], os.environ["EASTER_EGG_EMAIL"], message)

    return True


@app.get("/placed_easter_egg")
def placed_easter_egg_endpoint(name: str, email: str):
    webhook.send(
        "<@375419186798657536><@555709231697756160>"
        + f"The easter egg for {name} <{email}> is ready for pickup."
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", context=ssl_context) as server:
        server.login(os.environ["EMAIL"], os.environ["EMAIL_PASSWORD"])

        message = "Subject: Tech Catalog Easter Egg Ready\n\nYour catalog easter egg is ready for pickup. Please take the bag with your name on it off of the tech office door. Congrats!"

        server.sendmail(os.environ["EMAIL"], email, message)

        return "Success!"
