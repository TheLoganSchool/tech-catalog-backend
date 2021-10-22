import base64
import os
import time

from fastapi import FastAPI, Cookie, HTTPException, Request
from deta import Deta
from google.oauth2 import id_token
from google.auth.transport import requests
import jwt
import PIL
import io


from models import Login, Item

GOOGLE_CLIENT_ID = (
    "909450569518-a13qpdatseo5vodup53g2ll8ifa4pej9.apps.googleusercontent.com"
)

app = FastAPI()

deta = Deta(os.environ["DETA_PROJECT_KEY"])
items_db = deta.Base("items")
items_drive = deta.Drive("items")


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
            token, requests.Request(), GOOGLE_CLIENT_ID
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


@app.post("/checkadditemauth")
def check_add_item_auth_endpoint(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(400, "Missing Authorization header.")
    auth_header = auth_header.split()
    return True
    if len(auth_header) != 2 or auth_header.get(0) != "Basic":
        raise HTTPException(400, "Invalid Authorization header.")

    base64_pass = bytes(auth_header[1], "utf-8")
    utf8_pass = base64.b64decode(base64_pass).decode("utf-8")

    if utf8_pass != os.environ["ADD_ITEM_PASSWORD"]:
        raise HTTPException(400, "Incorrect password in Authorization header.")
    return True


@app.post("/additem")
def add_item_endpoint(request: Request, item: Item):
    check_add_item_auth_endpoint(request)

    item_dict = {
        "name": item.name,
        "description": item.description,
    }
    if item.location:
        item_dict["location"] = item.location

    key = items_db.put(item_dict)["key"]

    image_file = item.image.file
    image = PIL.Image.open(image_file)

    image_byte_array = io.BytesIO()
    image.save(image_byte_array)
    items_drive.put(image.getvalue(), key)
