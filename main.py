import os
import time

from fastapi import FastAPI, Cookie, HTTPException, Request
from fastapi.responses import HTMLResponse
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


@app.get("/", response_class=HTMLResponse)
def root():
    return "<center><h1>🐰🥚 🔴🐟</h1></center>"


@app.options("/login")
def test(req: Request):
    print(req.body())
    return req.body()


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


@app.get("/get-items")
def get_items_endpoint():
    pass
