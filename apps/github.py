
import sys
import os
import datetime
import logging
import json
from flask import Flask, Response, request, abort
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import jwt
import requests

user_agent = "petrographer v0.0"

app = Flask(__name__)
app.config.from_pyfile("config_github.ini")
app.logger.setLevel(logging.INFO)

__token = {"jwt": None,
           "exp": 0,
           "ins": {}}
__db = {"installations":{}}

def __authenticate():
    global __token
    now = datetime.datetime.now()
    if int(now.timestamp()) > __token["exp"]:
        expire = int((now + datetime.timedelta(minutes = 10)).timestamp())
        with open(os.path.abspath(app.config["KEYFILE"].replace("~", os.getenv("HOME"))), "rb") as keyfile:
            private_key = load_pem_private_key(keyfile.read(), None, default_backend())
        __token["jwt"] = jwt.encode({
            "iat": int(now.timestamp()),
            "exp": expire,
            "iss": app.config["APP_ID"]
            }, private_key, "RS256").decode("utf-8")
        __token["exp"] = expire
        response = requests.get("https://api.github.com/app", headers = {
            "Authorization": "Bearer " + __token["jwt"],
            "Accept": "application/vnd.github.machine-man-preview+json",
            "User-Agent": user_agent})
        if response.status_code != 200:
            app.logger.error(response.content.decode("utf-8"))
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    for ins in __token["ins"].keys():
        if __token["ins"][ins]["exp"] < now:
            print("authenticate installation", ins)
            response = requests.post("https://api.github.com/app/installations/" +
                                     ins +
                                     "/access_tokens",
                                     headers = {
                                         "Authorization": "Bearer " + __token["jwt"],
                                         "Accept": "application/vnd.github.machine-man-preview+json",
                                         "User-Agent": user_agent})
            print(response)
            print(response.content)
            if response.status_code == 201:
                content = json.loads(response.content.decode("utf-8"))
                __token["ins"][ins]["exp"] = content["expires_at"]
                __token["ins"][ins]["token"] = content["token"]
            else:
                app.logger.error(response.content.decode("utf-8"))

def __installation(content):
    global __db
    global __token
    if content["action"] == "created":
        app.logger.info("installing " + str(content["installation"]["id"]) + " from user " + content["installation"]["account"]["login"])
        __db["installations"] = {str(content["installation"]["id"]): content["installation"]}
        __token["ins"][str(content["installation"]["id"])] = {"exp": "0", "token": None}
    elif content["action"] == "deleted":
        app.logger.info("deleting " + str(content["installation"]["id"]) + " from user " + content["installation"]["account"]["login"])
        __db["installations"].pop(str(content["installation"]["id"]), None)
    else:
        return abort(400)
    dbf = os.path.abspath(app.config["DBFILE"].replace("~", os.getenv("HOME")))
    with open(dbf, "w+") as dbfile:
        json.dump(__db, dbfile)
    return Response("", 200)

@app.route("/")
def default():
    return abort(400)

@app.route("/", methods=["POST"])
def event():
    if "X-Github-Event" in request.headers:
        if not request.is_json:
            return abort(415)
        gh_event = request.headers["X-Github-Event"]
        if gh_event == "installation":
            return __installation(request.get_json())
        elif gh_event == "integration_installation":
            pass
        else:
            app.logger.warning("unknown event type: " + gh_event)
            print(request)
            print(request.headers)
            print(request.get_json())
        return Response("", 200)
    else:
        return abort(400)

@app.before_first_request
def load_db():
    global __db
    dbf = os.path.abspath(app.config["DBFILE"].replace("~", os.getenv("HOME")))
    if os.path.isfile(dbf):
        with open(dbf, "r") as dbfile:
            try:
                __db = json.load(dbfile)
            except json.decoder.JSONDecodeError:
                app.logger.error("Failed to read database: " + dbf + ", making backup and starting clean")
                os.rename(dbf, dbf + "_corrupted_" + datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
