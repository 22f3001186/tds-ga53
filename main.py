from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import os
import re
import base64
from urllib.parse import urlparse

app = FastAPI()

SECRET_FILE = "/home/agent/service-account.json"
HOME = "/home/agent"
WRITE_ROOT = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "pypi.org",
    "huggingface.co"
}


class GuardRequest(BaseModel):
    tool: str

    # For bash
    command: Optional[str] = None

    # For write_file
    path: Optional[str] = None
    content: Optional[str] = None

    # For http_request
    method: Optional[str] = None
    url: Optional[str] = None


def normalize(path: str):
    path = path.replace("$HOME", HOME)
    path = path.replace("~", HOME)
    return os.path.normpath(path)


def is_inside(path: str, root: str):
    full = os.path.normpath(path)
    root = os.path.normpath(root)
    return full == root or full.startswith(root + os.sep)


def check_bash(command: str):

    if command is None:
        return False

    cmd = command.replace("$HOME", HOME)
    cmd = cmd.replace("~", HOME)

    # Direct access
    if SECRET_FILE in cmd:
        return False

    # Any mention of the secret file
    if "service-account.json" in cmd:
        return False

    # Try decoding possible base64 strings
    tokens = re.findall(r"[A-Za-z0-9+/=]{8,}", command)

    for token in tokens:
        try:
            decoded = base64.b64decode(token).decode(errors="ignore")

            if SECRET_FILE in decoded:
                return False

            if "service-account.json" in decoded:
                return False

        except Exception:
            pass

    return True


@app.post("/check")
async def check(body: GuardRequest):

    if body.tool == "bash":

        if check_bash(body.command):
            return {
                "decision": "allow",
                "reason": "Safe command."
            }

        return {
            "decision": "block",
            "reason": "Restricted file access."
        }

    elif body.tool == "write_file":

        if body.path is None:
            return {
                "decision": "block",
                "reason": "Missing path."
            }

        path = normalize(body.path)

        if is_inside(path, WRITE_ROOT):
            return {
                "decision": "allow",
                "reason": "Write permitted."
            }

        return {
            "decision": "block",
            "reason": "Outside write directory."
        }

    elif body.tool == "http_request":

        if body.url is None:
            return {
                "decision": "block",
                "reason": "Missing URL."
            }

        host = urlparse(body.url).hostname or ""

        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Allowed host."
            }

        return {
            "decision": "block",
            "reason": "Host not allowed."
        }

    return {
        "decision": "allow",
        "reason": "Unknown tool."
    }
