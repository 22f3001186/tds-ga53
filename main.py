from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import os
import re
import base64
from urllib.parse import urlparse

app = FastAPI()

HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET_FILE = "/home/agent/service-account.json"
WRITE_ROOT = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "pypi.org",
    "huggingface.co"
}


class GuardRequest(BaseModel):
    tool: str

    command: Optional[str] = None

    path: Optional[str] = None
    content: Optional[str] = None

    method: Optional[str] = None
    url: Optional[str] = None


def expand_path(path: str, base: str = WORKSPACE):
    path = path.replace("$HOME", HOME)
    path = path.replace("~", HOME)

    if os.path.isabs(path):
        return os.path.normpath(path)

    return os.path.normpath(os.path.join(base, path))


def inside(path: str, root: str):
    path = os.path.normpath(path)
    root = os.path.normpath(root)
    return path == root or path.startswith(root + os.sep)


def reads_secret(command: str):

    if not command:
        return False

    cmd = command.replace("$HOME", HOME)
    cmd = cmd.replace("~", HOME)

    # decode any base64 blobs
    for token in re.findall(r"[A-Za-z0-9+/=]{12,}", cmd):
        try:
            decoded = base64.b64decode(token).decode(errors="ignore")
            cmd += " " + decoded
        except Exception:
            pass

    read_cmds = [
        "cat",
        "less",
        "more",
        "head",
        "tail",
        "grep",
        "sed",
        "awk",
        "cp"
    ]

    if not any(cmd_name in cmd for cmd_name in read_cmds):
        return False

    if SECRET_FILE in cmd:
        return True

    if "$HOME/service-account.json" in command:
        return True

    if "~/service-account.json" in command:
        return True

    for token in re.findall(r"(/[^\s;|]+|\.\.?/[^\s;|]+)", cmd):
        resolved = expand_path(token)

        if resolved == SECRET_FILE:
            return True

    if "service-account.json" in cmd:
        return True

    return False


@app.post("/check")
async def check(body: GuardRequest):

    if body.tool == "bash":

        if reads_secret(body.command):
            return {
                "decision": "block",
                "reason": "Restricted file access."
            }

        return {
            "decision": "allow",
            "reason": "Command allowed."
        }

    if body.tool == "write_file":

        if body.path is None:
            return {
                "decision": "block",
                "reason": "Missing path."
            }

        resolved = expand_path(body.path, WRITE_ROOT)

        if inside(resolved, WRITE_ROOT):
            return {
                "decision": "allow",
                "reason": "Write permitted."
            }

        return {
            "decision": "block",
            "reason": "Write outside allowed directory."
        }

    if body.tool == "http_request":

        if body.url is None:
            return {
                "decision": "block",
                "reason": "Missing URL."
            }

        host = (urlparse(body.url).hostname or "").lower()

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
        "reason": "Tool allowed."
    }
