from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import httpx
from github_client import get_installation_client
import os

app = FastAPI()

WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")


def verify_signature(body: bytes, signature: str):
    mac = hmac.new(
        WEBHOOK_SECRET.encode(),
        msg=body,
        digestmod=hashlib.sha256
    )
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post("/github/webhook")
async def github_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    if not signature or not verify_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()

    # Only handle new comments
    if payload.get("action") != "created":
        return {"ok": True}

    comment = payload["comment"]["body"]

    if "@cerberus suggest" not in comment.lower():
        return {"ok": True}

    # Prevent bot loop
    if payload["comment"]["user"]["type"] == "Bot":
        return {"ok": True}

    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    issue_number = payload["issue"]["number"]
    installation_id = payload["installation"]["id"]

    # Call localhost API
    async with httpx.AsyncClient() as client:
        r = await client.get("http://localhost:8000")
        message = r.json().get("message", "No response")

    # Post GitHub comment
    gh = get_installation_client(installation_id)
    gh.get_repo(f"{owner}/{repo}").get_issue(issue_number).create_comment(
        f"🛡️ **Cerberus says:** {message}"
    )

    return {"ok": True}
