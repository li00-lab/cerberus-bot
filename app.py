from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import httpx
from github_client import get_installation_client
import os
from dotenv import load_dotenv

# 🔹 Load environment variables (.env)
load_dotenv()

app = FastAPI()

WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

if not WEBHOOK_SECRET:
    raise RuntimeError("GITHUB_WEBHOOK_SECRET is not set")


# 🔹 Commands this bot responds to
COMMAND_TRIGGERS = [
    "@cerberus suggest",          # friendly alias
    "@cerberus-gh-app suggest",   # real GitHub App mention
]


def verify_signature(body: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature (sha256)"""
    if not signature.startswith("sha256="):
        return False

    mac = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        msg=body,
        digestmod=hashlib.sha256,
    )
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post("/github/webhook")
async def github_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    # 🔹 Verify webhook signature
    if not signature or not verify_signature(body, signature):
        print("❌ Invalid webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()

    print("✅ Webhook received")
    print("Action:", payload.get("action"))

    # 🔹 Only handle newly created comments
    if payload.get("action") != "created":
        return {"ok": True}

    # 🔹 Only handle PR / issue timeline comments
    if "comment" not in payload or "issue" not in payload:
        print("ℹ️ Not an issue/PR timeline comment")
        return {"ok": True}

    comment_body = payload["comment"]["body"].lower()
    print("Comment body:", comment_body)

    # 🔹 Check for command trigger
    if not any(cmd in comment_body for cmd in COMMAND_TRIGGERS):
        return {"ok": True}

    # 🔹 Prevent bot replying to itself
    if payload["comment"]["user"]["type"] == "Bot":
        return {"ok": True}

    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    issue_number = payload["issue"]["number"]
    installation_id = payload["installation"]["id"]

    print(f"🔧 Handling command for {owner}/{repo}#{issue_number}")

    # 🔹 Call local API (stubbed for now)
    # async with httpx.AsyncClient(timeout=10) as client:
    #     r = await client.get("http://localhost:8000")
    #     message = r.json().get("message", "No response")

    message = "success"

    # 🔹 Post GitHub comment as the App
    gh = get_installation_client(installation_id)
    gh.get_repo(f"{owner}/{repo}") \
        .get_issue(issue_number) \
        .create_comment(f"🛡️ **Cerberus says:** {message}")

    print("✅ Comment posted successfully")

    return {"ok": True}
