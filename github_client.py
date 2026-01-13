from github import Github
from github.Auth import AppAuth
from dotenv import load_dotenv
import os

load_dotenv()

APP_ID = os.getenv("GITHUB_APP_ID")
PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH")


def get_installation_client(installation_id: int) -> Github:
    with open(PRIVATE_KEY_PATH, "r") as f:
        private_key = f.read()

    auth = AppAuth(APP_ID, private_key)
    return Github(auth=auth.get_installation_auth(installation_id))
