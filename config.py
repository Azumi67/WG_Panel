import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

def _norm_sqlite(uri: str) -> str:
    if not uri or not uri.startswith("sqlite:///"):
        return uri
    path = uri[len("sqlite:///"):]
    if not os.path.isabs(path):
        if path.startswith("instance/"):
            path = os.path.join(INSTANCE_DIR, path.split("instance/", 1)[1])
        else:
            path = os.path.join(BASE_DIR, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return "sqlite:///" + path

class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me")
    SQLALCHEMY_DATABASE_URI = _norm_sqlite(
        os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(INSTANCE_DIR, 'wg_panel.db')}")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    WG_CONF_PATH = os.environ.get("WIREGUARD_CONF_PATH", "/etc/wireguard/")
    API_KEY = os.environ.get("API_KEY", "")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    SECURE_COOKIES = bool(int(os.environ.get("SECURE_COOKIES", "0")))
    SETUP_TOKEN = os.environ.get("SETUP_TOKEN", "")
    TG_HEARTBEAT_SEC = int(os.environ.get("TG_HEARTBEAT_SEC", "60"))
