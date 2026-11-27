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

def _database_uri():
    supplied = os.environ.get('DATABASE_URL', '').strip()
    if not supplied:
        raise RuntimeError('DATABASE_URL is required. Configure PostgreSQL for a new installation, or run sudo bash migrate.sh from the upgraded project to migrate existing SQLite data.')
    if supplied.startswith('postgres://'):
        supplied = 'postgresql://' + supplied[len('postgres://'):]
    if supplied.startswith('postgresql://'):
        supplied = 'postgresql+psycopg://' + supplied[len('postgresql://'):]
    if supplied.startswith('sqlite:///'):
        if os.environ.get('WG_ALLOW_SQLITE_LEGACY') != '1':
            raise RuntimeError('SQLite is a legacy backend. Set WG_ALLOW_SQLITE_LEGACY=1 for tests or rollback, or run sudo bash migrate.sh before starting the upgraded panel.')
        return _norm_sqlite(supplied)
    if not supplied.startswith('postgresql+psycopg://'):
        raise RuntimeError('DATABASE_URL must use postgresql+psycopg:// (or postgresql://).')
    return supplied


def _pg_role():
    role = os.environ.get('WG_DB_POOL_ROLE', 'web').strip().lower()
    return role if role in ('web','workspace','shop','combined','maintenance','provision','monitor') else 'web'


def _pg_pool_value(key, default):
    return int(os.environ.get(key+'_'+_pg_role().upper(), os.environ.get(key, str(default))))


class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me")
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "hide_parameters": True,
        "pool_pre_ping": True,
        "pool_size": _pg_pool_value("PG_POOL_SIZE", 5),
        "max_overflow": _pg_pool_value("PG_MAX_OVERFLOW", 5),
        "pool_timeout": _pg_pool_value("PG_POOL_TIMEOUT", 10),
        "pool_recycle": 1800,
        "connect_args": {"application_name": "wgpanel-"+_pg_role(), "options": "-c statement_timeout=30000 -c idle_in_transaction_session_timeout=60000"},
    } if SQLALCHEMY_DATABASE_URI.startswith("postgresql+") else {"hide_parameters": True}

    WG_CONF_PATH = os.environ.get("WIREGUARD_CONF_PATH", "/etc/wireguard/")
    API_KEY = os.environ.get("API_KEY", "")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    SECURE_COOKIES = bool(int(os.environ.get("SECURE_COOKIES", "0")))
    SETUP_TOKEN = os.environ.get("SETUP_TOKEN", "")
    TG_HEARTBEAT_SEC = int(os.environ.get("TG_HEARTBEAT_SEC", "60"))
