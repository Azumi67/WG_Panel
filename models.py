from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import BigInteger, Column, Integer, String, Boolean, DateTime, Text
from passlib.context import CryptContext
pwd_ctx = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt_sha256", "bcrypt"],
    deprecated="auto"
)

db = SQLAlchemy()

class InterfaceConfig(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(64), unique=True, nullable=False)
    path        = db.Column(db.String(256), nullable=False)
    address     = db.Column(db.String(64), nullable=False)
    listen_port = db.Column(db.Integer, nullable=False)
    private_key = db.Column(db.String(256), nullable=False)
    mtu         = db.Column(db.Integer)
    dns         = db.Column(db.String(128))
    post_up     = db.Column(db.Text)
    post_down   = db.Column(db.Text)
    peers       = db.relationship('Peer', backref='iface', lazy=True)
    node_id = db.Column(db.Integer, db.ForeignKey('node.id'), nullable=True)
    node    = db.relationship('Node', backref='interfaces', lazy=True)

class Peer(db.Model):
    id                   = db.Column(db.Integer, primary_key=True)
    iface_id             = db.Column(db.Integer, db.ForeignKey('interface_config.id'), nullable=False)
    name                 = db.Column(db.String(64), nullable=False)
    public_key           = db.Column(db.String(128), nullable=False)
    private_key          = db.Column(db.String(128), nullable=False)
    address              = db.Column(db.String(64), nullable=False)
    allowed_ips          = db.Column(db.String(256))
    endpoint             = db.Column(db.String(128))
    persistent_keepalive = db.Column(db.Integer)
    mtu                  = db.Column(db.Integer)
    dns                  = db.Column(db.String(128))
    status               = db.Column(db.String(16), default='offline')

    data_limit_value     = db.Column(db.BigInteger)   
    data_limit_unit      = db.Column(db.String(2))    
    bytes_offset         = db.Column(db.BigInteger, default=0)  

    time_limit_days      = db.Column(db.Integer)      
    start_on_first_use   = db.Column(db.Boolean, default=False)
    first_used_at        = db.Column(db.DateTime)    
    expires_at           = db.Column(db.DateTime)    

    unlimited            = db.Column(db.Boolean, default=False)

    phone_number         = db.Column(db.String(32))
    telegram_id          = db.Column(db.String(64))

    events               = db.relationship('PeerEvent', backref='peer', lazy=True, cascade="all, delete-orphan")
    created_at           = db.Column(db.DateTime, server_default=db.func.now())
    used_bytes_total = db.Column(BigInteger, default=0)

    def limit_bytes(self):
        if not self.data_limit_value or self.unlimited:
            return None
        mult = 1024**2 if (self.data_limit_unit or 'Mi') == 'Mi' else 1024**3
        return int(self.data_limit_value) * mult

class PeerEvent(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    peer_id   = db.Column(db.Integer, db.ForeignKey('peer.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event     = db.Column(db.String(32), nullable=False)
    details   = db.Column(db.Text)

class Node(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(64), unique=True, nullable=False)
    base_url = db.Column(db.String(256), nullable=False) 
    api_key  = db.Column(db.String(128), nullable=False)  
    enabled  = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime)

class AdminLog(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    at              = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id        = db.Column(db.String(64))    
    admin_username  = db.Column(db.String(128))   
    ip              = db.Column(db.String(64))    
    action          = db.Column(db.String(64))    
    details         = db.Column(db.Text)          

class AdminAccount(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret   = db.Column(db.String(32))
    twofa_enabled = db.Column(db.Boolean, default=False)
    recovery_codes = db.Column(db.Text)

    @staticmethod
    def hash_pw(password: str) -> str:
        password = (password or "").strip()
        return pwd_ctx.hash(password)

    def verify_pw(self, password: str) -> bool:

        password = (password or "").strip()
        if not password:
            return False

        h = (self.password_hash or "").strip()
        if not h:
            return False

        if h.startswith("pbkdf2:") or h.startswith("scrypt:"):
            try:
                ok = bool(check_password_hash(h, password))
            except Exception:
                ok = False

            if ok:
                try:
                    self.password_hash = pwd_ctx.hash(password)
                    db.session.add(self)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                return True

            return False

        try:
            ok = bool(pwd_ctx.verify(password, h))
        except Exception:
            ok = False

        if ok:
            try:
                if pwd_ctx.needs_update(h):
                    self.password_hash = pwd_ctx.hash(password)
                    db.session.add(self)
                    db.session.commit()
            except Exception:
                db.session.rollback()

        return ok

    
class Admin2FA(db.Model):
    __tablename__ = 'admin_twofa'
    id = Column(Integer, primary_key=True)
    username = Column(String(190), unique=True, index=True, nullable=False)
    secret_enc = Column(Text, nullable=True)         
    enabled = Column(Boolean, default=False, nullable=False)
    recovery_hashes = Column(Text, nullable=True)     
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)