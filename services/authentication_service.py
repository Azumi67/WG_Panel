def bind_authentication(*,
    Admin2FA,
    InvalidToken,
    UserMixin,
    app,
    bcrypt,
    db,
    fernet,
    json,
    login_manager,
    request,
    session,
    session_valid,
):

    def _create_twofa(username: str) -> Admin2FA:
        rec = Admin2FA.query.filter_by(username=username).first()
        if not rec:
            rec = Admin2FA(username=username, enabled=False)
            db.session.add(rec)
            db.session.commit()
        return rec

    def _set_secret(rec, secret_b32: str):
        rec.secret_enc = fernet.encrypt(secret_b32.encode()).decode()
        db.session.commit()

    def _get_secret(rec) -> str | None:
        if not rec.secret_enc:
            return None
        try:
            return fernet.decrypt(rec.secret_enc.encode()).decode()
        except InvalidToken:
            return None

    def _hash_codes(codes: list[str]) -> str:
        hashes = [bcrypt.hashpw(c.encode(), bcrypt.gensalt()).decode() for c in codes]
        return json.dumps(hashes)

    def _recovery(rec: Admin2FA, code: str) -> bool:
        arr = json.loads(rec.recovery_hashes or "[]")
        for i, h in enumerate(arr):
            if bcrypt.checkpw(code.encode(), h.encode()):
                arr.pop(i)
                rec.recovery_hashes = json.dumps(arr)
                db.session.commit()
                return True
        return False

    class Admin(UserMixin):
        def __init__(self, username='admin'):
            self.id = '1'
            self.username = username
            self.is_admin = True
            self.is_superuser = True

    @login_manager.user_loader
    def load_user(user_id):
        if user_id != '1':
            return None
        from models import AdminAccount
        acc = AdminAccount.query.first()
        if not acc:
            return None
        if not session_valid(session, acc, app.secret_key):
            return None
        return Admin(acc.username)

    def _admin_security_budget():
        from reseller_portal.request_guard import reserve
        from hashlib import sha256
        identity=sha256((request.remote_addr or '?').encode()).hexdigest()
        return reserve([('admin-security-ip:'+identity,25,900)])

    return {
        '_create_twofa': _create_twofa,
        '_set_secret': _set_secret,
        '_get_secret': _get_secret,
        '_hash_codes': _hash_codes,
        '_recovery': _recovery,
        'Admin': Admin,
        'load_user': load_user,
        '_admin_security_budget': _admin_security_budget,
    }
