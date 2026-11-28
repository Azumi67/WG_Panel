def build_routes(*,
    Admin,
    Admin2FA,
    AdminAccount,
    InvalidToken,
    _admin_security_budget,
    _gen_recovery,
    _http_security_record_login_failure,
    _is_https,
    _norm_adminlog,
    _request_client_ip,
    _safe_url,
    _send_security_notification,
    app,
    bind_session,
    consume_admin_factor,
    current_app,
    current_user,
    db,
    fernet,
    flash,
    hash_recovery,
    json,
    jsonify,
    login_required,
    login_user,
    logout_user,
    match_secret,
    os,
    pyotp,
    redirect,
    render_template,
    request,
    secrets,
    session,
    session_valid,
    time,
    url_for,
    verify_recovery,
):

    def login():
        from models import AdminAccount

        if not AdminAccount.query.first():
            return redirect(
                url_for('register')
            )

        if request.method == 'POST':
            username = (
                request.form.get('username')
                or ''
            ).strip()

            password = (
                request.form.get('password')
                or ''
            ).strip()

            otp = (
                request.form.get('twofa_code')
                or request.form.get(
                    'otp_or_recovery'
                )
                or ''
            ).strip().replace(' ', '')

            from reseller_portal.request_guard import reserve
            from hashlib import sha256
            db.session.rollback()
            if not reserve([('admin-login-ip:'+sha256((request.remote_addr or '?').encode()).hexdigest(), 25, 900)]):
                flash('Too many sign-in attempts. Try again in 15 minutes.', 'error')
                return render_template('login.html'), 429, {'Retry-After':'900'}
            if len(username)>64 or len(password)>1024 or len(otp)>64:
                flash('Invalid credentials or access unavailable.', 'error')
                return render_template('login.html')
            account = (
                AdminAccount.query
                .filter_by(
                    username=username
                )
                .first()
            )

            if (
                not account
                or not account.verify_pw(
                    password
                )
            ):
                _send_security_notification(
                    'login_failed',
                    username=(
                        username
                        or 'unknown'
                    ),
                    reason=(
                        'Invalid username or password'
                    ),
                )
                _http_security_record_login_failure(
                    username=(username or 'unknown'),
                    failure_type='credentials',
                )

                try:
                    client_ip, _ = (
                        _request_client_ip()
                    )

                    _norm_adminlog({
                        'action': 'login_failed',
                        'admin_username': (
                            username
                            or ''
                        ),
                        'details': (
                            f'ip={client_ip}; '
                            'reason=invalid_credentials'
                        ),
                        'result': 'denied',
                        'channel': 'web',
                    })
                except Exception:
                    pass

                flash(
                    'Invalid username or password',
                    'error',
                )

                return render_template(
                    'login.html'
                )

            account_id, password_hash = account.id, account.password_hash
            db.session.rollback()
            account = db.session.get(AdminAccount, account_id, with_for_update=True, populate_existing=True)
            if not account or account.username != username or account.password_hash != password_hash:
                db.session.rollback()
                flash('Invalid credentials or access unavailable.', 'error')
                return render_template('login.html')
            if account.twofa_enabled:
                verified = consume_admin_factor(account, otp, verify_recovery)
                if not verified:
                    db.session.rollback()
                    _send_security_notification(
                        'twofa_failed',
                        username=account.username,
                        reason=(
                            'Invalid TOTP or recovery code'
                        ),
                    )
                    _http_security_record_login_failure(
                        username=account.username,
                        failure_type='twofa',
                    )

                    try:
                        client_ip, _ = (
                            _request_client_ip()
                        )

                        _norm_adminlog({
                            'action': 'twofa_failed',
                            'admin_username': (
                                account.username
                            ),
                            'details': (
                                f'ip={client_ip}; '
                                'reason=invalid_twofa'
                            ),
                            'result': 'denied',
                            'channel': 'web',
                        })
                    except Exception:
                        pass

                    flash(
                        (
                            'Enter your 6-digit code '
                            'or a valid recovery code'
                        ),
                        'error',
                    )

                    return render_template(
                        'login.html'
                    )

            
            binding = {}
            bind_session(binding, account, app.secret_key)
            admin_username = account.username
            twofa_enabled = bool(account.twofa_enabled)
            db.session.commit()
            session.clear()
            session.update(binding)
            login_user(Admin(admin_username))

            _send_security_notification(
                'login_success',
                username=admin_username,
                reason=(
                    (
                        'Password and two-factor '
                        'checks passed'
                    )
                    if twofa_enabled
                    else 'Password accepted'
                ),
            )

            try:
                client_ip, _ = (
                    _request_client_ip()
                )

                _norm_adminlog({
                    'action': 'login_success',
                    'admin_username': admin_username,
                    'details': (
                        f'ip={client_ip}; '
                        f'scheme='
                        f'{"https" if _is_https() else "http"}'
                    ),
                    'result': 'ok',
                    'channel': 'web',
                })
            except Exception:
                pass

            next_url = (
                request.form.get('next')
                or request.args.get('next')
            )

            if (
                next_url
                and _safe_url(next_url)
            ):
                return redirect(
                    next_url
                )

            return redirect(
                url_for('index')
            )

        return render_template(
            'login.html'
        )

    def register_twofa_begin():
        from models import AdminAccount
        if AdminAccount.query.first():
            return jsonify({"error": "Registration closed"}), 403

        payload = request.get_json(silent=True) or {}
        account = (payload.get("username") or "admin").strip() or "admin"
        issuer  = "WG Panel"

        secret = pyotp.random_base32()
        session["reg_totp_secret"] = fernet.encrypt(secret.encode()).decode()
        session["reg_totp_until"] = int(time.time())+900
        session["reg_totp_confirmed"] = False
        session.pop("reg_recovery_codes_h", None)

        otp_uri = pyotp.TOTP(secret).provisioning_uri(name=f"{issuer}:{account}", issuer_name=issuer)
        session.modified = True
        return jsonify({"otp_uri": otp_uri, "secret": secret, "issuer": issuer, "account": account})

    def register_twofa_confirm():
        from models import AdminAccount
        if AdminAccount.query.first():
            return jsonify({"error": "Registration closed"}), 403

        data   = request.get_json(silent=True) or {}
        code   = (data.get("code") or "").strip()
        pending = session.get("reg_totp_secret")
        if not pending or session.get('reg_totp_until',0)<=time.time():
            return jsonify({"error": "Start 2FA first"}), 400
        try:secret=fernet.decrypt(pending.encode()).decode()
        except (InvalidToken, ValueError):return jsonify(error='Start 2FA first'),400
        from types import SimpleNamespace
        factor=SimpleNamespace(twofa_enabled=True,totp_secret=secret,last_totp_counter=0,recovery_codes='')
        if not consume_admin_factor(factor,code,verify_recovery):
            return jsonify({"error": "Invalid code"}), 400
        session['reg_totp_counter']=factor.last_totp_counter

        rec_plain = _gen_recovery()
        rec_h     = [hash_recovery(c) for c in rec_plain]

        session["reg_totp_confirmed"]   = True
        session["reg_recovery_codes_h"] = rec_h
        session.modified = True
        return jsonify({"recovery_codes": rec_plain})

    def register():
        from models import AdminAccount

        if AdminAccount.query.first():
            return redirect(url_for('login'))

        setup_token   = (current_app.config.get('SETUP_TOKEN') or os.getenv('SETUP_TOKEN', '')).strip()
        require_token = bool(setup_token)

        if request.method == 'POST':
            u   = (request.form.get('username') or '').strip()
            p1  = request.form.get('password') or ''
            p2  = request.form.get('password2') or ''
            tok = (request.form.get('setup_token') or '').strip()

            if require_token and not match_secret(tok, setup_token):
                flash('Invalid registration token.', 'error')
                return render_template('register.html', require_token=True)

            if not u:
                flash('Username is required.', 'error')
                return render_template('register.html', require_token=require_token)
            if p1 != p2:
                flash('Passwords do not match.', 'error')
                return render_template('register.html', require_token=require_token)
            if not 12 <= len(p1.strip()) <= 1024 or len(u)>64:
                flash('Use a username of at most 64 characters and a password of 12 to 1024 characters.', 'error')
                return render_template('register.html', require_token=require_token)
            if AdminAccount.query.filter_by(username=u).first():
                flash('That username is already taken.', 'error')
                return render_template('register.html', require_token=require_token)

            try:
                pw_hash = AdminAccount.hash_pw(p1)
                acc = AdminAccount(username=u, password_hash=pw_hash)
                if session.get('reg_totp_confirmed'):
                    if not session.get('reg_totp_secret') or session.get('reg_totp_until',0)<=time.time():
                        flash('2FA setup expired. Start again.', 'error')
                        return render_template('register.html',require_token=require_token)
                    try:acc.totp_secret=fernet.decrypt(session['reg_totp_secret'].encode()).decode()
                    except (InvalidToken,ValueError):
                        flash('2FA setup expired. Start again.', 'error')
                        return render_template('register.html',require_token=require_token)
                    acc.twofa_enabled=True
                    acc.last_totp_counter=int(session.get('reg_totp_counter',0))
                    acc.recovery_codes='\n'.join(session.get('reg_recovery_codes_h') or [])
                
                from reseller_portal.database import schema_lock
                db.session.rollback()
                with schema_lock(db.engine):
                    if AdminAccount.query.first():
                        db.session.rollback()
                        return redirect(url_for('login'))
                    db.session.add(acc)
                    db.session.commit()

            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("register() failed at commit")
                current_app.logger.error("u=%r totp_confirmed=%r has_rc=%r",
                                         u, bool(session.get('reg_totp_confirmed')),
                                         bool(session.get('reg_recovery_codes_h')))
                flash("Internal error while creating the admin. See app.log.", "error")
                return render_template('register.html', require_token=require_token), 500

            for k in ('reg_totp_secret', 'reg_totp_confirmed', 'reg_recovery_codes_h','reg_totp_until','reg_totp_counter'):
                session.pop(k, None)

            flash('Admin created. Please log in.' if len(p1) >= 12
                  else 'Admin created. Tip: use 12+ characters for better security.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html', require_token=require_token)

    @login_required
    def admin_status():
        from models import AdminAccount
        acc = AdminAccount.query.first()
        if not acc:
            return jsonify(error="no_admin"), 404
        rc = 0
        if (acc.recovery_codes or '').strip():
            rc = len([x for x in acc.recovery_codes.splitlines() if x.strip()])
        return jsonify({
            "username": acc.username,
            "twofa_enabled": bool(acc.twofa_enabled),
            "recovery_count": rc,
        }), 200

    @login_required
    def admin_change_password():
        if not _admin_security_budget():return jsonify(error='Too many security requests. Try again in 15 minutes.'),429,{'Retry-After':'900'}
        data = request.get_json(silent=True)
        if not isinstance(data,dict):return jsonify(error="Expected a JSON object."),400
        cur = data.get('current')
        new = data.get('new')
        if not isinstance(new,str) or not 12 <= len(new.strip()) <= 1024:
            return jsonify(error="Use a password of 12 to 1024 characters."), 400
        acc = AdminAccount.query.first()
        if not acc or not isinstance(cur,str) or len(cur)>1024 or not acc.verify_pw(cur):
            return jsonify(error="bad_current"), 400
        aid, old_hash = acc.id, acc.password_hash
        db.session.rollback()
        new_hash = AdminAccount.hash_pw(new)
        acc = db.session.get(AdminAccount,aid,with_for_update=True,populate_existing=True)
        if not acc or acc.password_hash!=old_hash or not session_valid(session,acc,app.secret_key):
            db.session.rollback()
            return jsonify(error='Account security changed. Sign in again.'),403
        acc.password_hash = new_hash
        acc.session_revision = int(acc.session_revision or 0)+1
        binding = {}
        bind_session(binding, acc, app.secret_key)
        db.session.commit()
        session['admin_binding'] = binding['admin_binding']
        return jsonify(ok=True)

    @login_required
    def admin_rename():
        data = request.get_json(silent=True)
        if not isinstance(data,dict):return jsonify(error="Expected a JSON object."),400
        raw = data.get('username')
        newu = raw.strip() if isinstance(raw,str) else ''
        if not newu:
            return jsonify(error="empty_username"), 400

        if AdminAccount.query.filter_by(username=newu).first():
            return jsonify(error="taken"), 400
        acc = AdminAccount.query.with_for_update().populate_existing().first()
        if not acc or not session_valid(session,acc,app.secret_key):
            db.session.rollback()
            return jsonify(error='Account security changed. Sign in again.'),403
        if len(newu)>64:
            return jsonify(error="Username is too long."), 400
        rec=Admin2FA.query.filter_by(username=acc.username).first()
        if rec:rec.username=newu
        acc.username = newu
        acc.session_revision = int(acc.session_revision or 0)+1
        binding = {}
        bind_session(binding, acc, app.secret_key)
        db.session.commit()
        session['admin_binding'] = binding['admin_binding']
        return jsonify(ok=True)

    @login_required
    def twofa_begin():
        if not _admin_security_budget():return jsonify(error='Too many security requests. Try again in 15 minutes.'),429,{'Retry-After':'900'}
        username = getattr(current_user, 'username', 'admin')
        data = request.get_json(silent=True)
        if not isinstance(data,dict):return jsonify(error="Expected a JSON object."),400
        acc = AdminAccount.query.filter_by(username=username).first()
        password = data.get('password')
        if not acc or acc.twofa_enabled or not isinstance(password,str) or len(password)>1024 or not acc.verify_pw(password):
            return jsonify(error='Current password required; disable existing 2FA first.'), 403
        secret = pyotp.random_base32()
        session['twofa_pending_secret'] = fernet.encrypt(secret.encode()).decode()
        session['twofa_pending_until'] = int(time.time()) + 300
        session.modified = True
        label = f"WG-Panel:{username}"
        issuer = "WG-Panel"
        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)
        return jsonify(secret=secret, otp_uri=otp_uri), 200

    @login_required
    def twofa_confirm():
        if not _admin_security_budget():return jsonify(error='Too many security requests. Try again in 15 minutes.'),429,{'Retry-After':'900'}
        data = request.get_json(silent=True)
        if not isinstance(data,dict):return jsonify(error="Expected a JSON object."),400
        otp = data.get('otp','')
        pending = session.get('twofa_pending_secret')
        if not pending or session.get('twofa_pending_until',0) <= time.time():
            return jsonify(error='Start 2FA setup again.'), 400
        try:
            secret = fernet.decrypt(pending.encode()).decode()
        except (InvalidToken, ValueError):
            return jsonify(error='Start 2FA setup again.'), 400
        acc = AdminAccount.query.filter_by(username=current_user.username).with_for_update().populate_existing().first()
        if not acc or acc.twofa_enabled or not session_valid(session,acc,app.secret_key):
            db.session.rollback()
            return jsonify(error='Account security changed. Sign in again.'),403
        acc.twofa_enabled = True
        acc.totp_secret = secret
        acc.last_totp_counter = 0
        acc.recovery_codes = ''
        if not consume_admin_factor(acc,otp,verify_recovery):
            db.session.rollback()
            return jsonify(error='Incorrect or expired code.'),400
        recovery_plain = [f"{secrets.token_hex(8)}-{secrets.token_hex(8)}" for _ in range(10)]
        hashes = [hash_recovery(c) for c in recovery_plain]
        acc.recovery_codes = '\n'.join(hashes)
        acc.session_revision = int(acc.session_revision or 0)+1
        rec = Admin2FA.query.filter_by(username=acc.username).first()
        if not rec:
            rec=Admin2FA(username=acc.username);db.session.add(rec)
        rec.secret_enc=fernet.encrypt(secret.encode()).decode()
        rec.recovery_hashes=json.dumps(hashes);rec.enabled=True
        binding={};bind_session(binding,acc,app.secret_key)
        db.session.commit()
        session['admin_binding']=binding['admin_binding']
        session.pop('twofa_pending_secret',None);session.pop('twofa_pending_until',None)
        return jsonify(ok=True,recovery_codes=recovery_plain)

    @login_required
    def twofa_disable():
        if not _admin_security_budget():return jsonify(error='Too many security requests. Try again in 15 minutes.'),429,{'Retry-After':'900'}
        data=request.get_json(silent=True)
        if not isinstance(data,dict):return jsonify(error="Expected a JSON object."),400
        password=data.get('password')
        acc=AdminAccount.query.filter_by(username=current_user.username).first()
        if not acc or not isinstance(password,str) or len(password)>1024 or not acc.verify_pw(password):
            return jsonify(error='Current password required.'),403
        aid,old_hash=acc.id,acc.password_hash
        db.session.rollback()
        acc=db.session.get(AdminAccount,aid,with_for_update=True,populate_existing=True)
        if (not acc or acc.password_hash!=old_hash or not session_valid(session,acc,app.secret_key)
                or not acc.twofa_enabled or not consume_admin_factor(acc,data.get('otp',''),verify_recovery)):
            db.session.rollback()
            return jsonify(error='Current authenticator or recovery code required.'),403
        rec=Admin2FA.query.filter_by(username=acc.username).first()
        if rec:
            rec.enabled=False;rec.secret_enc=None;rec.recovery_hashes='[]'
        acc.twofa_enabled=False;acc.totp_secret=None;acc.recovery_codes='';acc.last_totp_counter=0
        acc.session_revision = int(acc.session_revision or 0)+1
        binding={};bind_session(binding,acc,app.secret_key)
        db.session.commit()
        session['admin_binding']=binding['admin_binding']
        session.pop('twofa_pending_secret',None);session.pop('twofa_pending_until',None)
        return jsonify(ok=True)

    @login_required
    def logout():
        logout_user(); session.clear(); return redirect(url_for('login'))

    return {
        'login': login,
        'register_twofa_begin': register_twofa_begin,
        'register_twofa_confirm': register_twofa_confirm,
        'register': register,
        'admin_status': admin_status,
        'admin_change_password': admin_change_password,
        'admin_rename': admin_rename,
        'twofa_begin': twofa_begin,
        'twofa_confirm': twofa_confirm,
        'twofa_disable': twofa_disable,
        'logout': logout,
    }
