def bind_effective_dns(_panel_context):
    def _effective_dns(peer):
        return (peer.dns or getattr(peer.iface, 'dns', None) or _panel_context._panel_default_dns())

    return {
        '_effective_dns': _effective_dns,
    }


def bind_application_log_paths(_panel_context):
    def _application_log_paths():
        return [('panel', _panel_context.Path(_panel_context.APP_LOG_FILE))] + [(role, _panel_context.Path(_panel_context.app.instance_path)/('worker-'+role+'.log')) for role in _panel_context._WORKER_LOG_ROLES]


    def _utc_log_formatter(pattern: str) -> _panel_context.logging.Formatter:
        formatter = _panel_context.logging.Formatter(
            pattern,
            datefmt='%Y-%m-%dT%H:%M:%SZ',
        )
        formatter.converter = _panel_context.time.gmtime
        return formatter

    return {
        '_application_log_paths': _application_log_paths,
        '_utc_log_formatter': _utc_log_formatter,
    }


def bind_unhandled(_panel_context):
    @_panel_context.app.errorhandler(Exception)
    def _unhandled(e):
        if isinstance(e, _panel_context.HTTPException):
            return e
        if isinstance(e, _panel_context.OperationalError) and __import__('reseller_portal.database', fromlist=['writer_busy']).writer_busy(e):
            _panel_context.db.session.rollback()
            _panel_context.app.logger.warning('Database busy at %s',_panel_context.request.endpoint)
            return _panel_context.jsonify(error='Database temporarily unavailable. Your changes were not confirmed.'),503,{'Retry-After':'5'}
        _panel_context.app.logger.exception("Unhandled exception")
        return "Internal Server Error", 500

    return {
        '_unhandled': _unhandled,
    }


def bind_csrf_protect_ui(_panel_context):
    @_panel_context.app.before_request
    def _csrf_protect_ui():
        if _panel_context.csrf_required(_panel_context.request.method, _panel_context.request.path, _panel_context.session.get('_user_id'), _panel_context.request.blueprint):
            _panel_context.csrf.protect()

    return {
        '_csrf_protect_ui': _csrf_protect_ui,
    }


def bind_inject_nav_flags(_panel_context):
    @_panel_context.app.context_processor
    def inject_nav_flags():
        v = set(_panel_context.current_app.view_functions.keys())
        return {'HAS_NODES': 'nodes' in v, 'HAS_SETTINGS': 'settings_page' in v}


    @_panel_context.app.context_processor
    def inject_panel_timezone():
        try:
            timezone_name = (
                _panel_context._panel_timezone_name()
                or 'UTC'
            )
        except Exception:
            timezone_name = 'UTC'

        return {
            'PANEL_TIMEZONE': timezone_name
        }

    return {
        'inject_nav_flags': inject_nav_flags,
        'inject_panel_timezone': inject_panel_timezone,
    }


def bind_request_cookie_secure(_panel_context):
    def _request_cookie_secure(current_app):
        return bool(_panel_context.Config.SECURE_COOKIES or _panel_context._original_cookie_secure(current_app) or _panel_context.request.is_secure)

    return {
        '_request_cookie_secure': _request_cookie_secure,
    }


def bind_log_request(_panel_context):
    @_panel_context.app.after_request
    def _log_request(resp):
        try:
            path = _panel_context.request.path


            quiet = (_panel_context.request.method in ('GET', 'HEAD') and resp.status_code < 400
                     and (path.startswith(('/static/', '/reseller-assets/'))
                          or path in ('/api/healthz', '/api/app_logs', '/api/timezone')))
            if not quiet:
                rule = _panel_context.request.url_rule.rule if _panel_context.request.url_rule else path
                _panel_context.app.logger.info('HTTP %s %s %s', _panel_context.request.method, _panel_context.safe_path(rule), resp.status_code)
        except Exception:
            pass
        return resp


    @_panel_context.app.after_request
    def cache_headers(resp):
        if _panel_context.request.path.startswith(('/api/', '/r/', '/u/', '/s/')):
            resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp.headers['Pragma'] = 'no-cache'
            resp.headers['Expires'] = '0'
            resp.headers['Vary'] = 'Cookie, Authorization'
        elif resp.mimetype == 'text/html':
            resp.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate, max-age=0'
            resp.headers['Pragma'] = 'no-cache'
            resp.headers['Expires'] = '0'
            resp.headers['Vary'] = 'Cookie'
        elif _panel_context.request.path.startswith('/static/') and _panel_context.request.path.endswith(('.css','.js','.svg','.png','.woff2')):


            resp.headers['Cache-Control'] = 'public, max-age=300'
        return resp


    @_panel_context.app.after_request
    def inject_sec_headers(resp):
        secure_now = _panel_context._is_https()

        try:
            secure_flag = bool(secure_now or _panel_context.Config.SECURE_COOKIES)

            if _panel_context.request.endpoint not in ('static','reseller.static'):
                resp.set_cookie(
                    "csrf_token",
                    _panel_context.generate_csrf(),
                    samesite="Lax",
                    secure=secure_flag,
                    httponly=False,
                )
        except Exception as e:
            _panel_context.app.logger.debug("inject_sec_headers: failed to set csrf_token cookie: %s", e)

        resp.headers.setdefault('X-Frame-Options', 'DENY')
        if _panel_context.request.path.startswith(('/r/','/u/','/s/','/api/u/','/api/bot-apps/')):
            resp.headers['Referrer-Policy']='no-referrer'
        try:
            s = _panel_context._load_panel_settings()
            if s.get('hsts') and secure_now:
                resp.headers.setdefault(
                    'Strict-Transport-Security',
                    'max-age=31536000; includeSubDomains; preload'
                )
        except Exception:
            pass
        try:
            if _panel_context._is_https():
                ct = (resp.headers.get("Content-Type") or "").lower()
                if "text/html" in ct:
                    add = "upgrade-insecure-requests; block-all-mixed-content"
                    cur = (resp.headers.get("Content-Security-Policy") or "").strip()
                    if cur:
                        if "upgrade-insecure-requests" not in cur:
                            resp.headers["Content-Security-Policy"] = cur.rstrip("; ") + "; " + add
                    else:
                        resp.headers["Content-Security-Policy"] = add
        except Exception:
            pass


        return resp


    @_panel_context.app.before_request
    def _https_redirect():
        try:
            s = _panel_context._load_panel_settings() or {}
            if not s.get("force_https_redirect"):
                return

            if _panel_context.request.is_secure:
                return

            if not bool(getattr(_panel_context.app, "_tls_enabled_effective", False)):
                return

            if (_panel_context.request.path or "").startswith("/api/"):
                return

            host = (s.get("domain") or "").strip() or _panel_context.request.host.split(":", 1)[0]

            https_port = s.get("https_port")
            try:
                https_port = int(https_port) if https_port else 443
            except Exception:
                https_port = 443

            netloc = f"{host}:{https_port}" if https_port and https_port != 443 else host

            full = _panel_context.request.full_path
            if full.endswith("?"):
                full = full[:-1]

            return _panel_context.redirect(f"https://{netloc}{full}", code=301)

        except Exception as e:
            _panel_context.current_app.logger.warning("HTTPS redirect skipped: %s", e)
            return


    @_panel_context.app.after_request
    def _maybe_hsts(resp):
        try:
            s = _panel_context._load_panel_settings()
            if s.get('hsts') and _panel_context.request.is_secure:
                resp.headers.setdefault('Strict-Transport-Security',
                                        'max-age=31536000; includeSubDomains; preload')
        except Exception:
            pass
        return resp


    @_panel_context.app.after_request
    def security_headers(resp):
        p = (_panel_context.request.path or '').lower()

        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('Referrer-Policy', 'same-origin')

        if p.startswith('/preview/'):
            resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
            resp.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "style-src-elem 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; "
                "form-action 'none'; "
                "frame-ancestors 'self'"
            )

        if (
            p.endswith(('.woff2','.woff','.ttf','.otf')) or
            p.startswith('/static/fonts/') or
            p.startswith('/static/vendor/fa/webfonts/')
        ):
            resp.headers.setdefault('Access-Control-Allow-Origin', '*')
            if p.endswith('.woff2'): resp.headers.setdefault('Content-Type','font/woff2')
            elif p.endswith('.woff'): resp.headers.setdefault('Content-Type','font/woff')
            elif p.endswith('.ttf'):  resp.headers.setdefault('Content-Type','font/ttf')
            elif p.endswith('.otf'):  resp.headers.setdefault('Content-Type','font/otf')

        return resp

    return {
        '_log_request': _log_request,
        'cache_headers': cache_headers,
        'inject_sec_headers': inject_sec_headers,
        '_https_redirect': _https_redirect,
        '_maybe_hsts': _maybe_hsts,
        'security_headers': security_headers,
    }
