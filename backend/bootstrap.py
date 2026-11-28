def bind_bootstrap(_panel_context):
    def bootstrap():
        with _panel_context.app.app_context():
            _panel_context._migrate_schema()
            from reseller_portal import migrate as migrate_reseller_portal
            migrate_reseller_portal()
            from models import InterfaceConfig
            firewall_summary = (
                _panel_context.local_firewall_rules()
            )
            _panel_context.app.logger.info("Legacy local firewall migration: %s",firewall_summary,)
            p = (
                _panel_context.app.config.get("WG_CONF_PATH")
                or _panel_context.app.config.get(
                    "WIREGUARD_CONF_PATH"
                )
                or "/etc/wireguard")

            paths = (
                _panel_context.glob.glob(_panel_context.os.path.join(p,"*.conf",))
                if _panel_context.os.path.isdir(p)
                else (
                    [p]
                    if _panel_context.os.path.isfile(p)
                    else []
                )
            )
            for conf in paths:
                parsed = _panel_context.find_iface(conf)
                if not parsed:
                    continue
                name = _panel_context.os.path.splitext(_panel_context.os.path.basename(conf))[0]
                existing = (InterfaceConfig.query.filter_by(name=name).first())
                if not existing:
                    pk = _panel_context._derive_wg_public_key(parsed.private_key)
                    if pk:
                        parsed.public_key = pk
                    _panel_context.db.session.add(parsed)
                    continue
                _panel_context._copy_local_iface_from_parsed(existing, parsed)
            _panel_context.db.session.commit()

    return {
        'bootstrap': bootstrap,
    }


def bind_reconcile_web_startup(_panel_context):
    def _reconcile_web_startup():
        with _panel_context.app.app_context():
            _panel_context._on_boot()
            _panel_context._run_expiry_once('boot')
            _panel_context.repoint_endpoints()
            _panel_context._clear_retention()

    return {
        '_reconcile_web_startup': _reconcile_web_startup,
    }


def bind_start_web_background(_panel_context):
    def _start_web_background():
        if _panel_context.os.environ.get('WG_BACKGROUND_ROLE') not in ('reseller-worker', 'maintenance'):
            _panel_context._WEB_BACKGROUND.start()


    def _web_worker_initialized(worker):
        with _panel_context.app.app_context():
            _panel_context.db.session.remove()
            for engine in _panel_context.db.engines.values():
                engine.dispose(close=False)
        _panel_context._start_web_background()

    return {
        '_start_web_background': _start_web_background,
        '_web_worker_initialized': _web_worker_initialized,
    }


def configure_application(context):
    app = context.app
    Config = context.Config
    os = context.os
    db = context.db
    register_profile_routes = context.register_profile_routes
    app.config.from_object(Config)
    if not app.secret_key or app.secret_key in ('change-me', 'CHANGE_ME'):
        raise RuntimeError('Set a private FLASK_SECRET_KEY before starting WG Panel. Preserve existing valid keys.')
    if any(os.environ.get(k) for k in ('WG_RESELLER_ENCRYPTION_KEY','WG_RESELLER_PREVIOUS_KEYS','WG_RESELLER_LEGACY_SECRET')):
        from panel_core.encryption_keys import reseller_cipher
        try:
            reseller_cipher(app.secret_key,os.environ.get('WG_RESELLER_ENCRYPTION_KEY'),
                os.environ.get('WG_RESELLER_PREVIOUS_KEYS'),os.environ.get('WG_RESELLER_LEGACY_SECRET'))
        except (ValueError,TypeError) as exc:
            raise RuntimeError('Invalid reseller encryption key-ring configuration.') from None


    if os.environ.get('WG_BACKUP_ENCRYPTION_KEY') or os.environ.get('WG_BACKUP_PREVIOUS_KEYS'):
        from panel_core.backup_keys import configured_cipher
        try:configured_cipher()
        except (ValueError, TypeError):raise RuntimeError('Invalid backup encryption key-ring configuration.') from None

    if os.environ.get('WG_TRUSTED_HOSTS', '').strip():
        app.config['TRUSTED_HOSTS'] = [host.strip() for host in os.environ['WG_TRUSTED_HOSTS'].split(',') if host.strip()]
    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    from reseller_portal.database import configure as configure_database
    with app.app_context():
        configure_database(db.engine)

    register_profile_routes(app)
    context.namespace.update({
        'configure_database': configure_database,
    })
