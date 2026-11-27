from flask import current_app
from sqlalchemy import text
from models import db
from .models import Account, ManagementBot, Audit
from . import service as s


def snapshot(aid, authorize, generate):
    app = current_app._get_current_object()
    
    with app.app_context():
        try:
            if db.engine.dialect.name == 'postgresql':
                db.session.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
            elif db.engine.dialect.name == 'sqlite':
                db.session.execute(text('BEGIN'))
            account = db.session.get(Account, aid)
            if (not account or account.state != 'active' or account.expires_at <= s.now() or
                    not account.spec.get('panel_access') or 'backup' not in account.spec['permissions'] or
                    not authorize(account)):
                raise PermissionError('Backup access changed.')
            return generate(account)
        finally:
            db.session.rollback()


def web_snapshot(aid, version, generate):
    return snapshot(aid, lambda account: account.session_version == version, generate)


def bot_snapshot(a, b, generate):
    from .management_bot import allowed
    from .workspace_replies import binding
    from .telegram_policy import effective
    aid, expected = a.id, binding(a, b)
    db.session.rollback()
    def authorize(account):
        bot = db.session.get(ManagementBot, aid)
        return allowed(account, bot) and binding(account, bot) == expected and 'backup' in effective(account)
    return snapshot(aid, authorize, generate)


def record(aid, source, filename, size):
    
    app = current_app._get_current_object()
    with app.app_context():
        try:
            s.audit('reseller:' + str(aid), 'backup_generated', f'{source} · {filename} · {size} bytes')
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning('Backup history unavailable account=%s error=%s', aid, type(exc).__name__)


def history(aid):
    return Audit.query.filter_by(actor='reseller:' + str(aid), action='backup_generated').order_by(Audit.id.desc()).limit(20).all()
