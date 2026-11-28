
from datetime import datetime
import time
from contextlib import contextmanager
from flask import current_app
from sqlalchemy import case, delete, select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from models import db
from .models import AuthBudget, AuthEvent, Audit
from . import service as s


@contextmanager
def _guard_transaction(label):


    start = time.monotonic()
    checked_out = body_finished = None
    try:
        with db.engine.connect() as connection:
            checked_out = time.monotonic()
            with connection.begin():
                yield connection
                body_finished = time.monotonic()
    finally:
        end = time.monotonic()
        if end-start >= 1:
            checkout = checked_out or end
            body = body_finished or end
            current_app.logger.warning(
                'Reseller auth guard timing label=%s checkout_ms=%.0f body_ms=%.0f commit_close_ms=%.0f total_ms=%.0f',
                label, (checkout-start)*1000, (body-checkout)*1000,
                (end-body)*1000, (end-start)*1000)


def reserve(items, *, touch=None):
    now = time.time() if touch else s.now().timestamp()
    allowed = True
    with _guard_transaction('login-budget') as connection:
        for key, maximum, seconds in sorted(items, key=lambda item: str(item[0])):
            proposal = pg_insert(AuthBudget).values(key=str(key), count=1, until=now+seconds)
            stmt = proposal.on_conflict_do_update(
                index_elements=[AuthBudget.key],
                set_={
                    'count': case((AuthBudget.until > now, AuthBudget.count + 1), else_=1),
                    'until': case((AuthBudget.until > now, AuthBudget.until), else_=proposal.excluded.until),
                },
            ).returning(AuthBudget.count)
            count = connection.execute(stmt).scalar_one()
            allowed = allowed and count <= int(maximum)
        if touch:
            statement=pg_insert(AuthBudget).values(key=touch,count=1,until=now+30*86400)
            connection.execute(statement.on_conflict_do_update(index_elements=[AuthBudget.key],set_={'until':func.greatest(AuthBudget.until,statement.excluded.until)}))
    return allowed


def login_event(account_id):
    with _guard_transaction('login-audit') as connection:
        connection.execute(AuthEvent.__table__.insert().values(
            actor='reseller:' + str(account_id), at=s.now()))


def import_events():
    cursor = int(s.setting('auth_audit_cursor', 0) or 0)
    with db.engine.connect() as connection:
        rows = connection.execute(
            select(AuthEvent.id, AuthEvent.actor, AuthEvent.at).where(AuthEvent.id > cursor)
            .order_by(AuthEvent.id).limit(100)).all()
    for eid, actor, at in rows:
        db.session.add(Audit(actor=actor, action='login', details='Successful login', at=at))
    if rows:
        s.put('auth_audit_cursor', int(rows[-1][0]))


def prune_imported_events():
    cursor = int(s.setting('auth_audit_cursor', 0) or 0)
    db.session.rollback()
    if cursor:
        with db.engine.begin() as connection:
            ids = select(AuthEvent.id).where(AuthEvent.id <= cursor).order_by(AuthEvent.id).limit(500)
            connection.execute(delete(AuthEvent).where(AuthEvent.id.in_(ids)))


def prune_expired_budgets():
    now = s.now().timestamp()
    with _guard_transaction('expired-login-budget-cleanup') as connection:
        oldest = select(AuthBudget.key).where(AuthBudget.until < now - 86400).order_by(AuthBudget.until).limit(1000)
        connection.execute(delete(AuthBudget).where(AuthBudget.key.in_(oldest), AuthBudget.until < now - 86400))
