from datetime import timedelta

from sqlalchemy import inspect, update

from .queue_scheduler import MAX_WAIT_SECONDS


def migrate_stage(connection):
    if 'stage' not in {column['name'] for column in inspect(connection).get_columns('rp_provision_job')}:
        connection.exec_driver_sql('ALTER TABLE rp_provision_job ADD COLUMN stage VARCHAR(24)')


def mark_applying(engine, table, jid, attempt):
    
    with engine.begin() as connection:
        result = connection.execute(update(table).where(
            table.c.id == jid, table.c.state == 'running', table.c.attempts == attempt,
            table.c.stage == 'preflight',
        ).values(stage='applying', message='Applying customer changes.'))
        if result.rowcount != 1:
            raise RuntimeError('Operation execution marker could not be recorded.')


def recover_interrupted(session, table, now, *, jid=None, attempt=None):
    scope = [table.c.state == 'running']
    if jid is not None:
        scope.append(table.c.id == jid)
    if attempt is not None:
        scope.append(table.c.attempts == attempt)
    cutoff = now - timedelta(seconds=MAX_WAIT_SECONDS)
    preflight = table.c.stage == 'preflight'
    session.execute(update(table).where(*scope, preflight, table.c.created_at > cutoff).values(
        state='queued', stage=None, started_at=None, available_at=now,
        message='Worker restarted before customer changes; request queued again.'))
    session.execute(update(table).where(*scope, preflight, table.c.created_at <= cutoff).values(
        state='rejected', stage='not_applied', finished_at=now, payload_enc=None,
        message='Request expired before customer changes. Submit a new request.', notify_after=now))
    
    session.execute(update(table).where(*scope).values(
        state='review', stage='uncertain', finished_at=now,
        message='Worker stopped after execution may have started. Administrator reconciliation is required.', notify_after=now))
