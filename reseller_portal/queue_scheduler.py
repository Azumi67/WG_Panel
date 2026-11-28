from datetime import timedelta

from sqlalchemy import and_, exists, or_, select

MAX_WAIT_SECONDS = 900
MAX_PENDING_PER_ACCOUNT = 32
EXECUTION_STATES = ('running', 'review')
PENDING_STATES = ('queued', *EXECUTION_STATES)


def claim_statement(table, now):
    job = table.c
    other = table.alias('other_job').c
    active = exists(select(other.id).where(
        other.account_id == job.account_id,
        other.state.in_(EXECUTION_STATES),
    ).correlate(table))
    earlier = exists(select(other.id).where(
        other.account_id == job.account_id,
        other.state == 'queued',
        or_(other.created_at < job.created_at,
            and_(other.created_at == job.created_at, other.id < job.id)),
    ).correlate(table))
    return (select(table).where(
        job.state == 'queued',
        or_(job.created_at <= now - timedelta(seconds=MAX_WAIT_SECONDS),
            and_(job.available_at <= now, ~active, ~earlier)),
    ).order_by(job.available_at, job.created_at, job.id).limit(1)
        .with_for_update(of=table, skip_locked=True))


def migrate_execution_index(connection, execution_index, ordering_index):
    from sqlalchemy import inspect
    execution_index.create(connection, checkfirst=True)
    ordering_index.create(connection, checkfirst=True)
    indexes = {index['name'] for index in inspect(connection).get_indexes(execution_index.table.name)}
    if 'uq_rp_job_active_account' in indexes:
        connection.exec_driver_sql('DROP INDEX uq_rp_job_active_account')
