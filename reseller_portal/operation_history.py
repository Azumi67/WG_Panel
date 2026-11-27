from datetime import datetime, timedelta

from sqlalchemy import String, cast, func, or_

STATES = ('queued', 'running', 'completed', 'rejected', 'review', 'resolved')
GROUPS = {'active': ('queued', 'running'), 'completed': ('completed',),
          'attention': ('review', 'rejected')}


def history_page(query, job, args, *, administrator=False):
    counts = dict(query.with_entities(job.state, func.count(job.id)).group_by(job.state).all())
    counts = {'all': sum(counts.values()), **{key: sum(counts.get(state, 0) for state in values) for key, values in GROUPS.items()}}
    state = args.get('quick_state', args.get('state', 'all'))
    if state not in (*STATES, *GROUPS, 'all'):
        state = 'all'
    if state != 'all':
        query = query.filter(job.state.in_(GROUPS.get(state, (state,))))
    channel = args.get('channel', 'all')
    if channel == 'api':
        query = query.filter(job.request_key.startswith('app:'))
    elif channel == 'bot':
        query = query.filter(job.channel == 'bot')
    elif channel == 'web':
        query = query.filter(job.channel == 'web', ~job.request_key.startswith('app:'))
    else:
        channel = 'all'
    search = args.get('q', '').strip()[:100]
    if search:
        pattern = '%' + search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        columns = [job.id, job.action, job.section, job.message, job.request_key]
        if administrator:
            columns.append(cast(job.account_id, String))
        query = query.filter(or_(*(column.ilike(pattern, escape='\\') for column in columns)))
    dates = {}
    for name in ('from', 'to'):
        value = args.get(name, '')
        try:
            date = datetime.strptime(value, '%Y-%m-%d') if value else None
            if date:
                date = date + timedelta(days=1) if name == 'to' else date
                query = query.filter(job.created_at < date if name == 'to' else job.created_at >= date)
                dates[name] = value
        except (ValueError, OverflowError):
            pass
    size = args.get('size', 25, type=int)
    if size not in (10, 25, 50):
        size = 25
    total = query.count()
    pages = max(1, (total + size - 1) // size)
    page = min(pages, max(1, args.get('page', 1, type=int)))
    rows = query.order_by(job.created_at.desc(), job.id.desc()).offset((page - 1) * size).limit(size).all()
    return rows, dict(counts=counts, total=total, pages=pages, page=page, size=size,
                      state=state, channel=channel, q=search, dates=dates)
