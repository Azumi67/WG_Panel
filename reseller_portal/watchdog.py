
from datetime import datetime,timezone


def _age(value,now):
    if not value:return None
    try:
        dt=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        if dt.tzinfo is None:dt=dt.replace(tzinfo=timezone.utc)
        return max(0,int((now-dt.astimezone(timezone.utc)).total_seconds()))
    except (ValueError,TypeError,OverflowError):return None


def evaluate(worker,monitor,failed_count=0,enforcement_error=None,now=None,threshold=120):
    now=now or datetime.now(timezone.utc)
    worker_age=_age(worker,now);monitor_age=_age(monitor,now)
    reasons=[]
    if worker_age is None or worker_age>threshold:reasons.append('worker heartbeat missing or stale')
    if monitor_age is None or monitor_age>threshold:reasons.append('quota enforcement heartbeat missing or stale')
    try:failed=int(failed_count or 0)
    except (ValueError,TypeError):failed=1
    if failed:reasons.append('quota enforcement failed for one or more accounts')
    if enforcement_error:reasons.append('quota enforcement reported an error')
    return {'ok':not reasons,'worker_age_seconds':worker_age,'monitor_age_seconds':monitor_age,
            'failed_accounts':failed,'reasons':reasons}


def evaluate_services(instance, monitor, failed_count=0, enforcement_error=None, now=None):
    try:
        from .worker_supervision import group_status, HEALTH_GROUPS
    except ImportError:
        from worker_supervision import group_status, HEALTH_GROUPS
    now=now or datetime.now(timezone.utc)
    services={group:group_status(instance,group,now.timestamp()) for group in HEALTH_GROUPS}
    result=evaluate(now.isoformat(),monitor,failed_count,enforcement_error,now=now)
    result['worker_age_seconds']=services['worker']['age']
    result['services']=services
    for group,status in services.items():
        if status['state']!='ready':result['reasons'].append(group+': '+', '.join(status['unhealthy']))
    result['ok']=not result['reasons']
    return result


def read_status(database_url=None, base_dir=None):
    import json
    import os
    from pathlib import Path
    from sqlalchemy import create_engine, text
    url=database_url or os.environ.get('DATABASE_URL')
    if not url:
        raise ValueError('DATABASE_URL is required for the reseller watchdog.')
    if url.startswith('postgres://'):
        url='postgresql://'+url[len('postgres://'):]
    if url.startswith('postgresql://'):
        url='postgresql+psycopg://'+url[len('postgresql://'):]
    if url.startswith('sqlite:///'):
        import sqlite3
        target=url[len('sqlite:///'):]
        root=Path(base_dir or Path(__file__).resolve().parents[1])
        path=Path(target) if os.path.isabs(target) else root/target
        keys=('monitor_heartbeat','monitor_failed_count','enforcement_error')
        with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=3) as conn:
            rows=conn.execute('SELECT key,value FROM rp_setting WHERE key IN ('+','.join('?' for _ in keys)+')',keys).fetchall()
    else:
        if not url.startswith('postgresql+psycopg://'):
            raise ValueError('Unsupported database backend')
        engine=create_engine(url, pool_pre_ping=True, connect_args={'connect_timeout':3,'options':'-c statement_timeout=5000'}, hide_parameters=True)
        try:
            with engine.connect() as conn:
                rows=conn.execute(text('SELECT key,value FROM rp_setting WHERE key IN (:a,:b,:c)'),
                                  dict(a='monitor_heartbeat',b='monitor_failed_count',c='enforcement_error')).all()
        finally:
            engine.dispose()
    values={key:json.loads(value) if isinstance(value,str) else value for key,value in rows}
    keys=('monitor_heartbeat','monitor_failed_count','enforcement_error')
    root=Path(base_dir or Path(__file__).resolve().parents[1])
    return evaluate_services(root/'instance',values.get('monitor_heartbeat'),values.get('monitor_failed_count'),values.get('enforcement_error'))


def main():
    import json
    try:
        result=read_status()
    except Exception as exc:

        result={'ok':False,'reasons':['unable to read reseller enforcement health database'],'worker_age_seconds':None,
                'monitor_age_seconds':None,'failed_accounts':0}
    print(json.dumps(result,sort_keys=True))
    return 0 if result['ok'] else 2


if __name__=='__main__':
    raise SystemExit(main())
