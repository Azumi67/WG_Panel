import os
import sys
from pathlib import Path
from urllib.parse import urlsplit


def probe(role):
    if role in ('panel','agent'):
        import requests
        path = '/api/healthz' if role=='panel' else '/api/system/healthz'
        default = '8000' if role=='panel' else '9898'
        bind = os.getenv('BIND') or '0.0.0.0:'+default
        parsed = urlsplit('http://'+bind)
        host = parsed.hostname or '127.0.0.1'
        if host in ('0.0.0.0','::'): host = '127.0.0.1' if host=='0.0.0.0' else '::1'
        if ':' in host: host = '['+host+']'
        url = os.getenv('WG_DOCKER_HEALTH_URL') or 'http://'+host+':'+str(parsed.port or default)+path
        response = requests.get(url,headers={'Authorization':'Bearer '+os.environ['API_KEY']},timeout=(2,5),allow_redirects=False)
        return response.status_code==200 and response.json().get('ok') is True
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    
    import importlib.util
    path = Path(__file__).resolve().parents[1]/'reseller_portal'/'worker_supervision.py'
    spec = importlib.util.spec_from_file_location('worker_progress',path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.group_status('/app/instance',role)['state']=='ready'


if __name__=='__main__':
    try:
        sys.exit(0 if probe(sys.argv[1]) else 1)
    except Exception:
        sys.exit(1)
