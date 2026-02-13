#!/usr/bin/env python3
import os, json, subprocess, time, socket, ssl
from flask import Flask, request, jsonify, abort
from functools import wraps
import re
import ipaddress as ipa
import subprocess, os
import requests
import hmac

try:
    from dotenv import load_dotenv
    _here = os.path.dirname(os.path.abspath(__file__))
    load_dotenv(os.path.join(_here, '.env'))
except Exception:
    pass

API_KEY = os.environ.get('API_KEY','') 
WG_CONF_PATH = os.environ.get('WIREGUARD_CONF_PATH','/etc/wireguard')

app = Flask(__name__)

def require_api_key(f):
    @wraps(f)
    def inner(*a, **k):
        want = (API_KEY or '').strip()
        if not want:
            return jsonify({'error': 'Unauthorized'}), 401

        auth = (request.headers.get('Authorization') or '').strip()
        bearer = auth.split(None, 1)[1].strip() if auth.startswith('Bearer ') else ''
        xhdr = (request.headers.get('X-API-KEY') or '').strip()

        supplied = bearer or xhdr
        if supplied and hmac.compare_digest(supplied, want):
            return f(*a, **k)
        return jsonify({'error': 'Unauthorized'}), 401
    return inner


def _public_ipv4():
    try:
        return requests.get('https://api.ipify.org', timeout=2).text.strip()
    except Exception:
        return None


def _iface_up(name: str) -> bool:
    try:
        return subprocess.run(
            ['ip', 'link', 'show', 'dev', name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5
        ).returncode == 0
    except Exception:
        return False
    
def _split_address(addr_field: str) -> list[str]:
    if not addr_field:
        return []
    parts = re.split(r'[,\s]+', addr_field.strip())
    return [p for p in parts if '/' in p]

def _primary_iface(addr_field: str):

    cidrs = _split_address(addr_field)
    for c in cidrs:
        try:
            ii = ipa.ip_interface(c)
            if ii.version == 4:
                return ii
        except Exception:
            pass
    for c in cidrs:
        try:
            return ipa.ip_interface(c)
        except Exception:
            pass
    return None

def _extract_ips(conf_path: str, target_net: ipa._BaseNetwork) -> set:

    used = set()
    if not (conf_path and os.path.isfile(conf_path)):
        return used
    try:
        with open(conf_path, 'r') as f:
            in_peer = False
            block = []
            for raw in f:
                line = raw.strip()
                if line.startswith('[') and line.endswith(']'):
                    if in_peer and block:
                        for L in block:
                            if L.lower().startswith('allowedips'):
                                val = L.split('=', 1)[1]
                                for c in val.split(','):
                                    c = c.strip()
                                    try:
                                        ii = ipa.ip_interface(c)
                                        if ii.network.prefixlen in (32, 128) and (ii.ip in target_net):
                                            used.add(ii.ip)
                                    except Exception:
                                        pass
                        block = []
                    in_peer = (line[1:-1].lower() == 'peer')
                else:
                    if in_peer and '=' in line:
                        block.append(line)
            if in_peer and block:
                for L in block:
                    if L.lower().startswith('allowedips'):
                        val = L.split('=', 1)[1]
                        for c in val.split(','):
                            c = c.strip()
                            try:
                                ii = ipa.ip_interface(c)
                                if ii.network.prefixlen in (32, 128) and (ii.ip in target_net):
                                    used.add(ii.ip)
                            except Exception:
                                pass
    except Exception:
        pass
    return used

def _extract_wgip(iface_name: str, target_net: ipa._BaseNetwork) -> set:

    used = set()
    try:
        out = subprocess.check_output(
            ['wg', 'show', iface_name, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode()
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) != 2:
                continue
            for c in parts[1].split(','):
                c = c.strip()
                try:
                    ii = ipa.ip_interface(c)
                    if ii.network.prefixlen in (32, 128) and (ii.ip in target_net):
                        used.add(ii.ip)
                except Exception:
                    pass
    except Exception:
        pass
    return used

def available_ips(iface_name: str, iface_addr_field: str, conf_dir: str) -> list[str]:

    ii = _primary_iface(iface_addr_field)
    if ii is None:
        return []

    net = ii.network
    iface_ip = ii.ip

    if net.version == 6 and net.prefixlen < 120:
        return []  

    conf_path = os.path.join(conf_dir, f'{iface_name}.conf')

    used_hosts = set()
    used_hosts |= _extract_ips(conf_path, net)
    used_hosts |= _extract_wgip(iface_name, net)

    return [f"{host}/{net.prefixlen}"
            for host in net.hosts()
            if host != iface_ip and host not in used_hosts]

def _read_iface(path):
    address = listen_port = private_key = mtu = dns = None
    in_iface = False
    with open(path,'r') as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith('#'): continue
            if s.startswith('[') and s.endswith(']'):
                in_iface = (s[1:-1].lower()=='interface'); continue
            if not in_iface or '=' not in s: continue
            k,v = [x.strip() for x in s.split('=',1)]
            lk = k.lower()
            if lk=='address': address=v
            elif lk=='listenport':
                try: listen_port=int(v)
                except: pass
            elif lk=='privatekey': private_key=v
            elif lk=='mtu': 
                try: mtu=int(v)
                except: pass
            elif lk=='dns': dns=v
    if not (address and listen_port and private_key): return None
    return {
        'name': os.path.splitext(os.path.basename(path))[0],
        'path': path, 'address': address, 'listen_port': listen_port,
        'mtu': mtu, 'dns': dns
    }

def hostPrefix(host_cidr):
    import ipaddress as ipa
    ip = ipa.ip_interface(host_cidr).ip
    return f"{ip}/{32 if ip.version==4 else 128}"

def _orig_host(allowed: str | None) -> str | None:
    if not allowed: 
        return None
    for c in (x.strip() for x in allowed.split(',')):
        try:
            ii = ipa.ip_interface(c)
            if ii.network.prefixlen in (32, 128):
                return hostPrefix(c)  
        except Exception:
            pass
    return None

def _route(cmd, cidr):
    try:
        subprocess.run(['ip', 'route', *cmd, 'blackhole', cidr],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

@app.route('/api/health')
@require_api_key
def health():
    return jsonify(ok=True, host=socket.gethostname(), now=int(time.time()), public_ipv4=_public_ipv4())

@app.route('/api/interfaces')
@require_api_key
def interfaces():
    def _first_cidr(s: str | None) -> str | None:
        ...

    fast = str(request.args.get('fast', '')).lower() in ('1', 'true', 'yes')

    out = []
    if os.path.isdir(WG_CONF_PATH):
        for fn in os.listdir(WG_CONF_PATH):
            if not fn.endswith('.conf'):
                continue
            conf_path = os.path.join(WG_CONF_PATH, fn)
            meta = _read_iface(conf_path)
            if not meta:
                continue

            try:
                meta['is_up'] = _iface_up(meta['name'])
            except Exception:
                meta['is_up'] = False

            if fast:
                meta['available_ips'] = []
                meta['ips_deferred'] = True
            else:
                try:
                    prim = _first_cidr(meta.get('address'))
                    if prim:
                        meta['available_ips'] = available_ips(meta['name'], prim, WG_CONF_PATH)
                    else:
                        meta['available_ips'] = []
                except Exception as e:
                    app.logger.warning("available_ips error on %s: %s", meta.get('name'), e)
                    meta['available_ips'] = []

            out.append(meta)

    return jsonify(interfaces=out, public_ipv4=_public_ipv4())


@app.route('/api/peers')
@require_api_key
def peers():
    want_iface = (request.args.get('iface') or '').strip()
    peers = []
    try:
        dump = subprocess.check_output(['wg','show','all','dump']).decode().splitlines()
        for line in dump:
            parts = line.split('\t')
            if len(parts) != 9:
                continue
            iface = parts[0]
            if want_iface and iface != want_iface:
                continue
            peer_pub = parts[1]
            rx_bytes = int(parts[6] or 0)
            tx_bytes = int(parts[7] or 0)
            hs = int(parts[5] or 0)
            peers.append({
                'id': peer_pub,
                'iface': iface,
                'public_key': peer_pub,
                'rx_mib': round(rx_bytes/1048576.0, 2),
                'tx_mib': round(tx_bytes/1048576.0, 2),
                'status': 'online' if hs > 0 else 'offline'
            })
    except Exception:
        pass
    return jsonify(peers=peers)


@app.route('/api/peers/add', methods=['POST'])
@require_api_key
def add_peer():
    try:
        j = request.get_json(silent=True) or {}
        iface = (j.get('iface') or '').strip()
        pub   = (j.get('public_key') or '').strip()
        host_cidr = (j.get('host_cidr') or '').strip()

        if not iface or not pub or not host_cidr:
            return jsonify(error="iface, public_key, and host_cidr are required"), 400

        try:
            host = hostPrefix(host_cidr)
        except Exception as e:
            return jsonify(error="invalid host_cidr", detail=str(e)), 400

        try:
            subprocess.check_call(
                ['wg', 'show', iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            up = subprocess.run(
                ['wg-quick', 'up', iface],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            if up.returncode != 0:
                return jsonify(
                    error="failed_to_bring_iface_up",
                    iface=iface,
                    stderr=up.stderr.strip()
                ), 500

        cmd = ['wg', 'set', iface, 'peer', pub, 'allowed-ips', host]
        if j.get('endpoint'):
            cmd += ['endpoint', str(j['endpoint']).strip()]
        if j.get('persistent_keepalive'):
            cmd += ['persistent-keepalive', str(j['persistent_keepalive']).strip()]

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            return jsonify(
                error="wg_set_failed",
                stderr=proc.stderr.strip()
            ), 500

        conf = os.path.join(WG_CONF_PATH, f'{iface}.conf')
        os.makedirs(os.path.dirname(conf), exist_ok=True)
        if not os.path.exists(conf):
            with open(conf, 'w') as f:
                f.write(f"[Interface]\n# Autocreated for {iface}\n\n")

        with open(conf, 'a') as f:
            f.write('\n[Peer]\n')
            f.write(f'PublicKey = {pub}\n')
            f.write(f'AllowedIPs = {host}\n')
            if j.get('endpoint'):
                f.write(f"Endpoint = {str(j['endpoint']).strip()}\n")
            if j.get('persistent_keepalive'):
                f.write(f"PersistentKeepalive = {str(j['persistent_keepalive']).strip()}\n")
            f.write('\n')

        return jsonify(ok=True), 200

    except Exception as e:
        return jsonify(error="unhandled_exception", detail=str(e)), 500

def _peer_conf(pub):
    for fn in os.listdir(WG_CONF_PATH):
        if not fn.endswith('.conf'): continue
        iface = fn[:-5]
        with open(os.path.join(WG_CONF_PATH, fn)) as f:
            lines = [ln.strip() for ln in f]
        for i, ln in enumerate(lines):
            if ln.lower().startswith('publickey') and ln.split('=',1)[1].strip() == pub:
                allowed = endpoint = keep = None
                j = i
                while j < len(lines) and not lines[j].startswith('['):
                    s = lines[j].lower()
                    if s.startswith('allowedips'): allowed = lines[j].split('=',1)[1].strip()
                    if s.startswith('endpoint'):   endpoint = lines[j].split('=',1)[1].strip()
                    if s.startswith('persistentkeepalive'):
                        try: keep = int(lines[j].split('=',1)[1].strip())
                        except: keep = None
                    j += 1
                return {'iface': iface, 'allowed': allowed, 'endpoint': endpoint, 'keep': keep}
    return None

@app.route('/api/peer/<path:pub>/enable', methods=['POST'])
@require_api_key
def enable_peer(pub):
    info = _peer_conf(pub)
    if not info:
        return jsonify(error='peer_not_found'), 404

    j = request.get_json(silent=True) or {}
    host = j.get('host_cidr') or _orig_host(info.get('allowed'))

    try:
        subprocess.check_call(['wg','show',info['iface']],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        subprocess.run(['wg-quick','up',info['iface']], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    cmd = ['wg','set',info['iface'],'peer',pub]
    if info.get('allowed'):  cmd += ['allowed-ips', info['allowed']]
    if info.get('endpoint'): cmd += ['endpoint', info['endpoint']]
    if info.get('keep'):     cmd += ['persistent-keepalive', str(info['keep'])]
    subprocess.check_call(cmd)

    if host:
        _route(['del'], host)

    return jsonify(ok=True)

@app.route('/api/peer/<path:pub>/disable', methods=['POST'])
@require_api_key
def disable_peer(pub):
    j = request.get_json(silent=True) or {}
    info = _peer_conf(pub)  
    host = j.get('host_cidr') or (info and _orig_host(info.get('allowed')))

    try:
        dump = subprocess.check_output(['wg','show','all','dump']).decode().splitlines()
        for line in dump:
            parts = line.split('\t')
            if len(parts) == 9 and parts[1] == pub:
                subprocess.run(['wg','set',parts[0],'peer',pub,'remove'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
    except Exception:
        pass

    if host:
        _route(['add'], host)

    return jsonify(ok=True)

@app.route('/api/peer/<path:pub>', methods=['DELETE'])
@require_api_key
def delete_peer(pub):
    try:
        dump = subprocess.check_output(['wg','show','all','dump']).decode().splitlines()
        for line in dump:
            parts = line.split('\t')
            if len(parts) == 9 and parts[1] == pub:
                subprocess.run(['wg','set',parts[0],'peer',pub,'remove'])
                break
    except Exception:
        pass
    for fn in os.listdir(WG_CONF_PATH):
        if not fn.endswith('.conf'): continue
        p = os.path.join(WG_CONF_PATH, fn)
        lines = open(p,'r').readlines()
        out=[]; i=0
        while i<len(lines):
            if lines[i].strip().lower()=='[peer]':
                block=[lines[i]]; i+=1
                while i<len(lines) and not lines[i].strip().startswith('['):
                    block.append(lines[i]); i+=1
                if any(l.lower().startswith('publickey') and l.split('=',1)[1].strip()==pub for l in block):
                    continue
                out.extend(block)
            else:
                out.append(lines[i]); i+=1
        open(p,'w').writelines(out)
    return jsonify(ok=True)

@app.route('/api/iface/<name>/available_ips')
@require_api_key
def iface_availableIPS(name):
    conf = os.path.join(WG_CONF_PATH, f'{name}.conf')
    if not os.path.isfile(conf):
        return jsonify(error='not_found'), 404
    meta = _read_iface(conf)
    if not meta:
        return jsonify(error='bad_conf'), 400
    ips = available_ips(name, meta['address'], WG_CONF_PATH)
    return jsonify(available_ips=ips)


@app.route('/api/iface/<name>/up', methods=['POST'])
@require_api_key
def iface_up(name):
    subprocess.check_call(['wg-quick','up', name])
    return jsonify(ok=True)

@app.route('/api/iface/<name>/down', methods=['POST'])
@require_api_key
def iface_down(name):
    subprocess.check_call(['wg-quick','down', name])
    return jsonify(ok=True)

@app.get('/api/iface/<name>/pubkey')
@require_api_key
def iface_pubkey(name):

    try:
        out = subprocess.check_output(
            ['wg', 'show', name, 'public-key'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode().strip()
        if out:
            return jsonify(public_key=out)
    except Exception:
        pass

    try:
        conf_path = os.path.join(WG_CONF_PATH, f"{name}.conf")
        priv = None
        in_iface = False
        with open(conf_path, 'r') as f:
            for raw in f:
                s = raw.strip()
                if not s or s.startswith('#'): 
                    continue
                if s.startswith('[') and s.endswith(']'):
                    in_iface = (s[1:-1].lower() == 'interface')
                    continue
                if in_iface and '=' in s:
                    k, v = [x.strip() for x in s.split('=', 1)]
                    if k.lower() == 'privatekey':
                        priv = v
                        break
        if priv:
            out = subprocess.check_output(
                ['wg', 'pubkey'],
                input=(priv + '\n').encode(),
                stderr=subprocess.DEVNULL, timeout=2.0
            ).decode().strip()
            if out:
                return jsonify(public_key=out)
    except Exception:
        pass

    return jsonify(error='pubkey_unavailable'), 404

IFACE_CLEAR_MARK = {} 

@app.route('/api/iface/<name>/logs', methods=['GET', 'DELETE'])
@require_api_key
def agent_iface_logs(name):
    import subprocess, shlex, datetime

    if request.method == 'DELETE':
        IFACE_CLEAR_MARK[name] = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        return jsonify(ok=True)

    def _run(cmd):
        try:
            out = subprocess.check_output(
                shlex.split(cmd),
                stderr=subprocess.DEVNULL,
                timeout=6
            ).decode('utf-8', 'ignore')
            return out
        except Exception:
            return ''

    since = IFACE_CLEAR_MARK.get(name)  
    if since:
        since_arg = since.replace('T', ' ').split('.')[0].rstrip('Z')
        since_flag = f'--since "{since_arg}"'
    else:
        since_flag = '--since "2 days ago"'

    unit = f'wg-quick@{name}.service'
    text = _run(f'journalctl -u {unit} -n 300 --no-pager {since_flag}')
    if not text.strip():
        text = _run(f'journalctl -k -n 300 --no-pager {since_flag}')
        text = '\n'.join(
            ln for ln in text.splitlines()
            if ('wg' in ln.lower() or name in ln)
        )

    logs = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        try:
            ts = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        except Exception:
            ts = ''
        logs.append({'ts': ts, 'level': 'info', 'text': s})

    return jsonify({'logs': logs})


if __name__ == "__main__":
    import os, multiprocessing, sys

    use_gunicorn = os.getenv("USE_GUNICORN", "1") != "0"

    if not use_gunicorn:
        app.run(
            host=os.getenv("DEV_HOST", "127.0.0.1"),
            port=int(os.getenv("DEV_PORT", os.getenv("PORT", "9898"))),
            debug=os.getenv("FLASK_DEBUG", "0") == "1",
        )
        sys.exit(0)

    from gunicorn.app.base import BaseApplication

    class _Guni(BaseApplication):
        def __init__(self, wsgi_app, options=None):
            self.options = options or {}
            self.application = wsgi_app
            super().__init__()
        def load_config(self):
            cfg = {k: v for k, v in self.options.items()
                   if k in self.cfg.settings and v is not None}
            for k, v in cfg.items():
                self.cfg.set(k.lower(), v)
        def load(self):
            return self.application

    port = os.getenv("PORT") or "9898"
    bind = os.getenv("BIND") or f"0.0.0.0:{port}"
    workers = int(os.getenv("WORKERS") or (multiprocessing.cpu_count() * 2 + 1))
    threads = int(os.getenv("THREADS") or 4)
    timeout = int(os.getenv("TIMEOUT") or 60)
    graceful_timeout = int(os.getenv("GRACEFUL_TIMEOUT") or 30)
    loglevel = os.getenv("LOGLEVEL") or "info"

    options = {
        "bind": bind,
        "workers": workers,
        "worker_class": "gthread",
        "threads": threads,
        "timeout": timeout,
        "graceful_timeout": graceful_timeout,
        "accesslog": "-",
        "errorlog": "-",
        "loglevel": loglevel,
        "preload_app": False,
        "capture_output": True,
    }
    certfile = (os.getenv("AGENT_SSL_CERT") or "").strip()   # e.g. /etc/letsencrypt/live/agent.azumi.com/fullchain.pem
    keyfile  = (os.getenv("AGENT_SSL_KEY")  or "").strip()   # e.g. /etc/letsencrypt/live/agent.azumi.com/privkey.pem
    cafile   = (os.getenv("AGENT_SSL_CA")   or "").strip()   

    if certfile and keyfile:
        if not os.path.isfile(certfile):
            raise RuntimeError(f"AGENT_SSL_CERT not found: {certfile}")
        if not os.path.isfile(keyfile):
            raise RuntimeError(f"AGENT_SSL_KEY not found: {keyfile}")

        options["certfile"] = certfile
        options["keyfile"]  = keyfile

        if cafile:
            if not os.path.isfile(cafile):
                raise RuntimeError(f"AGENT_SSL_CA not found: {cafile}")
            options["ca_certs"]  = cafile
            options["cert_reqs"] = ssl.CERT_REQUIRED  

    _Guni(app, options).run()
