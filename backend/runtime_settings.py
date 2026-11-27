def bind_load_runtime(_panel_context):
    def _load_runtime():
        try:
            with open(_panel_context.RUNTIME_FILE, 'r') as f:
                s = _panel_context.json.load(f)
        except Exception:
            s = {}
        def _i(x):
            try:
                return int(x)
            except Exception:
                return None
        return {
            'bind':             (s.get('bind') or '').strip(),
            'port':             _i(s.get('port')),
            'workers':          _i(s.get('workers')),
            'threads':          _i(s.get('threads')),
            'timeout':          _i(s.get('timeout')),
            'graceful_timeout': _i(s.get('graceful_timeout')),
            'loglevel':         (s.get('loglevel') or _panel_context.os.getenv('LOGLEVEL') or 'info').lower(),
        }


    def _save_runtime(payload: dict):
        cur = _panel_context._load_runtime()
        cur.update({k: v for k, v in payload.items() if v is not None})
        _panel_context._json_save(_panel_context.RUNTIME_FILE, cur)


    def _confirm_runtime(p):
        bind = (p.get('bind') or '').strip()
        if bind:
            if ':' not in bind:
                raise ValueError('bind must be "host:port"')
            host, port_s = bind.rsplit(':', 1)
            if host not in _panel_context.ALLOWED_BINDS:
                raise ValueError('bind host not allowed')
            try:
                port = int(port_s)
            except Exception:
                raise ValueError('port must be a number')
        else:
            host = ''
            try:
                port = int(p.get('port'))
            except Exception:
                raise ValueError('port must be provided and be a number')

        if not (1024 <= port <= 65535):
            raise ValueError('port must be 1024–65535')
        if port in _panel_context.RESERVED_PORTS:
            raise ValueError('port is reserved')

        try:
            workers = int(p.get('workers', 0))
            threads = int(p.get('threads', 4))
            timeout = int(p.get('timeout', 60))
            gtime   = int(p.get('graceful_timeout', 30))
        except Exception:
            raise ValueError('numeric fields must be integers')

        workers = max(0, min(workers, 16))
        threads = max(1, min(threads, 64))
        timeout = max(10, min(timeout, 600))
        gtime   = max(5,  min(gtime,   600))

        ll = (p.get('loglevel') or 'info').lower()
        if ll not in _panel_context.ALLOWED_LOGLEVELS:
            raise ValueError('invalid loglevel')

        return {
            'bind': f'{host}:{port}' if bind else '',
            'port': port,
            'workers': workers,
            'threads': threads,
            'timeout': timeout,
            'graceful_timeout': gtime,
            'loglevel': ll,
        }

    return {
        '_load_runtime': _load_runtime,
        '_save_runtime': _save_runtime,
        '_confirm_runtime': _confirm_runtime,
    }
