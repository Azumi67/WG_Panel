import os
import socket
from gunicorn.workers.gthread import ThreadWorker


def seconds(name,default):
    try:return max(1,min(120,float(os.environ.get(name,default))))
    except (ValueError,TypeError):return default


def ssl_context(conf,default_factory):
    context=default_factory()
    original=context.wrap_socket
    def wrap(sock,*args,**kwargs):
        sock.settimeout(seconds('WG_TLS_HANDSHAKE_TIMEOUT',5))
        return original(sock,*args,**kwargs)
    context.wrap_socket=wrap
    return context


def close_without_waiting(sock):
    try:
        sock.setblocking(False)
        try:sock.shutdown(socket.SHUT_WR)
        except OSError:return
        remaining=65536
        while remaining>0:
            try:data=sock.recv(min(4096,remaining))
            except (OSError,ValueError):break
            if not data:break
            remaining-=len(data)
    except (OSError,ValueError):pass
    finally:
        try:sock.close()
        except OSError:pass


def read_request_headers(conn, parser, body_timeout, logger):
    conn.parser = parser
    try:
        req = next(parser, None)
    except TimeoutError:
        logger.debug('Connection closed before HTTP request headers arrived.')
        return
    finally:
        conn.sock.settimeout(body_timeout)
    if req is not None:
        yield req


class BoundedThreadWorker(ThreadWorker):
    def enqueue_req(self,conn):
        if not getattr(conn,'_panel_close_bound',False):
            original=conn.close
            def close(graceful=False):
                if graceful:close_without_waiting(conn.sock)
                else:original()
            conn.close=close
            conn._panel_close_bound=True
        return super().enqueue_req(conn)

    def run(self):
        import faulthandler
        try:self._diagnostic_stream=diagnostic_file()
        except OSError:self._diagnostic_stream=None
        try:return super().run()
        finally:
            faulthandler.cancel_dump_traceback_later()
            if self._diagnostic_stream:self._diagnostic_stream.close()

    def notify(self):
        import faulthandler
        stream=getattr(self,'_diagnostic_stream',None)
        if stream and self.cfg.timeout:
            faulthandler.dump_traceback_later(max(2,self.cfg.timeout*.75),file=stream,repeat=False)
        return super().notify()

    def handle(self,conn):
        original=conn.init
        def initialize():
            try:
                original()
            except TimeoutError:
                self.log.debug('Connection setup timed out before an HTTP request arrived.')
                raise StopIteration from None
            body_timeout = seconds('WG_HTTP_IDLE_TIMEOUT',15)
            if conn.is_http2:
                conn.sock.settimeout(body_timeout)
            else:
                conn.sock.settimeout(min(body_timeout,seconds('WG_HTTP_HEADER_TIMEOUT',5)))
                conn.parser = read_request_headers(conn,conn.parser,body_timeout,self.log)
        conn.init=initialize
        try:return super().handle(conn)
        finally:conn.init=original


def heartbeat_directory():
    value=os.environ.get('WORKER_TMP_DIR')
    if value:return value
    return '/dev/shm' if os.path.isdir('/dev/shm') and os.access('/dev/shm',os.W_OK|os.X_OK) else None


def diagnostic_file():
    from pathlib import Path
    directory=Path(os.environ.get('WG_WORKER_DIAGNOSTICS_DIR') or Path(__file__).resolve().parents[1]/'instance'/'worker-diagnostics')
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    paths=sorted(directory.glob('worker-*.log'),key=lambda p:p.stat().st_mtime)
    for path in paths[:-4]:
        try:path.unlink()
        except OSError:pass
    path=directory/f'worker-{os.getpid()}.log'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,'O_NOFOLLOW',0),0o600)
    os.fchmod(fd,0o600)
    return os.fdopen(fd,'a',buffering=1)
