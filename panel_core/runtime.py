import fcntl
import os
import threading
import time


class BackgroundLeader:
    def __init__(self, path, callbacks, logger, interval=5):
        self.path = path
        self.callbacks = callbacks
        self.logger = logger
        self.interval = interval
        self.pid = None
        self.thread = None
        self.lock = threading.Lock()

    def start(self):
        with self.lock:
            if self.pid == os.getpid() and self.thread and self.thread.is_alive():
                return
            self.pid = os.getpid()
            self.thread = threading.Thread(target=self.run, name='panel-background-leader', daemon=True)
            self.thread.start()

    def run(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'a') as handle:
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(self.interval)
            self.logger.info('Background maintenance leader pid=%s', os.getpid())
            pending = list(self.callbacks)
            while pending:
                retry = []
                for callback in pending:
                    try:
                        callback()
                    except Exception:
                        self.logger.exception('Background startup failed: %s', callback.__name__)
                        retry.append(callback)
                pending = retry
                if pending:
                    time.sleep(self.interval)
            while True:
                time.sleep(self.interval)
