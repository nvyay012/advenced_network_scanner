import socket
import threading
from queue import Queue
import logging

class PortScanner:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('timeout', 1)
        self.threads = config.get('threads', 50)
        self.port_range = config.get('port_range', (1, 1024))

    def scan_port(self, target, port):
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                return port if result == 0 else None
        except socket.error:
            return None

    def worker(self, target, port_queue, results):
        """Worker thread for port scanning"""
        while True:
            port = port_queue.get()
            if port is None:
                break
            if result := self.scan_port(target, port):
                results.append(result)
            port_queue.task_done()

    def scan(self, target):
        """Perform the port scan"""
        port_queue = Queue()
        results = []
        threads = []

        # Start worker threads
        for _ in range(self.threads):
            thread = threading.Thread(
                target=self.worker,
                args=(target, port_queue, results)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Add ports to queue
        for port in range(self.port_range[0], self.port_range[1] + 1):
            port_queue.put(port)

        # Add sentinel values
        for _ in range(self.threads):
            port_queue.put(None)

        # Wait for completion
        for thread in threads:
            thread.join()

        return sorted(results)