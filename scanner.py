import ipaddress
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "Submission",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2181: "ZooKeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Dev-HTTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "Sonar/PHP-FPM",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "ES-Transport",
    11211: "Memcached",
    27017: "MongoDB",
}

MAX_PORT_SPAN = 4096
MAX_WORKERS = 64
CONNECT_TIMEOUT = 0.45


def validate_ipv4(raw: str) -> str:
    text = (raw or "").strip()
    addr = ipaddress.ip_address(text)
    if addr.version != 4:
        raise ValueError("Only IPv4 addresses are allowed.")
    if not (addr.is_loopback or addr.is_private):
        raise ValueError("Only localhost and private IPv4 addresses may be scanned.")
    return str(addr)


def validate_ports(start_port: int, end_port: int) -> Tuple[int, int]:
    start = int(start_port)
    end = int(end_port)
    if start < 1 or end > 65535 or start > end:
        raise ValueError("Port range must be between 1 and 65535, with start ≤ end.")
    if (end - start + 1) > MAX_PORT_SPAN:
        raise ValueError(f"Port range cannot exceed {MAX_PORT_SPAN} ports per scan.")
    return start, end


def identify_service(port: int) -> str:
    return COMMON_SERVICES.get(port, "Unknown")


def probe_tcp(ip: str, port: int) -> Tuple[int, str, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        code = sock.connect_ex((ip, port))
        state = "open" if code == 0 else "closed"
    except OSError:
        state = "closed"
    finally:
        sock.close()
    return port, state, identify_service(port)


class ScanJob:
    def __init__(self, user_id: int, target_ip: str, start_port: int, end_port: int):
        self.id = uuid.uuid4().hex
        self.user_id = user_id
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.total = end_port - start_port + 1
        self.scanned = 0
        self.open_ports: List[Dict] = []
        self.closed_count = 0
        self.current_port = start_port
        self.status = "queued"
        self.error = ""
        self.started_at = None
        self.finished_at = None
        self.duration_ms = 0
        self.results: List[Dict] = []
        self.lock = threading.Lock()

    def snapshot(self) -> Dict:
        with self.lock:
            percent = 0 if self.total == 0 else int((self.scanned / self.total) * 100)
            elapsed = 0
            if self.started_at:
                end = self.finished_at or time.time()
                elapsed = max(0, end - self.started_at)
            return {
                "job_id": self.id,
                "status": self.status,
                "target_ip": self.target_ip,
                "start_port": self.start_port,
                "end_port": self.end_port,
                "total": self.total,
                "scanned": self.scanned,
                "percent": min(100, percent),
                "current_port": self.current_port,
                "open_count": len(self.open_ports),
                "closed_count": self.closed_count,
                "elapsed": round(elapsed, 2),
                "duration_ms": self.duration_ms,
                "error": self.error,
                "open_ports": list(self.open_ports),
                "results": list(self.results) if self.status in {"completed", "error"} else [],
            }


class JobStore:
    def __init__(self):
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def add(self, job: ScanJob) -> None:
        with self._lock:
            self._jobs[job.id] = job

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)


JOBS = JobStore()


def run_scan(job: ScanJob, on_complete: Optional[Callable[[ScanJob], None]] = None) -> None:
    job.status = "running"
    job.started_at = time.time()
    ports = range(job.start_port, job.end_port + 1)
    workers = min(MAX_WORKERS, max(4, job.total))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(probe_tcp, job.target_ip, port): port for port in ports}
            for future in as_completed(futures):
                port, state, service = future.result()
                with job.lock:
                    job.scanned += 1
                    job.current_port = port
                    row = {"port": port, "state": state, "service": service}
                    job.results.append(row)
                    if state == "open":
                        job.open_ports.append(row)
                    else:
                        job.closed_count += 1
        job.results.sort(key=lambda item: item["port"])
        job.open_ports.sort(key=lambda item: item["port"])
        job.finished_at = time.time()
        job.duration_ms = int((job.finished_at - job.started_at) * 1000)
        if on_complete:
            on_complete(job)
        job.status = "completed"
    except Exception:
        job.status = "error"
        job.error = "Scan failed due to a local network error."
        job.finished_at = time.time()
        if job.started_at:
            job.duration_ms = int((job.finished_at - job.started_at) * 1000)


def start_scan(user_id: int, target_ip: str, start_port: int, end_port: int, on_complete=None) -> ScanJob:
    ip = validate_ipv4(target_ip)
    start, end = validate_ports(start_port, end_port)
    job = ScanJob(user_id, ip, start, end)
    JOBS.add(job)
    thread = threading.Thread(target=run_scan, args=(job, on_complete), daemon=True)
    thread.start()
    return job
