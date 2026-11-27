from __future__ import annotations

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import ClassVar


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


@dataclass
class PortResult:
    port: int
    service: str
    banner: str


class PortScanner:
    COMMON_PORTS: ClassVar[dict[int, str]] = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3000: "Dev / Node.js",
        3306: "MySQL",
        3389: "RDP",
        5000: "Dev / Flask",
        5432: "PostgreSQL",
        6379: "Redis",
        8000: "HTTP-Alt",
        8080: "HTTP-Proxy / Dev",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }

    HTTP_PORTS: ClassVar[set[int]] = {80, 3000, 5000, 8000, 8080, 8443}

    def __init__(self, timeout: float = 1.0, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers

    def _clean_target(self, target: str) -> str:
        target = target.strip().lower().removeprefix("https://").removeprefix("http://")
        return target.split("/")[0].split(":")[0]

    def _resolve_target(self, target: str) -> str | None:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def _grab_banner(self, sock: socket.socket, target: str, port: int) -> str:
        """Read initial greeting or probe HTTP service for its Server header."""
        try:
            if port in self.HTTP_PORTS:
                probe = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                sock.sendall(probe.encode("utf-8"))

            raw_data = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if not raw_data:
                return "No banner returned"

            for line in raw_data.splitlines():
                if line.lower().startswith("server:"):
                    return line.strip()

            first_line = raw_data.splitlines()[0].strip()
            return first_line[:65]
        except OSError:
            return "No banner returned"

    def _scan_port(self, ip: str, target_host: str, port: int) -> PortResult | None:
        """Attempt TCP connection to a single port and grab its banner if open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((ip, port)) == 0:
                    service = self.COMMON_PORTS.get(port, "Unknown")
                    banner = self._grab_banner(sock, target_host, port)
                    return PortResult(port=port, service=service, banner=banner)
        except OSError:
            return None
        return None

    def scan(self, raw_target: str) -> tuple[str, str | None, list[PortResult], float]:
        target = self._clean_target(raw_target)
        ip = self._resolve_target(target)
        if not ip:
            return target, None, [], 0.0

        print(
            f"\n{Colors.CYAN}[*] Scanning {len(self.COMMON_PORTS)} critical ports on "
            f"{Colors.BOLD}{target}{Colors.RESET}{Colors.CYAN} ({ip})...{Colors.RESET}"
        )

        start_time = time.perf_counter()
        open_ports: list[PortResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_port, ip, target, port): port
                for port in self.COMMON_PORTS
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        elapsed = time.perf_counter() - start_time
        open_ports.sort(key=lambda item: item.port)
        return target, ip, open_ports, elapsed


def print_results(target: str, ip: str | None, results: list[PortResult], elapsed: float) -> None:
    if ip is None:
        print(f"\n{Colors.RED}[!] Could not resolve host: {target}{Colors.RESET}\n")
        return

    print(f"{Colors.CYAN}{'=' * 76}{Colors.RESET}")
    print(
        f"{Colors.BOLD}Target:{Colors.RESET} {target} ({ip}) | "
        f"{Colors.BOLD}Open Ports:{Colors.RESET} {len(results)} | "
        f"{Colors.BOLD}Time:{Colors.RESET} {elapsed:.2f}s"
    )
    print(f"{Colors.CYAN}{'=' * 76}{Colors.RESET}")

    if not results:
        print(f"{Colors.YELLOW}No open ports found from the checklist (all closed or filtered).{Colors.RESET}\n")
        return

    for item in results:
        port_label = f"{Colors.GREEN}{item.port}/tcp OPEN{Colors.RESET}"
        print(f"  {port_label:<24} {item.service:<18} -> {Colors.YELLOW}{item.banner}{Colors.RESET}")
    print()


if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["scanme.nmap.org"]
    scanner = PortScanner()

    for target in targets:
        clean_name, resolved_ip, open_ports, duration = scanner.scan(target)
        print_results(clean_name, resolved_ip, open_ports, duration)