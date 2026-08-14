from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List

class PortState(str, Enum):
    OPEN          = "open"
    CLOSED        = "closed"
    FILTERED      = "filtered"
    OPEN_FILTERED = "open|filtered"

@dataclass
class PortInfo:
    port: int; protocol: str; state: PortState
    service: str = ""; version: str = ""; banner: str = ""

@dataclass
class HostResult:
    host: str; ip: str; os_hint: str = ""
    ports: List[PortInfo] = field(default_factory=list)
    @property
    def open_ports(self): return [p for p in self.ports if p.state==PortState.OPEN]
    @property
    def open_filtered_ports(self): return [p for p in self.ports if p.state in (PortState.OPEN,PortState.OPEN_FILTERED)]
    @property
    def tcp_ports(self): return [p for p in self.ports if p.protocol=="tcp"]
    @property
    def udp_ports(self): return [p for p in self.ports if p.protocol=="udp"]
    def summary(self): return f"Host: {self.host} ({self.ip})  |  {len(self.open_ports)} open port(s)  |  OS: {self.os_hint or 'Unknown'}"

@dataclass
class ScanResult:
    hosts: List[HostResult] = field(default_factory=list)
    start_time: str = ""; end_time: str = ""; duration: float = 0.0
    scanner_version: str = ""; config: dict = field(default_factory=dict)
    @property
    def total_open_ports(self): return sum(len(h.open_ports) for h in self.hosts)
    @property
    def hosts_with_open_ports(self): return [h for h in self.hosts if h.open_ports]
    def summary(self): return f"Scanned {len(self.hosts)} host(s) in {self.duration:.2f}s  |  {self.total_open_ports} total open port(s)"
