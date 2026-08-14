from __future__ import annotations
import datetime, logging, socket as _socket, threading
from typing import Callable, List, Optional
from veilscan import __version__
from veilscan.config import ScanConfig
from veilscan.models import HostResult, PortState, ScanResult
from veilscan.tcp_scanner import scan_tcp_batch
from veilscan.udp_scanner import scan_udp_batch
from veilscan.banner_grabber import grab_banner
from veilscan.utils import expand_cidr, parse_ports, resolve_host, os_hint, get_service_name

logger=logging.getLogger(__name__)

class Scanner:
    def __init__(self,config,progress_cb=None):
        self.config=config; self.progress_cb=progress_cb; self._stop_event=threading.Event()

    def stop(self): self._stop_event.set()

    def scan(self):
        cfg=self.config; start=datetime.datetime.now()
        targets=expand_cidr(cfg.target); ports=parse_ports(cfg.ports)
        hosts=[]
        for t in targets:
            if self._stop_event.is_set(): break
            hosts.append(self._scan_host(t,ports))
        end=datetime.datetime.now()
        return ScanResult(hosts=hosts,start_time=start.isoformat(),end_time=end.isoformat(),
                          duration=(end-start).total_seconds(),scanner_version=__version__,config=cfg.to_dict())

    def _scan_host(self,raw,ports):
        try: ip=resolve_host(raw)
        except ValueError as e: return HostResult(host=raw,ip="unresolved",os_hint=str(e))
        h=HostResult(host=raw,ip=ip)
        self._run_tcp(h,ip,ports)
        if self.config.udp and not self._stop_event.is_set(): self._run_udp(h,ip,ports)
        if self.config.banners and not self._stop_event.is_set(): self._run_banners(h,ip)
        if not self._stop_event.is_set(): h.os_hint=self._get_os_hint(ip)
        h.ports.sort(key=lambda p:(p.port,p.protocol))
        return h

    def _run_tcp(self,h,ip,ports):
        if self._stop_event.is_set(): return
        cfg=self.config; cb=self._make_cb("tcp",len(ports))
        for p in scan_tcp_batch(ip,ports,cfg.timeout,cfg.threads,self._stop_event,cfg.retries,cb):
            if not p.service: p.service=get_service_name(p.port)
            if p.state==PortState.OPEN: h.ports.append(p)
            elif cfg.verbose and p.state==PortState.FILTERED: h.ports.append(p)

    def _run_udp(self,h,ip,ports):
        cfg=self.config; cb=self._make_cb("udp",min(len(ports),200))
        for p in scan_udp_batch(ip,ports[:200],cfg.timeout*2,self._stop_event,cb):
            if p.state in (PortState.OPEN,PortState.OPEN_FILTERED): h.ports.append(p)

    def _run_banners(self,h,ip):
        open_tcp=[p for p in h.ports if p.protocol=="tcp" and p.state==PortState.OPEN]
        if not open_tcp: return
        timeout=max(self.config.timeout*2,3.0)
        for i,p in enumerate(open_tcp):
            if self._stop_event.is_set(): break
            svc,ver,banner=grab_banner(ip,p.port,timeout)
            if svc and svc!=p.service: p.service=svc
            if ver: p.version=ver
            if banner: p.banner=banner
            if self.progress_cb: self.progress_cb("banner",i+1,len(open_tcp))

    def _get_os_hint(self,ip):
        try:
            raw=_socket.socket(_socket.AF_INET,_socket.SOCK_RAW,_socket.IPPROTO_ICMP)
            raw.settimeout(self.config.timeout)
            udp=_socket.socket(_socket.AF_INET,_socket.SOCK_DGRAM)
            udp.settimeout(self.config.timeout)
            try: udp.sendto(b"\x00",(ip,45678))
            finally: udp.close()
            data,addr=raw.recvfrom(1024); raw.close()
            if addr[0]==ip and len(data)>=9: return os_hint(data[8])
        except: pass
        return ""

    def _make_cb(self,phase,total):
        if self.progress_cb is None: return None
        ucb=self.progress_cb
        def cb(done,total=total): ucb(phase,done,total)
        return cb
