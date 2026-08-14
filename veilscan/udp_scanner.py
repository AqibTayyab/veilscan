from __future__ import annotations
import queue, socket, struct, sys, threading
from typing import Callable, List, Optional, Tuple
from veilscan.models import PortInfo, PortState
from veilscan.utils import get_service_name

UDP_PROBES: dict[int,bytes] = {
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b"+b"\x00"*47,
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    67: b"\x01\x01\x06\x00\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xbb\xcc\xdd\xee\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x01\xff",
    137: b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    138: b"\x11\x02\x00\x00\x00\x00\x00\x00\x00\x8a\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00",
    69:   b"\x00\x01test\x00octet\x00",
    514:  b"<14>VeilScan test\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\x0c\x00\x01",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
    19:   b"",
}

def check_udp_privileges() -> Tuple[bool,str]:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.close(); return True,""
    except PermissionError:
        msg=("\n  [!] UDP SCAN — LIMITED ACCURACY\n"
             "  Raw ICMP socket requires Administrator on Windows.\n"
             "  → Right-click CMD → Run as Administrator for accurate results.\n"
             if sys.platform=="win32" else
             "\n  [!] UDP SCAN — LIMITED ACCURACY\n"
             "  Raw ICMP socket requires root. Use: sudo python3 main.py ... --udp\n")
        return False,msg
    except OSError: return False,"  [!] Raw ICMP unavailable — UDP accuracy limited.\n"

def scan_udp_port(ip,port,timeout=2.0,can_icmp=True):
    service=get_service_name(port); probe=UDP_PROBES.get(port,b"\x00")
    icmp_sock=None
    if can_icmp:
        try: icmp_sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        except: icmp_sock=None
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout); udp.sendto(probe,(ip,port))
            try:
                resp,_=udp.recvfrom(1024)
                if resp: return PortInfo(port=port,protocol="udp",state=PortState.OPEN,service=service,banner=resp[:128].decode("utf-8",errors="replace").strip())
            except: pass
        if icmp_sock:
            icmp_sock.settimeout(timeout)
            try:
                while True:
                    data,addr=icmp_sock.recvfrom(1024)
                    if addr[0]==ip and len(data)>=44 and data[20]==3 and data[21]==3:
                        if len(data)>=44 and struct.unpack("!H",data[42:44])[0]==port:
                            return PortInfo(port=port,protocol="udp",state=PortState.CLOSED,service=service)
            except: pass
        return PortInfo(port=port,protocol="udp",state=PortState.OPEN_FILTERED,service=service)
    finally:
        if icmp_sock:
            try: icmp_sock.close()
            except: pass

def scan_udp_batch(ip,ports,timeout,stop_event,progress_cb=None):
    if not ports: return []
    can_icmp,msg=check_udp_privileges()
    if msg: print(msg,file=sys.stderr)
    results=[]; lock=threading.Lock(); q=queue.Queue(); total=len(ports); done=[0]
    for p in ports: q.put(p)
    def worker():
        while True:
            if stop_event.is_set():
                try:
                    while True: q.get_nowait(); q.task_done()
                except queue.Empty: pass
                return
            try: port=q.get_nowait()
            except queue.Empty: return
            try:
                info=scan_udp_port(ip,port,timeout,can_icmp)
                with lock: results.append(info); done[0]+=1; cur=done[0]
                if progress_cb:
                    try: progress_cb(cur,total)
                    except: pass
            finally: q.task_done()
    threads=[threading.Thread(target=worker,daemon=True) for _ in range(min(50,len(ports)))]
    for t in threads: t.start()
    q.join()
    for t in threads: t.join(timeout=2.0)
    return results
