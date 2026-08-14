from __future__ import annotations
import queue, socket, threading
from typing import Callable, List, Optional
from veilscan.models import PortInfo, PortState
from veilscan.utils import get_service_name

def scan_tcp_port(ip,port,timeout=1.0,retries=1):
    service=get_service_name(port)
    for attempt in range(retries+1):
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                s.settimeout(timeout); code=s.connect_ex((ip,port))
                if code==0: return PortInfo(port=port,protocol="tcp",state=PortState.OPEN,service=service)
                if code in (111,10061): break
        except (socket.timeout,TimeoutError):
            if attempt<retries: continue
        except (socket.error,OSError,ConnectionRefusedError): break
    return PortInfo(port=port,protocol="tcp",state=PortState.CLOSED,service=service)

def scan_tcp_batch(ip,ports,timeout,num_threads,stop_event,retries=1,progress_cb=None):
    if not ports: return []
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
                info=scan_tcp_port(ip,port,timeout,retries)
                with lock: results.append(info); done[0]+=1; cur=done[0]
                if progress_cb:
                    try: progress_cb(cur,total)
                    except: pass
            finally: q.task_done()
    threads=[threading.Thread(target=worker,daemon=True) for _ in range(min(num_threads,len(ports)))]
    for t in threads: t.start()
    q.join()
    for t in threads: t.join(timeout=2.0)
    return results
