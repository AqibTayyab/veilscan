from __future__ import annotations
import re, socket, ssl
from typing import Tuple

_HTTP_PROBE = b"GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: VeilScan/2.0\r\n\r\n"
PROBE_MAP: dict[int, bytes|None] = {
    21:None,22:None,25:None,110:None,143:None,465:None,587:None,993:None,995:None,
    3306:None,5432:None,11211:None,27017:None,
    6379: b"*1\r\n$4\r\nPING\r\n",
    80:_HTTP_PROBE,8000:_HTTP_PROBE,8008:_HTTP_PROBE,8080:_HTTP_PROBE,
    8081:_HTTP_PROBE,8888:_HTTP_PROBE,9090:_HTTP_PROBE,
}
TLS_PORTS: set[int] = {443,8443,993,995,465}

def _connect(ip,port,timeout):
    raw=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    raw.settimeout(timeout); raw.connect((ip,port))
    if port in TLS_PORTS:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        try: return ctx.wrap_socket(raw,server_hostname=ip)
        except ssl.SSLError: return raw
    return raw

def _parse_banner(port,banner):
    if not banner: return ("","","")
    b=banner.strip(); bl=b.lower()
    if b.startswith("SSH-"):
        parts=b.split("-",2); ver=parts[2].split()[0] if len(parts)>2 else ""
        return ("SSH",ver,b)
    if b.startswith("HTTP/"):
        srv=""
        for line in b.splitlines():
            if line.lower().startswith("server:"): srv=line.split(":",1)[1].strip(); break
        return ("HTTPS" if port in TLS_PORTS else "HTTP",srv,b)
    if b.startswith("220") and ("ftp" in bl or "filezilla" in bl or "proftpd" in bl or "vsftpd" in bl or port==21):
        return ("FTP",b[4:60].strip().split("\n")[0],b)
    if b.startswith("220") and ("smtp" in bl or "esmtp" in bl or "postfix" in bl or port in (25,465,587)):
        return ("SMTP",b[4:80].strip().split("\n")[0],b)
    if b.startswith("+OK") and port in (110,995): return ("POP3",b[4:60].strip(),b)
    if b.startswith("* OK") and port in (143,993): return ("IMAP",b[5:60].strip(),b)
    if b.startswith("+PONG") or (b.startswith("-ERR") and port==6379): return ("Redis","",b)
    if port==6379: return ("Redis","",b)
    if b.startswith("VERSION") and port==11211:
        parts=b.split(); return ("Memcached",parts[1] if len(parts)>1 else "",b)
    if port==3306:
        m=re.search(r"\d+\.\d+\.\d+[\w\-]*",b)
        if m: return ("MariaDB" if "mariadb" in bl else "MySQL",m.group(0),b[:80])
        return ("MySQL","",b[:80])
    if port==5432: return ("PostgreSQL","",b[:60])
    if port==27017: return ("MongoDB","",b[:60])
    if port==23: return ("Telnet","",b[:60])
    if b.startswith("RFB "): return ("VNC",b.split(" ",1)[1].split("\n")[0].strip(),b)
    if "NOTICE AUTH" in b or (port==6667 and b.startswith(":")):
        srv=b.split()[0].lstrip(":") if b.startswith(":") else ""
        return ("IRC",srv,b)
    return ("","",b)

def grab_banner(ip,port,timeout=2.0):
    try:
        probe=_HTTP_PROBE if port in TLS_PORTS else PROBE_MAP.get(port,b"\r\n")
        sock=_connect(ip,port,timeout)
        with sock:
            if probe is not None:
                try: sock.sendall(probe)
                except: return ("","","")
            raw=b""
            try: raw=sock.recv(4096)
            except (socket.timeout,TimeoutError): pass
            except: return ("","","")
        if not raw: return ("","","")
        text=raw.decode("utf-8",errors="replace").strip()
        svc,ver,_=_parse_banner(port,text)
        return (svc,ver,text[:256])
    except: return ("","","")
