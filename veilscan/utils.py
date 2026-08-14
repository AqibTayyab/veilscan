from __future__ import annotations
import ipaddress, socket
from typing import List, Optional

PORT_SERVICES: dict[int,str] = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",67:"DHCP-Server",
    68:"DHCP-Client",69:"TFTP",80:"HTTP",81:"HTTP-Alt",88:"Kerberos",110:"POP3",
    111:"RPCbind",119:"NNTP",123:"NTP",135:"MS-RPC",137:"NetBIOS-NS",138:"NetBIOS-DGM",
    139:"NetBIOS-SSN",143:"IMAP",161:"SNMP",162:"SNMP-Trap",179:"BGP",194:"IRC",
    389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",500:"IKE",512:"rexec",513:"rlogin",
    514:"Syslog",515:"LPD",520:"RIP",587:"SMTP-Sub",631:"IPP",636:"LDAPS",646:"LDP",
    873:"rsync",902:"VMware-Auth",912:"VMware-Auth-Alt",993:"IMAPS",995:"POP3S",
    1080:"SOCKS",1099:"Java-RMI",1194:"OpenVPN",1433:"MSSQL",1521:"Oracle",
    1701:"L2TP",1723:"PPTP",1883:"MQTT",1900:"UPnP",2049:"NFS",2082:"cPanel",
    2083:"cPanel-SSL",2086:"WHM",2087:"WHM-SSL",2181:"ZooKeeper",2375:"Docker-HTTP",
    2376:"Docker-HTTPS",2379:"etcd-Client",2380:"etcd-Peer",3000:"Grafana",
    3128:"Squid-Proxy",3268:"LDAP-GC",3269:"LDAPS-GC",3306:"MySQL",3389:"RDP",
    4369:"Erlang-EPMD",4444:"Metasploit",4500:"IPsec-NAT",5000:"UPnP-Alt",
    5001:"COMMPLEX",5432:"PostgreSQL",5672:"AMQP",5900:"VNC",5901:"VNC-1",
    5984:"CouchDB",5985:"WinRM-HTTP",5986:"WinRM-HTTPS",6000:"X11",6379:"Redis",
    6443:"Kubernetes-API",6667:"IRC",7474:"Neo4j-HTTP",7687:"Neo4j-Bolt",
    8000:"HTTP-Alt",8008:"HTTP-Alt",8080:"HTTP-Proxy",8081:"HTTP-Alt",8086:"InfluxDB",
    8161:"ActiveMQ",8443:"HTTPS-Alt",8883:"MQTT-TLS",8888:"HTTP-Alt",9042:"Cassandra",
    9090:"Prometheus",9092:"Kafka",9100:"Node-Exporter",9200:"Elasticsearch",
    9300:"Elasticsearch-Trans",10000:"Webmin",10250:"Kubelet",11211:"Memcached",
    15672:"RabbitMQ-Mgmt",27017:"MongoDB",27018:"MongoDB-Shard",44818:"EtherNet/IP",
    51820:"WireGuard",
}

TOP_100: List[int] = [
     21, 22, 23, 25, 53, 67, 69, 80, 88,110,
    111,119,123,135,137,138,139,143,161,179,
    194,389,443,445,464,465,500,512,513,514,
    515,520,587,631,636,646,873,902,912,993,
    995,1080,1099,1194,1433,1521,1701,1723,1883,1900,
    2049,2082,2083,2086,2087,2181,2375,2376,2379,3000,
    3128,3268,3269,3306,3389,4369,4444,4500,5000,5432,
    5672,5900,5984,5985,5986,6379,6443,6667,8000,8008,
    8080,8081,8086,8161,8443,8883,8888,9042,9090,9092,
    9100,9200,9300,10000,10250,11211,15672,27017,44818,51820,
]
assert len(TOP_100)==100

TOP_1000: List[int] = sorted(set(list(PORT_SERVICES.keys())+list(range(1,1025))))

def parse_ports(spec: str) -> List[int]:
    s = spec.strip().lower()
    if s=="top100":  return list(TOP_100)
    if s=="top1000": return list(TOP_1000)
    if s=="full":    return list(range(1,65536))
    ports: set[int] = set()
    for part in s.split(","):
        part=part.strip()
        if not part: continue
        if "-" in part:
            a,b=part.split("-",1); start,end=int(a.strip()),int(b.strip())
            if start>end: raise ValueError(f"Invalid range '{part}': start>end")
            if not(1<=start<=65535 and 1<=end<=65535): raise ValueError(f"Port range out of bounds: {part}")
            ports.update(range(start,end+1))
        else:
            n=int(part)
            if not 1<=n<=65535: raise ValueError(f"Port {n} out of bounds")
            ports.add(n)
    if not ports: raise ValueError(f"No valid ports in: {spec!r}")
    return sorted(ports)

def expand_cidr(target: str) -> List[str]:
    try:
        net=ipaddress.ip_network(target,strict=False)
        hosts=[str(h) for h in net.hosts()]
        return hosts if hosts else [str(net.network_address)]
    except ValueError: return [target]

def resolve_host(host: str) -> str:
    try: return socket.gethostbyname(host)
    except socket.gaierror as e: raise ValueError(f"Cannot resolve '{host}': {e}") from e

def os_hint(ttl: Optional[int]) -> str:
    if ttl is None: return ""
    if ttl<=64:  return f"Linux/Unix (TTL={ttl})"
    if ttl<=128: return f"Windows (TTL={ttl})"
    return f"Network device / Solaris (TTL={ttl})"

def is_private_ip(ip: str) -> bool:
    try:
        addr=ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError: return False

def get_service_name(port: int, protocol: str="tcp") -> str:
    return PORT_SERVICES.get(port,"")

def validate_target(target: str) -> None:
    if not target or not target.strip(): raise ValueError("Target cannot be empty.")
    host=target.split("/")[0].strip()
    if ":" in host: raise ValueError(f"IPv6 '{target}' not yet supported. Use IPv4.")
    try:
        addr=ipaddress.ip_address(host)
        if str(addr)=="0.0.0.0": raise ValueError("Target '0.0.0.0' is not valid.")
        if addr.is_multicast: raise ValueError(f"'{target}' is a multicast address.")
        if str(addr)=="255.255.255.255": raise ValueError("Broadcast address not valid.")
    except ValueError as e:
        if any(k in str(e) for k in ["0.0.0.0","multicast","Broadcast","not yet","cannot be empty"]): raise

def estimate_scan_time(num_hosts,num_ports,num_threads,timeout,banners=True,open_ports_estimate=5):
    tcp=( num_hosts*num_ports*timeout)/max(num_threads,1)
    ban=(num_hosts*open_ports_estimate*timeout*2) if banners else 0
    return tcp+ban

def format_duration(seconds: float) -> str:
    s=int(seconds)
    if s<60: return f"{s} second{'s' if s!=1 else ''}"
    if s<3600: m,sec=divmod(s,60); return f"{m} minute{'s' if m!=1 else ''} {sec}s"
    h,r=divmod(s,3600); m=r//60; return f"{h} hour{'s' if h!=1 else ''} {m} minute{'s' if m!=1 else ''}"
