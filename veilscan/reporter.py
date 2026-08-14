from __future__ import annotations
import csv, dataclasses, io, json, sys
from typing import TextIO
from veilscan.models import PortState, ScanResult

_RESET="\033[0m";_BOLD="\033[1m";_DIM="\033[2m";_GREEN="\033[92m"
_YELLOW="\033[93m";_CYAN="\033[96m";_WHITE="\033[97m"

def _supports_color():
    if not hasattr(sys.stdout,"isatty") or not sys.stdout.isatty(): return False
    if sys.platform=="win32":
        try: import colorama; colorama.init(); return True
        except ImportError: return False
    return True

class Reporter:
    def __init__(self,result,color=None):
        self.result=result; self.color=_supports_color() if color is None else color

    def _c(self,code,text): return f"{code}{text}{_RESET}" if self.color else text

    def print_table(self,file=sys.stdout):
        r=self.result
        for host in r.hosts:
            bw=58; hl=f"  Host: {host.host} ({host.ip})"; ol=f"  OS Hint: {host.os_hint}" if host.os_hint else ""
            print(self._c(_CYAN,"╔"+"═"*bw+"╗"),file=file)
            print(self._c(_CYAN,f"║{hl:<{bw}}║"),file=file)
            if ol: print(self._c(_CYAN,f"║{ol:<{bw}}║"),file=file)
            print(self._c(_CYAN,"╚"+"═"*bw+"╝"),file=file)
            pts=host.open_ports
            if not pts: print(self._c(_DIM,"  No open ports found.\n"),file=file); continue
            wp=max(max(len(str(p.port)) for p in pts),6)
            wpr=max(max(len(p.protocol) for p in pts),6)
            ws=max(max(len(p.state.value) for p in pts),12)
            wsvc=max(max(len(p.service) for p in pts),14)
            sep="─"*(wp+wpr+ws+wsvc+20)
            hdr=f"{'PORT':<{wp}}  {'PROTO':<{wpr}}  {'STATE':<{ws}}  {'SERVICE':<{wsvc}}  VERSION"
            print(self._c(_DIM,sep),file=file); print(self._c(_BOLD,hdr),file=file); print(self._c(_DIM,sep),file=file)
            for p in sorted(pts,key=lambda x:x.port):
                ss=p.state.value.upper()
                sc=self._c(_GREEN,f"{ss:<{ws}}") if p.state==PortState.OPEN else self._c(_YELLOW,f"{ss:<{ws}}") if p.state==PortState.OPEN_FILTERED else self._c(_DIM,f"{ss:<{ws}}")
                print(f"{self._c(_WHITE,f'{p.port:<{wp}}')}  {p.protocol:<{wpr}}  {sc}  {p.service:<{wsvc}}  {p.version[:32]}",file=file)
            print(self._c(_CYAN,f"\n  {len(pts)} open port(s) found on this host.\n"),file=file)
        sep="─"*70
        footer=f"  Scan complete: {len(r.hosts)} host(s)  |  {r.total_open_ports} open port(s)  |  {r.duration:.2f}s"
        print(self._c(_DIM,sep),file=file); print(self._c(_BOLD,footer),file=file); print(self._c(_DIM,sep),file=file)

    def to_json(self,indent=2):
        def _d(o):
            if dataclasses.is_dataclass(o): return dataclasses.asdict(o)
            raise TypeError
        return json.dumps(dataclasses.asdict(self.result),indent=indent,default=_d)

    def to_csv(self):
        buf=io.StringIO(); w=csv.writer(buf,lineterminator="\n")
        w.writerow(["host","ip","os_hint","port","protocol","state","service","version","banner"])
        for host in self.result.hosts:
            for p in host.open_filtered_ports:
                b=p.banner.replace("\n"," ").replace("\r"," ").strip()[:120]
                w.writerow([host.host,host.ip,host.os_hint,p.port,p.protocol,p.state.value,p.service,p.version,b])
        return buf.getvalue()

    def to_txt(self):
        buf=io.StringIO(); oc=self.color; self.color=False
        self.print_table(file=buf); self.color=oc; return buf.getvalue()

    def save(self,path,fmt="json"):
        fmt=fmt.lower().strip(); gens={"json":self.to_json,"csv":self.to_csv,"txt":self.to_txt}
        if fmt not in gens: print(f"[VeilScan] Unknown format {fmt!r}",file=sys.stderr); return False
        try:
            with open(path,"w",encoding="utf-8",newline="") as f: f.write(gens[fmt]())
            return True
        except OSError as e: print(f"[VeilScan] Cannot save to {path!r}: {e}",file=sys.stderr); return False
