from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

def _clamp_or_raise(name, value, lo, hi):
    if not (lo <= value <= hi):
        raise ValueError(f"ScanConfig: '{name}' must be between {lo} and {hi}, got {value!r}.")

@dataclass
class ScanConfig:
    target:      str
    ports:       str           = "top100"
    threads:     int           = 100
    timeout:     float         = 1.0
    udp:         bool          = False
    banners:     bool          = True
    output_file: Optional[str] = None
    output_fmt:  str           = "json"
    profile:     str           = "custom"
    verbose:     bool          = False
    agree:       bool          = False
    retries:     int           = 1

    def __post_init__(self):
        _clamp_or_raise("threads", self.threads, 1, 1000)
        _clamp_or_raise("timeout", self.timeout, 0.1, 30.0)
        _clamp_or_raise("retries", self.retries, 0, 5)
        if self.output_fmt not in {"json","csv","txt"}:
            raise ValueError(f"ScanConfig: 'output_fmt' must be json/csv/txt, got {self.output_fmt!r}.")

    def to_dict(self):
        return {"target":self.target,"ports":self.ports,"threads":self.threads,
                "timeout":self.timeout,"udp":self.udp,"banners":self.banners,
                "output_file":self.output_file,"output_fmt":self.output_fmt,
                "profile":self.profile,"verbose":self.verbose,"retries":self.retries}

    @classmethod
    def from_dict(cls, data):
        known = {k for k in cls.__dataclass_fields__}
        return cls(**{k:v for k,v in data.items() if k in known})

PROFILES = {
    "quick":    ScanConfig(target="",ports="top100",  threads=200,timeout=0.5,retries=0,banners=True, profile="quick"),
    "standard": ScanConfig(target="",ports="top1000", threads=100,timeout=1.0,retries=1,banners=True, profile="standard"),
    "full":     ScanConfig(target="",ports="full",    threads=50, timeout=2.0,retries=1,banners=True, profile="full"),
    "stealth":  ScanConfig(target="",ports="top100",  threads=10, timeout=3.0,retries=0,banners=False,profile="stealth"),
}
