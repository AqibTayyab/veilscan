"""tests/test_config.py — Unit tests for veilscan/config.py"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from veilscan.config import ScanConfig, PROFILES


class TestScanConfigDefaults:
    def test_ports(self):     assert ScanConfig(target="x").ports       == "top100"
    def test_threads(self):   assert ScanConfig(target="x").threads     == 100
    def test_timeout(self):   assert ScanConfig(target="x").timeout     == 1.0
    def test_retries(self):   assert ScanConfig(target="x").retries     == 1
    def test_udp(self):       assert ScanConfig(target="x").udp         == False
    def test_banners(self):   assert ScanConfig(target="x").banners     == True
    def test_verbose(self):   assert ScanConfig(target="x").verbose     == False
    def test_agree(self):     assert ScanConfig(target="x").agree       == False
    def test_output(self):    assert ScanConfig(target="x").output_file is None
    def test_fmt(self):       assert ScanConfig(target="x").output_fmt  == "json"
    def test_profile(self):   assert ScanConfig(target="x").profile     == "custom"


class TestScanConfigValidation:
    def test_threads_zero_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", threads=0)

    def test_threads_negative_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", threads=-1)

    def test_threads_max_ok(self):
        ScanConfig(target="x", threads=1000)  # should not raise

    def test_threads_over_max_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", threads=1001)

    def test_timeout_too_low_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", timeout=0.0)

    def test_timeout_negative_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", timeout=-1.0)

    def test_timeout_max_ok(self):
        ScanConfig(target="x", timeout=30.0)  # should not raise

    def test_timeout_over_max_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", timeout=30.1)

    def test_retries_negative_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", retries=-1)

    def test_retries_max_ok(self):
        ScanConfig(target="x", retries=5)  # should not raise

    def test_retries_over_max_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", retries=6)

    def test_bad_output_fmt_raises(self):
        with pytest.raises(ValueError): ScanConfig(target="x", output_fmt="xml")

    def test_valid_fmts_ok(self):
        for fmt in ["json", "csv", "txt"]:
            ScanConfig(target="x", output_fmt=fmt)  # should not raise


class TestScanConfigCustom:
    def test_custom_ports(self):
        c = ScanConfig(target="x", ports="22,80,443")
        assert c.ports == "22,80,443"

    def test_custom_threads(self):
        c = ScanConfig(target="x", threads=50)
        assert c.threads == 50

    def test_custom_timeout(self):
        c = ScanConfig(target="x", timeout=2.5)
        assert c.timeout == 2.5

    def test_udp_true(self):
        c = ScanConfig(target="x", udp=True)
        assert c.udp == True

    def test_banners_false(self):
        c = ScanConfig(target="x", banners=False)
        assert c.banners == False


class TestScanConfigDict:
    def test_to_dict_has_all_keys(self):
        d = ScanConfig(target="1.2.3.4").to_dict()
        expected = {"target","ports","threads","timeout","udp","banners",
                    "output_file","output_fmt","profile","verbose","retries"}
        assert expected.issubset(d.keys())

    def test_to_dict_values_correct(self):
        d = ScanConfig(target="1.2.3.4", threads=75, timeout=2.0).to_dict()
        assert d["target"]  == "1.2.3.4"
        assert d["threads"] == 75
        assert d["timeout"] == 2.0

    def test_from_dict_roundtrip(self):
        c  = ScanConfig(target="1.2.3.4", ports="top1000", threads=75, udp=True)
        c2 = ScanConfig.from_dict(c.to_dict())
        assert c2.target  == c.target
        assert c2.ports   == c.ports
        assert c2.threads == c.threads
        assert c2.udp     == c.udp

    def test_from_dict_ignores_unknown(self):
        d = ScanConfig(target="x").to_dict()
        d["future_unknown_key"] = "some_value"
        c = ScanConfig.from_dict(d)     # should not raise
        assert c.target == "x"


class TestProfiles:
    def test_four_profiles(self):
        assert set(PROFILES.keys()) == {"quick","standard","full","stealth"}

    def test_all_scan_configs(self):
        for name, p in PROFILES.items():
            assert isinstance(p, ScanConfig)

    def test_profile_names_match(self):
        for name, p in PROFILES.items():
            assert p.profile == name

    def test_quick_threads(self):   assert PROFILES["quick"].threads    == 200
    def test_quick_timeout(self):   assert PROFILES["quick"].timeout    == 0.5
    def test_quick_retries(self):   assert PROFILES["quick"].retries    == 0
    def test_quick_ports(self):     assert PROFILES["quick"].ports      == "top100"

    def test_standard_ports(self):  assert PROFILES["standard"].ports   == "top1000"
    def test_standard_threads(self):assert PROFILES["standard"].threads == 100

    def test_full_ports(self):      assert PROFILES["full"].ports       == "full"
    def test_full_threads(self):    assert PROFILES["full"].threads     == 50

    def test_stealth_threads(self): assert PROFILES["stealth"].threads  == 10
    def test_stealth_timeout(self): assert PROFILES["stealth"].timeout  == 3.0
    def test_stealth_banners(self): assert PROFILES["stealth"].banners  == False

    def test_quick_faster_than_standard(self):
        assert PROFILES["quick"].timeout < PROFILES["standard"].timeout
        assert PROFILES["quick"].threads > PROFILES["standard"].threads

    def test_stealth_slowest(self):
        stealth = PROFILES["stealth"]
        for name, p in PROFILES.items():
            if name != "stealth":
                assert stealth.threads <= p.threads
