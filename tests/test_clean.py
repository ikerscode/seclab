from pipeline import clean


def test_text_strips_control_and_escape_sequences():
    assert clean.text("root\x1b[2J\x07 pass\nword") == "root [2J pass word"
    assert clean.text("a‮b") == "a b"          # right-to-left override
    assert clean.text("x" * 500, 10) == "x" * 10
    assert clean.text(5) is None and clean.text(None) is None and clean.text("   ") is None


def test_numbers_reject_bool_nan_and_strings():
    assert clean.number(True) is None
    assert clean.number(float("nan")) is None
    assert clean.number(float("inf")) is None
    assert clean.number("5") is None
    assert clean.count(-1) is None and clean.count(3) == 3
    assert clean.timestamp(1794622631.8) == 1794622631.8
    assert clean.timestamp(12) is None and clean.timestamp(4e9) is None


def test_ip_rules():
    assert clean.ip("203.0.113.5") == "203.0.113.5"
    assert clean.ip(" 203.0.113.5\n") == "203.0.113.5"
    assert clean.ip("1.2.3.4; rm -rf /") is None
    assert clean.ip("x" * 100) is None
    assert clean.external_ip("127.0.0.1") is None
    assert clean.external_ip("10.1.2.3") is None
    assert clean.external_ip("192.168.10.37") is None
    assert clean.external_ip("fe80::1") is None
    assert clean.external_ip("198.51.100.23") == "198.51.100.23"   # documentation range kept on purpose
    assert clean.external_ip("8.8.8.8") == "8.8.8.8"


def test_url_is_parsed_not_fetched_and_odd_schemes_are_refused():
    u = clean.url("http://198.51.100.23/bins.sh")
    assert u == {"url": "http://198.51.100.23/bins.sh", "scheme": "http", "host": "198.51.100.23",
                 "host_ip": "198.51.100.23", "host_domain": None}
    assert clean.url("tftp://198.51.100.23/mips")["host"] == "198.51.100.23"
    assert clean.url("HTTP://Evil.Example.COM/x")["host_domain"] == "evil.example.com"
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "data:text/html,<script>", "http:///nohost",
                "http://exa mple.com/", "http://" + "a" * 400 + ".com/", "http://x.com/\r\nSet-Cookie: a",
                "http://[::1", 42, None, "http://xn--é.com/"):
        assert clean.url(bad) is None, bad


def test_domain_host_technique_hash():
    assert clean.domain("Telemetry-Sync.C2.test.") == "telemetry-sync.c2.test"
    assert clean.domain("bad_domain.com") is None
    assert clean.domain("<script>.com") is None
    assert clean.host_name("CORP-WS-37") == "CORP-WS-37"
    assert clean.host_name("a b") is None and clean.host_name("x" * 65) is None
    assert clean.technique("t1110.001") == "T1110.001"
    assert clean.technique("T1110; drop") is None
    assert clean.techniques("T0855,T0836, junk") == ["T0855", "T0836"]
    assert clean.sha256("A" * 64) == "a" * 64 and clean.sha256("g" * 64) is None
    assert clean.tags(["tor-exit", "in-drop", "<b>", 5]) == ["tor-exit", "in-drop"]
