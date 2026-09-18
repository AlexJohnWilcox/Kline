from siem.collectors.syslog import DEFAULT_DROP_PATTERNS, should_ingest

# Real lines, copied from the Gate's logread output.
COLLECTOR_NOISE = (
    "Thu Sep 17 09:06:57 2026 authpriv.notice dropbear[19781]: "
    "Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:uOzf... "
    "from 192.168.10.2:39248"
)
COLLECTOR_EXIT = (
    "Thu Sep 17 07:56:30 2026 authpriv.info dropbear[14976]: "
    "Exit (root) from <192.168.10.2:39248>: Disconnect received"
)
REAL_LOGIN_FROM_EREBUS = (
    "Thu Sep 17 09:06:57 2026 authpriv.notice dropbear[19781]: "
    "Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:uOzf... "
    "from 192.168.10.203:37442"
)
ROAD_ROTATION = (
    "Thu Sep 18 03:11:50 2026 daemon.notice rotate-road: "
    "FAIL US-VA did not carry traffic within 20s; rolling back"
)


def test_the_oracles_own_collector_logins_are_dropped():
    assert should_ingest(COLLECTOR_NOISE, DEFAULT_DROP_PATTERNS) is False
    assert should_ingest(COLLECTOR_EXIT, DEFAULT_DROP_PATTERNS) is False


def test_a_login_from_any_other_host_is_kept():
    """The filter must key on the source address, not on dropbear."""
    assert should_ingest(REAL_LOGIN_FROM_EREBUS, DEFAULT_DROP_PATTERNS) is True


def test_unrelated_gate_lines_are_kept():
    assert should_ingest(ROAD_ROTATION, DEFAULT_DROP_PATTERNS) is True


def test_an_empty_pattern_list_keeps_everything():
    assert should_ingest(COLLECTOR_NOISE, []) is True


def test_a_malformed_pattern_does_not_take_the_collector_down():
    """A bad regex in config must not stop ingestion."""
    assert should_ingest(ROAD_ROTATION, ["*unclosed["]) is True
