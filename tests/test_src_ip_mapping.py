"""parsed.src_ip must accept every value the parsers can emit.

It was mapped `ip`, which is strict: Elasticsearch rejects the *entire
document* when the value will not parse as an address. Five code paths
write the field, all from bare regex captures and none validated, and the
shipped parsers demonstrably produce non-addresses -- _split_source
deliberately declines to split IPv6 (so the peer arrives with its port
glued on), and sshd with UseDNS writes hostnames or "UNKNOWN".

ignore_malformed would not do: it drops the field silently, which is the
same shape of silent nothing. `ip` loses the document, ignore_malformed
loses the field, keyword loses neither.
"""

import ipaddress

from siem.collectors.syslog import parse_syslog_line
from siem.storage.indices import EVENT_INDEX_TEMPLATE

PARSED = EVENT_INDEX_TEMPLATE["template"]["mappings"]["properties"]["parsed"]["properties"]

# Real shapes the parsers emit, each one rejected by an `ip` mapping.
NOT_ADDRESSES = ("2001:db8::1:53800", "gate.lan", "UNKNOWN")


def test_src_ip_is_keyword_not_ip():
    assert PARSED["src_ip"] == {"type": "keyword"}


def test_dst_ip_is_mapped_the_same_way_as_src_ip():
    """They are written side by side from one regex in network.py; leaving
    dst_ip dynamic made two adjacent fields of a kind behave differently."""
    assert PARSED["dst_ip"] == PARSED["src_ip"]


def test_ignore_malformed_was_not_used_instead():
    assert "ignore_malformed" not in PARSED["src_ip"]


def test_the_values_the_parser_emits_are_not_all_addresses():
    """The premise, asserted rather than assumed."""
    for value in NOT_ADDRESSES:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        raise AssertionError(f"{value!r} parses as an IP, so it proves nothing")


def test_an_ipv6_dropbear_peer_reaches_src_ip_with_its_port_attached():
    """_split_source declines to split IPv6 on purpose, so the value stored
    is by construction never a valid address."""
    line = (
        "Sep 18 17:18:17 gate dropbear[1]: Bad password attempt for 'root' "
        "from 2001:db8::1:53800"
    )
    event = parse_syslog_line(line)

    assert event.parsed["src_ip"] == "2001:db8::1:53800"
    assert "src_port" not in event.parsed


def test_a_resolved_hostname_reaches_src_ip():
    """sshd with UseDNS yes writes a name where an address would go."""
    line = "Sep 18 17:18:17 erebus sshd[1]: Failed password for root from gate.lan"
    event = parse_syslog_line(line)

    assert event.parsed["src_ip"] == "gate.lan"
