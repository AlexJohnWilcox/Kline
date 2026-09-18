"""The Gate runs dropbear, not sshd, and words its auth lines differently."""

from siem.collectors.syslog import (
    AUTH_PROCESSES,
    _extract_auth_fields,
    _split_source,
)


def test_dropbear_is_an_auth_process():
    # Without this the category stays SYSTEM and _extract_auth_fields
    # is never called at all.
    assert "dropbear" in AUTH_PROCESSES


def test_split_source_splits_ipv4_and_port():
    assert _split_source("192.168.10.203:53800") == ("192.168.10.203", 53800)


def test_split_source_leaves_ipv6_alone():
    # More than one colon is ambiguous; better a whole address than a
    # silently truncated one.
    assert _split_source("2001:db8::1:53800") == ("2001:db8::1:53800", None)


def test_split_source_leaves_a_bare_host_alone():
    assert _split_source("192.168.10.203") == ("192.168.10.203", None)


def test_bad_password_attempt():
    parsed = {}
    _extract_auth_fields(
        "Bad password attempt for 'root' from 192.168.10.203:53800", parsed
    )
    assert parsed["action"] == "failed_login"
    assert parsed["user"] == "root"
    assert parsed["src_ip"] == "192.168.10.203"
    assert parsed["src_port"] == 53800


def test_bad_pam_password_attempt():
    parsed = {}
    _extract_auth_fields(
        "Bad PAM password attempt for 'admin' from 10.0.0.9:2222", parsed
    )
    assert parsed["action"] == "failed_login"
    assert parsed["user"] == "admin"


def test_nonexistent_user_has_no_username():
    parsed = {}
    _extract_auth_fields(
        "Login attempt for nonexistent user from 192.168.10.203:53786", parsed
    )
    assert parsed["action"] == "failed_login"
    assert parsed["src_ip"] == "192.168.10.203"
    assert "user" not in parsed


def test_pubkey_auth_succeeded():
    parsed = {}
    _extract_auth_fields(
        "Pubkey auth succeeded for 'root' with ssh-ed25519 key "
        "SHA256:uOzfIMm7JlbJip3ULsgCYcLx3AFAxstptcf4+tk3FKE "
        "from 192.168.10.203:53816",
        parsed,
    )
    assert parsed["action"] == "successful_login"
    assert parsed["user"] == "root"
    assert parsed["auth_method"] == "pubkey"
    # The key fingerprint also contains "from"-adjacent noise; the peer
    # must still come from the END of the line.
    assert parsed["src_ip"] == "192.168.10.203"


def test_password_auth_succeeded():
    parsed = {}
    _extract_auth_fields(
        "Password auth succeeded for 'alex' from 192.168.10.145:41000", parsed
    )
    assert parsed["action"] == "successful_login"
    assert parsed["auth_method"] == "password"


def test_sshd_lines_still_work():
    # The existing sshd branches must not regress.
    parsed = {}
    _extract_auth_fields(
        "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", parsed
    )
    assert parsed["action"] == "failed_login"
    assert parsed["user"] == "admin"
    assert parsed["src_ip"] == "1.2.3.4"


def test_brute_force_rule_queries_a_field_that_exists():
    """The rule read parsed.service for months; nothing ever wrote it."""
    from pathlib import Path

    import yaml

    from siem.detection.engine import build_rule_query
    from siem.models.rule import DetectionRule

    repo_root = Path(__file__).resolve().parent.parent
    raw = yaml.safe_load((repo_root / "rules" / "brute_force_ssh.yml").read_text())
    query = build_rule_query(DetectionRule(**raw))

    rendered = repr(query)
    assert "parsed.service" not in rendered
    assert "parsed.process" in rendered
    assert "parsed.action" in rendered
