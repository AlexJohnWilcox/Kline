import pytest


@pytest.fixture
def sample_syslog_lines():
    return [
        "Mar 22 10:15:32 myhost sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2",
        "Mar 22 10:15:33 myhost sshd[1234]: Accepted publickey for alex from 10.0.0.1 port 22 ssh2",
        "Mar 22 10:16:00 myhost sudo[5678]: alex : TTY=pts/0 ; PWD=/home/alex ; COMMAND=/usr/bin/apt update",
        "Mar 22 10:17:00 myhost kernel: [12345.678] Out of memory: Killed process 999 (python3)",
        "Mar 22 10:18:00 myhost cron[100]: (root) CMD (logrotate /etc/logrotate.conf)",
    ]
