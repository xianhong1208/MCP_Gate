"""Orchestrator -- docker flag -> docker SDK kwargs conversion tests

_start_locked now uses the docker SDK (replacing the shell-out to the `docker` CLI), which
removes the command injection sink (SAST: Stored Command Injection). Flag sequences validated
by argv_policy are converted by _flags_to_kwargs into containers.run/create kwargs; this file
pins the correctness of that mapping (closed whitelist, unambiguous mapping).
"""
import pytest

from src.orchestrator.manager import _flags_to_kwargs


@pytest.mark.parametrize("flags, expected_kwargs, expected_pull", [
    ([], {}, False),
    (["--rm"], {"auto_remove": True}, False),
    (["-i"], {"stdin_open": True}, False),
    (["-t"], {"tty": True}, False),
    (["-it"], {"stdin_open": True, "tty": True}, False),
    (["--init"], {"init": True}, False),
    (["--rm", "-i", "--init"], {"auto_remove": True, "stdin_open": True, "init": True}, False),
    # Flags with a value: inline and two-token forms are equivalent
    (["--network=bridge"], {"network": "bridge"}, False),
    (["--network", "none"], {"network": "none"}, False),
    (["--memory", "512m"], {"mem_limit": "512m"}, False),
    (["--cpus", "1.5"], {"nano_cpus": 1_500_000_000}, False),
    # --pull always triggers a pre-pull and does not go into kwargs
    (["--pull", "always"], {}, True),
    (["--pull", "missing"], {}, False),
    (["--rm", "--pull", "always"], {"auto_remove": True}, True),
])
def test_flags_to_kwargs(flags, expected_kwargs, expected_pull):
    kwargs, pull_always = _flags_to_kwargs(flags)
    assert kwargs == expected_kwargs
    assert pull_always is expected_pull
