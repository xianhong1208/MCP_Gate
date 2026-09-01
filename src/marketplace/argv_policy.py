"""Docker argv security policy (single source of truth)

This module defines which tokens may enter the argv of `docker run`, and it is shared
by **two boundaries**:

  1. Write boundary -- DockerSpec in src/marketplace/schema.py:
     validated when the catalog YAML is loaded; a broken entry simply cannot be installed.
  2. Execution boundary -- _start_locked in src/orchestrator/manager.py:
     validated again after image_args / image_command are read from the DB and before argv is built.

Why both boundaries must validate (this is not redundant):

  * This is a **stored** command/argument injection. The threat model includes "the attacker
    can already write to the DB" (SQL injection, leaked DB credentials, internal CRUD misuse).
    That path bypasses the catalog entirely, so validating only at write time is no defence at all.
  * Static analysis (SAST tools) cannot connect "validated before being written to the DB" with
    "read from the DB and used" -- that is an inherent limitation of stored flows. The sanitizer
    must sit between the DB read and the subprocess to actually be on that path.

The core trade-off of the policy: `args` uses a **flag-level** allowlist, not a character-level one.
`-v /:/host`, `--privileged` and `--pid=host` consist entirely of "safe characters", so any character
allowlist lets them through, and so does shlex.quote (quoting handles shell safety, not argv semantics).
Only enumerating the permitted flags makes escape flags "inexpressible".
"""
import re
from typing import Iterable, List

# Flags that take no value. Escape vectors deliberately left out (= always rejected):
#   -v/--volume/--mount  -> mounts the host filesystem
#   --privileged, --cap-add, --device, --security-opt, --userns -> privilege escalation
#   --pid/--ipc/--uts    -> shares host namespaces
#   --entrypoint         -> replaces the image entrypoint
#   -d/--detach          -> the orchestrator decides -i / -d itself; the catalog must not override it
_ALLOWED_BARE_FLAGS = frozenset({"--rm", "-i", "-t", "-it", "--init"})

# Inner commands allowed for BYO (bring-your-own launch command). Deliberately default-deny:
# only runtime launchers that exist in the controlled base image and are spawned by supergateway.
# Arbitrary paths/binaries are not allowed (avoids `bash`, `sh -c`, absolute-path executables, etc.).
_ALLOWED_BYO_COMMANDS = frozenset({"npx", "node", "uvx", "python", "python3"})

# Flags that take exactly one value -> the value format for each flag.
_ALLOWED_VALUE_FLAGS = {
    # host is deliberately not allowed: it removes network isolation and lets the container
    # reach the MCP Center admin API on the host (127.0.0.1) directly.
    "--network": re.compile(r"(bridge|none)"),
    "--pull": re.compile(r"(always|missing|never)"),
    "--memory": re.compile(r"\d+[bkmg]?"),
    "--cpus": re.compile(r"\d+(\.\d+)?"),
}

# docker image name (without tag); optional registry host[:port] prefix.
_IMAGE_RE = re.compile(
    r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
)

# docker's own tag rules.
_TAG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")

# entrypoint args (docker.command) are arguments passed to the *image*, not `docker run` flags,
# so they cannot cause a container escape -- a character allowlist is the appropriate strength here.
_SAFE_TOKEN_RE = re.compile(r"[A-Za-z0-9_.:=/@,+-]+")

# Note: every match below uses `fullmatch`, never `match`. `$` matches before a trailing newline
# at the end of the string, so `match` with `^...$` would still accept a token like "--rm\n".


class ArgvPolicyError(ValueError):
    """A token does not satisfy the docker argv policy.

    Inherits from ValueError so that raising it inside a Pydantic field_validator is converted
    into a ValidationError as usual; in the orchestrator the caller converts it into an OrchestratorError.
    """


def validate_docker_args(tokens: Iterable[str]) -> List[str]:
    """Validate a sequence of `docker run` flags and return the original sequence (for easy chaining).

    The args must be walked as a **sequence**, not checked token by token: docker flags come in
    both `--network=bridge` (single token) and `--network bridge` (two tokens) forms, so deciding
    whether `/:/host` is legitimate requires knowing whether the previous token was `-v`.

    Any flag not on the allowlist is rejected (default-deny), so escape flags such as `-v` and
    `--privileged` are "inexpressible" rather than "filtered out".
    """
    args = list(tokens)
    i = 0
    while i < len(args):
        token = args[i]

        if token in _ALLOWED_BARE_FLAGS:
            i += 1
            continue

        flag, sep, inline_value = token.partition("=")
        value_re = _ALLOWED_VALUE_FLAGS.get(flag)
        if value_re is None:
            raise ArgvPolicyError(
                f"docker flag not allowed: {token!r}. "
                f"Allowed flags: {sorted(_ALLOWED_BARE_FLAGS)} "
                f"+ {sorted(_ALLOWED_VALUE_FLAGS)}"
            )

        if sep:
            # --flag=value form
            value = inline_value
            i += 1
        else:
            # --flag value form
            if i + 1 >= len(args):
                raise ArgvPolicyError(f"docker flag {flag!r} is missing a value")
            value = args[i + 1]
            i += 2

        if not value_re.fullmatch(value):
            raise ArgvPolicyError(
                f"docker flag {flag!r} does not allow this value: {value!r}"
            )

    return args


def validate_command_tokens(tokens: Iterable[str]) -> List[str]:
    """Validate entrypoint args (docker.command) and return the original sequence.

    These tokens never become `docker run` flags, so they cannot cause a container escape;
    we only need to block shell metacharacters and whitespace (whitespace would also break the
    join/split round-trip of image_args, see orchestrator.manager).
    """
    command = list(tokens)
    for token in command:
        if not isinstance(token, str) or not _SAFE_TOKEN_RE.fullmatch(token):
            raise ArgvPolicyError(f"entrypoint arg contains unsafe characters: {token!r}")
    return command


def validate_byo_command(command: str) -> str:
    """Validate the BYO inner command (allowlist, default-deny)."""
    if command not in _ALLOWED_BYO_COMMANDS:
        raise ArgvPolicyError(
            f"BYO command not allowed: {command!r} "
            f"(only {sorted(_ALLOWED_BYO_COMMANDS)} are allowed)"
        )
    return command


def validate_byo_launch(command: str, args: Iterable[str]) -> tuple:
    """Validate a BYO inner launch command: command allowlist + args character allowlist.

    args reuse the character allowlist of `validate_command_tokens` (`_SAFE_TOKEN_RE`), which blocks
    shell metacharacters (`; | & $ ()` and backticks) and whitespace -- even if supergateway inside the
    container parses the inner command with a shell, nothing can be injected. The args are ultimately
    passed to the docker SDK as a **list** (no shell); the character allowlist is extra defence in depth.

    Returns:
        (command, validated_args_list)
    """
    cmd = validate_byo_command(command)
    validated_args = validate_command_tokens(args)
    return cmd, validated_args


def validate_image_name(image: str) -> str:
    """Validate an image name (without tag)."""
    if not _IMAGE_RE.fullmatch(image):
        raise ArgvPolicyError(f"not a valid docker image name: {image!r}")
    return image


def validate_tag(tag: str) -> str:
    """Validate an image tag."""
    if not _TAG_RE.fullmatch(tag):
        raise ArgvPolicyError(f"not a valid docker image tag: {tag!r}")
    return tag


def validate_image_ref(image_ref: str) -> str:
    """Validate a full `image[:tag]` reference read back from the DB.

    Split at the last ':', but treat it as the tag separator only when that ':' comes after the
    last '/' -- otherwise the port in `localhost:5000/img` would be mistaken for a tag.
    """
    head, sep, tail = image_ref.rpartition(":")
    if sep and "/" not in tail:
        validate_image_name(head)
        validate_tag(tail)
    else:
        validate_image_name(image_ref)
    return image_ref
