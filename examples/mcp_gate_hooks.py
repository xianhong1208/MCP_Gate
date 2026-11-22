"""MCPGateVerifier: FastMCP's JWTVerifier plus MCP Gate's revocation feed and usage reports.

A plain ``JWTVerifier`` checks tokens offline against the JWKS, which is fast but has two gaps: a token the
owner revoked keeps working until it expires, and MCP Gate never learns that the token was used. This
verifier closes both without introspecting every request:

* every ``poll_interval`` seconds it fetches ``POST <issuer>/oauth/revoked`` (revoked, not yet expired
  tokens) and rejects those jtis locally;
* every ``flush_interval`` seconds it reports how often each jti was verified to
  ``POST <issuer>/oauth/usage``, which feeds the token's "last used" and the dashboard statistics.

Both endpoints require a *confidential* client registered in the MCP Gate console (OAuth Clients ->
Register trusted client) and bound to this server as its resource server (``resource_service_id`` when
registering it, or ``PUT /api/oauth/clients/{client_id}/resource-server``); the feed and usage reports then
cover only tokens whose audience is this server. Give the verifier either that client's secret or, for ``private_key_jwt``
clients, the private key PEM and its kid.

Usage::

    from fastmcp.server.auth import RemoteAuthProvider
    from mcp_gate_hooks import MCPGateVerifier

    auth = RemoteAuthProvider(
        token_verifier=MCPGateVerifier(
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
            issuer="https://auth.example.com",
            audience="https://mcp.example.com/mcp",
            client_id="mcpc_...", client_secret="...",
        ),
        authorization_servers=["https://auth.example.com"],
        base_url="https://mcp.example.com",
    )

MCPGateToolPinning is a FastMCP middleware that enforces MCP Gate's tool approvals on this server (#33): every tool
definition is pinned by a hash, and only definitions an admin approved in the console are listed by ``tools/list``
or run by ``tools/call``. A new or changed tool is hidden at once and reported to MCP Gate, where it waits in the
console as pending. It reads ``POST <issuer>/oauth/policy`` with the verifier's client::

    verifier = MCPGateVerifier(...)                       # as above
    mcp = FastMCP(name="demo", auth=RemoteAuthProvider(token_verifier=verifier, ...),
                  middleware=[MCPGateToolPinning(verifier, cache_file="mcp_gate_policy.json")])

Copy this single file next to your server; it needs only ``fastmcp`` and ``httpx`` (``pyjwt`` and
``cryptography`` as well when using ``private_key_pem``).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
import time
import uuid
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

import httpx
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.middleware import Middleware

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
logger = logging.getLogger("mcp_gate_hooks")


class MCPGateVerifier(JWTVerifier):
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        kid: Optional[str] = None,
        assertion_alg: str = "RS256",
        poll_interval: float = 15.0,
        flush_interval: float = 30.0,
        http_client: Optional[httpx.AsyncClient] = None,
        **jwt_verifier_kwargs: Any,
    ):
        if not client_secret and not private_key_pem:
            raise ValueError("MCPGateVerifier needs client_secret or private_key_pem")
        if not jwt_verifier_kwargs.get("issuer") or isinstance(jwt_verifier_kwargs["issuer"], list):
            raise ValueError("MCPGateVerifier needs a single issuer (the MCP Gate URL)")
        super().__init__(http_client=http_client, **jwt_verifier_kwargs)
        self.center = str(jwt_verifier_kwargs["issuer"]).rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key_pem = private_key_pem
        self.kid = kid
        self.assertion_alg = assertion_alg
        self.poll_interval = poll_interval
        self.flush_interval = flush_interval
        self._http = http_client or httpx.AsyncClient(timeout=10.0)
        self._revoked: dict[str, int] = {}       # jti -> exp
        self._pending: dict[str, list] = {}      # jti -> [count, last_seen]
        self._last_poll: Optional[int] = None
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ verification
    async def verify_token(self, token: str):
        self._ensure_running()
        result = await super().verify_token(token)
        if result is None:
            return None
        if (result.claims or {}).get("token_use") != "access":
            # Only access tokens authorize requests. MCP Gate's refresh tokens name its token endpoint as their
            # audience, but refresh tokens from releases before 1.2 carried this server's audience.
            logger.info("Bearer token rejected for client %s: not an access token", result.client_id)
            return None
        jti = (result.claims or {}).get("jti")
        if jti and jti in self._revoked:
            logger.info("Bearer token rejected for client %s: revoked (jti %s)", result.client_id, jti)
            return None
        if jti:
            entry = self._pending.setdefault(jti, [0, 0])
            entry[0] += 1
            entry[1] = int(time.time())
        return result

    # ------------------------------------------------------------------ background sync
    def _ensure_running(self) -> None:
        if self._task is None or self._task.done():
            try:
                self._task = asyncio.get_running_loop().create_task(self._run())
            except RuntimeError:
                pass  # no loop yet (verifier constructed at import time); the first request will start it

    async def _run(self) -> None:
        next_poll = 0.0
        next_flush = time.monotonic() + self.flush_interval
        while True:
            now = time.monotonic()
            # Schedule the next attempt before trying: a failure (MCP Gate unreachable) waits one interval
            # instead of retrying, and logging, every half second
            if now >= next_poll:
                next_poll = now + self.poll_interval
                try:
                    await self.poll_revoked()
                except Exception as e:  # keep the loop alive; the next interval retries
                    logger.warning("MCP Gate revocation feed poll failed: %s", e)
            if now >= next_flush:
                next_flush = now + self.flush_interval
                try:
                    await self.flush_usage()
                except Exception as e:
                    logger.warning("MCP Gate usage report failed: %s", e)
            await asyncio.sleep(max(0.5, min(next_poll, next_flush) - time.monotonic()))

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
        try:
            await self.flush_usage()
        finally:
            await self._http.aclose()

    async def sync_once(self) -> None:
        """Poll the feed and flush usage right now (tests, shutdown hooks)."""
        await self.poll_revoked()
        await self.flush_usage()

    async def poll_revoked(self) -> None:
        form = {"since": str(self._last_poll)} if self._last_poll is not None else {}
        data = await self._post("/oauth/revoked", form)
        now = int(data.get("now", time.time()))
        for item in data.get("revoked", []):
            self._revoked[item["jti"]] = int(item.get("exp", now + 3600))
        # forget entries once the token would have expired anyway
        for jti in [j for j, exp in self._revoked.items() if exp < now]:
            self._revoked.pop(jti, None)
        # overlap the window by a few seconds so a revocation racing the previous poll is not missed
        self._last_poll = max(0, now - 5)

    async def flush_usage(self) -> None:
        async with self._lock:
            batch, self._pending = self._pending, {}
        if not batch:
            return
        events = [{"jti": jti, "count": count, "last_seen": last_seen} for jti, (count, last_seen) in batch.items()]
        try:
            await self._post("/oauth/usage", {"events": json.dumps(events)})
        except Exception:
            async with self._lock:  # put the batch back so nothing is lost on a transient failure
                for jti, (count, last_seen) in batch.items():
                    entry = self._pending.setdefault(jti, [0, 0])
                    entry[0] += count
                    entry[1] = max(entry[1], last_seen)
            raise

    # ------------------------------------------------------------------ client authentication
    def _auth_fields(self) -> dict:
        if self.private_key_pem:
            import jwt  # pyjwt, only needed for private_key_jwt clients

            now = int(time.time())
            assertion = jwt.encode(
                {"iss": self.client_id, "sub": self.client_id, "aud": f"{self.center}/oauth/token",
                 "iat": now, "exp": now + 60, "jti": uuid.uuid4().hex},
                self.private_key_pem, algorithm=self.assertion_alg, headers={"kid": self.kid} if self.kid else None,
            )
            return {"client_assertion_type": ASSERTION_TYPE, "client_assertion": assertion}
        return {"client_id": self.client_id, "client_secret": self.client_secret}

    async def _post(self, path: str, form: dict) -> dict:
        r = await self._http.post(f"{self.center}{path}", data={**self._auth_fields(), **form})
        r.raise_for_status()
        return r.json()


# ====================================================================== tool pinning (#33)
# A copy of MCP Gate's pin definition (src/tool_pinning/hashing.py, version 1), so this file needs nothing from MCP
# Gate's package. It must produce the same digest byte for byte; MCP Gate's tests check it against the golden vectors.
#
# The pin of a tool is the SHA-256 (lowercase hex) of the UTF-8 encoding of a canonical JSON text: of the tool as
# tools/list returns it, keep only the six fields below, leave out any that is absent or null, sort keys at every
# depth, no whitespace, non-ASCII written as itself, NaN / Infinity refused, array order kept.
HASH_VERSION = 1
HASHED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def canonical_tool(tool: Mapping[str, Any]) -> dict:
    return {key: tool[key] for key in HASHED_FIELDS if tool.get(key) is not None}


def canonical_json(tool: Mapping[str, Any]) -> str:
    return json.dumps(canonical_tool(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def tool_hash(tool: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(tool).encode("utf-8")).hexdigest()


def mcp_tool_dict(tool: Any) -> dict:
    """A FastMCP tool as tools/list sends it (MCP field names, unset fields left out): the form that is hashed."""
    return tool.to_mcp_tool(name=tool.name).model_dump(mode="json", by_alias=True, exclude_none=True)


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
CACHE_FORMAT = 1
NOT_AVAILABLE = "Tool {name!r} is not available on this server."
PROBE_CLAIM = "mcp_gate_probe"  # set by MCP Gate on the tokens of its own tools/list requests

try:  # which version of a versioned tool a call asks for (FastMCP's own helper; absent in other releases)
    from fastmcp.server.middleware.authorization import _requested_version
except ImportError:  # pragma: no cover - depends on the FastMCP release
    _requested_version = None


def _same_audience(a: Any, b: Any) -> bool:
    """Audiences compared the way MCP Gate stores them: scheme and host case-insensitive, no trailing slash."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    pa, pb = urlsplit(a.strip()), urlsplit(b.strip())
    return (pa.scheme.lower(), pa.netloc.lower(), pa.path.rstrip("/"), pa.query) == \
        (pb.scheme.lower(), pb.netloc.lower(), pb.path.rstrip("/"), pb.query)


class PolicyUnavailable(Exception):
    """The feed answered with something this middleware cannot use (wrong server, another hash version)."""


class MCPGateToolPinning(Middleware):
    """Hide and refuse every tool whose definition MCP Gate has not approved.

    On ``tools/list`` it hashes the server's own tools and lists only the approved ones; on ``tools/call`` it hashes
    the tool being called and refuses it unless approved, with the same error as for a tool that does not exist
    (the reason goes to this server's log, not to the caller). Definitions MCP Gate does not know yet are reported
    to ``POST /oauth/tool-report`` right away, so they appear as pending in the console.

    The approved list comes from ``POST /oauth/policy``, polled every ``poll_interval`` seconds with the
    verifier's resource-server client. When MCP Gate cannot be reached, the last list received keeps being used;
    it is also written to ``cache_file`` (atomically, mode 600) so a restart without MCP Gate keeps it. A cache
    written for another issuer, audience or hash version, or older than ``max_cache_age`` seconds (when set), is
    ignored. Set ``cache_file=None`` to keep the list in memory only.

    Before any list was received (no answer from the feed yet, no usable cache) every tool is hidden: closed by
    default, with one log line saying why. ``fail_open=True`` lists and runs every tool until the first list
    arrives instead.
    """

    def __init__(
        self,
        verifier: "MCPGateVerifier",
        *,
        cache_file: Optional[str] = "mcp_gate_policy.json",
        fail_open: bool = False,
        poll_interval: float = 15.0,
        max_cache_age: Optional[float] = None,
        report: bool = True,
    ):
        self.verifier = verifier
        self.audience = str(verifier.audience if not isinstance(verifier.audience, list) else verifier.audience[0])
        self.cache_file = cache_file
        self.fail_open = fail_open
        self.poll_interval = poll_interval
        self.max_cache_age = max_cache_age
        self.report_enabled = report
        self._policy: Optional[dict] = None       # {"approved", "pending", "rejected": set, "etag", "received_at"}
        self._policy_source: Optional[str] = None  # "feed" | "cache"
        self._to_report: dict[str, dict] = {}     # hash -> definition, waiting to be sent
        self._reported: set[str] = set()          # hashes MCP Gate already acknowledged
        self._task: Optional[asyncio.Task] = None
        self._wake: Optional[asyncio.Event] = None
        self._first_poll_done = False
        self._closed_logged = False
        self._load_cache()

    # ------------------------------------------------------------------ state
    @property
    def state(self) -> str:
        """``feed`` (a list from MCP Gate), ``cache`` (the cached list; MCP Gate not answered yet), ``open`` (no
        list, fail_open) or ``closed`` (no list: every tool hidden)."""
        if self._policy is not None:
            return self._policy_source or "feed"
        return "open" if self.fail_open else "closed"

    def is_allowed(self, digest: str) -> bool:
        if self._policy is None:
            return self.fail_open
        return digest in self._policy["approved"]

    def _is_known(self, digest: str) -> bool:
        if digest in self._reported:
            return True
        policy = self._policy
        return policy is not None and any(digest in policy[k] for k in ("approved", "pending", "rejected"))

    def _note(self, tool: Any) -> Optional[str]:
        """Hash one tool and queue it for a report when MCP Gate does not know it. Returns the hash (None when the
        definition cannot be hashed, which is then never allowed)."""
        try:
            definition = mcp_tool_dict(tool)
            digest = tool_hash(definition)
        except (TypeError, ValueError) as e:
            logger.warning("Tool %r cannot be pinned (%s); it stays hidden", getattr(tool, "name", "?"), e)
            return None
        if self.report_enabled and not self._is_known(digest) and digest not in self._to_report:
            self._to_report[digest] = definition
            if self._wake is not None:
                self._wake.set()
        return digest

    def _log_closed(self) -> None:
        if self._policy is None and not self.fail_open and not self._closed_logged:
            self._closed_logged = True
            logger.warning(
                "MCP Gate tool pinning: no approved tool list yet (the policy feed at %s/oauth/policy has not "
                "answered and there is no usable cache at %s), so every tool is hidden until it does "
                "(closed by default; fail_open=True lists them instead)", self.verifier.center, self.cache_file)

    # ------------------------------------------------------------------ middleware hooks
    @staticmethod
    def _is_mcp_gate_probe() -> bool:
        """A short-lived token MCP Gate signed for its own tools/list (scanner, refresh, "Inspect as"): it is shown
        every tool, approved or not, so the console records the server's real list. Calls stay refused."""
        try:
            from fastmcp.server.dependencies import get_access_token

            token = get_access_token()
        except Exception:
            return False
        return bool(token is not None and (token.claims or {}).get(PROBE_CLAIM) is True)

    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        await self._ensure_started()
        if self._is_mcp_gate_probe():
            for tool in tools:
                self._note(tool)
            return tools
        self._log_closed()
        visible = []
        for tool in tools:
            digest = self._note(tool)
            if digest is not None and self.is_allowed(digest):
                visible.append(tool)
        return visible

    async def on_call_tool(self, context, call_next):
        await self._ensure_started()
        self._log_closed()
        name = context.message.name
        fastmcp_context = context.fastmcp_context
        if fastmcp_context is None:
            raise ToolError(NOT_AVAILABLE.format(name=name))
        meta = getattr(context.message, "meta", None)
        if _requested_version is not None:
            version = _requested_version(meta)
        elif meta and isinstance(meta, Mapping) and meta.get("fastmcp"):
            raise ToolError(NOT_AVAILABLE.format(name=name))  # cannot tell which version would run
        else:
            version = None
        tool = await fastmcp_context.fastmcp.get_tool(name, version=version)
        if tool is None:
            raise ToolError(NOT_AVAILABLE.format(name=name))
        digest = self._note(tool)
        if digest is None or not self.is_allowed(digest):
            logger.warning("Refused a call to tool %r: its definition (%s) is not approved in MCP Gate (%s)",
                           name, (digest or "unhashable")[:12], self.state)
            raise ToolError(NOT_AVAILABLE.format(name=name))
        return await call_next(context)

    # ------------------------------------------------------------------ background sync
    async def _ensure_started(self) -> None:
        if not self._first_poll_done:
            # The first request waits for one answer (or failure), so a server that just started with MCP Gate up
            # serves its approved tools at once instead of hiding them until the first background poll
            self._first_poll_done = True
            try:
                await self.poll_policy()
            except Exception as e:
                logger.warning("MCP Gate tool policy feed unreachable (%s); using %s", e, self.state)
        if self._task is None or self._task.done():
            self._wake = asyncio.Event()
            if self._to_report:
                self._wake.set()
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self) -> None:
        next_poll = time.monotonic() + self.poll_interval
        while True:
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=max(0.5, next_poll - time.monotonic()))
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            try:
                if self._to_report:
                    await self.flush_reports()
                    next_poll = 0.0  # a report may have changed the policy: read it now
                if time.monotonic() >= next_poll:
                    await self.poll_policy()
                    next_poll = time.monotonic() + self.poll_interval
            except Exception as e:  # keep the loop alive; the next tick retries
                logger.warning("MCP Gate tool policy sync failed: %s", e)
                next_poll = time.monotonic() + self.poll_interval

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def sync_once(self) -> None:
        """Send pending reports and read the feed right now (tests, startup hooks)."""
        await self.flush_reports()
        await self.poll_policy()

    async def poll_policy(self) -> None:
        form = {"etag": self._policy["etag"]} if self._policy is not None and self._policy_source == "feed" else {}
        data = await self.verifier._post("/oauth/policy", form)
        if data.get("unchanged") and self._policy is not None and self._policy_source == "feed":
            return
        policy = self._parse(data, origin="feed")
        was_closed = self._policy is None
        self._policy, self._policy_source = policy, "feed"
        self._reported -= policy["approved"] | policy["pending"] | policy["rejected"]
        if was_closed:
            self._closed_logged = False
            logger.info("MCP Gate tool policy received: %d approved definition(s)", len(policy["approved"]))
        self._write_cache()

    async def flush_reports(self) -> None:
        if not self._to_report:
            return
        batch = dict(list(self._to_report.items())[:200])
        tools = [{**definition, "hash": digest} for digest, definition in batch.items()]
        data = await self.verifier._post("/oauth/tool-report", {"tools": json.dumps(tools, ensure_ascii=False)})
        for digest in batch:
            self._to_report.pop(digest, None)
        self._reported.update(item["hash"] for item in data.get("recorded", []) if isinstance(item, dict))
        for name in data.get("hash_mismatch", []):
            logger.warning("MCP Gate hashes tool %r differently: this file's pin definition is out of date", name)
        for item in data.get("invalid", []):
            logger.warning("MCP Gate refused the definition of tool %r: %s", item.get("name"), item.get("reason"))

    # ------------------------------------------------------------------ parsing and the cache file
    def _parse(self, data: Any, *, origin: str) -> dict:
        if not isinstance(data, dict):
            raise PolicyUnavailable(f"{origin}: not a JSON object")
        if data.get("hash_version") != HASH_VERSION:
            raise PolicyUnavailable(f"{origin}: hash version {data.get('hash_version')!r}, this file pins with "
                                    f"version {HASH_VERSION}; update mcp_gate_hooks.py")
        if not _same_audience(data.get("audience"), self.audience):
            raise PolicyUnavailable(f"{origin}: written for audience {data.get('audience')!r}, "
                                    f"this server is {self.audience!r}")
        tools = data.get("tools") if origin == "feed" else data
        if not isinstance(tools, dict):
            raise PolicyUnavailable(f"{origin}: no tool lists")
        lists = {}
        for key in ("approved", "pending", "rejected"):
            values = tools.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) and _HEX64.match(v) for v in values):
                raise PolicyUnavailable(f"{origin}: {key} is not a list of hashes")
            lists[key] = set(values)
        etag = data.get("etag")
        received = data.get("received_at") if origin == "cache" else time.time()
        return {**lists, "etag": etag if isinstance(etag, str) else None,
                "received_at": float(received) if isinstance(received, (int, float)) else 0.0}

    def _load_cache(self) -> None:
        if not self.cache_file or not os.path.exists(self.cache_file):
            return
        try:
            with open(self.cache_file, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or data.get("format") != CACHE_FORMAT:
                raise PolicyUnavailable("cache: unknown format")
            if str(data.get("issuer", "")).rstrip("/") != self.verifier.center:
                raise PolicyUnavailable(f"cache: written for issuer {data.get('issuer')!r}")
            policy = self._parse(data, origin="cache")
            if self.max_cache_age is not None and time.time() - policy["received_at"] > self.max_cache_age:
                raise PolicyUnavailable("cache: older than max_cache_age")
        except (OSError, ValueError, PolicyUnavailable) as e:
            logger.warning("Ignoring the MCP Gate tool policy cache %s: %s", self.cache_file, e)
            return
        self._policy, self._policy_source = policy, "cache"
        self._policy["etag"] = None  # never send a cached etag: the feed answers in full once
        logger.info("MCP Gate tool policy loaded from %s: %d approved definition(s)", self.cache_file,
                    len(policy["approved"]))

    def _write_cache(self) -> None:
        """Replace the cache file atomically: write a private temporary file in the same directory, fsync, rename."""
        if not self.cache_file or self._policy is None:
            return
        policy = self._policy
        data = {"format": CACHE_FORMAT, "hash_version": HASH_VERSION, "issuer": self.verifier.center,
                "audience": self.audience, "etag": policy["etag"], "received_at": policy["received_at"],
                "approved": sorted(policy["approved"]), "pending": sorted(policy["pending"]),
                "rejected": sorted(policy["rejected"])}
        directory = os.path.dirname(os.path.abspath(self.cache_file))
        fd, tmp = tempfile.mkstemp(prefix=".mcp_gate_policy.", suffix=".tmp", dir=directory)  # mode 600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.cache_file)
        except OSError as e:
            logger.warning("Could not write the MCP Gate tool policy cache %s: %s", self.cache_file, e)
            try:
                os.unlink(tmp)
            except OSError:
                pass
