"""Client configuration export (#36): Claude Code, Cursor, VS Code and Codex snippets for MCP servers.

Read-only. Same permission as reading a service (any signed-in console account). Nothing returned here is a
secret: the snippets carry the server URL, and the PAT variant references an environment variable or a
password prompt instead of a token.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from db import get_db
from db.models import AdminUser, Service
from src.adapters import ServiceAdapter, normalize_audience
from src.adapters.exceptions import AdapterError
from src.config import Config
from src.identity import get_current_user
from src.oauth import service as oauth
from src.utils.client_config import CLIENTS, VARIANTS, Server, generate

router = APIRouter(tags=["Services"])

_MEDIA = {"json": "application/json", "toml": "application/toml"}


def _client_url(service: Service) -> Optional[str]:
    """The URL a client connects to: the service's audience (= RFC 8707 resource), as tokens carry it. A client
    sends that URL as `resource`, and MCP Gate resolves it back to this service. An audience that is not an
    http(s) URL cannot be connected to, so the server's own address is used instead."""
    audience = normalize_audience(service.effective_audience)
    if audience and audience.lower().startswith(("http://", "https://")):
        return audience
    return service.get_mcp_url() or None


def _server(service: Service) -> Server:
    scopes = tuple((service.oauth_scopes or "").split())
    return Server(name=service.name, url=_client_url(service), scopes=scopes)


def _check(client: str, variant: str) -> None:
    if client not in CLIENTS:
        raise HTTPException(status_code=422, detail={"error": "client_config.unknown_client",
                                                     "fallback": f"client must be one of: {', '.join(CLIENTS)}"})
    if variant not in VARIANTS:
        raise HTTPException(status_code=422, detail={"error": "client_config.unknown_variant",
                                                     "fallback": f"variant must be one of: {', '.join(VARIANTS)}"})


def _respond(result: dict, download: bool):
    if not download:
        return result
    f = result["file"]
    return Response(content=f["content"], media_type=f"{_MEDIA[f['format']]}; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{f["filename"]}"',
                             "Cache-Control": "no-store"})


def _generate(client: str, variant: str, servers: list[Server], *, pat_service_id: Optional[str]) -> dict:
    base = oauth.issuer()
    pat_page = base + "/tokens/create" + (f"?service_id={pat_service_id}" if pat_service_id else "")
    result = generate(client, variant, servers, issuer=base, pat_page=pat_page)
    result["dcr_auto_approve"] = Config.get_oauth_config().dcr_auto_approve
    return result


@router.get("/api/services/{service_id}/client-config")
async def service_client_config(
    service_id: str,
    client: str = Query(..., description="claude-code | cursor | vscode | codex"),
    variant: str = Query("oauth", description="oauth (sign in through MCP Gate) | pat (personal access token)"),
    download: bool = Query(False, description="Return only the configuration file, as an attachment"),
    db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user),
):
    """Configuration for connecting one MCP server to an MCP client through MCP Gate.

    `file.content` is the JSON / TOML the client reads (`file.path` says where), `commands` the equivalent CLI
    commands where the client has them, `install_links` Cursor's one-click install links. The server URL is the
    service's audience. Answers 409 `client_config.no_url` when the service has neither an audience nor an
    address."""
    _check(client, variant)
    try:
        service = ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise HTTPException(status_code=e.status_code, detail=e.to_detail())
    if not _client_url(service):
        raise HTTPException(status_code=409, detail={"error": "client_config.no_url",
                                                     "fallback": "This server has no address or audience yet"})
    result = _generate(client, variant, [_server(service)], pat_service_id=str(service.id))
    result["requires_auth"] = bool(service.requires_auth)
    return _respond(result, download)


@router.get("/api/client-config")
async def all_client_config(
    client: str = Query(..., description="claude-code | cursor | vscode | codex"),
    variant: str = Query("oauth", description="oauth | pat"),
    download: bool = Query(False, description="Return only the configuration file, as an attachment"),
    db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user),
):
    """One configuration file with every active MCP server the console lists. Servers without an address or
    audience are left out and named in `skipped`."""
    _check(client, variant)
    servers, skipped = [], []
    for s in sorted(ServiceAdapter.get_all(db, include_inactive=False), key=lambda s: (s.name or "").lower()):
        (servers.append(_server(s)) if _client_url(s) else skipped.append(s.name))
    result = _generate(client, variant, servers, pat_service_id=None)
    result["skipped"] = skipped
    return _respond(result, download)
