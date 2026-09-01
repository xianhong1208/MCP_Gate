"""Marketplace + Managed MCP API routes

Endpoints:
  GET  /api/marketplace                   List all catalog entries (with installed status)
  GET  /api/marketplace/{catalog_id}      Catalog details (used by the frontend install form)
  POST /api/managed                       Install from the catalog + (optionally) start immediately
  GET  /api/managed                       List installed Managed MCPs
  GET  /api/managed/progress              Current stage of in-flight long operations (for frontend polling)
  GET  /api/managed/{id}                  Details of a single Managed MCP
  PUT  /api/managed/{id}/env-vars         Update env vars (auto-restarts while running)
  POST /api/managed/{id}/start            Start
  POST /api/managed/{id}/stop             Stop
  DELETE /api/managed/{id}                Uninstall (stop + delete row + delete Service)

All endpoints require login (session).

Single-instance rule: currently only one process is allowed per catalog_id (checked at install time).
To allow multiple instances, simply remove the 409 check inside install.
"""

from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from db import get_db
from src.adapters import BYODefinitionAdapter, ManagedMcpProcessAdapter
from src.adapters.exceptions import AdapterError
from db.models import AdminUser
from src.api.schemas import (
    ByoCreateRequest,
    ByoDefinitionInfo,
    ByoDeployRequest,
    ByoListResponse,
    ManagedActionResponse,
    ManagedInstallRequest,
    ManagedListResponse,
    ManagedProgressItem,
    ManagedProgressResponse,
    MarketplaceImageInstallResponse,
    ManagedProcessInfo,
    ManagedUpdateEnvRequest,
    MarketplaceCatalogInfo,
    MarketplaceDockerInfo,
    MarketplaceEnvVarInfo,
    MarketplaceListResponse,
)
from src.audit import (
    ActorType,
    AuditAction,
    AuditService,
    AuditStatus,
    ResourceType,
)
from src.identity import get_current_user
from src.logging import get_logger
from src.marketplace.loader import get_catalog_loader
from src.marketplace.schema import CatalogEntry
from src.orchestrator.launch_spec import MCP_RUNTIME_IMAGE, user_source_id
from src.orchestrator.manager import OrchestratorError, get_orchestrator
from src.orchestrator.progress import catalog_key, get_progress_registry

logger = get_logger("api.managed")

router = APIRouter()


def _adapter_http_exc(e: AdapterError) -> HTTPException:
    """AdapterError -> HTTPException (detail format of the managed routes: params is always present)."""
    return HTTPException(
        status_code=e.status_code,
        detail={"error": e.code, "params": e.params, "fallback": e.fallback},
    )


# ---------- Helpers ----------

def _catalog_to_info(
    db: Session, entry: CatalogEntry
) -> MarketplaceCatalogInfo:
    """Convert a CatalogEntry into an API response object, annotated with installed / image status"""
    installed_processes = ManagedMcpProcessAdapter.list_all(db, catalog_id=entry.id)
    installed = bool(installed_processes)
    installed_id = str(installed_processes[0].id) if installed_processes else None

    # Three offline-install states: whether the image is loaded (docker SDK), whether the tar is in place
    image_ref = f"{entry.docker.image}:{entry.docker.tag}"
    try:
        image_installed = get_orchestrator().image_exists(image_ref)
    except Exception:
        # When the docker daemon is unreachable, do not block the listing; show the status as not installed
        image_installed = False
    tar_path = get_catalog_loader().image_tar_path(entry)

    return MarketplaceCatalogInfo(
        image_installed=image_installed,
        image_tar_present=tar_path.is_file(),
        image_tar_name=entry.image_tar_name(),
        id=entry.id,
        name=entry.name,
        description=entry.description,
        category=entry.category,
        icon=entry.icon,
        docker=MarketplaceDockerInfo(
            image=entry.docker.image,
            tag=entry.docker.tag,
            args=entry.docker.args,
        ),
        env_vars=[
            MarketplaceEnvVarInfo(
                name=ev.name, label=ev.label, help=ev.help,
                required=ev.required, secret=ev.secret, default=ev.default,
                pattern=ev.pattern, error_message=ev.error_message,
            )
            for ev in entry.env_vars
        ],
        docs_url=entry.docs_url,
        installed=installed,
        installed_process_id=installed_id,
    )


def _process_to_info(db: Session, p) -> ManagedProcessInfo:
    """Convert an ORM ManagedMcpProcess into an API response, computing connection_url along the way"""
    catalog = get_catalog_loader().get(p.catalog_id)
    catalog_name = catalog.name if catalog else None

    # Connection URL for the vendor agent (MCP Center runs on the host network, so 127.0.0.1 = host)
    connection_url = (
        f"http://127.0.0.1:{p.port}/mcp" if p.port and p.actual_state == "running"
        else None
    )

    raw = p.to_dict()
    return ManagedProcessInfo(
        id=raw["id"],
        name=raw["name"],
        catalog_id=raw["catalog_id"],
        catalog_name=catalog_name,
        service_id=raw["service_id"],
        docker_image=raw["docker_image"],
        image_args=raw["image_args"],
        env_var_names=raw["env_var_names"],
        bridge_type=raw["bridge_type"],
        port=raw["port"],
        auto_port=raw["auto_port"],
        desired_state=raw["desired_state"],
        actual_state=raw["actual_state"],
        container_id=raw["container_id"],
        last_error=raw["last_error"],
        created_at=raw["created_at"],
        updated_at=raw["updated_at"],
        connection_url=connection_url,
    )


def _validate_env_vars(catalog: CatalogEntry, env_vars: dict) -> None:
    """Validate env vars against the catalog schema. Raises HTTPException(400) on failure."""
    provided_keys = set(env_vars.keys())
    expected = {ev.name: ev for ev in catalog.env_vars}

    # 1. Unknown keys
    extra = provided_keys - set(expected.keys())
    if extra:
        extras_list = sorted(extra)
        raise HTTPException(
            status_code=400,
            detail={
                "error": "managed.env_vars_unknown",
                "params": {"catalog_id": catalog.id, "extras": extras_list},
                "fallback": f"Unknown env vars for {catalog.id}: {extras_list}",
            },
        )

    # 2. Missing required vars
    for name, ev in expected.items():
        if ev.required and (name not in env_vars or env_vars[name] in (None, "")):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "managed.env_var_required_missing",
                    "params": {"name": name},
                    "fallback": f"Required env var '{name}' is missing or empty",
                },
            )

    # 3. Pattern validation
    for name, value in env_vars.items():
        if value in (None, ""):
            continue
        ev = expected[name]
        if ev.pattern and not re.match(ev.pattern, str(value)):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "managed.env_var_pattern_failed",
                    "params": {"name": name, "error_message": ev.error_message or ""},
                    "fallback": ev.error_message or f"Env var '{name}' failed pattern validation",
                },
            )


# ---------- Marketplace endpoints ----------

@router.get(
    "/api/managed/progress",
    response_model=ManagedProgressResponse,
    tags=["Managed MCP"],
)
async def list_managed_progress(
    _: AdminUser = Depends(get_current_user),
):
    """List in-flight long operations and their current stage (polled by the frontend to show "what is happening").

    The HTTP responses for deploy / start / stop / image load only return once the whole thing is done;
    this endpoint lets the frontend show the user stages such as "waiting for the port" or "warming up,
    downloading packages" while it waits, instead of a bare spinner.
    Purely in-memory, no DB access, so polling is extremely cheap.
    Note: must be declared before /api/managed/{process_id}, otherwise "progress" is treated as an id.
    """
    import time as _time
    now = _time.time()
    items = [
        ManagedProgressItem(**item, elapsed_seconds=round(now - item["started_at"], 1))
        for item in get_progress_registry().snapshot()
    ]
    return ManagedProgressResponse(items=items)


@router.get(
    "/api/marketplace",
    response_model=MarketplaceListResponse,
    tags=["Managed MCP"],
)
async def list_marketplace(
    db: Session = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    """List all marketplace catalog entries, annotated with installed status"""
    loader = get_catalog_loader()
    entries = loader.load_all()
    # The docker queries are synchronous I/O: run the whole batch in a worker thread (they share the db
    # Session, hence a single thread running them sequentially) to avoid blocking the event loop.
    items = await asyncio.to_thread(lambda: [_catalog_to_info(db, e) for e in entries.values()])
    return MarketplaceListResponse(catalog=items, total_count=len(items))


@router.get(
    "/api/marketplace/{catalog_id}",
    response_model=MarketplaceCatalogInfo,
    tags=["Managed MCP"],
)
async def get_catalog_entry(
    catalog_id: str,
    db: Session = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    entry = get_catalog_loader().get(catalog_id)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "managed.catalog_not_found",
                "params": {"catalog_id": catalog_id},
                "fallback": f"Catalog '{catalog_id}' not found",
            },
        )
    return await asyncio.to_thread(_catalog_to_info, db, entry)


@router.post(
    "/api/marketplace/{catalog_id}/install",
    response_model=MarketplaceImageInstallResponse,
    tags=["Managed MCP"],
)
async def install_marketplace_image(
    catalog_id: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """"Install": load the docker image from catalog/images/<tar> (offline, via the docker SDK).

    First step of the three-state flow: install (docker load) -> deploy (POST /api/managed).
    Returns 404 when the tar does not exist; the error message includes the manual `docker load -i` command
    as a fallback.
    """
    entry = get_catalog_loader().get(catalog_id)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "managed.catalog_not_found",
                "params": {"catalog_id": catalog_id},
                "fallback": f"Catalog '{catalog_id}' not found",
            },
        )

    image_ref = f"{entry.docker.image}:{entry.docker.tag}"
    orchestrator = get_orchestrator()

    # Already installed -> idempotent response
    if await asyncio.to_thread(orchestrator.image_exists, image_ref):
        return MarketplaceImageInstallResponse(
            success=True,
            message=f"Image '{image_ref}' already installed",
            image_installed=True,
        )

    tar_path = get_catalog_loader().image_tar_path(entry)
    if not tar_path.is_file():
        raise HTTPException(
            status_code=404,
            detail={
                "error": "managed.image_tar_not_found",
                "params": {"path": str(tar_path)},
                "fallback": (
                    f"Image tar not found: {tar_path}. Place the image tar at that path and retry, "
                    f"or run manually on the host: docker load -i {tar_path}"
                ),
            },
        )

    logger.info(f"Installing image for catalog={catalog_id}: tar={tar_path}, user={current_user.username}")
    progress = get_progress_registry()
    pkey = catalog_key(catalog_id)
    progress.begin(pkey, "install_image", "loading_image")
    try:
        # docker load reads the whole tar (can be several GB and minutes): must leave the event loop
        loaded_tags = await asyncio.to_thread(orchestrator.load_image, str(tar_path))
        progress.stage(pkey, "verifying_image", image_ref)
        # Verify that what was loaded actually contains the expected image (explicit error when the tar holds
        # the wrong content)
        image_installed = await asyncio.to_thread(orchestrator.image_exists, image_ref)
    except OrchestratorError as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "managed.image_load_failed",
                "params": {"reason": str(e)},
                "fallback": f"Image load failed: {e}",
            },
        )
    finally:
        progress.end(pkey)
    if not image_installed:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "managed.image_tar_mismatch",
                "params": {"expected": image_ref, "loaded": loaded_tags},
                "fallback": (
                    f"Tar loaded (tags={loaded_tags}) but it does not contain the image the catalog expects "
                    f"'{image_ref}'; check the tar content or the catalog's image/tag settings"
                ),
            },
        )

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.CREATE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS,
        resource_id=catalog_id,
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"action": "install_image", "image": image_ref, "tags": loaded_tags},
    )
    return MarketplaceImageInstallResponse(
        success=True,
        message=f"Image '{image_ref}' installed",
        image_installed=True,
        loaded_tags=loaded_tags,
    )


@router.get("/api/managed/{process_id}/logs", tags=["Managed MCP"])
async def get_managed_logs(
    process_id: str,
    tail: int = 200,
    db: Session = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    """Get the container output of this managed process (including exited containers).

    When a container crashes, the cause of death only exists in its own log; without this endpoint
    you would have to run docker commands by hand.
    """
    try:
        ManagedMcpProcessAdapter.get_existing(db, process_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)
    logs = await asyncio.to_thread(get_orchestrator().container_logs, process_id, tail)
    return {"process_id": process_id, "logs": logs}


# ---------- BYO (bring-your-own launch command) MCP definitions ----------
# Equivalent to authorising arbitrary container execution -- only the logged-in owner may use it
# (see docs/design/byo-mcp-launch.md).

@router.post("/api/byo-mcp", response_model=ByoDefinitionInfo, tags=["Managed MCP"])
async def create_byo_definition(
    request: ByoCreateRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Create a BYO MCP definition (paste the standard {command, args, env}).

    command/args are validated by the argv policy (command allowlist + args character allowlist).
    """
    try:
        d = BYODefinitionAdapter.create_definition(
            db,
            name=request.name,
            command=request.command,
            args=request.args,
            container_port=request.container_port,
            env_schema=[e.model_dump() for e in request.env_schema],
            description=request.description,
            created_by_id=str(current_user.id),
        )
    except AdapterError as e:
        raise _adapter_http_exc(e)

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.CREATE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS,
        resource_id=str(d.id),
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"action": "create_byo_definition", "name": d.name,
                 "command": d.command, "args": d.get_args()},
    )
    return ByoDefinitionInfo(**d.to_dict())


@router.get("/api/byo-mcp", response_model=ByoListResponse, tags=["Managed MCP"])
async def list_byo_definitions(
    db: Session = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    """List all BYO definitions."""
    defs = BYODefinitionAdapter.list_all(db)
    return ByoListResponse(
        definitions=[ByoDefinitionInfo(**d.to_dict()) for d in defs],
        total_count=len(defs),
    )


@router.delete("/api/byo-mcp/{definition_id}", tags=["Managed MCP"])
async def delete_byo_definition(
    definition_id: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Delete a BYO definition (refused while deployed; uninstall first)."""
    try:
        BYODefinitionAdapter.delete_guarded(db, definition_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.DELETE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS,
        resource_id=definition_id,
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"action": "delete_byo_definition"},
    )
    return {"message": "BYO definition deleted"}


@router.post(
    "/api/byo-mcp/{definition_id}/deploy",
    response_model=ManagedActionResponse,
    tags=["Managed MCP"],
)
async def deploy_byo_definition(
    definition_id: str,
    request: ByoDeployRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Deploy a BYO definition: bridge via supergateway inside the controlled container and expose 127.0.0.1:port."""
    try:
        definition = BYODefinitionAdapter.get_existing(db, definition_id)
        # single-instance: the same definition is already deployed -> 409
        ManagedMcpProcessAdapter.assert_not_installed(db, user_source_id(str(definition.id)))
    except AdapterError as e:
        raise _adapter_http_exc(e)

    # env vars validation: only keys declared in the definition schema are allowed (reject unknown keys)
    declared = {e["name"] for e in definition.get_env_schema()}
    extras = set(request.env_vars) - declared
    if extras:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "byo.unknown_env_vars",
                "params": {"extras": sorted(extras)},
                "fallback": f"Unknown env vars: {sorted(extras)}",
            },
        )

    name = request.name or definition.name
    # Create the managed process: image=controlled base, catalog_id=user:<id> (the orchestrator resolves the
    # inner command from it)
    process = ManagedMcpProcessAdapter.create(
        db=db,
        name=name,
        catalog_id=user_source_id(str(definition.id)),
        docker_image=MCP_RUNTIME_IMAGE,
        # Deliberately no --rm: auto_remove deletes the log together with the container on exit,
        # leaving no way to find the cause of a crash (stop/uninstall already force-remove explicitly).
        # --init provides a PID 1 that reaps children, so processes spawned by supergateway do not become zombies.
        image_args="--init",
        image_command=None,
        env_vars=request.env_vars,
        port=request.port,
        created_by=str(current_user.id),
    )

    started_ok = True
    err_msg = None
    if request.auto_start:
        try:
            ManagedMcpProcessAdapter.set_desired_state(db, str(process.id), "running")
            process = await asyncio.to_thread(get_orchestrator().start, db, str(process.id))
        except Exception as e:
            started_ok = False
            err_msg = str(e)
            logger.error(f"BYO deploy: process created but start failed: {e}")
            ManagedMcpProcessAdapter.update_state(
                db, str(process.id), actual_state="failed", last_error=err_msg,
            )
            process = ManagedMcpProcessAdapter.get_by_id(db, str(process.id))

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.CREATE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS if started_ok else AuditStatus.FAILURE,
        resource_id=str(process.id),
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"action": "deploy_byo", "definition_id": str(definition.id),
                 "auto_start": request.auto_start, "error": err_msg},
    )
    msg = (
        f"Deployed and started {name}" if started_ok and request.auto_start
        else f"Deployed {name} (start failed: {err_msg})" if not started_ok
        else f"Deployed {name} (not started)"
    )
    return ManagedActionResponse(
        success=started_ok, message=msg, process=_process_to_info(db, process),
    )


# ---------- Managed MCP endpoints ----------

@router.get(
    "/api/managed",
    response_model=ManagedListResponse,
    tags=["Managed MCP"],
)
async def list_managed(
    db: Session = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    procs = ManagedMcpProcessAdapter.list_all(db)
    return ManagedListResponse(
        processes=[_process_to_info(db, p) for p in procs],
        total_count=len(procs),
    )


@router.get(
    "/api/managed/{process_id}",
    response_model=ManagedProcessInfo,
    tags=["Managed MCP"],
)
async def get_managed(
    process_id: str,
    db: Session = Depends(get_db),
    _: AdminUser = Depends(get_current_user),
):
    try:
        p = ManagedMcpProcessAdapter.get_existing(db, process_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)
    return _process_to_info(db, p)


@router.post(
    "/api/managed",
    response_model=ManagedActionResponse,
    tags=["Managed MCP"],
)
async def install_managed(
    request: ManagedInstallRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Install from the catalog + (by default) start immediately"""
    logger.info(f"Install request: catalog={request.catalog_id}, name={request.name}, port={request.port}, user={current_user.username}")
    catalog = get_catalog_loader().get(request.catalog_id)
    if not catalog:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "managed.catalog_not_found",
                "params": {"catalog_id": request.catalog_id},
                "fallback": f"Catalog '{request.catalog_id}' not found",
            },
        )

    # Single instance check (logic lives in the adapter)
    try:
        ManagedMcpProcessAdapter.assert_not_installed(db, request.catalog_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)

    # Deploy precondition: the image must already be "installed" (offline two-phase flow; no automatic load,
    # guide the user explicitly)
    image_ref = f"{catalog.docker.image}:{catalog.docker.tag}"
    if not await asyncio.to_thread(get_orchestrator().image_exists, image_ref):
        tar_path = get_catalog_loader().image_tar_path(catalog)
        raise HTTPException(
            status_code=400,
            detail={
                "error": "managed.image_not_installed",
                "params": {"image": image_ref, "catalog_id": catalog.id},
                "fallback": (
                    f"Image '{image_ref}' is not installed yet. Run \"Install\" first "
                    f"(POST /api/marketplace/{catalog.id}/install), "
                    f"or run manually on the host: docker load -i {tar_path}"
                ),
            },
        )

    # Env vars validation (raises 400)
    _validate_env_vars(catalog, request.env_vars)

    # Create the DB row (port=None -> auto_port=True, port=int -> auto_port=False)
    name = request.name or catalog.id
    process = ManagedMcpProcessAdapter.create(
        db=db,
        name=name,
        catalog_id=catalog.id,
        docker_image=f"{catalog.docker.image}:{catalog.docker.tag}",
        image_args=" ".join(catalog.docker.args),
        image_command=list(catalog.docker.command) if catalog.docker.command else None,
        env_vars=request.env_vars,
        port=request.port,
        created_by=str(current_user.id),
    )

    # auto_start by default
    started_ok = True
    err_msg = None
    if request.auto_start:
        try:
            ManagedMcpProcessAdapter.set_desired_state(db, str(process.id), "running")
            process = await asyncio.to_thread(get_orchestrator().start, db, str(process.id))
        except (OrchestratorError, Exception) as e:
            started_ok = False
            err_msg = str(e)
            logger.error(f"Install: process created but start failed: {e}")
            ManagedMcpProcessAdapter.update_state(
                db, str(process.id),
                actual_state="failed",
                last_error=err_msg,
            )
            process = ManagedMcpProcessAdapter.get_by_id(db, str(process.id))

    # Audit
    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.CREATE_SERVICE,  # Reuses the existing enum; INSTALL_MANAGED could be added later
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS if started_ok else AuditStatus.FAILURE,
        resource_id=str(process.id),
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"catalog_id": catalog.id, "auto_start": request.auto_start, "error": err_msg},
    )

    msg = (
        f"Installed and started {catalog.name}" if started_ok and request.auto_start
        else f"Installed {catalog.name} (start failed: {err_msg})" if not started_ok
        else f"Installed {catalog.name} (not started)"
    )
    return ManagedActionResponse(
        success=started_ok,
        message=msg,
        process=_process_to_info(db, process),
    )


@router.post(
    "/api/managed/{process_id}/start",
    response_model=ManagedActionResponse,
    tags=["Managed MCP"],
)
async def start_managed(
    process_id: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    logger.info(f"Start request: process_id={process_id}, user={current_user.username}")
    try:
        p = ManagedMcpProcessAdapter.get_existing(db, process_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)

    try:
        ManagedMcpProcessAdapter.set_desired_state(db, process_id, "running")
        p = await asyncio.to_thread(get_orchestrator().start, db, process_id)
    except OrchestratorError as e:
        ManagedMcpProcessAdapter.update_state(
            db, process_id, actual_state="failed", last_error=str(e),
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "managed.start_failed",
                "params": {"reason": str(e)},
                "fallback": f"Start failed: {e}",
            },
        )

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.UPDATE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS,
        resource_id=process_id,
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"action": "start_managed"},
    )
    return ManagedActionResponse(
        success=True, message=f"Started {p.name}",
        process=_process_to_info(db, p),
    )


@router.post(
    "/api/managed/{process_id}/stop",
    response_model=ManagedActionResponse,
    tags=["Managed MCP"],
)
async def stop_managed(
    process_id: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    logger.info(f"Stop request: process_id={process_id}, user={current_user.username}")
    try:
        p = ManagedMcpProcessAdapter.get_existing(db, process_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)

    try:
        ManagedMcpProcessAdapter.set_desired_state(db, process_id, "stopped")
        p = await asyncio.to_thread(get_orchestrator().stop, db, process_id)
    except OrchestratorError as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "managed.stop_failed",
                "params": {"reason": str(e)},
                "fallback": f"Stop failed: {e}",
            },
        )

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.UPDATE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS,
        resource_id=process_id,
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"action": "stop_managed"},
    )
    return ManagedActionResponse(
        success=True, message=f"Stopped {p.name}",
        process=_process_to_info(db, p),
    )


@router.put(
    "/api/managed/{process_id}/env-vars",
    response_model=ManagedActionResponse,
    tags=["Managed MCP"],
)
async def update_env_vars(
    process_id: str,
    request: ManagedUpdateEnvRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Overwrite env vars (plaintext in, stored encrypted). Auto-restarts to apply them if currently running."""
    logger.info(f"Update env vars: process_id={process_id}, keys={list(request.env_vars.keys())}, user={current_user.username}")
    try:
        p = ManagedMcpProcessAdapter.get_existing(db, process_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)

    catalog = get_catalog_loader().get(p.catalog_id)
    if not catalog:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "managed.catalog_removed_from_image",
                "params": {"catalog_id": p.catalog_id},
                "fallback": f"Catalog '{p.catalog_id}' not found (removed from the image?)",
            },
        )
    _validate_env_vars(catalog, request.env_vars)

    was_running = (p.actual_state == "running")
    if was_running:
        await asyncio.to_thread(get_orchestrator().stop, db, process_id)

    ManagedMcpProcessAdapter.update_env_vars(db, process_id, request.env_vars)

    if was_running:
        try:
            p = await asyncio.to_thread(get_orchestrator().start, db, process_id)
        except OrchestratorError as e:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "managed.env_updated_restart_failed",
                    "params": {"reason": str(e)},
                    "fallback": f"Env updated but restart failed: {e}",
                },
            )
    else:
        p = ManagedMcpProcessAdapter.get_by_id(db, process_id)

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.UPDATE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS,
        resource_id=process_id,
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"action": "update_env_vars", "keys": list(request.env_vars.keys())},
    )
    return ManagedActionResponse(
        success=True,
        message=("Env vars updated and restarted" if was_running
                 else "Env vars updated (process not running)"),
        process=_process_to_info(db, p),
    )


@router.delete(
    "/api/managed/{process_id}",
    response_model=ManagedActionResponse,
    tags=["Managed MCP"],
)
async def uninstall_managed(
    process_id: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    """Uninstall: stop -> delete Service row -> delete tokens + usage -> delete process row"""
    logger.info(f"Uninstall request: process_id={process_id}, user={current_user.username}")
    try:
        p = ManagedMcpProcessAdapter.get_existing(db, process_id)
    except AdapterError as e:
        raise _adapter_http_exc(e)

    name = p.name
    catalog_id = p.catalog_id

    # 1. Stop (ignore already-stopped errors; the orchestrator is an external process, coordinated by the route)
    try:
        await asyncio.to_thread(get_orchestrator().stop, db, process_id)
    except Exception as e:
        logger.warning(f"Stop during uninstall failed (continuing): {e}")

    # 2+3. Clean up Service-related data + delete the process row (logic lives in the adapter)
    ManagedMcpProcessAdapter.purge_with_service(db, p, logger)

    AuditService.log_from_request(
        db=db, request=http_request,
        action=AuditAction.DELETE_SERVICE,
        resource_type=ResourceType.SERVICE,
        status=AuditStatus.SUCCESS,
        resource_id=process_id,
        actor_type=ActorType.ADMIN,
        actor_id=str(current_user.id),
        actor_name=current_user.audit_name,
        details={"catalog_id": catalog_id, "name": name},
    )
    return ManagedActionResponse(
        success=True,
        message=f"Uninstalled {name}",
        process=None,
    )
