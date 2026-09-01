"""API request / response models."""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict


# ==================== Service ====================

class ServiceCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "http"
    mcp_path: str = "/mcp"
    tags: Optional[List[str]] = None
    requires_auth: bool = True
    # The external service's own static Bearer token (optional; not needed for services protected by MCP Center OAuth)
    auth_token: Optional[str] = None
    # OAuth audience (RFC 8707 resource); falls back to the MCP URL when empty
    oauth_audience: Optional[str] = None
    oauth_scopes: Optional[List[str]] = None


class ServiceUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    mcp_path: Optional[str] = None
    tags: Optional[List[str]] = None
    requires_auth: Optional[bool] = None
    auth_token: Optional[str] = None  # empty string = clear
    oauth_audience: Optional[str] = None
    oauth_scopes: Optional[List[str]] = None


class ServiceHealthInfo(BaseModel):
    status: str
    last_checked: Optional[str] = None
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    fail_count: int = 0


class MCPToolInfo(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    input_schema: Optional[dict] = None
    created_at: Optional[str] = None


class ServiceInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    description: Optional[str] = None
    is_active: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "http"
    mcp_path: str = "/mcp"
    mcp_url: Optional[str] = None
    tags: List[str] = []
    source: str = "manual"
    requires_auth: bool = True
    has_static_token: bool = False
    oauth_audience: Optional[str] = None
    effective_audience: Optional[str] = None
    oauth_scopes: List[str] = []
    health: Optional[ServiceHealthInfo] = None
    tools: Optional[List[MCPToolInfo]] = None
    tools_count: int = 0


class ServiceListResponse(BaseModel):
    services: List[ServiceInfo]
    total_count: int


class HealthResponse(BaseModel):
    status: str
    service: str


# ==================== Audit ====================

class AuditLogInfo(BaseModel):
    id: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    actor_type: str
    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    status: str
    status_code: Optional[str] = None
    error_message: Optional[str] = None
    details: Optional[dict] = None
    created_at: str


class AuditLogListResponse(BaseModel):
    logs: List[AuditLogInfo]
    total_count: int
    page: int
    page_size: int


class AuditLogStatsResponse(BaseModel):
    period_days: int
    total: int
    success: int
    failure: int
    success_rate: float
    by_action: dict


# ==================== Discovery ====================

class ScanRequest(BaseModel):
    hosts: List[str] = ["localhost"]
    ports: List[int] = [3000, 8000, 8080]
    port_range_start: Optional[int] = None
    port_range_end: Optional[int] = None
    auto_register: bool = True
    auth_token: Optional[str] = None
    service_name: Optional[str] = None


class DiscoveredServiceInfo(BaseModel):
    host: str
    port: int
    protocol: str
    mcp_path: str
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    server_description: Optional[str] = None
    protocol_version: Optional[str] = None
    tools_count: int = 0
    registered: bool = False
    service_name: Optional[str] = None
    service_id: Optional[str] = None


class ScanResponse(BaseModel):
    success: bool
    message: str
    scanned_hosts: int
    scanned_ports: int
    discovered: List[DiscoveredServiceInfo]
    registered_count: int = 0


class VerifyRequest(BaseModel):
    host: str
    port: int
    protocol: str = "http"
    mcp_path: str = "/mcp"
    auth_token: Optional[str] = None


class VerifyResponse(BaseModel):
    success: bool
    protocol_version: Optional[str] = None
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    capabilities: Optional[dict] = None
    error: Optional[str] = None
    response_time_ms: float = 0.0


class ServiceHealthCheckResponse(BaseModel):
    service_name: str
    status: str
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    previous_status: Optional[str] = None
    status_changed: bool = False


class BulkHealthCheckResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    checked: int = 0
    online: int = 0
    offline: int = 0
    error: int = 0


class RefreshToolsResponse(BaseModel):
    success: bool
    message: str
    tools_count: int
    tools: List[MCPToolInfo] = []


# ==================== Marketplace / Managed MCP ====================

class MarketplaceEnvVarInfo(BaseModel):
    name: str
    label: str
    help: Optional[str] = None
    required: bool = True
    secret: bool = False
    default: Optional[str] = None
    pattern: Optional[str] = None
    error_message: Optional[str] = None


class MarketplaceDockerInfo(BaseModel):
    image: str
    tag: str = "latest"
    args: List[str] = []


class MarketplaceCatalogInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str = "general"
    icon: Optional[str] = None
    docker: MarketplaceDockerInfo
    env_vars: List[MarketplaceEnvVarInfo] = []
    docs_url: Optional[str] = None
    installed: bool = False
    installed_process_id: Optional[str] = None
    image_installed: bool = False
    image_tar_present: bool = False
    image_tar_name: Optional[str] = None


class MarketplaceListResponse(BaseModel):
    catalog: List[MarketplaceCatalogInfo]
    total_count: int


class MarketplaceImageInstallResponse(BaseModel):
    success: bool
    message: str
    image_installed: bool = False
    loaded_tags: List[str] = []


class ManagedInstallRequest(BaseModel):
    catalog_id: str
    name: Optional[str] = None
    env_vars: dict = {}
    port: Optional[int] = None
    auto_start: bool = True


class ByoEnvVarSchema(BaseModel):
    name: str
    label: Optional[str] = None
    help: Optional[str] = None
    secret: bool = False
    required: bool = True


class ByoCreateRequest(BaseModel):
    name: str
    command: str
    args: List[str] = []
    container_port: int = 8000
    env_schema: List[ByoEnvVarSchema] = []
    description: Optional[str] = None


class ByoDefinitionInfo(BaseModel):
    id: str
    name: str
    command: str
    args: List[str] = []
    container_port: int = 8000
    env_schema: List[dict] = []
    description: Optional[str] = None
    created_by_id: Optional[str] = None
    created_at: Optional[str] = None


class ByoListResponse(BaseModel):
    definitions: List[ByoDefinitionInfo]
    total_count: int


class ByoDeployRequest(BaseModel):
    name: Optional[str] = None
    env_vars: dict = {}
    port: Optional[int] = None
    auto_start: bool = True


class ManagedProcessInfo(BaseModel):
    id: str
    name: str
    catalog_id: str
    catalog_name: Optional[str] = None
    service_id: Optional[str] = None
    docker_image: str
    image_args: Optional[str] = None
    env_var_names: List[str] = []
    bridge_type: str
    port: Optional[int] = None
    auto_port: bool = True
    desired_state: str
    actual_state: str
    container_id: Optional[str] = None
    last_error: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    connection_url: Optional[str] = None


class ManagedProgressItem(BaseModel):
    key: str
    kind: str
    stage: str
    detail: Optional[str] = None
    started_at: float
    updated_at: float
    elapsed_seconds: float


class ManagedProgressResponse(BaseModel):
    items: List[ManagedProgressItem]


class ManagedListResponse(BaseModel):
    processes: List[ManagedProcessInfo]
    total_count: int


class ManagedUpdateEnvRequest(BaseModel):
    env_vars: dict


class ManagedActionResponse(BaseModel):
    success: bool
    message: str
    process: Optional[ManagedProcessInfo] = None
