"""Third-party login interface. A provider is enabled only when its client_id is configured."""

from typing import Dict, List

from src.config import Config
from src.identity.providers.base import ExternalIdentity, OAuthLoginProvider
from src.identity.providers.github import GitHubLoginProvider
from src.identity.providers.google import GoogleLoginProvider

_REGISTRY = {
    "github": GitHubLoginProvider,
    "google": GoogleLoginProvider,
}


def get_enabled_providers() -> Dict[str, OAuthLoginProvider]:
    cfg = Config.get_identity_config()
    enabled: Dict[str, OAuthLoginProvider] = {}
    for name, cls in _REGISTRY.items():
        pcfg = getattr(cfg, name, None)
        if pcfg and pcfg.client_id:
            enabled[name] = cls(client_id=pcfg.client_id, client_secret=pcfg.client_secret)
    return enabled


def describe_providers() -> List[dict]:
    """For the login page: which login methods are available."""
    cfg = Config.get_identity_config()
    out = []
    if cfg.local_enabled:
        out.append({"name": "local", "display_name": "Email / Password", "kind": "password"})
    for name, p in get_enabled_providers().items():
        out.append({"name": name, "display_name": p.display_name, "kind": "oauth"})
    return out


__all__ = ["ExternalIdentity", "OAuthLoginProvider", "get_enabled_providers", "describe_providers"]
