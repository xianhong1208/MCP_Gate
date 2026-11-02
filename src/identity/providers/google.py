"""Google login (OIDC). sub / email come from the userinfo endpoint."""

from src.identity.providers.base import ExternalIdentity, OAuthLoginProvider


class GoogleLoginProvider(OAuthLoginProvider):
    name = "google"
    display_name = "Google"
    authorize_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"
    userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo"
    scopes = ["openid", "email", "profile"]

    def extra_authorize_params(self) -> dict:
        return {"access_type": "online", "prompt": "select_account"}

    def parse_identity(self, data: dict) -> ExternalIdentity:
        return ExternalIdentity(
            provider=self.name,
            sub=str(data.get("sub")),
            email=(data.get("email") or "").lower() or None,
            name=data.get("name"),
            email_verified=_is_true(data.get("email_verified")),
        )


def _is_true(value) -> bool:
    """OIDC says boolean, but some responses carry the string "true"; anything else (including "false") is False."""
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")
