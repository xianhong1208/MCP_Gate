"""GitHub login (OAuth App). GitHub has no OIDC id_token, so identity comes from /user + /user/emails."""

import httpx

from src.identity.providers.base import ExternalIdentity, OAuthLoginProvider


class GitHubLoginProvider(OAuthLoginProvider):
    name = "github"
    display_name = "GitHub"
    authorize_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    userinfo_endpoint = "https://api.github.com/user"
    scopes = ["read:user", "user:email"]

    async def fetch_identity(self, client: httpx.AsyncClient, access_token: str, token_data: dict) -> ExternalIdentity:
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"}
        user_resp = await client.get(self.userinfo_endpoint, headers=headers)
        user_resp.raise_for_status()
        user = user_resp.json()
        email = user.get("email")
        verified = True
        if not email:
            emails_resp = await client.get("https://api.github.com/user/emails", headers=headers)
            if emails_resp.status_code == 200:
                primary = next((e for e in emails_resp.json() if e.get("primary")), None)
                if primary:
                    email = primary.get("email")
                    verified = bool(primary.get("verified", False))
        return ExternalIdentity(
            provider=self.name,
            sub=str(user.get("id")),
            email=email.lower() if email else None,
            name=user.get("name") or user.get("login"),
            email_verified=verified,
        )

    def parse_identity(self, data: dict) -> ExternalIdentity:
        return ExternalIdentity(provider=self.name, sub=str(data.get("id")),
                                email=(data.get("email") or "").lower() or None,
                                name=data.get("name") or data.get("login"))
