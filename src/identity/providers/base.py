"""Base class for third-party login providers (the RP side of the authorization code flow).

To add a new provider, subclass and implement the three endpoints + `parse_identity`; the rest of the flow
(state for CSRF protection, exchanging the code for a token, fetching userinfo) is handled here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import httpx


@dataclass
class ExternalIdentity:
    provider: str
    sub: str
    email: Optional[str]
    name: Optional[str]
    email_verified: bool = True


class OAuthLoginProvider:
    name: str = "base"
    display_name: str = "Base"
    authorize_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    scopes: list[str] = []
    # Some providers (GitHub) only return JSON from the token endpoint when Accept: application/json is sent
    token_headers: dict = {"Accept": "application/json"}

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret

    def authorize_url(self, *, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
        }
        params.update(self.extra_authorize_params())
        return f"{self.authorize_endpoint}?{urlencode(params)}"

    def extra_authorize_params(self) -> dict:
        return {}

    async def exchange(self, *, code: str, redirect_uri: str) -> ExternalIdentity:
        async with httpx.AsyncClient(timeout=15) as client:
            token_resp = await client.post(
                self.token_endpoint,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers=self.token_headers,
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise ValueError(f"{self.name}: no access_token in token response")
            return await self.fetch_identity(client, access_token, token_data)

    async def fetch_identity(self, client: httpx.AsyncClient, access_token: str, token_data: dict) -> ExternalIdentity:
        resp = await client.get(self.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
        resp.raise_for_status()
        return self.parse_identity(resp.json())

    def parse_identity(self, data: dict) -> ExternalIdentity:  # pragma: no cover - abstract
        raise NotImplementedError
