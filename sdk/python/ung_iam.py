"""Minimal UNG-IAM integration client for UNG backend services.

The client deliberately treats IAM bearer tokens as opaque. It resolves the
current human identity through /v1/me and provides deny-by-default permission
checks for application code.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable


class IAMError(RuntimeError):
    """Base IAM integration error."""


class IAMAuthenticationError(IAMError):
    """Credential is missing, invalid, expired, disabled, or revoked."""


class IAMAuthorizationError(IAMError):
    """Authenticated identity lacks a required permission."""


class IAMUnavailableError(IAMError):
    """IAM could not be reached or returned an unexpected response."""


@dataclass(frozen=True)
class IAMIdentity:
    id: str
    identity_type: str
    access_class: str
    display_name: str
    email: str | None
    is_active: bool
    roles: tuple[str, ...]
    permissions: frozenset[str]

    @classmethod
    def from_payload(cls, data: dict) -> "IAMIdentity":
        return cls(
            id=str(data["id"]),
            identity_type=str(data["identity_type"]),
            access_class=str(data["access_class"]),
            display_name=str(data["display_name"]),
            email=data.get("email"),
            is_active=bool(data.get("is_active", False)),
            roles=tuple(data.get("roles") or ()),
            permissions=frozenset(data.get("permissions") or ()),
        )


class UNGIAMClient:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, path: str, bearer_token: str, method: str = "GET") -> dict:
        if not bearer_token:
            raise IAMAuthenticationError("Bearer token required")
        request = urllib.request.Request(
            self.base_url + path,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {bearer_token}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise IAMAuthenticationError("IAM rejected the credential") from exc
            if exc.code == 403:
                raise IAMAuthorizationError("IAM denied the request") from exc
            raise IAMUnavailableError(f"IAM returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise IAMUnavailableError("IAM is unavailable") from exc

    def me(self, bearer_token: str) -> IAMIdentity:
        identity = IAMIdentity.from_payload(self._request("/v1/me", bearer_token))
        if not identity.is_active:
            raise IAMAuthenticationError("IAM identity is disabled")
        return identity

    def logout(self, bearer_token: str) -> None:
        self._request("/v1/auth/logout", bearer_token, method="POST")

    def require_permissions(
        self,
        identity: IAMIdentity,
        required: Iterable[str],
    ) -> IAMIdentity:
        missing = sorted(set(required) - identity.permissions)
        if missing:
            raise IAMAuthorizationError("Missing permission(s): " + ", ".join(missing))
        return identity

    def authenticate_and_authorize(
        self,
        bearer_token: str,
        required: Iterable[str] = (),
    ) -> IAMIdentity:
        identity = self.me(bearer_token)
        return self.require_permissions(identity, required)
