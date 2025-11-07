# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Trevor Baker, all rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Authorization endpoint for Alexa account linking using Home Assistant.

This Lambda function implements a stateless authorization code flow using a
short-lived, HMAC-signed JWT as the authorization "code" returned to Alexa.

Flow:
1) Alexa calls this endpoint with standard OAuth parameters (response_type=code,
   client_id, redirect_uri, state, scope).
2) We redirect the user's browser to Home Assistant /auth/authorize to perform
   the actual Home Assistant login (and user consent).
3) Home Assistant redirects back to this same endpoint with a temporary HA code.
4) We mint a short-lived JWT embedding the HA code and return the user to Alexa
   by redirecting to the original Alexa redirect_uri with code=<jwt>&state=<state>.

No server-side storage is required.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Final
from urllib.parse import urlencode, urlparse

from parameter_store import get_parameter


# Logging
logger = logging.getLogger("HomeAssistant-Authorize")
logger.setLevel(logging.DEBUG if os.getenv("DEBUG") else logging.INFO)

# Constants
JWT_TTL_SECONDS: Final[int] = 300  # 5 minutes


@dataclass(frozen=True)
class Config:
    base_url: str
    vendor_id: str
    jwt_secret: str

    @classmethod
    def from_env(cls) -> Config:
        """Load configuration from environment variables.

        OAUTH_JWT_SECRET is fetched from AWS Systems Manager Parameter Store
        with caching for performance.

        Raises:
            RuntimeError: If required configuration is missing.
        """
        base_url = os.getenv("BASE_URL")
        vendor_id = os.getenv("ALEXA_VENDOR_ID")
        jwt_secret_param = os.getenv("OAUTH_JWT_SECRET")

        if not base_url:
            raise RuntimeError("BASE_URL is required")
        if not vendor_id:
            raise RuntimeError("ALEXA_VENDOR_ID is required")
        if not jwt_secret_param:
            raise RuntimeError("OAUTH_JWT_SECRET is required")

        return cls(
            base_url=base_url.rstrip("/"),
            vendor_id=vendor_id,
            jwt_secret=get_parameter(jwt_secret_param),
        )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_jwt(payload: dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def _parse_query(event: dict[str, Any]) -> dict[str, str]:
    params = event.get("queryStringParameters") or {}
    return {k: v for k, v in params.items() if isinstance(k, str) and isinstance(v, str)}


def _allowed_redirects(vendor_id: str) -> set[str]:
    return {
        f"https://pitangui.amazon.com/api/skill/link/{vendor_id}",
        f"https://layla.amazon.com/api/skill/link/{vendor_id}",
        f"https://alexa.amazon.co.jp/api/skill/link/{vendor_id}",
    }


def _is_allowed_redirect(redirect_uri: str, vendor_id: str) -> bool:
    try:
        parsed = urlparse(redirect_uri)
        return redirect_uri in _allowed_redirects(vendor_id) and parsed.scheme == "https"
    except Exception:
        return False


def _json_b64(data: dict[str, Any]) -> str:
    return _b64url(json.dumps(data, separators=(",", ":")).encode("utf-8"))


def _json_from_b64(data: str) -> dict[str, Any]:
    # Add padding if required
    padding = "=" * (-len(data) % 4)
    raw = base64.urlsafe_b64decode(data + padding)
    result: dict[str, Any] = json.loads(raw.decode("utf-8"))
    return result


def _redirect(location: str) -> dict[str, Any]:
    return {
        "statusCode": 302,
        "headers": {"Location": location},
        "body": "",
    }


def _sanitize_query(params: dict[str, str]) -> dict[str, str]:
    redacted_keys = {"code"}  # never log authorization codes
    sanitized: dict[str, str] = {}
    for key, value in params.items():
        if key in redacted_keys:
            sanitized[key] = "[REDACTED]"
            continue
        v = value
        if len(v) > 64:
            v = v[:64] + "..."
        sanitized[key] = v
    return sanitized


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        config = Config.from_env()
        qs = _parse_query(event)
        # Derive our own public URL from the request context (Lambda Function URL)
        rc = event.get("requestContext") or {}
        domain = (rc.get("domainName") or "").strip()
        self_url = f"https://{domain}"
        if os.getenv("DEBUG"):
            logger.debug(
                "Authorize request: self_url=%s, qs=%s, rc_keys=%s",
                self_url,
                _sanitize_query(qs),
                list(rc.keys()),
            )

        # Alexa initial request
        if "code" not in qs:
            client_id = qs.get("client_id") or ""
            redirect_uri = qs.get("redirect_uri") or ""
            state = qs.get("state") or ""
            scope = qs.get("scope") or ""
            response_type = (qs.get("response_type") or "code").lower()

            if response_type != "code":
                # If we have a valid redirect_uri, return an OAuth error to Alexa
                if _is_allowed_redirect(redirect_uri, config.vendor_id):
                    err = {"error": "unsupported_response_type", "state": state}
                    return _redirect(f"{redirect_uri}?{urlencode(err)}")
                raise ValueError("unsupported response_type")
            if not client_id:
                raise ValueError("client_id is required")
            if not _is_allowed_redirect(redirect_uri, config.vendor_id):
                raise ValueError("redirect_uri is not an allowed Alexa redirect URL")

            # Envelope Alexa state so we can recover it after HA callback
            ha_state = _json_b64(
                {
                    "a_state": state,
                    "redirect_uri": redirect_uri,
                }
            )

            # Redirect user to Home Assistant authorize endpoint
            ha_params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": self_url,  # callback back to this function
                "state": ha_state,
                "scope": scope,
            }
            location = f"{config.base_url}/auth/authorize?{urlencode(ha_params)}"
            if os.getenv("DEBUG"):
                logger.debug(
                    "Redirecting to HA authorize endpoint: base=%s, has_scope=%s, state_len=%s",
                    config.base_url,
                    bool(scope),
                    len(ha_state),
                )
            logger.info("Redirecting user to Home Assistant authorize endpoint")
            return _redirect(location)

        # HA callback (has 'code' and 'state')
        ha_code = qs.get("code") or ""
        ha_state = qs.get("state") or ""
        if not ha_code or not ha_state:
            raise ValueError("Missing code or state on callback")

        # Recover Alexa state and redirect_uri
        envelope = _json_from_b64(ha_state)
        a_state = str(envelope.get("a_state", ""))
        redirect_uri = str(envelope.get("redirect_uri", ""))
        if not _is_allowed_redirect(redirect_uri, config.vendor_id):
            raise ValueError("Recovered redirect_uri is not allowed")

        # Mint short-lived JWT that carries the HA authorization code
        now = int(time.time())
        payload = {
            "iss": "ha-alexa",
            "iat": now,
            "exp": now + JWT_TTL_SECONDS,
            "ha_code": ha_code,
        }
        jwt_code = _sign_jwt(payload, config.jwt_secret)

        # Redirect back to Alexa with our JWT as the "code"
        location = f"{redirect_uri}?{urlencode({'code': jwt_code, 'state': a_state})}"
        if os.getenv("DEBUG"):
            logger.debug(
                "Authorization completed; redirecting back to Alexa: redirect_uri=%s, state_len=%s",
                redirect_uri,
                len(a_state),
            )
        logger.info("Authorization completed; redirecting back to Alexa")
        return _redirect(location)

    except Exception:
        logger.exception("Authorization flow failed")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "invalid_request"}),
        }
