# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Trevor Baker, all rights reserved.
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

"""OAuth token handler for Alexa-Home Assistant account linking.

This Lambda function handles OAuth token requests from Alexa during the
account linking process, forwarding them to Home Assistant's auth endpoint.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Any, Final
from urllib.parse import parse_qs, urlencode

import urllib3

from parameter_store import get_parameter


# Constants
CONNECT_TIMEOUT: Final[float] = 2.0
READ_TIMEOUT: Final[float] = 10.0
MAX_LOG_LENGTH: Final[int] = 100

# Configure logging
logger = logging.getLogger("HomeAssistant-OAuth")
logger.setLevel(logging.DEBUG if os.getenv("DEBUG") else logging.INFO)

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ErrorType(str, Enum):
    """OAuth error types."""

    INVALID_AUTHORIZATION = "INVALID_AUTHORIZATION_CREDENTIAL"
    INVALID_REQUEST = "INVALID_DIRECTIVE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class Config:
    """Lambda function configuration from environment variables."""

    base_url: str
    cf_client_id: str | None
    cf_client_secret: str | None
    oauth_jwt_secret: str | None

    @classmethod
    def from_environment(cls) -> Config:
        """Load configuration from environment variables.

        Sensitive values (CF_CLIENT_ID, CF_CLIENT_SECRET, OAUTH_JWT_SECRET) are fetched
        from AWS Systems Manager Parameter Store with caching for performance.

        Returns:
            Validated configuration instance.

        Raises:
            ValueError: If required configuration is missing.
        """
        base_url = os.getenv("BASE_URL")
        if not base_url:
            raise ValueError("BASE_URL environment variable is required")

        # Sensitive values: env vars contain Parameter Store names
        cf_client_id_param = os.getenv("CF_CLIENT_ID")
        cf_client_secret_param = os.getenv("CF_CLIENT_SECRET")
        oauth_jwt_secret_param = os.getenv("OAUTH_JWT_SECRET")

        return cls(
            base_url=base_url.rstrip("/"),
            cf_client_id=(get_parameter(cf_client_id_param) if cf_client_id_param else None),
            cf_client_secret=(
                get_parameter(cf_client_secret_param) if cf_client_secret_param else None
            ),
            oauth_jwt_secret=(
                get_parameter(oauth_jwt_secret_param) if oauth_jwt_secret_param else None
            ),
        )


@dataclass(frozen=True)
class TokenRequest:
    """Parsed OAuth token request."""

    body: bytes

    @classmethod
    def from_event(cls, event: dict[str, Any]) -> TokenRequest:
        """Parse and decode token request body from Lambda event.

        Handles both base64-encoded and plain text bodies from API Gateway.

        Args:
            event: Lambda event from API Gateway.

        Returns:
            Parsed token request.

        Raises:
            ValueError: If body is missing or cannot be decoded.
        """
        body = event.get("body")
        if not body:
            raise ValueError("Request body is required")

        # Handle base64-encoded bodies
        if event.get("isBase64Encoded", False):
            try:
                decoded = base64.b64decode(body)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 body: {e}") from e
        else:
            # Convert string to bytes
            decoded = body.encode("utf-8") if isinstance(body, str) else body

        return cls(body=decoded)


@dataclass(frozen=True)
class ErrorResponse:
    """OAuth error response."""

    error_type: ErrorType
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to Alexa response format."""
        return {
            "event": {
                "payload": {
                    "type": self.error_type.value,
                    "message": self.message,
                }
            }
        }


class HomeAssistantAuthClient:
    """Client for Home Assistant OAuth endpoints."""

    def __init__(self, config: Config) -> None:
        """Initialize Home Assistant auth client.

        Args:
            config: Configuration for connecting to Home Assistant.
        """
        self.config = config
        self.http = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED",
            timeout=urllib3.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT),
        )

    def exchange_token(self, request_body: bytes) -> dict[str, Any]:
        """Forward OAuth token request to Home Assistant.

        Args:
            request_body: OAuth token request body (application/x-www-form-urlencoded).

        Returns:
            Token response from Home Assistant.

        Raises:
            ValueError: If response cannot be parsed.
            PermissionError: If authentication fails.
            RuntimeError: If request fails.
        """
        url = f"{self.config.base_url}/auth/token"
        headers = self._build_headers()

        logger.info(f"Forwarding token request to {url}")

        # Log sanitized request body in debug mode
        if os.getenv("DEBUG"):
            sanitized = _sanitize_body(request_body)
            logger.debug(f"Request body: {sanitized}")

        try:
            response = self.http.request(  # type: ignore[no-untyped-call]
                "POST",
                url,
                headers=headers,
                body=request_body,
            )
        except Exception as e:
            logger.exception("Failed to connect to Home Assistant")
            raise RuntimeError(f"Connection failed: {e}") from e

        # Handle HTTP errors
        if response.status >= 400:
            error_msg = self._decode_response(response.data)
            logger.error(f"Token exchange failed: {response.status} - {error_msg}")

            if response.status in (401, 403):
                raise PermissionError(f"Authentication failed: {error_msg}")
            raise RuntimeError(f"Token exchange error {response.status}: {error_msg}")

        # Parse successful response
        try:
            result: dict[str, Any] = json.loads(response.data.decode("utf-8"))
            logger.info("Token exchange successful")

            # Log sanitized response in debug mode
            if os.getenv("DEBUG"):
                logger.debug(f"Response: {_sanitize_token_response(result)}")

            return result

        except json.JSONDecodeError as e:
            logger.exception("Invalid JSON response")
            raise ValueError("Home Assistant returned invalid JSON") from e

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for token request.

        Returns:
            Headers dictionary.
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Add Cloudflare Access headers if configured
        if self.config.cf_client_id and self.config.cf_client_secret:
            headers["CF-Access-Client-Id"] = self.config.cf_client_id
            headers["CF-Access-Client-Secret"] = self.config.cf_client_secret
            logger.debug("Added Cloudflare Access authentication")

        return headers

    @staticmethod
    def _decode_response(data: bytes) -> str:
        """Safely decode response data."""
        return data.decode("utf-8", errors="replace")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for OAuth token requests.

    This function handles OAuth token exchange during Alexa account linking:
    1. Extracts and decodes the token request body
    2. Forwards it to Home Assistant's /auth/token endpoint
    3. Returns the OAuth token response to Alexa

    Args:
        event: Lambda event from API Gateway.
        context: Lambda context (unused).

    Returns:
        OAuth token response or error response.

    Environment Variables:
        BASE_URL: Home Assistant URL (required)
        CF_CLIENT_ID: Cloudflare Access service token client ID (required)
        CF_CLIENT_SECRET: Cloudflare Access service token client secret (required)
        DEBUG: Enable debug logging (optional)
    """
    try:
        # Load configuration
        config = Config.from_environment()
        _log_request_context(event)

        # Parse request
        request = TokenRequest.from_event(event)

        # Possibly unwrap stateless JWT 'code' into Home Assistant code
        body = _maybe_unwrap_jwt_code(request.body, config)

        # Exchange token with Home Assistant
        client = HomeAssistantAuthClient(config)
        return client.exchange_token(body)

    except ValueError as e:
        logger.exception("Invalid request")
        return ErrorResponse(ErrorType.INVALID_REQUEST, str(e)).to_dict()

    except PermissionError as e:
        logger.exception("Authentication error")
        return ErrorResponse(ErrorType.INVALID_AUTHORIZATION, str(e)).to_dict()

    except RuntimeError as e:
        logger.exception("Runtime error")
        return ErrorResponse(ErrorType.INTERNAL_ERROR, str(e)).to_dict()

    except Exception:
        logger.exception("Unexpected error processing token request")
        return ErrorResponse(
            ErrorType.INTERNAL_ERROR,
            "An unexpected error occurred",
        ).to_dict()


def _sanitize_body(body: bytes) -> str:
    """Sanitize request body for logging.

    Redacts sensitive OAuth parameters like client_secret, password, code, etc.

    Args:
        body: Request body to sanitize.

    Returns:
        Sanitized string safe for logging.
    """
    try:
        decoded = body.decode("utf-8")

        # Truncate if too long
        if len(decoded) > MAX_LOG_LENGTH:
            decoded = decoded[:MAX_LOG_LENGTH] + "..."

        # Check for sensitive fields
        sensitive_fields = {
            "client_secret",
            "password",
            "code",
            "refresh_token",
            "access_token",
        }

        if any(field in decoded.lower() for field in sensitive_fields):
            return "[Request contains sensitive data - redacted]"

        return decoded

    except UnicodeDecodeError:
        return "[Binary data - redacted]"


def _sanitize_token_response(response: dict[str, Any]) -> dict[str, Any]:
    """Sanitize token response for logging.

    Args:
        response: Token response to sanitize.

    Returns:
        Response with tokens redacted.
    """
    return {
        key: "[REDACTED]" if "token" in key.lower() else value for key, value in response.items()
    }


def _log_request_context(event: dict[str, Any]) -> None:
    if not os.getenv("DEBUG"):
        return
    rc = event.get("requestContext") or {}
    method = (event.get("requestContext", {}).get("http", {}) or {}).get("method") or ""
    logger.debug(
        "Token request context: domain=%s, method=%s, keys=%s",
        rc.get("domainName"),
        method,
        list(rc.keys()),
    )


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _verify_and_extract_ha_code(jwt_code: str, secret: str) -> str | None:
    try:
        parts = jwt_code.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, sha256).digest()
        actual_sig = _b64url_decode(signature_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_raw = _b64url_decode(payload_b64)
        payload: dict[str, Any] = json.loads(payload_raw.decode("utf-8"))

        # exp check
        exp = int(payload.get("exp", 0))
        now = int(time.time())
        if exp and now > exp:
            return None

        ha_code = payload.get("ha_code")
        if not isinstance(ha_code, str) or not ha_code:
            return None
        return ha_code
    except Exception:
        return None


def _maybe_unwrap_jwt_code(body: bytes, config: Config) -> bytes:
    """If the request contains a JWT 'code', unwrap it into HA code."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body

    # Parse x-www-form-urlencoded
    params_multi = parse_qs(text, keep_blank_values=True)
    # Flatten first value
    params: dict[str, str] = {k: v[0] for k, v in params_multi.items() if v}

    grant_type = params.get("grant_type", "")
    code = params.get("code", "")
    if grant_type != "authorization_code" or "." not in code:
        if os.getenv("DEBUG"):
            logger.debug(
                "JWT unwrap skipped: grant_type=%s, code_present=%s", grant_type, bool(code)
            )
        return body

    if not config.oauth_jwt_secret:
        # No secret configured; cannot unwrap
        if os.getenv("DEBUG"):
            logger.debug("JWT unwrap skipped: missing OAUTH_JWT_SECRET")
        return body

    ha_code = _verify_and_extract_ha_code(code, config.oauth_jwt_secret)
    if not ha_code:
        # Invalid JWT; leave as-is so HA will reject and we surface an error
        if os.getenv("DEBUG"):
            logger.debug("JWT unwrap failed: signature/exp invalid")
        return body

    if os.getenv("DEBUG"):
        logger.debug("JWT unwrap successful")
    params["code"] = ha_code
    # Re-encode
    return urlencode(params).encode("utf-8")
