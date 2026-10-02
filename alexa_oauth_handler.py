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

It is served through a Lambda Function URL, so responses use the Function URL
proxy format ({"statusCode": ..., "body": ...}) with RFC 6749 OAuth error
bodies ({"error": "invalid_grant", ...}) that Alexa's account linking service
understands.
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


class TokenExchangeError(Exception):
    """OAuth error relayed from Home Assistant's token endpoint."""

    def __init__(self, error: dict[str, Any], status: int = 400) -> None:
        """Initialize with an RFC 6749 error object (e.g. {"error": "invalid_grant"})."""
        super().__init__(str(error.get("error_description") or error.get("error") or "error"))
        self.error = error
        self.status = status


@dataclass(frozen=True)
class Config:
    """Lambda function configuration from environment variables."""

    base_url: str
    cf_client_id: str | None
    cf_client_secret: str | None
    oauth_jwt_secret: str | None
    verify_ssl: bool = True

    @classmethod
    def from_environment(cls) -> Config:
        """Load configuration from environment variables.

        Sensitive values (CF_CLIENT_ID, CF_CLIENT_SECRET, OAUTH_JWT_SECRET) are fetched
        from AWS Systems Manager Parameter Store with caching for performance.

        Returns:
            Validated configuration instance.

        Raises:
            RuntimeError: If required configuration is missing.
        """
        base_url = os.getenv("BASE_URL")
        if not base_url:
            raise RuntimeError("BASE_URL environment variable is required")

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
            verify_ssl=not os.getenv("NOT_VERIFY_SSL"),
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


class HomeAssistantAuthClient:
    """Client for Home Assistant OAuth endpoints."""

    def __init__(self, config: Config) -> None:
        """Initialize Home Assistant auth client.

        Args:
            config: Configuration for connecting to Home Assistant.
        """
        self.config = config
        self.http = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED" if config.verify_ssl else "CERT_NONE",
            timeout=urllib3.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT),
        )

        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification is disabled - not recommended for production")

    def exchange_token(self, request_body: bytes) -> dict[str, Any]:
        """Forward OAuth token request to Home Assistant.

        Args:
            request_body: OAuth token request body (application/x-www-form-urlencoded).

        Returns:
            Token response from Home Assistant.

        Raises:
            ValueError: If response cannot be parsed.
            TokenExchangeError: If Home Assistant returns an OAuth error body.
            RuntimeError: If the request fails or the error did not come from
                Home Assistant's OAuth endpoint (e.g. a Cloudflare Access denial).
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

            # Relay only genuine OAuth error bodies from Home Assistant. Anything else
            # (e.g. a Cloudflare Access 403 for an expired service token) is a server
            # problem: answering invalid_grant would make Alexa unlink the account.
            oauth_error = self._parse_oauth_error(response.data)
            if response.status in (400, 401, 403) and oauth_error is not None:
                raise TokenExchangeError(oauth_error, response.status)
            raise RuntimeError(f"Token exchange error {response.status}")

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

    @staticmethod
    def _parse_oauth_error(data: bytes) -> dict[str, Any] | None:
        """Parse an RFC 6749 OAuth error body, or return None if it is not one."""
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
            return parsed
        return None


# Cached across warm Lambda invocations so HTTPS connections are reused
_cached_client: HomeAssistantAuthClient | None = None


def _get_client(config: Config) -> HomeAssistantAuthClient:
    """Return a client for the given config, reusing the cached one if possible."""
    global _cached_client  # noqa: PLW0603
    if _cached_client is None or _cached_client.config != config:
        _cached_client = HomeAssistantAuthClient(config)
    return _cached_client


def _http_response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    """Build a Lambda Function URL response with a JSON body."""
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
        "body": json.dumps(body),
    }


def _oauth_error(status: int, error: str, description: str) -> dict[str, Any]:
    """Build an RFC 6749 OAuth error response."""
    return _http_response(status, {"error": error, "error_description": description})


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for OAuth token requests.

    This function handles OAuth token exchange during Alexa account linking:
    1. Extracts and decodes the token request body
    2. Forwards it to Home Assistant's /auth/token endpoint
    3. Returns the OAuth token response to Alexa

    Args:
        event: Lambda event from the Function URL.
        context: Lambda context (unused).

    Returns:
        Function URL response with the OAuth token JSON, or an RFC 6749
        error response with an appropriate HTTP status code.

    Environment Variables:
        BASE_URL: Home Assistant URL (required)
        CF_CLIENT_ID: Parameter Store path for Cloudflare Access client ID (optional)
        CF_CLIENT_SECRET: Parameter Store path for Cloudflare Access client secret (optional)
        OAUTH_JWT_SECRET: Parameter Store path for the JWT signing secret (optional)
        NOT_VERIFY_SSL: Disable SSL verification (optional)
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
        client = _get_client(config)
        return _http_response(200, client.exchange_token(body))

    except TokenExchangeError as e:
        logger.exception("Token exchange rejected by Home Assistant")
        return _http_response(e.status, e.error)

    except ValueError as e:
        logger.exception("Invalid request")
        return _oauth_error(400, "invalid_request", str(e))

    except RuntimeError as e:
        logger.exception("Runtime error")
        return _oauth_error(502, "server_error", str(e))

    except Exception:
        logger.exception("Unexpected error processing token request")
        return _oauth_error(500, "server_error", "An unexpected error occurred")


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
    method = (rc.get("http") or {}).get("method") or ""
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

        # exp is required; tokens without it are rejected
        exp = payload.get("exp")
        now = int(time.time())
        if not isinstance(exp, int) or now > exp:
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
