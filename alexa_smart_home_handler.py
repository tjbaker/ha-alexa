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

"""Alexa Smart Home skill handler for Home Assistant integration.

This Lambda function receives Alexa Smart Home directives and forwards them
to Home Assistant's smart home API endpoint.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

import urllib3

from parameter_store import get_parameter


# Constants
SUPPORTED_PAYLOAD_VERSION: Final[str] = "3"
SUPPORTED_TOKEN_TYPE: Final[str] = "BearerToken"
CONNECT_TIMEOUT: Final[float] = 2.0
READ_TIMEOUT: Final[float] = 10.0

# Configure logging
logger = logging.getLogger("HomeAssistant-SmartHome")
logger.setLevel(logging.DEBUG if os.getenv("DEBUG") else logging.INFO)

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ErrorType(str, Enum):
    """Alexa Smart Home error types."""

    INVALID_AUTHORIZATION = "INVALID_AUTHORIZATION_CREDENTIAL"
    INVALID_DIRECTIVE = "INVALID_DIRECTIVE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    BRIDGE_UNREACHABLE = "BRIDGE_UNREACHABLE"


@dataclass(frozen=True)
class Config:
    """Lambda function configuration from environment variables."""

    base_url: str
    verify_ssl: bool
    cf_client_id: str | None
    cf_client_secret: str | None
    debug_token: str | None

    @classmethod
    def from_environment(cls) -> Config:
        """Load configuration from environment variables.

        Sensitive values (CF_CLIENT_ID, CF_CLIENT_SECRET) are fetched from
        AWS Systems Manager Parameter Store with caching for performance.

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

        return cls(
            base_url=base_url.rstrip("/"),
            verify_ssl=not os.getenv("NOT_VERIFY_SSL"),
            cf_client_id=(get_parameter(cf_client_id_param) if cf_client_id_param else None),
            cf_client_secret=(
                get_parameter(cf_client_secret_param) if cf_client_secret_param else None
            ),
            debug_token=os.getenv("LONG_LIVED_ACCESS_TOKEN") if os.getenv("DEBUG") else None,
        )


@dataclass(frozen=True)
class AlexaRequest:
    """Parsed and validated Alexa Smart Home request."""

    directive: dict[str, Any]
    token: str

    @classmethod
    def from_event(cls, event: dict[str, Any], config: Config) -> AlexaRequest:
        """Parse and validate an Alexa event.

        Args:
            event: Raw Lambda event from Alexa.
            config: Configuration including debug settings.

        Returns:
            Validated Alexa request.

        Raises:
            ValueError: If the event is invalid or missing required fields.
        """
        directive = event.get("directive")
        if not directive:
            raise ValueError("Missing 'directive' in event")

        # Validate payload version
        payload_version = directive.get("header", {}).get("payloadVersion")
        if payload_version != SUPPORTED_PAYLOAD_VERSION:
            raise ValueError(
                f"Unsupported payloadVersion '{payload_version}'. "
                f"Only version {SUPPORTED_PAYLOAD_VERSION} is supported."
            )

        # Extract token from various possible locations
        token = cls._extract_token(directive)

        # Fallback to debug token if available
        if not token and config.debug_token:
            logger.warning("Using debug token from environment (DEBUG mode only)")
            token = config.debug_token

        if not token:
            raise ValueError("No bearer token found in directive")

        return cls(directive=directive, token=token)

    @staticmethod
    def _extract_token(directive: dict[str, Any]) -> str | None:
        """Extract bearer token from directive.

        Token location varies by directive type:
        - endpoint.scope.token (most directives)
        - payload.grantee.token (AcceptGrant directive)
        - payload.scope.token (Discovery directive)

        Args:
            directive: Alexa directive.

        Returns:
            Bearer token if found, None otherwise.

        Raises:
            ValueError: If token type is not BearerToken.
        """
        # Try multiple locations
        scope = (
            directive.get("endpoint", {}).get("scope")
            or directive.get("payload", {}).get("grantee")
            or directive.get("payload", {}).get("scope")
        )

        if not scope:
            return None

        # Validate token type
        token_type = scope.get("type")
        if token_type and token_type != SUPPORTED_TOKEN_TYPE:
            raise ValueError(
                f"Unsupported token type '{token_type}'. Only {SUPPORTED_TOKEN_TYPE} is supported."
            )

        token: str | None = scope.get("token")
        return token


@dataclass(frozen=True)
class ErrorResponse:
    """Alexa Smart Home error response."""

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


class HomeAssistantClient:
    """Client for forwarding requests to Home Assistant."""

    def __init__(self, config: Config) -> None:
        """Initialize Home Assistant client.

        Args:
            config: Configuration for connecting to Home Assistant.
        """
        self.config = config
        self.http = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED" if config.verify_ssl else "CERT_NONE",
            timeout=urllib3.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT),
        )

        if not config.verify_ssl:
            logger.warning("SSL verification is disabled - not recommended for production")

    def forward_smart_home_request(self, event: dict[str, Any], token: str) -> dict[str, Any]:
        """Forward Alexa Smart Home request to Home Assistant.

        Args:
            event: Complete Alexa event to forward.
            token: Bearer token for authentication.

        Returns:
            Response from Home Assistant.

        Raises:
            ValueError: If response cannot be parsed.
            RuntimeError: If Home Assistant returns an error.
        """
        url = f"{self.config.base_url}/api/alexa/smart_home"
        headers = self._build_headers(token)

        logger.info(f"Forwarding request to {url}")

        try:
            response = self.http.request(  # type: ignore[no-untyped-call]
                "POST",
                url,
                headers=headers,
                body=json.dumps(event).encode("utf-8"),
            )
        except Exception as e:
            logger.exception("Failed to connect to Home Assistant")
            raise RuntimeError(f"Connection failed: {e}") from e

        # Handle HTTP errors
        if response.status >= 400:
            error_msg = self._decode_response(response.data)
            logger.error(f"Home Assistant error: {response.status} - {error_msg}")

            if response.status in (401, 403):
                raise PermissionError(f"Authentication failed: {error_msg}")
            raise RuntimeError(f"Home Assistant error {response.status}: {error_msg}")

        # Parse successful response
        try:
            result: dict[str, Any] = json.loads(response.data.decode("utf-8"))
            logger.info("Request completed successfully")
            return result
        except json.JSONDecodeError as e:
            logger.exception("Invalid JSON response")
            raise ValueError("Home Assistant returned invalid JSON") from e

    def _build_headers(self, token: str) -> dict[str, str]:
        """Build HTTP headers for request.

        Args:
            token: Bearer token for authentication.

        Returns:
            Headers dictionary.
        """
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
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
    """AWS Lambda handler for Alexa Smart Home directives.

    This function:
    1. Validates the incoming Alexa directive
    2. Extracts authentication token
    3. Forwards the request to Home Assistant
    4. Returns the response to Alexa

    Args:
        event: Lambda event containing Alexa directive.
        context: Lambda context (unused).

    Returns:
        Response from Home Assistant or error response.

    Environment Variables:
        BASE_URL: Home Assistant URL (required)
        CF_CLIENT_ID: Cloudflare Access service token client ID (required)
        CF_CLIENT_SECRET: Cloudflare Access service token client secret (required)
        NOT_VERIFY_SSL: Disable SSL verification (optional)
        DEBUG: Enable debug logging (optional)
        LONG_LIVED_ACCESS_TOKEN: Debug fallback token (optional)
    """
    try:
        # Load configuration
        config = Config.from_environment()

        # Parse and validate request
        request = AlexaRequest.from_event(event, config)

        # Log sanitized event in debug mode
        if os.getenv("DEBUG"):
            sanitized = _sanitize_event(event)
            logger.debug(f"Processing event: {sanitized}")

        # Forward to Home Assistant
        client = HomeAssistantClient(config)
        response = client.forward_smart_home_request(event, request.token)

        if os.getenv("DEBUG"):
            logger.debug(f"Response: {response}")

        return response

    except ValueError as e:
        logger.exception("Validation error")
        return ErrorResponse(ErrorType.INVALID_DIRECTIVE, str(e)).to_dict()

    except PermissionError as e:
        logger.exception("Authentication error")
        return ErrorResponse(ErrorType.INVALID_AUTHORIZATION, str(e)).to_dict()

    except RuntimeError as e:
        logger.exception("Runtime error")
        # Configuration errors (e.g., missing BASE_URL) return INTERNAL_ERROR
        # Network/connection errors to Home Assistant return BRIDGE_UNREACHABLE
        if "BASE_URL" in str(e) or "configuration" in str(e).lower():
            return ErrorResponse(ErrorType.INTERNAL_ERROR, str(e)).to_dict()
        return ErrorResponse(ErrorType.BRIDGE_UNREACHABLE, str(e)).to_dict()

    except Exception:
        logger.exception("Unexpected error processing directive")
        return ErrorResponse(
            ErrorType.INTERNAL_ERROR,
            "An unexpected error occurred",
        ).to_dict()


def _sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Create a sanitized copy of event for logging.

    Args:
        event: Event to sanitize.

    Returns:
        Event with tokens redacted.
    """
    import copy

    sanitized = copy.deepcopy(event)
    directive = sanitized.get("directive", {})

    # Redact tokens in all possible locations
    for path in [
        ("endpoint", "scope"),
        ("payload", "grantee"),
        ("payload", "scope"),
    ]:
        current = directive
        for key in path[:-1]:
            current = current.get(key, {})
        if path[-1] in current and "token" in current[path[-1]]:
            current[path[-1]]["token"] = "[REDACTED]"

    return sanitized
