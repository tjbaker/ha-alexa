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

"""Tests for Alexa OAuth handler."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import Mock

import pytest

from alexa_oauth_handler import (
    Config,
    ErrorType,
    HomeAssistantAuthClient,
    TokenRequest,
    lambda_handler,
)


@pytest.fixture
def mock_config() -> Config:
    """Create a mock configuration."""
    return Config(
        base_url="https://homeassistant.example.com",
        cf_client_id="test-client-id",
        cf_client_secret="test-client-secret",  # noqa: S106
        oauth_jwt_secret="test-jwt-secret",  # noqa: S106
    )


@pytest.fixture
def valid_oauth_event() -> dict[str, Any]:
    """Create a valid OAuth token request event."""
    body = "grant_type=authorization_code&code=test-code&client_id=test-client"
    return {
        "body": body,
        "isBase64Encoded": False,
    }


@pytest.fixture
def base64_oauth_event() -> dict[str, Any]:
    """Create a valid base64-encoded OAuth token request event."""
    body = "grant_type=authorization_code&code=test-code&client_id=test-client"
    encoded = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    return {
        "body": encoded,
        "isBase64Encoded": True,
    }


class TestConfig:
    """Tests for Config class."""

    def test_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test successful configuration loading."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "client-123")
        monkeypatch.setenv("CF_CLIENT_SECRET", "secret-456")

        config = Config.from_environment()
        assert config.base_url == "https://example.com"
        assert config.cf_client_id == "client-123"
        assert config.cf_client_secret == "secret-456"

    def test_from_environment_strips_trailing_slash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that trailing slash is removed from base URL."""
        monkeypatch.setenv("BASE_URL", "https://example.com/")
        config = Config.from_environment()
        assert config.base_url == "https://example.com"

    def test_from_environment_missing_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when BASE_URL is missing."""
        monkeypatch.delenv("BASE_URL", raising=False)
        with pytest.raises(ValueError, match="BASE_URL"):
            Config.from_environment()

    def test_cloudflare_optional(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that Cloudflare credentials are optional."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        monkeypatch.delenv("CF_CLIENT_ID", raising=False)
        monkeypatch.delenv("CF_CLIENT_SECRET", raising=False)

        config = Config.from_environment()
        assert config.cf_client_id is None
        assert config.cf_client_secret is None


class TestTokenRequest:
    """Tests for TokenRequest class."""

    def test_from_event_plain_text(self, valid_oauth_event: dict[str, Any]) -> None:
        """Test parsing plain text OAuth request."""
        request = TokenRequest.from_event(valid_oauth_event)
        assert b"grant_type=authorization_code" in request.body

    def test_from_event_base64_encoded(self, base64_oauth_event: dict[str, Any]) -> None:
        """Test parsing base64-encoded OAuth request."""
        request = TokenRequest.from_event(base64_oauth_event)
        assert b"grant_type=authorization_code" in request.body

    def test_from_event_missing_body(self) -> None:
        """Test error when body is missing."""
        event: dict[str, Any] = {}
        with pytest.raises(ValueError, match="body is required"):
            TokenRequest.from_event(event)

    def test_from_event_invalid_base64(self) -> None:
        """Test error handling for invalid base64."""
        event = {
            "body": "not-valid-base64!!!",
            "isBase64Encoded": True,
        }
        with pytest.raises(ValueError, match="Failed to decode"):
            TokenRequest.from_event(event)


class TestHomeAssistantAuthClient:
    """Tests for HomeAssistantAuthClient class."""

    def test_initialization(self, mock_config: Config) -> None:
        """Test client initialization."""
        client = HomeAssistantAuthClient(mock_config)
        assert client.config == mock_config

    def test_exchange_token_success(self, mock_config: Config, mocker: Any) -> None:
        """Test successful token exchange."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = json.dumps(
            {
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        ).encode("utf-8")

        mock_request = mocker.patch.object(client.http, "request", return_value=mock_response)

        body = b"grant_type=authorization_code&code=test"
        result = client.exchange_token(body)

        assert result["access_token"] == "new-access-token"
        assert result["token_type"] == "Bearer"
        mock_request.assert_called_once()

    def test_exchange_token_auth_error(self, mock_config: Config, mocker: Any) -> None:
        """Test handling of authentication errors."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 401
        mock_response.data = b"Unauthorized"

        mocker.patch.object(client.http, "request", return_value=mock_response)

        body = b"grant_type=authorization_code&code=invalid"
        with pytest.raises(PermissionError, match="Authentication failed"):
            client.exchange_token(body)

    def test_exchange_token_server_error(self, mock_config: Config, mocker: Any) -> None:
        """Test handling of server errors."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 500
        mock_response.data = b"Internal Server Error"

        mocker.patch.object(client.http, "request", return_value=mock_response)

        body = b"grant_type=authorization_code&code=test"
        with pytest.raises(RuntimeError, match="Token exchange error 500"):
            client.exchange_token(body)

    def test_cloudflare_headers(self, mocker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that Cloudflare headers are added when configured."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "client-123")
        monkeypatch.setenv("CF_CLIENT_SECRET", "secret-456")

        config = Config.from_environment()
        client = HomeAssistantAuthClient(config)

        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = json.dumps({"access_token": "token"}).encode("utf-8")

        mock_request = mocker.patch.object(client.http, "request", return_value=mock_response)

        body = b"grant_type=authorization_code"
        client.exchange_token(body)

        call_args = mock_request.call_args
        headers = call_args.kwargs["headers"]

        assert headers["CF-Access-Client-Id"] == "client-123"
        assert headers["CF-Access-Client-Secret"] == "secret-456"

    def test_invalid_json_response(self, mock_config: Config, mocker: Any) -> None:
        """Test handling of invalid JSON responses."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"not valid json"

        mocker.patch.object(client.http, "request", return_value=mock_response)

        body = b"grant_type=authorization_code"
        with pytest.raises(ValueError, match="invalid JSON"):
            client.exchange_token(body)


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_successful_token_exchange(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test successful token exchange through Lambda handler."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = json.dumps(
            {
                "access_token": "new-token",
                "token_type": "Bearer",
            }
        ).encode("utf-8")

        mocker.patch(
            "alexa_oauth_handler.HomeAssistantAuthClient.exchange_token",
            return_value={
                "access_token": "new-token",
                "token_type": "Bearer",
            },
        )

        result = lambda_handler(valid_oauth_event, None)

        assert result["access_token"] == "new-token"
        assert result["token_type"] == "Bearer"

    def test_missing_base_url(
        self, valid_oauth_event: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error when BASE_URL is missing."""
        monkeypatch.delenv("BASE_URL", raising=False)
        result = lambda_handler(valid_oauth_event, None)

        assert result["event"]["payload"]["type"] == ErrorType.INVALID_REQUEST.value

    def test_invalid_event(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test handling of invalid events."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        result = lambda_handler({}, None)

        assert result["event"]["payload"]["type"] == ErrorType.INVALID_REQUEST.value

    def test_authentication_error(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test handling of authentication errors."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mocker.patch(
            "alexa_oauth_handler.HomeAssistantAuthClient.exchange_token",
            side_effect=PermissionError("Auth failed"),
        )

        result = lambda_handler(valid_oauth_event, None)

        assert result["event"]["payload"]["type"] == ErrorType.INVALID_AUTHORIZATION.value

    def test_runtime_error(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test handling of runtime errors."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mocker.patch(
            "alexa_oauth_handler.HomeAssistantAuthClient.exchange_token",
            side_effect=RuntimeError("Connection failed"),
        )

        result = lambda_handler(valid_oauth_event, None)

        assert result["event"]["payload"]["type"] == ErrorType.INTERNAL_ERROR.value
