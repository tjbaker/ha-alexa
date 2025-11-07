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

"""Tests for Alexa Smart Home handler."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock

import pytest

from alexa_smart_home_handler import (
    AlexaRequest,
    Config,
    ErrorType,
    HomeAssistantClient,
    lambda_handler,
)


@pytest.fixture
def mock_config() -> Config:
    """Create a mock configuration."""
    return Config(
        base_url="https://homeassistant.example.com",
        verify_ssl=True,
        cf_client_id=None,
        cf_client_secret=None,
        debug_token=None,
    )


@pytest.fixture
def valid_alexa_event() -> dict[str, Any]:
    """Create a valid Alexa Smart Home event."""
    return {
        "directive": {
            "header": {
                "namespace": "Alexa.Discovery",
                "name": "Discover",
                "payloadVersion": "3",
                "messageId": "abc-123",
            },
            "payload": {
                "scope": {
                    "type": "BearerToken",
                    "token": "test-token-123",
                }
            },
        }
    }


class TestConfig:
    """Tests for Config class."""

    def test_from_environment_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test successful configuration loading."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        config = Config.from_environment()
        assert config.base_url == "https://example.com"
        assert config.verify_ssl is True

    def test_from_environment_strips_trailing_slash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that trailing slashes are removed from BASE_URL."""
        monkeypatch.setenv("BASE_URL", "https://example.com/")
        config = Config.from_environment()
        assert config.base_url == "https://example.com"

    def test_from_environment_missing_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when BASE_URL is missing."""
        monkeypatch.delenv("BASE_URL", raising=False)
        with pytest.raises(RuntimeError, match="BASE_URL"):
            Config.from_environment()

    def test_cloudflare_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Cloudflare Access configuration."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "client-123")
        monkeypatch.setenv("CF_CLIENT_SECRET", "secret-456")

        config = Config.from_environment()
        assert config.cf_client_id == "client-123"
        assert config.cf_client_secret == "secret-456"


class TestAlexaRequest:
    """Tests for AlexaRequest class."""

    def test_from_event_success(
        self, valid_alexa_event: dict[str, Any], mock_config: Config
    ) -> None:
        """Test successful request parsing."""
        request = AlexaRequest.from_event(valid_alexa_event, mock_config)
        assert request.token == "test-token-123"
        assert request.directive == valid_alexa_event["directive"]

    def test_from_event_missing_directive(self, mock_config: Config) -> None:
        """Test error when directive is missing."""
        event = {}
        with pytest.raises(ValueError, match="Missing 'directive'"):
            AlexaRequest.from_event(event, mock_config)

    def test_from_event_wrong_payload_version(self, mock_config: Config) -> None:
        """Test error with unsupported payload version."""
        event = {
            "directive": {
                "header": {"payloadVersion": "2"},
                "payload": {"scope": {"type": "BearerToken", "token": "test"}},
            }
        }
        with pytest.raises(ValueError, match="Unsupported payloadVersion"):
            AlexaRequest.from_event(event, mock_config)

    def test_from_event_missing_token(self, mock_config: Config) -> None:
        """Test error when token is missing."""
        event = {
            "directive": {
                "header": {"payloadVersion": "3"},
                "payload": {},
            }
        }
        with pytest.raises(ValueError, match="No bearer token"):
            AlexaRequest.from_event(event, mock_config)

    def test_token_from_endpoint_scope(self, mock_config: Config) -> None:
        """Test extracting token from endpoint.scope."""
        event = {
            "directive": {
                "header": {"payloadVersion": "3"},
                "endpoint": {"scope": {"type": "BearerToken", "token": "endpoint-token"}},
            }
        }
        request = AlexaRequest.from_event(event, mock_config)
        assert request.token == "endpoint-token"

    def test_token_from_grantee(self, mock_config: Config) -> None:
        """Test extracting token from payload.grantee."""
        event = {
            "directive": {
                "header": {"payloadVersion": "3"},
                "payload": {"grantee": {"type": "BearerToken", "token": "grantee-token"}},
            }
        }
        request = AlexaRequest.from_event(event, mock_config)
        assert request.token == "grantee-token"


class TestHomeAssistantClient:
    """Tests for HomeAssistantClient class."""

    def test_initialization(self, mock_config: Config) -> None:
        """Test client initialization."""
        client = HomeAssistantClient(mock_config)
        assert client.config == mock_config

    def test_forward_request_success(self, mock_config: Config, mocker: Any) -> None:
        """Test successful request forwarding."""
        client = HomeAssistantClient(mock_config)

        # Mock successful response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = json.dumps({"event": {"header": {"name": "Response"}}}).encode()

        mock_request = mocker.patch.object(client.http, "request", return_value=mock_response)

        event = {"directive": {"header": {"name": "TurnOn"}}}
        result = client.forward_smart_home_request(event, "test-token")

        assert result["event"]["header"]["name"] == "Response"
        mock_request.assert_called_once()

    def test_forward_request_auth_error(self, mock_config: Config, mocker: Any) -> None:
        """Test handling of authentication errors."""
        client = HomeAssistantClient(mock_config)

        mock_response = Mock()
        mock_response.status = 401
        mock_response.data = b"Unauthorized"

        mocker.patch.object(client.http, "request", return_value=mock_response)

        with pytest.raises(PermissionError, match="Authentication failed"):
            client.forward_smart_home_request({}, "test-token")

    def test_cloudflare_headers(self, mocker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that Cloudflare headers are added when configured."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "client-123")
        monkeypatch.setenv("CF_CLIENT_SECRET", "secret-456")

        config = Config.from_environment()
        client = HomeAssistantClient(config)

        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b'{"event": {}}'

        mock_request = mocker.patch.object(client.http, "request", return_value=mock_response)

        client.forward_smart_home_request({}, "test-token")

        call_args = mock_request.call_args
        headers = call_args.kwargs["headers"]

        assert headers["CF-Access-Client-Id"] == "client-123"
        assert headers["CF-Access-Client-Secret"] == "secret-456"


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_successful_request(
        self,
        valid_alexa_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test successful request processing."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = json.dumps({"event": {"header": {"name": "Response"}}}).encode()

        mocker.patch("urllib3.PoolManager.request", return_value=mock_response)

        result = lambda_handler(valid_alexa_event, None)

        assert result["event"]["header"]["name"] == "Response"

    def test_missing_base_url(
        self, valid_alexa_event: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error when BASE_URL is not configured."""
        monkeypatch.delenv("BASE_URL", raising=False)

        result = lambda_handler(valid_alexa_event, None)

        assert result["event"]["payload"]["type"] == ErrorType.INTERNAL_ERROR.value
        assert "BASE_URL" in result["event"]["payload"]["message"]

    def test_invalid_event(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test handling of invalid event."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        result = lambda_handler({}, None)

        assert result["event"]["payload"]["type"] == ErrorType.INVALID_DIRECTIVE.value

    def test_authentication_error(
        self,
        valid_alexa_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test handling of authentication errors."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mock_response = Mock()
        mock_response.status = 401
        mock_response.data = b"Unauthorized"

        mocker.patch("urllib3.PoolManager.request", return_value=mock_response)

        result = lambda_handler(valid_alexa_event, None)

        assert result["event"]["payload"]["type"] == ErrorType.INVALID_AUTHORIZATION.value
