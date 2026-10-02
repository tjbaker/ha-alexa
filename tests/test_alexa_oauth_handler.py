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
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from alexa_authorize_handler import _json_b64
from alexa_authorize_handler import lambda_handler as authorize_handler
from alexa_oauth_handler import (
    Config,
    HomeAssistantAuthClient,
    TokenExchangeError,
    TokenRequest,
    UpstreamError,
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
        with pytest.raises(RuntimeError, match="BASE_URL"):
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

    def test_exchange_token_non_oauth_403_is_server_error(
        self, mock_config: Config, mocker: Any
    ) -> None:
        """Test that a non-OAuth 403 (e.g. Cloudflare Access) is not relayed as invalid_grant."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 403
        mock_response.data = b"<html>Forbidden</html>"

        mocker.patch.object(client.http, "request", return_value=mock_response)

        body = b"grant_type=refresh_token&refresh_token=abc"
        with pytest.raises(RuntimeError, match="Token exchange error 403"):
            client.exchange_token(body)

    def test_exchange_token_relays_oauth_403(self, mock_config: Config, mocker: Any) -> None:
        """Test that a 403 OAuth error body from Home Assistant is relayed with its status."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 403
        mock_response.data = json.dumps(
            {"error": "access_denied", "error_description": "User is not active"}
        ).encode("utf-8")

        mocker.patch.object(client.http, "request", return_value=mock_response)

        with pytest.raises(TokenExchangeError) as exc_info:
            client.exchange_token(b"grant_type=refresh_token&refresh_token=abc")

        assert exc_info.value.error["error"] == "access_denied"
        assert exc_info.value.status == 403

    def test_exchange_token_relays_oauth_error(self, mock_config: Config, mocker: Any) -> None:
        """Test that HTTP 400 OAuth errors from Home Assistant are relayed."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 400
        mock_response.data = json.dumps(
            {"error": "invalid_grant", "error_description": "Invalid code"}
        ).encode("utf-8")

        mocker.patch.object(client.http, "request", return_value=mock_response)

        body = b"grant_type=authorization_code&code=expired"
        with pytest.raises(TokenExchangeError) as exc_info:
            client.exchange_token(body)

        assert exc_info.value.error["error"] == "invalid_grant"

    def test_exchange_token_400_with_unparseable_body(
        self, mock_config: Config, mocker: Any
    ) -> None:
        """Test that HTTP 400 with a non-OAuth body is a server error, not invalid_grant."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 400
        mock_response.data = b"Bad Request"

        mocker.patch.object(client.http, "request", return_value=mock_response)

        with pytest.raises(RuntimeError, match="Token exchange error 400"):
            client.exchange_token(b"grant_type=authorization_code&code=bad")

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
        with pytest.raises(UpstreamError, match="invalid JSON"):
            client.exchange_token(body)

    def test_non_object_json_response(self, mock_config: Config, mocker: Any) -> None:
        """Test that a JSON response that is not an object is an upstream error."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b'["not", "a", "token"]'

        mocker.patch.object(client.http, "request", return_value=mock_response)

        with pytest.raises(UpstreamError, match="unexpected response"):
            client.exchange_token(b"grant_type=authorization_code")

    def test_redirect_is_not_followed(self, mock_config: Config, mocker: Any) -> None:
        """Test that a redirect (e.g. Cloudflare Access login) is an upstream error."""
        client = HomeAssistantAuthClient(mock_config)

        mock_response = Mock()
        mock_response.status = 302
        mock_response.data = b""

        mock_request = mocker.patch.object(client.http, "request", return_value=mock_response)

        with pytest.raises(UpstreamError, match="Unexpected redirect 302"):
            client.exchange_token(b"grant_type=authorization_code")

        assert mock_request.call_args.kwargs["redirect"] is False


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

        assert result["statusCode"] == 200
        assert result["headers"]["Cache-Control"] == "no-store"
        body = json.loads(result["body"])
        assert body["access_token"] == "new-token"
        assert body["token_type"] == "Bearer"

    def test_missing_base_url(
        self, valid_oauth_event: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that missing configuration is a generic 500, not an upstream error."""
        monkeypatch.delenv("BASE_URL", raising=False)
        result = lambda_handler(valid_oauth_event, None)

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"] == "server_error"
        assert body["error_description"] == "Server configuration error"

    def test_invalid_event(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test handling of invalid events."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        result = lambda_handler({}, None)

        assert result["statusCode"] == 400
        assert json.loads(result["body"])["error"] == "invalid_request"

    def test_oauth_error_relayed(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that OAuth errors from Home Assistant are relayed with HTTP 400."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mocker.patch(
            "alexa_oauth_handler.HomeAssistantAuthClient.exchange_token",
            side_effect=TokenExchangeError({"error": "invalid_grant"}),
        )

        result = lambda_handler(valid_oauth_event, None)

        assert result["statusCode"] == 400
        assert json.loads(result["body"])["error"] == "invalid_grant"

    def test_token_exchange_error_keeps_status(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that relayed OAuth errors keep Home Assistant's HTTP status."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mocker.patch(
            "alexa_oauth_handler.HomeAssistantAuthClient.exchange_token",
            side_effect=TokenExchangeError({"error": "access_denied"}, 403),
        )

        result = lambda_handler(valid_oauth_event, None)

        assert result["statusCode"] == 403
        assert json.loads(result["body"])["error"] == "access_denied"

    def test_cloudflare_denial_is_not_invalid_grant(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that a Cloudflare Access 403 maps to server_error so Alexa keeps the link."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mock_response = Mock()
        mock_response.status = 403
        mock_response.data = b"<html>Forbidden</html>"
        mock_http = Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        result = lambda_handler(valid_oauth_event, None)

        assert result["statusCode"] == 502
        assert json.loads(result["body"])["error"] == "server_error"

    def test_runtime_error(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that Parameter Store failures don't leak the parameter path."""
        monkeypatch.setenv("BASE_URL", "https://example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "/ha-alexa/cloudflare-client-id")

        mocker.patch(
            "alexa_oauth_handler.get_parameter",
            side_effect=RuntimeError(
                "Failed to fetch parameter /ha-alexa/cloudflare-client-id: AccessDenied"
            ),
        )

        result = lambda_handler(valid_oauth_event, None)

        assert result["statusCode"] == 500
        assert json.loads(result["body"])["error"] == "server_error"
        assert "/ha-alexa/" not in result["body"]

    def test_upstream_error_hides_details(
        self,
        valid_oauth_event: dict[str, Any],
        mocker: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that upstream failures return a generic 502 without hostnames."""
        monkeypatch.setenv("BASE_URL", "https://example.com")

        mocker.patch(
            "alexa_oauth_handler.HomeAssistantAuthClient.exchange_token",
            side_effect=UpstreamError("Connection failed: example.com:443 refused"),
        )

        result = lambda_handler(valid_oauth_event, None)

        assert result["statusCode"] == 502
        assert json.loads(result["body"]) == {
            "error": "server_error",
            "error_description": "Home Assistant is unavailable",
        }


class TestAuthorizeToTokenRoundTrip:
    """End-to-end test of the stateless JWT authorization code flow."""

    def test_jwt_code_from_authorize_is_unwrapped_for_home_assistant(
        self, mocker: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a code minted by the authorize handler reaches HA as the raw HA code."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "VENDOR123")
        # Both handlers resolve the same Parameter Store path to the same secret
        monkeypatch.setenv("OAUTH_JWT_SECRET", "/ha-alexa/oauth-jwt-secret")

        # Home Assistant redirects back to the authorize endpoint with its own code
        redirect_uri = "https://pitangui.amazon.com/api/skill/link/VENDOR123"
        callback = authorize_handler(
            {
                "queryStringParameters": {
                    "code": "ha-code-123",
                    "state": _json_b64({"a_state": "alexa-state", "redirect_uri": redirect_uri}),
                },
                "requestContext": {"domainName": "authorize.lambda-url.us-east-1.on.aws"},
            },
            None,
        )
        assert callback["statusCode"] == 302
        location = urlparse(callback["headers"]["Location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == redirect_uri
        alexa_params = parse_qs(location.query)
        assert alexa_params["state"] == ["alexa-state"]
        jwt_code = alexa_params["code"][0]
        assert jwt_code.count(".") == 2
        assert "ha-code-123" not in jwt_code

        # Alexa then exchanges the JWT code at the token endpoint
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = json.dumps(
            {"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer"}
        ).encode("utf-8")
        mock_http = Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        token_body = urlencode(
            {
                "grant_type": "authorization_code",
                "code": jwt_code,
                "client_id": "https://pitangui.amazon.com/",
            }
        )
        result = lambda_handler({"body": token_body, "isBase64Encoded": False}, None)

        assert result["statusCode"] == 200
        assert json.loads(result["body"])["access_token"] == "access"

        # Home Assistant received its original code, with the other params intact
        forwarded = parse_qs(mock_http.request.call_args.kwargs["body"].decode("utf-8"))
        assert forwarded == {
            "grant_type": ["authorization_code"],
            "code": ["ha-code-123"],
            "client_id": ["https://pitangui.amazon.com/"],
        }
