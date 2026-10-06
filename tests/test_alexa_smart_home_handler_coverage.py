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

"""Additional tests to improve alexa_smart_home_handler coverage to 90%+.

This test module focuses on:
1. Exception handling edge cases
2. Event sanitization edge cases
3. Error response paths
4. Configuration edge cases
"""

from typing import Any

import pytest

from alexa_smart_home_handler import Config, _sanitize_event, lambda_handler


class TestEventSanitization:
    """Test event sanitization edge cases."""

    def test_sanitize_event_with_endpoint_scope_token(self) -> None:
        """Test sanitization of token in endpoint scope."""
        event = {
            "directive": {
                "endpoint": {"scope": {"token": "secret_bearer_token", "type": "BearerToken"}}
            }
        }
        sanitized = _sanitize_event(event)
        assert sanitized["directive"]["endpoint"]["scope"]["token"] == "[REDACTED]"
        assert sanitized["directive"]["endpoint"]["scope"]["type"] == "BearerToken"

    def test_sanitize_event_with_payload_grantee_token(self) -> None:
        """Test sanitization of token in payload grantee."""
        event = {
            "directive": {"payload": {"grantee": {"token": "secret_token", "type": "BearerToken"}}}
        }
        sanitized = _sanitize_event(event)
        assert sanitized["directive"]["payload"]["grantee"]["token"] == "[REDACTED]"

    def test_sanitize_event_with_accept_grant_code(self) -> None:
        """Test sanitization of an AcceptGrant directive's authorization code and grantee token."""
        event = {
            "directive": {
                "header": {"namespace": "Alexa.Authorization", "name": "AcceptGrant"},
                "payload": {
                    "grant": {"type": "OAuth2.AuthorizationCode", "code": "secret_auth_code"},
                    "grantee": {"type": "BearerToken", "token": "secret_token"},
                },
            }
        }
        sanitized = _sanitize_event(event)
        assert sanitized["directive"]["payload"]["grant"]["code"] == "[REDACTED]"
        assert sanitized["directive"]["payload"]["grant"]["type"] == "OAuth2.AuthorizationCode"
        assert sanitized["directive"]["payload"]["grantee"]["token"] == "[REDACTED]"
        # The original event is left intact for forwarding to Home Assistant.
        assert event["directive"]["payload"]["grant"]["code"] == "secret_auth_code"

    def test_sanitize_event_with_payload_scope_token(self) -> None:
        """Test sanitization of token in payload scope."""
        event = {
            "directive": {"payload": {"scope": {"token": "bearer_token", "type": "BearerToken"}}}
        }
        sanitized = _sanitize_event(event)
        assert sanitized["directive"]["payload"]["scope"]["token"] == "[REDACTED]"

    def test_sanitize_event_with_multiple_tokens(self) -> None:
        """Test sanitization when multiple token locations exist."""
        event = {
            "directive": {
                "endpoint": {"scope": {"token": "token1"}},
                "payload": {
                    "grantee": {"token": "token2"},
                    "scope": {"token": "token3"},
                },
            }
        }
        sanitized = _sanitize_event(event)
        assert sanitized["directive"]["endpoint"]["scope"]["token"] == "[REDACTED]"
        assert sanitized["directive"]["payload"]["grantee"]["token"] == "[REDACTED]"
        assert sanitized["directive"]["payload"]["scope"]["token"] == "[REDACTED]"

    def test_sanitize_event_missing_nested_keys(self) -> None:
        """Test sanitization when nested keys don't exist."""
        event = {"directive": {"header": {"name": "Discover"}}}
        sanitized = _sanitize_event(event)
        # Should not raise, just return as-is
        assert sanitized == event

    def test_sanitize_event_partial_paths(self) -> None:
        """Test sanitization with partial path existence."""
        event = {"directive": {"endpoint": {"endpointId": "123"}}}  # No scope
        sanitized = _sanitize_event(event)
        assert sanitized == event

    def test_sanitize_event_no_token_in_scope(self) -> None:
        """Test sanitization when scope exists but has no token."""
        event = {"directive": {"endpoint": {"scope": {"type": "BearerToken"}}}}  # No token key
        sanitized = _sanitize_event(event)
        assert sanitized == event


class TestExceptionHandling:
    """Test exception handling edge cases."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")

    def test_unexpected_exception_in_handler(self, mock_config: Any, mocker: Any) -> None:
        """Test handling of unexpected exceptions."""
        # Mock Config to raise unexpected exception
        mocker.patch(
            "alexa_smart_home_handler.Config.from_environment",
            side_effect=ZeroDivisionError("Unexpected error"),
        )

        event = {
            "directive": {
                "header": {"namespace": "Alexa.Discovery", "name": "Discover"},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert "payload" in response["event"]
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"
        assert "An unexpected error occurred" in response["event"]["payload"]["message"]

    def test_runtime_error_with_base_url_in_message(self, monkeypatch: Any, mocker: Any) -> None:
        """Test RuntimeError with BASE_URL in message returns INTERNAL_ERROR."""
        monkeypatch.delenv("BASE_URL", raising=False)

        event = {
            "directive": {
                "header": {"namespace": "Alexa.Discovery", "name": "Discover"},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"
        assert "BASE_URL" in response["event"]["payload"]["message"]

    def test_parameter_store_failure_returns_internal_error(
        self, mock_config: Any, mocker: Any
    ) -> None:
        """Test Parameter Store failures return INTERNAL_ERROR, not BRIDGE_UNREACHABLE."""
        mocker.patch(
            "alexa_smart_home_handler.get_parameter",
            side_effect=RuntimeError("Failed to fetch parameter /ha-alexa/cf-id: AccessDenied"),
        )

        event = {
            "directive": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "Discover",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "endpoint": {"scope": {"token": "bearer_token", "type": "BearerToken"}},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"
        assert "parameter" in response["event"]["payload"]["message"].lower()

    def test_runtime_error_network_issue_returns_bridge_unreachable(
        self, mock_config: Any, mocker: Any
    ) -> None:
        """Test RuntimeError without config keywords returns BRIDGE_UNREACHABLE."""
        mock_http = mocker.Mock()
        mock_http.request.side_effect = RuntimeError("Network timeout occurred")
        mocker.patch("alexa_smart_home_handler.urllib3.PoolManager", return_value=mock_http)

        event = {
            "directive": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "Discover",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "endpoint": {"scope": {"token": "bearer_token", "type": "BearerToken"}},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert response["event"]["payload"]["type"] == "BRIDGE_UNREACHABLE"

    def test_connection_error_returns_bridge_unreachable(
        self, mock_config: Any, mocker: Any
    ) -> None:
        """Test connection errors return BRIDGE_UNREACHABLE."""
        mock_http = mocker.Mock()
        mock_http.request.side_effect = ConnectionError("Could not connect to Home Assistant")
        mocker.patch("alexa_smart_home_handler.urllib3.PoolManager", return_value=mock_http)

        event = {
            "directive": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "Discover",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "endpoint": {"scope": {"token": "bearer_token", "type": "BearerToken"}},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert response["event"]["payload"]["type"] == "BRIDGE_UNREACHABLE"


class TestConfigEdgeCases:
    """Test Config edge cases."""

    def test_config_without_cloudflare_credentials(self, monkeypatch: Any) -> None:
        """Test Config when Cloudflare credentials are not set."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.delenv("CF_CLIENT_ID", raising=False)
        monkeypatch.delenv("CF_CLIENT_SECRET", raising=False)

        config = Config.from_environment()
        assert config.base_url == "https://ha.example.com"
        assert config.cf_client_id is None
        assert config.cf_client_secret is None

    def test_config_with_ssl_disabled(self, monkeypatch: Any) -> None:
        """Test Config with SSL verification disabled."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("NOT_VERIFY_SSL", "1")

        config = Config.from_environment()
        assert config.verify_ssl is False

    def test_config_with_ssl_enabled_by_default(self, monkeypatch: Any) -> None:
        """Test Config has SSL verification enabled by default."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")
        monkeypatch.delenv("NOT_VERIFY_SSL", raising=False)

        config = Config.from_environment()
        assert config.verify_ssl is True


class TestDebugMode:
    """Test DEBUG mode logging branches."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")

    def test_debug_logging_enabled(self, mock_config: Any, mocker: Any) -> None:
        """Test directive handling with DEBUG logging enabled."""
        mocker.patch.dict("os.environ", {"DEBUG": "1"})

        mock_response = mocker.Mock()
        mock_response.status = 200
        mock_response.data = b'{"event": {"header": {"name": "Response"}}}'

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_smart_home_handler.urllib3.PoolManager", return_value=mock_http)

        event = {
            "directive": {
                "header": {
                    "namespace": "Alexa.PowerController",
                    "name": "TurnOn",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "endpoint": {
                    "scope": {"token": "secret_token", "type": "BearerToken"},
                    "endpointId": "device-001",
                },
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        # Debug logging should have triggered, but response should still be successful
        assert response["event"]["header"]["name"] == "Response"


class TestHTTPErrorHandling:
    """Test HTTP error response handling."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")

    def test_http_401_returns_invalid_authorization(self, mock_config: Any, mocker: Any) -> None:
        """Test HTTP 401 returns INVALID_AUTHORIZATION_CREDENTIAL."""
        mock_response = mocker.Mock()
        mock_response.status = 401
        mock_response.data = b"Unauthorized"

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_smart_home_handler.urllib3.PoolManager", return_value=mock_http)

        event = {
            "directive": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "Discover",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "endpoint": {"scope": {"token": "bearer_token", "type": "BearerToken"}},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert response["event"]["payload"]["type"] == "INVALID_AUTHORIZATION_CREDENTIAL"

    def test_http_403_returns_bridge_unreachable(self, mock_config: Any, mocker: Any) -> None:
        """Test HTTP 403 (e.g. Cloudflare Access denial) is not reported as a bad credential."""
        mock_response = mocker.Mock()
        mock_response.status = 403
        mock_response.data = b"Forbidden"

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_smart_home_handler.urllib3.PoolManager", return_value=mock_http)

        event = {
            "directive": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "Discover",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "endpoint": {"scope": {"token": "bearer_token", "type": "BearerToken"}},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert response["event"]["payload"]["type"] == "BRIDGE_UNREACHABLE"

    def test_http_500_returns_bridge_unreachable(self, mock_config: Any, mocker: Any) -> None:
        """Test HTTP 500 returns BRIDGE_UNREACHABLE (HA is down/having issues)."""
        mock_response = mocker.Mock()
        mock_response.status = 500
        mock_response.data = b"Internal Server Error"

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_smart_home_handler.urllib3.PoolManager", return_value=mock_http)

        event = {
            "directive": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "Discover",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "endpoint": {"scope": {"token": "bearer_token", "type": "BearerToken"}},
                "payload": {},
            }
        }

        response = lambda_handler(event, None)
        assert "event" in response
        assert response["event"]["payload"]["type"] == "BRIDGE_UNREACHABLE"


class TestUnusableUpstreamResponses:
    """Responses that aren't from HA's API must not be blamed on Alexa's directive."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")

    @pytest.fixture
    def event(self) -> dict[str, Any]:
        """A minimal valid discovery directive."""
        return {
            "directive": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "Discover",
                    "payloadVersion": "3",
                    "messageId": "abc-123",
                },
                "payload": {"scope": {"token": "bearer_token", "type": "BearerToken"}},
            }
        }

    def _mock_response(self, mocker: Any, status: int, data: bytes) -> Any:
        mock_response = mocker.Mock()
        mock_response.status = status
        mock_response.data = data
        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_smart_home_handler.urllib3.PoolManager", return_value=mock_http)
        return mock_http

    def test_invalid_json_returns_bridge_unreachable(
        self, mock_config: Any, event: dict[str, Any], mocker: Any
    ) -> None:
        """Test that a non-JSON 200 (e.g. an HTML page) is BRIDGE_UNREACHABLE."""
        self._mock_response(mocker, 200, b"<html>Sign in</html>")

        response = lambda_handler(event, None)
        assert response["event"]["payload"]["type"] == "BRIDGE_UNREACHABLE"

    def test_non_object_json_returns_bridge_unreachable(
        self, mock_config: Any, event: dict[str, Any], mocker: Any
    ) -> None:
        """Test that a JSON response that is not an object is BRIDGE_UNREACHABLE."""
        self._mock_response(mocker, 200, b"[]")

        response = lambda_handler(event, None)
        assert response["event"]["payload"]["type"] == "BRIDGE_UNREACHABLE"

    def test_redirect_is_not_followed(
        self, mock_config: Any, event: dict[str, Any], mocker: Any
    ) -> None:
        """Test that a redirect (e.g. Cloudflare Access login) is BRIDGE_UNREACHABLE."""
        mock_http = self._mock_response(mocker, 302, b"")

        response = lambda_handler(event, None)
        assert response["event"]["payload"]["type"] == "BRIDGE_UNREACHABLE"
        assert mock_http.request.call_args.kwargs["redirect"] is False
