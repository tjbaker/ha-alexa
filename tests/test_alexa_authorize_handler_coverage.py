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

"""Additional tests to improve alexa_authorize_handler coverage to 92%+.

This test module focuses on:
1. Exception handling in URL parsing
2. Query sanitization edge cases
3. Error response edge cases
4. Exception handling in lambda_handler
"""

from typing import Any

import pytest

from alexa_authorize_handler import (
    Config,
    _is_allowed_redirect,
    _sanitize_query,
    lambda_handler,
)


class TestRedirectValidation:
    """Test redirect URL validation edge cases."""

    def test_is_allowed_redirect_with_exception(self) -> None:
        """Test redirect validation handles exceptions gracefully."""
        # Pass something that will cause urlparse to fail or validation to error
        result = _is_allowed_redirect(None, "vendor123")  # type: ignore[arg-type]
        assert result is False

    def test_is_allowed_redirect_with_http_scheme(self) -> None:
        """Test redirect validation rejects non-HTTPS URLs."""
        result = _is_allowed_redirect("http://pitangui.amazon.com/api/skill/link/ABC123", "ABC123")
        assert result is False

    def test_is_allowed_redirect_with_invalid_domain(self) -> None:
        """Test redirect validation rejects non-Alexa domains."""
        result = _is_allowed_redirect("https://evil.com/redirect", "ABC123")
        assert result is False


class TestQuerySanitization:
    """Test query parameter sanitization edge cases."""

    def test_sanitize_query_with_code(self) -> None:
        """Test that authorization codes are redacted."""
        params = {"code": "secret_authorization_code_123", "state": "some_state"}
        sanitized = _sanitize_query(params)
        assert sanitized["code"] == "[REDACTED]"
        assert sanitized["state"] == "some_state"

    def test_sanitize_query_with_long_value(self) -> None:
        """Test that long values are truncated."""
        long_value = "a" * 100
        params = {"state": long_value, "redirect_uri": "https://example.com"}
        sanitized = _sanitize_query(params)
        assert "..." in sanitized["state"]
        assert len(sanitized["state"]) == 67  # 64 chars + "..."
        assert sanitized["redirect_uri"] == "https://example.com"  # Short enough

    def test_sanitize_query_with_multiple_long_values(self) -> None:
        """Test truncation of multiple long values."""
        params = {
            "state": "b" * 80,
            "redirect_uri": "c" * 90,
            "client_id": "d" * 70,
        }
        sanitized = _sanitize_query(params)
        assert "..." in sanitized["state"]
        assert "..." in sanitized["redirect_uri"]
        assert "..." in sanitized["client_id"]

    def test_sanitize_query_empty_params(self) -> None:
        """Test sanitization of empty params dict."""
        params: dict[str, str] = {}
        sanitized = _sanitize_query(params)
        assert sanitized == {}

    def test_sanitize_query_only_code(self) -> None:
        """Test sanitization with only code parameter."""
        params = {"code": "auth_code"}
        sanitized = _sanitize_query(params)
        assert sanitized == {"code": "[REDACTED]"}


class TestExceptionHandling:
    """Test exception handling in lambda_handler."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "TEST123")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "test_secret")

    def test_exception_with_invalid_event_structure(self, mock_config: Any) -> None:
        """Test handling of completely invalid event structure."""
        event: dict[str, Any] = {}  # Missing requestContext

        response = lambda_handler(event, None)
        assert response["statusCode"] == 400
        assert "error" in response["body"]

    def test_exception_with_missing_domain_name(self, mock_config: Any) -> None:
        """Test handling of missing domainName in requestContext."""
        event = {"requestContext": {}, "rawQueryString": ""}  # Missing domainName

        response = lambda_handler(event, None)
        assert response["statusCode"] == 400

    def test_callback_with_missing_both_code_and_state(self, mock_config: Any) -> None:
        """Test callback without code or state."""
        event = {
            "requestContext": {"domainName": "test.lambda-url.us-east-1.on.aws"},
            "rawQueryString": "",  # No code, no state
        }

        response = lambda_handler(event, None)
        # Should handle as initial request, not callback
        # Will fail due to missing client_id
        assert response["statusCode"] == 400

    def test_unsupported_response_type_without_redirect_uri(self, mock_config: Any) -> None:
        """Test unsupported response_type without valid redirect_uri."""
        event = {
            "requestContext": {"domainName": "test.lambda-url.us-east-1.on.aws"},
            "rawQueryString": "response_type=token&client_id=test",  # No redirect_uri
        }

        response = lambda_handler(event, None)
        assert response["statusCode"] == 400
        assert "error" in response["body"]

    def test_callback_with_invalid_base64_state(self, mock_config: Any) -> None:
        """Test callback with state that's not valid base64."""
        event = {
            "requestContext": {"domainName": "test.lambda-url.us-east-1.on.aws"},
            "rawQueryString": "code=test_code&state=!!!not_base64!!!",
        }

        response = lambda_handler(event, None)
        assert response["statusCode"] == 400
        assert "error" in response["body"]


class TestDebugMode:
    """Test DEBUG mode logging."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "TEST123")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "test_secret")

    def test_initial_request_with_debug_logging(self, mock_config: Any, mocker: Any) -> None:
        """Test initial authorization request with DEBUG logging."""
        mocker.patch.dict("os.environ", {"DEBUG": "1"})

        event = {
            "requestContext": {"domainName": "test.lambda-url.us-east-1.on.aws"},
            "queryStringParameters": {
                "client_id": "https://ha.example.com",
                "redirect_uri": "https://pitangui.amazon.com/api/skill/link/TEST123",
                "state": "test_state",
                "response_type": "code",
            },
        }

        response = lambda_handler(event, None)
        assert response["statusCode"] == 302
        assert "Location" in response["headers"]

    def test_callback_with_debug_logging(self, mock_config: Any, mocker: Any) -> None:
        """Test callback with DEBUG logging."""
        mocker.patch.dict("os.environ", {"DEBUG": "1"})

        import base64
        import json

        envelope = {
            "a_state": "alexa_state_123",
            "redirect_uri": "https://pitangui.amazon.com/api/skill/link/TEST123",
        }
        encoded_state = base64.urlsafe_b64encode(json.dumps(envelope).encode()).decode().rstrip("=")

        event = {
            "requestContext": {"domainName": "test.lambda-url.us-east-1.on.aws"},
            "queryStringParameters": {
                "code": "ha_code_123",
                "state": encoded_state,
            },
        }

        response = lambda_handler(event, None)
        assert response["statusCode"] == 302
        assert "Location" in response["headers"]
        # Should include JWT code in redirect
        assert "code=" in response["headers"]["Location"]


class TestConfigEdgeCases:
    """Test Config edge cases."""

    def test_config_missing_vendor_id(self, monkeypatch: Any) -> None:
        """Test Config raises error when ALEXA_VENDOR_ID is missing."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "test_secret")
        monkeypatch.delenv("ALEXA_VENDOR_ID", raising=False)

        with pytest.raises(RuntimeError, match="ALEXA_VENDOR_ID"):
            Config.from_env()

    def test_config_missing_jwt_secret(self, monkeypatch: Any) -> None:
        """Test Config raises error when OAUTH_JWT_SECRET is missing."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "TEST123")
        monkeypatch.delenv("OAUTH_JWT_SECRET", raising=False)

        with pytest.raises(RuntimeError, match="OAUTH_JWT_SECRET"):
            Config.from_env()
