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

"""Additional tests to improve alexa_oauth_handler coverage to 85%+.

This test module focuses on:
1. DEBUG logging branches
2. JWT validation edge cases
3. Sanitization functions
4. Exception handling paths
"""

import base64
import hmac
import json
import time
from hashlib import sha256
from typing import Any

import pytest

from alexa_oauth_handler import (
    Config,
    _b64url_decode,
    _sanitize_body,
    _sanitize_token_response,
    _verify_and_extract_ha_code,
    lambda_handler,
)


class TestSanitizationFunctions:
    """Test sanitization utility functions."""

    def test_sanitize_body_with_client_secret(self) -> None:
        """Test body with client_secret is redacted."""
        body = b"grant_type=authorization_code&client_secret=abc123"
        result = _sanitize_body(body)
        assert result == "[Request contains sensitive data - redacted]"

    def test_sanitize_body_with_password(self) -> None:
        """Test body with password is redacted."""
        body = b"username=admin&password=secret123"
        result = _sanitize_body(body)
        assert result == "[Request contains sensitive data - redacted]"

    def test_sanitize_body_with_refresh_token(self) -> None:
        """Test body with refresh_token is redacted."""
        body = b"grant_type=refresh_token&refresh_token=xyz789"
        result = _sanitize_body(body)
        assert result == "[Request contains sensitive data - redacted]"

    def test_sanitize_body_with_access_token(self) -> None:
        """Test body with access_token is redacted."""
        body = b"token=access_token&value=secret"
        result = _sanitize_body(body)
        assert result == "[Request contains sensitive data - redacted]"

    def test_sanitize_body_with_code(self) -> None:
        """Test body with authorization code is redacted."""
        body = b"grant_type=authorization_code&code=auth_code_123"
        result = _sanitize_body(body)
        assert result == "[Request contains sensitive data - redacted]"

    def test_sanitize_body_long_content(self) -> None:
        """Test long body is truncated."""
        body = b"data=" + b"a" * 2000
        result = _sanitize_body(body)
        assert "..." in result
        assert len(result) <= 1003  # MAX_LOG_LENGTH (1000) + "..."

    def test_sanitize_body_binary_data(self) -> None:
        """Test binary data is redacted."""
        body = b"\x80\x81\x82\x83"  # Invalid UTF-8
        result = _sanitize_body(body)
        assert result == "[Binary data - redacted]"

    def test_sanitize_body_safe_content(self) -> None:
        """Test body without sensitive data is returned as-is."""
        body = b"grant_type=client_credentials&redirect_uri=https://example.com"
        result = _sanitize_body(body)
        assert "grant_type=client_credentials" in result
        assert "redirect_uri" in result

    def test_sanitize_token_response(self) -> None:
        """Test token response sanitization."""
        response = {
            "access_token": "secret_access",
            "refresh_token": "secret_refresh",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        sanitized = _sanitize_token_response(response)
        assert sanitized["access_token"] == "[REDACTED]"
        assert sanitized["refresh_token"] == "[REDACTED]"
        assert sanitized["token_type"] == "[REDACTED]"  # Contains "token" so redacted
        assert sanitized["expires_in"] == 3600  # No "token" in key


class TestJWTVerification:
    """Test JWT verification edge cases."""

    def test_jwt_invalid_format_too_few_parts(self) -> None:
        """Test JWT with less than 3 parts."""
        result = _verify_and_extract_ha_code("invalid.jwt", "secret")
        assert result is None

    def test_jwt_invalid_format_too_many_parts(self) -> None:
        """Test JWT with more than 3 parts."""
        result = _verify_and_extract_ha_code("a.b.c.d", "secret")
        assert result is None

    def test_jwt_invalid_format_empty_string(self) -> None:
        """Test JWT with empty string."""
        result = _verify_and_extract_ha_code("", "secret")
        assert result is None

    def test_jwt_invalid_signature(self) -> None:
        """Test JWT with invalid signature."""
        header = {"alg": "HS256"}
        payload = {"ha_code": "test_code", "exp": int(time.time()) + 3600}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        # Use wrong signature
        jwt_code = f"{header_b64}.{payload_b64}.wrong_signature"
        result = _verify_and_extract_ha_code(jwt_code, "secret")
        assert result is None

    def test_jwt_expired(self) -> None:
        """Test JWT that has expired."""
        header = {"alg": "HS256"}
        payload = {"ha_code": "test_code", "exp": int(time.time()) - 3600}  # Expired 1 hour ago

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = (
            base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, sha256).digest())
            .decode()
            .rstrip("=")
        )

        jwt_code = f"{header_b64}.{payload_b64}.{signature}"
        result = _verify_and_extract_ha_code(jwt_code, "secret")
        assert result is None

    def test_jwt_missing_ha_code(self) -> None:
        """Test JWT without ha_code field."""
        header = {"alg": "HS256"}
        payload = {"exp": int(time.time()) + 3600}  # No ha_code

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = (
            base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, sha256).digest())
            .decode()
            .rstrip("=")
        )

        jwt_code = f"{header_b64}.{payload_b64}.{signature}"
        result = _verify_and_extract_ha_code(jwt_code, "secret")
        assert result is None

    def test_jwt_empty_ha_code(self) -> None:
        """Test JWT with empty ha_code."""
        header = {"alg": "HS256"}
        payload = {"ha_code": "", "exp": int(time.time()) + 3600}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = (
            base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, sha256).digest())
            .decode()
            .rstrip("=")
        )

        jwt_code = f"{header_b64}.{payload_b64}.{signature}"
        result = _verify_and_extract_ha_code(jwt_code, "secret")
        assert result is None

    def test_jwt_non_string_ha_code(self) -> None:
        """Test JWT with non-string ha_code."""
        header = {"alg": "HS256"}
        payload = {"ha_code": 123, "exp": int(time.time()) + 3600}  # Integer instead of string

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = (
            base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, sha256).digest())
            .decode()
            .rstrip("=")
        )

        jwt_code = f"{header_b64}.{payload_b64}.{signature}"
        result = _verify_and_extract_ha_code(jwt_code, "secret")
        assert result is None

    def test_jwt_invalid_json_payload(self) -> None:
        """Test JWT with invalid JSON in payload."""
        header_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(b"not json").decode().rstrip("=")
        signature_b64 = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")

        jwt_code = f"{header_b64}.{payload_b64}.{signature_b64}"
        result = _verify_and_extract_ha_code(jwt_code, "secret")
        assert result is None

    def test_b64url_decode_without_padding(self) -> None:
        """Test base64 URL decoding without padding."""
        # Base64 without padding
        encoded = base64.urlsafe_b64encode(b"test").decode().rstrip("=")
        decoded = _b64url_decode(encoded)
        assert decoded == b"test"

    def test_b64url_decode_with_padding(self) -> None:
        """Test base64 URL decoding that needs padding."""
        # Test various padding scenarios
        for text in [b"a", b"ab", b"abc", b"abcd"]:
            encoded = base64.urlsafe_b64encode(text).decode().rstrip("=")
            decoded = _b64url_decode(encoded)
            assert decoded == text


class TestDebugMode:
    """Test DEBUG mode logging branches."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "test_jwt_secret")

    def test_exchange_token_with_debug_logging(self, mock_config: Any, mocker: Any) -> None:
        """Test token exchange with DEBUG mode enabled."""
        mocker.patch.dict("os.environ", {"DEBUG": "1"})

        # Mock HTTP response
        mock_response = mocker.Mock()
        mock_response.status = 200
        mock_response.data = b'{"access_token": "token123", "token_type": "Bearer"}'

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        event = {"body": "grant_type=authorization_code&code=test_code&client_id=test"}

        response = lambda_handler(event, None)
        assert "access_token" in response
        assert response["access_token"] == "token123"

    def test_jwt_unwrap_without_secret(self, monkeypatch: Any, mocker: Any) -> None:
        """Test JWT unwrap when OAUTH_JWT_SECRET is not set."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("DEBUG", "1")
        # Don't set OAUTH_JWT_SECRET

        # Mock HTTP response
        mock_response = mocker.Mock()
        mock_response.status = 200
        mock_response.data = b'{"access_token": "token123"}'

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        event = {"body": "grant_type=authorization_code&code=test_code"}

        response = lambda_handler(event, None)
        assert "access_token" in response

    def test_jwt_unwrap_with_invalid_jwt_debug(self, mock_config: Any, mocker: Any) -> None:
        """Test JWT unwrap failure with DEBUG logging."""
        mocker.patch.dict("os.environ", {"DEBUG": "1"})

        # Mock HTTP response (HA will reject invalid code)
        mock_response = mocker.Mock()
        mock_response.status = 400
        mock_response.data = b'{"error": "invalid_grant"}'

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        # Invalid JWT format
        event = {"body": "grant_type=authorization_code&code=invalid.jwt.format"}

        response = lambda_handler(event, None)
        assert "event" in response
        assert "payload" in response["event"]
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"

    def test_jwt_unwrap_refresh_token_debug(self, mock_config: Any, mocker: Any) -> None:
        """Test refresh_token grant type skips JWT unwrap with DEBUG."""
        mocker.patch.dict("os.environ", {"DEBUG": "1"})

        mock_response = mocker.Mock()
        mock_response.status = 200
        mock_response.data = b'{"access_token": "new_token"}'

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        event = {"body": "grant_type=refresh_token&refresh_token=refresh123"}

        response = lambda_handler(event, None)
        assert "access_token" in response
        assert response["access_token"] == "new_token"


class TestExceptionHandling:
    """Test exception handling paths."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment variables."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "test_jwt_secret")

    def test_connection_failure(self, mock_config: Any, mocker: Any) -> None:
        """Test connection failure to Home Assistant."""
        mock_http = mocker.Mock()
        mock_http.request.side_effect = ConnectionError("Network unreachable")
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        event = {"body": "grant_type=authorization_code&code=test_code"}

        response = lambda_handler(event, None)
        assert "event" in response
        assert "payload" in response["event"]
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"
        assert "Network unreachable" in response["event"]["payload"]["message"]

    def test_unicode_decode_error_in_body_parsing(self, mock_config: Any, mocker: Any) -> None:
        """Test handling of invalid UTF-8 in request body."""
        mock_http = mocker.Mock()
        mock_http.request.side_effect = ConnectionError("Connection failed")
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        event = {"body": "grant_type=authorization_code&code=\x80\x81\x82"}

        response = lambda_handler(event, None)
        # Should handle gracefully and return error
        assert "event" in response
        assert "payload" in response["event"]
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"

    def test_http_500_error(self, mock_config: Any, mocker: Any) -> None:
        """Test HTTP 500 error from Home Assistant."""
        mock_response = mocker.Mock()
        mock_response.status = 500
        mock_response.data = b"Internal Server Error"

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        event = {"body": "grant_type=authorization_code&code=test_code"}

        response = lambda_handler(event, None)
        assert "event" in response
        assert "payload" in response["event"]
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"
        assert "500" in response["event"]["payload"]["message"]

    def test_http_503_error(self, mock_config: Any, mocker: Any) -> None:
        """Test HTTP 503 (Service Unavailable) from Home Assistant."""
        mock_response = mocker.Mock()
        mock_response.status = 503
        mock_response.data = b"Service Temporarily Unavailable"

        mock_http = mocker.Mock()
        mock_http.request.return_value = mock_response
        mocker.patch("alexa_oauth_handler.urllib3.PoolManager", return_value=mock_http)

        event = {"body": "grant_type=authorization_code&code=test_code"}

        response = lambda_handler(event, None)
        assert "event" in response
        assert "payload" in response["event"]
        assert response["event"]["payload"]["type"] == "INTERNAL_ERROR"
        assert "503" in response["event"]["payload"]["message"]


class TestConfigEdgeCases:
    """Test Config edge cases."""

    def test_config_with_optional_jwt_secret(self, monkeypatch: Any) -> None:
        """Test Config when OAUTH_JWT_SECRET is not set."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")
        monkeypatch.delenv("OAUTH_JWT_SECRET", raising=False)

        config = Config.from_environment()
        assert config.base_url == "https://ha.example.com"
        assert config.cf_client_id == "test_id"
        assert config.cf_client_secret == "test_secret"
        assert config.oauth_jwt_secret is None

    def test_config_with_jwt_secret(self, monkeypatch: Any) -> None:
        """Test Config when OAUTH_JWT_SECRET is set."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("CF_CLIENT_ID", "test_id")
        monkeypatch.setenv("CF_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "my_secret_key")

        config = Config.from_environment()
        assert config.base_url == "https://ha.example.com"
        assert config.oauth_jwt_secret == "my_secret_key"
