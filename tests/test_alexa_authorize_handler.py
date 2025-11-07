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

"""Tests for Alexa authorization handler."""

from __future__ import annotations

import base64
import hmac
import json
from hashlib import sha256
from typing import Any

import pytest

from alexa_authorize_handler import (
    Config,
    _allowed_redirects,
    _b64url,
    _is_allowed_redirect,
    _json_b64,
    _json_from_b64,
    _parse_query,
    _redirect,
    _sign_jwt,
    lambda_handler,
)


class TestConfig:
    """Tests for Config dataclass."""

    def test_from_env_success(self, monkeypatch: Any) -> None:
        """Test successful config loading."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "VENDOR123")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "secret123")

        config = Config.from_env()

        assert config.base_url == "https://ha.example.com"
        assert config.vendor_id == "VENDOR123"
        assert config.jwt_secret == "secret123"

    def test_from_env_strips_trailing_slash(self, monkeypatch: Any) -> None:
        """Test BASE_URL trailing slash is stripped."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com/")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "VENDOR123")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "secret123")

        config = Config.from_env()

        assert config.base_url == "https://ha.example.com"

    def test_from_env_missing_base_url(self, monkeypatch: Any) -> None:
        """Test missing BASE_URL raises error."""
        monkeypatch.delenv("BASE_URL", raising=False)
        monkeypatch.setenv("ALEXA_VENDOR_ID", "VENDOR123")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "secret123")

        with pytest.raises(RuntimeError, match="BASE_URL is required"):
            Config.from_env()

    def test_from_env_missing_vendor_id(self, monkeypatch: Any) -> None:
        """Test missing ALEXA_VENDOR_ID raises error."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.delenv("ALEXA_VENDOR_ID", raising=False)
        monkeypatch.setenv("OAUTH_JWT_SECRET", "secret123")

        with pytest.raises(RuntimeError, match="ALEXA_VENDOR_ID is required"):
            Config.from_env()

    def test_from_env_missing_jwt_secret(self, monkeypatch: Any) -> None:
        """Test missing OAUTH_JWT_SECRET raises error."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "VENDOR123")
        monkeypatch.delenv("OAUTH_JWT_SECRET", raising=False)

        with pytest.raises(RuntimeError, match="OAUTH_JWT_SECRET is required"):
            Config.from_env()


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_b64url_encoding(self) -> None:
        """Test URL-safe base64 encoding."""
        result = _b64url(b"hello world")
        assert result == "aGVsbG8gd29ybGQ"
        assert "=" not in result

    def test_json_b64_roundtrip(self) -> None:
        """Test JSON base64 encoding and decoding."""
        data = {"key": "value", "number": 42}
        encoded = _json_b64(data)
        decoded = _json_from_b64(encoded)
        assert decoded == data

    def test_parse_query_empty(self) -> None:
        """Test parsing empty query parameters."""
        event = {}
        result = _parse_query(event)
        assert result == {}

    def test_parse_query_with_params(self) -> None:
        """Test parsing query parameters."""
        event = {
            "queryStringParameters": {
                "code": "abc123",
                "state": "xyz789",
            }
        }
        result = _parse_query(event)
        assert result == {"code": "abc123", "state": "xyz789"}

    def test_allowed_redirects(self) -> None:
        """Test allowed redirect URIs."""
        vendor_id = "TEST123"
        redirects = _allowed_redirects(vendor_id)

        assert f"https://pitangui.amazon.com/api/skill/link/{vendor_id}" in redirects
        assert f"https://layla.amazon.com/api/skill/link/{vendor_id}" in redirects
        assert f"https://alexa.amazon.co.jp/api/skill/link/{vendor_id}" in redirects
        assert len(redirects) == 3

    def test_is_allowed_redirect_valid(self) -> None:
        """Test valid redirect URI."""
        vendor_id = "TEST123"
        uri = f"https://pitangui.amazon.com/api/skill/link/{vendor_id}"
        assert _is_allowed_redirect(uri, vendor_id) is True

    def test_is_allowed_redirect_invalid_domain(self) -> None:
        """Test invalid redirect domain."""
        vendor_id = "TEST123"
        uri = f"https://evil.com/api/skill/link/{vendor_id}"
        assert _is_allowed_redirect(uri, vendor_id) is False

    def test_is_allowed_redirect_http_not_https(self) -> None:
        """Test non-HTTPS redirect is rejected."""
        vendor_id = "TEST123"
        uri = f"http://pitangui.amazon.com/api/skill/link/{vendor_id}"
        assert _is_allowed_redirect(uri, vendor_id) is False

    def test_redirect_response(self) -> None:
        """Test redirect response format."""
        result = _redirect("https://example.com")
        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://example.com"
        assert result["body"] == ""


class TestJWT:
    """Tests for JWT signing."""

    def test_sign_jwt(self) -> None:
        """Test JWT signing."""
        payload = {"sub": "test", "exp": 12345}
        secret = "test_secret"

        jwt = _sign_jwt(payload, secret)

        parts = jwt.split(".")
        assert len(parts) == 3

        # Verify header
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "HS256"
        assert header["typ"] == "JWT"

        # Verify payload
        decoded_payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        assert decoded_payload == payload

        # Verify signature
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode("ascii")
        assert parts[2] == expected_sig_b64


class TestLambdaHandler:
    """Tests for Lambda handler."""

    @pytest.fixture
    def mock_config(self, monkeypatch: Any) -> None:
        """Set up mock environment."""
        monkeypatch.setenv("BASE_URL", "https://ha.example.com")
        monkeypatch.setenv("ALEXA_VENDOR_ID", "VENDOR123")
        monkeypatch.setenv("OAUTH_JWT_SECRET", "test_secret")

    def test_initial_authorization_request(self, mock_config: Any) -> None:
        """Test initial authorization request from Alexa."""
        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "https://pitangui.amazon.com/api/skill/link/VENDOR123",
                "state": "alexa_state_123",
                "scope": "smart_home",
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert location.startswith("https://ha.example.com/auth/authorize?")
        assert "response_type=code" in location
        assert "client_id=test_client" in location
        assert "redirect_uri=https%3A%2F%2Flambda.us-east-1.on.aws" in location

    def test_callback_from_ha(self, mock_config: Any) -> None:
        """Test callback from Home Assistant with code."""
        # Create envelope state
        envelope = {
            "a_state": "alexa_state_123",
            "redirect_uri": "https://pitangui.amazon.com/api/skill/link/VENDOR123",
        }
        ha_state = _json_b64(envelope)

        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "code": "ha_auth_code_xyz",
                "state": ha_state,
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert location.startswith("https://pitangui.amazon.com/api/skill/link/VENDOR123?")
        assert "code=" in location
        assert "state=alexa_state_123" in location

        # Verify JWT code can be decoded
        code_param = location.split("code=")[1].split("&")[0]
        # Should be a JWT with ha_code
        parts = code_param.split(".")
        assert len(parts) == 3

    def test_missing_response_type_defaults_to_code(self, mock_config: Any) -> None:
        """Test missing response_type defaults to 'code'."""
        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "client_id": "test_client",
                "redirect_uri": "https://pitangui.amazon.com/api/skill/link/VENDOR123",
                "state": "alexa_state_123",
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert "response_type=code" in location

    def test_invalid_redirect_uri(self, mock_config: Any) -> None:
        """Test invalid redirect URI returns error."""
        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "https://evil.com/redirect",
                "state": "alexa_state_123",
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"] == "invalid_request"

    def test_missing_client_id(self, mock_config: Any) -> None:
        """Test missing client_id returns error."""
        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "response_type": "code",
                "redirect_uri": "https://pitangui.amazon.com/api/skill/link/VENDOR123",
                "state": "alexa_state_123",
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"] == "invalid_request"

    def test_callback_with_invalid_state(self, mock_config: Any) -> None:
        """Test callback with invalid state encoding."""
        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "code": "ha_auth_code_xyz",
                "state": "invalid_base64!!!",
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"] == "invalid_request"

    def test_callback_with_recovered_invalid_redirect(self, mock_config: Any) -> None:
        """Test callback with state containing invalid redirect URI."""
        envelope = {"a_state": "alexa_state_123", "redirect_uri": "https://evil.com/redirect"}
        ha_state = _json_b64(envelope)

        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "code": "ha_auth_code_xyz",
                "state": ha_state,
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"] == "invalid_request"

    def test_missing_code_in_callback(self, mock_config: Any) -> None:
        """Test callback without code parameter."""
        envelope = {
            "a_state": "alexa_state_123",
            "redirect_uri": "https://pitangui.amazon.com/api/skill/link/VENDOR123",
        }
        ha_state = _json_b64(envelope)

        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "state": ha_state,
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"] == "invalid_request"

    def test_unsupported_response_type_with_valid_redirect(self, mock_config: Any) -> None:
        """Test unsupported response_type redirects with error."""
        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "response_type": "token",
                "client_id": "test_client",
                "redirect_uri": "https://pitangui.amazon.com/api/skill/link/VENDOR123",
                "state": "alexa_state_123",
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert "error=unsupported_response_type" in location
        assert "state=alexa_state_123" in location

    def test_exception_handling(self, mock_config: Any, monkeypatch: Any) -> None:
        """Test exception handling returns 400."""
        monkeypatch.delenv("BASE_URL", raising=False)

        event = {
            "requestContext": {
                "domainName": "lambda.us-east-1.on.aws",
            },
            "queryStringParameters": {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "https://pitangui.amazon.com/api/skill/link/VENDOR123",
                "state": "alexa_state_123",
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"] == "invalid_request"
