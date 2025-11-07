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

"""Tests for AWS Systems Manager Parameter Store utility.

Note: boto3 is mocked since it's only available in AWS Lambda runtime.
"""

from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest

from parameter_store import clear_cache, get_parameter


@pytest.fixture(autouse=True)
def reset_cache() -> Generator[None]:
    """Clear cache before and after each test."""
    clear_cache()
    yield
    clear_cache()


class TestGetParameter:
    """Test get_parameter function."""

    @patch("sys.modules", {"boto3": MagicMock()})
    def test_fetch_parameter_success(self) -> None:
        """Test successful parameter fetch from Parameter Store."""
        with patch("builtins.__import__") as mock_import:
            mock_boto3 = MagicMock()
            mock_ssm = MagicMock()
            mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "test-value"}}
            mock_boto3.client.return_value = mock_ssm
            mock_import.return_value = mock_boto3

            result = get_parameter("/ha-alexa/test/param")

            assert result == "test-value"

    @patch("sys.modules", {"boto3": MagicMock()})
    def test_cache_behavior(self) -> None:
        """Test that parameters are cached after first fetch."""
        with patch("builtins.__import__") as mock_import:
            mock_boto3 = MagicMock()
            mock_ssm = MagicMock()
            mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "cached-value"}}
            mock_boto3.client.return_value = mock_ssm
            mock_import.return_value = mock_boto3

            # First call
            result1 = get_parameter("/ha-alexa/test/cached")
            assert result1 == "cached-value"

            # Clear the mock to ensure second call doesn't trigger SSM
            mock_import.reset_mock()
            mock_boto3.client.reset_mock()

            # Second call - should use cache
            result2 = get_parameter("/ha-alexa/test/cached")
            assert result2 == "cached-value"
            # SSM should not be called again (client.return_value won't have been accessed)

    @patch("sys.modules", {"boto3": MagicMock()})
    def test_error_raises_runtime_error(self) -> None:
        """Test that boto3 exceptions are wrapped in RuntimeError."""
        with patch("builtins.__import__") as mock_import:
            mock_boto3 = MagicMock()
            mock_ssm = MagicMock()
            mock_ssm.get_parameter.side_effect = Exception("ParameterNotFound")
            mock_boto3.client.return_value = mock_ssm
            mock_import.return_value = mock_boto3

            with pytest.raises(RuntimeError, match="Failed to fetch parameter"):
                get_parameter("/ha-alexa/test/nonexistent")


class TestClearCache:
    """Test clear_cache function."""

    def test_clear_cache_is_callable(self) -> None:
        """Test that clear_cache can be called without errors."""
        clear_cache()
        clear_cache()  # Multiple calls should be safe

    @patch("sys.modules", {"boto3": MagicMock()})
    def test_clear_cache_forces_refetch(self) -> None:
        """Test that clear_cache removes cached values."""
        with patch("builtins.__import__") as mock_import:
            mock_boto3 = MagicMock()
            mock_ssm = MagicMock()
            mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "original"}}
            mock_boto3.client.return_value = mock_ssm
            mock_import.return_value = mock_boto3

            # Cache a value
            result1 = get_parameter("/ha-alexa/test/param")
            assert result1 == "original"

            # Clear cache
            clear_cache()

            # Change the return value
            mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "updated"}}

            # Fetch again - should get new value
            result2 = get_parameter("/ha-alexa/test/param")
            assert result2 == "updated"
