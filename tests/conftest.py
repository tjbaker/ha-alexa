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

"""Shared test fixtures and configuration."""

from typing import Any

import pytest


@pytest.fixture(autouse=True)
def mock_parameter_store(mocker: Any) -> None:
    """Mock Parameter Store to return test values.

    This fixture runs automatically for all tests, preventing boto3 import errors
    by mocking the get_parameter function to return the parameter name as the value.

    For tests that need specific Parameter Store behavior, they can override this
    by patching the get_parameter function directly in the specific module.
    """

    def mock_get_param(param_name: str) -> str:
        """Return the param name itself as the value for tests."""
        return param_name

    # Patch get_parameter in all modules that import it
    mocker.patch("alexa_smart_home_handler.get_parameter", side_effect=mock_get_param)
    mocker.patch("alexa_oauth_handler.get_parameter", side_effect=mock_get_param)
    mocker.patch("alexa_authorize_handler.get_parameter", side_effect=mock_get_param)
    mocker.patch("parameter_store.get_parameter", side_effect=mock_get_param)
