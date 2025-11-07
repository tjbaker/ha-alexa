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

"""AWS Systems Manager Parameter Store utility for Lambda functions.

This module provides cached access to Parameter Store parameters, minimizing
API calls and improving Lambda cold start performance.
"""

import logging
from typing import Any


logger = logging.getLogger(__name__)

# Module-level cache (persists across warm Lambda invocations)
_parameter_cache: dict[str, str] = {}


def get_parameter(param_name: str) -> str:
    """Get value from AWS Systems Manager Parameter Store with caching.

    Args:
        param_name: Parameter Store parameter name (e.g., /ha-alexa/stack-name/secret)

    Returns:
        The decrypted parameter value from SSM

    Raises:
        RuntimeError: If Parameter Store fetch fails
    """
    # Check cache first (persists across warm Lambda invocations)
    if param_name in _parameter_cache:
        logger.debug(f"Using cached parameter: {param_name}")
        return _parameter_cache[param_name]

    # Fetch from Parameter Store
    try:
        import boto3  # type: ignore[import-not-found]  # boto3 is available in Lambda runtime

        ssm = boto3.client("ssm")
        logger.info(f"Fetching parameter from SSM: {param_name}")

        response: dict[str, Any] = ssm.get_parameter(Name=param_name, WithDecryption=True)

        value: str = response["Parameter"]["Value"]
        _parameter_cache[param_name] = value

        logger.info(f"Successfully fetched and cached parameter: {param_name}")
        return value

    except Exception as e:
        error_msg = f"Failed to fetch parameter {param_name}: {e}"
        logger.exception(error_msg)
        raise RuntimeError(error_msg) from e


def clear_cache() -> None:
    """Clear the parameter cache (useful for testing)."""
    _parameter_cache.clear()
    logger.debug("Parameter cache cleared")
