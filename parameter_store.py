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

"""AWS Systems Manager Parameter Store utility for Lambda functions.

This module provides cached access to Parameter Store parameters, minimizing
API calls and improving Lambda cold start performance.
"""

import logging
import time
from typing import Any, Final


logger = logging.getLogger(__name__)

# Cached values expire so rotated secrets are picked up without a redeploy
CACHE_TTL_SECONDS: Final[float] = 300.0

# Module-level cache (persists across warm Lambda invocations)
_parameter_cache: dict[str, tuple[str, float]] = {}


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
    cached = _parameter_cache.get(param_name)
    if cached is not None:
        cached_value, fetched_at = cached
        if time.monotonic() - fetched_at < CACHE_TTL_SECONDS:
            logger.debug(f"Using cached parameter: {param_name}")
            return cached_value

    # Fetch from Parameter Store
    try:
        import boto3  # boto3 is available in Lambda runtime

        ssm = boto3.client("ssm")
        logger.info(f"Fetching parameter from SSM: {param_name}")

        response: dict[str, Any] = ssm.get_parameter(Name=param_name, WithDecryption=True)

        value: str = response["Parameter"]["Value"]
        _parameter_cache[param_name] = (value, time.monotonic())

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
