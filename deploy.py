#!/usr/bin/env python3
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

"""Secure deployment script for ha-alexa.

This script:
1. Prompts for deployment configuration
2. Creates SecureString parameters in AWS Systems Manager Parameter Store (KMS encrypted)
3. Builds and deploys the SAM application
4. Never passes secrets to CloudFormation (only parameter paths)
"""

import shlex
import subprocess
import sys
import tomllib
from getpass import getpass
from pathlib import Path


try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("❌ Error: boto3 is required. Install with: pip install boto3")
    sys.exit(1)


# Parameter Store path constants
PARAM_CF_CLIENT_ID = "cloudflare-client-id"
PARAM_CF_CLIENT_SECRET = "cloudflare-client-secret"
PARAM_OAUTH_JWT_SECRET = "oauth-jwt-secret"


def get_param_path(stack_name: str, param_name: str) -> str:
    """Generate consistent parameter path for Parameter Store.

    Args:
        stack_name: CloudFormation stack name
        param_name: Parameter identifier (e.g., 'cloudflare-client-id')

    Returns:
        Full parameter path (e.g., '/ha-alexa/cloudflare-client-id')
    """
    return f"/{stack_name}/{param_name}"


def load_samconfig_defaults() -> dict[str, str]:
    """Load default values from samconfig.toml if it exists."""
    defaults: dict[str, str] = {}
    samconfig_path = Path("samconfig.toml")

    if not samconfig_path.exists():
        return defaults

    try:
        with samconfig_path.open("rb") as f:
            samconfig = tomllib.load(f)

        params = samconfig.get("default", {}).get("deploy", {}).get("parameters", {})

        if stack_name := params.get("stack_name"):
            defaults["stack_name"] = str(stack_name)
        if region := params.get("region"):
            defaults["region"] = str(region)

        # parameter_overrides is either a single 'Key="value" ...' string or a list
        overrides = params.get("parameter_overrides", "")
        items = overrides if isinstance(overrides, list) else [overrides]
        for token in (t for item in items for t in shlex.split(str(item))):
            key, sep, value = token.partition("=")
            if sep:
                defaults[key] = value

    except Exception as e:
        print(f"⚠️  Warning: Could not parse samconfig.toml: {e}")

    return defaults


def prompt(message: str, default: str | None = None) -> str:
    """Prompt user for input with an optional default."""
    if default:
        prompt_text = f"{message} [{default}]: "
    else:
        prompt_text = f"{message}: "

    return input(prompt_text).strip() or default or ""


def parameter_exists(ssm: "boto3.client", name: str) -> bool:
    """Check whether a parameter already exists in Parameter Store."""
    try:
        ssm.get_parameter(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ParameterNotFound":
            return False
        raise
    return True


def prompt_secret(label: str, keep_existing: bool) -> str:
    """Prompt for a secret value.

    When keep_existing is True (the parameter already exists in Parameter Store),
    an empty input means "keep the stored value" and returns "".
    """
    suffix = " (press Enter to keep existing)" if keep_existing else ""
    while True:
        value = getpass(f"{label}{suffix}: ").strip()
        if value or keep_existing:
            return value
        print(f"❌ {label} is required")


def create_secure_parameter(ssm: "boto3.client", name: str, value: str, description: str) -> None:
    """Create or update a SecureString parameter in Parameter Store."""
    try:
        ssm.put_parameter(
            Name=name,
            Value=value,
            Type="SecureString",
            Description=description,
            Overwrite=True,
        )
        print(f"  ✓ Created SecureString parameter: {name}")
    except ClientError as e:
        print(f"  ✗ Failed to create {name}: {e}")
        sys.exit(1)


def delete_parameters(ssm: "boto3.client", stack_name: str) -> None:
    """Delete all parameters for a stack."""
    param_names = [
        get_param_path(stack_name, PARAM_CF_CLIENT_ID),
        get_param_path(stack_name, PARAM_CF_CLIENT_SECRET),
        get_param_path(stack_name, PARAM_OAUTH_JWT_SECRET),
    ]

    print(f"\n🗑️  Deleting Parameter Store parameters for stack '{stack_name}'...")
    for name in param_names:
        try:
            ssm.delete_parameter(Name=name)
            print(f"  ✓ Deleted: {name}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                print(f"  ⚠️  Not found (already deleted?): {name}")
            else:
                print(f"  ✗ Failed to delete {name}: {e}")


def main() -> None:
    """Main deployment workflow."""
    print("🚀 ha-alexa Secure Deployment Script\n")
    print("This script creates SecureString parameters and deploys your Lambda functions.")
    print("Secrets are stored with KMS encryption and never passed to CloudFormation.\n")

    # Load defaults from samconfig.toml if it exists
    defaults = load_samconfig_defaults()
    if defaults:
        print("📖 Loaded defaults from samconfig.toml\n")

    # Check if user wants to delete
    action = prompt("Action (deploy/delete)", "deploy").lower()
    if action == "delete":
        stack_name = prompt("Stack name", defaults.get("stack_name", "ha-alexa"))
        region = prompt("AWS Region", defaults.get("region", "us-east-1"))

        try:
            ssm = boto3.client("ssm", region_name=region)
            delete_parameters(ssm, stack_name)
        except NoCredentialsError:
            print("❌ AWS credentials not found. Configure with 'aws configure'")
            sys.exit(1)

        print("\n⚠️  To delete the CloudFormation stack, run:")
        print(f"    sam delete --stack-name {stack_name} --region {region}")
        return

    # Prompt for configuration
    print("📋 Configuration")
    print("-" * 50)
    stack_name = prompt("Stack name", defaults.get("stack_name", "ha-alexa"))
    region = prompt("AWS Region", defaults.get("region", "us-east-1"))

    print("\n📍 Non-sensitive Configuration")
    print("-" * 50)

    # Home Assistant URL validation
    while True:
        ha_url = prompt(
            "Home Assistant URL",
            defaults.get("HomeAssistantUrl", "https://homeassistant.example.com"),
        )
        if ha_url.startswith("https://"):
            break
        print("❌ URL must start with https://")

    # Alexa Skill ID validation
    while True:
        alexa_skill_id = prompt("Alexa Skill ID (amzn1.ask.skill...)", defaults.get("AlexaSkillId"))
        if not alexa_skill_id:
            print("❌ Alexa Skill ID is required")
        elif alexa_skill_id.startswith("amzn1.ask.skill."):
            break
        else:
            print("❌ Skill ID must start with 'amzn1.ask.skill.'")

    # Alexa Vendor ID validation
    while True:
        alexa_vendor_id = prompt(
            "Alexa Vendor ID (from redirect URI)", defaults.get("AlexaVendorId")
        )
        if alexa_vendor_id:
            break
        print("❌ Alexa Vendor ID is required")

    # SSL verification validation
    while True:
        verify_ssl = prompt("Verify SSL certificates", defaults.get("VerifySSL", "true")).lower()
        if verify_ssl in ("true", "false"):
            break
        print("❌ Must be 'true' or 'false'")

    # Debug mode validation
    while True:
        debug_mode = prompt("Enable debug mode", defaults.get("DebugMode", "false")).lower()
        if debug_mode in ("true", "false"):
            break
        print("❌ Must be 'true' or 'false'")

    # Initialize boto3
    try:
        ssm = boto3.client("ssm", region_name=region)
    except NoCredentialsError:
        print("❌ AWS credentials not found. Configure with 'aws configure'")
        sys.exit(1)

    print("\n🔒 Secrets (stored as SecureString with KMS encryption)")
    print("-" * 50)

    secrets = [
        (
            PARAM_CF_CLIENT_ID,
            "Cloudflare Access Client ID",
            (
                f"Cloudflare Access service token client ID "
                f"(used by {stack_name} Lambdas: alexa-smart-home, alexa-oauth)"
            ),
        ),
        (
            PARAM_CF_CLIENT_SECRET,
            "Cloudflare Access Client Secret",
            (
                f"Cloudflare Access service token client secret "
                f"(used by {stack_name} Lambdas: alexa-smart-home, alexa-oauth)"
            ),
        ),
        (
            PARAM_OAUTH_JWT_SECRET,
            "OAuth JWT Secret (generate with: openssl rand -base64 32)",
            (
                f"Secret for signing/verifying JWT authorization codes "
                f"(used by {stack_name} Lambdas: alexa-authorize, alexa-oauth)"
            ),
        ),
    ]

    secret_values: dict[str, str] = {}
    for param_name, label, _ in secrets:
        path = get_param_path(stack_name, param_name)
        try:
            exists = parameter_exists(ssm, path)
        except NoCredentialsError:
            print("❌ AWS credentials not found. Configure with 'aws configure'")
            sys.exit(1)
        secret_values[param_name] = prompt_secret(label, keep_existing=exists)

    # Create SecureString parameters (skipping any the user chose to keep)
    print("\n📝 Creating SecureString parameters in Parameter Store...")
    print("   (Encrypted with KMS, visible only to authorized IAM principals)")

    for param_name, _, description in secrets:
        path = get_param_path(stack_name, param_name)
        if secret_values[param_name]:
            create_secure_parameter(ssm, path, secret_values[param_name], description)
        else:
            print(f"  ✓ Keeping existing parameter: {path}")

    # Build with SAM (output streams to the terminal)
    print("\n🔨 Building Lambda package with SAM...")
    result = subprocess.run(["sam", "build"], check=False)
    if result.returncode != 0:
        print("❌ Build failed")
        sys.exit(1)
    print("  ✓ Build complete")

    # Deploy with SAM (passing parameter PATHS, not secret values)
    print(f"\n🚀 Deploying stack '{stack_name}' to {region}...")
    deploy_cmd = [
        "sam",
        "deploy",
        "--stack-name",
        stack_name,
        "--region",
        region,
        "--parameter-overrides",
        f"HomeAssistantUrl={ha_url}",
        f"CloudflareClientId={get_param_path(stack_name, PARAM_CF_CLIENT_ID)}",
        f"CloudflareClientSecret={get_param_path(stack_name, PARAM_CF_CLIENT_SECRET)}",
        f"AlexaSkillId={alexa_skill_id}",
        f"AlexaVendorId={alexa_vendor_id}",
        f"OAuthJwtSecret={get_param_path(stack_name, PARAM_OAUTH_JWT_SECRET)}",
        f"VerifySSL={verify_ssl}",
        f"DebugMode={debug_mode}",
        "--capabilities",
        "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-confirm-changeset",
        "--no-fail-on-empty-changeset",
    ]

    result = subprocess.run(deploy_cmd, check=False)
    if result.returncode != 0:
        print("\n❌ Deployment failed")
        sys.exit(1)
    print("\n✅ Deployment complete!")

    print("\n📊 View Lambda function URLs:")
    print(f"    sam list stack-outputs --stack-name {stack_name} --region {region}")
    print("\n🔍 View CloudWatch logs:")
    print(f"    sam logs --stack-name {stack_name} --name AlexaSmartHomeFunction --tail")
    print("\n🗑️  To delete everything:")
    print("    python3 deploy.py  # Choose 'delete' action")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Deployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
