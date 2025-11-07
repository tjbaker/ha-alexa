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

import re
import subprocess
import sys
from getpass import getpass
from pathlib import Path


try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("❌ Error: boto3 is required. Install with: pip install boto3")
    sys.exit(1)


def load_samconfig_defaults() -> dict[str, str]:
    """Load default values from samconfig.toml if it exists."""
    defaults: dict[str, str] = {}
    samconfig_path = Path("samconfig.toml")

    if not samconfig_path.exists():
        return defaults

    try:
        content = samconfig_path.read_text()

        # Extract stack_name
        if match := re.search(r'stack_name\s*=\s*"([^"]+)"', content):
            defaults["stack_name"] = match.group(1)

        # Extract region
        if match := re.search(r'region\s*=\s*"([^"]+)"', content):
            defaults["region"] = match.group(1)

        # Extract parameter_overrides (handle escaped quotes in TOML string)
        if match := re.search(r'parameter_overrides\s*=\s*"((?:[^"\\]|\\.)*)"', content):
            overrides = match.group(1)

            # Parse individual parameters (values are between \" and \")
            param_patterns = {
                "HomeAssistantUrl": r'HomeAssistantUrl=\\"([^\\]+)\\"',
                "AlexaSkillId": r'AlexaSkillId=\\"([^\\]+)\\"',
                "AlexaVendorId": r'AlexaVendorId=\\"([^\\]+)\\"',
                "VerifySSL": r'VerifySSL=\\"([^\\]+)\\"',
                "DebugMode": r'DebugMode=\\"([^\\]+)\\"',
            }

            for key, pattern in param_patterns.items():
                if param_match := re.search(pattern, overrides):
                    defaults[key] = param_match.group(1)

    except Exception as e:
        print(f"⚠️  Warning: Could not parse samconfig.toml: {e}")

    return defaults


def prompt(message: str, default: str | None = None, secret: bool = False) -> str:
    """Prompt user for input with optional default and secret handling."""
    if default:
        prompt_text = f"{message} [{default}]: "
    else:
        prompt_text = f"{message}: "

    if secret:
        value = getpass(prompt_text)
    else:
        value = input(prompt_text)

    return value.strip() or default or ""


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
        f"/{stack_name}/cloudflare-client-id",
        f"/{stack_name}/cloudflare-client-secret",
        f"/{stack_name}/oauth-jwt-secret",
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
    action = prompt("Action", "deploy").lower()
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

    print("\n🔒 Secrets (stored as SecureString with KMS encryption)")
    print("-" * 50)

    # Cloudflare Client ID validation
    while True:
        cf_client_id = prompt("Cloudflare Access Client ID", secret=True)
        if cf_client_id:
            break
        print("❌ Cloudflare Client ID is required")

    # Cloudflare Client Secret validation
    while True:
        cf_client_secret = prompt("Cloudflare Access Client Secret", secret=True)
        if cf_client_secret:
            break
        print("❌ Cloudflare Client Secret is required")

    # OAuth JWT Secret validation
    while True:
        oauth_jwt_secret = prompt(
            "OAuth JWT Secret (generate with: openssl rand -base64 32)", secret=True
        )
        if oauth_jwt_secret:
            break
        print("❌ OAuth JWT Secret is required")

    # Initialize boto3
    try:
        ssm = boto3.client("ssm", region_name=region)
    except NoCredentialsError:
        print("❌ AWS credentials not found. Configure with 'aws configure'")
        sys.exit(1)

    # Create SecureString parameters
    print("\n📝 Creating SecureString parameters in Parameter Store...")
    print("   (Encrypted with KMS, visible only to authorized IAM principals)")

    create_secure_parameter(
        ssm,
        f"/{stack_name}/cloudflare-client-id",
        cf_client_id,
        f"Cloudflare Access service token client ID "
        f"(used by {stack_name} Lambdas: alexa-smart-home, alexa-oauth)",
    )

    create_secure_parameter(
        ssm,
        f"/{stack_name}/cloudflare-client-secret",
        cf_client_secret,
        f"Cloudflare Access service token client secret "
        f"(used by {stack_name} Lambdas: alexa-smart-home, alexa-oauth)",
    )

    create_secure_parameter(
        ssm,
        f"/{stack_name}/oauth-jwt-secret",
        oauth_jwt_secret,
        f"Secret for signing/verifying JWT authorization codes "
        f"(used by {stack_name} Lambdas: alexa-authorize, alexa-oauth)",
    )

    # Build with SAM
    print("\n🔨 Building Lambda package with SAM...")
    result = subprocess.run(["sam", "build"], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Build failed:\n{result.stderr}")
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
        f"CloudflareClientId=/{stack_name}/cloudflare-client-id",
        f"CloudflareClientSecret=/{stack_name}/cloudflare-client-secret",
        f"AlexaSkillId={alexa_skill_id}",
        f"AlexaVendorId={alexa_vendor_id}",
        f"OAuthJwtSecret=/{stack_name}/oauth-jwt-secret",
        f"VerifySSL={verify_ssl}",
        f"DebugMode={debug_mode}",
        "--capabilities",
        "CAPABILITY_IAM",
        "--resolve-s3",
        "--no-confirm-changeset",
    ]

    result = subprocess.run(deploy_cmd, check=False, capture_output=True, text=True)

    # Check if deployment failed (but treat "no changes" as success)
    if result.returncode != 0:
        if "No changes to deploy" in result.stderr or "No changes to deploy" in result.stdout:
            print("\n✅ No changes detected - stack is already up to date!")
        else:
            print("\n❌ Deployment failed")
            print(result.stderr)
            sys.exit(1)
    else:
        print("\n✅ Deployment complete!")

    print("\n📊 View Lambda function URLs:")
    print(f"    sam list stack-outputs --stack-name {stack_name} --region {region}")
    print("\n🔍 View CloudWatch logs:")
    print(f"    sam logs --stack-name {stack_name} --name alexa-smart-home --tail")
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
