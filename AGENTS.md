# AGENTS.md

Python 3.13 AWS Lambda project bridging Amazon Alexa Smart Home Skills with a
self-hosted Home Assistant (HA), deployed with AWS SAM behind Cloudflare Tunnel
and Cloudflare Access. User-facing setup docs live in `README.md`.

## Layout

- `alexa_smart_home_handler.py` - forwards Alexa Smart Home directives to HA's `/api/alexa/smart_home`
- `alexa_authorize_handler.py` - OAuth authorize endpoint; wraps HA's auth code in a short-lived HMAC-signed JWT
- `alexa_oauth_handler.py` - OAuth token endpoint; unwraps the JWT and forwards to HA's `/auth/token`
- `parameter_store.py` - SSM Parameter Store reads with a TTL cache (picks up rotated secrets)
- `template.yaml` - SAM template; `deploy.py` - interactive deploy script
- `tests/` - pytest; `test_*_coverage.py` files hold edge-case and error-path tests
- `events/` - sample events for `sam local invoke`
- `samconfig.toml` - SAM deploy defaults (stack name, region, parameter overrides)
- `.github/workflows/` - `ci.yml` (lint incl. cfn-lint, type-check, tests with the 90% coverage gate), `codeql.yml`

Account linking flow: Alexa → authorize handler → HA login → authorize handler
(mints JWT) → Alexa → token handler (unwraps JWT) → HA `/auth/token`.

## Commands

Use a Python 3.13 virtualenv (the system `python3` may be newer than the Lambda runtime):

```bash
make install-dev   # pip install -e ".[dev]"
make format        # ruff format + ruff check --fix
make lint          # ruff check + ruff format --check + cfn-lint on template.yaml
make type-check    # mypy (strict settings in pyproject.toml) on the four Lambda modules, not deploy.py or tests
make test          # pytest
make test-cov      # pytest with coverage; CI fails below 90%
```

Before finishing a change, run `make lint type-check test-cov`; all must pass.

## Code conventions

- Modern 3.13 typing (`X | None`, `dict[str, Any]`; never `Optional`/`Dict`); frozen dataclasses for config and request types
- Validate with explicit exceptions, never `assert`; no bare `except:`
- Production dependency is urllib3 only. boto3 comes from the Lambda runtime and is a dev/deploy dependency; don't add others
- Handlers cache HTTP clients at module level for warm invocations; tests reset
  them via the autouse fixture in `tests/conftest.py`
- In tests, `get_parameter` is auto-mocked to return the parameter *name* as its value,
  so set env vars to Parameter Store paths and assert on those paths

## Security rules

- NEVER log tokens, secrets, passwords, or authorization codes. Use the existing
  `_sanitize_*` helpers; extend them rather than logging raw request/response bodies
- Secrets live only in SSM SecureString at `/<stack-name>/<name>`. CloudFormation
  parameters carry the paths, never the values
- Error responses go to unauthenticated callers (the OAuth endpoints are public
  Function URLs): return generic messages and log the details. Never include upstream
  bodies, hostnames, or Parameter Store paths

## Gotchas

- **Error mapping matters to Alexa.** Returning OAuth `invalid_grant` from the token
  endpoint, or `INVALID_AUTHORIZATION_CREDENTIAL` from the smart home handler, makes
  Alexa treat the account link as broken. Use them only when HA itself rejected the
  credential (a JSON OAuth error body from HA, or a 401 from HA). Cloudflare Access
  denials and other upstream failures are server errors (`502 server_error` / `BRIDGE_UNREACHABLE`)
- The OAuth handlers sit behind Lambda Function URLs, so they return
  `{"statusCode", "headers", "body"}` with RFC 6749 JSON bodies, not Alexa-style events
- Smart home error responses must be full `Alexa.ErrorResponse` events (header with
  `messageId`, plus `correlationToken`/`endpointId` echoed from the directive)
- Function names in `template.yaml` (`alexa-smart-home`, `alexa-oauth`, `alexa-authorize`)
  are fixed on purpose. Changing them replaces the functions, which changes the ARN and
  Function URLs configured in the Alexa Developer Console
- Public Function URLs (`AuthType: NONE`) need both `lambda:InvokeFunctionUrl` and
  `lambda:InvokeFunction` permissions
- Lambda `Timeout` in `template.yaml` must exceed `CONNECT_TIMEOUT + READ_TIMEOUT` in the handlers
- **Alexa events (state reporting) need a fresh AcceptGrant.** The skill's "Send Alexa
  Events" permission plus HA's `alexa: smart_home:` `endpoint`, `client_id`, and
  `client_secret` let HA push state changes. Alexa sends an `Alexa.Authorization`
  `AcceptGrant` directive only when the skill is (re)linked; this handler forwards it to
  HA, which exchanges the code for event gateway tokens. If HA's `alexa.state_report` log
  shows `INVALID_ACCESS_TOKEN` or no token, the user must disable and re-enable the skill
- Functions run with 128 MB (`MemorySize` in `template.yaml`). Cold starts pay for
  importing boto3, the first Parameter Store reads, and a new TLS connection through
  Cloudflare, so keep module-level work light; raising `MemorySize` (more CPU) is the
  lever if cold-start latency matters

## Boundaries

- Don't run `deploy.py`, `sam deploy`, `sam delete`, or anything that writes to AWS
  without explicit approval; they change a live Alexa integration
- Keep `README.md` in sync when changing deploy parameters, outputs, or setup steps
