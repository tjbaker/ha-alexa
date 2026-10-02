# Test Event Files

Example Lambda event payloads for testing the Alexa integration locally with AWS SAM.

## Smart Home Events

### Discovery
Test Alexa device discovery:
```bash
sam local invoke AlexaSmartHomeFunction -e events/alexa-discovery.json
```

### Power Control
Test turning on/off a device:
```bash
sam local invoke AlexaSmartHomeFunction -e events/alexa-power-control.json
```

### Brightness Control
Test adjusting brightness:
```bash
sam local invoke AlexaSmartHomeFunction -e events/alexa-brightness-control.json
```

## OAuth Events

### Authorization Code Exchange
Test initial OAuth token exchange:
```bash
sam local invoke AlexaOAuthFunction -e events/oauth-authorization-code.json
```

### Refresh Token
Test OAuth token refresh:
```bash
sam local invoke AlexaOAuthFunction -e events/oauth-refresh-token.json
```

## Usage Tips

1. **Replace tokens**: Update the `token` fields with actual tokens from your Home Assistant instance
2. **Replace entity IDs**: Change `endpointId` values to match your Home Assistant entities
3. **Environment variables**: `sam local invoke` takes environment variables from
   `template.yaml`, not your shell. Override them with an `--env-vars` file:
   ```json
   {
     "AlexaSmartHomeFunction": { "BASE_URL": "https://your-ha-instance.com", "DEBUG": "1" },
     "AlexaOAuthFunction": { "BASE_URL": "https://your-ha-instance.com", "DEBUG": "1" }
   }
   ```
   ```bash
   sam local invoke AlexaSmartHomeFunction -e events/alexa-discovery.json --env-vars env.json
   ```
4. **AWS credentials**: `CF_CLIENT_ID`, `CF_CLIENT_SECRET`, and `OAUTH_JWT_SECRET` are
   Parameter Store paths, so the function reads the real secrets from SSM using your
   local AWS credentials (deploy with `deploy.py` first)

## Creating Custom Events

To capture real Alexa events:
1. Enable Debug Mode (see the main README) so the smart home handler logs each event
2. Trigger actions through the Alexa app
3. Copy the `Processing event` JSON from CloudWatch (tokens are already redacted)
4. Remove any remaining personal info
5. Save as a new test event

## More Event Examples

For more Alexa Smart Home directive examples, see:
- [Alexa Smart Home API Reference](https://developer.amazon.com/docs/device-apis/alexa-interface.html)
- [Home Assistant Alexa Documentation](https://www.home-assistant.io/integrations/alexa/)

