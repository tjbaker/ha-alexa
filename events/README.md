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
3. **Environment variables**: Set required environment variables before testing:
   ```bash
   export BASE_URL=https://your-ha-instance.com
   export CF_CLIENT_ID=your-cloudflare-client-id
   export CF_CLIENT_SECRET=your-cloudflare-client-secret
   ```

4. **Start local API**: SAM CLI will automatically start a local Lambda runtime

## Creating Custom Events

To capture real Alexa events:
1. Enable CloudWatch Logs for your Lambda functions
2. Trigger actions through the Alexa app
3. Copy the event JSON from CloudWatch
4. Remove sensitive data (real tokens, personal info)
5. Save as a new test event

## More Event Examples

For more Alexa Smart Home directive examples, see:
- [Alexa Smart Home API Reference](https://developer.amazon.com/docs/device-apis/alexa-interface.html)
- [Home Assistant Alexa Documentation](https://www.home-assistant.io/integrations/alexa/)

