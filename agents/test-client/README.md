# Agent Test Client UI

A web-based user interface for testing the agent client. This UI provides a simple way to send messages to the agent and view responses without using the command line.

## Features

- 🎨 Modern, responsive web interface
- 🚀 Easy-to-use button to send requests
- 📝 Customizable message input
- ✅ Clear success/error status indicators
- 🔄 Real-time response display
- 🧹 Clear output functionality

## Prerequisites

Make sure you have the required dependencies installed:

```bash
pip install -r ../requirements.txt
```

Or if you're using uv:

```bash
uv pip install -r ../requirements.txt
```

## Environment Variables

The UI uses the same environment variables as the original test-client.py:

### Required Variables:
- `AGENT_URL` - URL of the agent server (default: `http://localhost:9999`)

### Optional Variables (for authentication):
- `VAULT_ADDR` - Vault server address
- `VAULT_NAMESPACE` - Vault namespace
- `VAULT_TOKEN` - Vault authentication token
- `VAULT_ROLE` - Vault role for identity tokens (default: `default`)

### Optional Variables (for OIDC):
- `OPENID_CONNECT_SCOPES` - OIDC scopes (default: `openid`)
- `OPENID_CONNECT_PROVIDER_NAME` - OIDC provider name in Vault
- `OPENID_CONNECT_CLIENT_NAME` - OIDC client name in Vault
- `REDIRECT_URI_DOMAIN` - Redirect URI domain (default: `localhost`)
- `REDIRECT_URI_PORT` - Redirect URI port (default: `9998`)
- `REDIRECT_URI_ENDPOINT` - Redirect URI endpoint (default: `callback`)

## Running the UI

1. **Navigate to the test-client directory**:
   ```bash
   cd agents/test-client
   ```

2. **Set up environment variables** (if needed):
   ```bash
   export AGENT_URL="http://localhost:9999"
   # Add other variables as needed
   ```

3. **Run the Flask application**:
   ```bash
   python test-client-ui.py
   ```

4. **Open your browser** and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

1. **Enter your message** in the text area (default message is "Give me a hello world")
2. **Click "Send Request"** to send the message to the agent
3. **View the response** in the output box below
4. **Click "Clear Output"** to reset the output area

### Keyboard Shortcuts
- Press **Enter** to send the message (use Ctrl+Enter or Shift+Enter for new lines in the message)

## Response Indicators

- 🟢 **Green border** - Successful response
- 🔴 **Red border** - Error occurred
- 🔵 **Blue border** - Loading/processing request

## Troubleshooting

### Connection Errors
If you see connection errors, make sure:
- The agent server is running at the specified `AGENT_URL`
- The agent server is accessible from your machine
- Firewall settings allow the connection

### Authentication Errors
If you see authentication errors:
- Verify your Vault credentials are correct
- Check that the Vault server is accessible
- Ensure the OIDC provider and client are properly configured

### Port Already in Use
If port 5000 is already in use, you can change it by modifying the last line in `test-client-ui.py`:
```python
app.run(host='0.0.0.0', port=5001, debug=True)  # Change 5000 to 5001
```

## Architecture

The UI consists of:
- **Flask Backend** (`test-client-ui.py`) - Handles API requests and communicates with the agent
- **HTML/CSS/JavaScript Frontend** (`templates/index.html`) - Provides the user interface
- **A2A SDK** - Manages agent communication and authentication

## Development

To run in development mode with auto-reload:
```bash
export FLASK_ENV=development
python test-client-ui.py
```

## Production Deployment

For production deployment, consider using a production WSGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 test-client-ui:app
```

## Comparison with CLI Client

| Feature | CLI (`test-client.py`) | UI (`test-client-ui.py`) |
|---------|------------------------|--------------------------|
| Interface | Command line | Web browser |
| Message Input | Hardcoded in script | Interactive text input |
| Response Display | Terminal output | Formatted web display |
| Error Handling | Console logs | Visual indicators |
| Ease of Use | Requires code editing | Point and click |

## License

Same as the parent project.