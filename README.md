# LoginLlama Python Client

Official Python SDK for [LoginLlama](https://loginllama.app) - AI-powered login security and fraud detection.

## Features

- **Automatic Context Detection**: Auto-detects IP address and User-Agent from Flask, Django, FastAPI, and other frameworks
- **Multi-Source IP Extraction**: Supports X-Forwarded-For, CF-Connecting-IP, X-Real-IP, True-Client-IP with private IP filtering
- **Middleware Support**: Drop-in middleware for Flask, Django, and FastAPI
- **Type Hints**: Fully typed for excellent IDE support
- **Webhook Verification**: Built-in HMAC signature verification

## Installation

```bash
pip install loginllama==2.0.0
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv pip install loginllama==2.0.0
```

Requires Python 3.10 or higher.

## Quick Start

### With Middleware (Recommended)

The simplest way to use LoginLlama is with the middleware pattern, which automatically captures request context:

```python
from loginllama import LoginLlama
from flask import Flask, request, jsonify

app = Flask(__name__)
loginllama = LoginLlama(api_key='your-api-key')

# Add middleware to auto-capture request context
@app.before_request
def setup_loginllama():
    loginllama.middleware()()

@app.route('/login', methods=['POST'])
def login():
    try:
        # IP and User-Agent are automatically detected!
        result = loginllama.check(request.form['email'])

        if result.status == 'error' or result.risk_score > 5:
            print(f"Suspicious login blocked: {result.codes}")
            return jsonify({'error': 'Login blocked'}), 403

        # Continue with login...
        return jsonify({'success': True})
    except Exception as error:
        print(f'LoginLlama error: {error}')
        # Fail open on errors
        return jsonify({'success': True})
```

### Without Middleware

If you prefer not to use middleware, you can pass the request explicitly:

```python
result = loginllama.check(
    request.form['email'],
    request=request
)
```

Or provide IP and User-Agent manually:

```python
result = loginllama.check(
    'user@example.com',
    ip_address='203.0.113.42',
    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64)...'
)
```

## Framework Examples

### Flask

```python
from flask import Flask, request, jsonify
from loginllama import LoginLlama

app = Flask(__name__)
loginllama = LoginLlama()  # Uses LOGINLLAMA_API_KEY env var

# Use middleware for automatic detection
@app.before_request
def setup_loginllama():
    loginllama.middleware()()

@app.route('/login', methods=['POST'])
def login():
    result = loginllama.check(
        request.form['email'],
        geo_country='US',
        geo_city='San Francisco'
    )

    if result.risk_score > 5:
        return jsonify({'error': 'Suspicious login'}), 403

    return jsonify({'success': True})
```

### Django

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from loginllama import LoginLlama

loginllama = LoginLlama()

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Pass request explicitly for auto-detection
        result = loginllama.check(email, request=request)

        if result.risk_score > 5:
            return JsonResponse(
                {'error': 'Suspicious login'},
                status=403
            )

        return JsonResponse({'success': True})

    return JsonResponse({'error': 'Method not allowed'}, status=405)
```

### FastAPI

```python
from fastapi import FastAPI, Request, HTTPException
from loginllama import LoginLlama
from pydantic import BaseModel

app = FastAPI()
loginllama = LoginLlama()

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post('/login')
async def login(login_data: LoginRequest, request: Request):
    # Pass request explicitly for auto-detection
    result = loginllama.check(
        login_data.email,
        request=request
    )

    if result.risk_score > 5:
        raise HTTPException(
            status_code=403,
            detail='Suspicious login detected'
        )

    return {'success': True}
```

## API Reference

### `LoginLlama(api_key=None, base_url=None)`

Create a new LoginLlama client.

**Parameters:**
- `api_key` (optional): Your API key. Defaults to `LOGINLLAMA_API_KEY` environment variable
- `base_url` (optional): Custom API endpoint for testing

```python
from loginllama import LoginLlama

loginllama = LoginLlama(api_key='your-api-key')
```

### `loginllama.check(identity_key, **options)`

Check a login attempt for suspicious activity.

**Parameters:**
- `identity_key` (required): User identifier (email, username, user ID, etc.)
- `ip_address` (optional): Override auto-detected IP address
- `user_agent` (optional): Override auto-detected User-Agent
- `request` (optional): Explicit request object (Flask, Django, FastAPI)
- `email_address` (optional): User's email address for additional verification
- `geo_country` (optional): ISO country code (e.g., 'US', 'GB')
- `geo_city` (optional): City name for additional context
- `user_time_of_day` (optional): Time of login attempt

**Returns:** `LoginCheck` object

```python
class LoginCheck:
    status: str  # 'success' or 'error'
    message: str
    codes: List[LoginCheckStatus]
    risk_score: int  # 0-10 scale
    environment: str
    meta: Optional[dict]
```

**Detection Priority:**
1. Explicit `ip_address` and `user_agent` keyword arguments
2. Extract from `request` object if provided
3. Use context from middleware (if used)
4. Fallback to `$_SERVER` (PHP-style environments)

**Examples:**

```python
# Auto-detect from middleware context
result = loginllama.check('user@example.com')

# Pass request explicitly
result = loginllama.check('user@example.com', request=request)

# Manual override
result = loginllama.check(
    'user@example.com',
    ip_address='203.0.113.42',
    user_agent='Mozilla/5.0...'
)

# With additional context
result = loginllama.check(
    'user@example.com',
    email_address='user@example.com',
    geo_country='US',
    geo_city='San Francisco'
)
```

### `loginllama.middleware()`

Returns middleware function that automatically captures request context using `contextvars`.

**Flask:**
```python
@app.before_request
def setup_loginllama():
    loginllama.middleware()()
```

**Django (middleware class):**
```python
class LoginLlamaMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.loginllama = LoginLlama()

    def __call__(self, request):
        self.loginllama.middleware()(request)
        return self.get_response(request)
```

**FastAPI:**
```python
@app.middleware("http")
async def loginllama_middleware(request: Request, call_next):
    loginllama.middleware()(request)
    response = await call_next(request)
    return response
```

### `verify_webhook_signature(payload, signature, secret)`

Verify webhook signature using constant-time HMAC comparison.

**Parameters:**
- `payload`: Raw webhook body (bytes or str)
- `signature`: Value from `X-LoginLlama-Signature` header
- `secret`: Webhook secret from LoginLlama dashboard

**Returns:** `bool`

```python
from loginllama import verify_webhook_signature
from flask import Flask, request

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    signature = request.headers.get('X-LoginLlama-Signature')

    if not verify_webhook_signature(payload, signature, os.environ['WEBHOOK_SECRET']):
        return 'Invalid signature', 401

    event = request.get_json()
    # Handle event...
    return 'ok', 200
```

## Login Status Codes

The SDK exports a `LoginCheckStatus` enum with all possible status codes:

```python
from loginllama import LoginCheckStatus

# Example status codes:
LoginCheckStatus.VALID
LoginCheckStatus.IP_ADDRESS_SUSPICIOUS
LoginCheckStatus.KNOWN_BOT
LoginCheckStatus.GEO_IMPOSSIBLE_TRAVEL
LoginCheckStatus.USER_AGENT_SUSPICIOUS
# ... and more
```

## Error Handling

The SDK will raise exceptions if required parameters are missing:

```python
try:
    result = loginllama.check('user@example.com')
except ValueError as error:
    if 'IP address could not be detected' in str(error):
        # No IP available - pass ip_address or request explicitly
        # or use middleware()
        pass
except Exception as error:
    # Consider failing open on errors to avoid blocking legitimate users
    print(f'LoginLlama error: {error}')
```

**Best Practice:** Fail open on errors to avoid blocking legitimate users during API outages:

```python
try:
    result = loginllama.check(email)
    if result.risk_score > 5:
        # Block suspicious login
        return jsonify({'error': 'Login blocked'}), 403
except Exception as error:
    print(f'LoginLlama error: {error}')
    # Fail open - allow login to proceed
    return jsonify({'success': True})
```

## IP Detection

The SDK automatically detects IP addresses from multiple sources with priority fallback:

1. **X-Forwarded-For** - Parses chain, takes first public IP (filters private IPs)
2. **CF-Connecting-IP** - Cloudflare real client IP
3. **X-Real-IP** - nginx proxy header
4. **True-Client-IP** - Akamai/Cloudflare header
5. **Direct connection** - `REMOTE_ADDR`, framework-specific attributes

**Private IP Filtering:** Automatically filters `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, `127.x.x.x`, `::1`, `fc00::/7`, `fe80::/10`

## Type Hints

The SDK is fully typed with type hints:

```python
from loginllama import (
    LoginLlama,
    LoginCheck,
    LoginCheckStatus,
    verify_webhook_signature
)
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/joshghent/loginllama.py).

## License

MIT License

## Support

- Documentation: [loginllama.app/docs](https://loginllama.app/docs)
- Dashboard: [loginllama.app/dashboard](https://loginllama.app/dashboard)
- Issues: [GitHub Issues](https://github.com/joshghent/loginllama.py/issues)
