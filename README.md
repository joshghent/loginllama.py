# LoginLlama API Client

This Python module provides an interface to interact with the LoginLlama API, which offers login status checks for users based on various parameters.

## Sign up for free at [loginllama.app](https://loginllama.app).

## Installation

Install via `uv` or pip. Requires Python 3.10 or higher.

```sh
uv pip install loginllama
# or
pip install loginllama
```

## Usage

First, import the necessary classes:

```python
from loginllama import LoginLlama, verify_webhook_signature
```

### Initialization

To initialize the `LoginLlama` class, you can either provide an API token directly or set it in the environment variable `LOGINLLAMA_API_KEY`. Pass `base_url` if you need to target a mock server.

```python
loginllama = LoginLlama(api_token="YOUR_API_TOKEN")
```

Or, if using the environment variable `LOGINLLAMA_API_KEY`:

```python
loginllama = LoginLlama()
# Pulls from the environment variable LOGINLLAMA_API_KEY
```

### Checking Login Status

The primary function provided by this module is `check_login`, which checks the login status of a user based on various parameters. Both snake_case and camelCase parameter names are accepted to match the docs.

#### Parameters:

- `request` (optional): A Django or Flask request object. If provided, the IP address and user agent will be extracted from this object.
- `ip_address` / `ipAddress` (optional): The IP address of the user. If not provided and the `request` object is given, it will be extracted from the request.
- `user_agent` / `userAgent` (optional): The user agent string of the user. If not provided and the `request` object is given, it will be extracted from the request.
- `identity_key` / `identityKey`: The unique identity key for the user. This is a required parameter.
- `email_address`, `geo_country`, `geo_city`, `user_time_of_day`: Optional context fields.

#### Return Value:

The function returns a `LoginCheck` object. This object contains the result of the login check, including the status, message, codes, risk_score, environment, and meta data.

#### Examples:

Using IP address and user agent directly:

```python
loginCheckResult = loginllama.check_login(
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0",
    identity_key="user123"
)
print(loginCheckResult.status, loginCheckResult.risk_score, loginCheckResult.codes)
```

Using a Flask request object:

```python
from flask import Flask, request

app = Flask(__name__)
loginllama = LoginLlama(api_token='your_api_token')

@app.route('/login_check', methods=['POST'])
def login_check():
    identity_key = request.form.get('identity_key')
    if not identity_key:
        return "identity_key is required", 400

    try:
        login_check_result = loginllama.check_login(request=request, identity_key=identity_key)
        return {
            "status": login_check_result.status,
            "message": login_check_result.message,
            "codes": [getattr(code, "value", code) for code in login_check_result.codes]
        }
    except ValueError as e:
        return str(e), 400
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run()
```

Using a Django request object:

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from loginllama.loginllama import LoginLlama

@csrf_exempt
def login_check(request):
    if request.method == 'POST':
        identity_key = request.POST.get('identity_key')
        if not identity_key:
            return JsonResponse({"error": "identity_key is required"}, status=400)

        try:
            loginllama = LoginLlama(api_token='your_api_token')
            login_check_result = loginllama.check_login(request=request, identity_key=identity_key)
            return JsonResponse({
                "status": login_check_result.status,
                "message": login_check_result.message,
                "codes": [getattr(code, "value", code) for code in login_check_result.codes],
                "risk_score": login_check_result.risk_score,
                "environment": login_check_result.environment,
            })
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)
```

## Error Handling

The `check_login` function will raise exceptions if any of the required parameters (`ip_address`, `user_agent`, or `identity_key`) are missing (if `request` is not provided).

## API Endpoint

The default API endpoint used by this module is `https://loginllama.app/api/v1`.

## Login Status Codes

The module provides an enumeration `LoginCheckStatus` that lists various possible status codes returned by the LoginLlama API, such as `VALID`, `IP_ADDRESS_SUSPICIOUS`, `KNOWN_BOT`, etc.

## Webhook signature verification

Use the helper to verify the `X-LoginLlama-Signature` header with the raw request body:

```python
from loginllama import verify_webhook_signature

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data()
    signature = request.headers.get("X-LoginLlama-Signature")

    if not verify_webhook_signature(payload, signature, os.environ["WEBHOOK_SECRET"]):
        return "Invalid signature", 401

    event = request.get_json()
    # handle event...
    return "ok", 200
```

## Contributing

If you find any issues or have suggestions for improvements, please open an issue or submit a pull request. Your contributions are welcome!

## License

This module is licensed under the MIT License.
