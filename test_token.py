import requests
import json

# PASTE YOUR ACTUAL TOKEN HERE (the one from browser console)
token = "PASTE_YOUR_REAL_TOKEN_HERE"

print(f"Testing token: {token[:50]}...")

try:
    response = requests.post(
        'http://192.168.10.106:5000/api/verify-token',
        json={'token': token}
    )

    print("Status Code:", response.status_code)
    result = response.json()
    print("Response:")
    print(json.dumps(result, indent=2))

    if result.get('valid'):
        print("✅ Token is VALID!")
        print(f"User ID: {result.get('user_id')}")
    else:
        print("❌ Token is INVALID!")
        print(f"Error: {result.get('error')}")

except Exception as e:
    print("Error:", e)