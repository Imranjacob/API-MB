import requests
import json


# Test the login API directly
def test_login():
    base_url = "http://192.168.10.106:5000"

    # Test data
    test_cases = [
        {"username": "admin", "password": "Admin123!", "expected": "success"},
        {"username": "test", "password": "Test123!", "expected": "success"},
        {"username": "admin", "password": "wrong", "expected": "fail"},
    ]

    for test in test_cases:
        print(f"\nTesting login for {test['username']}...")

        try:
            response = requests.post(
                f"{base_url}/api/auth/login",
                json={
                    "username": test["username"],
                    "password": test["password"]
                },
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")

            if response.status_code == 200:
                data = response.json()
                print(f"✓ Login successful! Token: {data['access_token'][:50]}...")
            else:
                print(f"✗ Login failed: {response.json()}")

        except Exception as e:
            print(f"✗ Request failed: {e}")


if __name__ == "__main__":
    print("Testing API Login Endpoint...")
    test_login()