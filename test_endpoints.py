import requests
import json


def test_endpoints():
    base_url = "http://192.168.10.106:5000"

    endpoints = [
        "/api/debug/test",
        "/api/debug/headers",
        "/debug/users",
        "/debug/current-user"
    ]

    print("Testing API endpoints...")

    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            print(f"{endpoint}: {response.status_code} - {'✓' if response.status_code == 200 else '✗'}")
            if response.status_code != 200:
                print(f"  Response: {response.text}")
        except Exception as e:
            print(f"{endpoint}: ERROR - {e}")


if __name__ == "__main__":
    test_endpoints()