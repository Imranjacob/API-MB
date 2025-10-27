import os
import re


def find_api_routes():
    api_patterns = [
        r'@app\.route\([^)]*[\'"]\/api\/[^)]*[\'"]',
        r'@api\.route\([^)]*[\'"]\/[^)]*[\'"]',
        r'@bp\.route\([^)]*[\'"]\/api\/[^)]*[\'"]',
        r'@.*\.route\([^)]*[\'"]\/api\/[^)]*[\'"]'
    ]

    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.py') and '__pycache__' not in root:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        for pattern in api_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                print(f"\n📁 {filepath}:")
                                for match in matches:
                                    print(f"  🔗 {match}")
                except Exception as e:
                    pass


if __name__ == "__main__":
    find_api_routes()