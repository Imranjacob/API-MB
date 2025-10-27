import os
import sys

sys.path.append('.')

from app import create_app, db, User

app = create_app()

with app.app_context():
    print("=== Database Test ===")

    # Count users
    user_count = User.query.count()
    print(f"Total users in database: {user_count}")

    # List all users
    users = User.query.all()
    for user in users:
        print(f"User: {user.username} (ID: {user.id}, Role: {user.role})")

        # Test password verification
        test_passwords = ['Admin123!', 'Test123!', 'wrongpassword']
        for pwd in test_passwords:
            try:
                result = user.check_password(pwd)
                print(f"  Password '{pwd}': {'✓ Correct' if result else '✗ Incorrect'}")
            except Exception as e:
                print(f"  Password '{pwd}': Error - {e}")

    print("=== Test Complete ===")