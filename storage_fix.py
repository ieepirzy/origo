def fix_storage_and_tests():
    with open('origo/storage.py', 'r') as f:
        content = f.read()

    content = content.replace('"""Return True if redirect_uri is allowed for the client. No stored URIs means any is allowed."""', '"""Return True if redirect_uri is allowed for the client."""')
    content = content.replace('return not allowed or redirect_uri in allowed', 'return bool(allowed and redirect_uri in allowed)')

    with open('origo/storage.py', 'w') as f:
        f.write(content)

fix_storage_and_tests()
