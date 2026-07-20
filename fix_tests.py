import re
import glob

def fix_tests():
    for filename in glob.glob('tests/**/*.py', recursive=True):
        with open(filename, 'r') as f:
            content = f.read()

        # Update provider instantations to have a redirect_uri if they only have a client
        content = re.sub(r'clients=\{([^}]+)\}', r'clients={\1}, client_redirect_uris={\1: ["https://example.com/cb"]}', content)

        # We need to specifically replace some cases since the regex isn't perfect for all cases

        # For the dictionary {"test-client": "test-secret"}
        content = content.replace(
            'clients={"test-client": "test-secret"}, client_redirect_uris={"test-client": "test-secret": ["https://example.com/cb"]}',
            'clients={"test-client": "test-secret"}, client_redirect_uris={"test-client": ["https://example.com/cb"]}'
        )

        with open(filename, 'w') as f:
            f.write(content)

fix_tests()
