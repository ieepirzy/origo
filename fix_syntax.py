with open("tests/test_endpoints.py", "r") as f:
    content = f.read()

content = content.replace('clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb", "https://example.com/callback", "myapp://callback"]},\n        client_redirect_uris={"c": ["https://allowed.example/cb"]},', 'clients={"c": "s"},\n        client_redirect_uris={"c": ["https://allowed.example/cb"]},')

with open("tests/test_endpoints.py", "w") as f:
    f.write(content)
