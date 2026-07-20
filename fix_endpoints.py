with open("tests/test_endpoints.py", "r") as f:
    content = f.read()

replacements = [
    (
        'clients={"c": "s"}',
        'clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb", "https://example.com/callback", "myapp://callback"]}'
    ),
    (
        'clients={"client-a": "secret-a", "client-b": "secret-b"}',
        'clients={"client-a": "secret-a", "client-b": "secret-b"}, client_redirect_uris={"client-a": ["https://example.com/cb"], "client-b": ["https://example.com/cb"]}'
    ),
    (
        'clients={"preseeded-client": "preseeded-secret"}',
        'clients={"preseeded-client": "preseeded-secret"}, client_redirect_uris={"preseeded-client": ["https://example.com/callback"]}'
    ),
    (
        'clients={"existing": "secret"}',
        'clients={"existing": "secret"}, client_redirect_uris={"existing": ["https://example.com/cb"]}'
    ),
    (
        's.seed_clients({"c": "s"})',
        's.seed_clients({"c": "s"}, {"c": ["https://example.com/cb"]})'
    ),
    (
        'provider.storage.seed_clients({"other-client": "other-secret"})',
        'provider.storage.seed_clients({"other-client": "other-secret"}, {"other-client": ["https://example.com/cb"]})'
    )
]

for old, new in replacements:
    content = content.replace(old, new)

with open("tests/test_endpoints.py", "w") as f:
    f.write(content)
