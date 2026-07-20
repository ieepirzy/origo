for filename in ["tests/test_middleware.py", "tests/test_middleware_path_bypass.py"]:
    with open(filename, "r") as f:
        content = f.read()
    content = content.replace(
        'clients={"c": "s"}',
        'clients={"c": "s"}, client_redirect_uris={"c": ["https://example.com/cb"]}'
    )
    with open(filename, "w") as f:
        f.write(content)

with open("tests/test_storage.py", "r") as f:
    content = f.read()
replacements = [
    (
        'storage.seed_clients({"alice": "secret1", "bob": "secret2"})',
        'storage.seed_clients({"alice": "secret1", "bob": "secret2"}, {"alice": ["https://example.com"], "bob": ["https://example.com/cb"]})'
    ),
    (
        'storage.seed_clients({"c": "s"})',
        'storage.seed_clients({"c": "s"}, {"c": ["https://example.com/cb"]})'
    ),
    (
        'storage.seed_clients({"permanent-client": "s"})',
        'storage.seed_clients({"permanent-client": "s"}, {"permanent-client": ["https://example.com/cb"]})'
    ),
    (
        'bounded_storage.seed_clients({"permanent-1": "s1", "permanent-2": "s2"})',
        'bounded_storage.seed_clients({"permanent-1": "s1", "permanent-2": "s2"}, {"permanent-1": ["https://example.com/cb"], "permanent-2": ["https://example.com/cb"]})'
    ),
    (
        'bounded_storage.seed_clients({"permanent-client": "s"})',
        'bounded_storage.seed_clients({"permanent-client": "s"}, {"permanent-client": ["https://example.com/cb"]})'
    )
]
for old, new in replacements:
    content = content.replace(old, new)
with open("tests/test_storage.py", "w") as f:
    f.write(content)
