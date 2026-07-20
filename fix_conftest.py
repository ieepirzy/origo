with open("tests/conftest.py", "r") as f:
    content = f.read()
content = content.replace(
    'client_redirect_uris={"test-client": ["https://example.com/cb"]},',
    'client_redirect_uris={"test-client": ["https://example.com/cb", "https://example.com/cb?existing=1"]},'
)
with open("tests/conftest.py", "w") as f:
    f.write(content)
