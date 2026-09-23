## 2024-05-24 - DoS via Unhandled Multipart Form Parse Exception
**Vulnerability:** Unhandled `python_multipart.exceptions.MultipartParseError` when parsing malformed `multipart/form-data` payloads using `await request.form()` in Starlette.
**Learning:** Calling `await request.form()` directly without wrapping it in a generic `try...except Exception` block in ASGI frameworks like Starlette or FastAPI allows an attacker to crash the request handler or generate a 500 error by sending malformed multipart boundaries.
**Prevention:** Always wrap `await request.form()` and similar parsing calls in a broad `try...except` block, safely catching exceptions and returning an HTTP 400 Bad Request instead of allowing it to bubble up to a 500 Internal Server Error.
