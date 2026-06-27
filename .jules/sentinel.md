## 2023-10-24 - [XSS Fix]
**Vulnerability:** Cross-Site Scripting (XSS) in `_consent_page` HTML response.
**Learning:** Python f-strings used for dynamic HTML generation require explicit HTML escaping for any variable data, as standard variables are not sanitized by default.
**Prevention:** Always use `html.escape()` or a robust templating engine (like Jinja2) that handles auto-escaping when injecting user input into HTML structures.
## 2024-05-18 - [Authorization Bypass via Prefix Matching]
**Vulnerability:** Authorization bypass using path prefix matching. Protected endpoints that started with the same name as public OAuth endpoints (e.g., `/token_info` vs `/token`) were inadvertently exposed.
**Learning:** Using `startswith` for path validation without trailing slashes in an API router/middleware is extremely dangerous, as it creates unintentional wildcard matching for any endpoint starting with those characters.
**Prevention:** Always use exact path matching (`path in ALLOWED_PATHS`) for specific endpoints. If prefix matching is required (like for `/.well-known/`), ensure it includes necessary trailing slashes or path segment boundaries.
