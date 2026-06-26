## 2023-10-24 - [XSS Fix]
**Vulnerability:** Cross-Site Scripting (XSS) in `_consent_page` HTML response.
**Learning:** Python f-strings used for dynamic HTML generation require explicit HTML escaping for any variable data, as standard variables are not sanitized by default.
**Prevention:** Always use `html.escape()` or a robust templating engine (like Jinja2) that handles auto-escaping when injecting user input into HTML structures.
