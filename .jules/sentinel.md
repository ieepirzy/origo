## 2024-06-29 - Fixed CSRF Vulnerability in OAuth Consent Form

**Vulnerability:** A CSRF (Cross-Site Request Forgery) vulnerability allowed any website to trigger the OAuth authorization consent form via a direct POST request without the user's authorization or intent, potentially leaking the authorization code or granting access.
**Learning:** The absence of CSRF protection token validation, particularly using standard stateful or stateless paradigms like Double Submit Cookie, in endpoints that serve state-changing POST forms can lead to unintended approvals of authorization grants.
**Prevention:** Ensured the consent GET form correctly embeds a stateless cryptographic CSRF token, and required its presence and validation against a secure `Lax` or `Strict` cookie upon the subsequent POST request. Also, set the `X-Frame-Options: DENY` header on the consent form page to prevent Clickjacking.
