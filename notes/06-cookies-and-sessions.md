# Lab 6 – Cookies and Sessions

Completed: 7 November 2026 (Europe/London).

## Objectives and environment

I inspected cookies and login response headers in my own local OWASP Juice Shop lab at `http://localhost:3000`, using Burp Suite Community and its browser on Windows. I compared cookie protections with the authentication token traced in Lab 5.

## Procedure

1. In Burp's browser, I opened Developer Tools → Application → Storage → Cookies → `http://localhost:3000`.
2. I inspected Name, Domain, Path, Expires/Max-Age, HttpOnly, Secure and SameSite without recording values.
3. In Burp → Proxy → HTTP history, I selected `POST /rest/user/login` and inspected its response headers for `Set-Cookie`.
4. I compared my observations with the authentication flow established in Lab 5.

## Lab 6 observations

| Property | Observed setting |
|---|---|
| Cookie name | `language` |
| Domain | `localhost` |
| Path | `/` |
| Expires/Max-Age | Truncated; exact expiry unknown |
| HttpOnly | Unchecked |
| Secure | Unchecked |
| SameSite | Blank; no explicit setting shown |
| Login response `Set-Cookie` | No `Set-Cookie` header present |

Modern browsers generally apply Lax by default when SameSite is omitted. Blank does not mean `SameSite=None`.

The `language` cookie appears to be a preference cookie rather than an authentication token. Missing flags on this cookie alone do not demonstrate an account-security vulnerability.

## Evidence references

- [Cookie attributes](../captures/cookies-language.png)
- [Login response headers](../captures/login-response-headers-redacted.png)

The referenced screenshots are present locally. The login-header copy has an opaque redaction at the token-value boundary.

## Authentication flow previously observed in Lab 5

In Lab 5, I observed an `authentication` object containing `token` in the login JSON response, found Local Storage → `http://localhost:3000` → `token`, and observed a later request using `Authorization: Bearer …`.

Those storage and request-header observations were established in Lab 5, not newly demonstrated in Lab 6. In Lab 6, I inspected the login response and found no `Set-Cookie`. I must not assume that an authentication token is a cookie.

## Cookie protections

- **HttpOnly:** Prevents JavaScript from reading the particular cookie through `document.cookie`. It does not stop malicious JavaScript from making authenticated requests that the browser sends with cookies.
- **Secure:** Restricts transmission to secure connections, normally HTTPS; browsers make special allowances for localhost.
- **SameSite:** Restricts sending cookies on cross-site requests, helping reduce CSRF. `Strict` is most restrictive; `Lax` allows some top-level navigations; `None` permits cross-site use and requires `Secure`.

Cookies are sent automatically when their scope and transmission rules match. My application explicitly adds its Local Storage token to the Authorization header. Local Storage has none of these cookie attributes.

## Security interpretation

Malicious JavaScript executing on the same origin can read Local Storage and steal its authentication token. A stolen bearer token may allow impersonation while valid. Adding HttpOnly to an unrelated language cookie does not protect this token. HttpOnly is not a defence against all effects of XSS.

## My checkpoint answer

> No. Adding the HttpOnly attribute to the language cookie would not protect the authentication token stored in Local Storage.
>
> Why?
>
> HttpOnly applies only to cookies. It prevents JavaScript from reading a specific cookie through document.cookie.

## Conclusion

I passed Lab 6 by explaining the distinction between a preference cookie and my Local Storage token, and the scope of HttpOnly. All six Stage 1 labs are passed. The Stage 1 portfolio is still unfinished: the local packet-summary script has now been created and tested on my three captures, but publishing and a final portfolio sign-off remain outstanding. This folder is not currently a Git repository.

I have included no passwords, token values, cookie values or session secrets in these notes.
