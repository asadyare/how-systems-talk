# Lab 5 – Capture My Login in Burp

Completed: 7 November 2026 (Europe/London).

## Objectives and environment

I traced authentication from the login request to the response, browser storage and a later authenticated request. I used my own local OWASP Juice Shop instance at `http://localhost:3000` and Burp Suite Community on Windows, with Burp's built-in browser. This was a plain HTTP localhost lab, not an HTTPS connection.

## Procedure

1. I opened a temporary Burp project with the defaults and opened Burp's browser from Proxy → Intercept, with interception off.
2. I opened my local Juice Shop, registered a lab-only account and logged in.
3. I inspected `POST /rest/user/login` in Proxy → HTTP history, comparing the request and response.
4. I selected a later `GET /rest/user/whoami` request and checked its Authorization header without sharing its token value.
5. I opened the browser Developer Tools using Inspect or Ctrl+Shift+I, then checked Application → Local Storage → `http://localhost:3000`.

## Observed login flow

| Step | Observation |
|---|---|
| Login request | `POST /rest/user/login` |
| Request JSON field names | `email`, `password` |
| Login response status | `HTTP/1.1 200 OK` |
| Response JSON structure | `authentication` object containing `token` |
| Browser storage | Local Storage → `http://localhost:3000` → `token` |
| Later request | `GET /rest/user/whoami` |
| Authentication header | `Authorization: Bearer …` |

The login request sends my credentials. The response returns an authentication token in JSON. The browser stores that token in Local Storage and sends it on a later request in the Authorization header instead of sending my password again. A bearer token can authorise whoever possesses it while it remains valid.

I observed these steps rather than assuming the token was a cookie. Lab 6 separately inspected cookie attributes and the login response for `Set-Cookie`.

## Evidence references

- [Login request and response](../captures/login-request-response-redacted.png)
- [Authenticated request](../captures/authenticated-request-redacted.png)
- [Local Storage token key](../captures/local-storage-token-redacted.png)

I use the opaque-redacted copies below. Originals are preserved locally and excluded by `.gitignore`; they should not be published. The detailed flow is in [my Burp walkthrough](../burp/login-flow.md).

## Security interpretation

Because this local connection used HTTP, Burp could inspect its JSON directly; this did not require TLS session-key decryption. Plain HTTP would not protect credentials or tokens from a network observer, so this is appropriate only for my controlled lab, not a production authentication deployment.

Local Storage is readable by JavaScript running on the same origin. If an attacker successfully executes malicious JavaScript on this origin, for example through XSS, that script can read the token. Local Storage does not have the HttpOnly, Secure or SameSite attributes available to cookies. This observation explains a risk; it does not itself demonstrate an exploitable XSS vulnerability.

## My checkpoint answer

> An attacker who successfully executes malicious JavaScript on the same origin as the website can steal an authentication token stored in Local Storage because Local Storage is accessible to JavaScript running within that origin.

## Conclusion

I passed Lab 5 by tracing the login response token into Local Storage and then into a later Authorization header, and explaining the same-origin JavaScript risk. These notes contain no credential values, token values or session secrets.
