# DigestAuth
Library to use digest authentication in Vapor

Implements the digest authentication as described in [rfc2617](https://www.rfc-editor.org/rfc/rfc2617) and provides a convenient interface to use it in Vapor. In particular we implemented generation and validation of nonces (`generateNonce`, `generateClientNonce`, `validateNonce`), calculation of the digest response `digest` see [DigestAuth](https://github.com/stefanspringer1/DigestAuth/blob/main/Sources/DigestAuth/DigestAuth.swift). 

The vapor interface works as follows. To make a http get request from vapor routes using digest one just supplies `makeDigestQuery` with the request, the app, the uri, user and password and it gives the result of the request see [demoAuthClient](https://github.com/stefanspringer1/DigestAuthDemoApp/blob/main/Sources/App/routes.swift). 

To authenticate a user using vapor and digest we provide a wrapper for a function `Request async throws -> Response` as usually used in vapor routes. The idea is that `digestResponder` turns a function giving the response without authentication and a function mapping username to password to a function giving the response with authentication see [DigestAuth](https://github.com/stefanspringer1/DigestAuth/blob/main/Sources/DigestAuth/DigestAuth.swift) and [demoAuthServer](https://github.com/stefanspringer1/DigestAuthDemoApp/blob/main/Sources/App/routes.swift).
