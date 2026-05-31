
# webauthnext

`webauthnext` is a combined **WebAuthn (Passkeys)** and **OpenID Connect (OIDC) Identity Provider** package for Go. Built on top of `guikit` and `ultimate_db`, it provides an all-in-one authentication server capable of registering and authenticating users with passkeys while serving as an OIDC provider for external clients.

## Features

* **Passkey Native**: Full implementation of WebAuthn registration and login flows using `[github.com/go-webauthn/webauthn](https://github.com/go-webauthn/webauthn)`.
* **OIDC Identity Provider**: Supports standard OpenID Connect discovery (`.well-known/openid-configuration`), JWKS endpoint keys, authorization code grant flow, and ID token production.
* **Self-Contained Frontend**: Automatically serves required WebAuthn browser helper utilities (`/auth/webauthn.js`) for buffer conversion and credential requests.
* **Built-in Persistence**: Seamlessly handles state (users, active sessions, OIDC flow contexts, and auth codes) utilizing transactional features via `ultimate_db`.

---

## Architecture Overview

The authentication manager hooks directly into the `guikit.GUIKit` multiplexer and orchestrates communication between the web client, the storage engine, and external relying parties.

```
       [ OIDC Client ] <--- OIDC Discovery / Token Exchange ---> [ webauthnext.Manager ]
                                                                        |
[ Browser Client ] <--- WebAuthn Sign / Verify Handshake ---> [ HTTP Mux / Handlers ]
                                                                        |
                                                                  [ ultimate_db ]

```

---

## Core Endpoints

The package exposes the following routes automatically upon initialization:

### WebAuthn (Passkeys)

* `GET /auth/register/begin` — Generates credential creation options for registration.
* `POST /auth/register/finish` — Validates client attestation and saves new passkey.
* `GET /auth/login/begin` — Generates credential assertion options for signing.
* `POST /auth/login/finish` — Validates signed assertion data to complete login.
* `GET /auth/webauthn.js` — Client-side JavaScript handling passkey handshakes.

### OpenID Connect

* `GET /.well-known/openid-configuration` — Discovery endpoint mapping out capabilities.
* `GET /auth/keys` — Serves the JSON Web Key Set (JWKS) to verify generated ID Tokens.
* `GET /auth/authorize` — Handles client authorization requests, validates domains, and kicks off login/MFA verification.
* `POST /auth/token` — Exchanges authorization codes for cryptographically signed RS256 ID tokens.

---

## Database Key Layout

All internal state is managed under `ultimate_db.PageID = 1` (`AuthPageID`). Data keys utilize the following prefixes:

| Key Prefix | Data Structure | Purpose / Lifespan |
| --- | --- | --- |
| `user:{username}` | `PasskeyUser` (JSON) | Persistent user profile and registered credentials |
| `banned:{username}` | Primitive array/flag | Ban state listing blocked handles or devices |
| `session:reg_{username}` | `webauthn.SessionData` | In-flight registration challenge context (5-min TTL) |
| `session:login_{username}` | `webauthn.SessionData` | In-flight login challenge context (5-min TTL) |
| `oidc_flow:{flow_id}` | `AuthRequest` (JSON) | Active client authorization request details (10-min TTL) |
| `auth_code:{code}` | Context Map (JSON) | Issued OIDC auth code awaiting token exchange (5-min TTL) |
| `mfa_verified_{username}` | `"true"` / `"false"` string | MFA step completion marker |

---

## Installation

Ensure your Go module environment is configured with access to your custom dependencies:

```bash
go get github.com/gorrila/websocket
go get github.com/gddisney/ultimate_db
go get github.com/gddisney/guikit
go get github.com/go-webauthn/webauthn
go get github.com/golang-jwt/jwt/v5
go get gopkg.in/square/go-jose.v2

```

---

## Usage Example

Initialize the `webauthnext` manager inside your core application startup where `guikit` is configured:

```go
package main

import (
    "log"
    "net/http"

    "github.com/gddisney/guikit"
    "github.com/gddisney/webauthnext"
)

func main() {
    // 1. Initialize your GUIKit structure
    gk := guikit.NewEngine(/* config flags */)

    // 2. Instantiate the Auth Manager
    authManager, err := webauthnext.New(
        gk,
        "My Enterprise App",      // Relying Party Display Name
        "auth.example.com",       // Relying Party ID (Domain)
        "https://auth.example.com",// Relying Party Origin
    )
    if err != nil {
        log.Fatalf("Failed to initialize auth manager: %v", err)
    }

    // 3. (Optional) Custom hooks for successful login behaviors
    authManager.OnLoginSuccess = func(username string, w http.ResponseWriter, r *http.Request) {
        log.Printf("User %s successfully logged in via passkey!", username)
    }

    // 4. Start serving your application
    log.Fatal(http.ListenAndServe(":8080", gk.Mux))
}

```

### Front-End Implementation

To invoke passkey registration or login within your front-end templates, include the embedded script and use the exposed async functions:

```html
<!-- Load the client side bridge generated by the manager -->
<script src="/auth/webauthn.js"></script>

<script>
    // To register a new user or device passkey
    async function handleRegister() {
        const username = document.getElementById('usernameField').value;
        await passkeyRegister(username);
    }

    // To sign in using an existing passkey
    async function handleLogin() {
        const username = document.getElementById('usernameField').value;
        await passkeyLogin(username);
    }
</script>

```

---
